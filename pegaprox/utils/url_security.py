"""URL safety checks for outbound HTTP — SSRF defense (Aikido SAST hardening, May 2026).

Outbound HTTP from the backend that takes admin- or user-supplied URLs is the
classic SSRF vector. Most call sites in PegaProx hand a URL into requests.* or
urllib.request — examples are OIDC discovery, ACME directory, plugin webhook
push, SIEM forwarding, VMware host base URL.

What this module enforces:
  * scheme allowlist (default https; admins can permit http for localhost-only)
  * blocks raw IP literals that resolve into private / loopback / link-local /
    multicast space (RFC1918, 127/8, 169.254/16, ::1, fc00::/7, fe80::/10)
  * blocks the cloud metadata addresses (169.254.169.254, fd00:ec2::254)
  * CR/LF / NUL rejection (defeats header smuggling tricks)
  * resolves the hostname *before* the request and re-checks every returned IP,
    so an attacker can't dodge the IP-literal check by registering a DNS name
    that points at 127.0.0.1 or AWS metadata.

Two entry points:
  * is_safe_outbound_url(url, ...) -> (bool, reason)  — boolean check
  * sanitize_outbound_url(url, ...)  -> raises SsrfError on reject; returns url

Usage at the call site:
    from pegaprox.utils.url_security import sanitize_outbound_url
    sanitize_outbound_url(webhook_url)
    requests.post(webhook_url, ...)
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterable, Tuple
from urllib.parse import urlparse, urlunparse


class SsrfError(ValueError):
    """Raised when an outbound URL is rejected by the SSRF guard."""


# Cloud-metadata / well-known internal-only addresses we never want to hit.
_METADATA_HOSTS = frozenset({
    '169.254.169.254',         # AWS / GCP / Azure / DigitalOcean
    'metadata.google.internal',
    'metadata',                 # short alias used in some setups
    'fd00:ec2::254',            # AWS IPv6 metadata
})


def _embedded_ipv4(ip: ipaddress._BaseAddress):
    """The IPv4 address carried inside an IPv6 transition address, or None.

    Several IPv6 transition schemes embed a full IPv4 address in the v6 address.
    CPython's classification flags (is_private / is_reserved / …) have covered
    these inconsistently across 3.12.x point releases, so a guard that trusts the
    outer-address flags alone has a version-dependent hole
    (GHSA-ffhp-cpm8-4mpv, reported by tonghuaroot): a 6to4 / NAT64 / Teredo
    address embedding 169.254.169.254 or 127.0.0.1 can classify as 'public' and
    slip past. Decode the embedded v4 ourselves and classify THAT, so the verdict
    is correct on every Python version. Only the well-defined prefixes are decoded;
    anything else returns None and is classified as the plain v6 address it is.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    # ::ffff:a.b.c.d — IPv4-mapped (the common one; stdlib exposes it directly).
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    packed = ip.packed
    # 6to4  2002::/16 (RFC 3056) — the embedded IPv4 is bytes 2..5.
    if packed[0:2] == b'\x20\x02':
        return ipaddress.IPv4Address(packed[2:6])
    # NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) — embedded IPv4 in the last 4 bytes.
    if packed[0:12] == b'\x00\x64\xff\x9b' + b'\x00' * 8:
        return ipaddress.IPv4Address(packed[12:16])
    # NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215) — embedded IPv4 in the last 4 bytes.
    if packed[0:6] == b'\x00\x64\xff\x9b\x00\x01':
        return ipaddress.IPv4Address(packed[12:16])
    # Teredo 2001:0000::/32 (RFC 4380) — client IPv4 is the last 4 bytes, bitwise-inverted.
    if packed[0:4] == b'\x20\x01\x00\x00':
        return ipaddress.IPv4Address(bytes(b ^ 0xFF for b in packed[12:16]))
    # IPv4-compatible ::/96 (deprecated, RFC 4291 §2.5.5.1) — high 96 bits zero, embedded IPv4 in
    # the low 32. Caught last so :: / ::1 (also in ::/96) decode to 0.0.0.0 / 0.0.0.1, which stay
    # blocked as unspecified / reserved. Self-review add (not in the original advisory): the whole
    # ::/96 range was otherwise left to the stdlib flags — the exact version-dependent reliance this
    # fix removes for the other schemes. ::ffff:* was already handled above via .ipv4_mapped.
    if packed[0:12] == b'\x00' * 12:
        return ipaddress.IPv4Address(packed[12:16])
    return None


def _is_private_or_special(ip: ipaddress._BaseAddress) -> bool:
    """True if the IP falls in a range we should never reach over the public path."""
    # GHSA-ffhp-cpm8-4mpv — if this is an IPv6 transition address wrapping an IPv4
    # address, the real destination is that inner v4; classify it instead of trusting
    # the outer v6's stdlib flags (which miss embedded private/metadata targets on
    # some Python builds). A wrapped *public* v4 stays allowed; a wrapped private /
    # loopback / link-local (169.254/16 metadata) / reserved one is blocked.
    embedded = _embedded_ipv4(ip)
    if embedded is not None:
        return _is_private_or_special(embedded)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_loopback(ip: ipaddress._BaseAddress) -> bool:
    """Loopback on its own, transition addresses unwrapped like _is_private_or_special does.
    The outer address is judged FIRST: ::1 falls inside the ::/96 compat range, so unwrapping
    it first would hand back 0.0.0.1 and lose the loopback that was staring at us."""
    if ip.is_loopback or ip.is_unspecified:
        return True
    embedded = _embedded_ipv4(ip)
    if embedded is not None:
        return _is_loopback(embedded)
    return False


def _resolve_all(host: str) -> Iterable[ipaddress._BaseAddress]:
    """Resolve hostname to all A/AAAA records as ip_address objects.

    Raises socket.gaierror on resolution failure (caller should treat this
    as a hard reject — better safe than DNS-rebinding sorry).
    """
    addrs = []
    try:
        for info in socket.getaddrinfo(host, None):
            family = info[0]
            sockaddr = info[4]
            ip_str = sockaddr[0]
            # IPv6 sockaddr: (host, port, flowinfo, scopeid). Strip scope id.
            if family == socket.AF_INET6 and '%' in ip_str:
                ip_str = ip_str.split('%', 1)[0]
            try:
                addrs.append(ipaddress.ip_address(ip_str))
            except ValueError:
                continue
    except socket.gaierror:
        raise
    return addrs


def is_safe_outbound_url(
    url: str,
    *,
    allowed_schemes: Iterable[str] = ('https',),
    allow_private: bool = False,
    allow_loopback: bool = True,
    require_resolution: bool = True,
) -> Tuple[bool, str]:
    """Return (ok, reason).

    Args:
        url: The candidate URL.
        allowed_schemes: Schemes we permit; default https only. Pass
            ('https', 'http') if a specific call needs http (e.g. local
            test fixtures).
        allow_private: When True, skip private-IP / loopback rejection.
            Used for purely-internal outbound (cluster API on
            corporate LAN). Default False — most call sites want
            internal blocked.
        allow_loopback: Only consulted when allow_private is True. NS Sep 2026 — the
            private-LAN call sites need RFC1918 but not 127.0.0.0/8: a caller who can
            steer the URL and then read what came back gets at services bound to the
            fetching host's own loopback, which nothing else on the network can reach.
            Sites where the target is admin-configured (PBS, a node URL, a BMC) leave
            this True; a site that fetches a user-supplied URL passes False.
        require_resolution: When True, resolve DNS and reject if any
            returned IP is private / metadata / loopback. When False
            we only reject IP-literal hosts that are obviously bad
            (faster, but vulnerable to DNS rebinding).
    """
    if not isinstance(url, str) or not url:
        return False, 'empty url'
    # CR/LF/NUL anywhere in the URL → header smuggling vector
    if any(c in url for c in ('\r', '\n', '\x00')):
        return False, 'url contains control characters'

    try:
        parsed = urlparse(url)
    except Exception as exc:                # pragma: no cover - defensive
        return False, f'parse error: {exc}'

    scheme = (parsed.scheme or '').lower()
    if scheme not in {s.lower() for s in allowed_schemes}:
        return False, f'scheme {scheme!r} not allowed'

    host = (parsed.hostname or '').strip()
    if not host:
        return False, 'missing host'

    # Bare hostname matches against the metadata blocklist (case-insensitive)
    if host.lower() in _METADATA_HOSTS:
        return False, f'host {host!r} is a metadata endpoint'

    # If host is already an IP literal, check it directly. Strip IPv6 brackets.
    literal = host
    if literal.startswith('[') and literal.endswith(']'):
        literal = literal[1:-1]
    try:
        ip_literal = ipaddress.ip_address(literal)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        if str(ip_literal) in _METADATA_HOSTS:
            return False, f'IP {ip_literal} is metadata endpoint'
        if not allow_private and _is_private_or_special(ip_literal):
            return False, f'IP {ip_literal} is private / loopback / metadata'
        if not allow_loopback and _is_loopback(ip_literal):
            return False, f'IP {ip_literal} is loopback'
        return True, 'ok (ip literal)'

    if not require_resolution:
        return True, 'ok (resolution skipped)'

    try:
        resolved = list(_resolve_all(host))
    except socket.gaierror:
        return False, f'host {host!r} could not be resolved'

    if not resolved:
        return False, f'host {host!r} resolved to no addresses'

    for ip in resolved:
        if str(ip) in _METADATA_HOSTS:
            return False, f'host {host!r} resolves to metadata IP {ip}'
        if not allow_private and _is_private_or_special(ip):
            return False, f'host {host!r} resolves to private/loopback {ip}'
        if not allow_loopback and _is_loopback(ip):
            return False, f'host {host!r} resolves to loopback {ip}'

    return True, 'ok'


def sanitize_outbound_url(url: str, **kwargs) -> str:
    """Validate URL or raise :class:`SsrfError`. Returns the URL on success.

    Convenience wrapper for call sites that prefer raise-on-reject.
    """
    ok, reason = is_safe_outbound_url(url, **kwargs)
    if not ok:
        # Log without leaking the full URL (could be sensitive). Length only.
        logging.warning(
            "[ssrf-guard] rejected outbound URL: %s (len=%d)",
            reason, len(url) if isinstance(url, str) else -1,
        )
        raise SsrfError(reason)
    return url


def resolve_and_pin_url(
    url: str,
    *,
    allowed_schemes: Iterable[str] = ('https',),
    allow_private: bool = False,
    tls_verified: bool = True,
) -> str:
    """Close the validate-then-refetch DNS-rebinding window (GHSA-hmcf-9q7f-vx35 / senti-man):
    is_safe_outbound_url only *checks* the host, then the real request re-resolves it, so a
    low-TTL attacker domain can answer 'public' to the check and '127.0.0.1' to the connection.
    Pin the vetted IP into the URL so there is no second resolution to rebind. NS Aug 2026.

    Validates via :func:`is_safe_outbound_url` (raise on reject), then:

      * host already an IP literal  -> returned unchanged (nothing to rebind).
      * http, or https with tls_verified=False -> host rewritten to a freshly-validated safe IP
                                       literal, so the fetcher connects to the exact address we
                                       vetted. Plaintext http (no TLS) and https-without-cert-
                                       verification (the fetcher won't catch a rebind, e.g. PVE's
                                       download-url with verify-certificates=0, or a SIEM target
                                       with verify_tls off) both need the IP pin.
      * https with tls_verified=True -> returned unchanged. The fetcher validates the TLS cert
                                       against the hostname, so a rebind to an internal IP fails
                                       the handshake anyway; rewriting to an IP literal would
                                       instead break that legitimate cert check.

    Pass tls_verified=False whenever the eventual fetch does NOT verify the server certificate.

    Raises :class:`SsrfError` if the URL is unsafe, or resolves to no safe address.
    """
    ok, reason = is_safe_outbound_url(
        url, allowed_schemes=allowed_schemes, allow_private=allow_private, require_resolution=True
    )
    if not ok:
        logging.warning(
            "[ssrf-guard] rejected outbound URL: %s (len=%d)",
            reason, len(url) if isinstance(url, str) else -1,
        )
        raise SsrfError(reason)

    parsed = urlparse(url)
    host = (parsed.hostname or '').strip()

    # Already an IP literal (strip IPv6 brackets to test) → nothing to pin.
    _lit = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    try:
        ipaddress.ip_address(_lit)
        return url
    except ValueError:
        pass

    if (parsed.scheme or '').lower() == 'https' and tls_verified:
        return url  # verified https: TLS cert binding defeats a rebind; keep the hostname intact.

    # http, or https-without-verification: pick the first freshly-resolved safe address and pin it.
    try:
        resolved = list(_resolve_all(host))
    except socket.gaierror:
        raise SsrfError(f'host {host!r} could not be resolved')
    pinned = None
    for ip in resolved:
        if str(ip) in _METADATA_HOSTS:
            continue
        if not allow_private and _is_private_or_special(ip):
            continue
        pinned = ip
        break
    if pinned is None:
        raise SsrfError(f'host {host!r} resolved to no safe address')

    hostpart = f'[{pinned}]' if pinned.version == 6 else str(pinned)
    netloc = parsed.netloc
    userinfo = ''
    if '@' in netloc:
        userinfo = netloc.rsplit('@', 1)[0] + '@'
    portpart = f':{parsed.port}' if parsed.port else ''
    return urlunparse(parsed._replace(netloc=f'{userinfo}{hostpart}{portpart}'))
