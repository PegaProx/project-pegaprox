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
from urllib.parse import urlparse


class SsrfError(ValueError):
    """Raised when an outbound URL is rejected by the SSRF guard."""


# Cloud-metadata / well-known internal-only addresses we never want to hit.
_METADATA_HOSTS = frozenset({
    '169.254.169.254',         # AWS / GCP / Azure / DigitalOcean
    'metadata.google.internal',
    'metadata',                 # short alias used in some setups
    'fd00:ec2::254',            # AWS IPv6 metadata
})


def _is_private_or_special(ip: ipaddress._BaseAddress) -> bool:
    """True if the IP falls in a range we should never reach over the public path."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


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
    trusted_hosts: Iterable[str] = (),
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
        require_resolution: When True, resolve DNS and reject if any
            returned IP is private / metadata / loopback. When False
            we only reject IP-literal hosts that are obviously bad
            (faster, but vulnerable to DNS rebinding).
    """
    trusted_hosts = {
        h.strip().lower().strip("[]")
        for h in trusted_hosts
        if h
    }

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
        if (
            not allow_private
            and _is_private_or_special(ip_literal)
            and str(ip_literal) not in trusted_hosts
        ):
            return False, f'IP {ip_literal} is private / loopback / metadata'
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
        if (
            not allow_private
            and _is_private_or_special(ip)
            and host.lower() not in trusted_hosts
            and str(ip) not in trusted_hosts
        ):
            return False, f'host {host!r} resolves to private/loopback {ip}'

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
