# SSRF-guard invariants — pegaprox/utils/url_security.
#
# NS Jul 2026 (Phase 1) — every outbound fetch that takes an admin/user URL (OIDC
# discovery, ACME directory, webhook push, SIEM forward, VMware base URL, ISO/URL
# download) is gated by is_safe_outbound_url / sanitize_outbound_url. The 2026-07-12
# pentest found the OLD hand-rolled guard failed OPEN on an unresolvable host; the
# critical invariant below (`require_resolution=True` => unresolvable is BLOCKED)
# pins that fix. DNS is monkeypatched (_resolve_all) so the suite is deterministic
# and needs NO network — CI must never depend on real name resolution.

import socket

import pytest

from pegaprox.utils import url_security
from pegaprox.utils.url_security import (
    is_safe_outbound_url,
    sanitize_outbound_url,
    resolve_and_pin_url,
    SsrfError,
)


def _ok(url, **kw):
    ok, reason = is_safe_outbound_url(url, **kw)
    return ok


# ---------------------------------------------------------------------------
# IP-literal blocklist — no DNS needed, pure ipaddress classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('url', [
    'http://127.0.0.1/',            # loopback
    'http://127.0.0.1:8006/api',
    'http://10.0.0.5/',             # RFC1918
    'http://192.168.1.1/',
    'http://172.16.0.1/',
    'http://169.254.169.254/latest/meta-data/',   # cloud metadata
    'http://[::1]/',                # IPv6 loopback
    'http://0.0.0.0/',              # unspecified
    'http://[fd00::1]/',            # IPv6 ULA (private)
])
def test_blocks_private_and_metadata_ip_literals(url):
    # allow http here so the scheme check doesn't mask the IP check we're testing
    assert _ok(url, allowed_schemes=('http', 'https')) is False


def test_blocks_metadata_hostnames_without_dns():
    # in the metadata blocklist → rejected by name, before any resolution
    assert _ok('http://metadata.google.internal/', allowed_schemes=('http', 'https')) is False
    assert _ok('http://metadata/', allowed_schemes=('http', 'https')) is False


# ---------------------------------------------------------------------------
# scheme allowlist + control-char rejection — no DNS
# ---------------------------------------------------------------------------

def test_default_scheme_is_https_only():
    # http is NOT allowed unless the caller explicitly opts in via allowed_schemes.
    # (The public-host + http opt-in path is covered by test_public_hostname_* with
    # https; here we only assert the default rejects http.)
    ok, reason = is_safe_outbound_url('http://example.com/')
    assert ok is False
    assert 'scheme' in reason


@pytest.mark.parametrize('url', [
    'ftp://example.com/x',
    'file:///etc/passwd',
    'gopher://example.com/',
    'data:text/plain,hi',
    'jar:http://x/!/',
])
def test_blocks_dangerous_schemes(url):
    assert _ok(url) is False


@pytest.mark.parametrize('url', [
    'https://example.com/\r\nHost: evil',
    'https://exa\nmple.com/',
    'https://exa\x00mple.com/',
])
def test_blocks_control_characters(url):
    assert _ok(url) is False


def test_blocks_empty_and_hostless():
    assert _ok('') is False
    assert _ok('https:///path') is False   # no host


# ---------------------------------------------------------------------------
# DNS-resolution path — monkeypatched so it's deterministic + offline
# ---------------------------------------------------------------------------

def _fake_resolver(mapping):
    """Return a _resolve_all replacement that yields ipaddress objects for known
    hosts and raises gaierror (unresolvable) for anything else."""
    import ipaddress

    def _resolve(host):
        if host in mapping:
            return [ipaddress.ip_address(ip) for ip in mapping[host]]
        raise socket.gaierror(f'name not known: {host}')
    return _resolve


def test_hostname_resolving_to_private_is_blocked(monkeypatch):
    # DNS-rebinding shape: a public-looking name that points at an internal IP.
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'internal.attacker.example': ['10.0.0.5']}))
    assert _ok('https://internal.attacker.example/') is False


def test_hostname_resolving_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'rebind.evil.example': ['127.0.0.1']}))
    assert _ok('https://rebind.evil.example/') is False


def test_hostname_resolving_to_metadata_is_blocked(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'sneaky.example': ['169.254.169.254']}))
    assert _ok('https://sneaky.example/') is False


def test_public_hostname_is_allowed(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'good.example': ['93.184.216.34']}))
    assert _ok('https://good.example/path') is True


def test_unresolvable_host_fails_CLOSED(monkeypatch):
    # THE regression guard for the 2026-07-12 pentest finding: the old guard let an
    # unresolvable host through (failed OPEN). With require_resolution=True (default)
    # an unresolvable host MUST be rejected.
    monkeypatch.setattr(url_security, '_resolve_all', _fake_resolver({}))
    assert _ok('https://this-host-does-not-resolve.invalid/') is False


# ---------------------------------------------------------------------------
# opt-in relaxations behave as documented
# ---------------------------------------------------------------------------

def test_allow_private_opt_in_permits_internal_ip():
    # cluster API on the corporate LAN — call sites pass allow_private=True
    assert _ok('https://10.0.0.5:8006/', allow_private=True) is True


def test_require_resolution_false_skips_dns_but_still_blocks_bad_literals(monkeypatch):
    # never call the resolver in this mode
    def _boom(host):
        raise AssertionError('resolver must not be called when require_resolution=False')
    monkeypatch.setattr(url_security, '_resolve_all', _boom)
    # a hostname is accepted without DNS...
    assert _ok('https://anything.example/', require_resolution=False) is True
    # ...but a private IP LITERAL is still blocked (literal check runs first)
    assert _ok('https://127.0.0.1/', require_resolution=False,
               allowed_schemes=('http', 'https')) is False


# ---------------------------------------------------------------------------
# sanitize_outbound_url wrapper — raise vs return
# ---------------------------------------------------------------------------

def test_sanitize_raises_on_reject():
    with pytest.raises(SsrfError):
        sanitize_outbound_url('http://169.254.169.254/', allowed_schemes=('http', 'https'))


def test_sanitize_returns_url_on_ok(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'good.example': ['93.184.216.34']}))
    assert sanitize_outbound_url('https://good.example/') == 'https://good.example/'


# ---------------------------------------------------------------------------
# resolve_and_pin_url — closes the DNS-rebinding TOCTOU (GHSA-hmcf-9q7f-vx35, senti-man).
# The guard only *checks* the host; the real fetch re-resolves and can be rebound. Pinning
# rewrites the host to the vetted IP so there is no second lookup for an attacker to rebind.
# ---------------------------------------------------------------------------

def test_pin_http_rewrites_host_to_ip_literal(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'rebind.example': ['93.184.216.34']}))
    pinned = resolve_and_pin_url('http://rebind.example/path?q=1', allowed_schemes=('https', 'http'))
    # host is now an IP literal → the fetcher connects to the vetted address, never re-resolving
    assert pinned == 'http://93.184.216.34/path?q=1'


def test_pin_https_unverified_is_pinned(monkeypatch):
    # verify-off fetch (e.g. PVE download-url with verify-certificates=0, SIEM verify_tls=False):
    # TLS won't catch the rebind, so https must be pinned too.
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'good.example': ['93.184.216.34']}))
    pinned = resolve_and_pin_url('https://good.example/x', allowed_schemes=('https', 'http'),
                                 tls_verified=False)
    assert pinned == 'https://93.184.216.34/x'


def test_pin_https_verified_keeps_hostname_for_cert_check(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'good.example': ['93.184.216.34']}))
    # verified https: a rebind to an internal IP fails the cert check, so keep the hostname
    # (pinning to an IP would break the legitimate cert)
    assert resolve_and_pin_url('https://good.example/x', tls_verified=True) == 'https://good.example/x'


def test_pin_preserves_port_and_userinfo(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'h.example': ['8.8.8.8']}))
    pinned = resolve_and_pin_url('http://user:pw@h.example:8443/p', allowed_schemes=('https', 'http'))
    assert pinned == 'http://user:pw@8.8.8.8:8443/p'


def test_pin_ip_literal_unchanged(monkeypatch):
    # already an IP literal → nothing to rebind, and the resolver must not even be consulted
    def _boom(host):
        raise AssertionError('resolver must not run for an IP literal')
    monkeypatch.setattr(url_security, '_resolve_all', _boom)
    assert resolve_and_pin_url('http://93.184.216.34/x',
                               allowed_schemes=('https', 'http')) == 'http://93.184.216.34/x'


def test_pin_rejects_rebind_to_metadata(monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'rebind.evil.example': ['169.254.169.254']}))
    with pytest.raises(SsrfError):
        resolve_and_pin_url('http://rebind.evil.example/latest/meta-data/', allowed_schemes=('https', 'http'))


def test_pin_rejects_rebind_to_loopback(monkeypatch):
    # the pin's own resolution is re-checked — a host that resolves to loopback is rejected, never
    # pinned to it (fail-closed)
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'evil.example': ['127.0.0.1']}))
    with pytest.raises(SsrfError):
        resolve_and_pin_url('http://evil.example/', allowed_schemes=('https', 'http'))
