# GHSA-ffhp-cpm8-4mpv (reported by tonghuaroot) — IPv6 transition-address bypass of the
# url_security.py SSRF guard.
#
# _is_private_or_special() trusted the stdlib flags of the *outer* IPv6 address. Several IPv6
# transition schemes (6to4 2002::/16, NAT64 64:ff9b::/96 + 64:ff9b:1::/48, Teredo 2001:0::/32,
# IPv4-mapped ::ffff:0:0/96) embed a full IPv4 address, and CPython's is_private/is_reserved
# flags cover those inconsistently across 3.12.x point releases — so on some builds a 6to4/NAT64
# address wrapping 169.254.169.254 or 127.0.0.1 classified as 'public' and passed the guard,
# giving an admin-configured outbound URL (webhook / OIDC / ACME / SIEM / …) a path to cloud
# metadata and internal services.
#
# Fix: decode the embedded IPv4 and classify THAT. A wrapped private/loopback/link-local/reserved
# target is blocked on every Python version; a wrapped genuinely-public address stays allowed.

import ipaddress

import pytest

from pegaprox.utils.url_security import (
    _embedded_ipv4,
    _is_private_or_special,
    is_safe_outbound_url,
)


# ---- (1) the embedded-IPv4 decoder handles each transition scheme ----

@pytest.mark.parametrize('v6, expected_v4', [
    ('2002:a9fe:a9fe::1',        '169.254.169.254'),   # 6to4
    ('2002:7f00:1::1',           '127.0.0.1'),          # 6to4
    ('2002:c0a8:101::abcd',      '192.168.1.1'),        # 6to4
    ('64:ff9b::7f00:1',          '127.0.0.1'),          # NAT64 well-known /96
    ('64:ff9b::a9fe:a9fe',       '169.254.169.254'),    # NAT64 well-known /96
    ('64:ff9b:1::a9fe:a9fe',     '169.254.169.254'),    # NAT64 local-use /48
    ('2001:0:0:0:0:0:f5ff:fffe', '10.0.0.1'),           # Teredo (last 4 bytes inverted)
    ('::ffff:127.0.0.1',         '127.0.0.1'),          # IPv4-mapped
    ('::7f00:1',                 '127.0.0.1'),          # IPv4-compatible ::/96 (self-review add)
    ('::a9fe:a9fe',              '169.254.169.254'),    # IPv4-compatible ::/96
])
def test_embedded_ipv4_is_decoded(v6, expected_v4):
    assert _embedded_ipv4(ipaddress.ip_address(v6)) == ipaddress.ip_address(expected_v4)


def test_embedded_ipv4_is_none_for_plain_addresses():
    # genuine global v6 (not a transition-embedding) must NOT be decoded. 2001:4860:: is NOT
    # Teredo (only 2001:0000::/32 is); fd00::/8 is ULA, not a transition prefix.
    for s in ('2606:4700:4700::1111', '2001:4860:4860::8888', 'fd00:ec2::254', '2003::1'):
        assert _embedded_ipv4(ipaddress.ip_address(s)) is None
    assert _embedded_ipv4(ipaddress.ip_address('8.8.8.8')) is None   # plain v4, not v6


# ---- (2) classification blocks embedded private/metadata, allows embedded public ----

@pytest.mark.parametrize('addr', [
    '2002:a9fe:a9fe::1',          # 6to4 → 169.254.169.254 (link-local / cloud metadata)
    '2002:7f00:1::1',             # 6to4 → 127.0.0.1
    '2002:c0a8:101::1',           # 6to4 → 192.168.1.1
    '2002:0a00:1::1',             # 6to4 → 10.0.0.1
    '64:ff9b::7f00:1',            # NAT64 → 127.0.0.1
    '64:ff9b::a9fe:a9fe',         # NAT64 → 169.254.169.254
    '64:ff9b:1::a9fe:a9fe',       # NAT64 local-use → 169.254.169.254
    '2001:0:0:0:0:0:f5ff:fffe',   # Teredo → 10.0.0.1
    '::ffff:127.0.0.1',           # v4-mapped → 127.0.0.1
    '::ffff:169.254.169.254',     # v4-mapped → metadata
    '::7f00:1',                   # IPv4-compatible ::/96 → 127.0.0.1
    '::a9fe:a9fe',                # IPv4-compatible ::/96 → 169.254.169.254
    '::',                         # unspecified (also in ::/96) → stays blocked
    '::1',                        # loopback (also in ::/96) → stays blocked
])
def test_transition_wrapping_private_is_blocked(addr):
    assert _is_private_or_special(ipaddress.ip_address(addr)) is True


@pytest.mark.parametrize('addr', [
    '8.8.8.8',                    # plain public v4
    '2606:4700:4700::1111',       # plain public v6
    '2002:0808:0808::1',          # 6to4 wrapping public 8.8.8.8 — real destination is public
    '64:ff9b::0808:0808',         # NAT64 wrapping public 8.8.8.8
    '::0808:0808',                # IPv4-compatible ::/96 wrapping public 8.8.8.8
])
def test_public_targets_stay_allowed(addr):
    assert _is_private_or_special(ipaddress.ip_address(addr)) is False


# ---- (3) end-to-end through the guard's public entry point (IP-literal host) ----

@pytest.mark.parametrize('literal', [
    '2002:a9fe:a9fe::1',          # 6to4 metadata
    '64:ff9b::7f00:1',            # NAT64 loopback
    '2001:0:0:0:0:0:f5ff:fffe',   # Teredo private
    '::ffff:169.254.169.254',     # v4-mapped metadata
])
def test_is_safe_outbound_url_rejects_transition_literals(literal):
    ok, reason = is_safe_outbound_url(f'https://[{literal}]/hook')
    assert ok is False, reason


def test_is_safe_outbound_url_allows_public_ipv6():
    ok, reason = is_safe_outbound_url('https://[2606:4700:4700::1111]/hook',
                                      require_resolution=False)
    assert ok is True, reason
