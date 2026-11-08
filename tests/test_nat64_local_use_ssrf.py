"""The local-use NAT64 block 64:ff9b:1::/48 under every layout RFC 6052 allows there.

_embedded_ipv4() read the last four bytes of such an address as the IPv4 it carries,
which is the /96 layout. RFC 8215 leaves the prefix length inside the block to the
operator, and under /48 64:ff9b:1:a9fe:a9:fe00:808:808 carries 169.254.169.254 while
the guard read 8.8.8.8 and let it through (storage.download hands such a URL to the
node). The block is site-internal whatever the layout, so the private check refuses all
of it; the loopback check for the private-LAN sites reads every layout.

NS Oct 2026
"""
import ipaddress

import pytest

from pegaprox.utils.url_security import _is_loopback, _is_private_or_special, is_safe_outbound_url

METADATA_AT_48 = '64:ff9b:1:a9fe:a9:fe00:808:808'     # /48 -> 169.254.169.254, /96 -> 8.8.8.8
LOOPBACK_AT_48 = '64:ff9b:1:7f00:0:100:808:808'       # /48 -> 127.0.0.1, /96 -> 8.8.8.8


@pytest.mark.parametrize('addr', [METADATA_AT_48, LOOPBACK_AT_48, '64:ff9b:1::808:808'])
def test_the_local_use_block_is_never_a_public_destination(addr):
    assert _is_private_or_special(ipaddress.ip_address(addr)) is True
    ok, reason = is_safe_outbound_url(f'https://[{addr}]/image.iso')
    assert ok is False, reason


def test_loopback_under_the_48_layout_is_refused_where_private_is_allowed():
    """The template and OCI catalog sites allow the LAN but not this host's loopback."""
    assert _is_loopback(ipaddress.ip_address(LOOPBACK_AT_48)) is True
    ok, reason = is_safe_outbound_url(f'http://[{LOOPBACK_AT_48}]/x', allowed_schemes=('http',),
                                      allow_private=True, allow_loopback=False)
    assert ok is False, reason


@pytest.mark.parametrize('addr', ['64:ff9b:1::c0a8:101', '64:ff9b:1::a00:5'])
def test_a_lan_host_behind_a_local_translator_stays_reachable_where_private_is_allowed(addr):
    """The mirror: the zero runs of a /96 address read as 0.0.0.0 under the other layouts,
    which must not make an ordinary LAN target look like loopback."""
    ok, reason = is_safe_outbound_url(f'http://[{addr}]/x', allowed_schemes=('http',),
                                      allow_private=True, allow_loopback=False)
    assert ok is True, reason


def test_the_well_known_prefix_still_passes_a_public_address():
    ok, reason = is_safe_outbound_url('https://[64:ff9b::808:808]/image.iso')
    assert ok is True, reason
