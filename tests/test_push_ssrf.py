# Regression: the web-push endpoint host allow/deny must handle IPv6 literals (Aikido #469089273).
# The old code split the host on ':' which mangled every IPv6 literal ('::1' -> '') and let it
# through, so [::1] / [::ffff:169.254.169.254] became blind-SSRF targets.

from pegaprox.api.push import _is_internal_or_metadata_host as blocked


def test_ipv6_loopback_and_unspecified_blocked():
    assert blocked('::1') is True
    assert blocked('::') is True


def test_ipv6_ula_and_linklocal_blocked():
    assert blocked('fd00::1') is True          # unique-local
    assert blocked('fe80::1') is True          # link-local


def test_ipv4_mapped_metadata_blocked():
    # ::ffff:169.254.169.254 must be unwrapped and blocked like the bare metadata IP
    assert blocked('::ffff:169.254.169.254') is True
    assert blocked('169.254.169.254') is True


def test_private_ipv4_blocked():
    assert blocked('10.0.0.1') is True
    assert blocked('127.0.0.1') is True


def test_public_ipv6_allowed():
    # a real public IPv6 (Google DNS) must NOT be blocked
    assert blocked('2001:4860:4860::8888') is False


def test_public_ipv4_allowed():
    assert blocked('93.184.216.34') is False   # example.com's address literal
