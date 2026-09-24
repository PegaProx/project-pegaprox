"""The OIDC discovery fetch, after taking the substance of a bot PR but not its shape.

The finding was right: the guard only CHECKED the discovery host and requests.get then
resolved it a second time, which is the rebinding window from the shared-guard advisory.
Every other outbound path had already moved onto resolve_and_pin_url; this one had not.

What the PR also did, and what is deliberately NOT here: it passed
allowed_schemes=('https','http'), which would let discovery run over plain http. The
current default is https-only, and whoever answers a plaintext discovery request picks the
authorization and token endpoints - so that half is a step backwards wearing a security
fix's clothes.

MK
"""
import pytest

from pegaprox.utils.url_security import is_safe_outbound_url


def test_plain_http_discovery_is_still_refused():
    """The half of the bot PR that was not taken. If this ever goes green, somebody has
    widened the scheme list and handed an on-path attacker the token endpoint."""
    ok, reason = is_safe_outbound_url('http://example.com/.well-known/openid-configuration')
    assert not ok
    assert 'scheme' in reason.lower()


def test_https_discovery_is_allowed():
    ok, _ = is_safe_outbound_url('https://example.com/.well-known/openid-configuration')
    assert ok


def test_the_discovery_fetch_uses_the_pinning_helper():
    """Source-level, because driving get_oidc_endpoints far enough to reach the request
    needs a live IdP. The point is that the URL handed to requests.get is the one the
    guard vetted, not a second resolution of the same name."""
    import inspect
    import pegaprox.utils.oidc as O

    body = inspect.getsource(O.get_oidc_endpoints)
    stripped = '\n'.join(l for l in body.split('\n') if not l.strip().startswith('#'))

    assert 'resolve_and_pin_url(' in stripped, 'discovery still only checks, never pins'
    assert 'discovery_url = resolve_and_pin_url(' in stripped, \
        'the pinned URL is discarded instead of being the one we fetch'
    assert 'allowed_schemes' not in stripped, \
        'discovery must keep the https-only default, not name its own scheme list'


def test_the_pinning_helper_leaves_verified_https_alone():
    """Behavioural guard on the helper's contract: rewriting a verified-https host to an IP
    literal would break the certificate check it relies on."""
    from pegaprox.utils.url_security import resolve_and_pin_url

    url = 'https://example.com/.well-known/openid-configuration'
    assert resolve_and_pin_url(url, tls_verified=True) == url


def test_an_unverified_target_gets_pinned():
    """The case the change actually exists for: oidc_skip_ssl_verify installs have no cert
    check to catch a rebind, so the address has to be nailed down."""
    from pegaprox.utils.url_security import resolve_and_pin_url
    import ipaddress
    from urllib.parse import urlparse

    out = resolve_and_pin_url('https://example.com/x', tls_verified=False)
    host = urlparse(out).hostname
    ipaddress.ip_address(host)   # raises if it is still a name


# --- the half of #845 that could be taken without breaking anyone -------------------

def test_a_name_only_group_match_is_called_out(caplog):
    """The bot PR wanted to drop display-name matching entirely, which is right about the
    risk - a display name is not unique and in most Entra tenants ordinary users may create
    groups - and wrong about the blast radius, since the field is called `group_dn` and
    plenty of installs configured it that way on purpose. Removing it is a release decision.
    Saying so on every match is not, so that part is here."""
    import logging
    import pegaprox.utils.oidc as O

    cfg = {'group_mappings': [{'group_dn': 'Infra Admins', 'role': 'admin'}]}
    groups = [{'id': '0f8fad5b-d9cb-469f-a165-70867728950e', 'name': 'Infra Admins'}]

    with caplog.at_level(logging.WARNING, logger='root'):
        O.oidc_map_groups_to_role(cfg, groups)

    warned = [r.getMessage() for r in caplog.records if 'display NAME' in r.getMessage()]
    assert warned, 'a name-only match granted a role without saying so'
    assert 'admin' in warned[0]


def test_an_id_match_says_nothing(caplog):
    """The counter-case: a mapping pointed at the object id is the shape we want, and must
    not be nagged about."""
    import logging
    import pegaprox.utils.oidc as O

    gid = '0f8fad5b-d9cb-469f-a165-70867728950e'
    cfg = {'group_mappings': [{'group_id': gid, 'role': 'admin'}]}
    groups = [{'id': gid, 'name': 'Infra Admins'}]

    with caplog.at_level(logging.WARNING, logger='root'):
        O.oidc_map_groups_to_role(cfg, groups)

    assert not [r for r in caplog.records if 'display NAME' in r.getMessage()]
