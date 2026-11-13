"""The audit line of an OIDC sign-in says when its ID token signature went unchecked.

oidc_decode_id_token takes a token without its signature in two cases (OIDC Core 3.1.3.7):
the admin's oidc_skip_jwt_verification switch, and a key set (JWKS) that cannot be loaded
while TLS to the token endpoint is verified. Both stay as they are; the sign-in's
auth.oidc.login entry now names the case, and a sign-in without an ID token at all says
that. A checked sign-in writes the line it always wrote.

MK Nov 2026
"""
from pegaprox.utils import oidc
from tests.test_oidc_fallback_name_1141 import (  # noqa: F401 - idp and signer are fixtures
    GRAPH_ME, ISSUER, SUB, USERINFO, _id_token, _sign_in, idp, signer,
)


def _generic(api, monkeypatch, token, userinfo, **config):
    return _sign_in(api, monkeypatch, token, userinfo=userinfo, provider='generic', **config)


def _audit_lines(db):
    return [tuple(r) for r in db.conn.execute(
        "SELECT user, details FROM audit_log WHERE action = 'auth.oidc.login' ORDER BY id")]


def test_a_checked_sign_in_writes_its_audit_line_as_before(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer))
    assert r.status_code == 200, r.get_data(as_text=True)
    [(user, details)] = _audit_lines(db)
    assert user == 'wanda@corp.example'
    assert details.startswith('OIDC login via entra from ') and ' - ' not in details


def test_the_admin_switch_is_named_in_the_audit_line(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer), oidc_skip_jwt_verification=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    [(_, details)] = _audit_lines(db)
    assert details.startswith('OIDC login via entra from ')
    assert details.endswith(' - ID token signature not checked: oidc_skip_jwt_verification is on')


def test_a_key_set_that_cannot_be_loaded_is_named_in_the_audit_line(api, db, idp, signer, monkeypatch):
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: {
        'jwks': 'https://127.0.0.1:1/jwks', 'graph_me': GRAPH_ME, 'userinfo': USERINFO, 'issuer': ISSUER})
    r = _sign_in(api, monkeypatch, _id_token(signer))
    assert r.status_code == 200, r.get_data(as_text=True)
    [(_, details)] = _audit_lines(db)
    assert ("ID token signature not checked: the identity provider's key set (JWKS) could not be "
            "loaded, the token was taken on the verified TLS connection to the token endpoint") in details


def test_a_sign_in_without_an_id_token_is_named_in_the_audit_line(api, db, idp, monkeypatch):
    r = _generic(api, monkeypatch, '', {'sub': SUB, 'preferred_username': 'kc.user'})
    assert r.status_code == 200, r.get_data(as_text=True)
    [(user, details)] = _audit_lines(db)
    assert user == 'kc.user'
    assert details.endswith(' - no ID token: the token endpoint returned none')
