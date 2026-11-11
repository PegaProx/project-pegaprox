"""oidc_skip_ssl_verify reaches every request to the IdP, not only discovery.

The switch exists for a self-hosted IdP with a self-signed certificate, and only the
discovery GET honoured it. Discovery got through, then the token request failed on the
certificate and every sign-in ended in "Authentication failed". The userinfo request and
the JWKS fetch failed the same way, and so did the JWKS step of the settings test.

With the switch on, those requests now go the way discovery does: unverified, and to the
address the SSRF guard vetted, not to a second resolution of the name. With the switch off
every request is made exactly as before, verified. Entra's endpoints are Microsoft's and
discovery never read the switch for them, so they stay out of it.

The IdP here is a real TLS server on loopback with a self-signed certificate no trust
store knows, the way such an IdP looks to PegaProx.

MK Nov 2026
"""
import ipaddress
import json
import logging
import time
import types
import urllib.parse

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from gevent.pywsgi import WSGIServer

import pegaprox.utils.url_security as url_security
from pegaprox.utils import oidc
from tests.conftest import _seed_user
from tests.test_pyjwt_oidc_verification_972 import FALLBACK, _jwk, _tls_files, _token

NAME = 'idp.test'          # resolved by the guard only, never by the request itself


class _IdP:
    """Discovery, token, userinfo, JWKS and authorize on one self-signed TLS listener."""

    def __init__(self, tls, signer, host='127.0.0.1'):
        import ssl
        self.signer, self.hits, self.nonce = signer, [], 'the-nonce'
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        self.server = WSGIServer(('127.0.0.1', 0), self._app, log=None, error_log=None,
                                 ssl_context=ctx)
        self.server.start()
        self.port = self.server.server_port
        self.url = f'https://{host}:{self.port}'

    def id_token(self):
        now = int(time.time())
        return _token(self.signer, {'iss': self.url, 'sub': 'alice-sub', 'aud': 'pegaprox',
                                    'iat': now, 'exp': now + 300, 'nonce': self.nonce,
                                    'preferred_username': 'alice'})

    def _app(self, environ, start_response):
        path, method = environ['PATH_INFO'], environ['REQUEST_METHOD']
        body = environ['wsgi.input'].read().decode() if method == 'POST' else ''
        self.hits.append((method, path, environ.get('HTTP_HOST', ''), body))
        answers = {
            '/.well-known/openid-configuration': {
                'issuer': self.url, 'authorization_endpoint': self.url + '/authorize',
                'token_endpoint': self.url + '/token', 'userinfo_endpoint': self.url + '/userinfo',
                'jwks_uri': self.url + '/jwks'},
            '/token': {'access_token': 'the-access-token', 'token_type': 'Bearer',
                       'id_token': self.id_token()},
            '/userinfo': {'sub': 'alice-sub', 'preferred_username': 'alice'},
            '/jwks': {'keys': [_jwk(self.signer.public_key(), 'k1')]},
            '/authorize': {},
        }
        if path not in answers:
            start_response('404 Not Found', [('Content-Length', '0')])
            return [b'']
        out = json.dumps(answers[path]).encode()
        start_response('200 OK', [('Content-Type', 'application/json'), ('Content-Length', str(len(out)))])
        return [out]

    def paths(self):
        return [(m, p) for m, p, _h, _b in self.hits]


@pytest.fixture
def signer():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(oidc, '_jwks_clients', {})
    monkeypatch.setattr(oidc, '_oidc_discovery_cache', {})
    for var in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def idp(tmp_path, signer, fresh):
    ep = _IdP(_tls_files(tmp_path), signer)
    yield ep
    ep.server.stop()


@pytest.fixture
def named_idp(tmp_path, signer, fresh, monkeypatch):
    """The same IdP under a name that only the guard can resolve."""
    real = url_security._resolve_all
    monkeypatch.setattr(url_security, '_resolve_all', lambda host: (
        [ipaddress.ip_address('127.0.0.1')] if host == NAME else real(host)))
    ep = _IdP(_tls_files(tmp_path), signer, host=NAME)
    yield ep
    ep.server.stop()


def _cfg(ep, **over):
    cfg = {'provider': 'generic', 'authority': ep.url, 'client_id': 'pegaprox',
           'client_secret': 'the-client-secret', 'redirect_uri': 'https://pegaprox.example/oidc/callback',
           'scopes': 'openid profile', 'oidc_skip_ssl_verify': True, 'oidc_allow_private_ip': True}
    cfg.update(over)
    return cfg


# --- the switch on: a self-signed IdP answers ------------------------------------------

def test_the_token_request_reaches_a_self_signed_idp(idp):
    tokens = oidc.oidc_exchange_code(_cfg(idp), 'the-code', code_verifier='the-verifier')
    assert tokens.get('access_token') == 'the-access-token', tokens
    posted = [b for m, p, _h, b in idp.hits if (m, p) == ('POST', '/token')]
    assert len(posted) == 1
    form = urllib.parse.parse_qs(posted[0])
    assert form['client_secret'] == ['the-client-secret'] and form['code'] == ['the-code']


def test_the_userinfo_request_reaches_a_self_signed_idp(idp):
    assert oidc.oidc_get_user_info(_cfg(idp), 'the-access-token') == {
        'sub': 'alice-sub', 'preferred_username': 'alice'}


def test_the_id_token_of_a_self_signed_idp_is_verified_by_its_signature(idp, caplog):
    with caplog.at_level(logging.WARNING):
        claims = oidc.oidc_decode_id_token(idp.id_token(), expected_nonce='the-nonce', config=_cfg(idp))
    assert oidc.oidc_id_token_verified(claims), caplog.text
    assert FALLBACK not in caplog.text
    assert ('GET', '/jwks') in idp.paths()


def test_every_request_goes_to_the_address_the_guard_vetted(named_idp, caplog):
    """The discovery document names the IdP by name. Each request is pinned to the address
    the guard resolved: there is no certificate check left to catch a rebind, and the token
    request carries the client secret. Nothing here can resolve the name but the guard."""
    cfg = _cfg(named_idp)
    assert oidc.get_oidc_endpoints(cfg)['token'] == f'https://{NAME}:{named_idp.port}/token'
    assert oidc.oidc_exchange_code(cfg, 'the-code').get('access_token') == 'the-access-token'
    assert oidc.oidc_get_user_info(cfg, 'the-access-token').get('sub') == 'alice-sub'
    with caplog.at_level(logging.WARNING):
        claims = oidc.oidc_decode_id_token(named_idp.id_token(), expected_nonce='the-nonce', config=cfg)
    assert oidc.oidc_id_token_verified(claims), caplog.text

    assert [p for _m, p, _h, _b in named_idp.hits] == [
        '/.well-known/openid-configuration', '/token', '/userinfo', '/jwks']
    pinned = f'127.0.0.1:{named_idp.port}'
    assert {h for _m, _p, h, _b in named_idp.hits} == {pinned}, named_idp.hits


def test_a_sign_in_against_a_self_signed_idp_completes(api, db, idp):
    admin = api.as_user(_seed_user(db, 'root', role='admin'))
    r = admin.post('/api/settings/server', json={
        'oidc_enabled': True, 'oidc_provider': 'generic', 'oidc_authority': idp.url,
        'oidc_client_id': 'pegaprox', 'oidc_client_secret': 'the-client-secret',
        'oidc_redirect_uri': 'https://pegaprox.example/oidc/callback',
        'oidc_skip_ssl_verify': True, 'oidc_allow_private_ip': True})
    assert r.status_code == 200, r.get_data(as_text=True)

    import pegaprox.api.auth as auth_api
    for k in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(k, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    r = browser.post('/api/auth/oidc/callback', json={'code': 'the-code', 'state': 'the-state'},
                     headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                     base_url='http://localhost')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'alice'
    assert db.get_user('alice')['oidc_sub'] == 'alice-sub'
    assert {('POST', '/token'), ('GET', '/userinfo'), ('GET', '/jwks')} <= set(idp.paths())


def test_the_settings_test_reads_the_keys_of_a_self_signed_idp(api, db, idp, monkeypatch):
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'get_oidc_settings', lambda: _cfg(idp, enabled=True))
    admin = api.as_user(_seed_user(db, 'root', role='admin'))
    r = admin.post('/api/settings/oidc/test', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    step = next(s for s in r.get_json()['results'] if s['step'] == 'JWKS Endpoint')
    assert step == {'step': 'JWKS Endpoint', 'status': 'ok', 'detail': 'Found 1 signing keys'}, step


def test_turning_the_switch_off_again_does_not_reuse_the_unverified_key_client(idp, caplog):
    cfg = _cfg(idp)
    on = oidc.oidc_decode_id_token(idp.id_token(), expected_nonce='the-nonce', config=cfg)
    assert oidc.oidc_id_token_verified(on)
    with caplog.at_level(logging.WARNING):
        off = oidc.oidc_decode_id_token(idp.id_token(), expected_nonce='the-nonce',
                                        config=dict(cfg, oidc_skip_ssl_verify=False))
    assert not oidc.oidc_id_token_verified(off), 'a verified fetch took the unverified client'
    assert 'CERTIFICATE_VERIFY_FAILED' in caplog.text, caplog.text


# --- the switch off: every request exactly as before ------------------------------------

def test_with_the_switch_off_a_self_signed_idp_still_fails_its_certificate(idp, caplog):
    cfg = _cfg(idp, oidc_skip_ssl_verify=False)
    tokens = oidc.oidc_exchange_code(cfg, 'the-code')
    assert 'CERTIFICATE_VERIFY_FAILED' in tokens.get('error', ''), tokens
    with caplog.at_level(logging.WARNING):
        assert oidc.oidc_get_user_info(cfg, 'the-access-token') == {}
        claims = oidc.oidc_decode_id_token(idp.id_token(), expected_nonce='the-nonce', config=cfg)
    assert not oidc.oidc_id_token_verified(claims)
    assert FALLBACK in caplog.text
    assert not [h for h in idp.hits if h[1] in ('/token', '/userinfo', '/jwks')]


class _Answer:
    status_code = 200
    text = ''

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


def _spy(monkeypatch, endpoints):
    calls = []
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: dict(endpoints))
    monkeypatch.setattr(oidc, 'sanitize_outbound_url', lambda url, **kw: url)
    monkeypatch.setattr(oidc, 'resolve_and_pin_url', lambda *a, **kw: calls.append(('pin', a, kw)))

    def post(url, **kw):
        calls.append(('post', url, kw))
        return _Answer({'access_token': 'at'})

    def get(url, **kw):
        calls.append(('get', url, kw))
        return _Answer({'sub': 'alice-sub', 'id': 'alice-sub'})

    monkeypatch.setattr(oidc, 'requests', types.SimpleNamespace(post=post, get=get))
    return calls


GENERIC = {'token': 'https://idp.example/token', 'userinfo': 'https://idp.example/userinfo',
           'jwks': 'https://idp.example/jwks', 'graph_me': '', 'graph_groups': ''}
ENTRA = {'token': 'https://login.microsoftonline.com/t/oauth2/v2.0/token',
         'userinfo': 'https://graph.microsoft.com/oidc/userinfo',
         'jwks': 'https://login.microsoftonline.com/t/discovery/v2.0/keys',
         'graph_me': 'https://graph.microsoft.com/v1.0/me',
         'graph_groups': 'https://graph.microsoft.com/v1.0/me/memberOf'}


@pytest.mark.parametrize('provider,endpoints,switch', [
    ('generic', GENERIC, False), ('okta', GENERIC, False), ('entra', ENTRA, False), ('entra', ENTRA, True)])
def test_the_requests_are_made_as_before_where_the_switch_does_not_apply(monkeypatch, provider,
                                                                          endpoints, switch):
    calls = _spy(monkeypatch, endpoints)
    cfg = {'provider': provider, 'tenant_id': 't', 'client_id': 'pegaprox', 'client_secret': 's',
           'redirect_uri': 'https://pp/cb', 'scopes': 'openid', 'oidc_skip_ssl_verify': switch}
    assert oidc.oidc_exchange_code(cfg, 'the-code') == {'access_token': 'at'}
    oidc.oidc_get_user_info(cfg, 'at')
    if provider == 'entra':
        oidc.oidc_get_user_groups_ex(cfg, 'at')
    assert not [c for c in calls if c[0] == 'pin'], calls
    assert calls[0] == ('post', endpoints['token'], {'data': calls[0][2]['data'], 'timeout': 15})
    for kind, url, kw in calls[1:]:
        assert kind == 'get' and url in endpoints.values(), (kind, url)
        assert set(kw) == {'headers', 'timeout'}, kw


@pytest.mark.parametrize('provider,jwks,switch', [
    ('generic', GENERIC['jwks'], False), ('entra', ENTRA['jwks'], True)])
def test_the_key_client_is_built_as_before_where_the_switch_does_not_apply(monkeypatch, provider,
                                                                            jwks, switch):
    built = []

    class _Client:
        def __init__(self, *a, **kw):
            built.append((a, kw))

        def get_signing_key_from_jwt(self, token):
            raise RuntimeError('no keys here')

    monkeypatch.setattr(oidc, '_jwks_clients', {})
    monkeypatch.setattr(oidc, 'PyJWKClient', _Client)
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: {'jwks': jwks})
    monkeypatch.setattr(url_security, '_resolve_all', lambda host: [ipaddress.ip_address('203.0.113.7')])
    cfg = {'provider': provider, 'tenant_id': 't', 'client_id': 'pegaprox', 'oidc_skip_ssl_verify': switch}
    oidc.oidc_decode_id_token('a.b.c', config=cfg)
    assert built == [((jwks,), {'cache_keys': True, 'lifespan': 3600})], built
    assert list(oidc._jwks_clients) == [jwks]
