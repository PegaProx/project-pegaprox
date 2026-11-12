"""The OIDC sign-in requests do not follow a redirect.

Discovery and the JWKS step of the settings test refused a redirect already: its target is
a URL the outbound guard never saw. The token POST, the userinfo GET and the Graph calls
still followed one. A 307 from the token endpoint posted the code and the client secret
again to wherever its Location pointed, and a 302 on userinfo turned into a GET to any
address, past the guard and, with oidc_skip_ssl_verify on, past the pinned address and
unverified.

Each of them now answers a 3xx as an error that names the status, with the switch on or
off: the token exchange and the userinfo read fail and the sign-in with them, a Graph call
counts as failed. No second request is made. A 200 answer is handled as before.

The IdP is a TLS server on loopback with a self-signed certificate; with the switch off its
certificate is trusted through REQUESTS_CA_BUNDLE, so the request is verified as usual. The
Location points at a second server that records whatever reaches it.

MK Nov 2026
"""
import json
import logging
import time
import urllib.parse

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from gevent.pywsgi import WSGIServer

from pegaprox.utils import oidc
from tests.conftest import _seed_user
from tests.test_pyjwt_oidc_verification_972 import _jwk, _tls_files, _token


class _Elsewhere:
    """Where the redirects point: notes every request that reaches it, and answers like an
    IdP would, so a followed redirect would carry on."""

    def __init__(self):
        self.hits = []
        self.server = WSGIServer(('127.0.0.1', 0), self._app, log=None, error_log=None)
        self.server.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}/collect'

    def _app(self, environ, start_response):
        body = environ['wsgi.input'].read().decode()
        self.hits.append((environ['REQUEST_METHOD'], environ['PATH_INFO'], body))
        out = json.dumps({'access_token': 'from-elsewhere', 'sub': 'someone-else',
                          'preferred_username': 'someone-else', 'value': []}).encode()
        start_response('200 OK', [('Content-Type', 'application/json'), ('Content-Length', str(len(out)))])
        return [out]


class _IdP:
    """Discovery, token, userinfo, JWKS and two Graph paths on one TLS listener. A path in
    `redirects` answers that status with the trap as its Location."""

    def __init__(self, tls, signer, trap):
        import ssl
        self.signer, self.trap, self.hits, self.redirects = signer, trap, [], {}
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        self.server = WSGIServer(('127.0.0.1', 0), self._app, log=None, error_log=None, ssl_context=ctx)
        self.server.start()
        self.url = f'https://127.0.0.1:{self.server.server_port}'

    def id_token(self):
        now = int(time.time())
        return _token(self.signer, {'iss': self.url, 'sub': 'alice-sub', 'aud': 'pegaprox',
                                    'iat': now, 'exp': now + 300, 'nonce': 'the-nonce',
                                    'preferred_username': 'alice'})

    def _app(self, environ, start_response):
        path, method = environ['PATH_INFO'], environ['REQUEST_METHOD']
        body = environ['wsgi.input'].read().decode() if method == 'POST' else ''
        self.hits.append((method, path, body))
        if path in self.redirects:
            status = self.redirects[path]
            reason = {301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
                      307: 'Temporary Redirect', 308: 'Permanent Redirect'}[status]
            start_response(f'{status} {reason}', [('Location', self.trap.url), ('Content-Length', '0')])
            return [b'']
        answers = {
            '/.well-known/openid-configuration': {
                'issuer': self.url, 'authorization_endpoint': self.url + '/authorize',
                'token_endpoint': self.url + '/token', 'userinfo_endpoint': self.url + '/userinfo',
                'jwks_uri': self.url + '/jwks'},
            '/token': {'access_token': 'the-access-token', 'token_type': 'Bearer',
                       'id_token': self.id_token()},
            '/userinfo': {'sub': 'alice-sub', 'preferred_username': 'alice'},
            '/jwks': {'keys': [_jwk(self.signer.public_key(), 'k1')]},
            '/graph/me': {'id': 'alice-sub', 'userPrincipalName': 'alice@corp.example'},
            '/graph/memberOf': {'value': []},
        }
        if path not in answers:
            start_response('404 Not Found', [('Content-Length', '0')])
            return [b'']
        out = json.dumps(answers[path]).encode()
        start_response('200 OK', [('Content-Type', 'application/json'), ('Content-Length', str(len(out)))])
        return [out]

    def paths(self):
        return [(m, p) for m, p, _b in self.hits]


@pytest.fixture
def trap():
    t = _Elsewhere()
    yield t
    t.server.stop()


@pytest.fixture
def idp(tmp_path, trap, monkeypatch):
    monkeypatch.setattr(oidc, '_jwks_clients', {})
    monkeypatch.setattr(oidc, '_oidc_discovery_cache', {})
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)
    tls = _tls_files(tmp_path)
    # trusted for a verified request with the switch off (requests, and the key fetch over
    # urllib); the switch on does not ask
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', tls[0])
    monkeypatch.setenv('SSL_CERT_FILE', tls[0])
    ep = _IdP(tls, rsa.generate_private_key(public_exponent=65537, key_size=2048), trap)
    yield ep
    ep.server.stop()


def _cfg(ep, switch, **over):
    cfg = {'provider': 'generic', 'authority': ep.url, 'client_id': 'pegaprox',
           'client_secret': 'the-client-secret', 'redirect_uri': 'https://pegaprox.example/oidc/callback',
           'scopes': 'openid profile', 'oidc_skip_ssl_verify': switch, 'oidc_allow_private_ip': True}
    cfg.update(over)
    return cfg


SWITCH = pytest.mark.parametrize('switch', [True, False], ids=['switch-on', 'switch-off'])
STATUS = pytest.mark.parametrize('status', [302, 307])


# --- the token POST ---------------------------------------------------------------------

@SWITCH
@STATUS
def test_a_redirect_from_the_token_endpoint_is_an_error_and_not_followed(idp, trap, switch, status, caplog):
    idp.redirects['/token'] = status
    with caplog.at_level(logging.WARNING):
        tokens = oidc.oidc_exchange_code(_cfg(idp, switch), 'the-code', code_verifier='the-verifier')
    assert 'access_token' not in tokens, tokens
    assert f'HTTP {status}' in tokens.get('error', '') and 'redirect' in tokens['error'], tokens
    assert trap.hits == [], 'the code and the client secret went to the redirect target'
    assert idp.paths().count(('POST', '/token')) == 1
    assert trap.url in caplog.text and f'HTTP {status}' in caplog.text


@SWITCH
def test_a_token_endpoint_that_answers_200_works_as_before(idp, trap, switch):
    tokens = oidc.oidc_exchange_code(_cfg(idp, switch), 'the-code', code_verifier='the-verifier')
    assert tokens.get('access_token') == 'the-access-token', tokens
    (posted,) = [b for m, p, b in idp.hits if (m, p) == ('POST', '/token')]
    assert urllib.parse.parse_qs(posted)['client_secret'] == ['the-client-secret']
    assert trap.hits == []


# --- the userinfo GET -------------------------------------------------------------------

@SWITCH
@STATUS
def test_a_redirect_from_the_userinfo_endpoint_is_an_error_and_not_followed(idp, trap, switch, status):
    idp.redirects['/userinfo'] = status
    info = oidc.oidc_get_user_info(_cfg(idp, switch), 'the-access-token')
    assert set(info) == {'error'} and f'HTTP {status}' in info['error'], info
    assert trap.hits == [], 'the access token went to the redirect target'
    assert idp.paths().count(('GET', '/userinfo')) == 1


@SWITCH
def test_a_userinfo_endpoint_that_answers_200_works_as_before(idp, trap, switch):
    assert oidc.oidc_get_user_info(_cfg(idp, switch), 'the-access-token') == {
        'sub': 'alice-sub', 'preferred_username': 'alice'}
    assert trap.hits == []


# --- the Graph calls --------------------------------------------------------------------

def _entra(idp, monkeypatch):
    ep = {'authorization': idp.url + '/authorize', 'token': idp.url + '/token', 'jwks': idp.url + '/jwks',
          'userinfo': idp.url + '/userinfo', 'graph_me': idp.url + '/graph/me',
          'graph_groups': idp.url + '/graph/memberOf'}
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: dict(ep))
    return {'provider': 'entra', 'tenant_id': 't', 'client_id': 'pegaprox', 'oidc_allow_private_ip': True}


@STATUS
def test_a_redirect_on_the_graph_groups_is_a_failed_fetch(idp, trap, monkeypatch, status):
    cfg = _entra(idp, monkeypatch)
    # a member of no group: the walk is complete, so the login may revoke
    assert oidc.oidc_get_user_groups_ex(cfg, 'at') == ([], True)
    idp.redirects['/graph/memberOf'] = status
    assert oidc.oidc_get_user_groups_ex(cfg, 'at') == ([], False)
    assert trap.hits == []
    assert idp.paths().count(('GET', '/graph/memberOf')) == 2


@STATUS
def test_a_redirect_on_graph_me_falls_back_to_userinfo_without_following(idp, trap, monkeypatch, status):
    cfg = _entra(idp, monkeypatch)
    idp.redirects['/graph/me'] = status
    assert oidc.oidc_get_user_info(cfg, 'at') == {'sub': 'alice-sub', 'preferred_username': 'alice'}
    assert trap.hits == []
    assert ('GET', '/userinfo') in idp.paths()


# --- the sign-in ------------------------------------------------------------------------

def _configure(api, db, idp, switch):
    admin = api.as_user(_seed_user(db, 'root', role='admin'))
    r = admin.post('/api/settings/server', json={
        'oidc_enabled': True, 'oidc_provider': 'generic', 'oidc_authority': idp.url,
        'oidc_client_id': 'pegaprox', 'oidc_client_secret': 'the-client-secret',
        'oidc_redirect_uri': 'https://pegaprox.example/oidc/callback',
        'oidc_skip_ssl_verify': switch, 'oidc_allow_private_ip': True})
    assert r.status_code == 200, r.get_data(as_text=True)


def _callback(api):
    import pegaprox.api.auth as auth_api
    for k in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(k, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    return browser.post('/api/auth/oidc/callback', json={'code': 'the-code', 'state': 'the-state'},
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                        base_url='http://localhost')


@SWITCH
@pytest.mark.parametrize('path,status', [('/token', 307), ('/userinfo', 302)])
def test_a_sign_in_whose_idp_redirects_fails(api, db, idp, trap, switch, path, status, caplog):
    _configure(api, db, idp, switch)
    idp.redirects[path] = status
    with caplog.at_level(logging.WARNING):
        r = _callback(api)
    assert r.status_code == 401, r.get_data(as_text=True)
    assert 'session_id' not in (r.get_json() or {})
    assert db.get_user('alice') is None and db.get_user('someone-else') is None
    assert trap.hits == []
    assert f'HTTP {status} redirecting to {trap.url!r}' in caplog.text, caplog.text


@SWITCH
def test_a_sign_in_whose_idp_answers_200_completes_as_before(api, db, idp, trap, switch, caplog):
    _configure(api, db, idp, switch)
    with caplog.at_level(logging.WARNING):
        r = _callback(api)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'alice'
    assert db.get_user('alice')['oidc_sub'] == 'alice-sub'
    assert {('POST', '/token'), ('GET', '/userinfo'), ('GET', '/jwks')} <= set(idp.paths())
    assert trap.hits == []
    assert 'falling back to unverified decode' not in caplog.text, caplog.text
