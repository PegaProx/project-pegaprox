"""A link that starts the SSO sign-in by itself (#768).

GET /api/auth/oidc/authorize answers JSON with the auth_url, which the login buttons
fetch and then follow. A bookmark or a portal tile cannot do that, so
GET /api/auth/oidc/login runs the same start and answers 302 to the identity provider.

What has to hold, each driven through the real app and the real URL builder:
  * the Location is the authorize endpoint of the stored configuration, never anything
    the request carries, a hostile redirect_after included
  * the cookie is the one the authorize route sets: state, nonce and PKCE verifier that
    match the Location, redirect_after only when it is an internal path, and the
    callback accepts it
  * OIDC off or unusable sends the browser to the login page, never back to the link
  * no CSRF marker is needed (a bookmark sends none), and the API rate limit applies
    as it does to the authorize route

MK Oct 2026
"""
import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import pytest

from pegaprox.utils import oidc as O

LINK = '/api/auth/oidc/login'
AUTHORIZE = '/api/auth/oidc/authorize'
BASE = 'http://localhost'
REDIRECT_URI = 'https://pegaprox.example/oidc/callback'

ENTRA = {
    'oidc_enabled': True, 'oidc_provider': 'entra', 'oidc_client_id': 'pegaprox-client',
    'oidc_tenant_id': 'contoso-tenant', 'oidc_cloud_environment': 'commercial',
    'oidc_redirect_uri': REDIRECT_URI, 'oidc_button_text': 'Sign in with Contoso',
}
ENTRA_AUTHORIZE = 'https://login.microsoftonline.com/contoso-tenant/oauth2/v2.0/authorize'

ISSUER = 'https://idp.example/realms/corp'
KEYCLOAK = {
    'oidc_enabled': True, 'oidc_provider': 'keycloak', 'oidc_client_id': 'pegaprox-client',
    'oidc_authority': ISSUER, 'oidc_redirect_uri': REDIRECT_URI,
}
KEYCLOAK_AUTHORIZE = 'https://idp.example/realms/corp/protocol/openid-connect/auth'


def _configure(settings, discovery=None, monkeypatch=None):
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    s = load_server_settings()
    for key in ('oidc_tenant_id', 'oidc_authority', 'oidc_redirect_uri'):
        s.pop(key, None)
    s.update(settings)
    save_server_settings(s)
    if discovery is not None:
        # what the issuer's .well-known answered, cached: no network in a test
        monkeypatch.setitem(O._oidc_discovery_cache, settings['oidc_authority'],
                            {'data': discovery, 'expires': time.time() + 3600})


@pytest.fixture
def entra(api):
    _configure(ENTRA)
    return api


@pytest.fixture
def keycloak(api, monkeypatch):
    _configure(KEYCLOAK, {'authorization_endpoint': KEYCLOAK_AUTHORIZE}, monkeypatch)
    return api


def _browser(api):
    """A browser of its own: no cookie of another test, no CSRF marker, no session."""
    return api.app.test_client()


def _open(api, path=LINK, headers=None, **query):
    return _browser(api).get(path, query_string=query, headers=headers or {}, base_url=BASE)


def _state_cookie(resp):
    """(value, attributes) of the oidc_state Set-Cookie, or None."""
    for raw in resp.headers.getlist('Set-Cookie'):
        name, _, rest = raw.partition('=')
        if name != 'oidc_state':
            continue
        value, *attrs = [p.strip() for p in rest.split(';')]
        return value, {a.split('=', 1)[0].lower(): (a.split('=', 1)[1] if '=' in a else True)
                       for a in attrs}
    return None


def _params(location):
    return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}


def _challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()
                                    ).rstrip(b'=').decode('ascii')


# ── the redirect ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize('fixture,endpoint', [('entra', ENTRA_AUTHORIZE),
                                              ('keycloak', KEYCLOAK_AUTHORIZE)])
def test_the_link_sends_the_browser_to_the_configured_identity_provider(request, fixture, endpoint):
    api = request.getfixturevalue(fixture)

    r = _open(api)

    assert r.status_code == 302
    location = r.headers['Location']
    assert location.split('?')[0] == endpoint
    p = _params(location)
    assert p['client_id'] == 'pegaprox-client'
    assert p['redirect_uri'] == REDIRECT_URI
    assert p['response_type'] == 'code' and p['code_challenge_method'] == 'S256'


def test_the_cookie_carries_the_state_nonce_and_verifier_of_that_redirect(entra):
    r = _open(entra)

    value, attrs = _state_cookie(r)
    state, nonce, verifier = value.split(':')
    p = _params(r.headers['Location'])
    assert p['state'] == state and p['nonce'] == nonce
    assert p['code_challenge'] == _challenge(verifier)
    assert attrs.get('httponly') is True
    assert attrs.get('samesite') == 'Lax' and attrs.get('max-age') == '600'


def test_it_is_the_cookie_and_url_the_authorize_route_makes(entra):
    """Same start, other answer: one JSON, one 302, everything else alike."""
    link = _open(entra, redirect_after='/portal')
    authorize = _open(entra, AUTHORIZE, redirect_after='/portal')

    assert authorize.status_code == 200
    auth_url = authorize.get_json()['auth_url']
    assert link.headers['Location'].split('?')[0] == auth_url.split('?')[0]
    assert set(_params(link.headers['Location'])) == set(_params(auth_url))
    (lv, la), (av, aa) = _state_cookie(link), _state_cookie(authorize)
    assert la == aa
    assert [len(x) for x in lv.split(':')[:3]] == [len(x) for x in av.split(':')[:3]]
    assert lv.split(':')[3:] == av.split(':')[3:] == ['/portal']
    # fresh secrets every time
    assert lv.split(':')[:3] != av.split(':')[:3]


def test_the_callback_takes_the_cookie_the_link_set(entra, monkeypatch):
    """The state check passes with the link's cookie: what fails afterwards is the code,
    which is the identity provider's business. Counter-check: a state the cookie does not
    hold is refused at the state check."""
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'oidc_exchange_code',
                        lambda cfg, code, code_verifier=None: {'error': 'invalid_grant'})
    browser = _browser(entra)
    r = browser.get(LINK, base_url=BASE)
    state = _params(r.headers['Location'])['state']
    marker = {'X-Requested-With': 'XMLHttpRequest', 'Origin': BASE}

    good = browser.post('/api/auth/oidc/callback', json={'code': 'c', 'state': state},
                        headers=marker, base_url=BASE)
    browser.get(LINK, base_url=BASE)
    bad = browser.post('/api/auth/oidc/callback', json={'code': 'c', 'state': 'not-it'},
                       headers=marker, base_url=BASE)

    assert good.status_code == 401, good.get_json()
    assert good.get_json()['error'] == 'Authentication failed - please try again'
    assert bad.status_code == 400 and 'Invalid state' in bad.get_json()['error']


def test_an_internal_redirect_after_rides_in_the_cookie_not_in_the_location(entra):
    r = _open(entra, redirect_after='/portal')

    assert _state_cookie(r)[0].split(':')[3] == '/portal'
    assert 'portal' not in r.headers['Location']


# ── what the request cannot steer ────────────────────────────────────────────

HOSTILE = ['//evil.example', 'https://evil.example', '/\\evil.example', '/\\evil',
           '\\\\evil.example', 'evil.example', 'javascript:alert(1)',
           '/x\r\nLocation: https://evil.example', '/x\tevil', '/' + 'a' * 250]


@pytest.mark.parametrize('hostile', HOSTILE)
def test_a_hostile_redirect_after_changes_neither_location_nor_cookie(entra, hostile):
    r = _open(entra, redirect_after=hostile)

    assert r.status_code == 302
    location = r.headers['Location']
    assert urlparse(location).netloc == 'login.microsoftonline.com'
    assert location.split('?')[0] == ENTRA_AUTHORIZE
    assert 'evil' not in location
    value, _ = _state_cookie(r)
    assert len(value.split(':')) == 3, f'{hostile!r} reached the cookie: {value!r}'


@pytest.mark.parametrize('headers', [
    {'Host': 'evil.example'},
    {'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'https'},
    {'Origin': 'https://evil.example', 'Referer': 'https://evil.example/x'},
])
def test_request_headers_do_not_reach_the_location(entra, headers):
    r = _open(entra, headers=headers)

    assert r.status_code == 302
    assert r.headers['Location'].split('?')[0] == ENTRA_AUTHORIZE
    assert _params(r.headers['Location'])['redirect_uri'] == REDIRECT_URI
    assert 'evil' not in r.headers['Location']


# ── no loop when OIDC cannot start ───────────────────────────────────────────

@pytest.mark.parametrize('broken', [
    {'oidc_enabled': False},
    {'oidc_client_id': ''},
    # Entra without a tenant has no authorize endpoint: the URL comes out as '?client_id=...'
    {'oidc_tenant_id': ''},
])
def test_a_setup_that_cannot_start_sends_the_browser_to_the_login_page(api, broken):
    _configure(dict(ENTRA, **broken))

    r = _open(api)

    assert r.status_code == 302
    assert r.headers['Location'] == '/'
    assert _state_cookie(r) is None
    # and the login page is a page, not another redirect
    assert _browser(api).get('/', base_url=BASE).status_code == 200


@pytest.mark.parametrize('endpoint', ['http://idp.example/auth', 'javascript:alert(1)',
                                      '/api/auth/oidc/login', '//idp.example/auth',
                                      'https://user:pw@idp.example/auth',
                                      'https://idp.example/äuth',
                                      # a port werkzeug cannot write into the header, control characters
                                      'https://idp.example:99999/auth', 'https://idp.example:abc/auth',
                                      'https://idp.example\x00.evil.example/auth', 'https://idp.example\x0b/auth',
                                      # this route itself on this host, by absolute URL
                                      'https://localhost/api/auth/oidc/login'])
def test_a_discovery_document_with_an_unusable_endpoint_is_not_followed(api, monkeypatch, endpoint):
    _configure(KEYCLOAK, {'authorization_endpoint': endpoint}, monkeypatch)

    r = _open(api)

    assert r.status_code == 302 and r.headers['Location'] == '/'
    assert _state_cookie(r) is None


def test_the_authorize_route_still_answers_json(entra, api):
    r = _open(entra, AUTHORIZE)
    assert r.status_code == 200
    assert list(r.get_json()) == ['auth_url']
    assert r.get_json()['auth_url'].split('?')[0] == ENTRA_AUTHORIZE
    assert _state_cookie(r) is not None

    _configure(dict(ENTRA, oidc_enabled=False))
    off = _open(api, AUTHORIZE)
    assert off.status_code == 400
    assert off.get_json() == {'error': 'OIDC authentication is not configured'}
    assert _state_cookie(off) is None


# ── CSRF and rate limit ──────────────────────────────────────────────────────

def test_a_bookmark_needs_no_csrf_marker_and_a_post_starts_nothing(entra):
    """The CSRF gate in app.py covers POST/PUT/PATCH/DELETE only; a GET that sets the
    state cookie is what the authorize route has always been. A POST to the link is not
    on the exempt list, so the gate refuses it before the 405."""
    plain = _browser(entra).get(LINK, base_url=BASE)
    posted = _browser(entra).post(LINK, base_url=BASE)
    marked = _browser(entra).post(LINK, base_url=BASE,
                                  headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': BASE})

    assert plain.status_code == 302
    assert posted.status_code == 403
    assert marked.status_code == 405
    assert _state_cookie(posted) is None and _state_cookie(marked) is None


def test_the_api_rate_limit_applies_as_it_does_to_authorize(entra, monkeypatch):
    import pegaprox.app as app_mod
    monkeypatch.setattr(app_mod, '_check_api_rate_limit', lambda ip: False)

    assert _open(entra).status_code == 429
    assert _open(entra, AUTHORIZE).status_code == 429
    # counter-check: a route on the skip list is not limited, so the 429 is the limiter's
    assert _open(entra, '/api/auth/check').status_code == 401
