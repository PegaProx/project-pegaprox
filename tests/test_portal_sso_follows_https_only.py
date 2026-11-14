"""The client portal's SSO button follows only an https URL, and the JSON route it asks
hands out only a URL the login link would redirect to.

  * GET /api/auth/oidc/authorize put whatever the URL builder made into its answer, while
    GET /api/auth/oidc/login checks it first (_idp_location): an absolute https URL of
    the identity provider. Both check it now; the JSON keeps its shape, and a URL that
    fails answers like a setup that cannot start.
  * the portal's startOidcLogin went to d.auth_url whatever it was. It takes the rule of
    the main login button (web/src/auth.js): https:// or nothing, and says why.

The runtime part drives portal.html in headless Chromium against the real app; the
authorize answer is swapped for one an older or broken server could send.

MK Nov 2026
"""
import json
import time

import pytest

from test_ha_ui import BASE, browser  # noqa: F401  (browser is a fixture)
from test_forced_2fa_ui import _RealBackend
from test_oidc_login_link_768 import (
    AUTHORIZE, ENTRA, ENTRA_AUTHORIZE, KEYCLOAK, _configure, _open, _state_cookie,
)

NOT_CONFIGURED = {'error': 'OIDC authentication is not configured'}
UNUSABLE = ['http://idp.example/auth', 'javascript:alert(1)', 'data:text/html,<b>x</b>',
            '/api/auth/oidc/login', '//idp.example/auth', 'https://user:pw@idp.example/auth',
            'https://idp.example:99999/auth', 'https://idp.example\x00.evil.example/auth',
            'https://localhost/api/auth/oidc/authorize', '?client_id=pegaprox-client']


# --- the JSON route ---------------------------------------------------------------------

def test_a_usable_endpoint_is_still_handed_out(api):
    _configure(ENTRA)
    r = _open(api, AUTHORIZE, redirect_after='/portal')
    assert r.status_code == 200
    assert list(r.get_json()) == ['auth_url']
    assert r.get_json()['auth_url'].split('?')[0] == ENTRA_AUTHORIZE
    assert _state_cookie(r)[0].split(':')[3] == '/portal'


@pytest.mark.parametrize('endpoint', UNUSABLE)
def test_an_unusable_endpoint_is_not_handed_out(api, monkeypatch, endpoint):
    _configure(KEYCLOAK, {'authorization_endpoint': endpoint}, monkeypatch)
    r = _open(api, AUTHORIZE)
    assert r.status_code == 400
    assert r.get_json() == NOT_CONFIGURED
    assert _state_cookie(r) is None
    # the login link answers alike for the same setup
    link = _open(api)
    assert link.status_code == 302 and link.headers['Location'] == '/'


# --- the portal, at runtime ---------------------------------------------------------------

IDP_HOST = 'https://login.microsoftonline.com/'
PORTAL_OIDC = {'oidc_enabled': True, 'oidc_provider': 'entra', 'oidc_client_id': 'pegaprox-client',
               'oidc_tenant_id': 'contoso-tenant', 'oidc_button_text': 'Sign in with Contoso',
               'oidc_redirect_uri': 'https://pegaprox.example/oidc/callback'}


class _Backend(_RealBackend):
    """The real app, with the authorize answer swapped when `auth_url` is set, and the
    identity provider standing by so a navigation there can be seen."""

    def __init__(self, app, auth_url=None):
        super().__init__(app)
        self.auth_url = auth_url
        self.idp = []

    def handle(self, route):
        url = route.request.url
        if url.startswith(IDP_HOST):
            self.idp.append(url)
            return route.fulfill(status=200, body='<html><body>identity provider</body></html>',
                                 headers={'Content-Type': 'text/html'})
        if self.auth_url is not None and url.startswith(BASE + AUTHORIZE):
            self.calls.append(('GET', AUTHORIZE, 200, None))
            return route.fulfill(status=200, body=json.dumps({'auth_url': self.auth_url}),
                                 headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture
def portal(api, browser):  # noqa: F811
    _configure(PORTAL_OIDC)
    opened = []

    def _open_portal(auth_url=None):
        backend = _Backend(api.app, auth_url)
        ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
        page = ctx.new_page()
        page.route('**/*', backend.handle)
        page.goto(BASE + '/portal', wait_until='load')
        page.get_by_role('button', name='Sign in with Contoso').wait_for(timeout=15000)
        opened.append(ctx)
        return page, backend
    yield _open_portal
    for ctx in opened:
        ctx.close()


def _settle(page, backend, ms=1500):
    deadline = time.time() + ms / 1000
    while time.time() < deadline and not backend.idp:
        page.wait_for_timeout(100)


@pytest.mark.parametrize('auth_url', ['javascript:window.__followed=1',
                                      'data:text/html,<script>parent.__followed=1</script>',
                                      'http://login.microsoftonline.com/contoso-tenant/oauth2/v2.0/authorize',
                                      ' https://login.microsoftonline.com/x'])
def test_runtime_the_portal_does_not_follow_an_unsafe_url(portal, auth_url):
    page, backend = portal(auth_url)
    page.get_by_role('button', name='Sign in with Contoso').click()
    page.get_by_text('Insecure authentication URL rejected').wait_for(timeout=5000)
    _settle(page, backend)
    assert page.url == BASE + '/portal'
    assert page.evaluate('window.__followed') is None
    assert backend.idp == []
    assert ('GET', AUTHORIZE, 200, None) in backend.calls
    # the button is usable again
    assert page.get_by_role('button', name='Sign in with Contoso').is_enabled()


def test_runtime_the_portal_follows_the_url_the_server_hands_out(portal):
    """Counter-check: the real authorize answer is followed to the identity provider."""
    page, backend = portal()
    page.get_by_role('button', name='Sign in with Contoso').click()
    page.wait_for_url(IDP_HOST + '**', timeout=10000)
    assert backend.idp and backend.idp[0].split('?')[0] == ENTRA_AUTHORIZE
    assert page.get_by_text('identity provider').count() == 1


def test_runtime_a_refused_setup_shows_the_portal_s_message(portal, monkeypatch):
    _configure(dict(PORTAL_OIDC, oidc_tenant_id=''))      # no authorize endpoint: '?client_id=...'
    page, backend = portal()
    page.get_by_role('button', name='Sign in with Contoso').click()
    page.get_by_text('SSO is not configured or unavailable').wait_for(timeout=5000)
    assert page.url == BASE + '/portal' and backend.idp == []
