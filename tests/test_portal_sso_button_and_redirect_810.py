"""The client portal's SSO button and the way into the portal (#810).

  * The portal took its "Sign in with ..." button from /api/auth/check, which carries
    oidc_enabled only in its 401. A browser signed in to the main window got a 200 and
    no button. It now reads GET /api/auth/oidc/config, the public endpoint the flag
    already came from: /api/auth/check is unchanged, and an anonymous caller learns
    nothing it did not learn before.
  * A portal_only account that opened / was signed out. It is sent to /portal now, and
    the portal takes over the session it arrives with (also the one an SSO sign-in
    started from the portal comes back with), where it used to show the login form
    again. Another account's session at /portal is left alone.
  * What keeps a portal account out of the main API was its permissions alone when this
    was written; the server holds portal_only itself now, see
    test_portal_only_is_enforced_on_the_server.py.

The runtime parts drive web/index.html and portal.html in headless Chromium against
the real app (test_forced_2fa_ui._RealBackend). Each carries its counter-check.

MK Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import BASE, ROOT, browser  # noqa: F401  (browser is a fixture)
from test_forced_2fa_ui import _RealBackend

PASSWORD = 'C0rrect!horse9'
BUTTON = 'Sign in with Contoso'
OIDC_ON = {'oidc_enabled': True, 'oidc_provider': 'entra', 'oidc_client_id': 'pegaprox-client',
           'oidc_tenant_id': 'contoso-tenant', 'oidc_button_text': BUTTON,
           'oidc_redirect_uri': 'https://pegaprox.example/oidc/callback'}

# what /api/auth/check answered before this change, signed in and not
CHECK_401_KEYS = {'authenticated', 'initialized', 'ldap_enabled', 'oidc_enabled',
                  'oidc_button_text', 'login_background', 'ha_role'}
CHECK_200_KEYS = {'authenticated', 'session_id', 'user', 'password_expiry', 'requires_2fa_setup',
                  'reverse_proxy_enabled', 'air_gap_mode', 'default_theme', 'ha'}
CHECK_200_USER_KEYS = {'username', 'role', 'display_name', 'email', 'avatar_url', 'auth_source',
                       'tenant_id', 'permissions', 'theme', 'language', 'ui_layout',
                       'taskbar_auto_expand', 'sidebar_show_vmid', 'totp_enabled',
                       'layout_chosen', 'portal_only', 'autoinstall_access'}


def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _function(src, name):
    m = re.search(r'async function ' + name + r'\(\)\{.*?\n\}\n', src, re.S)
    assert m, name
    return m.group(0)


@pytest.fixture
def oidc_on(api):
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    s = load_server_settings()
    s.update(OIDC_ON)
    save_server_settings(s)
    return api


def _account(db, name, role='user', portal_only=False):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user(name, {'password_salt': salt, 'password_hash': pw_hash, 'role': role,
                        'enabled': True, 'auth_source': 'local', 'language': 'en',
                        'layout_chosen': True, 'portal_only': portal_only})
    user = db.get_user(name)
    user['username'] = name
    return user


# ── what the server answers ──────────────────────────────────────────────────

def test_the_public_oidc_config_answers_alike_signed_in_or_not(oidc_on, db):
    admin = oidc_on.as_user(_account(db, 'boss', role='admin'))

    anon = oidc_on.anon().get('/api/auth/oidc/config')
    signed_in = admin.get('/api/auth/oidc/config')

    assert anon.status_code == signed_in.status_code == 200
    assert anon.get_json() == signed_in.get_json() == {
        'enabled': True, 'provider': 'entra', 'button_text': BUTTON}


def test_it_says_what_the_401_of_auth_check_said(oidc_on):
    """The portal now reads this instead of the 401: the two fields it uses carry the same
    values, and the endpoint has no field beyond the three it always had (no client id,
    tenant, issuer or secret)."""
    check = oidc_on.anon().get('/api/auth/check')
    config = oidc_on.anon().get('/api/auth/oidc/config').get_json()

    assert check.status_code == 401
    assert config['enabled'] == check.get_json()['oidc_enabled']
    assert config['button_text'] == check.get_json()['oidc_button_text']
    assert set(config) == {'enabled', 'provider', 'button_text'}


def test_auth_check_answers_what_it_answered_before(oidc_on, db):
    """No field was added to either answer: the 401 keeps its login page fields, and the
    200 carries nothing beyond those and the fields it already had."""
    anon = oidc_on.anon().get('/api/auth/check')
    signed_in = oidc_on.as_user(_account(db, 'cust', portal_only=True)).get('/api/auth/check')

    assert anon.status_code == 401 and set(anon.get_json()) == CHECK_401_KEYS
    body = signed_in.get_json()
    assert signed_in.status_code == 200
    assert set(body) <= CHECK_401_KEYS | CHECK_200_KEYS, set(body) - CHECK_200_KEYS
    assert set(body) == CHECK_200_KEYS
    assert set(body['user']) == CHECK_200_USER_KEYS
    assert not {'oidc_enabled', 'oidc_button_text', 'ldap_enabled'} & set(body)


@pytest.mark.parametrize('route', ['/api/users', '/api/settings/server'])
def test_a_portal_account_is_refused_by_the_main_api(api, db, route):
    """Counter-checks: the same account without portal_only is refused alike (the
    permissions refuse it, the flag is UI routing), and an admin is let in, so the 403
    is the permission check and not a broken route."""
    portal = api.as_user(_account(db, 'cust', portal_only=True))
    plain = api.as_user(_account(db, 'other'))
    admin = api.as_user(_account(db, 'boss', role='admin'))

    assert portal.get(route).status_code == 403
    assert plain.get(route).status_code == 403
    assert admin.get(route).status_code == 200


# ── the source ───────────────────────────────────────────────────────────────

def test_the_portal_takes_the_button_from_the_public_config():
    body = _function(_src('plugins', 'client_portal', 'portal.html'), 'checkAuthProviders')

    assert '/api/auth/oidc/config' in body
    assert 'd.enabled' in body and 'd.button_text' in body
    assert 'auth/check' not in body and 'oidc_enabled' not in body


def test_the_main_page_sends_a_portal_account_on_instead_of_signing_it_out():
    src = _src('web', 'src', 'contexts.js')
    restore = src[src.index('d.user?.portal_only'):][:400]
    login = src[src.index('if (data.portal_only'):][:500]

    assert "window.location.replace('/portal')" in restore
    assert 'logout()' not in restore.split('return;')[0]
    assert "window.location.replace('/portal')" in login


# ── at runtime ───────────────────────────────────────────────────────────────

class _Page:
    def __init__(self, browser, api, sid=None):  # noqa: F811
        self.backend = _RealBackend(api.app)
        self.backend.sid = sid
        self.ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
        self.page = self.ctx.new_page()
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.route('**/*', self.backend.handle)

    def logouts(self):
        return [c for c in self.backend.calls if c[:2] == ('POST', '/api/auth/logout')]

    def portal_signed_in(self, timeout=15000):
        self.page.wait_for_url(BASE + '/portal', timeout=timeout)
        self.page.locator('#bo').wait_for(timeout=timeout)
        assert self.page.locator('#lf').count() == 0

    def close(self):
        self.ctx.close()


@pytest.fixture
def pages(browser):  # noqa: F811
    opened = []

    def _open(api, sid=None):
        p = _Page(browser, api, sid)
        opened.append(p)
        return p
    yield _open
    for p in opened:
        p.close()


def _still_valid(api, sid):
    from pegaprox.utils.auth import validate_session
    with api.app.test_request_context('/'):
        return bool(validate_session(sid))


def test_runtime_the_sso_button_shows_beside_a_main_window_session(oidc_on, db, pages):
    """The repro of #810: signed in to the main window, the portal had no SSO button.
    Counter-check: a browser without a session sees it too, so the button is not there
    for some other reason."""
    sid = oidc_on.as_user(_account(db, 'boss', role='admin')).session_id
    for session in (sid, None):
        p = pages(oidc_on, session)
        p.page.goto(BASE + '/portal', wait_until='load')
        p.page.get_by_role('button', name=BUTTON).wait_for(timeout=15000)
        assert not p.errors, p.errors
        assert not p.logouts()
    assert _still_valid(oidc_on, sid)


def test_runtime_no_sso_button_when_oidc_is_off(api, db, pages):
    p = pages(api)
    p.page.goto(BASE + '/portal', wait_until='load')
    p.page.locator('#lf').wait_for(timeout=15000)
    p.page.wait_for_timeout(500)
    assert p.page.get_by_text('Sign in with').count() == 0


def test_runtime_a_portal_account_opening_the_main_page_lands_in_the_portal(api, db, pages):
    sid = api.as_user(_account(db, 'cust', portal_only=True)).session_id
    p = pages(api, sid)

    p.page.goto(BASE + '/', wait_until='load')

    p.portal_signed_in()
    assert p.page.evaluate("sessionStorage.getItem('portal-sid')") == sid
    assert not p.logouts(), p.backend.calls
    assert _still_valid(api, sid)
    assert any(c[1].endswith('/my-vms') for c in p.backend.calls)
    assert not p.errors, p.errors


def test_runtime_a_portal_account_signing_in_on_the_main_page_lands_in_the_portal(api, db, pages):
    _account(db, 'cust', portal_only=True)
    p = pages(api)
    p.page.goto(BASE + '/', wait_until='load')
    p.page.locator('input[autocomplete="username"]').fill('cust')
    p.page.locator('input[autocomplete="current-password"]').fill(PASSWORD)
    # the login page signs out whatever the 401 of its first check left: before the sign-in
    before = len(p.logouts())
    p.page.locator('button[type="submit"]').click()

    p.portal_signed_in()
    assert p.backend.sid and _still_valid(api, p.backend.sid)
    assert len(p.logouts()) == before, p.backend.calls
    assert not p.errors, p.errors


def test_runtime_the_portal_takes_over_the_session_an_sso_sign_in_left(api, db, pages):
    """Back from the identity provider with redirect_after=/portal the browser has the
    session cookie and no portal-sid: the portal used to show its login form again."""
    sid = api.as_user(_account(db, 'cust', portal_only=True)).session_id
    p = pages(api, sid)

    p.page.goto(BASE + '/portal', wait_until='load')

    p.portal_signed_in()
    assert p.page.evaluate("sessionStorage.getItem('portal-sid')") == sid


@pytest.mark.parametrize('role,portal_only', [('admin', False), ('user', False)])
def test_runtime_another_accounts_session_is_left_alone_by_the_portal(api, db, pages, role, portal_only):
    """An account that is not a portal account stays on the portal's login form, and its
    session (the main window's) is not signed out."""
    sid = api.as_user(_account(db, 'other', role=role, portal_only=portal_only)).session_id
    p = pages(api, sid)

    p.page.goto(BASE + '/portal', wait_until='load')
    p.page.locator('#lf').wait_for(timeout=15000)
    p.page.wait_for_timeout(800)

    assert p.page.locator('#bo').count() == 0
    assert p.page.evaluate("sessionStorage.getItem('portal-sid')") is None
    assert not p.logouts(), p.backend.calls
    assert _still_valid(api, sid)
    assert not p.errors, p.errors


def test_runtime_the_main_page_still_opens_for_other_accounts(api, db, pages):
    """Counter-check for the redirect: an account without portal_only stays on /."""
    sid = api.as_user(_account(db, 'other')).session_id
    p = pages(api, sid)

    p.page.goto(BASE + '/', wait_until='load')
    p.page.wait_for_function(
        '() => document.querySelector("header") || document.querySelector(".cloud-shell")',
        timeout=30000)

    assert p.page.url == BASE + '/'
    assert not p.logouts()
