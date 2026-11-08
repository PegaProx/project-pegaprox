"""The forced 2FA setup screens against the real server (#1076).

The server now holds a session that still has to enrol to the enrolment itself. These
run web/index.html and the client portal in headless Chromium with every /api/ call
answered by the real app, so the screen the browser shows and the gate the server
applies meet: until the code is verified the API refuses the session, and both setup
screens still get through to the end and leave a session that works.

NS Oct 2026
"""
import json
import os

import pyotp
import pytest

from test_ha_ui import BASE, ROOT, _read, browser  # noqa: F401

PASSWORD = 'C0rrect!horse9'


class _RealBackend:
    """Routes the page's requests to the Flask app in this process. The session cookie
    is kept here and sent along like the browser would."""

    def __init__(self, app):
        self.client = app.test_client(use_cookies=False)
        self.sid = None
        self.calls = []

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE):
            return route.abort()
        path = req.url[len(BASE):] or '/'
        bare = path.split('?')[0]
        if bare in ('/', '/index.html'):
            return route.fulfill(status=200, body=_read('web', 'index.html'),
                                 headers={'Content-Type': 'text/html; charset=utf-8'})
        if bare == '/portal':
            return route.fulfill(status=200, body=_read('plugins', 'client_portal', 'portal.html'),
                                 headers={'Content-Type': 'text/html; charset=utf-8'})
        if bare.startswith('/static/'):
            fp = os.path.join(ROOT, bare.lstrip('/'))
            if not os.path.isfile(fp):
                return route.fulfill(status=404, body='')
            ctype = 'text/css' if fp.endswith('.css') else 'application/javascript'
            with open(fp, 'rb') as fh:
                return route.fulfill(status=200, body=fh.read(), headers={'Content-Type': ctype})
        # a live stream never ends, and there is nothing behind it here
        if not bare.startswith('/api/') or bare.startswith('/api/sse'):
            return route.abort()
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() in ('content-type', 'x-requested-with', 'origin')}
        if self.sid:
            headers['Cookie'] = f'session_id={self.sid}'
        resp = self.client.open(path, method=req.method, headers=headers,
                                data=req.post_data_buffer, base_url=BASE)
        for cookie in resp.headers.getlist('Set-Cookie'):
            if cookie.startswith('session_id='):
                value = cookie.split(';')[0].split('=', 1)[1]
                self.sid = value or None
        body = resp.get_data()
        try:
            code = json.loads(body).get('code')
        except Exception:
            code = None
        self.calls.append((req.method, bare, resp.status_code, code))
        return route.fulfill(status=resp.status_code, body=body,
                             headers={'Content-Type': resp.headers.get('Content-Type',
                                                                       'application/json')})


@pytest.fixture
def forced(api, db):
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    from pegaprox.utils.auth import hash_password
    s = load_server_settings()
    s['force_2fa'] = True
    save_server_settings(s)
    salt, pw_hash = hash_password(PASSWORD)
    # layout not chosen yet: the screen after the enrolment is the layout choice
    db.save_user('ops', {'password_salt': salt, 'password_hash': pw_hash, 'role': 'user',
                         'enabled': True, 'auth_source': 'local', 'language': 'en'})
    return api


def _signed_in(browser, api):  # noqa: F811
    backend = _RealBackend(api.app)
    ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.route('**/*', backend.handle)
    page.goto(BASE + '/', wait_until='load')
    page.locator('input[autocomplete="username"]').fill('ops')
    page.locator('input[autocomplete="current-password"]').fill(PASSWORD)
    page.locator('button[type="submit"]').click()
    page.get_by_text('2FA Setup Required').wait_for(timeout=15000)
    return ctx, page, backend, errors


def _fetch_status(page, path):
    return page.evaluate("""async (p) => {
        const r = await fetch(p, {credentials: 'include'});
        let code = null;
        try { code = (await r.json()).code; } catch (_) {}
        return [r.status, code];
    }""", path)


def test_runtime_the_api_holds_the_session_behind_the_setup_screen(browser, forced):  # noqa: F811
    ctx, page, backend, errors = _signed_in(browser, forced)
    try:
        assert _fetch_status(page, '/api/pbs') == [403, 'MFA_ENROLMENT_REQUIRED']
        assert _fetch_status(page, '/api/auth/2fa/status')[0] == 200
        assert not errors, errors
    finally:
        ctx.close()


def test_runtime_the_setup_screen_gets_through_and_the_session_works(browser, forced):  # noqa: F811
    ctx, page, backend, errors = _signed_in(browser, forced)
    try:
        page.get_by_role('button', name='Setup 2FA').click()
        secret = page.locator('code').first
        secret.wait_for(timeout=10000)
        code = pyotp.TOTP(secret.inner_text().strip()).now()
        page.get_by_role('button', name='Next').click()
        page.locator('input[placeholder="000000"]').fill(code)
        page.get_by_role('button', name='Verify').click()

        # past the enrolment: the layout choice of a first login, and it saves
        page.get_by_text('Corporate').first.wait_for(timeout=15000)
        mark = len(backend.calls)
        page.locator('[data-layout-pick="cloud"]').click()
        page.wait_for_timeout(800)
        after = backend.calls[mark:]

        assert ('PUT', '/api/user/preferences', 200, None) in after, after
        assert not [c for c in after if c[3] == 'MFA_ENROLMENT_REQUIRED'], after
        assert _fetch_status(page, '/api/pbs')[0] == 200
        assert not errors, errors
    finally:
        ctx.close()


def test_runtime_the_client_portal_opens_the_enrolment_first(browser, forced, db):  # noqa: F811
    """The portal never read requires_2fa_setup and loaded the guest list straight away,
    which the server now refuses; it opens its own 2FA dialog instead and loads the
    list once the code is verified."""
    rec = db.get_user('ops')
    rec['portal_only'] = True
    db.save_user('ops', rec)
    backend = _RealBackend(forced.app)
    ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.route('**/*', backend.handle)
    try:
        page.goto(BASE + '/portal', wait_until='load')
        page.locator('#lu').fill('ops')
        page.locator('#lp').fill(PASSWORD)
        page.locator('#lf button[type="submit"]').click()
        page.get_by_text('Setup Two-Factor Auth').wait_for(timeout=15000)
        held = [c for c in backend.calls if c[3] == 'MFA_ENROLMENT_REQUIRED']
        assert not held, f'the portal asked for what the server holds back: {held}'

        code = pyotp.TOTP(page.locator('#tfa-form').locator('xpath=..').locator('code')
                          .inner_text().strip()).now()
        mark = len(backend.calls)
        page.locator('#tfa-code').fill(code)
        page.locator('#tfa-form button[type="submit"]').click()
        page.get_by_text('2FA enabled successfully').wait_for(timeout=10000)
        page.wait_for_timeout(800)
        after = backend.calls[mark:]

        assert ('POST', '/api/auth/2fa/verify', 200, None) in after, after
        assert [c for c in after if c[1].endswith('/my-vms')], 'the list was not loaded after enrolment'
        assert not [c for c in after if c[3] == 'MFA_ENROLMENT_REQUIRED'], after
        assert not errors, errors
    finally:
        ctx.close()
