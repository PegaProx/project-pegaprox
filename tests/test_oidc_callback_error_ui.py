"""The login page says why an OIDC sign-in was refused.

checkSession() leaves /api/auth/check alone while the URL carries code and state, so its
logout cannot race the callback POST. That left oidcEnabled at its default false on the
callback page, and the callback error sat inside the oidcEnabled block: a refused sign-in
came back to a bare password form, with neither the reason nor the SSO button.

Now the callback page reads the public OIDC config (it does not touch the session) for
the button, and the error shows whether the button state is known or not, behind the
translated "Login failed".

The source tests run everywhere; the runtime ones drive the built bundle in headless
Chromium against a fake server and skip where Playwright is not installed.

LW Nov 2026
"""
import json
import re

import pytest

from test_ha_ui import BASE, LANGS, ROOT, _read, browser  # noqa: F401 - browser is a fixture

REFUSAL = 'Authentication failed - Failed to validate identity token'
BUTTON = 'Sign in with Corp IdP'
LOGIN_FAILED = {'en': 'Login failed', 'de': 'Anmeldung fehlgeschlagen'}


def _function_body(src, start):
    i = src.index(start)
    depth, j = 0, src.index('{', i)
    for k in range(j, len(src)):
        depth += {'{': 1, '}': -1}.get(src[k], 0)
        if depth == 0:
            return src[i:k + 1]
    raise AssertionError(start)


def _jsx_block(src, opener):
    """The text of a `{cond && ( ... )}` block, by its parentheses."""
    i = src.index(opener)
    depth = 0
    for k in range(i + len(opener) - 1, len(src)):
        depth += {'(': 1, ')': -1}.get(src[k], 0)
        if depth == 0:
            return src[i:k + 1]
    raise AssertionError(opener)


# --- source ---------------------------------------------------------------------------------

def test_the_error_is_not_inside_the_sso_button_block():
    login = _function_body(_read('web', 'src', 'auth.js'), 'function LoginScreen(')
    block = _jsx_block(login, '{oidcEnabled && (')
    assert 'oidcError' not in block, 'the callback error only shows once the button state is known'
    shown = re.search(r'\{oidcError && \(\s*<p[^>]*data-oidc-error[^>]*>\s*\{t\(\'loginError\'\)\}: \{oidcError\}',
                      login)
    assert shown, 'the error paragraph with the translated lead is gone'


def test_the_callback_page_reads_the_public_oidc_config_and_nothing_else():
    check = _function_body(_read('web', 'src', 'contexts.js'), 'const checkSession = async')
    early = check[check.index("_sp.get('code') && _sp.get('state')"):check.index('setLoading(false);\n')]
    assert '/auth/oidc/config' in early and 'setOidcEnabled' in early and 'setOidcButtonText' in early
    for nope in ('/auth/check', 'logout(', '/auth/logout'):
        assert nope not in early, nope


@pytest.mark.parametrize('lang', LANGS)
def test_the_lead_is_translated_in_every_language(lang):
    src = _read('web', 'src', 'translations.js')
    starts = {m.group(1): m.start() for m in re.finditer(r'^            ([a-z]{2}): \{', src, re.M)}
    order = sorted(starts.values())
    begin = starts[lang]
    end = next((p for p in order if p > begin), len(src))
    keys = re.findall(r"^                loginError: '([^']+)'", src[begin:end], re.M)
    assert len(keys) == 1 and keys[0].strip(), (lang, keys)


# --- runtime --------------------------------------------------------------------------------

class _Server:
    """The login page's side of a refused callback: /auth/check says signed out."""

    def __init__(self, config=(200, {'enabled': True, 'provider': 'generic', 'button_text': BUTTON}),
                 callback=(401, {'error': REFUSAL})):
        self.config, self.callback, self.calls = config, callback, []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE):
            return route.abort()
        if path in ('/', '/index.html', '/oidc/callback'):
            return route.fulfill(status=200, body=_read('web', 'index.html'),
                                 headers={'Content-Type': 'text/html; charset=utf-8'})
        for prefix, ctype in (('/static/', None), ('/i18n/', 'application/json')):
            if path.startswith(prefix):
                fp = ROOT + ('/web' if prefix == '/i18n/' else '') + path
                try:
                    with open(fp, 'rb') as fh:
                        body = fh.read()
                except OSError:
                    return route.fulfill(status=404, body='')
                ctype = ctype or ('text/css' if fp.endswith('.css') else 'application/javascript')
                return route.fulfill(status=200, body=body, headers={'Content-Type': ctype})
        if not path.startswith('/api/'):
            return route.fulfill(status=404, body='')
        self.calls.append((req.method, path))

        def answer(status, data):
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        if path == '/api/auth/oidc/config':
            return answer(*self.config)
        if path == '/api/auth/oidc/callback' and req.method == 'POST':
            return answer(*self.callback)
        if path == '/api/auth/check':
            return answer(401, {'authenticated': False, 'oidc_enabled': self.config[1].get('enabled', False),
                                'oidc_button_text': BUTTON, 'initialized': True})
        return answer(404, {'error': 'not mocked'})


def _open(browser, server, lang='en'):
    ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
    ctx.add_init_script(f"try {{ localStorage.setItem('pegaprox-language', '{lang}'); }} catch (e) {{}}")
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.route('**/*', server.handle)
    page.goto(BASE + '/oidc/callback?code=the-code&state=the-state', wait_until='load')
    return ctx, page, errors


@pytest.mark.parametrize('lang', ['en', 'de'])
def test_runtime_a_refused_callback_shows_its_reason_and_the_sso_button(browser, lang):
    server = _Server()
    ctx, page, errors = _open(browser, server, lang)
    try:
        # the reason is on the page at all, then how it reads
        page.get_by_text(REFUSAL).first.wait_for(timeout=15000)
        assert page.locator('[data-oidc-error]').inner_text().strip() == f'{LOGIN_FAILED[lang]}: {REFUSAL}'
        page.get_by_role('button', name=BUTTON).wait_for(timeout=5000)
        # no session check and no logout on the callback page, so nothing raced the POST
        assert ('POST', '/api/auth/oidc/callback') in server.calls
        assert not [c for c in server.calls if c[1] in ('/api/auth/check', '/api/auth/logout')], server.calls
        assert page.evaluate('() => window.location.search') == ''
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize('config', [(200, {'enabled': False, 'provider': 'generic', 'button_text': BUTTON}),
                                    (500, {'error': 'down'})], ids=['oidc-off-by-now', 'config-unreadable'])
def test_runtime_the_reason_shows_without_the_sso_button_too(browser, config):
    server = _Server(config=config, callback=(403, {'error': 'User account does not exist. Contact an administrator.'}))
    ctx, page, errors = _open(browser, server)
    try:
        page.get_by_text('User account does not exist').first.wait_for(timeout=15000)
        assert page.locator('[data-oidc-error]').inner_text().strip() == \
            'Login failed: User account does not exist. Contact an administrator.'
        page.wait_for_timeout(500)
        assert page.get_by_role('button', name=BUTTON).count() == 0
        assert errors == []
    finally:
        ctx.close()
