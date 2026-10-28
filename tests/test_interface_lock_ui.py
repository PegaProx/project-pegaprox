"""The interface lock in the browser (#1189, #1167).

An admin pins the layout and/or the language for everyone under Settings > Server. The
server holds the line (tests/test_interface_lock_1189.py); the page follows the lock it
reads from GET /api/interface/lock: the login page shows the pinned language, a held
account opens in the pinned layout without the first-login picker, and every switch it
could not use is gone, with a line in My Profile that says who set it. Admins are exempt
unless the lock says otherwise.

A refused save brings the lock along, so a page whose own read failed (a proxy, the
timeout) follows it at the first refusal instead of refusing every pick without a word.
A failed read keeps what the page had. The Corporate top bar toggle of a user pinned
there from another layout of their own stays in this browser: the stored theme belongs
to their own layout.

The runtime tests drive the built bundle in headless Chromium against the fake server of
test_ha_ui.py, with the lock, the preferences and the settings save answered the way the
real routes answer them. They skip where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import (  # noqa: F401  (browser is a fixture)
    BASE, LANGS, SRC, SSE_TOKEN, TOASTS_JS, _App, _FakeServer, _blocks, _classes, _read, browser)

KEYS = ('uiLockTitle', 'uiLockDesc', 'uiLockLayout', 'uiLockLanguage', 'uiLockUsersChoose',
        'uiLockAdmins', 'uiLockAdminsHint', 'uiLayoutLockedHint', 'uiLanguageLockedHint')
HA_CHAIN = '// LW Oct 2026 (#625) - the banners of a group that fails over automatically, for every user'
CARD_START = '<div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4" data-ui-lock-card>'
CARD_END = '{/* Login Background - NS Mar 2026 */}'
CTX_START = '// LW Oct 2026 (#1189, #1167) - the layout and language an admin pinned for everyone in'
CTX_END = 'function LanguageProvider({ children }) {'
DASHES = (chr(0x2014), chr(0x2013))


def _value(block, key):
    found = re.search(rf"^\s*{key}: '((?:[^'\\]|\\.)*)',$", block, re.M)
    assert found, key
    return found.group(1).replace("\\'", "'")


def _between(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


@pytest.fixture(scope='module')
def card():
    return _between(_read('web', 'src', 'settings_modal.js'), CARD_START, CARD_END)


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS:
        found = len(re.findall(rf'^\s*{key}:', block, re.M))
        assert found == 1, f'{key} is {found} times in {lang} - t() would show the raw key or the wrong one'


@pytest.mark.parametrize('lang', LANGS)
def test_the_new_keys_stay_out_of_the_pinned_ha_chain(lang):
    block = _blocks()[lang]
    chain = block.index(HA_CHAIN)
    for key in KEYS:
        assert block.index(f'{key}:') < chain, (lang, key)


@pytest.mark.parametrize('lang', LANGS)
def test_the_description_names_the_option_the_select_shows(lang):
    # "... once this is set to Users choose again": the words of the first option
    block = _blocks()[lang]
    assert _value(block, 'uiLockUsersChoose') in _value(block, 'uiLockDesc'), lang


def test_portuguese_is_the_brazilian_of_its_block():
    block = _blocks()['pt']
    said = ' '.join(_value(block, key) for key in KEYS)
    for european in ('utilizador', 'Definições', 'guardad'):
        assert european not in said, european


def test_the_cloud_rule_is_gone():
    """Cloud opens Users and Settings in place, so it holds admins like any other layout.
    The warning that said otherwise, and its key, are gone."""
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js'):
            assert 'uiLockCloudAdmins' not in _read('web', 'src', name), name
    cloud = _read('web', 'src', 'cloud.js')
    pick = _between(cloud, 'const selectSection = (id) => {', 'const openDetail')
    assert "if (id === 'settings' || id === 'users') { onOpenSettings && onOpenSettings(); return; }" in pick


def test_the_layouts_are_the_ones_the_server_pins(card):
    from pegaprox.api.helpers import UI_LAYOUT_LOCKS
    ctx = _read('web', 'src', 'contexts.js')
    found = re.search(r"const UI_LOCK_LAYOUTS = \[([^\]]*)\];", ctx)
    assert found
    assert re.findall(r"'(\w+)'", found.group(1)) == list(UI_LAYOUT_LOCKS)
    layout_select = _between(card, 'id="ui-layout-lock"', '</select>')
    assert re.findall(r'<option value="(\w*)"', layout_select) == [''] + list(UI_LAYOUT_LOCKS)


def test_the_card_loads_and_sends_its_three_fields(card):
    modal = _read('web', 'src', 'settings_modal.js')
    for key in ('ui_layout_lock', 'ui_language_lock', 'ui_lock_admins'):
        assert f"formData.append('{key}'" in modal, key
        assert f'{key}: data.{key}' in modal, key
    assert "formData.append('ui_lock_admins', serverSettings.ui_lock_admins ? 'true' : 'false')" in modal
    assert 'languageChoices(t).map' in card


def test_no_dash_in_what_this_change_added(card):
    src = _read('web', 'src', 'translations.js')
    added = card + _between(_read('web', 'src', 'contexts.js'), CTX_START, CTX_END) + ''.join(
        line for line in src.splitlines(True) if re.match(rf"^\s*({'|'.join(KEYS)}):", line))
    assert not [d for d in DASHES if d in added]


def test_every_class_is_in_the_static_tailwind_build(card):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(card) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('data-ui-lock-card', 'pegaprox-ui-lock', 'takeRefusedLock', 'uiLanguageLockedHint',
                   '/interface/lock'):
        assert needle in built, needle
    assert 'uiLockCloudAdmins' not in built


# --- runtime -------------------------------------------------------------------------------

NO_LOCK = {'layout': '', 'language': '', 'admins': False}
JSON_HEADERS = {'Content-Type': 'application/json'}
SETTINGS = {'domain': 'pegaprox-b.example', 'port': 5000, 'default_theme': 'proxmoxDark',
            'ui_layout_lock': '', 'ui_language_lock': '', 'ui_lock_admins': False}
# the page logs a refused save; for a UI_LOCKED that is the point of the test
REFUSAL_LOG = 'updatePreferences: Request failed'


class _LockServer(_FakeServer):
    """The fake server plus the lock, the preferences and the settings save, answered the
    way api/settings.py and api/users.py answer them."""

    def __init__(self, lock=None, lock_fails=False, signed_in=True, layout_chosen=True,
                 theme='proxmoxDark', refuse_save=None, **kw):
        kw.setdefault('layout', 'modern')
        kw.setdefault('language', 'de')
        super().__init__(role='standalone', extra={**SSE_TOKEN, ('GET', '/api/plugins'): (200, [])}, **kw)
        self.lock = dict(NO_LOCK, **(lock or {}))
        self.lock_fails = lock_fails
        self.logged_out = not signed_in
        self.prefs = {'ui_layout': self.layout, 'language': self.language, 'theme': theme,
                      'layout_chosen': layout_chosen, 'taskbar_auto_expand': True, 'sidebar_show_vmid': False}
        self.puts = []
        self.settings = dict(SETTINGS, ui_layout_lock=self.lock['layout'],
                             ui_language_lock=self.lock['language'], ui_lock_admins=self.lock['admins'])
        self.saves = []
        self.refuse_save = refuse_save

    def binds(self):
        return bool(self.lock['layout'] or self.lock['language']) and (self.lock['admins'] or not self.admin)

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE):
            return route.abort()

        def answer(data, status=200):
            self.calls.append((req.method, path))
            return route.fulfill(status=status, body=json.dumps(data), headers=JSON_HEADERS)

        if path == '/api/interface/lock':
            if self.lock_fails:
                self.calls.append((req.method, path))
                return route.abort()
            return answer(self.lock)
        if path == '/api/auth/check' and not self.logged_out:
            user = dict(self.prefs, username='admin' if self.admin else 'viewer',
                        role='admin' if self.admin else 'viewer', display_name='Pat',
                        permissions=[], enabled=True, auth_source='local')
            return answer({'authenticated': True, 'session_id': 'sid', 'user': user, 'ha': self.banner(),
                           'default_theme': 'proxmoxDark'})
        if path == '/api/user/preferences' and req.method == 'PUT':
            body = json.loads(req.post_data or '{}')
            if self.binds():
                for field, key in (('ui_layout', 'layout'), ('language', 'language')):
                    if self.lock[key] and field in body and body[field] != self.lock[key]:
                        self.puts.append((403, body))
                        return answer({'error': f'The {key} is set by your administrator', 'code': 'UI_LOCKED',
                                       'field': field, 'lock': self.lock}, 403)
            self.prefs.update(body)
            self.puts.append((200, body))
            return answer(dict(self.prefs, success=True, default_theme='proxmoxDark'))
        if path == '/api/settings/server' and req.method == 'GET':
            return answer(self.settings)
        if path == '/api/settings/server' and req.method == 'POST':
            form = dict(re.findall(r'name="([^"]+)"\r\n\r\n(.*?)\r\n--', req.post_data or '', re.S))
            self.saves.append(form)
            if self.refuse_save:
                return answer({'error': self.refuse_save}, 400)
            self.settings.update({k: form[k] for k in ('ui_layout_lock', 'ui_language_lock') if k in form})
            self.settings['ui_lock_admins'] = form.get('ui_lock_admins') == 'true'
            return answer({'success': True, 'restart_required': False})
        return super().handle(route)


class _Page(_App):
    """_App with a browser locale, a script before the page and the login page or the
    first-login picker as what to wait for."""

    def __init__(self, browser, server, locale='en-US', init_js='', wait='app'):  # noqa: F811
        self.server = server
        self.wait = wait
        self.ctx = browser.new_context(viewport={'width': 1600, 'height': 1000}, locale=locale)
        self.ctx.add_init_script("""try {
            for (const u of ['admin', 'viewer']) localStorage.setItem('pegaprox_sponsor_v2:' + u, String(Date.now() + 1e10));
            localStorage.setItem('pegaprox-shortcuts-hint-shown', '1');
        } catch (e) {}""" + init_js)
        self.page = self.ctx.new_page()
        self.errors = []
        self.loads = []
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('console', self._console)
        self.page.route('**/*', server.handle)
        self.page.goto(BASE + '/', wait_until='load')
        self.wait_for_app()

    def _console(self, msg):
        if REFUSAL_LOG in msg.text:
            return
        super()._console(msg)

    def wait_for_app(self):
        if self.wait == 'login':
            self.page.locator('input[autocomplete="username"]').wait_for(timeout=30000)
            self.page.wait_for_timeout(800)
        elif self.wait == 'picker':
            self.page.locator('[data-layout-pick]').wait_for(timeout=30000)
            self.page.wait_for_timeout(300)
        else:
            super().wait_for_app()

    def layout(self):
        return self.page.evaluate("document.body.getAttribute('data-layout')")

    def switchers(self):
        return self.page.evaluate("""() => document.querySelectorAll(
            'button[title="Deutsch"], select[aria-label="Select language"], .cloud-lang').length""")

    def menu(self):
        """the user menu's text, which says which language the page speaks"""
        self.page.locator('[data-user-menu]').first.click()
        self.page.wait_for_timeout(300)
        text = self.page.locator('div.absolute.right-0.top-full').first.inner_text()
        self.page.locator('div.fixed.inset-0.z-40').last.click(position={'x': 5, 'y': 5})
        self.page.wait_for_timeout(200)
        return text

    def profile(self):
        self.page.locator('[data-user-menu]').first.click()
        self.page.wait_for_timeout(300)
        self.page.locator('div.absolute.right-0.top-full button').filter(
            has_text=re.compile(r'My Profile|Mein Profil|Mon profil')).first.click()
        self.page.get_by_text(re.compile(r'Layout Style|Layout-Stil|Style de mise en page')).first.wait_for(timeout=5000)
        self.page.wait_for_timeout(300)


@pytest.fixture
def open_page(browser):  # noqa: F811
    pages = []

    def _open(locale='en-US', init_js='', wait='app', **kw):
        page = _Page(browser, _LockServer(**kw), locale=locale, init_js=init_js, wait=wait)
        pages.append(page)
        return page
    yield _open
    for page in pages:
        page.ctx.close()


GERMAN_BROWSER = "try { localStorage.setItem('pegaprox-language', 'de'); } catch (e) {}"


@pytest.mark.parametrize('pinned', [True, False], ids=['pinned', 'counter-check'])
def test_runtime_the_login_page_speaks_the_pinned_language(open_page, pinned):
    app = open_page(locale='de-DE', init_js=GERMAN_BROWSER, wait='login', signed_in=False,
                    lock={'language': 'en'} if pinned else None)
    text = app.page.locator('body').inner_text()
    if pinned:
        assert 'Username' in text and 'Benutzername' not in text, text[:300]
        assert app.switchers() == 0
    else:
        assert 'Benutzername' in text, text[:300]
        assert app.switchers() == 1
    # the own choice stays stored for when the lock is lifted
    assert app.page.evaluate("localStorage.getItem('pegaprox-language')") == 'de'
    assert not app.errors, app.errors


def test_runtime_a_held_account_opens_in_the_pin_without_a_switch(open_page):
    app = open_page(admin=False, layout_chosen=False, lock={'layout': 'corporate', 'language': 'en'})
    assert app.page.locator('[data-layout-pick]').count() == 0
    assert app.layout() == 'corporate'
    assert 'My Profile' in app.menu()
    assert app.switchers() == 0
    app.profile()
    assert app.page.locator('[data-ui-lock="layout"]').inner_text() == 'Layout set by your administrator'
    assert app.page.locator('[data-ui-lock="language"]').inner_text() == 'Set by your administrator'
    assert app.page.get_by_text('Cards, animations, gradients').count() == 0
    assert app.switchers() == 0
    assert app.server.puts == []
    assert not app.errors, app.errors


def test_runtime_an_admin_is_exempt_by_default(open_page):
    app = open_page(admin=True, lock={'layout': 'corporate', 'language': 'en'})
    assert app.layout() == 'modern'
    assert 'Mein Profil' in app.menu()
    assert app.switchers() >= 1
    app.profile()
    assert app.page.locator('[data-ui-lock]').count() == 0
    assert app.page.get_by_text(re.compile('Karten, Animationen|Cards, animations')).count() >= 1
    assert not app.errors, app.errors


def test_runtime_an_admin_is_held_when_the_lock_says_so(open_page):
    app = open_page(admin=True, lock={'layout': 'corporate', 'language': 'en', 'admins': True})
    assert app.layout() == 'corporate'
    assert 'My Profile' in app.menu() and app.switchers() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'cloud'])
def test_runtime_a_pinned_language_says_so_in_every_layout(open_page, layout):
    """Modern and Cloud have their switcher in the top bar, not in My Profile. With the
    language pinned the top bar has none, so the profile says who set it."""
    app = open_page(admin=False, layout=layout, theme='cloud' if layout == 'cloud' else 'proxmoxDark',
                    lock={'language': 'fr'})
    assert app.layout() == layout
    assert app.switchers() == 0
    if layout == 'cloud':
        app.page.locator('.cloud-user-btn').first.click()
        app.page.get_by_text(re.compile(r'Profil')).first.click()
    else:
        app.profile()
    hint = app.page.locator('[data-ui-lock="language"]')
    hint.wait_for(timeout=5000)
    assert hint.inner_text() == 'Défini par votre administrateur'
    # the layout is not pinned, its cards are there
    assert app.page.locator('[data-ui-lock="layout"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_without_a_pin_the_modern_profile_has_no_language_row(open_page):
    # the counter-check: the row came with the pin, not with this change for everyone
    app = open_page(admin=False, layout='modern')
    app.profile()
    assert app.page.locator('[data-ui-lock]').count() == 0
    assert app.page.get_by_text('Interface language for your account').count() == 0
    assert app.page.get_by_text('Oberflächensprache für Ihr Konto').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_refused_pick_brings_the_lock_when_the_read_failed(open_page):
    """The lock read fails (a proxy, the timeout): the first-login picker shows. The first
    pick the server refuses brings the lock, and the pinned layout takes over."""
    app = open_page(admin=False, layout_chosen=False, lock={'layout': 'corporate'}, lock_fails=True,
                    wait='picker')
    page = app.page
    page.locator('.fixed button').filter(has_text='Modern').first.click()
    page.wait_for_function("() => document.body.getAttribute('data-layout') === 'corporate'", timeout=8000)
    _App.wait_for_app(app)
    assert page.locator('[data-layout-pick]').count() == 0
    assert [status for status, _ in app.server.puts] == [403]
    cached = json.loads(page.evaluate("localStorage.getItem('pegaprox-ui-lock')"))
    assert cached == {'layout': 'corporate', 'language': '', 'admins': False}
    assert not app.errors, app.errors


def test_runtime_a_pick_without_a_lock_still_lands(open_page):
    # the counter-check: the same failed read with nothing pinned, the pick is saved
    app = open_page(admin=False, layout_chosen=False, lock_fails=True, wait='picker')
    app.page.locator('.fixed button').filter(has_text='Corporate').first.click()
    app.page.wait_for_function("() => document.body.getAttribute('data-layout') === 'corporate'", timeout=8000)
    assert [status for status, _ in app.server.puts] == [200]
    assert app.server.prefs['layout_chosen'] is True
    assert not app.errors, app.errors


def test_runtime_a_language_pinned_after_the_page_loaded_takes_over_at_the_refusal(open_page):
    app = open_page(admin=False, layout='modern', language='de')
    assert app.switchers() >= 1 and 'Mein Profil' in app.menu()
    app.server.lock = {'layout': '', 'language': 'fr', 'admins': False}
    app.page.locator('button[title="English"]').first.click()
    app.page.wait_for_function('() => !document.querySelector(\'button[title="Deutsch"]\')', timeout=8000)
    assert 'Mon profil' in app.menu()
    assert [status for status, _ in app.server.puts] == [403]
    assert app.server.prefs['language'] == 'de'
    assert not app.errors, app.errors


@pytest.mark.parametrize('cached', [True, False], ids=['cached', 'counter-check'])
def test_runtime_a_failed_read_keeps_the_last_lock(open_page, cached):
    last = json.dumps({'layout': 'corporate', 'language': 'en', 'admins': False})
    init = f"try {{ localStorage.setItem('pegaprox-ui-lock', '{last}'); }} catch (e) {{}}" if cached else ''
    app = open_page(admin=False, layout='modern', language='de', lock_fails=True, init_js=init)
    assert ('/api/interface/lock' in [p for _, p in app.server.calls])
    if cached:
        assert app.layout() == 'corporate' and 'My Profile' in app.menu() and app.switchers() == 0
    else:
        assert app.layout() == 'modern' and 'Mein Profil' in app.menu() and app.switchers() >= 1
    assert not app.errors, app.errors


TOGGLE = 'button[title="Light Mode"], button[title="Dark Mode"], button[title="Follow system"]'


@pytest.mark.parametrize('own', ['modern', 'corporate'])
def test_runtime_the_corporate_toggle_keeps_a_foreign_theme_in_this_browser(open_page, own):
    """Pinned into Corporate from Modern: the toggle paints, and stores nothing, since the
    stored theme is Modern's. A user whose own layout is Corporate still stores it."""
    app = open_page(admin=False, layout=own, language='en', lock={'layout': 'corporate'})
    assert app.layout() == 'corporate'
    painted = []
    for _ in range(3):
        app.page.locator(TOGGLE).first.click()
        app.page.wait_for_timeout(400)
        painted.append(app.page.evaluate("localStorage.getItem('pegaprox-theme')"))
    themes = [body.get('theme') for _, body in app.server.puts if 'theme' in body]
    # the toggle does its job on the page either way: system, light, dark
    assert painted == ['system', 'corporateLight', 'corporateDark'], painted
    if own == 'modern':
        assert themes == []
        assert app.server.prefs['theme'] == 'proxmoxDark'
        # and the pinned Corporate keeps the last pick in this browser
        assert app.page.evaluate("localStorage.getItem('corp-theme')") == ''
    else:
        assert len(themes) == 3 and 'corporateLight' in themes, themes
    assert not app.errors, app.errors


def _to_server_tab(app):
    page = app.page
    app.open_settings()
    page.get_by_role('button', name='Server', exact=True).first.click()
    page.locator('[data-ui-lock-card]').wait_for(timeout=10000)
    page.wait_for_timeout(800)
    page.locator('[data-ui-lock-card]').scroll_into_view_if_needed()
    return page


def _save(app):
    before = len(app.server.saves)
    btn = app.page.locator('button.px-6').filter(has_text=re.compile(r'^\s*Save Settings\s*$')).last
    btn.scroll_into_view_if_needed()
    btn.click()
    for _ in range(50):
        if len(app.server.saves) > before:
            break
        app.page.wait_for_timeout(100)
    assert len(app.server.saves) > before, app.server.calls[-5:]
    app.page.wait_for_timeout(600)
    return app.server.saves[-1]


def test_runtime_the_card_shows_the_lock_and_saves_it(open_page):
    app = open_page(admin=True, language='en', lock={'layout': 'corporate', 'language': 'en'})
    page = _to_server_tab(app)
    card = page.locator('[data-ui-lock-card]')
    assert 'Interface defaults' in card.inner_text() and 'Also apply to administrators' in card.inner_text()
    assert page.locator('#ui-layout-lock').input_value() == 'corporate'
    assert page.locator('#ui-language-lock').input_value() == 'en'
    assert not card.locator('input[type=checkbox]').is_checked()
    languages = page.locator('#ui-language-lock option').evaluate_all('os => os.map(o => o.value)')
    assert languages == ['', 'de', 'en', 'it', 'fr', 'es', 'pt', 'ko', 'zh', 'pl']

    # Cloud for the admins too is a lock like any other
    page.locator('#ui-layout-lock').select_option('cloud')
    page.locator('#ui-language-lock').select_option('pl')
    card.locator('input[type=checkbox]').check()
    assert card.locator('.text-yellow-400').count() == 0
    sent = _save(app)
    assert (sent['ui_layout_lock'], sent['ui_language_lock'], sent['ui_lock_admins']) == ('cloud', 'pl', 'true')
    # and back to users choose, admins off
    page.locator('#ui-layout-lock').select_option('')
    page.locator('#ui-language-lock').select_option('')
    card.locator('input[type=checkbox]').uncheck()
    sent = _save(app)
    assert (sent['ui_layout_lock'], sent['ui_language_lock'], sent['ui_lock_admins']) == ('', '', 'false')
    assert not app.errors, app.errors


def test_runtime_the_card_shows_the_servers_refusal(open_page):
    refusal = 'ui_layout_lock is empty or one of modern, corporate, cloud'
    app = open_page(admin=True, language='en', refuse_save=refusal)
    page = _to_server_tab(app)
    page.locator('#ui-layout-lock').select_option('modern')
    _save(app)
    toasts = page.evaluate(TOASTS_JS)
    assert any(refusal in t for t in toasts), toasts
    assert not app.errors, app.errors
