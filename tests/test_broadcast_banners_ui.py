"""The broadcast banners in the web UI.

Two pieces: BroadcastBanners (dashboard.js) puts what /api/banners sends at the top of the
page in Modern, Corporate and Cloud, closable per user until the text changes; and the
Banners tab of the settings modal (BroadcastBannerSettings in settings_modal.js) where an
admin writes them. The routes are tested in test_broadcast_banners.py.

The source checks hold the translations, the classes and the icons; the runtime tests drive
the built bundle in headless Chromium against the fake server of test_ha_ui.py, with the
banner routes added. They skip where Playwright is not installed.
LW
"""
import json
import os
import re
import time

import pytest

from test_ha_ui import (  # noqa: F401  (browser is a fixture)
    LANGS, SRC, _App, _FakeServer, _block, _blocks, _classes, _follows, _function, _read, _toasts,
    _wait_for_toast, browser)

EM_DASH = chr(0x2014)
REFUSED = 'Banners are managed by administrators who are not limited to a tenant or to specific clusters'
# would run if the text went in as markup
HOSTILE = '<img src=x onerror="window.__pwned=1"><b>bold</b> & more'


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


@pytest.fixture(scope='module')
def bar(dash):
    return _block(dash, '// LW Oct 2026 - the broadcast banners an admin writes', '// LW Sep 2026 (#625) - on a standby')


@pytest.fixture(scope='module')
def editor(modal):
    return _block(modal, '// LW Oct 2026 - Settings > Banners', '// PegaProx - Settings Modal')


# -- source ------------------------------------------------------------------------------------------

def test_the_text_goes_in_as_text(bar, editor):
    for block in (bar, editor):
        assert 'dangerouslySetInnerHTML' not in block and 'innerHTML' not in block
    assert '>{b.text}</span>' in bar
    assert '>{b.text}</div>' in editor


def test_every_layout_mounts_the_bar(dash):
    main = dash[dash.index('function PegaProxDashboard('):]
    at = main.index('<BroadcastBanners />')
    # Modern and Corporate share the return after the cloud branch, above the password banner
    assert main.index('if (isCloud) {') < at < main.index('<PasswordExpiryBanner onChangePassword=')
    shell = _function(_read('web', 'src', 'cloud.js'), 'CloudShell')
    assert shell.index('<CloudTopbar') < shell.index('<BroadcastBanners cloud />') < shell.index('<HaStandbyBanner cloud')


def test_the_tab_is_for_admins_and_the_standby_only_lists(modal, editor):
    component = _function(modal, 'PegaProxSettingsModal')
    button_at = component.index("onClick={() => setActiveTab('banners')}")
    gate_at = component.rindex('{isAdmin && (', 0, button_at)
    assert component[gate_at:button_at].count('<button') == 1
    assert "{activeTab === 'banners' && isAdmin && (" in component
    # every control that writes asks haStandby, the note takes their place
    assert 'const { haStandby } = useAuth();' in editor
    assert '{data && !haStandby && !editing && (' in editor
    assert '{!haStandby && form}' in editor
    assert '{data && haStandby && <HaSettingsOnActive />}' in editor
    assert editor.count('{!haStandby && (') == 1


def _used():
    keys = set()
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js') and name != 'translations.js':
            keys.update(re.findall(r"'(bcast\w+)'", _read('web', 'src', name)))
    return keys


def test_every_key_is_used_and_defined_once_per_language():
    used = _used()
    assert len(used) == 26, sorted(used)
    for lang, block in _blocks().items():
        defined = re.findall(r'^ +(bcast\w+): ', block, re.M)
        assert sorted(defined) == sorted(used), (lang, sorted(set(defined) ^ used))
        assert len(defined) == len(set(defined)), lang


def test_placeholders_survive_and_no_em_dash():
    blocks = _blocks()
    for key in _used():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)
            assert EM_DASH not in value, (lang, key)
    # the Austrian flag stays on 'de'
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9', label: 'DE'" in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_the_new_code(bar, editor):
    assert EM_DASH not in bar and EM_DASH not in editor


def test_every_icon_exists(bar, editor):
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'<Icons\.(\w+)', bar + editor))
    assert used, 'no icons found'
    missing = sorted(i for i in used if not re.search(r'^\s+%s: ' % i, icons, re.M))
    assert not missing, missing


def test_every_class_is_in_the_static_tailwind_build(bar, editor, modal):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    tab = modal[modal.index("onClick={() => setActiveTab('banners')}"):]
    tab = tab[:tab.index('</button>')]
    names = _classes(bar) | _classes(editor) | _classes(tab)
    names -= {'input'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function BroadcastBanners(', 'function BroadcastBannerSettings(', 'pegaprox-banners-changed',
                   'pegaprox-banners-closed:', "setActiveTab('banners')"):
        assert needle in bundle, needle
    for key in _used():
        assert key in bundle, key


# -- runtime -------------------------------------------------------------------------------------------

class _BannerServer(_FakeServer):
    """The fake of test_ha_ui with the banner routes. Every running banner goes to every user
    here; who gets which is the server's business (test_broadcast_banners.py)."""

    def __init__(self, banners=(), refuse_list='', role='standalone', **kw):
        super().__init__(role=role, **kw)
        self.store = [dict(b) for b in banners]
        self.refuse_list = refuse_list
        self.made = 0

    def _running(self):
        now = time.time()
        return [b for b in self.store if b.get('ends') is None or b['ends'] > now]

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith('http://pegaprox.test') or not (
                path == '/api/banners' or path.startswith('/api/settings/banners')):
            return super().handle(route)
        self.calls.append((req.method, path))
        body = json.loads(req.post_data) if req.post_data else {}
        if req.method != 'GET':
            self.bodies.setdefault(path, []).append(body)

        def answer(data, status=200):
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

        now = time.time()
        if path == '/api/banners':
            return answer({'banners': [{'id': b['id'], 'text': b['text'], 'severity': b['severity'], 'rev': b['rev'],
                                        'expires_at': b.get('expires_at'),
                                        'expires_in': int(b['ends'] - now) if b.get('ends') else None}
                                       for b in self._running()]})
        if req.method == 'GET':
            if self.refuse_list:
                return answer({'error': self.refuse_list}, 403)
            return answer({
                'banners': [dict({k: v for k, v in b.items() if k != 'ends'},
                                 expired=b.get('ends') is not None and b['ends'] <= now) for b in self.store],
                'limits': {'text': 500, 'count': 20, 'targets': 50},
                'choices': {'tenants': [{'id': 'default', 'name': 'Default'}, {'id': 'acme', 'name': 'Acme'}],
                            'roles': [{'id': r, 'name': r, 'tenants': []} for r in ('admin', 'user', 'viewer')]},
            })
        if self.role == 'standby':
            return answer({'error': 'This is a standby instance.', 'code': 'HA_STANDBY'}, 409)
        if path == '/api/settings/banners':
            self.made += 1
            b = {'id': f'{self.made:016x}', 'text': body['text'], 'severity': body['severity'],
                 'scope': body['scope'], 'tenants': body['tenants'], 'roles': body['roles'],
                 'expires_at': body.get('expires_at') or None, 'rev': 1}
            self.store.append(b)
            return answer({'success': True, 'banner': b}, 201)
        bid = path.rsplit('/', 1)[1]
        b = next((x for x in self.store if x['id'] == bid), None)
        if b is None:
            return answer({'error': 'Banner not found'}, 404)
        if req.method == 'DELETE':
            self.store.remove(b)
            return answer({'success': True})
        if body.get('text') not in (None, b['text']):
            b['rev'] += 1
        b.update({k: v for k, v in body.items() if k in ('text', 'severity', 'scope', 'tenants', 'roles', 'expires_at')})
        return answer({'success': True, 'banner': b})


def _banner(n, text='Maintenance tonight at 22:00', severity='warning', rev=1, ends=None, **more):
    return dict({'id': f'{n:016x}', 'text': text, 'severity': severity, 'scope': 'everyone', 'tenants': [],
                 'roles': [], 'expires_at': None, 'rev': rev, 'ends': ends}, **more)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _BannerServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _bars(page):
    return page.locator('[data-broadcast-banner]')


def _wait(page, cond, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if cond():
            return True
        page.wait_for_timeout(100)
    return cond()


def test_runtime_modern_shows_it_as_text_above_the_header_and_close_holds_until_the_text_changes(open_app):
    app = open_app(layout='modern', banners=[_banner(1, text=HOSTILE)])
    page = app.page
    bar = page.locator('[data-broadcast-banner="%016x"]' % 1)
    assert bar.is_visible()
    assert bar.get_attribute('data-broadcast-layout') == 'classic'
    assert bar.get_attribute('data-broadcast-severity') == 'warning'
    assert bar.inner_text().strip() == HOSTILE
    assert bar.locator('img').count() == 0 and bar.locator('b').count() == 0
    assert page.evaluate('() => window.__pwned') is None
    assert _follows(page, '[data-broadcast-banner]', 'header')

    bar.get_by_role('button', name='Close').click()
    assert _bars(page).count() == 0
    assert page.evaluate("() => localStorage.getItem('pegaprox-banners-closed:admin')") == json.dumps({'%016x' % 1: 1}).replace(' ', '')
    # closed for this user, also after a reload, while the server still sends it
    page.reload(wait_until='load')
    app.wait_for_app()
    asked = app.server.calls.count(('GET', '/api/banners'))
    assert asked >= 2
    assert _bars(page).count() == 0

    # the admin changes the text: a new revision, and it is back
    app.server.store[0].update(text='Maintenance moved to 23:00', rev=2)
    page.evaluate("() => window.dispatchEvent(new CustomEvent('pegaprox-banners-changed'))")
    assert _wait(page, lambda: _bars(page).count() == 1)
    assert _bars(page).first.inner_text().strip() == 'Maintenance moved to 23:00'
    assert not app.errors, app.errors


def test_runtime_closed_is_per_user(open_app):
    app = open_app(layout='modern', admin=False, banners=[_banner(7)])
    page = app.page
    assert _bars(page).count() == 1
    # what the admin closed in this browser is theirs
    page.evaluate("() => localStorage.setItem('pegaprox-banners-closed:admin', JSON.stringify({'%016x': 1}))" % 7)
    page.reload(wait_until='load')
    app.wait_for_app()
    assert _bars(page).count() == 1
    page.evaluate("() => localStorage.setItem('pegaprox-banners-closed:viewer', JSON.stringify({'%016x': 1}))" % 7)
    page.reload(wait_until='load')
    app.wait_for_app()
    assert _bars(page).count() == 0
    assert not app.errors, app.errors


def test_runtime_each_severity_has_its_tone_in_the_order_given(open_app):
    app = open_app(layout='modern', banners=[_banner(1, 'Disk array degraded', 'critical'),
                                             _banner(2, 'Patch window tonight', 'warning'),
                                             _banner(3, 'New templates available', 'info')])
    page = app.page
    bars = _bars(page)
    assert bars.count() == 3
    assert [bars.nth(i).get_attribute('data-broadcast-severity') for i in range(3)] == ['critical', 'warning', 'info']
    assert [bars.nth(i).get_attribute('role') for i in range(3)] == ['alert', 'status', 'status']
    for i, colour in enumerate(('red', 'yellow', 'blue')):
        assert f'bg-{colour}-500/10' in bars.nth(i).get_attribute('class'), i
    # closing one leaves the others
    bars.nth(1).get_by_role('button', name='Close').click()
    assert [bars.nth(i).get_attribute('data-broadcast-severity') for i in range(bars.count())] == ['critical', 'info']
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout,kind', [('corporate', 'classic'), ('cloud', 'cloud')])
def test_runtime_corporate_and_cloud_show_it(open_app, layout, kind):
    app = open_app(layout=layout, banners=[_banner(1, 'Disk array degraded', 'critical')])
    page = app.page
    bar = page.locator(f'[data-broadcast-layout="{kind}"]')
    assert bar.is_visible()
    assert 'Disk array degraded' in bar.inner_text()
    if layout == 'cloud':
        assert page.locator('.cloud-content [data-broadcast-layout="cloud"]').count() == 1
    else:
        assert _follows(page, '[data-broadcast-banner]', 'header')
    bar.get_by_role('button', name='Close').click()
    assert _bars(page).count() == 0
    assert not app.errors, app.errors


def test_runtime_it_goes_when_it_runs_out(open_app):
    app = open_app(layout='modern', banners=[_banner(1)])
    page = app.page
    assert _bars(page).count() == 1
    # the expiry is set once the page is up: a slow start would otherwise eat it
    app.server.store[0]['ends'] = time.time() + 3
    page.evaluate("() => window.dispatchEvent(new CustomEvent('pegaprox-banners-changed'))")
    page.wait_for_timeout(500)
    assert _bars(page).count() == 1
    before = app.server.calls.count(('GET', '/api/banners'))
    assert _wait(page, lambda: _bars(page).count() == 0, seconds=8)
    # looked again when it ran out, not only on the next minute
    assert app.server.calls.count(('GET', '/api/banners')) > before
    assert not app.errors, app.errors


def _open_banners(app, layout):
    page = app.page
    if layout == 'cloud':
        page.locator('button[title="Settings"]').first.click()
        page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)
    else:
        app.open_settings()
    page.get_by_role('button', name='Banners', exact=True).first.click()
    page.locator('[data-banner-settings]').wait_for(timeout=5000)
    return page.locator('[data-banner-settings]')


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_an_admin_writes_edits_and_deletes_one(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    panel = _open_banners(app, layout)
    assert 'No banners' in panel.inner_text()
    panel.get_by_role('button', name='New banner').click()
    form = panel.locator('[data-banner-form="new"]')
    save = form.get_by_role('button', name='Save')
    assert save.is_disabled()
    page.fill('#bcast-text', 'Viewers: the reporting cluster is read-only today')
    page.select_option('#bcast-severity', 'critical')
    form.get_by_label('Roles').check()
    assert save.is_disabled(), 'a role banner needs a role'
    form.locator('[data-banner-picker="roles"]').get_by_label('viewer').check()
    local = page.evaluate('''() => { const d = new Date(Date.now() + 86400000); const p = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }''')
    page.fill('#bcast-expires', local)
    utc = page.evaluate('(v) => new Date(v).toISOString()', local)
    save.click()
    assert _wait_for_toast(page, 'Banner saved')
    assert app.server.bodies['/api/settings/banners'][-1] == {
        'text': 'Viewers: the reporting cluster is read-only today', 'severity': 'critical', 'scope': 'roles',
        'tenants': [], 'roles': ['viewer'], 'expires_at': utc}
    row = panel.locator('[data-banner-row="%016x"]' % 1)
    row.wait_for(timeout=5000)
    assert 'Critical' in row.inner_text() and 'Roles: viewer' in row.inner_text()
    # the bar at the top picks it up at once
    assert _wait(page, lambda: _bars(page).count() == 1)

    row.get_by_role('button', name='Edit').click()
    edit = panel.locator('[data-banner-form="edit"]')
    assert page.input_value('#bcast-expires') == local
    page.fill('#bcast-text', 'Viewers: read-only until noon')
    edit.get_by_role('button', name='Save').click()
    assert _wait_for_toast(page, 'Banner saved')
    put = app.server.bodies['/api/settings/banners/%016x' % 1][-1]
    # the expiry was left alone, so it is not sent
    assert put == {'text': 'Viewers: read-only until noon', 'severity': 'critical', 'scope': 'roles',
                   'tenants': [], 'roles': ['viewer']}
    assert _wait(page, lambda: 'read-only until noon' in (_bars(page).first.inner_text() if _bars(page).count() else ''))

    page.once('dialog', lambda d: d.accept())
    row.get_by_role('button', name='Delete').click()
    assert _wait_for_toast(page, 'Banner deleted')
    assert ('DELETE', '/api/settings/banners/%016x' % 1) in app.server.calls
    assert _wait(page, lambda: _bars(page).count() == 0)
    assert panel.locator('[data-banner-row]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_refused_save_says_why(open_app):
    app = open_app(layout='modern', banners=[_banner(n) for n in range(1, 21)])
    panel = _open_banners(app, 'modern')
    assert panel.get_by_role('button', name='New banner').is_disabled()
    assert 'At most 20 banners - delete one to add another' in panel.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_standby_lists_them_and_offers_no_change(open_app):
    app = open_app(role='standby', layout='modern', banners=[_banner(1)])
    page = app.page
    assert _bars(page).count() == 1
    panel = _open_banners(app, 'modern')
    panel.locator('[data-banner-row="%016x"]' % 1).wait_for(timeout=5000)
    assert panel.locator('[data-ha-settings-on-active="shared"]').count() == 1
    for name in ('New banner', 'Edit', 'Delete', 'Save'):
        assert panel.get_by_role('button', name=name).count() == 0, name
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'banners' in c[1]]
    assert not app.errors, app.errors


def test_runtime_a_confined_admin_reads_the_refusal(open_app):
    app = open_app(layout='modern', refuse_list=REFUSED)
    panel = _open_banners(app, 'modern')
    page = app.page
    panel.locator('[data-banner-refused]').wait_for(timeout=5000)
    assert panel.locator('[data-banner-refused]').inner_text() == REFUSED
    assert panel.get_by_role('button', name='New banner').count() == 0
    assert not page.locator('[data-banner-row]').count()
    assert not app.errors, app.errors


def test_runtime_a_viewer_gets_the_bar_and_no_tab(open_app):
    app = open_app(layout='modern', admin=False, banners=[_banner(1)])
    assert _bars(app.page).count() == 1
    app.open_settings()
    assert app.page.get_by_role('button', name='Banners', exact=True).count() == 0
    assert ('GET', '/api/settings/banners') not in app.server.calls
    assert not app.errors, app.errors


def test_runtime_the_tab_speaks_german(open_app):
    app = open_app(layout='modern', language='de', banners=[_banner(1, severity='info')])
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.get_by_role('button', name='Banner', exact=True).first.click()
    panel = page.locator('[data-banner-settings]')
    panel.wait_for(timeout=5000)
    text = panel.inner_text()
    assert 'Hinweisbanner' in text and 'Neues Banner' in text and 'Ohne Ablauf' in text and 'Alle' in text
    assert _bars(page).first.get_by_role('button', name='Schließen').count() == 1
    assert not app.errors, app.errors
