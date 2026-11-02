"""Corporate Redesigned (Preview): the layout id and where it is wired in.

corporate-redesigned is Corporate with a scoped skin on top. The server stores it like any
other layout, a lock never names it, and a lock to corporate pins its users to the classic
one. In the browser useLayout() reports it as Corporate (isCorporate) plus isCorpRedesigned,
the body keeps data-layout="corporate" and carries data-corp-variant="redesigned"; every
other layout ends without that attribute. The runtime part drives the built bundle through
the fake server of tests/test_ha_ui.py and skips without Playwright. LW Oct 2026
"""
import json
import os
import re

import pytest

from tests.conftest import _seed_user

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'src')
# the files of the preview, in build order
CR_FILES = ('cr.js', 'cr_views.js', 'cr_topology.js', 'cr_compliance.js', 'cr_tasks.js', 'cr_datastore.js', 'cr_drift.js',
            'cr_storage.js', 'cr_vm.js', 'cr_reports.js', 'cr_whatif.js', 'cr_harden.js', 'cr_alerts.js', 'cr_datacenter.js',
            'cr_updates.js', 'cr_perf.js', 'cr_vmcfg.js', 'cr_node.js', 'cr_nodecfg.js', 'cr_nodestore.js', 'cr_nodemisc.js', 'cr_modules.js')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# --- server ------------------------------------------------------------------------------------

def _person(db, name, layout='modern'):
    _seed_user(db, name, role='user')
    row = db.get_user(name)
    row.update({'ui_layout': layout, 'language': 'en', 'theme': 'proxmoxDark', 'layout_chosen': True})
    db.save_user(name, row)
    out = db.get_user(name)
    out['username'] = name
    return out


def _pin(db, layout):
    db.save_server_setting('ui_layout_lock', layout)
    db.save_server_setting('ui_language_lock', '')
    db.save_server_setting('ui_lock_admins', False)


def test_the_preferences_take_the_new_id_and_hand_it_back(api, db):
    alice = api.as_user(_person(db, 'alice'))
    r = alice.put('/api/user/preferences', json={'ui_layout': 'corporate-redesigned', 'theme': 'corporateDark'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('alice')['ui_layout'] == 'corporate-redesigned'
    assert alice.get('/api/user/preferences').get_json()['ui_layout'] == 'corporate-redesigned'


@pytest.mark.parametrize('value', ['corporate-redesigned2', 'Corporate-Redesigned', 'redesigned', 'corporate '])
def test_anything_near_it_is_still_refused(api, db, value):
    alice = api.as_user(_person(db, 'alice', layout='corporate'))
    r = alice.put('/api/user/preferences', json={'ui_layout': value})
    assert r.status_code == 400
    assert db.get_user('alice')['ui_layout'] == 'corporate'


def test_a_corporate_lock_refuses_the_preview_and_keeps_the_stored_choice(api, db):
    _pin(db, 'corporate')
    alice = api.as_user(_person(db, 'alice', layout='corporate-redesigned'))
    r = alice.put('/api/user/preferences', json={'ui_layout': 'corporate-redesigned'})
    assert (r.status_code, r.get_json().get('code')) == (403, 'UI_LOCKED')
    # what the user picked stays stored: lifting the lock gives it back
    assert db.get_user('alice')['ui_layout'] == 'corporate-redesigned'
    _pin(db, '')
    r = alice.put('/api/user/preferences', json={'ui_layout': 'corporate-redesigned'})
    assert r.status_code == 200


def test_a_lock_cannot_name_the_preview(api, db):
    from pegaprox.api.helpers import UI_LAYOUT_LOCKS
    assert tuple(UI_LAYOUT_LOCKS) == ('modern', 'corporate', 'cloud')
    root = api.as_user(_seed_user(db, 'root', role='admin'))
    r = root.post('/api/settings/server', json={'ui_layout_lock': 'corporate-redesigned'})
    assert r.status_code == 400


def test_the_server_change_is_the_allowlist_alone():
    users = _read('pegaprox', 'api', 'users.py')
    assert users.count("'corporate-redesigned'") == 1
    assert "if layout in ['modern', 'classic', 'corporate', 'corporate-redesigned', 'cloud']:" in users
    for name in ('helpers.py', 'auth.py', 'settings.py'):
        assert 'corporate-redesigned' not in _read('pegaprox', 'api', name), name


# --- source ------------------------------------------------------------------------------------

def _function(src, name):
    start = src.index(f'        function {name}(')
    end = src.find('\n        function ', start + 10)
    return src[start:end]


def test_the_lock_list_is_unchanged():
    ctx = _read('web', 'src', 'contexts.js')
    assert "const UI_LOCK_LAYOUTS = ['modern', 'corporate', 'cloud'];" in ctx


def test_use_layout_reports_corporate_plus_the_variant():
    hook = _function(_read('web', 'src', 'contexts.js'), 'useLayout')
    assert "const isCorpRedesigned = layout === 'corporate-redesigned';" in hook
    assert "const isCorporate = layout === 'corporate' || isCorpRedesigned;" in hook
    assert "document.body.setAttribute('data-layout', isCorpRedesigned ? 'corporate' : layout);" in hook
    assert "else delete document.body.dataset.corpVariant;" in hook
    assert 'isCorpRedesigned, isCloud' in hook


def test_the_theme_choice_treats_the_preview_as_corporate():
    ctx = _read('web', 'src', 'contexts.js')
    for who in ('d', 'data'):
        assert ctx.count(f"({who}.user?.ui_layout === 'corporate' || {who}.user?.ui_layout === 'corporate-redesigned')"
                         " && userTheme !== 'system'") == 1, who
    dash = _read('web', 'src', 'dashboard.js')
    assert ("if (layoutLocked && user?.ui_layout !== 'corporate' && user?.ui_layout !== 'corporate-redesigned') return;"
            in dash)


def test_nothing_else_compares_the_layout_string():
    """Every other place goes by isCorporate / isCloud / layoutLocked, which useLayout()
    answers for the new id too. A new direct comparison would treat it as Modern."""
    hits = []
    for name in sorted(os.listdir(SRC)):
        if not name.endswith('.js') or name == 'translations.js':
            continue
        for n, line in enumerate(_read('web', 'src', name).splitlines(), 1):
            if re.search(r"ui_layout\s*(===|!==)\s*'corporate'", line):
                hits.append(f'{name}:{n}')
    # the classic Corporate card of the profile picker and the first-login picker mark their
    # own card selected, which is right for the plain id only
    allowed = {'create_modals.js', 'dashboard.js', 'contexts.js'}
    assert all(h.split(':')[0] in allowed for h in hits), hits
    picker = _read('web', 'src', 'create_modals.js')
    assert picker.count("user?.ui_layout === 'corporate-redesigned'") == 2


def test_the_new_file_is_built_and_shipped():
    build = _read('web', 'Dev', 'build.sh')
    assert re.search(r'\n    cloud\.js\n    cr\.js\n    cr_views\.js\n    cr_topology\.js\n    cr_compliance\.js\n    cr_tasks\.js\n    cr_datastore\.js\n    cr_drift\.js\n    cr_storage\.js\n    cr_vm\.js\n    cr_reports\.js\n    cr_whatif\.js\n    cr_harden\.js\n    cr_alerts\.js\n    cr_datacenter\.js\n    cr_updates\.js\n    cr_perf\.js\n    cr_vmcfg\.js\n    cr_node\.js\n    cr_nodecfg\.js\n    cr_nodestore\.js\n    cr_nodemisc\.js\n    cr_modules\.js\n    dashboard\.js\n', build)
    files = json.loads(_read('version.json'))['update_files']
    assert all(f'web/src/{n}' in files for n in CR_FILES)


def test_the_new_keys_are_in_english_and_german():
    keys = set()
    for name in CR_FILES + ('dashboard.js', 'create_modals.js', 'node_modals.js', 'vm_modals.js'):
        keys |= set(re.findall(r"\bt\('((?:cr|layoutCorporateRedesigned)[A-Za-z]*)'\)", _read('web', 'src', name)))
    assert len(keys) > 15, keys
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[a:b] for (a, lang), b in zip(starts, ends)}
    for lang in ('en', 'de'):
        missing = [k for k in keys if not re.search(rf'^                {k}: ', blocks[lang], re.M)]
        assert not missing, (lang, missing)
        # ahead of the pinned HA banner chain
        marker = blocks[lang].index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        assert all(blocks[lang].index(f'                {k}: ') < marker for k in keys)


def _selectors(css):
    """Every rule selector of a stylesheet, @media bodies included, keyframe steps left out."""
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    stack, buf, found = [], '', []
    for ch in css:
        if ch == '{':
            head, buf = buf.strip(), ''
            if head.startswith('@keyframes'):
                stack.append('kf')
            elif head.startswith('@'):
                stack.append('at')
            else:
                if 'kf' not in stack:
                    found.append(head)
                stack.append('rule')
        elif ch == '}':
            buf = ''
            if stack:
                stack.pop()
        elif ch == ';' and stack and stack[-1] == 'rule':
            buf = ''
        else:
            buf += ch
    return found


def test_the_css_block_is_one_and_every_rule_is_scoped():
    html = _read('web', 'index.html.original')
    assert html.count('LW Oct 2026 - Corporate Layout - Redesigned (Preview)') == 1
    title = html.index('LW Oct 2026 - Corporate Layout - Redesigned (Preview)')
    start = html.rindex('/*', 0, title)
    block = html[start:html.index('</style>', start)]
    sels = _selectors(block)
    assert len(sels) > 150
    for sel in sels:
        for part in sel.split(','):
            assert 'data-corp-variant="redesigned"' in part, part
    # nothing outside the block knows the attribute
    rest = html[:start] + html[html.index('</style>', start):]
    assert 'corp-variant' not in rest
    assert '\u2014' not in block


def test_no_em_dash_in_the_new_files():
    for name in CR_FILES:
        assert '\u2014' not in _read('web', 'src', name), name


# --- runtime -----------------------------------------------------------------------------------

from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp, _GuardServer  # noqa: E402


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout, corp_theme='', **kw):
        app = _GuardApp(browser, _GuardServer(layout=layout, **kw), corp_theme=corp_theme)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


BODY = '() => [document.body.dataset.layout || null, document.body.dataset.corpVariant || null]'
LOCK = {'layout': 'corporate', 'language': '', 'admins': True}


@pytest.mark.parametrize('layout,want', [
    ('corporate', ['corporate', None]),
    ('corporate-redesigned', ['corporate', 'redesigned']),
    ('modern', ['modern', None]),
])
def test_runtime_the_body_says_which_layout(open_app, layout, want):
    app = open_app(layout)
    assert app.page.evaluate(BODY) == want
    assert (app.page.locator('.cr-header').count() == 1) == (layout == 'corporate-redesigned')
    assert not app.errors, app.errors


def test_runtime_cloud_never_carries_the_variant(open_app):
    app = open_app('cloud')
    app.page.locator('.cloud-shell').first.wait_for(timeout=8000)
    assert app.page.evaluate('() => document.body.dataset.corpVariant || null') is None
    assert not app.errors, app.errors


def test_runtime_a_corporate_lock_shows_the_classic_layout(open_app):
    app = open_app('corporate-redesigned', extra={('GET', '/api/interface/lock'): (200, LOCK)})
    page = app.page
    page.wait_for_function('() => !document.body.dataset.corpVariant', timeout=8000)
    assert page.evaluate(BODY) == ['corporate', None]
    assert page.locator('.cr-header').count() == 0
    assert page.locator('header.sticky').count() == 1
    assert not app.errors, app.errors


def test_runtime_light_paints_the_light_tokens(open_app):
    app = open_app('corporate-redesigned', corp_theme='light')
    css = app.page.evaluate('''() => { const s = getComputedStyle(document.body);
        return [document.body.dataset.corpTheme, s.getPropertyValue('--cr-bg-panel').trim(),
                s.getPropertyValue('--cr-accent').trim(), s.backgroundColor,
                document.documentElement.style.getPropertyValue('--color-primary').trim()]; }''')
    # the shell palette is corporateLight, the skin's own tokens sit on top
    assert css == ['light', '#ffffff', '#0b6f99', 'rgb(238, 242, 245)', '#0079b8'], css
    dark = open_app('corporate-redesigned')
    assert dark.page.evaluate('() => getComputedStyle(document.body).getPropertyValue("--cr-bg-panel").trim()') == '#20333e'


def test_runtime_the_profile_card_picks_the_preview(open_app):
    app = open_app('corporate', extra={('PUT', '/api/user/preferences'): (200, {
        'success': True, 'theme': 'corporateDark', 'language': 'en', 'ui_layout': 'corporate-redesigned',
        'layout_chosen': True, 'taskbar_auto_expand': True, 'sidebar_show_vmid': False})})
    page = app.page
    page.locator('[data-user-menu]').click()
    page.get_by_text('My Profile').first.click()
    card = page.locator('[data-layout-pick="corporate-redesigned"]')
    card.wait_for(timeout=5000)
    text = card.text_content()
    assert 'Corporate Redesigned' in text and 'Preview' in text, text
    card.click()
    page.wait_for_function('() => document.body.dataset.corpVariant === "redesigned"', timeout=5000)
    sent = [b for b in app.server.bodies.get('/api/user/preferences', []) if b.get('ui_layout')]
    assert sent[-1] == {'ui_layout': 'corporate-redesigned', 'theme': 'corporateDark'}
    assert page.evaluate(BODY) == ['corporate', 'redesigned']
    assert not app.errors, app.errors
