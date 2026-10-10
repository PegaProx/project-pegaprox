"""The search expressions in the UI: the header search, the command palette and the text
filter of the All Guests table.

Each search box has a '?' with examples to click into it, shows where the server stopped
reading a query it cannot read, and the tag pills of the header search complete the term
at the end of the query, after AND or OR as well. The palette lists every guest the
server found for an expression, not only the hits by MAC, IP or notes.

The source checks read web/src and the bundle. The runtime tests drive the built bundle
in headless Chromium: the page from the fake server of tests/test_ha_ui.py, the search and
the guest table from the real routes of the app, as the signed-in user. They skip where
Playwright is not installed. The language itself is tested in tests/test_search_query.py.
LW Oct 2026
"""
import os
import re

import pytest

import test_guest_search_ui as gs
import test_global_guest_table_ui as gt
from test_ha_ui import LANGS, _App, _blocks, browser  # noqa: F401 (browser is a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ['searchSyntaxHelp', 'searchSyntaxTitle', 'searchSyntaxFree', 'searchSyntaxAnd', 'searchSyntaxOr',
        'searchSyntaxNot', 'searchSyntaxGroup', 'searchSyntaxQuote', 'searchSyntaxRange', 'searchSyntaxPrefixes',
        'searchSyntaxNote', 'searchErrUnclosedParen', 'searchErrUnexpectedParen', 'searchErrEmptyGroup',
        'searchErrUnclosedQuote', 'searchErrTermBefore', 'searchErrTermAfter', 'searchErrEmptyValue',
        'searchErrBadId', 'searchErrBadType', 'searchErrTooLong', 'searchErrTooManyTerms', 'searchErrTooDeep']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _helpers():
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index('// LW Oct 2026 - the query language of the search')
    return dash[start:dash.index('// LW Apr 2026', start)]


# -- source ---------------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS:
        n = len(re.findall(rf'^ +{key}: ', block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_every_key_is_used_and_keeps_its_placeholders():
    helpers = _helpers()
    for key in KEYS:
        assert f"'{key}'" in helpers, key
    blocks = _blocks()
    for key in KEYS:
        en = re.search(rf'^ +{key}: (.*),$', blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(rf'^ +{key}: (.*),$', block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_every_reason_of_the_server_has_its_message():
    from pegaprox.utils import search_query
    helpers = _helpers()
    for reason in search_query._MESSAGES:
        if reason != 'empty':   # an empty query never reaches the parser from a search box
            assert f'{reason}: ' in helpers, reason


def test_no_em_dash_and_every_class_is_in_the_static_build():
    new_strings = [line for block in _blocks().values() for line in block.splitlines()
                   if any(f' {k}: ' in line for k in KEYS)]
    tables = _read('web', 'src', 'tables.js')
    table_part = tables[tables.index('const [syntaxError, setSyntaxError]'):]
    table_part = table_part[:table_part.index('const [picked, setPicked]')]
    for text in new_strings + [_helpers(), table_part]:
        assert '\u2014' not in text
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    dash = _read('web', 'src', 'dashboard.js')
    blocks = [_helpers(),
              dash[dash.index('{remote.error && remote.q === query.trim()'):dash.index('<div className="flex-1 overflow-y-auto"')],
              dash[dash.index('{/* above the click-away layer'):dash.index('{globalSearchLoading ? (')],
              dash[dash.index('{globalSearchResults.syntaxError && ('):dash.index('{/* MK: clickable tag pills')],
              tables[tables.index('{syntaxError && <div'):tables.index('{!data && !syntaxError')]]
    names = set()
    for block in blocks:
        for m in re.finditer(r'className=(?:"([^"]*)"|\{`([^`]*)`\})', block):
            txt = re.sub(r'\$\{[^}]*\}', ' ', m.group(1) if m.group(1) is not None else m.group(2))
            names.update(n for n in txt.split() if re.match(r'^[a-z]', n))
    names.update(re.findall(r"'([a-z][\w-]*(?:-\d)?)'", "'left-0' 'right-0' 'border-2' 'bg-proxmox-card'"))
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_three_boxes_carry_the_help_and_the_bundle_was_rebuilt():
    dash, tables = _read('web', 'src', 'dashboard.js'), _read('web', 'src', 'tables.js')
    assert dash.count('<SearchSyntaxHelp ') == 2 and tables.count('<SearchSyntaxHelp ') == 1
    bundle = _read('web', 'index.html')
    for needle in ('function SearchSyntaxHelp(', 'function searchSyntaxMessage(', 'function searchWithTag(',
                   'data-search-syntax-help', 'data-cmdpal-syntax-error', 'data-search-syntax-error',
                   'data-all-guests-syntax-error', 'data-search-tag-pill') + tuple(KEYS):
        assert needle in bundle, needle


# -- runtime: the header search and the palette -----------------------------------------------------

VM = gs.VM
C1_VMS = [dict(VM, vmid=100, name='web01', type='qemu', status='running', node='pve1', tags='web;prod')]
C2_VMS = [dict(VM, vmid=201, name='db-primary', type='qemu', status='stopped', node='pve2', tags='db;prod'),
          dict(VM, vmid=301, name='cache', type='lxc', status='running', node='pve2', tags='cache')]
PLACEHOLDER = gs.PLACEHOLDER


@pytest.fixture
def search_app(browser, api, seed):  # noqa: F811
    for cid, name, vms in (('c1', 'Testi', C1_VMS), ('c2', 'Zweit', C2_VMS)):
        m = api.make_fake_manager(cluster_id=cid, get_vm_resources=[dict(v) for v in vms])
        m.is_connected = True
        m.config.name = name
        m.nodes = {}
        api.set_manager(cid, m)
    apps = []

    def _open(user=None, **kw):
        user = user or seed.user('admin', role='admin')
        app = _App(browser, gs._Server(api.as_user(user), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _box(app, layout):
    return app.page.locator(f'input[placeholder="{PLACEHOLDER[layout]}"]')


def _dropdown_names(page):
    return sorted(set(page.locator('.pp-search-results .font-medium.truncate').all_inner_texts()))


def _open_help(page):
    # the harness has no live updates: after a while their banner lies over the header,
    # and a pointer click would land on it
    page.locator('header [data-search-syntax]').dispatch_event('click')


def _wait_names(page, want, seconds=6):
    for _ in range(int(seconds * 10)):
        if _dropdown_names(page) == want:
            return
        page.wait_for_timeout(100)
    assert _dropdown_names(page) == want


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_header_search_reads_expressions_and_says_where_one_breaks(search_app, layout):
    app = search_app(layout=layout)
    page = app.page
    box = _box(app, layout)
    box.fill('tag:prod -tag:web')
    _wait_names(page, ['db-primary'])
    box.fill('tag:cache OR name:web')
    _wait_names(page, ['cache', 'web01'])
    box.fill('(tag:web OR db')
    err = page.locator('.pp-search-results [data-search-syntax-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text().strip() == 'The ( at character 1 is not closed'
    assert _dropdown_names(page) == []
    # fixed: the error goes, the hits come
    box.fill('(tag:web OR db)')
    _wait_names(page, ['db-primary', 'web01'])
    assert page.locator('[data-search-syntax-error]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_tag_pill_completes_the_term_after_and(search_app, layout):
    app = search_app(layout=layout)
    page = app.page
    box = _box(app, layout)
    box.fill('node:pve2 AND tag:pr')
    pill = page.locator('.pp-search-results [data-search-tag-pill="prod"]')
    pill.wait_for(timeout=5000)
    pill.click()
    assert box.input_value() == 'node:pve2 AND tag:prod'
    _wait_names(page, ['db-primary'])
    # a bare word at the end becomes a tag: term in its place
    box.fill('tag:prod OR cac')
    pill = page.locator('.pp-search-results [data-search-tag-pill="cache"]')
    pill.wait_for(timeout=5000)
    pill.click()
    assert box.input_value() == 'tag:prod OR tag:cache'
    _wait_names(page, ['cache', 'db-primary', 'web01'])
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_help_lists_examples_that_go_into_the_box(search_app, layout):
    app = search_app(layout=layout)
    page = app.page
    _open_help(page)
    help_ = page.locator('[data-search-syntax-help]')
    help_.wait_for(timeout=3000)
    assert help_.locator('[data-search-syntax-example]').count() == 7
    assert 'Search syntax' in help_.inner_text() and 'cluster:' in help_.inner_text()
    # it is not cut off by the search box it belongs to
    box = help_.bounding_box()
    assert box and box['height'] > 200 and box['x'] >= 0 and box['x'] + box['width'] <= 1600
    help_.locator('[data-search-syntax-example="tag:web OR tag:api"]').click()
    assert page.locator('[data-search-syntax-help]').count() == 0
    assert _box(app, layout).input_value() == 'tag:web OR tag:api'
    _wait_names(page, ['web01'])
    # with the dropdown open the help still opens, and Escape closes it
    _open_help(page)
    help_.wait_for(timeout=3000)
    page.keyboard.press('Escape')
    page.locator('[data-search-syntax-help]').wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


def test_runtime_german_messages(search_app):
    app = search_app(layout='modern', language='de')
    page = app.page
    page.fill('input[placeholder="Alle Cluster durchsuchen..."]', 'web AND')
    err = page.locator('.pp-search-results [data-search-syntax-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text().strip() == 'AND an Zeichen 5 braucht danach einen Begriff'
    _open_help(page)
    page.locator('[data-search-syntax-help]', has_text='Suchsyntax').wait_for(timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_palette_lists_what_an_expression_finds(search_app, layout):
    app = search_app(layout=layout)
    page = app.page
    box = gs._palette(app, 'tag:prod -tag:web')
    row = page.locator('[data-cmdpal-idx]', has_text='db-primary')
    row.wait_for(timeout=5000)
    assert 'VMID 201' in row.inner_text() and 'Zweit' in row.inner_text()
    assert page.locator('[data-cmdpal-idx]', has_text='web01').count() == 0
    # an expression hit has no MAC, IP or notes to show
    assert row.locator('[data-cmdpal-match]').count() == 0
    box.fill('tag:prod OR')
    err = page.locator('[data-cmdpal-syntax-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text().strip() == 'OR at character 10 needs a term after it'
    # the palette's own help puts an example into the palette
    page.locator('[data-cmdpal-syntax-error]').locator('xpath=..').locator('[data-search-syntax]').click()
    page.locator('[data-search-syntax-help] [data-search-syntax-example="id:100-199"]').click()
    assert box.input_value() == 'id:100-199'
    page.locator('[data-cmdpal-idx]', has_text='web01').wait_for(timeout=5000)
    assert page.locator('[data-cmdpal-syntax-error]').count() == 0
    assert not app.errors, app.errors


def test_runtime_names_still_stay_with_the_open_cluster_in_the_palette(search_app):
    """A plain query: the palette adds only what the index knows, as before."""
    app = search_app(layout='modern')
    page = app.page
    gs._palette(app, 'db-primary')
    page.wait_for_function('() => !document.querySelector("[data-cmdpal-searching]")', timeout=5000)
    page.wait_for_timeout(200)
    assert page.locator('[data-cmdpal-idx]', has_text='db-primary').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_pool_user_finds_their_guest_only(search_app, seed):
    import time
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=['c2'])
    user = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('c2', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['c2'] = {'data': {'301:lxc': 'pool_1'}, 'timestamp': time.time(),
                                             'refreshing': False}
    app = search_app(user=user, layout='modern', admin=False)
    page = app.page
    _box(app, 'modern').fill('-tag:nothing type:vm OR type:ct')
    _wait_names(page, ['cache'])
    assert not app.errors, app.errors


# -- runtime: the All Guests table ------------------------------------------------------------------

@pytest.fixture
def table_app(browser, api, seed):  # noqa: F811
    apps = []

    def _open(**kw):
        gt._Clusters(api)
        app = _App(browser, gt._Server(api.as_user(seed.user('admin', role='admin')), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_guest_table_filter_takes_expressions(table_app, layout):
    app = table_app(layout=layout)
    page = app.page
    gt._open_table(app, layout)
    search = page.locator('[data-all-guests-search]')
    search.fill('tag:prod -tag:web')
    gt._wait_rows(app, ['c1:200'])
    search.fill('(cluster:branch OR id:100) status:run')
    gt._wait_rows(app, ['c2:300', 'c1:100'])
    search.fill('(tag:prod')
    err = page.locator('[data-all-guests-syntax-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text().strip() == "The ( at character 1 is not closed"
    # the rows of the last query that could be read stay
    assert gt._rows(page) == ['c2:300', 'c1:100']
    page.locator('[data-all-guests] [data-search-syntax]').click()
    page.locator('[data-search-syntax-help] [data-search-syntax-example="-status:running"]').click()
    assert search.input_value() == '-status:running'
    gt._wait_rows(app, ['c2:301', 'c1:102'])
    assert page.locator('[data-all-guests-syntax-error]').count() == 0
    # plain text as before
    search.fill('WEB')
    gt._wait_rows(app, ['c1:100'])
    assert not app.errors, app.errors
