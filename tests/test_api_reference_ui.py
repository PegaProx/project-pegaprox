"""The API reference in the web UI: an entry in the user menu (Modern and Corporate share
it, Cloud has its own menu) opens a modal that renders GET /api/pegaprox/openapi.json by
area, with method, path, permission, parameters and the description, and a search.

The route is tested in tests/test_api_reference.py. These read the source and the bundle,
and the runtime tests drive the built bundle in headless Chromium against the fake server
of tests/test_ha_ui.py; they skip where Playwright is not installed.
LW
"""
import json
import os
import re

import pytest

from test_ha_ui import LANGS, _classes, _read, browser, open_app  # noqa: F401 (fixtures)

SHOTS = os.environ.get('API_REF_SHOTS', '')
ROUTE = '/api/pegaprox/openapi.json'
SPEC = json.loads(_read('docs', 'openapi.json'))


@pytest.fixture(scope='module')
def ui():
    return _read('web', 'src', 'ui.js')


@pytest.fixture(scope='module')
def block(ui):
    start = ui.index('        // LW Oct 2026 - API reference from the user menu.')
    return ui[start:ui.index('        // NS \u2014 sticky banner at top while WS is dropped.', start)]


def _used_keys(src):
    return set(re.findall(r"'(apiRef[A-Za-z]+)'", src)) | set(re.findall(r"t\('(apiRef[A-Za-z]+)'\)", src))


def _all_used():
    return (_used_keys(_read('web', 'src', 'ui.js')) | _used_keys(_read('web', 'src', 'dashboard.js'))
            | _used_keys(_read('web', 'src', 'cloud.js')))


def _lang_blocks():
    tr = _read('web', 'src', 'translations.js')
    starts = {lang: re.search(r'^            %s: \{$' % lang, tr, re.M).start() for lang in LANGS}
    order = sorted(starts, key=starts.get)
    out = {}
    for i, lang in enumerate(order):
        end = starts[order[i + 1]] if i + 1 < len(order) else len(tr)
        out[lang] = tr[starts[lang]:end]
    return out


# -- source ----------------------------------------------------------------------------------

def test_every_key_exists_once_per_language_and_none_is_unused():
    used = _all_used()
    assert len(used) >= 25
    for lang, text in _lang_blocks().items():
        for key in used:
            n = len(re.findall(r'^                %s: ' % key, text, re.M))
            assert n == 1, (lang, key, n)
        assert set(re.findall(r'^                (apiRef[A-Za-z]+): ', text, re.M)) == used, lang


def test_placeholders_survive_translation():
    blocks = _lang_blocks()
    for key in ('apiRefCount', 'apiRefRole', 'apiRefShadowed'):
        want = None
        for lang, text in blocks.items():
            line = re.search(r'^                %s: (.*)$' % key, text, re.M).group(1)
            found = sorted(re.findall(r'\{[a-z]+\}', line))
            want = want or found
            assert found == want and found, (lang, key, found)


def test_no_em_dash_and_every_icon_exists(block, ui):
    assert '\u2014' not in block and '\u2013' not in block
    for text in _lang_blocks().values():
        for line in re.findall(r'^                apiRef[A-Za-z]+: .*$', text, re.M):
            assert '\u2014' not in line, line
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.([A-Za-z]+)', block)) | {'Book'}
    for name in used:
        assert re.search(r'\b%s: \(' % name, icons), name


def test_every_class_is_in_the_static_tailwind_build(block):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(block)
    # class strings also sit in constants, in helpers and inside ${...} of a template literal
    token = re.compile(r'^[a-z][a-z0-9:/\-\.\[\]]*$')
    for m in re.finditer(r"'([^'\n]*)'|`([^`]*)`", block):
        txt = re.sub(r"\$\{|\}|'", ' ', m.group(1) if m.group(1) is not None else m.group(2))
        names.update(n for n in txt.split() if token.match(n) and '-' in n)
    # the spec's own field names and the download's file name
    names = {n for n in names if not n.startswith(('x-pegaprox-', 'pegaprox-openapi-', 'area:'))}
    assert {'opacity-50', 'rotate-90', 'border-red-500/50', 'whitespace-pre-wrap'} <= names
    assert len(names) > 60
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_reference_only_reads(block):
    """No try-it-out: one fetch, a GET of the description, and nothing that sends a body."""
    assert block.count('fetch(') == 1
    assert ("fetch(`${API_URL}/pegaprox/openapi.json`, { credentials: 'include', headers: getAuthHeaders() })"
            in block)
    for other in ('authFetch', 'XMLHttpRequest', 'sendBeacon', 'EventSource', 'WebSocket', 'window.open'):
        assert other not in block, other


def test_every_layout_has_the_entry():
    dash = _read('web', 'src', 'dashboard.js')
    menu = dash[dash.index('{showUserMenu && ('):dash.index("{t('logout')}")]
    # Modern and Corporate render the same menu, for every role
    assert "setShowApiReference(true)" in menu and "{t('apiRefTitle')}" in menu
    assert '{isAdmin && (' not in menu[menu.index('setShowApiReference(true)') - 400:menu.index('setShowApiReference(true)')]
    assert dash.count('<ApiReferenceModal onClose={() => setShowApiReference(false)} />') == 2
    assert 'onOpenApiReference={() => setShowApiReference(true)}' in dash
    cloud = _read('web', 'src', 'cloud.js')
    assert "label: t('apiRefTitle'), icon: 'Book', onClick: onOpenApiReference" in cloud
    assert 'onOpenApiReference={onOpenApiReference}' in cloud


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function ApiReferenceModal(', 'function apiRefOperations(', '/pegaprox/openapi.json',
                   'onOpenApiReference', 'data-user-menu'):
        assert needle in bundle, needle
    for key in _all_used():
        assert key in bundle, key


# -- runtime -----------------------------------------------------------------------------------

def _ops():
    for path, methods in SPEC['paths'].items():
        for method, op in methods.items():
            yield method.upper(), path, op


def _expected(query=None, method=None, tag=None):
    """The rows the modal shows, by the rule apiRefMatcher applies to plain words."""
    out = []
    for m, path, op in _ops():
        text = ' '.join([m, path, op.get('summary') or '', op.get('description') or '',
                         (op.get('tags') or [''])[0], op.get('operationId') or '',
                         *op.get('x-pegaprox-permissions', []), *op.get('x-pegaprox-roles', [])]).lower()
        if query and not all(w.lower() in text for w in query.split()):
            continue
        if method and m != method:
            continue
        if tag and (op.get('tags') or [''])[0] != tag:
            continue
        out.append(f'{m} {path}')
    return out


TOTAL = len(list(_ops()))
READS = {('GET', ROUTE): (200, SPEC)}


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.wait_for_timeout(300)   # the chevron turns with a transition
        app.page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _open(app, layout='modern', label='API reference'):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-user-btn').first.click()
        page.locator('.cloud-menu-item', has_text=label).first.click()
    else:
        page.locator('header [data-user-menu]').first.click()
        page.locator('header button', has_text=label).first.click()
    page.locator('[data-api-reference]').wait_for(timeout=5000)


def _rows(page):
    return page.locator('[data-api-reference] [data-api-op]').evaluate_all('els => els.map(e => e.dataset.apiOp)')


def _count(page):
    return page.locator('[data-api-count]').inner_text().strip()


def _search(page, text):
    page.locator('[data-api-reference] input[type="search"]').fill(text)
    page.wait_for_timeout(150)


def test_runtime_modern_lists_searches_and_explains_every_route(open_app):
    app = open_app(role='standalone', layout='modern', extra=READS)
    page = app.page
    before = len(app.server.calls)
    _open(app)
    page.locator('[data-api-op]').first.wait_for(timeout=10000)
    assert _count(page) == f'{TOTAL} of {TOTAL} operations'
    assert len(_rows(page)) == TOTAL
    for area in ('vms', 'ha', 'settings'):
        assert page.locator(f'[data-api-area="{area}"]').count() == 1, area
    _shot(app, 'modern-all.png')

    # a permission, as words
    _search(page, 'node.update')
    want = _expected('node.update')
    assert 0 < len(want) < TOTAL
    assert sorted(_rows(page)) == sorted(want)
    assert _count(page) == f'{len(want)} of {TOTAL} operations'

    # a URL pasted from the browser finds its route, ids and all
    _search(page, 'https://pegaprox.example:5000/api/clusters/c1/updates/rolling')
    rolling = '/api/clusters/{cluster_id}/updates/rolling'
    assert set(_rows(page)) == {f'{m.upper()} {rolling}' for m in SPEC['paths'][rolling]}

    # open one: description, who may call it, parameters, body, responses
    key = f'POST {rolling}'
    page.locator(f'[data-api-op="{key}"] > button').click()
    detail = page.locator(f'[data-api-detail="{key}"]')
    detail.wait_for(timeout=3000)
    text = detail.inner_text()
    op = SPEC['paths'][rolling]['post']
    for needle in (op['summary'], 'node.update', 'cluster_id', 'path', 'string', 'required',
                   'Request body: a JSON object', 'API token (Authorization: Bearer pgx_...)',
                   'Session (X-Session-ID)', '403', op['operationId']):
        assert needle in text, needle
    _shot(app, 'modern-detail.png')

    # the method filter and an area
    _search(page, '')
    page.locator('[data-api-method="DELETE"]').click()
    page.wait_for_timeout(150)
    assert set(_rows(page)) == set(_expected(method='DELETE'))
    page.locator('[data-api-method="all"]').click()
    page.locator('[data-api-area-pick="ha"]').click()
    page.wait_for_timeout(150)
    assert set(_rows(page)) == set(_expected(tag='ha'))
    assert page.locator('[data-api-area]').count() == 0   # one area, no headers

    # how each route takes its caller: signed in, public, its own check, a code in the body
    page.locator('[data-api-area-pick="ha"]').click()   # again: all areas
    for path, method, chip, scheme in (
            (ROUTE, 'GET', 'Any signed-in user', 'API token (Authorization: Bearer pgx_...)'),
            ('/api/health', 'GET', 'Public', 'Public'),
            ('/api/ha/peer/status', 'GET', 'Checks its own credentials', 'Signed request of a standby group member'),
            ('/api/ha/peer/pair', 'POST', 'Checks its own credentials', 'One-time code in the request body')):
        _search(page, f'{method} {path}')
        key = f'{method} {path}'
        assert _rows(page) == [key], (key, _rows(page))
        assert chip in page.locator(f'[data-api-op="{key}"] > button').inner_text(), key
        page.locator(f'[data-api-op="{key}"] > button').click()
        assert scheme in page.locator(f'[data-api-detail="{key}"]').inner_text(), key

    # the download is the document itself
    with page.expect_download() as dl:
        page.locator('[data-api-reference] button', has_text='Download openapi.json').click()
    assert dl.value.suggested_filename == f"pegaprox-openapi-{SPEC['info']['version']}.json"
    with open(dl.value.path(), encoding='utf-8') as fh:
        assert json.load(fh)['paths'].keys() == SPEC['paths'].keys()

    # Escape closes it, a second open does not fetch again
    page.keyboard.press('Escape')
    page.locator('[data-api-reference]').wait_for(state='detached', timeout=3000)
    _open(app)
    page.locator('[data-api-op]').first.wait_for(timeout=10000)
    calls = app.server.calls[before:]
    assert calls.count(('GET', ROUTE)) == 1
    # read-only: nothing but reads went out while it was open
    assert [c for c in calls if c[0] != 'GET' and c[1] not in ('/api/sse/token',)] == []
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate', 'cloud'])
def test_runtime_the_other_layouts_open_it_from_their_user_menu(open_app, layout):
    app = open_app(role='standalone', layout=layout, extra=READS)
    page = app.page
    _open(app, layout)
    page.locator('[data-api-op]').first.wait_for(timeout=10000)
    assert _count(page) == f'{TOTAL} of {TOTAL} operations'
    _search(page, 'GET /api/pegaprox/version')
    assert _rows(page) == ['GET /api/pegaprox/version']
    page.locator('[data-api-op="GET /api/pegaprox/version"] > button').click()
    page.locator('[data-api-detail="GET /api/pegaprox/version"]').wait_for(timeout=3000)
    _shot(app, f'{layout}-detail.png')
    # "/" is the search of the reference, not the page behind it
    page.locator('[data-api-reference] h3').click()
    page.keyboard.press('/')
    assert page.evaluate('() => document.activeElement && document.activeElement.type') == 'search'
    page.keyboard.press('Escape')
    page.locator('[data-api-reference]').wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


def test_runtime_a_viewer_has_it_and_it_speaks_german(open_app):
    app = open_app(role='standalone', layout='modern', admin=False, language='de', extra=READS)
    page = app.page
    _open(app, label='API-Referenz')
    page.locator('[data-api-op]').first.wait_for(timeout=10000)
    assert _count(page) == f'{TOTAL} von {TOTAL} Operationen'
    _search(page, 'kein-solcher-pfad-xyz')
    assert _rows(page) == []
    app.see('Keine Route passt zur Suche.')
    _shot(app, 'modern-de-viewer.png')
    assert not app.errors, app.errors


def test_runtime_a_failed_load_says_so_and_tries_again(open_app):
    app = open_app(role='standalone', layout='modern', extra={('GET', ROUTE): (500, {'error': 'boom'})})
    page = app.page
    _open(app)
    app.see('The API description could not be loaded.')
    assert _rows(page) == []
    app.server.extra[('GET', ROUTE)] = (200, SPEC)
    page.locator('[data-api-reference] button', has_text='Try again').click()
    page.locator('[data-api-op]').first.wait_for(timeout=10000)
    assert _count(page) == f'{TOTAL} of {TOTAL} operations'
    assert app.server.calls.count(('GET', ROUTE)) == 2
