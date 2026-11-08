"""The favorite star in the global search dropdown of the dashboard.

The route behind it is tested in tests/test_favorites.py. These read the source and the
bundle, and the runtime tests at the end drive the built bundle in headless Chromium:
the page around the search comes from the fake server of tests/test_ha_ui.py, the
global search and the favorites are the real routes of the app, as the signed-in
admin, against the test database. So what the page sends is what the server takes,
and what the server answers is what lights the star. They skip where Playwright is
not installed.

Two things the page got wrong next to the server: a container row of the search says
'ct', which the server refused and the star never knew, and a refused toggle said
nothing at all.
LW
"""
import json
import os
import re

import pytest

from pegaprox.api import search

from test_ha_ui import BASE, _App, _FakeServer, browser  # noqa: F401 (browser is a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


def _arrow(src, name):
    start = src.index(f'const {name} = ')
    return src[start:src.index('\n            };', start)]


# -- source --------------------------------------------------------------------------------

def test_a_container_row_is_a_vm_favorite(dash):
    toggle = _arrow(dash, 'toggleFavorite')
    normalized = toggle.index("if (type === 'ct') type = 'vm';")
    # before the list is read and before the body is built
    assert normalized < toggle.index("favorites[type + 's']") < toggle.index(
        'const body = { action, type, cluster_id: clusterId };')
    assert "if (type === 'vm' || type === 'ct') {" in _arrow(dash, 'isFavorite')


def test_a_vm_star_compares_the_id_as_text(dash):
    """A standalone ESXi host lists its VMs by string ids, the server answers numbers:
    both comparisons of a VM star go by the text of the id."""
    assert dash.count('String(f.vmid) === String(vmid)') == 2
    assert 'f.vmid === vmid' not in dash


def test_only_a_node_favorite_sends_a_node(dash):
    toggle = _arrow(dash, 'toggleFavorite')
    assert "if (nodeName && type === 'node') body.node = nodeName;" in toggle
    assert 'if (nodeName) body.node' not in toggle


def test_a_refused_toggle_says_why(dash):
    toggle = _arrow(dash, 'toggleFavorite')
    assert "} else if (response) {" in toggle
    assert "addToast(await PegaProxApiErrors.message(response, t('actionFailed')), 'error');" in toggle


def test_the_search_rows_still_hand_the_toggle_what_it_reads(dash):
    """result.type is vm, ct or node; the toggle and the star read it as they are."""
    assert ("toggleFavorite(result.type, result.cluster_id, result.vmid, result.type === 'vm' ? 'qemu' : 'lxc', "
            "result.name);") in dash
    assert "isFavorite(result.type, result.cluster_id, result.vmid, result.name)" in dash


def test_the_fallback_is_translated_everywhere():
    """t() hands back the key itself on a miss; the fallback has to exist in every language."""
    tr = _read('web', 'src', 'translations.js')
    assert len(re.findall(r"^ +actionFailed: '[^']+',$", tr, re.M)) == 9


def test_no_em_dash_in_the_new_lines(dash):
    assert '\u2014' not in _arrow(dash, 'toggleFavorite')
    assert '\u2014' not in _arrow(dash, 'isFavorite')


def test_the_bundle_was_rebuilt():
    """web/index.html is generated from web/src; a source-only change ships nothing."""
    bundle = _read('web', 'index.html')
    for needle in ("if(type==='ct')type='vm';", "if(type==='vm'||type==='ct')",
                   "if(nodeName&&type==='node')body.node=nodeName;",
                   "addToast(await PegaProxApiErrors.message(response,t('actionFailed')),'error');"):
        assert needle in bundle, needle


# -- runtime: the built bundle against the real routes --------------------------------------

REAL = ('/api/global/search', '/api/user/favorites')
PLACEHOLDER = {'modern': 'Search all clusters...', 'corporate': 'Search in all inventories...'}
VMS = [
    {'vmid': 100, 'name': 'pp-web', 'node': 'pp-node1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 200, 'name': 'pp-ct', 'node': 'pp-node1', 'type': 'lxc', 'status': 'stopped'},
]


class _Server(_FakeServer):
    """The page from the fake server, the search and the favorites from the app."""

    def __init__(self, client, **kw):
        super().__init__(role='standalone', **kw)
        self.client = client

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url)
        bare = path.split('?')[0]
        if not req.url.startswith(BASE) or bare not in REAL:
            return super().handle(route)
        self.calls.append((req.method, bare))
        if req.method == 'GET':
            r = self.client.get(path)
        else:
            raw = req.post_data or ''
            self.bodies.setdefault(bare, []).append(json.loads(raw) if raw else {})
            r = self.client.post(bare, data=raw, headers={'Content-Type': 'application/json'})
        return route.fulfill(status=r.status_code, body=r.get_data(),
                             headers={'Content-Type': 'application/json'})


@pytest.fixture
def real_app(browser, api, seed):  # noqa: F811
    admin = seed.user('admin', role='admin')
    m = api.make_fake_manager(cluster_id='c1', get_vm_resources=list(VMS))
    m.is_connected = True
    m.config.name = 'Cluster One'
    m.nodes = {'pp-node1': {'status': 'online'}}
    api.set_manager('c1', m)
    apps = []

    def _open(**kw):
        app = _App(browser, _Server(api.as_user(admin), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _search(app, layout):
    page = app.page
    page.fill(f'input[placeholder="{PLACEHOLDER[layout]}"]', 'pp')
    page.locator('.pp-search-results', has_text='pp-node1').wait_for(timeout=5000)


def _row(app, name):
    # by the name of the row: a VM row names its node as well
    title = app.page.locator('span.font-medium', has_text=re.compile(f'^{re.escape(name)}$'))
    return app.page.locator('.pp-search-results .divide-y > div', has=title)


def _star(app, name):
    return _row(app, name).locator('button[title="Toggle favorite"]')


def _lit(app, name):
    return 'fill-yellow-400' in (_star(app, name).locator('svg').get_attribute('class') or '')


def _wait_lit(app, name, lit=True, seconds=4):
    page = app.page
    for _ in range(int(seconds * 10)):
        if _lit(app, name) == lit:
            return
        page.wait_for_timeout(100)
    raise AssertionError(f'the star of {name} is {"not " if lit else ""}lit')


def _rows():
    import pegaprox.core.db as dbmod
    return sorted(tuple(r) for r in dbmod.get_db().conn.execute(
        'SELECT username, kind, cluster_id, vmid, vm_type, vm_name, node FROM user_favorites'))


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_every_kind_of_row_stars_and_stays_starred(real_app, layout):
    app = real_app(layout=layout)
    _search(app, layout)
    for name in ('pp-web', 'pp-ct', 'pp-node1'):
        assert not _lit(app, name), name
        _star(app, name).click()
        _wait_lit(app, name)
    assert _rows() == [
        ('admin', 'node', 'c1', None, None, None, 'pp-node1'),
        ('admin', 'vm', 'c1', 100, 'qemu', 'pp-web', ''),
        ('admin', 'vm', 'c1', 200, 'lxc', 'pp-ct', ''),
    ]
    sent = app.server.bodies['/api/user/favorites']
    assert sent == [
        {'action': 'add', 'type': 'vm', 'cluster_id': 'c1', 'vmid': 100, 'vm_type': 'qemu'},
        {'action': 'add', 'type': 'vm', 'cluster_id': 'c1', 'vmid': 200, 'vm_type': 'lxc'},
        {'action': 'add', 'type': 'node', 'cluster_id': 'c1', 'vm_type': 'lxc', 'node': 'pp-node1'},
    ]

    # the container's star goes again: before the fix every click on it was another add
    _star(app, 'pp-ct').click()
    _wait_lit(app, 'pp-ct', lit=False)
    assert sent[-1] == {'action': 'remove', 'type': 'vm', 'cluster_id': 'c1', 'vmid': 200, 'vm_type': 'lxc'}
    assert [r[3] for r in _rows()] == [None, 100]

    # a new page load reads them from the server
    app.page.reload()
    app.wait_for_app()
    _search(app, layout)
    assert (_lit(app, 'pp-web'), _lit(app, 'pp-ct'), _lit(app, 'pp-node1')) == (True, False, True)
    assert ('GET', '/api/user/favorites') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_a_refused_star_says_why_and_stays_dark(real_app, monkeypatch):
    monkeypatch.setitem(search.FAVORITES_MAX, 'vm', 1)
    app = real_app(layout='modern')
    _search(app, 'modern')
    _star(app, 'pp-web').click()
    _wait_lit(app, 'pp-web')
    _star(app, 'pp-ct').click()
    app.see('At most 1 VMs can be favorites - remove one first')
    assert not _lit(app, 'pp-ct')
    assert [r[3] for r in _rows()] == [100]
    assert not app.errors, app.errors
