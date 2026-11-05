"""Corporate Redesigned: the shell, the overview and the cluster-level views.

- All Clusters: a cluster whose datacenter status is older than two polls, or never came, is in
  none of the sums; each tile says how many it leaves out, the row says "Not current" or "Not read"
  (no green dot, no Online) and the Online chip counts what the rows call Online. An ESXi
  connection alone never waits for a status. Byte sizes follow the UI language. The dashboard
  links the Topology view, the status bar counts the guests of every cluster, the storage scale
  names no preview.
- The cluster overview colours storage by the storage pair (70/85).
- Compliance: the node checks run CMP_PARALLEL at a time and the page fills as they answer; SSH
  switched off stops asking the other nodes and is said once for the cluster; a node list that
  could not be read is said with Retry; the controls table has no evidence column.
- Topology: "Collapse nodes by default" folds the nodes, Cards view next to Diagram, a failed
  affinity read is said, a backup server linked to no cluster is drawn for every cluster.
- Shell: the folded rail opens the Tools views, the trail stays on a phone, a group the sidebar
  left behind is not in the trail.
- Layout: the first login and the admin pin offer Corporate Redesigned, the profile card calls it
  no preview. Tasks: a Today filter. Automation > Alerts: a failed read of the active alerts is
  said, with Retry.

Runs against the fake servers of tests/test_ha_ui.py; PEGAPROX_CR_BUNDLE=<file> serves another
bundle (the counterproof). Skips without Playwright. LW Nov 2026
"""
import json
import os
import re

import pytest

from test_corp_redesigned_compliance_ui import _CmpServer
from test_corp_redesigned_dashboard_ui import STATUS, _DashServer, _bytes, _col, _crumbs, _rows, _stat
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, _GuardApp
from test_corp_redesigned_tasks_ui import _TaskServer, _task, shaped
from test_corp_redesigned_topology_ui import _TopoServer, _cluster_topo
from test_ha_ui import BASE, PBS, _App, _FakeServer
from test_interface_lock_ui import _LockServer, _Page, _to_server_tab

LAYOUT = 'corporate-redesigned'
GIB = 1024 ** 3
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
HTML = {'Content-Type': 'text/html; charset=utf-8'}
JSON = {'Content-Type': 'application/json'}


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
def opener(browser):
    """opener(server_cls, **kw) opens the app on that fake with the bundle under test."""
    apps = []

    def _open(server_cls=_DashServer, storage=None, viewport=(1600, 1000), **kw):
        kw.setdefault('layout', LAYOUT)
        # the task fake serves PEGAPROX_CR_BUNDLE itself
        if not issubclass(server_cls, _TaskServer):
            kw['bundle'] = BUNDLE
        app = _GuardApp(browser, server_cls(**kw), storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _need(page, selector, what, timeout=10000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _until(page, js, what, timeout=20000, arg=None):
    try:
        page.wait_for_function(js, arg=arg, timeout=timeout)
    except Exception:
        raise AssertionError(what) from None


def _note(page, sid):
    box = page.locator(f'[data-cr-stat="{sid}"] [data-cr-stat-note]')
    return box.inner_text().strip() if box.count() else ''


def _row(page, name):
    rows = {r[_col(page, 'dash-clusters', 'name')]: r for r in _rows(page, 'dash-clusters')}
    return rows[name]


def _row_dot(page, name):
    return page.evaluate('''(name) => {
        const tr = Array.from(document.querySelectorAll('[data-cr-table="dash-clusters"] tbody tr.cr-row'))
            .find(r => r.innerText.includes(name));
        const dot = tr && tr.querySelector('.cr-dot');
        return dot ? dot.className : '';
    }''', name)


def _chip(page, sid):
    b = page.locator(f'[data-cr-table="dash-clusters"] [data-cr-show="{sid}"]')
    return b.locator('.cr-seg-n').inner_text().strip() if b.count() else None


# --- a status that is not current is in no sum and says so -------------------------

def test_runtime_an_old_status_leaves_every_sum_and_its_row_says_not_current(opener):
    app = opener()
    page = app.page
    page.locator('[data-cr-stat="cpu"]').wait_for(timeout=15000)
    assert _stat(page, 'vms')['value'] == '4/5' and _note(page, 'vms') == ''
    # Prod stops answering; two minutes on its last status is older than two polls
    app.server.extra[('GET', '/api/clusters/c2/datacenter/status')] = (500, {'error': 'boom'})
    app.ctx.clock.set_fixed_time(FIXED + 120)
    _until(page, '() => !!document.querySelector(\'[data-cr-table="dash-clusters"] [data-cr-cl-state="stale"]\')',
           'the row of a cluster with an old status says "Not current"', timeout=15000)
    st = STATUS['c1']
    vms, cts = st['guests']['vms'], st['guests']['containers']
    # the tiles are Testi alone now, each one names what it leaves out
    assert _stat(page, 'vms')['value'] == f"{vms['running']}/{vms['total']}"
    assert _stat(page, 'cts')['value'] == f"{cts['running']}/{cts['total']}"
    mem = st['resources']['memory']
    assert _stat(page, 'mem')['sub'] == f"{_bytes(mem['used'])} of {_bytes(mem['total'])}"
    for sid in ('vms', 'cts', 'cpu', 'mem', 'storage'):
        assert _note(page, sid) == '1 cluster(s) not counted', sid
    assert _note(page, 'clusters') == '1 without a current status'
    assert 'Prod' in (page.locator('[data-cr-stat="vms"]').get_attribute('title') or '')
    prod = _row(page, 'Prod')
    col = lambda key: _col(page, 'dash-clusters', key)  # noqa: E731
    assert prod[col('status')] == 'Not current'
    assert (prod[col('nodes')], prod[col('vms')], prod[col('cpu')], prod[col('storage')]) == ('-', '-', '-', '-')
    assert 'cr-dot-success' not in _row_dot(page, 'Prod')
    # Online is what the rows call Online
    assert _chip(page, 'online') == '1' and _chip(page, 'unread') == '1'
    _no_errors(app)


def test_runtime_a_status_that_never_came_is_not_counted_and_its_row_is_not_online(opener):
    status = {'c1': STATUS['c1']}
    app = opener(status=status, extra={('GET', '/api/clusters/c2/datacenter/status'): (502, {'error': 'refused', 'unread': ['cluster']})})
    page = app.page
    page.locator('[data-cr-stat="vms"]').wait_for(timeout=15000)
    page.wait_for_timeout(800)
    vms = STATUS['c1']['guests']['vms']
    assert _stat(page, 'vms')['value'] == f"{vms['running']}/{vms['total']}"
    assert _note(page, 'vms') == '1 cluster(s) not counted'
    # first it is being read, a while later it is not read; never Online, never a green dot
    col = lambda key: _col(page, 'dash-clusters', key)  # noqa: E731
    assert _row(page, 'Prod')[col('status')] in ('Reading', 'Not read')
    assert 'cr-dot-success' not in _row_dot(page, 'Prod')
    app.ctx.clock.set_fixed_time(FIXED + 60)
    _until(page, '() => !!document.querySelector(\'[data-cr-table="dash-clusters"] [data-cr-cl-state="unread"]\')',
           'a status that did not come is "Not read" once the wait is over', timeout=15000)
    assert _row(page, 'Prod')[col('status')] == 'Not read'
    assert _chip(page, 'online') == '1'
    page.locator('[data-cr-table="dash-clusters"] [data-cr-show="unread"]').click()
    names = [r[col('name')] for r in _rows(page, 'dash-clusters')]
    assert names == ['Prod'], names
    _no_errors(app)


def test_runtime_esxi_alone_waits_for_no_status(opener):
    esxi = {'id': 'v1', 'name': 'esx01', 'display_name': 'esx01', 'host': '10.0.0.9', 'connected': True,
            'status': 'running', 'cluster_type': 'esxi', 'enabled': True}
    app = opener(clusters=[esxi], status={})
    page = app.page
    page.locator('[data-cr-stat="clusters"]').wait_for(timeout=15000)
    page.wait_for_timeout(2500)
    assert page.locator('[data-cr-stat="waiting"]').count() == 0, 'an ESXi host has no datacenter status to wait for'
    assert _stat(page, 'clusters')['value'] == '1/1'
    _no_errors(app)


def test_runtime_byte_sizes_follow_the_ui_language(opener):
    app = opener(language='de')
    page = app.page
    page.locator('[data-cr-stat="mem"]').wait_for(timeout=15000)
    used = sum(s['resources']['memory']['used'] for s in STATUS.values())
    total = sum(s['resources']['memory']['total'] for s in STATUS.values())
    want = f"{_bytes(used)} von {_bytes(total)}".replace('.', ',')
    assert _stat(page, 'mem')['sub'] == want
    _no_errors(app)


def test_runtime_the_dashboard_links_the_topology_and_the_status_bar_counts_every_cluster(opener):
    app = opener()
    page = app.page
    page.locator('[data-cr-stat="vms"]').wait_for(timeout=15000)
    # the guests of Testi and Prod as their status counts them; classic said 0/0 here
    run = sum(s['guests'][k]['running'] for s in STATUS.values() for k in ('vms', 'containers'))
    total = sum(s['guests'][k]['total'] for s in STATUS.values() for k in ('vms', 'containers'))
    _need(page, '[data-cr-status-guests]', 'the status bar counts the guests of All Clusters')
    assert page.locator('[data-cr-status-guests]').inner_text().strip() == f'{run}/{total} VMs'
    # no figure in it calls the layout a preview
    title = page.locator('[data-cr-stat="storage"]').get_attribute('title') or ''
    assert 'warning from 70%' in title and 'preview' not in title.lower(), title
    _need(page, '[data-cr-dash-topology]', 'the dashboard points to the Topology view')
    page.locator('[data-cr-dash-topology]').click()
    _need(page, '[data-cr-topo-root="multi"]', 'the link opens the topology of every cluster')
    _no_errors(app)


# --- the overview storage bar takes the storage pair -----------------------------------------

def test_runtime_the_overview_storage_bar_takes_the_storage_pair(opener):
    store = {'storage': 'ceph', 'type': 'rbd', 'content': 'images,rootdir', 'total': 1000 * GIB, 'used': 750 * GIB,
             'avail': 250 * GIB, 'active': 1, 'enabled': 1, 'shared': True, 'active_on': ['pve1', 'pve2'], 'inactive_on': []}
    app = opener(extra={('GET', '/api/clusters/c1/datastores'): (200, {'shared': [store], 'local': {}, 'nodes': ['pve1', 'pve2'],
                                                                       'offline_nodes': []})})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    bar = page.locator('[data-cr-cluster-summary] [data-cr-stat="storage"] .cr-stat-bar')
    bar.wait_for(timeout=15000)
    _until(page, '''() => /75\\.0%/.test((document.querySelector('[data-cr-cluster-summary] [data-cr-stat="storage"] .cr-stat-value') || {}).innerText || '')''',
           'the overview reads 75 % from the datastores')
    # 75 % is a warning by the storage pair (70/85), green by the CPU pair (80/90)
    assert 'cr-tone-warning' in bar.get_attribute('class'), bar.get_attribute('class')
    _no_errors(app)


# --- compliance: parallel, failures said, no dead column -----------------------------------------

NODES20 = [f'pve{i:02d}' for i in range(1, 21)]


class _ManyNodes(_CmpServer):
    """Testi with 20 nodes. ssh_off: every check answers SSH switched off (an old server: not
    marked cluster wide). hold: the checks wait until the test answers them."""

    def __init__(self, ssh_off=False, hold=False, **kw):
        extra = {('GET', '/api/clusters/c1/nodes'): (200, [{'node': n} for n in NODES20])}
        extra.update(kw.pop('extra', {}))
        super().__init__(extra=extra, **kw)
        self.ssh_off, self.hold = ssh_off, hold
        self.held = []
        self.checks = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/c1/nodes/([^/]+)/hardening', path)
        if req.url.startswith(BASE) and m and req.method == 'GET' and m.group(1) in NODES20:
            self.checks.append(m.group(1))
            if self.hold:
                self.held.append((route, m.group(1)))
                return None
            if self.ssh_off:
                body = {'error': f'Cannot read {m.group(1)} over SSH: SSH to this cluster is switched off',
                        'code': 'SSH_DISABLED', 'hint': 'SSH to this cluster is switched off in its settings.',
                        'node': m.group(1), 'cluster_wide': False}
                return route.fulfill(status=412, body=json.dumps(body), headers=JSON)
            return route.fulfill(status=200, body=json.dumps(self.verdict(m.group(1))), headers=JSON)
        return super().handle(route)

    @staticmethod
    def verdict(node):
        return {'node': node, 'profile': 'cis-l1', 'controls': {'fs_modules': True, 'core_dumps': False}}

    def answer(self, n=1):
        take, self.held = self.held[:n], self.held[n:]
        for route, node in take:
            route.fulfill(status=200, body=json.dumps(self.verdict(node)), headers=JSON)

    def drop_held(self):
        for route, _ in self.held:
            try:
                route.abort()
            except Exception:
                pass
        self.held = []


def _compliance(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="compliance"]').click()
    _need(page, '[data-cr-compliance]', 'the compliance page', timeout=20000)


def test_runtime_the_node_checks_run_side_by_side_and_the_page_fills_as_they_answer(opener):
    app = opener(_ManyNodes, hold=True)
    page = app.page
    try:
        _compliance(page)
        # wait for the first wave to stand still
        last, still = -1, 0
        for _ in range(60):
            page.wait_for_timeout(150)
            n = len(app.server.held)
            still = still + 1 if n == last and n > 0 else 0
            last = n
            if still >= 6:
                break
        assert 1 < len(app.server.held) <= 8, ('the checks run side by side, a few at a time', len(app.server.held))
        app.server.answer(1)
        _until(page, '''() => document.querySelectorAll('[data-cr-table="cmp-nodes"] tbody tr.cr-row').length === 1''',
               'the first answer is on the page before the others came')
        sub = page.locator('[data-cr-stat="nodes"] .cr-stat-sub').inner_text().strip()
        assert sub == '1 of 20 read', sub
        # the rest, as they come
        for _ in range(40):
            if len(app.server.checks) >= 20 and not app.server.held:
                break
            app.server.answer(len(app.server.held))
            page.wait_for_timeout(100)
        _until(page, '''() => document.querySelectorAll('[data-cr-table="cmp-nodes"] tbody tr.cr-row').length === 20''',
               'every node is in once all answered')
        assert sorted(app.server.checks) == NODES20
    finally:
        app.server.drop_held()
    _no_errors(app)


def test_runtime_ssh_switched_off_is_said_once_and_the_other_nodes_are_not_asked(opener):
    app = opener(_ManyNodes, ssh_off=True)
    page = app.page
    _compliance(page)
    _need(page, '[data-cr-cmp-cluster-error="SSH_DISABLED"]', 'SSH switched off is a callout for the whole cluster', timeout=20000)
    page.wait_for_timeout(1500)
    text = page.locator('[data-cr-cmp-cluster-error]').inner_text()
    assert 'SSH to this cluster is switched off in its settings.' in text
    assert 'Settings > Clusters' in text, text
    assert len(app.server.checks) <= 8, ('the other nodes are not asked', len(app.server.checks))
    _no_errors(app)


def test_runtime_a_node_list_that_could_not_be_read_is_said_with_retry(opener):
    app = opener(_CmpServer, nodes_status=502)
    page = app.page
    _compliance(page)
    _need(page, '[data-cr-cmp-cluster-error="NODES_UNREAD"]', 'a failed node list read is said', timeout=20000)
    text = page.locator('[data-cr-cmp-cluster-error]').inner_text()
    assert 'Compliance not checked' in text and 'HTTP 502' in text, text
    before = sum(1 for c in app.server.calls if c == ('GET', '/api/clusters/c1/nodes'))
    page.locator('[data-cr-cmp-retry]').click()
    page.wait_for_timeout(1000)
    after = sum(1 for c in app.server.calls if c == ('GET', '/api/clusters/c1/nodes'))
    assert after > before, (before, after)
    _no_errors(app)


def test_runtime_the_controls_table_has_no_column_that_cannot_fill(opener):
    app = opener(_ManyNodes)
    page = app.page
    _compliance(page)
    _until(page, '''() => document.querySelectorAll('[data-cr-table="cmp-nodes"] tbody tr.cr-row').length === 20''',
           'every node answered')
    page.locator('[data-cr-table="cmp-controls"] [data-cr-colmenu]').click()
    cols = page.locator('.cr-menu input[data-cr-col]').evaluate_all('es => es.map(e => e.dataset.crCol)')
    assert 'evidence' not in cols, cols
    assert 'fws' in cols, cols
    # the page asks once per node, without verbose
    assert not any('verbose' in u for u in app.server.urls if '/hardening' in u)
    _no_errors(app)


# --- topology ------------------------------------------------------------------------------------

def _guests(page):
    return page.locator('[data-cr-topo-root="single"] [data-cr-topo="guest"]').count()


def test_runtime_collapse_nodes_by_default_folds_the_nodes(opener):
    app = opener(_TopoServer, storage={'pegaprox-nodes-default-collapsed': '1'})
    page = app.page
    _cluster_topo(page)
    page.wait_for_timeout(500)
    assert _guests(page) == 0, 'with the setting on every node starts folded'
    assert page.locator('[data-cr-topo-root="single"] [data-cr-topo="fold"]').count() >= 2
    # switched off in Settings > Display: the nodes open again without a reload
    page.evaluate("() => window.dispatchEvent(new CustomEvent('pegaprox-node-collapse-pref', { detail: false }))")
    _until(page, '() => document.querySelectorAll(\'[data-cr-topo-root="single"] [data-cr-topo="guest"]\').length > 0',
           'the setting switched off opens the nodes again')
    _no_errors(app)


def test_runtime_the_cards_view_lists_the_nodes_and_their_guests(opener):
    app = opener(_TopoServer, storage={'pegaprox-nodes-default-collapsed': '1'})
    page = app.page
    _cluster_topo(page)
    _need(page, '[data-cr-topo-view="cards"]', 'the topology offers Cards next to Diagram')
    page.locator('[data-cr-topo-view="cards"]').click()
    _need(page, '[data-cr-topo-cards]', 'the cards view')
    cards = page.locator('[data-cr-topo-card]').evaluate_all('es => es.map(e => [e.dataset.crTopoCard, e.dataset.open])')
    assert cards == [['pve1', '0'], ['pve2', '0']], cards
    assert page.locator('[data-cr-topo-card-guest]').count() == 0
    # unfold pve1: its two guests; pve2 has 21, the first five and "show all"
    page.locator('[data-cr-topo-card="pve1"] [data-cr-topo-card-fold]').click()
    assert page.locator('[data-cr-topo-card="pve1"] [data-cr-topo-card-guest]').count() == 2
    page.locator('[data-cr-topo-card="pve2"] [data-cr-topo-card-fold]').click()
    assert page.locator('[data-cr-topo-card="pve2"] [data-cr-topo-card-guest]').count() == 5
    page.locator('[data-cr-topo-card="pve2"] [data-cr-topo-card-more]').click()
    assert page.locator('[data-cr-topo-card="pve2"] [data-cr-topo-card-guest]').count() == 21
    # the backup server linked to Testi has a card
    assert page.locator('[data-cr-topo-card-pbs="p1"]').count() == 1
    # a guest opens the guest
    page.locator('[data-cr-topo-card="pve1"] [data-cr-topo-card-guest="100"]').click()
    _need(page, '[data-cr-objhead="vm"]', 'a guest card row opens the guest')
    _no_errors(app)


def test_runtime_a_refused_affinity_read_is_said_next_to_the_chip(opener):
    app = opener(_TopoServer, extra={('GET', '/api/clusters/c1/affinity-rules'): (403, {'error': 'Permission denied'})})
    page = app.page
    _cluster_topo(page)
    page.locator('[data-cr-topo-show="affinity"]').click()
    _need(page, '[data-affinity-unread]', 'a refused affinity read is no "no rules"')
    assert page.locator('[data-affinity-unread]').inner_text().strip() == 'The affinity rules could not be read'
    _no_errors(app)


def test_runtime_a_backup_server_linked_to_no_cluster_is_drawn_for_the_cluster(opener):
    app = opener(_TopoServer, extra={('GET', '/api/pbs'): (200, [dict(PBS, linked_clusters=[])])})
    page = app.page
    _cluster_topo(page)
    page.wait_for_timeout(500)
    keys = page.evaluate('() => Array.from(document.querySelectorAll(\'[data-cr-topo="pbs"]\')).map(e => e.dataset.k)')
    assert keys == ['p:c1:p1'], keys
    _no_errors(app)


# --- the shell -----------------------------------------------------------------------------------

def test_runtime_the_folded_rail_opens_the_tools(opener):
    app = opener(storage={'cr-sidebar-collapsed': '1'})
    page = app.page
    _need(page, '.cr-rail', 'the folded sidebar is a rail')
    tools = page.locator('.cr-rail [data-cr-rail-tool]').evaluate_all('es => es.map(e => e.dataset.crRailTool)')
    # Testi and Prod are connected, two clusters: EVPN is there, no XCP-ng pair, auto install is for the admin
    assert tools[:3] == ['guests', 'topology', 'worldmap'] and 'mcevpn' in tools, tools
    page.locator('.cr-rail [data-cr-rail-tool="topology"]').click()
    _need(page, '[data-cr-topo-root="multi"]', 'the rail opens the Topology view')
    assert page.locator('.cr-rail').count() == 1, 'the sidebar stays folded'
    assert page.locator('.cr-rail [data-cr-rail-tool="topology"]').get_attribute('aria-pressed') == 'true'
    _no_errors(app)


def test_runtime_the_trail_stays_on_a_phone(opener):
    app = opener()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _need(page, '[data-cr-objhead="cluster"]', 'Testi is open')
    # the phone width with Testi open (the sidebar is a drawer there)
    page.set_viewport_size({'width': 800, 'height': 900})
    page.wait_for_timeout(500)
    shown = page.evaluate('''() => { const n = document.querySelector('.cr-crumbs'); if (!n) return null;
        const s = getComputedStyle(n); const items = Array.from(n.querySelectorAll('li')).filter(li => getComputedStyle(li).display !== 'none');
        return { display: s.display, items: items.map(li => li.innerText.replace('/', '').trim()),
                 right: Math.max(...items.map(li => li.getBoundingClientRect().right)) }; }''')
    assert shown and shown['display'] != 'none', shown
    assert shown['items'] == ['Testi', 'Overview'], shown
    assert shown['right'] <= 800, shown
    assert page.evaluate('() => document.scrollingElement.scrollWidth <= window.innerWidth')
    _no_errors(app)


def test_runtime_a_group_left_behind_is_not_in_the_trail(opener):
    app = opener()
    page = app.page
    _need(page, '.corp-tree-item', 'the sidebar tree')
    page.get_by_role('button', name='EU', exact=True).first.click()
    page.wait_for_timeout(600)
    assert _crumbs(page)[:2] == ['All', 'EU'], _crumbs(page)
    # Testi is in no group: the trail does not name EU over it
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _need(page, '[data-cr-objhead="cluster"]', 'Testi is open')
    assert 'EU' not in _crumbs(page), _crumbs(page)
    # Prod is in EU: picked from the group's overview the trail keeps it
    page.get_by_role('button', name='EU', exact=True).first.click()
    page.wait_for_timeout(600)
    page.locator('.corp-tree-item', has_text='Prod').first.click()
    page.wait_for_timeout(600)
    assert _crumbs(page)[:3] == ['All', 'EU', 'Prod'], _crumbs(page)
    _no_errors(app)


# --- the layout choice ---------------------------------------------------------------------------

class _BundleFake(_FakeServer):
    def handle(self, route):
        path = re.sub(r'^https?://[^/]+', '', route.request.url).split('?')[0]
        if BUNDLE is not None and route.request.url.startswith(BASE) and path in ('/', '/index.html'):
            return route.fulfill(status=200, body=BUNDLE, headers=HTML)
        return super().handle(route)


class _FirstLogin(_App):
    def wait_for_app(self):
        self.page.get_by_text('Corporate').first.wait_for(timeout=30000)
        self.page.wait_for_timeout(300)


def test_runtime_the_first_login_offers_corporate_redesigned(browser):
    user = {'username': 'admin', 'role': 'admin', 'display_name': 'Admin', 'ui_layout': 'modern',
            'layout_chosen': False, 'theme': '', 'language': 'en', 'permissions': [], 'enabled': True,
            'auth_source': 'local'}
    saved = {'ui_layout': 'corporate-redesigned', 'layout_chosen': True}
    srv = _BundleFake(role='standalone', extra={
        ('GET', '/api/auth/check'): (200, {'authenticated': True, 'session_id': 'sid', 'user': user,
                                           'ha': {}, 'default_theme': 'proxmoxDark'}),
        ('PUT', '/api/user/preferences'): (200, {'success': True, 'preferences': saved}),
    })
    app = _FirstLogin(browser, srv)
    try:
        page = app.page
        card = page.locator('[data-layout-pick="corporate-redesigned"]')
        try:
            card.wait_for(timeout=5000)
        except Exception:
            raise AssertionError('the first login offers Corporate Redesigned') from None
        assert 'Corporate Redesigned' in card.inner_text() and 'preview' not in card.inner_text().lower()
        card.click()
        page.wait_for_timeout(800)
        bodies = srv.bodies.get('/api/user/preferences', [])
        assert {'ui_layout': 'corporate-redesigned', 'layout_chosen': True} in bodies, bodies
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_the_profile_card_calls_the_layout_no_preview(opener):
    app = opener()
    page = app.page
    page.locator('[data-user-menu]').click()
    page.get_by_text('My Profile').first.click()
    card = page.locator('[data-layout-pick="corporate-redesigned"]')
    card.wait_for(timeout=5000)
    text = card.text_content()
    assert 'Corporate Redesigned' in text and 'preview' not in text.lower(), text
    _no_errors(app)


class _BundleLock(_LockServer):
    def handle(self, route):
        path = re.sub(r'^https?://[^/]+', '', route.request.url).split('?')[0]
        if BUNDLE is not None and route.request.url.startswith(BASE) and path in ('/', '/index.html'):
            return route.fulfill(status=200, body=BUNDLE, headers=HTML)
        return super().handle(route)


def test_runtime_an_admin_can_pin_corporate_redesigned_and_it_is_drawn(browser):
    # the admin's own card: the select offers it and shows the stored pin
    admin = _Page(browser, _BundleLock(admin=True, language='en', lock={'layout': 'corporate-redesigned'}))
    try:
        page = _to_server_tab(admin)
        values = page.locator('#ui-layout-lock option').evaluate_all('os => os.map(o => o.value)')
        assert values == ['', 'modern', 'corporate', 'corporate-redesigned', 'cloud'], values
        assert page.locator('#ui-layout-lock').input_value() == 'corporate-redesigned'
        assert not admin.errors, admin.errors
    finally:
        admin.ctx.close()
    # a user it holds gets the redesign, whatever they chose for themselves
    user = _Page(browser, _BundleLock(admin=False, language='en', lock={'layout': 'corporate-redesigned'}))
    try:
        user.page.wait_for_function('() => document.body.dataset.corpVariant === "redesigned"', timeout=10000)
        assert user.page.evaluate('() => document.body.getAttribute("data-layout")') == 'corporate'
    except Exception:
        raise AssertionError('a pin to Corporate Redesigned draws the redesign') from None
    finally:
        user.ctx.close()


# --- tasks: today ---------------------------------------------------------------------------------

def test_runtime_the_task_drawer_filters_todays_tasks(opener):
    lists = {'c1': shaped([_task('pve1', 1, 'qmstart', 100, 'OK', 600),
                           _task('pve1', 2, 'qmstop', 101, 'OK', 2 * 86400),
                           _task('pve1', 3, 'vzdump', 102, 'OK', 3 * 86400)], 'real'), 'c2': []}
    app = opener(_TaskServer, lists=lists)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=10000)
    page.locator('[data-cr-tc-toggle]').first.click()
    _until(page, '() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === 3', 'the three tasks')
    _need(page, '[data-cr-tc-today]', 'the drawer has a Today filter')
    chip = page.locator('[data-cr-tc-today]')
    assert re.sub(r'\s+', ' ', chip.inner_text()).strip() == 'Today 1'
    chip.click()
    assert chip.get_attribute('aria-pressed') == 'true'
    _until(page, '() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === 1', 'only the task of today')
    # it counts as a filter, and Clear takes it away
    page.locator('[data-cr-tc-clearfilters]').click()
    _until(page, '() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === 3', 'all three again')
    assert chip.get_attribute('aria-pressed') == 'false'
    _no_errors(app)


# --- Automation > Alerts: a failed read of the active alerts --------------------------------------

def test_runtime_a_failed_active_alerts_read_is_said_with_retry(opener):
    app = opener(extra={('GET', '/api/clusters/c1/active-alerts'): (500, {'error': 'boom'})})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(400)
    page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Alerts\s*$')).first.click()
    _need(page, '[data-cr-auto-alerts-unread="500"]', 'a failed read of the active alerts is said, not an empty list')
    text = page.locator('[data-cr-auto-alerts-unread]').inner_text()
    assert 'could not be read (HTTP 500)' in text, text
    reads = lambda: sum(1 for c in app.server.calls if c == ('GET', '/api/clusters/c1/active-alerts'))  # noqa: E731
    before = reads()
    page.locator('[data-cr-auto-alerts-retry]').click()
    page.wait_for_timeout(1000)
    assert reads() > before, 'Retry reads again'
    # the answer comes back: the note goes
    app.server.extra[('GET', '/api/clusters/c1/active-alerts')] = (200, {'active_alerts': []})
    page.locator('[data-cr-auto-alerts-retry]').click()
    _until(page, '() => !document.querySelector("[data-cr-auto-alerts-unread]")', 'a read that answered takes the note away')
    _no_errors(app)


def test_runtime_the_routes_own_failure_answer_is_said_by_its_text(opener):
    # get_active_alerts answers a failed read with 200, an empty list and the error text
    app = opener(extra={('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': [], 'error': 'Alert operation failed'})})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(400)
    page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Alerts\s*$')).first.click()
    _need(page, '[data-cr-auto-alerts-unread]', 'the route\'s own failure answer is said, not an empty list')
    text = page.locator('[data-cr-auto-alerts-unread]').inner_text()
    assert 'could not be read (Alert operation failed)' in text, text
    assert 'HTTP 200' not in text, text
    _no_errors(app)


# --- All Clusters: the tile and the table title name the clusters, not a count form ----------------

def test_runtime_the_cluster_tile_and_table_title_say_clusters(opener):
    app = opener()
    page = app.page
    page.locator('[data-cr-stat="clusters"]').wait_for(timeout=15000)
    label = page.locator('[data-cr-stat="clusters"] .cr-stat-label').inner_text().strip()
    title = page.locator('[data-cr-table="dash-clusters"] .cr-table-title').first.inner_text().strip()
    # classic writes 'cluster(s)' next to its numbers; a heading has no number to agree with
    assert label.lower() == 'clusters', label
    assert title.lower() == 'clusters', title
    _no_errors(app)
