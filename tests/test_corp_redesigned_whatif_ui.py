"""Reports > What-if of Corporate Redesigned (Preview), and the links between the modules, in the browser.

The page runs the existing simulator: the options on open, a scenario or the ranking only on a
click, one at a time. Its reports are what pegaprox/core/whatif.py answers (generated here by
the real engine on a small cluster), shown with what each statement rests on. A report with
guests the engine could not judge or configs it did not read is incomplete whatever its
verdict; a node's figure takes the threshold the report used; the headroom headline carries its
own assumptions and says how many combinations it shows. Refused, failed and unreachable runs
are said, never drawn as a report. The ranking is a table of single points of failure with its
caps and gaps, and a confined account is told it is not for it. The capacity panel beside the
picker shows the Insights forecast and right-sizing and the node figures now, labelled, never
mixed into the simulation. The links of the redesign lead into Reports > Insights / What-if,
Compliance > Config Drift and the Datacenter sections, and the classic layouts keep their pages.

PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the build before
stage J). Skips without Playwright. LW Oct 2026
"""
import copy
import json
import os
import re
import time

import pytest

from pegaprox.core import whatif
from test_corp_redesigned_dashboard_ui import _crumbs
from test_corp_redesigned_guard_ui import CT, DETERMINISTIC, DRIFT_EVENTS, VM, VM_OFF, _GuardApp
from test_corp_redesigned_reports_ui import FORECAST, _RpServer, _rs
from test_ha_ui import BASE, NODE_METRICS
from test_whatif import NETS, THR, _cfg, _cluster, _manager, _vm
from test_whatif_risk import _pve

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3
URL = '/api/clusters/c1/whatif'
RANK = URL + '/ranking'

# the guests of the dashboard and of the engine's cluster are the same, so the rows link
WEB = dict(VM, tags='critical;web')
CT1 = dict(CT)
DB = dict(VM_OFF)
APP = dict(VM, vmid=103, name='app01', node='pve2')
CACHE = dict(VM, vmid=104, name='cache01')
GUESTS = [WEB, CT1, DB, APP, CACHE]
NODES = ('pve1', 'pve2', 'pve3')
METRICS = {n: dict(NODE_METRICS['pve1'], cpu_percent=12.0, mem_percent=35.0) for n in NODES}
METRICS['pve2'] = dict(METRICS['pve2'], mem_percent=86.0)
DATASTORES = {'shared': [{'storage': 'ceph', 'type': 'rbd', 'content': 'images,rootdir', 'total': 1000 * GIB, 'used': 400 * GIB,
                          'avail': 600 * GIB, 'active': 1, 'enabled': 1, 'shared': True, 'active_on': list(NODES), 'inactive_on': []}],
              'local': {n: [] for n in NODES}, 'nodes': list(NODES), 'offline_nodes': []}


def _json(x):
    return json.loads(json.dumps(x))


def _engine(fn, tenants=True):
    """Runs fn with the restore marks and tenants of the engine fixed (none read from a database)."""
    marks, before = whatif._marks, whatif._tenants
    whatif._marks = lambda cid: {}
    whatif._tenants = lambda cid: [{'id': 'acme', 'name': 'Acme Corp'}] if tenants else []
    try:
        return _json(fn())
    finally:
        whatif._marks, whatif._tenants = marks, before


def _mgr(nodes=NODES, guests=None, cores=16):
    g = guests or [dict(_vm(x['vmid'], x['node'], x['type'], x['status']), name=x['name'], tags=x.get('tags', '')) for x in GUESTS]
    cfg = {100: _cfg(), 101: {'rootfs': 'ceph:vm-101-disk-0', 'net0': 'name=eth0,bridge=vmbr0'}, 102: _cfg(), 103: _cfg('local-lvm')}
    api = _cluster(g, cfg, ha=[('vm:100', 'started'), ('ct:101', 'started')], extra=NETS)
    api[('/nodes/pve1/storage/ceph/content', 'images')] = [{'vmid': 100}, {'vmid': 102}]
    api[('/nodes/pve1/storage/ceph/content', 'rootdir')] = [{'vmid': 101}]
    for n in nodes:
        api.setdefault(f'/nodes/{n}/network', [{'iface': 'vmbr0', 'type': 'bridge'}])
    return _manager(api, g, nodes=nodes, cores=cores)


def report(tenants=True, **body):
    """The route's answer for one scenario on the cluster above (thresholds as thresholds_for says them)."""
    thr = dict(THR, cpu_source='default', memory_source='default')

    def go():
        r = whatif.run(_mgr(), whatif.parse_scenario(body), dict(thr, nodes={}))
        r['thresholds'] = {k: v for k, v in thr.items()}
        return r
    out = _engine(go, tenants)
    out.update(guests_hidden=0, guests_truncated=0)
    return out


def options():
    out = _engine(lambda: whatif.options(_mgr()))
    out['thresholds'] = {'cpu': 80.0, 'memory': 90.0, 'cpu_source': 'default', 'memory_source': 'alert_rule'}
    return out


def ranking():
    return _engine(lambda: whatif.ranking(_mgr(), dict(THR)))


def headroom_report(n=21):
    """N+2 on n nodes: n*(n-1)/2 pairs, 60 placed guest by guest, the rest by totals, 200 shown."""
    nodes = tuple(f'pve{i}' for i in range(1, n + 1))
    guests = [dict(_vm(200 + i, nodes[i % n], mem=2 + i % 5, maxmem=8), name=f'g{200 + i}') for i in range(3 * n)]

    def go():
        m = _manager(_cluster(guests, {}), guests, nodes=nodes, mem_used=40, mem_total=64)
        return whatif.run(m, whatif.parse_scenario({'type': 'headroom', 'depth': 2}), dict(THR))
    out = _engine(go)
    out.update(guests_hidden=0, guests_truncated=0)
    return out


def pbs_report():
    def go():
        guests, pve = _pve(tags={100: 'critical', 101: 'db'},
                           jobs=[{'id': 'job-a', 'storage': 'pbs1', 'all': 1, 'exclude': '103', 'schedule': '01:00'}])
        return whatif.run(_manager(pve, guests), whatif.parse_scenario({'type': 'pbs_failure', 'storage': 'pbs1'}), dict(THR))
    out = _engine(go)
    out.update(guests_hidden=0, guests_truncated=0)
    return out


OPTIONS = options()
NODE_FAIL = report(type='node_failure', nodes=['pve1'])


class _WiServer(_RpServer):
    """The reports fake (forecast, right-sizing) plus the three what-if routes and the datastores,
    each settable as (code, body), a callable of the request body, 'abort' or 'hold'."""

    def __init__(self, opts=None, run=None, rank=None, guests=None, node_metrics=None, **kw):
        super().__init__(guests=list(GUESTS if guests is None else guests),
                         node_metrics=node_metrics if node_metrics is not None else METRICS, **kw)
        self.routes.update({
            ('GET', URL + '/options'): opts or (200, OPTIONS),
            ('POST', URL): run or self.run_route,
            ('POST', RANK): rank or (200, ranking()),
            ('GET', '/api/clusters/c1/datastores'): (200, DATASTORES),
        })
        self.sent = {}

    @staticmethod
    def run_route(body):
        return 200, report(**body)

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path)) if req.url.startswith(BASE) else None
        if how is not None and req.method == 'POST':
            body = json.loads(req.post_data) if req.post_data else {}
            self.sent.setdefault(path, []).append(body)
            if callable(how):
                self.calls.append((req.method, path))
                self.urls.append(req.url)
                code, data = how(body)
                return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, theme='', storage=None, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _WiServer(layout=layout, bundle=BUNDLE, **kw), corp_theme=theme,
                        storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -------------------------------------------------------------------------------------

def _wait(page, fn, seconds=6):
    deadline = time.time() + seconds
    while time.time() < deadline and not fn():
        page.wait_for_timeout(100)
    return fn()


def _no_errors(app, dropped=False):
    errors = [e for e in app.errors if not (dropped and 'Failed to fetch' in e)]
    assert not errors, errors


def _calls(app, path, method=None):
    return [c for c in app.server.calls if c[1] == path and (method is None or c[0] == method)]


def _whatif(page, cluster='Testi'):
    page.locator('.corp-tree-item', has_text=cluster).first.click()
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text='What-if').first.click()
    page.locator('[data-cr-wi]').wait_for(timeout=10000)


def _ready(page):
    assert _wait(page, lambda: page.locator('[data-cr-wi]').get_attribute('data-cr-wi') != 'loading')
    return page.locator('[data-cr-wi]').get_attribute('data-cr-wi')


def _run(page, *nodes):
    for n in nodes:
        page.locator(f'[data-cr-wi-node="{n}"]').check()
    page.locator('[data-cr-wi-run="scenario"]').click()
    assert _wait(page, lambda: page.locator('[data-cr-wi-run-state="running"]').count() == 0, 10)


def _verdict(page):
    v = page.locator('[data-cr-wi-verdict]')
    return v.get_attribute('data-cr-wi-verdict'), v.get_attribute('data-cr-wi-server'), v.inner_text()


def _tiles(page):
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-wi-count]'))
        .map(t => [t.dataset.crWiCount, t.querySelector('.cr-stat-value').innerText.trim()]))''')


def _rows(page, table, cols):
    return page.evaluate('''([table, cols]) => Array.from(document.querySelectorAll(`[data-cr-table="${table}"] tbody tr.cr-row`))
        .map(tr => { const tds = Array.from(tr.children); const heads = Array.from(tr.closest('table').querySelectorAll('thead th'));
                     return Object.fromEntries(cols.map(c => { const i = heads.findIndex(h => h.dataset.crCol === c);
                         return [c, i < 0 ? null : tds[i].innerText.replace(/\\s+/g, ' ').trim()]; })); })''', [table, cols])


# --- opening and the picker ---------------------------------------------------------------------------

def test_runtime_opening_reads_the_options_and_runs_nothing(open_app):
    app = open_app()
    page = app.page
    _whatif(page)
    assert _ready(page) == 'ok'
    # the options, the forecast and the right-sizing beside them; no scenario, no ranking (the
    # overview's capacity card reads its own forecast without a window)
    assert len(_calls(app, URL + '/options', 'GET')) == 1
    assert not _calls(app, URL, 'POST') and not _calls(app, RANK, 'POST')
    assert [c for c in app.server.urls if '/insights/forecast?' in c] == [f'{BASE}/api/clusters/c1/insights/forecast?days=30']
    assert [c for c in app.server.urls if '/insights/right-sizing' in c] == [f'{BASE}/api/clusters/c1/insights/right-sizing?days=30']
    assert page.locator('[data-cr-wi-run-state="idle"]').count() == 1
    assert page.locator('[data-cr-wi-kind]').count() == 6
    assert page.locator('[data-cr-wi-kind="node_failure"]').get_attribute('aria-pressed') == 'true'
    run = page.locator('[data-cr-wi-run="scenario"]')
    assert run.is_disabled()
    assert page.locator('[data-cr-wi-missing]').inner_text() == 'Pick at least one node.'
    # the sources of the thresholds and tags, and what is not simulated
    common = page.locator('[data-cr-wi-common]').inner_text()
    assert 'CPU threshold % (default)' in common and 'Memory threshold % (from alert rules)' in common
    assert 'additional VM' in page.locator('[data-cr-wi-notsim]').inner_text()
    # the trail names the sub tab
    assert _crumbs(page)[-2:] == ['Reports', 'What-if'], _crumbs(page)
    page.wait_for_timeout(1500)
    assert not _calls(app, URL, 'POST')
    _no_errors(app)


def test_runtime_a_node_failure_report_shows_every_outcome_with_its_basis(open_app):
    app = open_app()
    page = app.page
    _whatif(page)
    _ready(page)
    _run(page, 'pve1')
    assert app.server.sent[URL] == [{'type': 'node_failure', 'memory': 'configured', 'nodes': ['pve1']}]
    page.locator('[data-cr-wi-report="node_failure"]').wait_for(timeout=8000)
    state, server, text = _verdict(page)
    assert (state, server) == ('blocked', 'blocked'), text
    assert page.locator('[data-cr-wi-reason="guests_down"]').inner_text() == '1 guest cannot be placed anywhere and stays down'
    assert page.locator('[data-cr-wi-scenario]').inner_text() == 'Node failure: pve1'
    t = _tiles(page)
    assert t == {'down': '1', 'degraded': '0', 'restarted': '2', 'moved': '0', 'unknown': '0', 'unaffected': '1', 'stopped': '1'}, t
    rows = {r['guest'].split(' ')[0]: r for r in _rows(page, 'wi-guests', ['guest', 'node', 'outcome', 'target', 'why', 'restore', 'basis'])}
    assert rows['cache01']['outcome'] == 'Down' and rows['cache01']['why'].startswith('not managed by HA')
    assert rows['web01']['outcome'] == 'Restarted' and 'assumed' in rows['web01']['target']
    assert rows['web01']['restore'] == 'Never tested' and rows['web01']['basis'] == 'known'
    # a critical guest carries its badge; the restore column is the restore test, never "proven"
    assert page.locator('[data-cr-wi-go="guest:100"]').locator('xpath=ancestor::tr').locator('[data-cr-wi-critical]').count() == 1
    assert 'Proven' not in page.locator('[data-cr-wi-guests]').inner_text()
    # limits, assumptions and reads with their basis
    assert page.locator('[data-cr-wi-limit="not_ha"] [data-cr-wi-basis="known"]').count() == 1
    assert page.locator('[data-cr-wi-assumption="tenant_by_cluster"] [data-cr-wi-basis="assumed"]').count() == 1
    assert 'Guest configurations read: 2' in page.locator('[data-cr-wi-reads]').inner_text()
    assert 'Assumed: tenants are counted per cluster' in page.locator('[data-cr-wi-risk-tenants]').inner_text()
    # a tile filters the list, and again shows everything
    page.locator('[data-cr-wi-count="restarted"]').click()
    assert page.locator('[data-cr-wi-count="restarted"]').get_attribute('aria-pressed') == 'true'
    assert {r['outcome'] for r in _rows(page, 'wi-guests', ['outcome'])} == {'Restarted'}
    page.locator('[data-cr-wi-filter="all"]').click()
    assert len(_rows(page, 'wi-guests', ['outcome'])) == 3
    # the guest leads to its view
    page.locator('[data-cr-wi-go="guest:100"]').click()
    page.locator('[data-cr-crumb="guest"]', has_text='web01').wait_for(timeout=5000)
    _no_errors(app)


@pytest.mark.parametrize('case', ['unknown', 'risk', 'ha'])
def test_runtime_a_ready_verdict_with_gaps_is_incomplete_never_ready(open_app, case):
    if case == 'unknown':
        # vmbr1 is on pve1 only and nobody's, cache01's config was not read: the engine itself counts
        # the guest it could not judge as a warning now
        rep = report(tenants=False, type='network_failure', bridge='vmbr1')
        assert rep['verdict']['level'] == 'warning' and rep['summary']['unknown'] == 1
    else:
        rep = copy.deepcopy(report(type='headroom', depth=1))
        assert rep['verdict']['level'] == 'ready'
        if case == 'risk':
            rep['risk'] = None
        else:
            rep['limits'].append({'code': 'ha_unreadable', 'basis': 'known', 'args': {}, 'guests': [],
                                  'text': 'The HA configuration could not be read'})
    app = open_app(run=(200, rep))
    page = app.page
    _whatif(page)
    _ready(page)
    _run(page, 'pve1')
    page.locator('[data-cr-wi-report]').wait_for(timeout=8000)
    state, server, text = _verdict(page)
    if case == 'unknown':
        # gaps still make the result incomplete, the server's warning stands beside it
        assert (state, server) == ('incomplete', 'warning'), text
        assert "The server's verdict: Warning - read the notes before you go on" in text
    else:
        assert (state, server) == ('incomplete', 'ready'), text
        assert "The server's verdict: Ready - nothing in the way" in text
    assert page.locator('.cr-wi-verdict.cr-callout-success').count() == 0
    gap = {'unknown': 'unknown', 'risk': 'risk', 'ha': 'ha_unreadable'}[case]
    assert page.locator(f'[data-cr-wi-gap="{gap}"]').count() == 1
    if case == 'unknown':
        assert page.locator('[data-cr-wi-gap="configs_unread"]').inner_text().startswith('Guest configurations not read in this run: 1')
    _no_errors(app)


def test_runtime_a_complete_ready_report_says_it_is_a_calculation(open_app):
    rep = report(type='headroom', depth=1)
    app = open_app(run=(200, rep))
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-kind="headroom"]').click()
    page.locator('[data-cr-wi-run="scenario"]').click()
    page.locator('[data-cr-wi-report="headroom"]').wait_for(timeout=8000)
    state, server, text = _verdict(page)
    assert (state, server) == ('ready', 'ready')
    assert 'No guest stays down in this calculation' in text and 'Not a guarantee' in text
    # the headroom check carries its own assumption next to the verdict
    assert page.locator('[data-cr-wi-hrnote="headroom_no_storage"]').inner_text() == 'Local disks and storage limits are not applied in the headroom check'
    assert app.server.sent[URL][-1] == {'type': 'headroom', 'memory': 'configured', 'depth': 1, 'guests': 'all'}
    _no_errors(app)


def test_runtime_headroom_says_how_many_combinations_it_shows_and_how_they_were_checked(open_app):
    rep = headroom_report()
    h = rep['headroom']
    assert h['checked'] == 210 and len(h['combinations']) == 200
    app = open_app(run=(200, rep))
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-kind="headroom"]').click()
    page.locator('[data-cr-wi-field="depth"]').select_option('2')
    page.locator('[data-cr-wi-run="scenario"]').click()
    page.locator('[data-cr-wi-headroom]').wait_for(timeout=8000)
    assert page.locator('[data-cr-wi-hrnote="shown"]').inner_text() == 'Showing 200 of 210 failure combinations'
    totals = sum(1 for c in h['combinations'] if c['checked'] == 'totals')
    assert totals > 0
    assert page.locator('[data-cr-wi-hrnote="totals"]').inner_text().startswith(f'{totals} of the 200 combinations shown were checked by totals')
    assert page.locator('[data-cr-wi-hrnote="headroom_pairs"]').inner_text() == '60 of 210 node pairs were placed guest by guest, the others by totals'
    assert page.locator('[data-cr-wi-shown]').inner_text() == 'Showing 200 of 210 failure combinations'
    # no outcome tiles for a check that moves no guest of its own; drawn as a window
    assert page.locator('[data-cr-wi-count]').count() == 0
    # the server's 200 rows, in a scroll box
    assert page.locator('[data-cr-table="wi-headroom"] tbody tr.cr-row').count() == 200
    _no_errors(app)


def test_runtime_maintenance_storage_and_network_send_their_inputs(open_app):
    app = open_app()
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-kind="maintenance"]').click()
    page.locator('[data-cr-wi-node="pve2"]').check()
    page.locator('[data-cr-wi-field="local"]').check()
    page.locator('[data-cr-wi-run="scenario"]').click()
    page.locator('[data-cr-wi-report="maintenance"]').wait_for(timeout=8000)
    assert app.server.sent[URL][-1] == {'type': 'maintenance', 'memory': 'configured', 'nodes': ['pve2'],
                                        'allow_local_disks': True, 'relax_anti_affinity': False}
    page.locator('[data-cr-wi-kind="storage_failure"]').click()
    assert page.locator('[data-cr-wi-missing]').inner_text() == 'Pick a storage.'
    page.locator('[data-cr-wi-field="storage"]').select_option('ceph')
    assert page.locator('[data-cr-wi-field="where"] option').all_inner_texts() == ['All nodes', 'pve1', 'pve2', 'pve3']
    page.locator('[data-cr-wi-run="scenario"]').click()
    page.locator('[data-cr-wi-report="storage_failure"]').wait_for(timeout=8000)
    assert app.server.sent[URL][-1] == {'type': 'storage_failure', 'memory': 'configured', 'storage': 'ceph'}
    # the storage of the report leads to the shared storage
    page.locator('[data-cr-wi-extra="storage"] [data-cr-wi-go="storage:ceph"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-wi-gap]').count() == 0
    page.locator('[data-cr-wi-kind="network_failure"]').click()
    page.locator('[data-cr-wi-field="bridge"]').select_option('vmbr0')
    page.locator('[data-cr-wi-field="vlan"]').fill('5000')
    assert page.locator('[data-cr-wi-missing]').inner_text() == 'The VLAN is a number from 1 to 4094.'
    page.locator('[data-cr-wi-field="vlan"]').fill('20')
    page.locator('[data-cr-wi-field="where"]').select_option('pve1')
    page.locator('[data-cr-wi-run="scenario"]').click()
    page.locator('[data-cr-wi-report="network_failure"]').wait_for(timeout=8000)
    assert app.server.sent[URL][-1] == {'type': 'network_failure', 'memory': 'configured', 'bridge': 'vmbr0', 'vlan': 20, 'node': 'pve1'}
    assert page.locator('[data-cr-wi-scenario]').inner_text() == 'Network failure: vmbr0 VLAN 20 on pve1'
    page.locator('[data-cr-wi-extra="network"]').wait_for(timeout=5000)
    _no_errors(app)


def test_runtime_wrong_inputs_keep_run_off_and_changes_are_sent(open_app):
    app = open_app()
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-node="pve1"]').check()
    missing = page.locator('[data-cr-wi-missing]')
    run = page.locator('[data-cr-wi-run="scenario"]')
    for field, value, says in (('cpu', '0', 'The thresholds are numbers from 1 to 100.'),
                               ('cpu', '150', 'The thresholds are numbers from 1 to 100.'),
                               ('tags', 'prod, bad tag!', 'A critical tag is a word of letters, digits, . _ + -')):
        page.locator(f'[data-cr-wi-field="{field}"]').fill(value)
        assert missing.inner_text() == says and run.is_disabled(), field
        page.locator(f'[data-cr-wi-field="{field}"]').fill({'cpu': '80', 'tags': 'critical'}[field])
    assert missing.count() == 0 and not run.is_disabled()
    page.locator('[data-cr-wi-field="cpu"]').fill('70')
    page.locator('[data-cr-wi-field="tags"]').fill('critical, Prod')
    page.locator('[data-cr-wi-field="memory"]').select_option('current')
    run.click()
    page.locator('[data-cr-wi-report]').wait_for(timeout=8000)
    assert app.server.sent[URL][-1] == {'type': 'node_failure', 'memory': 'current', 'critical_tags': ['critical', 'prod'],
                                        'thresholds': {'cpu': 70.0}, 'nodes': ['pve1']}
    # a PBS run needs a PBS storage: the cluster above has one
    page.locator('[data-cr-wi-kind="pbs_failure"]').click()
    assert missing.inner_text() == 'Pick a backup storage.'
    _no_errors(app)


def test_runtime_at_most_sixteen_nodes_and_a_filter_for_many(open_app):
    opts = copy.deepcopy(OPTIONS)
    opts['nodes'] = [{'name': f'node{i:03d}', 'status': 'online', 'maintenance': i == 3} for i in range(30)] + \
                    [{'name': 'down1', 'status': 'offline', 'maintenance': False}]
    app = open_app(opts=(200, opts))
    page = app.page
    _whatif(page)
    _ready(page)
    assert page.locator('[data-cr-wi-offline]').inner_text() == 'Offline nodes are not offered, they are down already: 1'
    assert page.locator('[data-cr-wi-node="down1"]').count() == 0
    for i in range(16):
        page.locator(f'[data-cr-wi-node="node{i:03d}"]').check()
    assert page.locator('[data-cr-wi-picked]').inner_text() == '16 picked, at most 16'
    assert page.locator('[data-cr-wi-node="node020"]').is_disabled()
    assert not page.locator('[data-cr-wi-node="node002"]').is_disabled()
    page.locator('[data-cr-wi-nodefilter]').fill('node02')
    assert page.locator('[data-cr-wi-node]').count() == 10
    _no_errors(app)


# --- failed reads and runs -----------------------------------------------------------------------------

@pytest.mark.parametrize('answer,state,says,retry', [
    ((403, {'error': 'Permission denied: cluster.view'}), 'forbidden', 'No permission for the what-if simulator', False),
    ((503, {'error': 'Cluster not connected', 'offline': True}), 'offline', 'not connected', True),
    ((503, {'error': 'The node status of the cluster could not be read'}), 'unreadable', 'node status of the cluster could not be read', True),
    ((500, {'error': 'boom'}), 'error', 'boom', True),
    ('abort', 'unreachable', 'PegaProx could not be reached', True),
    ((200, {'supported': False}), 'unsupported', 'covers Proxmox VE clusters', False),
], ids=['403', 'offline', 'unreadable', '500', 'unreachable', 'unsupported'])
def test_runtime_options_that_could_not_be_read_offer_no_run(open_app, answer, state, says, retry):
    app = open_app(opts=answer)
    page = app.page
    _whatif(page)
    assert _ready(page) == state
    note = page.locator(f'[data-cr-wi-note="opts-{state}"]')
    assert says in note.inner_text(), note.inner_text()
    assert page.locator('[data-cr-wi-run="scenario"]').is_disabled()
    assert page.locator('[data-cr-wi-node]').count() == 0
    assert page.locator(f'[data-cr-wi-retry="opts-{state}"]').count() == (1 if retry else 0)
    if retry:
        before = len(_calls(app, URL + '/options'))
        page.locator(f'[data-cr-wi-retry="opts-{state}"]').click()
        assert _wait(page, lambda: len(_calls(app, URL + '/options')) > before)
    _no_errors(app, dropped=True)


@pytest.mark.parametrize('answer,state,says', [
    ((400, {'error': 'nodes is a list of 1 to 16 node names', 'code': 'bad_nodes'}), 'invalid', 'The server refused this scenario: nodes is a list'),
    ((403, {'error': 'Permission denied'}), 'forbidden', 'No permission'),
    ((503, {'error': 'Cluster not connected', 'offline': True}), 'offline', 'not connected'),
    ((503, {'error': 'The guest list of the cluster could not be read'}), 'unreadable', 'guest list of the cluster could not be read'),
    ((500, {'error': 'The what-if simulation failed'}), 'error', 'The what-if simulation failed'),
    ('abort', 'unreachable', 'PegaProx could not be reached'),
    ((200, {'supported': False}), 'unsupported', 'covers Proxmox VE clusters'),
    ((200, {'supported': True, 'scenario': {'type': 'node_failure'}}), 'malformed', 'could not be read as a report'),
], ids=['400', '403', 'offline', 'unreadable', '500', 'unreachable', 'unsupported', 'malformed'])
def test_runtime_a_failed_run_is_said_never_drawn_as_a_report(open_app, answer, state, says):
    app = open_app(run=answer)
    page = app.page
    _whatif(page)
    _ready(page)
    _run(page, 'pve1')
    box = page.locator(f'[data-cr-wi-run-state="{state}"]')
    box.wait_for(timeout=8000)
    assert says in box.inner_text(), box.inner_text()
    assert page.locator('[data-cr-wi-report]').count() == 0 and page.locator('[data-cr-wi-count]').count() == 0
    if state in ('offline', 'unreadable', 'error', 'unreachable', 'malformed'):
        # the retry sends the same scenario again
        before = len(_calls(app, URL, 'POST'))
        page.locator(f'[data-cr-wi-retry="run-{state}"]').click()
        assert _wait(page, lambda: len(_calls(app, URL, 'POST')) > before)
    _no_errors(app, dropped=True)


def test_runtime_a_run_in_flight_starts_once_and_says_so(open_app):
    app = open_app(run='hold')
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-node="pve1"]').check()
    run = page.locator('[data-cr-wi-run="scenario"]')
    run.click()
    page.locator('[data-cr-wi-run-state="running"]').wait_for(timeout=5000)
    assert run.is_disabled() and run.get_attribute('aria-busy') == 'true'
    run.click(force=True)
    run.press('Enter')
    page.wait_for_timeout(1300)
    assert len(_calls(app, URL, 'POST')) == 1
    assert re.search(r'Simulating on the server\.\.\. [1-9]\d* s', page.locator('[data-cr-wi-run-state="running"]').inner_text())
    app.server.release((200, NODE_FAIL))
    page.locator('[data-cr-wi-report="node_failure"]').wait_for(timeout=5000)
    assert not run.is_disabled()
    _no_errors(app)


def test_runtime_node_figures_take_the_thresholds_of_the_report(open_app):
    rep = copy.deepcopy(NODE_FAIL)
    by = {n['node']: n for n in rep['nodes']}
    # pve2: 75 % after against its own 70 % rule -> over; pve3: 85 % against 90 -> under (80/90 would warn)
    by['pve2'].update(mem_threshold=70.0, mem_after=75.0, over_mem=True)
    by['pve3'].update(mem_threshold=90.0, mem_after=85.0, over_mem=False)
    app = open_app(run=(200, rep))
    page = app.page
    _whatif(page)
    _ready(page)
    _run(page, 'pve1')
    page.locator('[data-cr-table="wi-nodes"]').wait_for(timeout=8000)
    tone = lambda node: page.evaluate('''(node) => {
            const tr = document.querySelector(`[data-cr-table="wi-nodes"] [data-cr-wi-go="node:${node}"]`).closest('tr');
            const i = Array.from(tr.closest('table').querySelectorAll('thead th')).findIndex(h => h.dataset.crCol === 'memA');
            return tr.children[i].querySelector('.cr-meter').className; }''', node)
    assert 'cr-tone-error' in tone('pve2')
    assert 'cr-tone-success' in tone('pve3')
    # the failed node has no after figure, a dash, not 0 %
    rows = {r['node'].split(' ')[0]: r for r in _rows(page, 'wi-nodes', ['node', 'state', 'cpuA', 'memA', 'thr'])}
    assert rows['pve1']['memA'] == '-' and rows['pve1']['state'] == 'failed'
    assert rows['pve2']['thr'] == '80 / 70 %'
    assert page.locator('[data-cr-wi-over="mem"]').count() == 1
    _no_errors(app)


# --- the ranking ----------------------------------------------------------------------------------------

def test_runtime_the_ranking_is_a_table_of_single_points_of_failure_with_its_gaps(open_app):
    rk = ranking()
    rk['capped'] = [{'kind': 'node', 'cap': 100, 'total': 200}]
    rk['skipped'] = [{'kind': 'bridge', 'name': 'vmbr9', 'code': 'unreadable'}]
    rk['stopped'] = {'ranked': 3, 'left': 4}
    rk['configs_unread'] = 2
    app = open_app(rank=(200, rk))
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-view="ranking"]').click()
    assert page.locator('[data-cr-wi-rank="idle"]').count() == 1 and not _calls(app, RANK, 'POST')
    page.locator('[data-cr-wi-run="ranking"]').click()
    page.locator('[data-cr-wi-rank="ok"]').wait_for(timeout=8000)
    assert app.server.sent[RANK] == [{}]
    rows = _rows(page, 'wi-rank', ['n', 'kind', 'name', 'affected', 'weight'])
    assert [r['n'] for r in rows] == [str(i + 1) for i in range(len(rk['ranking']))]
    assert [(r['kind'], r['name'], r['weight']) for r in rows] == [
        ({'node': 'Node', 'storage': 'Shared storage', 'pbs': 'PBS storage', 'bridge': 'Bridge'}[x['kind']], x['name'], '%g' % x['weight'])
        for x in rk['ranking']]
    notes = {k: page.locator(f'[data-cr-wi-note="{k}"]').inner_text() for k in ('capped-node', 'skipped', 'stopped', 'unread')}
    assert notes['capped-node'] == 'Capped: Node, 100 of 200 ranked.'
    assert 'vmbr9 (unreadable)' in notes['skipped'] and '3 run, 4 not run' in notes['stopped']
    assert page.locator('[data-cr-wi-ranked]').inner_text() == f"{len(rk['ranking'])} ranked of {rk['considered']} considered"
    assert 'A ranking aid, not a cost.' in page.locator('[data-cr-wi-weighting]').inner_text()
    # a candidate runs as a scenario of its own
    page.locator('[data-cr-wi-sim="node:pve1"]').click()
    page.locator('[data-cr-wi-report="node_failure"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-wi-view="scenario"]').get_attribute('aria-pressed') == 'true'
    assert app.server.sent[URL] == [{'type': 'node_failure', 'memory': 'configured', 'nodes': ['pve1']}]
    _no_errors(app)


def test_runtime_a_confined_account_is_told_the_ranking_is_not_for_it(open_app):
    app = open_app(rank=(403, {'error': 'Access denied: this action affects the whole cluster'}))
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-view="ranking"]').click()
    page.locator('[data-cr-wi-run="ranking"]').click()
    box = page.locator('[data-cr-wi-rank="denied"]')
    box.wait_for(timeout=8000)
    assert 'Not available for your access' in box.inner_text() and 'affects the whole cluster' in box.inner_text()
    assert 'Nothing to rank' not in page.locator('[data-cr-wi]').inner_text()
    _no_errors(app)


# --- the capacity panel ---------------------------------------------------------------------------------

def test_runtime_the_capacity_panel_shows_measured_and_forecast_apart(open_app):
    app = open_app(rightsizing=(200, _rs(summary={'oversized_cpu': 1, 'oversized_mem': 1, 'undersized_cpu': 0, 'undersized_mem': 0,
                                                   'idle': 0, 'no_data': 1, 'ok': 2})))
    page = app.page
    _whatif(page)
    _ready(page)
    cap = page.locator('[data-cr-wi-cap]')
    page.locator('[data-cr-wi-cap-fc="ok"]').wait_for(timeout=8000)
    assert 'none of it goes into the calculation' in page.locator('[data-cr-wi-capbasis]').inner_text()
    # cluster CPU and memory, then the storages that cross inside the window or are already high
    metrics = [m for m in page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-wi-capm]')).map(e => e.dataset.crWiCapm)''')]
    assert metrics[:2] == ['cluster_cpu', 'cluster_memory']
    # ceph-b trends up inside the window but failed the server's gate: Insights does not estimate it either
    assert set(metrics[2:]) == {'local-lvm', 'nfs-backup'}, metrics
    # the ETA only where the server's rule holds; a weak fit says so
    assert 'Not estimated (weak trend)' in page.locator('[data-cr-wi-capm="cluster_memory"]').inner_text()
    assert 'Already above' in page.locator('[data-cr-wi-capm="nfs-backup"]').inner_text()
    # nodes now: pve2 at 86 % memory, measured now
    assert page.locator('[data-cr-wi-cap-nodes="hot"] [data-cr-wi-hot="pve2"]').count() == 1
    assert page.locator('[data-cr-wi-hot]').count() == 1
    rs = page.locator('[data-cr-wi-rscounts]').inner_text()
    assert 'Evaluated: 3' in rs and 'Oversized: 1' in rs and 'Not enough data: 1' in rs
    text = cap.inner_text().lower()
    assert 'forecast' in text and 'measured' in text and 'now' in text
    # the simulation knows nothing of it: the report has no forecast figure in it
    _run(page, 'pve1')
    assert 'trend' not in page.locator('[data-cr-wi-report]').inner_text().lower()
    # what-if -> insights
    page.locator('[data-cr-wi-insights="cap"]').click()
    page.locator('[data-cr-ins]').wait_for(timeout=8000)
    assert _crumbs(page)[-1] == 'Insights'
    _no_errors(app)


def test_runtime_the_capacity_reads_fail_on_their_own(open_app):
    app = open_app(forecast=(403, {'error': 'Permission denied: cluster.view'}), rightsizing=(500, {'error': 'database is locked'}),
                   node_metrics={})
    page = app.page
    _whatif(page)
    assert _ready(page) == 'ok'
    page.locator('[data-cr-wi-cap-fc="forbidden"]').wait_for(timeout=8000)
    page.locator('[data-cr-wi-cap-rs="error"]').wait_for(timeout=8000)
    assert 'database is locked' in page.locator('[data-cr-wi-note="cap-rs-error"]').inner_text()
    assert page.locator('[data-cr-wi-retry="cap-fc-forbidden"]').count() == 0
    assert page.locator('[data-cr-wi-cap-nodes="unread"]').count() == 1
    # the picker is untouched by them
    assert page.locator('[data-cr-wi-node="pve1"]').count() == 1
    _no_errors(app)


def test_runtime_not_enough_history_is_said_in_the_capacity_panel(open_app):
    app = open_app(forecast=(200, dict(FORECAST, enough_data=False, snapshots_in_window=4, forecasts=[])))
    page = app.page
    _whatif(page)
    page.locator('[data-cr-wi-cap-fc="notenough"]').wait_for(timeout=8000)
    assert '4' in page.locator('[data-cr-wi-capnote="notenough"]').inner_text()
    assert page.locator('[data-cr-wi-capm]').count() == 0
    _no_errors(app)


# --- the PBS scenario and a large report -----------------------------------------------------------------

def test_runtime_a_backup_storage_failure_lists_jobs_restore_points_and_tests(open_app):
    rep = pbs_report()
    app = open_app(run=(200, rep))
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-kind="pbs_failure"]').click()
    page.locator('[data-cr-wi-field="pbs"]').select_option('backups')
    page.locator('[data-cr-wi-run="scenario"]').click()
    page.locator('[data-cr-wi-extra="pbs"]').wait_for(timeout=8000)
    assert app.server.sent[URL][-1] == {'type': 'pbs_failure', 'memory': 'configured', 'storage': 'backups'}
    assert 'Job job-a (01:00)' in page.locator('[data-cr-wi-pbs-jobs]').inner_text()
    p = rep['pbs']
    assert page.locator('[data-cr-wi-pbs-counts]').inner_text() == (
        f"Every listed restore point lost: {p['guests_all_lost']}. Some lost: {p['guests_some_lost']}. "
        f"Covered by a job, none listed: {p['guests_job_only']}.")
    assert page.locator('[data-cr-wi-limits] .cr-panel-title').inner_text().lower() == 'backup limits and gaps found'
    _no_errors(app)


def test_runtime_a_large_report_is_drawn_as_a_window_and_says_how_much_it_lists(open_app):
    rep = copy.deepcopy(NODE_FAIL)
    row = rep['guests'][0]
    rep['guests'] = [dict(row, vmid=5000 + i, name=f'g{i:05d}', outcome=('down', 'restarted', 'unknown')[i % 3]) for i in range(2000)]
    rep['summary'].update(down=1700, restarted=1667, unknown=1633, unaffected=4000, running=9000)
    rep['guests_truncated'] = 3000
    rep['guests_hidden'] = 5
    opts = copy.deepcopy(OPTIONS)
    opts['nodes'] = [{'name': f'pve{i}', 'status': 'online', 'maintenance': False} for i in range(1, 201)]
    app = open_app(run=(200, rep), opts=(200, opts))
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-nodefilter]').fill('pve1')
    t0 = time.time()
    _run(page, 'pve1')
    page.locator('[data-cr-table="wi-guests"] tbody tr.cr-row').first.wait_for(timeout=10000)
    assert time.time() - t0 < 6
    assert 0 < page.locator('[data-cr-table="wi-guests"] tbody tr.cr-row').count() < 120
    assert page.locator('[data-cr-wi-listed]').inner_text() == '2000 listed of 5000 affected'
    assert page.locator('[data-cr-wi-truncated]').inner_text().startswith('The report lists 2000 of 5000 affected guests')
    assert '5' in page.locator('[data-cr-wi-hidden]').inner_text()
    # unknown guests make it incomplete
    assert _verdict(page)[0] == 'blocked' and page.locator('[data-cr-wi-gap="unknown"]').count() == 1
    _no_errors(app)


# --- links between the modules ----------------------------------------------------------------------------

def test_runtime_the_cluster_menu_and_insights_lead_to_the_module_pages(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-dashboard]').wait_for(timeout=10000)
    row = page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text='Testi').first
    row.click(button='right')
    page.locator('.corp-context-menu button', has_text=re.compile(r'^\s*What-if\s*$')).first.click()
    page.locator('[data-cr-wi]').wait_for(timeout=8000)
    assert _crumbs(page)[-3:] == ['Testi', 'Reports', 'What-if'], _crumbs(page)
    page.locator('[data-cr-crumb="all"] button').click()
    page.locator('[data-cr-dashboard]').wait_for(timeout=8000)
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text='Testi').first.click(button='right')
    page.locator('.corp-context-menu button', has_text=re.compile(r'^\s*Insights\s*$')).first.click()
    page.locator('[data-cr-ins]').wait_for(timeout=8000)
    # insights -> what-if
    page.locator('[data-cr-ins-whatif]').click()
    page.locator('[data-cr-wi]').wait_for(timeout=8000)
    page.locator('[data-cr-crumb="all"] button').click()
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text='Testi').first.click(button='right')
    page.locator('.corp-context-menu button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.locator('.corp-tab-strip [data-compliance-sub]').first.wait_for(timeout=8000)
    assert _crumbs(page)[2] == 'Compliance'
    # the health figure says what it is made of
    page.locator('[data-cr-crumb="all"] button').click()
    title = page.locator('[data-cr-table="dash-clusters"] thead th[data-cr-col="health"] [title]').first.get_attribute('title')
    assert 'Compliance and drift are not part of it' in title
    _no_errors(app)


def test_runtime_a_viewer_without_compliance_gets_no_compliance_entry(open_app):
    app = open_app(admin=False, perms=['cluster.view'])
    page = app.page
    page.locator('[data-cr-dashboard]').wait_for(timeout=10000)
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text='Testi').first.click(button='right')
    page.locator('.corp-context-menu button', has_text=re.compile(r'^\s*What-if\s*$')).first.wait_for(timeout=5000)
    assert page.locator('.corp-context-menu button', has_text=re.compile(r'^\s*Compliance\s*$')).count() == 0
    _no_errors(app)


def test_runtime_what_if_nodes_lead_to_insights_and_their_node(open_app):
    app = open_app()
    page = app.page
    _whatif(page)
    _ready(page)
    _run(page, 'pve1')
    page.locator('[data-cr-wi-insights="nodes"]').click()
    page.locator('[data-cr-ins]').wait_for(timeout=8000)
    page.locator('.corp-tab-strip button', has_text='What-if').first.click()
    page.locator('[data-cr-wi]').wait_for(timeout=8000)
    _ready(page)
    _run(page, 'pve1')
    page.locator('[data-cr-table="wi-nodes"] [data-cr-wi-go="node:pve2"]').click()
    page.locator('[data-cr-crumb="node"]', has_text='pve2').wait_for(timeout=5000)
    _no_errors(app)


def test_runtime_a_guest_health_leads_to_config_drift_and_drift_to_the_datacenter(open_app):
    events = [dict(DRIFT_EVENTS[0]), {'id': 34, 'cluster_id': 'c1', 'kind': 'cluster_options', 'scope': 'global', 'severity': 'warning',
                                      'summary': 'cluster_options global: keyboard', 'detected_at': '2026-10-30T07:00:00.000000',
                                      'status': 'open', 'acknowledged_at': None, 'acknowledged_by': None, 'category': 'deviation',
                                      'confirmed_by': None, 'confirmed_at': None, 'change_id': None,
                                      'diff': [{'path': 'keyboard', 'op': 'changed', 'before': 'de', 'after': 'en-us'}]}]
    app = open_app()
    app.server.routes[('GET', '/api/clusters/c1/drift/events')] = (200, {'events': events})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.locator('[data-cr-vm-health]').wait_for(timeout=10000)
    link = page.locator('[data-cr-vm-hlink="audit-2"]')
    assert link.inner_text() == 'Config drift' and 'Nothing of it is counted here' in link.get_attribute('title')
    # the audit line stays "not per guest": the link is navigation only
    assert page.locator('[data-cr-vm-h="audit"]').get_attribute('data-cr-vm-hstate') == 'na'
    link.click()
    page.locator('[data-cr-drift]').wait_for(timeout=8000)
    assert _crumbs(page)[-2:] == ['Compliance', 'Config Drift Detection'], _crumbs(page)
    row = page.locator('[data-cr-drift-row="34"]').locator('xpath=ancestor::tr')
    row.locator('[data-cr-drift-go="cluster"]').click()
    page.locator('.corp-subnav-item.active', has_text='Options').wait_for(timeout=8000)
    assert _crumbs(page)[-1] == 'Datacenter'
    _no_errors(app, dropped=True)


# --- classic, language, keyboard, layout ---------------------------------------------------------------

@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_keep_the_classic_what_if(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)
    page.locator('button', has_text=re.compile(r'^\s*Reports\s*$')).first.click()
    page.locator('button', has_text=re.compile(r'^\s*What-if\s*$')).first.click()
    page.locator('[data-whatif="view"]').wait_for(timeout=8000)
    page.locator('[data-whatif-node="pve1"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-wi]').count() == 0
    # the classic page reads nothing for a capacity panel
    assert not [u for u in app.server.urls if '/insights/right-sizing' in u]


def test_runtime_german(open_app):
    app = open_app(language='de')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text='Was-wäre-wenn').first.click()
    page.locator('[data-cr-wi]').wait_for(timeout=10000)
    _ready(page)
    assert 'keine Messung' in page.locator('.cr-wi-intro').inner_text()
    _run(page, 'pve1')
    page.locator('[data-cr-wi-report]').wait_for(timeout=8000)
    assert _verdict(page)[2].startswith('Blockiert: Gäste blieben aus')
    assert 'kapazität jetzt und prognose' in page.locator('[data-cr-wi-cap]').inner_text().lower()
    _no_errors(app)


def test_runtime_the_keyboard_runs_it_and_every_control_is_named(open_app):
    app = open_app()
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-node="pve1"]').focus()
    page.keyboard.press('Space')
    assert page.locator('[data-cr-wi-node="pve1"]').is_checked()
    page.locator('[data-cr-wi-run="scenario"]').focus()
    page.keyboard.press('Enter')
    page.locator('[data-cr-wi-report]').wait_for(timeout=8000)
    page.locator('[data-cr-wi-count="down"]').focus()
    page.keyboard.press('Enter')
    assert page.locator('[data-cr-wi-count="down"]').get_attribute('aria-pressed') == 'true'
    unnamed = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-wi button, .cr-wi select, .cr-wi input'))
        .filter(e => !(e.getAttribute('aria-label') || e.innerText.trim() || e.title || (e.labels && e.labels.length)))
        .map(e => e.outerHTML.slice(0, 120))''')
    assert unnamed == [], unnamed
    _no_errors(app)


def _overlaps(page):
    return page.evaluate('''() => {
        const boxes = (sel) => Array.from(document.querySelectorAll(sel)).map(e => e.getBoundingClientRect()).filter(r => r.width && r.height);
        const hit = (a, b) => a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1;
        const out = [];
        for (const sel of ['.cr-wi-top > *', '[data-cr-wi-count]', '[data-cr-wi-kind]', '.cr-wi-common > *', '.cr-pagehead-actions > *', '.cr-wi-caprow > *']) {
            const b = boxes(sel);
            for (let i = 0; i < b.length; i++) for (let j = i + 1; j < b.length; j++) if (hit(b[i], b[j])) out.push(sel);
        }
        const clipped = Array.from(document.querySelectorAll('[data-cr-wi-count] .cr-stat-value, [data-cr-wi-count] .cr-stat-label'))
            .filter(e => e.scrollWidth > e.clientWidth + 1).map(e => e.innerText);
        return { out, clipped, over: document.documentElement.scrollWidth - window.innerWidth };
    }''')


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_nothing_overlaps_or_scrolls_sideways(open_app, firefox, engine, width):
    app = open_app(viewport=(width, 1000), br=firefox if engine == 'firefox' else None)
    page = app.page
    _whatif(page)
    _ready(page)
    page.locator('[data-cr-wi-cap-fc="ok"]').wait_for(timeout=8000)
    _run(page, 'pve1')
    page.locator('[data-cr-wi-report]').wait_for(timeout=8000)
    page.wait_for_timeout(500)
    r = _overlaps(page)
    assert r == {'out': [], 'clipped': [], 'over': 0}, r
    page.locator('[data-cr-wi-view="ranking"]').click()
    page.locator('[data-cr-wi-run="ranking"]').click()
    page.locator('[data-cr-wi-rank="ok"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    r = _overlaps(page)
    assert r == {'out': [], 'clipped': [], 'over': 0}, r
    _no_errors(app)


# --- after the review of round 3 -------------------------------------------------------------------

def test_runtime_a_cluster_that_is_not_connected_has_no_node_figures_now(open_app):
    from test_corp_redesigned_dashboard_ui import EDGE, PROD
    from test_ha_ui import CLUSTER
    # /metrics answers the last figures (or zeros) of a cluster that is not connected
    c1 = dict(CLUSTER, connected=False, status='error')
    app = open_app(clusters=[c1, PROD, EDGE], opts=(503, {'error': 'Connection temporarily unavailable', 'offline': True}))
    page = app.page
    _whatif(page)
    assert _ready(page) == 'offline'
    sec = page.locator('[data-cr-wi-cap-nodes]')
    assert _wait(page, lambda: sec.get_attribute('data-cr-wi-cap-nodes') == 'offline'), sec.get_attribute('data-cr-wi-cap-nodes')
    assert page.locator('[data-cr-wi-hot]').count() == 0
    assert 'the cluster is not connected' in sec.inner_text() and 'No node' not in sec.inner_text()
    _no_errors(app)


class _WiNoGuests(_WiServer):
    """The guest list of the cluster cannot be read."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.routes[('GET', '/api/clusters/c1/resources')] = (500, {'error': 'resources down'})


def test_runtime_an_unread_guest_list_is_not_said_to_hide_the_guests(browser):
    app = _GuardApp(browser, _WiNoGuests(layout=LAYOUT, bundle=BUNDLE), viewport=(1600, 1000))
    try:
        page = app.page
        _whatif(page)
        _ready(page)
        _run(page, 'pve1')
        page.locator('[data-cr-wi-report]').wait_for(timeout=8000)
        names = page.locator('[data-cr-table="wi-guests"] [data-cr-wi-nolink="guest"]')
        assert names.count() > 0
        titles = set(names.evaluate_all('(els) => els.map(e => e.title)'))
        assert titles == {'the inventory of the cluster is not loaded'}, titles
        assert page.locator('[data-cr-wi-go^="guest:"]').count() == 0
    finally:
        app.close()


def test_runtime_the_compliance_entry_opens_drift_and_asks_no_node(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-dashboard]').wait_for(timeout=10000)
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text='Testi').first.click(button='right')
    page.locator('.corp-context-menu button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.locator('[data-cr-drift]').wait_for(timeout=8000)
    page.wait_for_timeout(1500)
    # the hardening sub tab asks every node over SSH as it opens: a menu click does not land there
    assert not [c for c in app.server.calls if '/hardening' in c[1]], app.server.calls
    assert _crumbs(page)[-3:] == ['Testi', 'Compliance', 'Config Drift Detection'], _crumbs(page)
    # the first sub tab is named like its tab: the trail says it once
    page.locator('[data-compliance-sub="hardening"]').click()
    assert _wait(page, lambda: page.locator('[data-cr-drift]').count() == 0)
    assert _crumbs(page)[-2:] == ['Testi', 'Compliance'], _crumbs(page)
    _no_errors(app)
