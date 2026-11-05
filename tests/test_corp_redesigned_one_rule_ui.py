"""One rule set for Corporate Redesigned (Preview), in the browser.

The decisions taken before the Testing push, each held here at runtime:
- an offline node is critical on the All Clusters dashboard, as the alert strip says it, and the
  Datacenter cell is named for what it judges (nodes and resources), not "Infrastructure";
- a datacenter status that came back without any node is "not read" on the dashboard too (never a
  green Online with 0/0), and the node count says which clusters it leaves out;
- storage, root disks and thin pools use one pair, 70 % warning and 85 % critical, everywhere in the
  preview (dashboard alerts and meters, the cluster table, the Datacenter verdict, the node summary,
  LVM-Thin); CPU, RAM and swap keep 80 / 90; every caption naming a limit names these numbers;
- the balancing overview calls a member that is only a node's own storage "not shared", as the
  detail does;
- the active alerts of a cluster are read once per cluster and minute for the strip, the Datacenter
  page and Automation > Alerts (one store), again at once after an ack, with the failure handling
  each view had.

Runs against the fake servers of the other redesign tests with the backend's shapes, and skips
without Playwright. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof).
LW Nov 2026
"""
import copy
import os
import re

import pytest

from test_corp_redesigned_dashboard_ui import EDGE, PROD, _DashServer, _col, _rows, _stat
from test_corp_redesigned_datacenter_ui import ALERTS as DC_ALERTS
from test_corp_redesigned_datacenter_ui import C1, _DcServer, _incident, _line, _open_dc, _verdict
from test_corp_redesigned_datacenter_ui import _status as _dc_status
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, METRICS, _GuardApp
from test_corp_redesigned_node_storage_ui import NODE_LVMTHIN, THIN, _StoreServer, _open_cfg, _sec
from test_corp_redesigned_node_ui import _NodeServer, _open_summary
from test_corp_redesigned_storage_ui import DATASTORES, _balancing, _cells, _group, _SbServer
from test_ha_ui import CLUSTER

LAYOUT = 'corporate-redesigned'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3
TIB = 1024 ** 4
ALERTS_PATH = f'{C1}/active-alerts'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def browsers():
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
    try:
        ff = pw.firefox.launch(headless=True)
    except Exception:
        ff = None
    yield {'chromium': br, 'firefox': ff}
    br.close()
    if ff:
        ff.close()
    pw.stop()


@pytest.fixture
def open_app(browsers):
    apps = []

    def _open(server, engine='chromium', viewport=(1600, 1000)):
        br = browsers[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = _GuardApp(br, server, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _reads(app, path=ALERTS_PATH):
    return sum(1 for m, p in app.server.calls if m == 'GET' and p == path)


def _no_sideways(page, what):
    over = page.evaluate('() => document.documentElement.scrollWidth - document.documentElement.clientWidth')
    assert over <= 0, f'{what}: the page scrolls sideways by {over}px'


# --- the scene of the dashboard ----------------------------------------------------------------

def _dash_status(online, offline, storage_used_gib, standalone=False):
    """/datacenter/status as pegaprox/api/vms.py answers it; online + offline 0 is its zero answer."""
    def part(total, used):
        return {'total': total, 'used': used, 'percent': round(used / total * 100, 1)}
    return {'cluster': {'name': 'x', 'quorate': None if standalone else True, 'standalone': standalone, 'version': 3},
            'nodes': {'online': online, 'offline': offline, 'total': online + offline},
            'guests': {'vms': {'running': 1, 'stopped': 0, 'total': 1}, 'containers': {'running': 0, 'stopped': 0, 'total': 0}},
            'resources': {'cpu': part(16, 1.6), 'memory': part(64 * GIB, 12.8 * GIB),
                          'storage': part(1 * TIB, storage_used_gib * GIB)},
            'hardware': None}


# Testi: one of three nodes offline, storage at 75 %; Prod: the zero answer (no node, guests and
# resources counted), storage at 69 %; Edge: not connected. Storage of both: 72 %
DASH = {'c1': _dash_status(2, 1, 768), 'c2': _dash_status(0, 0, 706.56, standalone=True)}


def _open_dash(open_app, **kw):
    server = _DashServer(layout=LAYOUT, bundle=BUNDLE, clusters=[CLUSTER, PROD, EDGE], status=DASH, **kw)
    app = open_app(server, **{k: v for k, v in kw.items() if k in ()})
    page = app.page
    _need(page, '[data-cr-dashboard]', 'the All Clusters dashboard of the preview')
    page.locator('[data-cr-stat="storage"]').wait_for(timeout=10000)
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row').nth(2).wait_for(timeout=10000)
    return app, page


def _cluster_rows(page):
    col = lambda key: _col(page, 'dash-clusters', key)  # noqa: E731
    return {r[col('name')]: {k: r[col(k)] for k in ('status', 'nodes', 'cpu', 'storage')}
            for r in _rows(page, 'dash-clusters')}


def _row_el(page, name):
    return page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text=name).first


def _cell(page, name, key):
    """The cell of a column (the column key is on the head only)."""
    return _row_el(page, name).locator('td').nth(_col(page, 'dash-clusters', key))


def _tone(loc):
    m = re.search(r'cr-tone-(\w+)', loc.get_attribute('class') or '')
    return m.group(1) if m else None


# --- X-O2: an offline node is critical, as the strip says ------------------------------------

def test_runtime_an_offline_node_is_critical_on_the_dashboard(open_app):
    app, page = _open_dash(open_app)
    rows = [tuple(r[:3]) for r in _rows(page, 'dash-alerts')]
    assert ('Critical', '1 node(s) offline', 'Testi') in rows, rows
    assert ('Warning', '1 node(s) offline', 'Testi') not in rows, rows
    # Edge not connected and Testi's node: two critical; Testi's storage at 75 % the one warning
    assert _stat(page, 'alerts') == {'value': '2', 'sub': '1 warnings'}, _stat(page, 'alerts')
    # the node count takes the tone of its alert, the row the red dot of a critical one
    assert 'cr-stat-error' in page.locator('[data-cr-stat="nodes"]').get_attribute('class')
    assert _row_el(page, 'Testi').locator('.cr-dot').get_attribute('class').split()[-1] == 'cr-dot-error'
    assert _cell(page, 'Testi', 'alerts').locator('.cr-badge-error').count() == 1
    _no_errors(app)


def test_runtime_the_datacenter_cell_is_named_for_what_it_judges_and_an_offline_node_is_critical(open_app):
    # pve3 offline, storage of the status at 75 %
    app = open_app(_DcServer(layout=LAYOUT, c1=_dc_status(storage=(4096 * GIB, 3072 * GIB))))
    page = _open_dc(app)
    cell = page.locator('[data-cr-dc-cell="infra"]')
    assert cell.locator('.cr-dc-label').text_content().strip() == 'Nodes and resources'
    assert cell.get_attribute('aria-label') == 'Nodes and resources'
    assert _verdict(page, 'infra') == ('critical', 'Critical')
    reasons = cell.locator('[data-cr-dc-line^="reason-"]').evaluate_all(
        'els => els.map(e => [e.dataset.crDcLine, e.innerText.trim(), e.className])')
    texts = {r[0]: r[1] for r in reasons}
    assert texts.get('reason-nodes') == '1 node(s) offline', reasons
    # the storage of the status at 75 % is a reason by the storage pair (it was none at 80 / 90)
    assert texts.get('reason-storage') == 'Storage at 75%', reasons
    # the rules name both pairs and say the active alerts are not part of the verdict
    rules = cell.locator('[data-cr-dc-line="i-basis"]').get_attribute('title')
    assert 'offline nodes' in rules.split('Warning:')[0], rules
    for part in ('CPU or RAM above 90%', 'storage above 85%', 'CPU or RAM above 80%', 'storage from 70%',
                 'not part of this verdict'):
        assert part in rules, (part, rules)
    # the alerts stay listed in the cell, beside the verdict
    assert _line(page, 'alerts').startswith('Active alerts: 2 open (1 critical)')
    _no_errors(app)


# --- R4-A3: a status without any node is not read, and the node count says so -----------------

def test_runtime_a_status_without_any_node_is_not_read_on_the_dashboard(open_app):
    app, page = _open_dash(open_app)
    rows = _cluster_rows(page)
    prod = rows['Prod']
    assert prod['status'] == 'Not read' and prod['nodes'] == '-', prod
    assert 'Online' not in prod['status'] and '0/0' not in prod['nodes']
    # neutral, with the reason on hover; guests and resources of the answer still show
    row = _row_el(page, 'Prod')
    assert row.locator('[data-cr-cl-state="unread"] .cr-badge').get_attribute('class').split()[-1] != 'cr-badge-success'
    assert 'without any node' in row.locator('[data-cr-cl-state="unread"]').get_attribute('title')
    assert row.locator('.cr-dot').get_attribute('class').split()[-1] not in ('cr-dot-success',)
    assert prod['cpu'] == '10%', prod
    assert rows['Testi']['status'] == 'Online' and rows['Testi']['nodes'] == '2/3', rows['Testi']
    # the node count leaves Prod out and says so
    nodes = _stat(page, 'nodes')
    assert nodes == {'value': '2/3', 'sub': '1 offline, 1 cluster(s) not counted'}, nodes
    assert 'not in this count' in page.locator('[data-cr-stat="nodes"]').get_attribute('title')
    _no_errors(app)


def test_runtime_the_node_count_shows_when_no_cluster_counted_a_node(open_app):
    # only Prod's zero answer: no node to count, said instead of a hidden tile
    server = _DashServer(layout=LAYOUT, bundle=BUNDLE, clusters=[PROD], status={'c2': DASH['c2']})
    app = open_app(server)
    page = app.page
    page.locator('[data-cr-stat="vms"]').wait_for(timeout=10000)
    page.locator('[data-cr-stat="nodes"]').wait_for(timeout=5000)
    assert _stat(page, 'nodes') == {'value': '-', 'sub': '1 cluster(s) not counted'}, _stat(page, 'nodes')
    _no_errors(app)


# --- R3-Q2 + R6-7: storage, root disk and thin pools at 70 / 85 -------------------------------

def test_runtime_storage_uses_the_storage_pair_on_the_dashboard(open_app):
    app, page = _open_dash(open_app)
    # the alert: Testi's storage at 75 % is a warning (none at 80 / 90)
    rows = [tuple(r[:3]) for r in _rows(page, 'dash-alerts')]
    assert ('Warning', 'Storage at 75%', 'Testi') in rows, rows
    # the meters: the cluster table and the summary tile at 72 %
    assert _tone(_cell(page, 'Testi', 'storage').locator('.cr-meter')) == 'warning'
    assert _tone(_cell(page, 'Prod', 'storage').locator('.cr-meter')) == 'success'
    assert _stat(page, 'storage')['value'] == '72%'
    assert _tone(page.locator('[data-cr-stat="storage"] .cr-stat-bar')) == 'warning'
    assert 'warning from 70%, critical above 85%' in page.locator('[data-cr-stat="storage"]').get_attribute('title')
    # CPU and RAM keep 80 / 90: 10 % and 20 % stay normal
    assert _tone(page.locator('[data-cr-stat="cpu"] .cr-stat-bar')) == 'success'
    _no_errors(app)


def test_rules_the_node_summary_judges_the_root_disk_by_the_storage_pair(open_app):
    app = open_app(_NodeServer(layout=LAYOUT))
    page = app.page
    page.wait_for_function('() => !!window.PegaProxNodeSum', timeout=10000)
    live = dict(METRICS['pve1'], disk_total=100 * GIB)

    def root(pct, **kw):
        m = page.evaluate('(a) => window.PegaProxNodeSum.model(a)', dict(
            metrics=dict(live, disk_used=pct * GIB, **kw), summary=None, hw=None, alerts=None, node='pve1'))
        it = [i for i in m['items'] if i['id'] == 'root']
        return it[0]['level'] if it else None
    assert root(69.9) is None
    assert root(70.0) == 'warning' and root(75) == 'warning' and root(85.0) == 'warning'
    assert root(85.1) == 'critical' and root(88) == 'critical'
    # swap and CPU keep 80 / 90
    m = page.evaluate('(a) => window.PegaProxNodeSum.model(a)', dict(
        metrics=dict(live, disk_used=10 * GIB, cpu_percent=85.0), summary=None, hw=None, alerts=None, node='pve1'))
    assert {i['id']: i['level'] for i in m['items'] if i['level'] != 'info'} == {'cpu': 'warning'}, m['items']
    _no_errors(app)


def test_runtime_the_node_summary_root_tile_and_its_caption(open_app):
    metrics = copy.deepcopy(METRICS)
    metrics['pve1'].update(disk_used=72 * GIB, disk_total=100 * GIB)
    app = open_app(_NodeServer(layout=LAYOUT, metrics=metrics))
    page = app.page
    _open_summary(page)
    page.locator('[data-cr-stat="ns-root"]').wait_for(timeout=8000)
    page.wait_for_timeout(500)
    item = page.locator('[data-cr-ns-item="root"]')
    assert item.count() == 1, 'a root disk at 72 % is a warning by the storage pair (it was none at 80 / 90)'
    assert item.get_attribute('data-cr-ns-level') == 'warning'
    assert 'Root disk at 72.0 % (warning from 70 %, critical above 85 %)' in item.inner_text()
    tile = page.locator('[data-cr-stat="ns-root"]')
    assert _tone(tile.locator('.cr-stat-bar')) == 'warning' and 'cr-stat-warning' in tile.get_attribute('class')
    basis = page.locator('.cr-ns-basis').inner_text()
    assert 'CPU, memory and swap: warning above 80 %, critical above 90 %' in basis, basis
    assert 'Root disk: warning from 70 %, critical above 85 %' in basis, basis
    _no_errors(app)


def test_runtime_thin_pools_take_the_storage_pair(open_app):
    pools = NODE_LVMTHIN + [{'lv': 'mid', 'vg': 'nvme', 'lv_size': 100 * GIB, 'used': 75 * GIB},
                            {'lv': 'full', 'vg': 'nvme', 'lv_size': 100 * GIB, 'used': 87 * GIB}]
    app = open_app(_StoreServer(layout=LAYOUT, routes={('GET', THIN): (200, pools)}))
    page = app.page
    _open_cfg(page, 'lvmthin')
    sec = _sec(page, 'lvmthin')
    sec.locator('[data-cr-nv-thin="nvme/full"]').wait_for(timeout=8000)
    tone = lambda lv: sec.locator(f'[data-cr-nv-thin="{lv}"] [data-cr-nc-k="data"] [data-cr-nv-usage]').get_attribute('data-cr-nv-tone')  # noqa: E731
    assert tone('pve/data') == 'success'
    assert tone('nvme/mid') == 'warning', 'a thin pool at 75 % is a warning by the storage pair'
    assert tone('nvme/full') == 'error', 'a thin pool at 87 % is critical by the storage pair'
    assert 'warning from 70%' in sec.locator('[data-cr-nv-thin="nvme/mid"] [data-cr-nv-usage]').first.get_attribute('title')
    _no_errors(app)


def test_the_storage_pair_is_one_constant_pair_beside_cr_warn():
    views = _read('web', 'src', 'cr_views.js')
    assert re.search(r'const CR_WARN = 80;\s*\n\s*const CR_CRIT = 90;', views)
    assert 'const CR_STORE_WARN = 70;' in views and 'const CR_STORE_CRIT = 85;' in views
    for name in os.listdir(os.path.join(ROOT, 'web', 'src')):
        if name.startswith('cr') and name.endswith('.js') and name != 'cr_views.js':
            src = _read('web', 'src', name)
            assert 'const CR_STORE_WARN' not in src and 'function crStoreTone' not in src, name
    # every caption in English and German that names a limit takes the numbers from the constants
    tr = _read('web', 'src', 'translations.js')
    for key in ('crDcInfraRules', 'crNsBasis', 'crNsRootHigh'):
        vals = re.findall(rf'^                {key}: (.+)$', tr, re.M)[:2]
        assert len(vals) == 2, key
        for v in vals:
            assert not re.search(r'\b(70|80|85|90) ?%', v), (key, v)


# --- R3-P1: a node's own storage in a balancing group is "not shared" -------------------------

def test_runtime_the_balancing_overview_says_not_shared_like_the_detail(open_app):
    groups = [_group('l1o2c3a4', 'With local', ['ceph-a', 'local-lvm']),
              _group('b0t1h2x3', 'Both', ['ceph-b', 'local-lvm', 'renamed-store'])]
    app = open_app(_SbServer(layout=LAYOUT, bundle=BUNDLE, groups=groups, datastores=copy.deepcopy(DATASTORES)))
    page = _balancing(app)
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row').nth(1).wait_for(timeout=5000)
    rows = {r['name'].split(' Off')[0]: r for r in _cells(page, 'sb-groups')}
    assert rows['With local']['state'] == '1 not shared', rows['With local']
    assert rows['Both']['state'] == '1 not found 1 not shared', rows['Both']
    both = page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text='Both').first
    assert both.locator('[data-cr-sb-state]').evaluate_all('xs => xs.map(x => x.dataset.crSbState)') == ['missing', 'local']
    # the detail says the same word for the member
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text='With local').first.click()
    _need(page, '[data-cr-sb-member="local-lvm"] [data-cr-sb-why="local"]', 'the detail names the local member')
    assert page.locator('[data-cr-sb-member="local-lvm"] [data-cr-sb-why="local"]').inner_text() == 'Not shared'
    _no_errors(app)


# --- R-16: one store of the active alerts per cluster -----------------------------------------

def _automation_alerts(page):
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(400)
    page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Alerts\s*$')).first.click()


def _fresh_app(open_app, **kw):
    extra = {('POST', f'{ALERTS_PATH}/a1/ack'): (200, {'success': True})}
    extra.update(kw.pop('extra', {}))
    return open_app(_DcServer(layout=LAYOUT, extra=extra, **kw))


def test_runtime_the_strip_the_datacenter_page_and_automation_read_the_active_alerts_once(open_app):
    app = _fresh_app(open_app)
    page = _open_dc(app)
    # the strip (on the pick) and the Datacenter page share one read
    assert _line(page, 'alerts').startswith('Active alerts: 2 open (1 critical)')
    page.wait_for_timeout(600)
    assert _reads(app) == 1, f'the strip and the Datacenter page read {_reads(app)} times'
    # Automation > Alerts takes the same answer
    _automation_alerts(page)
    _need(page, '[data-active-alert="a1"]', 'Automation > Alerts lists the active alerts of the store')
    assert page.locator('[data-active-alert]').count() == 2
    page.wait_for_timeout(600)
    assert _reads(app) == 1, f'three views read {_reads(app)} times within a minute'
    # an ack asks again at once, and the strip takes that answer too
    app.server.extra[('GET', ALERTS_PATH)] = (200, {'active_alerts': [DC_ALERTS['active_alerts'][1]]})
    page.locator('[data-active-alert="a1"] button', has_text='Acknowledge').click()
    page.wait_for_function('() => !document.querySelector(\'[data-active-alert="a1"]\')', timeout=8000)
    assert _reads(app) == 2
    page.wait_for_function('''() => { const s = document.querySelector('[data-cr-alerts]');
        return s && !s.querySelector('[data-cr-al-row="critical"] [data-cr-al-seg="incident"]'); }''', timeout=8000)
    # back to the Datacenter page within the minute: no read, the new answer
    page.locator('[data-cr-tab="datacenter"]').click()
    _need(page, '[data-cr-dc-sum]', 'the Datacenter summary again')
    page.wait_for_function('() => /Active alerts: 1 open \\(0 critical\\)/.test(document.querySelector(\'[data-cr-dc-line="alerts"]\').innerText)',
                           timeout=8000)
    page.wait_for_timeout(600)
    assert _reads(app) == 2
    # a minute later the next view that asks reads once
    app.ctx.clock.set_fixed_time(FIXED + 61)
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(400)
    page.locator('[data-cr-tab="datacenter"]').click()
    _need(page, '[data-cr-dc-sum]', 'the Datacenter summary a third time')
    page.wait_for_timeout(1200)
    assert _reads(app) == 3, f'after a minute: {_reads(app)} reads'
    # Refresh asks again whatever the age
    page.locator('[data-cr-dc-refresh]').click()
    page.wait_for_timeout(1200)
    assert _reads(app) == 4
    _no_errors(app)


@pytest.mark.parametrize('answer,strip,dc', [
    ((500, {'error': 'boom'}), 'The read failed (HTTP 500).', 'not read (boom - HTTP 500)'),
    ((503, {'code': 'HA_ACTIVE_UNREACHABLE', 'error': 'The active instance cannot be reached'}),
     'The leader instance does not answer; only it keeps the alerts.', 'not read (the leader instance cannot be reached)'),
])
def test_runtime_a_failed_read_is_said_by_each_view_as_before_and_read_once(open_app, answer, strip, dc):
    app = _fresh_app(open_app, extra={('GET', ALERTS_PATH): answer})
    page = _open_dc(app)
    assert _line(page, 'alerts') == f'Active alerts: {dc}', _line(page, 'alerts')
    page.locator('[data-cr-al-details]').click()
    assert strip in page.locator('[data-cr-al-item="alertsunread|c1"]').inner_text()
    _automation_alerts(page)
    page.wait_for_timeout(800)
    assert page.locator('[data-active-alert]').count() == 0
    away = answer[0] == 503
    assert page.locator('[data-ha-leader-away="alerts"]').count() == (1 if away else 0)
    assert _reads(app) == 1, f'{_reads(app)} reads of a failing route within a minute'
    _no_errors(app)


def test_the_store_is_the_only_reader_of_the_route_in_the_preview():
    alerts = _read('web', 'src', 'cr_alerts.js')
    dc = _read('web', 'src', 'cr_datacenter.js')
    dash = _read('web', 'src', 'dashboard.js')
    assert alerts.count('/active-alerts`') == 1, 'one GET in the store'
    assert '/active-alerts' not in dc
    load = dash[dash.index('const loadActiveAlerts = async'):dash.index('const ackAlert = async')]
    # the classic read stays as it was behind the gate
    assert 'if (isCorpRedesigned) {' in load and 'crAlertsRead(authFetch, clusterId, force)' in load
    assert "setActiveAlerts(d.active_alerts || [])" in load


# --- layout --------------------------------------------------------------------------------------

@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_the_changed_cells_fit(open_app, engine, width):
    server = _DashServer(layout=LAYOUT, bundle=BUNDLE, clusters=[CLUSTER, PROD, EDGE], status=DASH)
    app = open_app(server, engine=engine, viewport=(width, 900))
    page = app.page
    _row_el(page, 'Prod').wait_for(timeout=10000)
    _no_sideways(page, f'dashboard {engine} {width}')
    badge = _row_el(page, 'Prod').locator('[data-cr-cl-state="unread"] .cr-badge')
    assert badge.count() == 1, 'Prod is not read'
    fits = badge.evaluate('b => { const td = b.closest("td"); const r = b.getBoundingClientRect(), c = td.getBoundingClientRect(); '
                          'return r.right <= c.right + 0.5 && b.scrollWidth <= b.clientWidth + 1; }')
    assert fits, f'the Not read badge is cut at {width} ({engine})'
    # the node count's note is read whole (it wraps where the tile is narrow)
    nodes = page.locator('[data-cr-stat="nodes"] .cr-stat-sub')
    assert nodes.evaluate('e => e.scrollWidth <= e.clientWidth + 1'), f'the node count note is cut at {width} ({engine})'
    _no_errors(app)


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_the_balancing_state_and_the_datacenter_cell_fit(open_app, engine, width):
    groups = [_group('b0t1h2x3', 'Both', ['ceph-b', 'local-lvm', 'renamed-store'])]
    app = open_app(_SbServer(layout=LAYOUT, bundle=BUNDLE, groups=groups, datastores=copy.deepcopy(DATASTORES)),
                   engine=engine, viewport=(width, 900))
    page = _balancing(app)
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row').first.wait_for(timeout=5000)
    _no_sideways(page, f'balancing {engine} {width}')
    states = page.locator('[data-cr-sb-state]')
    assert states.evaluate_all('xs => xs.map(x => x.innerText.trim())') == ['1 not found', '1 not shared']
    for i in range(2):
        cut = states.nth(i).evaluate('s => { const b = s.closest(".cr-badge"), td = s.closest("td"); '
                                     'const r = b.getBoundingClientRect(), c = td.getBoundingClientRect(); '
                                     'return [r.right - c.right, b.scrollWidth - b.clientWidth, s.scrollWidth - s.clientWidth]; }')
        assert cut[0] <= 0.5 and cut[1] <= 1 and cut[2] <= 1, f'the members state is cut at {width} ({engine}): {cut}'
    _no_errors(app)

    dc = open_app(_DcServer(layout=LAYOUT), engine=engine, viewport=(width, 900))
    page = _open_dc(dc)
    _no_sideways(page, f'datacenter {engine} {width}')
    label = page.locator('[data-cr-dc-cell="infra"] .cr-dc-label')
    assert label.evaluate('e => e.scrollWidth <= e.clientWidth + 1'), f'the cell name is cut at {width} ({engine})'
    _no_errors(dc)
