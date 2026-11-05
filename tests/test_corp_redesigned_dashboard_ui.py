"""The dashboard of Corporate Redesigned (Preview) in the browser.

The All Clusters view of the preview is drawn from what the dashboard already polls: the
datacenter status of every connected cluster, the guests of each cluster and, for a user who
may read it, the audit trail. Every figure on screen has to be the sum of the fake data, a
figure no cluster reported must not show up as a 0, and each table row and alert has to lead
to its cluster or guest. Runs against the fake server of tests/test_ha_ui.py and skips
without Playwright. LW Oct 2026
"""
import re
import time

import pytest

from test_corp_redesigned_guard_ui import CT, DETERMINISTIC, RESOURCES, VM, _GuardApp, _GuardServer
from test_ha_ui import CLUSTER

LAYOUT = 'corporate-redesigned'
GIB = 1024 ** 3
TIB = 1024 ** 4

PROD = {'id': 'c2', 'name': 'Prod', 'display_name': 'Prod', 'host': '10.0.1.1', 'connected': True,
        'status': 'running', 'cluster_type': 'proxmox', 'enabled': True, 'group_id': 'g1'}
EDGE = {'id': 'c3', 'name': 'Edge', 'display_name': 'Edge', 'host': '10.0.2.1', 'connected': False,
        'status': 'error', 'cluster_type': 'proxmox', 'enabled': True}
CLUSTERS = [CLUSTER, PROD, EDGE]

# what /datacenter/status says per cluster (pegaprox/api/vms.py get_datacenter_status)
STATUS = {
    'c1': {'cluster': {'name': 'testi', 'quorate': True, 'standalone': False, 'version': 4},
           'nodes': {'online': 2, 'offline': 0, 'total': 2},
           'guests': {'vms': {'running': 1, 'stopped': 1, 'total': 2}, 'containers': {'running': 1, 'stopped': 0, 'total': 1}},
           'resources': {'cpu': {'total': 16, 'used': 2.4, 'percent': 15.0},
                         'memory': {'total': 64 * GIB, 'used': 20 * GIB, 'percent': 31.2},
                         'storage': {'total': 1 * TIB, 'used': 870.4 * GIB, 'percent': 85.0}},
           'hardware': None},
    'c2': {'cluster': {'name': 'prod-eu', 'quorate': False, 'standalone': False, 'version': 9},
           'nodes': {'online': 2, 'offline': 1, 'total': 3},
           'guests': {'vms': {'running': 3, 'stopped': 0, 'total': 3}, 'containers': {'running': 0, 'stopped': 0, 'total': 0}},
           'resources': {'cpu': {'total': 32, 'used': 29.44, 'percent': 92.0},
                         'memory': {'total': 128 * GIB, 'used': 108.8 * GIB, 'percent': 85.0},
                         'storage': {'total': 2 * TIB, 'used': 512 * GIB, 'percent': 25.0}},
           'hardware': {'health': 'warning', 'degraded': 1, 'checked': 3}},
}


def _app(name, vmid, node, cpu, mem):
    return dict(VM, vmid=vmid, name=name, node=node, cpu=cpu, cpu_percent=cpu * 100, mem=mem,
                maxmem=8 * GIB, mem_percent=mem / (8 * GIB) * 100)


PROD_GUESTS = [_app('app01', 200, 'prod1', 0.90, 3 * GIB), _app('app02', 201, 'prod2', 0.50, 7 * GIB),
               _app('app03', 202, 'prod1', 0.30, 4 * GIB)]

AUDIT = [
    {'id': 2, 'timestamp': '2026-10-30T08:55:00+00:00', 'user': 'admin', 'action': 'vm.start',
     'details': 'Started VM 100 (web01)', 'cluster': 'Testi', 'cluster_id': 'c1', 'severity': 'info'},
    {'id': 1, 'timestamp': '2026-10-30T08:40:00+00:00', 'user': 'ops', 'action': 'cluster.update',
     'details': 'Changed the HA settings', 'cluster': 'Prod', 'cluster_id': 'c2', 'severity': 'warning'},
]


class _DashServer(_GuardServer):
    """The guard fake with three clusters: two that report a datacenter status, one offline."""

    def __init__(self, clusters=None, status=None, audit=None, extra=None, **kw):
        reads = {('GET', '/api/cluster-groups'): (200, [{'id': 'g1', 'name': 'EU'}]),
                 ('GET', '/api/clusters/c2/resources'): (200, PROD_GUESTS),
                 ('GET', '/api/audit'): audit or (200, AUDIT)}
        for cid, body in (STATUS if status is None else status).items():
            reads[('GET', f'/api/clusters/{cid}/datacenter/status')] = (200, body)
        reads.update(extra or {})
        super().__init__(extra=reads, **kw)
        self.clusters = list(CLUSTERS if clusters is None else clusters)


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

    def _open(layout=LAYOUT, storage=None, viewport=(1600, 1000), **kw):
        app = _GuardApp(browser, _DashServer(layout=layout, **kw), storage=storage, viewport=viewport)
        apps.append(app)
        app.page.locator('[data-cr-dashboard]').wait_for(timeout=15000)
        return app
    yield _open
    for app in apps:
        app.close()


# --- what the page should say, worked out from the fake data the way the UI rounds -------------

def _bytes(b):
    """formatBytes of ui.js."""
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    return f'{b:.1f} {units[i]}'


def _pct(v, digits=0):
    return f'{v:.{digits}f}%'


def _sums(status):
    out = {}
    for key, res in (('cpu', 'cpu'), ('mem', 'memory'), ('storage', 'storage')):
        used = sum(s['resources'][res]['used'] for s in status.values())
        total = sum(s['resources'][res]['total'] for s in status.values())
        out[key] = (used, total, used / total * 100)
    return out


def _stat(page, sid):
    box = page.locator(f'[data-cr-stat="{sid}"]')
    return {'value': re.sub(r'\s+', '', box.locator('.cr-stat-value').inner_text()),
            'sub': box.locator('.cr-stat-sub').inner_text() if box.locator('.cr-stat-sub').count() else ''}


def _rows(page, table):
    return page.evaluate('''(id) => Array.from(document.querySelectorAll(`[data-cr-table="${id}"] tbody tr.cr-row`))
        .map(tr => Array.from(tr.querySelectorAll('td')).map(td => td.innerText.trim()))''', table)


def _col(page, table, key):
    """The visible column order, so a check reads a column by name."""
    keys = page.evaluate('''(id) => Array.from(document.querySelectorAll(`[data-cr-table="${id}"] thead th`))
        .map(th => th.dataset.crCol)''', table)
    return keys.index(key)


def _crumbs(page):
    return page.evaluate('''() => Array.from(document.querySelectorAll('.cr-crumbs li'))
        .map(li => li.innerText.replace('/', '').trim())''')


def _no_errors(app):
    assert not app.errors, app.errors


# --- the summary strip ---------------------------------------------------------------------------

def test_runtime_the_summary_strip_is_the_sum_of_the_fake_data(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-stat="cpu"]').wait_for(timeout=10000)
    s = _sums(STATUS)
    assert _stat(page, 'clusters') == {'value': '2/3', 'sub': '1 offline'}
    assert _stat(page, 'nodes') == {'value': '4/5', 'sub': '1 offline'}
    assert _stat(page, 'vms') == {'value': '4/5', 'sub': '1 stopped'}
    assert _stat(page, 'cts') == {'value': '1/1', 'sub': '0 stopped'}
    cpu_used, cpu_total, cpu = s['cpu']
    assert _stat(page, 'cpu') == {'value': _pct(cpu), 'sub': f'{cpu_used:.1f} of {cpu_total} cores'}
    for sid in ('mem', 'storage'):
        used, total, pct = s[sid]
        assert _stat(page, sid) == {'value': _pct(pct), 'sub': f'{_bytes(used)} of {_bytes(total)}'}, sid
    # Edge offline, Prod without quorum, Prod's offline node (critical since round 8, as the strip says),
    # Prod CPU over 90 % critical; Prod RAM, Prod hardware and Testi storage (85 %: from 70 % a warning,
    # above 85 % critical) warnings
    assert _stat(page, 'alerts') == {'value': '4', 'sub': '3 warnings'}
    assert page.locator('[data-cr-stat="waiting"]').count() == 0
    # the strip and the tables, no horizontal scroll of the page
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 1600
    _no_errors(app)


def test_runtime_a_figure_no_cluster_reported_is_left_out(open_app):
    # the datacenter status answers nothing: no CPU, RAM, storage or guest tile, and no 0 %
    app = open_app(status={})
    page = app.page
    page.locator('[data-cr-stat="clusters"]').wait_for(timeout=10000)
    page.wait_for_timeout(800)
    present = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-stat]")).map(e => e.dataset.crStat)')
    assert present == ['clusters', 'alerts', 'waiting'], present
    assert _stat(page, 'clusters')['value'] == '2/3'
    # the offline cluster is still an alert, the others have nothing to raise
    assert _stat(page, 'alerts') == {'value': '1', 'sub': '0 warnings'}
    rows = {r[_col(page, 'dash-clusters', 'name')]: r for r in _rows(page, 'dash-clusters')}
    for name in ('Testi', 'Prod'):
        for key in ('nodes', 'cpu', 'mem', 'storage', 'health'):
            assert rows[name][_col(page, 'dash-clusters', key)] == '-', (name, key)
    assert '0%' not in page.locator('[data-cr-summary]').inner_text()
    _no_errors(app)


# --- the cluster table ---------------------------------------------------------------------------

def test_runtime_the_cluster_table_shows_each_cluster_as_reported(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row').nth(2).wait_for(timeout=10000)
    page.wait_for_function('''() => document.querySelector('[data-cr-table="dash-clusters"] th[data-cr-col="group"]')''')
    col = lambda key: _col(page, 'dash-clusters', key)  # noqa: E731
    rows = {r[col('name')]: r for r in _rows(page, 'dash-clusters')}
    assert sorted(rows) == ['Edge', 'Prod', 'Testi']
    prod = rows['Prod']
    assert prod[col('group')] == 'EU'
    assert prod[col('status')] == 'Online'
    assert prod[col('nodes')] == '2/3'
    assert prod[col('vms')] == '3/3'
    assert prod[col('cts')] == '0/0'
    assert prod[col('cpu')] == '92%'
    assert prod[col('mem')] == '85%'
    assert prod[col('storage')] == '25%'
    assert prod[col('alerts')] == '5'
    testi = rows['Testi']
    assert (testi[col('nodes')], testi[col('vms')], testi[col('cts')]) == ('2/2', '1/2', '1/1')
    assert (testi[col('cpu')], testi[col('mem')], testi[col('storage')]) == ('15%', '31%', '85%')
    edge = rows['Edge']
    assert edge[col('status')] == 'Offline'
    assert edge[col('nodes')] == '-' and edge[col('cpu')] == '-'
    # the bars take the colour of the alert they would raise
    tone = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-table="dash-clusters"] tbody tr.cr-row'))
        .map(tr => [tr.innerText.split('\\n')[0].trim(), Array.from(tr.querySelectorAll('.cr-meter')).map(m => m.className)])''')
    assert any('cr-tone-error' in c for _, cls in tone for c in cls)
    _no_errors(app)


def test_runtime_the_cluster_table_sorts_filters_and_keeps_its_columns(open_app):
    app = open_app()
    page = app.page
    table = page.locator('[data-cr-table="dash-clusters"]')
    table.locator('tbody tr.cr-row').nth(2).wait_for(timeout=10000)
    name = lambda: [r[_col(page, 'dash-clusters', 'name')] for r in _rows(page, 'dash-clusters')]  # noqa: E731
    assert name() == ['Edge', 'Prod', 'Testi']
    # CPU: ascending, then descending; a cluster without a figure stays last both times
    table.locator('th[data-cr-col="cpu"] button').click()
    assert name() == ['Testi', 'Prod', 'Edge']
    table.locator('th[data-cr-col="cpu"] button').click()
    assert name() == ['Prod', 'Testi', 'Edge']
    assert table.locator('th[data-cr-col="cpu"]').get_attribute('aria-sort') == 'descending'
    # the chips
    table.locator('[data-cr-show="offline"]').click()
    assert name() == ['Edge']
    table.locator('[data-cr-show="alerts"]').click()
    assert sorted(name()) == ['Edge', 'Prod', 'Testi']
    table.locator('[data-cr-show="online"]').click()
    assert sorted(name()) == ['Prod', 'Testi']
    assert table.locator('[data-cr-show="online"] .cr-seg-n').inner_text() == '2'
    table.locator('[data-cr-show="all"]').click()
    table.locator('input[type="search"]').fill('pro')
    assert name() == ['Prod']
    table.locator('input[type="search"]').fill('')
    # a wider name column and a hidden one survive a reload
    grip = table.locator('th[data-cr-col="name"] .cr-col-grip')
    grip.focus()
    for _ in range(3):
        page.keyboard.press('ArrowRight')
    table.locator('[data-cr-colmenu]').click()
    table.locator('.cr-menu input[data-cr-col="health"]').uncheck()
    stored = page.evaluate('() => JSON.parse(localStorage.getItem("cr-table:dash-clusters"))')
    assert stored['h'] == {'health': True} and stored['w']['name'] > 0
    page.reload()
    page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row').nth(2).wait_for(timeout=15000)
    assert page.locator('[data-cr-table="dash-clusters"] th[data-cr-col="health"]').count() == 0
    # the column takes the stored width (a fixed table spreads what is left over all columns)
    cols = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-table="dash-clusters"] colgroup col'))
        .map(c => c.style.width)''')
    assert cols[_col(page, 'dash-clusters', 'name')] == f"{stored['w']['name']}px", cols
    _no_errors(app)


def test_runtime_a_cluster_row_and_its_menu_lead_to_the_cluster(open_app):
    app = open_app()
    page = app.page
    table = page.locator('[data-cr-table="dash-clusters"]')
    table.locator('tbody tr.cr-row', has_text='Testi').click()
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=8000)
    assert _crumbs(page) == ['All', 'Testi', 'Overview']
    assert page.locator('[data-cr-objhead="cluster"] .cr-objhead-name').inner_text() == 'Testi'
    page.locator('[data-cr-crumb="all"] button').click()
    page.locator('[data-cr-dashboard]').wait_for(timeout=8000)
    # the context menu by mouse, and by keyboard from a focused row
    table.locator('tbody tr.cr-row', has_text='Prod').click(button='right')
    menu = page.locator('.corp-context-menu')
    menu.wait_for(timeout=3000)
    labels = [x.strip() for x in menu.locator('button').all_inner_texts()]
    # round 3 (stage J): the module pages of the cluster follow (compliance for an account that may see it)
    assert labels == ['Open', 'Resources', 'Datacenter', 'Datastore', 'Timeline', 'Insights', 'What-if', 'Compliance']
    menu.locator('button', has_text='Datacenter').click()
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 3', timeout=5000)
    assert _crumbs(page) == ['All', 'Prod', 'Datacenter']
    page.locator('[data-cr-crumb="all"] button').click()
    row = page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row', has_text='Testi')
    row.wait_for(timeout=8000)
    row.focus()
    page.keyboard.press('Shift+F10')
    page.locator('.corp-context-menu').wait_for(timeout=3000)
    page.keyboard.press('Escape')
    assert page.locator('.corp-context-menu').count() == 0
    page.keyboard.press('Enter')
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=8000)
    assert _crumbs(page) == ['All', 'Testi', 'Overview']
    _no_errors(app)


# --- top resources -------------------------------------------------------------------------------

def test_runtime_top_resources_rank_the_running_guests(open_app):
    app = open_app()
    page = app.page
    table = page.locator('[data-cr-table="dash-top"]')
    table.locator('tbody tr.cr-row').nth(4).wait_for(timeout=10000)
    col = lambda key: _col(page, 'dash-top', key)  # noqa: E731
    running = [(g, 'Prod') for g in PROD_GUESTS] + [(g, 'Testi') for g in RESOURCES if g['status'] == 'running']
    by_cpu = sorted(running, key=lambda x: -x[0]['cpu'])
    rows = _rows(page, 'dash-top')
    assert [r[col('name')] for r in rows] == [g['name'] for g, _ in by_cpu]
    for r, (g, cl) in zip(rows, by_cpu):
        assert r[col('vmid')] == str(g['vmid'])
        assert r[col('cluster')] == cl and r[col('node')] == g['node']
        assert r[col('cpu')] == _pct(g['cpu'] * 100, 1)
        assert r[col('ram')] == _pct(g['mem'] / g['maxmem'] * 100, 1)
        assert r[col('status')] == 'Running'
    # the stopped VM is not a top consumer
    assert 'db01' not in table.inner_text()
    assert table.locator('[data-cr-top-of]').inner_text() == f'Top {len(running)} of {len(running)} running'
    # ranked by RAM instead
    table.locator('[data-cr-rank="ram"]').click()
    page.wait_for_timeout(200)
    by_ram = sorted(running, key=lambda x: -(x[0]['mem'] / x[0]['maxmem']))
    assert [r[col('name')] for r in _rows(page, 'dash-top')] == [g['name'] for g, _ in by_ram]
    assert page.locator('[data-cr-table="dash-top"] th[data-cr-col="ram"]').get_attribute('aria-sort') == 'descending'
    # a row opens the guest in its own cluster
    page.locator('[data-cr-table="dash-top"] tbody tr.cr-row', has_text='app01').click()
    head = page.locator('[data-cr-objhead="vm"]')
    head.wait_for(timeout=8000)
    assert head.locator('.cr-objhead-name').inner_text() == 'app01'
    assert head.locator('[data-cr-objid]').inner_text() == '200'
    assert head.locator('[data-cr-meta="cluster"] dd').inner_text() == 'Prod'
    assert _crumbs(page) == ['All', 'Prod', 'Resources', 'app01']
    _no_errors(app)


# --- alerts --------------------------------------------------------------------------------------

def test_runtime_every_alert_names_and_opens_its_cluster(open_app):
    app = open_app()
    page = app.page
    table = page.locator('[data-cr-table="dash-alerts"]')
    table.locator('tbody tr.cr-row').nth(6).wait_for(timeout=10000)
    rows = _rows(page, 'dash-alerts')
    got = [(r[0], r[1], r[2]) for r in rows]
    assert got == [
        ('Critical', 'Cluster is not connected', 'Edge'),
        ('Critical', 'Quorum Lost', 'Prod'),
        ('Critical', '1 node(s) offline', 'Prod'),
        ('Critical', 'CPU at 92%', 'Prod'),
        ('Warning', 'RAM at 85%', 'Prod'),
        ('Warning', 'Degraded hardware on 1 node(s)', 'Prod'),
        ('Warning', 'Storage at 85%', 'Testi'),
    ], got
    # the alerts tile takes the keyboard to the list
    page.locator('[data-cr-stat="alerts"]').click()
    assert page.evaluate('() => document.activeElement.closest("[data-cr-table]").dataset.crTable') == 'dash-alerts'
    # an alert opens its cluster; a storage alert the cluster's datastores
    table.locator('tbody tr.cr-row', has_text='Cluster is not connected').click()
    page.locator('[data-cr-crumb="cluster"]', has_text='Edge').wait_for(timeout=5000)
    page.locator('[data-cr-crumb="all"] button').click()
    page.locator('[data-cr-table="dash-alerts"] tbody tr.cr-row', has_text='Storage at 85%').click()
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 3', timeout=5000)
    assert _crumbs(page) == ['All', 'Testi', 'Datastore']
    _no_errors(app)


# --- recent operations ---------------------------------------------------------------------------

def test_runtime_recent_operations_come_from_the_audit_trail(open_app):
    app = open_app()
    page = app.page
    table = page.locator('[data-cr-table="dash-ops"]')
    table.locator('tbody tr.cr-row').nth(1).wait_for(timeout=10000)
    assert table.locator('[data-cr-ops-source]').get_attribute('data-cr-ops-source') == 'audit'
    col = lambda key: _col(page, 'dash-ops', key)  # noqa: E731
    rows = _rows(page, 'dash-ops')
    assert [(r[col('user')], r[col('action')], r[col('details')], r[col('cluster')]) for r in rows] == [
        (e['user'], e['action'], e['details'], e['cluster']) for e in AUDIT]
    # the one read the panel makes, with its limit, and one more for the refresh button
    reads = [u for u in app.server.urls if '/api/audit' in u]
    assert len(reads) == 1 and reads[0].endswith('/api/audit?limit=25'), reads
    table.locator('[data-cr-ops-refresh]').click()
    deadline = time.time() + 3
    while time.time() < deadline and len([u for u in app.server.urls if '/api/audit' in u]) < 2:
        page.wait_for_timeout(100)
    assert len([u for u in app.server.urls if '/api/audit' in u]) == 2
    # the cluster of an entry is a way to it
    table.locator('tbody tr.cr-row', has_text='cluster.update').locator('button.cr-link').click()
    page.locator('[data-cr-crumb="cluster"]', has_text='Prod').wait_for(timeout=5000)
    _no_errors(app)


@pytest.mark.parametrize('why', ['no-permission', 'refused'])
def test_runtime_without_the_audit_trail_the_session_events_show(open_app, why):
    if why == 'no-permission':
        app = open_app(admin=False, permissions=['cluster.view', 'vm.view'])
    else:
        app = open_app(audit=(403, {'error': 'Permission denied'}))
    page = app.page
    table = page.locator('[data-cr-table="dash-events"]')
    table.wait_for(timeout=10000)
    assert table.locator('[data-cr-ops-source]').get_attribute('data-cr-ops-source') == 'session'
    assert 'Events of this session' in table.inner_text()
    assert 'Nothing recorded yet' in table.inner_text()
    reads = [u for u in app.server.urls if '/api/audit' in u]
    assert reads == ([] if why == 'no-permission' else [reads[0]]), reads
    _no_errors(app)


# --- scale ---------------------------------------------------------------------------------------

def _big_inventory(clusters=10, nodes=20, guests=1000):
    """200 nodes and 10 000 guests over ten clusters, each with its own status and guests."""
    cl, extra = [], {}
    for c in range(clusters):
        cid = f'k{c:02d}'
        cl.append({'id': cid, 'name': f'Site{c:02d}', 'display_name': f'Site{c:02d}', 'host': f'10.9.{c}.1',
                   'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True})
        res = []
        for g in range(guests):
            vmid = 1000 + c * guests + g
            run = g % 4 != 0
            res.append({'vmid': vmid, 'name': f'g{vmid}', 'type': 'qemu' if g % 3 else 'lxc',
                        'status': 'running' if run else 'stopped', 'node': f's{c:02d}n{g % nodes:02d}',
                        'cpu': ((vmid * 37) % 100) / 100 if run else 0, 'maxcpu': 2, 'mem': ((vmid * 53) % 8) * GIB if run else 0,
                        'maxmem': 8 * GIB, 'disk': 0, 'maxdisk': 32 * GIB, 'uptime': 3600 if run else 0})
        extra[('GET', f'/api/clusters/{cid}/resources')] = (200, res)
        vms = [r for r in res if r['type'] == 'qemu']
        cts = [r for r in res if r['type'] == 'lxc']
        extra[('GET', f'/api/clusters/{cid}/datacenter/status')] = (200, {
            'cluster': {'name': cid, 'quorate': True, 'standalone': False, 'version': 1},
            'nodes': {'online': nodes, 'offline': 0, 'total': nodes},
            'guests': {'vms': {'running': sum(r['status'] == 'running' for r in vms), 'stopped': sum(r['status'] != 'running' for r in vms), 'total': len(vms)},
                       'containers': {'running': sum(r['status'] == 'running' for r in cts), 'stopped': sum(r['status'] != 'running' for r in cts), 'total': len(cts)}},
            'resources': {'cpu': {'total': nodes * 32, 'used': nodes * 8.0, 'percent': 25.0},
                          'memory': {'total': nodes * 256 * GIB, 'used': nodes * 96 * GIB, 'percent': 37.5},
                          'storage': {'total': nodes * 4 * TIB, 'used': nodes * 1 * TIB, 'percent': 25.0}},
            'hardware': None})
    return cl, extra


def test_runtime_the_dashboard_renders_200_nodes_and_10k_guests(browser):
    clusters, extra = _big_inventory()
    t0 = time.time()
    app = _GuardApp(browser, _DashServer(layout=LAYOUT, clusters=clusters, status={}, extra=extra))
    try:
        page = app.page
        page.locator('[data-cr-dashboard]').wait_for(timeout=30000)
        page.wait_for_function('''() => {
            const s = document.querySelector('[data-cr-stat="nodes"] .cr-stat-value');
            const top = document.querySelector('[data-cr-top-of]');
            return s && s.innerText.replace(/\\s/g, '') === '200/200' && top && top.innerText.includes('of 7500');
        }''', timeout=60000)
        ready = time.time() - t0
        guests = [g for cid in (c['id'] for c in clusters) for g in extra[('GET', f'/api/clusters/{cid}/resources')][1]]
        for sid, kind in (('vms', 'qemu'), ('cts', 'lxc')):
            mine = [g for g in guests if g['type'] == kind]
            assert _stat(page, sid)['value'] == f"{sum(g['status'] == 'running' for g in mine)}/{len(mine)}", sid
        # ten clusters in the table, the ten busiest guests (not 10 000 rows) in the top list
        assert page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row').count() == 10
        assert page.locator('[data-cr-table="dash-top"] tbody tr.cr-row').count() == 10
        top = [r[_col(page, 'dash-top', 'cpu')] for r in _rows(page, 'dash-top')]
        assert top[0] == '99.0%'
        nodes = page.evaluate('() => document.querySelector("[data-cr-dashboard]").getElementsByTagName("*").length')
        # sorting the cluster table and switching the ranking stay quick
        t1 = time.time()
        page.locator('[data-cr-table="dash-clusters"] th[data-cr-col="cpu"] button').click()
        page.locator('[data-cr-table="dash-top"] [data-cr-rank="ram"]').click()
        page.wait_for_function('''() => document.querySelector('[data-cr-table="dash-top"] th[data-cr-col="ram"]')
            .getAttribute('aria-sort') === 'descending' ''', timeout=10000)
        react = time.time() - t1
        print(f'\n200 nodes / 10k guests: dashboard with figures after {ready:.2f}s, {nodes} DOM nodes in it, '
              f'sort + re-rank {react:.2f}s')
        assert nodes < 4000, nodes
        assert react < 3.0, react
        _no_errors(app)
    finally:
        app.close()
