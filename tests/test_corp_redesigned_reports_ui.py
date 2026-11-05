"""The Reports summary and Infrastructure Insights of Corporate Redesigned (Preview), in the browser.

The summary reads the cluster report through the dashboard's loader (period for 1h, 24h and 7d,
from/to for 6h and 30d) and shows each figure with its basis: CPU and memory now (live, only when
an online node answered), average, minimum and maximum of the stored 5-minute snapshots (hidden
when the range holds none), the running and stopped guests of the guest list, the charts with
their gaps, and the two rankings of the guest list (CPU and RAM apart, never one derived from the
other). A refused, failed or unreachable read, a cluster that is not connected and a confined
account are said, never drawn as zeros. Insights reads the forecast and the right-sizing apart:
each has its own state, an ETA is shown only where the server's rule holds, a weak fit is
labelled, a projection is drawn apart from the measured value, and right-sizing never claims an
all-clear for guests it did not evaluate. Top talkers and rollups come from the guest lists the
dashboard holds (no request of their own), with averages since start labelled as such.

The fake serves the shapes of pegaprox/api/reports.py (summary, with the from/to clamp to the
retention), insights.py (forecast, right-sizing, force-snapshot) and the /resources and /metrics
rows. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the build before
stage I). Skips without Playwright. LW Oct 2026
"""
import datetime
import os
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest

from test_corp_redesigned_dashboard_ui import CLUSTERS, PROD_GUESTS, _DashServer
from test_corp_redesigned_guard_ui import (CT, DETERMINISTIC, FIXED, INSIGHTS_FORECAST, INSIGHTS_RIGHTSIZING, VM,
                                           VM_OFF, _GuardApp)
from test_ha_ui import BASE, CLUSTER, NODE_METRICS

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3
RETENTION = 30 * 86400

# the guest list rows (/resources): a template, a paused guest, tags, a pool, I/O counters
WEB = dict(VM, tags='web;prod', pool='front', diskread=7 * GIB, diskwrite=1 * GIB, netin=3 * GIB, netout=1 * GIB, uptime=8 * 3600)
CT1 = dict(CT, tags='prod', pool='front', disk=2 * GIB, diskread=GIB, diskwrite=GIB, netin=GIB, netout=0, uptime=600)
DB = dict(VM_OFF, tags='db', maxdisk=64 * GIB)
TPL = dict(VM_OFF, vmid=9000, name='tpl-debian', template=1, status='stopped', node='pve1')
PAUSED = dict(VM, vmid=104, name='batch01', status='paused', cpu=0, cpu_percent=0, mem=0, mem_percent=0, uptime=0)
GUESTS = [WEB, CT1, DB, TPL, PAUSED]


def _iso(sec):
    return datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc).isoformat()


def _summary(n=48, step=1800, end=FIXED, live=True, scoped=False, gap=None, cpu_short=0, period='day'):
    """reports.py get_cluster_report_summary: one snapshot per step, newest at `end`; gap = (index,
    seconds) moves every later snapshot that much forward (a stretch the collector stored nothing)."""
    ts = [end - step * (n - 1 - i) for i in range(n)]
    if gap:
        at, sec = gap
        ts = [x - sec if i < at else x for i, x in enumerate(ts)]
    cpu = [round(4 + 11 * ((i * 7) % 11) / 10, 1) for i in range(n)]
    mem = [round(28 + 11 * ((i * 5) % 11) / 10, 1) for i in range(n)]
    cpu = cpu[cpu_short:]
    stat = lambda a: ({'avg': round(sum(a) / len(a), 1), 'min': min(a), 'max': max(a), 'current': a[-1], 'samples': a}
                      if a else {'avg': 8.5, 'min': 8.5, 'max': 8.5, 'current': 8.5, 'samples': []})
    body = {'period': period, 'cluster_id': 'c1', 'cluster_name': 'Testi', 'data_points': n, 'timestamps': [_iso(x) for x in ts],
            'cpu': stat(cpu), 'memory': stat(mem),
            'vms_running': {'avg': 2, 'min': 2, 'max': 3, 'current': 2, 'samples': [] if scoped else [2 + (i % 2) for i in range(n)]},
            'live': ({'cpu_percent': 8.5, 'mem_percent': 27.5, 'vms_running': 1, 'cts_running': 1, 'cpu_total': 0,
                      'mem_total': 64 * GIB, 'mem_used': 17.6 * GIB} if live else
                     {'cpu_percent': 0, 'mem_percent': 0, 'vms_running': 0, 'cts_running': 0, 'cpu_total': 0, 'mem_total': 0, 'mem_used': 0})}
    if scoped:
        body['scoped'] = True
    return body


def _forecast_item(metric, current, slope, r2, status, eta=None, kind='cluster', samples=720):
    f = {'metric': metric, 'kind': kind, 'current_pct': current, 'slope_per_day_pct': slope, 'r_squared': r2,
         'threshold_pct': 90.0, 'eta_days': eta, 'eta_iso': _iso(FIXED + eta * 86400)[:19] if eta else None,
         'status': status, 'samples': samples}
    if kind == 'storage':
        f['storage'] = metric
    return f


FORECAST = {'cluster_id': 'c1', 'window_days': 30, 'threshold_pct': 90.0, 'snapshots_in_window': 720, 'enough_data': True,
            'forecasts': [
                _forecast_item('cluster_cpu', 11.7, 0.012, 0.04, 'stable'),
                _forecast_item('cluster_memory', 35.0, 0.41, 0.18, 'trending_up', eta=134.1),
                _forecast_item('local-lvm', 81.2, 0.9, 0.86, 'warning', eta=9.8, kind='storage'),
                _forecast_item('nfs-backup', 92.5, 0.2, 0.7, 'over_threshold', kind='storage'),
                _forecast_item('ceph-a', 40.0, 1.0, 0.92, 'trending_up', eta=50.0, kind='storage'),
                _forecast_item('ceph-b', 60.0, 2.5, 0.95, 'trending_up', eta=12.0, kind='storage', samples=30),
                _forecast_item('old-iso', 55.0, -0.4, 0.8, 'decreasing', kind='storage'),
            ]}


def _rs(recs=None, summary=None, total=3, snaps=720, refreshing=False):
    body = dict(INSIGHTS_RIGHTSIZING, snapshots_in_window=snaps, total_vms=total, refreshing=refreshing)
    if recs is not None:
        body['recommendations'] = recs
    if summary is not None:
        body['summary'] = summary
    return body


SHORT = {'vmid': '101', 'type': 'lxc', 'name': 'ct01', 'node': 'pve1', 'cpu_avg': 62.0, 'cpu_p95': 91.0, 'mem_avg': 70.0,
         'mem_max': 95.0, 'maxcpu': 1, 'maxmem_gb': 1.0, 'samples': 30, 'flags': [
             {'kind': 'undersized_cpu', 'severity': 'warning', 'detail': 'avg 62.0% / p95 91.0% on 1 cores', 'current': 1,
              'recommended': 2, 'rationale': 'sustained high CPU \u2014 add cores'},
             {'kind': 'undersized_mem', 'severity': 'warning', 'detail': 'avg 70.0% / max 95.0% of 1.0 GB', 'current_gb': 1.0,
              'recommended_gb': 1.5, 'rationale': 'RAM pressure \u2014 increase by ~50%'}]}


class _RpServer(_DashServer):
    """The dashboard fake plus the report and insights routes, each settable: (code, body), a
    callable of the request url, 'abort' (dropped connection) or 'hold' (answered by release())."""

    def __init__(self, guests=None, summary=None, forecast=None, rightsizing=None, snapshot=None, node_metrics=None,
                 perms=None, admin=True, **kw):
        self.rp_perms = set(perms or [])
        metrics = node_metrics if node_metrics is not None else {
            'pve1': dict(NODE_METRICS['pve1'], disk_used=86 * GIB, disk_total=100 * GIB, disk_percent=86.0),
            'pve2': dict(NODE_METRICS['pve1'], disk_used=72 * GIB, disk_total=100 * GIB, disk_percent=72.0),
            'pve3': {'status': 'offline', 'cpu_percent': 0, 'mem_percent': 0, 'mem_used': 0, 'mem_total': 0, 'disk_percent': 0,
                     'disk_used': 0, 'disk_total': 0, 'netin': 0, 'netout': 0, 'score': 0, 'uptime': 0,
                     'maintenance_mode': False, 'offline': True}}
        super().__init__(resources=list(GUESTS if guests is None else guests), metrics=metrics, admin=admin,
                         permissions=sorted(self.rp_perms), **kw)
        self.routes = {
            ('GET', '/api/clusters/c1/reports/summary'): summary or self.summary_route,
            ('GET', '/api/clusters/c1/insights/forecast'): forecast or (200, FORECAST),
            ('GET', '/api/clusters/c1/insights/right-sizing'): rightsizing or (200, _rs()),
            ('POST', '/api/insights/force-snapshot'): snapshot or (200, {'ok': True, 'clusters': {}}),
        }
        self.held = []
        self.writes = []

    @staticmethod
    def summary_route(url):
        q = parse_qs(urlparse(url).query)
        if 'from' in q:
            start, end = float(q['from'][0]), float(q['to'][0])
            # history_range: cut to the retention and to now
            start, end = max(start, FIXED - RETENTION), min(end, FIXED)
            n = max(2, min(200, int((end - start) // 300)))
            body = _summary(n=n, step=(end - start) / n, end=end, period='range')
            body['from'], body['to'] = int(start), int(end)
            return 200, body
        period = q.get('period', ['day'])[0]
        return 200, _summary(n={'hour': 12, 'week': 56}.get(period, 48), step={'hour': 300, 'week': 10800}.get(period, 1800),
                             period=period)

    def release(self, answer):
        held, self.held = self.held, []
        for route in held:
            code, data = answer
            route.fulfill(status=code, body=__import__('json').dumps(data), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE):
            return super().handle(route)
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        if req.method != 'GET':
            self.writes.append((req.method, path))
        if callable(how):
            how = how(req.url)
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=__import__('json').dumps(data), headers={'Content-Type': 'application/json'})


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
        app = _GuardApp(br or browser, _RpServer(layout=layout, bundle=BUNDLE, **kw), corp_theme=theme,
                        storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -------------------------------------------------------------------------------------

def _wait(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline and not fn():
        page.wait_for_timeout(100)
    return fn()


def _calls(app, part, method=None):
    return [c for c in app.server.calls if part in c[1] and (method is None or c[0] == method)]


def _urls(app, part):
    return [u for u in app.server.urls if part in u]


def _no_errors(app, dropped=False):
    errors = [e for e in app.errors if not (dropped and ('Failed to fetch' in e or 'Failed to load report' in e))]
    assert not errors, errors


def _reports(page, cluster='Testi'):
    page.locator('.corp-tree-item', has_text=cluster).first.click()
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('[data-cr-rp]').wait_for(timeout=10000)


def _settled(page, seconds=8):
    _wait(page, lambda: page.locator('[data-cr-rp]').get_attribute('data-cr-rp') != 'loading', seconds)
    return page.locator('[data-cr-rp]').get_attribute('data-cr-rp')


def _insights(page, cluster='Testi'):
    _reports(page, cluster)
    page.locator('.corp-tab-strip button', has_text='Insights').first.click()
    page.locator('[data-cr-ins]').wait_for(timeout=10000)


def _stats(page):
    """{tile: (value, sub, basis)} of the key figures."""
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-rp-stat]')).map(s => [
        s.dataset.crRpStat, [Array.from(s.querySelector('.cr-stat-value').childNodes).map(n => n.textContent.trim()).filter(Boolean).join(' '),
                             (s.querySelector('[data-cr-rp-sub]') || {innerText: ''}).innerText.trim(),
                             (s.querySelector('[data-cr-rp-basis]') || {innerText: ''}).innerText.trim()]]))''')


def _rows(page, table, cols):
    return page.evaluate('''([table, cols]) => Array.from(document.querySelectorAll(`[data-cr-table="${table}"] tbody tr.cr-row`))
        .map(tr => { const tds = Array.from(tr.children); const heads = Array.from(tr.closest('table').querySelectorAll('thead th'));
                     return Object.fromEntries(cols.map(c => { const i = heads.findIndex(h => h.dataset.crCol === c);
                         return [c, i < 0 ? null : tds[i].innerText.replace(/\\s+/g, ' ').trim()]; })); })''', [table, cols])


def _notes(page):
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-rp-note]'))
        .map(n => [n.dataset.crRpNote, n.innerText.replace(/\\s+/g, ' ').trim()]))''')


# --- the summary ---------------------------------------------------------------------------------

def test_runtime_the_summary_shows_each_figure_with_its_basis(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok'
    s = _stats(page)
    body = _summary()
    assert s['cpu'][0] == '8.5%' and s['memory'][0] == '27.5%', s
    assert s['cpu'][1] == f"avg {body['cpu']['avg']:.1f}% · min {body['cpu']['min']:.1f}% · max {body['cpu']['max']:.1f}%", s['cpu']
    assert s['cpu'][2] == 'of 48 stored 5-minute snapshots' and s['memory'][2] == 'of 48 stored 5-minute snapshots'
    # VMs: web01 running, db01 stopped, batch01 paused (another state); the template is not a guest
    assert s['vms'][:2] == ['1 / 3', '1 stopped · 1 in another state'], s['vms']
    assert s['cts'][:2] == ['1 / 1', '0 stopped'], s['cts']
    assert 'Templates (1)' in page.locator('[data-cr-rp-stat="vms"]').get_attribute('title')
    assert s['history'][0] == '48 snapshots'
    # one report read for the 24 h preset, no top-vms walk: the rankings come from the guest list
    assert _urls(app, '/reports/summary') == [f'{BASE}/api/clusters/c1/reports/summary?period=day']
    assert not _calls(app, '/reports/top-vms')
    foot = page.locator('[data-cr-rp-history]').inner_text()
    assert foot.startswith('48 snapshots, about one every 30 min.'), foot
    _no_errors(app)


def test_runtime_no_stored_snapshot_hides_average_minimum_and_maximum(open_app):
    empty = _summary(n=0)
    # the server falls back to the live value for avg/min/max: they must not show
    empty['cpu'].update(avg=8.5, min=8.5, max=8.5)
    app = open_app(summary=(200, empty))
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok'
    s = _stats(page)
    assert s['cpu'] == ['8.5%', '', 'No stored snapshot in this range'], s['cpu']
    assert 'avg' not in page.locator('[data-cr-rp-stats]').inner_text()
    assert page.locator('[data-cr-perf="empty"]').count() == 1
    assert 'No snapshot stored in this range' in page.locator('[data-cr-perf]').inner_text()
    _no_errors(app)


@pytest.mark.parametrize('answer,state,says', [
    ((500, {'error': 'database is locked'}), 'error', 'database is locked'),
    ((403, {'error': 'Access denied to this cluster'}), 'forbidden', 'No permission'),
    ((404, {'error': 'Cluster not found'}), 'notfound', 'Not found'),
    ('abort', 'unreachable', 'PegaProx could not be reached'),
    ((503, {'error': 'The active instance cannot be reached', 'code': 'HA_ACTIVE_UNREACHABLE'}), 'away', 'active instance'),
], ids=['500', '403', '404', 'unreachable', 'leader-away'])
def test_runtime_a_failed_summary_read_is_said_never_drawn_as_zero(open_app, answer, state, says):
    app = open_app(summary=answer)
    page = app.page
    _reports(page)
    assert _settled(page) == state
    note = page.locator(f'[data-cr-rp-note="read-{state}"]')
    assert note.count() == 1 and says.lower() in note.inner_text().lower(), note.inner_text() if note.count() else _notes(page)
    s = _stats(page)
    assert s['cpu'][0] == '-' and s['memory'][0] == '-' and s['history'][0] == '-', s
    text = page.locator('[data-cr-rp]').inner_text()
    assert '0.0%' not in text and 'No running' not in text
    assert page.locator('[data-cr-perf="error"]').count() == 1
    # the retry asks again
    before = len(_calls(app, '/reports/summary'))
    page.locator(f'[data-cr-rp-retry="read-{state}"]').click()
    assert _wait(page, lambda: len(_calls(app, '/reports/summary')) > before)
    _no_errors(app, dropped=True)


def test_runtime_a_failed_refresh_drops_what_was_shown(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok' and _stats(page)['cpu'][0] == '8.5%'
    app.server.routes[('GET', '/api/clusters/c1/reports/summary')] = (500, {'error': 'boom'})
    page.locator('[data-cr-rp-refresh]').click()
    assert _wait(page, lambda: page.locator('[data-cr-rp]').get_attribute('data-cr-rp') == 'error')
    assert _stats(page)['cpu'][0] == '-'
    _no_errors(app)


def test_runtime_a_cluster_that_is_not_connected_shows_no_live_figure(open_app):
    off = dict(CLUSTER, connected=False, status='error')
    app = open_app(clusters=[off] + CLUSTERS[1:], summary=(200, _summary(live=False)))
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok'
    notes = _notes(page)
    assert 'not connected' in notes.get('offline', ''), notes
    s = _stats(page)
    assert s['cpu'][0] == '-' and s['memory'][0] == '-', s
    assert s['vms'] == ['-', 'Cluster not connected', ''] and s['cts'][0] == '-', s
    # the stored history stays: it is what it was
    assert s['history'][0] == '48 snapshots' and s['cpu'][2] == 'of 48 stored 5-minute snapshots'
    # the old lists of the dashboard are not shown as now
    for table in ('rp-top-cpu', 'rp-top-ram', 'rp-rootfs'):
        assert page.locator(f'[data-cr-table="{table}"] tbody tr.cr-row').count() == 0
        assert 'Cluster not connected' in page.locator(f'[data-cr-table="{table}"] td.cr-state').inner_text()
    assert '0.0%' not in page.locator('[data-cr-rp-stats]').inner_text()
    _no_errors(app)


def test_runtime_no_online_node_answer_is_unknown_not_zero(open_app):
    app = open_app(summary=(200, _summary(live=False)))
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok'
    assert 'No online node answered' in _notes(page).get('nolive', '')
    s = _stats(page)
    assert s['cpu'][0] == '-' and s['memory'][0] == '-'
    _no_errors(app)


def test_runtime_highest_ram_is_its_own_ranking_not_the_cpu_top_ten(open_app):
    busy = [dict(VM, vmid=200 + i, name=f'cpu{i:02d}', cpu=0.5 + i / 100, cpu_percent=50 + i, mem=GIB, maxmem=8 * GIB) for i in range(12)]
    fat = dict(VM, vmid=300, name='fat01', cpu=0.01, cpu_percent=1, mem=7.5 * GIB, maxmem=8 * GIB)
    app = open_app(guests=busy + [fat])
    page = app.page
    _reports(page)
    _settled(page)
    _wait(page, lambda: page.locator('[data-cr-table="rp-top-ram"] tbody tr.cr-row').count() == 10)
    cpu = _rows(page, 'rp-top-cpu', ['rank', 'name', 'v'])
    ram = _rows(page, 'rp-top-ram', ['rank', 'name', 'v'])
    assert [r['name'].split(' ')[0] for r in cpu] == [f'cpu{i:02d}' for i in range(11, 1, -1)], cpu
    assert 'fat01' not in ' '.join(r['name'] for r in cpu)
    assert ram[0]['name'].startswith('fat01') and ram[0]['v'] == '93.8%', ram[0]
    assert page.locator('[data-cr-rp-rankof="ram"]').inner_text() == 'Top 10 of 13 running'
    # both say they are now, not tied to the range
    assert 'highest cpu now' in page.locator('[data-cr-table="rp-top-cpu"]').inner_text().lower()
    assert 'highest ram now' in page.locator('[data-cr-table="rp-top-ram"]').inner_text().lower()
    _no_errors(app)


def test_runtime_a_ranked_guest_opens_its_view(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    _settled(page)
    page.locator('[data-cr-table="rp-top-cpu"] [data-cr-rp-go="c1:100"]').click()
    page.locator('[data-cr-objhead="vm"]').wait_for(timeout=8000)
    assert 'web01' in page.locator('[data-cr-objhead="vm"]').inner_text()
    _no_errors(app)


def test_runtime_a_confined_account_sees_its_note_and_no_guest_history(open_app):
    app = open_app(summary=(200, _summary(scoped=True)))
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok'
    assert 'part of this cluster' in _notes(page).get('scoped', '')
    charts = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-chart]")).map(c => c.dataset.crChart)')
    assert charts == ['cpu', 'memory'], charts
    _no_errors(app)


@pytest.mark.parametrize('preset,query,span', [
    ('hour', {'period': ['hour']}, None), ('6h', None, 6 * 3600), ('week', {'period': ['week']}, None), ('30d', None, 30 * 86400),
])
def test_runtime_a_preset_reads_by_period_or_from_to(open_app, preset, query, span):
    app = open_app()
    page = app.page
    _reports(page)
    _settled(page)
    page.locator(f'[data-cr-range="{preset}"]').click()
    assert _wait(page, lambda: len(_urls(app, '/reports/summary')) == 2)
    assert _wait(page, lambda: page.locator('[data-cr-rp]').get_attribute('data-cr-rp-range') == preset and _settled(page) == 'ok')
    q = parse_qs(urlparse(_urls(app, '/reports/summary')[-1]).query)
    if query:
        assert q == query, q
    else:
        # never period=6h: the server would answer a day and call it 6h
        assert 'period' not in q and abs(float(q['to'][0]) - float(q['from'][0]) - span) <= 2, q
    _no_errors(app)


def test_runtime_a_range_longer_than_the_history_says_where_it_starts(open_app):
    def short(url):
        q = parse_qs(urlparse(url).query)
        if 'from' not in q:
            return 200, _summary()
        # a server that keeps 7 days: the start is cut there
        start = FIXED - 7 * 86400
        body = _summary(n=200, step=7 * 86400 / 200, period='range')
        body['from'], body['to'] = start, int(float(q['to'][0]))
        return 200, body
    app = open_app(summary=short)
    page = app.page
    _reports(page)
    _settled(page)
    page.locator('[data-cr-range="30d"]').click()
    page.locator('[data-cr-rp-clamp="kept"]').wait_for(timeout=6000)
    assert 'Asked for 30d: this server keeps less history' in page.locator('[data-cr-rp-clamp]').inner_text()
    _no_errors(app)


def test_runtime_gaps_and_unplaceable_samples_are_said(open_app):
    # a 3 hour stretch without snapshots after the 20th; two snapshots without a CPU figure
    body = _summary(gap=(20, 3 * 3600), cpu_short=2)
    app = open_app(summary=(200, body))
    page = app.page
    _reports(page)
    assert _settled(page) == 'ok'
    page.locator('[data-cr-rp-gaps]').wait_for(timeout=5000)
    assert page.locator('[data-cr-rp-gaps]').get_attribute('data-cr-rp-gaps') == '1'
    skew = page.locator('[data-cr-rp-skew="cpu"]').inner_text()
    assert skew.startswith('CPU: 46 of 48 snapshots carry a figure'), skew
    # the CPU chart is left out with the reason, the memory chart is drawn
    assert 'Cannot be placed in time' in page.locator('[data-cr-chart="cpu"]').inner_text()
    assert page.locator('[data-cr-chart="memory"] canvas').count() == 1
    # avg/min/max stay: they are over the snapshots that carry a figure
    assert _stats(page)['cpu'][2] == 'of 46 stored 5-minute snapshots'
    _no_errors(app)


def test_runtime_node_root_file_systems_show_offline_nodes_and_storage_tones(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    _settled(page)
    _wait(page, lambda: page.locator('[data-cr-table="rp-rootfs"] tbody tr.cr-row').count() == 3)
    tones = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-rp-fs]'))
        .map(e => [e.dataset.crRpFs, [e.dataset.crRpFstone, e.innerText.trim()]]))''')
    assert tones == {'pve1': ['error', '86.0%'], 'pve2': ['warning', '72.0%'], 'pve3': ['unknown', 'offline, no figure']}, tones
    rows = _rows(page, 'rp-rootfs', ['name', 'state', 'used', 'free'])
    # sorted by use, the node without a figure last
    assert [r['name'] for r in rows] == ['pve1', 'pve2', 'pve3'] and rows[2]['state'] == 'Offline' and rows[2]['used'] == '-', rows
    assert '2 at or above 70%' in page.locator('[data-cr-table="rp-rootfs"]').inner_text()
    page.locator('[data-cr-rp-node="pve2"]').click()
    page.locator('[data-cr-objhead="node"]').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_the_more_section_says_what_is_not_there_and_leads_to_insights(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    _settled(page)
    btn = page.locator('[data-cr-rp-more]')
    assert btn.get_attribute('aria-expanded') == 'false'
    btn.focus()
    page.keyboard.press('Enter')
    body = page.locator('[data-cr-rp-more-body]')
    body.wait_for(timeout=3000)
    assert btn.get_attribute('aria-expanded') == 'true'
    assert 'nothing in PegaProx reads IOPS' in body.inner_text()
    page.locator('[data-cr-rp-insights]').click()
    page.locator('[data-cr-ins]').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_the_pdf_says_dash_where_nothing_was_reported(open_app):
    off = dict(CLUSTER, connected=False, status='error')
    app = open_app(clusters=[off] + CLUSTERS[1:], summary=(500, {'error': 'boom'}))
    page = app.page
    _reports(page)
    assert _settled(page) == 'error'
    with page.expect_download(timeout=15000) as dl:
        page.locator('[data-cr-rp-export="pdf"]').click()
    data = open(dl.value.path(), 'rb').read()
    assert data.startswith(b'%PDF')
    text = data.decode('latin-1')
    assert 'CPU now' in text and '0.0%' not in text and '(0%)' not in text
    assert dl.value.suggested_filename.startswith('pegaprox-report-Testi-')
    _no_errors(app)


def test_runtime_the_png_export_still_works(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    _settled(page)
    with page.expect_download(timeout=20000) as dl:
        page.locator('[data-cr-rp-export="png"]').click()
    assert dl.value.suggested_filename.endswith('.png')
    assert open(dl.value.path(), 'rb').read()[:8] == b'\x89PNG\r\n\x1a\n'
    _no_errors(app)


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_keep_the_classic_summary_and_insights(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)
    page.locator('button', has_text=re.compile(r'^\s*Reports\s*$')).first.click()
    page.locator('#report-summary-content').wait_for(timeout=8000)
    assert page.locator('[data-cr-rp]').count() == 0
    # classic still reads its top-vms list
    assert _wait(page, lambda: bool(_calls(app, '/reports/top-vms')))
    page.locator('button', has_text=re.compile(r'^\s*Insights\s*$')).first.click()
    page.get_by_text('Right-sizing Recommendations').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-ins]').count() == 0
    assert _wait(page, lambda: bool(_calls(app, '/insights/top-talkers')))


# --- Insights -------------------------------------------------------------------------------------

def _fc_rows(page):
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-table="ins-forecast"] tbody tr.cr-row'))
        .map(tr => [tr.children[0].innerText.trim(), {
            status: tr.querySelector('[data-cr-ins-status]').dataset.crInsStatus,
            fit: tr.querySelector('[data-cr-ins-fit]').dataset.crInsFit,
            eta: tr.querySelector('[data-cr-ins-eta]').dataset.crInsEta,
            etaText: tr.querySelector('[data-cr-ins-eta]').innerText.trim(),
            proj: tr.querySelector('[data-cr-ins-proj]').dataset.crInsProj,
            projLabel: tr.querySelector('[data-cr-ins-proj]').getAttribute('aria-label'),
        }]))''')


def test_runtime_insights_reads_the_forecast_and_right_sizing_apart(open_app):
    app = open_app(forecast=(403, {'error': 'Permission denied: cluster.view'}))
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-fc="forbidden"]').wait_for(timeout=6000)
    note = page.locator('[data-cr-rp-note="fc-forbidden"]').inner_text()
    assert 'capacity forecast could not be read: no permission' in note.lower(), note
    # right-sizing landed on its own
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    assert page.locator('[data-cr-table="ins-rightsizing"] tbody tr.cr-row').count() == 1
    assert _urls(app, '/insights/forecast?days=30') and _urls(app, '/insights/right-sizing?days=30')
    # top talkers and rollups ask nothing: the guest list is held already
    assert not _calls(app, '/insights/top-talkers') and not _calls(app, '/insights/rollups')
    _no_errors(app)


def test_runtime_a_failed_right_sizing_read_leaves_the_forecast(open_app):
    app = open_app(rightsizing='abort')
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-rs="unreachable"]').wait_for(timeout=6000)
    assert 'right-sizing recommendations could not be read' in page.locator('[data-cr-rp-note="rs-unreachable"]').inner_text().lower()
    page.locator('[data-cr-ins-fc="ok"]').wait_for(timeout=6000)
    # the retry reads again
    app.server.routes[('GET', '/api/clusters/c1/insights/right-sizing')] = (200, _rs())
    page.locator('[data-cr-rp-retry="rs-unreachable"]').click()
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    _no_errors(app, dropped=True)


def test_runtime_the_forecast_shows_its_fit_and_an_eta_only_where_the_rule_holds(open_app):
    app = open_app()
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-fc="ok"]').wait_for(timeout=6000)
    _wait(page, lambda: len(_fc_rows(page)) == 7)
    rows = _fc_rows(page)
    # warning: the server's gate passed, the date is an estimate
    assert rows['local-lvm']['eta'] == 'estimate' and rows['local-lvm']['etaText'].startswith('in about 9.8 days'), rows['local-lvm']
    # trending up with R2 0.18: the server computed 134 days, its rule does not hold: no date
    assert rows['Cluster Memory']['eta'] == 'weak' and rows['Cluster Memory']['fit'] == 'weak', rows['Cluster Memory']
    # trending up within 30 days: the server judged it weak (else it would say warning)
    assert rows['ceph-b']['eta'] == 'weak'
    # beyond 30 days the server does not judge: the same rule applied here holds
    assert rows['ceph-a']['eta'] == 'estimate' and rows['ceph-a']['fit'] == 'ok'
    assert rows['Cluster CPU']['eta'] == 'none' and rows['nfs-backup']['eta'] == 'over'
    assert rows['nfs-backup']['status'] == 'over_threshold' and rows['old-iso']['status'] == 'decreasing'
    # measured and projected apart: memory 35 % + 0.41/day x 30 days; a decreasing series goes down
    assert rows['Cluster Memory']['proj'] == '47.3' and 'projected 47.3%' in rows['Cluster Memory']['projLabel']
    assert float(rows['old-iso']['proj']) < 55.0 and float(rows['local-lvm']['proj']) == 100.0
    assert 'Measured 35.0%' in rows['Cluster Memory']['projLabel']
    text = page.locator('[data-cr-ins-fc]').inner_text()
    assert 'Straight-line estimate over 30 days' in text and 'A projection is not a measurement' in text
    assert '720/720' in text and '30/720' in text
    _no_errors(app)


def test_runtime_not_enough_history_is_said_and_nothing_projected(open_app):
    app = open_app(forecast=(200, {'cluster_id': 'c1', 'window_days': 30, 'snapshots_in_window': 4, 'enough_data': False,
                                   'message': 'not enough history yet', 'forecasts': []}))
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-fc="notenough"]').wait_for(timeout=6000)
    assert 'Not enough history yet: 4 snapshots in the window' in page.locator('[data-cr-rp-note="fc-notenough"]').inner_text()
    assert page.locator('[data-cr-table="ins-forecast"]').count() == 0
    _no_errors(app)


@pytest.mark.parametrize('summary,says', [
    ({'oversized_cpu': 0, 'oversized_mem': 0, 'undersized_cpu': 0, 'undersized_mem': 0, 'idle': 0, 'no_data': 100, 'ok': 5},
     'None of the 5 evaluated guests has a finding; 100 guests were not evaluated'),
    ({'oversized_cpu': 0, 'oversized_mem': 0, 'undersized_cpu': 0, 'undersized_mem': 0, 'idle': 0, 'no_data': 40, 'ok': 0},
     'No guest has enough history yet: 40 guests have fewer than 24 running samples'),
], ids=['most-not-evaluated', 'none-evaluated'])
def test_runtime_right_sizing_never_claims_an_all_clear(open_app, summary, says):
    app = open_app(rightsizing=(200, _rs(recs=[], summary=summary, total=105)))
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    text = page.locator('[data-cr-ins-rs]').inner_text()
    assert says in text, text
    assert 'right-sized' not in text.lower()
    counts = page.locator('[data-cr-ins-counts]')
    assert counts.locator(f'[data-cr-ins-nodata="{summary["no_data"]}"]').count() == 1
    assert counts.locator(f'[data-cr-ins-evaluated="{summary["ok"]}"]').count() == 1
    _no_errors(app)


def test_runtime_a_recommendation_explains_itself_and_leads_to_the_configuration(open_app):
    app = open_app(rightsizing=(200, _rs(recs=INSIGHTS_RIGHTSIZING['recommendations'] + [SHORT],
                                        summary=dict(INSIGHTS_RIGHTSIZING['summary'], undersized_cpu=1, undersized_mem=1))))
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    rows = _rows(page, 'ins-rightsizing', ['guest', 'flags', 'suggest', 'cov'])
    by = {r['guest'].split(' ')[0]: r for r in rows}
    assert by['web01']['suggest'] == 'vCPU 4 → 2 · RAM 4 → 2 GB' and by['web01']['cov'] == '97%', by['web01']
    assert by['ct01']['cov'] == '4%', by['ct01']
    # the short observation opens with its risks; the rationale keeps no long dash
    page.locator('[data-cr-table="ins-rightsizing"] tbody tr.cr-row', has_text='ct01').click()
    panel = page.locator('[data-cr-sidepanel="ins-rs"]')
    panel.wait_for(timeout=4000)
    txt = panel.inner_text()
    assert '30 running samples, 4% of the window\'s snapshots' in txt, txt
    assert 'Seen running in less than half of the window.' in txt and 'not checked inside the guest' in txt
    assert '\u2014' not in txt and 'Never applied automatically.' in txt
    assert panel.locator('[data-cr-ins-config]').count() == 1
    page.keyboard.press('Escape')
    panel.wait_for(state='detached', timeout=3000)
    # web01: the configuration opens on its hardware tab, nothing is sent
    page.locator('[data-cr-table="ins-rightsizing"] tbody tr.cr-row', has_text='web01').click()
    page.locator('[data-cr-ins-config]').click()
    # the dialog opens on its hardware tab (the general tab with the name field is not drawn)
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    # the preview's Hardware tab in sections (round 5): cores per socket beside the sockets
    page.locator('[data-cr-vc-hw] [data-cr-vc-input="cores"]').wait_for(timeout=8000)
    assert page.locator('input[value="web01"]').count() == 0
    assert not [w for w in app.server.writes if 'config' in w[1]]
    _no_errors(app)


def test_runtime_without_vm_config_a_recommendation_offers_no_change(open_app):
    app = open_app(admin=False, perms=['cluster.view', 'vm.view', 'node.view'])
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    page.locator('[data-cr-table="ins-rightsizing"] tbody tr.cr-row').first.click()
    panel = page.locator('[data-cr-sidepanel="ins-rs"]')
    panel.wait_for(timeout=4000)
    assert panel.locator('[data-cr-ins-config]').count() == 0
    assert 'vm.config' in panel.locator('[data-cr-ins-noconfig]').inner_text()
    # the snapshot is an admin's
    assert page.locator('[data-cr-ins-snap]').count() == 0
    _no_errors(app)


def test_runtime_the_snapshot_reads_both_again_and_says_a_refusal(open_app):
    app = open_app()
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-fc="ok"]').wait_for(timeout=6000)
    before = len(_calls(app, '/insights/forecast'))
    page.locator('[data-cr-ins-snap]').click()
    page.locator('[data-cr-rp-note="snap-ok"]').wait_for(timeout=6000)
    assert app.server.writes == [('POST', '/api/insights/force-snapshot')]
    assert _wait(page, lambda: len(_calls(app, '/insights/forecast')) > before)
    app.server.routes[('POST', '/api/insights/force-snapshot')] = (500, {'ok': False, 'error': 'collector timed out'})
    page.locator('[data-cr-ins-snap]').click()
    page.locator('[data-cr-rp-note="snap"]').wait_for(timeout=6000)
    assert 'Snapshot not taken: collector timed out' in page.locator('[data-cr-rp-note="snap"]').inner_text()
    _no_errors(app)


def test_runtime_top_talkers_rank_the_guest_list_with_averages_since_start(open_app):
    chatty = dict(VM, vmid=110, name='old01', diskread=50 * GIB, diskwrite=10 * GIB, netin=0, netout=0, uptime=60 * 86400)
    app = open_app(guests=GUESTS + [chatty])
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-tt]').wait_for(timeout=6000)
    page.locator('[data-cr-ins-metric]').select_option('dio')
    _wait(page, lambda: page.locator('[data-cr-ins-tt="dio"]').count() == 1)
    rows = _rows(page, 'ins-talkers', ['guest', 'dio', 'dioRate', 'disk'])
    # by the counter the long-running guest is first; its average since start is small
    assert rows[0]['guest'].startswith('old01') and rows[0]['dio'] == '60.0 GB', rows
    page.locator('[data-cr-ins-metric]').select_option('dioRate')
    _wait(page, lambda: page.locator('[data-cr-ins-tt="dioRate"]').count() == 1)
    rows = _rows(page, 'ins-talkers', ['guest', 'dioRate', 'disk'])
    assert [r['guest'].split(' ')[0] for r in rows] == ['ct01', 'web01', 'old01'], rows
    # 2 GiB in 600 s
    assert rows[0]['dioRate'] == '3.4 MB/s', rows[0]
    # a VM without agent data reports no disk use: unknown, not 0 %
    web = next(r for r in rows if r['guest'].startswith('web01'))
    assert web['disk'] == 'not reported', web
    hint = page.locator('[data-cr-ins-tthint]').inner_text()
    assert 'cumulative since VM boot' in hint and 'not the current throughput' in hint
    assert not _calls(app, '/insights/top-talkers')
    _no_errors(app)


def test_runtime_top_talkers_filter_by_node_and_take_every_cluster(open_app):
    other = dict(VM, vmid=120, name='edge01', node='pve2', cpu=0.8, cpu_percent=80)
    app = open_app(guests=GUESTS + [other])
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-tt]').wait_for(timeout=6000)
    _wait(page, lambda: page.locator('[data-cr-table="ins-talkers"] tbody tr.cr-row').count() == 3)
    page.locator('[data-cr-ins-node="tt"]').select_option('pve2')
    _wait(page, lambda: page.locator('[data-cr-table="ins-talkers"] tbody tr.cr-row').count() == 1)
    assert _rows(page, 'ins-talkers', ['guest'])[0]['guest'].startswith('edge01')
    page.locator('[data-cr-ins-scope="tt"]').select_option('all')
    # Prod's guests come from the overview poll the dashboard runs anyway
    assert _wait(page, lambda: page.locator('[data-cr-table="ins-talkers"] tbody tr.cr-row').count() == 3 + len(PROD_GUESTS), 8)
    names = [r['guest'].split(' ')[0] for r in _rows(page, 'ins-talkers', ['guest'])]
    assert names[0] == 'app01' and 'edge01' in names, names
    assert page.locator('[data-cr-table="ins-talkers"] thead th[data-cr-col="cluster"]').count() == 1
    _no_errors(app)


def test_runtime_rollups_open_to_their_member_guests(open_app):
    app = open_app()
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-ru="tag"]').wait_for(timeout=6000)
    _wait(page, lambda: page.locator('[data-cr-table="ins-rollups"] tbody tr.cr-row').count() == 4)
    rows = {r['key']: r for r in _rows(page, 'ins-rollups', ['key', 'count', 'running', 'vcpu', 'cores'])}
    # web01 counts in web and in prod; the template and the paused guest have no tag
    assert {k: (v['count'], v['running']) for k, v in rows.items()} == {
        'prod': ('2', '2'), 'web': ('1', '1'), 'db': ('1', '0'), '(untagged)': ('2', '0')}, rows
    assert rows['prod']['cores'] == '0.1'
    exp = page.locator('[data-cr-ins-expand="prod"]')
    assert exp.get_attribute('aria-expanded') == 'false'
    exp.click()
    members = page.locator('[data-cr-ins-members="prod"]')
    members.wait_for(timeout=3000)
    assert exp.get_attribute('aria-expanded') == 'true'
    names = sorted(re.split(r'\s+', t.strip())[0] for t in members.locator('tbody tr.cr-row').all_inner_texts())
    assert names == ['ct01', 'web01'], names
    # a member opens its guest
    members.locator('[data-cr-rp-go="c1:101"]').click()
    page.locator('[data-cr-objhead="ct"]').wait_for(timeout=8000)
    assert not _calls(app, '/insights/rollups')
    _no_errors(app)


def test_runtime_rollups_by_pool_running_only_and_without_tags(open_app):
    untagged = [dict(g, tags='') for g in GUESTS]
    app = open_app(guests=untagged)
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-ru="tag"]').wait_for(timeout=6000)
    page.locator('[data-cr-rp-note="ru-untagged"]').wait_for(timeout=4000)
    page.locator('[data-cr-ins-by="pool"]').click()
    _wait(page, lambda: page.locator('[data-cr-ins-ru="pool"]').count() == 1)
    rows = {r['key']: r['count'] for r in _rows(page, 'ins-rollups', ['key', 'count'])}
    assert rows == {'front': '2', '(no pool)': '3'}, rows
    page.locator('[data-cr-ins-running]').check()
    _wait(page, lambda: {r['key'] for r in _rows(page, 'ins-rollups', ['key'])} == {'front'})
    _no_errors(app)


def test_runtime_a_large_inventory_stays_quick(open_app):
    many = [dict(VM, vmid=1000 + i, name=f'g{i:05d}', node=f'pve{i % 200}', cpu=(i % 97) / 100, cpu_percent=i % 97,
                 mem=(i % 89) * GIB / 10, maxmem=10 * GIB, tags=f'team{i % 40};env{i % 3}', diskread=i * 1000, diskwrite=i,
                 netin=i * 10, netout=i, uptime=1000 + i) for i in range(10000)]
    app = open_app(guests=many)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('[data-cr-rp]').wait_for(timeout=15000)
    _wait(page, lambda: page.locator('[data-cr-rp-rankof="cpu"]').inner_text().endswith('of 10000 running'), 15)
    t0 = time.time()
    page.locator('.corp-tab-strip button', has_text='Insights').first.click()
    page.locator('[data-cr-table="ins-rollups"] tbody tr.cr-row').first.wait_for(timeout=15000)
    page.locator('[data-cr-table="ins-talkers"] tbody tr.cr-row').first.wait_for(timeout=15000)
    took = time.time() - t0
    assert took < 6, took
    assert page.locator('[data-cr-ins-ttof]').inner_text() == 'Top 20 of 10000 running'
    assert page.locator('[data-cr-table="ins-rollups"] tbody tr.cr-row').count() == 43
    # the 3333-guest group opens as a virtualized list
    page.locator('[data-cr-ins-expand="env0"]').click()
    members = page.locator('[data-cr-ins-members="env0"] tbody tr.cr-row')
    members.first.wait_for(timeout=5000)
    assert members.count() < 100
    _no_errors(app)


def test_runtime_german(open_app):
    app = open_app(language='de')
    page = app.page
    _reports(page)
    _settled(page)
    assert 'cpu jetzt' in page.locator('[data-cr-rp-stats]').inner_text().lower()
    assert 'aus 48 gespeicherten 5-Minuten-Snapshots' in page.locator('[data-cr-rp-basis="cpu"]').inner_text()
    page.locator('.corp-tab-strip button', has_text='Insights').first.click()
    page.locator('[data-cr-ins-fc="ok"]').wait_for(timeout=8000)
    assert 'Geradenschätzung über 30 Tage' in page.locator('[data-cr-ins-fc]').inner_text()
    _no_errors(app)


def _overlaps(page):
    """Pairs of key-figure tiles or toolbar controls that overlap, and the sideways overflow."""
    return page.evaluate('''() => {
        const boxes = (sel) => Array.from(document.querySelectorAll(sel)).map(e => e.getBoundingClientRect()).filter(r => r.width && r.height);
        const hit = (a, b) => a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1;
        const out = [];
        for (const sel of ['[data-cr-rp-stat]', '.cr-pagehead-actions > *', '.cr-ins-panel .cr-table-toolbar-left > *']) {
            const b = boxes(sel);
            for (let i = 0; i < b.length; i++) for (let j = i + 1; j < b.length; j++) if (hit(b[i], b[j])) out.push(sel);
        }
        const clipped = Array.from(document.querySelectorAll('[data-cr-rp-stat] .cr-stat-value, [data-cr-rp-stat] .cr-stat-sub'))
            .filter(e => e.scrollWidth > e.clientWidth + 1).length;
        return { out, clipped, over: document.documentElement.scrollWidth - window.innerWidth };
    }''')


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_nothing_overlaps_or_scrolls_sideways(open_app, firefox, engine, width):
    app = open_app(viewport=(width, 1000), br=firefox if engine == 'firefox' else None)
    page = app.page
    _reports(page)
    _settled(page)
    page.wait_for_timeout(600)
    r = _overlaps(page)
    assert r == {'out': [], 'clipped': 0, 'over': 0}, r
    page.locator('.corp-tab-strip button', has_text='Insights').first.click()
    page.locator('[data-cr-ins-fc="ok"]').wait_for(timeout=8000)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=8000)
    page.wait_for_timeout(600)
    r = _overlaps(page)
    assert r == {'out': [], 'clipped': 0, 'over': 0}, r
    # the threshold crossing column is in view without scrolling the table at either width
    box = page.locator('[data-cr-table="ins-forecast"] thead th[data-cr-col="eta"]').bounding_box()
    wrap = page.locator('[data-cr-table="ins-forecast"] .cr-table-scroll').bounding_box()
    assert box['x'] + box['width'] <= wrap['x'] + wrap['width'] + 1, (box, wrap)
    _no_errors(app)


def test_runtime_every_control_is_named(open_app):
    app = open_app()
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-fc="ok"]').wait_for(timeout=8000)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=8000)
    unnamed = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-ins button, .cr-ins select, .cr-ins input'))
        .filter(e => !(e.getAttribute('aria-label') || e.innerText.trim() || e.title || (e.labels && e.labels.length)))
        .map(e => e.outerHTML.slice(0, 120))''')
    assert unnamed == [], unnamed
    # each projection bar is a picture with words
    assert page.locator('[data-cr-ins-proj][role="img"][aria-label]').count() == 7
    _no_errors(app)


# --- after the review of round 3 -------------------------------------------------------------------

def test_runtime_a_node_status_without_rootfs_is_not_reported_never_empty(open_app):
    # manager.py reads a node status without rootfs as 0 used of 1 byte
    metrics = {'pve1': dict(NODE_METRICS['pve1'], disk_used=0, disk_total=1, disk_percent=0.0),
               'pve2': dict(NODE_METRICS['pve1'], disk_used=72 * GIB, disk_total=100 * GIB, disk_percent=72.0)}
    app = open_app(node_metrics=metrics)
    page = app.page
    _reports(page)
    _settled(page)
    _wait(page, lambda: page.locator('[data-cr-table="rp-rootfs"] tbody tr.cr-row').count() == 2)
    tones = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-rp-fs]'))
        .map(e => [e.dataset.crRpFs, [e.dataset.crRpFstone, e.innerText.trim()]]))''')
    assert tones == {'pve1': ['unknown', 'not reported'], 'pve2': ['warning', '72.0%']}, tones
    rows = {r['name']: r for r in _rows(page, 'rp-rootfs', ['name', 'used', 'free'])}
    assert rows['pve1']['used'] == '-' and rows['pve1']['free'] == '-', rows
    _no_errors(app)


def test_runtime_aria_controls_of_the_more_section_names_only_what_is_there(open_app):
    app = open_app()
    page = app.page
    _reports(page)
    _settled(page)
    btn = page.locator('[data-cr-rp-more]')
    assert btn.get_attribute('aria-expanded') == 'false'
    dangling = '''() => Array.from(document.querySelectorAll('[aria-controls]')).flatMap(el => el.getAttribute('aria-controls')
        .split(/\\s+/).filter(id => !document.getElementById(id)).map(id => el.tagName + ' ' + id))'''
    assert page.evaluate(dangling) == []
    btn.click()
    page.locator('[data-cr-rp-more-body]').wait_for(timeout=3000)
    assert btn.get_attribute('aria-controls') == 'cr-rp-more-body'
    assert page.evaluate(dangling) == []
    _no_errors(app)


def test_runtime_the_groups_without_a_tag_or_pool_are_named_in_the_users_language(open_app):
    app = open_app(language='de')
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-ru="tag"]').wait_for(timeout=6000)
    _wait(page, lambda: page.locator('[data-cr-table="ins-rollups"] tbody tr.cr-row').count() == 4)
    names = {r['key'] for r in _rows(page, 'ins-rollups', ['key'])}
    assert names == {'prod', 'web', 'db', '(ohne Tag)'}, names
    page.locator('[data-cr-ins-by="pool"]').click()
    _wait(page, lambda: page.locator('[data-cr-ins-ru="pool"]').count() == 1)
    assert '(ohne Pool)' in {r['key'] for r in _rows(page, 'ins-rollups', ['key'])}
    _no_errors(app)


def test_runtime_escape_in_the_configuration_dialog_leaves_the_panel(open_app):
    app = open_app()
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    page.locator('[data-cr-table="ins-rightsizing"] tbody tr.cr-row', has_text='web01').click()
    panel = page.locator('[data-cr-sidepanel="ins-rs"]')
    panel.wait_for(timeout=4000)
    page.locator('[data-cr-ins-config]').click()
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    # a click on the dialog's text, then Escape: the classic dialog has no Escape of its own,
    # and the panel behind it stays
    page.get_by_text('Sockets').first.click()
    page.keyboard.press('Escape')
    page.wait_for_timeout(400)
    assert panel.count() == 1
    # a field of the dialog has the focus: the same
    page.locator('.corp-vm-modal input').first.focus()
    page.keyboard.press('Escape')
    page.wait_for_timeout(400)
    assert panel.count() == 1
    _no_errors(app)


def test_runtime_escape_on_the_page_still_closes_the_panel(open_app):
    app = open_app()
    page = app.page
    _insights(page)
    page.locator('[data-cr-ins-rs="ok"]').wait_for(timeout=6000)
    page.locator('[data-cr-table="ins-rightsizing"] tbody tr.cr-row', has_text='web01').click()
    panel = page.locator('[data-cr-sidepanel="ins-rs"]')
    panel.wait_for(timeout=4000)
    # the focus back on the page behind the panel (it is not modal)
    page.locator('[data-cr-ins] .cr-pagehead-title').first.click()
    assert not page.evaluate('() => !!document.activeElement.closest("[data-cr-sidepanel]")')
    page.keyboard.press('Escape')
    panel.wait_for(state='detached', timeout=3000)
    _no_errors(app)
