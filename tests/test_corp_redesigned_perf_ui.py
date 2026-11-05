"""The performance metrics of a node and a guest in Corporate Redesigned (Preview), round 4.

The Monitor tab of a node and of a guest shows figures above the charts (each with its source and
the time of its sample), the charts with straight lines, the thresholds PegaProx has and the slots
without a sample shaded, the newest sample, its age and the gaps under them, three groups a user
opens (pressure stall, the period before from the stored snapshots, the interface counters of a
node over SSH) and what the loaded range says against a threshold. Opening asks the RRD of the
range and the alert rules of the cluster once, nothing per node; the stored history and the SSH
counters only on a click. The fake answers in the shapes of pegaprox/core/manager.py
(get_node_rrddata, get_vm_rrd, get_node_netstats), pegaprox/api/nodes.py and vms.py
(metrics-history with history_range of background/metrics.py), api/alerts.py (the rule list) and
core/xcpng.py (the wrapped node answer). PEGAPROX_CR_BUNDLE=<file> serves another bundle (the
counterproof). Skips without Playwright. LW Nov 2026
"""
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_corp_redesigned_dashboard_ui import CLUSTERS, _bytes
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, METRICS, _GuardApp
from test_corp_redesigned_objects_ui import (SUMMARY, _ObjServer, _no_errors, _open_guest, _open_node, _rrd_urls,
                                             _wait)
from test_ha_ui import BASE, NODE_METRICS, VM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3

# the hour preset as PVE gives it: 70 slots of a minute, the two newest still empty, four minutes
# without a sample in the middle; CPU above 90 % for five minutes
TS = [FIXED - 60 * (71 - i) for i in range(70)]
GAP = (30, 34)
HOT = (50, 55)


def _wave(base, spread, hot=None, n=70, gap=GAP):
    out = []
    for i in range(n):
        if gap[0] <= i < gap[1] or i >= n - 2:
            out.append(None)
            continue
        v = round(base + spread * (((i * 7) % 11) / 10.0), 2)
        if hot and hot[0] <= i < hot[1]:
            v = hot[2]
        out.append(v)
    return out


PSI = {'pressurecpusome': _wave(1, 2), 'pressurecpufull': _wave(0, 0.5), 'pressurememorysome': _wave(0.5, 1),
       'pressurememoryfull': _wave(0, 0.3), 'pressureiosome': _wave(2, 3), 'pressureiofull': _wave(1, 2)}
NODE_RRD = {'timeframe': 'hour', 'node': 'pve1', 'timestamps': TS, 'metrics': dict({
    'cpu': _wave(8, 20, hot=HOT + (93.5,)), 'memory': _wave(40, 6), 'swap': _wave(12, 0.5), 'iowait': _wave(0.5, 3),
    'loadavg': _wave(0.4, 1.2), 'net_in': _wave(120, 80), 'net_out': _wave(60, 50), 'rootfs': _wave(10, 0.2)}, **PSI)}
# a node of PVE 8: no pressure series
NODE_RRD_PVE8 = {'timeframe': 'hour', 'node': 'pve1', 'timestamps': TS,
                 'metrics': {k: v for k, v in NODE_RRD['metrics'].items() if not k.startswith('pressure')}}
GUEST_RRD = {'timeframe': 'hour', 'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'timestamps': TS, 'metrics': dict({
    'cpu': _wave(4, 30), 'memory': _wave(50, 10, hot=HOT + (95.0,)), 'disk_read': _wave(20000, 90000),
    'disk_write': _wave(50000, 120000), 'net_in': _wave(3000, 9000), 'net_out': _wave(1500, 4000)}, **PSI)}
SUMMARY_SWAP = dict(SUMMARY, swap={'used': 1 * GIB, 'total': 8 * GIB})

# the rules of api/alerts.py: one watches this node's CPU, one the cluster's average (not this node's
# line), one switched off, one watches the memory of guest 100
RULES = [
    {'id': 'r1', 'name': 'Node CPU high', 'metric': 'cpu', 'operator': '>', 'threshold': 85, 'target_type': 'node',
     'target_id': 'pve1', 'enabled': True, 'severity': 'critical'},
    {'id': 'r2', 'name': 'Cluster CPU', 'metric': 'cpu', 'operator': '>', 'threshold': 50, 'target_type': 'cluster',
     'target_id': None, 'enabled': True, 'severity': 'warning'},
    {'id': 'r3', 'name': 'Node memory off', 'metric': 'memory', 'operator': '>', 'threshold': 30, 'target_type': 'node',
     'target_id': 'pve1', 'enabled': False, 'severity': 'warning'},
    {'id': 'r4', 'name': 'web01 memory', 'metric': 'memory', 'operator': '>=', 'threshold': 90, 'target_type': 'vm',
     'target_id': '100', 'enabled': True, 'severity': 'warning'},
]


def _nic(name, rx_bytes, rx_packets, rx_errs=0, rx_drop=0, tx_bytes=0, tx_packets=0, tx_errs=0, tx_drop=0):
    row = {'iface': name}
    for k in ('rx_fifo', 'rx_frame', 'rx_compressed', 'rx_multicast', 'tx_fifo', 'tx_colls', 'tx_carrier', 'tx_compressed'):
        row[k] = 0
    row.update(rx_bytes=rx_bytes, rx_packets=rx_packets, rx_errs=rx_errs, rx_drop=rx_drop, tx_bytes=tx_bytes,
               tx_packets=tx_packets, tx_errs=tx_errs, tx_drop=tx_drop)
    return row


NICS = [_nic('lo', 5000, 50, tx_bytes=5000, tx_packets=50), _nic('eno1', 9 * GIB, 7_400_000, 3, 12, 4 * GIB, 3_100_000),
        _nic('vmbr0', 8 * GIB, 7_000_000, 0, 0, 4 * GIB, 3_000_000), _nic('tap100i0', GIB, 900_000, tx_bytes=GIB, tx_packets=800_000),
        _nic('fwbr100i0', GIB, 900_000), _nic('veth101i0', GIB, 10_000)]

RETENTION = 30 * 86400
HOLE = (FIXED - 40 * 60, FIXED - 25 * 60)


def _history(qs, kind, retention=RETENTION):
    """metrics-history: history_range clamps from to the retention and to to now (the frozen clock); 5-minute
    snapshots thinned to 200 rows; none collected in HOLE; the period before reads lower than this one."""
    start, end = float(qs['from'][0]), float(qs['to'][0])
    start, end = max(start, FIXED - retention), min(end, FIXED)
    ts = [x for x in range(int(start // 300 * 300), int(end) + 1, 300) if start <= x < end and not HOLE[0] <= x < HOLE[1]]
    stride = max(1, -(-len(ts) // 200))
    ts = ts[::stride]
    base = 30 if ts and ts[-1] > FIXED - 3600 else 12
    cpu = [round(base + (i % 5), 1) for i in range(len(ts))]
    mem = [round(base + 20 + (i % 3), 1) for i in range(len(ts))]
    out = {'timestamps': ts, 'metrics': {'cpu': cpu, 'memory': mem}, 'source': 'history', 'from': int(start), 'to': int(end)}
    out.update(kind)
    return out


class _PfServer(_ObjServer):
    """The object fake with the reads of the metrics view: the RRD of node and guest by route, the stored
    history by from/to, the interface counters (rising on a second read), the alert rules."""

    def __init__(self, node_rrd=None, guest_rrd=None, rules=(200, {'alerts': RULES}), nics=(200, None), summary=None,
                 live=None, hold_nics=False, retention=RETENTION, **kw):
        extra = {('GET', '/api/clusters/c1/alerts'): rules,
                 ('GET', '/api/clusters/c1/nodes/pve1/summary'): summary or (200, SUMMARY_SWAP)}
        if live is not None:
            extra[('GET', '/api/clusters/c1/metrics')] = (200, live)
        extra.update(kw.pop('extra', {}))
        super().__init__(extra=extra, bundle=BUNDLE, **kw)
        if live is not None:
            self.metrics = dict(live)
        self.node_rrd = NODE_RRD if node_rrd is None else node_rrd
        self.guest_rrd = GUEST_RRD if guest_rrd is None else guest_rrd
        self.nics = nics
        self.nic_reads = 0
        self.hold_nics = hold_nics
        self.held = []
        self.retention = retention

    def handle(self, route):
        req = route.request
        url = req.url
        path = re.sub(r'^https?://[^/]+', '', url).split('?')[0]

        def answer(status, body):
            return route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})
        if not url.startswith(BASE):
            return super().handle(route)
        if path == '/api/clusters/c1/nodes/pve1/rrddata' or re.fullmatch(r'/api/clusters/c1/vms/pve1/qemu/100/rrd/\w+', path):
            self.calls.append((req.method, path))
            self.urls.append(url)
            body = self.node_rrd if 'rrddata' in path else self.guest_rrd
            if isinstance(body, tuple):
                return answer(*body)
            return answer(200, body)
        hist = re.fullmatch(r'/api/clusters/c1/(nodes/pve1|vms/100)/metrics-history', path)
        if hist:
            self.calls.append((req.method, path))
            self.urls.append(url)
            qs = parse_qs(urlparse(url).query)
            kind = {'node': 'pve1'} if hist.group(1).startswith('nodes') else {'vmid': 100}
            return answer(200, _history(qs, kind, self.retention))
        if path == '/api/clusters/c1/nodes/pve1/netstats':
            self.calls.append((req.method, path))
            self.urls.append(url)
            if self.hold_nics:
                self.held.append(route)
                return None
            return self._nics(route)
        return super().handle(route)

    def _nics(self, route):
        self.nic_reads += 1
        status, body = self.nics
        if body is None:
            rows = json.loads(json.dumps(NICS))
            if self.nic_reads > 1:
                rows[1]['rx_packets'] += 500
                rows[1]['rx_drop'] += 2
                rows[1]['rx_bytes'] += 1024 * 1024
            body = {'interfaces': rows, 'count': len(rows)}
        return route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})

    def release(self):
        held, self.held = self.held, []
        for r in held:
            self._nics(r)


def _launch(pw, engine):
    if engine == 'firefox':
        return pw.firefox.launch(headless=True)
    return pw.chromium.launch(headless=True, args=DETERMINISTIC)


@pytest.fixture(scope='module')
def pw():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        p = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield p
    p.stop()


@pytest.fixture(scope='module')
def browsers(pw):
    seen = {}

    def get(engine='chromium'):
        if engine not in seen:
            try:
                seen[engine] = _launch(pw, engine)
            except Exception as e:
                pytest.skip(f'no {engine} for Playwright: {e}')
        return seen[engine]
    yield get
    for b in seen.values():
        b.close()


@pytest.fixture
def open_app(browsers):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), storage=None, **kw):
        app = _GuardApp(browsers(engine), _PfServer(layout=LAYOUT, **kw), storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _node_monitor(app):
    page = app.page
    _open_node(page)
    page.locator('[data-cr-tabs="node"] [data-cr-tab="monitor"]').click()
    try:
        page.locator('[data-cr-pf="node"]').wait_for(timeout=8000)
    except Exception:
        raise AssertionError('the node Monitor is the redesigned metrics view (no [data-cr-pf])') from None


def _guest_monitor(app, name='web01'):
    page = app.page
    _open_guest(page, name)
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="monitor"]').click()
    try:
        page.locator('[data-cr-pf="guest"]').wait_for(timeout=8000)
    except Exception:
        raise AssertionError('the guest Monitor is the redesigned metrics view (no [data-cr-pf])') from None


def _tiles(page):
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-pf-kpi]')).map(x => [x.dataset.crPfKpi, {
        value: x.querySelector('.cr-stat-value').innerText.trim(), sub: (x.querySelector('.cr-stat-sub') || {}).innerText || '',
        basis: (x.querySelector('[data-cr-pf-basis]') || {}).innerText || '', state: x.dataset.crPfState, title: x.title || ''}]))''')


def _clock(page, sec):
    return page.evaluate('''(ms) => new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', hour12: false})
        .format(new Date(ms))''', sec * 1000)


_CHARTS = """() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-chart]')).map(cell => {
    const c = cell.querySelector('canvas');
    const ch = c && window.Chart && window.Chart.getChart(c);
    return [cell.dataset.crChart, ch ? {
        labels: ch.data.datasets.map(d => d.label), hidden: ch.data.datasets.map((d, i) => !ch.isDatasetVisible(i)),
        tension: ch.data.datasets.map(d => d.tension), dash: ch.data.datasets.map(d => d.borderDash || null),
        plugins: (ch.config.plugins || []).map(p => p.id), legend: ch.options.plugins.legend.display,
        data: ch.data.datasets.map(d => d.data), max: ch.options.scales.y.max, width: c.width,
        box: c.parentElement.clientWidth} : {none: cell.innerText}];
}))"""


def _charts(page):
    return page.evaluate(_CHARTS)


def _calls(app, part):
    return [c for c in app.server.calls if part in c[1]]


def _settle_charts(page, n):
    page.wait_for_function('(n) => Array.from(document.querySelectorAll("[data-cr-chart] canvas")).filter(c => window.Chart && window.Chart.getChart(c)).length >= n',
                           arg=n, timeout=8000)


# --- source ------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_classic_charts_keep_their_defaults_and_the_preview_branches_are_gated():
    ui = _read('web', 'src', 'ui.js')
    chart = ui[ui.index('const LineChart = React.memo('):ui.index('function VmMetricsModal(')]
    # every new option falls back to what LineChart drew before
    assert "tension: typeof tension === 'number' ? tension : 0.4," in chart
    assert "display: legend === false ? false : processedDatasets.length > 1," in chart
    assert "plugins: [bandPlugin, ...(lines.length ? [linesPlugin] : []), ...(markGaps ? [gapsPlugin] : [])]," in chart
    assert "...(ds.hidden ? { hidden: true } : {})," in chart and "...(ds.dash ? { borderDash: ds.dash } : {})," in chart
    assert "if (!resize || !box || typeof ResizeObserver === 'undefined') return undefined;" in chart
    nm = _read('web', 'src', 'node_modals.js')
    assert "loaded: isCorpRedesigned ? crPerf : data.performance," in nm
    assert "const crPerfPrep = (d) => (isCorpRedesigned ? crPfPrep(d, crKind) : d);" in nm
    assert "{monitorSubTab === 'performance' && isCorpRedesigned && (" in nm and "<CrNodePerf " in nm
    # classic Corporate keeps its own seven charts with their labels
    assert '<LineChart {...perfZoom.series(\'cpu\')} label="CPU" color="#49afd9" unit="%" yMin={0} yMax={100} />' in nm
    vm = _read('web', 'src', 'vm_modals.js')
    assert "loaded: isCorpRedesigned ? crMetrics : metricsData," in vm
    assert "{isCorpRedesigned && activeDetailTab === 'monitor' && (" in vm and '<CrGuestPerf ' in vm
    dash = _read('web', 'src', 'dashboard.js')
    assert dash.count("crKind={isCorpRedesigned ? (") == 2
    assert dash.count('holds(') == 10
    src = _read('web', 'src', 'cr_perf.js')
    for bad in ('\u2014', '\u2013', 'window.confirm', 'setInterval(() => read', 'localStorage'):
        assert bad not in src, bad
    # one interval only: the 30 s re-draw of the age, it asks nothing
    assert src.count('setInterval(') == 1 and 'setInterval(() => setN(n => n + 1), 30000)' in src


def test_every_key_of_the_view_is_in_english_and_german():
    src = _read('web', 'src', 'cr_perf.js') + _read('web', 'src', 'cr_views.js')
    keys = set(re.findall(r"'(crPf[A-Za-z0-9]+)'", src))
    assert len(keys) > 100, len(keys)
    tr = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', tr, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(tr)]
    blocks = {lang: tr[a:b] for (a, lang), b in zip(starts, ends)}
    for lang in ('en', 'de'):
        block = blocks[lang]
        marker = block.index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in keys:
            m = re.search(rf'^                {k}: (.*),$', block, re.M)
            assert m, (lang, k)
            assert m.start() < marker, (lang, k)
            assert '\u2014' not in m.group(1) and '\u2013' not in m.group(1), (lang, k)
        en = dict(re.findall(r'^                (crPf[A-Za-z0-9]+): (.*),$', blocks['en'], re.M))
        here = dict(re.findall(r'^                (crPf[A-Za-z0-9]+): (.*),$', block, re.M))
        for k in keys:
            assert set(re.findall(r'\{(\w+)\}', en[k])) == set(re.findall(r'\{(\w+)\}', here[k])), (lang, k)


# --- the pure rules, as the bundle under test has them --------------------------------------------

RULES_JS = r'''
const HISTORY_STEP = 300, CR_WARN = 80, CR_CRIT = 90;
const CHART_PRESET_SECONDS = { hour: 3600, day: 86400, week: 604800, month: 2592000, year: 31536000 };
const crFill = (s, vars) => Object.keys(vars).reduce((o, k) => o.split(`{${k}}`).join(vars[k]), s || '');
const crVmWhen = (ms) => String(ms / 1000);
const crVmClock = crVmWhen;
const formatBytes = (n) => `${n}B`;
const useState = () => [0, () => {}], useEffect = () => {}, useRef = () => ({}), useMemo = (f) => f();
const out = {};
// an error answer of the node route (HTTP 200), the XCP-ng wrapper, an unknown shape, nothing
out.err = crPfPrep({ error: 'Failed to get RRD data' });
out.none = [crPfPrep(null), crPfPrep(undefined) === undefined, crPfPrep({ nope: 1 })];
const xcp = crPfPrep({ success: true, data: { timestamps: [60, 120], metrics: { cpu: [1, 2], iowait: [0, 0], swap: [0, 0], rootfs: [0, 0], loadavg: [0, 0], net_in: [0, 0], net_out: [0, 0], memory: [5, 6] } } }, 'xcpng');
out.xcp = [Object.keys(xcp.metrics).sort(), xcp.xcp];
// stored snapshots every 5 min with an hour missing: one empty slot breaks the line there
const hist = { timestamps: [0, 300, 600, 900, 4500, 4800, 5100], metrics: { cpu: [1, 2, 3, 4, 5, 'x', null], memory: [1, 1, 1, 1, 1, 1, 1] }, source: 'history' };
const h = crPfPrep(hist);
out.hist = [h.timestamps, h.metrics.cpu, h.holes, h.step, h.source];
// RRD slots are every slot already: nothing is added
const rrd = { timestamps: [60, 120, 180, 240], metrics: { cpu: [1, null, null, 4] } };
out.rrd = crPfPrep(rrd).timestamps;
out.stats = crPfStats([10, 20, 30, 40], [null, 5, 9, 'y']);
// quality: a gap of two slots, the newest slot empty, the first slot empty
const q = crPfQuality({ timestamps: [0, 60, 120, 180, 240, 300, 360], metrics: { cpu: [null, 1, null, null, 2, 3, null], memory: [null, 1, null, null, 2, 3, null] }, step: 60 }, ['cpu', 'memory'], 600);
out.q = [q.lastAt, q.age, q.stale, q.trailing, q.stretches.map(s => [s.from, s.secs, s.lead]), q.longest && q.longest.secs];
out.fresh = crPfQuality({ timestamps: [0, 60], metrics: { cpu: [1, 2] }, step: 60 }, ['cpu'], 300).stale;
out.runs = crPfRuns([0, 60, 120, 180, 240, 300], [95, 96, null, 97, 50, 99], v => v > 90, 60);
const store = { state: 'ok', rules: [
    { id: 'a', metric: 'cpu', operator: '>', threshold: 85, target_type: 'node', target_id: 'pve1', enabled: true },
    { id: 'b', metric: 'cpu', operator: '>', threshold: 50, target_type: 'cluster', target_id: null, enabled: true },
    { id: 'c', metric: 'cpu', operator: '>', threshold: 70, target_type: 'node', target_id: 'pve1', enabled: false },
    { id: 'd', metric: 'cpu', operator: '!=', threshold: 70, target_type: 'node', target_id: 'pve1' },
    { id: 'e', metric: 'cpu', operator: '<=', threshold: '20', target_type: 'node', target_id: 'pve2' },
    { id: 'f', metric: 'memory', operator: '>=', threshold: 90, target_type: 'vm', target_id: '100' }] };
out.rules = [crPfObjectRules(store, 'node', 'pve1', 'cpu').map(r => r.id), crPfObjectRules(store, 'node', 'pve2', 'cpu').map(r => r.id),
             crPfObjectRules(store, 'vm', 100, 'memory').map(r => r.id), crPfObjectRules({ state: 'error' }, 'node', 'pve1', 'cpu').length];
// the period before laid under this one, a slot without a neighbour within half a step is empty
out.align = crPfAlign({ timestamps: [3600, 3900, 4200, 4500, 4800] }, { timestamps: [0, 300, 900, 1200], metrics: { cpu: [1, 2, 4, 5] } }, 3600, 'cpu');
out.delta = [crPfNicDelta(null, {}), crPfNicDelta({ rx_bytes: 10, rx_packets: 5, rx_errs: 1, rx_drop: 0, tx_bytes: 0, tx_packets: 0, tx_errs: 0, tx_drop: 0 },
                                                  { rx_bytes: 15, rx_packets: 4, rx_errs: 1, rx_drop: 2, tx_bytes: 0, tx_packets: 0, tx_errs: 0, tx_drop: 0 })];
console.log(JSON.stringify(out));
'''


def test_the_rules_of_the_view():
    """The pure functions as the bundle under test has them (compiled, the names are kept)."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('no node here')
    src = BUNDLE or _read('web', 'index.html')
    try:
        start = src.index('const crPfNum')
        code = src[start:src.index('function CrPfTile(', start)]
    except ValueError:
        raise AssertionError('the bundle has no rules of the redesigned performance view') from None
    got = subprocess.run([node, '-e', code + RULES_JS], capture_output=True, text=True, timeout=30)
    assert got.returncode == 0, got.stderr
    out = json.loads(got.stdout)
    assert out['err'] == {'error': 'Failed to get RRD data'}
    assert out['none'] == [None, True, {'error': ''}]
    # the series the XCP-ng adapter fills with zeros are left out, the wrapper is gone
    assert out['xcp'] == [['cpu', 'memory'], True]
    ts, cpu, holes, step, source = out['hist']
    assert ts == [0, 300, 600, 900, 2700, 4500, 4800, 5100] and cpu == [1, 2, 3, 4, None, 5, None, None]
    assert holes == 1 and step == 300 and source == 'history'
    assert out['rrd'] == [60, 120, 180, 240]
    assert out['stats'] == {'n': 2, 'avg': 7, 'max': 9, 'maxAt': 30, 'min': 5, 'last': 9, 'lastAt': 30}
    last, age, stale, trailing, stretches, longest = out['q']
    assert last == 300 and age == 300 and stale is False and trailing == 1
    # before the first sample (lead) and the two empty slots between 60 and 240
    assert stretches == [[0, 60, True], [120, 120, False]] and longest == 120
    assert out['fresh'] is False
    assert out['runs'] == {'n': 4, 'm': 5, 'longest': {'secs': 120, 'from': 0}}
    # a cluster rule watches the average, a switched-off or unknown operator is not a line, another node's is not
    assert out['rules'] == [['a'], ['e'], ['f'], 0]
    assert out['align'] == [1, 2, None, 4, 5]
    assert out['delta'][0] is None
    assert out['delta'][1] == {'rx_bytes': 5, 'rx_packets': 'reset', 'rx_errs': 0, 'rx_drop': 2, 'tx_bytes': 0,
                               'tx_packets': 0, 'tx_errs': 0, 'tx_drop': 0}


# --- the node ----------------------------------------------------------------------------------

def test_runtime_the_node_figures_say_their_source_and_opening_asks_little(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.wait_for_function('() => document.querySelector("[data-cr-pf-rules]") && !/Reading/.test(document.querySelector("[data-cr-pf-rules]").innerText)', timeout=5000)
    tiles = _tiles(page)
    assert list(tiles) == ['cpu', 'load', 'iowait', 'memory', 'swap', 'net_in', 'net_out', 'rootfs'], list(tiles)
    m = NODE_METRICS['pve1']
    # CPU: the live value, the loaded hour under it, the source of each
    assert tiles['cpu']['value'] == '5.0%' and tiles['cpu']['basis'].startswith('Live, received ')
    assert 'range from the Proxmox VE RRD' in tiles['cpu']['basis'] and tiles['cpu']['sub'].startswith('1h: average ')
    assert tiles['cpu']['sub'].endswith('peak 93.5%')
    assert tiles['load']['value'] == '0.10 / 0.20 / 0.30' and tiles['load']['sub'] == '1, 5 and 15 min · 8 CPUs'
    io = [v for v in NODE_RRD['metrics']['iowait'] if v is not None]
    assert tiles['iowait']['value'] == f'{io[-1]:.1f}%'
    assert tiles['iowait']['basis'] == f'Proxmox VE average per 1 min, as of {_clock(page, TS[67])}'
    assert 'no threshold' in tiles['iowait']['title']
    assert tiles['memory']['value'] == f"{m['mem_used'] / m['mem_total'] * 100:.1f}%" and 'free' in tiles['memory']['sub']
    assert "available memory" in tiles['memory']['title'] and 'not read' in tiles['memory']['title']
    assert tiles['swap']['value'] == '12.5%' and tiles['swap']['basis'].startswith('Node summary, read ')
    # the node route sends KB/s: the tile says bytes per second like the guest's
    net_in = [v for v in NODE_RRD['metrics']['net_in'] if v is not None][-1]
    assert tiles['net_in']['value'] == f'{_bytes(net_in * 1024)}/s'
    assert tiles['rootfs']['value'] == '10.0%'
    # the same seven charts in the same order, the groups closed
    charts = _charts(page)
    assert list(charts) == ['cpu', 'memory', 'iowait', 'loadavg', 'net', 'swap', 'rootfs']
    assert page.locator('[data-cr-pf-open]').count() == 0
    # opening: the hour once, the rules of the cluster once; no history, no SSH
    assert _rrd_urls(app, '/nodes/pve1/rrddata') == [f'{BASE}/api/clusters/c1/nodes/pve1/rrddata?timeframe=hour']
    assert len(_calls(app, '/api/clusters/c1/alerts')) == 1
    assert not _calls(app, 'metrics-history') and not _calls(app, 'netstats')
    # the app's own stream token is the only write, and no write of this view
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1] != '/api/sse/token']
    assert 'CPU steal' in page.locator('[data-cr-pf-notcollected]').inner_text()
    _no_errors(app)


@pytest.mark.parametrize('case', ['noswap', 'summary-failed', 'offline', 'no-load'])
def test_runtime_a_missing_figure_is_said_never_a_zero(open_app, case):
    live = json.loads(json.dumps(METRICS))
    kw = {}
    if case == 'noswap':
        kw['summary'] = (200, dict(SUMMARY, swap={'used': 0, 'total': 0}))
    elif case == 'summary-failed':
        kw['summary'] = (500, {'error': 'boom'})
    elif case == 'offline':
        live['pve1'].update(status='offline', cpu_percent=0, mem_used=0, mem_total=1, disk_used=0, disk_total=1, loadavg=[])
        kw['live'] = live
    else:
        live['pve1']['loadavg'] = [0, 0]
        kw['live'] = live
    app = open_app(**kw)
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    tiles = _tiles(page)
    if case == 'noswap':
        assert tiles['swap']['value'] == 'None' and tiles['swap']['sub'] == 'No swap configured on this node'
        assert page.locator('[data-cr-pf-obs="swap"]').inner_text().startswith('No swap configured')
        assert 'No swap configured' in page.locator('[data-cr-chart="swap"]').inner_text()
    elif case == 'summary-failed':
        assert tiles['swap']['value'] == '-' and tiles['swap']['sub'] == 'The node summary could not be read'
        assert page.locator('[data-cr-pf-obs="swap"]').count() == 0
    elif case == 'offline':
        # no live 0 shown: CPU and memory fall back to the newest RRD sample with its time, root FS goes
        cpu = [v for v in NODE_RRD['metrics']['cpu'] if v is not None][-1]
        assert tiles['cpu']['value'] == f'{cpu:.1f}%' and tiles['cpu']['basis'].startswith('Proxmox VE average per 1 min, as of ')
        assert 'rootfs' not in tiles and 'load' not in tiles
    else:
        assert 'load' not in tiles
    for x in tiles.values():
        assert x['value'] not in ('0', '0.0%', '0 B/s'), tiles
    _no_errors(app)


def test_runtime_the_quality_line_names_the_newest_sample_the_step_and_the_gaps(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    box = page.locator('[data-cr-pf-quality]')
    box.wait_for(timeout=8000)
    assert box.get_attribute('data-cr-pf-stale') == '0' and box.get_attribute('data-cr-pf-gaps') == '1'
    # the newest sample is the slot before the two PVE still averages, four minutes before now
    assert page.locator('[data-cr-pf-last]').inner_text() == f'Newest sample {_clock(page, TS[67])} (4 min ago)'
    assert page.locator('[data-cr-pf-step]').inner_text() == 'Proxmox VE RRD, average per 1 min, 70 slots in 1h'
    gaps = page.locator('[data-cr-pf-gaptext]').inner_text()
    assert gaps.startswith(f'1 stretch without a sample (4 min, from {_clock(page, TS[GAP[0]])}).'), gaps
    assert 'The 2 newest slots have no sample yet' in gaps
    # the slots without a sample are shaded in the chart, the lines are straight
    cpu = _charts(page)['cpu']
    assert 'ppGaps' in cpu['plugins'] and cpu['tension'] == [0]
    assert [i for i, v in enumerate(cpu['data'][0]) if v is None] == list(range(*GAP)) + [68, 69]
    _no_errors(app)


def test_runtime_an_old_range_is_not_current_and_refresh_reads_it_once_more(open_app):
    old = json.loads(json.dumps(NODE_RRD))
    old['timestamps'] = [x - 40 * 60 for x in TS]
    app = open_app(node_rrd=old)
    page = app.page
    _node_monitor(app)
    box = page.locator('[data-cr-pf-quality]')
    box.wait_for(timeout=8000)
    assert box.get_attribute('data-cr-pf-stale') == '1'
    assert 'Not current' in box.inner_text()
    assert page.locator('[data-cr-pf-stale-why]').inner_text().startswith('Nothing newer than 44 min ago')
    app.server.node_rrd = NODE_RRD
    page.locator('[data-cr-pf-refresh]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-pf-quality]").dataset.crPfStale === "0"', timeout=5000)
    assert len(_rrd_urls(app, '/nodes/pve1/rrddata')) == 2
    assert _rrd_urls(app, '/nodes/pve1/rrddata')[-1].endswith('timeframe=hour')
    _no_errors(app)


def test_runtime_an_error_the_node_route_answers_with_200_is_an_error(open_app):
    app = open_app(node_rrd={'error': 'Failed to get RRD data'})
    page = app.page
    _node_monitor(app)
    box = page.locator('[data-cr-perf="error"]')
    box.wait_for(timeout=8000)
    assert box.locator('[role="alert"]').inner_text().startswith('The metrics could not be loaded: Failed to get RRD data')
    assert page.locator('[data-cr-perf="empty"]').count() == 0
    tiles = _tiles(page)
    assert tiles['iowait']['value'] == '-' and tiles['iowait']['sub'] == 'The metrics could not be loaded'
    # the live figures stay: they do not come from this read
    assert tiles['cpu']['value'] == '5.0%'
    app.server.node_rrd = NODE_RRD
    box.locator('[data-cr-perf-retry]').click()
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_an_xcpng_pool_draws_what_its_adapter_really_reports(open_app):
    xc = {'success': True, 'data': {'timeframe': 'hour', 'node': 'pve1', 'timestamps': TS, 'metrics': {
        'cpu': _wave(8, 20), 'memory': _wave(40, 6), 'swap': [0] * 70, 'iowait': [0] * 70, 'loadavg': [0] * 70,
        'net_in': [0] * 70, 'net_out': [0] * 70, 'rootfs': [0] * 70}}}
    clusters = [dict(CLUSTERS[0], cluster_type='xcpng')] + CLUSTERS[1:]
    app = open_app(node_rrd=xc, clusters=clusters)
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    charts = _charts(page)
    assert 'labels' in charts['cpu'] and 'labels' in charts['memory']
    for k in ('iowait', 'loadavg', 'net', 'swap', 'rootfs'):
        assert charts[k] == {'none': {'loadavg': 'Load Average (1 min)', 'net': 'Network', 'iowait': 'IO wait', 'swap': 'Swap',
                                      'rootfs': 'Root FS'}[k] + '\nNot reported for XCP-ng pools'}, (k, charts[k])
    assert 'reports a slot without a sample as 0' in page.locator('[data-cr-pf-xcp]').inner_text()
    assert set(_tiles(page)) == {'cpu', 'memory'}
    page.locator('[data-cr-pf-group="nics"]').click()
    assert 'Not available for XCP-ng pools' in page.locator('[data-cr-pf-nics-xcp]').inner_text()
    assert not _calls(app, 'netstats')
    _no_errors(app)


def test_runtime_the_threshold_lines_are_the_rules_of_the_node_or_the_display_scale(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.wait_for_function('() => /Node CPU high/.test((document.querySelector(\'[data-cr-chart="cpu"] [data-cr-chart-caption]\') || {}).innerText || "")',
                           timeout=5000)
    charts = _charts(page)
    # CPU: the rule that watches this node; the cluster rule watches the average and is not drawn here
    assert 'ppThresholds' in charts['cpu']['plugins']
    assert page.locator('[data-cr-chart="cpu"] [data-cr-chart-caption]').inner_text() == 'Dashed: alert rule Node CPU high (> 85%, critical)'
    lines = page.evaluate('''() => { const ch = window.Chart.getChart(document.querySelector('[data-cr-chart="cpu"] canvas'));
        return ch.config.plugins.find(p => p.id === 'ppThresholds') ? true : false; }''')
    assert lines
    # memory: the switched-off rule does not count, the display scale is drawn and named as such
    assert page.locator('[data-cr-chart="memory"] [data-cr-chart-caption]').inner_text() == \
        'Dashed: display scale of this view, 80% and 90% (not an alert rule)'
    # a chart without a threshold has no line and says so
    assert 'ppThresholds' not in charts['iowait']['plugins']
    assert page.locator('[data-cr-chart="iowait"] [data-cr-chart-caption]').inner_text() == 'No threshold set in PegaProx'
    _no_errors(app)


def test_runtime_a_series_switched_off_stays_off_and_the_keys_reach_it(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    net = _charts(page)['net']
    assert net['labels'] == ['Network In', 'Network Out'] and net['legend'] is False and net['hidden'] == [False, False]
    out = page.locator('[data-cr-chart="net"] [data-cr-series="Network Out"]')
    assert out.get_attribute('aria-pressed') == 'true'
    out.focus()
    page.keyboard.press('Space')
    page.wait_for_function('''() => { const ch = window.Chart.getChart(document.querySelector('[data-cr-chart="net"] canvas'));
        return ch && !ch.isDatasetVisible(1) && ch.isDatasetVisible(0); }''', timeout=4000)
    assert out.get_attribute('aria-pressed') == 'false'
    # another range draws the chart again: the series stays off
    page.locator('[data-cr-perf] [data-cr-range="day"]').click()
    assert _wait(page, lambda: len(_rrd_urls(app, '/nodes/pve1/rrddata')) == 2)
    page.locator('[data-cr-perf="ready"] [data-cr-range="day"][aria-pressed="true"]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert _charts(page)['net']['hidden'] == [False, True]
    out.click()
    page.wait_for_function('''() => window.Chart.getChart(document.querySelector('[data-cr-chart="net"] canvas')).isDatasetVisible(1)''', timeout=4000)
    _no_errors(app)


@pytest.mark.parametrize('pve', [9, 8])
def test_runtime_the_pressure_group_opens_on_a_click_and_says_when_pve_has_none(open_app, pve):
    app = open_app(node_rrd=NODE_RRD if pve == 9 else NODE_RRD_PVE8)
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    before = page.evaluate('() => document.querySelectorAll("canvas").length')
    btn = page.locator('[data-cr-pf-group="psi"]')
    assert btn.get_attribute('aria-expanded') == 'false'
    btn.focus()
    page.keyboard.press('Enter')
    page.locator('[data-cr-pf-open="psi"]').wait_for(timeout=4000)
    assert btn.get_attribute('aria-expanded') == 'true' and btn.get_attribute('aria-controls') == 'cr-pf-node-group'
    if pve == 9:
        _settle_charts(page, 10)
        charts = _charts(page)
        assert [k for k in charts if k.startswith('psi-')] == ['psi-cpu', 'psi-memory', 'psi-io']
        assert charts['psi-io']['labels'] == ['Some', 'Full']
        assert page.locator('[data-cr-chart="psi-io"] .cr-chart-title, [data-cr-chart="psi-io"] span.text-sm').first.inner_text() == 'I/O pressure'
    else:
        assert 'Proxmox VE 9 and newer report it' in page.locator('[data-cr-pf-psi-none]').inner_text()
        assert page.evaluate('() => document.querySelectorAll("canvas").length') == before
    # a second click closes it, its charts go
    btn.click()
    page.locator('[data-cr-pf-open]').wait_for(state='detached', timeout=3000)
    assert page.evaluate('() => document.querySelectorAll("canvas").length') == before
    assert not _calls(app, 'metrics-history') and not _calls(app, 'netstats')
    _no_errors(app)


def _history_urls(app, part):
    return [parse_qs(urlparse(u).query) for u in app.server.urls if part in u and 'metrics-history' in u]


def test_runtime_the_period_before_is_read_on_a_click_from_the_stored_snapshots(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.locator('[data-cr-pf-group="compare"]').click()
    grp = page.locator('[data-cr-pf-cmp]')
    grp.wait_for(timeout=4000)
    assert grp.get_attribute('data-cr-pf-cmp') == 'idle' and not _calls(app, 'metrics-history')
    read = page.locator('[data-cr-pf-cmp-read]')
    assert read.inner_text() == 'Read the last 1h and the 1h before'
    read.click()
    page.locator('[data-cr-pf-cmp="ok"]').wait_for(timeout=6000)
    q = _history_urls(app, '/nodes/pve1/')
    assert len(q) == 2
    spans = sorted((int(x['from'][0]), int(x['to'][0])) for x in q)
    assert spans == [(FIXED - 7200, FIXED - 3600), (FIXED - 3600, FIXED)], spans
    _settle_charts(page, 9)
    charts = _charts(page)
    cmp = charts['cmp-cpu']
    assert cmp['labels'] == ['This period', 'The 1h before'] and cmp['dash'] == [None, [4, 3]]
    # the snapshots that were never collected are a gap in this period's line, not a straight line across
    assert None in cmp['data'][0]
    avgs = page.locator('[data-cr-pf-cmp-avg="cpu"]').inner_text()
    assert avgs.startswith('CPU: average ') and 'in the period before' in avgs
    assert 'not from the Proxmox VE RRD above' in page.locator('[data-cr-pf-cmp-basis]').inner_text()
    assert page.locator('[data-cr-pf-cmp-none]').count() == 0
    _no_errors(app)


@pytest.mark.parametrize('rng', ['week', 'month', 'year'])
def test_runtime_the_period_before_says_what_is_not_stored(open_app, rng):
    # week: a server that keeps 10 days has the week before only in part
    app = open_app(retention=10 * 86400 if rng == 'week' else RETENTION)
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.locator(f'[data-cr-perf] [data-cr-range="{rng}"]').click()
    page.locator(f'[data-cr-perf="ready"] [data-cr-range="{rng}"][aria-pressed="true"]').wait_for(timeout=5000)
    page.locator('[data-cr-pf-group="compare"]').click()
    read = page.locator('[data-cr-pf-cmp-read]')
    read.wait_for(timeout=4000)
    if rng == 'year':
        assert read.is_disabled()
        assert '365 days at most' in page.locator('[data-cr-pf-cmp-never]').inner_text()
        page.wait_for_timeout(300)
        assert not _calls(app, 'metrics-history')
    elif rng == 'month':
        assert 'Needs 60 days of stored snapshots' in page.locator('[data-cr-pf-cmp-keep]').inner_text()
        read.click()
        page.locator('[data-cr-pf-cmp="ok"]').wait_for(timeout=6000)
        assert 'Nothing is stored for the period before' in page.locator('[data-cr-pf-cmp-none]').inner_text()
        assert len(_history_urls(app, '/nodes/pve1/')) == 2
        # the chart of this period is drawn, the line of the period before is empty, not 0
        assert all(v is None for v in _charts(page)['cmp-cpu']['data'][1])
    else:
        assert page.locator('[data-cr-pf-cmp-keep]').count() == 0
        read.click()
        page.locator('[data-cr-pf-cmp="ok"]').wait_for(timeout=6000)
        cut = page.locator('[data-cr-pf-cmp-cut]').inner_text()
        assert cut.startswith('The period before is stored from ') and cut.endswith('only (PegaProx keeps its snapshots for a limited time).')
        assert page.locator('[data-cr-pf-cmp-none]').count() == 0
    _no_errors(app)


def test_runtime_the_interface_counters_are_read_on_a_click_and_a_second_read_shows_the_change(open_app):
    app = open_app(hold_nics=True)
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.locator('[data-cr-pf-group="nics"]').click()
    btn = page.locator('[data-cr-pf-nics-read]')
    btn.wait_for(timeout=4000)
    assert not _calls(app, 'netstats')
    btn.click()
    page.locator('[data-cr-pf-nics="loading"]').wait_for(timeout=4000)
    assert btn.is_disabled()
    btn.click(force=True)
    page.wait_for_timeout(300)
    assert len(_calls(app, 'netstats')) == 1
    app.server.release()
    page.locator('[data-cr-pf-nics="ok"]').wait_for(timeout=5000)
    rows = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-pf-nic]")).map(r => r.dataset.crPfNic)')
    # the interfaces of guests and firewall bridges and lo are left out until asked for
    assert rows == ['eno1', 'vmbr0'], rows
    assert page.locator('[data-cr-pf-nics-count]').inner_text() == '6 interfaces, 1 with errors or drops since boot'
    eno = page.locator('[data-cr-pf-nic="eno1"] td')
    assert eno.nth(2).get_attribute('class') == 'cr-strong' and eno.nth(2).inner_text() == '3'
    assert eno.nth(6).get_attribute('class') == '' and eno.nth(6).inner_text() == '0'
    page.locator('[data-cr-pf-nics-all]').check()
    assert page.evaluate('() => document.querySelectorAll("[data-cr-pf-nic]").length') == 6
    app.server.hold_nics = False
    btn.click()
    page.locator('[data-cr-pf-nics-since]').wait_for(timeout=5000)
    assert page.locator('[data-cr-pf-nic="eno1"] td').nth(3).locator('[data-cr-pf-delta]').inner_text() == '+2'
    assert page.locator('[data-cr-pf-nic="vmbr0"] td').nth(3).locator('[data-cr-pf-delta]').inner_text() == '+0'
    assert len(_calls(app, 'netstats')) == 2
    assert 'a 0 is not proof of no errors' in page.locator('[data-cr-pf-nics]').inner_text()
    _no_errors(app)


def test_runtime_interface_counters_that_ssh_cannot_read_say_why(open_app):
    app = open_app(nics=(502, {'error': 'SSH read failed (auth, timeout, or empty)'}))
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.locator('[data-cr-pf-group="nics"]').click()
    page.locator('[data-cr-pf-nics-read]').click()
    err = page.locator('[data-cr-pf-nics-error="502"]')
    err.wait_for(timeout=5000)
    assert err.inner_text() == 'The counters could not be read over SSH: SSH read failed (auth, timeout, or empty)'
    assert page.locator('[data-cr-pf-nics-table]').count() == 0
    _no_errors(app)


def test_runtime_the_observations_hold_a_verdict_only_against_a_threshold_pegaprox_has(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    panel = page.locator('[data-cr-pf-insights]')
    panel.wait_for(timeout=8000)
    page.wait_for_function('() => document.querySelector("[data-cr-pf-obs=\'cpu-rule-r1\']")', timeout=5000)
    obs = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-pf-obs]'))
        .map(o => [o.dataset.crPfObs, [o.dataset.crPfTone, o.innerText]]))''')
    assert list(obs) == ['cpu-rule-r1', 'memory', 'iowait', 'psi-cpu', 'psi-memory', 'psi-io', 'swap'], list(obs)
    tone, text = obs['cpu-rule-r1']
    assert tone == 'error'
    assert text.startswith(f'CPU: alert rule Node CPU high (> 85%) matched in 5 of 64 samples, the longest run 5 min from {_clock(page, TS[HOT[0]])}.')
    assert f'Peak 93.5% at {_clock(page, TS[HOT[0]])}.' in text and 'short peaks can be averaged away' in text
    tone, text = obs['memory']
    assert tone == 'neutral' and text.startswith('Memory (RAM): at or below 80% in all 64 samples.')
    assert 'Display scale of this view (80% and 90%), no alert rule for this object.' in text
    for k in ('iowait', 'psi-cpu', 'psi-io', 'swap'):
        assert obs[k][0] == 'neutral' and 'No threshold set in PegaProx.' in obs[k][1], (k, obs[k])
    assert obs['swap'][1].startswith('Swap in use: 12.5% (')
    assert panel.locator('[data-cr-pf-window]').inner_text() == 'Loaded range 1h: 70 slots, Proxmox VE average per 1 min'
    assert page.locator('[data-cr-pf-rules]').inner_text() == 'Alert rules for CPU or memory that watch this node: 1.'
    _no_errors(app)


@pytest.mark.parametrize('rules', [(403, {'error': 'Permission denied'}), (200, {'alerts': [], 'error': 'Alert operation failed'})])
def test_runtime_rules_that_cannot_be_read_leave_the_display_scale_and_say_so(open_app, rules):
    app = open_app(rules=rules)
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-pf-insights]').wait_for(timeout=8000)
    page.wait_for_function('() => !/Reading/.test(document.querySelector("[data-cr-pf-rules]").innerText)', timeout=5000)
    note = page.locator('[data-cr-pf-rules]').inner_text()
    if rules[0] == 403:
        assert note == 'The alert rules are not readable with your role: the display scale of this view is used.'
    else:
        assert note == 'The alert rules could not be read (Alert operation failed): the display scale of this view is used.'
    tone, text = page.evaluate('''() => { const o = document.querySelector('[data-cr-pf-obs="cpu"]'); return [o.dataset.crPfTone, o.innerText]; }''')
    assert tone == 'error' and text.startswith('CPU: above 90% in 5 of 64 samples')
    assert page.locator('[data-cr-chart="cpu"] [data-cr-chart-caption]').inner_text().startswith('Dashed: display scale')
    _no_errors(app)


def test_runtime_the_charts_follow_the_width_of_their_box(open_app):
    app = open_app()
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    _settle_charts(page, 7)
    wide = _charts(page)['cpu']
    assert abs(wide['width'] - wide['box']) <= 2
    page.set_viewport_size({'width': 1280, 'height': 1000})
    page.wait_for_function('''() => { const c = document.querySelector('[data-cr-chart="cpu"] canvas');
        return c && Math.abs(c.getBoundingClientRect().width - c.parentElement.clientWidth) <= 2; }''', timeout=5000)
    narrow = _charts(page)['cpu']
    assert narrow['box'] < wide['box'] - 100 and abs(narrow['width'] - narrow['box']) <= 2
    assert page.evaluate('() => document.documentElement.scrollWidth <= document.documentElement.clientWidth')
    _no_errors(app)


# --- the guest ----------------------------------------------------------------------------------

def test_runtime_the_guest_figures_charts_and_observations(open_app):
    app = open_app()
    page = app.page
    _guest_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.wait_for_function('() => document.querySelector("[data-cr-pf-obs=\'memory-rule-r4\']")', timeout=5000)
    tiles = _tiles(page)
    assert list(tiles) == ['cpu', 'memory', 'disk_read', 'disk_write', 'net_in', 'net_out']
    mem = [v for v in GUEST_RRD['metrics']['memory'] if v is not None][-1]
    assert tiles['memory']['value'] == f'{mem:.1f}%' and tiles['memory']['sub'].endswith('(its size today)')
    assert tiles['memory']['basis'] == f'Proxmox VE average per 1 min, as of {_clock(page, TS[67])}'
    dr = [v for v in GUEST_RRD['metrics']['disk_read'] if v is not None][-1]
    assert tiles['disk_read']['value'] == f'{_bytes(dr)}/s'
    charts = _charts(page)
    assert list(charts) == ['cpu', 'memory', 'disk', 'net']
    # CPU on 0 to 100 like the node's, memory in GB of today's size with the rule of guest 100 drawn there
    assert charts['cpu']['max'] == 100 and charts['cpu']['tension'] == [0]
    assert charts['memory']['max'] == VM['maxmem'] / GIB
    cap = page.locator('[data-cr-chart="memory"] [data-cr-chart-caption]').inner_text()
    assert cap.startswith('Dashed: alert rule web01 memory (>= 90%, warning)')
    assert charts['disk']['labels'] == ['Read', 'Write'] and charts['disk']['legend'] is False
    tone, text = page.evaluate('''() => { const o = document.querySelector('[data-cr-pf-obs="memory-rule-r4"]'); return [o.dataset.crPfTone, o.innerText]; }''')
    assert tone == 'warning' and 'matched in 5 of 64 samples' in text
    assert page.locator('[data-cr-pf-group="nics"]').count() == 0
    assert 'I/O wait' in page.locator('[data-cr-pf-notcollected]').inner_text()
    # the rules are read when Monitor opens, the guest's own RRD was read when the guest opened
    assert len(_calls(app, '/api/clusters/c1/alerts')) == 1 and len(_rrd_urls(app, '/qemu/100/rrd/')) == 1
    page.locator('[data-cr-pf-group="compare"]').click()
    page.locator('[data-cr-pf-cmp-read]').click()
    page.locator('[data-cr-pf-cmp="ok"]').wait_for(timeout=6000)
    assert len(_history_urls(app, '/vms/100/')) == 2
    _no_errors(app)


def test_runtime_a_stopped_guest_has_no_figures_and_no_groups(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'db01')
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="monitor"]').click()
    box = page.locator('[data-cr-perf="empty"]')
    box.wait_for(timeout=5000)
    assert 'Metrics are shown while the guest is running' in box.inner_text()
    assert page.locator('[data-cr-pf-kpi]').count() == 0 and page.locator('[data-cr-pf-more]').count() == 0
    assert page.locator('[data-cr-pf-insights]').count() == 0
    # nothing to read for it: no RRD, no alert rules
    page.wait_for_timeout(300)
    assert not _rrd_urls(app, '/qemu/102/rrd/') and not _calls(app, '/api/clusters/c1/alerts')
    _no_errors(app)


# --- layout -------------------------------------------------------------------------------------

_LAYOUT = """() => {
    const doc = document.documentElement;
    const out = { sideways: doc.scrollWidth > doc.clientWidth, outside: [], scroll: [] };
    const root = document.querySelector('[data-cr-pf]').getBoundingClientRect();
    document.querySelectorAll('[data-cr-pf-kpi], [data-cr-chart], [data-cr-pf-obs], [data-cr-pf-quality], [data-cr-pf-nics-table]').forEach(el => {
        const r = el.getBoundingClientRect();
        if (r.left < root.left - 1 || r.right > root.right + 1) out.outside.push(el.dataset.crPfKpi || el.dataset.crChart || el.dataset.crPfObs || el.className);
        if (el.scrollWidth > el.clientWidth + 1 && el.dataset.crPfKpi === undefined) out.scroll.push(el.dataset.crChart || el.className);
    });
    document.querySelectorAll('[data-cr-pf-kpi] .cr-stat-value').forEach(v => {
        if (v.scrollWidth > v.clientWidth + 1) out.scroll.push('tile ' + v.parentElement.dataset.crPfKpi);
    });
    return out;
}"""


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('firefox', 1600), ('firefox', 1280)])
def test_runtime_the_view_fits_its_width_in_both_engines(open_app, engine, width):
    app = open_app(engine=engine, viewport=(width, 1000))
    page = app.page
    _node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.locator('[data-cr-pf-group="nics"]').click()
    page.locator('[data-cr-pf-nics-read]').click()
    page.locator('[data-cr-pf-nics="ok"]').wait_for(timeout=5000)
    page.locator('[data-cr-pf-nics-all]').check()
    page.wait_for_timeout(400)
    got = page.evaluate(_LAYOUT)
    assert not got['sideways'] and not got['outside'] and not got['scroll'], got
    # the figures sit in rows of whole tiles, at most two rows at these widths
    rows = page.evaluate('''() => new Set(Array.from(document.querySelectorAll('[data-cr-pf-kpi]')).map(x => Math.round(x.getBoundingClientRect().top))).size''')
    assert rows <= (2 if width == 1600 else 3), rows
    shots = os.environ.get('PEGAPROX_UI_SHOTS')
    if shots:
        os.makedirs(shots, exist_ok=True)
        page.screenshot(path=os.path.join(shots, f'perf-{engine}-{width}.png'), full_page=True)
    assert not [e for e in app.errors if 'Failed to load resource' not in e], app.errors
