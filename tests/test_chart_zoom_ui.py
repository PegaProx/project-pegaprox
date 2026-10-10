"""Picking a time range by dragging on the performance charts, at runtime.

Drives the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py, with the presets and the stored history answered by time. A drag on
one chart zooms every chart of the view; where the loaded preset has only a few points in
the range, the finest preset that still reaches back to it is loaded, and where that is
sparse too, CPU and memory come from PegaProx's own history (test_chart_zoom_history.py).
Escape drops a drag, a click picks nothing, a touch drag picks like a mouse. The charts
are read back from Chart.js itself. Skips where Playwright is not installed. The source
checks up front read web/src and the bundle.
LW Oct 2026
"""
import json
import os
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import BASE, CLUSTER, LANGS, _App, _blocks, _classes, _read, browser  # noqa: F401
from test_lists_ui import GUESTS, _ListServer, _resources, _row

SHOTS = os.environ.get('PP_FEATURE_SHOTS', '')
STEP = {'hour': 60, 'day': 1800, 'week': 10800}
# what each source's CPU reads, so a chart says where its points came from
BASE_CPU = {'hour': 50, 'day': 10, 'week': 20, 'history': 80}
VM_KEYS = ('cpu', 'memory', 'disk_read', 'disk_write', 'net_in', 'net_out')
NODE_KEYS = ('cpu', 'memory', 'swap', 'iowait', 'loadavg', 'net_in', 'net_out', 'rootfs')
NODE = '/api/clusters/c1/nodes/pve1'
ACCENT = {'modern': (0xE5, 0x70, 0x00), 'corporate': (0x49, 0xAF, 0xD9), 'corporate-light': (0x00, 0x72, 0xA3)}
KEYS = ['chartDragToZoom', 'chartLoadingFiner', 'chartZoomFromHistory']
VIEWS = ('ui.js', 'vm_modals.js', 'node_modals.js', 'dashboard.js')


def _zoom_code():
    ui = _read('web', 'src', 'ui.js')
    return ui[ui.index('// LW Oct 2026 - a time range is picked by dragging'):ui.index('function VmMetricsModal(')]


# --- source ------------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_string_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS + ['resetZoom']:
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    for key in KEYS:
        value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
        assert '\u2014' not in value and '\u2013' not in value, (lang, key)


def test_every_new_key_is_used():
    used = set(re.findall(r"t\('(chart[A-Z]\w+)'\)", _zoom_code()))
    assert used == set(KEYS), sorted(used ^ set(KEYS))


def test_the_german_block_keeps_its_flag():
    tr = _read('web', 'src', 'translations.js')
    assert tr.index('            de: {') < tr.index("chartDragToZoom: 'Zum Vergr") < tr.index('            en: {')


def test_one_chart_component_draws_every_chart_and_each_view_shares_a_zoom():
    """Chart.js is created in LineChart only, and every LineChart of a view sits inside the
    zoom of that view: one drag zooms all of them"""
    created = sum(_read('web', 'src', f).count('new window.Chart(') for f in VIEWS + ('cloud.js', 'tables.js'))
    assert created == 1
    for name in VIEWS:
        src = _read('web', 'src', name)
        depth, seen = 0, 0
        for m in re.finditer(r'<ChartZoomContext\.Provider|</ChartZoomContext\.Provider>|<LineChart\b', src):
            tok = m.group(0)
            if tok == '<LineChart':
                seen += 1
                assert depth == 1, (name, src.count('\n', 0, m.start()) + 1)
            else:
                depth += -1 if tok.startswith('</') else 1
        assert depth == 0 and seen, name


def test_no_em_dash_and_no_zoom_library():
    code = _zoom_code()
    assert '\u2014' not in code and '\u2013' not in code
    shell = _read('web', 'index.html.original')
    assert 'chartjs-plugin-zoom' not in shell and 'hammer' not in shell.lower()


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'<Icons\.([A-Za-z]+)', _zoom_code()))
    assert used == {'ZoomIn', 'ZoomOut', 'RotateCw'}, used
    for name in used:
        assert re.search(rf'^\s*{name}: \(', icons, re.M), name


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    code = _zoom_code()
    names = _classes(code)
    # the class strings picked by the layout
    for lit in re.findall(r"'((?:[a-z][a-z0-9:/\-\.\[\]]* ?)+)'", code):
        if re.fullmatch(r'(?:(?:flex|items-|gap-|bg-|text-|p-|px-|py-|rounded|font-|border|hover:)[^ ]* ?)+', lit):
            names.update(lit.split())
    nm = _read('web', 'src', 'node_modals.js')
    for at in re.finditer(r'<ChartZoomBar zoom=\{perfZoom\} />', nm):
        names |= _classes(nm[at.start() - 200:at.start()])
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function useChartZoom(', 'function ChartZoomBar(', 'ppZoomBand', 'data-chart-zoom-reset',
                   'metrics-history?from=', 'chartZoomFromHistory'):
        assert needle in built, needle


def _values(src, keys, n):
    base = BASE_CPU[src]
    out = {}
    for k in keys:
        if k == 'cpu':
            out[k] = [base + i % 3 for i in range(n)]
        elif k == 'memory':
            out[k] = [base + 1 + i % 2 for i in range(n)]
        else:
            out[k] = [(base + i % 3) * 1000 for i in range(n)]
    return out


class _ZoomServer(_ListServer):
    """RRD presets of 70 slots each (PVE's own size), the stored history at 5 minutes"""

    def __init__(self, history_status=200, **kw):
        super().__init__(**kw)
        self.now = int(time.time())
        self.history_status = history_status

    def preset(self, tf, keys):
        ts = [self.now - STEP[tf] * (69 - i) for i in range(70)]
        metrics = _values(tf, keys, 70)
        if tf == 'hour':
            # two slots without a sample, 19 and 18 minutes ago: a gap, also when zoomed
            metrics['cpu'][50] = metrics['cpu'][51] = None
        return {'timeframe': tf, 'timestamps': ts, 'metrics': metrics}

    def history(self, q, keys):
        start, end = float(q['from'][0]), float(q['to'][0])
        ts = list(range(int(self.now - (self.now - start) // 300 * 300), int(end) + 1, 300))
        return {'source': 'history', 'timestamps': ts, 'metrics': _values('history', ('cpu', 'memory'), len(ts))}

    def report(self, q):
        if 'from' in q:
            body = self.history(q, ('cpu', 'memory'))
            period = 'range'
        else:
            period = q.get('period', ['day'])[0]
            body = self.preset(period if period != 'hour' else 'day', ('cpu', 'memory'))
            if period == 'week':
                # what the stored history keeps of a week: every third snapshot, 15 minutes
                n = 7 * 96
                body = {'timestamps': [self.now - 900 * (n - 1 - i) for i in range(n)],
                        'metrics': _values('week', ('cpu', 'memory'), n)}
        iso = [time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(t)) for t in body['timestamps']]
        m = body['metrics']
        return {'period': period, 'cluster_id': 'c1', 'data_points': len(iso), 'timestamps': iso,
                'cpu': {'samples': m['cpu'], 'current': m['cpu'][-1], 'avg': 1, 'min': 1, 'max': 1},
                'memory': {'samples': m['memory'], 'current': m['memory'][-1], 'avg': 1, 'min': 1, 'max': 1},
                'vms_running': {'samples': [], 'current': 2},
                'live': {'cpu_percent': 5, 'mem_percent': 20, 'vms_running': 2, 'cts_running': 0}}

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE) or req.method != 'GET':
            return super().handle(route)
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        q = parse_qs(urlparse(req.url).query)
        body, status = None, 200
        rrd = re.fullmatch(r'/api/clusters/c1/vms/pve1/(?:qemu|lxc)/\d+/rrd/(\w+)', path)
        if rrd:
            body = self.preset(rrd.group(1), VM_KEYS)
        elif path == NODE + '/rrddata':
            body = dict(self.preset(q['timeframe'][0], NODE_KEYS), node='pve1')
        elif path.endswith('/metrics-history'):
            status = self.history_status
            body = self.history(q, ()) if status == 200 else {'error': 'Access denied'}
        elif path == '/api/clusters/c1/reports/summary':
            body = self.report(q)
        elif path == '/api/clusters/c1/reports/top-vms':
            body = []
        if body is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        return route.fulfill(status=status, body=json.dumps(body),
                             headers={'Content-Type': 'application/json'})


class _TouchApp(_App):
    """_App on a touch screen: the same page, in a context that has touch"""

    def __init__(self, browser, server):
        self.server = server
        self.ctx = browser.new_context(viewport={'width': 1600, 'height': 1000}, has_touch=True)
        self.ctx.add_init_script("""try {
            for (const u of ['admin', 'viewer']) localStorage.setItem('pegaprox_sponsor_v2:' + u, String(Date.now() + 1e10));
            localStorage.setItem('pegaprox-shortcuts-hint-shown', '1');
        } catch (e) {}""")
        self.page = self.ctx.new_page()
        self.errors = []
        self.loads = []
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('console', self._console)
        self.page.route('**/*', server.handle)
        self.page.goto(BASE + '/', wait_until='load')
        self.wait_for_app()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(touch=False, **kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('layout', 'modern')
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [dict(g) for g in GUESTS])
        server = _ZoomServer(**kw)
        app = _TouchApp(browser, server) if touch else _App(browser, server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


# --- reading the charts back --------------------------------------------------------------

_CHARTS = """() => [...document.querySelectorAll('canvas')].map(c => window.Chart && window.Chart.getChart(c)).filter(Boolean)
    .map(ch => ({label: ch.data.datasets[0].label, points: ch.data.labels.length,
                 data: ch.data.datasets.map(d => d.data)}))"""

_FIND = """const find = label => [...document.querySelectorAll('canvas')].map(c => window.Chart && window.Chart.getChart(c))
    .find(ch => ch && ch.data.datasets[0].label === label);"""

# viewport pixels of two drawn points (fractional indexes work) of the chart with that label
_GEOM = '([label, a, b]) => {' + _FIND + """
    const ch = find(label);
    ch.canvas.scrollIntoView({block: 'center'});
    const r = ch.canvas.getBoundingClientRect(), sc = ch.scales.x, area = ch.chartArea;
    return {x0: r.left + sc.getPixelForValue(a), x1: r.left + sc.getPixelForValue(b),
            y: r.top + (area.top + area.bottom) / 2, top: r.top + area.top, left: r.left, cy: r.top};
}"""

# the band's pixels: those of a small patch near the top of the plot, in canvas pixels
_PATCH = '([label, x, y]) => {' + _FIND + """
    const ch = find(label), r = ch.canvas.getBoundingClientRect();
    const k = ch.canvas.width / r.width;
    const d = ch.canvas.getContext('2d').getImageData(Math.round((x - r.left) * k) - 3, Math.round((y - r.top) * k), 7, 4).data;
    const px = [];
    for (let i = 0; i < d.length; i += 4) px.push([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    return px;
}"""


def _charts(app, want):
    app.page.wait_for_function(
        f'() => [...document.querySelectorAll("canvas")].filter(c => window.Chart && window.Chart.getChart(c)).length >= {want}',
        timeout=10000)
    app.page.wait_for_timeout(200)
    return {c['label']: c for c in app.page.evaluate(_CHARTS)}


def _chart(app, label):
    return {c['label']: c for c in app.page.evaluate(_CHARTS)}[label]


def _wait_points(app, label, test, timeout=8000):
    """until the chart with that label has a number of points that passes `test` (a JS expression on n)"""
    try:
        app.page.wait_for_function('() => {' + _FIND + f"""
            const ch = find({label!r});
            const n = ch ? ch.data.labels.length : -1;
            return {test};
        }}""", timeout=timeout)
    except Exception:
        got = {c['label']: c['points'] for c in app.page.evaluate(_CHARTS)}
        raise AssertionError(f'{label}: no {test} in {got}, chart reads {_gets(app, CHART_READS)}')
    return _chart(app, label)


def _wait_values(app, label, values, timeout=8000):
    """until the chart with that label draws values of that set only (a preset's own)"""
    app.page.wait_for_function('([want]) => {' + _FIND + f"""
        const ch = find({label!r});
        const got = ch ? ch.data.datasets[0].data.filter(v => v !== null) : [];
        return got.length > 0 && got.every(v => want.includes(v));
    }}""", arg=[sorted(values)], timeout=timeout)
    return _chart(app, label)


# the gaps (skipped points) of a chart's first series, its spanGaps, and what the tooltip
# shows over drawn point i
_GAPS = '([label]) => {' + _FIND + """
    const ch = find(label);
    return {skip: ch.getDatasetMeta(0).data.map(p => !!p.skip), span: ch.data.datasets[0].spanGaps,
            legend: ch.legend && ch.options.plugins.legend.display ? ch.legend.legendItems.map(l => l.text) : []};
}"""
_TIP = '([label, i]) => {' + _FIND + """
    const ch = find(label);
    return {active: ch.tooltip.getActiveElements().map(a => a.index), title: (ch.tooltip.title || []).join(''),
            label: ch.data.labels[i]};
}"""


def _hover(app, label, i):
    g = app.page.evaluate(_GEOM, [label, i, i])
    app.page.mouse.move(g['x0'], g['y'])
    app.page.wait_for_timeout(200)
    return app.page.evaluate(_TIP, [label, i])


def _drag(app, label, a, b, steps=8):
    page = app.page
    g = page.evaluate(_GEOM, [label, a, b])
    page.mouse.move(g['x0'], g['y'])
    page.mouse.down()
    page.mouse.move(g['x1'], g['y'], steps=steps)
    page.mouse.up()
    return g


def _vals(chart):
    return {v for v in chart['data'][0] if v is not None}


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.wait_for_timeout(200)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _gets(app, pattern):
    return [u for u in app.server.urls if re.search(pattern, u)]


CHART_READS = r'/rrd/|/rrddata|metrics-history|reports/summary'


def _zoomed(app):
    return app.page.locator('[data-chart-zoom-range]').count() > 0


def _open_vm_metrics(app):
    _resources(app)
    _row(app, 'web01').locator('button[title="Metrics"]').click()
    return _charts(app, 6)


# --- the guest --------------------------------------------------------------------------

def test_runtime_a_drag_zooms_every_chart_of_the_guest_and_loads_the_hour(open_app):
    app = open_app()
    charts = _open_vm_metrics(app)
    assert charts['CPU']['points'] == 70 and _vals(charts['CPU']) <= {10, 11, 12}
    assert app.page.get_by_text('Drag across a chart to zoom in').first.is_visible()

    # the last 45 minutes of the day: two of its half-hour points, so the hour is loaded
    _drag(app, 'CPU', 67.5, 69)
    cpu = _wait_points(app, 'CPU', 'n >= 40 && n <= 50')
    assert _vals(cpu) <= {50, 51, 52}, cpu
    assert _gets(app, r'/rrd/hour$')
    # the other charts follow, from the same finer data
    mem = _chart(app, 'Memory')
    assert mem['points'] == cpu['points']
    assert {round(v, 2) for v in mem['data'][0] if v is not None} <= {round(51 / 100 * 4, 2), round(52 / 100 * 4, 2)}
    disk = _chart(app, 'Disk Read')
    assert disk['points'] == cpu['points'] and _vals(disk) <= {50000, 51000, 52000}
    assert not _gets(app, 'metrics-history')
    bar = app.page.locator('[data-chart-zoom-range]').inner_text()
    assert ' - ' in bar, bar
    # the hour's two slots without a sample stay a gap in the zoom, and the tooltip works
    gaps = app.page.evaluate(_GAPS, ['CPU'])
    holes = [i for i, s in enumerate(gaps['skip']) if s]
    assert gaps['span'] is False and len(holes) == 2 and holes[1] == holes[0] + 1, gaps
    assert [i for i, v in enumerate(cpu['data'][0]) if v is None] == holes
    tip = _hover(app, 'CPU', 5)
    assert tip['active'] == [5] and tip['title'] == tip['label'], tip
    _shot(app, 'chart_zoom_guest_modern')

    # Reset zoom: the day as it was loaded, nothing fetched for it
    before = len(_gets(app, CHART_READS))
    app.page.locator('[data-chart-zoom-reset]').first.click()
    cpu = _wait_points(app, 'CPU', 'n === 70')
    assert _vals(cpu) <= {10, 11, 12} and _chart(app, 'Memory')['points'] == 70
    assert not _zoomed(app) and len(_gets(app, CHART_READS)) == before
    assert not app.errors, app.errors


def test_runtime_a_range_the_presets_cannot_resolve_takes_cpu_and_memory_from_the_history(open_app):
    app = open_app()
    _open_vm_metrics(app)
    # 20 half-hour points from 19.5 to 9.5 hours back: no finer preset reaches there
    g = _drag(app, 'CPU', 30, 50)
    cpu = _wait_points(app, 'CPU', 'n > 100')
    assert _vals(cpu) <= {80, 81, 82}
    url, = _gets(app, 'metrics-history')
    q = parse_qs(urlparse(url).query)
    assert urlparse(url).path == '/api/clusters/c1/vms/100/metrics-history'
    now = app.server.now
    assert abs(int(q['from'][0]) - (now - 39 * 1800)) <= 60 and abs(int(q['to'][0]) - (now - 19 * 1800)) <= 60
    assert not _gets(app, r'/rrd/(hour|week)$')
    # memory from the history too; the disk keeps the day's points in the range
    assert _chart(app, 'Memory')['points'] == cpu['points']
    disk = _chart(app, 'Disk Read')
    assert 19 <= disk['points'] <= 22 and _vals(disk) <= {10000, 11000, 12000}
    assert app.page.locator('[data-chart-zoom-history]').count() == 1
    _shot(app, 'chart_zoom_history_modern')
    assert g['x1'] > g['x0']
    assert not app.errors, app.errors


def test_runtime_without_the_history_the_zoom_spreads_the_loaded_points(open_app):
    app = open_app(history_status=403)
    _open_vm_metrics(app)
    _drag(app, 'CPU', 30, 50)
    cpu = _wait_points(app, 'CPU', 'n < 70')
    assert 19 <= cpu['points'] <= 22 and _vals(cpu) <= {10, 11, 12}
    app.page.wait_for_function('() => !document.querySelector("[data-chart-zoom] .animate-spin")', timeout=5000)
    assert _gets(app, 'metrics-history')
    assert _chart(app, 'Network Out')['points'] == cpu['points']
    assert app.page.locator('[data-chart-zoom-history]').count() == 0
    assert not [e for e in app.errors if '403' not in e], app.errors


def _band(app, label, accent, spot):
    """True when the patch at the top of the drag shows the band in that accent: on an empty
    canvas a fill of 18% comes back as the accent at that alpha"""
    px = app.page.evaluate(_PATCH, [label, spot['x'], spot['y']])
    return any(25 <= a <= 70 and all(abs(c - want) <= 30 for c, want in zip((r, g, b), accent))
               for r, g, b, a in px)


def test_runtime_escape_drops_a_drag_and_a_click_picks_nothing(open_app):
    app = open_app()
    page = app.page
    _open_vm_metrics(app)
    before = len(_gets(app, CHART_READS))
    # on the memory chart: its line runs in the middle, the top of the plot is empty
    g = page.evaluate(_GEOM, ['Memory', 20, 40])
    spot = {'x': (g['x0'] + g['x1']) / 2, 'y': g['top'] + 6}
    assert not _band(app, 'Memory', ACCENT['modern'], spot)
    page.mouse.move(g['x0'], g['y'])
    page.mouse.down()
    page.mouse.move(g['x1'], g['y'], steps=6)
    assert _band(app, 'Memory', ACCENT['modern'], spot)
    _shot(app, 'chart_zoom_band_modern')
    page.keyboard.press('Escape')
    page.wait_for_timeout(100)
    assert not _band(app, 'Memory', ACCENT['modern'], spot)
    page.mouse.up()
    page.wait_for_timeout(300)
    # nothing picked, and the dialog around stays open
    assert not _zoomed(app) and _chart(app, 'CPU')['points'] == 70
    assert page.locator('canvas').count() >= 6

    # a click, and a hand that twitched
    page.mouse.click(g['x1'], g['y'])
    page.mouse.move(g['x0'], g['y'])
    page.mouse.down()
    page.mouse.move(g['x0'] + 3, g['y'])
    page.mouse.up()
    page.wait_for_timeout(300)
    assert not _zoomed(app) and _chart(app, 'CPU')['points'] == 70
    assert len(_gets(app, CHART_READS)) == before
    assert not app.errors, app.errors


def test_runtime_a_touch_drag_picks_a_range(open_app):
    app = open_app(touch=True)
    page = app.page
    _open_vm_metrics(app)
    g = page.evaluate(_GEOM, ['CPU', 30, 50])
    cdp = app.ctx.new_cdp_session(page)
    cdp.send('Input.dispatchTouchEvent', {'type': 'touchStart', 'touchPoints': [{'x': g['x0'], 'y': g['y']}]})
    for i in range(1, 9):
        x = g['x0'] + (g['x1'] - g['x0']) * i / 8
        cdp.send('Input.dispatchTouchEvent', {'type': 'touchMove', 'touchPoints': [{'x': x, 'y': g['y']}]})
    cdp.send('Input.dispatchTouchEvent', {'type': 'touchEnd', 'touchPoints': []})
    _wait_points(app, 'CPU', 'n > 100')
    assert _zoomed(app)
    assert page.evaluate("() => document.querySelector('canvas').style.touchAction") == 'pan-y pinch-zoom'
    assert not app.errors, app.errors


def test_runtime_the_corporate_guest_view_zooms_its_six_charts(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    charts = _charts(app, 6)
    assert charts['CPU']['points'] == 70 and _vals(charts['CPU']) <= {50, 51, 52}

    # the band in Corporate's accent, dark and light
    for theme in ('corporate', 'corporate-light'):
        if theme == 'corporate-light':
            page.evaluate("() => { document.body.dataset.corpTheme = 'light'; applyTheme('corporateLight'); }")
            page.wait_for_timeout(200)
        g = page.evaluate(_GEOM, ['Memory', 20, 40])
        page.mouse.move(g['x0'], g['y'])
        page.mouse.down()
        page.mouse.move(g['x1'], g['y'], steps=6)
        assert _band(app, 'Memory', ACCENT[theme], {'x': (g['x0'] + g['x1']) / 2, 'y': g['top'] + 6}), theme
        _shot(app, f'chart_zoom_band_{theme}')
        page.keyboard.press('Escape')
        page.mouse.up()

    # twenty minutes of the hour: nothing finer to have, the hour's own points spread out
    _drag(app, 'CPU', 20, 40)
    cpu = _wait_points(app, 'CPU', 'n >= 19 && n <= 21')
    assert _vals(cpu) <= {50, 51, 52}
    for label in ('Memory', 'Disk Read', 'Disk Write', 'Network In', 'Network Out'):
        assert _chart(app, label)['points'] == cpu['points'], label
    assert not _gets(app, 'metrics-history') and not _gets(app, r'/rrd/day$')
    _shot(app, 'chart_zoom_guest_corporate_light')
    page.locator('[data-chart-zoom-reset]').first.click()
    _wait_points(app, 'Memory', 'n === 70')
    assert page.get_by_text('Drag across a chart to zoom in').first.is_visible()
    assert not app.errors, app.errors


# --- the node ------------------------------------------------------------------------------

def _open_node_performance(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('.corp-tree-child', has_text='pve1').first.click()
        page.locator('.corp-tab-strip').last.get_by_text('Monitor').click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
        page.locator('button[title="Node Configuration"]').first.click()
        page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
        page.locator('button', has_text='Performance').last.click()
    return _charts(app, 7)


def test_runtime_the_node_week_loads_the_day_and_the_history_for_a_range(open_app):
    app = open_app()
    page = app.page
    _open_node_performance(app, 'modern')
    page.locator('button', has_text=re.compile(r'^\s*Week\s*$')).first.click()
    cpu = _wait_values(app, 'CPU Usage', {20, 21, 22})
    assert cpu['points'] == 70

    # 18 hours of the last day: six of the week's points, the day has 37, the history more
    _drag(app, 'CPU Usage', 62, 68)
    cpu = _wait_points(app, 'CPU Usage', 'n > 100')
    assert _vals(cpu) <= {80, 81, 82}
    assert _gets(app, r'/rrddata\?timeframe=day$') and _gets(app, r'/nodes/pve1/metrics-history\?from=\d+&to=\d+$')
    assert _chart(app, 'Memory Usage')['points'] == cpu['points']
    # what the history has not: from the day, in the range
    net = _chart(app, 'Net In')
    assert 34 <= net['points'] <= 38 and _vals(net) <= {10000, 11000, 12000}
    assert _vals(_chart(app, 'IO Wait')) <= {10000, 11000, 12000}
    # the two series of the network chart keep their legend
    assert app.page.evaluate(_GAPS, ['Net In'])['legend'] == ['Net In', 'Net Out']
    _shot(app, 'chart_zoom_node_modern')

    # another preset starts from the whole of it
    page.locator('button', has_text=re.compile(r'^\s*Day\s*$')).first.click()
    cpu = _wait_values(app, 'CPU Usage', {10, 11, 12})
    assert cpu['points'] == 70 and not _zoomed(app)
    assert not app.errors, app.errors


def test_runtime_the_corporate_node_view_zooms_its_charts_together(open_app):
    app = open_app(layout='corporate')
    page = app.page
    charts = _open_node_performance(app, 'corporate')
    assert charts['CPU']['points'] == 70
    _drag(app, 'Memory', 10, 30)
    cpu = _wait_points(app, 'CPU', 'n >= 19 && n <= 21')
    for label in ('Memory', 'IO Wait', 'Load Average', 'Net In', 'Swap', 'Root FS'):
        assert _chart(app, label)['points'] == cpu['points'], label
    _shot(app, 'chart_zoom_node_corporate')
    page.locator('[data-chart-zoom-reset]').first.click()
    _wait_points(app, 'Net In', 'n === 70')
    assert not app.errors, app.errors


# --- the dashboard -------------------------------------------------------------------------

def _open_reports(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press('p')
    return _charts(app, 2)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_report_charts_read_a_week_range_again_at_full_resolution(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _open_reports(app)
    page.locator('button', has_text='Last Week').first.click()
    cpu = _wait_values(app, 'CPU', {20, 21, 22})
    assert cpu['points'] == 168    # 672 snapshots, every 4th drawn

    # six hours three days back: the week has 25 snapshots there, the history 73. The chart
    # draws every 4th of the 672, so a drawn point i is snapshot 4 * i
    n = 7 * 96
    first = n - 1 - 3 * 96
    _drag(app, 'CPU', first / 4, (first + 24) / 4)
    cpu = _wait_points(app, 'CPU', 'n > 60')
    assert _vals(cpu) <= {80, 81, 82}
    url, = _gets(app, r'/reports/summary\?from=')
    assert 'period' not in url
    assert _chart(app, 'Memory')['points'] == cpu['points']
    _shot(app, f'chart_zoom_report_{layout}')
    page.locator('[data-chart-zoom-reset]').first.click()
    _wait_points(app, 'Memory', 'n > 150')
    assert not app.errors, app.errors
