"""Report times in browser time, on the user's 12h/24h setting.

The server sent naive server-local ISO strings and a browser in another zone read
them as its own time, so the report charts, the CVE scan times and the syslog list
were off by the difference between the zones. The server now sends the offset
(test_report_times_carry_their_offset.py) and the page renders the instant through
the shared formatters of constants.js, which also keep the 12h/24h setting the chart
axes ignored. Also here: the drift scan says which kinds it could not read
(test_drift_failed_reads.py).

The runtime tests drive the built bundle in headless Chromium against the fake server
of tests/test_ha_ui.py, with every payload taken from the real route in process: the
server in Asia/Kolkata, the browser in America/New_York. They skip where Playwright is
not installed.
LW Oct 2026
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

import metrics_history_fixture as mhf

from test_ha_ui import CLUSTER, LANGS, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401
from test_report_times_carry_their_offset import OFFSET, SERVER_TZ, server_tz, syslog_db  # noqa: F401
from test_drift_failed_reads import CL as DRIFT_CL, pve  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROWSER_TZ = 'America/New_York'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def _line_chart():
    return _between(_read('web', 'src', 'ui.js'), 'const LineChart = React.memo', '// Decimation factor')


def _fmt_clock():
    return _between(_read('web', 'src', 'constants.js'), '// LW Oct 2026 - hour and minute', '// NS: timezone list')


def _drift_scan():
    src = _read('web', 'src', 'dashboard.js')
    return _between(src[src.index('function DriftTab('):], 'const scan = async', 'const setBaseline')


# --- source ---------------------------------------------------------------------------------

def test_the_chart_axis_goes_through_the_shared_formatter():
    chart = _line_chart()
    assert 'toLocaleTimeString' not in chart
    assert chart.count('fmtClock(d)') == 2


def test_the_formatter_keeps_the_time_setting_and_the_cache():
    body = _fmt_clock()
    assert "localStorage.getItem('pegaprox-time-format') === '12h'" in body
    assert "_dtf('M', h12, opts || null)" in body
    consts = _read('web', 'src', 'constants.js')
    assert "kind === 'M'" in consts and "{ hour: '2-digit', minute: '2-digit', hour12: h12 }" in consts


def test_the_cve_and_syslog_times_use_it_too():
    dash = _read('web', 'src', 'dashboard.js')
    assert "{t('scannedAt') || 'Scanned at'}: {fmtTime(node.timestamp)}" in dash
    assert "fmtClock(event.timestamp, { month: 'short', day: '2-digit', second: '2-digit' })" in dash
    assert 'new Date(event.timestamp).toLocaleString' not in dash
    assert 'new Date(node.timestamp).toLocaleTimeString' not in dash


def _lang_blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{', src, re.M)]
    return {lang: src[a:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (a, lang) in enumerate(starts)}


def test_the_drift_word_is_in_every_language_once():
    blocks = _lang_blocks()
    assert set(LANGS) <= set(blocks)
    for lang in LANGS:
        found = re.findall(r"^\s*driftNotRead: '((?:[^'\\]|\\.)+)',$", blocks[lang], re.M)
        assert len(found) == 1, (lang, found)
    assert "t('driftNotRead')" in _drift_scan()


def test_no_em_dash_in_what_this_change_added():
    toast = _drift_scan()
    toast = toast[toast.index('// LW Oct 2026'):]
    words = [line for line in _read('web', 'src', 'translations.js').split('\n') if 'driftNotRead:' in line]
    for block in [_fmt_clock(), _line_chart(), toast] + words:
        assert '\u2014' not in block and '\u2013' not in block, block[:200]


def test_the_bundle_was_rebuilt():
    html = _read('web', 'index.html')
    for compiled in ('function fmtClock(d,opts)', 'rawLabels.push(fmtClock(d))', 'fmtTime(node.timestamp)',
                     "fmtClock(event.timestamp,{month:'short',day:'2-digit',second:'2-digit'})",
                     "t('driftNotRead')||'Not read this time, baselines kept'"):
        assert compiled in html, compiled


# --- runtime --------------------------------------------------------------------------------

def _in_browser_tz(stored):
    """Where a stored server-local string lands for someone in New York."""
    return datetime.fromisoformat(stored).replace(tzinfo=ZoneInfo(SERVER_TZ)).astimezone(ZoneInfo(BROWSER_TZ))


def _epoch_ms(stored):
    return int(datetime.fromisoformat(stored).replace(tzinfo=timezone(OFFSET)).timestamp() * 1000)


class _Zoned:
    """The browser, with every context in New York, in English, and the 12h setting on
    when asked."""

    def __init__(self, browser, twelve):  # noqa: F811
        self._browser, self._twelve = browser, twelve

    def new_context(self, **kw):
        ctx = self._browser.new_context(timezone_id=BROWSER_TZ, locale='en-US', **kw)
        if self._twelve:
            ctx.add_init_script("try { localStorage.setItem('pegaprox-time-format', '12h'); } catch (e) {}")
        return ctx


@pytest.fixture
def open_app(browser):  # noqa: F811
    apps = []

    def _open(layout, extra, twelve=False, **kw):
        routes = dict(SSE_TOKEN)
        routes.update(extra)
        kw.setdefault('role', 'standalone')
        app = _App(_Zoned(browser, twelve), _FakeServer(layout=layout, clusters=[CLUSTER], resources=[VM],
                                                         extra=routes, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _admin(api, seed):
    m = api.make_fake_manager(cluster_id='c1')
    m.is_connected = False
    m.config.name = 'Testi'
    api.set_manager('c1', m)
    return api.as_user(seed.user('root', role='admin')), m


@pytest.fixture
def report(server_tz, api, seed, monkeypatch):  # noqa: F811
    """Four snapshots in the server's zone and what the real summary route answers for
    them. Kept off the New York midnight hour, which some ICU builds print as 24."""
    now = datetime.now()
    back = 5
    while True:
        stamps = [(now - timedelta(minutes=back + m)).isoformat() for m in (30, 20, 10, 0)]
        if all(_in_browser_tz(s).hour != 0 for s in stamps):
            break
        back += 60
    # written as PegaProx writes them, into the test's own database (api brings the db fixture)
    mhf.recorded(monkeypatch).write([(ts, {'clusters': {'c1': {'name': 'Testi', 'totals': {
        'cpu_total': 100, 'cpu_used': 20 + i, 'mem_total': 1000, 'mem_used': 400 + i,
        'vms_running': 1, 'cts_running': 0}}}}) for i, ts in enumerate(stamps)])
    admin, _ = _admin(api, seed)
    body = admin.get('/api/clusters/c1/reports/summary?period=day').get_json()
    assert body['data_points'] == 4, body
    yield stamps, body


CHARTS_JS = '''() => Array.from(document.querySelectorAll('canvas'))
    .map(c => window.Chart && window.Chart.getChart(c)).filter(Boolean)
    .map(ch => ch.data.labels.map(l => String(l).replace(/[\\u202f\\u00a0]/g, ' ')))'''


def _open_reports(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press('p')
    page.wait_for_function('''() => Array.from(document.querySelectorAll('canvas'))
        .some(c => window.Chart && window.Chart.getChart(c))''', timeout=10000)
    page.wait_for_timeout(300)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('twelve', [False, True])
def test_runtime_the_report_charts_read_in_browser_time(open_app, report, layout, twelve):
    stamps, body = report
    extra = {('GET', '/api/clusters/c1/reports/summary'): (200, body),
             ('GET', '/api/clusters/c1/reports/top-vms'): (200, [])}
    app = open_app(layout, extra, twelve=twelve)
    page = _open_reports(app)
    want = [_in_browser_tz(s).strftime('%I:%M %p' if twelve else '%H:%M') for s in stamps]
    charts = page.evaluate(CHARTS_JS)
    # CPU and memory over time, both on the New York clock
    assert charts == [want, want], (charts, want, body['timestamps'])
    assert not app.errors, app.errors


ORACLE_JS = '''([ms, opts]) => new Intl.DateTimeFormat('en-US', Object.assign({timeZone: 'America/New_York'}, opts))
    .format(new Date(ms)).replace(/[\\u202f\\u00a0]/g, ' ')'''
TIME = {'hour': '2-digit', 'minute': '2-digit', 'second': '2-digit', 'hour12': False}
DATE_TIME = dict(TIME, year='numeric', month='2-digit', day='2-digit')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_cve_scan_says_its_time_in_browser_time(open_app, server_tz, api, seed, layout):  # noqa: F811
    admin, m = _admin(api, seed)
    m.is_connected = True
    stored = (datetime.now() - timedelta(minutes=3)).replace(microsecond=0).isoformat()
    m.get_node_status.return_value = {'pve1': {'status': 'online'}}
    m.scan_node_packages.side_effect = lambda node: {
        'node': node, 'timestamp': stored, 'os': 'Debian GNU/Linux 13', 'kernel': '6.14.8-2-pve',
        'cves': [], 'packages': [], 'cve_count': 0, 'security_count': 0, 'total_count': 0}
    body = admin.post('/api/clusters/c1/reports/cve-scan').get_json()

    extra = {('GET', '/api/clusters/c1/reports/summary'): (200, {'period': 'day', 'timestamps': []}),
             ('GET', '/api/clusters/c1/reports/top-vms'): (200, []),
             ('POST', '/api/clusters/c1/reports/cve-scan'): (200, body)}
    app = open_app(layout, extra)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press('p')
    page.locator('button', has_text=re.compile(r'^\s*CVE Scanner\s*$')).first.click()
    page.locator('button', has_text='Scan All Nodes').first.click()
    page.locator('button', has_text=re.compile(r'pve1[\s\S]*Up to date')).first.click()
    page.get_by_text('Kernel: 6.14.8-2-pve').first.wait_for(timeout=8000)

    node_time = page.evaluate(ORACLE_JS, [_epoch_ms(stored), TIME])
    # the minutes alone tell New York (UTC-4/-5) from Kolkata (UTC+5:30)
    assert node_time.endswith(_in_browser_tz(stored).strftime(':%M:%S')), node_time
    page.get_by_text(f'Scanned at: {node_time}').first.wait_for(timeout=3000)
    scanned = datetime.fromisoformat(body['scanned_at'])
    footer = page.evaluate(ORACLE_JS, [int(scanned.timestamp() * 1000), DATE_TIME])
    page.get_by_text(f'Scanned at {footer}').first.wait_for(timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_syslog_row_reads_in_browser_time(open_app, api, seed, syslog_db, layout):  # noqa: F811
    admin, _ = _admin(api, seed)
    body = admin.get('/api/syslog/events').get_json()
    assert len(body['items']) == 1, body
    app = open_app(layout, {('GET', '/api/syslog/events'): (200, body)})
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Syslog\s*$')).first.click()
    page.get_by_text('hello').first.wait_for(timeout=8000)

    want = page.evaluate(ORACLE_JS, [_epoch_ms(syslog_db), {'month': 'short', 'day': '2-digit', 'hour': '2-digit',
                                                            'minute': '2-digit', 'second': '2-digit', 'hour12': False}])
    assert want.endswith(_in_browser_tz(syslog_db).strftime(':%M:%S')), want
    cell = page.locator('tr', has_text='hello').first.locator('td').first.inner_text()
    assert cell.replace('\u202f', ' ').replace('\xa0', ' ').strip() == want
    assert not app.errors, app.errors


# --- the drift scan's word on what it could not read ----------------------------------------

DRIFT_READS = {
    ('GET', '/api/clusters/c1/drift/status'): (200, {
        'cluster_id': 'c1', 'open_total': 0, 'baselines': 9, 'last_event_at': None,
        'by_kind': {}, 'by_severity': {'critical': 0, 'warning': 0, 'info': 0}}),
    ('GET', '/api/clusters/c1/drift/events'): (200, {'events': []}),
}


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_scan_that_could_not_read_the_guests_says_so(open_app, pve, layout):  # noqa: F811
    from pegaprox.api import drift
    pve.fail['guests'] = 'timeout'
    result = json.loads(json.dumps(drift._scan_cluster(DRIFT_CL)))
    extra = dict(DRIFT_READS)
    extra[('POST', '/api/clusters/c1/drift/scan')] = (200, result)
    app = open_app(layout, extra)
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text='Config Drift').first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
        page.locator('button', has_text=re.compile(r'^\s*Config Drift Detection\s*$')).first.click()
    page.locator('button', has_text='Scan now').first.click()
    page.get_by_text('Not read this time, baselines kept: VM Config').first.wait_for(timeout=5000)
    # and the scan itself still reports as done
    page.get_by_text(re.compile(r'Scan complete')).first.wait_for(timeout=3000)
    assert not app.errors, app.errors
