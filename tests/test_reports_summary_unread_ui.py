"""Reports > Summary: its own memory ranking, and what it could not read (web/src/dashboard.js).

"Highest Memory Usage" was the ten guests busiest on CPU sorted by memory, so a guest with
the most memory in use and little CPU never showed; the page asks the server for the memory
ranking now (reports/top-vms?metric=memory). And a summary or a list that could not be read
drew "0.0%", "0" and "No running VMs": a failed read says so now, and so does a figure the
server says it could not read (live.unread, tests/test_report_summary_says_what_it_did_not_read.py).

The bundle runs in headless Chromium (Firefox too where Playwright has it) against the fake
server of tests/test_ha_ui.py, in Modern and Corporate (Cloud has no Summary); skipped where
Playwright is not installed.
NS Nov 2026
"""
import json
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import BASE, CLUSTER, SSE_TOKEN, _App, _FakeServer

LIVE = {'cpu_percent': 40.0, 'mem_percent': 55.0, 'vms_running': 2, 'cts_running': 1}
SUMMARY = {'period': 'day', 'cluster_id': 'c1', 'cluster_name': 'Testi', 'data_points': 0,
           'cpu': {'avg': 40.0, 'min': 40.0, 'max': 40.0, 'current': 40.0, 'samples': []},
           'memory': {'avg': 55.0, 'min': 55.0, 'max': 55.0, 'current': 55.0, 'samples': []},
           'vms_running': {'avg': 3, 'min': 3, 'max': 3, 'current': 3, 'samples': []},
           'timestamps': [], 'live': LIVE}
# what the server ranks: busy01 tops the CPU list, bigmem01 the memory list with little CPU
TOP_CPU = [{'vmid': 100 + i, 'name': f'busy{i:02d}', 'node': 'pve1', 'type': 'qemu', 'cpu': 0.9 - i * 0.05,
            'mem': 1, 'maxmem': 10, 'mem_percent': 10.0 + i} for i in range(10)]
TOP_MEM = [{'vmid': 200 + i, 'name': f'bigmem{i:02d}', 'node': 'pve1', 'type': 'qemu', 'cpu': 0.01,
            'mem': 9, 'maxmem': 10, 'mem_percent': 95.0 - i} for i in range(10)]


class _ReportServer(_FakeServer):
    def __init__(self, summary=(200, SUMMARY), top=None, **kw):
        super().__init__(**kw)
        self.summary = summary
        self.top = top or {'cpu': (200, TOP_CPU), 'memory': (200, TOP_MEM)}

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE) or req.method != 'GET':
            return super().handle(route)
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        q = parse_qs(urlparse(req.url).query)
        if path == '/api/clusters/c1/reports/summary':
            status, body = self.summary
        elif path == '/api/clusters/c1/reports/top-vms':
            status, body = self.top[q.get('metric', ['cpu'])[0]]
        else:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        return route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})


def _browsers():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    return pw


@pytest.fixture(scope='module', params=['chromium', 'firefox'])
def browser(request):
    pw = _browsers()
    try:
        br = getattr(pw, request.param).launch(headless=True)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no {request.param} for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout, language='en', **kw):
        app = _App(browser, _ReportServer(role='standalone', layout=layout, language=language,
                                          clusters=[CLUSTER], extra=dict(SSE_TOKEN), **kw))
        apps.append(app)
        page = app.page
        page.get_by_text('Testi').first.click()
        page.wait_for_timeout(500)
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press('p')
        page.wait_for_function('() => !!document.getElementById("report-summary-content")', timeout=10000)
        page.wait_for_timeout(500)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


# the card under a heading, its text and the guest names in it
CARD_JS = '''(title) => {
  const h = Array.from(document.querySelectorAll('h3')).find(x => x.innerText.trim() === title);
  if (!h) return null;
  const card = h.parentElement;
  return {text: card.innerText, names: Array.from(card.querySelectorAll('span.truncate')).map(s => s.innerText)};
}'''
TILES_JS = '''() => {
  const root = document.getElementById('report-summary-content');
  const unread = Array.from(root.querySelectorAll('[data-report-unread]')).map(e => e.getAttribute('data-report-unread'));
  const gauges = Array.from(root.querySelectorAll('.gauge-text')).map(e => e.textContent.trim());
  const grid = root.querySelector('.grid');
  return {unread, gauges, text: root.innerText, grid: grid ? grid.innerText : null,
          overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth};
}'''


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_memory_list_is_the_memory_ranking(open_app, layout):
    app = open_app(layout)
    page = app.page
    cpu = page.evaluate(CARD_JS, 'Highest CPU Usage')
    mem = page.evaluate(CARD_JS, 'Highest Memory Usage')
    assert cpu['names'] == [f'busy{i:02d}' for i in range(5)], cpu
    assert mem['names'] == [f'bigmem{i:02d}' for i in range(5)], mem
    asked = sorted(parse_qs(urlparse(u).query).get('metric', ['?'])[0]
                   for u in app.server.urls if '/reports/top-vms' in u)
    assert asked == ['cpu', 'memory'], app.server.urls
    tiles = page.evaluate(TILES_JS)
    assert tiles['unread'] == [] and tiles['gauges'] == ['40.0%', '55.0%'], tiles
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_summary_that_could_not_be_read_shows_no_zeros(open_app, layout):
    app = open_app(layout, summary=(500, {'error': 'boom'}))
    page = app.page
    tiles = page.evaluate(TILES_JS)
    assert tiles['unread'] == ['summary'], tiles
    assert 'The report could not be read' in tiles['text'], tiles['text']
    # no gauge and no counter with a made-up 0
    assert tiles['gauges'] == [] and not re.search(r'(^|\n)0(\.0%)?\n', tiles['text']), tiles
    assert 'VMs running' not in tiles['text'], tiles
    # the lists were read, they stay
    assert page.evaluate(CARD_JS, 'Highest Memory Usage')['names'][0] == 'bigmem00'
    # Retry asks again, and a good answer brings the tiles back
    app.server.summary = (200, SUMMARY)
    page.locator('[data-report-unread="summary"] button').click()
    page.wait_for_function('() => document.querySelectorAll("#report-summary-content .gauge-text").length === 2',
                           timeout=5000)
    assert page.evaluate(TILES_JS)['unread'] == []
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('unread', [['nodes', 'guests'], ['guests']])
def test_runtime_a_figure_the_server_could_not_read_is_a_dash(open_app, layout, unread):
    body = dict(SUMMARY, live=dict(LIVE, cpu_percent=0, mem_percent=0, vms_running=0, cts_running=0, unread=unread))
    if unread == ['guests']:
        body['live'].update(cpu_percent=40.0, mem_percent=55.0)
    else:
        body.update(cpu=dict(SUMMARY['cpu'], current=0, avg=0, min=0, max=0),
                    memory=dict(SUMMARY['memory'], current=0, avg=0, min=0, max=0))
    app = open_app(layout, summary=(200, body))
    tiles = app.page.evaluate(TILES_JS)
    want = (['cpu', 'memory'] if 'nodes' in unread else []) + ['vms', 'cts']
    assert tiles['unread'] == want, tiles
    assert tiles['gauges'] == ([] if 'nodes' in unread else ['40.0%', '55.0%']), tiles
    assert tiles['grid'].count('Could not be read') == len(want), tiles['grid']
    assert not re.search(r'(^|\n)0(\.0%)?\n', tiles['grid']), tiles['grid']
    assert not tiles['overflow']
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_ranking_that_could_not_be_read_is_no_empty_list(open_app, layout):
    app = open_app(layout, top={'cpu': (503, {'error': 'Cluster not connected', 'offline': True}),
                                'memory': (503, {'error': 'Cluster not connected', 'offline': True})})
    page = app.page
    for title, mark in (('Highest CPU Usage', 'top-cpu'), ('Highest Memory Usage', 'top-mem')):
        card = page.evaluate(CARD_JS, title)
        assert 'Could not be read' in card['text'] and 'No running VMs' not in card['text'], card
        assert page.locator(f'[data-report-unread="{mark}"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_an_empty_ranking_still_says_no_running_vms(open_app):
    app = open_app('modern', top={'cpu': (200, []), 'memory': (200, [])})
    card = app.page.evaluate(CARD_JS, 'Highest Memory Usage')
    assert 'No running VMs' in card['text'] and 'Could not be read' not in card['text'], card
    assert not app.errors, app.errors


def test_runtime_the_lines_speak_german(open_app):
    body = dict(SUMMARY, live=dict(LIVE, unread=['guests']))
    app = open_app('modern', language='de', summary=(200, body),
                   top={'cpu': (503, {'error': 'x'}), 'memory': (200, TOP_MEM)})
    text = app.page.evaluate(TILES_JS)['text']
    assert text.count('Konnte nicht gelesen werden') == 3, text
    app.server.summary = (500, {'error': 'boom'})
    app.page.locator('button[title="Aktualisieren"], button[title="Refresh"]').first.click()
    app.page.get_by_text('Der Bericht konnte nicht gelesen werden').first.wait_for(timeout=5000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_null_figures_of_the_server_draw_no_average(open_app, layout):
    # the server's answer when the node status did not answer and no snapshot of the window
    # had CPU or memory: null figures, a stored guest count still there. An average line
    # under the dash said "avg 0% · 0%-0%" for them.
    blank = {'avg': None, 'min': None, 'max': None, 'current': None, 'samples': []}
    body = dict(SUMMARY, data_points=1, timestamps=['2026-11-01T10:00:00+01:00'],
                cpu=dict(blank), memory=dict(blank),
                vms_running={'avg': 3, 'min': 3, 'max': 3, 'current': 3, 'samples': [3]},
                live=dict(LIVE, cpu_percent=0, mem_percent=0, unread=['nodes']))
    app = open_app(layout, summary=(200, body))
    tiles = app.page.evaluate(TILES_JS)
    assert tiles['unread'] == ['cpu', 'memory'], tiles
    assert 'avg' not in tiles['grid'], tiles['grid']
    assert 'VMs running' in tiles['grid'] and not tiles['overflow'], tiles
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_none_running_now_is_zero_not_the_stored_count(open_app, layout):
    # the guest list was read and says no VM runs now; a stored snapshot of the window
    # still had 3. The tile took the stored 3 because 0 is falsy.
    body = dict(SUMMARY, live=dict(LIVE, vms_running=0, cts_running=0))
    app = open_app(layout, summary=(200, body))
    counts = app.page.evaluate('''() => Array.from(document.querySelectorAll(
        '#report-summary-content .text-orange-400, #report-summary-content .text-purple-400'))
        .filter(e => e.classList.contains('text-4xl')).map(e => e.textContent.trim())''')
    assert counts == ['0', '0'], counts
    assert not app.errors, app.errors
