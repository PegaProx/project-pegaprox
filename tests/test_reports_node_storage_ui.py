"""Reports > Summary > Node Storage on a cluster (#963).

The rows are one grid, so the longest node name sets the name column for every row and
names sharing a long prefix stay apart. The source check reads web/src; the runtime tests
drive the built bundle in headless Chromium against the fake server of tests/test_ha_ui.py,
in Modern and Corporate, and skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SAME_PREFIX = ['pve-node-rack01-a', 'pve-node-rack01-b', 'pve-node-rack02-a', 'pve-node-rack02-b', 'x1']
LONG = ['pve-production-frankfurt-rack17-node-a-with-a-very-long-name',
        'pve-production-frankfurt-rack17-node-b-with-a-very-long-name', 'short']
SUMMARY = {'period': 'day', 'cluster_id': 'c1', 'cluster_name': 'Testi', 'data_points': 0,
           'cpu': {'avg': 5, 'min': 5, 'max': 5, 'current': 5, 'samples': []},
           'memory': {'avg': 20, 'min': 20, 'max': 20, 'current': 20, 'samples': []},
           'vms_running': {'avg': 0, 'min': 0, 'max': 0, 'current': 0, 'samples': []},
           'timestamps': [], 'live': {'cpu_percent': 5, 'mem_percent': 20, 'vms_running': 0, 'cts_running': 0}}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _block():
    src = _read('web', 'src', 'dashboard.js')
    at = src.index("{t('storageOverview') || 'Node Storage'}")
    return src[at:src.index('{/* CVE Scanner Sub-Tab */}', at)]


def test_every_class_of_the_rows_is_in_the_static_tailwind_build():
    """A class the static build lacks does nothing: gap-y-2 left the rows touching."""
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_block())
    assert 'truncate' in names and 'grid' in names, sorted(names)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    cls = re.search(r'className="(grid items-center [^"]*)"', _block()).group(1)
    assert f'className:"{cls}"' in _read('web', 'index.html'), cls


# --- runtime -------------------------------------------------------------------------------

# the rows are the element after the card's heading
GRID_JS = '''(() => {
  const h = Array.from(document.querySelectorAll('h3')).find(x => x.innerText.trim() === 'Node Storage');
  return h ? h.nextElementSibling : null;
})()'''
ROWS_JS = '''() => {
  const grid = ''' + GRID_JS + ''';
  const kids = Array.from(grid.children);
  const box = el => el.getBoundingClientRect();
  return {rowGap: getComputedStyle(grid).rowGap, clientW: grid.clientWidth, scrollW: grid.scrollWidth,
          pageOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
          names: kids.filter((_, i) => i % 3 === 0).map(n => ({text: n.innerText, title: n.title,
                 clipped: n.scrollWidth > n.clientWidth, top: box(n).top, height: box(n).height})),
          bars: kids.filter((_, i) => i % 3 === 1).map(b => ({left: box(b).left, width: box(b).width}))};
}'''


@pytest.fixture
def open_app(browser):  # noqa: F811
    apps = []

    def _open(layout, names):
        metrics = {n: dict(NODE_METRICS['pve1'], disk_percent=40.0 + 10 * i) for i, n in enumerate(names)}
        extra = dict(SSE_TOKEN)
        extra[('GET', '/api/clusters/c1/reports/summary')] = (200, SUMMARY)
        extra[('GET', '/api/clusters/c1/reports/top-vms')] = (200, [])
        app = _App(browser, _FakeServer(role='standalone', layout=layout, clusters=[CLUSTER],
                                        metrics=metrics, extra=extra))
        apps.append(app)
        page = app.page
        page.get_by_text('Testi').first.click()
        page.wait_for_timeout(500)
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press('p')
        page.wait_for_function('() => !!' + GRID_JS, timeout=10000)
        page.wait_for_timeout(300)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_names_with_a_shared_prefix_stay_apart(open_app, layout):
    app = open_app(layout, SAME_PREFIX)
    rows = app.page.evaluate(ROWS_JS)
    assert [n['text'] for n in rows['names']] == SAME_PREFIX
    for n in rows['names']:
        assert not n['clipped'], n
        assert n['title'] == n['text']
    # one column for every row: the bars start and end in the same place
    assert len({round(b['left']) for b in rows['bars']}) == 1, rows['bars']
    assert len({round(b['width']) for b in rows['bars']}) == 1, rows['bars']
    # and the rows have air between them, as the space-y-2 list had
    assert rows['rowGap'] == '8px', rows['rowGap']
    tops = [n['top'] for n in rows['names']]
    assert all(b - a >= rows['names'][0]['height'] + 7 for a, b in zip(tops, tops[1:])), tops
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_long_name_truncates_on_a_narrow_screen(open_app, layout):
    app = open_app(layout, LONG)
    app.page.set_viewport_size({'width': 420, 'height': 1000})
    app.page.wait_for_timeout(500)
    rows = app.page.evaluate(ROWS_JS)
    assert rows['scrollW'] <= rows['clientW'], rows
    assert not rows['pageOverflow']
    first = rows['names'][0]
    assert first['clipped'] and first['title'] == LONG[0], first
    # the bar keeps its 6rem floor
    assert all(b['width'] >= 95 for b in rows['bars']), rows['bars']
    assert not app.errors, app.errors
