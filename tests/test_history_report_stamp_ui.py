"""Power & Carbon, Cost Dashboard and Insights say how old their figures are.

The server works these reports out off its main loop and keeps them (helpers.history_report):
a newer history gets the kept figures at once while new ones are worked out, so an answer
carries computed_at and refreshing. The page shows "As of HH:MM", adds "updating" while
newer figures are on the way, and fetches again every 15 s until they are there (at most
four times). Runtime tests drive the built bundle in headless Chromium against the fake
server of tests/test_ha_ui.py; they skip where Playwright is not installed.
"""
import json
import os
import re
from datetime import datetime, timedelta

import pytest

from test_ha_ui import CLUSTER, LANGS, SSE_TOKEN, VM, _App, _FakeServer, _blocks, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ['reportAsOf', 'reportUpdating']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _added():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// NS Oct 2026 - power, costs and right-sizing come from a kept result')
    return src[start:src.index('        // MK May 2026', start)]


def _tab(name):
    """The component's source, up to the next top-level component."""
    src = _read('web', 'src', 'dashboard.js')
    start = src.index(f'        function {name}(')
    return src[start:src.index('\n        function ', start + 1)]


# -- source -------------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language_with_its_placeholder():
    blocks = _blocks()
    assert sorted(blocks) == sorted(LANGS)
    for lang, block in blocks.items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)
        value = re.search(r"^ +reportAsOf: '(.*)',$", block, re.M).group(1)
        assert value.count('{time}') == 1, (lang, value)


def test_the_three_reports_show_the_stamp_and_follow_up():
    for name, report in (('PowerCarbonTab', 'summary'), ('CostDashboardTab', 'summary'), ('InsightsTab', 'rs')):
        tab = _tab(name)
        assert f'<ReportStamp report={{{report}}} t={{t}} />' in tab, name
        assert f'useReportFollowUp({report}, refresh, [clusterId' in tab, name
        # only the newest request writes
        assert 'const mine = ++asked.current;' in tab and 'if (mine !== asked.current) return;' in tab, name


def test_no_dash_and_every_class_in_the_static_build():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(%s):' % '|'.join(KEYS), line)]
    assert len(lines) == len(KEYS) * len(LANGS)
    for text in [_added()] + lines:
        assert '\u2014' not in text and '\u2013' not in text
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_added()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


# -- runtime ------------------------------------------------------------------------------------

# the stamp leaves the date out for figures of the browser's today, so the times the
# tests want as plain HH:MM are today's: a fixed day turned them red the day after
_TODAY = datetime.now().astimezone().replace(hour=9, minute=40, second=0, microsecond=0)


def _today_at(minutes=0):
    return (_TODAY + timedelta(minutes=minutes)).isoformat()


AT = _today_at()
POWER = '/api/clusters/c1/power/summary'
COSTS = '/api/clusters/c1/costs/summary'
SIZING = '/api/clusters/c1/insights/right-sizing'
MONEY = {'kwh': 150.0, 'cost': 45.0, 'kg_co2': 60.0}
RATES = {'cluster_id': 'c1', 'node_idle_w': 80.0, 'node_max_w': 300.0, 'mem_w_per_gb': 0.3, 'pue': 1.5,
         'kwh_price': 0.3, 'kg_co2_per_kwh': 0.4, 'currency': 'EUR', 'notes': ''}


def _power(**stamp):
    return {'enough_data': True, 'cluster_id': 'c1', 'days': 30, 'snapshots_count': 720, 'rates': RATES,
            'scoped': True, 'vm_count': 0, 'coverage': {'window_h': 720, 'covered_h': 720.0, 'missing_h': 0.0,
                                                         'node_estimated_vms': 0},
            'window': MONEY, 'monthly': MONEY, 'by_node': {}, 'top_consumers': [], **stamp}


def _costs(**stamp):
    return {'enough_data': True, 'cluster_id': 'c1', 'days': 30, 'snapshots_count': 720,
            'rates': {'cluster_id': 'c1', 'cpu_per_core_h': 0.012, 'mem_per_gb_h': 0.0035,
                      'storage_per_gb_month': 0.1, 'currency': 'EUR', 'notes': ''},
            'total_window': 10.0, 'monthly_total': 10.0,
            'monthly_breakdown': {'cpu': 5.0, 'memory': 3.0, 'storage': 2.0},
            'by_node': {}, 'top_spenders': [], 'vm_count': 0, **stamp}


def _sizing(**stamp):
    return {'cluster_id': 'c1', 'window_days': 30, 'snapshots_in_window': 720, 'min_samples_required': 24,
            'summary': {'oversized_cpu': 0, 'oversized_mem': 0, 'undersized_cpu': 0, 'undersized_mem': 0,
                        'idle': 0, 'no_data': 0, 'ok': 0}, 'total_vms': 0, 'recommendations': [], **stamp}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(clock=False, **kw):
        extra = dict(SSE_TOKEN)
        extra[('GET', POWER)] = (200, _power(computed_at=AT, refreshing=False))
        extra[('GET', '/api/clusters/c1/power/per-vm')] = (200, {'enough_data': True, 'rows': []})
        extra[('GET', COSTS)] = (200, _costs(computed_at=AT, refreshing=False))
        extra[('GET', '/api/clusters/c1/costs/per-vm')] = (200, {'enough_data': True, 'rows': []})
        extra[('GET', SIZING)] = (200, _sizing(computed_at=AT, refreshing=False))
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw), clock=clock)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open(app, tab, ready):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Reports', exact=True).first.click()
    page.get_by_role('button', name=tab, exact=True).first.click()
    page.get_by_text(ready).first.wait_for(timeout=5000)
    return page


def _stamp(page):
    s = page.locator('[data-report-stamp]')
    s.wait_for(timeout=5000)
    return s.inner_text().strip()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_power_says_how_old_and_fetches_again_until_the_new_figures_are_there(open_app, layout):
    app = open_app(clock=True, layout=layout, extra={('GET', POWER): (200, _power(computed_at=AT, refreshing=True))})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    assert re.fullmatch(r'As of \d\d:\d\d · updating', _stamp(page)), _stamp(page)
    asked = app.server.calls.count(('GET', POWER))
    page.clock.run_for(16000)
    page.wait_for_timeout(300)
    assert app.server.calls.count(('GET', POWER)) == asked + 1
    # the new figures are there: no more fetching
    app.server.extra[('GET', POWER)] = (200, _power(computed_at=_today_at(5), refreshing=False))
    page.clock.run_for(16000)
    page.wait_for_timeout(300)
    assert re.fullmatch(r'As of \d\d:\d\d', _stamp(page)), _stamp(page)
    asked = app.server.calls.count(('GET', POWER))
    page.clock.run_for(40000)
    page.wait_for_timeout(300)
    assert app.server.calls.count(('GET', POWER)) == asked
    assert not app.errors, app.errors


def test_runtime_the_follow_up_gives_up_after_four_tries(open_app):
    app = open_app(clock=True, extra={('GET', POWER): (200, _power(computed_at=AT, refreshing=True))})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    _stamp(page)
    asked = app.server.calls.count(('GET', POWER))
    for _ in range(6):
        page.clock.run_for(16000)
        page.wait_for_timeout(200)
    assert app.server.calls.count(('GET', POWER)) == asked + 4
    assert not app.errors, app.errors


def test_runtime_costs_and_insights_say_how_old_too(open_app):
    app = open_app()
    page = _open(app, 'Cost Dashboard', 'Cost Dashboard')
    assert re.fullmatch(r'As of \d\d:\d\d', _stamp(page)), _stamp(page)
    page.get_by_role('button', name='Insights', exact=True).first.click()
    page.get_by_text('Right-sizing').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert re.fullmatch(r'As of \d\d:\d\d', _stamp(page)), _stamp(page)
    assert not app.errors, app.errors


def test_runtime_no_stamp_without_a_time(open_app):
    app = open_app(extra={('GET', POWER): (200, _power())})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    page.wait_for_timeout(500)
    assert page.locator('[data-report-stamp]').count() == 0
    assert not app.errors, app.errors


# -- what the attack round found ----------------------------------------------------------------

def test_runtime_a_failed_follow_up_does_not_end_the_follow_up(open_app):
    app = open_app(clock=True, extra={('GET', POWER): (200, _power(computed_at=AT, refreshing=True))})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    _stamp(page)
    app.server.extra[('GET', POWER)] = (500, {'error': 'busy'})
    page.clock.run_for(16000)
    page.wait_for_timeout(300)
    app.server.extra[('GET', POWER)] = (200, _power(computed_at=AT, refreshing=True))
    asked = app.server.calls.count(('GET', POWER))
    for _ in range(3):
        page.clock.run_for(16000)
        page.wait_for_timeout(300)
    assert app.server.calls.count(('GET', POWER)) > asked


def test_runtime_another_window_gets_its_own_four_tries(open_app):
    app = open_app(clock=True, extra={('GET', POWER): (200, _power(computed_at=AT, refreshing=True))})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    _stamp(page)
    for _ in range(6):
        page.clock.run_for(16000)
        page.wait_for_timeout(200)
    page.locator('select').first.select_option('7')
    page.wait_for_timeout(500)
    assert 'updating' in _stamp(page)
    asked = app.server.calls.count(('GET', POWER))
    for _ in range(3):
        page.clock.run_for(16000)
        page.wait_for_timeout(200)
    assert app.server.calls.count(('GET', POWER)) == asked + 3


def test_runtime_a_late_answer_for_the_old_window_is_dropped(open_app):
    app = open_app(clock=True, extra={('GET', POWER): (200, _power(computed_at=AT, refreshing=True))})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    _stamp(page)
    held = []

    def hold(route):
        if 'days=30' in route.request.url:
            held.append(route)
        else:
            body = _power(computed_at=_today_at(80), refreshing=False)
            route.fulfill(status=200, content_type='application/json', body=json.dumps(body))
    page.route('**/power/summary?days=*', hold)
    page.clock.run_for(16000)       # the follow-up asks for 30 days and waits
    page.wait_for_timeout(300)
    assert held
    page.locator('select').first.select_option('7')
    page.wait_for_timeout(500)
    fresh = _stamp(page)
    old = _power(computed_at=AT, refreshing=False)
    held[0].fulfill(status=200, content_type='application/json', body=json.dumps(old))
    page.wait_for_timeout(500)
    assert _stamp(page) == fresh, (fresh, _stamp(page))
    assert not app.errors, app.errors


def test_runtime_figures_from_another_day_carry_the_date(open_app):
    app = open_app(extra={('GET', POWER): (200, _power(computed_at='2026-10-14T07:40:00+00:00', refreshing=False))})
    page = _open(app, 'Power & Carbon', 'Monthly kWh')
    # 14/10 or 14.10., as the browser's locale writes it
    assert re.fullmatch(r'As of \d\d[./]\d\d\.?, \d\d:\d\d', _stamp(page)), _stamp(page)
