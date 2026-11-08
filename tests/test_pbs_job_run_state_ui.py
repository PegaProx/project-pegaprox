"""A PBS job's last run says how it went, and when the next one is due.

PBS hands every sync, verify and prune job (and a datastore's GC job) its last-run-state:
"OK", "WARNINGS: n" or the error itself, and next-run. The views showed only when the last
run ended, so a failed sync read like a good one. Both columns are shown now, in the Jobs
tab and beside each datastore, and opening either tab reads the jobs again instead of
showing what the last 30 s poll had. Runtime tests drive the built bundle against the fake
server of tests/test_ha_ui.py.
"""
import os
import re

import pytest

from test_ha_ui import LANGS, PBS, _App, _FakeServer, _blocks, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STORES = [
    {'name': 'alpha', 'gc-schedule': 'daily',
     'gc-job': {'store': 'alpha', 'schedule': 'sat 01:00', 'last-run-endtime': 1780000000,
                'last-run-state': 'OK', 'next-run': 1780600000},
     'detail': {'gc-status': {'upid': 'UPID:gc'}}},
]
JOBS = {
    'sync': [{'id': 'sync-alpha', 'store': 'alpha', 'schedule': 'mon 02:00', 'last-run-endtime': 1780000010,
              'last-run-state': 'connection error: timed out', 'next-run': 1780100000}],
    'verify': [{'id': 'verify-alpha', 'store': 'alpha', 'schedule': 'wed 04:00', 'last-run-endtime': 1780000020,
                'last-run-state': 'WARNINGS: 2', 'next-run': 1780200000}],
    'prune': [{'id': 'prune-alpha', 'store': 'alpha', 'schedule': 'fri 06:00', 'disable': True,
               'last-run-endtime': 1780000030, 'last-run-state': 'OK'}],
}
READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, STORES),
    ('GET', '/api/pbs/p1/jobs'): (200, JOBS),
}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _added():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Oct 2026 - what PBS wrote for the last run of a job')
    return src[start:src.index('function PbsJobReadError(', start)]


# -- source -------------------------------------------------------------------------------------

def test_the_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        assert len(re.findall(r'^ +pbsNextRun:', block, re.M)) == 1, lang


def test_no_dash_and_every_class_in_the_static_build():
    text = _added()
    assert '\u2014' not in text and '\u2013' not in text
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    assert not sorted(n for n in _classes(text) if n not in have)


# -- runtime ------------------------------------------------------------------------------------

def _states(locator):
    return [s.get_attribute('data-pbs-run-state') for s in locator.locator('[data-pbs-run-state]').all()]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_beside_the_datastore_each_run_says_how_it_went_and_when_the_next_is(browser, layout):
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=READS))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="alpha"]')
        table.wait_for(timeout=5000)
        assert _states(table) == ['ok', 'error', 'warning', 'ok']
        sync = table.locator('[data-pbs-schedule-kind="sync"]')
        assert 'connection error: timed out' in sync.inner_text()
        assert sync.locator('td').nth(5).inner_text().strip() != '-'
        # a disabled job has no next run
        assert table.locator('[data-pbs-schedule-kind="prune"] td').nth(5).inner_text().strip() == '-'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_the_jobs_tab_shows_the_state_and_next_run_and_reads_the_jobs_again(browser):
    app = _App(browser, _FakeServer(role='standalone', extra=READS))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_text('4.0').first.wait_for(timeout=5000)
        page.wait_for_timeout(500)
        before = app.server.calls.count(('GET', '/api/pbs/p1/jobs'))
        page.get_by_role('button', name='Jobs').first.click()
        page.locator('tr').filter(has_text='sync-alpha').first.wait_for(timeout=5000)
        page.wait_for_timeout(300)
        assert app.server.calls.count(('GET', '/api/pbs/p1/jobs')) == before + 1
        assert _states(page.locator('tr').filter(has_text='sync-alpha')) == ['error']
        assert _states(page.locator('tr').filter(has_text='verify-alpha')) == ['warning']
        assert _states(page.locator('tr').filter(has_text='prune-alpha')) == ['ok']
        headers = page.locator('thead').first.inner_text()
        assert 'Status' in headers and 'Next Run' in headers
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
