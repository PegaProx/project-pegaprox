"""Issue #804: PBS job schedules belong beside their datastore.

The existing PBS reads return datastore GC schedules and server-wide sync,
verify and prune jobs. This browser test checks that selecting one datastore
shows only its jobs, in both layouts, using the built frontend bundle.
"""

import re

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


STORES = [
    {'name': 'alpha', 'gc-schedule': 'daily',
     'gc-job': {'store': 'alpha', 'schedule': 'sat 01:00',
                'last-run-endtime': 1780000000, 'last-run-state': 'OK'},
     'detail': {'gc-status': {'upid': 'UPID:gc', 'removed-bytes': 1024}}},
    {'name': 'beta', 'gc-schedule': 'weekly', 'detail': {'gc-status': {}}},
]
JOBS = {
    'sync': [
        {'id': 'sync-alpha', 'store': 'alpha', 'schedule': 'mon 02:00', 'last-run-endtime': 1780000010},
        {'id': 'sync-beta', 'store': 'beta', 'schedule': 'tue 03:00'},
    ],
    'verify': [
        {'id': 'verify-alpha', 'store': 'alpha', 'schedule': 'wed 04:00'},
        {'id': 'verify-beta', 'store': 'beta', 'schedule': 'thu 05:00'},
    ],
    'prune': [
        {'id': 'prune-alpha', 'store': 'alpha', 'schedule': ''},
        {'id': 'prune-beta', 'store': 'beta', 'schedule': 'fri 06:00', 'disable': True},
    ],
}
READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, STORES),
    ('GET', '/api/pbs/p1/jobs'): (200, JOBS),
}


def _jobs_after_run():
    """Return the mocked PBS job list after the sync job has finished."""
    jobs = {kind: [dict(job) for job in entries] for kind, entries in JOBS.items()}
    jobs['sync'][0]['last-run-endtime'] += 3600
    return jobs


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_selected_datastore_shows_only_its_schedules(browser, layout):
    """Changing stores changes the GC schedule and filters each kind of PBS job."""
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=READS))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()

        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="alpha"]')
        table.wait_for(timeout=5000)
        rows = table.locator('[data-pbs-schedule-kind]')
        assert rows.count() == 4
        assert [r.get_attribute('data-pbs-schedule-kind') for r in rows.all()] == [
            'gc', 'sync', 'verify', 'prune'
        ]
        text = table.inner_text()
        for expected in ('sat 01:00', 'sync-alpha', 'mon 02:00', 'verify-alpha', 'prune-alpha', 'Manual'):
            assert expected in text
        assert 'sync-beta' not in text and 'verify-beta' not in text and 'prune-beta' not in text
        assert rows.first.locator('td').nth(3).inner_text() != '-'
        assert rows.nth(1).locator('td').nth(3).inner_text() != '-'

        page.get_by_role('button', name=re.compile(r'^beta\b')).click()
        other = page.locator('[data-pbs-datastore-schedules="beta"]')
        other.wait_for(timeout=5000)
        text = other.inner_text()
        for expected in ('weekly', 'sync-beta', 'verify-beta', 'prune-beta'):
            assert expected in text
        assert 'fri 06:00' in text and 'disabled' in text.lower()
        assert 'sync-alpha' not in text and 'verify-alpha' not in text and 'prune-alpha' not in text
        assert not [call for call in app.server.calls
                    if call[0] != 'GET' and call[1].startswith('/api/pbs/')], app.server.calls
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_scheduled_run_refreshes_datastore_last_run_on_poll(browser):
    """The 30-second PBS poll refreshes last-run status without changing stores."""
    app = _App(browser, _FakeServer(role='standalone', extra=READS), clock=True)
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        cell = page.locator('[data-pbs-datastore-schedules="alpha"] [data-pbs-schedule-kind="sync"] td').nth(3)
        previous = cell.inner_text()
        assert previous != '-'
        initial_reads = app.server.calls.count(('GET', '/api/pbs/p1/jobs'))

        app.server.extra[('GET', '/api/pbs/p1/jobs')] = (200, _jobs_after_run())
        page.clock.run_for(31000)
        page.wait_for_function(
            '''previous => {
                const cell = document.querySelector('[data-pbs-datastore-schedules="alpha"] '
                    + '[data-pbs-schedule-kind="sync"] td:nth-child(4)');
                return cell && cell.textContent.trim() !== previous;
            }''', arg=previous, timeout=5000,
        )
        assert app.server.calls.count(('GET', '/api/pbs/p1/jobs')) > initial_reads
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_manual_run_refreshes_jobs_last_run(browser):
    """Run now reloads job status as well as tasks for the selected PBS."""
    reads = dict(READS)
    reads[('POST', '/api/pbs/p1/jobs/sync/sync-alpha/run')] = (200, {'data': 'UPID:run'})
    app = _App(browser, _FakeServer(role='standalone', extra=reads), clock=True)
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Jobs').first.click()
        row = page.locator('tr').filter(has_text='sync-alpha').first
        previous = row.locator('td').nth(4).inner_text()
        assert previous != '-'
        initial_reads = app.server.calls.count(('GET', '/api/pbs/p1/jobs'))

        row.get_by_role('button', name='Run').click()
        page.get_by_text("sync job 'sync-alpha' started").wait_for(timeout=5000)
        app.server.extra[('GET', '/api/pbs/p1/jobs')] = (200, _jobs_after_run())
        page.clock.run_for(1100)
        page.wait_for_function(
            '''previous => {
                const row = [...document.querySelectorAll('tr')]
                    .find(row => row.textContent.includes('sync-alpha'));
                return row && row.querySelectorAll('td')[4]?.textContent.trim() !== previous;
            }''', arg=previous, timeout=5000,
        )
        assert app.server.calls.count(('GET', '/api/pbs/p1/jobs')) > initial_reads
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_gc_schedule_remains_visible_without_configured_jobs(browser):
    """A datastore's GC schedule is useful even when its job list is empty."""
    reads = dict(READS)
    reads[('GET', '/api/pbs/p1/jobs')] = (200, {'sync': [], 'verify': [], 'prune': []})
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="alpha"]')
        table.wait_for(timeout=5000)
        assert table.locator('[data-pbs-schedule-kind="gc"]').count() == 1
        assert table.locator('[data-pbs-schedule-kind]').count() == 1
        assert 'sat 01:00' in table.inner_text()
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_job_read_refusal_is_visible_beside_datastore_schedules(browser):
    """An upstream permission refusal cannot masquerade as no configured jobs."""
    reads = dict(READS)
    reads[('GET', '/api/pbs/p1/jobs')] = (403, {'code': 'PBS_FORBIDDEN',
                                               'error': 'PBS denied the request'})
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="alpha"]')
        table.wait_for(timeout=5000)
        table.get_by_role('alert').wait_for(timeout=5000)
        assert 'Jobs' in table.get_by_role('alert').inner_text()
        assert table.locator('[data-pbs-schedule-kind="gc"]').count() == 1
        assert table.locator('[data-pbs-schedule-kind="sync"]').count() == 0

        page.get_by_role('button', name='Jobs').first.click()
        assert page.get_by_role('alert').filter(has_text='Jobs').count() > 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_failed_prune_read_keeps_sync_and_verify_visible(browser, layout):
    reads = dict(READS)
    reads[('GET', '/api/pbs/p1/jobs')] = (200, {
        **JOBS, 'prune': [], 'errors': {'prune': 'PBS_FORBIDDEN'},
    })
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="alpha"]')
        table.wait_for(timeout=5000)
        assert table.get_by_role('alert').count() == 1
        assert 'Prune Jobs' in table.get_by_role('alert').inner_text()
        assert table.locator('[data-pbs-schedule-kind="sync"]').count() == 1
        assert table.locator('[data-pbs-schedule-kind="verify"]').count() == 1
        assert table.locator('[data-pbs-schedule-kind="prune"]').count() == 0

        page.get_by_role('button', name='Jobs').first.click()
        assert page.get_by_role('alert').count() == 1
        assert 'Prune Jobs' in page.get_by_role('alert').inner_text()
        assert page.locator('tr').filter(has_text='sync-alpha').count() == 1
        assert page.locator('tr').filter(has_text='verify-alpha').count() == 1
        assert page.get_by_text('No prune jobs configured').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
