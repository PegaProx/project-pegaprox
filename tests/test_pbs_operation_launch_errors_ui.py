"""A PBS launch error body cannot become a success toast in the built UI."""

import re

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, [{'name': 'alpha'}]),
    ('GET', '/api/pbs/p1/jobs'): (200, {
        'sync': [{'id': 'sync-alpha', 'store': 'alpha'}], 'verify': [], 'prune': [],
    }),
}
GC_UPID = 'UPID:pbs:00001234:0000ABCD:00000001:65000000:garbage_collection:alpha:root@pam:'
JOB_UPID = 'UPID:pbs:00001234:10000ABCD:0000000000000001:65000000:sync::root@pam!token:'


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('language, message', [
    ('en', 'Operation failed'), ('de', 'Operation fehlgeschlagen'),
])
def test_gc_error_body_shows_failure_instead_of_started(browser, layout, language, message):
    """A 200 error body from an older server must not claim GC started."""
    reads = dict(READS)
    reads[('POST', '/api/pbs/p1/datastores/alpha/gc')] = (200, {'error': 'PBS refused'})
    app = _App(browser, _FakeServer(role='standalone', layout=layout,
                                    language=language, extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datenspeicher' if language == 'de' else 'Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        page.get_by_role('button', name='Garbage Collection').click()

        page.get_by_text(message, exact=True).wait_for(timeout=5000)
        assert page.get_by_text('gc started on alpha').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('result', [
    {'error': 'PBS refused'}, {'data': 'UPID:launched'},
] + [{'data': JOB_UPID + suffix} for suffix in ('\n', '\r', '\r\n', '\u2028', '\u2029')])
def test_job_invalid_body_shows_failure_instead_of_started(browser, result):
    """A 200 error or truncated UPID must not claim a job started."""
    reads = dict(READS)
    reads[('POST', '/api/pbs/p1/jobs/sync/sync-alpha/run')] = (200, result)
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Jobs').first.click()
        row = page.locator('tr').filter(has_text='sync-alpha').first
        row.get_by_role('button', name='Run').click()

        page.get_by_text('Operation failed', exact=True).wait_for(timeout=5000)
        assert page.get_by_text("sync job 'sync-alpha' started").count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('result', [{}, {'data': 'UPID:launched'}] + [
    {'data': GC_UPID + suffix} for suffix in ('\n', '\r', '\r\n', '\u2028', '\u2029')])
def test_gc_invalid_result_shows_failure_instead_of_started(browser, result):
    """An empty or truncated success envelope cannot claim GC started."""
    reads = dict(READS)
    reads[('POST', '/api/pbs/p1/datastores/alpha/gc')] = (200, result)
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        page.get_by_role('button', name='Garbage Collection').click()

        page.get_by_text('Operation failed', exact=True).wait_for(timeout=5000)
        assert page.get_by_text('gc started on alpha').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


class _InvalidJsonJobServer(_FakeServer):
    """Return malformed JSON only for the job launch under test."""

    def handle(self, route):
        """Keep normal mocked reads while making the launch body unparseable."""
        if (route.request.method == 'POST'
                and route.request.url.endswith('/api/pbs/p1/jobs/sync/sync-alpha/run')):
            return route.fulfill(status=200, body='not json',
                                 headers={'Content-Type': 'application/json'})
        return super().handle(route)


def test_job_invalid_json_shows_failure_instead_of_started(browser):
    """An unparseable 200 response cannot claim a job launched."""
    app = _App(browser, _InvalidJsonJobServer(role='standalone', extra=READS))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Jobs').first.click()
        row = page.locator('tr').filter(has_text='sync-alpha').first
        row.get_by_role('button', name='Run').click()

        page.get_by_text('Operation failed', exact=True).wait_for(timeout=5000)
        assert page.get_by_text("sync job 'sync-alpha' started").count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_complete_gc_upid_still_shows_started(browser):
    """A complete PBS worker ID preserves a successful GC launch toast."""
    reads = dict(READS)
    reads[('POST', '/api/pbs/p1/datastores/alpha/gc')] = (200, {'data': GC_UPID})
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        page.get_by_role('button', name='Garbage Collection').click()

        page.get_by_text(re.compile(r'^gc started on alpha')).wait_for(timeout=5000)
        assert page.get_by_text('Operation failed', exact=True).count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_complete_job_upid_with_token_and_empty_worker_id_still_shows_started(browser):
    """An empty worker ID and token auth name are valid in a completed job UPID."""
    reads = dict(READS)
    reads[('POST', '/api/pbs/p1/jobs/sync/sync-alpha/run')] = (200, {'data': JOB_UPID})
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Jobs').first.click()
        row = page.locator('tr').filter(has_text='sync-alpha').first
        row.get_by_role('button', name='Run').click()

        page.get_by_text("sync job 'sync-alpha' started").wait_for(timeout=5000)
        assert page.get_by_text('Operation failed', exact=True).count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
