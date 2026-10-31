"""PBS task read failures must be visible in the deployed web interface."""

from urllib.parse import quote

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


TASK = {'upid': 'UPID:pbs:0000:0000:0000:6A1B2C00:verify:alpha:root@pam:',
        'worker_type': 'verify', 'worker_id': 'alpha', 'status': 'OK',
        'starttime': 1780000000, 'endtime': 1780000100, 'user': 'root@pam'}
READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, []),
}


def _open_tasks(page):
    """Select the mocked PBS server and its task tab."""
    page.get_by_text('backup01').first.click()
    page.get_by_role('button', name='Tasks', exact=True).click()


def test_task_list_refusal_is_not_presented_as_no_tasks(browser):
    """The task pane explains a failed read instead of claiming no tasks exist."""
    reads = {**READS, ('GET', '/api/pbs/p1/tasks'): (403, {'error': 'forbidden'})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        _open_tasks(app.page)
        app.page.get_by_role('alert').filter(has_text='Tasks').wait_for(timeout=5000)
        assert app.page.get_by_text('No tasks found').count() == 0
        app.server.extra[('GET', '/api/pbs/p1/tasks')] = (200, [])
        app.page.get_by_role('button', name='Refresh').last.click()
        app.page.get_by_text('No tasks found').wait_for(timeout=5000)
        assert app.page.get_by_role('alert').filter(has_text='Tasks').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_task_log_refusal_reports_error(browser):
    """A task detail refusal is visible after the operator opens that task."""
    detail_path = f'/api/pbs/p1/tasks/{quote(TASK["upid"], safe="")}'
    reads = {**READS,
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK]),
             ('GET', detail_path): (403, {'error': 'forbidden'})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        _open_tasks(app.page)
        app.page.get_by_text('alpha').first.click()
        app.page.get_by_text('Failed to load task log').wait_for(timeout=5000)
        assert ('GET', detail_path) in app.server.calls
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_task_log_success_still_displays_log(browser):
    """A successful detail read opens the selected task's log text."""
    detail_path = f'/api/pbs/p1/tasks/{quote(TASK["upid"], safe="")}'
    reads = {**READS,
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK]),
             ('GET', detail_path): (200, {'status': {'status': 'stopped'},
                                         'log': [{'t': 'Verification finished'}]})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        _open_tasks(app.page)
        app.page.get_by_text('alpha').first.click()
        app.page.get_by_text('Verification finished').wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
