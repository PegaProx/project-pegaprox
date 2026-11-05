"""PBS task read failures must be visible in the deployed web interface."""

import json
import re
from urllib.parse import quote

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


TASK = {'upid': 'UPID:pbs:0000:0000:0000:6A1B2C00:verify:alpha:root@pam:',
        'worker_type': 'verify', 'worker_id': 'alpha', 'status': 'OK',
        'starttime': 1780000000, 'endtime': 1780000100, 'user': 'root@pam'}
TASK_B = {**TASK, 'upid': 'UPID:pbs:0000:0000:0000:6A1B2C01:verify:beta:root@pam:',
          'worker_id': 'beta'}
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


@pytest.mark.parametrize(('language', 'message'), [
    ('en', 'Error loading log'), ('de', 'Fehler beim Laden des Logs'),
])
def test_task_log_refusal_reports_error(browser, language, message):
    """A task detail refusal is visible in the operator's selected language."""
    detail_path = f'/api/pbs/p1/tasks/{quote(TASK["upid"], safe="")}'
    reads = {**READS,
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK]),
             ('GET', detail_path): (403, {'error': 'forbidden'})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads, language=language))
    try:
        _open_tasks(app.page)
        app.page.get_by_text('alpha').first.click()
        app.page.get_by_text(message).wait_for(timeout=5000)
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


def test_old_server_action_refresh_cannot_cancel_new_server_tasks(browser):
    """A delayed refresh from PBS A cannot invalidate PBS B's pending task read."""
    other = dict(PBS, id='p2', name='backup02')
    reads = {**READS,
             ('GET', '/api/pbs'): (200, [PBS, other]),
             ('GET', '/api/pbs/p1/datastores'): (200, [{'name': 'alpha'}]),
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK]),
             ('GET', '/api/pbs/p2/status'): (200, {'version': {'version': '4.0'}}),
             ('GET', '/api/pbs/p2/datastores'): (200, []),
             ('POST', '/api/pbs/p1/datastores/alpha/gc'): (200, {
                 'data': 'UPID:pbs:00001234:0000ABCD:00000001:65000000:garbage_collection:alpha:root@pam:'})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads), clock=True)
    try:
        page = app.page
        held = []
        page.route('**/api/pbs/p2/tasks*', lambda route: held.append(route))
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        page.get_by_role('button', name='Garbage Collection').click()
        page.get_by_text('gc started on alpha').wait_for(timeout=5000)
        old_reads = app.server.calls.count(('GET', '/api/pbs/p1/tasks'))

        page.get_by_text('backup02').first.click()
        page.get_by_role('button', name='Tasks', exact=True).click()
        page.wait_for_timeout(200)
        assert len(held) == 1
        page.clock.run_for(1100)
        page.wait_for_timeout(200)
        held[0].fulfill(status=200, content_type='application/json', body=json.dumps([TASK_B]))

        page.get_by_text('beta', exact=True).wait_for(timeout=5000)
        assert app.server.calls.count(('GET', '/api/pbs/p1/tasks')) == old_reads
        assert page.get_by_text('alpha', exact=True).count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('stale_status', [200, 403])
def test_latest_task_log_click_wins_over_older_response(browser, stale_status):
    """A late success or refusal for task A cannot replace task B's log."""
    path_a = f'/api/pbs/p1/tasks/{quote(TASK["upid"], safe="")}'
    path_b = f'/api/pbs/p1/tasks/{quote(TASK_B["upid"], safe="")}'
    reads = {**READS,
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK, TASK_B]),
             ('GET', path_b): (200, {'status': {'status': 'stopped'},
                                    'log': [{'t': 'B log'}]})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        held = []
        page.route(f'**{path_a}', lambda route: held.append(route))
        _open_tasks(page)
        page.get_by_text('alpha', exact=True).first.click()
        page.wait_for_timeout(200)
        assert len(held) == 1
        page.get_by_text('beta', exact=True).first.click()
        page.get_by_text('B log').wait_for(timeout=5000)

        old_response = ({'status': {'status': 'stopped'}, 'log': [{'t': 'A log'}]}
                        if stale_status == 200 else {'error': 'forbidden'})
        held[0].fulfill(status=stale_status, content_type='application/json',
                        body=json.dumps(old_response))
        page.wait_for_timeout(500)

        assert page.get_by_text('B log').count() == 1
        assert page.get_by_text('A log').count() == 0
        assert page.get_by_text('Error loading log').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_closing_task_log_cancels_pending_detail_read(browser):
    """Closing the viewer prevents an older pending click from reopening it."""
    path_a = f'/api/pbs/p1/tasks/{quote(TASK["upid"], safe="")}'
    path_b = f'/api/pbs/p1/tasks/{quote(TASK_B["upid"], safe="")}'
    reads = {**READS,
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK, TASK_B]),
             ('GET', path_b): (200, {'status': {'status': 'stopped'},
                                    'log': [{'t': 'B log'}]})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        held = []
        page.route(f'**{path_a}', lambda route: held.append(route))
        _open_tasks(page)
        page.get_by_text('beta', exact=True).first.click()
        page.get_by_text('B log').wait_for(timeout=5000)
        page.get_by_text('alpha', exact=True).first.click()
        page.wait_for_timeout(200)
        assert len(held) == 1

        page.get_by_text('Task Log').locator('..').get_by_role('button').click()
        assert page.get_by_text('B log').count() == 0
        held[0].fulfill(status=200, content_type='application/json',
                        body=json.dumps({'status': {'status': 'stopped'},
                                         'log': [{'t': 'A log'}]}))
        page.wait_for_timeout(500)

        assert page.get_by_text('A log').count() == 0
        assert page.get_by_text('Task Log').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_dashboard_task_read_failure_is_visible_and_recovers(browser, layout):
    """The default PBS dashboard explains a failed task read and clears it on success."""
    reads = {**READS, ('GET', '/api/pbs/p1/tasks'): (403, {'error': 'forbidden'})}
    app = _App(browser, _FakeServer(layout=layout, role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('alert').filter(has_text='Tasks').wait_for(timeout=5000)
        assert page.get_by_text('alpha', exact=True).count() == 0

        app.server.extra[('GET', '/api/pbs/p1/tasks')] = (200, [TASK])
        page.get_by_role('button', name='Tasks', exact=True).click()
        page.get_by_role('button', name='Refresh', exact=True).last.click()
        page.get_by_text('alpha', exact=True).first.wait_for(timeout=5000)
        page.get_by_role('button', name='Dashboard', exact=True).last.click()
        page.get_by_text('alpha', exact=True).first.wait_for(timeout=5000)
        assert page.get_by_role('alert').filter(has_text='Tasks').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_pending_server_task_read_is_not_a_successful_empty_result(browser, layout):
    """An unfinished read after a server switch must not claim that no tasks exist."""
    other = dict(PBS, id='p2', name='backup02')
    reads = {**READS,
             ('GET', '/api/pbs'): (200, [PBS, other]),
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK]),
             ('GET', '/api/pbs/p2/status'): (200, {'version': {'version': '4.0'}}),
             ('GET', '/api/pbs/p2/datastores'): (200, [])}
    app = _App(browser, _FakeServer(layout=layout, role='standalone', extra=reads))
    held = []
    try:
        page = app.page
        page.route('**/api/pbs/p2/tasks*', lambda route: held.append(route))
        _open_tasks(page)
        page.get_by_text('alpha', exact=True).first.wait_for(timeout=5000)
        with page.expect_request('**/api/pbs/p2/tasks*'):
            page.get_by_text('backup02').first.click()
        page.get_by_role('button', name='Tasks', exact=True).click()
        assert len(held) == 1
        assert page.get_by_text('alpha', exact=True).count() == 0
        assert page.get_by_text('No tasks found', exact=True).count() == 0

        held.pop(0).fulfill(status=200, content_type='application/json', body='[]')
        page.get_by_text('No tasks found', exact=True).wait_for(timeout=5000)
        assert page.get_by_role('alert').filter(has_text='Tasks').count() == 0
        assert not app.errors, app.errors
    finally:
        for route in held:
            route.fulfill(status=200, content_type='application/json', body='[]')
        app.ctx.close()


@pytest.mark.parametrize('initial_status', [200, 403])
def test_returning_to_server_does_not_restore_old_empty_or_error_state(browser, initial_status):
    """A-to-B-to-A stays pending until a fresh A read, not its cached empty/error result."""
    other = dict(PBS, id='p2', name='backup02')
    reads = {**READS,
             ('GET', '/api/pbs'): (200, [PBS, other]),
             ('GET', '/api/pbs/p1/tasks'): (initial_status, [] if initial_status == 200 else {'error': 'forbidden'}),
             ('GET', '/api/pbs/p2/status'): (200, {'version': {'version': '4.0'}}),
             ('GET', '/api/pbs/p2/datastores'): (200, [])}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    held_a, held_b = [], []
    try:
        page = app.page
        _open_tasks(page)
        if initial_status == 200:
            page.get_by_text('No tasks found', exact=True).wait_for(timeout=5000)
        else:
            page.get_by_role('alert').filter(has_text='Tasks').wait_for(timeout=5000)
        page.route('**/api/pbs/p1/tasks*', lambda route: held_a.append(route))
        page.route('**/api/pbs/p2/tasks*', lambda route: held_b.append(route))
        with page.expect_request('**/api/pbs/p2/tasks*'):
            page.get_by_text('backup02').first.click()
        with page.expect_request('**/api/pbs/p1/tasks*'):
            page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Tasks', exact=True).click()
        assert len(held_a) == len(held_b) == 1
        assert page.get_by_text('No tasks found', exact=True).count() == 0
        assert page.get_by_role('alert').filter(has_text='Tasks').count() == 0

        held_b.pop(0).fulfill(status=200, content_type='application/json', body=json.dumps([TASK_B]))
        held_a.pop(0).fulfill(status=200, content_type='application/json', body=json.dumps([TASK]))
        page.get_by_text('alpha', exact=True).first.wait_for(timeout=5000)
        assert page.get_by_text('beta', exact=True).count() == 0
        assert page.get_by_role('alert').filter(has_text='Tasks').count() == 0
        assert not app.errors, app.errors
    finally:
        for route in held_a + held_b:
            route.fulfill(status=200, content_type='application/json', body='[]')
        app.ctx.close()


@pytest.mark.parametrize('stale_status', [200, 403])
def test_leaving_server_invalidates_pending_task_log_before_return(browser, stale_status):
    """An old detail success/refusal cannot reopen a log or toast after A-to-B-to-A."""
    other = dict(PBS, id='p2', name='backup02')
    detail_path = f'/api/pbs/p1/tasks/{quote(TASK["upid"], safe="")}'
    reads = {**READS,
             ('GET', '/api/pbs'): (200, [PBS, other]),
             ('GET', '/api/pbs/p1/tasks'): (200, [TASK]),
             ('GET', '/api/pbs/p2/status'): (200, {'version': {'version': '4.0'}}),
             ('GET', '/api/pbs/p2/datastores'): (200, []),
             ('GET', '/api/pbs/p2/tasks'): (200, []),
             ('GET', detail_path): (200, {'status': {'status': 'stopped'}, 'log': [{'t': 'fresh A log'}]})}
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    held = []
    try:
        page = app.page
        page.route(f'**{detail_path}', lambda route: held.append(route))
        _open_tasks(page)
        with page.expect_request(f'**{detail_path}'):
            page.get_by_text('alpha', exact=True).first.click()
        page.get_by_text('backup02').first.click()
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Tasks', exact=True).click()
        page.get_by_text('alpha', exact=True).first.wait_for(timeout=5000)
        payload = ({'status': {'status': 'stopped'}, 'log': [{'t': 'stale A log'}]}
                   if stale_status == 200 else {'error': 'forbidden'})
        held.pop(0).fulfill(status=stale_status, content_type='application/json', body=json.dumps(payload))
        page.wait_for_timeout(500)
        assert page.get_by_text('stale A log', exact=True).count() == 0
        assert page.get_by_text('Error loading log', exact=True).count() == 0
        page.unroute(f'**{detail_path}')
        page.get_by_text('alpha', exact=True).first.click()
        page.get_by_text('fresh A log', exact=True).wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        for route in held:
            route.fulfill(status=200, content_type='application/json', body='{}')
        app.ctx.close()
