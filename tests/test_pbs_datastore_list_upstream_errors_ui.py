"""PBS datastore read failures stay visible and recover in the built UI."""

import re

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_datastore_read_failure_is_visible_and_refresh_recovers(browser, layout):
    """A refusal is shown in both PBS views, then a successful retry clears it."""
    datastore_path = '/api/pbs/p1/datastores'
    reads = {
        ('GET', '/api/pbs'): (200, [PBS]),
        ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
        ('GET', datastore_path): (403, {'code': 'PBS_FORBIDDEN',
                                       'error': 'PBS denied the request'}),
    }
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        error = page.get_by_role('alert').filter(has_text='Could not load all data: Datastores')
        error.wait_for(timeout=5000)

        page.get_by_role('button', name='Datastores').first.click()
        error.wait_for(timeout=5000)
        assert page.get_by_role('button', name=re.compile(r'^alpha\b')).count() == 0

        app.server.extra[('GET', datastore_path)] = (200, [{'name': 'alpha'}])
        page.get_by_role('button', name='Refresh').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).wait_for(timeout=5000)
        assert error.count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_switching_pbs_hides_datastores_from_previous_server(browser):
    """A failed read on the next server cannot keep the previous server's cards."""
    other = dict(PBS, id='p2', name='backup02')
    reads = {
        ('GET', '/api/pbs'): (200, [PBS, other]),
        ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
        ('GET', '/api/pbs/p2/status'): (200, {'version': {'version': '4.0'}}),
        ('GET', '/api/pbs/p1/datastores'): (200, [{'name': 'alpha'}]),
        ('GET', '/api/pbs/p2/datastores'): (502, {'code': 'PBS_UNREACHABLE',
                                                'error': 'PBS is unreachable'}),
    }
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_text('alpha', exact=True).wait_for(timeout=5000)

        page.get_by_text('backup02').first.click()
        page.get_by_role('alert').filter(has_text='Could not load all data: Datastores').wait_for(timeout=5000)
        assert page.get_by_text('alpha', exact=True).count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_malformed_successful_datastore_response_is_visible(browser):
    """An unexpected 200 body is reported without crashing the PBS view."""
    reads = {
        ('GET', '/api/pbs'): (200, [PBS]),
        ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
        ('GET', '/api/pbs/p1/datastores'): (200, {'data': []}),
    }
    app = _App(browser, _FakeServer(role='standalone', extra=reads))
    try:
        app.page.get_by_text('backup01').first.click()
        app.page.get_by_role('alert').filter(has_text='Could not load all data: Datastores').wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_failed_refresh_hides_selected_datastore_actions_until_retry(browser, layout):
    """A failed list hides selected-store controls, and a retry restores them."""
    datastore_path = '/api/pbs/p1/datastores'
    reads = {
        ('GET', '/api/pbs'): (200, [PBS]),
        ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
        ('GET', datastore_path): (200, [{'name': 'alpha'}]),
    }
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=reads))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
        page.get_by_role('button', name='Garbage Collection').wait_for(timeout=5000)

        app.server.extra[('GET', datastore_path)] = (403, {'code': 'PBS_FORBIDDEN',
                                                          'error': 'PBS denied the request'})
        page.get_by_role('button', name='Refresh').first.click()
        page.get_by_role('alert').filter(has_text='Could not load all data: Datastores').wait_for(timeout=5000)
        assert page.get_by_role('button', name='Garbage Collection').count() == 0
        assert page.get_by_text('Select a datastore to view details').count() == 1

        app.server.extra[('GET', datastore_path)] = (200, [{'name': 'alpha'}])
        page.get_by_role('button', name='Refresh').first.click()
        page.get_by_role('button', name='Garbage Collection').wait_for(timeout=5000)
        assert page.get_by_role('alert').filter(has_text='Could not load all data: Datastores').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
