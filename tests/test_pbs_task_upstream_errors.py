"""PBS task reads must distinguish upstream refusals from empty task data."""

from unittest.mock import MagicMock

import pytest

from pegaprox.globals import pbs_managers


PBS_ID = 'pbs_tasks_error'
UPID = 'UPID:pbs:0000A1B2:00003C4D:00005E6F:68AB1F00:backup:store1:vm/100/68ab1f00:root@pam:'


@pytest.fixture
def task_client(api, seed):
    """Provide an admin and a PBS manager with successful empty task responses."""
    mgr = MagicMock()
    mgr.connected = True
    mgr.linked_clusters = []
    mgr.get_tasks.return_value = {'data': []}
    mgr.get_task_status.return_value = {'data': {'status': 'stopped'}}
    mgr.get_task_log.return_value = {'data': []}
    pbs_managers[PBS_ID] = mgr
    try:
        yield api.as_user(seed.user('task_admin', role='admin')), mgr
    finally:
        pbs_managers.pop(PBS_ID, None)


@pytest.mark.parametrize('failure,expected_status,expected_code', [
    ({'error': 'HTTP 403', 'status_code': 403}, 403, 'PBS_FORBIDDEN'),
    ({'error': 'connection timed out'}, 502, 'PBS_UNREACHABLE'),
])
def test_task_list_surfaces_upstream_failure(task_client, failure, expected_status, expected_code):
    """A refused or unreachable PBS task list is not an empty successful list."""
    client, mgr = task_client
    mgr.get_tasks.return_value = failure

    response = client.get(f'/api/pbs/{PBS_ID}/tasks')

    assert response.status_code == expected_status
    assert response.get_json()['code'] == expected_code


@pytest.mark.parametrize('failed_method', ['get_task_status', 'get_task_log'])
def test_task_detail_surfaces_upstream_refusal(task_client, failed_method):
    """Either failed PBS read makes the whole task detail a refusal."""
    client, mgr = task_client
    getattr(mgr, failed_method).return_value = {'error': 'HTTP 403', 'status_code': 403}

    response = client.get(f'/api/pbs/{PBS_ID}/tasks/{UPID}')

    assert response.status_code == 403
    assert response.get_json()['code'] == 'PBS_FORBIDDEN'


def test_task_detail_surfaces_transport_failure(task_client):
    """A transport failure in the log fetch cannot look like a blank log."""
    client, mgr = task_client
    mgr.get_task_log.return_value = {'error': 'connection timed out'}

    response = client.get(f'/api/pbs/{PBS_ID}/tasks/{UPID}')

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UNREACHABLE'


def test_empty_task_list_and_log_remain_successful(task_client):
    """Genuinely empty PBS data remains a normal 200 response."""
    client, _mgr = task_client

    listing = client.get(f'/api/pbs/{PBS_ID}/tasks')
    detail = client.get(f'/api/pbs/{PBS_ID}/tasks/{UPID}')

    assert listing.status_code == 200 and listing.get_json() == []
    assert detail.status_code == 200 and detail.get_json() == {
        'status': {'status': 'stopped'}, 'log': [],
    }


@pytest.mark.parametrize('failed_method', ['get_tasks', 'get_task_status', 'get_task_log'])
@pytest.mark.parametrize('reauthenticate', [False, True])
def test_malformed_json_is_an_upstream_response_error(task_client, failed_method, reauthenticate):
    """A responding PBS with invalid JSON is not an unreachable PBS."""
    from requests import Response
    from pegaprox.core.pbs import PBSManager

    client, mgr = task_client
    response = Response()
    response.status_code, response._content = 200, b'not json'
    upstream = MagicMock()
    upstream.base_url, upstream.name = 'https://pbs.invalid/api2/json', 'test PBS'
    upstream.connect.return_value = True
    if reauthenticate:
        expired = Response()
        expired.status_code = 401
        upstream._session.get.side_effect = [expired, response]
    else:
        upstream._session.get.return_value = response
    getattr(mgr, failed_method).side_effect = (
        lambda *a, **kw: PBSManager.api_get(upstream, 'nodes/localhost/tasks'))

    path = f'/api/pbs/{PBS_ID}/tasks'
    if failed_method != 'get_tasks':
        path += f'/{UPID}'
    result = client.get(path)

    assert result.status_code == 502
    assert result.get_json()['code'] == 'PBS_UPSTREAM'
    assert result.get_json()['upstream_status'] == 200


@pytest.mark.parametrize('row', [None, 0, 'bad row', []])
@pytest.mark.parametrize('scoped', [False, True])
def test_malformed_task_rows_are_rejected_before_scoping(task_client, monkeypatch, row, scoped):
    """Malformed rows are 502 responses for scoped and unconfined callers alike."""
    import pegaprox.api.pbs as pbs_api

    client, mgr = task_client
    monkeypatch.setattr(pbs_api, 'acts_as_admin', lambda user: False)
    monkeypatch.setattr(pbs_api, '_caller_is_scoped_here', lambda manager, user: scoped)
    mgr.get_tasks.return_value = {'data': [row]}

    result = client.get(f'/api/pbs/{PBS_ID}/tasks')

    assert result.status_code == 502
    assert result.get_json()['code'] == 'PBS_UPSTREAM'


def test_invalid_json_cannot_turn_a_snapshot_read_error_into_http_200(task_client):
    """Other PBS read routes must retain a failing HTTP status for decode errors."""
    from requests import Response
    from pegaprox.core.pbs import PBSManager

    client, mgr = task_client
    reply = Response()
    reply.status_code, reply._content = 200, b'not json'
    upstream = MagicMock()
    upstream.base_url, upstream.name = 'https://pbs.invalid/api2/json', 'test PBS'
    upstream._session.get.return_value = reply
    mgr.get_snapshots.side_effect = (
        lambda *a, **kw: PBSManager.api_get(upstream, 'admin/datastore/store/snapshots'))

    result = client.get(f'/api/pbs/{PBS_ID}/datastores/store/snapshots')

    assert result.status_code == 502


@pytest.mark.parametrize('field', ['upid', 'worker_type', 'worker_id', 'user', 'status'])
@pytest.mark.parametrize('value', [{}, ['value'], 42, True])
@pytest.mark.parametrize('scoped', [False, True])
def test_invalid_task_text_fields_are_upstream_errors(task_client, monkeypatch, field, value, scoped):
    """Reject malformed displayed/action fields before rendering or tenant filtering."""
    import pegaprox.api.pbs as pbs_api

    client, mgr = task_client
    monkeypatch.setattr(pbs_api, 'acts_as_admin', lambda user: False)
    monkeypatch.setattr(pbs_api, '_caller_is_scoped_here', lambda manager, user: scoped)
    mgr.get_tasks.return_value = {'data': [{field: value}]}

    result = client.get(f'/api/pbs/{PBS_ID}/tasks')

    assert result.status_code == 502
    assert result.get_json()['code'] == 'PBS_UPSTREAM'


@pytest.mark.parametrize('field', ['starttime', 'endtime'])
@pytest.mark.parametrize('value', [{}, [], '123', True, 1.5])
def test_invalid_task_timestamp_fields_are_upstream_errors(task_client, field, value):
    """PBS task timestamps are integer seconds, not structured or coerced values."""
    client, mgr = task_client
    mgr.get_tasks.return_value = {'data': [{field: value}]}

    result = client.get(f'/api/pbs/{PBS_ID}/tasks')

    assert result.status_code == 502
    assert result.get_json()['code'] == 'PBS_UPSTREAM'


@pytest.mark.parametrize('row', [
    {},
    {'worker_type': None, 'worker_id': None, 'status': None, 'endtime': None},
    {'upid': UPID, 'worker_type': 'backup', 'worker_id': None,
     'starttime': 1756045056, 'user': 'root@pam'},
    {'upid': UPID, 'worker_type': 'backup', 'worker_id': 'store1:vm/100/68ab1f00',
     'starttime': 1756045056, 'endtime': 1756045057, 'status': 'WARNINGS: 1',
     'user': 'root@pam'},
])
def test_valid_optional_task_fields_remain_unchanged(task_client, row):
    """Optional running-task fields stay optional and successful rows are preserved."""
    client, mgr = task_client
    mgr.get_tasks.return_value = {'data': [row]}

    result = client.get(f'/api/pbs/{PBS_ID}/tasks')

    assert result.status_code == 200
    assert result.get_json() == [row]


@pytest.mark.parametrize('needle', ['backup', 'sync-job', '', 'job with spaces', 'a' * 256])
def test_task_typefilter_preserves_pbs_substring_contract(task_client, needle):
    """PBS defines a plain substring filter without a restricted name format."""
    client, manager = task_client

    response = client.get(f'/api/pbs/{PBS_ID}/tasks', query_string={'typefilter': needle})

    assert response.status_code == 200
    manager.get_tasks.assert_called_once_with(limit=50, typefilter=needle, running=None)


@pytest.mark.parametrize('status', [
    {'status': {}}, {'status': []}, {'status': 42}, {'status': True},
    {'status': 'stopped', 'exitstatus': {}},
    {'status': 'stopped', 'exitstatus': []},
    {'status': 'stopped', 'exitstatus': 42},
    {'status': 'stopped', 'exitstatus': True},
])
def test_task_detail_content_rejects_malformed_displayed_status(task_client, status):
    """Malformed displayed status cannot reach the task-log React view as success."""
    client, mgr = task_client
    mgr.get_task_status.return_value = {'data': status}

    response = client.get(f'/api/pbs/{PBS_ID}/tasks/{UPID}')

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'
    mgr.get_task_log.assert_not_called()


@pytest.mark.parametrize('entry', [
    None, 0, 'line', [], {'t': {}}, {'t': []}, {'t': 42}, {'d': []}, {'d': True},
])
def test_task_detail_content_rejects_malformed_log_entries(task_client, entry):
    """Each log entry must support the displayed text fields, not just the list."""
    client, mgr = task_client
    mgr.get_task_log.return_value = {'data': [{'n': 1, 't': 'valid line'}, entry]}

    response = client.get(f'/api/pbs/{PBS_ID}/tasks/{UPID}')

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'


@pytest.mark.parametrize('status,log', [
    ({}, []),
    ({'status': None, 'exitstatus': None}, [{'t': None, 'd': None}]),
    ({'status': 'running', 'id': None}, []),
    ({'status': 'stopped', 'exitstatus': None},
     [{'n': 1, 't': ''}, {'t': None, 'd': 'legacy fallback'}, {}]),
    ({'status': 'stopped', 'exitstatus': 'OK'},
     [{'n': 1, 't': 'finished'}, {'d': 'legacy line'}, {'t': None, 'd': None}]),
])
def test_task_detail_content_preserves_optional_fields(task_client, status, log):
    """Existing missing/null text fallbacks, empty logs and legacy text stay valid."""
    client, mgr = task_client
    mgr.get_task_status.return_value = {'data': status}
    mgr.get_task_log.return_value = {'data': log}

    response = client.get(f'/api/pbs/{PBS_ID}/tasks/{UPID}')

    assert response.status_code == 200
    assert response.get_json() == {'status': status, 'log': log}


def test_openapi_task_read_failures_are_machine_readable(api):
    """Generated and published task-read contracts expose their real HTTP502 response."""
    import json
    from pathlib import Path
    from pegaprox.cli.gen_openapi import build

    generated = build(api.app)
    committed = json.loads((Path(__file__).parents[1] / 'docs/openapi.json').read_text())['paths']
    for paths in (generated, committed):
        for path in ('/api/pbs/{pbs_id}/tasks', '/api/pbs/{pbs_id}/tasks/{upid}'):
            assert {'200', '400', '401', '403', '502'} <= set(paths[path]['get']['responses'])
        assert '502' not in paths['/api/pbs/{pbs_id}/tasks/{upid}']['delete']['responses']
