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
