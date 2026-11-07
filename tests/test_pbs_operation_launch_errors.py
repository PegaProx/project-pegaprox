"""PBS operation launch failures must not masquerade as successful starts."""

from unittest.mock import MagicMock, patch

import pytest
import json
from pathlib import Path

import pegaprox.globals as ppglobals
from pegaprox.cli.gen_openapi import build


PBS = 'pbs_launch_errors'
VALID_UPIDS = [
    'UPID:pbs:00001234:0000ABCD:00000001:65000000:garbage_collection:alpha:root@pam:',
    'UPID:pbs:00001234:10000ABCD:0000000000000001:65000000:sync::root@pam!token:',
]
OPERATIONS = [
    (f'/api/pbs/{PBS}/datastores/backup/gc', 'start_gc'),
    (f'/api/pbs/{PBS}/datastores/backup/verify', 'start_verify'),
    (f'/api/pbs/{PBS}/datastores/backup/prune', 'prune_datastore'),
    (f'/api/pbs/{PBS}/jobs/sync/daily/run', 'run_sync_job'),
    (f'/api/pbs/{PBS}/jobs/verify/daily/run', 'run_verify_job'),
    (f'/api/pbs/{PBS}/jobs/prune/daily/run', 'run_prune_job'),
]


@pytest.mark.parametrize('source', ['generated', 'committed', 'served'])
@pytest.mark.parametrize('path', [
    '/api/pbs/{pbs_id}/datastores/{store}/gc',
    '/api/pbs/{pbs_id}/datastores/{store}/verify',
    '/api/pbs/{pbs_id}/datastores/{store}/prune',
    '/api/pbs/{pbs_id}/jobs/{job_type}/{job_id}/run',
])
def test_launch_api_reference_documents_the_upstream_failure(api, admin, source, path):
    """External clients see the same 502 contract as the launch routes return."""
    if source == 'generated':
        paths = build(api.app)
    elif source == 'committed':
        paths = json.loads((Path(__file__).parents[1] / 'docs/openapi.json').read_text())['paths']
    else:
        import pegaprox.api.settings as settings
        settings._openapi_doc.clear()
        try:
            response = admin.get('/api/pegaprox/openapi.json')
            assert response.status_code == 200
            paths = response.get_json()['paths']
        finally:
            settings._openapi_doc.clear()
    responses = paths[path]['post']['responses']
    assert '502' in responses
    assert {'200', '400', '401', '403'} <= responses.keys()


@pytest.fixture
def pbs(api):
    """Expose one connected fake PBS manager without network requests."""
    manager = MagicMock()
    manager.name = 'backup01'
    manager.connected = True
    manager.linked_clusters = ['cluster_1']
    ppglobals.pbs_managers[PBS] = manager
    try:
        yield manager
    finally:
        ppglobals.pbs_managers.pop(PBS, None)


@pytest.fixture
def admin(api, seed):
    """Use an authorized caller so only upstream launch behavior is tested."""
    return api.as_user(seed.user('pbs_launch_admin', role='admin'))


@pytest.mark.parametrize('path,method', OPERATIONS)
def test_upstream_refusal_uses_the_shared_502_contract(admin, pbs, path, method):
    """Launch refusals retain the same envelope as the upstream PBS helper."""
    result = {'error': 'permission denied', 'status_code': 403}
    getattr(pbs, method).return_value = result

    with patch('pegaprox.api.pbs.log_audit') as audit:
        response = admin.post(path, json={})

    assert response.status_code == 502
    assert response.get_json() == result
    audit.assert_not_called()


@pytest.mark.parametrize('path,method', OPERATIONS)
def test_transport_failure_keeps_the_shared_error_envelope(admin, pbs, path, method):
    """Launch errors use the existing helper, without changing read-route policy."""
    result = {'error': 'connection refused'}
    getattr(pbs, method).return_value = result

    with patch('pegaprox.api.pbs.log_audit') as audit:
        response = admin.post(path, json={})

    assert response.status_code == 502
    assert response.get_json() == result
    audit.assert_not_called()


@pytest.mark.parametrize('path,method', OPERATIONS)
@pytest.mark.parametrize('result', [None, {}, {'data': None}, {'data': []},
                                    {'data': 'not-a-task-id'}, {'data': 'UPID:'},
                                    {'data': 'UPID:launched'},
                                    {'data': VALID_UPIDS[0][:-1]},
                                    {'data': VALID_UPIDS[0] + '\n'}])
def test_missing_launch_result_is_not_a_success(admin, pbs, path, method, result):
    """Missing or invalid PBS task IDs are insufficient to claim a launch."""
    getattr(pbs, method).return_value = result

    with patch('pegaprox.api.pbs.log_audit') as audit:
        response = admin.post(path, json={})

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'
    audit.assert_not_called()


@pytest.mark.parametrize('path,method', OPERATIONS)
@pytest.mark.parametrize('upid', VALID_UPIDS)
def test_successful_launch_keeps_the_original_result(admin, pbs, path, method, upid):
    """A valid PBS launch stays 200 and returns the upstream task identifier."""
    getattr(pbs, method).return_value = {'data': upid}

    with patch('pegaprox.api.pbs.log_audit') as audit:
        response = admin.post(path, json={})

    audit.assert_called_once()
    assert response.status_code == 200
    assert response.get_json() == {'data': upid}



@pytest.mark.parametrize('result', [{'data': None}, {'data': 'UPID:pbs:1'},
                                    {'error': 'snapshot is protected'}])
def test_snapshot_delete_keeps_the_existing_helper_contract(admin, pbs, result):
    """Snapshot deletion is not a worker launch and needs no worker UPID."""
    pbs.delete_snapshot.return_value = result
    with patch('pegaprox.api.pbs._authz_pbs_backup', return_value=(True, None)):
        response = admin.delete(f'/api/pbs/{PBS}/datastores/backup/snapshots', json={
            'backup_type': 'vm', 'backup_id': '100', 'backup_time': 1,
        })
    assert response.status_code == (502 if 'error' in result else 200)
    assert response.get_json() == result
