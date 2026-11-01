"""PBS datastore lists distinguish an upstream refusal from an empty server."""

from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals


PBS = 'pbs_datastore_errors'
PATH = f'/api/pbs/{PBS}/datastores'


@pytest.fixture
def pbs(api):
    """Expose a connected PBS manager without making a network request."""
    manager = MagicMock()
    manager.connected = True
    manager.linked_clusters = ['cluster_1']
    manager.get_datastores.return_value = {'data': []}
    manager.get_datastore_usage.return_value = {'data': []}
    manager.get_gc_jobs.return_value = {'data': []}
    ppglobals.pbs_managers[PBS] = manager
    try:
        yield manager
    finally:
        ppglobals.pbs_managers.pop(PBS, None)


@pytest.fixture
def admin(api, seed):
    """Use an authorized caller to isolate the PBS response behavior."""
    return api.as_user(seed.user('pbs_datastore_admin', role='admin'))


def test_config_refusal_is_not_an_empty_datastore_list(admin, pbs):
    """A PBS 403 on the required config list reaches the caller as a 403."""
    pbs.get_datastores.return_value = {'error': 'HTTP 403', 'status_code': 403}

    response = admin.get(PATH)

    assert response.status_code == 403
    assert response.get_json()['code'] == 'PBS_FORBIDDEN'


def test_usage_failure_is_not_a_healthy_datastore_list(admin, pbs):
    """A failed required usage read cannot produce a partial success response."""
    pbs.get_datastores.return_value = {'data': [{'name': 'backup'}]}
    pbs.get_datastore_usage.return_value = {'error': 'connection refused'}

    response = admin.get(PATH)

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UNREACHABLE'


def test_genuinely_empty_datastore_list_stays_successful(admin, pbs):
    """An empty PBS config and usage list are a valid empty result."""
    response = admin.get(PATH)

    assert response.status_code == 200
    assert response.get_json() == []


@pytest.mark.parametrize('method,bad_response', [
    ('get_datastores', {'data': None}),
    ('get_datastores', {'data': {}}),
    ('get_datastore_usage', {'data': None}),
    ('get_datastore_usage', {'data': {}}),
])
def test_malformed_required_list_is_an_upstream_error(admin, pbs, method, bad_response):
    """A malformed successful PBS response is neither an empty nor healthy list."""
    getattr(pbs, method).return_value = bad_response

    response = admin.get(PATH)

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'


@pytest.mark.parametrize('failed_method', ['get_datastores', 'get_datastore_usage'])
@pytest.mark.parametrize('reauthenticate', [False, True])
def test_invalid_json_is_not_reported_as_an_outage(admin, pbs, failed_method, reauthenticate):
    """Retain the HTTP response classification when a successful read is malformed."""
    from requests import Response
    from pegaprox.core.pbs import PBSManager

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
    getattr(pbs, failed_method).side_effect = (
        lambda *a, **kw: PBSManager.api_get(upstream, 'config/datastore'))

    result = admin.get(PATH)

    assert result.status_code == 502
    assert result.get_json()['code'] == 'PBS_UPSTREAM'
    assert result.get_json()['upstream_status'] == 200


def test_datastore_error_responses_are_generated_and_published(api):
    """The generated contract distinguishes local denial, PBS refusal and bad reads."""
    import json
    from pathlib import Path
    from pegaprox.cli.gen_openapi import build

    key = '/api/pbs/{pbs_id}/datastores'
    generated = build(api.app)[key]['get']['responses']
    published = json.loads((Path(__file__).parents[1] / 'docs/openapi.json').read_text())
    assert generated['403'] == published['paths'][key]['get']['responses']['403']
    assert generated['502'] == published['paths'][key]['get']['responses']['502']
    schema = generated['502']['content']['application/json']['schema']
    assert set(schema['properties']['code']['enum']) == {'PBS_UNREACHABLE', 'PBS_UPSTREAM'}
    forbidden = generated['403']['content']['application/json']['schema']
    assert 'PBS_FORBIDDEN' in forbidden['properties']['code']['examples']
    assert 'MISSING_PERMISSION' in forbidden['properties']['code']['examples']
    assert 'permission' in generated['403']['description'].lower()


def test_invalid_json_cannot_turn_a_snapshot_read_error_into_http_200(admin, pbs):
    """Other PBS read routes must retain a failing HTTP status for decode errors."""
    from requests import Response
    from pegaprox.core.pbs import PBSManager

    reply = Response()
    reply.status_code, reply._content = 200, b'not json'
    upstream = MagicMock()
    upstream.base_url, upstream.name = 'https://pbs.invalid/api2/json', 'test PBS'
    upstream._session.get.return_value = reply
    pbs.get_snapshots.side_effect = (
        lambda *a, **kw: PBSManager.api_get(upstream, 'admin/datastore/store/snapshots'))

    result = admin.get(f'/api/pbs/{PBS}/datastores/store/snapshots')

    assert result.status_code == 502


@pytest.mark.parametrize('method,key', [('get_datastores', 'name'),
                                       ('get_datastore_usage', 'store')])
@pytest.mark.parametrize('entry', [None, 1, 'bad', [], {}, {'value': None},
                                  {'value': ''}, {'value': []}])
def test_malformed_required_entry_is_an_upstream_error(admin, pbs, method, key, entry):
    """Validate each required row before indexing, merging or fetching details."""
    if isinstance(entry, dict) and 'value' in entry:
        entry = {key: entry['value']}
    getattr(pbs, method).return_value = {'data': [entry]}

    response = admin.get(PATH)

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'
    pbs.get_datastore_status.assert_not_called()


def test_valid_required_entries_still_merge_usage_and_details(admin, pbs):
    """Required row validation preserves nonempty datastore results."""
    pbs.get_datastores.return_value = {'data': [{'name': 'backup', 'path': '/backup'}]}
    pbs.get_datastore_usage.return_value = {'data': [{'store': 'backup', 'total': 1024}]}
    pbs.get_datastore_status.return_value = {'data': {'used': 128}}

    response = admin.get(PATH)

    assert response.status_code == 200
    assert response.get_json() == [{'name': 'backup', 'path': '/backup',
                                   'store': 'backup', 'total': 1024,
                                   'detail': {'used': 128}}]
    pbs.get_datastore_status.assert_called_once_with('backup')
