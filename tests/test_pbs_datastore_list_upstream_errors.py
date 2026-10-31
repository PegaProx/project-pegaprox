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
