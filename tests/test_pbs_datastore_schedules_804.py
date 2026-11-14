"""Issue #804: PBS job listings supply datastore schedules and last-run status."""

from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.pbs import PBSManager


PBS = 'pbs_schedules'
JOBS_PATH = f'/api/pbs/{PBS}/jobs'
JOB_LISTS = {
    'sync': [{'id': 'sync-alpha', 'store': 'alpha', 'schedule': 'mon 02:00',
              'last-run-endtime': 1780000010}],
    'verify': [{'id': 'verify-alpha', 'store': 'alpha', 'schedule': 'wed 04:00',
                'last-run-endtime': 1780000020}],
    'prune': [{'id': 'prune-alpha', 'store': 'alpha', 'schedule': 'fri 06:00',
               'last-run-endtime': 1780000030}],
}


@pytest.fixture
def pbs(api):
    """Register a PBS manager with separate, status-bearing job lists."""
    manager = MagicMock()
    manager.linked_clusters = ['cluster_1']
    manager.connected = True
    for kind, rows in JOB_LISTS.items():
        getattr(manager, f'get_{kind}_jobs').return_value = {'data': rows}
    ppglobals.pbs_managers[PBS] = manager
    return manager


@pytest.fixture
def admin(api, seed):
    """Use a fully authorized caller to exercise upstream response handling."""
    return api.as_user(seed.user('schedule_admin', role='admin'))


@pytest.mark.parametrize('kind', ['sync', 'verify', 'prune'])
def test_status_bearing_admin_endpoint_is_used_for_each_job_kind(kind):
    """PBS /config lists omit last-run fields; /admin lists include them."""
    manager = PBSManager.__new__(PBSManager)
    paths = []
    expected = {'data': JOB_LISTS[kind]}
    # the sync list also asks for both directions (#801)
    manager.api_get = lambda path, params=None, **kw: paths.append(path) or expected

    result = getattr(manager, f'get_{kind}_jobs')()

    assert paths == [f'/admin/{kind}']
    assert result['data'][0]['last-run-endtime'] == JOB_LISTS[kind][0]['last-run-endtime']


def test_jobs_route_keeps_schedule_store_and_last_run_for_each_kind(pbs, admin):
    """The browser receives the fields needed for exact datastore matching."""
    response = admin.get(JOBS_PATH)

    assert response.status_code == 200
    assert response.get_json() == JOB_LISTS
    for kind in JOB_LISTS:
        getattr(pbs, f'get_{kind}_jobs').assert_called_once_with()


@pytest.mark.parametrize('kind', ['sync', 'verify', 'prune'])
@pytest.mark.parametrize('upstream,expected_code', [
    ({'error': 'HTTP 403', 'status_code': 403}, 'PBS_FORBIDDEN'),
    ({'error': 'HTTP 500', 'status_code': 500}, 'PBS_UPSTREAM'),
    ({'error': 'Connection refused'}, 'PBS_UNREACHABLE'),
    ({'data': None}, 'PBS_UPSTREAM'),
])
def test_failed_job_listing_keeps_other_kinds(pbs, admin, kind, upstream, expected_code):
    getattr(pbs, f'get_{kind}_jobs').return_value = upstream

    response = admin.get(JOBS_PATH)

    assert response.status_code == 200
    assert response.get_json() == {
        **JOB_LISTS, kind: [], 'errors': {kind: expected_code},
    }
    for name in JOB_LISTS:
        getattr(pbs, f'get_{name}_jobs').assert_called_once_with()


def test_all_job_listings_fail_with_explicit_errors(pbs, admin):
    for kind in JOB_LISTS:
        getattr(pbs, f'get_{kind}_jobs').return_value = {'error': 'HTTP 403', 'status_code': 403}

    response = admin.get(JOBS_PATH)

    assert response.status_code == 200
    assert response.get_json() == {
        'sync': [], 'verify': [], 'prune': [],
        'errors': {kind: 'PBS_FORBIDDEN' for kind in JOB_LISTS},
    }


def test_caller_without_jobs_view_cannot_reach_pbs(api, seed, pbs):
    """The route's jobs-view permission is checked before requesting PBS data."""
    user = seed.user('no_jobs', role='user', denied=['pbs.jobs.view'])
    client = api.as_user(user)

    response = client.get(JOBS_PATH)

    assert response.status_code == 403
    pbs.get_sync_jobs.assert_not_called()


def test_caller_outside_linked_cluster_cannot_reach_pbs(api, seed, pbs):
    """Linked-cluster tenant isolation applies to the status-bearing job list."""
    seed.tenant('elsewhere', clusters=['cluster_2'])
    user = seed.user('elsewhere_op', role='user', tenant_id='elsewhere',
                     permissions=['pbs.jobs.view'])
    client = api.as_user(user)

    response = client.get(JOBS_PATH)

    assert response.status_code == 403
    pbs.get_sync_jobs.assert_not_called()
