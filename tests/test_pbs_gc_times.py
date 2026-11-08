"""When GC ran on a PBS datastore comes from /admin/gc.

PBS keeps the counters of the last GC run in gc-status (the datastore usage list, or the
datastore status with verbose=1) and the end time, state, duration and next run of the GC
job in /admin/gc. The datastore view and the health score read times that gc-status never
carries, so the GC card never showed and the GC age never counted.
"""

import time
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.pbs import PBSManager


PBS = 'pbs_gc'


def _manager(gc_jobs, stores=('alpha', 'beta')):
    mgr = MagicMock()
    mgr.connected = True
    mgr.linked_clusters = ['cluster_1']
    mgr.get_datastores.return_value = {'data': [{'name': s, 'gc-schedule': 'daily'} for s in stores]}
    mgr.get_datastore_usage.return_value = {'data': [
        {'store': 'alpha', 'total': 1000, 'used': 400, 'avail': 600,
         'gc-status': {'upid': 'UPID:pbs:0000:0000:0000:6700A000:garbage_collection:alpha:root@pam:',
                       'index-data-bytes': 3500, 'disk-bytes': 1000, 'disk-chunks': 12}},
    ]}
    mgr.get_datastore_status.return_value = {'data': {'total': 1000, 'used': 400}}
    mgr.get_snapshots.return_value = {'data': []}
    mgr.get_gc_jobs.return_value = gc_jobs
    ppglobals.pbs_managers[PBS] = mgr
    return mgr


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('gc_admin', role='admin'))


def test_the_gc_list_is_read_from_admin_gc():
    mgr = PBSManager.__new__(PBSManager)
    paths = []
    mgr.api_get = lambda path: paths.append(path) or {'data': []}
    mgr.get_gc_jobs()
    assert paths == ['/admin/gc']


def test_each_datastore_carries_its_gc_job(admin):
    job = {'store': 'alpha', 'last-run-endtime': 1780000000, 'last-run-state': 'ok',
           'duration': 75, 'next-run': 1780086400, 'schedule': 'daily'}
    _manager({'data': [job, {'store': 'gone', 'last-run-endtime': 1}]})

    r = admin.get(f'/api/pbs/{PBS}/datastores')

    assert r.status_code == 200
    by_name = {d['name']: d for d in r.get_json()}
    assert by_name['alpha']['gc-job'] == job
    # the counters stay where PBS puts them, next to the usage
    assert by_name['alpha']['gc-status']['index-data-bytes'] == 3500
    # a store without GC history has no job, and no store is made up from the list
    assert 'gc-job' not in by_name['beta']
    assert set(by_name) == {'alpha', 'beta'}


@pytest.mark.parametrize('answer', [
    {'error': 'HTTP 404', 'status_code': 404},     # a PBS without /admin/gc
    {'error': 'HTTP 403', 'status_code': 403},     # a token that may not read it
    {'data': None},
    {'data': ['alpha', None, {'store': 7}]},
])
def test_without_a_usable_gc_list_the_datastores_still_load(admin, answer):
    _manager(answer)

    r = admin.get(f'/api/pbs/{PBS}/datastores')

    assert r.status_code == 200
    assert [d['name'] for d in r.get_json()] == ['alpha', 'beta']
    assert all('gc-job' not in d for d in r.get_json())


def test_a_gc_list_that_raises_does_not_break_the_datastores(admin):
    _manager({})
    ppglobals.pbs_managers[PBS].get_gc_jobs.side_effect = RuntimeError('boom')

    r = admin.get(f'/api/pbs/{PBS}/datastores')

    assert r.status_code == 200
    assert len(r.get_json()) == 2


def _gc_factor(client):
    r = client.get(f'/api/pbs/{PBS}/health')
    assert r.status_code == 200
    return next((f for f in r.get_json()['factors'] if f['key'] == 'gc'), None)


def test_an_old_gc_run_lowers_the_health_score(admin):
    _manager({'data': [{'store': 'alpha', 'last-run-endtime': int(time.time()) - 40 * 86400}]})

    factor = _gc_factor(admin)

    assert factor is not None and factor['delta'] == -10 and factor['severity'] == 'warning'


def test_a_recent_gc_run_counts_as_ok(admin):
    _manager({'data': [{'store': 'alpha', 'last-run-endtime': int(time.time()) - 3600}]})

    factor = _gc_factor(admin)

    assert factor is not None and factor['delta'] == 0 and factor['severity'] == 'ok'


@pytest.mark.parametrize('endtime', ['1780000000', None, True, 0, -5])
def test_a_gc_time_that_is_no_time_is_left_out(admin, endtime):
    _manager({'data': [{'store': 'alpha', 'last-run-endtime': endtime}]})

    assert _gc_factor(admin) is None
