"""A PBS job that PBS refuses to start is an error, as a refused verify is.

Running a sync, verify or prune job handed PBS's refusal back under a 200, so the UI
went by the status and said "job started" over nothing.
"""
from unittest.mock import MagicMock, patch

import pytest

import pegaprox.globals as g

RUNS = [('sync', 'run_sync_job'), ('verify', 'run_verify_job'), ('prune', 'run_prune_job')]
REFUSAL = {'error': 'job is already running'}


@pytest.fixture
def client(api, seed, db):
    mgr = MagicMock()
    mgr.name = 'pbs'
    g.pbs_managers['x'] = mgr
    with patch('pegaprox.api.pbs.check_pbs_access', return_value=(True, None)), \
            patch('pegaprox.api.pbs.require_pbs_wide', return_value=None):
        yield api.as_user(seed.user('adm', role='admin')), mgr
    g.pbs_managers.pop('x', None)


@pytest.mark.parametrize('job_type,method', RUNS)
def test_a_refused_run_answers_what_a_refused_verify_answers(client, job_type, method):
    """The operator sees a 502 with PBS's reason, the same as for a refused datastore verify."""
    c, mgr = client
    getattr(mgr, method).return_value = dict(REFUSAL)
    mgr.start_verify.return_value = dict(REFUSAL)
    r = c.post(f'/api/pbs/x/jobs/{job_type}/daily/run')
    neighbour = c.post('/api/pbs/x/datastores/s/verify', json={})
    assert r.status_code == 502, r.get_json()
    assert r.get_json() == REFUSAL
    assert (r.status_code, r.get_json()) == (neighbour.status_code, neighbour.get_json())


@pytest.mark.parametrize('job_type,method', RUNS)
def test_an_accepted_run_answers_the_same_200_with_the_task_id(client, job_type, method):
    """The operator sees the 200 with the task id PBS returned, as before."""
    c, mgr = client
    getattr(mgr, method).return_value = {'data': 'UPID:pbs:1'}
    r = c.post(f'/api/pbs/x/jobs/{job_type}/daily/run')
    assert r.status_code == 200
    assert r.get_json() == {'data': 'UPID:pbs:1'}


@pytest.mark.parametrize('job_type,method', RUNS)
def test_the_manager_gets_the_job_type_and_the_job_id(client, job_type, method):
    """The click starts the job with that id on the manager method for its kind, and no other."""
    c, mgr = client
    getattr(mgr, method).return_value = {'data': 'UPID:pbs:1'}
    c.post(f'/api/pbs/x/jobs/{job_type}/daily-3am/run')
    getattr(mgr, method).assert_called_once_with('daily-3am')
    for other_job, other_method in RUNS:
        if other_method != method:
            getattr(mgr, other_method).assert_not_called()


def test_an_unknown_pbs_server_is_a_404(client):
    """The operator picks a PBS server that is not connected and sees 'PBS server not found'."""
    c, mgr = client
    r = c.post('/api/pbs/nope/jobs/sync/daily/run')
    assert r.status_code == 404
    assert r.get_json() == {'error': 'PBS server not found'}
