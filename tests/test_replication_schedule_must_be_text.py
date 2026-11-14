"""A replication job whose schedule is no text stops no other job.

The create route stored data.get('schedule', ...) as it came, so {"schedule": null}
(anyone with cluster.config on a cluster of their own, a tenant operator too) made a
row with a NULL schedule. The scheduler handed that to _parse_interval_seconds, whose
.strip() raised inside the loop over all jobs: every job stored after that row was
never started again, tick after tick, with one log line a minute.

The scheduler reads a missing schedule as the default now, as the replication alert
already did, and the route answers a schedule that is no string with a 400.
"""
import time
import types
from datetime import datetime, timedelta

import pytest

import pegaprox.background.cross_cluster_replication as xcr
import pegaprox.background.site_recovery as srw
from pegaprox.core import ha

SRC, TGT = 'cluster_1', 'cluster_2'


@pytest.fixture
def admin(api, seed):
    for cid in (SRC, TGT):
        m = api.make_fake_manager(cid)
        m.config = types.SimpleNamespace(name=cid)
        api.set_manager(cid, m)
    return api.as_user(seed.user('root', role='admin'))


def _rows(db):
    return {r['vmid']: r['schedule'] for r in db.query('SELECT vmid, schedule FROM cross_cluster_replications')}


@pytest.mark.parametrize('schedule', [None, 6, ['0 */6 * * *'], {'hours': 6}])
def test_a_schedule_that_is_no_string_is_refused(admin, db, schedule):
    r = admin.post('/api/cross-cluster-replications',
                   json={'source_cluster': SRC, 'target_cluster': TGT, 'vmid': 100, 'schedule': schedule})
    assert r.status_code == 400, (r.status_code, r.get_data(as_text=True))
    assert 'schedule' in r.get_json()['error']
    assert _rows(db) == {}


def test_a_job_without_a_schedule_still_gets_the_default(admin, db):
    for vmid, body in ((100, {}), (101, {'schedule': '*/15'})):
        r = admin.post('/api/cross-cluster-replications',
                       json={'source_cluster': SRC, 'target_cluster': TGT, 'vmid': vmid, **body})
        assert r.status_code == 200, r.get_data(as_text=True)
    assert _rows(db) == {100: '0 */6 * * *', 101: '*/15'}


class _Stop(Exception):
    pass


def _tick(monkeypatch):
    """One pass of the scheduler; the ids of the jobs it started."""
    started = []

    class _Thread:
        def __init__(self, target=None, args=(), daemon=None):
            self.job = args[1]

        def start(self):
            started.append(self.job['id'])
            xcr._release_job(self.job['id'])

    def nap(seconds):
        raise _Stop()
    monkeypatch.setattr(xcr, 'time', types.SimpleNamespace(sleep=nap, time=time.time))
    monkeypatch.setattr(xcr, 'threading', types.SimpleNamespace(Thread=_Thread))
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **kw: True)
    monkeypatch.setattr(srw, 'replay_failover_state', lambda: None)
    monkeypatch.setattr(xcr, '_xcrepl_running', False)
    with pytest.raises(_Stop):
        xcr._xcrepl_loop()
    return sorted(started)


def _job(db, job_id, vmid, schedule, last_run=''):
    db.execute("INSERT INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, enabled, "
               "schedule, last_run, created_at) VALUES (?, ?, ?, ?, 1, ?, ?, '2026-10-01')",
               (job_id, SRC, TGT, vmid, schedule, last_run))


def test_a_stored_null_schedule_does_not_stop_the_jobs_after_it(db, monkeypatch):
    # rows from before the route checked it; the first one is read first
    _job(db, 'jnull', 100, None)
    _job(db, 'jgood', 101, '0 */6 * * *')
    # due under the default 6 hours only after 6 hours
    _job(db, 'jnull-recent', 102, None, (datetime.now() - timedelta(hours=1)).isoformat())
    assert _tick(monkeypatch) == ['jgood', 'jnull']
