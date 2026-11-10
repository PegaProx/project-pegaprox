"""A snapshot policy that could not read the guest list has not run.

get_vm_resources() answers a timeout with an empty list that says so, and `or []` threw that away. The run ended completed with "0
targets" and stamped the policy, so a daily one was blocked for 23 hours and a weekly one for 6 days with nothing done.
"""
import pytest

import pegaprox.api.snapshots as snaps
from pegaprox.core.manager import UnreadList


def _policy(db, seed, schedule='daily'):
    seed.user('adm', role='admin')
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, enabled, created_by, "
                    "created_at) VALUES ('p1','c1','p','tag','prod',?,1,'adm','2026-01-01T00:00:00')", (schedule,))
    db.conn.commit()


def _run(api, db, answer):
    mgr = api.make_fake_manager(cluster_id='c1')
    mgr.get_vm_resources.return_value = answer
    api.set_manager('c1', mgr)
    snaps._execute_policy('p1')
    run = db.conn.execute("SELECT status, summary FROM snapshot_runs WHERE policy_id='p1'").fetchone()
    pol = db.conn.execute("SELECT last_run_at, last_run_status FROM snapshot_policies WHERE id='p1'").fetchone()
    return run, pol


def test_an_unread_list_is_a_failed_run_and_the_policy_stays_due(api, seed, db):
    _policy(db, seed)
    run, pol = _run(api, db, UnreadList())
    assert run['status'] == 'failed' and run['summary'] == 'target resolution failed'
    assert pol['last_run_status'] == 'failed' and not pol['last_run_at']


def test_an_empty_list_that_was_read_still_means_nothing_matches(api, seed, db):
    _policy(db, seed)
    run, pol = _run(api, db, [])
    assert run['status'] == 'completed'
    assert pol['last_run_at']


def test_a_once_policy_stays_used_up_as_it_was_decided(api, seed, db):
    """A once policy is stamped first (#586) so that an early exit cannot fire it each minute. The failed run at least says so now."""
    _policy(db, seed, schedule='once')
    run, pol = _run(api, db, UnreadList())
    assert run['status'] == 'failed' and pol['last_run_at'] and pol['last_run_status'] == 'failed'


# -- the routes: a cluster that does not answer keeps an admin at work, a confined caller out --

from test_guest_paths_low_oct2026 import _policy_cluster, _scoped, _vm  # noqa: E402

URL = '/api/clusters/cluster_1/snapshot-policies'


@pytest.fixture
def silent_cluster(api, monkeypatch):
    """A cluster whose guest list read timed out, and a run-now that only records."""
    runs = []
    monkeypatch.setattr(snaps, '_execute_policy', lambda pid, force=False: runs.append(pid))
    m = _policy_cluster(api, [])
    m.get_vm_resources.return_value = UnreadList('timed out')
    return runs


def _row(db, pid):
    row = db.conn.execute('SELECT enabled FROM snapshot_policies WHERE id=?', (pid,)).fetchone()
    return None if row is None else row['enabled']


def _stored(db, pid, owner):
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, enabled, "
                    "created_by, created_at) VALUES (?, 'cluster_1', 'p', 'tag', 'prod', 'daily', 1, ?, '2026-01-01')",
                    (pid, owner))
    db.conn.commit()


def test_an_admin_manages_policies_while_the_cluster_does_not_answer(api, seed, db, silent_cluster):
    admin = api.as_user(seed.user('root', role='admin'))
    _stored(db, 'p1', 'root')
    assert admin.put(f'{URL}/p1', json={'enabled': 0}).status_code == 200 and _row(db, 'p1') == 0
    assert admin.post(f'{URL}/p1/run').status_code == 200 and silent_cluster == ['p1']
    made = admin.post(URL, json={'name': 'new', 'target_type': 'tag', 'target_value': 'prod'})
    assert made.status_code == 200, made.get_data(as_text=True)
    assert admin.delete(f'{URL}/p1').status_code == 200 and _row(db, 'p1') is None


def test_a_confined_caller_is_refused_while_the_cluster_does_not_answer(api, seed, db, silent_cluster):
    seed.user('boss', role='admin')
    mal = api.as_user(_scoped(seed, 'mallory', ['vm.snapshot'], pool_perms=('pool.view', 'vm.view', 'vm.snapshot')))
    _stored(db, 'boss1', 'boss')
    # nothing could be walked to deny, so nothing is allowed
    r = mal.post(URL, json={'name': 'new', 'target_type': 'tag', 'target_value': 'prod'})
    assert r.status_code == 400 and 'failed to resolve targets' in r.get_json()['error']
    assert db.conn.execute("SELECT COUNT(*) FROM snapshot_policies WHERE name='new'").fetchone()[0] == 0
    assert mal.put(f'{URL}/boss1', json={'enabled': 0}).status_code in (400, 403)
    assert mal.post(f'{URL}/boss1/run').status_code in (400, 403)
    assert mal.delete(f'{URL}/boss1').status_code in (400, 403)
    assert _row(db, 'boss1') == 1 and silent_cluster == []
