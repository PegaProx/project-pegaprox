"""A snapshot policy that matches no guest right now is not anybody's to read or change.

Every route on a policy decides for a confined caller by walking the guests the policy
resolves to and denying when one of them is out of reach. A policy whose guests have
left it (deleted, or the tag taken off) resolves to nothing, so there was nothing to
deny: such a caller saw it in the list, read its run log, which names the guests it
snapshotted, and could edit, delete or run it. Now a policy with no current target is
the caller's only when they made it, or when it names its guests by vmid and they may
reach every one. A new target that matches nothing yet stays allowed, so a confined
caller can still point their policy at a guest that is not there yet.
MK Oct 2026
"""
import pytest

import pegaprox.api.snapshots as snaps

from test_guest_paths_low_oct2026 import _owner, _policy_cluster, _scoped, _vm

URL = '/api/clusters/cluster_1/snapshot-policies'


@pytest.fixture
def started(monkeypatch):
    """Run now starts a thread; record the policy instead of running it."""
    runs = []
    monkeypatch.setattr(snaps, '_execute_policy', lambda pid, force=False: runs.append(pid))
    return runs


def _mallory(seed):
    return _scoped(seed, 'mallory', ['vm.snapshot'], pool_perms=('pool.view', 'vm.view', 'vm.snapshot'))


def _policy(db, pid, target_type, target_value, created_by):
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, "
                    "schedule, created_by, created_at) VALUES (?, 'cluster_1', ?, ?, ?, 'daily', ?, "
                    "'2026-10-01')", (pid, f'policy {pid}', target_type, target_value, created_by))
    db.conn.execute("INSERT INTO snapshot_runs (policy_id, started_at, status, log, summary) VALUES "
                    "(?, '2026-10-02', 'ok', '  + qemu/200@n1: auto-snap created', '1 ok')", (pid,))
    db.conn.commit()


def _stored(db, pid):
    row = db.conn.execute('SELECT enabled, target_value, created_by FROM snapshot_policies WHERE id=?',
                          (pid,)).fetchone()
    return tuple(row) if row else None


def _listed(client):
    r = client.get(URL)
    assert r.status_code == 200, r.get_data(as_text=True)
    return {p['id'] for p in r.get_json()['policies']}


def test_a_policy_whose_guests_left_it_is_not_listed_and_its_runs_stay_closed(api, seed, db):
    mal = api.as_user(_mallory(seed))
    seed.user('boss', role='admin')
    # guest 200 lost the tag: the policy matches nothing now
    _policy_cluster(api, [_vm(100), _vm(200)])
    _policy(db, 'boss1', 'tag', 'secretdb', 'boss')
    assert 'boss1' not in _listed(mal)
    r = mal.get(f'{URL}/boss1/runs')
    assert r.status_code == 403 and 'qemu/200' not in r.get_data(as_text=True)
    # counterproof: her own policy that matches nothing stays hers, and the admin sees both
    _policy(db, 'mine', 'tag', 'notyet', 'mallory')
    assert _listed(mal) == {'mine'}
    assert mal.get(f'{URL}/mine/runs').status_code == 200
    assert _listed(api.as_user(seed.user('root', role='admin'))) == {'boss1', 'mine'}


def test_a_vm_policy_with_no_live_guest_goes_by_the_guests_it_names(api, seed, db):
    mal = api.as_user(_mallory(seed))
    seed.user('boss', role='admin')
    # neither guest is in the inventory right now, guest 100 is in her pool
    _policy_cluster(api, [_vm(300)])
    _policy(db, 'hers', 'vm', '100', 'boss')
    _policy(db, 'theirs', 'vm', '100,200', 'boss')
    assert _listed(mal) == {'hers'}
    assert mal.get(f'{URL}/hers/runs').status_code == 200
    assert mal.get(f'{URL}/theirs/runs').status_code == 403


def test_a_policy_whose_guests_left_it_is_not_edited_deleted_or_run(api, seed, db, started):
    mal = api.as_user(_mallory(seed))
    # seeded before the first request reads the tenants
    ops = api.as_user(_owner(seed, 'ops', ['vm.snapshot']))
    seed.user('boss', role='admin')
    _policy_cluster(api, [_vm(100)])
    _policy(db, 'boss1', 'tag', 'secretdb', 'boss')
    before = _stored(db, 'boss1')
    assert mal.put(f'{URL}/boss1', json={'enabled': 0}).status_code == 403
    assert mal.put(f'{URL}/boss1', json={'target_type': 'vm', 'target_value': '100'}).status_code == 403
    assert mal.post(f'{URL}/boss1/run').status_code == 403
    assert mal.delete(f'{URL}/boss1').status_code == 403
    assert _stored(db, 'boss1') == before and started == []
    # counterproof: a cluster-wide operator still manages it
    assert ops.put(f'{URL}/boss1', json={'enabled': 0}).status_code == 200
    assert ops.post(f'{URL}/boss1/run').status_code == 200 and started == ['boss1']
    assert ops.delete(f'{URL}/boss1').status_code == 200 and _stored(db, 'boss1') is None


def test_her_own_policy_that_matches_nothing_stays_hers(api, seed, db, started):
    mal = api.as_user(_mallory(seed))
    _policy_cluster(api, [_vm(100)])
    _policy(db, 'mine', 'vm', '999', 'mallory')
    assert mal.put(f'{URL}/mine', json={'enabled': 0}).status_code == 200
    # a new target that is not there yet is still fine
    r = mal.put(f'{URL}/mine', json={'target_value': '998'})
    assert r.status_code == 200 and r.get_json()['policy']['created_by'] == 'mallory'
    assert mal.post(f'{URL}/mine/run').status_code == 200 and started == ['mine']
    assert mal.delete(f'{URL}/mine').status_code == 200 and _stored(db, 'mine') is None
