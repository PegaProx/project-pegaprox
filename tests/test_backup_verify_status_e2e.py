"""HTTP-level cover for the backup-verification status route.

The scoping fix for these three reads was guarded only by a test that greps
pbs.py for '_verification_rows_visible'. That grep stayed green while the helper
was sitting between the route decorators and the handler — so the URL was served
by the helper, the real handler was unregistered, and nothing noticed. Drive the
route instead. MK
"""
import pytest

import pegaprox.core.backup_verify as bv


CLUSTER = 'cluster_1'
MINE, THEIRS = 100, 200


def _verification(task_id, vmid):
    return {'id': task_id, 'cluster_id': CLUSTER, 'vmid': vmid, 'status': 'running',
            'node': 'pve1', 'progress': 42, 'archive': f'vm/{vmid}/2026-09-04T22:00:00Z'}


@pytest.fixture
def active(monkeypatch):
    """Two in-flight verifications, one per guest."""
    rows = {'task-mine': _verification('task-mine', MINE),
            'task-theirs': _verification('task-theirs', THEIRS)}
    monkeypatch.setattr(bv, 'get_verification', lambda tid: rows.get(tid))
    monkeypatch.setattr(bv, 'get_active_verifications', lambda: dict(rows))
    return rows


@pytest.fixture
def scoped(api, seed):
    """Tenant owns the cluster; the user holds a VM ACL on MINE only."""
    seed.tenant('tenant_a', clusters=[CLUSTER])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['vm.backup'])
    seed.vm_acl(CLUSTER, MINE, ['alice'], permissions=['vm.backup', 'vm.view'])
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    return api.as_user(alice)


def test_status_requires_authentication(api, active):
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))

    r = api.anon().get(f'/api/clusters/{CLUSTER}/backup-verify/task-mine')

    assert r.status_code == 401, r.get_data(as_text=True)[:200]


def test_scoped_caller_reads_back_their_own_verification(scoped, active):
    r = scoped.get(f'/api/clusters/{CLUSTER}/backup-verify/task-mine')

    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert r.get_json()['vmid'] == MINE


def test_scoped_caller_cannot_read_a_co_tenants_verification(scoped, active):
    r = scoped.get(f'/api/clusters/{CLUSTER}/backup-verify/task-theirs')

    assert r.status_code == 404, r.get_data(as_text=True)[:300]
    assert str(THEIRS) not in r.get_data(as_text=True)


def test_admin_reads_either_verification(api, seed, active):
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    root = api.as_user(seed.user('root_admin', role='admin'))

    for task_id, vmid in (('task-mine', MINE), ('task-theirs', THEIRS)):
        r = root.get(f'/api/clusters/{CLUSTER}/backup-verify/{task_id}')
        assert r.status_code == 200, r.get_data(as_text=True)[:300]
        assert r.get_json()['vmid'] == vmid


def test_active_listing_is_scoped_too(scoped, active):
    r = scoped.get(f'/api/clusters/{CLUSTER}/backup-verify/active')

    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    body = r.get_json()          # {task_id: verification}
    assert sorted(body) == ['task-mine'], body
    assert body['task-mine']['vmid'] == MINE
