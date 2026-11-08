# Full-stack E2E for the 2026-09 audit M3: GET /api/clusters/<id>/tasks returned the whole cluster
# task log (per-VM UPIDs, PVE users) to any cluster-reaching caller. A pool-/ACL-scoped caller now
# sees only tasks for VMs they can access; admins and plain cluster-wide operators keep the full log.
import time

import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


_TASKS = [
    {'id': 100, 'type': 'qmstart', 'node': 'n1', 'user': 'root@pam'},
    {'id': 101, 'type': 'qmstop', 'node': 'n1', 'user': 'root@pam'},
    {'node': 'n1', 'type': 'vzdump', 'user': 'root@pam'},   # node-level task, no vmid
]


def _mgr(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_tasks.return_value = list(_TASKS)
    return m


def test_tasks_pool_user_scoped(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    api.set_manager('cluster_1', _mgr(api))
    resp = api.as_user(u).get('/api/clusters/cluster_1/tasks')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    ids = sorted(t.get('id') for t in resp.get_json())
    assert ids == [100], f"pool user must only see their VM's tasks, got {ids}"


def test_tasks_admin_full_log(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _mgr(api))
    resp = api.as_user(admin).get('/api/clusters/cluster_1/tasks')
    assert len(resp.get_json()) == 3, "admin sees the full task log incl. node tasks"


def test_tasks_plain_operator_full_log(api, seed):
    # plain operator: tenant owns the cluster, NO pool grant → keeps the full task log
    seed.tenant('tenant_y', clusters=['cluster_1'])
    otto = seed.user('otto', role='viewer', tenant_id='tenant_y')
    rbac.tenants_db = {}
    api.set_manager('cluster_1', _mgr(api))
    resp = api.as_user(otto).get('/api/clusters/cluster_1/tasks')
    assert len(resp.get_json()) == 3, "plain operator keeps cluster-wide task visibility"
