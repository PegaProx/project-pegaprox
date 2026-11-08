# E2E for the Round-2 audit findings — all regressions introduced by Round-1 fixes:
#   HIGH  pool-member ADD: #766's gate-lowering (admin.users -> pool.assign, a default ROLE_USER perm)
#         let a pool-scoped caller re-pool a FOREIGN VM into a pool they control and self-grant access.
#   MED   pool-member REMOVE: mirror — detach any VM from any reachable pool.
#   MED   SSE 'tasks' frame dropped node/cluster tasks for PLAIN cluster-wide operators too (should
#         only confine pool-/ACL-scoped clients), inconsistent with the REST /clusters/<id>/tasks view.
import json
import queue
import time
import types

import pegaprox.utils.rbac as rbac
import pegaprox.globals as ppglobals
from pegaprox.utils.realtime import broadcast_sse


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=['pool.assign'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _mgr_ok(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m._api_put.return_value = types.SimpleNamespace(status_code=200, text='{"data":null}')
    return m


# ── HIGH: pool-member add BOLA ────────────────────────────────────────────────
def test_add_foreign_vm_to_own_pool_denied(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_ok(api))
    # 999 is outside mallory's grant → assigning it must not self-grant access
    resp = api.as_user(u).post('/api/clusters/cluster_1/pools/pool_1/members', json={'vmid': 999, 'type': 'qemu'})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_add_own_vm_to_unmanaged_pool_denied(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_ok(api))
    # mallory can access VM 100, but pool_2 is not a pool she manages
    resp = api.as_user(u).post('/api/clusters/cluster_1/pools/pool_2/members', json={'vmid': 100, 'type': 'qemu'})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_add_own_vm_to_own_pool_allowed(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_ok(api))
    # the legit #766 use case: assign a VM you can access to a pool you manage
    resp = api.as_user(u).post('/api/clusters/cluster_1/pools/pool_1/members', json={'vmid': 100, 'type': 'qemu'})
    assert resp.status_code == 200, resp.get_data(as_text=True)


def test_remove_foreign_vm_denied(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_ok(api))
    resp = api.as_user(u).delete('/api/clusters/cluster_1/pools/pool_1/members/999')
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_admin_add_passes_gate(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _mgr_ok(api))
    resp = api.as_user(admin).post('/api/clusters/cluster_1/pools/pool_1/members', json={'vmid': 999, 'type': 'qemu'})
    assert resp.status_code == 200, resp.get_data(as_text=True)  # admin manages all → gate passes


# ── MED: SSE 'tasks' plain-operator regression ────────────────────────────────
def _register(user, is_admin, clusters):
    q = queue.Queue()
    cid = f'test-r2-{user}'
    with ppglobals.sse_clients_lock:
        ppglobals.sse_clients[cid] = {'queue': q, 'user': user, 'clusters': clusters,
                                      'is_admin': is_admin, 'connected_at': 'x', 'auth_method': 'test'}
    return q, cid


def _drain(q):
    out = []
    try:
        while True:
            out.append(json.loads(q.get_nowait()))
    except queue.Empty:
        pass
    return out


_TASKS = [{'vmid': 100, 'type': 'qmstart'}, {'vmid': 101, 'type': 'qmstop'}, {'node': 'n1', 'type': 'vzdump'}]


def test_sse_tasks_plain_operator_gets_full_log(api, seed):
    # otto: tenant owns cluster_1, NO pool grant → plain cluster-wide operator → full task frame
    seed.tenant('tenant_y', clusters=['cluster_1'])
    seed.user('otto', role='viewer', tenant_id='tenant_y')
    rbac.tenants_db = {}
    oq, ocid = _register('otto', is_admin=False, clusters=['cluster_1'])
    try:
        broadcast_sse('tasks', list(_TASKS), 'cluster_1')
        rows = _drain(oq)
        assert len(rows) == 1 and len(rows[0]['data']) == 3, "plain operator must keep node/cluster tasks"
    finally:
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(ocid, None)


def test_sse_tasks_pool_user_still_scoped(api, seed):
    _pool_user(seed)
    mq, mcid = _register('mallory', is_admin=False, clusters=['cluster_1'])
    try:
        broadcast_sse('tasks', list(_TASKS), 'cluster_1')
        rows = _drain(mq)
        assert len(rows) == 1
        assert sorted(t['vmid'] for t in rows[0]['data']) == [100], "pool user still confined to their VM's tasks"
    finally:
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(mcid, None)
