# E2E for the 2026-09 audit M1: the SSE stream only per-VM-filtered the 'resources' frame; the
# 'vm_config' frame (full VM config incl. possible cloud-init secrets) and per-VM 'tasks' rows were
# broadcast cluster-wide to any subscribed non-admin. Drives the REAL broadcast_sse against
# registered client queues (there is no request context for SSE, matching production).
import json
import queue
import time

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac
from pegaprox.utils.realtime import broadcast_sse


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _register(user, is_admin, clusters):
    q = queue.Queue()
    cid = f'test-sse-{user}'
    with ppglobals.sse_clients_lock:
        ppglobals.sse_clients[cid] = {
            'queue': q, 'user': user, 'clusters': clusters, 'is_admin': is_admin,
            'connected_at': 'x', 'auth_method': 'test',
        }
    return q, cid


def _drain(q):
    out = []
    try:
        while True:
            out.append(json.loads(q.get_nowait()))
    except queue.Empty:
        pass
    return out


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})


def test_vm_config_frame_scoped(db, seed):
    _pool_user(seed)
    mq, mcid = _register('mallory', is_admin=False, clusters=['cluster_1'])
    aq, acid = _register('root', is_admin=True, clusters=None)
    try:
        # foreign VM (101) config → must NOT reach the pool user, but reaches admin
        broadcast_sse('vm_config', {'vmid': 101, 'node': 'n1', 'vm_type': 'qemu', 'config': {'net0': 'x'}}, 'cluster_1')
        assert _drain(mq) == [], "pool user must not receive a foreign VM's config frame"
        assert len(_drain(aq)) == 1, "admin should receive it"
        # own VM (100) config → reaches the pool user
        broadcast_sse('vm_config', {'vmid': 100, 'node': 'n1', 'vm_type': 'qemu', 'config': {'net0': 'y'}}, 'cluster_1')
        got = _drain(mq)
        assert len(got) == 1 and got[0]['data']['vmid'] == 100, "pool user should receive their own VM's config"
    finally:
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(mcid, None)
            ppglobals.sse_clients.pop(acid, None)


def test_tasks_frame_scoped(db, seed):
    _pool_user(seed)
    mq, mcid = _register('mallory', is_admin=False, clusters=['cluster_1'])
    aq, acid = _register('root', is_admin=True, clusters=None)
    try:
        tasks = [{'vmid': 100, 'type': 'qmstart'}, {'vmid': 101, 'type': 'qmstop'}, {'node': 'n1', 'type': 'vzdump'}]
        broadcast_sse('tasks', tasks, 'cluster_1')
        mrows = _drain(mq)
        assert len(mrows) == 1, mrows
        assert sorted(t['vmid'] for t in mrows[0]['data']) == [100], "pool user must only see their VM's tasks"
        arows = _drain(aq)
        assert len(arows) == 1 and len(arows[0]['data']) == 3, "admin sees the full task list"
    finally:
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(mcid, None)
            ppglobals.sse_clients.pop(acid, None)
