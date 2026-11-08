"""ESXi SSE frames must answer the same per-VM question the REST twins do.

The REST list has filtered per VM since the Sep audit (user_can_access_vmware_vm
on every row). The stream only asked whether the client held vmware.vm.view — a
builtin ROLE_USER and ROLE_VIEWER permission — and then handed over the whole
server inventory. The detail push was worse: its watch registry is global, so one
authorized watcher put a guest's config, guest info and performance counters in
front of every client subscribed to that server's linked clusters. MK
"""
import json
import queue

import pytest

import pegaprox.globals as ppglobals
from pegaprox.utils.realtime import broadcast_sse


ESXI = 'esxi1'
MINE, THEIRS = 'vm-100', 'vm-200'


def _register(user, is_admin=False, clusters=None):
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


@pytest.fixture
def clients(db, seed):
    """A VM-ACL-scoped viewer, an unscoped viewer, and an admin — all subscribed."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.user('scoped', role='viewer', tenant_id='tenant_x', permissions=['vmware.vm.view'])
    seed.user('operator', role='viewer', tenant_id='tenant_x', permissions=['vmware.vm.view'])
    seed.user('rootvmw', role='admin', tenant_id='tenant_x')
    # ESXi ACLs live under the 'vmware:<id>' cluster key
    seed.vm_acl(f'vmware:{ESXI}', MINE, ['scoped'], permissions=['vmware.vm.view'])

    made = []
    def _mk(user, is_admin=False):
        q, cid = _register(user, is_admin=is_admin, clusters=['cluster_1'])
        made.append(cid)
        return q

    try:
        yield _mk
    finally:
        with ppglobals.sse_clients_lock:
            for cid in made:
                ppglobals.sse_clients.pop(cid, None)


def test_inventory_frame_is_filtered_per_vm(clients):
    scoped = clients('scoped')

    broadcast_sse('vmware_vms', {'vmware_id': ESXI, 'vms': [
        {'vm': MINE, 'name': 'app-01'}, {'vm': THEIRS, 'name': 'finance-01'},
    ]}, target_clusters=[])

    frames = _drain(scoped)
    assert len(frames) == 1, frames
    assert [v['vm'] for v in frames[0]['data']['vms']] == [MINE], frames[0]['data']['vms']
    assert 'finance-01' not in json.dumps(frames[0])


def test_admin_still_gets_the_whole_inventory(clients):
    root = clients('rootvmw', is_admin=True)

    broadcast_sse('vmware_vms', {'vmware_id': ESXI, 'vms': [
        {'vm': MINE, 'name': 'app-01'}, {'vm': THEIRS, 'name': 'finance-01'},
    ]}, target_clusters=[])

    frames = _drain(root)
    assert len(frames) == 1
    assert len(frames[0]['data']['vms']) == 2


def test_detail_push_does_not_follow_someone_elses_watch(clients):
    """The watch registry is global. A guest another user asked to watch must not be
    delivered to a client that cannot see it."""
    scoped = clients('scoped')

    broadcast_sse('vmware_vm_detail', {'vmware_id': ESXI, 'vm_id': THEIRS,
                                       'data': {'name': 'finance-01', 'guest_info': {'ip': '10.0.0.9'}}},
                  target_clusters=[])

    assert _drain(scoped) == [], 'a foreign ESXi guest reached a scoped client'


def test_detail_push_still_reaches_a_client_that_owns_the_guest(clients):
    scoped = clients('scoped')

    broadcast_sse('vmware_vm_detail', {'vmware_id': ESXI, 'vm_id': MINE,
                                       'data': {'name': 'app-01'}}, target_clusters=[])

    frames = _drain(scoped)
    assert len(frames) == 1, frames
    assert frames[0]['data']['vm_id'] == MINE


def test_an_unscoped_operator_keeps_the_whole_server(clients):
    """No ESXi ACL anywhere for this user → the role permission decides, as before."""
    operator = clients('operator')

    broadcast_sse('vmware_vms', {'vmware_id': ESXI, 'vms': [
        {'vm': MINE, 'name': 'app-01'}, {'vm': THEIRS, 'name': 'finance-01'},
    ]}, target_clusters=[])

    frames = _drain(operator)
    assert len(frames) == 1
    assert len(frames[0]['data']['vms']) == 2, frames[0]['data']['vms']
