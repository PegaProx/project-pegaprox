# #773 (mbo-nw) — a portal/tenant user scoped to a resource pool must see ONLY that pool's VMs
# when querying the REST API's /resources list, exactly as the client portal shows them.
#
# The bug: GET /api/clusters/<id>/resources filtered by VM-ACL + tenant + vm.view but NOT by
# pool. A tenant_operator whose tenant OWNS the cluster and whose access came from a pool grant
# (no per-VM ACLs) fell through to the blanket vm.view branch and got the WHOLE cluster's VMs
# and templates back — while the portal (get_user_pool_vmids) shows only the pool's members.
# The fix routes any pool-scoped caller through user_can_access_vm, the same per-VM check the
# non-owner path already used, so "what you can list" == "what you can access".
#
# Pool membership is normally resolved live from the manager and cached; here we seed rbac's
# membership cache directly (fresh timestamp) so the decision runs without a live PVE manager,
# same trick as tests/test_authz_pool.py.

import time

import pegaprox.utils.rbac as rbac


RES_ROUTE = '/api/clusters/cluster_1/resources'

# db01 (in the pool), web01 (not), and a golden template (the reporter saw templates leak too).
_ALL_VMS = [
    {'vmid': 100, 'name': 'db01', 'type': 'qemu', 'status': 'running'},
    {'vmid': 101, 'name': 'web01', 'type': 'qemu', 'status': 'running'},
    {'vmid': 900, 'name': 'tmpl-golden', 'type': 'qemu', 'status': 'stopped', 'template': 1},
]


def _mgr(api):
    return api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_ALL_VMS))


def _seed_pool_membership(cluster_id, mapping):
    """mapping = {vmid(int): (vm_type, pool_id)} -> cache key 'vmid:vm_type', fresh timestamp."""
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def test_pool_scoped_owner_sees_only_pool_members(api, seed):
    """THE #773 regression. mallory's tenant OWNS cluster_1 and she holds a pool grant on pool_1
    (VM 100 only). She must see ONLY VM 100 — not web01 (101) or the golden template (900) that
    the pre-fix blanket-vm.view branch handed back to a portal user querying the API directly."""
    seed.tenant('tenant_x', clusters=['cluster_1'])                 # tenant OWNS the cluster
    mallory = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})   # 101 + 900 are in no pool
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(mallory).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    vmids = sorted(v['vmid'] for v in resp.get_json())
    assert vmids == [100]                              # only her pool member
    assert 101 not in vmids and 900 not in vmids       # no blanket-vm.view leak of the cluster


def test_pool_scoped_owner_visibility_is_pool_union_acl(api, seed):
    """A pool-scoped caller sees pool members UNION her own VM-ACL grants: a per-VM ACL on 101
    adds it, but 900 (neither pool nor ACL) stays hidden."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    mallory = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    seed.vm_acl('cluster_1', 101, users=['mallory'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(mallory).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    vmids = sorted(v['vmid'] for v in resp.get_json())
    assert vmids == [100, 101]
    assert 900 not in vmids


def test_pool_perms_read_is_memoised_per_request(api, seed, db, monkeypatch):
    """#773 scale follow-up: the per-VM authz loop must read the user's pool grants ONCE per
    request, not once per VM. Without the request memo this was ~N+1 identical indexed SELECTs
    for an N-VM cluster; _pool_perms_for() collapses it to a small constant on Flask's g."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    mallory = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    # a wider VM list so once-per-VM would be visibly larger than the memoised count
    big = [{'vmid': v, 'name': f'vm{v}', 'type': 'qemu', 'status': 'running'} for v in range(100, 110)]
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=big))

    calls = {'n': 0}
    real = db.get_user_pool_permissions
    def counting(*a, **k):
        calls['n'] += 1
        return real(*a, **k)
    monkeypatch.setattr(db, 'get_user_pool_permissions', counting)

    resp = api.as_user(mallory).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    # 10 VMs → once-per-VM would be ~11 reads; memoised to a small constant for the request.
    assert calls['n'] <= 2, f"pool-perms read {calls['n']}x for 10 VMs; expected memoised (<=2)"


def test_plain_operator_without_pool_grant_is_unchanged(api, seed):
    """Guard the fix's blast radius: a same-tenant 'user' with vm.view and NO pool/ACL grant must
    keep the cluster-wide restrictive-ACL listing — with no ACLs at all, that's every VM. If the
    _uhpa gate wrongly caught this caller it would confine them and this would regress."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    otto = seed.user('otto', role='user', tenant_id='tenant_x')
    _seed_pool_membership('cluster_1', {})            # nobody has a pool grant here
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(otto).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    vmids = sorted(v['vmid'] for v in resp.get_json())
    assert vmids == [100, 101, 900]                   # unchanged blanket vm.view listing
