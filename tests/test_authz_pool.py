# Pool-scoped access invariants.
#
# VM→pool membership is normally resolved live from the cluster manager and
# cached. Here we seed rbac's membership cache directly (fresh timestamp) so the
# decision path runs without any live PVE/ESXi manager, and assert the pool
# permission semantics + that a pool grant does not leak beyond its pool/cluster.

import time

import pegaprox.utils.rbac as rbac
from pegaprox.utils.rbac import user_can_access_vm


def _seed_pool_membership(cluster_id, mapping):
    """mapping = {vmid(int): (vm_type, pool_id)} → cache key 'vmid:vm_type'."""
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def test_pool_admin_grants_all_ops_on_member_vm(seed):
    """pool.admin on a pool → every VM op on that pool's members, even for a
    viewer who reached the cluster only via the pool grant."""
    seed.tenant('tenant_a', clusters=['cluster_home'])   # tenant does NOT own cluster_x
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a')
    seed.pool('cluster_x', 'pool_1', 'alice', ['pool.admin'])
    _seed_pool_membership('cluster_x', {100: ('qemu', 'pool_1')})

    assert user_can_access_vm(alice, 'cluster_x', 100, 'vm.start') is True
    assert user_can_access_vm(alice, 'cluster_x', 100, 'vm.delete') is True


def test_pool_view_grant_does_not_widen_to_write_ops(seed):
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a')
    seed.pool('cluster_x', 'pool_1', 'alice', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_x', {100: ('qemu', 'pool_1')})

    assert user_can_access_vm(alice, 'cluster_x', 100, 'vm.view') is True
    assert user_can_access_vm(alice, 'cluster_x', 100, 'vm.start') is False


def test_pool_grant_does_not_leak_to_non_member_vm(seed):
    """A pool grant covers pool members only; a non-member VM on the same cluster
    falls through to the tenant guard (cluster not in tenant) → denied."""
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.pool('cluster_x', 'pool_1', 'alice', ['pool.admin'])
    _seed_pool_membership('cluster_x', {100: ('qemu', 'pool_1')})  # VM 200 is NOT a member

    assert user_can_access_vm(alice, 'cluster_x', 200, 'vm.view') is False


def test_pool_grant_does_not_leak_across_clusters(seed):
    """A pool grant on cluster_x must not grant access to the same vmid on
    cluster_y where the user has neither tenant nor pool reach."""
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a')
    seed.pool('cluster_x', 'pool_1', 'alice', ['pool.admin'])
    _seed_pool_membership('cluster_x', {100: ('qemu', 'pool_1')})
    _seed_pool_membership('cluster_y', {})   # alice has no reach to cluster_y at all

    assert user_can_access_vm(alice, 'cluster_y', 100, 'vm.view') is False
