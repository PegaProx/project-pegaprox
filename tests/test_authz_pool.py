# Pool-scoped access invariants.
#
# VM→pool membership is normally resolved live from the cluster manager and
# cached. Here we seed rbac's membership cache directly (fresh timestamp) so the
# decision path runs without any live PVE/ESXi manager, and assert the pool
# permission semantics + that a pool grant does not leak beyond its pool/cluster.

import time

import pegaprox.utils.rbac as rbac
from pegaprox.utils.rbac import user_can_access_vm, get_user_pool_vmids


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


# --------------------------------------------------------------------------- #
# #635 pool-subset — a pool grant is exactly "assign once, see all its VMs".
# The client portal's _get_my_vms() unions the set get_user_pool_vmids() returns.
# --------------------------------------------------------------------------- #

def test_user_pool_grant_gives_portal_visibility_of_all_pool_vms(seed):
    """A per-user pool grant makes every VM in that pool reachable via get_user_pool_vmids — the
    exact set the client portal unions in — so a portal client sees all the pool's VMs without a
    per-VM ACL each (#635 / #555). A VM in another pool is not included."""
    alice = seed.user('alice', role='viewer')
    seed.pool('cluster_x', 'pool_1', 'alice', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_x', {100: ('qemu', 'pool_1'), 101: ('lxc', 'pool_1'),
                                        200: ('qemu', 'other_pool')})
    vmids = get_user_pool_vmids(alice, 'cluster_x')
    assert 100 in vmids and 101 in vmids   # both pool_1 members
    assert 200 not in vmids                # different pool → not visible


def test_group_pool_grant_resolves_when_user_carries_groups(seed):
    """The group→pool resolution works when the user object carries its groups (subject_type='group').
    Since #940 the stored user row carries them (directory_groups), filled at LDAP/OIDC sign-in;
    tests/test_directory_groups_940.py drives that end to end."""
    seed.pool('cluster_x', 'pool_1', 'engineering', ['pool.view', 'vm.view'], subject_type='group')
    _seed_pool_membership('cluster_x', {100: ('qemu', 'pool_1')})
    bob = seed.user('bob', role='viewer')
    bob['groups'] = ['engineering']          # as an IdP-authenticated session user would carry
    assert 100 in get_user_pool_vmids(bob, 'cluster_x')
    carol = seed.user('carol', role='viewer')   # not in the group
    assert 100 not in get_user_pool_vmids(carol, 'cluster_x')
