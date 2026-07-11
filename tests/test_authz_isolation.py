# Core authorization / tenant-isolation invariants.
#
# Each test seeds a minimal world (tenants, users, VM-ACLs, pools) into a
# throwaway DB and asserts an access decision. A failure here means a real
# BOLA / privilege-escalation regression, not a style nit.

import pytest

from pegaprox.utils.rbac import (
    user_can_access_vm,
    get_user_clusters,
    has_permission,
    get_user_vms,
)


# ---------------------------------------------------------------------------
# Cross-tenant isolation (the #1 BOLA surface)
# ---------------------------------------------------------------------------

def test_cross_tenant_vm_access_denied(seed):
    """A tenant-A user must NOT reach a VM on a tenant-B cluster."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    seed.user('alice', role='user', tenant_id='tenant_a')
    bob = seed.user('bob', role='user', tenant_id='tenant_b')

    # bob (tenant_b) tries to reach VM 100 on cluster_1 (tenant_a) — forbidden.
    assert user_can_access_vm(bob, 'cluster_1', 100, 'vm.view') is False


def test_get_user_clusters_scoped_to_tenant(seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    bob = seed.user('bob', role='user', tenant_id='tenant_b')

    assert get_user_clusters(alice) == ['cluster_1']
    assert get_user_clusters(bob) == ['cluster_2']
    assert 'cluster_2' not in get_user_clusters(alice)


def test_non_default_tenant_with_no_clusters_sees_nothing(seed):
    """A non-default tenant with an empty cluster list must see nothing (not all)."""
    seed.tenant('locked', clusters=[])
    user = seed.user('nobody', role='user', tenant_id='locked')
    assert get_user_clusters(user) == []
    assert user_can_access_vm(user, 'cluster_1', 100, 'vm.view') is False


# ---------------------------------------------------------------------------
# Per-VM ACL whitelist
# ---------------------------------------------------------------------------

def test_vm_acl_is_additive_grant_not_restriction(seed):
    """VM-ACLs are ADDITIVE (rbac.py:738): the ACL GRANTS the listed user elevated
    access; it neither hides the VM from other legitimate same-tenant users nor
    elevates them. This pins the intended model so a future 'make ACLs restrictive'
    refactor can't silently break same-tenant role access — or silently elevate."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a')
    bob = seed.user('bob', role='viewer', tenant_id='tenant_a')
    seed.vm_acl('cluster_1', 100, users=['alice'], inherit_role=True)

    # alice: ACL inherit_role=True → full VM ops (incl. start) even as a viewer.
    assert user_can_access_vm(alice, 'cluster_1', 100, 'vm.start') is True
    # bob: not listed, but a same-tenant viewer → sees the VM via role (additive).
    assert user_can_access_vm(bob, 'cluster_1', 100, 'vm.view') is True
    # ...but bob is NOT elevated by alice's ACL — his viewer role has no vm.start.
    assert user_can_access_vm(bob, 'cluster_1', 100, 'vm.start') is False


def test_vm_acl_wildcard_grants_tenant_members(seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a')
    bob = seed.user('bob', role='viewer', tenant_id='tenant_a')
    seed.vm_acl('cluster_1', 100, users=['*'], inherit_role=True)

    assert user_can_access_vm(alice, 'cluster_1', 100, 'vm.view') is True
    assert user_can_access_vm(bob, 'cluster_1', 100, 'vm.view') is True


@pytest.mark.xfail(
    strict=True,
    reason="LIVE BUG (broken access control, CWE-863): the vm_acls table has no "
           "'inherit_role' column (db.py:343-350), so save_vm_acl (db.py:3596) and "
           "the bulk path (db.py:2251) silently DROP inherit_role. get_all_vm_acls "
           "(db.py:3579) can't restore it, so user_can_access_vm (rbac.py:774) reads "
           "vm_acl.get('inherit_role', True) → always True → a UI-configured "
           "'custom permissions' (inherit_role=False) ACL grants FULL VM access "
           "instead of the restricted set. Fix = add the column + migration + "
           "read/write it; then drop this xfail.",
)
def test_vm_acl_inherit_role_false_restricts_to_listed_perms(seed):
    """inherit_role=False → only the ACL's explicit permissions apply, even if
    the user's role would otherwise allow more. (Currently xfails: see reason.)"""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.vm_acl('cluster_1', 100, users=['alice'], inherit_role=False,
                permissions=['vm.view', 'vm.console'])

    assert user_can_access_vm(alice, 'cluster_1', 100, 'vm.console') is True
    assert user_can_access_vm(alice, 'cluster_1', 100, 'vm.start') is False


# ---------------------------------------------------------------------------
# Pool-scoped access must not leak into role-wide cluster access (#555)
# ---------------------------------------------------------------------------

def test_pool_reach_does_not_grant_role_wide_access_on_that_cluster(seed):
    """The #555/#248 guard (rbac.py:837-840): a non-default-tenant user whose
    tenant does NOT own a cluster may reach it via a pool grant, but must NOT fall
    through to their role's cluster-wide vm.view on a VM outside that pool grant.

    (A default-tenant user is intentionally all-cluster, so this guard only bites
    for explicitly-tenanted users — hence tenant_a here, not the default tenant.)"""
    seed.tenant('tenant_a', clusters=['cluster_home'])   # tenant_a does NOT own cluster_x
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.pool('cluster_x', 'pool_1', 'alice', ['pool.view', 'vm.view'])

    # VM 200 on cluster_x is not covered by alice's pool grant → role fallback is
    # gated out by line 837-840 because cluster_x is not in tenant_a's clusters.
    assert user_can_access_vm(alice, 'cluster_x', 200, 'vm.view') is False


# ---------------------------------------------------------------------------
# Admin bypass + role permissions
# ---------------------------------------------------------------------------

def test_admin_has_blanket_access(seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    assert user_can_access_vm(admin, 'any_cluster', 999, 'vm.stop') is True


def test_denied_permissions_subtracted_from_role(seed):
    """denied_permissions must override the role's granted permissions."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    user = seed.user('u', role='user', tenant_id='tenant_a', denied=['vm.delete'])
    assert has_permission(user, 'vm.delete') is False
