# Regression: CodeAnt re-scan (2026-07-13) critical findings.

from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
from pegaprox.utils.rbac import user_can_access_vmware_vm


# --- Finding 1: set_user_perms global-permission privilege escalation -------------------------

def test_tenant_admin_cannot_set_global_permissions(api, seed):
    # a tenant-scoped admin holds admin.users but is NOT a global admin (role != admin)
    seed.tenant('tenant_a', clusters=['cluster_1'])
    tadmin = seed.user('tadmin', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('victim', role='user', tenant_id='tenant_a')
    # global-permission edit (no tenant_id) must be denied for a non-global-admin
    r = api.as_user(tadmin).put('/api/users/victim/permissions',
                                json={'permissions': ['admin.settings']})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_global_admin_can_set_global_permissions(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    seed.user('victim', role='user', tenant_id='default')
    r = api.as_user(root).put('/api/users/victim/permissions',
                              json={'permissions': ['vm.view']})
    assert r.status_code == 200, r.get_data(as_text=True)


# --- Finding 3: user_can_access_vmware_vm cross-tenant BOLA ------------------------------------

def _mk_vmware(vmware_id, linked):
    m = MagicMock()
    m.linked_clusters = linked
    ppglobals.vmware_managers[vmware_id] = m
    return m


def test_vmware_route_cross_tenant_denied(api, seed):
    # the vmware.py read routes now enforce check_vmware_access (were role-perm only)
    ppglobals.vmware_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['vmware.vm.view'])
    _mk_vmware('vmw_b', ['cluster_2'])   # linked to tenant_b's cluster
    try:
        r = api.as_user(alice).get('/api/vmware/vmw_b/vms')
        assert r.status_code == 403, r.get_data(as_text=True)
    finally:
        ppglobals.vmware_managers.clear()


def test_tenant_admin_cannot_amplify_via_tenant_perms(api, seed):
    # the set_user_perms TENANT branch must reject a non-global-admin granting admin role/perms
    seed.tenant('tenant_a', clusters=['cluster_1'])
    tadmin = seed.user('tadmin', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('victim', role='user', tenant_id='tenant_a')
    c = api.as_user(tadmin)
    # vector 1: role='admin' in own tenant
    r1 = c.put('/api/users/victim/permissions', json={'tenant_id': 'tenant_a', 'role': 'admin'})
    assert r1.status_code == 403, r1.get_data(as_text=True)
    # vector 2: admin.* perms in own tenant
    r2 = c.put('/api/users/victim/permissions',
               json={'tenant_id': 'tenant_a', 'extra': ['admin.users', 'admin.settings']})
    assert r2.status_code == 403, r2.get_data(as_text=True)


def test_vmware_vm_cross_tenant_denied(api, seed):
    ppglobals.vmware_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['vmware.vm.view'])
    root = seed.user('root', role='admin', tenant_id='default')
    _mk_vmware('vmw_b', ['cluster_2'])       # VMware server linked to tenant_b's cluster
    _mk_vmware('vmw_open', [])               # unlinked (backward-compat open)
    try:
        # alice (tenant_a) can't reach vmw_b's linked cluster -> denied (was: allowed = BOLA)
        assert user_can_access_vmware_vm(alice, 'vmw_b', '10', 'vmware.vm.view') is False
        # admin -> allowed
        assert user_can_access_vmware_vm(root, 'vmw_b', '10', 'vmware.vm.view') is True
        # unlinked server -> backward-compat open (alice holds the perm)
        assert user_can_access_vmware_vm(alice, 'vmw_open', '10', 'vmware.vm.view') is True
    finally:
        ppglobals.vmware_managers.clear()
