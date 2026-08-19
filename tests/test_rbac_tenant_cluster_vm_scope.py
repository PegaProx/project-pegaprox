# Security report (Jörg Morasch, symplasson) — Client Portal / console BOLA.
#
# A user whose TENANT is assigned a cluster, but who is explicitly scoped to specific VMs via
# VM-ACL (exactly how the Client Portal grants a user "their" VMs), could still reach ANY VM in
# that cluster. user_can_access_vm fell through to the role-wide has_permission() because the
# cluster IS in the tenant, ignoring the ACL scope — so a portal user granted one VM could
# substitute a foreign vmid on the console websocket and connect to a VM they were never
# granted. The scope has to win: if a user is VM-ACL-scoped in a cluster, per-VM ops are limited
# to those VMs even when the tenant owns the cluster. This mirrors get_user_vms(), which is what
# the portal already uses to decide which VMs to *show*.

import time

import pegaprox.utils.rbac as rbac
from pegaprox.utils.rbac import user_can_access_vm, user_can_access_vmware_vm


def _seed_pool_membership(cluster_id, mapping):
    """mapping = {vmid(int): (vm_type, pool_id)} → rbac's membership cache key 'vmid:vm_type'."""
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def test_acl_scoped_user_on_tenant_cluster_is_confined_to_granted_vms(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])                       # tenant OWNS the cluster
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.console'])
    seed.vm_acl('cluster_1', 100, users=['bob'], inherit_role=True)   # granted ONLY VM 100
    with api.app.app_context():
        assert user_can_access_vm(bob, 'cluster_1', 100, 'vm.console') is True    # own VM
        assert user_can_access_vm(bob, 'cluster_1', 138, 'vm.console') is False   # BOLA — deny


def test_plain_tenant_operator_keeps_cluster_wide_access(api, seed):
    # no VM-ACL scoping in this cluster → a normal tenant operator is unaffected by the fix
    seed.tenant('ops', clusters=['cluster_1'])
    alice = seed.user('alice', role='user', tenant_id='ops', permissions=['vm.console'])
    with api.app.app_context():
        assert user_can_access_vm(alice, 'cluster_1', 138, 'vm.console') is True


def test_acl_reach_into_foreign_cluster_still_scoped(api, seed):
    # #248/#555 regression: reaching a cluster NOT in the tenant only via a VM-ACL stays
    # confined to that one VM (this path already denied; keep it green under the new fix)
    seed.tenant('t2', clusters=['cluster_other'])
    carol = seed.user('carol', role='user', tenant_id='t2', permissions=['vm.console'])
    seed.vm_acl('cluster_1', 100, users=['carol'], inherit_role=True)
    with api.app.app_context():
        assert user_can_access_vm(carol, 'cluster_1', 100, 'vm.console') is True
        assert user_can_access_vm(carol, 'cluster_1', 138, 'vm.console') is False


def test_pool_scoped_user_on_tenant_cluster_is_confined_to_pool_vms(api, seed):
    # pool-variant of the same BOLA: a user scoped via a POOL grant (no VM-ACL) on a cluster
    # their tenant owns must stay confined to that pool's VMs. (This is the gap the audit found
    # in the first VM-ACL-only fix — user_can_access_vm now unions pool scope.)
    seed.tenant('acme', clusters=['cluster_1'])
    dave = seed.user('dave', role='user', tenant_id='acme', permissions=['vm.console'])
    seed.pool('cluster_1', 'poolA', 'dave', ['pool.admin'])   # unambiguous grant on the pool's VMs
    _seed_pool_membership('cluster_1', {100: ('qemu', 'poolA')})   # only VM 100 is in dave's pool
    with api.app.app_context():
        assert user_can_access_vm(dave, 'cluster_1', 100, 'vm.console') is True
        assert user_can_access_vm(dave, 'cluster_1', 138, 'vm.console') is False   # pool-BOLA — deny


def test_vmware_acl_scoped_user_is_confined_to_granted_vms(api, seed):
    # VMware twin of the console BOLA — user_can_access_vmware_vm must confine an ACL-scoped user.
    seed.tenant('acme', clusters=['cluster_1'])
    eve = seed.user('eve', role='user', tenant_id='acme', permissions=['vmware.vm.power'])
    seed.db.save_vm_acl('vmware:esxi-1', '100', {'users': ['eve'], 'inherit_role': True, 'permissions': []})
    rbac.invalidate_vm_acls_cache()
    with api.app.app_context():
        assert user_can_access_vmware_vm(eve, 'esxi-1', '100', 'vmware.vm.power') is True
        assert user_can_access_vmware_vm(eve, 'esxi-1', '200', 'vmware.vm.power') is False   # BOLA — deny
