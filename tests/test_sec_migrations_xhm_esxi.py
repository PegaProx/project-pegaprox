# -*- coding: utf-8 -*-
"""XHM authorizes a standalone ESXi source with the ESXi VM-level check (#1039). NS Oct 2026.

A standalone ESXi host is registered in cluster_managers under its vmware_id. The XHM gate
asked user_can_access_vm(vm.migrate), which found no Proxmox ACL under that id and fell
through to the role permission - so a caller holding vm.migrate but not vmware.vm.migrate
could copy any guest off that ESXi host. The gate routes ESXi sources through
user_can_access_vmware_vm with the ESXi permissions now.
"""
import types

import pytest

import pegaprox.globals as ppglobals
import pegaprox.api.xhm as xhm
from pegaprox.utils.rbac import user_can_access_vm


ESXI_ID = 'esxi_srv1'


@pytest.fixture
def esxi_registered(db):
    """Register a standalone ESXi manager where XHM looks (cluster_managers + vmware_managers),
    unlinked so the ESXi tenant gate is backward-compat open and the decision lands on the
    permission check - the exact fall-through the bug rode."""
    ppglobals.cluster_managers.clear()
    ppglobals.vmware_managers.clear()
    mgr = types.SimpleNamespace(cluster_type='esxi', host='10.0.0.5', linked_clusters=[])
    ppglobals.cluster_managers[ESXI_ID] = mgr
    ppglobals.vmware_managers[ESXI_ID] = mgr
    try:
        yield mgr
    finally:
        ppglobals.cluster_managers.clear()
        ppglobals.vmware_managers.clear()


def _user_with(db, perms):
    db.save_user('migrator', {
        'password_salt': 'x', 'password_hash': 'x', 'role': 'viewer',
        'tenant_id': 'default', 'enabled': True,
        'permissions': list(perms), 'denied_permissions': [], 'tenant_permissions': {},
    })
    u = db.get_user('migrator')
    u['username'] = 'migrator'
    return u


def test_the_old_proxmox_gate_would_have_granted_an_esxi_source(esxi_registered, db):
    """Counterproof: this is the decision 8b36c2a made - vm.migrate alone said yes."""
    u = _user_with(db, ['vm.migrate'])
    assert user_can_access_vm(u, ESXI_ID, 100, 'vm.migrate') is True


def test_the_gate_denies_an_esxi_source_without_vmware_vm_migrate(esxi_registered, db):
    """The fix: an ESXi source is judged by the ESXi permission, which this caller lacks."""
    u = _user_with(db, ['vm.migrate'])
    assert xhm._may_migrate_source(u, ESXI_ID, 100, 'vm.migrate') is False


def test_the_gate_allows_an_esxi_source_with_vmware_vm_migrate(esxi_registered, db):
    u = _user_with(db, ['vmware.vm.migrate'])
    assert xhm._may_migrate_source(u, ESXI_ID, 100, 'vm.migrate') is True


def test_source_removal_on_esxi_needs_manage_not_migrate(esxi_registered, db):
    """delete maps to vmware.vm.manage for an ESXi source; migrate rights alone do not remove."""
    u = _user_with(db, ['vmware.vm.migrate'])
    assert xhm._may_migrate_source(u, ESXI_ID, 100, 'vm.delete') is False
    u2 = _user_with(db, ['vmware.vm.migrate', 'vmware.vm.manage'])
    assert xhm._may_migrate_source(u2, ESXI_ID, 100, 'vm.delete') is True


def test_a_proxmox_source_still_uses_the_proxmox_check(db):
    """The invariant: a real Proxmox cluster is unchanged - vm.migrate governs it."""
    ppglobals.cluster_managers.clear()
    ppglobals.cluster_managers['cluster_1'] = types.SimpleNamespace(cluster_type='proxmox')
    try:
        u = _user_with(db, ['vm.migrate'])
        assert xhm._may_migrate_source(u, 'cluster_1', 100, 'vm.migrate') is True
        u2 = _user_with(db, ['vmware.vm.migrate'])
        assert xhm._may_migrate_source(u2, 'cluster_1', 100, 'vm.migrate') is False
    finally:
        ppglobals.cluster_managers.clear()
