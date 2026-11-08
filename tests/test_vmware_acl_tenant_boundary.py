"""A VMware per-VM ACL is a grant inside a tenant's estate, not a way into another's.

user_can_access_vmware_vm resolved the ACL row FIRST and returned on a match. The
linked-server tenant gate - the one that stops a vmware.vm.* holder reaching every
server in the installation - sat below it, in the branch that runs only when no ACL row
exists. So a row on tenant B's ESXi server naming a tenant-A user, or carrying the '*'
wildcard, handed that user full VM access across the boundary: power, config, snapshot,
migrate, console.

The row is also read through acl_grants_user now, so the wildcard means the same thing
here as in the nine other places that ask this question.

Aikido ai_pentest 700487370. MK
"""
import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


SERVER = 'esxi_b'
VM = '42'


class _Vmware:
    def __init__(self, linked):
        self.linked_clusters = list(linked)


@pytest.fixture
def estate(monkeypatch):
    """One ESXi server linked to tenant B's cluster, and an ACL row naming a tenant-A user."""
    def _install(acl_users=('ann',), linked=('cluster_b',), inherit=True):
        ppglobals.vmware_managers.clear()
        ppglobals.vmware_managers[SERVER] = _Vmware(linked)
        snapshot = rbac._Snapshot({
            f'vmware:{SERVER}': {VM: {'users': list(acl_users), 'inherit_role': inherit,
                                      'permissions': ['vmware.vm.view']}}
        })
        monkeypatch.setattr(rbac, 'get_vm_acls', lambda: snapshot)
        monkeypatch.setattr(rbac, 'get_user_clusters',
                            lambda u, include_pools=True: (None if u.get('_all')
                                                           else list(u.get('_clusters', []))))
    try:
        yield _install
    finally:
        ppglobals.vmware_managers.clear()


def _user(name, clusters=(), all_clusters=False, role='user'):
    return {'username': name, 'role': role, '_clusters': list(clusters), '_all': all_clusters}


def test_an_acl_row_does_not_reach_across_the_tenant_boundary(estate):
    """Tenant A's ann holds an ACL row on tenant B's server. She still may not."""
    estate(acl_users=('ann',))

    assert rbac.user_can_access_vmware_vm(
        _user('ann', clusters=['cluster_a']), SERVER, VM, 'vmware.vm.power') is False


def test_a_wildcard_row_does_not_reach_across_it_either(estate):
    """'*' is the worst case: it names everybody in the installation."""
    estate(acl_users=('*',))

    assert rbac.user_can_access_vmware_vm(
        _user('mallory', clusters=['cluster_a']), SERVER, VM, 'vmware.vm.console') is False


def test_the_row_still_grants_inside_the_tenant(estate):
    """The counterweight: this is what an ACL row is for."""
    estate(acl_users=('bert',))

    assert rbac.user_can_access_vmware_vm(
        _user('bert', clusters=['cluster_b']), SERVER, VM, 'vmware.vm.power') is True


def test_a_wildcard_row_still_grants_inside_the_tenant(estate):
    estate(acl_users=('*',))

    assert rbac.user_can_access_vmware_vm(
        _user('bert', clusters=['cluster_b']), SERVER, VM, 'vmware.vm.view') is True


def test_an_explicit_permission_list_is_still_honoured(estate):
    estate(acl_users=('bert',), inherit=False)
    u = _user('bert', clusters=['cluster_b'])

    assert rbac.user_can_access_vmware_vm(u, SERVER, VM, 'vmware.vm.view') is True
    assert rbac.user_can_access_vmware_vm(u, SERVER, VM, 'vmware.vm.power') is False


def test_an_unlinked_server_stays_backward_compatible(estate):
    """A server nobody has linked yet must not lock its existing users out."""
    estate(acl_users=('ann',), linked=())

    assert rbac.user_can_access_vmware_vm(
        _user('ann', clusters=['cluster_a']), SERVER, VM, 'vmware.vm.power') is True


def test_an_admin_is_unaffected(estate):
    estate(acl_users=('bert',))

    assert rbac.user_can_access_vmware_vm(
        _user('root', all_clusters=True, role=rbac.ROLE_ADMIN), SERVER, VM,
        'vmware.vm.power') is True


def test_an_unreadable_acl_store_still_denies_first(estate, monkeypatch):
    """Ordering check: the tenant gate must not be reachable on a failed read.

    (CodeAnt, 18.09.: this used to assign get_vm_acls straight onto the module with a
    `finally: pass` that restored nothing - the stub then leaked into every test that
    ran after it in the same process.)"""
    estate(acl_users=('bert',))
    monkeypatch.setattr(rbac, 'get_vm_acls', lambda: rbac._Snapshot(unavailable=True))

    assert rbac.user_can_access_vmware_vm(
        _user('bert', clusters=['cluster_b']), SERVER, VM, 'vmware.vm.view') is False


def test_the_tenant_gate_denies_when_it_cannot_run(estate, monkeypatch):
    """CodeAnt, 18.09.: the gate used to log its own error and carry on. While it only
    guarded the no-ACL fallback that merely reopened the older hole; now that it guards
    the ACL path too, swallowing an exception skips exactly the cross-tenant check this
    function exists for."""
    estate(acl_users=('ann',))

    def _boom(user, include_pools=True):
        raise RuntimeError('tenant lookup exploded')
    monkeypatch.setattr(rbac, 'get_user_clusters', _boom)

    assert rbac.user_can_access_vmware_vm(
        _user('ann', clusters=['cluster_a']), SERVER, VM, 'vmware.vm.power') is False


def test_an_admin_is_still_answered_before_the_gate_can_fail(estate, monkeypatch):
    """Failing closed must not lock out whoever has to go and fix it."""
    estate(acl_users=('ann',))
    monkeypatch.setattr(rbac, 'get_user_clusters',
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('boom')))

    assert rbac.user_can_access_vmware_vm(
        _user('root', all_clusters=True, role=rbac.ROLE_ADMIN), SERVER, VM,
        'vmware.vm.power') is True
