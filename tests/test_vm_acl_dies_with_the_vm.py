"""A deleted VM must take its per-VM ACL with it, or a recycled VMID inherits the grant.

vm_acls rows are keyed by the NUMERIC vmid. Proxmox's next-free-VMID allocator hands out
the lowest unused number, so on any busy cluster an id freed by a deletion is very likely
the next one handed out — recycling is the normal case here, not a corner.

Leave the row behind and the new guest on that number is reachable by the previous guest's
users, with whatever permissions the old grant carried, across tenants. user_can_access_vm
has no way to notice: the ACL says vmid 100 and the caller asked about vmid 100.

client_portal's self-service teardown has deleted the row since #556, with a comment
saying why. The main delete route — where essentially every VM actually goes — did not.
Only on success, so a refused delete does not strip a live VM's grants.

Aikido ai_pentest 700486986. MK
"""
import pytest

from pegaprox.core.db import get_db
from pegaprox.utils.rbac import user_can_access_vm

CL = 'cluster_1'
VMID = 100


@pytest.fixture
def estate(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    # t_confined holds NO clusters: the ACL is the only thing that connects olsen to
    # cluster_1. VM ACLs are additive rather than restrictive, so a tenant user whose
    # tenant DID hold the cluster would reach the guest through their role anyway and
    # the ACL would not be what this test is measuring.
    seed.tenant('t_confined', [])
    seed.tenant('t_ops', [CL])
    # the previous owner of VMID 100, granted through a per-VM ACL
    seed.user('olsen', role='user', tenant_id='t_confined', permissions=['vm.view'])
    seed.vm_acl(CL, VMID, ['olsen'], permissions=['vm.view', 'vm.config'])
    # and the operator who tears the guest down
    admin = seed.user('dana', role='admin')

    m = api.make_fake_manager(CL)
    m.is_connected = True
    m.delete_vm.return_value = {'success': True, 'task': 'UPID:x'}
    m.config.name = CL
    api.set_manager(CL, m)
    return api.as_user(admin), m


def _delete(client):
    return client.delete(f'/api/clusters/{CL}/vms/pve1/qemu/{VMID}', json={'purge': True})


def test_the_acl_row_is_gone_after_the_vm_is_deleted(estate):
    client, mgr = estate
    assert user_can_access_vm({'username': 'olsen', 'role': 'user', 'tenant_id': 't_confined'},
                              CL, VMID, 'vm.view'), 'fixture is wrong — no grant to begin with'

    r = _delete(client)
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    mgr.delete_vm.assert_called_once()

    rows = get_db().query('SELECT vmid FROM vm_acls WHERE cluster_id = ? AND vmid = ?',
                          (CL, str(VMID)))
    assert not rows, 'the ACL outlived the VM — a recycled VMID inherits it'


def test_the_previous_owner_cannot_reach_the_recycled_vmid(estate):
    """The property that actually matters, stated the way an attacker would use it."""
    client, _ = estate
    _delete(client)

    # a new guest lands on the same number, belonging to someone else entirely
    reachable = user_can_access_vm(
        {'username': 'olsen', 'role': 'user', 'tenant_id': 't_confined'}, CL, VMID, 'vm.view')
    assert not reachable, 'the previous owner still reaches the number'


def test_a_refused_delete_leaves_the_grant_alone(api, seed):
    """The counterweight — a failed teardown must not strip a live VM's access."""
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t_confined', [])
    seed.user('olsen', role='user', tenant_id='t_confined', permissions=['vm.view'])
    seed.vm_acl(CL, VMID, ['olsen'], permissions=['vm.view'])
    admin = seed.user('dana', role='admin')

    m = api.make_fake_manager(CL)
    m.is_connected = True
    m.delete_vm.return_value = {'success': False, 'error': 'VM is locked'}
    m.config.name = CL
    api.set_manager(CL, m)

    r = _delete(api.as_user(admin))
    assert r.status_code == 500
    rows = get_db().query('SELECT vmid FROM vm_acls WHERE cluster_id = ? AND vmid = ?',
                          (CL, str(VMID)))
    assert rows, 'the grant was dropped even though the VM is still there'
