"""A VM-ACL delete that fails says so instead of reading as "there was no grant".

delete_vm_acl() caught the database error, logged it and answered False - the same as
"no row". After a VM delete the route took that as done, so its own error branch (log
plus manual-cleanup hint) never ran and the grant stayed for the next guest on that
VMID with one generic log line. The ACL route answered success. The error is raised
now: the VM delete records it in the audit trail, the ACL route answers 500.

NS Oct 2026
"""
import pytest

from pegaprox.core.db import get_db

CL = 'cluster_1'
VMID = 100


@pytest.fixture
def estate(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t_confined', [])
    seed.user('olsen', role='user', tenant_id='t_confined', permissions=['vm.view'])
    seed.vm_acl(CL, VMID, ['olsen'], permissions=['vm.view'])
    admin = seed.user('dana', role='admin')
    m = api.make_fake_manager(CL)
    m.is_connected = True
    m.delete_vm.return_value = {'success': True, 'task': 'UPID:x'}
    m.config.name = CL
    api.set_manager(CL, m)
    return api.as_user(admin)


def _break_acl_deletes():
    # a write the database refuses, as a full disk or a locked file would
    get_db().conn.execute("CREATE TRIGGER vm_acls_refuse_delete BEFORE DELETE ON vm_acls "
                          "BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END")
    get_db().conn.commit()


def _rows():
    return get_db().query('SELECT vmid FROM vm_acls WHERE cluster_id = ? AND vmid = ?', (CL, str(VMID)))


def test_a_failed_cleanup_after_a_vm_delete_lands_in_the_audit_trail(estate, monkeypatch):
    audit = []
    monkeypatch.setattr('pegaprox.api.vms.log_audit', lambda u, a, d=None, **k: audit.append((a, d)))
    _break_acl_deletes()

    r = estate.delete(f'/api/clusters/{CL}/vms/pve1/qemu/{VMID}', json={'purge': True})

    assert r.status_code == 200, r.get_data(as_text=True)[:200]     # the VM is gone either way
    assert _rows(), 'fixture: the trigger did not hold the row'
    assert any(a == 'vm.acl_cleanup_failed' and str(VMID) in (d or '') for a, d in audit), audit


def test_the_acl_route_does_not_report_success_for_a_delete_that_failed(estate):
    _break_acl_deletes()

    r = estate.delete(f'/api/clusters/{CL}/vm-acls/{VMID}')

    assert r.status_code == 500, r.get_data(as_text=True)[:200]
    assert _rows()


def test_the_acl_route_still_deletes(estate):
    """The mirror: a working database removes the row and says so."""
    r = estate.delete(f'/api/clusters/{CL}/vm-acls/{VMID}')

    assert r.status_code == 200 and r.get_json() == {'success': True, 'deleted': True}
    assert not _rows()
