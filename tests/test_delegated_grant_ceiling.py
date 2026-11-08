"""A delegate cannot hand out authority they do not hold themselves.

_authz_object_write() is the gate for writing authorization objects - VM ACLs, pool
permissions, pools. It asks the right three questions (caller not confined here,
subjects inside their tenant, permissions within their own). Its callers just did not
give it the arguments to ask with:

  * set_vm_acl weighed `permissions`, the explicit list - but `inherit_role` is the
    DEFAULT and hands out a fixed ten-permission set instead, `permissions` unused. A
    delegate holding only vm.view granted full VM control by leaving the default on.
  * add_pool_permission_api passed `permissions=[]`, so the ceiling ran over nothing,
    and pool.admin short-circuits the per-VM gate for every VM in the pool.
  * delete_pool_permission and delete_vm_acl passed no subject at all, so a
    tenant-scoped admin could revoke another tenant's grants.

Note which role each fixture carries: the builtin `user` role already holds all ten
inherited VM permissions, so only a lower-role delegate can overrun that ceiling. The
first draft of these tests used `user` and passed against the unfixed code - a fixture
that cannot exceed the limit proves nothing about the limit.

Aikido ai_pentest 700488973 / 700488817 / 700487603. MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac


def _capped(seed):
    """viewer + admin.users + vm.config: enough to administer users and to control the
    VM they are writing a rule for (set_vm_acl demands vm.config on the VM itself), but
    vm.migrate, vm.backup, vm.clone and pool.admin are all still above them - so the
    inherited ten-permission set overruns their ceiling and an explicit ['vm.view'] does
    not."""
    seed.tenant('tenant_x', ['cluster_1'])
    return seed.user('delegate', role='viewer', tenant_id='tenant_x',
                     permissions=['admin.users', 'cluster.view', 'vm.config'])


def _full(seed):
    """user + admin.users: holds every inherited VM permission, so the ceiling lets
    them through. The control case."""
    seed.tenant('tenant_x', ['cluster_1'])
    return seed.user('operator', role='user', tenant_id='tenant_x',
                     permissions=['admin.users', 'cluster.view'])


def _target(seed, name='bob', tenant='tenant_x'):
    return seed.user(name, role='viewer', tenant_id=tenant)


def _acl_row(db, cluster_id, vmid):
    cur = db.conn.cursor()
    cur.execute('SELECT users, permissions, inherit_role FROM vm_acls WHERE cluster_id=? AND vmid=?',
                (cluster_id, str(vmid)))
    return cur.fetchone()


def _pool_rows(db):
    cur = db.conn.cursor()
    cur.execute('SELECT subject_id, permissions FROM pool_permissions')
    return cur.fetchall()


# --- inherit_role is the permission set that counts ---------------------------

def test_a_capped_delegate_cannot_grant_full_vm_control_via_inherit_role(api, db, seed):
    """`permissions: []` looks harmless; inherit_role=True is what actually grants."""
    rbac.invalidate_vm_acls_cache()
    d = _capped(seed)
    _target(seed)

    r = api.as_user(d).put('/api/clusters/cluster_1/vm-acls/100',
                           json={'users': ['bob'], 'permissions': [], 'inherit_role': True})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _acl_row(db, 'cluster_1', 100) is None


def test_a_capped_delegate_may_still_grant_inside_their_ceiling(api, db, seed):
    """The invariant: delegation keeps working for what they do hold."""
    rbac.invalidate_vm_acls_cache()
    d = _capped(seed)
    _target(seed)

    r = api.as_user(d).put('/api/clusters/cluster_1/vm-acls/100',
                           json={'users': ['bob'], 'permissions': ['vm.view'],
                                 'inherit_role': False})

    assert r.status_code == 200, r.get_data(as_text=True)
    row = _acl_row(db, 'cluster_1', 100)
    assert json.loads(row[1]) == ['vm.view']
    assert row[2] == 0


def test_a_delegate_who_holds_the_whole_set_may_use_inherit_role(api, db, seed):
    """The ceiling is a ceiling, not a ban: the `user` role holds all ten."""
    rbac.invalidate_vm_acls_cache()
    d = _full(seed)
    _target(seed)

    r = api.as_user(d).put('/api/clusters/cluster_1/vm-acls/100',
                           json={'users': ['bob'], 'permissions': [], 'inherit_role': True})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _acl_row(db, 'cluster_1', 100) is not None


def test_the_explicit_list_is_still_weighed_when_inherit_role_is_off(api, db, seed):
    rbac.invalidate_vm_acls_cache()
    d = _capped(seed)
    _target(seed)

    r = api.as_user(d).put('/api/clusters/cluster_1/vm-acls/100',
                           json={'users': ['bob'], 'permissions': ['vm.migrate'],
                                 'inherit_role': False})

    assert r.status_code == 403, r.get_data(as_text=True)


# --- pool permissions were never weighed --------------------------------------

def _pool_url(cluster='cluster_1', pool='pool_1'):
    return f'/api/clusters/{cluster}/pools/{pool}/permissions'


def test_a_capped_delegate_cannot_grant_pool_admin(api, db, seed):
    """pool.admin short-circuits the per-VM gate for every VM in the pool."""
    d = _capped(seed)
    _target(seed)

    r = api.as_user(d).post(_pool_url(), json={'subject_type': 'user',
                                               'subject_id': 'bob',
                                               'permissions': ['pool.admin']})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _pool_rows(db) == []


def test_a_capped_delegate_may_grant_a_pool_permission_they_hold(api, db, seed):
    d = _capped(seed)
    _target(seed)

    r = api.as_user(d).post(_pool_url(), json={'subject_type': 'user',
                                               'subject_id': 'bob',
                                               'permissions': ['pool.view']})

    assert r.status_code in (200, 201), r.get_data(as_text=True)
    assert len(_pool_rows(db)) == 1


# --- revoking reaches across the boundary too ---------------------------------

def test_a_delegate_cannot_revoke_another_tenants_pool_grant(api, db, seed):
    d = _capped(seed)
    seed.tenant('tenant_y', ['cluster_1'])
    _target(seed, name='carol', tenant='tenant_y')
    seed.pool('cluster_1', 'pool_1', 'carol', ['pool.view'])

    r = api.as_user(d).delete(_pool_url() + '/user/carol')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert len(_pool_rows(db)) == 1, "the other tenant's grant was revoked"


def test_a_delegate_may_revoke_a_grant_inside_their_own_tenant(api, db, seed):
    d = _capped(seed)
    _target(seed)
    seed.pool('cluster_1', 'pool_1', 'bob', ['pool.view'])

    r = api.as_user(d).delete(_pool_url() + '/user/bob')

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _pool_rows(db) == []


def test_a_delegate_cannot_delete_another_tenants_vm_acl(api, db, seed):
    rbac.invalidate_vm_acls_cache()
    d = _capped(seed)
    seed.tenant('tenant_y', ['cluster_1'])
    _target(seed, name='carol', tenant='tenant_y')
    seed.vm_acl('cluster_1', 100, ['carol'])
    rbac.invalidate_vm_acls_cache()

    r = api.as_user(d).delete('/api/clusters/cluster_1/vm-acls/100')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _acl_row(db, 'cluster_1', 100) is not None


def test_a_delegate_may_delete_a_vm_acl_inside_their_own_tenant(api, db, seed):
    rbac.invalidate_vm_acls_cache()
    d = _capped(seed)
    _target(seed)
    seed.vm_acl('cluster_1', 100, ['bob'])
    rbac.invalidate_vm_acls_cache()

    r = api.as_user(d).delete('/api/clusters/cluster_1/vm-acls/100')

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _acl_row(db, 'cluster_1', 100) is None
