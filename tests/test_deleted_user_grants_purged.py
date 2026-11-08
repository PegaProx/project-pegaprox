"""Deleting an account must take its per-resource grants with it.

delete_user revoked sessions, console tokens and API tokens, but VM-ACL memberships
and pool permissions are keyed by the bare username and were left in place. The next
account created under that name - a rehire, an MSP reusing a customer login, a tenant
delegate naming a new user after one another tenant deleted - inherited every VM and
pool the old account held, silently, with nothing in the UI to show for it.

Aikido ai_pentest 700487669. MK
"""
import json

import pytest

from pegaprox.models.permissions import ROLE_ADMIN
import pegaprox.utils.rbac as rbac


def _acl_members(db, cluster_id, vmid):
    cur = db.conn.cursor()
    cur.execute('SELECT users FROM vm_acls WHERE cluster_id=? AND vmid=?',
                (cluster_id, str(vmid)))
    row = cur.fetchone()
    return None if row is None else json.loads(row[0] or '[]')


def _pool_rows(db, username):
    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM pool_permissions WHERE subject_type='user' "
                "AND subject_id=?", (username,))
    return cur.fetchone()[0]


def test_the_vm_acl_membership_goes_with_the_account(db, seed):
    seed.user('alice')
    seed.vm_acl('cluster_1', 100, ['alice', 'bob'])

    db.delete_user('alice')

    assert _acl_members(db, 'cluster_1', 100) == ['bob']


def test_an_acl_left_with_nobody_is_removed(db, seed):
    """An empty ACL row grants nothing but still makes the cluster "have ACLs",
    which narrows what other callers are shown."""
    seed.user('alice')
    seed.vm_acl('cluster_1', 100, ['alice'])

    db.delete_user('alice')

    assert _acl_members(db, 'cluster_1', 100) is None


def test_pool_permissions_go_with_the_account(db, seed):
    seed.user('alice')
    seed.pool('cluster_1', 'pool_1', 'alice', ['pool.view', 'vm.start'])

    db.delete_user('alice')

    assert _pool_rows(db, 'alice') == 0


def test_a_recreated_name_does_not_inherit_the_old_grants(db, seed):
    """The finding as a user would hit it."""
    seed.user('alice')
    seed.tenant('default', ['cluster_1'])
    seed.vm_acl('cluster_1', 100, ['alice'])
    rbac.invalidate_vm_acls_cache()

    db.delete_user('alice')
    newcomer = seed.user('alice', role='viewer')       # same name, new person
    rbac.invalidate_vm_acls_cache()

    assert rbac.user_can_access_vm(newcomer, 'cluster_1', 100, 'vm.start') is False


def test_a_wildcard_grant_is_not_this_user_and_stays(db, seed):
    seed.user('alice')
    seed.vm_acl('cluster_1', 100, ['alice', '*'])

    db.delete_user('alice')

    assert _acl_members(db, 'cluster_1', 100) == ['*']


def test_other_peoples_grants_are_untouched(db, seed):
    seed.user('alice')
    seed.user('bob')
    seed.vm_acl('cluster_1', 100, ['alice'])
    seed.vm_acl('cluster_1', 200, ['bob'])
    seed.pool('cluster_1', 'pool_1', 'bob', ['pool.view'])

    db.delete_user('alice')

    assert _acl_members(db, 'cluster_1', 200) == ['bob']
    assert _pool_rows(db, 'bob') == 1


def test_deleting_a_user_with_no_grants_is_a_no_op(db, seed):
    seed.user('alice')

    assert db.purge_user_grants('alice') == {'vm_acls': 0, 'pool_permissions': 0}
