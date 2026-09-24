"""Every gate has to read a VM-ACL row the same way.

Nine places ask "does this ACL row grant this user access". Eight honour the `'*'`
wildcard; caller_is_scoped() tested `username in users` and did not. So a user whose
only reach into a cluster was a wildcard ACL was classified as a cluster-wide operator
and handed the whole-cluster views, while user_can_access_vm() correctly treated them
as ACL-scoped - the two gates disagreed about the same row.

Aikido ai_pentest 700487205. MK
"""
import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped


# --- the shared definition ---------------------------------------------------

@pytest.mark.parametrize('members,user,expected', [
    (['alice'], 'alice', True),
    (['alice'], 'bob', False),
    (['*'], 'anyone', True),
    (['alice', '*'], 'bob', True),
    ([], 'alice', False),
    (None, 'alice', False),
])
def test_membership_is_one_definition(members, user, expected):
    assert rbac.acl_grants_user({'users': members}, user) is expected


def test_a_row_that_is_not_a_dict_grants_nobody(): 
    assert rbac.acl_grants_user(None, 'alice') is False
    assert rbac.acl_grants_user('junk', 'alice') is False


# --- the gates now agree -----------------------------------------------------

def test_a_wildcard_only_user_is_confined_not_cluster_wide(db, seed):
    """The finding: this user reaches VM 100 through a wildcard row and nothing else.
    user_can_access_vm scopes them to it; caller_is_scoped used to call them an
    unconfined operator, which is what opens the whole-cluster views."""
    rbac.invalidate_vm_acls_cache()
    user = seed.user('alice', role='user', tenant_id='tenant_x')
    seed.tenant('tenant_x', ['cluster_1'])
    seed.vm_acl('cluster_1', 100, ['*'])
    rbac.invalidate_vm_acls_cache()

    assert caller_is_scoped(user, 'cluster_1') is True


def test_an_explicitly_named_user_is_still_confined(db, seed):
    rbac.invalidate_vm_acls_cache()
    user = seed.user('alice', role='user', tenant_id='tenant_x')
    seed.tenant('tenant_x', ['cluster_1'])
    seed.vm_acl('cluster_1', 100, ['alice'])
    rbac.invalidate_vm_acls_cache()

    assert caller_is_scoped(user, 'cluster_1') is True


def test_a_plain_operator_with_no_acl_stays_unconfined(db, seed):
    """The invariant: this fix must not start confining ordinary cluster operators."""
    rbac.invalidate_vm_acls_cache()
    user = seed.user('alice', role='user', tenant_id='tenant_x')
    seed.tenant('tenant_x', ['cluster_1'])

    assert caller_is_scoped(user, 'cluster_1') is False


def test_an_admin_is_never_confined(db, seed):
    rbac.invalidate_vm_acls_cache()
    admin = seed.user('root', role='admin')
    seed.vm_acl('cluster_1', 100, ['*'])
    rbac.invalidate_vm_acls_cache()

    assert caller_is_scoped(admin, 'cluster_1') is False


def test_the_wildcard_still_grants_access_to_the_vm_itself(db, seed):
    """Both halves of the answer: confined, but genuinely allowed on that VM."""
    rbac.invalidate_vm_acls_cache()
    user = seed.user('alice', role='user', tenant_id='tenant_x')
    seed.tenant('tenant_x', ['cluster_1'])
    seed.vm_acl('cluster_1', 100, ['*'])
    rbac.invalidate_vm_acls_cache()

    assert rbac.user_can_access_vm(user, 'cluster_1', 100, 'vm.view') is True
