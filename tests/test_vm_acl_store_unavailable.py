"""An unread VM-ACL store must not read as an empty one.

load_vm_acls() answered `{}` for two very different things: "this install has no
VM ACLs" and "the database did not answer". Every authorization path reads an empty
ACL set as "this caller is not confined to particular VMs" and falls through to their
role-wide grant - so a momentary DB failure handed an ACL-scoped user the whole
cluster, and get_vm_acls() kept that answer for its 30s TTL.

Aikido ai_pentest 700487652. Same shape as the first-run findings in
test_first_run_gate_and_legacy_restore.py: the undetermined state was read as the
permissive one. MK
"""
import pytest

from pegaprox.models.permissions import ROLE_ADMIN
import pegaprox.utils.rbac as rbac


@pytest.fixture
def broken_store(db, monkeypatch):
    """ONLY the ACL read fails; every other DB call goes to the real test database.

    A stub that breaks everything would let these tests pass through some unrelated
    `except Exception` further up and prove nothing - caller_is_scoped() in particular
    has a pool lookup ahead of its ACL loop that would swallow a broken handle first.
    """
    rbac.invalidate_vm_acls_cache()

    class _AclReadFails:
        def get_all_vm_acls(self):
            raise RuntimeError('database is locked')

        def __getattr__(self, name):
            return getattr(db, name)

    monkeypatch.setattr(rbac, 'get_db', lambda: _AclReadFails())
    monkeypatch.setattr(rbac.os.path, 'exists', lambda p: False)   # no legacy file either
    yield
    rbac.invalidate_vm_acls_cache()


# --- the snapshot itself -----------------------------------------------------

def test_a_failed_load_is_marked_unavailable(broken_store):
    assert rbac.acls_unavailable(rbac.load_vm_acls()) is True


def test_a_successful_load_is_not_marked_unavailable(db, seed):
    rbac.invalidate_vm_acls_cache()
    seed.vm_acl('cluster_1', 100, ['alice'])
    acls = rbac.load_vm_acls()
    assert rbac.acls_unavailable(acls) is False
    assert '100' in acls.get('cluster_1', {})


def test_an_install_with_no_acls_is_not_marked_unavailable(db):
    """The distinction this whole change rests on: empty is not broken."""
    rbac.invalidate_vm_acls_cache()
    acls = rbac.load_vm_acls()
    assert dict(acls) == {}
    assert rbac.acls_unavailable(acls) is False


def test_a_failed_load_is_never_cached(broken_store, monkeypatch):
    """Otherwise one DB hiccup denies every scoped user for the full TTL."""
    rbac.get_vm_acls()
    assert rbac._vm_acls_cache is None


# --- the decisions -----------------------------------------------------------

def test_a_scoped_user_is_denied_while_the_store_is_unreadable(db, seed, broken_store):
    """Before: empty ACLs -> "not confined" -> has_permission() -> whole cluster."""
    user = seed.user('alice', role='user')

    assert rbac.user_can_access_vm(user, 'cluster_1', 100, 'vm.start') is False


def test_an_admin_is_unaffected_by_the_store(db, seed, broken_store):
    """The admin bypass sits above the ACL lookup and must stay there."""
    admin = seed.user('root', role=ROLE_ADMIN)

    assert rbac.user_can_access_vm(admin, 'cluster_1', 100, 'vm.start') is True


def test_the_vm_list_is_empty_not_unrestricted(db, seed, broken_store):
    """get_user_vms() answers None for "no restrictions" - the worst possible
    answer when the restrictions are what we failed to read."""
    user = seed.user('alice', role='user')

    assert rbac.get_user_vms(user, 'cluster_1') == []


def test_vmware_per_vm_access_is_denied_too(db, seed, broken_store):
    user = seed.user('alice', role='user')

    assert rbac.user_can_access_vmware_vm(user, 'esxi_1', 'vm-42', 'vmware.vm.view') is False


def test_a_caller_counts_as_confined_while_the_store_is_unreadable(db, seed, broken_store):
    """caller_is_scoped() documents itself as fail-closed; the empty snapshot would
    have walked past its ACL loop and reported "cluster-wide operator"."""
    from pegaprox.api.helpers import caller_is_scoped
    user = seed.user('alice', role='user')
    seed.tenant('default', ['cluster_1'])

    assert caller_is_scoped(user, 'cluster_1') is True


# --- what must not change ----------------------------------------------------

def test_a_readable_empty_store_still_grants_the_cluster_wide_operator(db, seed):
    """The invariant: an install with no ACLs at all keeps working exactly as before."""
    rbac.invalidate_vm_acls_cache()
    user = seed.user('alice', role='user')
    seed.tenant('default', ['cluster_1'])

    assert rbac.user_can_access_vm(user, 'cluster_1', 100, 'vm.view') is True


def test_a_readable_store_still_scopes_an_acl_user(db, seed):
    rbac.invalidate_vm_acls_cache()
    user = seed.user('alice', role='user')
    seed.tenant('default', ['cluster_1'])
    seed.vm_acl('cluster_1', 100, ['alice'])
    rbac.invalidate_vm_acls_cache()

    assert rbac.user_can_access_vm(user, 'cluster_1', 100, 'vm.view') is True
    assert rbac.user_can_access_vm(user, 'cluster_1', 999, 'vm.view') is False
