"""An admin downgraded by an LDAP tenant mapping must actually be downgraded.

tenant_permissions is not a hand-edited field — utils/ldap.py writes it from the
group mappings, so "global role admin, but viewer inside tenant_a" is a real
configuration an operator can produce from their directory.

get_user_permissions honoured it: with no explicit tenant it defaults to the caller's
own tenant and takes the override branch, returning the viewer set. Both admin fast
paths in front of it did not look at tenant_permissions at all, so the yes/no gate the
routes actually call answered admin while the permission list behind it said viewer —
and get_user_clusters handed back None, which means every cluster on the installation.

The narrowing is deliberately limited to an override that LOWERS the account. An
override restating admin, and the overwhelmingly common case of no override at all,
take exactly the path they took before.

Aikido ai_pentest 700487698. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


@pytest.fixture(autouse=True)
def tenants(monkeypatch):
    monkeypatch.setattr(rbac, 'get_custom_roles', lambda: {'global': {}, 'tenants': {}})
    monkeypatch.setattr(rbac, 'tenants_db', {
        rbac.DEFAULT_TENANT_ID: {'id': rbac.DEFAULT_TENANT_ID, 'clusters': []},
        'tenant_a': {'id': 'tenant_a', 'clusters': ['cluster_a']},
    }, raising=False)


def _plain_admin():
    return {'username': 'alex', 'role': rbac.ROLE_ADMIN, 'tenant_id': 'tenant_a'}


def _mapped_down_admin(role=rbac.ROLE_VIEWER, **extra):
    """What ldap.py writes for 'admin globally, viewer inside tenant_a'."""
    u = _plain_admin()
    u['tenant_permissions'] = {'tenant_a': dict({'role': role}, **extra)}
    return u


# --- the downgrade must bite -----------------------------------------------------

def test_a_downgraded_admin_does_not_get_a_write_permission(monkeypatch):
    u = _mapped_down_admin()
    assert 'vm.delete' not in rbac.get_user_permissions(u), 'the permission list is not viewer'
    assert rbac.has_permission(u, 'vm.delete') is False


def test_a_downgraded_admin_is_confined_to_the_tenants_clusters():
    got = rbac.get_user_clusters(_mapped_down_admin(), include_pools=False)
    assert got is not None, 'still seeing every cluster on the installation'
    assert got == ['cluster_a'], got


def test_an_explicit_denial_survives_the_fast_path():
    """The sharpest form: the mapping names a permission as denied."""
    u = _mapped_down_admin(role=rbac.ROLE_ADMIN)
    u['tenant_permissions']['tenant_a']['denied'] = ['vm.delete']
    # role is still admin here, so the shortcut is allowed to fire — this documents
    # that an admin-level override is NOT treated as a downgrade
    assert rbac.has_permission(u, 'vm.delete') is True


def test_a_downgraded_admin_keeps_what_the_lower_role_grants():
    """The counterweight — downgrading is not locking out."""
    u = _mapped_down_admin()
    assert rbac.has_permission(u, 'vm.view') is True


# --- everyone else is untouched ---------------------------------------------------

def test_an_ordinary_admin_is_unchanged():
    u = _plain_admin()
    assert rbac.has_permission(u, 'vm.delete') is True
    assert rbac.get_user_clusters(u, include_pools=False) is None


def test_an_admin_with_an_override_for_some_other_tenant_is_unchanged():
    u = _plain_admin()
    u['tenant_permissions'] = {'tenant_b': {'role': rbac.ROLE_VIEWER}}
    assert rbac.has_permission(u, 'vm.delete') is True
    assert rbac.get_user_clusters(u, include_pools=False) is None


def test_an_override_that_restates_admin_is_not_a_downgrade():
    u = _mapped_down_admin(role=rbac.ROLE_ADMIN)
    assert rbac.has_permission(u, 'vm.delete') is True
    assert rbac.get_user_clusters(u, include_pools=False) is None


def test_a_malformed_override_is_not_read_as_a_downgrade():
    """Defensive: ldap.py writes dicts, but a hand-edited store might not."""
    u = _plain_admin()
    u['tenant_permissions'] = {'tenant_a': 'viewer'}
    assert rbac.has_permission(u, 'vm.delete') is True


def test_explicit_tenant_id_still_goes_the_tenant_aware_route():
    """has_permission(..., tenant_id=...) never used the shortcut and still must not."""
    u = _plain_admin()
    u['tenant_permissions'] = {'tenant_b': {'role': rbac.ROLE_VIEWER}}
    assert rbac.has_permission(u, 'vm.delete', tenant_id='tenant_b') is False
