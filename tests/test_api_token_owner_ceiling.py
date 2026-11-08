"""An API token cannot outlive its owner's authority.

require_auth re-floors a BUILTIN token role against the owner's current role on every
request. A token bound to a CUSTOM role never goes through that floor - build_authz_user
keeps the role name deliberately, because get_user_clusters needs it to resolve the
role's tenant. The consequence was that the custom-role branch had no ceiling at all:
demote the owner, strip one of their permissions, or widen the custom role itself, and a
token minted earlier carried on resolving through the old, larger set.

The cap has to be applied where permissions are resolved rather than where the identity
is built, because the answer differs per tenant.

Aikido ai_pentest 700487540 / 700487762 / 700488293. MK
"""
import json

import pytest

import pegaprox.utils.auth as authmod
import pegaprox.utils.rbac as rbac


@pytest.fixture
def ops_role(db):
    """A custom role that can do more than a viewer."""
    rbac.invalidate_roles_cache()
    db.conn.execute(
        "INSERT INTO custom_roles (name, permissions, description, tenant_id, created_at) "
        "VALUES ('ops', ?, 'ops', '', '2026-01-01T00:00:00')",
        (json.dumps(['vm.view', 'vm.delete', 'vm.config']),))
    db.conn.commit()
    rbac.invalidate_roles_cache()
    yield
    rbac.invalidate_roles_cache()


def _token_identity(username, role):
    return authmod.build_authz_user(username, {'api_token': True, 'role': role})


@pytest.mark.parametrize('permission', ['vm.delete', 'vm.config'])
def test_a_demoted_owner_drags_their_custom_role_token_down(db, seed, ops_role, permission):
    """The finding: the owner is a viewer now, so the token is too. Both permissions
    listed separately - each one is a distinct thing the token should have lost."""
    seed.user('owner', role='viewer')

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, permission) is False


def test_widening_the_custom_role_does_not_widen_the_token_past_its_owner(db, seed, ops_role):
    """The role is editable after the token was minted. An admin adding a permission to
    a custom role must not hand it to a token whose owner cannot use it."""
    seed.user('owner', role='viewer')
    rbac.invalidate_roles_cache()
    db.conn.execute("UPDATE custom_roles SET permissions = ? WHERE name = 'ops'",
                    (json.dumps(['vm.view', 'vm.delete', 'vm.config', 'cluster.edit']),))
    db.conn.commit()
    rbac.invalidate_roles_cache()

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, 'cluster.edit') is False


def test_a_tenant_demotion_reaches_the_token_in_that_tenant(db, seed, ops_role):
    """Per-tenant is exactly why the cap lives in get_user_permissions: the owner is a
    full `user` globally but cut down to viewer inside tenant_x, so their token loses
    vm.delete THERE and keeps it elsewhere."""
    seed.user('owner', role='user',
              tenant_permissions={'tenant_x': {'role': 'viewer', 'extra': [], 'denied': []}})

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, 'vm.config', 'tenant_x') is False


def test_the_owner_keeps_the_permission_outside_the_demoted_tenant(db, seed, ops_role):
    seed.user('owner', role='user',
              tenant_permissions={'tenant_x': {'role': 'viewer', 'extra': [], 'denied': []}})

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, 'vm.config', 'tenant_y') is True


def test_the_token_keeps_what_the_owner_still_holds(db, seed, ops_role):
    """A ceiling, not a ban - the intersection is what survives."""
    seed.user('owner', role='viewer')

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, 'vm.view') is True


def test_an_undemoted_owner_keeps_the_full_custom_role(db, seed, ops_role):
    """The invariant: while the owner still holds it, the token still works."""
    seed.user('owner', role='user')      # the builtin user role holds vm.delete? no - check
    user = _token_identity('owner', 'ops')

    # vm.config is in both the custom role and the builtin `user` role
    assert rbac.has_permission(user, 'vm.config') is True


def test_an_admin_owner_is_not_narrowed(db, seed, ops_role):
    seed.user('owner', role='admin')

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, 'vm.delete') is True


def test_stripping_a_direct_permission_reaches_the_token(db, seed, ops_role):
    """Not just the role label: a denied permission has to bite too."""
    seed.user('owner', role='admin', denied=['vm.delete'])

    user = _token_identity('owner', 'ops')

    assert rbac.has_permission(user, 'vm.delete') is False


def test_session_auth_is_untouched(db, seed, ops_role):
    """The cap keys off the token marker; an interactive login must not see it."""
    u = seed.user('owner', role='admin')
    session_identity = authmod.build_authz_user('owner', {})

    assert '_token_owner_capped' not in session_identity
    assert rbac.has_permission(session_identity, 'vm.delete') is True


def test_a_builtin_role_token_still_floors_numerically(db, seed):
    """The pre-existing behaviour for builtin roles must not change."""
    seed.user('owner', role='viewer')

    user = _token_identity('owner', 'admin')      # token claims admin, owner is viewer

    assert user['effective_role'] == 'viewer'
    assert rbac.has_permission(user, 'vm.delete') is False
