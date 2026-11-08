"""A tenant delegate cannot write themselves permissions they do not hold.

PUT /api/users/<u>/permissions has been hardened twice already: global permissions need a
global admin, a tenant delegate is confined to their own tenant, and neither ROLE_ADMIN nor
any admin.* permission may appear in `extra`. Two ways past that were left:

  * the admin.* PREFIX is all that was checked, so every permission without it -
    vm.delete, storage.edit, cluster.edit - could be handed out by a delegate who does
    not hold it. The sibling route create_custom_role has asked _caller_can_grant_perms
    exactly this question since August; this one never did.
  * `role` was compared against ROLE_ADMIN and never resolved. A custom role carrying
    admin.* permissions - legitimately created by a global admin - walks straight past a
    prefix test when it is set as the tenant role.

And there was no self-check at all, so a delegate could write their own entry.

Aikido ai_pentest 700487681. MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac


def _delegate(seed):
    """admin.users inside one tenant, vm.view and nothing else."""
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('delegate', role='viewer', tenant_id='acme',
                     permissions=['admin.users', 'vm.view'])


def _victim(seed):
    return seed.user('bob', role='viewer', tenant_id='acme')


def _tenant_perms(db, username):
    u = db.get_user(username)
    return (u or {}).get('tenant_permissions') or {}


def test_a_delegate_cannot_grant_a_permission_they_lack(db, api, seed):
    """No admin. prefix, so the old check waved it through."""
    d = _delegate(seed)
    _victim(seed)

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'extra': ['vm.delete']})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _tenant_perms(db, 'bob') == {}


def test_a_delegate_may_grant_what_they_hold(db, api, seed):
    """The invariant: delegation still works inside the ceiling."""
    d = _delegate(seed)
    _victim(seed)

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'extra': ['vm.view']})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _tenant_perms(db, 'bob')['acme']['extra'] == ['vm.view']


def test_a_custom_role_cannot_smuggle_admin_permissions_in(db, api, seed):
    """The prefix test never resolved `role`, so a role carrying admin.* went past it."""
    rbac.invalidate_roles_cache()
    db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, "
                    "created_at) VALUES ('superops', ?, 'x', '', '2026-01-01T00:00:00')",
                    (json.dumps(['admin.settings', 'vm.view']),))
    db.conn.commit()
    rbac.invalidate_roles_cache()
    d = _delegate(seed)
    _victim(seed)

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'role': 'superops'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _tenant_perms(db, 'bob') == {}


def test_a_delegate_cannot_edit_their_own_grants(db, api, seed):
    d = _delegate(seed)

    r = api.as_user(d).put('/api/users/delegate/permissions',
                           json={'tenant_id': 'acme', 'extra': ['vm.view']})

    assert r.status_code == 403, r.get_data(as_text=True)


def test_the_admin_prefix_rule_still_holds(db, api, seed):
    """The check that was already there must not have been lost in the rewrite."""
    d = _delegate(seed)
    _victim(seed)

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'extra': ['admin.users']})

    assert r.status_code == 403, r.get_data(as_text=True)


def test_a_global_admin_is_unaffected(db, api, seed):
    admin = seed.user('root', role='admin')
    seed.tenant('acme', clusters=['cluster_1'])
    _victim(seed)

    r = api.as_user(admin).put('/api/users/bob/permissions',
                               json={'tenant_id': 'acme', 'extra': ['vm.delete']})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _tenant_perms(db, 'bob')['acme']['extra'] == ['vm.delete']
