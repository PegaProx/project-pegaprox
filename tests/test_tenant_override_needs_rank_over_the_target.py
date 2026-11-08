"""Writing or removing a tenant override is managing the account it sits on.

PUT /api/users/<u>/permissions with a tenant_id weighed only what the request itself
conferred, and an unknown role name confers nothing. So a tenant delegate holding
admin.users could write {'role': '<anything>'} over a same-tenant global admin: the admin
was left holding no permissions at all, which made the account "manageable" for the
password reset (it weighs what the target holds), and DELETE on the override was never
weighed at all - so the delegate took the override off again and signed in as a full
administrator.

Now: the role has to exist, the target as it stands has to be one the caller may manage,
what it holds afterwards must stay within the caller's own permissions - and the same on
removal, which raises the account back to its own role. A password reset weighs the
account without its own tenant's override too, since that override is one DELETE away.

(#998) MK
"""
import pytest


@pytest.fixture
def acme(seed):
    seed.tenant('acme', ['cluster_1'])


def _delegate(seed):
    """admin.users inside acme, on top of the viewer set."""
    return seed.user('delegate', role='viewer', tenant_id='acme',
                     permissions=['admin.users', 'vm.view'])


def _overrides(db, username):
    return (db.get_user(username) or {}).get('tenant_permissions') or {}


# --- the chain from the report --------------------------------------------------------

def test_a_delegate_cannot_write_an_unknown_role_over_an_admin(api, db, seed, acme):
    d = _delegate(seed)
    seed.user('boss', role='admin', tenant_id='acme')

    r = api.as_user(d).put('/api/users/boss/permissions',
                           json={'tenant_id': 'acme', 'role': 'no-such-role'})

    assert r.status_code in (400, 403), r.get_data(as_text=True)
    assert _overrides(db, 'boss') == {}, 'the admin was stripped'


def test_a_delegate_cannot_lower_an_admin_with_a_real_role_either(api, db, seed, acme):
    """viewer is inside the delegate's own set, so the old ceiling let it through."""
    d = _delegate(seed)
    seed.user('boss', role='admin', tenant_id='acme')

    r = api.as_user(d).put('/api/users/boss/permissions',
                           json={'tenant_id': 'acme', 'role': 'viewer'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _overrides(db, 'boss') == {}


def test_a_delegate_cannot_lift_an_override_off_an_admin(api, db, seed, acme):
    """The last step: removing the override raised the account back to admin, unweighed."""
    d = _delegate(seed)
    seed.user('boss', role='admin', tenant_id='acme',
              tenant_permissions={'acme': {'role': 'viewer', 'extra': [], 'denied': []}})

    r = api.as_user(d).delete('/api/users/boss/tenant-permissions/acme')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'acme' in _overrides(db, 'boss'), 'the override came off'


def test_a_delegate_cannot_reset_a_lowered_admin(api, db, seed, acme):
    """However the admin got lowered (a directory mapping writes the same field), the
    account is still an administrator the moment the override goes."""
    d = _delegate(seed)
    seed.user('boss', role='admin', tenant_id='acme',
              tenant_permissions={'acme': {'role': 'viewer', 'extra': [], 'denied': []}})
    before = db.get_user('boss')['password_hash']

    r = api.as_user(d).put('/api/users/boss/password', json={'password': 'Takeover-2026!x'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert db.get_user('boss')['password_hash'] == before


def test_an_unknown_role_is_refused_for_a_global_admin_too(api, db, seed, acme):
    """Not a privilege question: a name that resolves to nothing is a mistake to store."""
    admin = seed.user('root', role='admin')
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(admin).put('/api/users/bob/permissions',
                               json={'tenant_id': 'acme', 'role': 'no-such-role'})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert _overrides(db, 'bob') == {}


def test_removal_weighs_what_the_account_returns_to(api, db, seed, acme):
    """A user-role account a global admin lowered to viewer in acme: lifting that is a
    grant of the user set, which a viewer-level delegate does not hold."""
    d = _delegate(seed)
    seed.user('bob', role='user', tenant_id='acme',
              tenant_permissions={'acme': {'role': 'viewer', 'extra': [], 'denied': []}})

    r = api.as_user(d).delete('/api/users/bob/tenant-permissions/acme')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'acme' in _overrides(db, 'bob')


# --- what keeps working -----------------------------------------------------------------

def test_a_delegate_still_manages_a_peer_inside_the_ceiling(api, db, seed, acme):
    d = _delegate(seed)
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'role': 'viewer', 'extra': ['vm.view']})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _overrides(db, 'bob')['acme']['role'] == 'viewer'

    r = api.as_user(d).delete('/api/users/bob/tenant-permissions/acme')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _overrides(db, 'bob') == {}


def test_a_delegate_may_still_narrow_a_peer(api, db, seed, acme):
    d = _delegate(seed)
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'denied': ['vm.console']})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _overrides(db, 'bob')['acme']['denied'] == ['vm.console']


def test_a_delegate_may_reset_a_peer_inside_the_ceiling(api, db, seed, acme):
    d = _delegate(seed)
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(d).put('/api/users/bob/password', json={'password': 'Rotated-2026!x'})

    assert r.status_code == 200, r.get_data(as_text=True)


def test_a_global_admin_keeps_full_delegation(api, db, seed, acme):
    admin = seed.user('root', role='admin')
    seed.user('boss', role='admin', tenant_id='acme')

    r = api.as_user(admin).put('/api/users/boss/permissions',
                               json={'tenant_id': 'acme', 'role': 'viewer'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _overrides(db, 'boss')['acme']['role'] == 'viewer'

    r = api.as_user(admin).delete('/api/users/boss/tenant-permissions/acme')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _overrides(db, 'boss') == {}


def test_a_global_admin_may_set_a_custom_role_of_that_tenant(api, db, seed, acme):
    import json
    import pegaprox.utils.rbac as rbac
    db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, "
                    "created_at) VALUES ('acmeops', ?, 'x', 'acme', '2026-01-01T00:00:00')",
                    (json.dumps(['vm.view', 'vm.start']),))
    db.conn.commit()
    rbac.invalidate_roles_cache()
    admin = seed.user('root', role='admin')
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(admin).put('/api/users/bob/permissions',
                               json={'tenant_id': 'acme', 'role': 'acmeops'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert sorted(r.get_json()['effective_permissions']) == ['vm.start', 'vm.view']
