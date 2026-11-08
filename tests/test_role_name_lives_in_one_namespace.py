"""A custom role name resolves to the role somebody meant, not to whichever table has it.

_tenant_defining_role remaps a caller of the DEFAULT tenant to the one tenant that defines
their role name, and it did so even when a GLOBAL role of that name existed - which is the
role such a caller actually holds. create_custom_role allowed the collision, so a tenant
admin creating 'ops' in their tenant turned every default-tenant holder of the global 'ops'
into a holder of theirs: the attacker's permission list, the attacker's clusters.

create_user and update_user had the same reading of "the tenant that defines it": the
first one the store returned, so with two tenants defining a name, or a global role beside
a tenant one, the account moved into a tenant nobody chose.

Now a global role of the name wins for a default-tenant caller, a name lives in the global
namespace or in tenant tables but not both, and the user routes resolve the tenant the
request names, refusing to guess between several.

(#1013) MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac


def _role(db, name, perms, tenant=''):
    db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, "
                    "created_at) VALUES (?, ?, 'x', ?, '2026-01-01T00:00:00')",
                    (name, json.dumps(perms), tenant))
    db.conn.commit()
    rbac.invalidate_roles_cache()


@pytest.fixture
def tenants(seed):
    seed.tenant('default', [])
    seed.tenant('evil', ['cluster_e'])
    seed.tenant('acme', ['cluster_a'])


# --- resolution -------------------------------------------------------------------------

def test_a_global_role_beats_a_tenant_role_of_the_same_name(db, seed, tenants):
    """The state an existing install can already be in: both are stored."""
    _role(db, 'ops', ['vm.view', 'vm.start'])
    _role(db, 'ops', ['vm.view', 'vm.delete', 'cluster.config'], tenant='evil')
    u = seed.user('robin', role='ops', tenant_id='default')

    assert rbac._tenant_defining_role('ops', 'default') == 'default'
    assert sorted(rbac.get_user_permissions(u)) == ['vm.start', 'vm.view']
    assert rbac.get_user_clusters(u, include_pools=False) is None, 'moved into the tenant'


def test_a_tenant_only_role_still_remaps_a_default_tenant_holder(db, seed, tenants):
    """The case the remap exists for (an API token of a default-tenant owner)."""
    _role(db, 'acmeops', ['vm.view', 'vm.start'], tenant='acme')
    u = seed.user('robin', role='acmeops', tenant_id='default')

    assert rbac._tenant_defining_role('acmeops', 'default') == 'acme'
    assert sorted(rbac.get_user_permissions(u)) == ['vm.start', 'vm.view']
    assert rbac.get_user_clusters(u, include_pools=False) == ['cluster_a']


# --- creation -------------------------------------------------------------------------

def test_a_tenant_admin_cannot_shadow_a_global_role(api, db, seed, tenants):
    _role(db, 'ops', ['vm.view'])
    _role(db, 'evilroles', ['admin.roles', 'vm.view', 'vm.delete'], tenant='evil')
    mallory = seed.user('mallory', role='evilroles', tenant_id='evil')

    r = api.as_user(mallory).post('/api/roles', json={'id': 'ops', 'permissions': ['vm.view',
                                                                                   'vm.delete']})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'ops' not in rbac.load_custom_roles()['tenants'].get('evil', {})


def test_a_template_cannot_shadow_a_global_role_either(api, db, seed, tenants):
    _role(db, 'ops', ['vm.view'])
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/roles/templates/vm_operator/apply',
                                json={'role_id': 'ops', 'tenant_id': 'evil'})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'ops' not in rbac.load_custom_roles()['tenants'].get('evil', {})


def test_a_global_role_cannot_take_a_tenants_name(api, db, seed, tenants):
    _role(db, 'acmeops', ['vm.view'], tenant='acme')
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/roles', json={'id': 'acmeops', 'permissions': ['vm.view']})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'acmeops' not in rbac.load_custom_roles()['global']


def test_two_tenants_may_still_each_have_an_ops_role(api, db, seed, tenants):
    _role(db, 'ops', ['vm.view'], tenant='acme')
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/roles', json={'id': 'ops', 'permissions': ['vm.view'],
                                                    'tenant_id': 'evil'})

    assert r.status_code == 200, r.get_data(as_text=True)


# --- assignment -------------------------------------------------------------------------

def test_creating_a_user_lands_in_the_tenant_the_request_names(api, db, seed, tenants):
    _role(db, 'ops', ['vm.view'], tenant='evil')
    _role(db, 'ops', ['vm.view'], tenant='acme')
    # ask for the one the store does NOT hand out first, which is what the loop took
    first = next(t for t, r in rbac.load_custom_roles()['tenants'].items() if 'ops' in r)
    wanted = 'acme' if first == 'evil' else 'evil'
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/users', json={
        'username': 'newbie', 'password': 'Welcome-2026!x', 'role': 'ops', 'tenant_id': wanted})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('newbie')['tenant_id'] == wanted


def test_an_ambiguous_role_without_a_tenant_is_refused(api, db, seed, tenants):
    _role(db, 'ops', ['vm.view'], tenant='evil')
    _role(db, 'ops', ['vm.view'], tenant='acme')
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/users', json={
        'username': 'newbie', 'password': 'Welcome-2026!x', 'role': 'ops'})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert db.get_user('newbie') is None


def test_assigning_a_global_role_keeps_the_account_where_it_is(api, db, seed, tenants):
    _role(db, 'ops', ['vm.view'])
    _role(db, 'ops', ['vm.view', 'vm.delete'], tenant='evil')
    admin = seed.user('root', role='admin')
    seed.user('robin', role='viewer', tenant_id='default')

    r = api.as_user(admin).put('/api/users/robin', json={'role': 'ops'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('robin')['tenant_id'] == 'default', 'moved into the other tenant'


def test_assigning_a_tenant_role_still_moves_the_account_into_it(api, db, seed, tenants):
    _role(db, 'acmeops', ['vm.view'], tenant='acme')
    admin = seed.user('root', role='admin')
    seed.user('robin', role='viewer', tenant_id='default')

    r = api.as_user(admin).put('/api/users/robin', json={'role': 'acmeops'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('robin')['tenant_id'] == 'acme'


def test_a_tenant_admin_still_cannot_assign_another_tenants_role(api, db, seed, tenants):
    _role(db, 'acmeops', ['vm.view'], tenant='acme')
    from pegaprox.models.permissions import ROLE_PERMISSIONS
    _role(db, 'evilusers', ROLE_PERMISSIONS['viewer'] + ['admin.users'], tenant='evil')
    mallory = seed.user('mallory', role='evilusers', tenant_id='evil')
    seed.user('pawn', role='viewer', tenant_id='evil')

    r = api.as_user(mallory).put('/api/users/pawn', json={'role': 'acmeops'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert db.get_user('pawn')['tenant_id'] == 'evil'


# --- the default tenant's own table -----------------------------------------------------

def test_a_tenant_admin_cannot_take_a_name_the_default_tenant_defines(api, db, seed, tenants):
    """A default-tenant account resolves its role through every tenant table that has the
    name. One more tenant defining it made the name ambiguous, and the account was left with
    no permissions and no clusters: another tenant's admin switching it off."""
    _role(db, 'ops', ['vm.view', 'cluster.view'], tenant='default')
    robin = seed.user('robin', role='ops', tenant_id='default')
    _role(db, 'evilroles', ['admin.roles', 'vm.view'], tenant='evil')
    mallory = seed.user('mallory', role='evilroles', tenant_id='evil')

    r = api.as_user(mallory).post('/api/roles', json={'id': 'ops', 'permissions': ['vm.view']})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert sorted(rbac.get_user_permissions(robin)) == ['cluster.view', 'vm.view']
    assert rbac.get_user_clusters(robin, include_pools=False) is None


def test_the_default_tenant_cannot_take_another_tenants_name(api, db, seed, tenants):
    """The same ambiguity from the other side, for default-tenant holders of acme's role."""
    _role(db, 'acmeops', ['vm.view'], tenant='acme')
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/roles', json={'id': 'acmeops', 'permissions': ['vm.view'],
                                                    'tenant_id': 'default'})
    assert r.status_code == 400, r.get_data(as_text=True)
    r = api.as_user(admin).post('/api/roles/templates/vm_operator/apply',
                                json={'role_id': 'acmeops', 'tenant_id': 'default'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'acmeops' not in rbac.load_custom_roles()['tenants'].get('default', {})
