"""The permission ceiling and the runtime grant resolved a role name differently.

Two functions answer "what does the role `ops` grant?" and they walk the two
namespaces in opposite orders:

    api/users.py  _role_permissions()            global first, then tenants
    utils/rbac.py get_role_permissions_for_user() tenant first, then global

_caller_can_grant_role() — the guard that stops a delegate handing out
permissions it does not hold itself — asks the first one. The user's actual
permissions at request time come from the second. So with a harmless GLOBAL role
`ops` and a powerful TENANT role of the same name, the ceiling check weighs the
harmless one and the account receives the powerful one:

    grant check weighs : ['vm.view']
    account receives   : ['admin.settings', 'admin.users', 'vm.view']

Measured directly in test_the_check_never_weighs_less_than_the_grant below,
which is the real statement: whatever the runtime hands out, the ceiling check
must have looked at at least that much. Fixed by resolving an ambiguous name to
the UNION of both namespaces — for a ceiling check, "it could be either" has to
mean "you need to cover both", and that holds no matter which resolver wins
downstream. Aikido ai_pentest 700488943. MK
"""
import pytest

import pegaprox.api.users as users_api
import pegaprox.utils.rbac as rbac

USERS = '/api/users'
TENANT = 'acme'

WEAK = ['vm.view']
STRONG = ['vm.view', 'admin.users', 'admin.settings']


@pytest.fixture
def colliding_roles(api, db):
    """A global 'ops' and a tenant 'ops'. Both namespaces are writable by a global
    admin through the normal role endpoints, so this is a reachable state, not a
    contrived one."""
    roles = {
        'global': {'ops': {'name': 'Ops (read-only)', 'permissions': list(WEAK),
                           'created_by': 'boss'}},
        'tenants': {TENANT: {'ops': {'name': 'Ops (tenant)', 'permissions': list(STRONG),
                                     'created_by': 'boss'}}},
    }
    assert rbac.save_custom_roles(roles), 'could not seed the colliding roles'
    rbac.invalidate_roles_cache()
    return roles


@pytest.fixture
def delegate(api, seed):
    """admin.users on top of the ordinary user role. Holds vm.view (so the weak
    reading of 'ops' is fully covered) and NOT admin.settings (so the strong one
    is not)."""
    return api.as_user(seed.user('delegate', role='user', tenant_id=TENANT,
                                 permissions=['admin.users']))


@pytest.fixture
def victim(seed):
    return seed.user('victim', role='viewer', tenant_id=TENANT)


def test_the_check_never_weighs_less_than_the_grant(colliding_roles):
    """The property, with no HTTP in the way."""
    weighed = set(users_api._role_permissions('ops'))
    granted = set(rbac.get_role_permissions_for_user(
        {'role': 'ops', 'tenant_id': TENANT}, TENANT))

    assert granted <= weighed, (
        'the ceiling check never saw: ' + ', '.join(sorted(granted - weighed)))


def test_a_delegate_cannot_assign_the_role_it_does_not_cover(delegate, victim,
                                                             colliding_roles, seed):
    r = delegate.put(f'{USERS}/victim', json={'role': 'ops'})

    assert r.status_code == 403, (
        f'assigned a role granting admin.settings without holding it: {r.data}')
    assert (seed.db.get_user('victim') or {}).get('role') == 'viewer'


def test_the_victim_did_not_end_up_with_the_stronger_permissions(delegate, victim,
                                                                 colliding_roles, seed):
    """The consequence, stated as what the account can actually do."""
    delegate.put(f'{USERS}/victim', json={'role': 'ops'})

    stored = seed.db.get_user('victim') or {}
    stored['username'] = 'victim'
    effective = set(rbac.get_user_permissions(stored))
    assert 'admin.users' not in effective, 'victim was handed admin.users'
    assert 'admin.settings' not in effective, 'victim was handed admin.settings'


def test_a_delegate_still_assigns_roles_it_does_cover(delegate, victim, seed):
    """The mirror — no collision in play, ordinary delegation must survive."""
    r = delegate.put(f'{USERS}/victim', json={'role': 'user'})
    assert r.status_code == 200, r.data
    assert (seed.db.get_user('victim') or {}).get('role') == 'user'


def test_a_global_admin_keeps_full_delegation(api, seed, victim, colliding_roles):
    boss = api.as_user(seed.user('boss', role='admin'))
    r = boss.put(f'{USERS}/victim', json={'role': 'ops'})
    assert r.status_code == 200, r.data
