"""Changing a user's role was the one account operation with no rank guard.

pegaprox/api/users.py gates the dangerous parts of PUT /api/users/<u> with
_caller_can_manage_user(target) — "the caller holds every effective permission
the target has". Disabling an account goes through it. Resetting a password and
clearing 2FA (their own routes) go through it. Changing the target's ROLE did
not, and it is strictly the more powerful operation: after a demotion the target
holds fewer permissions, so _caller_can_manage_user starts returning True and
every other guard opens up.

Two shapes, same hole:

  * two requests. PUT {"role": "viewer"} on an administrator, then reset their
    password on the next call — by then they are a viewer and the rank guard
    passes. The demotion is persisted, so this needs nothing clever.
  * one request. The handler mutates user['role'] at the top of the body and
    only afterwards reaches `if 'enabled' in data:`, which calls
    _caller_can_manage_user(user) on the ALREADY-MUTATED dict. So
    {"role": "viewer", "enabled": false} disables an administrator the caller
    could not have disabled on its own, and the last-admin check below it reads
    the new role too and stays quiet.

What stopped this from being trivial is _caller_can_grant_role(new_role): a
delegate can only assign a role whose permissions it fully holds. That bounds
who can pull it off, it does not close it — a delegate that covers the ordinary
user/viewer permission sets is an unremarkable thing to hand out with
admin.users, and that is all it takes.

The guard is the same predicate the weaker operation already uses, applied
before the mutation rather than after it. The mirror test below is the point of
the exercise: a delegate must keep re-roling the users it genuinely outranks.
Aikido ai_pentest 700487628. MK
"""
import pytest

from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_USER

USERS = '/api/users'
TENANT = 'acme'


@pytest.fixture
def delegate(api, seed):
    """admin.users inside one tenant, plus the whole ordinary-user permission
    set — enough that _caller_can_grant_role lets it hand out 'user'/'viewer'.
    Deliberately NOT an admin: this is the tenant-delegate persona the rest of
    this blueprint's guards exist for."""
    u = seed.user('delegate', role='user', tenant_id=TENANT,
                  permissions=['admin.users'] + list(ROLE_PERMISSIONS[ROLE_USER]))
    return api.as_user(u)


@pytest.fixture
def victim(seed):
    """An administrator in the delegate's own tenant, so the tenant gate passes
    and the rank guard is the only thing left standing."""
    seed.user('second_admin', role='admin', tenant_id=TENANT)  # keep last-admin quiet
    return seed.user('tenant_admin', role='admin', tenant_id=TENANT)


@pytest.fixture
def peer(seed):
    """An ordinary user the delegate really does outrank."""
    return seed.user('ordinary', role='user', tenant_id=TENANT)


def _role_of(seed, username):
    return (seed.db.get_user(username) or {}).get('role')


def test_a_delegate_cannot_demote_an_administrator(delegate, victim, seed):
    r = delegate.put(f'{USERS}/tenant_admin', json={'role': 'viewer'})

    assert r.status_code == 403, (
        f'demotion of an administrator was accepted ({r.status_code}): {r.data}')
    assert _role_of(seed, 'tenant_admin') == 'admin', 'the role was changed anyway'


def test_demote_and_disable_in_one_request_is_refused(delegate, victim, seed):
    """The ordering half: the enabled-guard must not read the new role."""
    r = delegate.put(f'{USERS}/tenant_admin', json={'role': 'viewer', 'enabled': False})

    assert r.status_code == 403, r.data
    stored = seed.db.get_user('tenant_admin') or {}
    assert stored.get('role') == 'admin'
    assert stored.get('enabled', True) is True, 'the administrator was disabled'


def test_a_delegate_cannot_disable_an_administrator_on_its_own(delegate, victim, seed):
    """The guard that was already there — pinned so the fix above can't be
    mistaken for the thing that introduced it."""
    r = delegate.put(f'{USERS}/tenant_admin', json={'enabled': False})
    assert r.status_code == 403, r.data


def test_a_delegate_still_re_roles_the_users_it_outranks(delegate, peer, seed):
    """The mirror. A rank guard that also blocks ordinary delegation is not a
    fix, it is an outage — this is the case the guard has to keep allowing."""
    r = delegate.put(f'{USERS}/ordinary', json={'role': 'viewer'})

    assert r.status_code == 200, (
        f'the delegate lost a legitimate re-role ({r.status_code}): {r.data}')
    assert _role_of(seed, 'ordinary') == 'viewer'


def test_a_delegate_still_disables_the_users_it_outranks(delegate, peer, seed):
    r = delegate.put(f'{USERS}/ordinary', json={'enabled': False})
    assert r.status_code == 200, r.data
    assert (seed.db.get_user('ordinary') or {}).get('enabled') is False


def test_a_global_admin_keeps_full_delegation(api, seed, victim):
    """Global admins are explicitly exempt from every guard in this family."""
    boss = api.as_user(seed.user('boss', role='admin'))
    r = boss.put(f'{USERS}/tenant_admin', json={'role': 'viewer'})
    assert r.status_code == 200, r.data
    assert _role_of(seed, 'tenant_admin') == 'viewer'


def test_demote_and_reset_the_password_in_one_request_is_refused(delegate, victim, seed):
    """The sharpest form of it. The password branch calls _caller_can_manage_user
    too — on the dict the role branch has already rewritten — so a single PUT
    carrying both keys demoted an administrator and took the account over in the
    same breath, with the takeover guard looking at the role it had just been
    given."""
    before = (seed.db.get_user('tenant_admin') or {}).get('password_hash')

    r = delegate.put(f'{USERS}/tenant_admin',
                     json={'role': 'viewer', 'password': 'N0t-your-account!42'})

    assert r.status_code == 403, f'administrator account taken over: {r.data}'
    stored = seed.db.get_user('tenant_admin') or {}
    assert stored.get('role') == 'admin'
    assert stored.get('password_hash') == before, 'the password was reset anyway'
