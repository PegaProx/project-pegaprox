"""The bulk unlock endpoints rebound a name instead of clearing the store.

`unlock_all_ips()` / `unlock_all_users()` in pegaprox/api/users.py did

    global login_attempts_by_ip
    login_attempts_by_ip = {}

The two dicts live in pegaprox/globals.py and every module pulls its own name
for them through `from pegaprox.globals import *`. `global` there means "the
module global of pegaprox.api.users", not "the object in globals.py" — so the
rebind swapped out ONE module's name and left the object every other module
still points at untouched. Measured, not assumed: see the identity assertion in
test_every_module_still_points_at_one_store.

Three consequences, all in the same direction:

  * pegaprox/api/auth.py keeps the original dict, so the login path goes on
    rejecting every locked IP and username. The admin is told "All N IPs
    unlocked" and nothing is.
  * the listing route in this same file now reads the fresh empty dict, so the
    lockout page shows nothing — the admin cannot even see what is still locked.
  * the single-entry unlock routes (`del login_attempts_by_ip[ip]`) now delete
    out of that empty dict, so targeted unlock stays broken for the life of the
    process. One click on "unlock all" makes the lockout unclearable until
    restart.

The single-entry routes were always correct because they mutate. That is the
whole difference, and it is what these tests measure: after the call, is the
dict the LOGIN path consults empty?

Asserting on the handler's own module global would pass against the broken code
— it is the one name the rebind does update. Aikido ai_pentest 700489109. MK
"""
import time

import pytest

import pegaprox.globals as ppglobals
import pegaprox.api.auth as authapi
import pegaprox.api.users as usersapi
import pegaprox.utils.auth as authmod

LOCKED_IPS = '/api/security/locked-ips'
LOCKED_USERS = '/api/security/locked-users'

_MODULES = (ppglobals, authapi, usersapi, authmod)


def _login_path_ip_store():
    """The dict pegaprox/api/auth.py actually consults on a login attempt."""
    return authapi.login_attempts_by_ip


def _login_path_user_store():
    return authapi.login_attempts_by_user


@pytest.fixture
def lockouts():
    """Seed a locked IP and a locked username, and put every module's binding
    back the way it was afterwards — a rebinding handler would otherwise leak a
    detached dict into every later test in the process."""
    before = {m: (m.login_attempts_by_ip, m.login_attempts_by_user) for m in _MODULES}

    locked_until = time.time() + 3600
    for m in _MODULES:
        m.login_attempts_by_ip.clear()
        m.login_attempts_by_user.clear()
    ppglobals.login_attempts_by_ip['203.0.113.7'] = {
        'attempts': [time.time()], 'locked_until': locked_until}
    ppglobals.login_attempts_by_user['mallory'] = {
        'attempts': [time.time()], 'locked_until': locked_until}
    try:
        yield
    finally:
        for m, (ips, users) in before.items():
            m.login_attempts_by_ip = ips
            m.login_attempts_by_user = users
        for m in _MODULES:
            m.login_attempts_by_ip.clear()
            m.login_attempts_by_user.clear()


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('lockadmin', role='admin'))


def test_every_module_still_points_at_one_store(lockouts):
    """The premise. If this ever fails the fixtures below prove nothing."""
    first_ip = ppglobals.login_attempts_by_ip
    first_user = ppglobals.login_attempts_by_user
    for m in _MODULES:
        assert m.login_attempts_by_ip is first_ip, f'{m.__name__} holds a detached IP store'
        assert m.login_attempts_by_user is first_user, f'{m.__name__} holds a detached user store'


def test_unlock_all_ips_clears_the_store_the_login_path_reads(admin, lockouts):
    assert '203.0.113.7' in _login_path_ip_store()

    r = admin.delete(LOCKED_IPS)
    assert r.status_code == 200, r.data
    assert r.get_json()['success'] is True

    assert _login_path_ip_store() == {}, (
        'the login path still sees the lockout the admin was told was cleared: '
        f'{_login_path_ip_store()}')


def test_unlock_all_users_clears_the_store_the_login_path_reads(admin, lockouts):
    assert 'mallory' in _login_path_user_store()

    r = admin.delete(LOCKED_USERS)
    assert r.status_code == 200, r.data

    assert _login_path_user_store() == {}, (
        'the login path still sees the username lockout: '
        f'{_login_path_user_store()}')


def test_bulk_unlock_does_not_break_the_single_entry_routes(admin, lockouts):
    """The knock-on. After a bulk reset the targeted unlock has to keep working —
    it was the rebind, not the deletion, that broke it."""
    admin.delete(LOCKED_IPS)

    ppglobals.login_attempts_by_ip['198.51.100.9'] = {
        'attempts': [time.time()], 'locked_until': time.time() + 3600}

    r = admin.delete(f'{LOCKED_IPS}/198.51.100.9')
    assert r.status_code == 200, r.data
    assert '198.51.100.9' not in _login_path_ip_store()


def test_the_listing_route_and_the_login_path_agree_after_a_reset(admin, lockouts):
    """The admin-facing half: the page must not report empty while the gate locks."""
    admin.delete(LOCKED_IPS)
    admin.delete(LOCKED_USERS)

    r = admin.get(LOCKED_IPS)
    assert r.status_code == 200, r.data
    body = r.get_json()

    assert body.get('total_tracked_ips', 0) == len(_login_path_ip_store())
    assert body.get('total_tracked_users', 0) == len(_login_path_user_store())


def test_the_count_reported_back_is_what_was_actually_cleared(admin, lockouts):
    r = admin.delete(LOCKED_IPS)
    assert '1' in r.get_json()['message'], r.get_json()
