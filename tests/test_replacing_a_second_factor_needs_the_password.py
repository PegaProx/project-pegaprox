"""Replacing an account's TOTP device asked for nothing.

/api/auth/2fa/setup mints a new TOTP secret and /api/auth/2fa/verify activates it,
overwriting totp_secret and setting totp_enabled. Neither looked at whether the
account ALREADY had a second factor, and neither asked for the password. So a
live session on a 2FA-protected account could enrol a fresh secret, verify it
with its own authenticator, and walk away owning the second factor — leaving the
password as the only thing the attacker still lacked, on an account they were
already inside.

The asymmetry is what settles it: /api/auth/2fa/disable has always required the
password, and disabling is the weaker act. It drops the account to one factor;
replacing hands the second one to somebody else.

So: replacing needs the password, enrolling a first factor does not. Onboarding
is the case where the session IS the only credential the user has, and putting a
password prompt in front of it would buy nothing. Aikido ai_pentest 700489538. MK
"""
import pytest

SETUP = '/api/auth/2fa/setup'
DISABLE = '/api/auth/2fa/disable'


pytest.importorskip('pyotp')


@pytest.fixture
def account(api, seed):
    """A local account with a real password hash, so verify_password can run."""
    from pegaprox.utils.auth import hash_password
    salt, pwhash = hash_password('Correct-Horse-42')
    u = seed.user('carol', role='user')
    from pegaprox.core.db import get_db
    rec = get_db().get_user('carol')
    rec.update({'password_salt': salt, 'password_hash': pwhash})
    get_db().save_user('carol', rec)
    return api.as_user(u)


def _enable_totp(username, secret='JBSWY3DPEHPK3PXP'):
    from pegaprox.core.db import get_db
    rec = get_db().get_user(username)
    rec.update({'totp_enabled': True, 'totp_secret': secret})
    get_db().save_user(username, rec)


def test_enrolling_a_first_factor_still_needs_nothing_extra(account):
    """The mirror. Onboarding must not grow a password prompt."""
    r = account.post(SETUP, json={})
    assert r.status_code == 200, r.data
    assert 'secret' in r.get_json()


def test_replacing_an_existing_factor_without_the_password_is_refused(account):
    _enable_totp('carol')

    r = account.post(SETUP, json={})

    assert r.status_code == 400, r.data
    assert r.get_json().get('code') == 'PASSWORD_REQUIRED'


def test_replacing_with_a_wrong_password_is_refused(account):
    _enable_totp('carol')

    r = account.post(SETUP, json={'password': 'not-the-password'})

    assert r.status_code == 401, r.data


def test_replacing_with_the_right_password_works(account):
    """The owner rotating their own device has to keep being able to."""
    _enable_totp('carol')

    r = account.post(SETUP, json={'password': 'Correct-Horse-42'})

    assert r.status_code == 200, r.data
    assert 'secret' in r.get_json()


def test_the_secret_is_not_handed_over_on_the_refused_path(account):
    """The property that matters: a refusal must not still mint and return a secret."""
    _enable_totp('carol')

    body = account.post(SETUP, json={}).get_data(as_text=True)

    assert 'secret' not in body
    assert 'qr_code' not in body
