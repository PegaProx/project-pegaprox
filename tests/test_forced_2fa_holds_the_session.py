"""force_2fa is held on the server: a session that still has to enrol reaches nothing else.

auth_login minted a full session and only answered requires_2fa_setup; the setup screen
in the browser was the whole enforcement. A client that ignored the flag - a script, or
anyone who had the password - used the whole API without ever enrolling, and could mint
an API token on the way out. validate_session now holds such a session to the enrolment,
the session check and signing out, whichever way the request comes in. (#1076) MK
"""
import pyotp
import pytest

import pegaprox.utils.auth as authmod
from pegaprox.utils.auth import create_api_token, hash_password

pytest.importorskip('qrcode')

PASSWORD = 'C0rrect!horse9'


@pytest.fixture
def force_2fa(db):
    from pegaprox.api.helpers import load_server_settings, save_server_settings

    def switch(on=True, exclude_admins=False):
        s = load_server_settings()
        s['force_2fa'] = on
        s['force_2fa_exclude_admins'] = exclude_admins
        save_server_settings(s)
    switch()
    return switch


def _account(db, username='ops', role='user', **extra):
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user(username, dict({'password_salt': salt, 'password_hash': pw_hash, 'role': role,
                                 'enabled': True, 'auth_source': 'local'}, **extra))
    rec = db.get_user(username)
    rec['username'] = username
    return rec


def _sign_in(api, username='ops'):
    r = api.anon().post('/api/auth/login', json={'username': username, 'password': PASSWORD})
    assert r.status_code == 200, r.data
    body = r.get_json()
    return body, {'X-Session-ID': body['session_id']}


# --- the finding -------------------------------------------------------------------------

def test_a_session_that_must_enrol_reaches_nothing_else(api, db, force_2fa):
    _account(db)
    body, sid = _sign_in(api)
    assert body['requires_2fa_setup'] is True

    r = api.anon().get('/api/pbs', headers=sid)

    assert r.status_code == 403, 'the API answered a session that skipped the enrolment'
    assert r.get_json()['code'] == 'MFA_ENROLMENT_REQUIRED'


def test_it_cannot_mint_a_token_to_get_around_it(api, db, force_2fa):
    _account(db)
    _, sid = _sign_in(api)

    r = api.anon().post('/api/auth/tokens', json={'name': 'way-out'}, headers=sid)

    assert r.status_code == 403
    assert db.conn.execute('SELECT COUNT(*) FROM api_tokens').fetchone()[0] == 0


@pytest.mark.parametrize('method,path', [
    ('get', '/api/auth/validate'),        # the console server asks this one
    ('get', '/api/user/sessions'),
    ('post', '/api/webauthn/register/begin'),
])
def test_the_ways_in_that_skip_require_auth_hold_it_too(api, db, force_2fa, method, path):
    _account(db)
    _, sid = _sign_in(api)

    r = getattr(api.anon(), method)(path, headers=sid, **({'json': {}} if method == 'post' else {}))

    assert r.status_code == 401, (path, r.status_code)


def test_switching_force_2fa_on_reaches_a_session_already_open(api, db, force_2fa, monkeypatch):
    force_2fa(on=False)
    _account(db)
    body, sid = _sign_in(api)
    assert body['requires_2fa_setup'] is False
    assert api.anon().get('/api/pbs', headers=sid).status_code == 200

    force_2fa(on=True)
    # the recheck interval has passed (raising=False: the property is what is measured)
    monkeypatch.setattr(authmod, '_MFA_RECHECK_S', 0, raising=False)

    assert api.anon().get('/api/pbs', headers=sid).status_code == 403


# --- the way through ---------------------------------------------------------------------

def test_the_enrolment_itself_stays_open_and_frees_the_session_at_once(api, db, force_2fa):
    _account(db)
    _, sid = _sign_in(api)
    client = api.anon()

    check = client.get('/api/auth/check', headers=sid)
    assert check.status_code == 200 and check.get_json()['requires_2fa_setup'] is True
    assert client.get('/api/auth/2fa/status', headers=sid).status_code == 200
    setup = client.post('/api/auth/2fa/setup', json={}, headers=sid)
    assert setup.status_code == 200, setup.data
    code = pyotp.TOTP(setup.get_json()['secret']).now()
    assert client.post('/api/auth/2fa/verify', json={'code': code}, headers=sid).status_code == 200

    assert client.get('/api/pbs', headers=sid).status_code == 200
    assert client.get('/api/auth/check', headers=sid).get_json()['requires_2fa_setup'] is False


def test_a_held_session_can_still_sign_out(api, db, force_2fa):
    _account(db)
    _, sid = _sign_in(api)

    assert api.anon().post('/api/auth/logout', headers=sid).status_code == 200
    assert api.anon().get('/api/auth/check', headers=sid).status_code == 401


def test_a_half_finished_enrolment_still_holds(api, db, force_2fa):
    """A secret was generated and never verified: no code can be asked at the login."""
    _account(db, totp_pending_secret=pyotp.random_base32())
    _, sid = _sign_in(api)

    assert api.anon().get('/api/pbs', headers=sid).status_code == 403


# --- who is not held ---------------------------------------------------------------------

def test_an_enrolled_account_is_not_held(api, db, force_2fa):
    user = _account(db, totp_enabled=True, totp_secret=pyotp.random_base32())

    assert api.as_user(user).get('/api/pbs').status_code == 200


def test_nobody_is_held_without_force_2fa(api, db, force_2fa):
    force_2fa(on=False)
    user = _account(db)

    assert api.as_user(user).get('/api/pbs').status_code == 200


def test_admins_are_not_held_when_they_are_excluded(api, db, force_2fa):
    force_2fa(on=True, exclude_admins=True)
    admin = _account(db, 'root', role='admin')
    user = _account(db, 'ops')

    assert api.as_user(admin).get('/api/pbs').status_code == 200
    assert api.as_user(user).get('/api/pbs').status_code == 403


def test_an_idp_account_is_not_held(api, db, force_2fa):
    """OIDC/Entra accounts take their MFA from the identity provider."""
    user = _account(db, 'sso', auth_source='oidc')

    assert api.as_user(user).get('/api/pbs').status_code == 200


def test_an_api_token_is_not_a_sign_in(api, db, force_2fa):
    """A token is no interactive sign-in and asks no second factor; one minted before
    force_2fa keeps working. A held session cannot mint one (above)."""
    _account(db)
    tok = create_api_token('ops', 'ci')

    r = api.anon().get('/api/pbs', headers={'Authorization': f"Bearer {tok['token']}"})

    assert r.status_code == 200
