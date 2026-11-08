"""An API token cannot mint a token or change its owner's second factor.

POST /api/auth/tokens checked the requested role against the owner's stored role, not
against the token making the call. Only the one-active-token rule stood between a viewer
token of an administrator and a fresh admin token, and that rule is read after the body:
a DELETE of the calling token that lands while the POST body is still arriving clears it.
The new token then also outlives the revocation that was meant to end the caller.

The 2FA routes acted for the owner the same way: a viewer token could enrol its own
authenticator on an owner who had none, after which the owner cannot sign in. (#1001) MK
"""
import pyotp
import pytest

import pegaprox.api.auth as apiauth
from pegaprox.utils.auth import create_api_token, validate_api_token, hash_password

pytest.importorskip('qrcode')


def _bearer(tok):
    return {'Authorization': f"Bearer {tok['token']}"}


def _active_roles(db):
    rows = db.conn.execute('SELECT role FROM api_tokens WHERE revoked = 0').fetchall()
    return sorted(r[0] for r in rows)


def _with_password(db, username, password='Correct-Horse-42'):
    salt, pw_hash = hash_password(password)
    rec = db.get_user(username)
    rec.update({'password_salt': salt, 'password_hash': pw_hash})
    db.save_user(username, rec)
    return password


# --- the finding -------------------------------------------------------------------------

def test_a_viewer_token_cannot_mint_an_admin_token_while_its_revocation_lands(api, seed, db,
                                                                            monkeypatch):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'ci', role='viewer')
    client = api.anon()
    real = apiauth.list_user_tokens

    def body_still_arriving(username):
        # the DELETE of the calling token, landing between the auth check and the
        # one-active-token rule (on the live server: send the POST body slowly)
        monkeypatch.setattr(apiauth, 'list_user_tokens', real)
        r = client.delete(f"/api/auth/tokens/{tok['token_id']}", headers=_bearer(tok))
        assert r.status_code == 200, r.data
        return real(username)

    monkeypatch.setattr(apiauth, 'list_user_tokens', body_still_arriving)

    r = client.post('/api/auth/tokens', json={'name': 'mine', 'role': 'admin'},
                    headers=_bearer(tok))

    assert 'admin' not in _active_roles(db), 'a viewer token minted an admin token'
    assert r.status_code == 403
    assert r.get_json()['code'] == 'INTERACTIVE_SESSION_REQUIRED'


def test_a_token_cannot_put_its_own_authenticator_on_its_owner(api, seed, db):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'ci', role='viewer')
    client = api.anon()

    r = client.post('/api/auth/2fa/setup', json={}, headers=_bearer(tok))
    if r.status_code == 200:
        code = pyotp.TOTP(r.get_json()['secret']).now()
        client.post('/api/auth/2fa/verify', json={'code': code}, headers=_bearer(tok))

    rec = db.get_user('root')
    assert not rec.get('totp_enabled'), 'the token enrolled its own authenticator on the owner'
    assert not rec.get('totp_pending_secret')
    assert r.status_code == 403


def test_a_token_cannot_switch_off_its_owners_second_factor(api, seed, db):
    seed.user('root', role='admin')
    password = _with_password(db, 'root')
    rec = db.get_user('root')
    rec.update({'totp_enabled': True, 'totp_secret': pyotp.random_base32()})
    db.save_user('root', rec)
    tok = create_api_token('root', 'ci', role='viewer')

    r = api.anon().post('/api/auth/2fa/disable', json={'password': password},
                        headers=_bearer(tok))

    assert db.get_user('root').get('totp_enabled'), 'a token switched the second factor off'
    assert r.status_code == 403


# --- what keeps working ------------------------------------------------------------------

def test_a_signed_in_user_still_creates_a_token(api, seed, db):
    root = seed.user('root', role='admin')

    r = api.as_user(root).post('/api/auth/tokens', json={'name': 'ci', 'role': 'viewer'})

    assert r.status_code == 200, r.data
    assert validate_api_token(r.get_json()['token']) is not None


def test_a_token_still_lists_and_revokes_itself(api, seed):
    seed.user('ops', role='user')
    tok = create_api_token('ops', 'ci')
    client = api.anon()

    listed = client.get('/api/auth/tokens', headers=_bearer(tok))
    assert listed.status_code == 200
    assert [t['id'] for t in listed.get_json()['tokens']] == [tok['token_id']]

    r = client.delete(f"/api/auth/tokens/{tok['token_id']}", headers=_bearer(tok))
    assert r.status_code == 200, r.data
    with api.app.test_request_context('/'):
        assert validate_api_token(tok['token']) is None


def test_a_signed_in_user_still_enrols_and_disables_2fa(api, seed, db):
    ops = seed.user('ops', role='user')
    password = _with_password(db, 'ops')
    client = api.as_user(ops)

    r = client.post('/api/auth/2fa/setup', json={})
    assert r.status_code == 200, r.data
    code = pyotp.TOTP(r.get_json()['secret']).now()
    assert client.post('/api/auth/2fa/verify', json={'code': code}).status_code == 200
    assert db.get_user('ops').get('totp_enabled')

    assert client.post('/api/auth/2fa/disable', json={'password': password}).status_code == 200
    assert not db.get_user('ops').get('totp_enabled')
