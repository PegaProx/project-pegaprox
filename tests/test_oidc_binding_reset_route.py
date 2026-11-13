"""DELETE /api/users/<username>/oidc-binding: an admin clears the identity provider subject
an OIDC / Entra account is bound to (test_oidc_subject_binding.py), so the next sign-in
under that name binds it again - after a move to another identity provider, say.

  * the checks of PUT /api/users/<username>: admin.users, the caller's tenant, and the
    tier guard of a password reset, since whoever signs in next gets the account
  * only OIDC and Entra rows; a local or directory account is refused and left alone, and
    so is an account keyed on its subject (a sign-in without a name made it): its owner
    finds it by the stored sub alone, and a sign-in spelling the key would get it
  * audited, and refused on a standby like every other users write
  * GET /api/users says whether an account is bound (oidc_bound) and whether the reset
    takes it (oidc_resettable), never what it is bound to

MK Nov 2026
"""
import pytest

from tests.conftest import _seed_user
from tests.test_oidc_fallback_name_1141 import (  # noqa: F401 - idp and signer are fixtures
    SUB, UPPER, _id_token, _key, _seed_oidc, _sign_in, idp, signer,
)

OLD = 'subject-at-the-old-identity-provider'


def _reset(client, username):
    return client.delete(f'/api/users/{username}/oidc-binding')


def _audit(db, action='user.oidc_binding_reset'):
    return [tuple(r) for r in db.conn.execute(
        'SELECT user, details FROM audit_log WHERE action = ? ORDER BY id', (action,))]


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


def test_a_reset_lets_the_next_sign_in_bind_the_account(api, admin, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'wanda@corp.example', sub=OLD, role='user', tenant_id='default')
    refused = _sign_in(api, monkeypatch, _id_token(signer))
    assert refused.status_code == 403

    r = _reset(admin, 'wanda@corp.example')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == {'success': True}
    assert db.get_user('wanda@corp.example')['oidc_sub'] == ''
    [(who, details)] = _audit(db)
    assert who == 'root' and 'wanda@corp.example' in details and OLD not in details

    again = _sign_in(api, monkeypatch, _id_token(signer))
    assert again.status_code == 200, again.get_data(as_text=True)
    assert again.get_json()['user'] == 'wanda@corp.example'
    assert db.get_user('wanda@corp.example')['oidc_sub'] == SUB


def test_the_user_list_says_whether_an_account_is_bound_and_not_to_what(admin, db):
    _seed_oidc(db, 'wanda@corp.example', sub=OLD)
    _seed_oidc(db, 'nora@corp.example', sub='', auth_source='oidc')
    _seed_oidc(db, _key('s-owner'), sub='s-owner', auth_source='oidc')
    _seed_user(db, 'carol')
    r = admin.get('/api/users')
    assert r.status_code == 200
    flags = {u['username']: (u['oidc_bound'], u['oidc_resettable']) for u in r.get_json()}
    assert flags == {'root': (False, False), 'carol': (False, False), 'wanda@corp.example': (True, True),
                     'nora@corp.example': (False, False), _key('s-owner'): (True, False)}
    assert OLD not in r.get_data(as_text=True) and 's-owner' not in r.get_data(as_text=True)
    assert 'oidc_sub' not in r.get_data(as_text=True)

    assert _reset(admin, 'wanda@corp.example').status_code == 200
    after = {u['username']: (u['oidc_bound'], u['oidc_resettable']) for u in admin.get('/api/users').get_json()}
    assert after['wanda@corp.example'] == (False, False)


@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_a_local_or_directory_account_has_no_binding_to_reset(admin, db, source):
    _seed_user(db, 'carol')
    row = db.get_user('carol')
    row.update(auth_source=source, oidc_sub='left-over')
    db.save_user('carol', row)
    r = _reset(admin, 'carol')
    assert r.status_code == 400
    assert 'Only OIDC and Entra ID accounts' in r.get_json()['error']
    assert db.get_user('carol')['oidc_sub'] == 'left-over'
    assert _audit(db) == []


def test_an_unknown_account_is_not_found(admin, db):
    assert _reset(admin, 'nobody').status_code == 404


def test_the_exact_key_of_an_old_named_account_is_found(admin, db):
    _seed_oidc(db, 'Wanda.Mixed@Corp.Example', sub=OLD)
    assert _reset(admin, 'Wanda.Mixed@Corp.Example').status_code == 200
    assert db.get_user('Wanda.Mixed@Corp.Example')['oidc_sub'] == ''


@pytest.mark.parametrize('key,sub', [(UPPER, 'AbCdEf123456-rest-of-the-sub'),   # oidc_<12 of the sub>
                                     (_key('s-owner'), 's-owner'),                 # the hash
                                     (_key('gone'), '')])                          # its shape alone
def test_an_account_keyed_on_its_subject_is_not_reset(api, admin, db, idp, signer, monkeypatch, key, sub):
    _seed_oidc(db, key, sub=sub, auth_source='oidc', role='admin')
    r = _reset(admin, key)
    assert r.status_code == 400
    assert 'Delete the account instead' in r.get_json()['error']
    assert db.get_user(key)['oidc_sub'] == sub
    assert _audit(db) == []
    if sub:
        # its owner, a sign-in without a name, still lands on it
        owner = _sign_in(api, monkeypatch, _id_token(signer, sub=sub, preferred_username=None, email=None),
                         userinfo={'sub': sub}, provider='generic')
        assert owner.status_code == 200 and owner.get_json()['user'] == key, owner.get_data(as_text=True)


def test_a_caller_without_admin_users_is_refused(api, db):
    _seed_oidc(db, 'wanda@corp.example', sub=OLD)
    for role in ('user', 'viewer'):
        caller = api.as_user(_seed_user(db, f'some-{role}', role=role))
        assert _reset(caller, 'wanda@corp.example').status_code == 403
    assert db.get_user('wanda@corp.example')['oidc_sub'] == OLD


def test_a_tenant_delegate_stops_at_its_tenant(api, seed, db):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users']))
    _seed_oidc(db, 'other@corp.example', sub=OLD, tenant_id='tenant_b')
    _seed_oidc(db, 'own@corp.example', sub=OLD, tenant_id='tenant_a')

    r = _reset(alice, 'other@corp.example')
    assert r.status_code == 403 and 'other tenants' in r.get_json()['error']
    assert db.get_user('other@corp.example')['oidc_sub'] == OLD
    # counter-check: the same delegate resets an account of its own tenant
    assert _reset(alice, 'own@corp.example').status_code == 200
    assert db.get_user('own@corp.example')['oidc_sub'] == ''


def test_a_delegate_cannot_reset_a_peer_above_it(api, seed, db):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users']))
    _seed_oidc(db, 'boss@corp.example', sub=OLD, role='admin', tenant_id='tenant_a')
    r = _reset(alice, 'boss@corp.example')
    assert r.status_code == 403 and 'beyond your own' in r.get_json()['error']
    assert db.get_user('boss@corp.example')['oidc_sub'] == OLD
    assert _audit(db) == []


from test_ha_api import ha_env, _standby_of_active, _admin  # noqa: E402,F401 - ha_env is a fixture


def test_a_standby_refuses_the_reset(ha_env, seed, db):
    admin = _admin(ha_env.api, seed)
    _seed_oidc(db, 'wanda@corp.example', sub=OLD)
    _standby_of_active(ha_env)
    r = _reset(admin, 'wanda@corp.example')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert db.get_user('wanda@corp.example')['oidc_sub'] == OLD
    assert _audit(db) == []
