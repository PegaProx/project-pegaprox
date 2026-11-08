"""An Entra sign-in without a name claim, and the account it left behind (#1141).

Entra reads the name from Graph /me. Without User.Read consent that call fails and the
userinfo endpoint answers instead, with a sub and nothing else, so the account came out
as oidc_<first 12 chars of the sub> - upper-case letters included. Every admin route
lower-cased the name from the URL first and answered 404 for it: the account could not be
edited, deleted, reset or have 2FA cleared.

Three parts, each pinned here:
  a) the admin routes take the exact stored key first, then the lower-cased name
  b) a fallback key is a lower-case hash of the whole sub; the same sub keeps the OIDC
     account it already has, and a key held by another identity is never adopted - nor
     is a fallback account taken by a name claim that spells its key
  c) a userinfo answer without a name takes preferred_username / email from the ID token,
     only when that token's signature was checked in this sign-in and the sub matches

MK Oct 2026
"""
import copy
import hashlib
import logging
import time
import types
import urllib.request

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pegaprox.utils import oidc
from pegaprox.utils.oidc import oidc_derive_username, oidc_provision_user
from tests.conftest import _seed_user
from tests.test_pyjwt_oidc_verification_972 import _Endpoint, _jwk, _tls_files, _token

UPPER = 'oidc_AbCdEf123456'   # what the old fallback stored for a sub starting AbCdEf123456


def _key(sub):
    return 'oidc_' + hashlib.sha256(sub.encode()).hexdigest()[:16]


def _seed_oidc(db, username, sub, auth_source='entra', **extra):
    _seed_user(db, username, role=extra.pop('role', 'viewer'), tenant_id=extra.pop('tenant_id', 'default'))
    row = db.get_user(username)
    row.update(auth_source=auth_source, oidc_sub=sub, **extra)
    db.save_user(username, row)


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


# --- a) the admin routes reach an account whose key has upper-case letters -----------

def test_the_upper_case_account_is_read_through_the_admin_routes(admin, db):
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub')
    listed = [u['username'] for u in admin.get('/api/users').get_json()]
    assert UPPER in listed
    r = admin.get(f'/api/users/{UPPER}/permissions')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['username'] == UPPER
    assert admin.get(f'/api/users/{UPPER}/vm-access').status_code == 200


def test_the_upper_case_account_is_edited(admin, db):
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub')
    r = admin.put(f'/api/users/{UPPER}', json={'display_name': 'Wanda', 'role': 'user'})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = db.get_user(UPPER)
    assert (row['display_name'], row['role']) == ('Wanda', 'user')
    assert db.get_user(UPPER.lower()) is None   # no second row under the lower-cased name

    r = admin.put(f'/api/users/{UPPER}/permissions', json={'permissions': ['vm.view'],
                                                          'denied_permissions': []})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user(UPPER)['permissions'] == ['vm.view']
    r = admin.delete(f'/api/users/{UPPER}/tenant-permissions/default')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_the_upper_case_account_has_its_2fa_cleared(admin, db):
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub', totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    assert db.get_user(UPPER)['totp_enabled']
    r = admin.delete(f'/api/users/{UPPER}/2fa')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert not db.get_user(UPPER)['totp_enabled']


def test_the_upper_case_account_gets_to_the_password_reset(admin, db):
    # an IdP account is turned away by the reset itself - found, not 404
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub')
    r = admin.put(f'/api/users/{UPPER}/password', json={'password': 'Corr3ct-Horse-Battery!'})
    assert r.status_code == 400 and 'Microsoft Entra ID' in r.get_json()['error'], r.get_data(as_text=True)
    # and one an admin switched to local is reset
    _seed_user(db, 'Local_Mixed')
    before = db.get_user('Local_Mixed')['password_hash']
    r = admin.put('/api/users/Local_Mixed/password', json={'password': 'Corr3ct-Horse-Battery!'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['relogin_required'] is False
    assert db.get_user('Local_Mixed')['password_hash'] != before


def test_the_upper_case_account_is_deleted(admin, db):
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub')
    r = admin.delete(f'/api/users/{UPPER}')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user(UPPER) is None


def test_a_lockout_under_the_exact_key_is_lifted(admin):
    from pegaprox.globals import login_attempts_by_user
    login_attempts_by_user[UPPER] = {'attempts': [time.time()], 'locked_until': time.time() + 300}
    login_attempts_by_user['carol'] = {'attempts': [time.time()], 'locked_until': time.time() + 300}
    try:
        assert admin.delete(f'/api/security/locked-users/{UPPER}').status_code == 200
        assert admin.delete('/api/security/locked-users/Carol').status_code == 200
        assert UPPER not in login_attempts_by_user and 'carol' not in login_attempts_by_user
    finally:
        login_attempts_by_user.pop(UPPER, None)
        login_attempts_by_user.pop('carol', None)


def test_a_lower_case_account_is_still_found_by_any_case(admin, db):
    _seed_user(db, 'carol')
    assert admin.put('/api/users/Carol', json={'display_name': 'C'}).status_code == 200
    assert admin.get('/api/users/CAROL/permissions').get_json()['username'] == 'carol'
    assert admin.put('/api/users/carol', json={'email': 'c@corp.example'}).status_code == 200
    assert db.get_user('carol')['display_name'] == 'C'
    assert admin.delete('/api/users/Carol').status_code == 200
    assert db.get_user('carol') is None


def test_the_exact_key_wins_over_its_lower_cased_namesake(admin, db):
    _seed_oidc(db, 'Dave', sub='sub-dave-upper')
    _seed_user(db, 'dave')
    assert admin.put('/api/users/Dave', json={'display_name': 'upper'}).status_code == 200
    assert admin.put('/api/users/dave', json={'display_name': 'lower'}).status_code == 200
    assert db.get_user('Dave')['display_name'] == 'upper'
    assert db.get_user('dave')['display_name'] == 'lower'


def test_a_tenant_delegate_still_stops_at_its_tenant(api, seed, db):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users']))
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub', tenant_id='tenant_b')
    assert alice.delete(f'/api/users/{UPPER}').status_code == 403
    assert alice.put(f'/api/users/{UPPER}', json={'display_name': 'x'}).status_code == 403
    assert alice.delete(f'/api/users/{UPPER}/2fa').status_code == 403
    assert alice.get(f'/api/users/{UPPER}/permissions').status_code == 404
    assert db.get_user(UPPER)['display_name'] != 'x'


# --- b) the fallback key ---------------------------------------------------------------

def test_a_new_fallback_key_is_lower_case(db):
    sub = 'WdXyZ0123456-Pairwise-SUB'
    name = oidc_derive_username({'sub': sub})
    assert name == _key(sub) and name == name.lower()


def test_the_same_sub_lands_on_its_account_again(db):
    first = oidc_provision_user({'sub': 'Sub-One-ABC'}, {'role': 'viewer'}, auth_source='entra')
    again = oidc_provision_user({'sub': 'Sub-One-ABC'}, {'role': 'viewer'}, auth_source='entra')
    assert first['username'] == again['username'] == _key('Sub-One-ABC')
    assert [r[0] for r in db.conn.execute('SELECT username FROM users')] == [first['username']]


def test_the_same_sub_keeps_its_old_upper_case_account(db):
    sub = 'AbCdEf123456-rest-of-the-sub'
    _seed_oidc(db, UPPER, sub=sub, role='user')
    assert oidc_derive_username({'sub': sub}) == UPPER
    user = oidc_provision_user({'sub': sub}, {'role': 'viewer'}, auth_source='entra')
    assert user['username'] == UPPER and user['role'] == 'user'   # not authoritative, kept
    assert sorted(r[0] for r in db.conn.execute('SELECT username FROM users')) == [UPPER]


def test_two_subs_with_one_prefix_get_two_accounts(db):
    # the old key was the first 12 characters, so these two shared an account
    a = oidc_provision_user({'sub': 'abcdef012345-AAAA'}, {'role': 'viewer'}, auth_source='oidc')
    b = oidc_provision_user({'sub': 'abcdef012345-BBBB'}, {'role': 'viewer'}, auth_source='oidc')
    assert a['username'] != b['username']
    assert db.get_user(a['username'])['oidc_sub'] == 'abcdef012345-AAAA'
    assert db.get_user(b['username'])['oidc_sub'] == 'abcdef012345-BBBB'


def test_a_key_held_by_another_identity_is_never_adopted(db, caplog):
    # e.g. an IdP account whose preferred_username was set to someone's fallback key
    _seed_oidc(db, _key('victim-sub'), sub='someone-else', role='admin')
    with caplog.at_level(logging.WARNING):
        assert oidc_derive_username({'sub': 'victim-sub'}) is None
        assert oidc_provision_user({'sub': 'victim-sub'}, {'role': 'viewer'}) is None
    assert 'belongs to another identity' in caplog.text
    row = db.get_user(_key('victim-sub'))
    assert (row['oidc_sub'], row['role']) == ('someone-else', 'admin')


@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_a_local_or_directory_row_with_that_sub_is_not_taken(db, source):
    _seed_oidc(db, 'mallory', sub='sub-m', auth_source=source)
    assert oidc_derive_username({'sub': 'sub-m'}) == _key('sub-m')


def test_no_name_and_no_sub_is_refused(db):
    assert oidc_derive_username({'name': 'Nobody'}) is None
    assert oidc_provision_user({'name': 'Nobody'}, {'role': 'viewer'}) is None


# --- the sign-in itself: a real ID token, checked against keys an IdP on loopback serves ---

GRAPH_ME = 'https://graph.example/v1.0/me'
USERINFO = 'https://graph.example/oidc/userinfo'
ENTRA = {'enabled': True, 'provider': 'entra', 'client_id': 'pegaprox', 'auto_create_users': True,
         'redirect_uri': 'https://pegaprox.example/oidc/callback', 'default_role': 'viewer',
         'admin_group_id': '', 'user_group_id': '', 'viewer_group_id': '', 'group_mappings': []}
SUB = 'Wd8kPairwiseSubOfWanda'


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


@pytest.fixture
def signer():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def idp(tmp_path, signer, monkeypatch):
    tls = _tls_files(tmp_path)
    monkeypatch.setenv('SSL_CERT_FILE', tls[0])
    monkeypatch.setattr(urllib.request, '_opener', None)
    monkeypatch.setattr(oidc, '_jwks_clients', {})
    ep = _Endpoint({'keys': [_jwk(signer.public_key(), 'k1')]}, tls=tls)
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: {
        'jwks': ep.url + '/jwks', 'graph_me': GRAPH_ME, 'userinfo': USERINFO})
    # the userinfo URL is not what is under test, and its guard would resolve DNS
    monkeypatch.setattr(oidc, 'sanitize_outbound_url', lambda url, **kw: url)
    yield ep
    ep.server.stop()


def _id_token(key, **claims):
    now = int(time.time())
    body = {'iss': 'https://login.example/tenant/v2.0', 'aud': 'pegaprox', 'iat': now,
            'exp': now + 300, 'nonce': 'the-nonce', 'sub': SUB,
            'preferred_username': 'Wanda@Corp.Example', 'email': 'wanda@corp.example'}
    body.update(claims)
    return _token(key, body)


def _sign_in(api, monkeypatch, id_token, graph=(403, {}), userinfo=None, **config):
    """One callback: the token endpoint hands out `id_token`, Graph /me answers `graph`,
    the userinfo endpoint `userinfo`. Decoding, userinfo and provisioning are the real ones."""
    import pegaprox.api.auth as auth_api
    cfg = dict(ENTRA, **config)
    monkeypatch.setattr(auth_api, 'get_oidc_settings', lambda: copy.deepcopy(cfg))
    monkeypatch.setattr(auth_api, 'oidc_exchange_code',
                        lambda c, code, code_verifier=None: {'access_token': 'at', 'id_token': id_token})
    monkeypatch.setattr(auth_api, 'oidc_get_user_groups_ex', lambda c, token: ([], True))
    answers = {GRAPH_ME: graph, USERINFO: (200, userinfo if userinfo is not None else {'sub': SUB})}
    monkeypatch.setattr(oidc, 'requests', types.SimpleNamespace(
        get=lambda url, headers=None, timeout=None: _Resp(*answers[url])))
    for k in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(k, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    return browser.post('/api/auth/oidc/callback', json={'code': 'c', 'state': 'the-state'},
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                        base_url='http://localhost')


def _accounts(db):
    return sorted(r[0] for r in db.conn.execute('SELECT username FROM users'))


def test_without_graph_the_name_comes_from_the_verified_id_token(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'wanda@corp.example'
    row = db.get_user('wanda@corp.example')
    assert (row['oidc_sub'], row['email'], row['auth_source']) == (SUB, 'wanda@corp.example', 'entra')
    assert _accounts(db) == ['wanda@corp.example']


def test_an_unverified_id_token_never_names_the_account(api, db, idp, signer, monkeypatch, caplog):
    # the admin switch that skips the signature check: the decode answers, unverified
    with caplog.at_level(logging.WARNING):
        r = _sign_in(api, monkeypatch, _id_token(signer), oidc_skip_jwt_verification=True)
    assert 'verification DISABLED' in caplog.text
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == _key(SUB)
    assert _accounts(db) == [_key(SUB)]


def test_a_token_with_a_bad_signature_never_names_the_account(api, db, idp, monkeypatch, caplog):
    # signed by a key the IdP does not publish: verification fails and the decode falls
    # back to reading the token unchecked
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with caplog.at_level(logging.WARNING):
        r = _sign_in(api, monkeypatch, _id_token(stranger, preferred_username='root'))
    assert 'falling back to unverified decode' in caplog.text
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == _key(SUB)
    assert _accounts(db) == [_key(SUB)]


def test_a_verified_token_of_another_subject_does_not_name_it(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer, sub='someone-else'))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == _key(SUB)


def test_graph_me_still_names_the_account(api, db, idp, signer, monkeypatch):
    graph = (200, {'id': 'object-id-1', 'userPrincipalName': 'Graph.Upn@Corp.Example',
                   'displayName': 'Wanda', 'mail': None})
    r = _sign_in(api, monkeypatch, _id_token(signer, preferred_username='token.name@corp.example'),
                 graph=graph)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'graph.upn@corp.example'
    assert db.get_user('graph.upn@corp.example')['oidc_sub'] == 'object-id-1'
    assert _accounts(db) == ['graph.upn@corp.example']


def test_a_generic_provider_that_sends_a_name_keeps_it(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer, preferred_username='token.name'),
                 userinfo={'sub': SUB, 'preferred_username': 'kc.user'}, provider='generic')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'kc.user'
    assert db.get_user('kc.user')['auth_source'] == 'oidc'


def test_an_old_fallback_account_stays_and_can_go_once_a_name_arrives(api, db, idp, signer, monkeypatch):
    _seed_user(db, 'root', role='admin')
    _seed_oidc(db, 'oidc_Wd8kPairwis', sub=SUB, role='user')
    r = _sign_in(api, monkeypatch, _id_token(signer))
    assert r.get_json()['user'] == 'wanda@corp.example'
    assert db.get_user('wanda@corp.example')['role'] == 'viewer'   # a new account, default role
    assert db.get_user('oidc_Wd8kPairwis')['role'] == 'user'       # the old one untouched
    admin = api.as_user(dict(db.get_user('root'), username='root'))
    assert admin.delete('/api/users/oidc_Wd8kPairwis').status_code == 200
    assert _accounts(db) == ['root', 'wanda@corp.example']


@pytest.mark.parametrize('enabled', [True, False])
def test_a_nameless_sign_in_after_the_name_arrived_keeps_to_the_named_account(
        api, db, idp, signer, monkeypatch, enabled):
    # both rows carry the sub once the token named the user. A sign-in that loses the name
    # again (a JWKS hiccup: the token is read unchecked) went back to the old account and
    # what it holds, even when an admin had disabled the named one
    _seed_oidc(db, 'oidc_' + SUB[:12], sub=SUB, role='admin')
    _seed_oidc(db, 'wanda@corp.example', sub=SUB, role='viewer', enabled=enabled)
    r = _sign_in(api, monkeypatch, _id_token(signer), oidc_skip_jwt_verification=True)
    if enabled:
        assert r.status_code == 200, r.get_data(as_text=True)
        assert (r.get_json()['user'], r.get_json()['role']) == ('wanda@corp.example', 'viewer')
    else:
        assert r.status_code == 403, r.get_data(as_text=True)
    assert db.get_user('oidc_' + SUB[:12])['role'] == 'admin'


def test_a_nameless_sign_in_makes_an_account_an_admin_can_manage(api, db, idp, signer, monkeypatch):
    _seed_user(db, 'root', role='admin')
    r = _sign_in(api, monkeypatch, _id_token(signer), oidc_skip_jwt_verification=True)
    name = r.get_json()['user']
    assert name == _key(SUB)
    again = _sign_in(api, monkeypatch, _id_token(signer), oidc_skip_jwt_verification=True)
    assert again.get_json()['user'] == name
    admin = api.as_user(dict(db.get_user('root'), username='root'))
    assert admin.put(f'/api/users/{name}', json={'role': 'user'}).status_code == 200
    assert admin.delete(f'/api/users/{name}').status_code == 200
    assert _accounts(db) == ['root']


def test_the_verified_mark_cannot_come_from_the_token():
    # the unverified decode is plain JSON: whatever key the token carries, it is not the type
    claims = oidc.oidc_decode_id_token(
        _token(rsa.generate_private_key(public_exponent=65537, key_size=2048),
               {'sub': 'x', 'exp': int(time.time()) + 300, '_VerifiedClaims': True, 'verified': True}),
        config={'provider': 'generic', 'client_id': 'pegaprox', 'oidc_skip_jwt_verification': True})
    assert claims['sub'] == 'x' and not oidc.oidc_id_token_verified(claims)
    assert not oidc.oidc_id_token_verified(dict(claims))


# --- what another identity can get out of it ------------------------------------------

def test_a_named_sign_in_never_takes_over_a_fallback_account(db):
    # the new keys are lower case, so a name claim can spell one: an IdP account that
    # picks someone's fallback key as its username landed on that row by name
    victim = oidc_provision_user({'sub': 'Victim-Sub-XYZ'}, {'role': 'viewer'}, auth_source='oidc')
    key = victim['username']
    row = db.get_user(key)
    row.update(role='admin', tenant_id='tenant_v')
    db.save_user(key, row)

    taken = oidc_provision_user({'sub': 'attacker-sub', 'preferred_username': key.upper() + '!'},
                                {'role': 'viewer'}, auth_source='oidc')
    assert taken is None
    row = db.get_user(key)
    assert (row['oidc_sub'], row['role'], row['tenant_id']) == ('Victim-Sub-XYZ', 'admin', 'tenant_v')
    # and the owner still gets in
    assert oidc_provision_user({'sub': 'Victim-Sub-XYZ'}, {'role': 'viewer'},
                               auth_source='oidc')['username'] == key


def test_a_named_sign_in_never_takes_over_an_old_lower_case_fallback_account(db):
    # oidc_<first 12 of the sub> was lower case already for a Keycloak or Google sub, and
    # the sub lookup keeps such a row in use
    sub = '3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b'
    old = 'oidc_' + sub[:12]
    _seed_oidc(db, old, sub=sub, auth_source='oidc', role='admin')
    assert oidc_provision_user({'sub': 'other', 'preferred_username': old},
                               {'role': 'viewer'}, auth_source='oidc') is None
    assert db.get_user(old)['oidc_sub'] == sub
    # the same subject naming that key is still the same identity
    same = oidc_provision_user({'sub': sub, 'preferred_username': old},
                               {'role': 'viewer'}, auth_source='oidc')
    assert same['username'] == old and same['role'] == 'admin'


def test_a_named_account_is_still_adopted_by_name(db):
    # unchanged: an OIDC row under a real name follows its name, whatever the sub says now
    # (Entra stores the Graph object id, the userinfo endpoint answers a pairwise sub)
    _seed_oidc(db, 'wanda@corp.example', sub='object-id-1', role='user')
    user = oidc_provision_user({'sub': 'pairwise-sub', 'preferred_username': 'Wanda@Corp.Example'},
                               {'role': 'viewer'}, auth_source='entra')
    assert user['username'] == 'wanda@corp.example' and user['role'] == 'user'


@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_a_token_name_does_not_take_a_local_or_directory_account(api, db, idp, signer, monkeypatch, source):
    # the name from the ID token goes through the same ownership check as any other
    _seed_user(db, 'boss@corp.example', role='admin')
    row = db.get_user('boss@corp.example')
    row['auth_source'] = source
    db.save_user('boss@corp.example', row)
    r = _sign_in(api, monkeypatch, _id_token(signer, preferred_username=None, email='Boss@Corp.Example'))
    assert r.status_code == 403, r.get_data(as_text=True)
    row = db.get_user('boss@corp.example')
    assert row['auth_source'] == source and not row.get('oidc_sub')


def test_a_sub_that_differs_only_in_case_is_another_identity(db):
    _seed_oidc(db, _key('abc-sub'), sub='abc-sub', auth_source='oidc', role='admin')
    assert oidc_derive_username({'sub': 'ABC-SUB'}) == _key('ABC-SUB') != _key('abc-sub')


def test_a_sign_in_naming_a_fallback_key_is_refused_at_the_callback(api, db, idp, signer, monkeypatch):
    key = oidc_provision_user({'sub': SUB}, {'role': 'viewer'}, auth_source='oidc')['username']
    r = _sign_in(api, monkeypatch, _id_token(signer, sub='attacker-sub', preferred_username=key),
                 userinfo={'sub': 'attacker-sub', 'preferred_username': key}, provider='generic')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert db.get_user(key)['oidc_sub'] == SUB
    assert _accounts(db) == [key]


def test_an_unlock_checks_the_tenant_of_the_lockout_it_lifts(api, seed, db):
    # lockouts are keyed by the lower-cased login name; the tenant check looked at the
    # exact key and the unlock then lifted the lower-cased entry of another tenant
    from pegaprox.globals import login_attempts_by_user
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a',
                                  permissions=['admin.users', 'security.lockout.manage']))
    _seed_oidc(db, UPPER, sub='AbCdEf123456-rest-of-the-sub', tenant_id='tenant_a')
    _seed_user(db, UPPER.lower(), tenant_id='tenant_b')
    _seed_user(db, 'carol', tenant_id='tenant_a')
    now = time.time()
    login_attempts_by_user[UPPER.lower()] = {'attempts': [now], 'locked_until': now + 300}
    login_attempts_by_user['carol'] = {'attempts': [now], 'locked_until': now + 300}
    try:
        r = alice.delete(f'/api/security/locked-users/{UPPER}')
        assert r.status_code == 403, r.get_data(as_text=True)
        assert UPPER.lower() in login_attempts_by_user
        # its own tenant's entry it still lifts, in any case
        assert alice.delete('/api/security/locked-users/Carol').status_code == 200
        assert 'carol' not in login_attempts_by_user
    finally:
        login_attempts_by_user.pop(UPPER.lower(), None)
        login_attempts_by_user.pop('carol', None)
