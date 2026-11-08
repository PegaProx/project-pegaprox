"""The claim an admin picks to name OIDC accounts (#1149).

AD FS answers the userinfo endpoint with the sub alone and puts the claims it issues
(email, upn) into the tokens, so every account came out as oidc_<sub>. The OIDC settings
now say which claim becomes the username:

  a) only preferred_username, email or upn; anything else is refused at the save
  b) the value comes from the userinfo answer, else from the ID token - and from the token
     only when its signature was checked in this sign-in and it is about the same subject;
     an email the IdP marks as not verified names nobody
  c) a sign-in without a usable value is refused; it never falls back to another name, and
     a value is taken whole or not at all (nothing is dropped or folded)
  d) with a picked claim an account stays with the subject it was made for: the ids this
     sign-in goes by (with Entra the Graph id and the token's sub and oid), never a row
     with no subject stored, and the refusals read alike so nobody can probe for names -
     on a standby too, where a held name answers like a missing one
  e) email never names an Entra account: there it is the mail attribute, unverified

NS Oct 2026
"""
import copy
import logging

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pegaprox.utils import oidc
from pegaprox.utils.oidc import (
    oidc_build_user_row, oidc_derive_username, oidc_username_claim_value,
)
from tests.conftest import _seed_user
from tests.test_oidc_fallback_name_1141 import (  # noqa: F401 - idp and signer are fixtures
    SUB, _accounts, _id_token, _seed_oidc, _sign_in, idp, signer,
)

VERIFIED = oidc._VerifiedClaims
UNMATCHED = 'This sign-in could not be matched to a PegaProx account. Contact an administrator.'
OID = 'object-id-of-wanda'
GRAPH_OK = (200, {'id': OID, 'userPrincipalName': 'Wanda@Corp.Example', 'displayName': 'Wanda',
                  'mail': 'wanda.mail@corp.example'})


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


def _adfs(api, monkeypatch, token, userinfo=None, **config):
    """An AD FS shaped sign-in: generic provider, userinfo with a sub and nothing else."""
    return _sign_in(api, monkeypatch, token, userinfo=userinfo or {'sub': SUB}, provider='generic',
                    **config)


# --- a) the setting -----------------------------------------------------------------------

def test_the_picked_claim_is_saved_and_read_back(admin):
    r = admin.post('/api/settings/server', json={'oidc_username_claim': 'upn'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert admin.get('/api/settings/server').get_json()['oidc_username_claim'] == 'upn'
    assert oidc.get_oidc_settings()['username_claim'] == 'upn'


@pytest.mark.parametrize('value', ['unique_name', 'sub', 'name', 'UPN', 42])
def test_a_claim_outside_the_list_is_refused_and_nothing_is_saved(admin, value):
    assert admin.post('/api/settings/server', json={'oidc_provider': 'generic',
                                                    'oidc_username_claim': 'email'}).status_code == 200
    r = admin.post('/api/settings/server', json={'oidc_username_claim': value, 'oidc_enabled': True})
    assert r.status_code == 400
    assert 'oidc_username_claim' in r.get_json()['error']
    stored = admin.get('/api/settings/server').get_json()
    assert stored['oidc_username_claim'] == 'email'
    assert stored['oidc_enabled'] is False          # the rest of that save did not land either


@pytest.mark.parametrize('value,stored', [(None, ''), ('', ''), ('upn ', 'upn')])
def test_empty_means_the_old_order_and_blanks_are_forgiven(admin, value, stored):
    r = admin.post('/api/settings/server', json={'oidc_username_claim': value})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert admin.get('/api/settings/server').get_json()['oidc_username_claim'] == stored


def test_a_change_of_the_claim_is_audited_with_both_values(admin, db):
    admin.post('/api/settings/server', json={'oidc_username_claim': 'upn'})
    details = [r[0] for r in db.conn.execute(
        "SELECT details FROM audit_log WHERE action = 'settings.oidc' ORDER BY id")]
    assert any('username_claim=auto->upn' in d for d in details), details


def test_a_value_outside_the_list_that_got_into_the_store_is_not_used(monkeypatch):
    import pegaprox.api.helpers as helpers
    monkeypatch.setattr(helpers, 'load_server_settings', lambda: {'oidc_username_claim': 'name'})
    assert oidc.get_oidc_settings()['username_claim'] == ''


def test_the_default_is_the_old_order():
    assert oidc.get_oidc_settings()['username_claim'] == ''


# --- b) where the value comes from --------------------------------------------------------

def test_the_userinfo_answer_wins_over_the_token():
    token = VERIFIED(sub='s1', email='token@corp.example')
    assert oidc_username_claim_value({'sub': 's1', 'email': 'info@corp.example'}, token, 'email') \
        == 'info@corp.example'


def test_a_verified_token_of_the_same_subject_fills_in():
    token = VERIFIED(sub='s1', upn='bob@corp.example')
    assert oidc_username_claim_value({'sub': 's1'}, token, 'upn') == 'bob@corp.example'


def test_an_unverified_token_never_fills_in():
    # the same claims as a plain dict: what the unchecked decode hands back
    token = {'sub': 's1', 'upn': 'bob@corp.example', 'verified': True}
    assert oidc_username_claim_value({'sub': 's1'}, token, 'upn') is None


def test_a_verified_token_of_another_subject_does_not_fill_in():
    token = VERIFIED(sub='someone-else', upn='bob@corp.example')
    assert oidc_username_claim_value({'sub': 's1'}, token, 'upn') is None
    assert oidc_username_claim_value({'upn': ''}, token, 'upn') is None   # an answer without a sub


def test_without_a_userinfo_answer_only_a_verified_token_counts():
    assert oidc_username_claim_value(None, VERIFIED(sub='s1', upn='bob@corp.example'), 'upn') \
        == 'bob@corp.example'
    assert oidc_username_claim_value({}, {'sub': 's1', 'upn': 'bob@corp.example'}, 'upn') is None


@pytest.mark.parametrize('flag', [False, 'false', 'False'])
def test_an_email_the_idp_calls_unverified_names_nobody(flag):
    info = {'sub': 's1', 'email': 'karen@corp.example', 'email_verified': flag}
    assert oidc_username_claim_value(info, VERIFIED(sub='s1'), 'email') is None
    token = VERIFIED(sub='s1', email='karen@corp.example', email_verified=flag)
    assert oidc_username_claim_value(None, token, 'email') is None
    # the flag only matters for email
    assert oidc_username_claim_value({**info, 'upn': 'karen@corp.example'}, VERIFIED(sub='s1'), 'upn') \
        == 'karen@corp.example'


@pytest.mark.parametrize('flag', [True, 'true', None])
def test_a_verified_or_unflagged_email_counts(flag):
    info = {'sub': 's1', 'email': 'karen@corp.example'}
    if flag is not None:
        info['email_verified'] = flag
    assert oidc_username_claim_value(info, VERIFIED(sub='s1'), 'email') == 'karen@corp.example'


@pytest.mark.parametrize('claim', ['name', 'unique_name', 'sub', '', None])
def test_a_claim_outside_the_list_has_no_value(claim):
    claims = {'sub': 's1', 'name': 'Bob', 'unique_name': 'CORP\\bob', '': 'x'}
    assert oidc_username_claim_value(dict(claims), VERIFIED(claims), claim) is None


@pytest.mark.parametrize('value', ['', '   ', None, 7, ['bob@corp.example']])
def test_a_blank_or_odd_value_is_no_value(value):
    assert oidc_username_claim_value({'sub': 's1', 'upn': value}, VERIFIED(sub='s1', upn=value), 'upn') is None


# --- c) the name ------------------------------------------------------------------------

def test_a_picked_name_replaces_the_claim_order(db):
    info = {'sub': 's1', 'preferred_username': 'Bob.Pref', 'email': 'bob@corp.example'}
    assert oidc_derive_username(info, {}, name='Bob@Corp.Example') == 'bob@corp.example'
    assert oidc_derive_username(info, {}) == 'bob.pref'


@pytest.mark.parametrize('value', ['admİn@corp.example',      # a dotted capital I
                                   'ad​min@corp.example',      # a zero-width space
                                   "o'brien@corp.example",
                                   'ádmin@corp.example',       # a letter outside ASCII
                                   'CORP\\bob', 'bob smith', '\\\\ !!',
                                   '\u212aaren@corp.example',      # the Kelvin sign, lower() makes it k
                                   '\u00a0karen@corp.example',     # a no-break space
                                   'karen@corp.example\u2003',     # an em space
                                   ' karen@corp.example'])
def test_a_picked_name_is_taken_whole_or_not_at_all(db, value, caplog):
    with caplog.at_level(logging.WARNING):
        assert oidc_derive_username({'sub': 's1'}, {}, name=value) is None
    assert 'cannot carry' in caplog.text


def test_an_odd_name_refuses_the_sign_in_and_makes_no_account(api, db, idp, signer, monkeypatch):
    r = _adfs(api, monkeypatch, _id_token(signer, upn='admİn@corp.example'), username_claim='upn')
    assert r.status_code == 403
    assert r.get_json()['error'] == UNMATCHED
    assert _accounts(db) == []


# --- c) the sign-in ------------------------------------------------------------------------

def test_an_ad_fs_sign_in_is_named_by_the_upn_in_the_token(api, db, idp, signer, monkeypatch):
    r = _adfs(api, monkeypatch, _id_token(signer, preferred_username=None, email=None,
                                          upn='Bob.Upn@Corp.Example'), username_claim='upn')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'bob.upn@corp.example'
    assert db.get_user('bob.upn@corp.example')['oidc_sub'] == SUB
    assert _accounts(db) == ['bob.upn@corp.example']


def test_an_ad_fs_userinfo_sub_that_is_not_the_tokens_does_not_matter(api, db, idp, signer, monkeypatch):
    # userinfo with a sub alone says nothing about the user: the verified token is the identity
    r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'),
              userinfo={'sub': 'a-sub-the-userinfo-resource-gets'}, username_claim='upn')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


def test_a_userinfo_answer_about_another_subject_refuses_the_sign_in(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'),
                  userinfo={'sub': 'mallory', 'upn': 'bob@corp.example'}, username_claim='upn')
    assert r.status_code == 401
    assert 'another subject than the verified ID token' in caplog.text
    assert _accounts(db) == []


def test_the_picked_claim_wins_over_preferred_username(api, db, idp, signer, monkeypatch):
    r = _adfs(api, monkeypatch, _id_token(signer, preferred_username='Wanda.Pref',
                                          email='wanda.mail@corp.example'), username_claim='email')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'wanda.mail@corp.example'


def test_a_sign_in_without_the_picked_claim_is_refused(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer), username_claim='upn')
    assert r.status_code == 401
    assert "no usable 'upn' claim" in r.get_json()['error']
    assert 'neither the userinfo answer nor the ID token carries it' in caplog.text
    assert _accounts(db) == []


def test_an_unverified_token_does_not_name_the_account(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'), username_claim='upn',
                  oidc_skip_jwt_verification=True)
    assert r.status_code == 401
    assert 'its signature was not checked' in caplog.text
    assert _accounts(db) == []


def test_a_token_signed_by_a_stranger_does_not_name_the_account(api, db, idp, monkeypatch, caplog):
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(stranger, upn='root@corp.example'), username_claim='upn')
    assert r.status_code == 401
    assert 'falling back to unverified decode' in caplog.text
    assert 'its signature was not checked' in caplog.text
    assert _accounts(db) == []


def test_an_unverified_email_refuses_the_sign_in(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, email='karen@corp.example', email_verified=False),
                  username_claim='email')
    assert r.status_code == 401
    assert 'marks the email as not verified' in caplog.text
    assert _accounts(db) == []


def test_a_claim_outside_the_list_in_the_config_refuses_the_sign_in(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, unique_name='CORP\\wanda'), username_claim='unique_name')
    assert r.status_code == 401
    assert "no usable 'unique_name' claim" in caplog.text
    assert _accounts(db) == []


def test_a_userinfo_answer_that_is_no_object_is_ignored(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer), userinfo=['not', 'an', 'object'], provider='generic')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'wanda@corp.example'


def test_without_a_picked_claim_the_old_order_stays(api, db, idp, signer, monkeypatch):
    r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'wanda@corp.example'


# --- c) Entra -------------------------------------------------------------------------------

def test_entra_names_the_account_by_upn_while_graph_answers(api, db, idp, signer, monkeypatch):
    r = _sign_in(api, monkeypatch, _id_token(signer, oid=OID), graph=GRAPH_OK, username_claim='upn')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'wanda@corp.example'


def test_entra_keeps_the_account_when_graph_comes_and_goes(api, db, idp, signer, monkeypatch):
    token = _id_token(signer, oid=OID)
    for graph in [(503, {}), GRAPH_OK, (429, {}), GRAPH_OK]:
        r = _sign_in(api, monkeypatch, token, graph=graph, username_claim='preferred_username')
        assert r.status_code == 200, (graph[0], r.get_data(as_text=True))
        assert r.get_json()['user'] == 'wanda@corp.example'
    assert _accounts(db) == ['wanda@corp.example']


def test_an_oid_counts_for_entra_only(api, db, idp, signer, monkeypatch):
    # a generic IdP's oid claim is just a claim: it does not open someone's account
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='admin')
    r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example', oid='the-real-bob'),
              username_claim='upn')
    assert r.status_code == 403
    assert db.get_user('bob@corp.example')['oidc_sub'] == 'the-real-bob'


# --- d) the account stays with its subject ------------------------------------------------

def test_an_account_of_another_subject_is_not_taken(api, db, idp, signer, monkeypatch, caplog):
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='admin')
    before = copy.deepcopy(db.get_user('bob@corp.example'))
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, email='bob@corp.example'), username_claim='email')
    assert r.status_code == 403
    assert r.get_json()['error'] == UNMATCHED
    assert 'belongs to another subject' in caplog.text
    after = db.get_user('bob@corp.example')
    assert (after['oidc_sub'], after['role']) == (before['oidc_sub'], before['role'])


def test_the_same_subject_gets_its_account_again(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'bob@corp.example', sub=SUB, auth_source='oidc', role='user')
    r = _adfs(api, monkeypatch, _id_token(signer, email='bob@corp.example'), username_claim='email')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'bob@corp.example'
    assert _accounts(db) == ['bob@corp.example']


def test_a_row_without_a_stored_subject_is_not_taken(api, db, idp, signer, monkeypatch, caplog):
    _seed_oidc(db, 'bob@corp.example', sub='', auth_source='oidc', role='admin', tenant_id='t-secret')
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'), username_claim='upn')
    assert r.status_code == 403
    assert 'has no identity provider subject stored' in caplog.text
    row = db.get_user('bob@corp.example')
    assert (row['oidc_sub'], row['role'], row['tenant_id']) == ('', 'admin', 't-secret')


def test_without_auto_create_a_missing_and_a_foreign_account_read_alike(api, db, idp, signer, monkeypatch):
    token = _id_token(signer, upn='bob@corp.example')
    missing = _adfs(api, monkeypatch, token, username_claim='upn', auto_create_users=False)
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc')
    foreign = _adfs(api, monkeypatch, token, username_claim='upn', auto_create_users=False)
    assert (missing.status_code, missing.get_json()) == (foreign.status_code, foreign.get_json())
    assert missing.get_json()['error'] == UNMATCHED


def test_without_auto_create_the_own_account_is_found(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'bob@corp.example', sub=SUB, auth_source='oidc')
    r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'), username_claim='upn',
              auto_create_users=False)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'bob@corp.example'


def test_a_sign_in_without_a_sub_cannot_use_a_picked_claim(db, caplog):
    with caplog.at_level(logging.WARNING):
        built = oidc_build_user_row({'email': 'bob@corp.example'}, {'role': 'viewer'},
                                    'oidc', {}, name='bob@corp.example')
    assert built is None
    assert 'has no sub' in caplog.text


@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_a_local_or_directory_account_is_still_never_taken(db, source):
    users = {'bob@corp.example': {'auth_source': source, 'role': 'admin'}}
    assert oidc_build_user_row({'sub': 's1'}, {'role': 'viewer'}, 'oidc', users,
                               name='bob@corp.example') is None


def test_without_a_picked_claim_the_old_update_is_unchanged(db):
    # the old order still updates an OIDC row by name, sub and all: this change does not
    # reach installs that leave the setting empty
    users = {'bob@corp.example': {'auth_source': 'oidc', 'oidc_sub': 'old', 'role': 'user'}}
    built = oidc_build_user_row({'sub': 'new', 'email': 'bob@corp.example'}, {'role': 'viewer'},
                                'oidc', users)
    assert built is not None and built[1]['oidc_sub'] == 'new'


def test_a_kelvin_sign_does_not_get_karen_s_name(api, db, idp, signer, monkeypatch):
    r = _adfs(api, monkeypatch, _id_token(signer, upn='\u212aaren@corp.example'), username_claim='upn')
    assert r.status_code == 403
    assert _accounts(db) == []


# --- e) email and Entra ---------------------------------------------------------------------

def test_email_cannot_be_saved_for_entra(admin):
    r = admin.post('/api/settings/server', json={'oidc_provider': 'entra', 'oidc_username_claim': 'email'})
    assert r.status_code == 400
    assert 'does not verify' in r.get_json()['error']
    assert admin.get('/api/settings/server').get_json()['oidc_username_claim'] == ''


def test_email_stays_for_other_providers_but_blocks_a_switch_to_entra(admin):
    assert admin.post('/api/settings/server', json={'oidc_provider': 'generic',
                                                    'oidc_username_claim': 'email'}).status_code == 200
    r = admin.post('/api/settings/server', json={'oidc_provider': 'entra'})
    assert r.status_code == 400
    assert admin.get('/api/settings/server').get_json()['oidc_provider'] == 'generic'
    # an unknown provider is stored as entra, so it is refused the same way
    assert admin.post('/api/settings/server', json={'oidc_provider': 'nonsense'}).status_code == 400


def test_email_does_not_name_an_entra_account_at_the_sign_in(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _sign_in(api, monkeypatch, _id_token(signer, oid=OID), graph=GRAPH_OK, username_claim='email')
    assert r.status_code == 401
    assert 'email cannot name Entra accounts' in caplog.text
    assert _accounts(db) == []


def test_an_entra_token_without_an_oid_is_the_identity_itself(api, db, idp, signer, monkeypatch):
    # Graph answers, but nothing ties its id to the token: the token names and binds
    r = _sign_in(api, monkeypatch, _id_token(signer), graph=GRAPH_OK, username_claim='preferred_username')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'wanda@corp.example'
    assert db.get_user('wanda@corp.example')['oidc_sub'] == SUB


# --- odd answers ----------------------------------------------------------------------------

@pytest.mark.parametrize('skip', [False, True])
def test_a_subject_id_that_is_no_text_refuses_the_sign_in(api, db, idp, signer, monkeypatch, skip):
    r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'),
              userinfo={'sub': {'nested': 'object'}, 'upn': 'bob@corp.example'}, username_claim='upn',
              oidc_skip_jwt_verification=skip)
    assert r.status_code == 401
    assert _accounts(db) == []


def test_without_signature_checks_the_userinfo_answer_names_and_binds(api, db, idp, signer, monkeypatch):
    # the admin switch for broken JWKS: the token counts for nothing, the userinfo answer
    # (fetched with the access token, straight from the IdP) still does
    r = _adfs(api, monkeypatch, _id_token(signer), userinfo={'sub': 'info-sub', 'upn': 'bob@corp.example'},
              username_claim='upn', oidc_skip_jwt_verification=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('bob@corp.example')['oidc_sub'] == 'info-sub'


def test_a_userinfo_answer_that_is_no_object_leaves_the_token(api, db, idp, signer, monkeypatch):
    r = _adfs(api, monkeypatch, _id_token(signer, upn='bob@corp.example'), userinfo='just a string',
              username_claim='upn')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


# --- d) on a standby ------------------------------------------------------------------------

from test_ha_api import ha_env, _standby_of_active  # noqa: E402,F401 - ha_env is a fixture
from test_ha_standby_oidc import (  # noqa: E402
    NOT_HERE, _claims, _idp as _sb_idp, _oidc_row, _sign_in as _sb_sign_in, _stored,
)


def _upn_claims(who, **extra):
    return VERIFIED(_claims(who, upn=f'{who}@corp.example', **extra))


def test_on_a_standby_a_held_name_answers_like_a_missing_one(ha_env, db, monkeypatch, caplog):
    _standby_of_active(ha_env)
    held = _oidc_row(db, 'olga@corp.example', oidc_sub='someone-else')
    _sb_idp(monkeypatch, {'username_claim': 'upn'}, erin=_upn_claims('erin'), olga=_upn_claims('olga'))
    missing = _sb_sign_in(ha_env.api, 'erin')
    with caplog.at_level(logging.WARNING):
        taken = _sb_sign_in(ha_env.api, 'olga')
    assert (missing.status_code, missing.get_json()) == (taken.status_code, taken.get_json()) \
        == (409, {'code': 'HA_STANDBY', 'error': NOT_HERE})
    assert 'answered like a missing one' in caplog.text
    assert _stored(db, 'olga@corp.example') == held


def test_on_a_standby_the_own_row_signs_in(ha_env, db, monkeypatch):
    _standby_of_active(ha_env)
    before = _oidc_row(db, 'olga@corp.example', oidc_sub='idp-subject-olga')
    _sb_idp(monkeypatch, {'username_claim': 'upn'}, olga=_upn_claims('olga'))
    r = _sb_sign_in(ha_env.api, 'olga')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(db, 'olga@corp.example') == before


def test_on_a_standby_without_auto_create_a_held_name_answers_like_a_missing_one(ha_env, db, monkeypatch):
    _standby_of_active(ha_env)
    held = _oidc_row(db, 'olga@corp.example', oidc_sub='someone-else')
    _sb_idp(monkeypatch, {'username_claim': 'upn', 'auto_create_users': False},
            erin=_upn_claims('erin'), olga=_upn_claims('olga'))
    missing = _sb_sign_in(ha_env.api, 'erin')
    taken = _sb_sign_in(ha_env.api, 'olga')
    assert (missing.status_code, missing.get_json()) == (taken.status_code, taken.get_json()) \
        == (403, {'error': UNMATCHED})
    assert _stored(db, 'olga@corp.example') == held


def test_email_does_not_name_an_entra_tenant_set_up_as_generic(api, db, idp, signer, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        r = _adfs(api, monkeypatch, _id_token(signer, email='ceo@corp.example', tid='a-tenant-id'),
                  username_claim='email')
    assert r.status_code == 401
    assert 'email cannot name Entra accounts' in caplog.text
    assert _accounts(db) == []
