"""An email the identity provider marks as not verified does not name an OIDC account.

With a picked username claim this held already (test_oidc_username_claim_1149.py). In the
automatic order (preferred_username, else email) an address anybody could have typed in at
a self-service sign-up named the account, and an account with no subject stored yet went
to that sign-in with its role. Now such a sign-in goes on as one without a name: the
account bound to its sub, else one keyed on the sub (test_oidc_fallback_name_1141.py).

  * a false, a 0, or 'false', '0', 'no', 'n' or 'off' in any case and padding; Entra and
    AD FS send no flag, and nothing changes for them
  * a userinfo answer that carries the address without a flag takes the flag the verified
    ID token of the same subject sets on the same address, with a picked claim as well
  * preferred_username is not affected
  * the flag travels along when the verified ID token fills in the email

MK Nov 2026
"""
import logging

import pytest

from pegaprox.utils import oidc
from pegaprox.utils.oidc import oidc_derive_username, oidc_name_from_id_token
from tests.test_oidc_fallback_name_1141 import (  # noqa: F401 - idp and signer are fixtures
    SUB, _accounts, _id_token, _key, _seed_oidc, _sign_in, idp, signer,
)

VERIFIED = oidc._VerifiedClaims


def _row(sub, **extra):
    return dict({'auth_source': 'oidc', 'oidc_sub': sub, 'role': 'admin', 'tenant_id': 'acme'}, **extra)


def _generic(api, monkeypatch, token, userinfo, **config):
    return _sign_in(api, monkeypatch, token, userinfo=userinfo, provider='generic', **config)


# --- the name ------------------------------------------------------------------------------

@pytest.mark.parametrize('flag', [False, 'false', 'FALSE', ' false ', 0, 0.0, '0', 'no', 'No ', 'n',
                                  'off', 'OFF'])
def test_an_unverified_email_does_not_name_the_account(db, caplog, flag):
    info = {'sub': 's-karen', 'email': 'boss@corp.example', 'email_verified': flag}
    with caplog.at_level(logging.WARNING):
        assert oidc_derive_username(info, {}) == _key('s-karen')
    assert 'marked as not verified' in caplog.text


@pytest.mark.parametrize('flag', [True, 'true', 1, '1', 'yes', None])
def test_a_verified_or_unflagged_email_still_names_it(db, flag):
    # Entra and AD FS send no flag at all: nothing changes for them
    info = {'sub': 's-karen', 'email': 'Karen@Corp.Example'}
    if flag is not None:
        info['email_verified'] = flag
    assert oidc_derive_username(info, {}) == 'karen@corp.example'


def test_the_flag_does_not_touch_preferred_username(db):
    info = {'sub': 's1', 'preferred_username': 'kc.user', 'email': 'boss@corp.example',
            'email_verified': False}
    assert oidc_derive_username(info, {}) == 'kc.user'


def test_an_unverified_email_finds_the_account_bound_to_its_sub(db):
    users = {'karen@corp.example': _row('s-karen')}
    info = {'sub': 's-karen', 'email': 'karen@corp.example', 'email_verified': False}
    assert oidc_derive_username(info, users) == 'karen@corp.example'


def test_the_flag_comes_along_when_the_token_fills_in_the_email(db):
    token = VERIFIED(sub='s1', email='boss@corp.example', email_verified=False)
    named = oidc_name_from_id_token({'sub': 's1'}, token)
    assert (named['email'], named['email_verified']) == ('boss@corp.example', False)
    assert oidc_derive_username(named, {}) == _key('s1')
    # a token without the flag adds none
    assert 'email_verified' not in oidc_name_from_id_token({'sub': 's1'}, VERIFIED(sub='s1', email='x@y.z'))


# --- through the callback ------------------------------------------------------------------

def test_an_unverified_email_does_not_take_an_unbound_account(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'boss@corp.example', sub='', auth_source='oidc', role='admin', tenant_id='t-boss')
    token = _id_token(signer, sub='mallory', preferred_username=None, email='boss@corp.example',
                      email_verified=False)
    r = _generic(api, monkeypatch, token, {'sub': 'mallory', 'email': 'boss@corp.example',
                                           'email_verified': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == _key('mallory')
    row = db.get_user('boss@corp.example')
    assert (row['oidc_sub'], row['role'], row['tenant_id']) == ('', 'admin', 't-boss')


def test_an_unverified_email_from_the_token_does_not_name_either(api, db, idp, signer, monkeypatch):
    # the userinfo answer carries the sub alone, the verified token fills in the email
    token = _id_token(signer, preferred_username=None, email='boss@corp.example', email_verified=False)
    r = _generic(api, monkeypatch, token, {'sub': SUB})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == _key(SUB)
    assert db.get_user('boss@corp.example') is None


def test_an_unverified_email_finds_its_own_account(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'karen@corp.example', sub=SUB, auth_source='oidc', role='user')
    token = _id_token(signer, preferred_username=None, email='karen@corp.example', email_verified=False)
    r = _generic(api, monkeypatch, token, {'sub': SUB, 'email': 'karen@corp.example', 'email_verified': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'karen@corp.example'
    assert _accounts(db) == ['karen@corp.example']


def test_the_token_s_flag_counts_when_userinfo_leaves_it_out(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'victim@corp.example', sub='', auth_source='oidc', role='admin', tenant_id='t-v')
    token = _id_token(signer, sub='mallory', preferred_username=None, email='Victim@Corp.Example',
                      email_verified=False)
    r = _generic(api, monkeypatch, token, {'sub': 'mallory', 'email': 'victim@corp.example'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == _key('mallory')
    row = db.get_user('victim@corp.example')
    assert (row['oidc_sub'], row['role'], row['tenant_id']) == ('', 'admin', 't-v')


def test_the_token_s_flag_for_another_address_does_not_count(db):
    token = VERIFIED(sub='s1', email='other@corp.example', email_verified=False)
    named = oidc_name_from_id_token({'sub': 's1', 'email': 'karen@corp.example'}, token)
    assert 'email_verified' not in named
    assert oidc_derive_username(named, {}) == 'karen@corp.example'
    # nor an unverified token, nor one of another subject
    for other in ({'sub': 's1', 'email': 'karen@corp.example', 'email_verified': False},
                  VERIFIED(sub='s2', email='karen@corp.example', email_verified=False)):
        assert 'email_verified' not in oidc_name_from_id_token({'sub': 's1', 'email': 'karen@corp.example'},
                                                               other)


def test_with_a_picked_email_claim_the_token_s_flag_counts_too(api, db, idp, signer, monkeypatch, caplog):
    token = _id_token(signer, preferred_username=None, email='victim@corp.example', email_verified='no')
    with caplog.at_level(logging.WARNING):
        r = _generic(api, monkeypatch, token, {'sub': SUB, 'email': 'victim@corp.example', 'name': 'V'},
                     username_claim='email')
    assert r.status_code == 401
    assert 'the ID token marks the email as not verified' in caplog.text
    assert _accounts(db) == []
