"""An OIDC / Entra account stays with the identity provider subject it is bound to, in
both naming modes.

With a picked username claim this held already (test_oidc_username_claim_1149.py). The
automatic order (oidc_username_claim empty, the default) updated a row by name, oidc_sub
included: whoever signed in last under a preferred_username got the account and its role.
Now:

  a) a row with a stored oidc_sub signs in only for a subject among this sign-in's ids:
     user_info's sub, and from a verified ID token its sub and, with Entra, its oid. So an
     Entra sign-in whose Graph /me answers one time and not the next keeps its account
  b) a row without one (made by hand, or reset by an admin) is bound by the next sign-in
     that carries a subject id and names it exactly: a name that reaches its key only
     once characters are dropped or folded (padding, a zero-width space, an apostrophe, a
     combining mark, the Kelvin sign) does not bind it. Nor does such a name make a new
     account under the key, but for punctuation the filter drops (an O'Brien address). A
     sign-in without any subject id makes and binds no account, and a stored sub is never
     written over with an empty one
  c) a refused binding answers with the neutral sentence and logs why; with auto-create
     off a missing account answers the same. A name another identity source owns and
     reserved names keep their answers. A disabled account is refused before anything
     of the sign-in is stored
  d) on a standby a held name answers like a missing one, as with a picked claim, and an
     account not bound yet sends the user to the active, where the binding is made

MK Nov 2026
"""
import copy
import logging

import pytest

from pegaprox.utils.oidc import oidc_build_user_row, oidc_derive_username, oidc_provision_user
from tests.conftest import _seed_user
from tests.test_oidc_fallback_name_1141 import (  # noqa: F401 - idp and signer are fixtures
    SUB, _accounts, _id_token, _key, _seed_oidc, _sign_in, idp, signer,
)

UNMATCHED = 'This sign-in could not be matched to a PegaProx account. Contact an administrator.'
LOCAL_OWNS = 'A local account with this username already exists. Contact an administrator.'
NOT_EXACT = 'is taken only by its exact name'
OID = 'object-id-of-wanda'
GRAPH_OK = (200, {'id': OID, 'userPrincipalName': 'Wanda@Corp.Example', 'displayName': 'Wanda',
                  'mail': 'wanda.mail@corp.example'})
MAPPING = {'role': 'viewer'}


def _row(sub, **extra):
    return dict({'auth_source': 'oidc', 'oidc_sub': sub, 'role': 'admin', 'tenant_id': 'acme'}, **extra)


def _generic(api, monkeypatch, token, userinfo, **config):
    return _sign_in(api, monkeypatch, token, userinfo=userinfo, provider='generic', **config)


# --- a) b) the rule, on the row builder ---------------------------------------------------

@pytest.mark.parametrize('name', [None, 'bob@corp.example'])
def test_another_subject_does_not_get_the_account(db, caplog, name):
    users = {'bob@corp.example': _row('the-real-bob')}
    before = copy.deepcopy(users)
    with caplog.at_level(logging.WARNING):
        built = oidc_build_user_row({'sub': 'mallory', 'preferred_username': 'bob@corp.example'},
                                    MAPPING, 'oidc', users, name=name)
    assert built is None
    assert 'belongs to another subject of the identity provider' in caplog.text
    assert 'reset its sign-in binding' in caplog.text
    assert users == before


@pytest.mark.parametrize('name', [None, 'bob@corp.example'])
def test_the_bound_subject_gets_its_account_again(db, name):
    users = {'bob@corp.example': _row('the-real-bob')}
    built = oidc_build_user_row({'sub': 'the-real-bob', 'preferred_username': 'bob@corp.example'},
                                MAPPING, 'oidc', users, name=name)
    assert built is not None
    username, row = built
    assert (username, row['oidc_sub'], row['tenant_id']) == ('bob@corp.example', 'the-real-bob', 'acme')


@pytest.mark.parametrize('name', [None, 'bob@corp.example'])
def test_a_row_without_a_subject_is_bound_by_the_next_sign_in(db, name):
    users = {'bob@corp.example': _row('')}
    built = oidc_build_user_row({'sub': 's-bob', 'preferred_username': 'bob@corp.example'},
                                MAPPING, 'oidc', users, name=name)
    assert built is not None and built[1]['oidc_sub'] == 's-bob'


def test_any_id_of_the_sign_in_opens_its_account(db):
    # Entra: the row holds the Graph id, this sign-in came through the userinfo endpoint
    # (pairwise sub), and the verified token carries both
    users = {'wanda@corp.example': _row(OID, auth_source='entra')}
    info = {'sub': 'pairwise-sub', 'preferred_username': 'wanda@corp.example'}
    assert oidc_build_user_row(info, MAPPING, 'entra', users) is None
    built = oidc_build_user_row(info, MAPPING, 'entra', users, subjects={'pairwise-sub', OID})
    assert built is not None and built[1]['oidc_sub'] == 'pairwise-sub'
    # and back: the row holds the pairwise sub, Graph answers with the object id
    users = {'wanda@corp.example': _row('pairwise-sub', auth_source='entra')}
    graph = {'sub': OID, 'preferred_username': 'wanda@corp.example'}
    assert oidc_build_user_row(graph, MAPPING, 'entra', users, subjects={'pairwise-sub', OID}) is not None


@pytest.mark.parametrize('odd', [None, '', 42, {'nested': 'the-real-bob'}, ['the-real-bob']])
def test_an_id_that_is_no_text_opens_nothing(db, odd):
    users = {'bob@corp.example': _row('the-real-bob')}
    info = {'sub': odd, 'preferred_username': 'bob@corp.example'}
    assert oidc_build_user_row(info, MAPPING, 'oidc', users, subjects=[odd, None, '']) is None


def test_a_fallback_row_stays_with_its_subject(db, caplog):
    key = _key('s-first')
    users = {key: _row('s-first')}
    assert oidc_derive_username({'sub': 's-first'}, users) == key
    with caplog.at_level(logging.WARNING):
        assert oidc_build_user_row({'sub': 'other', 'preferred_username': key}, MAPPING, 'oidc', users,
                                   subjects={'s-first'}) is None
    assert "made for another subject's sign-in without a name" in caplog.text
    assert oidc_build_user_row({'sub': 's-first'}, MAPPING, 'oidc', users) is not None


def test_the_legacy_key_of_the_same_subject_is_still_found(db):
    users = {'olga': _row('s-olga')}
    info = {'sub': 's-olga', 'preferred_username': 'olga@corp.example'}
    assert oidc_derive_username(info, users) == 'olga'
    assert oidc_build_user_row(info, MAPPING, 'oidc', users)[0] == 'olga'
    # another subject with that local part gets an account of its own, the old one stays
    other = {'sub': 's-olga-2', 'preferred_username': 'olga@corp.example'}
    assert oidc_build_user_row(other, MAPPING, 'oidc', users)[0] == 'olga@corp.example'


def test_provisioning_writes_nothing_for_a_refused_binding(db):
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='admin')
    assert oidc_provision_user({'sub': 'mallory', 'preferred_username': 'bob@corp.example'},
                               {'role': 'viewer', '_authoritative': True}) is None
    row = db.get_user('bob@corp.example')
    assert (row['oidc_sub'], row['role']) == ('the-real-bob', 'admin')
    assert _accounts(db) == ['bob@corp.example']


# names that reach the key bob@corp.example (kelvin@corp.example) only once a character is
# dropped or folded
FOLDED = ['bob\u200b@corp.example', ' bob@corp.example', 'bob@corp.example ', "bo'b@corp.example",
          'bo\u0308b@corp.example', '\u212aelvin@corp.example']


def _target(variant):
    return 'kelvin@corp.example' if 'elvin' in variant else 'bob@corp.example'


@pytest.mark.parametrize('name', [None, 'bob@corp.example'])
@pytest.mark.parametrize('variant', FOLDED)
def test_a_folded_name_does_not_bind_an_unbound_row(db, caplog, variant, name):
    target = _target(variant)
    users = {target: _row('')}
    info = {'sub': 'mallory', 'preferred_username': variant}
    if name is not None:
        # a picked claim is taken whole or not at all already: no folded name gets this far
        assert oidc_derive_username(info, users, name=variant) is None
        return
    assert oidc_derive_username(info, users) == target
    with caplog.at_level(logging.WARNING):
        assert oidc_build_user_row(info, MAPPING, 'oidc', users) is None
    assert NOT_EXACT in caplog.text


@pytest.mark.parametrize('claim', ['bob@corp.example', 'BOB@Corp.Example'])
def test_the_exact_name_binds_an_unbound_row_in_any_case(db, claim):
    users = {'bob@corp.example': _row('')}
    built = oidc_build_user_row({'sub': 's-bob', 'preferred_username': claim}, MAPPING, 'oidc', users)
    assert built is not None and built[1]['oidc_sub'] == 's-bob'
    picked = oidc_build_user_row({'sub': 's-bob'}, MAPPING, 'oidc', users, name=claim)
    assert picked is not None and picked[1]['oidc_sub'] == 's-bob'


@pytest.mark.parametrize('sub', [None, '', 42, {'nested': 's'}])
def test_a_sign_in_without_a_sub_makes_and_binds_no_account(db, caplog, sub):
    info = {'preferred_username': 'bob@corp.example'}
    if sub is not None:
        info['sub'] = sub
    with caplog.at_level(logging.WARNING):
        assert oidc_build_user_row(info, MAPPING, 'oidc', {}) is None
        assert oidc_build_user_row(info, MAPPING, 'oidc', {'bob@corp.example': _row('')},
                                   subjects={'token-sub'}) is None
    assert 'has no sub' in caplog.text


# --- c) through the callback, automatic order -------------------------------------------

def test_another_subject_with_that_name_gets_the_neutral_answer(api, db, idp, signer, monkeypatch, caplog):
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='admin')
    token = _id_token(signer, preferred_username='bob@corp.example')
    with caplog.at_level(logging.WARNING):
        r = _generic(api, monkeypatch, token, {'sub': SUB, 'preferred_username': 'bob@corp.example'})
    assert r.status_code == 403
    assert r.get_json() == {'error': UNMATCHED}
    assert 'belongs to another subject' in caplog.text
    row = db.get_user('bob@corp.example')
    assert (row['oidc_sub'], row['role']) == ('the-real-bob', 'admin')


def test_the_bound_subject_signs_in(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='user')
    token = _id_token(signer, sub='the-real-bob', preferred_username='bob@corp.example')
    r = _generic(api, monkeypatch, token, {'sub': 'the-real-bob', 'preferred_username': 'bob@corp.example'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'bob@corp.example'


def test_a_row_without_a_subject_is_bound_and_then_kept(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'bob@corp.example', sub='', auth_source='oidc', role='user')
    first = _generic(api, monkeypatch, _id_token(signer, preferred_username='bob@corp.example'),
                     {'sub': SUB, 'preferred_username': 'bob@corp.example'})
    assert first.status_code == 200, first.get_data(as_text=True)
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB
    second = _generic(api, monkeypatch, _id_token(signer, sub='mallory', preferred_username='bob@corp.example'),
                      {'sub': 'mallory', 'preferred_username': 'bob@corp.example'})
    assert second.status_code == 403 and second.get_json() == {'error': UNMATCHED}
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


def test_entra_keeps_the_account_when_graph_comes_and_goes(api, db, idp, signer, monkeypatch):
    # Graph /me answers with the object id, the userinfo endpoint with the pairwise sub:
    # the stored sub flips between them, the verified token's sub and oid cover both
    token = _id_token(signer, oid=OID)
    for graph in [(503, {}), GRAPH_OK, (429, {}), GRAPH_OK, (403, {})]:
        r = _sign_in(api, monkeypatch, token, graph=graph)
        assert r.status_code == 200, (graph[0], r.get_data(as_text=True))
        assert r.get_json()['user'] == 'wanda@corp.example'
    assert _accounts(db) == ['wanda@corp.example']


def test_entra_another_person_under_that_name_is_refused(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'wanda@corp.example', sub=OID, role='admin')
    token = _id_token(signer, sub='pairwise-of-someone-else', oid='object-id-of-someone-else')
    graph = (200, dict(GRAPH_OK[1], id='object-id-of-someone-else'))
    r = _sign_in(api, monkeypatch, token, graph=graph)
    assert r.status_code == 403 and r.get_json() == {'error': UNMATCHED}
    assert db.get_user('wanda@corp.example')['oidc_sub'] == OID


def test_an_oid_counts_for_entra_only(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='admin')
    token = _id_token(signer, preferred_username='bob@corp.example', oid='the-real-bob')
    r = _generic(api, monkeypatch, token, {'sub': SUB, 'preferred_username': 'bob@corp.example'})
    assert r.status_code == 403
    assert db.get_user('bob@corp.example')['oidc_sub'] == 'the-real-bob'


def test_an_unverified_token_s_ids_do_not_count(api, db, idp, signer, monkeypatch):
    # with the signature check off the token's sub is no id of the sign-in, the userinfo
    # answer's still is
    _seed_oidc(db, 'bob@corp.example', sub=SUB, auth_source='oidc', role='admin')
    token = _id_token(signer, preferred_username='bob@corp.example')
    r = _generic(api, monkeypatch, token, {'sub': 'info-sub', 'preferred_username': 'bob@corp.example'},
                 oidc_skip_jwt_verification=True)
    assert r.status_code == 403
    ok = _generic(api, monkeypatch, token, {'sub': SUB, 'preferred_username': 'bob@corp.example'},
                  oidc_skip_jwt_verification=True)
    assert ok.status_code == 200, ok.get_data(as_text=True)


@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_an_account_of_another_source_keeps_its_answer(api, db, idp, signer, monkeypatch, source):
    _seed_user(db, 'boss@corp.example', role='admin')
    row = db.get_user('boss@corp.example')
    row['auth_source'] = source
    db.save_user('boss@corp.example', row)
    r = _generic(api, monkeypatch, _id_token(signer, preferred_username='boss@corp.example'),
                 {'sub': SUB, 'preferred_username': 'boss@corp.example'})
    assert r.status_code == 403 and r.get_json() == {'error': LOCAL_OWNS}


def test_without_auto_create_a_missing_and_a_held_account_read_alike(api, db, idp, signer, monkeypatch):
    # a missing name answered 'User account does not exist', a held one the neutral
    # sentence: the difference told which names are taken
    token = _id_token(signer, preferred_username='bob@corp.example')
    info = {'sub': SUB, 'preferred_username': 'bob@corp.example'}
    missing = _generic(api, monkeypatch, token, info, auto_create_users=False)
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc')
    held = _generic(api, monkeypatch, token, info, auto_create_users=False)
    assert (missing.status_code, missing.get_json()) == (held.status_code, held.get_json()) \
        == (403, {'error': UNMATCHED})
    _seed_oidc(db, 'bob@corp.example', sub=SUB, auth_source='oidc')
    own = _generic(api, monkeypatch, token, info, auto_create_users=False)
    assert own.status_code == 200, own.get_data(as_text=True)


def _groups_not_known(monkeypatch):
    # a provider that sends no group set: the sign-in may grant but revoke nothing, so a
    # row it takes keeps the role it has
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'oidc_map_groups_to_role',
                        lambda config, groups, id_claims=None, groups_complete=True: {'role': 'viewer'})


@pytest.mark.parametrize('variant', FOLDED)
def test_a_folded_name_does_not_take_an_unbound_admin_account(api, db, idp, signer, monkeypatch, caplog,
                                                              variant):
    target = _target(variant)
    _seed_oidc(db, target, sub='', auth_source='oidc', role='admin', tenant_id='t-boss')
    _groups_not_known(monkeypatch)
    with caplog.at_level(logging.WARNING):
        r = _generic(api, monkeypatch, _id_token(signer, sub='mallory', preferred_username=variant),
                     {'sub': 'mallory', 'preferred_username': variant})
    assert r.status_code == 403 and r.get_json() == {'error': UNMATCHED}
    assert NOT_EXACT in caplog.text
    row = db.get_user(target)
    assert (row['oidc_sub'], row['role'], row['tenant_id']) == ('', 'admin', 't-boss')
    assert _accounts(db) == [target]


def test_the_exact_name_takes_its_unbound_admin_account(api, db, idp, signer, monkeypatch):
    # counter-check: the owner's own name, in another case, binds it and keeps the role
    _seed_oidc(db, 'bob@corp.example', sub='', auth_source='oidc', role='admin', tenant_id='t-boss')
    _groups_not_known(monkeypatch)
    r = _generic(api, monkeypatch, _id_token(signer, preferred_username='Bob@Corp.Example'),
                 {'sub': SUB, 'preferred_username': 'Bob@Corp.Example'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert (r.get_json()['user'], r.get_json()['role']) == ('bob@corp.example', 'admin')
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


# names with padding, a character NFKC folds, or one that cannot be seen or combines with
# a letter, and the clean name of the person they pass for. Most land on that person's key;
# the fullwidth forms and the ligature make a look-alike key of their own
NOT_SPELLED = [('bob@corp.example', 'Bob\u200b@corp.example', True),      # zero-width space
               ('bob@corp.example', 'bob@corp.example ', True),            # padding
               ('bob@corp.example', ' bob@corp.example', True),
               ('bob@corp.example', 'bo\u0308b@corp.example', True),       # a combining mark
               ('bob@corp.example', 'bob\u00ad@corp.example', True),       # soft hyphen
               ('bob@corp.example', 'bob\t@corp.example', True),
               ('kelvin@corp.example', '\u212aelvin@corp.example', True),  # the Kelvin sign
               ('ines@corp.example', '\u0130nes@corp.example', True),      # a dotted capital I
               ('bob@corp.example', '\uff42ob@corp.example', False),       # fullwidth b
               ('bob@corp.example', 'bob@corp\uff0eexample', False),       # fullwidth full stop
               ('fin@corp.example', '\ufb01n@corp.example', False)]        # the fi ligature


@pytest.mark.parametrize('clean,variant,same_key', NOT_SPELLED)
def test_a_folded_name_makes_no_new_account(db, caplog, clean, variant, same_key):
    info = {'sub': 'mallory', 'preferred_username': variant}
    assert (oidc_derive_username(info, {}) == clean) is same_key
    with caplog.at_level(logging.WARNING):
        assert oidc_build_user_row(info, MAPPING, 'oidc', {}) is None
    assert 'a new account takes a name only as the identity provider spells it' in caplog.text


@pytest.mark.parametrize('claim,key', [('Bob@Corp.Example', 'bob@corp.example'),
                                       ("O'Brien@corp.example", 'obrien@corp.example'),
                                       ('bob smith', 'bobsmith'),
                                       ('b\u043eb@corp.example', 'b\u043eb@corp.example')])  # a Cyrillic o: its own key
def test_a_name_with_punctuation_or_case_still_makes_its_account(db, claim, key):
    built = oidc_build_user_row({'sub': 's1', 'preferred_username': claim}, MAPPING, 'oidc', {})
    assert built is not None and built[0] == key and built[1]['oidc_sub'] == 's1'


def test_a_sign_in_without_a_name_still_makes_its_account(db):
    # keyed on the sub, also when the only name was an unverified email
    for info in ({'sub': 's1'}, {'sub': 's1', 'email': 'Bob\u200b@corp.example', 'email_verified': False}):
        built = oidc_build_user_row(info, MAPPING, 'oidc', {})
        assert built is not None and built[0] == _key('s1')


@pytest.mark.parametrize('key,variant,same_key', NOT_SPELLED)
def test_a_folded_name_does_not_take_a_free_key_from_its_owner(api, db, idp, signer, monkeypatch, caplog,
                                                               key, variant, same_key):
    with caplog.at_level(logging.WARNING):
        r = _generic(api, monkeypatch, _id_token(signer, sub='mallory', preferred_username=variant),
                     {'sub': 'mallory', 'preferred_username': variant})
    assert r.status_code == 403 and r.get_json() == {'error': UNMATCHED}
    assert 'spells it' in caplog.text
    assert _accounts(db) == []
    # the person of that name makes it with the first sign-in
    owner = _generic(api, monkeypatch, _id_token(signer, sub='the-owner', preferred_username=key),
                     {'sub': 'the-owner', 'preferred_username': key})
    assert owner.status_code == 200, owner.get_data(as_text=True)
    assert owner.get_json()['user'] == key and db.get_user(key)['oidc_sub'] == 'the-owner'


def test_an_o_brien_address_still_makes_its_account(api, db, idp, signer, monkeypatch):
    claim = "O'Brien@corp.example"
    r = _generic(api, monkeypatch, _id_token(signer, preferred_username=claim),
                 {'sub': SUB, 'preferred_username': claim})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'obrien@corp.example'
    assert db.get_user('obrien@corp.example')['oidc_sub'] == SUB


def test_a_bound_account_is_not_touched_by_the_rule_for_new_ones(api, db, idp, signer, monkeypatch):
    # its own subject gets in, whatever padding its IdP name carries; another one does not
    _seed_oidc(db, 'bob@corp.example', sub=SUB, auth_source='oidc', role='user')
    for variant in ('Bob\u200b@corp.example', 'bob@corp.example'):
        r = _generic(api, monkeypatch, _id_token(signer, preferred_username=variant),
                     {'sub': SUB, 'preferred_username': variant})
        assert r.status_code == 200 and r.get_json()['user'] == 'bob@corp.example', r.get_data(as_text=True)
    other = _generic(api, monkeypatch, _id_token(signer, sub='mallory', preferred_username='bob@corp.example'),
                     {'sub': 'mallory', 'preferred_username': 'bob@corp.example'})
    assert other.status_code == 403
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


def test_a_userinfo_answer_without_a_sub_keeps_the_binding(api, db, idp, signer, monkeypatch):
    # its sub is the verified token's: written over with '' it left the row to anyone
    _seed_oidc(db, 'bob@corp.example', sub=SUB, auth_source='oidc', role='admin')
    r = _generic(api, monkeypatch, _id_token(signer, preferred_username='bob@corp.example'),
                 {'preferred_username': 'bob@corp.example'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB
    other = _generic(api, monkeypatch, _id_token(signer, sub='mallory', preferred_username='bob@corp.example'),
                     {'sub': 'mallory', 'preferred_username': 'bob@corp.example'})
    assert other.status_code == 403
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


def test_a_new_account_from_a_userinfo_answer_without_a_sub_is_bound(api, db, idp, signer, monkeypatch):
    r = _generic(api, monkeypatch, _id_token(signer, preferred_username='new@corp.example'),
                 {'preferred_username': 'new@corp.example'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('new@corp.example')['oidc_sub'] == SUB


def test_without_any_subject_id_the_sign_in_is_refused(api, db, idp, signer, monkeypatch, caplog):
    # the token's sub does not count unchecked, and the userinfo answer carries none
    _seed_oidc(db, 'bob@corp.example', sub='', auth_source='oidc', role='admin')
    with caplog.at_level(logging.WARNING):
        r = _generic(api, monkeypatch, _id_token(signer, preferred_username='bob@corp.example'),
                     {'preferred_username': 'bob@corp.example'}, oidc_skip_jwt_verification=True)
    assert r.status_code == 401
    assert 'carries a subject id' in caplog.text
    assert db.get_user('bob@corp.example')['oidc_sub'] == ''
    assert _accounts(db) == ['bob@corp.example']


@pytest.mark.parametrize('bound', ['', SUB])
def test_a_disabled_account_is_refused_before_anything_is_stored(api, db, idp, signer, monkeypatch, bound):
    _seed_oidc(db, 'bob@corp.example', sub=bound, auth_source='oidc', role='admin', enabled=False,
               tenant_id='t-boss', last_oidc_sync='2026-09-01T08:00:00')
    before = db.get_user('bob@corp.example')
    token = _id_token(signer, preferred_username='bob@corp.example')
    r = _generic(api, monkeypatch, token, {'sub': SUB, 'preferred_username': 'bob@corp.example'})
    assert r.status_code == 403 and r.get_json() == {'error': 'Account is disabled'}
    assert db.get_user('bob@corp.example') == before
    # enabled again, the owner gets in and binds it
    row = db.get_user('bob@corp.example')
    row['enabled'] = True
    db.save_user('bob@corp.example', row)
    again = _generic(api, monkeypatch, token, {'sub': SUB, 'preferred_username': 'bob@corp.example'})
    assert again.status_code == 200, again.get_data(as_text=True)
    assert db.get_user('bob@corp.example')['oidc_sub'] == SUB


def test_a_disabled_account_of_another_subject_reads_like_any_held_one(api, db, idp, signer, monkeypatch):
    _seed_oidc(db, 'bob@corp.example', sub='the-real-bob', auth_source='oidc', role='admin', enabled=False)
    r = _generic(api, monkeypatch, _id_token(signer, preferred_username='bob@corp.example'),
                 {'sub': SUB, 'preferred_username': 'bob@corp.example'})
    assert r.status_code == 403 and r.get_json() == {'error': UNMATCHED}


# --- d) on a standby --------------------------------------------------------------------

from test_ha_api import ha_env, _standby_of_active  # noqa: E402,F401 - ha_env is a fixture
from test_ha_standby_oidc import (  # noqa: E402
    NOT_HERE, _claims, _idp as _sb_idp, _oidc_row, _sign_in as _sb_sign_in, _stored,
)


def test_on_a_standby_a_held_name_answers_like_a_missing_one(ha_env, db, monkeypatch, caplog):
    _standby_of_active(ha_env)
    held = _oidc_row(db, 'olga', oidc_sub='someone-else')
    _sb_idp(monkeypatch, None, erin=_claims('erin'), olga=_claims('olga'))
    missing = _sb_sign_in(ha_env.api, 'erin')
    with caplog.at_level(logging.WARNING):
        taken = _sb_sign_in(ha_env.api, 'olga')
    assert (missing.status_code, missing.get_json()) == (taken.status_code, taken.get_json()) \
        == (409, {'code': 'HA_STANDBY', 'error': NOT_HERE})
    assert 'answered like a missing one' in caplog.text
    assert _stored(db, 'olga') == held


def test_on_a_standby_without_auto_create_a_held_name_gets_the_neutral_answer(ha_env, db, monkeypatch):
    _standby_of_active(ha_env)
    held = _oidc_row(db, 'olga', oidc_sub='someone-else')
    _sb_idp(monkeypatch, {'auto_create_users': False}, olga=_claims('olga'))
    r = _sb_sign_in(ha_env.api, 'olga')
    assert (r.status_code, r.get_json()) == (403, {'error': UNMATCHED})
    assert _stored(db, 'olga') == held


def test_on_a_standby_an_unbound_row_sends_the_user_to_the_active(ha_env, db, monkeypatch, caplog):
    # a standby writes no binding, so every subject of that name got in, again and again
    _standby_of_active(ha_env)
    before = _oidc_row(db, 'olga', oidc_sub='')
    _sb_idp(monkeypatch, None, olga=_claims('olga'), mallory=_claims('olga', sub='idp-subject-mallory'))
    with caplog.at_level(logging.WARNING):
        for who in ('olga', 'mallory', 'olga'):
            r = _sb_sign_in(ha_env.api, who)
            assert (r.status_code, r.get_json()) == (409, {'code': 'HA_STANDBY', 'error': NOT_HERE}), who
    assert 'does not hold the account bound to a subject yet' in caplog.text
    assert _stored(db, 'olga') == before
    # counter-check: bound to olga's subject, the standby lets her in
    _oidc_row(db, 'olga', oidc_sub='idp-subject-olga')
    assert _sb_sign_in(ha_env.api, 'olga').status_code == 200

