"""Warm standby (#625): an OIDC / Entra sign-in on a standby is treated like a directory
sign-in there (tests/test_ha_standby_auth.py).

  * The callback writes no users row on a standby: not the provisioning, not the
    last_login stamp. The next sync would put the active's copy back, take a new
    account away again and keep a copy of it, while the session made from it stays.
  * The sign-in goes through only when the synced row is there, belongs to OIDC and the
    identity provider says what the row says: role, tenant, permissions, per-tenant
    overrides. A first sign-in and changed access are refused with a 409 that sends
    the user to the active instance once.
  * A name another identity source owns, a disabled account and a missing account with
    auto-create off answer as they do on the active.
  * A member that serves users is a standby here.
  * Where the row is this instance's to write, nothing changed: oidc_provision_user
    stores what it stored before it was split into "build the row" and "save it".

Everything on the callback drives the real route; the identity provider is the only
stand-in. Each part carries its counterproof: the same call where the rule does not apply.

MK Oct 2026
"""
import copy
import logging
from datetime import datetime

import pytest

from pegaprox.core import ha
from pegaprox.utils import oidc as O
from test_ha_api import (  # noqa: F401  (ha_env is a fixture)
    ha_env, _audit, _be, _peer_record, _standby_of_active, ACTIVE_URL, A_ID, B_ID,
)
from test_ha_core import _wire
from test_ha_forward import fwd, _forward_calls  # noqa: F401  (fwd is a fixture)
from test_ha_members import group, _built, _sync, IDS  # noqa: F401  (group is a fixture)
from test_ha_orphans import _copies, _next_from_leader, _one_tag_more
from test_ha_standby_auth import _sessions_of

NOT_HERE = ('Your account is not on this instance yet - sign in on the active instance once; '
            'it reaches this standby with the next sync.')
CHANGED = ('Your access changed at the identity provider - sign in on the active instance once; '
           'it reaches this standby with the next sync.')
OTHER_OWNER = 'A local account with this username already exists. Contact an administrator.'

# what the admin configured: two built-in groups and four mappings
OIDC_ON = {
    'enabled': True, 'provider': 'keycloak', 'client_id': 'pegaprox', 'auto_create_users': True,
    'redirect_uri': 'https://pegaprox.example/oidc/callback', 'default_role': 'viewer',
    'admin_group_id': 'g-admins', 'user_group_id': 'g-users', 'viewer_group_id': '',
    'group_mappings': [
        {'group_id': 'g-acme', 'tenant': 'acme', 'tenant_role': 'admin'},
        {'group_id': 'g-ops', 'permissions': ['vm.view', 'vm.start']},
        {'group_id': 'g-globex', 'tenant': 'globex'},
        {'group_id': 'g-delete', 'permissions': ['vm.delete']},
    ],
}
# the groups of an account that is settled below, and the access they map to
SETTLED = ('g-admins', 'g-acme', 'g-ops')
ACME_ADMIN = {'acme': {'role': 'admin', 'extra': []}}


def _claims(who, groups=SETTLED, **extra):
    """What the ID token says about `who`. groups=None is a provider that sends no
    groups claim: the group set is not known, so the sign-in may grant but not revoke."""
    claims = {'sub': f'idp-subject-{who}', 'preferred_username': who,
              'email': f'{who}@corp.example', 'name': who.title()}
    if groups is not None:
        claims['groups'] = list(groups)
    claims.update(extra)
    return claims


def _idp(monkeypatch, config=None, **people):
    """An identity provider that knows `people`: the code of a sign-in is the name, and
    the token it is exchanged for carries that person's claims. The mapping of groups
    to access and everything after it is the real code."""
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'get_oidc_settings', lambda: copy.deepcopy(dict(OIDC_ON, **(config or {}))))
    monkeypatch.setattr(auth_api, 'oidc_exchange_code',
                        lambda cfg, code, code_verifier=None: (
                            {'access_token': code, 'id_token': code} if code in people
                            else {'error': 'invalid_grant'}))
    monkeypatch.setattr(auth_api, 'oidc_decode_id_token',
                        lambda token, expected_nonce=None, config=None: copy.deepcopy(people[token]))
    monkeypatch.setattr(auth_api, 'oidc_get_user_info', lambda cfg, token: {})
    monkeypatch.setattr(auth_api, 'oidc_get_user_groups_ex', lambda cfg, token: ([], False))


def _sign_in(api, name):
    """The callback as the login page sends it after the redirect, from a browser of
    its own: no session cookie of an earlier sign-in travels along."""
    import pegaprox.api.auth as auth_api
    for key in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(key, None)      # ten a minute, and a test makes more
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    return browser.post(
        '/api/auth/oidc/callback', json={'code': name, 'state': 'the-state'},
        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
        base_url='http://localhost')


def _oidc_row(db, username, **extra):
    """An account an earlier sign-in on the active left behind, as a sync brought it."""
    row = {'password_salt': '', 'password_hash': '', 'role': 'admin', 'tenant_id': 'acme',
           'enabled': True, 'permissions': ['vm.start', 'vm.view'], 'denied_permissions': [],
           'tenant_permissions': copy.deepcopy(ACME_ADMIN), 'auth_source': 'oidc',
           'oidc_sub': f'idp-subject-{username}', 'display_name': 'As The Active Stored It',
           'email': f'{username}@old.example', 'last_login': '2026-09-01T08:00:00',
           'last_oidc_sync': '2026-09-01T08:00:00'}
    row.update(extra)
    db.save_user(username, row)
    return _stored(db, username)


def _stored(db, username):
    """The users row as it lies in the table, every column."""
    row = db.conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    return dict(row) if row else None


def _cookies(resp):
    return [c.split('=', 1)[0] for c in resp.headers.getlist('Set-Cookie')]


def _sign_out(username):
    import pegaprox.utils.auth as authmod
    for sid in [sid for sid, s in authmod.active_sessions.items() if s.get('user') == username]:
        del authmod.active_sessions[sid]


def _refused(resp, db, username, before, message=None, status=409):
    """Refused, and nothing came of it: no row written, no session, no cookie."""
    assert resp.status_code == status, resp.data
    if status == 409:
        assert resp.get_json() == {'code': 'HA_STANDBY', 'error': message}
        # where a standby follows is for signed-in users
        assert ACTIVE_URL not in resp.get_data(as_text=True)
    elif message is not None:
        assert resp.get_json() == {'error': message}
    assert _stored(db, username) == before
    assert _sessions_of(username) == [] and _cookies(resp) == []


# --- a first sign-in --------------------------------------------------------------------

def test_a_first_sign_in_on_a_standby_creates_no_account(ha_env, db, monkeypatch, caplog):
    """The next sync would delete it again and keep a copy of it, at every sign-in."""
    _standby_of_active(ha_env)
    _idp(monkeypatch, erin=_claims('erin'))
    with caplog.at_level(logging.INFO):
        r = _sign_in(ha_env.api, 'erin')
    _refused(r, db, 'erin', None, NOT_HERE)
    assert "[OIDC] 'erin' signs in on a standby that does not hold the account yet - refused" in caplog.messages
    assert _audit('auth.oidc.login') == []

    # counterproof: where the row is ours to write, the account is provisioned as always
    for role, peer in (('standalone', None), ('active', _peer_record())):
        _be(ha_env, role, peer=peer)
        db.conn.execute("DELETE FROM users WHERE username = 'erin'")
        db.conn.commit()
        r = _sign_in(ha_env.api, 'erin')
        assert r.status_code == 200, (role, r.data)
        row = db.get_user('erin')
        assert (row['auth_source'], row['role'], row['tenant_id']) == ('oidc', 'admin', 'acme'), role


# --- a settled account ------------------------------------------------------------------

@pytest.mark.parametrize('provider,label', [('keycloak', 'oidc'), ('entra', 'entra'), ('entra', 'oidc')])
def test_a_settled_account_signs_in_without_writing(ha_env, db, monkeypatch, caplog, provider, label):
    """Both labels an OIDC account can carry. The third: the provider was switched to
    Entra since the row was written, which the active would note on the row and which
    changes nothing a check reads."""
    import pegaprox.api.auth as auth_api
    before = _oidc_row(db, 'olga', auth_source=label)
    _standby_of_active(ha_env)
    # so did the name and the mail at the provider
    _idp(monkeypatch, {'provider': provider},
         olga=_claims('olga', name='Olga Married', email='olga@new.example'))

    def no_write(*a, **kw):
        raise AssertionError('a standby must not write a users row')
    monkeypatch.setattr(auth_api, 'oidc_provision_user', no_write)
    monkeypatch.setattr(auth_api, 'save_single_user', no_write)
    monkeypatch.setattr(auth_api, 'save_users', no_write)

    with caplog.at_level(logging.INFO):
        r = _sign_in(ha_env.api, 'olga')
    assert r.status_code == 200, r.data
    body = r.get_json()
    sid = body.pop('session_id')
    # the session is made from the synced row
    assert body == {'success': True, 'user': 'olga', 'role': 'admin', 'portal_only': False,
                    'display_name': 'As The Active Stored It',
                    'auth_source': 'entra' if provider == 'entra' else 'oidc'}
    assert _stored(db, 'olga') == before          # last_login and last_oidc_sync as well
    assert sorted(_cookies(r)) == ['oidc_state', 'session_id']
    assert [s['role'] for s in _sessions_of('olga')] == ['admin']
    check = ha_env.api.anon().get('/api/auth/check', headers={'X-Session-ID': sid})
    assert check.status_code == 200 and check.get_json()['user']['username'] == 'olga'
    assert check.get_json()['ha']['role'] == 'standby'
    assert any('(standby, synced row)' in m and "'olga'" in m for m in caplog.messages)
    assert len(_audit('auth.oidc.login')) == 1


@pytest.mark.parametrize('role', ['standalone', 'active'])
def test_where_the_row_is_ours_a_sign_in_provisions_and_stamps_as_before(ha_env, db, monkeypatch, role):
    """Counterproof, and the pin of what an instance that acts does: the row is updated
    from the provider, a demotion sticks, and last_login is stamped."""
    _be(ha_env, role, peer=_peer_record() if role == 'active' else None)
    before = _oidc_row(db, 'olga')
    _idp(monkeypatch, olga=_claims('olga', groups=('g-users', 'g-acme'), name='Olga Married'),
         nora=_claims('nora', groups=()))

    r = _sign_in(ha_env.api, 'olga')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert (body['role'], body['display_name'], body['auth_source']) == ('user', 'Olga Married', 'oidc')
    assert [s['role'] for s in _sessions_of('olga')] == ['user']
    after = db.get_user('olga')
    assert (after['role'], after['tenant_id'], after['permissions'], after['tenant_permissions']) == \
        ('user', 'acme', [], ACME_ADMIN)
    assert (after['display_name'], after['email'], after['oidc_sub']) == \
        ('Olga Married', 'olga@corp.example', 'idp-subject-olga')
    for stamp in ('last_login', 'last_oidc_sync'):
        assert after[stamp] != before[stamp] and datetime.fromisoformat(after[stamp]), stamp

    # and a first sign-in makes the account, with the role of no group
    r = _sign_in(ha_env.api, 'nora')
    assert r.status_code == 200 and r.get_json()['role'] == 'viewer', r.data
    made = db.get_user('nora')
    assert (made['auth_source'], made['role'], made['tenant_id'], made['enabled']) == \
        ('oidc', 'viewer', 'default', True)
    assert datetime.fromisoformat(made['last_login']) and made['oidc_sub'] == 'idp-subject-nora'
    assert [a['user'] for a in _audit('auth.oidc.login')] == ['olga', 'nora']


# --- access that changed at the provider -------------------------------------------------

CHANGES = {
    'role': ('g-users', 'g-acme', 'g-ops'),                     # demoted
    'tenant': SETTLED + ('g-globex',),                           # moved to another tenant
    'permissions': ('g-admins', 'g-acme'),                      # taken out of g-ops
    'tenant_permissions': ('g-admins', 'g-ops'),                # taken out of g-acme
    'more_permissions': SETTLED + ('g-delete',),                 # a grant is a change too
}


@pytest.mark.parametrize('change', sorted(CHANGES))
def test_any_change_to_what_decides_access_is_refused(ha_env, db, monkeypatch, caplog, change):
    before = _oidc_row(db, 'olga')
    _standby_of_active(ha_env)
    _idp(monkeypatch, olga=_claims('olga', groups=CHANGES[change]))
    with caplog.at_level(logging.INFO):
        r = _sign_in(ha_env.api, 'olga')
    _refused(r, db, 'olga', before, CHANGED)
    assert ("[OIDC] 'olga' signs in on a standby with access at the identity provider that "
            "differs from the synced account - refused") in caplog.messages

    # counterproof: the groups the account was settled with, in
    _idp(monkeypatch, olga=_claims('olga', groups=SETTLED[::-1]))
    assert _sign_in(ha_env.api, 'olga').status_code == 200
    assert _stored(db, 'olga') == before


def test_a_group_set_that_is_not_the_whole_keeps_what_is_stored(ha_env, db, monkeypatch):
    """A provider that sends no groups claim, or a claim it cut short: provisioning
    keeps the stored access then and only adds what did match, and so does the row the
    standby compares with."""
    before = _oidc_row(db, 'olga')
    _standby_of_active(ha_env)
    overage = {'_claim_names': {'groups': 'src1'}}
    _idp(monkeypatch,
         olga=_claims('olga', groups=None),                              # nothing known
         part=_claims('olga', groups=('g-ops',), **overage),             # part of what is stored
         more=_claims('olga', groups=('g-delete',), **overage))          # part, and a new grant
    for code in ('olga', 'part'):
        r = _sign_in(ha_env.api, code)
        assert r.status_code == 200 and r.get_json()['role'] == 'admin', (code, r.data)
        assert _stored(db, 'olga') == before
    _sign_out('olga')
    _refused(_sign_in(ha_env.api, 'more'), db, 'olga', before, CHANGED)

    # counterproof: with the whole group set the same groups are a demotion
    _idp(monkeypatch, olga=_claims('olga', groups=('g-ops',)))
    _refused(_sign_in(ha_env.api, 'olga'), db, 'olga', before, CHANGED)


def test_what_agrees_with_a_synced_row():
    """The helper on its own: a missing row or one another identity source owns is
    never a match, whatever the sign-in would store."""
    import functools
    from pegaprox.api.auth import _idp_agrees_with_synced_row
    agrees = functools.partial(_idp_agrees_with_synced_row, username='olga')
    row = {'auth_source': 'oidc', 'role': 'admin', 'tenant_id': 'acme', 'permissions': ['a', 'b'],
           'tenant_permissions': copy.deepcopy(ACME_ADMIN)}
    assert agrees(copy.deepcopy(row), row)
    assert agrees(dict(row, permissions=['b', 'a', 'a'], auth_source='entra', display_name='x'), row)
    assert agrees(dict(row, permissions=None, tenant_permissions=None),
                  dict(row, permissions=[], tenant_permissions={}))
    for key, other in (('role', 'user'), ('tenant_id', 'globex'), ('permissions', ['a']),
                       ('tenant_permissions', {'acme': {'role': 'user', 'extra': []}})):
        assert not agrees(dict(row, **{key: other}), row), key
    for source in ('local', 'ldap', 'saml', None):
        assert not agrees(copy.deepcopy(row), dict(row, auth_source=source)), source
    no_source = {k: v for k, v in row.items() if k != 'auth_source'}
    assert not agrees(copy.deepcopy(row), no_source)
    assert not agrees(copy.deepcopy(row), None) and not agrees(None, row)


# --- the answers that stay as they are on the active -------------------------------------

@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_a_name_another_identity_source_owns_is_refused_as_on_the_active(ha_env, db, monkeypatch, source):
    before = _oidc_row(db, 'frank', auth_source=source, oidc_sub='')
    _idp(monkeypatch, frank=_claims('frank'))
    for role, peer in (('standby', None), ('active', _peer_record()), ('standalone', None)):
        if role == 'standby':
            _standby_of_active(ha_env)
        else:
            _be(ha_env, role, peer=peer)
        _refused(_sign_in(ha_env.api, 'frank'), db, 'frank', before, OTHER_OWNER, status=403)


def test_a_disabled_account_is_refused_as_on_the_active(ha_env, db, monkeypatch):
    before = _oidc_row(db, 'olga', enabled=False)
    _standby_of_active(ha_env)
    # whatever the provider says about its access: disabled is the answer
    _idp(monkeypatch, olga=_claims('olga'), demoted=_claims('olga', groups=('g-users',)))
    for code in ('olga', 'demoted'):
        _refused(_sign_in(ha_env.api, code), db, 'olga', before, 'Account is disabled', status=403)

    # the active answers the same
    _be(ha_env, 'active', peer=_peer_record())
    r = _sign_in(ha_env.api, 'olga')
    assert r.status_code == 403 and r.get_json() == {'error': 'Account is disabled'}
    assert _sessions_of('olga') == [] and db.get_user('olga')['last_login'] == '2026-09-01T08:00:00'
    # counterproof: enabled, the standby lets the same sign-in in
    _oidc_row(db, 'olga')
    _standby_of_active(ha_env)
    assert _sign_in(ha_env.api, 'olga').status_code == 200


def test_without_auto_create_a_missing_account_is_refused_as_on_the_active(ha_env, db, monkeypatch):
    before = _oidc_row(db, 'olga')
    _idp(monkeypatch, {'auto_create_users': False}, erin=_claims('erin'), olga=_claims('olga'))
    missing = 'User account does not exist. Contact an administrator.'
    for role, peer in (('standby', None), ('active', _peer_record())):
        if role == 'standby':
            _standby_of_active(ha_env)
        else:
            _be(ha_env, role, peer=peer)
        _refused(_sign_in(ha_env.api, 'erin'), db, 'erin', None, missing, status=403)
    # an account that is there needs no auto-create, on a standby either
    _standby_of_active(ha_env)
    assert _sign_in(ha_env.api, 'olga').status_code == 200
    assert _stored(db, 'olga') == before


def test_an_account_stored_under_the_key_of_an_earlier_release_is_found(ha_env, db, monkeypatch):
    """The name is derived as on the active: bob@corp.example lands on the row 'bob' an
    earlier release made for this subject, and on no row of another subject."""
    before = _oidc_row(db, 'bob')
    _standby_of_active(ha_env)
    _idp(monkeypatch, bob=_claims('bob', preferred_username='bob@corp.example'),
         other=_claims('bob', preferred_username='bob@partner.example', sub='another-subject'))
    r = _sign_in(ha_env.api, 'bob')
    assert r.status_code == 200 and r.get_json()['user'] == 'bob', r.data
    assert _stored(db, 'bob') == before
    r = _sign_in(ha_env.api, 'other')
    _refused(r, db, 'bob@partner.example', None, NOT_HERE)
    assert _stored(db, 'bob') == before and len(_sessions_of('bob')) == 1


# --- a member that serves users -----------------------------------------------------------

def test_a_serving_member_is_a_standby_for_a_sign_in(fwd, seed, db, monkeypatch):
    """It serves users the way the leader does, and its users table is still the
    leader's copy. The callback is answered here and never forwarded."""
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('a') as on_a:
        on_a.set_member_serve(IDS['b'], True)
    with g.at('b') as on_b:
        assert on_b.pull_once() in ('applied', 'unchanged')
        assert (on_b.serving(), on_b.is_standby()) == (True, True)
    _idp(monkeypatch, erin=_claims('erin'), demoted=_claims('erin', groups=('g-users',)))

    with g.at('b'):
        _refused(_sign_in(g.api, 'erin'), db, 'erin', None, NOT_HERE)
    # once on the leader, as the answer says ...
    with g.at('a'):
        assert _sign_in(g.api, 'erin').status_code == 200
    _sign_out('erin')
    _sync(g, admin, 'b')
    before = _stored(db, 'erin')
    assert before['auth_source'] == 'oidc' and before['last_login']
    # ... and the member lets the account in, on the row as the leader wrote it
    with g.at('b'):
        r = _sign_in(g.api, 'erin')
        assert r.status_code == 200 and r.get_json()['role'] == 'admin', r.data
        assert _stored(db, 'erin') == before and len(_sessions_of('erin')) == 1
        _sign_out('erin')
        _refused(_sign_in(g.api, 'demoted'), db, 'erin', before, CHANGED)
    assert _forward_calls(g) == []


# --- nothing is left for a sync to take away ---------------------------------------------

def test_sign_ins_on_a_member_leave_no_copy_of_changes_not_carried_over(ha_env, db, seed, monkeypatch):
    """Before, every sign-in of a new account made a row the next sync replaced: a copy
    in ha_orphans, an ERROR and an audit row, and only an admin removes a copy."""
    seed.user('alice')
    settled = _oidc_row(db, 'olga')
    _be(ha_env, 'active', instance_id=A_ID, epoch=1, peer=_peer_record())
    snap = _wire(ha.build_snapshot())
    _be(ha_env, 'standby', instance_id=B_ID, epoch=1, forward_writes=False,
        peer=_peer_record(A_ID, ACTIVE_URL, 'active'), cv={'joined': True})
    ha.apply_snapshot(snap)
    _idp(monkeypatch, olga=_claims('olga'), jane=_claims('jane'))

    for round_no in range(20):
        assert _sign_in(ha_env.api, 'jane').status_code == 409
        assert _sign_in(ha_env.api, 'olga').status_code == 200
        snap = _next_from_leader(snap, _one_tag_more(f'tag-{round_no}'))
        assert ha.apply_snapshot(snap)['captured'] is None, round_no
    assert _copies() == [] and _audit('ha.changes_not_carried_over') == []
    assert not ha.banner().get('orphans')
    assert _stored(db, 'olga') == settled and _stored(db, 'jane') is None
    assert len(_audit('auth.oidc.login')) == 20

    # counterproof: the row a sign-in used to make here is taken away and kept
    assert O.oidc_provision_user(_claims('jane'), {'role': 'viewer', '_authoritative': True})
    name = ha.apply_snapshot(_next_from_leader(snap, _one_tag_more('after')))['captured']
    assert name and _copies() == [name] and len(_audit('ha.changes_not_carried_over')) == 1
    assert _stored(db, 'jane') is None


# --- the split of oidc_provision_user ----------------------------------------------------

NOW = '2026-10-02T09:30:00'
FULL = {'role': 'viewer', 'tenant': '', 'permissions': ['vm.view'], 'tenant_permissions': {},
        '_authoritative': True}
PARTIAL = {'role': 'viewer', 'tenant': 'globex', 'permissions': ['vm.view'],
           'tenant_permissions': {'globex': {'role': 'user', 'extra': ['vm.view']}},
           '_authoritative': False}
NOTHING_KNOWN = {'role': 'viewer', 'tenant': '', 'permissions': [], 'tenant_permissions': {},
                 '_authoritative': False}
HELD = {'auth_source': 'oidc', 'oidc_sub': 's-olga', 'role': 'admin', 'tenant_id': 'acme',
        'permissions': ['vm.delete', 'node.maintenance'], 'tenant_permissions': ACME_ADMIN,
        'display_name': 'Old Name', 'email': 'old@corp.example', 'last_oidc_sync': '2026-09-01T08:00:00'}
OLGA = {'sub': 's-olga-2', 'preferred_username': 'olga', 'email': 'olga@corp.example',
        'given_name': 'Olga'}
UNTOUCHED = "a {} account of that name exists and cannot be taken over by OIDC"

# (rows held, claims, mapping, label) -> (stored under, what the row says then, last log line).
# A sign-in that is refused stores under None and the row stays what was held.
PROVISIONING = {
    'a-new-account': (
        {}, {'sub': 's-nora', 'preferred_username': 'Nora@Corp.Example', 'email': 'nora@corp.example',
             'name': 'Nora N'},
        {'role': 'user', 'tenant': 'acme', 'permissions': ['vm.view'],
         'tenant_permissions': {'acme': {'role': 'admin', 'extra': ['vm.view']}}, '_authoritative': True},
        'oidc',
        'nora@corp.example',
        {'role': 'user', 'tenant_id': 'acme', 'permissions': ['vm.view'],
         'tenant_permissions': {'acme': {'role': 'admin', 'extra': ['vm.view']}}, 'auth_source': 'oidc',
         'oidc_sub': 's-nora', 'display_name': 'Nora N', 'email': 'nora@corp.example', 'enabled': True,
         'last_oidc_sync': NOW},
        "[OIDC] Provisioned new user 'nora@corp.example' (role=user, source=oidc)"),
    'a-new-account-with-nothing-but-a-subject': (
        {}, {'sub': 'abcdef0123456789'}, {}, 'entra',
        'oidc_f445801e0cb89926',  # sha256 of the sub, lower case (#1141)
        {'role': 'viewer', 'tenant_id': 'default', 'permissions': [], 'tenant_permissions': {},
         'auth_source': 'entra', 'oidc_sub': 'abcdef0123456789', 'display_name': 'oidc_f445801e0cb89926',
         'email': '', 'enabled': True, 'last_oidc_sync': NOW},
        "[OIDC] Provisioned new user 'oidc_f445801e0cb89926' (role=viewer, source=entra)"),
    'a-settled-account-the-whole-group-set': (
        {'olga': HELD}, OLGA, FULL, 'entra',
        'olga',
        {'role': 'viewer', 'tenant_id': 'acme', 'permissions': ['vm.view'], 'tenant_permissions': {},
         'auth_source': 'entra', 'oidc_sub': 's-olga-2', 'display_name': 'Olga',
         'email': 'olga@corp.example', 'enabled': True, 'last_oidc_sync': NOW},
        "[OIDC] Updated user 'olga' (role=viewer, source=entra)"),
    'a-settled-account-part-of-the-group-set': (
        {'olga': HELD}, OLGA, PARTIAL, 'oidc',
        'olga',
        {'role': 'admin', 'tenant_id': 'globex',
         'permissions': ['node.maintenance', 'vm.delete', 'vm.view'],
         'tenant_permissions': dict(ACME_ADMIN, globex={'role': 'user', 'extra': ['vm.view']}),
         'auth_source': 'oidc', 'oidc_sub': 's-olga-2', 'display_name': 'Olga',
         'email': 'olga@corp.example', 'enabled': True, 'last_oidc_sync': NOW},
        "[OIDC] Updated user 'olga' (role=admin, source=oidc)"),
    'a-settled-account-no-group-set-at-all': (
        {'olga': HELD}, OLGA, NOTHING_KNOWN, 'oidc',
        'olga',
        {'role': 'admin', 'tenant_id': 'acme', 'permissions': ['node.maintenance', 'vm.delete'],
         'tenant_permissions': ACME_ADMIN, 'auth_source': 'oidc', 'oidc_sub': 's-olga-2',
         'display_name': 'Olga', 'email': 'olga@corp.example', 'enabled': True, 'last_oidc_sync': NOW},
        "[OIDC] Updated user 'olga' (role=admin, source=oidc)"),
    'a-local-account-of-that-name': (
        {'olga': dict(HELD, auth_source='local', oidc_sub='')}, OLGA, FULL, 'oidc',
        None, None, "[OIDC] Rejected login for 'olga' - " + UNTOUCHED.format('local')),
    'a-directory-account-of-that-name': (
        {'olga': dict(HELD, auth_source='ldap', oidc_sub='')}, OLGA, FULL, 'oidc',
        None, None, "[OIDC] Rejected login for 'olga' - " + UNTOUCHED.format('ldap')),
    'the-key-of-an-earlier-release': (
        {'olga': HELD}, dict(OLGA, sub='s-olga', preferred_username='olga@corp.example'), FULL, 'oidc',
        'olga',
        {'role': 'viewer', 'tenant_id': 'acme', 'permissions': ['vm.view'], 'tenant_permissions': {},
         'auth_source': 'oidc', 'oidc_sub': 's-olga', 'display_name': 'Olga',
         'email': 'olga@corp.example', 'enabled': True, 'last_oidc_sync': NOW},
        "[OIDC] Updated user 'olga' (role=viewer, source=oidc)"),
    'another-subject-with-that-local-part': (
        {'olga': HELD}, dict(OLGA, preferred_username='olga@partner.example'), FULL, 'oidc',
        'olga@partner.example',
        {'role': 'viewer', 'tenant_id': 'default', 'permissions': ['vm.view'], 'tenant_permissions': {},
         'auth_source': 'oidc', 'oidc_sub': 's-olga-2', 'display_name': 'Olga',
         'email': 'olga@corp.example', 'enabled': True, 'last_oidc_sync': NOW},
        "[OIDC] Provisioned new user 'olga@partner.example' (role=viewer, source=oidc)"),
}


class _Clock:
    @staticmethod
    def now():
        return datetime.fromisoformat(NOW)


def _says(row):
    """What a row says about the account, the permissions in one order."""
    if row is None:
        return None
    out = {k: row[k] for k in ('role', 'tenant_id', 'tenant_permissions', 'auth_source', 'oidc_sub',
                               'display_name', 'email', 'enabled', 'last_oidc_sync')}
    out['permissions'] = sorted(row['permissions'])
    return out


@pytest.mark.parametrize('case', sorted(PROVISIONING))
def test_provisioning_stores_what_it_stored_before_the_split(db, seed, monkeypatch, caplog, case):
    held, claims, mapping, label, stored_under, says, log_line = copy.deepcopy(PROVISIONING[case])
    monkeypatch.setattr(O, 'datetime', _Clock)
    seed.user('root', role='admin')
    for name, row in held.items():
        db.save_user(name, row)
    before = {name: db.get_user(name) for name in ['root'] + list(held)}

    with caplog.at_level(logging.INFO):
        user = O.oidc_provision_user(claims, mapping, auth_source=label)
    assert caplog.messages[-1] == log_line
    if stored_under is None:
        assert user is None
    else:
        assert user['username'] == stored_under
        # the table reads an empty tenant as the default one
        assert _says(dict(user, tenant_id=user['tenant_id'] or 'default')) == says
        assert _says(db.get_user(stored_under)) == says
        before.pop(stored_under, None)
    # every other row, and the one a refused sign-in met, is what it was
    assert {name: db.get_user(name) for name in before} == before
    assert set(r['username'] for r in db.conn.execute('SELECT username FROM users')) == \
        set(before) | ({stored_under} - {None})


@pytest.mark.parametrize('case', sorted(PROVISIONING))
def test_building_the_row_says_the_same_and_writes_nothing(db, monkeypatch, case):
    """What the standby compares with is the row the active would store."""
    held, claims, mapping, label, stored_under, says, _ = copy.deepcopy(PROVISIONING[case])
    monkeypatch.setattr(O, 'datetime', _Clock)
    for name, row in held.items():
        db.save_user(name, row)
    users = db.get_all_users()
    snapshot, asked = copy.deepcopy(users), copy.deepcopy((claims, mapping))

    built = O.oidc_build_user_row(claims, mapping, label, users)
    assert users == snapshot and (claims, mapping) == asked       # the table it was handed
    assert db.get_all_users() == snapshot                          # and nothing was saved
    if stored_under is None:
        assert built is None
        return
    username, row = built
    assert username == stored_under

    stored = O.oidc_provision_user(claims, mapping, auth_source=label)
    stored.pop('username')
    assert row == stored
