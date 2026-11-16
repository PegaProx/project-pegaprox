# -*- coding: utf-8 -*-
"""The auth guards of the federation routes and the switch, over the real Flask app.

The guards in api/federation.py and api/auth.py (refuse_foreign,
_refuse_own_mirror, _refuse_confined_admin, _refuse_without_reauth) each stand
between a caller and a federation-privileged change. None of the wire tests in
test_federation.py drives them - they build a bare federation blueprint with no
login stack - so each guard could be switched off without a test going red.
Every test here goes through create_app and the real session store, exactly as
test_ha_api.py drives the HA routes, and makes one guard refuse one caller:

  * a non-admin (or nobody at all) reaches no federation route;
  * an admin an LDAP tenant mapping has capped where they lives reaches none
    either - the registry of a federation is the whole deployment's, not a
    tenant's slice of it;
  * a pairing code needs the account password typed just now - a session
    without one, and an API token (which can never type one), get no code;
  * a user mirrored from another member is that member's to change: not this
    instance's users route, not its token revocation, not its password change;
  * a mirrored admin administers neither this instance's accounts, tenants and roles
    nor the role an LDAP or OIDC sign-in gets here, nor an OIDC binding;
  * the switch: any unconfined local admin flips it, no password; a forced switch
    cannot be flipped, switching off says what keeps it on, and the workers follow it;
  * a signed member call passes the real app: the CSRF gate, the rate limit and the
    standby forwarding stand aside for it, and its answer carries the signature.

MK Nov 2026
"""
import base64
import secrets
import time

import pytest

from pegaprox.api.settings import (EXTERNAL_ROLE_SETTINGS, EXTERNAL_SOURCE_SECRETS,
                                   EXTERNAL_SOURCE_SETTINGS)
from pegaprox.core import federation, ha_wire

# a member id this instance is not: what fed_home names on a mirrored row
FOREIGN = 'f' * 32


@pytest.fixture
def fed(api, monkeypatch):
    """The real app with the federation of a fresh instance (conftest gives every test
    its own lease file and forgets the caches), and the pairing/re-auth budgets of the
    routes reset, as the HA tests reset theirs. The federation is switched on, as
    PEGAPROX_FEDERATION=1 does it."""
    import pegaprox.api.federation as api_fed
    from pegaprox.globals import login_attempts_by_ip, login_attempts_by_user
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    for window in (api_fed._pair_attempts, api_fed._peer_failures,
                   api_fed._reauth_attempts, api_fed._lease_votes, api_fed._lease_ticks,
                   api_fed._lease_returns):
        window.reset()
    # the sign-ins below fail on purpose, all from the one address of the test client
    login_attempts_by_ip.clear()
    login_attempts_by_user.clear()
    yield api
    login_attempts_by_ip.clear()
    login_attempts_by_user.clear()


@pytest.fixture
def switchable(api, monkeypatch):
    """The real app with the switch left to the setting (no PEGAPROX_FEDERATION)."""
    monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    yield api
    federation.stop_workers()


def _mirror(seed, name, role='viewer'):
    """A user row another member of the federation homed: fed_home names it, so
    every guard below refuses a change to the row at this instance."""
    user = seed.user(name, role=role)
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = ?",
                         (FOREIGN, name))
    seed.db.conn.commit()
    return user


# --- who reaches the federation routes at all --------------------------------------------

def test_nobody_without_a_login_reads_the_federation_status(fed):
    assert fed.anon().get('/api/federation/status').status_code == 401


def test_a_non_admin_cannot_read_the_federation_status(fed, seed):
    # every permission a settings page could ask for, still not an admin
    c = fed.as_user(seed.user('ops', role='user', permissions=[
        'admin.users', 'admin.settings', 'security.settings.manage']))
    r = c.get('/api/federation/status')
    assert r.status_code == 403


def test_a_tenant_capped_admin_cannot_read_the_federation_status(fed, seed):
    """An admin that an LDAP tenant mapping has lowered where they live is no admin to
    the status route at all."""
    seed.tenant('globex', ['cluster_globex'])
    c = fed.as_user(seed.user('gx', role='admin', tenant_id='globex',
                              tenant_permissions={'globex': {'role': 'user'}}))
    r = c.get('/api/federation/status')
    assert r.status_code == 403


def test_a_confined_admin_reads_the_switch_and_nothing_else(fed, seed, monkeypatch):
    """An admin the cluster-scope rule confines (_refuse_confined_admin's question) hears
    the switch - the status answers every admin - and nothing of the registry: manage
    false, no instance id, no members, no key."""
    import pegaprox.api.federation as api_fed
    real = api_fed._confined
    monkeypatch.setattr(api_fed, '_confined', lambda: True)
    c = fed.as_user(seed.user('gx', role='admin'))
    r = c.get('/api/federation/status')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['manage'] is False and body['enabled'] is True
    for key in ('instance_id', 'members', 'public_key'):
        assert key not in body, key
    # counterproof: an unconfined admin reads them
    monkeypatch.setattr(api_fed, '_confined', real)
    root = fed.as_user(seed.user('root', role='admin'))
    body = root.get('/api/federation/status').get_json()
    assert body['manage'] is True and body['instance_id'] and body['members'] == []


def test_a_tenant_capped_admin_reaches_no_federation_admin_route(fed, seed):
    """The same capped admin against every admin route of the blueprint: the
    guard runs in each of them, not only in the status read."""
    seed.tenant('globex', ['cluster_globex'])
    c = fed.as_user(seed.user('gx2', role='admin', tenant_id='globex',
                              tenant_permissions={'globex': {'role': 'user'}}))
    for method, path in (('post', '/api/federation/switch'),
                         ('get', '/api/federation/members'),
                         ('get', '/api/federation/clusters'),
                         ('get', '/api/federation/leases'),
                         ('post', '/api/federation/pairing-code'),
                         ('post', '/api/federation/join'),
                         ('post', '/api/federation/reconcile'),
                         ('post', '/api/federation/sync'),
                         ('post', f'/api/federation/members/{"0" * 32}/remove'),
                         ('post', '/api/federation/leave'),
                         ('post', '/api/federation/clusters/c1/enroll'),
                         ('post', '/api/federation/clusters/c1/release'),
                         ('post', '/api/federation/clusters/c1/unenroll'),
                         ('post', '/api/federation/clusters/c1/adopt'),
                         ('post', '/api/federation/clusters/c1/renew'),
                         ('get', '/api/federation/identity-map'),
                         ('post', '/api/federation/identity-map')):
        r = getattr(c, method)(path, json={})
        assert r.status_code == 403, (method, path, r.status_code, r.data)
        assert b'tenant' in r.data or b'administrators' in r.data, (path, r.data)


# --- the pairing code needs proof the caller is at the keyboard --------------------------

def test_an_admin_session_without_the_password_gets_no_pairing_code(fed, seed):
    """The re-auth guard: a pairing code builds the registry of the federation,
    so the account password has to be typed just now. A session that sends
    none hears FED_REAUTH, not a code."""
    c = fed.as_user(seed.user('root', role='admin'))
    r = c.post('/api/federation/pairing-code',
               json={'url': 'https://a.example:5000'})
    assert r.status_code == 403
    assert r.get_json().get('code') == 'FED_REAUTH'


def test_an_api_token_cannot_confirm_a_pairing_code(fed, seed):
    """An API token can hold the admin role, but it cannot type a password -
    the re-auth guard refuses it by name, before anything else is asked."""
    from pegaprox.utils.auth import create_api_token
    seed.user('root', role='admin')
    res = create_api_token('root', 'ci', role='admin')
    assert res.get('success'), res
    r = fed.anon().post('/api/federation/pairing-code',
                        json={'url': 'https://a.example:5000'},
                        headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 403
    body = r.get_json()
    assert body.get('code') == 'FED_REAUTH'
    assert 'API token' in body.get('error', ''), body


def test_the_peer_word_passes_the_real_csrf_gate(fed):
    """The CSRF gate of the real app takes a state-changing /api call that
    carries no Origin only when X-Requested-With says exactly the word the
    federation peer calls send (federation.PEER_XHR). A call with exactly the
    peer headers reaches the pairing route - it is refused for its junk code,
    not by the CSRF gate. This is what every signed peer call of the wire
    tests depends on, held in place over the real app."""
    from pegaprox.core import federation
    client = fed.app.test_client()
    r = client.post('/api/federation/peer/join',
                    json={'code': 'pgxfd1_not-a-code', 'url': 'https://b.example:5000',
                          'instance_id': '0' * 32, 'public_key': 'x', 'site': ''},
                    headers={'X-Requested-With': federation.PEER_XHR,
                             'Content-Type': 'application/json'},
                    base_url='http://localhost')
    assert r.status_code == 403, (r.status_code, r.data)
    assert 'CSRF' not in (r.get_json().get('error') or ''), r.data


# --- a mirrored user is the home's to change ----------------------------------------------

def test_a_mirrored_user_is_not_changed_by_this_instances_users_route(fed, seed):
    """PUT /api/users/<name> on a row another member homed: refuse_foreign
    answers 409 FED_FOREIGN - the home decides, this instance only mirrors."""
    admin = fed.as_user(seed.user('root', role='admin'))
    _mirror(seed, 'miriam')
    r = admin.put('/api/users/miriam', json={'display_name': 'M.'})
    assert r.status_code == 409
    body = r.get_json()
    assert body.get('code') == 'FED_FOREIGN'
    assert body.get('home') == FOREIGN


def test_a_mirrored_token_is_not_revoked_by_this_instance(fed, seed):
    """The mirrored user's own API token, mirrored with it: revoking it here
    would diverge from the home, so the token route refuses the DELETE."""
    miriam = _mirror(seed, 'miriam')
    seed.db.conn.execute(
        "INSERT INTO api_tokens (token_hash, token_prefix, username, name, role, "
        "created_at, fed_home) VALUES ('th-mirror', 'pgx_m', 'miriam', 'ci', "
        "'viewer', '2026', ?)", (FOREIGN,))
    seed.db.conn.commit()
    row = seed.db.conn.execute(
        "SELECT id FROM api_tokens WHERE token_hash = 'th-mirror'").fetchone()
    c = fed.as_user(miriam)
    r = c.delete(f"/api/auth/tokens/{row['id']}")
    assert r.status_code == 409
    body = r.get_json()
    assert body.get('code') == 'FED_FOREIGN'
    assert body.get('home') == FOREIGN


def test_a_mirrored_user_cannot_change_the_password_here(fed, seed):
    """POST /api/auth/change-password as the mirrored user: the mirror guard
    refuses before the current password is even checked - the account's
    password is the home's to change."""
    miriam = _mirror(seed, 'miriam')
    c = fed.as_user(miriam)
    r = c.post('/api/auth/change-password',
               json={'current_password': 'Whatever1x',
                     'new_password': 'NewPassword1x'})
    assert r.status_code == 409
    body = r.get_json()
    assert body.get('code') == 'FED_FOREIGN'
    assert body.get('home') == FOREIGN


def test_a_local_user_is_still_ours_to_change(fed, seed):
    """Counterproof for the mirror guards: the same routes, on a row homed
    here (fed_home empty), refuse nothing - the PUT lands, the guard is what
    answered 409 above and not the route's own validation."""
    admin = fed.as_user(seed.user('root', role='admin'))
    seed.user('localperson', role='viewer')
    r = admin.put('/api/users/localperson', json={'display_name': 'L.'})
    assert r.status_code == 200, (r.status_code, r.data)
    assert r.get_json().get('success') is not False, r.data


# --- the re-auth on the cluster routes ------------------------------------------------------

@pytest.mark.parametrize('path', ('/api/federation/clusters/c1/enroll',
                                  '/api/federation/clusters/c1/adopt',
                                  '/api/federation/clusters/c1/release',
                                  '/api/federation/clusters/c1/unenroll'))
def test_enroll_and_adopt_want_the_password(fed, seed, path):
    c = fed.as_user(seed.user('root', role='admin'))
    r = c.post(path, json={'confirm': 'ADOPT'})
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_REAUTH', r.data
    # counterproof: with the password the guard lets it through to the route's own answer
    from pegaprox.utils.auth import hash_password
    c2 = fed.as_user(seed.user('root2', role='admin'))
    salt, pw_hash = hash_password('C0rrect!horse9')
    seed.db.conn.execute("UPDATE users SET password_salt = ?, password_hash = ? "
                         "WHERE username = 'root2'", (salt, pw_hash))
    seed.db.conn.commit()
    r = c2.post(path, json={'confirm': 'ADOPT', 'user_password': 'C0rrect!horse9'})
    assert (r.get_json() or {}).get('code') not in ('FED_REAUTH', 'FED_REAUTH_RECENT'), r.data


@pytest.mark.parametrize('path', ('/api/federation/clusters/c1/enroll',
                                  '/api/federation/clusters/c1/adopt'))
def test_an_api_token_cannot_enroll_or_adopt(fed, seed, path):
    from pegaprox.utils.auth import create_api_token
    seed.user('root', role='admin')
    res = create_api_token('root', 'ci', role='admin')
    r = fed.anon().post(path, json={'confirm': 'ADOPT', 'user_password': 'x'},
                        headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_REAUTH', r.data


# --- the switch -------------------------------------------------------------------------------

def test_the_switch_wants_an_unconfined_admin(switchable, seed):
    seed.tenant('globex', ['cluster_globex'])
    capped = switchable.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                          tenant_permissions={'globex': {'role': 'user'}}))
    assert capped.post('/api/federation/switch', json={'enabled': True}).status_code == 403
    user = switchable.as_user(seed.user('ops', role='user', permissions=['admin.settings']))
    assert user.post('/api/federation/switch', json={'enabled': True}).status_code == 403
    assert switchable.anon().post('/api/federation/switch', json={'enabled': True}).status_code == 401
    assert federation.enabled() is False


def test_a_mirrored_admin_cannot_flip_the_switch(switchable, seed):
    _mirror(seed, 'miriam', role='admin')
    c = switchable.as_user({'username': 'miriam', 'role': 'admin'})
    # switched off, a leftover mirror is a disabled account: it does not get that far
    r = c.post('/api/federation/switch', json={'enabled': True})
    assert r.status_code == 401 and r.get_json()['code'] == 'ACCOUNT_DISABLED', r.data
    assert federation.enabled() is False
    # a local admin flips it, no password asked
    root = switchable.as_user(seed.user('root', role='admin'))
    r = root.post('/api/federation/switch', json={'enabled': True})
    assert r.status_code == 200 and r.get_json()['enabled'] is True, r.data
    # switched on, the mirror signs in and is still refused the switch
    r = c.post('/api/federation/switch', json={'enabled': False})
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_MIRROR_ADMIN', r.data
    assert r.get_json()['home'] == FOREIGN and federation.enabled() is True
    # counterproof: the local admin gets past the guard, to what keeps it on (the mirror)
    r = root.post('/api/federation/switch', json={'enabled': False})
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_IN_USE', r.data


def test_the_switch_starts_and_stops_the_workers(switchable, seed):
    """On starts both loops without a restart and makes this instance's identity; off
    stops them. Off is refused while this instance is a member of a federation."""
    import threading
    import gevent
    root = switchable.as_user(seed.user('root', role='admin'))
    assert federation.workers_running() is False
    r = root.post('/api/federation/switch', json={'enabled': True})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'enabled': True, 'forced': False, 'can_disable': True,
                            'disable_blockers': []}
    assert federation.workers_running() is True
    names = sorted(t.name for t in threading.enumerate() if t.name.startswith('federation-'))
    assert names == ['federation-lease', 'federation-sync']
    assert federation.instance_id()
    assert seed.db.get_server_setting(federation.SETTING_KEY) is True

    # a member in the view: off is refused, the workers keep running
    _add_member(federation)
    r = root.post('/api/federation/switch', json={'enabled': False})
    assert r.status_code == 409, r.data
    assert r.get_json()['code'] == 'FED_IN_USE' and r.get_json()['blockers'] == ['member']
    assert 'Leave the federation first' in r.get_json()['error']
    assert federation.workers_running() is True and federation.enabled() is True

    # without it, off stops both loops
    federation._mutate_identity(lambda ident: ident['view']['members'].clear() or True)
    r = root.post('/api/federation/switch', json={'enabled': False})
    assert r.status_code == 200 and r.get_json()['enabled'] is False, r.data
    assert federation.workers_running() is False
    for _ in range(50):
        if not [t for t in threading.enumerate() if t.name.startswith('federation-')]:
            break
        gevent.sleep(0.02)
    assert not [t.name for t in threading.enumerate() if t.name.startswith('federation-')]
    assert seed.db.get_server_setting(federation.SETTING_KEY) is False


def test_the_switch_is_refused_while_forced(switchable, seed, monkeypatch):
    root = switchable.as_user(seed.user('root', role='admin'))
    for word, state in (('1', True), ('0', False)):
        monkeypatch.setenv(federation.ENV_SWITCH, word)
        r = root.post('/api/federation/switch', json={'enabled': not state})
        assert r.status_code == 409 and r.get_json()['code'] == 'FED_FORCED', r.data
        assert f'PEGAPROX_FEDERATION={word}' in r.get_json()['error']
        status = root.get('/api/federation/status').get_json()
        assert status['forced'] is True and status['enabled'] is state
        assert status['can_disable'] is False
        assert seed.db.get_server_setting(federation.SETTING_KEY) is None


@pytest.mark.parametrize('blocker', ('member', 'lease', 'mirrors'))
def test_switching_off_says_what_blocks_it(switchable, seed, blocker):
    root = switchable.as_user(seed.user('root', role='admin'))
    assert root.post('/api/federation/switch', json={'enabled': True}).status_code == 200
    me = federation.instance_id()
    if blocker == 'member':
        _add_member(federation)
    elif blocker == 'lease':
        seed.db.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, fed_owner) "
                        "VALUES ('c-led', 'c', 'h', 'u', 'x', ?)", (me,))
    else:
        _mirror(seed, 'miriam')
    status = root.get('/api/federation/status').get_json()
    assert status['disable_blockers'] == [blocker] and status['can_disable'] is False
    r = root.post('/api/federation/switch', json={'enabled': False})
    assert r.status_code == 409 and r.get_json()['blockers'] == [blocker], r.data
    assert federation.enabled() is True


def test_the_settings_form_cannot_flip_the_federation_switch(switchable, seed):
    """The generic settings save never writes the switch: a form that saves back what it
    read a while ago would undo a toggle."""
    from pegaprox.api.helpers import save_server_settings
    root = switchable.as_user(seed.user('root', role='admin'))
    assert root.post('/api/federation/switch', json={'enabled': True}).status_code == 200
    assert save_server_settings({federation.SETTING_KEY: False, 'login_banner': 'hi'})
    assert seed.db.get_server_setting(federation.SETTING_KEY) is True
    assert seed.db.get_server_setting('login_banner') == 'hi'


# --- a member's signed call through the real app -----------------------------------------------

PEER = 'a' * 32


def _add_member(fed_mod, iid=PEER):
    key = ha_wire.new_signing_key()
    priv = ha_wire.private_key(key)

    def go(ident):
        ident['view']['members'][iid] = {'url': 'https://peer.example:5000',
                                         'public_key': ha_wire.public_of(priv),
                                         'site': 'peer', 'fingerprints': []}
        ident['view']['epoch'] = int(ident['view'].get('epoch') or 0) + 1
        return True
    fed_mod.ensure_identity()
    fed_mod._mutate_identity(go)
    return priv


def _signed(priv, receiver, method, path, body=None):
    raw = ha_wire.wire_body(body) if body is not None else b''
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(18)
    sig = priv.sign(federation._to_sign(method, path, raw, ts, nonce, receiver, PEER))
    return {ha_wire.PEER_HEADER: PEER, ha_wire.PEER_TS_HEADER: ts,
            ha_wire.PEER_NONCE_HEADER: nonce,
            ha_wire.PEER_SIG_HEADER: base64.b64encode(sig).decode(),
            ha_wire.PEER_BODY_HEADER: ha_wire.body_digest(raw),
            'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}, raw


def test_a_signed_member_call_passes_the_real_app(fed, monkeypatch):
    # the lease file is read before the member arrives, as a pairing does it: a voter
    # whose file went missing under a view with members would hold its votes
    federation.ensure_identity()
    federation._lease_state()
    priv = _add_member(federation)
    me = federation.instance_id()
    import pegaprox.app as app_mod
    counted = []
    monkeypatch.setattr(app_mod, '_check_api_rate_limit',
                        lambda ip: counted.append(ip) or True)
    client = fed.app.test_client()
    status_path = '/api/federation/peer/status'
    for _ in range(3):
        headers, _raw = _signed(priv, me, 'GET', status_path)
        r = client.get(status_path, headers=headers)
        assert r.status_code == 200, r.data
        assert r.get_json()['instance_id'] == me
        # not counted against the address like a browser's call
        assert counted == []
        # the answer carries this instance's signature over the caller's nonce
        assert federation._answer_ok(r.headers, 'GET', status_path,
                                     headers[ha_wire.PEER_NONCE_HEADER], 200, r.get_data(),
                                     me, PEER, federation.public_key())
    # a POST passes the CSRF gate and the standby forwarding: the vote answers
    vote = {'candidate': PEER, 'view': federation.view_digest(),
            'epoch': federation.view_epoch(), 'asks': [{'cluster_id': 'c9', 'adopt': False}],
            'releases': []}
    headers, raw = _signed(priv, me, 'POST', federation.LEASE_PATH, vote)
    r = client.post(federation.LEASE_PATH, data=raw, headers=headers)
    assert r.status_code == 200 and r.get_json()['votes']['c9']['granted'] is True, r.data
    # on a standby the federation route answers itself, nothing is forwarded
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    headers, raw = _signed(priv, me, 'POST', federation.LEASE_PATH, vote)
    r = client.post(federation.LEASE_PATH, data=raw, headers=headers)
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_STANDBY', r.data
    monkeypatch.setattr(ha, 'is_standby', lambda: False)
    # counterproof: the same call without its signature is nobody's, and is counted
    r = client.get(status_path, headers={'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_NOT_MEMBER'
    assert len(counted) == 1


def test_a_member_cannot_become_an_ha_standby(fed, seed):
    """As a standby an instance takes its active's federation identity with the sync; its
    own, which the other sites still count, would be gone without a word."""
    _add_member(federation)
    root = fed.as_user(seed.user('root', role='admin'))
    body = {'confirm': True, 'code': 'pgxha1_whatever', 'own_url': 'https://b.example:5000'}
    r = root.post('/api/ha/join', json=body)
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_MEMBER', r.data
    # counterproof: without other members the join goes on to its own checks
    federation._mutate_identity(lambda ident: ident['view']['members'].clear() or True)
    r = root.post('/api/ha/join', json=body)
    assert (r.get_json() or {}).get('code') != 'FED_MEMBER', r.data


# --- mirrored accounts at the login, the users routes and the federation routes -------------
#
# The mirrors here arrive the way a pull brings them: a member in the view, the mappings an
# admin made, and federation.apply_identity_snapshot over the rows the member sent.

PASSWORD = 'C0rrect!horse9'


def _member(home=FOREIGN, site='berlin'):
    priv = ha_wire.private_key(ha_wire.new_signing_key())
    federation.ensure_identity()

    def go(ident):
        ident['view']['members'][home] = {'url': f'https://{site}.example:5000',
                                          'public_key': ha_wire.public_of(priv),
                                          'site': site, 'fingerprints': []}
        ident['view']['epoch'] = int(ident['view'].get('epoch') or 0) + 1
        return True
    federation._mutate_identity(go)
    # nothing answers for the member: a pull after a mapping finds it silent
    federation._runtime['transport'] = lambda *args: (0, b'', {})
    return priv


def _account(username, password=PASSWORD, **cols):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(password)
    row = {'username': username, 'password_salt': salt, 'password_hash': pw_hash,
           'role': 'user', 'permissions': '[]', 'tenant': 'default', 'created_at': '2026',
           'password_expiry': None, 'totp_enabled': 0, 'enabled': 1, 'auth_source': 'local',
           'display_name': username, 'email': '', 'tenant_permissions': '{}',
           'denied_permissions': '[]', 'portal_only': 0, 'force_password_change': 0}
    row.update(cols)
    return row


def _passkey(username, cred=b'key-1'):
    return {'username': username, 'credential_id': base64.b64encode(cred).decode(),
            'public_key': base64.b64encode(b'public').decode(), 'transports': '',
            'aaguid': '', 'name': 'key', 'user_handle': base64.b64encode(b'handle').decode(),
            'created_at': '2026'}


MAPPED = (('tenant', 'default', 'default'),)


def _from_member(db, users=(), tokens=(), passkeys=(), home=FOREIGN, maps=MAPPED):
    """Apply what member `home` sends, with `maps` made by an admin here first."""
    if federation.member_record(home) is None:
        _member(home)
    for kind, value, local in maps:
        db.conn.execute('INSERT OR REPLACE INTO federation_identity_map (home, kind, '
                        'home_value, local_value) VALUES (?, ?, ?, ?)',
                        (home, kind, value, local))
    db.conn.commit()
    body = {'fed': federation.FED_MARK, 'home': home, 'etag': secrets.token_hex(8),
            'rows': {'users': list(users), 'api_tokens': list(tokens),
                     'webauthn_credentials': list(passkeys)}, 'clusters': []}
    return federation.apply_identity_snapshot(body, home)


def _login(api, username, password=PASSWORD, **extra):
    return api.anon().post('/api/auth/login',
                           json=dict(username=username, password=password, **extra))


def _no_session(r):
    return not (r.get_json(silent=True) or {}).get('session_id')


def test_a_mirrored_totp_user_is_sent_to_its_home(fed, db):
    _from_member(db, [_account('tess', totp_enabled=1)])
    r = _login(fed, 'tess')
    assert r.status_code == 409, r.data
    assert r.get_json()['code'] == 'FED_2FA_HOME' and r.get_json()['home'] == FOREIGN
    assert _no_session(r)


def test_a_mirrored_totp_user_with_a_passkey_gets_the_passkey_step(fed, db):
    _from_member(db, [_account('kai', totp_enabled=1)], passkeys=[_passkey('kai')])
    r = _login(fed, 'kai')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body.get('requires_2fa') is True and body['methods'] == ['webauthn']
    assert _no_session(r)


def test_an_unreadable_local_secret_fails_closed_with_the_federation_on(fed, db):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user('lou', {'password_salt': salt, 'password_hash': pw_hash, 'role': 'user',
                         'enabled': True})
    db.conn.execute("UPDATE users SET totp_enabled = 1, totp_secret_encrypted = 'aes256:AAAA' "
                    "WHERE username = 'lou'")
    db.conn.commit()
    r = _login(fed, 'lou')
    assert r.status_code != 200 and _no_session(r), r.data
    # counterproof: readable, the same account is asked for its code
    db.conn.execute("UPDATE users SET totp_secret_encrypted = ? WHERE username = 'lou'",
                    (db._encrypt('JBSWY3DPEHPK3PXP'),))
    db.conn.commit()
    r = _login(fed, 'lou')
    assert r.status_code == 200 and r.get_json().get('requires_2fa'), r.data


def test_a_mirror_with_a_forced_password_change_is_sent_home(fed, db):
    _from_member(db, [_account('finn', force_password_change=1)])
    r = _login(fed, 'finn')
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_PASSWORD_HOME', r.data
    assert _no_session(r)
    # counterproof: a local account with the same demand signs in and is asked to change it
    db.save_user('fiona', dict(db.get_user('finn'), fed_home='', force_password_change=True))
    db.conn.execute("UPDATE users SET fed_home = '' WHERE username = 'fiona'")
    db.conn.commit()
    r = _login(fed, 'fiona')
    assert r.status_code == 200 and r.get_json()['requires_password_change'] is True, r.data


def test_a_quarantined_mirror_cannot_sign_in(fed, db):
    report = _from_member(db, [_account('quinn')], maps=())
    assert report['quarantined'] == 1
    r = _login(fed, 'quinn')
    assert r.status_code == 401 and _no_session(r), r.data
    # counterproof: mapped, it signs in
    _from_member(db, [_account('quinn')])
    r = _login(fed, 'quinn')
    assert r.status_code == 200 and r.get_json().get('session_id'), r.data


def test_a_disabled_mirror_cannot_sign_in(fed, db):
    _from_member(db, [_account('dana', enabled=0)])
    r = _login(fed, 'dana')
    assert r.status_code == 401 and _no_session(r), r.data


def test_a_portal_only_mirror_stays_in_the_portal(fed, db):
    from pegaprox.utils.rbac import portal_only_holds
    pola = _account('pola', portal_only=1)
    _from_member(db, [pola])
    user = db.get_user('pola')
    assert portal_only_holds(user) is True
    c = fed.as_user({'username': 'pola', 'role': 'user'})
    r = c.get('/api/clusters')
    assert r.status_code == 403, r.data
    # counterproof: the flag taken away at the home, the same session reaches the route
    _from_member(db, [dict(pola, portal_only=0)])
    assert c.get('/api/clusters').status_code == 200


def _ldap(monkeypatch, username, role='admin'):
    import pegaprox.api.auth as auth_api
    result = {'success': True, 'username': username, 'email': f'{username}@corp.example',
              'display_name': username, 'role': role, 'tenant': '', 'permissions': [],
              'tenant_permissions': {}, 'groups': [], 'user_dn': f'cn={username}',
              'auth_source': 'ldap'}
    monkeypatch.setattr(auth_api, 'get_ldap_settings',
                        lambda: {'enabled': True, 'auto_create_users': True})
    monkeypatch.setattr(auth_api, 'ldap_authenticate',
                        lambda u, p: dict(result) if u == username
                        else {'error': 'User not found in LDAP'})


def test_an_ldap_sign_in_never_takes_over_a_mirror(fed, db, monkeypatch):
    _from_member(db, [_account('jsmith', password='The-Home-Pw-9!', auth_source='ldap',
                               role='viewer')])
    _ldap(monkeypatch, 'jsmith')
    r = _login(fed, 'jsmith', password='the-directory-password')
    assert r.status_code == 401 and _no_session(r), r.data
    row = db.get_user('jsmith')
    assert row['role'] == 'viewer' and row['fed_home'] == FOREIGN and not row['ldap_dn']
    # counterproof: a directory account of this instance signs in through the same mock
    db.save_user('jsmith2', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                             'auth_source': 'ldap', 'enabled': True})
    _ldap(monkeypatch, 'jsmith2')
    r = _login(fed, 'jsmith2', password='the-directory-password')
    assert r.status_code == 200 and r.get_json().get('session_id'), r.data


def test_an_ldap_sign_in_on_a_standby_never_takes_over_a_mirror(fed, db, monkeypatch):
    """The standby branch asks ldap_build_user_row too: a mirror falls to local auth. The
    directory says exactly what the mirror row says, so nothing but that rule stands
    between the directory password and a session here."""
    from pegaprox.core import ha
    _from_member(db, [_account('jstand', password='The-Home-Pw-9!', auth_source='ldap',
                               role='viewer')])
    _ldap(monkeypatch, 'jstand', role='viewer')
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    r = _login(fed, 'jstand', password='the-directory-password')
    assert r.status_code == 401 and _no_session(r), r.data
    assert db.get_user('jstand')['role'] == 'viewer'
    # counterproof: a directory account of this instance with the same row signs in there
    db.save_user('jlocal', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                            'tenant_id': 'default', 'auth_source': 'ldap', 'enabled': True})
    _ldap(monkeypatch, 'jlocal', role='viewer')
    r = _login(fed, 'jlocal', password='the-directory-password')
    assert r.status_code == 200 and r.get_json().get('session_id'), r.data


def test_an_oidc_sign_in_never_returns_a_mirror(fed, db):
    from pegaprox.utils.oidc import oidc_build_user_row, oidc_provision_user
    from pegaprox.utils.auth import load_users
    _from_member(db, [_account('ops', role='admin', auth_source='oidc')])
    info = {'sub': 'sub-of-somebody', 'preferred_username': 'ops', 'email': 'ops'}
    assert oidc_provision_user(info, {'role': 'admin', '_authoritative': True}) is None
    # the standby branch of the callback asks the row builder, which refuses it as well
    assert oidc_build_user_row(info, {'role': 'admin'}, 'oidc', load_users()) is None
    row = db.get_user('ops')
    assert row['fed_home'] == FOREIGN and row['oidc_sub'] == ''
    # counterproof: an unbound OIDC account of this instance is bound by that sign-in
    db.save_user('ops2', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                          'auth_source': 'oidc', 'enabled': True})
    got = oidc_provision_user({'sub': 'sub-2', 'preferred_username': 'ops2'},
                              {'role': 'viewer', '_authoritative': True})
    assert got is not None and db.get_user('ops2')['oidc_sub'] == 'sub-2'


USERS_ROUTES = (
    ('put', '/api/users/{u}', {'display_name': 'x'}),
    ('delete', '/api/users/{u}', None),
    ('put', '/api/users/{u}/password', {'password': 'An0ther!Passw0rd'}),
    ('delete', '/api/users/{u}/2fa', None),
    ('put', '/api/users/{u}/permissions', {'permissions': ['vm.view']}),
    ('delete', '/api/users/{u}/tenant-permissions/default', None),
)


@pytest.mark.parametrize('method,path,body', USERS_ROUTES)
def test_every_users_route_refuses_a_mirror(fed, seed, method, path, body):
    admin = fed.as_user(seed.user('root', role='admin'))
    _mirror(seed, 'miriam')
    kw = {'json': body} if body is not None else {}
    r = getattr(admin, method)(path.format(u='miriam'), **kw)
    assert r.status_code == 409, (path, r.status_code, r.data)
    assert r.get_json()['code'] == 'FED_FOREIGN' and r.get_json()['home'] == FOREIGN


FACTOR_ROUTES = (
    ('post', '/api/auth/2fa/setup', {}),
    ('post', '/api/auth/2fa/verify', {'code': '123456'}),
    ('post', '/api/auth/2fa/disable', {'password': PASSWORD}),
    ('post', '/api/auth/tokens', {'name': 'ci'}),
    ('post', '/api/auth/change-password', {'current_password': PASSWORD,
                                           'new_password': 'NewPassword1x!'}),
    ('post', '/api/webauthn/register/begin', {}),
    ('post', '/api/webauthn/register/finish', {}),
    ('delete', '/api/webauthn/credentials/1', None),
)


@pytest.mark.parametrize('method,path,body', FACTOR_ROUTES)
def test_a_mirror_cannot_change_its_own_factors_here(fed, seed, method, path, body):
    c = fed.as_user(_mirror(seed, 'miriam'))
    kw = {'json': body} if body is not None else {}
    r = getattr(c, method)(path, **kw)
    assert r.status_code == 409, (path, r.status_code, r.data)
    assert r.get_json()['code'] == 'FED_FOREIGN' and r.get_json()['home'] == FOREIGN
    # counterproof: an account of this instance is not refused for that reason
    local = fed.as_user(seed.user('lotte', role='user'))
    r = getattr(local, method)(path, **kw)
    assert (r.get_json(silent=True) or {}).get('code') != 'FED_FOREIGN', (path, r.data)


def _admin_with_password(seed, name='root'):
    from pegaprox.utils.auth import hash_password
    user = seed.user(name, role='admin')
    salt, pw_hash = hash_password(PASSWORD)
    seed.db.conn.execute('UPDATE users SET password_salt = ?, password_hash = ? '
                         'WHERE username = ?', (salt, pw_hash, name))
    seed.db.conn.commit()
    return user


GUARDED_ROUTES = (
    ('/api/federation/pairing-code', {'url': 'https://a.example:5000'}),
    ('/api/federation/join', {'code': 'pgxfd1_x', 'own_url': 'https://a.example:5000'}),
    (f'/api/federation/members/{FOREIGN}/remove', {'confirm': 'REMOVE'}),
    ('/api/federation/leave', {'confirm': 'LEAVE'}),
    ('/api/federation/identity-map', {'home': FOREIGN, 'kind': 'tenant',
                                      'home_value': 'default', 'local_value': 'default'}),
    ('/api/federation/clusters/c1/enroll', {}),
    ('/api/federation/clusters/c1/release', {'confirm': 'RELEASE'}),
    ('/api/federation/clusters/c1/unenroll', {'confirm': 'UNENROLL'}),
    ('/api/federation/clusters/c1/adopt', {'confirm': 'ADOPT'}),
)


@pytest.mark.parametrize('path,body', GUARDED_ROUTES)
def test_every_reauth_route_wants_the_password(fed, seed, path, body):
    from pegaprox.utils.auth import create_api_token
    root = fed.as_user(_admin_with_password(seed))
    r = root.post(path, json=body)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_REAUTH', (path, r.data)
    res = create_api_token('root', 'ci', role='admin')
    r = fed.anon().post(path, json=dict(body, user_password=PASSWORD),
                        headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_REAUTH', (path, r.data)


def test_taking_a_mapping_away_asks_no_password(fed, seed, db):
    root = fed.as_user(_admin_with_password(seed))
    _from_member(db, [_account('una')])
    assert db.get_user('una')['enabled'] is True
    r = root.post('/api/federation/identity-map',
                  json={'home': FOREIGN, 'kind': 'tenant', 'home_value': 'default',
                        'local_value': ''})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'saved': True, 'pulled': False, 'report': {'failed': True}}
    user = db.get_user('una')
    assert user['enabled'] is False and user['tenant_id'] == federation.QUARANTINE


SWITCH = ('/api/federation/switch', {'enabled': True})


@pytest.mark.parametrize('path,body', (SWITCH,) + GUARDED_ROUTES)
def test_a_mirrored_admin_changes_no_federation_state(fed, seed, path, body):
    miriam = fed.as_user(_mirror(seed, 'miriam', role='admin'))
    r = miriam.post(path, json=dict(body, user_password=PASSWORD))
    assert r.status_code == 403, (path, r.status_code, r.data)
    assert r.get_json()['code'] == 'FED_MIRROR_ADMIN' and r.get_json()['home'] == FOREIGN
    # counterproof: a local admin with the password gets past the guard to the route's
    # own answer
    root = fed.as_user(_admin_with_password(seed))
    r = root.post(path, json=dict(body, user_password=PASSWORD))
    assert (r.get_json(silent=True) or {}).get('code') not in (
        'FED_MIRROR_ADMIN', 'FED_REAUTH', 'FED_REAUTH_RECENT'), (path, r.data)


def _template_id():
    from pegaprox.api import users as users_api
    return next(iter(users_api.ROLE_TEMPLATES))


def test_a_mirrored_admin_administers_no_account_tenant_or_role_here(fed, seed):
    """FED_MIRROR_ADMIN keeps a mirrored admin out of the trust changes of the federation.
    A local admin account it could create, give a password or raise to admin would make
    every one of them under that name, so the routes that administer this instance's
    accounts, tenants and roles refuse it as well."""
    miriam = fed.as_user(_mirror(seed, 'miriam', role='admin'))
    seed.user('lotte', role='viewer')
    pw = 'Sup3r-Secret-Pass!word9'
    for method, path, body in (
            ('post', '/api/users', {'username': 'shadow', 'password': pw, 'role': 'admin'}),
            ('put', '/api/users/lotte', {'role': 'admin'}),
            ('put', '/api/users/lotte/password', {'password': pw}),
            ('delete', '/api/users/lotte/2fa', None),
            ('put', '/api/users/lotte/permissions', {'permissions': ['vm.view']}),
            ('delete', '/api/users/lotte', None),
            ('post', '/api/tenants', {'name': 'shadow-tenant'}),
            ('put', '/api/tenants/default', {'name': 'x'}),
            ('delete', '/api/tenants/no-such-tenant', None),
            ('post', '/api/roles', {'id': 'shadow', 'name': 'Shadow',
                                    'permissions': ['vm.view']}),
            ('put', '/api/roles/no-such-role', {'permissions': ['vm.view']}),
            ('delete', '/api/roles/no-such-role', None),
            ('post', f'/api/roles/templates/{_template_id()}/apply', {'role_id': 'shadow'}),
            ('delete', '/api/users/lotte/oidc-binding', None),
            ('post', '/api/config/restore', None),
            ('post', '/api/settings/server', {'ldap_group_mappings': [
                {'group_dn': 'CN=ops,DC=example,DC=org', 'role': 'admin'}]})):
        r = getattr(miriam, method)(path, **({'json': body} if body is not None else {}))
        assert r.status_code == 403, (path, r.status_code, r.data)
        assert r.get_json()['code'] == 'FED_MIRROR_ADMIN' and r.get_json()['home'] == FOREIGN
    assert seed.db.get_user('shadow') is None
    assert seed.db.get_user('lotte')['role'] == 'viewer'
    # counterproof: a local admin creates the same account
    root = fed.as_user(seed.user('root', role='admin'))
    r = root.post('/api/users', json={'username': 'shadow', 'password': pw, 'role': 'admin'})
    assert r.status_code in (200, 201), r.data
    assert seed.db.get_user('shadow')['role'] == 'admin'


# --- the role a directory or single sign-on account gets here ----------------------------------

def _changed(key):
    """A value of `key` (EXTERNAL_ROLE_SETTINGS) that is not the default."""
    return {'ldap_group_mappings': [{'group_dn': 'CN=ops,DC=example,DC=org', 'role': 'admin'}],
            'oidc_group_mappings': [{'group_id': 'g-ops', 'role': 'admin'}],
            'ldap_auto_create_users': False, 'oidc_auto_create_users': False,
            'ldap_default_role': 'admin', 'oidc_default_role': 'admin',
            'ldap_group_filter': '(objectClass=group)'}.get(key, 'CN=ops,DC=example,DC=org')


def _settings():
    from pegaprox.api.helpers import load_server_settings
    return load_server_settings()


@pytest.mark.parametrize('key', sorted(EXTERNAL_ROLE_SETTINGS))
def test_a_mirrored_admin_changes_no_role_an_external_sign_in_gets(fed, seed, key):
    """A mirrored admin that maps a directory group it is in to admin (or makes admin the
    default role, or widens the group filter) is an admin of this instance at its next
    LDAP or OIDC sign-in, under a local account. Refused for the whole request: the other
    setting it carries is not saved either. Counterproof: a local admin saves the same."""
    before = _settings()
    miriam = fed.as_user(_mirror(seed, 'miriam', role='admin'))
    r = miriam.post('/api/settings/server', json={key: _changed(key), 'domain': 'pp.example.org'})
    assert r.status_code == 403, (key, r.data)
    assert r.get_json()['code'] == 'FED_MIRROR_ADMIN' and r.get_json()['home'] == FOREIGN
    after = _settings()
    assert after[key] == before[key] and after['domain'] == before['domain']
    root = fed.as_user(seed.user('root', role='admin'))
    r = root.post('/api/settings/server', json={key: _changed(key), 'domain': 'pp.example.org'})
    assert r.status_code == 200, (key, r.data)
    assert _settings()[key] == _changed(key) and _settings()['domain'] == 'pp.example.org'


def _ca_pem():
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shadow CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _source_value(key, before):
    """A value of `key` (EXTERNAL_SOURCE_SETTINGS or a secret) other than the stored one."""
    if key in EXTERNAL_SOURCE_SECRETS:
        return 'Sh4dow-secret'
    if EXTERNAL_SOURCE_SETTINGS[key] is bool:
        return not before.get(key)
    return {'ldap_server': 'dc2.example.org', 'ldap_port': 6363, 'ldap_ca_cert': _ca_pem(),
            'ldap_username_attribute': 'uid', 'oidc_provider': 'okta',
            'oidc_cloud_environment': 'gcc', 'oidc_username_claim': 'upn',
            'oidc_authority': 'https://idp.example.org'}.get(key, 'CN=ops,DC=example,DC=org')


@pytest.mark.parametrize('key', sorted(EXTERNAL_SOURCE_SETTINGS) + list(EXTERNAL_SOURCE_SECRETS))
def test_a_mirrored_admin_points_no_sign_in_at_a_directory_of_its_own(fed, seed, key):
    """A directory or identity provider the mirrored admin runs would hand the group
    mappings to any account it makes up there. So whether LDAP and OIDC are on, where they
    point, what checks them and how a name is read are refused as well, the whole request
    with them. Counterproof: a local admin saves the same."""
    # a directory set up before (without one the TLS switches read as the new defaults)
    seed.db.save_server_settings({'ldap_server': 'dc1.example.org'})
    before = _settings()
    value = _source_value(key, before)
    miriam = fed.as_user(_mirror(seed, 'miriam', role='admin'))
    r = miriam.post('/api/settings/server', json={key: value, 'domain': 'pp.example.org'})
    assert r.status_code == 403, (key, r.data)
    assert r.get_json()['code'] == 'FED_MIRROR_ADMIN' and r.get_json()['home'] == FOREIGN
    after = _settings()
    assert after.get(key) == before.get(key) and after['domain'] == before['domain']
    root = fed.as_user(seed.user('root', role='admin'))
    r = root.post('/api/settings/server', json={key: value, 'domain': 'pp.example.org'})
    assert r.status_code == 200, (key, r.data)
    assert _settings().get(key) != before.get(key) and _settings()['domain'] == 'pp.example.org'


def test_a_mirrored_admin_saves_the_whole_settings_form_with_them_as_they_are(fed, seed):
    """The settings page sends the whole form. A mirrored admin that changes an unrelated
    setting sends the LDAP and OIDC role settings back as they are stored, and the save
    goes through; group mappings set before by a local admin included."""
    root = fed.as_user(seed.user('root', role='admin'))
    r = root.post('/api/settings/server', json={
        'ldap_group_mappings': [{'group_dn': ' CN=ops,DC=example,DC=org ', 'role': 'user'}],
        'oidc_group_mappings': [{'group_dn': 'g-ops', 'role': 'viewer'}],
        'oidc_default_role': ''})
    assert r.status_code == 200, r.data
    miriam = fed.as_user(_mirror(seed, 'miriam', role='admin'))
    form = miriam.get('/api/settings/server').get_json()
    form['domain'] = 'pp.example.org'
    r = miriam.post('/api/settings/server', json=form)
    assert r.status_code == 200, r.data
    assert _settings()['domain'] == 'pp.example.org'
    assert _settings()['ldap_group_mappings'] == [{'group_dn': 'CN=ops,DC=example,DC=org',
                                                   'role': 'user'}]
    # counterproof: one mapping more in the same form is refused
    form['oidc_group_mappings'] = form['oidc_group_mappings'] + [{'group_id': 'g-x', 'role': 'admin'}]
    r = miriam.post('/api/settings/server', json=form)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_MIRROR_ADMIN', r.data
    # saved mappings clear the built-in groups: a form that would clear an admin group set
    # next to them (a save of that field alone) changes it as well
    r = root.post('/api/settings/server', json={'ldap_admin_group': 'CN=admins,DC=example,DC=org'})
    assert r.status_code == 200, r.data
    form = miriam.get('/api/settings/server').get_json()
    r = miriam.post('/api/settings/server', json=form)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_MIRROR_ADMIN', r.data
    assert _settings()['ldap_admin_group'] == 'CN=admins,DC=example,DC=org'


def test_with_the_federation_off_a_mirrored_admin_reaches_no_settings_at_all(switchable, seed,
                                                                             monkeypatch):
    """The switch is off: a mirror counts as disabled. It does not sign in, its session is
    refused before the route runs, and the mirror check is never asked. A local admin
    changes the role settings as before, and the save asks the check then (the tripwire
    sits where the route looks)."""
    from pegaprox.api import settings as settings_api
    asked = []
    monkeypatch.setattr(settings_api, 'refuse_mirror_caller', lambda *a: asked.append(a))
    mira = _admin_with_password(seed, 'mira')
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'mira'", (FOREIGN,))
    seed.db.conn.commit()
    r = _login(switchable, 'mira')
    assert r.status_code == 401 and _no_session(r), r.data
    body = {'ldap_group_mappings': [{'group_dn': 'CN=ops,DC=example,DC=org', 'role': 'admin'}]}
    r = switchable.as_user(mira).post('/api/settings/server', json=body)
    assert r.status_code == 401 and r.get_json()['code'] == 'ACCOUNT_DISABLED', r.data
    assert asked == [] and _settings()['ldap_group_mappings'] == []
    r = switchable.as_user(seed.user('root', role='admin')).post('/api/settings/server', json=body)
    assert r.status_code == 200, r.data
    assert _settings()['ldap_group_mappings'] == body['ldap_group_mappings'] and len(asked) == 1


def test_a_mirrored_admin_resets_no_oidc_binding(fed, seed, db):
    """Whoever signs in next through the identity provider under the name gets the account
    a reset unbinds. A mirrored admin does not reset one here, and a mirrored account's
    binding is its home's. Counterproof: a local admin resets a local account's."""
    db.save_user('ops', {'password_salt': '', 'password_hash': '', 'role': 'admin',
                         'auth_source': 'oidc', 'oidc_sub': 'sub-1', 'enabled': True})
    miriam = fed.as_user(_mirror(seed, 'miriam', role='admin'))
    r = miriam.delete('/api/users/ops/oidc-binding')
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_MIRROR_ADMIN', r.data
    assert db.get_user('ops')['oidc_sub'] == 'sub-1'
    root = fed.as_user(seed.user('root', role='admin'))
    db.save_user('otto', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                          'auth_source': 'oidc', 'oidc_sub': 'sub-2', 'enabled': True})
    db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'otto'", (FOREIGN,))
    db.conn.commit()
    r = root.delete('/api/users/otto/oidc-binding')
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_FOREIGN', r.data
    r = root.delete('/api/users/ops/oidc-binding')
    assert r.status_code == 200, r.data
    assert db.get_user('ops')['oidc_sub'] == ''


def test_the_mapping_routes_map_and_unmap(fed, seed, db, monkeypatch):
    import pegaprox.api.federation as api_fed
    audits = []
    monkeypatch.setattr(api_fed, 'log_audit',
                        lambda user, action, details=None, **kw: audits.append((action, details)))
    root = fed.as_user(_admin_with_password(seed))
    _from_member(db, [_account('wim', tenant='acme', role='support')], maps=())
    seed.tenant('acme-here', ['c1'])
    r = root.get('/api/federation/identity-map')
    assert r.status_code == 200, r.data
    body = r.get_json()
    entries = body['members'][FOREIGN]['entries']
    assert body['members'][FOREIGN]['site'] == 'berlin'
    assert {(e['kind'], e['home_value'], e['local_value'], e['users']) for e in entries} == {
        ('tenant', 'acme', '', 1), ('role', 'support', '', 1)}
    assert {'id': 'acme-here', 'name': 'acme-here'} in body['local']['tenants']
    status = root.get('/api/federation/status').get_json()
    assert [m['unmapped'] for m in status['members']] == [2]
    # a value nobody names, or a target this instance does not have
    r = root.post('/api/federation/identity-map',
                  json={'home': FOREIGN, 'kind': 'tenant', 'home_value': 'nope',
                        'local_value': 'acme-here', 'user_password': PASSWORD})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_MAP_UNKNOWN', r.data
    r = root.post('/api/federation/identity-map',
                  json={'home': FOREIGN, 'kind': 'tenant', 'home_value': 'acme',
                        'local_value': 'no-such', 'user_password': PASSWORD})
    assert r.status_code == 400 and r.get_json()['code'] == 'FED_MAP_INVALID', r.data
    for kind, value, local in (('tenant', 'acme', 'acme-here'), ('role', 'support', 'viewer')):
        r = root.post('/api/federation/identity-map',
                      json={'home': FOREIGN, 'kind': kind, 'home_value': value,
                            'local_value': local, 'user_password': PASSWORD})
        assert r.status_code == 200 and r.get_json()['saved'] is True, r.data
    assert [a[0] for a in audits] == ['federation.identity_mapped'] * 2
    assert 'mapped onto "acme-here"' in audits[0][1]
    # the member is silent here, so the accounts follow at its next snapshot
    _from_member(db, [_account('wim', tenant='acme', role='support')], maps=())
    user = db.get_user('wim')
    assert (user['tenant_id'], user['role'], user['enabled']) == ('acme-here', 'viewer', True)


def test_the_last_local_admin_cannot_go_while_mirrored_admins_exist(fed, seed, db):
    root = fed.as_user(seed.user('root', role='admin'))
    _from_member(db, [_account('miri', role='admin')])
    miri = fed.as_user({'username': 'miri', 'role': 'admin'})
    # the mirrored admin administers no account of this instance at all
    for r in (miri.put('/api/users/root', json={'role': 'user'}),
              miri.put('/api/users/root', json={'enabled': False}),
              miri.delete('/api/users/root')):
        assert r.status_code == 403 and r.get_json()['code'] == 'FED_MIRROR_ADMIN', r.data
    # and does not count as an admin here: root is the last one
    r = root.put('/api/users/root', json={'enabled': False})
    assert r.status_code == 400 and 'last admin' in r.get_json()['error'], r.data
    assert db.get_user('root')['role'] == 'admin' and db.get_user('root')['enabled']
    # counterproof: with a second admin of this instance the delete goes through
    root2 = fed.as_user(seed.user('root2', role='admin'))
    assert root2.delete('/api/users/root').status_code == 200
    assert db.get_user('root') is None


def test_a_mirror_is_not_held_to_the_local_password_expiry(fed, seed, db, monkeypatch):
    import pegaprox.api.auth as auth_api
    real = auth_api.load_server_settings
    monkeypatch.setattr(auth_api, 'load_server_settings',
                        lambda *a, **k: dict(real(*a, **k), password_expiry_enabled=True,
                                             password_expiry_days=90))
    _from_member(db, [_account('exp')])
    r = fed.as_user({'username': 'exp', 'role': 'user'}).get('/api/auth/check')
    assert r.status_code == 200 and r.get_json()['password_expiry'] is None, r.data
    # counterproof: an account of this instance without a change date reads as expired
    seed.user('local-exp', role='user')
    db.conn.execute("UPDATE users SET password_changed_at = NULL WHERE username = 'local-exp'")
    db.conn.commit()
    r = fed.as_user({'username': 'local-exp', 'role': 'user'}).get('/api/auth/check')
    assert r.get_json()['password_expiry']['expired'] is True, r.data


def test_the_users_list_marks_the_mirrors(fed, seed, db):
    admin = fed.as_user(seed.user('root', role='admin'))
    _from_member(db, [_account('mia')])
    rows = {u['username']: u for u in admin.get('/api/users').get_json()}
    assert rows['mia']['fed_home'] == FOREIGN and rows['mia']['fed_site'] == 'berlin'
    assert rows['root']['fed_home'] == '' and rows['root']['fed_site'] == ''


# --- the bounds of the identity apply, and what the status and the expiry reset count -------

def test_the_mapping_of_one_home_is_bounded(fed, db):
    """One home naming more tenants than MAX_MAP_ROWS gets that many mapping rows: the
    accounts naming a value beyond them get no row and stay quarantined, and the value
    cannot be mapped (fail closed, never a wider access)."""
    n = federation.MAX_MAP_ROWS
    users = [_account(f'u{i:03d}', tenant=f't{i:03d}') for i in range(n + 1)]
    _from_member(db, users, maps=())
    held = {r[0] for r in db.conn.execute(
        "SELECT home_value FROM federation_identity_map WHERE home = ? AND kind = 'tenant'",
        (FOREIGN,)).fetchall()}
    beyond = f't{n:03d}'
    assert len(held) == n and beyond not in held
    row = db.conn.execute('SELECT tenant, enabled FROM users WHERE username = ?',
                          (f'u{n:03d}',)).fetchone()
    assert row['tenant'] == federation.QUARANTINE and not row['enabled']
    with pytest.raises(federation.FederationError) as err:
        federation.map_identity(FOREIGN, 'tenant', beyond, 'default', by='root')
    assert err.value.code == 'FED_MAP_UNKNOWN'
    # counterproof: a value inside the bound maps
    federation.map_identity(FOREIGN, 'tenant', 't000', 'default', by='root')


def test_the_conflicts_of_one_snapshot_are_capped(fed, seed, db):
    """A snapshot naming more local accounts than MAX_REPORT_CONFLICTS lists that many
    conflicts and counts the rest."""
    n = federation.MAX_REPORT_CONFLICTS
    for i in range(n + 1):
        seed.user(f'local{i:03d}', role='viewer')
    report = _from_member(db, [_account(f'local{i:03d}') for i in range(n + 1)])
    assert len(report['conflicts']) == n and report['conflicts_more'] == 1
    for i in range(n + 1):
        assert db.get_user(f'local{i:03d}')['fed_home'] == ''


def test_the_status_counts_the_mirrored_clusters_per_member(fed, seed, db):
    """Each member in the status says how many of its clusters this instance mirrors."""
    other = 'e' * 32
    _member(FOREIGN)
    _member(other, site='paris')
    for cid, owner in (('m1', FOREIGN), ('m2', FOREIGN), ('m3', other)):
        db.conn.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, "
                        "fed_owner) VALUES (?, ?, 'h', 'u', '', ?)", (cid, cid, owner))
    db.conn.commit()
    admin = fed.as_user(seed.user('root', role='admin'))
    r = admin.get('/api/federation/status')
    assert r.status_code == 200, r.data
    counts = {m['instance_id']: m['mirrored_clusters'] for m in r.get_json()['members']}
    assert counts == {FOREIGN: 2, other: 1}


def test_the_expiry_reset_leaves_the_mirrors_alone(fed, seed, db):
    """Resetting every password's age expires this instance's accounts, not the mirrors:
    their home's policy holds, and they are not counted."""
    admin = fed.as_user(seed.user('root', role='admin'))
    seed.user('local-user', role='user')
    _from_member(db, [_account('mirror-user')])
    db.conn.execute("UPDATE users SET password_changed_at = '2026-11-01T00:00:00' "
                    "WHERE username IN ('local-user', 'mirror-user')")
    db.conn.commit()
    r = admin.post('/api/security/password-expiry/reset-all', json={})
    assert r.status_code == 200, r.data
    assert r.get_json().get('reset_count') == 1, r.get_json()
    changed = {u: db.conn.execute('SELECT password_changed_at FROM users WHERE username = ?',
                                  (u,)).fetchone()[0] for u in ('local-user', 'mirror-user')}
    assert changed['mirror-user'] == '2026-11-01T00:00:00'
    assert changed['local-user'] != '2026-11-01T00:00:00'


# --- a delegate revoking another tenant's mirrored token ------------------------------------

def test_a_delegate_learns_nothing_of_another_tenants_mirrored_token(fed, seed):
    """ann holds admin.api inside tenant_a. A token of tenant_b, mirrored from another
    site, answers her as any out-of-tenant token does (404), not with its home. A global
    admin is still sent to the home."""
    import pegaprox.api.auth as authapi
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    ann = seed.user('ann', role='user', tenant_id='tenant_a', permissions=['admin.api'])
    seed.user('bert', role='user', tenant_id='tenant_b')
    root = seed.user('root', role='admin')
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'bert'", (FOREIGN,))
    authapi.ensure_api_tokens_table()
    seed.db.conn.execute(
        "INSERT INTO api_tokens (token_hash, token_prefix, username, name, role, created_at, "
        "fed_home) VALUES ('th-bert', 'pgx_b', 'bert', 'ci', 'viewer', '2026', ?)", (FOREIGN,))
    seed.db.conn.commit()
    tid = seed.db.conn.execute("SELECT id FROM api_tokens WHERE token_hash = 'th-bert'").fetchone()[0]
    r = fed.as_user(ann).delete(f'/api/auth/tokens/{tid}')
    assert r.status_code == 404, r.data
    assert 'home' not in (r.get_json() or {}) and FOREIGN not in r.get_data(as_text=True)
    r = fed.as_user(root).delete(f'/api/auth/tokens/{tid}')
    assert r.status_code == 409 and r.get_json()['home'] == FOREIGN, r.data


# --- the passkey routes with the switch off ----------------------------------------------------

def test_a_leftover_mirror_session_registers_and_removes_no_passkey(switchable, seed):
    """The switch went off (forced, or a database restored onto a plain install) while a
    mirror's session lived on. The passkey routes check the session, not the account: they
    refuse it as require_auth does, so no second factor this site's home does not know of
    is left behind. Counterproof: the same session of a local account gets through."""
    from pegaprox.api import webauthn as wa
    if not wa.FIDO2_AVAILABLE:
        pytest.skip('fido2 is not installed')
    mira = _mirror(seed, 'mira')
    seed.db.conn.execute(
        "INSERT INTO webauthn_credentials (username, credential_id, public_key, name, "
        "user_handle, created_at, fed_home) VALUES ('mira', 'Y3JlZA==', X'00', 'key', X'00', "
        "'2026', ?)", (FOREIGN,))
    seed.db.conn.commit()
    cred = seed.db.conn.execute("SELECT id FROM webauthn_credentials").fetchone()[0]
    c = switchable.as_user(mira)
    for method, path in (('post', '/api/webauthn/register/begin'),
                         ('post', '/api/webauthn/register/finish'),
                         ('delete', f'/api/webauthn/credentials/{cred}')):
        r = getattr(c, method)(path, json={})
        assert r.status_code == 401 and r.get_json()['code'] == 'ACCOUNT_DISABLED', (path, r.data)
    assert seed.db.conn.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone()[0] == 1
    seed.db.conn.execute("UPDATE users SET fed_home = '' WHERE username = 'mira'")
    seed.db.conn.commit()
    r = c.delete(f'/api/webauthn/credentials/{cred}', json={})
    assert r.status_code != 401, r.data


# --- forced second factor and a mirror -----------------------------------------------------------

def test_a_mirror_with_a_passkey_is_enrolled_under_force_2fa(fed, db):
    """force_2fa holds every account without a factor this site can ask for. A mirror's
    TOTP secret never travels and the setup routes refuse it here, so its passkey is that
    factor: a mirror with one is not held. A local account with only a passkey still is."""
    from pegaprox.utils.auth import mfa_enrolment_state, MFA_DUE, MFA_NOT_DUE
    _from_member(db, [_account('kai', totp_enabled=1), _account('noa')],
                 passkeys=[_passkey('kai')])
    settings = {'force_2fa': True}
    assert mfa_enrolment_state(db.get_user('kai'), settings, 'kai') == MFA_NOT_DUE
    assert mfa_enrolment_state(db.get_user('noa'), settings, 'noa') == MFA_DUE
    db.save_user('lena', {'password_salt': 's', 'password_hash': 'h', 'role': 'user',
                          'enabled': True})
    db.conn.execute("INSERT INTO webauthn_credentials (username, credential_id, public_key, "
                    "name, user_handle, created_at) VALUES ('lena', 'bGVuYQ==', X'00', 'k', "
                    "X'00', '2026')")
    db.conn.commit()
    assert mfa_enrolment_state(db.get_user('lena'), settings, 'lena') == MFA_DUE


def test_a_mirror_signs_in_with_its_passkey_and_works_under_force_2fa(fed, db):
    """The same over the routes: the sign-in, validate_session and the session check each
    hand mfa_enrolment_state the account's name, which is what finds the passkey. A mapped
    mirror that signs in with it is not sent to the enrolment, and its session reaches the
    API. Counterproof: a mirror without one is held to an enrolment it cannot do here."""
    from pegaprox.api import webauthn as wa
    from pegaprox.api.helpers import save_server_settings
    pytest.importorskip('pyotp')
    s = _settings()
    s['force_2fa'] = True
    save_server_settings(s)
    _from_member(db, [_account('kai'), _account('noa')], passkeys=[_passkey('kai')])
    proof = secrets.token_urlsafe(32)
    wa._challenges[('kai', 'proof')] = (proof, time.time() + 60)
    r = _login(fed, 'kai', webauthn_proof=proof)
    assert r.status_code == 200 and r.get_json()['requires_2fa_setup'] is False, r.data
    sid = {'X-Session-ID': r.get_json()['session_id']}
    assert fed.anon().get('/api/pbs', headers=sid).status_code == 200
    r = fed.anon().get('/api/auth/check', headers=sid)
    assert r.status_code == 200 and r.get_json()['requires_2fa_setup'] is False, r.data
    r = _login(fed, 'noa')
    assert r.status_code == 200 and r.get_json()['requires_2fa_setup'] is True, r.data
    sid = {'X-Session-ID': r.get_json()['session_id']}
    r = fed.anon().get('/api/pbs', headers=sid)
    assert r.status_code == 403 and r.get_json()['code'] == 'MFA_ENROLMENT_REQUIRED', r.data


# --- the reconcile and the renewal are on record --------------------------------------------------

def test_reconcile_and_renew_are_audited(fed, seed, db):
    admin = fed.as_user(seed.user('root', role='admin'))
    federation.ensure_identity()
    assert admin.post('/api/federation/reconcile', json={}).status_code == 200
    r = admin.post('/api/federation/clusters/c1/renew', json={})
    assert r.status_code == 200, r.data
    rows = {r['action']: (r['user'], r['details']) for r in db.conn.execute(
        "SELECT user, action, details FROM audit_log WHERE action LIKE 'federation.%'")}
    assert rows['federation.reconciled'][0] == 'root'
    assert rows['federation.lease_renewed'][0] == 'root' and 'c1' in rows['federation.lease_renewed'][1]
