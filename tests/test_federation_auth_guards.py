# -*- coding: utf-8 -*-
"""The auth guards of the federation routes, over the real Flask app.

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
    instance's users route, not its token revocation, not its password change.

Nov 2026, three-leader federation Phase 2.
"""
import pytest

# a member id this instance is not: what fed_home names on a mirrored row
FOREIGN = 'f' * 32


@pytest.fixture
def fed(api, tmp_path, monkeypatch):
    """The real app with the federation state of a fresh instance: a state file
    in the test's tmp dir (never the config dir the process started with), a
    fresh instance id, and the pairing/re-auth budgets of the routes reset, as
    the HA tests reset theirs."""
    from pegaprox.core import federation
    import pegaprox.api.federation as api_fed
    state = tmp_path / 'federation_state.json'
    monkeypatch.setitem(federation._runtime, 'file', str(state))
    federation._runtime.pop('instance_id_cache', None)
    for window in (api_fed._pair_attempts, api_fed._peer_failures,
                   api_fed._reauth_attempts):
        window.reset()
    yield api
    federation._runtime.pop('instance_id_cache', None)


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
    """An admin that an LDAP tenant mapping has lowered where they live: the
    confinement guard refuses them before the registry is read - a federation
    member is trusted with the whole deployment's registry, not a tenant's
    slice of it."""
    seed.tenant('globex', ['cluster_globex'])
    c = fed.as_user(seed.user('gx', role='admin', tenant_id='globex',
                              tenant_permissions={'globex': {'role': 'user'}}))
    r = c.get('/api/federation/status')
    assert r.status_code == 403
    assert b'tenant' in r.data or b'administrators' in r.data, r.data


def test_a_tenant_capped_admin_reaches_no_federation_admin_route(fed, seed):
    """The same capped admin against every admin route of the blueprint: the
    guard runs in each of them, not only in the status read."""
    seed.tenant('globex', ['cluster_globex'])
    c = fed.as_user(seed.user('gx2', role='admin', tenant_id='globex',
                              tenant_permissions={'globex': {'role': 'user'}}))
    for method, path in (('get', '/api/federation/members'),
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
                         ('post', '/api/federation/clusters/c1/renew')):
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
