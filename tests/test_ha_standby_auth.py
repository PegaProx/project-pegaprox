"""Warm standby (#625): who gets in on a standby, and who may pair, join, promote or
unpair anywhere.

Four decisions, each driven through the real app:

  * a directory (LDAP) sign-in on a standby writes no users row. The next sync would
    put the active's copy back and hand a demoted user their old role again, so the
    sign-in only goes through when the directory says what the synced row says;
  * pairing, joining, promotion and unpairing want the account password again (or a
    fresh sign-in for an OIDC account without one), never an API token;
  * forced 2FA enrolment is not demanded of an admin on a standby, which refuses the
    enrolment itself and would otherwise show them a dead end during a failover;
  * the synced IP allow list lets the paired instance's own peer calls through when
    their peer header is right.

Each part carries its counterproof: the same call where the rule does not apply.
"""
import copy
import time

import pytest

from test_ha_api import (  # noqa: F401  (ha_env is a fixture)
    ha_env, _admin, _audit, _be, _code, _local_user, _pair_body, _peer_record,
    _standby_of_active, _active_with_standby, ADMIN_PW, ACTIVE_URL, A_ID, B_ID, PEER_SECRET,
)

# --- directory sign-in on a standby (Q1) ---------------------------------------------

LDAP_ON = {'enabled': True, 'auto_create_users': True}


def _ldap_result(username, role='admin', tenant='', permissions=(), tenant_permissions=None):
    return {'success': True, 'username': username, 'email': f'{username}@corp.example',
            'display_name': username.title(), 'role': role, 'tenant': tenant,
            'permissions': list(permissions), 'tenant_permissions': dict(tenant_permissions or {}),
            'groups': [], 'user_dn': f'cn={username},dc=corp,dc=example', 'auth_source': 'ldap'}


def _ldap_row(db, username, **extra):
    """An account an earlier directory sign-in on the active left behind."""
    row = {'password_salt': '', 'password_hash': '', 'role': 'admin', 'tenant_id': 'default',
           'enabled': True, 'permissions': [], 'denied_permissions': [],
           'tenant_permissions': {}, 'auth_source': 'ldap', 'ldap_dn': f'cn={username}',
           'last_login': '2026-09-01T08:00:00'}
    row.update(extra)
    db.save_user(username, row)
    return db.get_user(username)


def _directory(monkeypatch, **results):
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'get_ldap_settings', lambda: dict(LDAP_ON))
    monkeypatch.setattr(auth_api, 'ldap_authenticate',
                        lambda u, p: results[u] if u in results else {'error': 'User not found in LDAP'})


def _sign_in(api, username, password='pw-from-the-directory'):
    return api.anon().post('/api/auth/login', json={'username': username, 'password': password})


def _sessions_of(username):
    import pegaprox.utils.auth as authmod
    return [s for s in authmod.active_sessions.values() if s.get('user') == username]


REFUSAL = ('Your directory access changed - sign in on the active instance once; '
           'it reaches this standby with the next sync.')


def test_a_directory_demotion_on_a_standby_is_refused_and_writes_nothing(ha_env, db, monkeypatch):
    before = _ldap_row(db, 'dora')
    _standby_of_active(ha_env)
    _directory(monkeypatch, dora=_ldap_result('dora', role='viewer'))

    r = _sign_in(ha_env.api, 'dora')
    assert r.status_code == 409, r.data
    assert r.get_json() == {'code': 'HA_STANDBY', 'error': REFUSAL}
    assert db.get_user('dora') == before           # not demoted here, not touched at all
    assert _sessions_of('dora') == []


def test_the_same_demotion_on_a_standalone_sticks(ha_env, db, monkeypatch):
    """Counterproof: where the row is ours to write, the directory login writes it."""
    _ldap_row(db, 'dora')
    _directory(monkeypatch, dora=_ldap_result('dora', role='viewer'))
    for role, peer in (('standalone', None), ('active', _peer_record())):
        _be(ha_env, role, peer=peer)
        _ldap_row(db, 'dora')
        r = _sign_in(ha_env.api, 'dora')
        assert r.status_code == 200, (role, r.data)
        assert r.get_json()['user']['role'] == 'viewer'
        assert db.get_user('dora')['role'] == 'viewer'


def test_a_directory_login_that_matches_signs_in_without_writing(ha_env, db, monkeypatch):
    import pegaprox.api.auth as auth_api
    before = _ldap_row(db, 'dora', tenant_id='acme', ldap_tenant='acme',
                       permissions=['vm.start', 'vm.view'], ldap_permissions=['vm.start'],
                       tenant_permissions={'acme': {'role': 'admin'}},
                       ldap_tenant_permissions={'acme': {'role': 'admin'}})
    _standby_of_active(ha_env)
    # the same access, the permissions merely in another order
    _directory(monkeypatch, dora=_ldap_result('dora', tenant='acme', permissions=['vm.start'],
                                               tenant_permissions={'acme': {'role': 'admin'}}))

    def no_provisioning(_result):
        raise AssertionError('a standby must not provision')
    monkeypatch.setattr(auth_api, 'ldap_provision_user', no_provisioning)

    r = _sign_in(ha_env.api, 'dora')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['user']['role'] == 'admin' and body['user']['tenant_id'] == 'acme'
    assert body['ha']['role'] == 'standby'
    assert db.get_user('dora') == before           # last_login and last_ldap_sync as well
    assert len(_sessions_of('dora')) == 1
    check = ha_env.api.anon().get('/api/auth/check', headers={'X-Session-ID': body['session_id']})
    assert check.status_code == 200 and check.get_json()['user']['username'] == 'dora'


@pytest.mark.parametrize('change', ['role', 'tenant', 'permissions', 'tenant_permissions'])
def test_any_change_to_what_decides_access_is_refused(ha_env, db, monkeypatch, change):
    before = _ldap_row(db, 'dora', tenant_id='acme', ldap_tenant='acme',
                       permissions=['vm.view'], ldap_permissions=['vm.view'],
                       tenant_permissions={'acme': {'role': 'admin'}},
                       ldap_tenant_permissions={'acme': {'role': 'admin'}})
    _standby_of_active(ha_env)
    same = dict(role='admin', tenant='acme', permissions=['vm.view'],
                tenant_permissions={'acme': {'role': 'admin'}})
    changed = dict(same, **{
        'role': {'role': 'user'},
        'tenant': {'tenant': 'globex'},
        'permissions': {'permissions': ['vm.view', 'vm.delete']},
        'tenant_permissions': {'tenant_permissions': {'acme': {'role': 'viewer'}}},
    }[change])
    _directory(monkeypatch, dora=_ldap_result('dora', **changed))
    r = _sign_in(ha_env.api, 'dora')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (change, r.data)
    assert db.get_user('dora') == before and _sessions_of('dora') == []

    # counterproof: nothing changed, in
    _directory(monkeypatch, dora=_ldap_result('dora', **same))
    assert _sign_in(ha_env.api, 'dora').status_code == 200


def test_a_first_directory_login_on_a_standby_creates_no_account(ha_env, db, monkeypatch):
    """The next sync would delete it again and the session would die with it."""
    _ldap_row(db, 'root', auth_source='local')          # an installation that is set up
    _standby_of_active(ha_env)
    _directory(monkeypatch, erin=_ldap_result('erin', role='user'))
    r = _sign_in(ha_env.api, 'erin')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert db.get_user('erin') is None and _sessions_of('erin') == []

    # counterproof: a standalone provisions the account as always
    _be(ha_env, 'standalone')
    r = _sign_in(ha_env.api, 'erin')
    assert r.status_code == 200, r.data
    assert db.get_user('erin')['auth_source'] == 'ldap'


def test_a_directory_login_onto_an_account_it_does_not_own_falls_to_local_auth(ha_env, db, monkeypatch):
    """Same as on the active: a local account with the same name is not the
    directory's, so its own password decides and the row stays as it is."""
    before = _ldap_row(db, 'frank', auth_source='local', role='user')
    _standby_of_active(ha_env)
    _directory(monkeypatch, frank=_ldap_result('frank', role='user'))
    r = _sign_in(ha_env.api, 'frank')
    assert r.status_code == 401, r.data           # the seeded local hash does not match
    assert (r.get_json() or {}).get('code') != 'HA_STANDBY'
    assert db.get_user('frank') == before


def test_building_the_row_leaves_the_row_it_was_given_alone(db):
    from pegaprox.utils.ldap import ldap_build_user_row
    # held in memory as a login sees it; ldap_tenant_permissions has no column to
    # survive a trip through the database
    row = {'role': 'admin', 'tenant_id': 'default', 'auth_source': 'ldap',
           'permissions': ['vm.view'], 'ldap_permissions': ['vm.view'],
           'tenant_permissions': {'acme': {'role': 'admin'}},
           'ldap_tenant_permissions': {'acme': {'role': 'admin'}}}
    snapshot = copy.deepcopy(row)
    built = ldap_build_user_row(_ldap_result('dora', role='viewer'), row)
    assert built['role'] == 'viewer' and built['permissions'] == []
    assert built['tenant_permissions'] == {}
    assert row == snapshot
    assert db.get_user('dora') is None                      # and nothing was saved
    assert ldap_build_user_row(_ldap_result('dora'), dict(row, auth_source='oidc')) is None


# --- re-authentication for pairing, join, promotion, unpairing (Q2) -------------------

def _prepared(env, route):
    """Put this instance where `route` gets past its own checks. Returns the body."""
    if route == '/api/ha/pairing-code':
        return {'url': ACTIVE_URL}
    if route == '/api/ha/join':
        return {'code': env.ha.encode_code(ACTIVE_URL, '', 'f' * 43, A_ID),
                'own_url': 'https://standby.example:5000', 'confirm': True}
    if route == '/api/ha/promote':
        _standby_of_active(env)
        return {'confirm': 'PROMOTE'}
    _active_with_standby(env)
    return {'confirm': 'UNPAIR'}


REAUTH_ROUTES = ('/api/ha/pairing-code', '/api/ha/join', '/api/ha/promote', '/api/ha/unpair')


@pytest.mark.parametrize('route', REAUTH_ROUTES)
def test_an_api_token_cannot_pair_join_promote_or_unpair(ha_env, seed, route):
    from pegaprox.utils.auth import create_api_token
    _admin(ha_env.api, seed)
    res = create_api_token('root', 'automation', role='admin')
    token = {'Authorization': f"Bearer {res['token']}"}
    body = dict(_prepared(ha_env, route), user_password=ADMIN_PW)
    state = open(ha_env.ha.STATE_FILE).read() if route in ('/api/ha/promote', '/api/ha/unpair') else None

    r = ha_env.api.anon().post(route, json=body, headers=token)
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH', r.data
    assert ha_env.restarts == [] and ha_env.calls == [] and ha_env.installed == []
    if state is not None:
        assert open(ha_env.ha.STATE_FILE).read() == state
    else:
        assert ha_env.ha.public_status()['pairing_open_until'] is None
    # reading still works with the token
    assert ha_env.api.anon().get('/api/ha/status', headers=token).status_code == 200


@pytest.mark.parametrize('route', REAUTH_ROUTES)
def test_a_session_alone_is_not_enough(ha_env, seed, monkeypatch, route):
    from test_ha_api import _wire_to
    admin = _admin(ha_env.api, seed)
    body = _prepared(ha_env, route)
    for password in (None, '', 'not-the-password', 42, 'x' * 2000):
        sent = dict(body) if password is None else dict(body, user_password=password)
        r = admin.post(route, json=sent)
        assert r.status_code == 403, (route, password, r.status_code, r.data)
        assert r.get_json()['code'] == 'HA_REAUTH'
    assert ha_env.restarts == [] and ha_env.calls == []
    failed = _audit('ha.reauth_failed')
    assert len(failed) == 1 and failed[0]['user'] == 'root'
    assert 'auth_source=local' in failed[0]['details']

    # counterproof: the right password goes through to the action
    _wire_to(ha_env, monkeypatch, str(ha_env.tmp / 'nobody.json'), down=True)
    r = admin.post(route, json=dict(body, user_password=ADMIN_PW))
    expected = {'/api/ha/join': 502}.get(route, 200)     # join then fails at the network
    assert r.status_code == expected, (route, r.status_code, r.data)


def test_password_guesses_are_rate_limited(ha_env, seed):
    admin = _admin(ha_env.api, seed)
    for _ in range(5):
        r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': 'guess'})
        assert r.status_code == 403
    # the sixth is refused before the password is looked at, the right one too
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
    assert r.status_code == 429 and r.headers['Retry-After'] == '300'
    assert len(_audit('ha.reauth_failed')) == 5
    assert ha_env.ha.public_status()['pairing_open_until'] is None


def test_a_directory_account_confirms_against_the_directory(ha_env, seed, monkeypatch):
    import pegaprox.utils.ldap as ldapmod
    admin = ha_env.api.as_user(seed.user('dora', role='admin'))
    row = seed.db.get_user('dora')
    row.update(auth_source='ldap', password_hash='', password_salt='')
    seed.db.save_user('dora', row)
    asked = []

    def bind(username, password):
        asked.append((username, password))
        return _ldap_result(username) if password == 'directory-pw' else {'error': 'Invalid LDAP credentials'}
    monkeypatch.setattr(ldapmod, 'ldap_authenticate', bind)
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': 'wrong'})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    assert 'auth_source=ldap' in _audit('ha.reauth_failed')[0]['details']
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': 'directory-pw'})
    assert r.status_code == 200, r.data
    assert asked == [('dora', 'wrong'), ('dora', 'directory-pw')]


def test_an_oidc_account_needs_a_fresh_sign_in_instead(ha_env, seed):
    import pegaprox.utils.auth as authmod
    admin = ha_env.api.as_user(seed.user('olga', role='admin'))
    row = seed.db.get_user('olga')
    row.update(auth_source='oidc', password_hash='', password_salt='')
    seed.db.save_user('olga', row)
    session = authmod.active_sessions[admin.session_id]

    session['created_at'] = time.time() - 11 * 60
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL})
    assert r.status_code == 403, r.data
    assert r.get_json() == {'code': 'HA_REAUTH_RECENT',
                            'error': 'Sign in again, then retry within 10 minutes'}
    session.pop('created_at')
    assert admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL}).status_code == 403
    assert ha_env.ha.public_status()['pairing_open_until'] is None

    # counterproof: signed in a minute ago, no password to type
    session['created_at'] = time.time() - 60
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL})
    assert r.status_code == 200, r.data


def test_the_config_backup_checks_the_password_the_same_way(ha_env, seed, monkeypatch):
    """Behaviour unchanged there, and it goes through the shared helper."""
    import pegaprox.utils.auth as authmod
    admin = _admin(ha_env.api, seed)
    asked = []
    real = authmod.recheck_account_password

    def spy(*a, **kw):
        asked.append(kw.get('audit_action'))
        return real(*a, **kw)
    monkeypatch.setattr(authmod, 'recheck_account_password', spy)

    r = admin.post('/api/config/backup', json={'backup_password': 'long-enough'})
    assert r.status_code == 400 and 'User password required' in r.get_json()['error']
    r = admin.post('/api/config/backup', json={'user_password': 'wrong', 'backup_password': 'long-enough'})
    assert r.status_code == 401 and r.get_json()['error'] == 'Incorrect password'
    assert _audit('config.backup_failed')[-1]['details'] == \
        'Password verification failed (auth_source=local)'
    # the right password gets past the check to the next one
    r = admin.post('/api/config/backup', json={'user_password': ADMIN_PW, 'backup_password': 'short'})
    assert r.status_code == 400 and 'Backup password' in r.get_json()['error']
    assert asked == ['config.backup_failed', 'config.backup_failed']
    assert _audit('ha.reauth_failed') == []


# --- forced 2FA on a standby (Q3) --------------------------------------------------------

@pytest.fixture
def force_2fa():
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    s = load_server_settings()
    s['force_2fa'] = True
    s['force_2fa_exclude_admins'] = False
    save_server_settings(s)


def _login_and_check(api, creds):
    r = api.anon().post('/api/auth/login', json=creds)
    assert r.status_code == 200, r.data
    body = r.get_json()
    check = api.anon().get('/api/auth/check', headers={'X-Session-ID': body['session_id']})
    assert check.status_code == 200, check.data
    return body['requires_2fa_setup'], check.get_json()['requires_2fa_setup']


def test_an_admin_without_totp_is_let_in_on_a_standby(ha_env, db, tmp_path, monkeypatch, force_2fa):
    creds = _local_user(db, tmp_path, monkeypatch, 'breakglass', role='admin')
    _standby_of_active(ha_env)
    assert _login_and_check(ha_env.api, creds) == (False, False)
    skipped = _audit('ha.standby_2fa_skipped')
    assert len(skipped) == 1 and skipped[0]['user'] == 'breakglass'
    # every such sign-in is on the record
    _login_and_check(ha_env.api, creds)
    assert len(_audit('ha.standby_2fa_skipped')) == 2


def test_a_standby_that_forwards_enrols_its_admins_too(ha_env, db, tmp_path, monkeypatch, force_2fa):
    """While the standby hands its writes to the active, enrolment goes there like any
    other change: nobody skips it. Once it cannot (the active does not answer), the
    admin gets in again, as above."""
    from pegaprox.core import ha
    creds = _local_user(db, tmp_path, monkeypatch, 'breakglass', role='admin')
    _standby_of_active(ha_env, forward_writes=True)
    assert ha.forwarding() is True
    assert _login_and_check(ha_env.api, creds) == (True, True)
    assert _audit('ha.standby_2fa_skipped') == []
    ha._note_source_heard(A_ID, False)
    assert _login_and_check(ha_env.api, creds) == (False, False)
    assert len(_audit('ha.standby_2fa_skipped')) == 1


def test_everyone_else_still_enrols(ha_env, db, tmp_path, monkeypatch, force_2fa):
    """Counterproof: the same admin on an active or a standalone, and a non-admin on
    the standby, are still sent to the enrolment."""
    admin = _local_user(db, tmp_path, monkeypatch, 'breakglass', role='admin')
    user = _local_user(db, tmp_path, monkeypatch, 'ops', role='user')
    for role, peer in (('standalone', None), ('active', _peer_record())):
        _be(ha_env, role, peer=peer)
        assert _login_and_check(ha_env.api, admin) == (True, True), role
    _standby_of_active(ha_env)
    assert _login_and_check(ha_env.api, user) == (True, True)
    assert _audit('ha.standby_2fa_skipped') == []


# --- the IP allow list and the peer calls (Q4) --------------------------------------------

ADMIN_NET, ACTIVE_IP, STRANGER_IP = '10.20.0.0/24', '192.0.2.10', '203.0.113.50'
FROM_ACTIVE = f'{A_ID}:{PEER_SECRET}'       # what the active presents to this standby


@pytest.fixture
def allow_list(monkeypatch):
    """The active's list, synced here: the admin network, not the active itself."""
    import pegaprox.api.settings as st
    monkeypatch.setattr(st, '_ip_whitelist_enabled', True)
    monkeypatch.setattr(st, '_ip_whitelist', {ADMIN_NET})
    monkeypatch.setattr(st, '_ip_blacklist', set())


def _from(api, ip, method, path, header, **kw):
    h = {'X-Requested-With': 'XMLHttpRequest'}
    if header is not None:
        h['X-PegaProx-Peer'] = header
    return api.app.test_client().open(path, method=method, headers=h, base_url='http://localhost',
                                      environ_base={'REMOTE_ADDR': ip}, **kw)


def test_the_paired_instance_gets_past_the_list(ha_env, allow_list):
    ha, api = ha_env.ha, ha_env.api
    _standby_of_active(ha_env)
    r = _from(api, ACTIVE_IP, 'GET', '/api/ha/peer/status', FROM_ACTIVE)
    assert r.status_code == 200, r.data
    assert r.get_json()['role'] == 'standby'
    # so does its unpair notice, which is what lets this standby go
    r = _from(api, ACTIVE_IP, 'POST', '/api/ha/peer/unpaired', FROM_ACTIVE)
    assert r.status_code == 200 and r.get_json()['forgotten'] is True
    assert ha.peer() is None


def test_a_wrong_header_gets_the_list_and_is_counted(ha_env, allow_list):
    import pegaprox.api.ha as ha_api
    api = ha_env.api
    _standby_of_active(ha_env)
    for header in (None, '', f'{A_ID}:wrong', f'{B_ID}:{PEER_SECRET}'):
        r = _from(api, STRANGER_IP, 'GET', '/api/ha/peer/status', header)
        assert r.status_code == 403 and r.get_json()['error'] == 'Access denied', header
    for _ in range(6):
        _from(api, STRANGER_IP, 'POST', '/api/ha/peer/step-down', 'x:y', json={'epoch': 9})
    # ten failures: the address is at the same budget the peer routes keep
    assert ha_api._peer_failures.allow(STRANGER_IP) is False
    assert ha_api._peer_failures.allow(ACTIVE_IP) is True
    assert ha_env.ha.role() == 'standby' and ha_env.restarts == []


def test_the_list_still_guards_everything_else(ha_env, seed, allow_list):
    api = ha_env.api
    _standby_of_active(ha_env)
    # the right peer header opens /api/ha/peer/* and nothing next to it
    for method, path in (('GET', '/api/ha/status'), ('GET', '/api/users'),
                         ('GET', '/api/ha/peer'), ('GET', '/api/ha/peerstatus')):
        r = _from(api, ACTIVE_IP, method, path, FROM_ACTIVE)
        assert r.status_code == 403 and r.get_json()['error'] == 'Access denied', path
    # the pairing call has no peer header to show and stays behind the list
    _be(ha_env, 'standalone')
    info = ha_env.ha.decode_code(_code(_admin_from_the_admin_net(api, seed))['code'])
    r = _from(api, STRANGER_IP, 'POST', '/api/ha/peer/pair', FROM_ACTIVE,
              json=_pair_body(info['secret']))
    assert r.status_code == 403 and r.get_json()['error'] == 'Access denied'
    assert ha_env.ha.peer() is None
    # counterproof: from a listed address the same pairing goes through
    r = _from(api, '10.20.0.7', 'POST', '/api/ha/peer/pair', None, json=_pair_body(info['secret']))
    assert r.status_code == 200, r.data


def _admin_from_the_admin_net(api, seed):
    """_admin, but its requests come from the listed admin network."""
    c = _admin(api, seed)
    inner = c._call

    def call(method, path, write, headers=None, **kw):
        kw.setdefault('environ_base', {'REMOTE_ADDR': '10.20.0.5'})
        return inner(method, path, write, headers=headers, **kw)
    c._call = call
    return c


def test_without_the_list_nothing_changes(ha_env):
    """Counterproof: no list, the peer routes answer for themselves as before."""
    api = ha_env.api
    _standby_of_active(ha_env)
    assert _from(api, STRANGER_IP, 'GET', '/api/ha/peer/status', FROM_ACTIVE).status_code == 200
    r = _from(api, STRANGER_IP, 'GET', '/api/ha/peer/status', f'{A_ID}:wrong')
    assert r.status_code == 401 and r.get_json()['error'] == 'Not the paired instance'


# --- second review of the fix round -----------------------------------------------------

def test_a_blacklisted_address_stays_out_even_with_the_peer_header(ha_env, allow_list, monkeypatch):
    """The exception is for the allow list, where nobody lists the active's own
    address. A blacklist entry is an explicit no and stays one."""
    import pegaprox.api.settings as st
    monkeypatch.setattr(st, '_ip_blacklist', {ACTIVE_IP})
    _standby_of_active(ha_env)
    r = _from(ha_env.api, ACTIVE_IP, 'GET', '/api/ha/peer/status', FROM_ACTIVE)
    assert r.status_code == 403 and r.get_json()['error'] == 'Access denied', r.data
    # and the same header from a listed-nowhere address still passes, as decided
    monkeypatch.setattr(st, '_ip_blacklist', set())
    assert _from(ha_env.api, ACTIVE_IP, 'GET', '/api/ha/peer/status', FROM_ACTIVE).status_code == 200


def test_a_local_login_on_a_standby_writes_no_row(ha_env, seed, db, monkeypatch):
    """No login writes the synced users row on a standby: last_login would be put
    back by the next sync, and a password rehash came back as a changed hash that
    ended the user's sessions at every applied sync."""
    import pegaprox.api.auth as auth_api
    _admin(ha_env.api, seed)
    before = dict(db.get_user('root'))
    _standby_of_active(ha_env)
    monkeypatch.setattr(auth_api, 'needs_password_rehash', lambda *a: True)

    r = ha_env.api.anon().post('/api/auth/login', json={'username': 'root', 'password': ADMIN_PW})
    assert r.status_code == 200, r.data
    after = db.get_user('root')
    assert after['password_hash'] == before['password_hash']
    assert after.get('last_login') == before.get('last_login')


def test_the_same_login_on_an_active_still_rehashes_and_stamps(ha_env, seed, db, monkeypatch):
    import pegaprox.api.auth as auth_api
    _admin(ha_env.api, seed)
    before = dict(db.get_user('root'))
    monkeypatch.setattr(auth_api, 'needs_password_rehash', lambda *a: True)

    r = ha_env.api.anon().post('/api/auth/login', json={'username': 'root', 'password': ADMIN_PW})
    assert r.status_code == 200, r.data
    after = db.get_user('root')
    assert after['password_hash'] != before['password_hash']
    assert after.get('last_login') and after.get('last_login') != before.get('last_login')
