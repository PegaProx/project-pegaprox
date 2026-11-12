"""No new account takes a name the background jobs write audit entries under.

The audit scope matches a confined caller's own rows by name, and 'system', 'scheduler',
'installer' and 'unknown' are the names the scheduler, the HA and storage loops, the auto
installer and the session fallbacks of the routes write under. A tenant admin holding
admin.users and admin.audit could create such an account, and an LDAP or OIDC sign-in
created one for whoever the directory or the identity provider named that way.

POST /api/users refuses those names now, whoever asks, and a directory or identity provider
sign-in that would create such an account is refused with the reason. One that exists
already signs in as before.

MK Nov 2026
"""
import copy

import pytest

from pegaprox.utils.audit import AUDIT_PSEUDO_ACTORS


@pytest.fixture
def estate(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_a'])
    seed.tenant('tenant_b', clusters=['cluster_b'])
    return api


def _tenant_admin(seed, name='ta'):
    return seed.user(name, role='user', tenant_id='tenant_a',
                     permissions=['admin.users', 'admin.audit'])


# --- POST /api/users --------------------------------------------------------------------

@pytest.mark.parametrize('name', sorted(AUDIT_PSEUDO_ACTORS) + ['System'])
def test_a_tenant_admin_cannot_create_one_of_them(estate, seed, db, name):
    c = estate.as_user(_tenant_admin(seed))
    r = c.post('/api/users', json={'username': name, 'password': 'Planted-2026!x',
                                   'role': 'viewer', 'tenant_id': 'tenant_a'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'reserved' in r.get_json()['error']
    assert db.get_user(name.lower()) is None


def test_a_tenant_admin_still_creates_an_ordinary_account(estate, seed, db):
    c = estate.as_user(_tenant_admin(seed))
    r = c.post('/api/users', json={'username': 'carol', 'password': 'Planted-2026!x',
                                   'role': 'viewer', 'tenant_id': 'tenant_a'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('carol')['tenant_id'] == 'tenant_a'


def test_a_global_admin_cannot_create_one_either(estate, seed, db):
    c = estate.as_user(seed.user('root', role='admin'))
    body = {'password': 'Planted-2026!x', 'role': 'viewer', 'tenant_id': 'tenant_b'}
    r = c.post('/api/users', json=dict(body, username='system'))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'reserved' in r.get_json()['error']
    assert db.get_user('system') is None
    assert c.post('/api/users', json=dict(body, username='dave')).status_code == 200


# --- the directory and identity provider sign-ins ---------------------------------------

def _initialised(tmp_path, monkeypatch):
    import pegaprox.utils.auth as authmod
    marker = tmp_path / '.admin_initialized'
    marker.write_text('x')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', str(marker))


@pytest.fixture
def directory(api, tmp_path, monkeypatch):
    import pegaprox.api.auth as auth_api
    _initialised(tmp_path, monkeypatch)
    monkeypatch.setattr(auth_api, 'get_ldap_settings',
                        lambda: {'enabled': True, 'auto_create_users': True})

    def bind(username, password):
        return {'success': True, 'username': username, 'email': '',
                'display_name': username, 'role': 'viewer', 'tenant': '', 'permissions': [],
                'tenant_permissions': {}, 'groups': [], 'user_dn': f'CN={username},DC=corp',
                'auth_source': 'ldap'}
    monkeypatch.setattr(auth_api, 'ldap_authenticate', bind)
    return api


def _ldap_login(api, name):
    return api.anon().post('/api/auth/login', json={'username': name, 'password': 'from-the-directory'})


@pytest.mark.parametrize('name', ['system', 'Scheduler'])
def test_an_ldap_sign_in_does_not_create_one_of_them(directory, db, name):
    r = _ldap_login(directory, name)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'reserved' in r.get_json()['error']
    assert db.get_user(name.lower()) is None


def test_an_ldap_sign_in_of_an_ordinary_name_still_creates_it(directory, db):
    r = _ldap_login(directory, 'jdoe')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('jdoe')['auth_source'] == 'ldap'


def test_an_ldap_account_of_that_name_that_exists_signs_in_as_before(directory, db):
    db.save_user('system', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                            'tenant_id': 'default', 'enabled': True, 'auth_source': 'ldap'})
    r = _ldap_login(directory, 'system')
    assert r.status_code == 200, r.get_data(as_text=True)


OIDC_ON = {
    'enabled': True, 'provider': 'keycloak', 'client_id': 'pegaprox', 'auto_create_users': True,
    'redirect_uri': 'https://pegaprox.example/oidc/callback', 'default_role': 'viewer',
    'admin_group_id': '', 'user_group_id': '', 'viewer_group_id': '', 'group_mappings': [],
}


@pytest.fixture
def idp(api, monkeypatch):
    import pegaprox.api.auth as auth_api
    people = {}
    monkeypatch.setattr(auth_api, 'get_oidc_settings', lambda: copy.deepcopy(OIDC_ON))
    monkeypatch.setattr(auth_api, 'oidc_exchange_code',
                        lambda cfg, code, code_verifier=None: {'access_token': code, 'id_token': code})
    monkeypatch.setattr(auth_api, 'oidc_decode_id_token',
                        lambda token, expected_nonce=None, config=None: copy.deepcopy(people[token]))
    monkeypatch.setattr(auth_api, 'oidc_get_user_info', lambda cfg, token: {})
    monkeypatch.setattr(auth_api, 'oidc_get_user_groups_ex', lambda cfg, token: ([], False))
    return people


def _oidc_sign_in(api, code):
    import pegaprox.api.auth as auth_api
    for key in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(key, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    return browser.post('/api/auth/oidc/callback', json={'code': code, 'state': 'the-state'},
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                        base_url='http://localhost')


@pytest.mark.parametrize('name', ['system', 'Installer'])
def test_an_oidc_sign_in_does_not_create_one_of_them(api, db, idp, name):
    idp['x'] = {'sub': 'sub-x', 'preferred_username': name}
    r = _oidc_sign_in(api, 'x')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'reserved' in r.get_json()['error']
    assert db.get_user(name.lower()) is None


def test_an_oidc_sign_in_of_an_ordinary_name_still_creates_it(api, db, idp):
    idp['k'] = {'sub': 'sub-kim', 'preferred_username': 'kim'}
    r = _oidc_sign_in(api, 'k')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('kim')['oidc_sub'] == 'sub-kim'


def test_an_oidc_account_of_that_name_that_exists_signs_in_as_before(api, db, idp):
    db.save_user('system', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                            'tenant_id': 'default', 'enabled': True, 'auth_source': 'oidc',
                            'oidc_sub': 'sub-s'})
    idp['s'] = {'sub': 'sub-s', 'preferred_username': 'system'}
    r = _oidc_sign_in(api, 's')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['user'] == 'system'
