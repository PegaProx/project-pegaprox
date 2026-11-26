"""An account whose name has a slash in it can be edited and deleted (#1367).

Before #1141 an OIDC sign-in without a name claim stored its account as oidc_<first 12
chars of the sub>, and a sub can carry '/' and '+'. The user routes took the name as one
path segment, so PUT and DELETE /api/users/<name> answered Flask's HTML 404 for such an
account, encoded or not, and the user list showed only its generic error. Local names
cannot hold a slash (sanitize_username), so only these old accounts are concerned.

The routes with a fixed tail after the name (/password, /2fa, /oidc-binding, /permissions,
/vm-access, /tenant-permissions/<id>) take it as a path as well. Such an address can name
two accounts: /api/users/x/2fa is the 2FA route of x and the account x/2fa. werkzeug picks
the route; when another reading names an account the caller can see, the request is
refused with 409 and neither account changes.
"""
from urllib.parse import quote

import pytest

from tests.conftest import _seed_user

SLASHED = 'oidc_50g1L/K/o9+R'   # the shape of the accounts in the report


def _url(name):
    return '/api/users/' + quote(name, safe='')   # what the user list sends


@pytest.fixture
def admin(api, db):
    _seed_user(db, SLASHED, role='admin')
    return api.as_user(_seed_user(db, 'root', role='admin'))


def test_an_account_with_a_slash_is_edited(admin, db):
    r = admin.put(_url(SLASHED), json={'display_name': 'old sign-in', 'role': 'user'})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = db.get_user(SLASHED)
    assert row['display_name'] == 'old sign-in' and row['role'] == 'user'


def test_an_account_with_a_slash_is_disabled(admin, db):
    r = admin.put(_url(SLASHED), json={'enabled': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert not db.get_user(SLASHED)['enabled']


def test_an_account_with_a_slash_is_deleted(admin, db):
    r = admin.delete(_url(SLASHED))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user(SLASHED) is None
    assert db.get_user('root') is not None


def test_an_unknown_name_with_a_slash_is_a_json_404(admin):
    r = admin.delete(_url('oidc_nobody/here'))
    assert r.status_code == 404 and r.get_json() == {'error': 'User not found'}


def test_the_guards_still_stand_for_such_an_account(api, seed, db):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    _seed_user(db, SLASHED, role='admin', tenant_id='tenant_b')
    delegate = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users']))
    plain = api.as_user(seed.user('bob', role='user'))
    for client, status in ((delegate, 403), (plain, 403), (api.anon(), 401)):
        assert client.put(_url(SLASHED), json={'display_name': 'x'}).status_code == status
        assert client.delete(_url(SLASHED)).status_code == status
    row = db.get_user(SLASHED)
    assert row is not None and row['display_name'] != 'x'


@pytest.mark.parametrize('method,path,endpoint', [
    ('PUT', '/api/users/alice/password', 'users.admin_change_password'),
    ('PUT', '/api/users/alice/permissions', 'static_files.set_user_perms'),
    ('GET', '/api/users/alice/permissions', 'static_files.get_user_perms'),
    ('GET', '/api/users/alice/vm-access', 'static_files.get_user_vm_access'),
    ('DELETE', '/api/users/alice/2fa', 'users.admin_disable_2fa'),
    ('DELETE', '/api/users/alice/oidc-binding', 'users.reset_oidc_binding'),
    ('DELETE', '/api/users/alice/tenant-permissions/t1', 'static_files.remove_user_tenant_perms'),
    ('PUT', '/api/users/alice', 'users.update_user'),
    ('DELETE', '/api/users/alice', 'users.delete_user'),
])
def test_the_routes_under_an_account_keep_their_handler(api, method, path, endpoint):
    assert api.app.url_map.bind('localhost').match(path, method=method)[0] == endpoint


# --- the routes with a fixed tail (MK Nov 2026) ----------------------------------------

OLD_KEY = 'oidc_https://idp.example/abc'   # an account keyed on an issuer address
NEW_PASSWORD = 'Corr3ct-Horse-Battery!'


def _seed(db, name, **fields):
    _seed_user(db, name, role=fields.pop('role', 'user'), tenant_id=fields.pop('tenant_id', 'default'))
    if fields:
        row = db.get_user(name)
        row.update(fields)
        db.save_user(name, row)


@pytest.fixture
def root(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


@pytest.mark.parametrize('name', [SLASHED, OLD_KEY])
def test_a_slashed_account_gets_its_password_reset(root, db, name):
    _seed(db, name, auth_source='local')   # an old sign-in an admin switched to local
    r = root.put(_url(name) + '/password', json={'password': NEW_PASSWORD})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user(name)['password_hash'] != 'x'


@pytest.mark.parametrize('name', [SLASHED, OLD_KEY])
def test_a_slashed_account_has_its_2fa_cleared(root, db, name):
    _seed(db, name, totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    r = root.delete(_url(name) + '/2fa')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert not db.get_user(name)['totp_enabled']


def test_a_slashed_account_has_its_sign_in_binding_reset(root, db):
    _seed(db, OLD_KEY, auth_source='oidc', oidc_sub='sub-at-the-old-idp')
    r = root.delete(_url(OLD_KEY) + '/oidc-binding')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user(OLD_KEY)['oidc_sub'] == ''


def test_a_slashed_account_keyed_on_its_sub_reaches_the_binding_route(root, db):
    # found, and turned away by the route itself: it is named after its subject
    _seed(db, SLASHED, auth_source='entra', oidc_sub='50g1L/K/o9+R-rest')
    r = root.delete(_url(SLASHED) + '/oidc-binding')
    assert r.status_code == 400 and 'named after its identity provider subject' in r.get_json()['error']
    assert db.get_user(SLASHED)['oidc_sub'] == '50g1L/K/o9+R-rest'


@pytest.mark.parametrize('name', [SLASHED, OLD_KEY])
def test_a_slashed_account_has_its_permissions_read_and_set(root, db, name):
    _seed(db, name, tenant_permissions={'default': {'role': 'viewer', 'extra': [], 'denied': []}})
    r = root.get(_url(name) + '/permissions')
    assert r.status_code == 200 and r.get_json()['username'] == name, r.get_data(as_text=True)
    r = root.put(_url(name) + '/permissions', json={'permissions': ['vm.view'], 'denied_permissions': []})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user(name)['permissions'] == ['vm.view']
    r = root.get(_url(name) + '/vm-access')
    assert r.status_code == 200 and r.get_json() == [], r.get_data(as_text=True)
    r = root.delete(_url(name) + '/tenant-permissions/default')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'default' not in (db.get_user(name).get('tenant_permissions') or {})


def test_the_tail_routes_keep_their_guards_for_such_an_account(api, seed, db):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    _seed(db, OLD_KEY, tenant_id='tenant_b', totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    delegate = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users']))
    plain = api.as_user(seed.user('bob', role='user'))
    for client, status in ((delegate, 403), (plain, 403), (api.anon(), 401)):
        assert client.put(_url(OLD_KEY) + '/password', json={'password': NEW_PASSWORD}).status_code == status
        assert client.delete(_url(OLD_KEY) + '/2fa').status_code == status
    # the tenant delegate is told nothing about an account of another tenant
    assert delegate.get(_url(OLD_KEY) + '/permissions').status_code == 404
    row = db.get_user(OLD_KEY)
    assert row['password_hash'] == 'x' and row['totp_enabled']


# what makes each route change something on the account it reaches
_TWINS = {
    '/2fa': dict(totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP'),
    '/oidc-binding': dict(auth_source='oidc', oidc_sub='bound-sub'),
    '/tenant-permissions/default': dict(tenant_permissions={'default': {'role': 'viewer', 'extra': [], 'denied': []}}),
    '/password': dict(auth_source='local'),
    '/permissions': dict(),
}
_BODY = {'/password': {'password': NEW_PASSWORD}, '/permissions': {'permissions': ['vm.view'], 'denied_permissions': []}}


def _send(client, tail, url):
    method = 'put' if tail in _BODY else 'delete'
    return getattr(client, method)(url, json=_BODY.get(tail))


@pytest.mark.parametrize('encoded', [False, True], ids=['as-a-route', 'as-an-account'])
@pytest.mark.parametrize('tail', list(_TWINS))
def test_an_address_that_names_two_accounts_changes_neither(root, db, tail, encoded):
    for name in ('x', 'x' + tail):
        _seed(db, name, **_TWINS[tail])
    before = {name: db.get_user(name) for name in ('x', 'x' + tail)}
    r = _send(root, tail, _url('x' + tail) if encoded else '/api/users/x' + tail)
    assert r.status_code == 409, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'ACCOUNT_AMBIGUOUS'
    assert {name: db.get_user(name) for name in before} == before


@pytest.mark.parametrize('tail', ['/2fa', '/oidc-binding', '/tenant-permissions/default', '/password', '/permissions'])
def test_an_account_named_like_a_route_of_a_missing_one_is_left_alone(root, db, tail):
    # x/2fa alone: the address is still the 2FA route of x, and a request meant for
    # x - deleted a moment ago - must not land on x/2fa
    _seed(db, 'x' + tail, **_TWINS[tail])
    before = db.get_user('x' + tail)
    r = _send(root, tail, _url('x' + tail))
    assert r.status_code == 409 and r.get_json()['account'] == 'x' + tail, r.get_data(as_text=True)
    assert db.get_user('x' + tail) == before


def test_a_route_word_of_another_method_is_no_clash(root, db):
    # there is no PUT /2fa and no DELETE /password, so these name one account each
    _seed(db, 'x')
    _seed(db, 'x/2fa')
    _seed(db, 'x/password')
    r = root.put(_url('x/2fa'), json={'display_name': 'renamed'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('x/2fa')['display_name'] == 'renamed'
    r = root.delete(_url('x/password'))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('x/password') is None and db.get_user('x') is not None


def test_two_tail_routes_on_one_address_change_neither(root, db):
    # the tenant-permissions route of x for a tenant called 2fa, or the 2FA route of
    # the account x/tenant-permissions
    _seed(db, 'x', tenant_permissions={'2fa': {'role': 'viewer', 'extra': [], 'denied': []}})
    _seed(db, 'x/tenant-permissions', totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    before = {name: db.get_user(name) for name in ('x', 'x/tenant-permissions')}
    r = root.delete('/api/users/x/tenant-permissions/2fa')
    assert r.status_code == 409, r.get_data(as_text=True)
    assert {name: db.get_user(name) for name in before} == before


def test_an_account_of_another_tenant_neither_blocks_nor_shows(api, root, seed, db):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    _seed(db, 'x', tenant_id='tenant_a')
    _seed(db, 'x/password', tenant_id='tenant_b')
    delegate = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users']))
    r = delegate.put('/api/users/x/password', json={'password': NEW_PASSWORD})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'x/password' not in r.get_data(as_text=True)
    assert db.get_user('x')['password_hash'] != 'x'
    # a global admin sees both accounts, and is asked which one it means
    assert root.put('/api/users/x/password', json={'password': NEW_PASSWORD}).status_code == 409


def test_an_install_without_such_names_is_answered_as_before(root, db):
    _seed(db, 'carol', totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    assert root.put('/api/users/carol/password', json={'password': NEW_PASSWORD}).status_code == 200
    assert root.delete('/api/users/carol/2fa').status_code == 200
    assert root.put('/api/users/carol/permissions', json={'permissions': [], 'denied_permissions': []}).status_code == 200
    assert root.delete('/api/users/nobody/2fa').get_json() == {'error': 'User not found'}
    assert root.put('/api/users/nobody/password', json={'password': NEW_PASSWORD}).status_code == 404


def test_every_route_under_users_takes_the_name_as_a_path_and_is_guarded(api):
    from pegaprox.api.helpers import ACCOUNT_ROUTE_TAILS
    prefix = '/api/users/<path:username>'
    seen = {}
    for rule in api.app.url_map.iter_rules():
        if not rule.rule.startswith('/api/users/'):
            continue
        assert rule.rule.startswith(prefix), rule.rule
        assert getattr(api.app.view_functions[rule.endpoint], '_pp_account_route', False), rule.endpoint
        for method in rule.methods - {'HEAD', 'OPTIONS'}:
            seen.setdefault(method, set()).add(rule.rule[len(prefix):])
    assert seen == {method: set(tails) for method, tails in ACCOUNT_ROUTE_TAILS.items()}


@pytest.mark.parametrize('name', ['alice', SLASHED, OLD_KEY, 'x/2fa'])
def test_the_readings_are_the_ones_werkzeug_matches(api, name):
    from pegaprox.api.helpers import ACCOUNT_ROUTE_TAILS, account_route_readings
    adapter = api.app.url_map.bind('localhost')
    for method, tails in ACCOUNT_ROUTE_TAILS.items():
        for tail in tails:
            path = '/api/users/' + name + tail.replace('<tenant_id>', 't1')
            readings = account_route_readings(method, path)
            # the name as sent is one reading, and so is the one werkzeug routes to
            assert name in readings, (method, path)
            assert adapter.match(path, method=method)[1]['username'] in readings, (method, path)


def test_the_frontend_encodes_the_name_in_every_user_route():
    # the slashes of the name must not become path segments of another route (#1367)
    import glob
    import os
    import re
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web', 'src')
    calls = []
    for path in sorted(glob.glob(os.path.join(src, '*.js'))):
        with open(path, encoding='utf-8') as fh:
            calls += [(os.path.basename(path), m.group(1)) for m in re.finditer(r'/users/\$\{([^}]*)\}', fh.read())]
    assert len(calls) >= 7, calls
    assert [c for c in calls if not c[1].startswith('encodeURIComponent(')] == []
