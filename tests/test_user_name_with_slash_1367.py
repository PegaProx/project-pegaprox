"""An account whose name has a slash in it can be edited and deleted (#1367).

Before #1141 an OIDC sign-in without a name claim stored its account as oidc_<first 12
chars of the sub>, and a sub can carry '/' and '+'. The user routes took the name as one
path segment, so PUT and DELETE /api/users/<name> answered Flask's HTML 404 for such an
account, encoded or not, and the user list showed only its generic error. Local names
cannot hold a slash (sanitize_username), so only these old accounts are concerned.
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
