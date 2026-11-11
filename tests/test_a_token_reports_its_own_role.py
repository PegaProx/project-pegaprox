"""An API token is told its own role, not the role its owner holds through an override.

/api/me/permissions swapped the token's role into the record and asked
get_user_effective_role, which reads the owner's tenant override before any role. So
a viewer token of an owner with an admin override was told effective_role 'admin',
next to a permission list that was correctly the viewer's. /api/me/tenants did not
even swap the role: an admin's viewer token was told 'admin' in every tenant.

Neither answer decides access - the gates read the capped permission list - but an
API client or a UI that goes by effective_role offers what the backend then refuses.
Now a token reports its owner's role in that tenant where that role grants nothing the
token's role does not, and its own role otherwise; for the builtins that is the lower
of the two, and a custom role on either side is compared by what it grants. And
/api/me/permissions does not hand a token its owner's overrides. A session user is
answered as before.

MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.utils.auth import create_api_token

DEFAULT = rbac.DEFAULT_TENANT_ID


@pytest.fixture(autouse=True)
def _tenants(seed):
    seed.tenant(DEFAULT, [])
    seed.tenant('acme', [])
    seed.tenant('beta', [])
    rbac.invalidate_tenants_cache()


def _token(owner, role):
    res = create_api_token(owner, 'ci', role=role)
    assert res.get('token'), res
    return res['token']


def _get(api, token, path):
    r = api.anon().get(path, headers={'Authorization': f'Bearer {token}'})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def _viewer_perms():
    return set(rbac.get_role_permissions_for_user({'role': 'viewer'}))


# --- /api/me/permissions ---------------------------------------------------------------

@pytest.mark.parametrize('owner_role,override,token_role,tenant,want', [
    ('admin', {DEFAULT: {'role': 'admin'}}, 'viewer', DEFAULT, 'viewer'),
    ('user', {DEFAULT: {'role': 'user'}}, 'viewer', DEFAULT, 'viewer'),
    ('admin', {'acme': {'role': 'admin'}}, 'viewer', 'acme', 'viewer'),
    ('admin', {'acme': {'role': 'admin'}}, 'user', 'acme', 'user'),
])
def test_a_token_is_not_told_its_owners_override_role(api, seed, owner_role, override,
                                                       token_role, tenant, want):
    owner = seed.user('owen', role=owner_role, tenant_permissions=override)
    token = _token('owen', token_role)

    own = api.as_user(owner).get(f'/api/me/permissions?tenant_id={tenant}').get_json()
    assert own['effective_role'] == override[tenant]['role'], 'the owner holds the override'

    body = _get(api, token, f'/api/me/permissions?tenant_id={tenant}')

    assert body['role'] == token_role
    assert body['effective_role'] == want, body


def test_a_token_takes_the_lower_role_where_its_owner_holds_less(api, seed):
    """The other direction stays: an override that lowers the owner lowers the token."""
    seed.user('owen', role='admin', tenant_permissions={'acme': {'role': 'viewer'},
                                                        'beta': {'role': 'admin'}})
    token = _token('owen', 'user')

    acme = _get(api, token, '/api/me/permissions?tenant_id=acme')
    beta = _get(api, token, '/api/me/permissions?tenant_id=beta')

    assert acme['effective_role'] == 'viewer', acme
    assert set(acme['permissions']) <= _viewer_perms()
    assert beta['effective_role'] == 'user', beta


def test_a_custom_token_role_keeps_its_name(api, seed, db):
    db.conn.execute("INSERT OR REPLACE INTO custom_roles "
                    "(name, permissions, description, tenant_id, created_at) VALUES (?,?,?,?,?)",
                    ('ops', json.dumps(['vm.view', 'vm.start']), 'ops', '', '2026-01-01'))
    db.conn.commit()
    rbac.invalidate_roles_cache()
    seed.user('owen', role='admin', tenant_permissions={DEFAULT: {'role': 'admin'}})
    token = _token('owen', 'ops')

    body = _get(api, token, '/api/me/permissions')

    assert body['effective_role'] == 'ops', body


def test_a_token_is_not_handed_its_owners_overrides(api, seed):
    override = {'acme': {'role': 'admin', 'extra': ['admin.users']}}
    owner = seed.user('owen', role='admin', tenant_permissions=override)
    token = _token('owen', 'viewer')

    assert api.as_user(owner).get('/api/me/permissions').get_json()['tenant_permissions'] == override
    assert _get(api, token, '/api/me/permissions')['tenant_permissions'] == {}


# --- /api/me/tenants -------------------------------------------------------------------

def test_the_tenant_list_tells_a_token_its_own_role(api, seed):
    owner = seed.user('owen', role='admin', tenant_permissions={'acme': {'role': 'admin'}})
    token = _token('owen', 'viewer')

    own = api.as_user(owner).get('/api/me/tenants').get_json()
    assert {t['effective_role'] for t in own['tenants']} == {'admin'}

    body = _get(api, token, '/api/me/tenants')

    assert {t['id'] for t in body['tenants']} == {DEFAULT, 'acme'}
    assert {t['effective_role'] for t in body['tenants']} == {'viewer'}, body


# --- a custom role held in the tenant --------------------------------------------------

@pytest.mark.parametrize('token_role,want,perms', [
    ('admin', 'ops', {'vm.view', 'vm.start'}),
    ('user', 'ops', {'vm.view', 'vm.start'}),
    ('viewer', 'viewer', {'vm.view'}),
])
def test_a_custom_role_the_owner_holds_there_is_compared_by_what_it_grants(api, seed, db,
                                                                          token_role, want, perms):
    """The owner holds the custom role 'ops' of acme there. A token whose role grants all
    of it acts as 'ops', so it is told 'ops': an admin token told 'admin' next to the two
    permissions of 'ops' was the same mismatch again. A viewer token cannot start a VM,
    'ops' is not inside it, so it stays 'viewer'."""
    db.conn.execute("INSERT OR REPLACE INTO custom_roles "
                    "(name, permissions, description, tenant_id, created_at) VALUES (?,?,?,?,?)",
                    ('ops', json.dumps(['vm.view', 'vm.start']), 'ops', 'acme', '2026-01-01'))
    db.conn.commit()
    rbac.invalidate_roles_cache()
    seed.user('owen', role='admin', tenant_permissions={'acme': {'role': 'ops'}})
    token = _token('owen', token_role)

    body = _get(api, token, '/api/me/permissions?tenant_id=acme')
    tenants = {t['id']: t['effective_role'] for t in _get(api, token, '/api/me/tenants')['tenants']}

    assert set(body['permissions']) == perms, body
    assert body['effective_role'] == want, body
    assert tenants['acme'] == want, tenants
