"""An API token gets what its own role grants, of what its owner holds - on every gate.

require_auth built its own identity for a token on perms= routes and capped the owner's
tenant override only by builtin level. A custom tenant role scores level 1, so it went
through whole: a token scoped to viewer passed admin.users wherever its owner's override
named a custom role holding it, and the override's extra grants came along the same way.
A token bound to a custom role was judged as a plain viewer instead - its owner could be
refused a route the token then passed.

The object checks behind build_authz_user had the twin of the extras gap: the owner's
global extra grants extended to a token whose role matched the stored one. Both now go
through one function. (#1014) MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.utils.auth import create_api_token


def _role(db, name, perms, tenant=''):
    db.conn.execute("INSERT OR REPLACE INTO custom_roles "
                    "(name, permissions, description, tenant_id, created_at) VALUES (?,?,?,?,?)",
                    (name, json.dumps(perms), name, tenant, '2026-01-01'))
    db.conn.commit()
    rbac.invalidate_roles_cache()


def _token(owner, role=None):
    res = create_api_token(owner, 'ci', role=role)
    assert res.get('token'), res
    return res['token']


def _get(api, token, path):
    return api.anon().get(path, headers={'Authorization': f'Bearer {token}'})


# --- the finding ---------------------------------------------------------------------

def test_a_viewer_token_does_not_carry_its_owners_custom_tenant_role(api, seed, db):
    _role(db, 'ops', ['vm.view', 'admin.users'])
    owner = seed.user('owner', role='user', tenant_permissions={'default': {'role': 'ops'}})
    token = _token('owner', role='viewer')

    assert api.as_user(owner).get('/api/users').status_code == 200, \
        'the owner holds admin.users through the override, or this proves nothing'
    r = _get(api, token, '/api/users')

    assert r.status_code == 403, 'a viewer token listed the accounts through its owner\'s tenant role'
    assert r.get_json()['required'] == 'admin.users'


def test_a_viewer_token_does_not_carry_the_extras_of_a_tenant_override(api, seed, db):
    owner = seed.user('owner', role='user', tenant_permissions={
        'default': {'role': 'viewer', 'extra': ['admin.users']}})
    token = _token('owner', role='viewer')

    assert api.as_user(owner).get('/api/users').status_code == 200
    assert _get(api, token, '/api/users').status_code == 403


def test_a_custom_role_token_is_not_judged_as_a_viewer(api, seed, db):
    """The owner is refused pbs.view; the token their role defaulted to was let in."""
    _role(db, 'vm_only', ['vm.view'])
    owner = seed.user('owner', role='vm_only')
    token = _token('owner')

    assert api.as_user(owner).get('/api/pbs').status_code == 403
    assert _get(api, token, '/api/pbs').status_code == 403, 'the token outranked its owner'


def test_the_owners_global_extras_do_not_reach_a_token_on_the_object_path(api, seed, db):
    """build_authz_user path: admin.api as an extra grant on a viewer account lists every
    token for the owner, and listed them for the owner's viewer token as well."""
    owner = seed.user('owner', role='viewer', permissions=['admin.api'])
    seed.user('other', role='user')
    _token('other')
    token = _token('owner', role='viewer')

    by_owner = api.as_user(owner).get('/api/auth/tokens?all=true').get_json()['tokens']
    by_token = _get(api, token, '/api/auth/tokens?all=true').get_json()['tokens']

    assert {t['username'] for t in by_owner} == {'owner', 'other'}
    assert {t.get('username', 'owner') for t in by_token} == {'owner'}, \
        'a viewer token read every token on the install'


# --- what keeps working ----------------------------------------------------------------

def test_a_custom_role_token_reaches_what_its_role_grants(api, seed, db):
    """Judged as a viewer, this token was refused admin.users its role exists for."""
    _role(db, 'account_desk', ['admin.users'])
    seed.user('owner', role='admin')
    token = _token('owner', role='account_desk')

    assert _get(api, token, '/api/users').status_code == 200
    assert _get(api, token, '/api/pbs').status_code == 403


def test_a_custom_role_token_stays_under_a_demoted_owner(api, seed, db):
    _role(db, 'account_desk', ['admin.users'])
    seed.user('owner', role='admin')
    token = _token('owner', role='account_desk')
    rec = db.get_user('owner')
    rec['role'] = 'viewer'
    db.save_user('owner', rec)

    assert _get(api, token, '/api/users').status_code == 403


@pytest.mark.parametrize('owner_role,token_role,path,status', [
    ('admin', 'admin', '/api/users', 200),
    ('admin', None, '/api/users', 200),
    ('admin', 'viewer', '/api/pbs', 200),
    ('admin', 'viewer', '/api/users', 403),
    ('user', 'user', '/api/pbs', 200),
    ('viewer', None, '/api/pbs', 200),
])
def test_the_builtin_roles_keep_their_answers(api, seed, owner_role, token_role, path, status):
    seed.user('owner', role=owner_role)
    token = _token('owner', role=token_role)

    assert _get(api, token, path).status_code == status


def test_an_owner_denial_still_reaches_the_token(api, seed):
    seed.user('owner', role='user', denied=['pbs.view'])
    token = _token('owner', role='user')

    assert _get(api, token, '/api/pbs').status_code == 403


def test_a_tenant_override_still_lowers_an_admin_token(api, seed, db):
    """An admin the directory maps down to viewer in their own tenant: the admin token
    follows the override, as before."""
    seed.user('owner', role='admin', tenant_permissions={'default': {'role': 'viewer'}})
    token = _token('owner', role='admin')

    assert _get(api, token, '/api/users').status_code == 403
    assert _get(api, token, '/api/pbs').status_code == 200


def test_a_scrape_role_token_still_reads_the_metrics(api, seed, db):
    """#818 through a role, not mocked: the way a Prometheus token gets metrics.view now
    that an extra grant on the account no longer reaches the token."""
    _role(db, 'scrape', ['metrics.view'])
    seed.user('prom', role='scrape')
    seed.user('root', role='admin')

    assert _get(api, _token('prom'), '/api/metrics').status_code == 200
    assert _get(api, _token('root', role='scrape'), '/api/metrics').status_code == 200
    assert _get(api, _token('root', role='viewer'), '/api/metrics').status_code == 401


def test_a_signed_in_session_keeps_its_extras(api, seed):
    """The cap is the token's alone: the owner's own session keeps the extra grant."""
    owner = seed.user('owner', role='viewer', permissions=['admin.users'])

    assert api.as_user(owner).get('/api/users').status_code == 200
