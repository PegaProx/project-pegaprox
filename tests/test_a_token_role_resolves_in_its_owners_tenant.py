"""An API token's custom role resolves in its owner's tenant, and nowhere else.

A custom role is looked up by name, and _tenant_defining_role moves a default-tenant
caller into whichever tenant defines that name. For an account an administrator placed on
a tenant role that is the point: the account lives in that tenant. A token's role is
picked by the token's owner, though. create_api_token compared permissions in the owner's
own tenant, where another tenant's role resolves to nothing, so "nothing beyond your own
role" held for every such name. At request time the token was remapped into the tenant
that defines the role, and get_user_clusters handed it that tenant's clusters while its
owner was confined to the default tenant's list.

Three parts to the fix:
  * minting refuses a role that does not resolve where its owner does (token_role_tenant)
  * every use refuses it again (validate_api_token): tokens minted before the check, an
    owner moved off the role since, a role deleted or defined elsewhere since
  * a token reaches no cluster its owner cannot (#1049), which also keeps a builtin-role
    token of a tenant-role holder inside her tenant

NS Oct 2026, Aikido ai_pentest 797414256.
"""
import json
from datetime import datetime

import pytest

import pegaprox.utils.auth as authmod
import pegaprox.utils.rbac as rbac

PERMS = ['vm.view', 'cluster.view']


def _role(db, name, tenant_id=''):
    db.conn.execute(
        "INSERT INTO custom_roles (name, permissions, description, tenant_id, created_at) "
        "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00')",
        (name, json.dumps(PERMS), name, tenant_id))
    db.conn.commit()
    rbac.invalidate_roles_cache()


@pytest.fixture
def estate(db, seed):
    """The default tenant is confined to c_home. tenant_a owns c_a and defines a-ops,
    tenant_b owns c_b and defines b-ops, g-ops is global.

    mallory  a plain user in the default tenant
    bea      in the default tenant on b-ops, put there by an admin: she lives in tenant_b
    alma     a user placed in tenant_a
    root     a global admin
    """
    seed.tenant(rbac.DEFAULT_TENANT_ID, ['c_home'])
    seed.tenant('tenant_a', ['c_a'])
    seed.tenant('tenant_b', ['c_b'])
    _role(db, 'a-ops', 'tenant_a')
    _role(db, 'b-ops', 'tenant_b')
    _role(db, 'g-ops')
    for table in ('cost_rates', 'power_rates'):
        for cid in ('c_home', 'c_a', 'c_b'):
            db.conn.execute(f"INSERT OR IGNORE INTO {table} (cluster_id, updated_at) VALUES (?, ?)",
                            (cid, datetime.now().isoformat()))
    db.conn.commit()
    rbac.invalidate_tenants_cache()
    return {
        'mallory': seed.user('mallory', role='user'),
        'bea': seed.user('bea', role='b-ops'),
        'alma': seed.user('alma', role='user', tenant_id='tenant_a'),
        'root': seed.user('root', role='admin'),
    }


def _unconfine_default(seed):
    seed.tenant(rbac.DEFAULT_TENANT_ID, [])
    rbac.invalidate_tenants_cache()


def _plant(db, username, role):
    """A token row exactly as create_api_token writes it: one minted before the check
    existed, or under a configuration that has changed since."""
    authmod.ensure_api_tokens_table()
    token, token_hash, prefix = authmod.generate_api_token()
    db.conn.execute(
        "INSERT INTO api_tokens (token_hash, token_prefix, username, name, role, permissions, "
        "expires_at, created_at) VALUES (?, ?, ?, 'planted', ?, '[]', NULL, ?)",
        (token_hash, prefix, username, role, datetime.now().isoformat()))
    db.conn.commit()
    return token


def _mint(api, user, **body):
    return api.as_user(user).post('/api/auth/tokens', json={'name': 'ci', **body})


def _bearer(api, token, path, method='get'):
    return getattr(api.anon(), method)(path, headers={'Authorization': f'Bearer {token}'})


def _reach(api, token):
    return [c for c in ('c_home', 'c_a', 'c_b')
            if _bearer(api, token, f'/api/cost/rates/{c}').status_code == 200]


# --- minting -------------------------------------------------------------------------

def test_a_role_of_another_tenant_is_refused_at_mint(estate):
    """The finding: mallory sits in the default tenant and names tenant_b's role."""
    res = authmod.create_api_token('mallory', 'ci', role='b-ops')
    assert 'error' in res and not res.get('token'), res


def test_the_token_route_refuses_it_and_stores_nothing(api, estate):
    r = _mint(api, estate['mallory'], role='b-ops')
    assert r.status_code == 400, r.get_json()
    assert 'tenant' in r.get_json()['error']
    assert authmod.list_user_tokens('mallory') == []


def test_an_unconfined_default_tenant_does_not_open_it_either(seed, estate):
    """Nothing to widen in cluster terms, but the role still belongs to tenant_b."""
    _unconfine_default(seed)
    assert 'error' in authmod.create_api_token('mallory', 'ci', role='b-ops')


def test_a_tenant_user_cannot_borrow_another_tenants_role(estate):
    assert 'error' in authmod.create_api_token('alma', 'ci', role='b-ops')


def test_a_name_both_global_and_of_another_tenant_carries_no_token_out(api, db, estate):
    """Whether such a name resolves globally or in tenant_b is the remap's business; a
    token of mallory's reaches nothing she cannot either way."""
    _role(db, 'ops')
    _role(db, 'ops', 'tenant_b')
    res = authmod.create_api_token('mallory', 'ci', role='ops')
    reach = _reach(api, res['token']) if res.get('token') else []
    assert set(reach) <= {'c_home'}, reach


def test_a_role_that_does_not_exist_is_refused(estate):
    """Used to mint a token that resolved to nothing at all."""
    assert 'error' in authmod.create_api_token('mallory', 'ci', role='no-such-role')


@pytest.mark.parametrize('role', ['b-ops ', 'B-OPS', 'b-ops​', 'Viewer', 'admin '])
def test_a_near_spelling_of_a_role_is_no_role(estate, role):
    """Roles are matched by exact name, nothing is normalised on the way in."""
    assert 'error' in authmod.create_api_token('mallory', 'ci', role=role)


@pytest.mark.parametrize('role', [['b-ops'], {'b-ops': True}])
def test_a_role_that_is_no_string_is_refused_not_a_crash(api, estate, role):
    """A list or an object where the role name goes ended in a TypeError and a 500."""
    r = _mint(api, estate['mallory'], role=role)
    assert r.status_code == 400, r.get_json()
    assert authmod.list_user_tokens('mallory') == []


@pytest.mark.parametrize('owner,role', [
    ('bea', None),          # her own role, the default when none is named
    ('bea', 'b-ops'),       # the same, named
    ('alma', 'a-ops'),      # a role of the tenant she is placed in
    ('mallory', 'g-ops'),   # a global role
    ('mallory', 'viewer'),  # builtin roles are not affected
    ('root', 'b-ops'),      # a global admin is not confined to a tenant
])
def test_roles_the_owner_may_carry_still_mint(estate, owner, role):
    res = authmod.create_api_token(owner, 'ci', role=role)
    assert res.get('success') and res.get('token'), res


def test_the_route_still_mints_an_own_tenant_role(api, estate):
    r = _mint(api, estate['alma'], role='a-ops')
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['role'] == 'a-ops'


# --- every use -----------------------------------------------------------------------

def test_a_token_minted_before_the_check_is_refused_on_use(api, db, estate):
    """The token reached tenant_b's cluster that its owner never could."""
    token = _plant(db, 'mallory', 'b-ops')
    r = _bearer(api, token, '/api/cost/rates/c_b')
    assert r.status_code == 401, r.get_json()


def test_such_a_token_is_refused_outright_not_rescoped(api, db, estate):
    token = _plant(db, 'mallory', 'b-ops')
    assert _bearer(api, token, '/api/cost/rates/c_home').status_code == 401


def test_the_owner_moved_off_the_role_takes_the_token_with_them(api, seed, estate):
    """#1049: bea minted b-ops while she held it, then an admin put her on `user`."""
    token = _mint(api, estate['bea']).get_json()['token']
    assert _bearer(api, token, '/api/cost/rates/c_b').status_code == 200
    seed.user('bea', role='user')
    assert _bearer(api, token, '/api/cost/rates/c_b').status_code == 401


def test_a_deleted_role_takes_its_tokens_with_it(api, db, estate):
    """#1061: a deleted role granted nothing, but its token kept the tenant's clusters."""
    token = _mint(api, estate['alma'], role='a-ops').get_json()['token']
    db.conn.execute("DELETE FROM custom_roles WHERE name = 'a-ops'")
    db.conn.commit()
    rbac.invalidate_roles_cache()
    assert _bearer(api, token, '/api/cost/rates/c_a').status_code == 401


def test_a_session_of_the_same_owner_is_untouched(api, db, estate):
    """Only the token is refused; the account keeps working."""
    _plant(db, 'mallory', 'b-ops')
    r = api.as_user(estate['mallory']).get('/api/cost/rates/c_home')
    assert r.status_code == 200


@pytest.mark.parametrize('owner,role,reach', [
    ('bea', 'b-ops', ['c_b']),
    ('alma', 'a-ops', ['c_a']),
    ('mallory', 'g-ops', ['c_home']),
    ('root', 'b-ops', ['c_b']),        # an admin's tenant-role token is narrowed, as before
    ('root', 'viewer', ['c_home']),    # an admin's viewer token, as before (#491)
])
def test_legitimate_tokens_keep_their_scope(api, estate, owner, role, reach):
    token = authmod.create_api_token(owner, 'ci', role=role)['token']
    assert _reach(api, token) == reach


# --- a token reaches no cluster its owner cannot (#1049) -----------------------------

def test_a_builtin_token_of_a_tenant_role_holder_stays_in_her_tenant(api, seed, estate):
    """bea lives in tenant_b through her role. A viewer token resolves a builtin role,
    which is never remapped, so it landed in the default tenant: everything, when that
    tenant has no cluster list."""
    _unconfine_default(seed)
    token = authmod.create_api_token('bea', 'ci', role='viewer')['token']
    assert _reach(api, token) == ['c_b']


@pytest.mark.parametrize('path', ['/api/cost/rates', '/api/power/rates'])
def test_the_rate_lists_are_cut_to_the_owner(api, seed, estate, path):
    """Both put the token's role in place of the owner's, so the cut had nothing to cut to."""
    _unconfine_default(seed)
    token = authmod.create_api_token('bea', 'ci', role='viewer')['token']
    r = _bearer(api, token, path)
    assert r.status_code == 200
    assert sorted(x['cluster_id'] for x in r.get_json()['rates']) == ['__default__', 'c_b']


@pytest.mark.parametrize('path', ['/api/cost/rates', '/api/power/rates'])
def test_the_rate_lists_still_scope_a_session_and_an_admin_viewer_token(api, estate, path):
    r = api.as_user(estate['mallory']).get(path)
    assert sorted(x['cluster_id'] for x in r.get_json()['rates']) == ['__default__', 'c_home']
    r = api.as_user(estate['root']).get(path)
    assert sorted(x['cluster_id'] for x in r.get_json()['rates']) == \
        ['__default__', 'c_a', 'c_b', 'c_home']
    token = authmod.create_api_token('root', 'ci', role='viewer')['token']
    r = _bearer(api, token, path)
    assert sorted(x['cluster_id'] for x in r.get_json()['rates']) == ['__default__', 'c_home']


def test_the_sse_token_carries_the_owners_scope(api, seed, estate):
    from pegaprox.utils.realtime import validate_sse_token
    _unconfine_default(seed)
    token = authmod.create_api_token('bea', 'ci', role='viewer')['token']
    r = _bearer(api, token, '/api/sse/token', method='post')
    assert r.status_code == 200, r.get_json()
    assert validate_sse_token(r.get_json()['token'])['allowed_clusters'] == ['c_b']


def _stream(api, sse_token):
    """The registry entry of a stream opened with `sse_token`, as it starts."""
    import pegaprox.api.realtime as rt
    import pegaprox.globals as ppglobals
    ppglobals.sse_clients.clear()
    try:
        with api.app.test_request_context(f'/api/sse/updates?token={sse_token}'):
            resp = rt.sse_updates()
        assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
        (client,) = ppglobals.sse_clients.values()
        return dict(client)
    finally:
        ppglobals.sse_clients.clear()


def _stream_clusters(api, sse_token):
    return _stream(api, sse_token)['clusters']


def test_a_stream_from_an_older_sse_token_starts_in_the_owners_scope(api, seed, estate):
    """An SSE token can be reused for its whole TTL and carries the cluster list of the
    moment it was minted. bea's b-ops token got one, then an admin moved her off the role,
    so the token itself is refused now. Every stream that SSE token opened still started
    on c_b, until the re-check 30s later."""
    token = _mint(api, estate['bea']).get_json()['token']
    sse = _bearer(api, token, '/api/sse/token', method='post').get_json()['token']
    assert _stream_clusters(api, sse) == ['c_b']
    seed.user('bea', role='user')
    assert _bearer(api, token, '/api/cost/rates/c_b').status_code == 401
    assert _stream_clusters(api, sse) == []


def test_a_stream_from_an_older_admin_sse_token_starts_as_the_demoted_owner(api, seed, estate):
    """The same for an admin token's SSE token: the stream started unrestricted and with
    the per-VM filters off, though its owner had been demoted to a confined user."""
    token = authmod.create_api_token('root', 'ci', role='admin')['token']
    sse = _bearer(api, token, '/api/sse/token', method='post').get_json()['token']
    seed.user('root', role='user')
    client = _stream(api, sse)
    assert client['clusters'] == ['c_home']
    assert client['is_admin'] is False


def test_a_stream_from_a_current_sse_token_keeps_its_scope(api, seed, estate):
    _unconfine_default(seed)
    token = authmod.create_api_token('bea', 'ci', role='viewer')['token']
    sse = _bearer(api, token, '/api/sse/token', method='post').get_json()['token']
    assert _stream_clusters(api, sse) == ['c_b']
    token = authmod.create_api_token('root', 'ci', role='admin')['token']
    sse = _bearer(api, token, '/api/sse/token', method='post').get_json()['token']
    assert _stream_clusters(api, sse) is None


def test_an_identity_rebuilt_from_a_stored_role_is_cut_too(estate):
    """The SSE stream and the ws paths rebuild a token identity from the stored record
    and the minted role, without passing validate_api_token again."""
    ident = dict(estate['mallory'], effective_role='b-ops')
    assert rbac.get_user_clusters(ident) == []


def test_session_identities_are_unchanged(estate):
    assert rbac.get_user_clusters(estate['mallory']) == ['c_home']
    assert rbac.get_user_clusters(estate['bea']) == ['c_b']
    assert rbac.get_user_clusters(estate['alma']) == ['c_a']
    assert rbac.get_user_clusters(estate['root']) is None
