"""admin.api and node.shell are delegations, and a delegate stays inside their tenant.

Both are admin-only builtin permissions, so a non-admin can only ever hold them through
a custom role - which is by definition a tenant delegation. Neither route asked which
tenant:

  * GET /api/auth/tokens?all=true returned every token in the installation: owner,
    prefix, role, permission list and last-used IP, for every tenant.
  * DELETE /api/auth/tokens/<id> revoked any of them, which is an availability attack on
    another customer's automation.
  * /api/internal/cluster-creds/<cluster> hands back a root shell credential for a
    hypervisor node. It stopped at check_cluster_access, which deliberately admits a
    caller who reached the cluster only through a VM ACL or a pool grant, and it read the
    caller's permissions off the STORED account - so an admin-owned token capped at
    viewer was handed its owner's node.shell.

Aikido ai_pentest 700489476 / 700489221. MK
"""
import contextlib

import pytest

import pegaprox.api.auth as authapi


@contextlib.contextmanager
def _ctx(api, session, query=''):
    from flask import request as _rq
    with api.app.test_request_context('/' + query, base_url='http://localhost'):
        _rq.session = session
        yield


def _handler(name):
    fn = getattr(authapi, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


@pytest.fixture
def estate(api, seed):
    """Two tenants, one token each, and a delegate in tenant_a holding admin.api."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    seed.user('ann', role='user', tenant_id='tenant_a', permissions=['admin.api'])
    seed.user('bert', role='user', tenant_id='tenant_b')
    seed.user('root9', role='admin')

    authapi.ensure_api_tokens_table()
    db = seed.db
    for tid, owner in ((1, 'ann'), (2, 'bert')):
        db.execute('''INSERT INTO api_tokens (id, token_prefix, token_hash, username, name,
                      role, permissions, created_at, revoked)
                      VALUES (?, ?, ?, ?, ?, 'viewer', '[]', '2026-01-01', 0)''',
                   (tid, f'pgx_{owner}', f'hash-{owner}', owner, f'{owner}-ci'))
    return db


def _owners(resp):
    return sorted(t['username'] for t in resp.get_json()['tokens'])


# --- listing --------------------------------------------------------------------

def test_a_delegate_sees_only_their_own_tenants_tokens(api, estate):
    with _ctx(api, {'user': 'ann', 'role': 'user'}, '?all=true'):
        resp = _handler('list_api_tokens')()

    assert _owners(resp) == ['ann']


def test_a_global_admin_still_sees_every_token(api, estate):
    with _ctx(api, {'user': 'root9', 'role': 'admin'}, '?all=true'):
        resp = _handler('list_api_tokens')()

    assert _owners(resp) == ['ann', 'bert']


# --- revocation -----------------------------------------------------------------

def test_a_delegate_cannot_revoke_another_tenants_token(api, estate):
    with _ctx(api, {'user': 'ann', 'role': 'user'}):
        resp = _handler('revoke_api_token_endpoint')(2)

    assert resp[1] == 404
    row = estate.query_one('SELECT revoked FROM api_tokens WHERE id = 2')
    assert not row['revoked'], 'the token was revoked anyway'


def test_a_delegate_can_still_revoke_inside_their_tenant(api, estate):
    with _ctx(api, {'user': 'ann', 'role': 'user'}):
        resp = _handler('revoke_api_token_endpoint')(1)

    assert resp.get_json() == {'success': True}


def test_a_global_admin_can_still_revoke_anything(api, estate):
    with _ctx(api, {'user': 'root9', 'role': 'admin'}):
        resp = _handler('revoke_api_token_endpoint')(2)

    assert resp.get_json() == {'success': True}


# --- the node shell --------------------------------------------------------------

def test_the_node_shell_route_is_gated_on_being_unconfined(api):
    """It is a root shell on a hypervisor, so a VM-ACL or pool grant is not standing
    for it - the same rule every other node-level route in the tree already follows."""
    import inspect
    body = inspect.getsource(_handler('get_cluster_creds_internal'))

    assert 'require_unconfined(cluster_id)' in body


def test_the_node_shell_route_reads_the_callers_own_permissions(api):
    """Not the stored account: an admin-owned token capped at viewer must not be handed
    its owner's node.shell."""
    import inspect
    body = inspect.getsource(_handler('get_cluster_creds_internal'))

    assert 'get_user_permissions(user_data)' not in body
    assert 'build_authz_user' in body
