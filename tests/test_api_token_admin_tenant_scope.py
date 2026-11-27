"""admin.api and node.shell are delegations, and a delegate stays inside their tenant.

Both are admin-only builtin permissions, so a non-admin can only ever hold them through
a custom role - which is by definition a tenant delegation. Neither route asked which
tenant:

  * GET /api/auth/tokens?all=true returned every token in the installation: owner,
    prefix, role, permission list and last-used IP, for every tenant.
  * DELETE /api/auth/tokens/<id> revoked any of them, which is an availability attack on
    another customer's automation.
  * /api/internal/cluster-creds/<cluster> handed back a root shell credential for a
    hypervisor node. It stopped at check_cluster_access, which deliberately admits a
    caller who reached the cluster only through a VM ACL or a pool grant, and it read the
    caller's permissions off the STORED account - so an admin-owned token capped at
    viewer was handed its owner's node.shell. That route went with the SSH console server
    on port+2 (Nov 2026); the node shell on the main port holds both rules now.

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

ASKED = {'status': 'need_credentials', 'node': 'pve1', 'ip': '10.0.0.11'}


def _shell_cluster(api):
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = mgr.config.host = '10.0.0.1'
    mgr.config.ssh_port = 22
    mgr.nodes = {'pve1': {}}
    mgr.connect_to_proxmox.return_value = True
    mgr.member_node_ip.side_effect = {'pve1': '10.0.0.11'}.get
    api.set_manager('cluster_1', mgr)
    return mgr


def _open_shell(api, ws_token):
    """The main port shell up to its login dialog, which nobody answers: what it said."""
    import json

    class _Page:
        def __init__(self):
            self.sent = []

        def send(self, data):
            self.sent.append(data)

        def receive(self, timeout=None):
            return None

        def close(self, *a, **k):
            pass

    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    page = _Page()
    with api.app.test_request_context(f'/api/clusters/cluster_1/nodes/pve1/shellws?token={ws_token}'):
        view(page, 'cluster_1', 'pve1')
    return [json.loads(m) for m in page.sent]


def _ws_token(api, user=None, bearer=None):
    if bearer:
        r = api.anon().post('/api/ws/token', headers={'Authorization': f'Bearer {bearer}'})
    else:
        r = api.as_user(user).post('/api/ws/token', json={})
    assert r.status_code == 200, r.data
    return r.get_json()['token']


@pytest.fixture
def _released():
    import pegaprox.utils.realtime as rt
    before = set(rt._held_ws)
    yield
    for key in set(rt._held_ws) - before:
        rt.release_websocket(key)


def test_the_node_shell_is_gated_on_being_unconfined(api, seed, _released):
    """It is a root shell on a hypervisor, so a VM-ACL or pool grant is not standing
    for it - the same rule every other node-level route in the tree already follows."""
    mgr = _shell_cluster(api)
    # node.shell delegated in a tenant that owns cluster_1, the account confined there
    # to one VM by its ACL
    seed.tenant('tenant_y', clusters=['cluster_1'])
    confined = seed.user('carl', role='viewer', tenant_id='tenant_y', permissions=['node.shell'])
    seed.vm_acl('cluster_1', 100, ['carl'])
    said = _open_shell(api, _ws_token(api, confined))
    assert said == [{'status': 'error', 'message': 'Access denied: this action affects the whole cluster'}]
    mgr.connect_to_proxmox.assert_not_called()

    # reach to the cluster only through that ACL, from a tenant that does not own it
    seed.tenant('tenant_x', clusters=['other'])
    outsider = seed.user('erik', role='viewer', tenant_id='tenant_x', permissions=['node.shell'])
    seed.vm_acl('cluster_1', 101, ['erik'])
    said = _open_shell(api, _ws_token(api, outsider))
    assert said == [{'status': 'error', 'message': 'Access denied to this cluster'}]
    mgr.connect_to_proxmox.assert_not_called()

    # counterproof: the same delegation without the ACL
    owner = seed.user('dora', role='viewer', tenant_id='tenant_y', permissions=['node.shell'])
    said = _open_shell(api, _ws_token(api, owner))
    assert said[0] == ASKED, said


@pytest.mark.parametrize('cap,opens', [('viewer', False), ('admin', True)])
def test_the_node_shell_reads_the_callers_own_permissions(api, seed, _released, cap, opens):
    """Not the stored account: an admin-owned token capped at viewer must not be handed
    its owner's node.shell."""
    from pegaprox.utils import auth as authmod
    _shell_cluster(api)
    seed.user('root9', role='admin')
    made = authmod.create_api_token('root9', f'ci-{cap}', role=cap)
    said = _open_shell(api, _ws_token(api, bearer=made['token']))
    if opens:
        assert said[0] == ASKED, said
    else:
        assert said == [{'status': 'error', 'message': 'Permission denied'}]


def test_cluster_creds_is_gone(api, seed):
    """The credential route has no successor: nothing hands out node addresses or a
    login for a shell any more."""
    import pegaprox.api.auth as auth_routes
    assert not hasattr(auth_routes, 'get_cluster_creds_internal')
    r = api.as_user(seed.user('root9', role='admin')).get('/api/internal/cluster-creds/cluster_1')
    assert r.status_code == 404
