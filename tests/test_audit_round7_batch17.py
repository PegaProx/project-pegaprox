# E2E for Batch 17 — Round-7 part 2. The theme here is grant-authoring: vm-acls and pool
# permissions ARE the objects user_can_access_vm consults, so writing them is granting access,
# yet they were gated on cluster reach alone. Plus the credential-lifecycle gaps (SSE tokens had
# no revocation path at all) and the WS twin of the SSE per-VM filter.
import json
import queue
import time

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _cluster(api, cid='cluster_1'):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    return api.set_manager(cid, m)


def _pool_scoped_usermanager(seed, name='delegate'):
    """A pool-scoped caller who has been delegated admin.users — the realistic shape of the
    'tenant user manager' role. They must not be able to author grants."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x',
                  permissions=['admin.users', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── vm-acls: writing the ACL IS granting access ───────────────────────────────
def test_scoped_caller_cannot_write_a_vm_acl(api, seed):
    u = _pool_scoped_usermanager(seed)
    _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1/vm-acls/9001',
                           json={'users': ['delegate'], 'inherit_role': True})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_scoped_caller_cannot_delete_a_vm_acl(api, seed):
    u = _pool_scoped_usermanager(seed, 'delegate2')
    _cluster(api)
    r = api.as_user(u).delete('/api/clusters/cluster_1/vm-acls/9001')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_admin_can_still_write_a_vm_acl(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root', role='admin', tenant_id='acme')
    seed.user('bob', role='user', tenant_id='acme')
    _cluster(api)
    r = api.as_user(admin).put('/api/clusters/cluster_1/vm-acls/9001',
                               json={'users': ['bob'], 'inherit_role': True})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_wildcard_acl_grant_requires_a_global_admin(api, seed):
    # '*' reaches every account in the install, including other tenants'
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('tenantadmin', role='user', tenant_id='acme',
                  permissions=['admin.users', 'cluster.view', 'vm.config'])
    _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1/vm-acls/9001',
                           json={'users': ['*'], 'inherit_role': True})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_acl_cannot_grant_a_permission_the_caller_lacks(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('tenantadmin2', role='user', tenant_id='acme',
                  permissions=['admin.users', 'cluster.view', 'vm.config'])
    seed.user('peer', role='user', tenant_id='acme')
    _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1/vm-acls/9001',
                           json={'users': ['peer'], 'inherit_role': False,
                                 'permissions': ['admin.settings']})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_acl_cannot_target_another_tenants_account(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=['cluster_2'])
    u = seed.user('tenantadmin3', role='user', tenant_id='acme',
                  permissions=['admin.users', 'cluster.view', 'vm.config'])
    seed.user('outsider', role='user', tenant_id='other')
    _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1/vm-acls/9001',
                           json={'users': ['outsider'], 'inherit_role': True})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── pool permissions: pool.admin short-circuits the per-VM gate for a whole pool ──
def test_scoped_caller_cannot_grant_pool_permissions(api, seed):
    u = _pool_scoped_usermanager(seed, 'delegate3')
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/pools/pool_other/permissions',
                            json={'subject_type': 'user', 'subject_id': 'delegate3',
                                  'permissions': ['pool.admin']})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_scoped_caller_cannot_revoke_pool_permissions(api, seed):
    u = _pool_scoped_usermanager(seed, 'delegate4')
    _cluster(api)
    r = api.as_user(u).delete(
        '/api/clusters/cluster_1/pools/pool_other/permissions/user/someone')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_admin_can_still_grant_pool_permissions(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root2', role='admin', tenant_id='acme')
    seed.user('bob2', role='user', tenant_id='acme')
    _cluster(api)
    r = api.as_user(admin).post('/api/clusters/cluster_1/pools/pool_1/permissions',
                                json={'subject_type': 'user', 'subject_id': 'bob2',
                                      'permissions': ['pool.view']})
    assert r.status_code == 200, r.get_data(as_text=True)


# ── a tenant delegate could hand its own tenant any cluster ───────────────────
def test_tenant_delegate_cannot_self_grant_clusters(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('tadmin', role='user', tenant_id='acme',
                  permissions=['admin.tenants', 'cluster.view'])
    r = api.as_user(u).put('/api/tenants/acme',
                           json={'clusters': ['cluster_1', 'cluster_secret']})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_tenant_delegate_can_still_rename_its_tenant(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('tadmin2', role='user', tenant_id='acme',
                  permissions=['admin.tenants', 'cluster.view'])
    r = api.as_user(u).put('/api/tenants/acme', json={'name': 'Acme Corp'})
    assert r.status_code == 200, r.get_data(as_text=True)


# ── a delegate must not delete or disable a peer who outranks them ────────────
def test_delegate_cannot_delete_a_more_privileged_peer(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('weak', role='user', tenant_id='acme', permissions=['admin.users'])
    seed.user('strong', role='user', tenant_id='acme',
              permissions=['admin.users', 'admin.settings'])
    r = api.as_user(u).delete('/api/users/strong')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_delegate_cannot_disable_a_more_privileged_peer(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('weak2', role='user', tenant_id='acme', permissions=['admin.users'])
    seed.user('strong2', role='user', tenant_id='acme',
              permissions=['admin.users', 'admin.settings'])
    r = api.as_user(u).put('/api/users/strong2', json={'enabled': False})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── SSE tokens had no revocation path at all ─────────────────────────────────
def _mint_sse(api, u):
    body = api.as_user(u).post('/api/sse/token').get_json()
    return body['token']


def test_sse_token_dies_with_the_account(api, seed):
    from pegaprox.utils.realtime import validate_sse_token
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root3', role='admin', tenant_id='acme')
    victim = seed.user('victim', role='user', tenant_id='acme')
    _cluster(api)
    tok = _mint_sse(api, victim)
    assert validate_sse_token(tok) is not None
    api.as_user(admin).put('/api/users/victim', json={'enabled': False})
    assert validate_sse_token(tok) is None, "a disabled account's SSE token must stop working"


def test_sse_token_dies_on_logout(api, seed):
    from pegaprox.utils.realtime import validate_sse_token
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('leaver', role='user', tenant_id='acme')
    _cluster(api)
    client = api.as_user(u)
    tok = client.post('/api/sse/token').get_json()['token']
    assert validate_sse_token(tok) is not None
    client.post('/api/auth/logout')
    assert validate_sse_token(tok) is None, "logout must drop the SSE token"


def test_sse_token_dies_on_admin_password_reset(api, seed):
    from pegaprox.utils.realtime import validate_sse_token
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root4', role='admin', tenant_id='acme')
    u = seed.user('resetme', role='user', tenant_id='acme')
    _cluster(api)
    tok = _mint_sse(api, u)
    assert validate_sse_token(tok) is not None
    api.as_user(admin).put('/api/users/resetme/password', json={'password': 'NewPassw0rd!x'})
    assert validate_sse_token(tok) is None


# ── the WS twin of the SSE per-VM filter ─────────────────────────────────────
class _FakeWS:
    def __init__(self):
        self.sent = []

    def send(self, m):
        self.sent.append(json.loads(m))


def _register_ws(user, is_admin, clusters):
    import threading
    ws = _FakeWS()
    cid = f'test-ws-{user}'
    with ppglobals.ws_clients_lock:
        ppglobals.ws_clients[cid] = {
            'ws': ws, 'lock': threading.Lock(), 'user': user,
            'clusters': clusters, 'is_admin': is_admin, 'connected_at': 'x',
        }
    return ws, cid


def test_ws_action_frames_are_scoped_per_vm(api, seed, db):
    from pegaprox.utils.realtime import broadcast_action
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    seed.user('rootws', role='admin', tenant_id='tenant_x')
    mws, mcid = _register_ws('mallory', False, ['cluster_1'])
    aws, acid = _register_ws('rootws', True, None)
    try:
        broadcast_action('delete', 'vm', '300', {'name': 'finance-db'}, 'cluster_1', 'root')
        assert mws.sent == [], "a pool user must not see a foreign VM's action frame"
        assert len(aws.sent) == 1, "admin still sees it"
        broadcast_action('start', 'vm', '100', {'name': 'mine'}, 'cluster_1', 'mallory')
        assert len(mws.sent) == 1, "their own VM's action frame must still arrive"
    finally:
        with ppglobals.ws_clients_lock:
            ppglobals.ws_clients.pop(mcid, None)
            ppglobals.ws_clients.pop(acid, None)


def test_ws_non_vm_action_frames_still_broadcast(api, seed, db):
    # node/cluster-level events carry no vmid — they must not be swallowed by the filter
    from pegaprox.utils.realtime import broadcast_action
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.user('mallory2', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory2', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    mws, mcid = _register_ws('mallory2', False, ['cluster_1'])
    try:
        broadcast_action('maintenance', 'node', 'n1', {}, 'cluster_1', 'root')
        assert len(mws.sent) == 1, "a node-level event is not per-VM and must still arrive"
    finally:
        with ppglobals.ws_clients_lock:
            ppglobals.ws_clients.pop(mcid, None)


# ── TOTP codes were replayable inside the ~90s acceptance window ──────────────
def test_totp_code_cannot_be_replayed():
    from pegaprox.api.auth import _totp_replayed
    assert _totp_replayed('alice', '123456') is False, "first use must be accepted"
    assert _totp_replayed('alice', '123456') is True, "a replay must be rejected"
    assert _totp_replayed('bob', '123456') is False, "a different user is unaffected"
    assert _totp_replayed('alice', '654321') is False, "a different code is unaffected"


# ── the WebAuthn begin route was an anonymous account oracle ──────────────────
def test_webauthn_begin_does_not_confirm_account_existence(api, seed):
    seed.user('haskeys', role='user', tenant_id='default')
    a = api.anon().post('/api/webauthn/auth/begin', json={'username': 'haskeys'})
    b = api.anon().post('/api/webauthn/auth/begin', json={'username': 'does-not-exist'})
    assert a.status_code == b.status_code, (a.status_code, b.status_code)
    assert a.get_json() == b.get_json(), (a.get_json(), b.get_json())
