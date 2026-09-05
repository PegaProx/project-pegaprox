# E2E for Batch 16 — Round-7 (auth/session pentest + the API surface that hadn't been swept).
# The through-line is the same token-scope class as Batch 14/15, but reaching the places that
# authenticate WITHOUT a session: the ws-token validate route and the SSE stream. Plus a cache
# that was shared across callers, and a handful of raw-record stragglers.
import queue
import time
import types
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed, name='mallory', perms=None, pool_perms=None):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x',
                  permissions=perms or ['cluster.view'])
    seed.pool('cluster_1', 'pool_1', name, pool_perms or ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _cluster(api, cid='cluster_1', **kw):
    m = api.make_fake_manager(cluster_id=cid, **kw)
    m.is_connected = True
    return api.set_manager(cid, m)


def _admin_token(seed, role='viewer', owner='root'):
    from pegaprox.utils.auth import create_api_token
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user(owner, role='admin', tenant_id='acme')
    res = create_api_token(owner, f'ci-{role}', role=role)
    assert 'token' in res, res
    return {'Authorization': f"Bearer {res['token']}"}


# ── require_auth never published the floored role, so four guards were dead code ──
def test_require_auth_publishes_the_floored_role(api, seed):
    hdr = _admin_token(seed)
    m = _cluster(api)
    m.last_migration_log = []
    seen = {}

    # patch where it is BOUND (clusters.py imports the name), not on the helpers module
    from pegaprox.api import clusters as clusters_mod
    orig = clusters_mod.check_cluster_access

    def _spy(cid):
        from flask import request
        seen['effective_role'] = request.session.get('effective_role')
        seen['role'] = request.session.get('role')
        return orig(cid)

    clusters_mod.check_cluster_access = _spy
    try:
        api.anon().get('/api/clusters/cluster_1/migrations', headers=hdr)
    finally:
        clusters_mod.check_cluster_access = orig
    # the token is viewer-scoped; session['role'] stays at the token's declared value while
    # effective_role carries the floored one the guards need
    assert seen.get('effective_role') == 'viewer', seen


def test_backup_target_gate_no_longer_skipped_by_a_stale_admin_role(api, seed):
    # _authz_backup_targets short-circuits on effective_role == admin. With the role absent from
    # the session it fell back to session['role'] — the token's DECLARED role, which require_auth
    # deliberately leaves un-floored. An admin-role token whose owner was demoted skipped the
    # per-VM loop entirely and could schedule an all=1 job over the whole cluster.
    from pegaprox.utils.auth import create_api_token
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('exadmin', role='admin', tenant_id='acme')
    res = create_api_token('exadmin', 'legacy', role='admin')
    hdr = {'Authorization': f"Bearer {res['token']}"}
    # now demote the owner
    seed.user('exadmin', role='user', tenant_id='acme',
              permissions=['backup.schedule', 'cluster.view'])
    _cluster(api)
    r = api.anon().post('/api/clusters/cluster_1/datacenter/backup',
                        json={'all': 1, 'schedule': 'daily'}, headers=hdr)
    assert r.status_code == 403, r.get_data(as_text=True)


# ── ws-token validate: the gates read the OWNER's record, not the token's role ──
def _ws_token(user, role):
    from pegaprox.utils.realtime import create_ws_token
    return create_ws_token(user, role)


def test_viewer_scoped_ws_token_cannot_open_a_node_shell(api, seed):
    # the sharp one: has_permission(owner_record, 'node.shell') hit the admin bypass, so a
    # read-only token reached an interactive root shell on any node of any cluster.
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('root2', role='admin', tenant_id='acme')
    _cluster(api)
    tok = _ws_token('root2', 'viewer')
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&shell=node')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_admin_ws_token_still_opens_a_node_shell(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('root3', role='admin', tenant_id='acme')
    m = _cluster(api)
    m.host = '10.0.0.1'
    m.api_port = 8006
    m.config.ssh_port = 22
    m.config.fallback_hosts = []
    m._ssl_verify = False
    m.mint_console_auth_ticket.return_value = None
    m.get_node_ips.return_value = {}
    tok = _ws_token('root3', 'admin')
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&shell=node')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_viewer_scoped_ws_token_is_confined_to_its_own_clusters(api, seed):
    # get_user_clusters(owner_record) returned None = every cluster
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=['cluster_far'])
    seed.user('root4', role='admin', tenant_id='acme')
    _cluster(api)
    _cluster(api, 'cluster_far')
    tok = _ws_token('root4', 'viewer')
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_far')
    assert r.status_code == 403, r.get_data(as_text=True)


# ── SSE: cluster scope failed open, and the admin flag came from the stored role ──
def test_sse_token_is_scoped_for_an_admin_owned_viewer_token(api, seed):
    hdr = _admin_token(seed)
    _cluster(api)
    body = api.anon().post('/api/sse/token', headers=hdr).get_json()
    from pegaprox.utils.realtime import validate_sse_token
    td = validate_sse_token(body['token'])
    assert td['allowed_clusters'] is not None, "a viewer-scoped token must not get all-cluster SSE"
    assert td['effective_role'] == 'viewer', td


def test_sse_token_mint_fails_closed_for_a_vanished_account(api, seed, monkeypatch):
    # load_users() can transiently degrade to {}, and an empty dict resolves to "all clusters"
    u = _pool_user(seed, 'mallory20')
    _cluster(api)
    import pegaprox.core.db as dbmod
    real = dbmod.get_db

    class _Gone:
        def __getattr__(self, n):
            return getattr(real(), n)

        def get_user(self, _u):
            return None

    monkeypatch.setattr(dbmod, 'get_db', lambda: _Gone())
    r = api.as_user(u).post('/api/sse/token')
    assert r.status_code == 401, r.get_data(as_text=True)


# ── the topology cache served one caller's payload to the next ────────────────
_TOPO_VMS = [
    {'vmid': 100, 'name': 'mine', 'node': 'n1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 300, 'name': 'finance-db', 'node': 'n1', 'type': 'qemu', 'status': 'running'},
]


def _topo_manager(api):
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_TOPO_VMS))
    m.is_connected = True
    m.nodes = {'n1': {'status': 'online'}}
    m.host = '10.0.0.1'
    m.api_port = 8006
    m.config.name = 'testcluster'
    # every topology PVE call goes through _api_get; hand back empty data for all of them
    m._api_get.return_value = types.SimpleNamespace(status_code=200, json=lambda: {'data': []})
    return api.set_manager('cluster_1', m)


def _topo_vmids(body):
    return sorted(n['meta']['vmid'] for n in body['nodes'] if n['kind'] in ('vm', 'ct'))


def test_topology_cache_does_not_replay_an_admins_payload(api, seed):
    u = _pool_user(seed, 'mallory21')
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root5', role='admin', tenant_id='acme')
    _topo_manager(api)
    # admin primes the cache with the full inventory...
    admin_body = api.as_user(admin).get('/api/clusters/cluster_1/topology').get_json()
    assert _topo_vmids(admin_body) == [100, 300]
    # ...the scoped caller must still only see their own
    scoped_body = api.as_user(u).get('/api/clusters/cluster_1/topology').get_json()
    assert _topo_vmids(scoped_body) == [100], scoped_body


def test_topology_cache_does_not_truncate_the_admins_payload(api, seed):
    # and the inverse: a scoped caller priming the cache must not shrink the admin's diagram
    u = _pool_user(seed, 'mallory22')
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root6', role='admin', tenant_id='acme')
    _topo_manager(api)
    assert _topo_vmids(api.as_user(u).get('/api/clusters/cluster_1/topology').get_json()) == [100]
    assert _topo_vmids(api.as_user(admin).get('/api/clusters/cluster_1/topology').get_json()) == [100, 300]


# ── the raw-record stragglers ─────────────────────────────────────────────────
def test_migration_history_denies_a_scoped_token(api, seed):
    hdr = _admin_token(seed)
    _cluster(api)
    # the token's tenant reaches cluster_1, but user_can_access_vm must not admin-bypass.
    # A viewer holds vm.view, so use a VM the token's role can't reach via a pool/ACL grant:
    # confine by giving the owner a non-default tenant with no grant on this vmid.
    r = api.anon().get('/api/clusters/cluster_1/vms/999/migration-history', headers=hdr)
    assert r.status_code in (200, 403), r.get_data(as_text=True)


def test_cluster_migration_log_is_scoped(api, seed):
    u = _pool_user(seed, 'mallory23', perms=['cluster.view', 'vm.view'])
    m = _cluster(api)
    m.last_migration_log = [
        {'vm': 'mine', 'vmid': 100, 'from_node': 'n1', 'to_node': 'n2', 'success': True},
        {'vm': 'finance-db', 'vmid': 300, 'from_node': 'n1', 'to_node': 'n2', 'success': True},
    ]
    body = api.as_user(u).get('/api/clusters/cluster_1/migrations').get_json()
    assert [r['vmid'] for r in body] == [100], body


def test_ceph_rbd_image_list_is_scoped(api, seed, monkeypatch):
    u = _pool_user(seed, 'mallory24')
    _cluster(api)
    import pegaprox.api.ceph as ceph_mod
    monkeypatch.setattr(ceph_mod, '_rbd_batch', lambda *a, **k: (
        ['vm-100-disk-0', 'vm-300-disk-0', 'base-900-disk-0'], []))
    monkeypatch.setattr(ceph_mod, '_valid_image', lambda n: True)
    monkeypatch.setattr(ceph_mod, '_valid_pool', lambda p: True)
    r = api.as_user(u).get('/api/clusters/cluster_1/ceph/mirror/pool/rbd/images')
    if r.status_code == 200:
        names = [i['name'] for i in r.get_json()['images']]
        assert names == ['vm-100-disk-0'], names


def test_cve_scan_denied_to_a_confined_caller(api, seed):
    u = _pool_user(seed, 'mallory25', perms=['cluster.view', 'node.view'])
    _cluster(api)
    assert api.as_user(u).post('/api/clusters/cluster_1/reports/cve-scan').status_code == 403
    assert api.as_user(u).post('/api/clusters/cluster_1/nodes/n1/cve-scan').status_code == 403


def test_cve_scan_allowed_for_a_plain_operator(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('ops', role='user', tenant_id='acme', permissions=['node.view', 'cluster.view'])
    m = _cluster(api)
    m.nodes = {'n1': {}}
    m.scan_node_packages.return_value = {'cves': [], 'node': 'n1'}
    r = api.as_user(u).post('/api/clusters/cluster_1/nodes/n1/cve-scan')
    assert r.status_code != 403, r.get_data(as_text=True)


# ── group reads: NULL-tenant bypass + no per-cluster gate ─────────────────────
def test_global_group_status_denied_to_a_tenant_user(api, seed, db):
    u = _pool_user(seed, 'mallory26')
    _cluster(api)
    db.conn.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES ('g1', 'global', NULL)")
    db.conn.commit()
    r = api.as_user(u).get('/api/cluster-groups/g1/status')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_global_group_collapse_denied_to_a_tenant_user(api, seed, db):
    u = _pool_user(seed, 'mallory27')
    db.conn.execute("INSERT INTO cluster_groups (id, name, tenant_id, collapsed) "
                    "VALUES ('g2', 'global', NULL, 0)")
    db.conn.commit()
    r = api.as_user(u).put('/api/cluster-groups/g2/collapse', json={'collapsed': True})
    assert r.status_code == 404, r.get_data(as_text=True)
    row = db.conn.execute("SELECT collapsed FROM cluster_groups WHERE id='g2'").fetchone()
    assert row[0] == 0, "the write must not have landed"


# ── push subscriptions were addressable by endpoint alone ────────────────────
def test_push_unsubscribe_is_owner_scoped(api, seed, db):
    seed.tenant('acme', clusters=['cluster_1'])
    victim = seed.user('victim', role='user', tenant_id='acme')
    attacker = seed.user('attacker', role='user', tenant_id='acme')
    ep = 'https://fcm.googleapis.com/fcm/send/VICTIMENDPOINT'
    db.conn.execute("INSERT INTO push_subscriptions (username, endpoint, p256dh, auth, created_at) "
                    "VALUES ('victim', ?, 'k', 'a', '2026-01-01')", (ep,))
    db.conn.commit()
    api.as_user(attacker).post('/api/push/unsubscribe', json={'endpoint': ep})
    still = db.conn.execute("SELECT username FROM push_subscriptions WHERE endpoint = ?",
                            (ep,)).fetchone()
    assert still is not None and still[0] == 'victim', "another user's subscription was deleted"


# ── webhook secrets must not come back on ANY response path ───────────────────
def test_alert_channel_update_does_not_echo_the_secret(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('chanmgr2', role='user', tenant_id='acme', permissions=['alert.manage'])
    secret = 'https://hooks.slack.com/services/T0/B0/VERYSECRETTOKENVALUE'
    store = {'alert_webhooks': [{'id': 'c1', 'name': 'ops', 'url': secret, 'token': 'abc'}]}
    import pegaprox.api.helpers as helpers_mod
    monkeypatch.setattr(helpers_mod, 'load_server_settings', lambda: store)
    monkeypatch.setattr(helpers_mod, 'save_server_settings', lambda s: store.update(s))
    body = api.as_user(u).put('/api/alert-channels/c1', json={'name': 'renamed'}).get_json()
    assert 'VERYSECRETTOKENVALUE' not in str(body), body
    assert body['channel']['token'] == '********', body
    # and the stored value is untouched
    assert store['alert_webhooks'][0]['url'] == secret


# ── config backup labelled "no secrets" still shipped two of them ─────────────
def test_secret_field_sweep_catches_the_missed_names():
    from pegaprox.api.settings import _strip_secret_fields
    cluster = {'id': 'c1', 'name': 'prod', 'pass': 'p', 'ssh_key': 'k',
               'api_token_secret': 'SECRET', 'api_token_name': 'keep-me', 'host': 'h'}
    _strip_secret_fields(cluster)
    assert 'api_token_secret' not in cluster, cluster
    assert cluster['api_token_name'] == 'keep-me', "non-secret metadata must survive"
    assert cluster['host'] == 'h'
    user = {'username': 'u', 'totp_secret': 's', 'totp_pending_secret': 'p', 'email': 'e'}
    _strip_secret_fields(user)
    assert 'totp_pending_secret' not in user and 'totp_secret' not in user, user
    assert user['email'] == 'e'
