# Regression guards for the Aikido Testing-branch pentest fixes (batch 2/2, Aug 2026, NS) — authz +
# validation invariants driven through the real Flask app (the deny path fires before any manager is
# touched). The SSRF-pin unit tests that used to live here were consolidated into
# tests/test_url_security.py (the canonical SSRF suite) to keep pin coverage in one place.


# ---------------------------------------------------------------------------
# power rates — only a global admin may overwrite the shared __default__ row
# ---------------------------------------------------------------------------

def test_cluster_config_holder_cannot_write_default_power_rates(api, seed):
    # tenant-scoped holder of cluster.config (restricted to their own clusters) must NOT be able
    # to tamper with the __default__ fallback row every other cluster reads.
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['cluster.config'])
    r = api.as_user(alice).put('/api/power/rates/__default__', json={'kwh_price': 0.01})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_admin_can_write_default_power_rates(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    r = api.as_user(root).put('/api/power/rates/__default__', json={'kwh_price': 0.30})
    assert r.status_code != 403, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# cluster-groups — a global (tenant_id NULL) group is admin-only for writes
# ---------------------------------------------------------------------------

def _seed_global_group(seed, gid='g-global'):
    seed.db.execute(
        'INSERT INTO cluster_groups (id, name, description, color, tenant_id, sort_order, '
        'created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (gid, 'Global Group', '', '#ffffff', None, 0, '2026-01-01T00:00:00', '2026-01-01T00:00:00'))
    return gid


def test_tenant_admin_groups_holder_cannot_delete_global_group(api, seed):
    gid = _seed_global_group(seed)
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.groups'])
    r = api.as_user(alice).delete(f'/api/cluster-groups/{gid}')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_tenant_cluster_config_holder_cannot_balance_global_group(api, seed):
    gid = _seed_global_group(seed, 'g-global-2')
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['cluster.config'])
    r = api.as_user(alice).post(f'/api/cluster-groups/{gid}/balance-now')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_admin_can_delete_global_group(api, seed):
    gid = _seed_global_group(seed, 'g-global-3')
    root = seed.user('root', role='admin', tenant_id='default')
    r = api.as_user(root).delete(f'/api/cluster-groups/{gid}')
    assert r.status_code == 200, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# vm-tags — a non-numeric vmid must be rejected BEFORE the global DELETE+rewrite
# ---------------------------------------------------------------------------

def test_non_numeric_vmid_rejected_on_tag_update(api, seed):
    # admin passes check_cluster_access, so we reach (and prove) the numeric guard rather than a
    # cluster-access 403. A bad vmid used to ValueError mid-rewrite and persist a table wipe.
    root = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.as_user(root).post('/api/clusters/cluster_1/vms/abc/tags', json={'tags': [{'name': 'x'}]})
    assert r.status_code == 400, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Prometheus exporter — only an ADMIN-role token may scrape the global feed
# ---------------------------------------------------------------------------

def test_metrics_rejects_non_admin_token(api, monkeypatch):
    import pegaprox.api.metrics_exporter as mx
    monkeypatch.setattr(mx, 'validate_api_token', lambda tok: {'user': 'svc', 'role': 'viewer'})
    r = api.anon().get('/api/metrics', headers={'Authorization': 'Bearer pgx_dummy'})
    assert r.status_code == 401, r.get_data(as_text=True)


def test_metrics_allows_admin_token(api, seed, monkeypatch):
    # the token's owner has to actually exist and still be an enabled admin — the route has no
    # @require_auth, so it re-checks that itself (audit)
    seed.user('svc', role='admin', tenant_id='default')
    import pegaprox.api.metrics_exporter as mx
    monkeypatch.setattr(mx, 'validate_api_token', lambda tok: {'user': 'svc', 'role': 'admin'})
    r = api.anon().get('/api/metrics', headers={'Authorization': 'Bearer pgx_dummy'})
    assert r.status_code == 200, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# ws-token validate — the node SSH shell path (shell=node) must enforce node.shell
# ---------------------------------------------------------------------------

def _ws_token(user, role):
    from pegaprox.utils.realtime import create_ws_token
    return create_ws_token(user, role)


def test_node_shell_ws_requires_node_shell_permission(api, seed):
    # alice reaches cluster_1 (her tenant owns it) but has no node.shell → the standalone SSH
    # shell server's validate call (shell=node) must 403, not just wave the cluster grant through.
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.user('alice', role='viewer', tenant_id='tenant_a')
    tok = _ws_token('alice', 'viewer')
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&node=pve1&shell=node')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'node.shell' in r.get_data(as_text=True)


def test_vm_termproxy_ws_not_gated_on_node_shell(api, seed):
    # the VM termproxy path does NOT send shell=node — the same cluster-only grant must still be
    # accepted there (guest console is gated separately), i.e. NOT a node.shell 403.
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.user('alice', role='viewer', tenant_id='tenant_a')
    tok = _ws_token('alice', 'viewer')
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&node=pve1')
    assert r.status_code != 403, r.get_data(as_text=True)


def test_node_shell_ws_allows_holder(api, seed):
    # positive control: an admin (holds node.shell) is not blocked by the new gate.
    seed.user('root', role='admin', tenant_id='default')
    tok = _ws_token('root', 'admin')
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&node=pve1&shell=node')
    assert r.status_code != 403, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# multi-sdn create/purge TOCTOU — in-flight provisioning advert is observed
# ---------------------------------------------------------------------------

def test_provisioning_advert_marks_shared_infra():
    from pegaprox.api import multi_sdn
    tok = multi_sdn._register_provisioning(
        ['cluster_1', 'cluster_2'], {'zone': 'evpnz', 'controller': 'evpnc'})
    try:
        # a concurrent purge on a shared member sees the in-flight zone+controller as shared
        assert multi_sdn._provisioning_shares('cluster_1', 'evpnz', 'evpnc') == (True, True)
        # a non-member cluster is unaffected
        assert multi_sdn._provisioning_shares('cluster_9', 'evpnz', 'evpnc') == (False, False)
        # partial match: only the controller name lines up
        assert multi_sdn._provisioning_shares('cluster_2', 'other', 'evpnc') == (False, True)
    finally:
        multi_sdn._unregister_provisioning(tok)
    # once the create records its DB row and unregisters, the advert is gone
    assert multi_sdn._provisioning_shares('cluster_1', 'evpnz', 'evpnc') == (False, False)
