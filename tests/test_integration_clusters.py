# Full-stack integration suite for the `clusters` blueprint (pegaprox/api/clusters.py).
#
# Drives the REAL Flask app + real clusters blueprint through the shared harness in
# tests/conftest.py, faking only the cluster manager. Each test traverses the real
# require_auth(perms) -> check_cluster_access (403) -> 404 gate -> manager sequence,
# so every authz decision is asserted exactly as a browser / attacker would get it.
#
# Focus (per the task): the RESTRICTIVE /resources list (hides ACL-restricted VMs
# from non-whitelisted users, unlike the additive per-VM routes), cluster status /
# summary reads, add / remove / edit cluster (admin-only perms -> non-admin 403),
# excluded-VM add / remove, and HA remove.
#
# Perm facts pinned from pegaprox/models/permissions.py:
#   cluster.view   -> admin + user + viewer
#   cluster.add / cluster.delete / cluster.config -> ADMIN ONLY
#   ha.config      -> ADMIN ONLY   (ha.view -> admin + user + viewer)
#   vm.view        -> admin + user + viewer

import types

import pegaprox.globals as _ppglobals


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _mgr_from_globals(cluster_id='cluster_1'):
    """The fake manager currently injected into the live cluster_managers dict —
    lets a deny-test assert the manager method was never invoked."""
    return _ppglobals.cluster_managers[cluster_id]


def _real_config(**overrides):
    """A plain, JSON-serializable stand-in for mgr.config. The /api/clusters admin
    branch serializes ~30 config fields directly; a MagicMock config would blow up
    json.dumps. This object exposes the directly-accessed fields with real values;
    everything else the handler reads via getattr(config, k, default) falls back to
    the default because the attribute is genuinely absent."""
    cfg = types.SimpleNamespace(
        name='lab-cluster', host='10.0.0.1',
        migration_threshold=80, check_interval=60,
        auto_migrate=False, dry_run=True, enabled=True,
        ha_enabled=False, fallback_hosts=[],
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


# ===========================================================================
# /resources — the RESTRICTIVE list. Admin sees everything; a non-whitelisted
# same-tenant role user sees a FILTERED list (ACL-restricted VMs hidden).
# ===========================================================================

RES_ROUTE = '/api/clusters/cluster_1/resources'

_ALL_VMS = [
    {'vmid': 100, 'name': 'db01', 'type': 'qemu', 'status': 'running'},
    {'vmid': 101, 'name': 'web01', 'type': 'qemu', 'status': 'running'},
]


def _resources_manager(api):
    return api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_ALL_VMS))


def test_resources_anon_is_401(api, seed):
    api.set_manager('cluster_1', _resources_manager(api))
    resp = api.anon().get(RES_ROUTE)
    assert resp.status_code == 401


def test_resources_admin_sees_all_vms_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _resources_manager(api))

    resp = api.as_user(admin).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    vmids = sorted(v['vmid'] for v in body)
    assert vmids == [100, 101]


def test_resources_restricted_user_gets_filtered_list_200(api, seed):
    """A same-tenant 'user' (has vm.view) reaches cluster_1 at the cluster level.
    VM 100 carries an ACL that whitelists only someone else -> hidden. VM 101 has
    no ACL -> visible via the general vm.view fallback. This is the RESTRICTIVE
    behaviour of /resources (per-VM routes are additive; this list is not)."""
    seed.tenant('tenant_x', clusters=['cluster_1'])          # owns cluster_1
    carol = seed.user('carol', role='user', tenant_id='tenant_x')
    seed.vm_acl('cluster_1', 100, users=['someone_else'])    # carol NOT whitelisted
    api.set_manager('cluster_1', _resources_manager(api))

    resp = api.as_user(carol).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    vmids = [v['vmid'] for v in body]
    assert 101 in vmids           # no-ACL VM stays (general vm.view)
    assert 100 not in vmids       # ACL VM hidden from non-whitelisted user


def test_resources_whitelisted_user_sees_acl_vm_200(api, seed):
    """The mirror of the above: whitelist carol on VM 100 and she now sees it too."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    carol = seed.user('carol', role='user', tenant_id='tenant_x')
    seed.vm_acl('cluster_1', 100, users=['carol'])
    api.set_manager('cluster_1', _resources_manager(api))

    resp = api.as_user(carol).get(RES_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    vmids = sorted(v['vmid'] for v in body)
    assert vmids == [100, 101]


def test_resources_cross_tenant_user_denied_at_cluster_level_403(api, seed):
    """Cross-tenant user is stopped by check_cluster_access before any VM filtering
    and before the manager is consulted."""
    seed.tenant('tenant_other', clusters=['cluster_2'])      # does NOT own cluster_1
    dave = seed.user('dave', role='user', tenant_id='tenant_other')
    api.set_manager('cluster_1', _resources_manager(api))

    resp = api.as_user(dave).get(RES_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_from_globals().get_vm_resources.assert_not_called()


# ===========================================================================
# Cluster status / summary reads.
#   GET /api/clusters               -> tenant/ACL-filtered list (require_auth only)
#   GET /api/clusters/<id>/metrics  -> cluster.view + check_cluster_access
# ===========================================================================

def _list_manager(api):
    """A fake whose scalar attributes are JSON-serializable so the admin branch of
    the /api/clusters list can serialize the full config payload."""
    fake = api.make_fake_manager(cluster_id='cluster_1')
    fake.config = _real_config()
    fake.running = True
    fake.is_connected = True
    fake.connection_error = None
    fake.last_run = None            # else .isoformat() returns an unserializable mock
    fake._original_host = '10.0.0.1'
    fake._using_api_token = False
    return fake


def test_list_clusters_admin_sees_cluster_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _list_manager(api))

    resp = api.as_user(admin).get('/api/clusters')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    ids = [c['id'] for c in body]
    assert 'cluster_1' in ids


def test_list_clusters_cross_tenant_user_sees_empty_200(api, seed):
    """A user whose tenant owns a DIFFERENT cluster gets an empty list (no 403 here —
    the list route just filters), proving tenant scoping on the summary read."""
    seed.tenant('tenant_z', clusters=['cluster_2'])
    zed = seed.user('zed', role='user', tenant_id='tenant_z')
    api.set_manager('cluster_1', _list_manager(api))

    resp = api.as_user(zed).get('/api/clusters')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    ids = [c['id'] for c in resp.get_json()]
    assert 'cluster_1' not in ids


def test_metrics_viewer_reads_node_status_200(api, seed):
    """cluster.view is held by viewer; get_cluster_metrics returns mgr.get_node_status()
    when connected."""
    viewer = seed.user('val', role='viewer', tenant_id='default')
    metrics = {'pve1': {'status': 'online', 'cpu': 0.12}}
    fake = api.make_fake_manager(cluster_id='cluster_1', get_node_status=metrics)
    api.set_manager('cluster_1', fake)

    resp = api.as_user(viewer).get('/api/clusters/cluster_1/metrics')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json() == metrics


def test_metrics_cross_tenant_denied_403(api, seed):
    seed.tenant('tenant_m', clusters=['cluster_2'])
    mal = seed.user('mal', role='user', tenant_id='tenant_m')
    fake = api.make_fake_manager(cluster_id='cluster_1', get_node_status={'pve1': {}})
    api.set_manager('cluster_1', fake)

    resp = api.as_user(mal).get('/api/clusters/cluster_1/metrics')
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_from_globals().get_node_status.assert_not_called()


# ===========================================================================
# Add cluster — POST /api/clusters — perm cluster.add (ADMIN ONLY).
# A non-admin must be 403 (require_auth's perm gate) BEFORE any connect attempt.
# ===========================================================================

def test_add_cluster_non_admin_forbidden_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    resp = api.as_user(user).post('/api/clusters', json={
        'name': 'new', 'host': '1.2.3.4', 'user': 'root@pam', 'pass': 'x',
    })
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_add_cluster_viewer_forbidden_403(api, seed):
    viewer = seed.user('vic', role='viewer', tenant_id='default')
    resp = api.as_user(viewer).post('/api/clusters', json={
        'name': 'new', 'host': '1.2.3.4', 'user': 'root@pam', 'pass': 'x',
    })
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_add_cluster_admin_missing_field_400(api, seed):
    """Admin passes the cluster.add perm gate and reaches the handler's own
    validation (no connect attempted because a required field is missing).
    Proves the ALLOW side of the perm gate without needing a live PVE."""
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post('/api/clusters', json={
        'name': 'new', 'host': '1.2.3.4',   # missing 'user'
    })
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'user' in (resp.get_json() or {}).get('error', '')


# ===========================================================================
# Edit cluster — PUT /api/clusters/<id> — perm cluster.config (ADMIN ONLY).
# ===========================================================================

def test_update_config_non_admin_forbidden_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).put('/api/clusters/cluster_1', json={'auto_migrate': True})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_update_config_admin_updates_allowed_field_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(cluster_id='cluster_1')
    # ALLOWED_CONFIG_FIELDS is filtered against hasattr(mgr.config, key); the fake's
    # config is a MagicMock so hasattr() is always True. Only allowed keys pass.
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).put('/api/clusters/cluster_1',
                                  json={'auto_migrate': True, 'not_a_field': 1})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert 'auto_migrate' in body['updated_fields']
    assert 'not_a_field' not in body['updated_fields']   # mass-assignment blocked


def test_update_config_admin_unknown_cluster_404(api, seed):
    """No manager injected -> the 404 gate fires (admin passes the perm gate first)."""
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).put('/api/clusters/ghost', json={'auto_migrate': True})
    assert resp.status_code == 404, resp.get_data(as_text=True)


# ===========================================================================
# Remove cluster — DELETE /api/clusters/<id> — perm cluster.delete (ADMIN ONLY).
# ===========================================================================

def test_delete_cluster_non_admin_forbidden_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).delete('/api/clusters/cluster_1')
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_delete_cluster_admin_unknown_cluster_404(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).delete('/api/clusters/ghost')
    assert resp.status_code == 404, resp.get_data(as_text=True)


# ===========================================================================
# Excluded-VM add / remove — perm cluster.config (ADMIN ONLY).
#   POST   /api/clusters/<id>/excluded-vms/<int:vmid>
#   DELETE /api/clusters/<id>/excluded-vms/<int:vmid>
# handler calls mgr.set_vm_balancing_excluded(...) -> truthy on success.
# ===========================================================================

def test_add_excluded_vm_non_admin_forbidden_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).post('/api/clusters/cluster_1/excluded-vms/100', json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_add_excluded_vm_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(cluster_id='cluster_1', set_vm_balancing_excluded=True)
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).post('/api/clusters/cluster_1/excluded-vms/100',
                                   json={'reason': 'pinned db'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['vmid'] == 100
    fake.set_vm_balancing_excluded.assert_called_once()


def test_add_excluded_vm_admin_manager_failure_500(api, seed):
    """When the manager reports failure the route surfaces a 500 (loud, not silent)."""
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(cluster_id='cluster_1', set_vm_balancing_excluded=False)
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).post('/api/clusters/cluster_1/excluded-vms/100', json={})
    assert resp.status_code == 500, resp.get_data(as_text=True)


def test_remove_excluded_vm_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(cluster_id='cluster_1', set_vm_balancing_excluded=True)
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).delete('/api/clusters/cluster_1/excluded-vms/100')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['vmid'] == 100


def test_remove_excluded_vm_non_admin_forbidden_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).delete('/api/clusters/cluster_1/excluded-vms/100')
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_from_globals().set_vm_balancing_excluded.assert_not_called()


def test_get_excluded_vms_cross_tenant_denied_403(api, seed):
    """GET excluded-vms requires cluster.view (user has it) but check_cluster_access
    still stops a cross-tenant user."""
    seed.tenant('tenant_e', clusters=['cluster_2'])
    eve = seed.user('eve', role='user', tenant_id='tenant_e')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(eve).get('/api/clusters/cluster_1/excluded-vms')
    assert resp.status_code == 403, resp.get_data(as_text=True)


# ===========================================================================
# HA remove — DELETE /api/clusters/<id>/proxmox-ha/resources/<vm_type>:<vmid>
#   perm ha.config (ADMIN ONLY). handler -> mgr.remove_vm_from_proxmox_ha(...)
#   which returns {'success': True/False}.
# ===========================================================================

HA_RM_ROUTE = '/api/clusters/cluster_1/proxmox-ha/resources/vm:100'


def test_ha_remove_non_admin_forbidden_403(api, seed):
    """user role holds ha.view but NOT ha.config -> the write is 403."""
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).delete(HA_RM_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_from_globals().remove_vm_from_proxmox_ha.assert_not_called()


def test_ha_remove_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(
        cluster_id='cluster_1',
        remove_vm_from_proxmox_ha={'success': True, 'message': 'removed'},
    )
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).delete(HA_RM_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True
    fake.remove_vm_from_proxmox_ha.assert_called_once()


def test_ha_remove_admin_manager_reports_failure_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(
        cluster_id='cluster_1',
        remove_vm_from_proxmox_ha={'success': False, 'error': 'not in HA'},
    )
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).delete(HA_RM_ROUTE)
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is False


def test_ha_remove_non_admin_is_perm_gate_deny_not_cluster(api, seed):
    """Distinct from the cross-tenant read deny below: here a SAME-tenant 'user'
    (default tenant => reaches cluster_1 at the cluster level) is still 403 on the
    ha.config write. That proves the deny is the PERM gate, not check_cluster_access —
    the write stays admin-only even for a user who fully owns the cluster."""
    user = seed.user('samuel', role='user', tenant_id='default')  # reaches cluster_1
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).delete(HA_RM_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_from_globals().remove_vm_from_proxmox_ha.assert_not_called()


def test_ha_status_cross_tenant_denied_at_cluster_level_403(api, seed):
    """Cluster-level cross-tenant deny on an HA route. A 'user' HOLDS ha.view, so the
    perm gate PASSES; the 403 therefore comes from check_cluster_access (their tenant
    owns cluster_2, not cluster_1) — the gate no other HA test exercises. get_ha_status
    must never be consulted on the deny path."""
    seed.tenant('tenant_h', clusters=['cluster_2'])          # does NOT own cluster_1
    heidi = seed.user('heidi', role='user', tenant_id='tenant_h')
    # inject a fake so the 404 gate can't preempt the check_cluster_access 403
    fake = api.make_fake_manager(cluster_id='cluster_1', get_ha_status={'enabled': True})
    api.set_manager('cluster_1', fake)

    resp = api.as_user(heidi).get('/api/clusters/cluster_1/ha')
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_from_globals().get_ha_status.assert_not_called()


# ===========================================================================
# HA status read — GET /api/clusters/<id>/ha — perm ha.view (viewer holds it).
# ===========================================================================

def test_ha_status_viewer_reads_200(api, seed):
    viewer = seed.user('val', role='viewer', tenant_id='default')
    ha = {'enabled': True, 'monitor_running': True, 'nodes': {}}
    fake = api.make_fake_manager(cluster_id='cluster_1', get_ha_status=ha)
    api.set_manager('cluster_1', fake)

    resp = api.as_user(viewer).get('/api/clusters/cluster_1/ha')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json() == ha
