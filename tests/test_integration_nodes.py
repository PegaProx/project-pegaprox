# Full-stack integration suite for the `nodes` blueprint (pegaprox/api/nodes.py).
#
# Same harness as tests/test_integration_smoke.py: the REAL Flask app + REAL nodes
# blueprint, only the cluster manager is faked. Every case traverses the real
#   require_auth(perms) -> check_cluster_access (403) -> "cluster not found" (404) -> manager
# chain, so each asserts the exact decision a browser / attacker would get.
#
# nodes.py permission gating (from pegaprox/models/permissions.py ROLE_PERMISSIONS):
#   * node.view      -> admin, user, viewer   (node status/summary/metrics reads)
#   * node.network   -> admin ONLY            (network mutation writes; user/viewer 403)
#   * vm.config      -> admin, user           (set VM HA priority; viewer 403)
#   * vm.view        -> admin, user, viewer   (guest metrics read)
#   * admin.settings -> admin ONLY            (subscription writes)
#
# NOTE on "node.shell": the FOCUS mentions node.shell-gated operations, but the
# node.shell permission is NOT used anywhere in the nodes blueprint — grep shows it
# lives in pegaprox/api/vms.py (the exec-command route) and auth.py, not nodes.py.
# So the privilege-gate we prove here for a "privileged write a plain user can't do"
# is node.network (admin-only in this blueprint): a `user` WITHOUT it gets 403 while
# an `admin` WITH it reaches the manager. See test at the bottom of the WRITE section
# and the SKIP note returned in the structured result.
#
# None of the nodes.py routes call _require_vm_access, so there is NO per-VM
# reach-only deny in this blueprint (tenant isolation is enforced purely at the
# cluster level by check_cluster_access). The pool/ACL reach-only case is therefore
# covered as a cluster-level deny below, not a per-VM one.

import pegaprox.globals as _ppglobals


CID = 'cluster_1'
NODE = 'pve1'

SUMMARY_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/summary'
RRD_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/rrddata'
NETSTATS_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/netstats'
NET_IFACE_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/network/vmbr0'
NET_CREATE_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/network'
HA_PRIORITY_ROUTE = f'/api/clusters/{CID}/vms/100/ha-priority'
GUEST_METRICS_ROUTE = f'/api/clusters/{CID}/vms/100/guest-metrics'
SUBSCRIPTION_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/subscription'


def _mgr(api, **methods):
    """A fake manager for cluster_1 with config.name set (the audit-logged write
    routes read mgr.config.name) and any route methods stubbed via kwargs."""
    m = api.make_fake_manager(cluster_id=CID, **methods)
    m.config.name = CID
    return m


def _current_mgr():
    return _ppglobals.cluster_managers[CID]


# ===========================================================================
# READS — node.view gated (summary + metrics), cluster-access enforced
# ===========================================================================

def test_anon_node_summary_is_401(api, seed):
    api.set_manager(CID, _mgr(api, get_node_summary={'node': NODE, 'status': 'online'}))
    resp = api.anon().get(SUMMARY_ROUTE)
    assert resp.status_code == 401


def test_admin_reads_node_summary_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, get_node_summary={
        'node': NODE, 'status': 'online', 'cpu': 0.12, 'maxmem': 137438953472}))

    resp = api.as_user(admin).get(SUMMARY_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['node'] == NODE
    assert body['status'] == 'online'
    # the node path segment is forwarded verbatim to the manager
    _current_mgr().get_node_summary.assert_called_once_with(NODE)


def test_viewer_reads_node_summary_200(api, seed):
    # viewer holds node.view -> summary read is allowed.
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    api.set_manager(CID, _mgr(api, get_node_summary={'node': NODE, 'status': 'online'}))

    resp = api.as_user(viewer).get(SUMMARY_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['status'] == 'online'


def test_user_reads_node_rrddata_metrics_200(api, seed):
    # node performance metrics (RRD) — node.view; user role holds it.
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager(CID, _mgr(api, get_node_rrddata=[
        {'time': 1710000000, 'cpu': 0.25, 'memused': 4096},
        {'time': 1710000060, 'cpu': 0.30, 'memused': 4200},
    ]))

    resp = api.as_user(user).get(RRD_ROUTE + '?timeframe=day')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list) and len(body) == 2
    assert body[0]['cpu'] == 0.25
    # the timeframe query param is forwarded verbatim to the manager
    _current_mgr().get_node_rrddata.assert_called_once_with(NODE, 'day')


def test_netstats_upstream_error_is_502(api, seed):
    # get_node_netstats returns {'error': ...} -> the route maps it to 502 (not 200).
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, get_node_netstats={'error': 'SSH unavailable'}))

    resp = api.as_user(admin).get(NETSTATS_ROUTE)
    assert resp.status_code == 502, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'SSH unavailable'


def test_netstats_success_is_200(api, seed):
    # the 200 branch of the netstats route (result dict has no 'error' key ->
    # passed straight through). Success shape from manager.get_node_netstats is
    # {'interfaces': [...], 'count': N}.
    user = seed.user('joe', role='user', tenant_id='default')  # node.view holder
    api.set_manager(CID, _mgr(api, get_node_netstats={
        'interfaces': [{'iface': 'eth0', 'rx_errs': 0, 'tx_drop': 2}], 'count': 1}))

    resp = api.as_user(user).get(NETSTATS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['count'] == 1
    assert body['interfaces'][0]['iface'] == 'eth0'
    # node forwarded to the manager (netstats is SSH-fronted per-node)
    _current_mgr().get_node_netstats.assert_called_once_with(NODE)


def test_netstats_invalid_node_name_is_400(api, seed):
    # netstats is one of the SSH-fronted reads guarded by _reject_bad_node (a
    # blueprint-unique defense-in-depth gate). A node name failing the RFC-1035-ish
    # regex is rejected 400 AFTER check_cluster_access but BEFORE the manager.
    admin = seed.user('root', role='admin', tenant_id='default')
    # inject the manager so the 404 gate can't be what returns non-200 instead
    api.set_manager(CID, _mgr(api, get_node_netstats={'interfaces': [], 'count': 0}))

    bad_route = f'/api/clusters/{CID}/nodes/bad;rm%20-rf/netstats'
    resp = api.as_user(admin).get(bad_route)
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'Invalid node name' in resp.get_json()['error']
    _current_mgr().get_node_netstats.assert_not_called()


# ---------------------------------------------------------------------------
# READ deny — cross-tenant user denied at the CLUSTER level (check_cluster_access).
# ---------------------------------------------------------------------------

def test_cross_tenant_user_denied_node_summary_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])   # owns cluster_2, not cluster_1
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager(CID, _mgr(api, get_node_summary={'node': NODE, 'status': 'online'}))

    resp = api.as_user(bob).get(SUMMARY_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # deny fired before the manager was consulted
    _current_mgr().get_node_summary.assert_not_called()


def test_pool_reach_user_allowed_at_cluster_level_200(api, seed):
    # A user reaching cluster_1 SOLELY via a pool grant: nodes.py has no
    # _require_vm_access, so cluster-level reach is sufficient for node.view reads
    # (the reach-only per-VM deny that exists for vms.py does NOT apply here).
    seed.tenant('tenant_a', clusters=['cluster_home'])   # does NOT own cluster_1
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.pool(CID, 'pool_1', 'alice', ['pool.view', 'vm.view'])  # reaches cluster_1
    api.set_manager(CID, _mgr(api, get_node_summary={'node': NODE, 'status': 'online'}))

    resp = api.as_user(alice).get(SUMMARY_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['node'] == NODE


# ===========================================================================
# WRITES — node.network gated (admin-only in this blueprint). This is the
# "privileged operation a plain user cannot perform" gate (node.shell has no
# route in nodes.py, so node.network is the analogous privileged write here).
# ===========================================================================

def test_user_without_node_network_denied_network_update_403(api, seed):
    # role 'user' holds node.view but NOT node.network -> 403 at the perm gate,
    # BEFORE check_cluster_access / the manager. Still inject the manager so a
    # missing 404-gate can't be what fails.
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager(CID, _mgr(api, update_node_network={'success': True, 'message': 'ok'}))

    resp = api.as_user(user).put(NET_IFACE_ROUTE, json={'address': '10.0.0.5'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().update_node_network.assert_not_called()


def test_viewer_without_node_network_denied_network_update_403(api, seed):
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    api.set_manager(CID, _mgr(api, update_node_network={'success': True, 'message': 'ok'}))

    resp = api.as_user(viewer).put(NET_IFACE_ROUTE, json={'address': '10.0.0.5'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().update_node_network.assert_not_called()


def test_admin_with_node_network_updates_iface_200(api, seed):
    # admin holds node.network -> reaches the manager. Success shape is
    # {'success': True, 'message': ...}; route returns {'message': ...}.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, update_node_network={
        'success': True, 'message': 'Interface vmbr0 updated'}))

    resp = api.as_user(admin).put(NET_IFACE_ROUTE, json={'address': '10.0.0.5', 'netmask': '24'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['message'] == 'Interface vmbr0 updated'
    # payload was forwarded to the manager
    _current_mgr().update_node_network.assert_called_once()
    call = _current_mgr().update_node_network.call_args
    assert call.args[0] == NODE and call.args[1] == 'vmbr0'
    assert call.args[2].get('address') == '10.0.0.5'


def test_admin_network_update_manager_failure_is_500(api, seed):
    # manager reports success=False -> route surfaces the error as 500.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, update_node_network={
        'success': False, 'error': 'ifreload failed'}))

    resp = api.as_user(admin).put(NET_IFACE_ROUTE, json={'address': 'bad'})
    assert resp.status_code == 500, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'ifreload failed'


def test_admin_create_network_missing_iface_is_400(api, seed):
    # validation gate fires before the manager is called.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, create_node_network={'success': True, 'message': 'x'}))

    resp = api.as_user(admin).post(NET_CREATE_ROUTE, json={'type': 'bridge'})  # no 'iface'
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'Interface name required' in resp.get_json()['error']
    _current_mgr().create_node_network.assert_not_called()


def test_admin_create_network_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, create_node_network={
        'success': True, 'message': 'Created vmbr9'}))

    resp = api.as_user(admin).post(NET_CREATE_ROUTE, json={
        'iface': 'vmbr9', 'type': 'bridge', 'address': '10.9.9.1'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['message'] == 'Created vmbr9'
    # iface/type stripped out of config, the rest forwarded
    _current_mgr().create_node_network.assert_called_once()
    args = _current_mgr().create_node_network.call_args.args
    assert args[0] == NODE and args[1] == 'vmbr9' and args[2] == 'bridge'
    assert args[3] == {'address': '10.9.9.1'}


def test_pool_reach_user_denied_network_write_403(api, seed):
    # The important companion to test_pool_reach_user_allowed_at_cluster_level_200:
    # reaching cluster_1 via a pool grant lets alice READ node.view data, but it
    # does NOT confer the admin-only node.network WRITE permission. The perm gate
    # (require_auth, which runs BEFORE check_cluster_access) still denies her 403.
    # This proves a reach grant is not a privilege grant.
    seed.tenant('tenant_a', clusters=['cluster_home'])   # does NOT own cluster_1
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.pool(CID, 'pool_1', 'alice', ['pool.view', 'vm.view'])  # reaches cluster_1
    api.set_manager(CID, _mgr(api, update_node_network={'success': True, 'message': 'ok'}))

    resp = api.as_user(alice).put(NET_IFACE_ROUTE, json={'address': '10.0.0.5'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().update_node_network.assert_not_called()


# ---------------------------------------------------------------------------
# admin.settings gated write — subscription update. A plain user is denied.
# ---------------------------------------------------------------------------

def test_user_denied_subscription_update_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager(CID, _mgr(api, update_node_subscription={'success': True, 'message': 'ok'}))

    resp = api.as_user(user).put(SUBSCRIPTION_ROUTE, json={'key': 'pve-1234'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().update_node_subscription.assert_not_called()


def test_admin_subscription_update_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, update_node_subscription={
        'success': True, 'message': 'Subscription key set'}))

    resp = api.as_user(admin).put(SUBSCRIPTION_ROUTE, json={'key': 'pve-1234'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['message'] == 'Subscription key set'
    _current_mgr().update_node_subscription.assert_called_once_with(NODE, 'pve-1234')


# ===========================================================================
# SET VM HA PRIORITY — vm.config gated (admin, user hold it; viewer does NOT).
# ===========================================================================

def test_viewer_denied_set_ha_priority_403(api, seed):
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    api.set_manager(CID, _mgr(api, set_vm_ha_restart_priority={'success': True}))

    resp = api.as_user(viewer).put(HA_PRIORITY_ROUTE, json={'priority': 'restart'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().set_vm_ha_restart_priority.assert_not_called()


def test_user_sets_ha_priority_200(api, seed):
    # role 'user' holds vm.config -> allowed; valid priority forwarded to manager.
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager(CID, _mgr(api, set_vm_ha_restart_priority={
        'success': True, 'priority': 'restart'}))

    resp = api.as_user(user).put(HA_PRIORITY_ROUTE, json={'priority': 'restart'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True
    _current_mgr().set_vm_ha_restart_priority.assert_called_once_with(100, 'restart')


def test_admin_sets_ha_priority_empty_string_200(api, seed):
    # empty string is a valid priority (clears HA priority) per the route validator.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, set_vm_ha_restart_priority={'success': True}))

    resp = api.as_user(admin).put(HA_PRIORITY_ROUTE, json={'priority': ''})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    _current_mgr().set_vm_ha_restart_priority.assert_called_once_with(100, '')


def test_set_ha_priority_invalid_value_is_400(api, seed):
    # validation fires before the manager call.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, set_vm_ha_restart_priority={'success': True}))

    resp = api.as_user(admin).put(HA_PRIORITY_ROUTE, json={'priority': 'nonsense'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'Invalid priority' in resp.get_json()['error']
    _current_mgr().set_vm_ha_restart_priority.assert_not_called()


def test_set_ha_priority_manager_failure_is_500(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, set_vm_ha_restart_priority={
        'success': False, 'error': 'no HA on this cluster'}))

    resp = api.as_user(admin).put(HA_PRIORITY_ROUTE, json={'priority': 'best-effort'})
    assert resp.status_code == 500, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'no HA on this cluster'


def test_cross_tenant_user_denied_set_ha_priority_403(api, seed):
    # cross-tenant denial for the HA-priority write (cluster level). Use admin-role
    # is exempt, so a non-admin non-default-tenant user is the right subject — they
    # hold vm.config via the 'user' role but are stopped by check_cluster_access.
    seed.tenant('tenant_d', clusters=['cluster_2'])
    dave = seed.user('dave', role='user', tenant_id='tenant_d')
    api.set_manager(CID, _mgr(api, set_vm_ha_restart_priority={'success': True}))

    resp = api.as_user(dave).put(HA_PRIORITY_ROUTE, json={'priority': 'restart'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().set_vm_ha_restart_priority.assert_not_called()


# ===========================================================================
# GUEST METRICS — vm.view gated (admin, user, viewer all hold it).
# ===========================================================================

def test_viewer_reads_guest_metrics_200(api, seed):
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    api.set_manager(CID, _mgr(api, get_guest_metrics={
        'memory_free': 2048, 'os_version': 'Debian 12', 'ip': '10.0.0.50'}))

    resp = api.as_user(viewer).get(GUEST_METRICS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['os_version'] == 'Debian 12'
    # route calls get_guest_metrics(None, vmid)
    _current_mgr().get_guest_metrics.assert_called_once_with(None, 100)


def test_cross_tenant_user_denied_guest_metrics_403(api, seed):
    seed.tenant('tenant_e', clusters=['cluster_2'])
    eve = seed.user('eve', role='user', tenant_id='tenant_e')
    api.set_manager(CID, _mgr(api, get_guest_metrics={'memory_free': 1}))

    resp = api.as_user(eve).get(GUEST_METRICS_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr().get_guest_metrics.assert_not_called()


def test_guest_metrics_unsupported_cluster_returns_empty_200(api, seed):
    # If the manager has no get_guest_metrics attribute, the route returns {} 200.
    # A MagicMock has every attribute, so simulate "unsupported" by deleting it.
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = _mgr(api)
    del fake.get_guest_metrics  # hasattr(mgr, 'get_guest_metrics') -> False
    api.set_manager(CID, fake)

    resp = api.as_user(admin).get(GUEST_METRICS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json() == {}


# ===========================================================================
# 404 gate — authorized user, but the cluster manager isn't loaded.
# ===========================================================================

def test_missing_cluster_manager_is_404(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    # deliberately do NOT set_manager -> passes auth + cluster-access, hits 404 gate.
    resp = api.as_user(admin).get(SUMMARY_ROUTE)
    assert resp.status_code == 404, resp.get_data(as_text=True)
    assert 'not found' in resp.get_json()['error'].lower()
