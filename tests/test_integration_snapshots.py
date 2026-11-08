# Full-stack integration suite for the per-VM SNAPSHOT CRUD routes.
#
# The FOCUS is the per-VM snapshot lifecycle: list / create / delete / rollback.
# Those routes live in pegaprox/api/vms.py (5383-5486) — snapshots.py itself is the
# snapshot-SCHEDULING (policies) blueprint; the "per-VM snapshot CRUD, list/create/
# delete/rollback, all per-VM => cross-tenant + pool-reach-only deny + admin allow"
# the task describes is exactly these four VM-scoped endpoints, each guarded by a
# per-VM authz check (_require_vm_access on the read, user_can_access_vm on the
# writes). This suite drives them through the REAL Flask app end-to-end, faking only
# the cluster manager — the same style as tests/test_integration_smoke.py.
#
# Route → guard → manager method → success shape (read from vms.py):
#   GET    .../snapshots                    vm.view     _require_vm_access(vm.view)      get_snapshots  -> List[Dict]  (jsonify'd as-is)
#   POST   .../snapshots                    vm.snapshot user_can_access_vm(vm.snapshot)  create_snapshot -> {'success':True,'task':..}
#   DELETE .../snapshots/<snap>             vm.snapshot user_can_access_vm(vm.snapshot)  delete_snapshot -> {'success':True,'task':..}
#   POST   .../snapshots/<snap>/rollback    vm.snapshot user_can_access_vm(vm.snapshot)  rollback_snapshot-> {'success':True,'task':..}
#
# Handler order (all four): require_auth(perm) -> check_cluster_access (403) ->
# "cluster not in cluster_managers" (404) -> per-VM authz (403) -> manager call.
# So deny tests still set the manager (so the 404 gate doesn't fire first) and, on
# the deny path, assert the manager method was never invoked.

VMID = 100
BASE = f'/api/clusters/cluster_1/vms/pve1/qemu/{VMID}'
LIST_ROUTE = f'{BASE}/snapshots'
CREATE_ROUTE = f'{BASE}/snapshots'
DELETE_ROUTE = f'{BASE}/snapshots/snap1'
ROLLBACK_ROUTE = f'{BASE}/snapshots/snap1/rollback'

_TASK = 'UPID:pve1:00001234:qemu:100:snap:root@pam:'


def _snap_manager(api):
    """A fake manager wired for every snapshot op on the allow-path.

    - get_snapshots      -> a plain list (route jsonify's it directly)
    - create/delete/rollback -> {'success': True, 'task': ...}
    - config.name is a REAL string because the success branch passes it to
      log_audit(cluster=mgr.config.name); a bare MagicMock there is asking for a
      sanitize/DB write on a mock. Pin it so the allow-path can't 500 on audit.
    """
    fake = api.make_fake_manager(
        cluster_id='cluster_1',
        get_snapshots=[
            {'name': 'snap1', 'description': 'before upgrade', 'snaptime': 1700000000},
            {'name': 'current', 'description': 'You are here!'},
        ],
        create_snapshot={'success': True, 'task': _TASK},
        delete_snapshot={'success': True, 'task': _TASK},
        rollback_snapshot={'success': True, 'task': _TASK},
    )
    fake.config.name = 'cluster_1'
    return fake


def _mgr_in_globals():
    return __import__('pegaprox.globals', fromlist=['cluster_managers']).cluster_managers['cluster_1']


# ---------------------------------------------------------------------------
# unauthenticated -> 401 on every verb, manager never touched
# ---------------------------------------------------------------------------

def test_anon_list_is_401(api, seed):
    api.set_manager('cluster_1', _snap_manager(api))
    resp = api.anon().get(LIST_ROUTE)
    assert resp.status_code == 401
    _mgr_in_globals().get_snapshots.assert_not_called()


def test_anon_create_is_401(api, seed):
    api.set_manager('cluster_1', _snap_manager(api))
    resp = api.anon().post(CREATE_ROUTE, json={'snapname': 'x'})
    assert resp.status_code == 401
    _mgr_in_globals().create_snapshot.assert_not_called()


def test_anon_rollback_is_401(api, seed):
    api.set_manager('cluster_1', _snap_manager(api))
    resp = api.anon().post(ROLLBACK_ROUTE, json={})
    assert resp.status_code == 401
    _mgr_in_globals().rollback_snapshot.assert_not_called()


# ---------------------------------------------------------------------------
# ALLOW — an admin (default tenant => all clusters) drives the full lifecycle.
# ---------------------------------------------------------------------------

def test_admin_lists_snapshots_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(admin).get(LIST_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    # route jsonify's the manager's list verbatim
    assert isinstance(body, list)
    names = {s['name'] for s in body}
    assert 'snap1' in names and 'current' in names
    _mgr_in_globals().get_snapshots.assert_called_once()


def test_admin_creates_snapshot_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(admin).post(CREATE_ROUTE,
                                   json={'snapname': 'pre-patch', 'description': 'nightly',
                                         'vmstate': True})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert 'pre-patch' in body['message']
    assert body['task'] == _TASK
    mgr = _mgr_in_globals()
    mgr.create_snapshot.assert_called_once()
    # snapname + vmstate flowed through to the manager call
    args = mgr.create_snapshot.call_args.args
    assert 'pre-patch' in args
    assert args[-1] is True  # vmstate


def test_admin_deletes_snapshot_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(admin).delete(DELETE_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert 'deleted' in body['message'].lower()
    assert body['task'] == _TASK
    mgr = _mgr_in_globals()
    mgr.delete_snapshot.assert_called_once()
    assert 'snap1' in mgr.delete_snapshot.call_args.args


def test_admin_rolls_back_snapshot_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(admin).post(ROLLBACK_ROUTE, json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert 'snap1' in body['message']
    assert body['task'] == _TASK
    mgr = _mgr_in_globals()
    mgr.rollback_snapshot.assert_called_once()
    assert 'snap1' in mgr.rollback_snapshot.call_args.args


# ---------------------------------------------------------------------------
# ALLOW — a plain 'user' in the DEFAULT tenant also reaches the VM (default
# tenant is all-cluster; VM-ACLs are additive grants, not restrictions).
# vm.snapshot is in the default user permission set, so create must go through.
# ---------------------------------------------------------------------------

def test_default_tenant_user_creates_snapshot_200(api, seed):
    alice = seed.user('alice', role='user', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(alice).post(CREATE_ROUTE, json={'snapname': 'user-snap'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'user-snap' in resp.get_json()['message']
    _mgr_in_globals().create_snapshot.assert_called_once()


# ---------------------------------------------------------------------------
# PERMISSION gate — a default-tenant VIEWER reaches the VM (default tenant is
# all-cluster, vm.view is in the viewer set) so the read succeeds, but the
# write routes require vm.snapshot which viewers lack: the require_auth(perm)
# decorator returns 403 BEFORE the handler body, so the manager is never
# consulted. This exercises the perm gate — distinct from the tenant/reach guards.
# ---------------------------------------------------------------------------

def test_viewer_lists_snapshots_200(api, seed):
    viewer = seed.user('val', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(viewer).get(LIST_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert {s['name'] for s in resp.get_json()} == {'snap1', 'current'}
    _mgr_in_globals().get_snapshots.assert_called_once()


def test_viewer_denied_create_403(api, seed):
    viewer = seed.user('val', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(viewer).post(CREATE_ROUTE, json={'snapname': 'nope'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # blocked by the require_auth(perms=['vm.snapshot']) decorator, so the route
    # body — and therefore the manager — is never reached.
    _mgr_in_globals().create_snapshot.assert_not_called()


# ---------------------------------------------------------------------------
# DENY A — cluster-level: a cross-tenant user is rejected by check_cluster_access
# BEFORE the per-VM check or the manager is ever consulted (403, not 404).
# ---------------------------------------------------------------------------

def test_cross_tenant_user_denied_list_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])   # owns cluster_2, not cluster_1
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(bob).get(LIST_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # prove it's the CLUSTER-level gate (check_cluster_access), not the VM guard —
    # a refactor that let a cross-tenant user reach the VM check would be a real bug
    # even if it still 403'd there for another reason.
    assert resp.get_json()['error'] == 'Access denied to this cluster'
    _mgr_in_globals().get_snapshots.assert_not_called()


def test_cross_tenant_user_denied_create_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(bob).post(CREATE_ROUTE, json={'snapname': 'nope'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'Access denied to this cluster'
    _mgr_in_globals().create_snapshot.assert_not_called()


def test_cross_tenant_user_denied_delete_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(bob).delete(DELETE_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'Access denied to this cluster'
    _mgr_in_globals().delete_snapshot.assert_not_called()


# ---------------------------------------------------------------------------
# DENY B — VM-level reach-only: a user in a NON-default tenant who reaches
# cluster_1 SOLELY via a pool grant (on a different VM) is denied VM 100, which
# is outside that grant. This is the rbac.py:853 reach guard, proven over HTTP.
# The cluster gate passes (pool fallback in check_cluster_access); the per-VM
# guard (_require_vm_access on read / user_can_access_vm on write) fires the 403.
# ---------------------------------------------------------------------------

def test_pool_reach_user_denied_list_403(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_home'])        # does NOT own cluster_1
    carol = seed.user('carol', role='user', tenant_id='tenant_a')
    seed.pool('cluster_1', 'pool_1', 'carol', ['pool.view', 'vm.view'])  # reaches cluster_1
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(carol).get(LIST_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # carol PASSES the cluster gate (pool fallback) — the 403 MUST come from the
    # per-VM reach guard (rbac.py:853), not the cluster gate. Assert the VM-level
    # error so a regression that denies her at the cluster level (masking a broken
    # reach guard behind a still-green 403) is caught.
    assert resp.get_json()['error'] == 'Access denied to this VM (vm.view)'
    _mgr_in_globals().get_snapshots.assert_not_called()


def test_pool_reach_user_denied_create_403(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_home'])
    carol = seed.user('carol', role='user', tenant_id='tenant_a')
    seed.pool('cluster_1', 'pool_1', 'carol', ['pool.view', 'vm.snapshot'])
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(carol).post(CREATE_ROUTE, json={'snapname': 'nope'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # VM-level (user_can_access_vm) deny, not the cluster gate: carol holds
    # vm.snapshot on the pool so the cluster gate lets her in — VM 100 isn't in
    # that pool, so the reach guard is the only thing that can stop her here.
    assert resp.get_json()['error'] == 'Permission denied: vm.snapshot'
    _mgr_in_globals().create_snapshot.assert_not_called()


def test_pool_reach_user_denied_delete_403(api, seed):
    # destructive op — prove the reach guard blocks DELETE too, not just create.
    seed.tenant('tenant_a', clusters=['cluster_home'])
    carol = seed.user('carol', role='user', tenant_id='tenant_a')
    seed.pool('cluster_1', 'pool_1', 'carol', ['pool.view', 'vm.snapshot'])
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(carol).delete(DELETE_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'Permission denied: vm.snapshot'
    _mgr_in_globals().delete_snapshot.assert_not_called()


def test_pool_reach_user_denied_rollback_403(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_home'])
    carol = seed.user('carol', role='user', tenant_id='tenant_a')
    seed.pool('cluster_1', 'pool_1', 'carol', ['pool.view', 'vm.snapshot'])
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(carol).post(ROLLBACK_ROUTE, json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'Permission denied: vm.snapshot'
    _mgr_in_globals().rollback_snapshot.assert_not_called()


# ---------------------------------------------------------------------------
# ALLOW via ADDITIVE ACL — a non-default-tenant user granted VM 100 by ACL
# (with vm.snapshot) reaches the cluster (ACL fallback) AND passes the per-VM
# guard, so the create goes through. Proves the grant is additive, not a block.
# ---------------------------------------------------------------------------

def test_acl_granted_user_creates_snapshot_200(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_home'])   # not cluster_1
    dave = seed.user('dave', role='user', tenant_id='tenant_a')
    # ACL grant for THIS exact VM, with the snapshot perm, no role inheritance
    seed.vm_acl('cluster_1', VMID, users=['dave'], inherit_role=False,
                permissions=['vm.view', 'vm.snapshot'])
    api.set_manager('cluster_1', _snap_manager(api))

    resp = api.as_user(dave).post(CREATE_ROUTE, json={'snapname': 'acl-snap'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'acl-snap' in resp.get_json()['message']
    _mgr_in_globals().create_snapshot.assert_called_once()


# ---------------------------------------------------------------------------
# 404 gate — an authorized admin hitting a cluster with NO manager registered
# gets the "Cluster not found" 404 (the gate that sits before the per-VM check
# on these routes). Confirms the ordering the deny tests rely on.
# ---------------------------------------------------------------------------

def test_admin_missing_manager_is_404(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    # deliberately do NOT set a manager for cluster_1
    resp = api.as_user(admin).get(LIST_ROUTE)
    assert resp.status_code == 404, resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# manager failure path — create_snapshot returning {'success': False} surfaces
# as a 500 with the error message (the else branch of the handler).
# ---------------------------------------------------------------------------

def test_create_snapshot_manager_failure_500(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = _snap_manager(api)
    fake.create_snapshot.return_value = {'success': False, 'error': 'VM is locked'}
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).post(CREATE_ROUTE, json={'snapname': 'boom'})
    assert resp.status_code == 500, resp.get_data(as_text=True)
    assert resp.get_json()['error'] == 'VM is locked'


# ---------------------------------------------------------------------------
# CSRF plumbing — a state-changing snapshot POST without the same-origin/XHR
# proof is rejected by the CSRF gate even when authenticated; the harness's own
# post() (which adds those headers) sails past it (proven by the allow tests).
# ---------------------------------------------------------------------------

def _csrf_blocked(resp):
    if resp.status_code != 403:
        return False
    return (resp.get_json(silent=True) or {}).get('error') == 'CSRF validation failed'


def test_create_without_csrf_headers_is_blocked(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _snap_manager(api))
    sid = api.as_user(admin).session_id
    raw = api.app.test_client()
    resp = raw.post(CREATE_ROUTE, json={'snapname': 'x'},
                    headers={'X-Session-ID': sid}, base_url='http://localhost')
    assert _csrf_blocked(resp) is True
    _mgr_in_globals().create_snapshot.assert_not_called()
