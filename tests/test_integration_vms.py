# Full-stack integration suite for the `vms` blueprint — the per-VM lifecycle +
# detail routes BEYOND /config (which the smoke test already pins). This is the
# biggest per-VM authz surface in the codebase (45+ _require_vm_access guards),
# so the point here is to prove — through the REAL Flask stack, not a direct RBAC
# unit call — that each op fires the SAME decision a browser/attacker would get:
#
#   require_auth(perm)  -> 401 (no session) / 403 (role lacks perm)
#   check_cluster_access -> 403 (cross-tenant, cluster not reachable)
#   "cluster not in cluster_managers" -> 404
#   _require_vm_access / user_can_access_vm -> 403 (pool/ACL reach-only)
#   manager.<method>(...) -> 2xx / 5xx
#
# Deny tests still inject a fake manager so the 404 gate can't fire first; they
# assert 403/401 AND that the manager method was never invoked. Allow tests stub
# the EXACT method + success shape the handler reads (verified against vms.py) so
# the route returns real JSON rather than jsonify-ing a MagicMock and 500-ing.
#
# Reference: tests/test_integration_smoke.py (harness) — do NOT edit conftest.py.

import pegaprox.globals as _ppglobals


# --------------------------------------------------------------------------- #
# route builders — one place so a path typo can't drift between tests
# --------------------------------------------------------------------------- #
CID = 'cluster_1'
BASE = f'/api/clusters/{CID}/vms/pve1/qemu/100'


def _action(act):        return f'{BASE}/{act}'                      # POST  start/stop/...
def _clone():            return f'{BASE}/clone'                      # POST
def _snapshots():        return f'{BASE}/snapshots'                  # GET / POST
def _snapshot(name):     return f'{BASE}/snapshots/{name}'           # DELETE
def _rollback(name):     return f'{BASE}/snapshots/{name}/rollback'  # POST
def _resize():           return f'{BASE}/resize'                     # PUT
def _move(disk):         return f'{BASE}/disks/{disk}/move'          # POST
def _migrate():          return f'{BASE}/migrate'                    # POST
def _remote_migrate():   return f'{BASE}/remote-migrate'             # POST
def _unlock():           return f'{BASE}/unlock'                     # POST
def _guest_file_read():  return f'{BASE}/guest-file-read'            # POST
def _delete_vm():        return BASE                                 # DELETE


def _mgr(api):
    """A fake cluster_1 manager for deny-path tests. All the per-VM methods this
    suite touches are present but never reached on a 403 path — the deny fires
    upstream of the manager call, which the tests then assert."""
    return api.make_fake_manager(cluster_id=CID)


def _mgr_method(name):
    """The live injected fake manager for cluster_1, to assert a method was (not) called."""
    return _ppglobals.cluster_managers[CID]


# =========================================================================== #
# unauthenticated — 401 before anything else
# =========================================================================== #

def test_anon_vm_action_is_401(api, seed):
    fake = api.set_manager(CID, _mgr(api))
    resp = api.anon().post(_action('start'), json={})
    assert resp.status_code == 401
    # 401 fires in require_auth, upstream of everything — manager untouched
    fake.vm_action.assert_not_called()


def test_anon_snapshot_list_is_401(api, seed):
    api.set_manager(CID, _mgr(api))
    resp = api.anon().get(_snapshots())
    assert resp.status_code == 401


# =========================================================================== #
# ALLOW paths — an admin (default tenant => all clusters) reaches the stubbed
# manager and gets the handler's real success JSON back.
# =========================================================================== #

def test_admin_start_vm_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID,
        vm_action={'success': True, 'data': 'UPID:pve1:vm-action:'},
    ))
    resp = api.as_user(admin).post(_action('start'), json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert 'start successful' in body['message']
    # the manager op ran with the routed args (node, vmid, vm_type, action)
    fake.vm_action.assert_called_once()
    call = fake.vm_action.call_args
    assert call.args[0] == 'pve1'          # node
    assert call.args[1] == 100             # vmid (int converter)
    assert 'start' in call.args


def test_admin_stop_vm_maps_to_vm_stop_perm_200(api, seed):
    # a different action to prove the perm_map branch is exercised end-to-end
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, vm_action={'success': True, 'data': None}))
    resp = api.as_user(admin).post(_action('stop'), json={'force': True})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'stop successful' in resp.get_json()['message']
    assert fake.vm_action.call_args.kwargs.get('force') is True


def test_admin_invalid_action_is_400(api, seed):
    # validation runs AFTER the manager-exists gate but BEFORE the manager call
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(_action('frobnicate'), json={})
    assert resp.status_code == 400
    fake.vm_action.assert_not_called()


def test_admin_clone_vm_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID,
        clone_vm={'success': True, 'data': 'UPID:pve1:clone:'},
    ))
    resp = api.as_user(admin).post(_clone(), json={'newid': 999, 'name': 'clone01'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['newid'] == 999
    fake.clone_vm.assert_called_once()
    assert fake.clone_vm.call_args.kwargs['newid'] == 999


def test_admin_list_snapshots_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    snaps = [{'name': 'current', 'snaptime': 0},
             {'name': 'preupdate', 'snaptime': 1710000000, 'description': 'before patch'}]
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID, get_snapshots=snaps))
    resp = api.as_user(admin).get(_snapshots())
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list) and body[1]['name'] == 'preupdate'


def test_admin_create_snapshot_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, create_snapshot={'success': True, 'task': 'UPID:pve1:snap:'}))
    resp = api.as_user(admin).post(_snapshots(), json={'snapname': 'nightly', 'vmstate': True})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'nightly' in resp.get_json()['message']
    assert fake.create_snapshot.call_args.args[3] == 'nightly'   # (node, vmid, type, snapname, ...)


def test_admin_delete_snapshot_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, delete_snapshot={'success': True, 'task': 'UPID:pve1:delsnap:'}))
    resp = api.as_user(admin).delete(_snapshot('nightly'))
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['message'] == 'Snapshot deleted'
    fake.delete_snapshot.assert_called_once()


def test_admin_rollback_snapshot_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, rollback_snapshot={'success': True, 'task': 'UPID:pve1:rb:'}))
    resp = api.as_user(admin).post(_rollback('nightly'), json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'nightly' in resp.get_json()['message']
    fake.rollback_snapshot.assert_called_once()


def test_admin_resize_disk_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, resize_vm_disk={'success': True, 'message': 'scsi0 resized to +8G'}))
    resp = api.as_user(admin).put(_resize(), json={'disk': 'scsi0', 'size': '+8G'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'resized' in resp.get_json()['message']
    assert fake.resize_vm_disk.call_args.args[3:5] == ('scsi0', '+8G')


def test_resize_disk_missing_params_is_400(api, seed):
    # 400 validation is downstream of authz + the manager gate, upstream of the mgr call
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).put(_resize(), json={'disk': 'scsi0'})   # no size
    assert resp.status_code == 400
    fake.resize_vm_disk.assert_not_called()


def test_admin_move_disk_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, move_disk={'success': True, 'message': 'moved', 'task': 'UPID:pve1:move:'}))
    resp = api.as_user(admin).post(_move('scsi0'), json={'storage': 'ceph-pool'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['task'] == 'UPID:pve1:move:'
    assert fake.move_disk.call_args.args[4] == 'ceph-pool'   # target_storage


def test_admin_migrate_vm_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    # migrate runs check_affinity_violation() which calls manager.get_vm_resources();
    # an empty resource list -> no affinity rule matches -> {'violation': False}.
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID,
        get_vm_resources=[],
        migrate_vm_manual={'success': True, 'upid': 'UPID:pve1:migrate:'}))
    resp = api.as_user(admin).post(_migrate(), json={'target': 'pve2', 'online': True})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True and body['upid'] == 'UPID:pve1:migrate:'
    assert fake.migrate_vm_manual.call_args.args[3] == 'pve2'   # target_node


def test_migrate_vm_missing_target_is_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(_migrate(), json={'online': True})   # no target
    assert resp.status_code == 400
    fake.migrate_vm_manual.assert_not_called()


def test_admin_remote_migrate_vm_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, remote_migrate_vm={'success': True, 'task': 'UPID:pve1:rmig:'}))
    resp = api.as_user(admin).post(_remote_migrate(), json={
        'target_endpoint': 'https://other:8006',
        'target_storage': 'local-lvm',
        'target_bridge': 'vmbr0',
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'Remote migration started' in resp.get_json()['message']
    fake.remote_migrate_vm.assert_called_once()


def test_admin_delete_vm_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, delete_vm={'success': True, 'task': 'UPID:pve1:destroy:'}))
    resp = api.as_user(admin).delete(_delete_vm(), json={'purge': True})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert '100 deleted' in resp.get_json()['message']
    assert fake.delete_vm.call_args.args[3] is True   # purge flag


def test_admin_unlock_vm_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID,
        unlock_vm={'success': True, 'message': 'unlocked', 'was_locked': True,
                   'lock_reason': 'backup'}))
    resp = api.as_user(admin).post(_unlock(), json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['was_locked'] is True and body['lock_reason'] == 'backup'
    fake.unlock_vm.assert_called_once()


# =========================================================================== #
# ALLOW path — same-tenant plain 'user' (default tenant reaches all clusters,
# role 'user' holds vm.snapshot) can act on a VM with NO per-VM ACL. Proves VM
# ACLs are ADDITIVE grants, not a blanket restriction (the 2026-07-12 correction).
# =========================================================================== #

def test_same_tenant_user_creates_snapshot_without_acl_200(api, seed):
    user = seed.user('dev', role='user', tenant_id='default')
    fake = api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, create_snapshot={'success': True, 'task': 'UPID:pve1:snap:'}))
    resp = api.as_user(user).post(_snapshots(), json={'snapname': 'wip'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    fake.create_snapshot.assert_called_once()


# =========================================================================== #
# DENY A — role lacks the required permission => require_auth 403, upstream of
# any cluster/VM check. A viewer (default tenant, reaches the cluster) has
# vm.view/vm.console only; it may NOT snapshot / resize / clone / migrate / delete.
# =========================================================================== #

def test_viewer_denied_create_snapshot_403(api, seed):
    viewer = seed.user('watcher', role='viewer', tenant_id='default')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(viewer).post(_snapshots(), json={'snapname': 'x'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _mgr_method('create_snapshot')  # ensure present
    _ppglobals.cluster_managers[CID].create_snapshot.assert_not_called()


def test_viewer_denied_resize_disk_403(api, seed):
    viewer = seed.user('watcher', role='viewer', tenant_id='default')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(viewer).put(_resize(), json={'disk': 'scsi0', 'size': '+1G'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].resize_vm_disk.assert_not_called()


def test_viewer_denied_delete_vm_403(api, seed):
    viewer = seed.user('watcher', role='viewer', tenant_id='default')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(viewer).delete(_delete_vm(), json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].delete_vm.assert_not_called()


def test_viewer_denied_vm_start_action_403(api, seed):
    # vm_action_api uses @require_auth() (no perm) then user_can_access_vm(..,'vm.start')
    # internally: a viewer's role lacks vm.start -> 403 without ever calling vm_action.
    viewer = seed.user('watcher', role='viewer', tenant_id='default')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(viewer).post(_action('start'), json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].vm_action.assert_not_called()


def test_viewer_denied_migrate_403(api, seed):
    # migrate is @require_auth(perms=['vm.migrate']); a viewer's role lacks vm.migrate,
    # so the perm gate 403s in require_auth — upstream of cluster/VM checks and the
    # affinity walk. This pins the require_auth perm layer for the migrate verb
    # (distinct from the cross-tenant cluster-level and pool-reach VM-level denies).
    viewer = seed.user('watcher', role='viewer', tenant_id='default')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(viewer).post(_migrate(), json={'target': 'pve2'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].migrate_vm_manual.assert_not_called()


# =========================================================================== #
# DENY B — cross-tenant user is stopped at the CLUSTER level (check_cluster_access
# 403) before the VM check. Tenant_b owns cluster_2, not cluster_1.
# =========================================================================== #

def test_cross_tenant_denied_migrate_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(bob).post(_migrate(), json={'target': 'pve2'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].migrate_vm_manual.assert_not_called()


def test_cross_tenant_denied_delete_vm_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(bob).delete(_delete_vm(), json={'purge': True})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].delete_vm.assert_not_called()


def test_cross_tenant_denied_snapshot_list_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    resp = api.as_user(bob).get(_snapshots())
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].get_snapshots.assert_not_called()


# =========================================================================== #
# DENY C — pool-reach-only: a user in a NON-default tenant reaches cluster_1
# SOLELY through a pool grant. check_cluster_access lets them onto the cluster,
# but VM 100 is outside their pool grant AND cluster_1 isn't in their tenant set,
# so _require_vm_access / user_can_access_vm denies at the VM level (rbac.py:854).
# This is the ONLY per-VM DENY the model has — assert it on each verb the
# blueprint gates per-VM.
# =========================================================================== #

def _pool_reach_user(api, seed, perms=('pool.view', 'vm.view')):
    seed.tenant('tenant_a', clusters=['cluster_home'])        # does NOT own cluster_1
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.pool(CID, 'pool_1', 'alice', list(perms))            # reaches cluster_1 only
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID))
    return alice


def test_pool_reach_denied_at_vm_level_snapshot_list_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).get(_snapshots())
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].get_snapshots.assert_not_called()


def test_pool_reach_denied_at_vm_level_resize_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).put(_resize(), json={'disk': 'scsi0', 'size': '+1G'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].resize_vm_disk.assert_not_called()


def test_pool_reach_denied_at_vm_level_move_disk_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_move('scsi0'), json={'storage': 'ceph'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].move_disk.assert_not_called()


def test_pool_reach_denied_at_vm_level_unlock_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_unlock(), json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].unlock_vm.assert_not_called()


def test_pool_reach_denied_at_vm_level_clone_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_clone(), json={'newid': 999})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].clone_vm.assert_not_called()


def test_pool_reach_denied_at_vm_level_migrate_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_migrate(), json={'target': 'pve2'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].migrate_vm_manual.assert_not_called()


def test_pool_reach_denied_at_vm_level_remote_migrate_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_remote_migrate(), json={
        'target_endpoint': 'https://other:8006',
        'target_storage': 'local-lvm', 'target_bridge': 'vmbr0'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].remote_migrate_vm.assert_not_called()


def test_pool_reach_denied_at_vm_level_delete_vm_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).delete(_delete_vm(), json={'purge': True})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].delete_vm.assert_not_called()


def test_pool_reach_denied_at_vm_level_vm_action_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_action('stop'), json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _ppglobals.cluster_managers[CID].vm_action.assert_not_called()


def test_pool_reach_denied_at_vm_level_guest_file_read_403(api, seed):
    alice = _pool_reach_user(api, seed)
    resp = api.as_user(alice).post(_guest_file_read(), json={'file': '/etc/hostname'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # deny fires at _require_vm_access, upstream of the raw mgr._api_post the
    # allow-path would make — so the guest-agent HTTP call is never issued.
    _ppglobals.cluster_managers[CID]._api_post.assert_not_called()


# =========================================================================== #
# 404 gate — an authed, authorized admin hitting a cluster with NO manager
# registered gets 404 (proves the manager-existence gate, not a stray 500/200).
# =========================================================================== #

def test_admin_snapshot_list_no_manager_is_404(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    # deliberately do NOT set_manager(cluster_1, ...)
    resp = api.as_user(admin).get(_snapshots())
    assert resp.status_code == 404, resp.get_data(as_text=True)
