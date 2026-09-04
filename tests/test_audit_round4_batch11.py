# E2E for the Round-4 broad-sweep fixes (Batch 11). Same per-object-scoping class in read/list spots.
#   #1 storage content list — scope vmid-carrying rows (ISO/vztmpl rows stay)
#   #2 datacenter backup-job list — read-side of the _authz_backup_targets write gate
#   #3/#4 site_recovery check_readiness / cancel_action — per-VM plan gate (2 routes missed in Batch 8)
#   #6 get_user_vm_access — cross-tenant read guard (mirrors get_user_perms)
# (#5 insights force-snapshot cluster-filter and #7 error-body sanitisation are verified by code review;
#  they depend on the background metrics collector / triggering an exception and aren't cleanly harnessable.)
import time
import types

import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                  permissions=['storage.view', 'backup.view', 'vm.backup', 'site_recovery.failover'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _mgr_with_get(api, payload):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m._create_session.return_value.get.return_value = types.SimpleNamespace(
        status_code=200, text='', json=lambda: {'data': payload})
    return m


# ── #1 storage content list ──────────────────────────────────────────────────
_CONTENT = [
    {'volid': 'local:vm-100-disk-0', 'vmid': 100, 'size': 1, 'content': 'images'},
    {'volid': 'local:vm-200-disk-0', 'vmid': 200, 'size': 1, 'content': 'images'},
    {'volid': 'local:iso/ubuntu.iso', 'content': 'iso', 'size': 1},   # no vmid — shared, must stay
]


def test_storage_content_scoped(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_with_get(api, _CONTENT))
    body = api.as_user(u).get('/api/clusters/cluster_1/nodes/n1/storage/local/content').get_json()
    volids = sorted(r['volid'] for r in body)
    assert 'local:vm-100-disk-0' in volids, "own VM's disk must stay"
    assert 'local:vm-200-disk-0' not in volids, "foreign VM's disk must be hidden"
    assert 'local:iso/ubuntu.iso' in volids, "shared ISO (no vmid) must stay"


def test_storage_content_admin_all(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _mgr_with_get(api, _CONTENT))
    body = api.as_user(admin).get('/api/clusters/cluster_1/nodes/n1/storage/local/content').get_json()
    assert len(body) == 3


# ── #2 datacenter backup-job list ─────────────────────────────────────────────
_JOBS = [
    {'id': 'job1', 'vmid': '100', 'schedule': 'daily'},   # mallory owns 100
    {'id': 'job2', 'vmid': '200', 'schedule': 'daily'},   # foreign
    {'id': 'job3', 'all': '1', 'schedule': 'daily'},       # cluster-wide → admin-only
]


def test_backup_jobs_scoped(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_with_get(api, _JOBS))
    body = api.as_user(u).get('/api/clusters/cluster_1/datacenter/backup').get_json()
    assert sorted(j['id'] for j in body) == ['job1'], f"pool user sees only jobs they own; got {body}"


def test_backup_jobs_admin_all(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _mgr_with_get(api, _JOBS))
    body = api.as_user(admin).get('/api/clusters/cluster_1/datacenter/backup').get_json()
    assert sorted(j['id'] for j in body) == ['job1', 'job2', 'job3']


# ── #3/#4 site_recovery readiness + cancel ────────────────────────────────────
def _seed_plan(db):
    db.conn.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, status) "
                    "VALUES ('plan1','g1','p','cluster_1','cluster_1','running')")
    db.conn.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type) "
                    "VALUES ('v1','plan1',999,'foreign','qemu')")
    db.conn.commit()


def test_site_recovery_readiness_foreign_denied(api, seed, db):
    u = _pool_user(seed)
    _seed_plan(db)
    assert api.as_user(u).post('/api/site-recovery/plans/plan1/readiness').status_code == 403


def test_site_recovery_cancel_foreign_denied(api, seed, db):
    u = _pool_user(seed)
    _seed_plan(db)
    assert api.as_user(u).post('/api/site-recovery/plans/plan1/cancel').status_code == 403


# ── #6 get_user_vm_access cross-tenant ────────────────────────────────────────
def test_vm_access_cross_tenant_denied(api, seed):
    seed.tenant('tenant_a', clusters=[])
    seed.tenant('tenant_b', clusters=[])
    tadmin = seed.user('tadmin', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('victim', role='user', tenant_id='tenant_b')
    rbac.tenants_db = {}
    assert api.as_user(tadmin).get('/api/users/victim/vm-access').status_code == 403


def test_vm_access_global_admin_allowed(api, seed):
    seed.tenant('tenant_b', clusters=[])
    admin = seed.user('root', role='admin')
    seed.user('victim', role='user', tenant_id='tenant_b')
    rbac.tenants_db = {}
    assert api.as_user(admin).get('/api/users/victim/vm-access').status_code == 200
