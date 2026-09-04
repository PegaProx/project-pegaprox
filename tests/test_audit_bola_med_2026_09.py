# Full-stack E2E for the 2026-09 audit MEDIUM list-scoping findings.
#   M2  GET /api/clusters/<id>/vms-backup-status  — was ACL-only, not pool-aware
#   M4  GET /api/clusters/<id>/templates/existing  — enumerated every template VM
#   M5  GET /api/clusters/<id>/insights/rollups     — aggregated the whole cluster
#   M6  GET /api/schedules                           — per-VM rows, cluster-filtered only
import time

import pegaprox.utils.rbac as rbac
import pegaprox.api.pbs as pbsmod
from pegaprox.api.schedules import save_schedules


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── M2: per-VM backup status ─────────────────────────────────────────────────
def test_m2_backup_status_pool_aware(api, seed):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    api.set_manager('cluster_1', m)
    # seed a fresh cache so the endpoint returns cached rows and only the scope filter runs
    pbsmod._backup_status_cache['cluster_1'] = (
        time.time(),
        [{'vmid': 100, 'last_backup_ts': 1, 'count_30d': 1, 'encrypted': True, 'last_verify_ts': 0},
         {'vmid': 101, 'last_backup_ts': 1, 'count_30d': 1, 'encrypted': False, 'last_verify_ts': 0}],
        300)
    try:
        resp = api.as_user(u).get('/api/clusters/cluster_1/vms-backup-status')
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert sorted(r['vmid'] for r in resp.get_json()) == [100], "pool user must only see their VM's backup posture"
    finally:
        pbsmod._backup_status_cache.clear()


# ── M4: existing templates ────────────────────────────────────────────────────
_TPL = [
    {'vmid': 100, 'name': 't100', 'node': 'n1', 'type': 'qemu', 'template': 1, 'maxdisk': 1, 'maxmem': 1},
    {'vmid': 101, 'name': 't101', 'node': 'n1', 'type': 'qemu', 'template': 1, 'maxdisk': 1, 'maxmem': 1},
]


def test_m4_existing_templates_scoped(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_TPL)))
    resp = api.as_user(u).get('/api/clusters/cluster_1/templates/existing')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(t['vmid'] for t in resp.get_json()['templates']) == [100]


def test_m4_existing_templates_admin_all(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_TPL)))
    resp = api.as_user(admin).get('/api/clusters/cluster_1/templates/existing')
    assert sorted(t['vmid'] for t in resp.get_json()['templates']) == [100, 101]


# ── M5: insights rollups ──────────────────────────────────────────────────────
_RVMS = [
    {'vmid': 100, 'name': 'a', 'type': 'qemu', 'status': 'running', 'tags': 'prod', 'cpu_percent': 1, 'mem': 1, 'maxmem': 2, 'maxdisk': 1},
    {'vmid': 101, 'name': 'b', 'type': 'qemu', 'status': 'running', 'tags': 'prod', 'cpu_percent': 1, 'mem': 1, 'maxmem': 2, 'maxdisk': 1},
    {'vmid': 900, 'name': 'c', 'type': 'qemu', 'status': 'running', 'tags': 'prod', 'cpu_percent': 1, 'mem': 1, 'maxmem': 2, 'maxdisk': 1},
]


def test_m5_rollups_scoped_total(api, seed):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_RVMS))
    m.is_connected = True
    api.set_manager('cluster_1', m)
    resp = api.as_user(u).get('/api/clusters/cluster_1/insights/rollups?group_by=tag')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['total_vms'] == 1, "pool user's rollup must count only their VM"


def test_m5_rollups_admin_total(api, seed):
    admin = seed.user('root', role='admin')
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_RVMS))
    m.is_connected = True
    api.set_manager('cluster_1', m)
    resp = api.as_user(admin).get('/api/clusters/cluster_1/insights/rollups?group_by=tag')
    assert resp.get_json()['total_vms'] == 3


# ── M6: schedules list ────────────────────────────────────────────────────────
def _seed_schedules():
    save_schedules({'actions': [
        {'id': 1, 'cluster_id': 'cluster_1', 'vmid': 100, 'vm_type': 'qemu', 'action': 'start',
         'schedule_type': 'daily', 'time': '02:00', 'enabled': True, 'created_by': 'admin'},
        {'id': 2, 'cluster_id': 'cluster_1', 'vmid': 101, 'vm_type': 'qemu', 'action': 'stop',
         'schedule_type': 'daily', 'time': '03:00', 'enabled': True, 'created_by': 'admin'},
    ]})


def test_m6_schedules_list_scoped(api, seed):
    u = _pool_user(seed)
    _seed_schedules()
    resp = api.as_user(u).get('/api/schedules')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(a['vmid'] for a in resp.get_json()) == [100], "pool user must only see their VM's schedules"


def test_m6_schedules_list_admin_all(api, seed):
    admin = seed.user('root', role='admin')
    _seed_schedules()
    resp = api.as_user(admin).get('/api/schedules')
    assert sorted(a['vmid'] for a in resp.get_json()) == [100, 101]
