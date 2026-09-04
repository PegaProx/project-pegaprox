# E2E for the 2026-09 audit LOW metadata-list findings:
#   GET /api/clusters/<id>/excluded-vms   — load-balancer exclusions enumerated cluster-wide
#   GET /api/clusters/<id>/replication    — replication jobs (vmid/source/target) cluster-wide
# Both now confine a pool-/ACL-scoped caller to their own VMs (admins/plain operators keep all).
import time

import pegaprox.utils.rbac as rbac


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


# ── excluded-vms ──────────────────────────────────────────────────────────────
def test_excluded_vms_scoped(api, seed, db):
    u = _pool_user(seed)
    db.conn.execute('''CREATE TABLE IF NOT EXISTS balancing_excluded_vms (
        id INTEGER PRIMARY KEY AUTOINCREMENT, cluster_id TEXT NOT NULL, vmid INTEGER NOT NULL,
        reason TEXT, created_by TEXT, created_at TEXT, UNIQUE(cluster_id, vmid))''')
    for v in (100, 101):
        db.conn.execute('INSERT INTO balancing_excluded_vms (cluster_id, vmid, reason, created_by) VALUES (?,?,?,?)',
                        ('cluster_1', v, 'r', 'admin'))
    db.conn.commit()
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=[
        {'vmid': 100, 'name': 'a', 'type': 'qemu'}, {'vmid': 101, 'name': 'b', 'type': 'qemu'}])
    m.is_connected = True
    api.set_manager('cluster_1', m)
    resp = api.as_user(u).get('/api/clusters/cluster_1/excluded-vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(e['vmid'] for e in resp.get_json()['excluded_vms']) == [100]


# ── replication jobs ──────────────────────────────────────────────────────────
def test_replication_jobs_scoped(api, seed):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_replication_jobs.return_value = [
        {'id': '100-0', 'guest': 100, 'source': 'n1', 'target': 'n2'},
        {'id': '101-0', 'guest': 101, 'source': 'n1', 'target': 'n2'},
    ]
    api.set_manager('cluster_1', m)
    resp = api.as_user(u).get('/api/clusters/cluster_1/replication')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(j['guest'] for j in resp.get_json()) == [100]


def test_replication_jobs_admin_all(api, seed):
    admin = seed.user('root', role='admin')
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_replication_jobs.return_value = [{'id': '100-0', 'guest': 100}, {'id': '101-0', 'guest': 101}]
    api.set_manager('cluster_1', m)
    resp = api.as_user(admin).get('/api/clusters/cluster_1/replication')
    assert sorted(j['guest'] for j in resp.get_json()) == [100, 101]
