# #773 follow-up audit — five read endpoints enumerated every VM on a cluster via
# get_vm_resources() and returned per-VM rows gated only by check_cluster_access (tenant/cluster
# reach), so a pool-/ACL-scoped user got per-VM data for VMs outside their grant — the same class
# as the /resources leak. All now route their per-VM rows through helpers.scope_vm_rows(), which
# filters by user_can_access_vm. Admins / plain cluster-wide operators keep every row; a pool user
# is confined to their pool's VMs.

import time

import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


# 100 is in mallory's pool; 101 and 900 are not.
_VMS = [
    {'vmid': 100, 'name': 'db01', 'node': 'n1', 'type': 'qemu', 'status': 'running',
     'cpu': 0.5, 'mem': 120, 'maxmem': 200, 'maxdisk': 10, 'tags': ''},
    {'vmid': 101, 'name': 'web01', 'node': 'n1', 'type': 'qemu', 'status': 'running',
     'cpu': 0.3, 'mem': 60, 'maxmem': 200, 'maxdisk': 10, 'tags': ''},
    {'vmid': 900, 'name': 'tmpl', 'node': 'n2', 'type': 'qemu', 'status': 'running',
     'cpu': 0.1, 'mem': 10, 'maxmem': 200, 'maxdisk': 10, 'tags': ''},
]


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])          # tenant OWNS cluster_1
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── alerts.py /reports/top-vms — full proof (pool-scoped + plain-operator) ──

def test_alerts_top_vms_pool_user_sees_only_pool_vm(api, seed):
    mallory = _pool_user(seed)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_VMS)))
    resp = api.as_user(mallory).get('/api/clusters/cluster_1/reports/top-vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(v['vmid'] for v in resp.get_json()) == [100]


def test_alerts_top_vms_plain_operator_sees_all(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    otto = seed.user('otto', role='user', tenant_id='tenant_x')   # no pool grant → cluster-wide
    _seed_pool_membership('cluster_1', {})
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_VMS)))
    resp = api.as_user(otto).get('/api/clusters/cluster_1/reports/top-vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(v['vmid'] for v in resp.get_json()) == [100, 101, 900]


# ── reports.py /api/reports/top-vms (multi-cluster) ──

def test_reports_top_vms_pool_user_scoped(api, seed):
    mallory = _pool_user(seed)
    fm = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_VMS))
    fm.config.name = 'lab'
    api.set_manager('cluster_1', fm)
    resp = api.as_user(mallory).get('/api/reports/top-vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(v['vmid'] for v in resp.get_json()) == [100]


# topology.py /topology uses the identical `resources = scope_vm_rows(cluster_id, resources)`
# one-liner before building its VM/CT graph nodes; the helper's correctness is proven by the
# alerts tests above, so it is not re-exercised through topology's heavier manager surface here.


# ── costs.py /costs/per-vm and power.py /power/per-vm (compute patched to canned rows) ──

def _canned_rows():
    return [{'vmid': v, 'name': f'vm{v}', 'node': 'n1', 'type': 'qemu', 'cost_total': 1.0,
             'cost_cpu': 0.5, 'cost_memory': 0.3, 'cost_storage': 0.2,
             'kwh': 1.0, 'cost': 1.0, 'kg_co2': 0.1} for v in (100, 101, 900)]


def test_costs_per_vm_pool_user_scoped(api, seed, monkeypatch):
    mallory = _pool_user(seed)
    monkeypatch.setattr('pegaprox.api.costs._load_history', lambda *a, **k: [{'x': 1}])
    monkeypatch.setattr('pegaprox.api.costs._compute_per_vm', lambda *a, **k: _canned_rows())
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    resp = api.as_user(mallory).get('/api/clusters/cluster_1/costs/per-vm')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(r['vmid'] for r in resp.get_json()['rows']) == [100]


def test_power_per_vm_pool_user_scoped(api, seed, monkeypatch):
    mallory = _pool_user(seed)
    monkeypatch.setattr('pegaprox.api.power._load_history', lambda *a, **k: [{'x': 1}])
    monkeypatch.setattr('pegaprox.api.power._compute_per_vm', lambda *a, **k: _canned_rows())
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    resp = api.as_user(mallory).get('/api/clusters/cluster_1/power/per-vm')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(r['vmid'] for r in resp.get_json()['rows']) == [100]
