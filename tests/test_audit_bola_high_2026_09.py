# Full-stack E2E for the 2026-09 audit HIGH BOLA findings. Real app + real gates, managers faked.
#   H1  GET /api/snapshots/overview   — scanned every VM on every cluster (broken cluster gate)
#   H2  GET /api/vmware/<id>/vms       — returned the full ESXi inventory, no per-VM filter
#   H3  GET /api/clusters/<id>/pools[/<pool>] — enumerated all pools' members; detail was an IDOR
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.rbac as rbac
import pegaprox.globals as ppglobals


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


_VMS = [
    {'vmid': 100, 'name': 'db01', 'node': 'n1', 'type': 'qemu', 'status': 'running', 'maxdisk': 10},
    {'vmid': 101, 'name': 'web01', 'node': 'n1', 'type': 'qemu', 'status': 'running', 'maxdisk': 10},
    {'vmid': 900, 'name': 'tmpl', 'node': 'n2', 'type': 'qemu', 'status': 'running', 'maxdisk': 10},
]


def _pool_user(seed):
    # viewer == global vm.view+vm.console; ONE direct pool grant on pool_1 (VM 100 only); tenant owns.
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── H1: snapshots overview ──────────────────────────────────────────────────
def _snap_mgr(api):
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_VMS))
    m.is_connected = True
    m.get_snapshots.side_effect = lambda node, vmid, vtype: [
        {'name': f'snap{vmid}', 'snaptime': 1700000000},   # old, no 'current'
    ]
    return m


def test_h1_snapshots_overview_confines_pool_user(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _snap_mgr(api))
    resp = api.as_user(u).get('/api/snapshots/overview')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    vmids = sorted({s['vmid'] for s in resp.get_json()['snapshots']})
    assert vmids == [100], f"pool user must only see their pool VM's snapshots, got {vmids}"


def test_h1_snapshots_overview_admin_sees_all(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _snap_mgr(api))
    resp = api.as_user(admin).get('/api/snapshots/overview')
    assert sorted({s['vmid'] for s in resp.get_json()['snapshots']}) == [100, 101, 900]


# ── H2: VMware VM list ────────────────────────────────────────────────────────
def _vmware_mgr(vms):
    m = MagicMock()
    m.linked_clusters = []                 # backward-compat open → only the ACL scope confines
    m.get_vms.return_value = {'data': vms}
    m.ensure_connected.return_value = None
    m.connect.return_value = False
    return m


def test_h2_vmware_list_confines_acl_scoped_user(api, seed, db):
    ppglobals.vmware_managers.clear()
    ppglobals.vmware_managers['esxi1'] = _vmware_mgr(
        [{'vm': 'vm-100', 'name': 'a'}, {'vm': 'vm-101', 'name': 'b'}])
    # give the user vmware.vm.view + a VMware ACL on vm-100 only → scope-wins confinement
    u = seed.user('esxiuser', role='viewer', permissions=['vmware.vm.view'])
    db.save_vm_acl('vmware:esxi1', 'vm-100', {'users': ['esxiuser'], 'inherit_role': True, 'permissions': []})
    rbac.invalidate_vm_acls_cache()
    resp = api.as_user(u).get('/api/vmware/esxi1/vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    ids = sorted(v['vm'] for v in resp.get_json())
    assert ids == ['vm-100'], f"ACL-scoped user must only see vm-100, got {ids}"
    ppglobals.vmware_managers.clear()


def test_h2_vmware_list_admin_sees_all(api, seed):
    ppglobals.vmware_managers.clear()
    ppglobals.vmware_managers['esxi1'] = _vmware_mgr(
        [{'vm': 'vm-100', 'name': 'a'}, {'vm': 'vm-101', 'name': 'b'}])
    admin = seed.user('root', role='admin')
    resp = api.as_user(admin).get('/api/vmware/esxi1/vms')
    assert sorted(v['vm'] for v in resp.get_json()) == ['vm-100', 'vm-101']
    ppglobals.vmware_managers.clear()


# ── H3: pools list + detail IDOR ──────────────────────────────────────────────
def _pool_mgr(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_pools.return_value = [{'poolid': 'pool_1'}, {'poolid': 'pool_2'}]
    m.get_pool_members.side_effect = lambda pid: {'members': [{'vmid': 100 if pid == 'pool_1' else 101, 'type': 'qemu'}]}
    return m


def test_h3_pool_list_confines_pool_user(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _pool_mgr(api))
    resp = api.as_user(u).get('/api/clusters/cluster_1/pools')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    poolids = sorted(p['poolid'] for p in resp.get_json())
    assert poolids == ['pool_1'], f"pool user must only see their granted pool, got {poolids}"


def test_h3_pool_detail_idor_blocked(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _pool_mgr(api))
    assert api.as_user(u).get('/api/clusters/cluster_1/pools/pool_1').status_code == 200   # granted
    assert api.as_user(u).get('/api/clusters/cluster_1/pools/pool_2').status_code == 403   # IDOR blocked


def test_h3_pool_list_admin_and_plain_operator_see_all(api, seed):
    api.set_manager('cluster_1', _pool_mgr(api))
    admin = seed.user('root', role='admin')
    assert sorted(p['poolid'] for p in api.as_user(admin).get('/api/clusters/cluster_1/pools').get_json()) == ['pool_1', 'pool_2']
    # plain operator: tenant owns the cluster, NO pool grant → keeps cluster-wide pool visibility
    seed.tenant('tenant_y', clusters=['cluster_1'])
    otto = seed.user('otto', role='viewer', tenant_id='tenant_y')
    rbac.tenants_db = {}   # admin's earlier call cached tenants_db before tenant_y was seeded
    body = api.as_user(otto).get('/api/clusters/cluster_1/pools').get_json()
    assert sorted(p['poolid'] for p in body) == ['pool_1', 'pool_2'], body
