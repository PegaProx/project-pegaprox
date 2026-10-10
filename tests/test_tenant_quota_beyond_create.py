"""The tenant quota on every path that grows a tenant, not only on create.

check_tenant_quota ran on VM/CT create, OCI deploy and the portal's container create. A
clone, a restore into a new VMID, a template deploy, a guest landing from another
hypervisor or ESXi, a replica, and a resize that adds cores, memory or disk only asked
about the VMID range, or nothing. A tenant at its ceiling grew past it through any of them.
Same check now, same enforcement ('block' refuses, 'warn' lets it through with a warning),
counting what the operation adds; a restore over the guest it came from counts only what
the backup has more of. MK Oct 2026
"""
import types

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.utils.rbac import config_footprint, quota_verdict, landing_adds

CL, CL2 = 'cluster_1', 'cluster_2'
GB = 1024 ** 3
# two guests of 2 cores, 2 GB, 10 GB each: at a quota of 2 VMs / 4 cores / 4 GB / 20 GB
ROWS = [{'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'maxcpu': 2, 'maxmem': 2 * GB, 'maxdisk': 10 * GB},
        {'vmid': 101, 'node': 'pve1', 'type': 'qemu', 'maxcpu': 2, 'maxmem': 2 * GB, 'maxdisk': 10 * GB}]
CFG_100 = {'cores': '2', 'sockets': '1', 'memory': '2048', 'scsi0': 'local-lvm:vm-100-disk-0,size=10G'}


def _ok(data=None):
    return types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': data})


def _tenant(db, enforce='block', clusters=(CL,), **quota):
    q = {'quota_max_vms': 2, 'quota_max_cores': 4, 'quota_max_memory_gb': 4, 'quota_max_disk_gb': 20}
    q.update(quota)
    db.save_tenant('acme', {'id': 'acme', 'name': 'Acme', 'clusters': list(clusters),
                            'quota_enforcement': enforce, **q})
    rbac.invalidate_tenants_cache()


def _mgr(api, cid=CL, rows=ROWS, cluster_type='proxmox', backup_cfg=None):
    m = api.make_fake_manager(cid, cluster_type=cluster_type)
    m.is_connected = True
    m.config.name = cid
    m.host, m.api_port = '10.0.0.1', 8006
    m.get_vm_resources = lambda max_age=0: list(rows)
    # the shape PegaProxManager.get_vm_config answers: the guest's own keys under 'raw'
    m.get_vm_config.return_value = {'success': True, 'config': {
        'hardware': {'cores': 2, 'sockets': 1, 'memory': 2048}, 'raw': dict(CFG_100)}}
    m.clone_vm.return_value = {'success': True, 'data': 'UPID:pve1:clone'}
    m.update_vm_config.return_value = {'success': True, 'message': 'ok'}
    m.resize_vm_disk.return_value = {'success': True, 'message': 'ok'}
    m.add_disk.return_value = {'success': True, 'message': 'ok'}
    m._api_get.return_value = _ok(backup_cfg)
    m._api_post.return_value = _ok('UPID:pve1:restore')
    m._create_session.return_value.post.return_value = _ok('UPID:pve1:restore')
    m.get_node_status.return_value = {'pve1': {'status': 'online'}}
    return api.set_manager(cid, m)


def _users(seed):
    seed.tenant('default', [])
    return {'tenant': seed.user('tina', role='admin', tenant_id='acme'),
            'root': seed.user('root', role='admin')}


def _warned(db):
    return [dict(r) for r in db.conn.execute(
        "SELECT * FROM audit_log WHERE action = 'tenant.quota_warning'")]


# ---- the pieces ----------------------------------------------------------------------

def test_config_footprint_reads_a_backup_config_text():
    text = ('cores: 4\nsockets: 2\nmemory: 8192\nscsi0: local-lvm:vm-1-disk-0,size=32G\n'
            'ide2: local:iso/x.iso,media=cdrom,size=600M\nefidisk0: local-lvm:vm-1-disk-1,size=4M\n'
            '[snap1]\ncores: 64\nscsi1: local-lvm:big,size=9T\n')
    fp = config_footprint(text, 'qemu')
    assert fp['cores'] == 8 and fp['memory_gb'] == 8.0
    assert round(fp['disk_gb'], 3) == round(32 + 4 / 1024, 3)


def test_config_footprint_of_a_container():
    fp = config_footprint({'cores': '2', 'memory': '1024', 'rootfs': 'local:101/vm-101-disk-0.raw,size=8G',
                           'mp0': 'local-lvm:vm-101-disk-1,size=2G'}, 'lxc')
    assert fp == {'cores': 2, 'memory_gb': 1.0, 'disk_gb': 10.0}


def test_a_dimension_the_operation_does_not_grow_is_not_its_violation(db, api):
    """A quota lowered below what a tenant has: more memory is refused, the same memory is not."""
    _tenant(db, quota_max_vms=1)
    _mgr(api)
    assert quota_verdict('acme', add_mem_gb=1) is not None      # memory 4 + 1 > 4
    assert quota_verdict('acme', add_cores=0, add_mem_gb=0) is None
    v = quota_verdict('acme', add_disk_gb=-5, add_cores=1)
    assert v['violations'] == ['cores']                          # not 'vms', not 'disk'


def test_a_move_between_the_tenants_own_clusters_adds_nothing(db, api):
    _tenant(db, clusters=(CL, CL2))
    _mgr(api), _mgr(api, CL2, rows=[])
    fp = {'cores': 2}
    assert landing_adds('acme', CL2, fp, source_cluster=CL, source_removed=True) is None
    assert landing_adds('acme', CL2, fp, source_cluster=CL, source_removed=False) == {'cores': 2, 'vms': 1}
    assert landing_adds('acme', CL2, fp, source_cluster='esxi-elsewhere', source_removed=True) == {'cores': 2, 'vms': 1}


# ---- clone ------------------------------------------------------------------------------

def _clone(api, u):
    return api.as_user(u).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/clone', json={'newid': 150})


def test_clone_at_the_limit_is_refused(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    m = _mgr(api)
    r = _clone(api, us['tenant'])
    assert r.status_code == 403 and 'quota' in r.get_json()['error'].lower()
    m.clone_vm.assert_not_called()


def test_clone_at_the_limit_is_warned_in_warn_mode(api, seed):
    us = _users(seed)
    _tenant(seed.db, enforce='warn')
    m = _mgr(api)
    r = _clone(api, us['tenant'])
    assert r.status_code == 200, r.get_data(as_text=True)
    assert set(r.get_json()['quota_warning']['violations']) == {'vms', 'cores', 'memory', 'disk'}
    m.clone_vm.assert_called_once()
    assert _warned(seed.db)


def test_an_admin_outside_tenants_is_not_limited(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    m = _mgr(api)
    r = _clone(api, us['root'])
    assert r.status_code == 200 and 'quota_warning' not in r.get_json()
    m.clone_vm.assert_called_once()


def test_a_scoped_tenant_user_is_limited_too(api, seed):
    _users(seed)
    _tenant(seed.db)
    m = _mgr(api)
    u = seed.user('ula', role='user', tenant_id='acme')
    seed.vm_acl(CL, 100, ['ula'], permissions=['vm.view', 'vm.clone'])
    r = _clone(api, u)
    assert r.status_code == 403, r.get_data(as_text=True)
    m.clone_vm.assert_not_called()


# ---- restore ----------------------------------------------------------------------------

VOLID = 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst'


def _vzrestore(api, u, target):
    return api.as_user(u).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/backups/restore',
                               json={'volid': VOLID, 'target_vmid': target})


def test_restore_into_a_new_vmid_is_refused_at_the_limit(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    m = _mgr(api, backup_cfg='cores: 2\nmemory: 2048\nscsi0: local-lvm:x,size=10G\n')
    r = _vzrestore(api, us['tenant'], 160)
    assert r.status_code == 403
    m._create_session.return_value.post.assert_not_called()


def test_restore_over_the_same_guest_counts_only_the_difference(api, seed):
    """At the VM ceiling, a restore over guest 100 adds no guest: the same size goes through,
    a backup with more cores than the guest has now does not."""
    us = _users(seed)
    _tenant(seed.db)
    _mgr(api, backup_cfg='cores: 2\nmemory: 2048\nscsi0: local-lvm:x,size=10G\n')
    assert _vzrestore(api, us['tenant'], 100).status_code == 200
    _mgr(api, backup_cfg='cores: 6\nmemory: 2048\nscsi0: local-lvm:x,size=10G\n')
    r = _vzrestore(api, us['tenant'], 100)
    assert r.status_code == 403 and r.get_json()['quota']['violations'] == ['cores']


def test_pbs_restore_new_is_refused_and_warned(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    m = _mgr(api, backup_cfg='cores: 1\nmemory: 512\n')
    body = {'volid': 'pbs:backup/vm/100/2026-10-01T00:00:00Z', 'target_node': 'pve1',
            'target_vmid': 170, 'mode': 'new'}
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/backup-restore', json=body)
    assert r.status_code == 403
    m._api_post.assert_not_called()
    _tenant(seed.db, enforce='warn')
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/backup-restore', json=body)
    assert r.status_code == 200 and r.get_json()['quota_warning']['violations']


def test_batch_restore_counts_the_whole_batch(api, seed, monkeypatch):
    us = _users(seed)
    _tenant(seed.db, quota_max_vms=3, quota_max_cores=100, quota_max_memory_gb=100, quota_max_disk_gb=1000)
    m = _mgr(api, backup_cfg='cores: 1\nmemory: 512\n')
    from pegaprox.core import batch_restore
    monkeypatch.setattr(batch_restore, 'launch', lambda run: None)
    items = [{'volid': 'pbs:backup/vm/100/2026-10-01T00:00:00Z'},
             {'volid': 'pbs:backup/vm/101/2026-10-01T00:00:00Z'}]
    body = {'items': items, 'mode': 'new', 'target_node': 'pve1', 'first_vmid': 200}
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/backup-restore/batch', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)      # 2 + 2 > 3
    assert r.get_json()['quota']['violations'] == ['vms']
    body['items'] = items[:1]
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/backup-restore/batch', json=body)
    assert r.status_code == 202, r.get_data(as_text=True)
    # every item is counted by what its backup brings back, read from the backup itself
    assert any('vzdump/extractconfig' in str(c) for c in m._api_get.call_args_list)


# ---- template deploy ----------------------------------------------------------------------

def test_template_deploy_at_the_limit(api, seed, monkeypatch):
    from pegaprox.api import templates_lib
    us = _users(seed)
    _tenant(seed.db)
    _mgr(api)
    started = []
    monkeypatch.setattr(templates_lib.threading, 'Thread',
                        lambda *a, **k: types.SimpleNamespace(start=lambda: started.append(1)))
    tid = next(iter(templates_lib.CATALOG_BY_ID))
    body = {'template_id': tid, 'node': 'pve1', 'storage': 'local-lvm', 'vmid': 180}
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/templates/deploy', json=body)
    assert r.status_code == 403 and not started
    _tenant(seed.db, enforce='warn')
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/templates/deploy', json=body)
    assert r.status_code == 200 and r.get_json()['quota_warning'] and started


# ---- landing from another hypervisor, ESXi, another cluster -------------------------------

def test_cross_hypervisor_landing(api, seed, monkeypatch):
    from pegaprox.api import xhm
    us = _users(seed)
    _tenant(seed.db, clusters=(CL, 'xcp1'))
    _mgr(api)
    _mgr(api, 'xcp1', rows=[{'vmid': 300, 'maxcpu': 1, 'maxmem': GB, 'maxdisk': GB}], cluster_type='xcpng')
    monkeypatch.setattr(xhm.threading, 'Thread', lambda *a, **k: types.SimpleNamespace(start=lambda: None))
    body = {'source_cluster': 'xcp1', 'source_vmid': 300, 'target_cluster': CL,
            'target_storage': 'local-lvm', 'target_node': 'pve1'}
    r = api.as_user(us['tenant']).post('/api/xhm/migrate', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)
    # moved, not copied: the xcp1 guest is counted already and goes once the copy lands
    r = api.as_user(us['tenant']).post('/api/xhm/migrate', json=dict(body, remove_source=True))
    assert r.status_code == 202, r.get_data(as_text=True)


def test_esxi_landing(api, seed):
    import pegaprox.globals as g
    us = _users(seed)
    _tenant(seed.db)
    _mgr(api)
    esx = types.SimpleNamespace(host='10.0.0.9', ensure_connected=lambda: None,
                                get_vm=lambda vid: {'data': {'name': 'web', 'cpu': {'count': 2, 'sockets': 1, 'cores_per_socket': 2},
                                                             'memory': {'size_MiB': 2048},
                                                             'disks': {'2000': {'capacity': 10 * GB}}}})
    g.vmware_managers['esxi1'] = esx
    body = {'target_cluster': CL, 'target_node': 'pve1', 'target_storage': 'local-lvm',
            'esxi_password': 'x'}
    r = api.as_user(us['tenant']).post('/api/vmware/esxi1/vms/vm-1/migrate', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'quota' in r.get_json()['error'].lower()


def test_cross_cluster_copy_counts_a_move_does_not(api, seed):
    us = _users(seed)
    _tenant(seed.db, clusters=(CL, CL2))
    _mgr(api), _mgr(api, CL2, rows=[])
    body = {'source_cluster': CL, 'target_cluster': CL2, 'vmid': 100, 'source_node': 'pve1',
            'target_node': 'pve9', 'delete_source': False}
    r = api.as_user(us['tenant']).post('/api/cross-cluster-migrate', json=body)
    assert r.status_code == 403 and 'quota' in r.get_json()['error'].lower()
    r = api.as_user(us['tenant']).post('/api/cross-cluster-migrate', json=dict(body, delete_source=True))
    assert 'quota' not in (r.get_json() or {}).get('error', '').lower()


def test_a_replica_is_a_guest_of_its_own(api, seed):
    us = _users(seed)
    _tenant(seed.db, clusters=(CL, CL2))
    _mgr(api), _mgr(api, CL2, rows=[])
    body = {'source_cluster': CL, 'target_cluster': CL2, 'vmid': 100, 'source_node': 'pve1'}
    r = api.as_user(us['tenant']).post('/api/cross-cluster-replications', json=body)
    assert r.status_code == 403 and 'quota' in r.get_json()['error'].lower()


# ---- growing a guest ------------------------------------------------------------------------

def test_more_cores_are_refused_less_memory_is_not(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    m = _mgr(api)
    url = f'/api/clusters/{CL}/vms/pve1/qemu/100/config'
    r = api.as_user(us['tenant']).put(url, json={'cores': 4})
    assert r.status_code == 403 and r.get_json()['quota']['violations'] == ['cores']
    m.update_vm_config.assert_not_called()
    r = api.as_user(us['tenant']).put(url, json={'memory': 1024, 'description': 'smaller'})
    assert r.status_code == 200, r.get_data(as_text=True)
    # a change that grows nothing does not even read the guest's config
    from pegaprox.api.vms import _config_growth
    m.get_vm_config.reset_mock()
    assert _config_growth(m, 'pve1', 'qemu', 100, {'description': 'x'}) is None
    m.get_vm_config.assert_not_called()


def test_a_new_volume_in_the_config_counts_as_disk(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    _mgr(api)
    r = api.as_user(us['tenant']).put(f'/api/clusters/{CL}/vms/pve1/qemu/100/config',
                                      json={'scsi1': 'local-lvm:32'})
    assert r.status_code == 403 and r.get_json()['quota']['violations'] == ['disk']


@pytest.mark.parametrize('size,status', [('+5G', 403), ('10G', 200), ('15G', 403)])
def test_disk_resize(api, seed, size, status):
    us = _users(seed)
    _tenant(seed.db)
    _mgr(api)
    r = api.as_user(us['tenant']).put(f'/api/clusters/{CL}/vms/pve1/qemu/100/resize',
                                      json={'disk': 'scsi0', 'size': size})
    assert r.status_code == status, r.get_data(as_text=True)


def test_add_disk_in_warn_mode(api, seed):
    us = _users(seed)
    _tenant(seed.db, enforce='warn')
    m = _mgr(api)
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/disks',
                                       json={'storage': 'local-lvm', 'size': '50'})
    assert r.status_code == 200 and r.get_json()['quota_warning']['violations'] == ['disk']
    m.add_disk.assert_called_once()


# ---- what did not change ----------------------------------------------------------------------

def test_the_create_path_behaves_as_before(api, seed):
    us = _users(seed)
    _tenant(seed.db)
    m = _mgr(api)
    m.create_vm.return_value = {'success': True, 'vmid': 190}
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/nodes/pve1/qemu',
                                       json={'vmid': 190, 'cores': 1, 'memory': 512})
    assert r.status_code == 403 and 'Tenant quota exceeded' in r.get_json()['error']
    m.create_vm.assert_not_called()
    r = api.as_user(us['root']).post(f'/api/clusters/{CL}/nodes/pve1/qemu',
                                     json={'vmid': 190, 'cores': 1, 'memory': 512})
    assert r.status_code == 200


def test_no_quota_means_no_extra_call(api, seed):
    """A tenant without any quota never has its guest's size looked up."""
    us = _users(seed)
    _tenant(seed.db, quota_max_vms=0, quota_max_cores=0, quota_max_memory_gb=0, quota_max_disk_gb=0)
    m = _mgr(api)
    calls = []
    m.get_vm_resources = lambda max_age=0: calls.append(max_age) or list(ROWS)
    assert _clone(api, us['tenant']).status_code == 200
    assert calls == []


# ---- every volume of a guest counts, read from the storages --------------------------------

def _storage_api(m, stores, contents, other=None):
    """_api_get answering /cluster/resources?type=storage and the storages' content lists"""
    def get(url, **kw):
        if url.endswith('/cluster/resources'):
            return _ok(stores)
        for (node, name), items in contents.items():
            if url.endswith(f'/nodes/{node}/storage/{name}/content'):
                return _ok(items)
        return _ok(other)
    m._api_get.side_effect = get


def _vol(vmid, n, gb, store='local-lvm'):
    return {'volid': f'{store}:vm-{vmid}-disk-{n}', 'vmid': vmid, 'size': gb * GB, 'content': 'images'}


def test_disk_usage_counts_every_volume_of_a_guest(api, seed):
    """maxdisk is the boot disk; the storages list the data disks too"""
    _users(seed)
    _tenant(seed.db, quota_max_disk_gb=500)
    m = _mgr(api)
    stores = [{'storage': 'local-lvm', 'node': 'pve1', 'status': 'available', 'content': 'images,rootdir', 'shared': 0},
              {'storage': 'ceph', 'node': 'pve1', 'status': 'available', 'content': 'images', 'shared': 1},
              {'storage': 'ceph', 'node': 'pve2', 'status': 'available', 'content': 'images', 'shared': 1},
              {'storage': 'local', 'node': 'pve1', 'status': 'available', 'content': 'iso,backup', 'shared': 0}]
    contents = {('pve1', 'local-lvm'): [_vol(100, 0, 10), _vol(100, 1, 100)],
                ('pve1', 'ceph'): [_vol(101, 0, 10, 'ceph'), _vol(101, 1, 50, 'ceph')],
                ('pve2', 'ceph'): [_vol(101, 0, 10, 'ceph'), _vol(101, 1, 50, 'ceph')]}
    _storage_api(m, stores, contents)
    assert rbac.check_tenant_quota('acme', add_vms=0)['usage']['disk_gb'] == 170.0
    urls = [str(c.args[0]) for c in m._api_get.call_args_list]
    assert sum('/storage/ceph/content' in u for u in urls) == 1          # shared: listed once
    assert not any('/storage/local/content' in u for u in urls)           # holds no guest disks
    # read once for a while, not on every check
    rbac.check_tenant_quota('acme', add_vms=0)
    assert sum(str(c.args[0]).endswith('/cluster/resources') for c in m._api_get.call_args_list) == 1


def test_a_data_disk_counts_once_the_storage_shows_it(api, seed):
    """The add-disk hold lasts until the storage lists the new volume; from then on the
    volume is what counts, and the next disk past the quota is refused"""
    us = _users(seed)
    _tenant(seed.db, quota_max_disk_gb=40)
    m = _mgr(api)
    vols = [_vol(100, 0, 10), _vol(101, 0, 10)]
    _storage_api(m, [{'storage': 'local-lvm', 'node': 'pve1', 'status': 'available',
                      'content': 'images', 'shared': 0}], {('pve1', 'local-lvm'): vols})
    url = f'/api/clusters/{CL}/vms/pve1/qemu/100/disks'
    r = api.as_user(us['tenant']).post(url, json={'storage': 'local-lvm', 'size': '15', 'disk_id': 'scsi1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert rbac.check_tenant_quota('acme', add_vms=0)['pending']['disk_gb'] == 15.0
    vols.append(_vol(100, 1, 15))
    rbac._disk_alloc_cache.clear()
    q = rbac.check_tenant_quota('acme', add_vms=0)
    assert q['usage']['disk_gb'] == 35.0 and 'pending' not in q
    r = api.as_user(us['tenant']).post(url, json={'storage': 'local-lvm', 'size': '10', 'disk_id': 'scsi2'})
    assert r.status_code == 403


# ---- the holds ------------------------------------------------------------------------------

def test_a_failed_clone_leaves_no_hold_a_landed_one_lets_go(api, seed):
    us = _users(seed)
    _tenant(seed.db, quota_max_vms=3, quota_max_cores=100, quota_max_memory_gb=100, quota_max_disk_gb=1000)
    m = _mgr(api)
    m.clone_vm.return_value = {'success': False, 'error': 'storage full'}
    assert _clone(api, us['tenant']).status_code == 500
    assert rbac._quota_holds == {}
    m.clone_vm.return_value = {'success': True, 'data': 'UPID:pve1:clone'}
    assert _clone(api, us['tenant']).status_code == 200
    assert rbac.check_tenant_quota('acme', add_vms=0)['usage']['vms'] == 3      # 2 + the one held
    # the clone shows on the cluster: counted as itself, the hold is gone
    m.get_vm_resources = lambda max_age=0: list(ROWS) + [dict(ROWS[0], vmid=150)]
    q = rbac.check_tenant_quota('acme', add_vms=0)
    assert q['usage']['vms'] == 3 and 'pending' not in q and rbac._quota_holds == {}


def test_a_clone_without_a_vmid_is_held_under_the_one_it_gets(api, seed):
    us = _users(seed)
    _tenant(seed.db, quota_max_vms=3, quota_max_cores=100, quota_max_memory_gb=100, quota_max_disk_gb=1000)
    m = _mgr(api)
    m.get_next_vmid.return_value = {'success': True, 'vmid': 777}
    r = api.as_user(us['tenant']).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/clone', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [h['vmids'] for h in rbac._quota_holds.values()] == [{777}]


def test_a_failed_deploy_frees_its_hold(api, seed, monkeypatch):
    from pegaprox.api import templates_lib
    us = _users(seed)
    _tenant(seed.db, quota_max_vms=3, quota_max_cores=100, quota_max_memory_gb=100, quota_max_disk_gb=1000)
    _mgr(api)
    monkeypatch.setattr(templates_lib.threading, 'Thread',
                        lambda *a, **k: types.SimpleNamespace(start=lambda: None))
    tid = next(iter(templates_lib.CATALOG_BY_ID))
    url = f'/api/clusters/{CL}/templates/deploy'
    r = api.as_user(us['tenant']).post(url, json={'template_id': tid, 'node': 'pve1', 'storage': 'local-lvm', 'vmid': 180})
    assert r.status_code == 200
    body = {'template_id': tid, 'node': 'pve1', 'storage': 'local-lvm', 'vmid': 181}
    assert api.as_user(us['tenant']).post(url, json=body).status_code == 403
    seed.db.conn.execute("UPDATE cloud_init_deployments SET status = 'failed' WHERE id = ?",
                         (r.get_json()['deployment_id'],))
    seed.db.conn.commit()
    assert api.as_user(us['tenant']).post(url, json=body).status_code == 200


def test_a_replica_hold_goes_with_its_first_good_run(api, seed):
    from pegaprox.api import vms
    us = _users(seed)
    _tenant(seed.db, clusters=(CL, CL2), quota_max_vms=3, quota_max_cores=100,
            quota_max_memory_gb=100, quota_max_disk_gb=1000)
    _mgr(api), _mgr(api, CL2, rows=[])
    body = {'source_cluster': CL, 'target_cluster': CL2, 'vmid': 100, 'source_node': 'pve1'}
    r = api.as_user(us['tenant']).post('/api/cross-cluster-replications', json=body)
    assert r.status_code == 200
    assert rbac.check_tenant_quota('acme', add_vms=0)['pending']['vms'] == 1
    vms._update_repl_status(seed.db, r.get_json()['id'], 'error', 'x')
    assert rbac.check_tenant_quota('acme', add_vms=0)['pending']['vms'] == 1
    vms._update_repl_status(seed.db, r.get_json()['id'], 'ok')
    assert 'pending' not in rbac.check_tenant_quota('acme', add_vms=0)


def test_xcpng_config_change_counts_vcpus_and_memory(api, seed):
    us = _users(seed)
    _tenant(seed.db, clusters=('xcp1',))
    m = _mgr(api, 'xcp1', cluster_type='xcpng')
    m.get_vm_config.return_value = {'success': True, 'config': {'vcpus': 2, 'memory': 2 * GB, 'disks': []}}
    url = '/api/clusters/xcp1/vms/xh1/qemu/100/config'
    r = api.as_user(us['tenant']).put(url, json={'vcpus': 4})
    assert r.status_code == 403 and r.get_json()['quota']['violations'] == ['cores']
    r = api.as_user(us['tenant']).put(url, json={'memory': '8'})          # 8 GB, as XAPI reads it
    assert r.status_code == 403 and r.get_json()['quota']['violations'] == ['memory']
    assert api.as_user(us['tenant']).put(url, json={'memory': '1'}).status_code == 200


def test_xcpng_sizes_are_read_as_the_manager_reads_them():
    from pegaprox.core.xcpng import xapi_add_disk_gb, xapi_resize_bytes, xapi_memory_bytes
    assert xapi_add_disk_gb('1G000') == 1000 and xapi_add_disk_gb('x') is None
    assert xapi_resize_bytes('+3000') == 3000 * GB and xapi_resize_bytes(5000) == 5000
    assert xapi_memory_bytes('1') == GB and xapi_memory_bytes('100') == 100 * GB
    assert xapi_memory_bytes(5000) == 128 * 1024 * 1024


def test_a_custom_template_needs_a_disk_size(api, seed):
    us = _users(seed)
    r = api.as_user(us['root']).post('/api/templates/custom', json={
        'name': 'x', 'image_url': 'https://mirror.example/x.qcow2', 'disk_gb': -50})
    assert r.status_code == 400
