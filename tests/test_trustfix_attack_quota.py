"""Attacks on the tenant quota beyond create: ways a tenant grows past its quota on the
paths the quota now guards, and refusals of operations that grow nothing."""
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.rbac as rbac

CL, CL2 = 'cluster_1', 'cluster_2'
GB = 1024 ** 3
ROWS = [{'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'maxcpu': 2, 'maxmem': 2 * GB, 'maxdisk': 10 * GB},
        {'vmid': 101, 'node': 'pve1', 'type': 'qemu', 'maxcpu': 2, 'maxmem': 2 * GB, 'maxdisk': 10 * GB}]
RAW_100 = {'cores': 2, 'sockets': 1, 'memory': '2048',
           'scsi0': 'local-lvm:vm-100-disk-0,size=10G', 'digest': 'x'}


def _ok(data=None):
    return types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': data})


def _real_get_vm_config(raw):
    """PegaProxManager.get_vm_config itself over a fake PVE answer: the shape the routes
    really get back ({'config': {'hardware': ..., 'disks': [...], 'raw': {...}}})."""
    from pegaprox.core.manager import PegaProxManager

    def get_vm_config(node, vmid, vm_type):
        fake = MagicMock()
        fake.is_connected = True
        fake.host, fake.api_port = '10.0.0.1', 8006
        fake._api_get.return_value = _ok(dict(raw))
        fake._create_session.return_value.get.return_value = _ok({'status': 'running'})
        fake._parse_vm_config = lambda c, t: PegaProxManager._parse_vm_config(fake, c, t)
        fake.LOCK_DESCRIPTIONS = PegaProxManager.LOCK_DESCRIPTIONS
        return PegaProxManager.get_vm_config(fake, node, vmid, vm_type)
    return get_vm_config


def _tenant(db, enforce='block', clusters=(CL,), **quota):
    q = {'quota_max_vms': 2, 'quota_max_cores': 4, 'quota_max_memory_gb': 4, 'quota_max_disk_gb': 20}
    q.update(quota)
    db.save_tenant('acme', {'id': 'acme', 'name': 'Acme', 'clusters': list(clusters),
                            'quota_enforcement': enforce, **q})
    rbac.invalidate_tenants_cache()


def _mgr(api, cid=CL, rows=ROWS, cluster_type='proxmox', backup_cfg=None, raw=RAW_100):
    m = api.make_fake_manager(cid, cluster_type=cluster_type)
    m.is_connected = True
    m.config.name = cid
    m.host, m.api_port = '10.0.0.1', 8006
    m.get_vm_resources = lambda max_age=0: list(rows)
    m.get_vm_config.side_effect = _real_get_vm_config(raw)
    m.clone_vm.return_value = {'success': True, 'data': 'UPID:pve1:clone'}
    m.update_vm_config.return_value = {'success': True, 'message': 'ok'}
    m.resize_vm_disk.return_value = {'success': True, 'message': 'ok'}
    m.add_disk.return_value = {'success': True, 'message': 'ok'}
    m._api_get.return_value = _ok(backup_cfg)
    m._api_post.return_value = _ok('UPID:pve1:restore')
    m._create_session.return_value.post.return_value = _ok('UPID:pve1:restore')
    m.get_node_status.return_value = {'pve1': {'status': 'online'}}
    return api.set_manager(cid, m)


def _tina(seed):
    seed.tenant('default', [])
    return seed.user('tina', role='admin', tenant_id='acme')


# ---- the guest config is nested, the growth helpers read it flat ----------------------------

def test_an_absolute_resize_is_checked_against_the_real_config(api, seed):
    """get_vm_config answers {'config': {..., 'raw': {'scsi0': ...}}}; _resize_growth looks
    for config['scsi0'], finds nothing and lets every absolute resize through."""
    u = _tina(seed)
    _tenant(seed.db)                                  # disk 20 of 20 used
    m = _mgr(api)
    r = api.as_user(u).put(f'/api/clusters/{CL}/vms/pve1/qemu/100/resize',
                           json={'disk': 'scsi0', 'size': '5000G'})
    assert r.status_code == 403, r.get_data(as_text=True)
    m.resize_vm_disk.assert_not_called()


def test_shrinking_memory_at_the_ceiling_is_not_refused(api, seed):
    """_config_growth reads cores/memory at the top of the nested config, finds nothing and
    measures against the defaults (1 core, 512 MB): 2048 -> 1024 MB reads as +0.5 GB."""
    u = _tina(seed)
    _tenant(seed.db)                                  # memory 4 of 4 GB used
    m = _mgr(api)
    r = api.as_user(u).put(f'/api/clusters/{CL}/vms/pve1/qemu/100/config', json={'memory': 1024})
    assert r.status_code == 200, r.get_data(as_text=True)
    m.update_vm_config.assert_called_once()


def test_saving_unchanged_cores_at_the_ceiling_is_not_refused(api, seed):
    u = _tina(seed)
    _tenant(seed.db)                                  # cores 4 of 4 used
    _mgr(api)
    r = api.as_user(u).put(f'/api/clusters/{CL}/vms/pve1/qemu/100/config',
                           json={'cores': 2, 'description': 'renamed'})
    assert r.status_code == 200, r.get_data(as_text=True)


# ---- spellings of growth the config gate does not read -------------------------------------

@pytest.mark.parametrize('vm_type,updates', [
    # the drive's default key written out: same new 500 GB volume
    ('qemu', {'scsi1': 'file=local-lvm:500,ssd=1'}),
    # a new volume filled from an image: the size is the image's
    ('qemu', {'scsi1': 'local-lvm:0,import-from=local:iso/big.qcow2'}),
    # memory as the property string PVE 8.1+ takes
    ('qemu', {'memory': 'current=65536'}),
    # a container mount point with its key written out
    ('lxc', {'mp0': 'volume=local-lvm:500,mp=/data'}),
    # a container without a core limit runs on every core of its node
    ('lxc', {'delete': 'cores'}),
])
def test_config_growth_in_other_spellings_is_counted(api, seed, vm_type, updates):
    u = _tina(seed)
    _tenant(seed.db)                                  # every dimension at its ceiling
    rows = [dict(r, type=vm_type) for r in ROWS]
    raw = {'cores': 2, 'memory': 2048, 'rootfs': 'local-lvm:vm-100-disk-0,size=10G'} \
        if vm_type == 'lxc' else RAW_100
    m = _mgr(api, rows=rows, raw=raw)
    r = api.as_user(u).put(f'/api/clusters/{CL}/vms/pve1/{vm_type}/100/config', json=updates)
    assert r.status_code == 403, r.get_data(as_text=True)
    m.update_vm_config.assert_not_called()


# ---- XCP-ng sizes are read differently by the gate and by the manager -----------------------

def test_xcpng_add_disk_size_the_gate_cannot_parse_is_not_let_through(api, seed):
    """The gate float()s size.rstrip('Gg'), the XCP-ng manager int()s size with every G
    removed: '1G000' fails the gate (open on error) and becomes a 1000 GB VDI."""
    u = _tina(seed)
    _tenant(seed.db, clusters=('xcp1',))
    m = _mgr(api, 'xcp1', cluster_type='xcpng')
    url = '/api/clusters/xcp1/vms/xh1/qemu/100/disks'
    assert api.as_user(u).post(url, json={'size': '1000'}).status_code == 403   # the gate holds
    r = api.as_user(u).post(url, json={'size': '1G000'})
    assert r.status_code in (400, 403), r.get_data(as_text=True)
    m.add_disk.assert_not_called()


def test_xcpng_resize_without_unit_is_gigabytes(api, seed):
    """XCP-ng reads a size below 4096 without unit as GB (and '+3000' as 3000 GB); the gate
    reads it as bytes, ~0 GB, and lets it through with 5 GB of headroom."""
    u = _tina(seed)
    _tenant(seed.db, clusters=('xcp1',), quota_max_disk_gb=25)
    m = _mgr(api, 'xcp1', cluster_type='xcpng')
    url = '/api/clusters/xcp1/vms/xh1/qemu/100/resize'
    assert api.as_user(u).put(url, json={'disk': '0', 'size': '+3000G'}).status_code == 403
    r = api.as_user(u).put(url, json={'disk': '0', 'size': '+3000'})
    assert r.status_code == 403, r.get_data(as_text=True)
    m.resize_vm_disk.assert_not_called()


# ---- batch restore counts the guest as it is now, not the backup ---------------------------

def test_batch_restore_counts_what_the_backup_brings_back(api, seed, monkeypatch):
    """Shrink the guest (always allowed), then batch-restore an old, big backup of it into a
    new VMID: the batch counts the live (small) guest and never reads the backup."""
    u = _tina(seed)
    _tenant(seed.db, quota_max_vms=10, quota_max_cores=8, quota_max_memory_gb=100,
            quota_max_disk_gb=1000)
    small = [dict(ROWS[0], maxcpu=1, maxmem=GB), ROWS[1]]
    _mgr(api, rows=small, backup_cfg='cores: 16\nmemory: 32768\nscsi0: local-lvm:x,size=10G\n')
    from pegaprox.core import batch_restore
    monkeypatch.setattr(batch_restore, 'launch', lambda run: None)
    body = {'items': [{'volid': 'pbs:backup/vm/100/2026-01-01T00:00:00Z'}], 'mode': 'new',
            'target_node': 'pve1', 'first_vmid': 200}
    r = api.as_user(u).post(f'/api/clusters/{CL}/backup-restore/batch', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)      # 3 + 16 cores > 8
    # the single restore of the same backup is refused: it reads the backup
    r = api.as_user(u).post(f'/api/clusters/{CL}/backup-restore',
                            json={'volid': 'pbs:backup/vm/100/2026-01-01T00:00:00Z',
                                  'target_node': 'pve1', 'target_vmid': 201, 'mode': 'new'})
    assert r.status_code == 403


# ---- a guest that is created later is not seen by the next check ---------------------------

def test_a_second_template_deploy_sees_the_first_one(api, seed, monkeypatch):
    """The deploy creates its guest minutes later (after the image download). Until then the
    usage does not include it, so one call after another all pass at one guest of headroom."""
    from pegaprox.api import templates_lib
    u = _tina(seed)
    _tenant(seed.db, quota_max_vms=3, quota_max_cores=100, quota_max_memory_gb=100,
            quota_max_disk_gb=1000)
    _mgr(api)
    monkeypatch.setattr(templates_lib.threading, 'Thread',
                        lambda *a, **k: types.SimpleNamespace(start=lambda: None))
    tid = next(iter(templates_lib.CATALOG_BY_ID))
    url = f'/api/clusters/{CL}/templates/deploy'
    r1 = api.as_user(u).post(url, json={'template_id': tid, 'node': 'pve1', 'storage': 'local-lvm', 'vmid': 180})
    assert r1.status_code == 200, r1.get_data(as_text=True)
    r2 = api.as_user(u).post(url, json={'template_id': tid, 'node': 'pve1', 'storage': 'local-lvm', 'vmid': 181})
    assert r2.status_code == 403, r2.get_data(as_text=True)


def test_a_second_replication_job_sees_the_first_replica(api, seed):
    """A job makes its replica at its first run, not when it is created: two jobs created
    at one guest of headroom both pass and land two guests."""
    u = _tina(seed)
    _tenant(seed.db, clusters=(CL, CL2), quota_max_vms=3, quota_max_cores=100,
            quota_max_memory_gb=100, quota_max_disk_gb=1000)
    _mgr(api), _mgr(api, CL2, rows=[])
    body = {'source_cluster': CL, 'target_cluster': CL2, 'vmid': 100, 'source_node': 'pve1'}
    r1 = api.as_user(u).post('/api/cross-cluster-replications', json=body)
    assert r1.status_code == 200, r1.get_data(as_text=True)
    r2 = api.as_user(u).post('/api/cross-cluster-replications', json=dict(body, vmid=101))
    assert r2.status_code == 403, r2.get_data(as_text=True)


def test_two_clones_at_once_do_not_both_fit_into_one_slot(api, seed):
    """The check reads the usage, the clone creates the guest; nothing holds the two together
    (the portal's container create takes a per-tenant lock for exactly this)."""
    import threading
    import time
    u = _tina(seed)
    _tenant(seed.db, quota_max_vms=3, quota_max_cores=100, quota_max_memory_gb=100,
            quota_max_disk_gb=1000)
    m = _mgr(api)
    live = list(ROWS)

    def resources(max_age=0):
        snap = list(live)
        time.sleep(1.0)                     # the walk over the tenant's clusters takes a while
        return snap
    m.get_vm_resources = resources

    def clone(node, vmid, newid, *a, **k):
        live.append(dict(ROWS[0], vmid=newid))
        return {'success': True, 'data': 'UPID:pve1:clone'}
    m.clone_vm.side_effect = clone
    client = api.as_user(u)
    codes = []

    def go(newid):
        codes.append(client.post(f'/api/clusters/{CL}/vms/pve1/qemu/100/clone', json={'newid': newid}).status_code)
    ts = [threading.Thread(target=go, args=(n,)) for n in (150, 151)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [200, 403], codes


# ---- the disk quota counts boot disks only --------------------------------------------------
# Proxmox's /cluster/resources reports maxdisk of a VM as the size of its boot disk
# (QemuServer::vmstatus -> bootdisk_size) and of a container as its rootfs, so a second
# disk never shows up in the usage check_tenant_quota adds up. The fake below reports
# maxdisk the way Proxmox does.

def test_data_disks_added_one_by_one_reach_the_quota(api, seed):
    u = _tina(seed)
    _tenant(seed.db, quota_max_disk_gb=25)            # boot disks 20 of 25
    m = _mgr(api)
    url = f'/api/clusters/{CL}/vms/pve1/qemu/100/disks'
    codes = [api.as_user(u).post(url, json={'storage': 'local-lvm', 'size': '5', 'disk_id': f'scsi{i}'}).status_code
             for i in range(1, 5)]
    # 20 + 5 fits, 20 + 10 does not
    assert codes[0] == 200 and 403 in codes[1:], codes
    assert m.add_disk.call_count == 1


def test_restoring_an_unchanged_backup_over_its_own_guest_is_not_refused(api, seed):
    """The backup's config counts every disk, the live view only the boot disk: an
    identical backup with a 100 GB data disk reads as +100 GB."""
    u = _tina(seed)
    _tenant(seed.db, quota_max_disk_gb=20)
    cfg = 'cores: 2\nmemory: 2048\nscsi0: local-lvm:x,size=10G\nscsi1: local-lvm:y,size=100G\n'
    body = {'volid': 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst', 'target_vmid': 100}
    # the guest as the backup has it: the 100 GB data disk is in its config as well
    _mgr(api, backup_cfg=cfg, raw=dict(RAW_100, scsi1='local-lvm:vm-100-disk-1,size=100G'))
    r = api.as_user(u).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/backups/restore', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    # a guest without that disk does get 100 GB back from the backup: that is growth
    _mgr(api, backup_cfg=cfg)
    r = api.as_user(u).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/backups/restore', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)


# ---- a template's declared disk size is what the gate counts --------------------------------

def test_a_custom_template_cannot_declare_its_disk_away(api, seed, monkeypatch):
    """disk_gb of a custom template is the caller's to set, negative included; the deploy
    never applies it (the disk is the image's own size), the gate counts only it."""
    from pegaprox.api import templates_lib
    u = _tina(seed)
    _tenant(seed.db, quota_max_vms=10, quota_max_cores=100, quota_max_memory_gb=100)  # disk 20 of 20
    _mgr(api)
    seed.db.conn.execute(
        "INSERT INTO custom_cloud_templates (id, name, image_url, cores, memory, disk_gb, created_by, created_at) "
        "VALUES ('custom-big', 'big', 'https://mirror.example/big.qcow2', 1, 512, -50, 'tina', '2026-10-10')")
    seed.db.conn.commit()
    monkeypatch.setattr(templates_lib.threading, 'Thread',
                        lambda *a, **k: types.SimpleNamespace(start=lambda: None))
    r = api.as_user(u).post(f'/api/clusters/{CL}/templates/deploy',
                            json={'template_id': 'custom-big', 'node': 'pve1', 'storage': 'local-lvm', 'vmid': 190})
    assert r.status_code in (400, 403), r.get_data(as_text=True)


# ---- a snapshot rollback brings the snapshot's config back ---------------------------------

def test_rolling_back_to_a_bigger_snapshot_is_counted(api, seed):
    """Snapshot at 8 cores, shrink to 2 (always allowed), spend the freed cores on another
    guest, roll back: the guest has its 8 cores again and the rollback route asks nothing."""
    u = _tina(seed)
    _tenant(seed.db)                                  # cores 4 of 4 used
    m = _mgr(api, backup_cfg={'cores': 8, 'sockets': 1, 'memory': 2048,
                              'scsi0': 'local-lvm:vm-100-disk-0,size=10G'})
    m.rollback_snapshot.return_value = {'success': True, 'task': 'UPID:pve1:rollback'}
    r = api.as_user(u).post(f'/api/clusters/{CL}/vms/pve1/qemu/100/snapshots/big/rollback')
    assert r.status_code == 403, r.get_data(as_text=True)
    m.rollback_snapshot.assert_not_called()
