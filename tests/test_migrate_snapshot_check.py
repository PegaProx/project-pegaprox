"""What the migrate dialog warns about for a guest with snapshots: GET .../migrate-check.

Proxmox refuses to move a local disk that is part of a snapshot while the VM runs, unless
replication keeps it on the target already (QemuMigrate: "online storage migration not
possible if non-replicated snapshot exists"). Offline, storage_migrate only takes the
snapshots along in a format that keeps them in the volume: zfs, btrfs, or a qcow2/vmdk file
on a storage with a path. LVM-thin and a raw file have none, so the migration fails.

The route reads the snapshot list, then the config and the storages of the node (the shared
/cluster/resources read), and lists the local volumes with how their snapshots would travel.
Read only: one call when the dialog opens.
MK Oct 2026
"""
import json
import time

import pytest

from pegaprox.core.cache import StorageDataCache

from test_ha_api import ha_env, _standby_of_active  # noqa: F401  (ha_env is a fixture)

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/vms/pve1/qemu/100/migrate-check'

STORAGES = [
    {'id': 'storage/pve1/local', 'storage': 'local', 'node': 'pve1', 'plugintype': 'dir', 'shared': 0},
    {'id': 'storage/pve1/local-lvm', 'storage': 'local-lvm', 'node': 'pve1', 'plugintype': 'lvmthin', 'shared': 0},
    {'id': 'storage/pve1/local-zfs', 'storage': 'local-zfs', 'node': 'pve1', 'plugintype': 'zfspool', 'shared': 0},
    {'id': 'storage/pve1/ceph', 'storage': 'ceph', 'node': 'pve1', 'plugintype': 'rbd', 'shared': 1},
    {'id': 'storage/pve1/nfs', 'storage': 'nfs', 'node': 'pve1', 'plugintype': 'nfs', 'shared': 1},
    # the same name on another node says nothing about pve1
    {'id': 'storage/pve2/fast', 'storage': 'fast', 'node': 'pve2', 'plugintype': 'zfspool', 'shared': 0},
]

VM_CFG = {
    'name': 'web01', 'memory': '4096', 'net0': 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0',
    'scsi0': 'local-lvm:vm-100-disk-0,size=32G',
    'scsi1': 'local-zfs:vm-100-disk-1,size=8G',
    'scsi2': 'ceph:vm-100-disk-2,size=8G',
    'scsi3': 'local-lvm:vm-100-disk-6,shared=1,size=1G',
    'scsi4': 'fast:vm-100-disk-7,size=1G',
    'virtio0': 'local:100/vm-100-disk-3.qcow2,size=4G',
    'virtio1': 'nfs:100/vm-100-disk-8.qcow2,size=4G',
    'sata0': '/dev/disk/by-id/ata-SAMSUNG_123,size=100G',
    'ide2': 'local:iso/debian-12.iso,media=cdrom',
    'ide0': 'none,media=cdrom',
    'efidisk0': 'local-lvm:vm-100-disk-4,efitype=4m,size=4M',
    'unused0': 'local-lvm:vm-100-disk-5',
}

SNAPS = [{'name': 'pre-upgrade', 'snaptime': 200, 'vmstate': 1, 'description': ''},
         {'name': 'daily', 'snaptime': 100, 'description': 'x'}]


class _Resp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data
        self.text = json.dumps({'data': data})

    def json(self):
        return {'data': self._data}


@pytest.fixture(autouse=True)
def _fresh_storage_cache(monkeypatch):
    import pegaprox.api.clusters as clusters_mod
    monkeypatch.setattr(clusters_mod, '_health_storage_cache', StorageDataCache(), raising=False)


def _manager(api, snaps=(), cfg=None, repl=(), fail=(), cluster_type='proxmox', cid=CID,
             guests=(('qemu', 100),)):
    m = api.make_fake_manager(cid, cluster_type=cluster_type)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    m.reads = []
    paths = {'/cluster/resources?type=storage': [dict(s) for s in STORAGES],
             '/cluster/replication': [dict(j) for j in repl]}
    for vm_type, vmid in guests:
        paths[f'/nodes/pve1/{vm_type}/{vmid}/snapshot'] = [{'name': 'current', 'running': 1}] + [dict(s) for s in snaps]
        paths[f'/nodes/pve1/{vm_type}/{vmid}/config'] = dict(VM_CFG if cfg is None else cfg)

    def _api_get(url, **kw):
        path = url.split('/api2/json', 1)[1]
        m.reads.append(path)
        if path in fail:
            return _Resp(500, None)
        if path not in paths:
            return _Resp(404, None)
        return _Resp(200, paths[path])
    m._api_get = _api_get
    api.set_manager(cid, m)
    return m


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


# --- what it says ---------------------------------------------------------------------------

def test_a_guest_without_snapshots_costs_one_read(api, admin):
    m = _manager(api)
    r = admin.get(URL)
    assert r.status_code == 200, r.data
    assert r.get_json() == {'supported': True, 'snapshot_count': 0, 'snapshots': [], 'volumes': [],
                            'replicated_to': []}
    assert m.reads == ['/nodes/pve1/qemu/100/snapshot']


def test_the_local_volumes_and_how_their_snapshots_travel(api, admin):
    m = _manager(api, snaps=SNAPS)
    r = admin.get(URL)
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['supported'] is True and d['snapshot_count'] == 2
    # oldest first, 'current' (the live state PVE lists with them) left out
    assert d['snapshots'] == [{'name': 'daily', 'vmstate': False}, {'name': 'pre-upgrade', 'vmstate': True}]
    # shared storage, a disk flagged shared=1, a passthrough device, CD-ROMs and a storage
    # pve1 does not list are no local volume of pve1
    assert d['volumes'] == [
        {'key': 'efidisk0', 'storage': 'local-lvm', 'type': 'lvmthin', 'format': 'raw', 'family': None},
        {'key': 'scsi0', 'storage': 'local-lvm', 'type': 'lvmthin', 'format': 'raw', 'family': None},
        {'key': 'scsi1', 'storage': 'local-zfs', 'type': 'zfspool', 'format': 'raw', 'family': 'zfs'},
        {'key': 'unused0', 'storage': 'local-lvm', 'type': 'lvmthin', 'format': 'raw', 'family': None},
        {'key': 'virtio0', 'storage': 'local', 'type': 'dir', 'format': 'qcow2', 'family': 'qcow2'},
    ]
    # a ZFS volume makes the replication jobs worth reading
    assert '/cluster/replication' in m.reads


def test_replication_targets_count_only_for_this_guest_and_enabled_jobs(api, admin):
    _manager(api, snaps=SNAPS, repl=[
        {'id': '100-0', 'guest': 100, 'target': 'pve2', 'type': 'local'},
        {'id': '100-1', 'guest': 100, 'target': 'pve3', 'type': 'local', 'disable': 1},
        {'id': '101-0', 'guest': 101, 'target': 'pve3', 'type': 'local'},
    ])
    assert admin.get(URL).get_json()['replicated_to'] == ['pve2']


def test_no_zfs_volume_reads_no_replication(api, admin):
    m = _manager(api, snaps=SNAPS, cfg={'scsi0': 'local-lvm:vm-100-disk-0,size=32G'})
    d = admin.get(URL).get_json()
    assert [v['key'] for v in d['volumes']] == ['scsi0'] and d['replicated_to'] == []
    assert '/cluster/replication' not in m.reads


def test_only_shared_storage_lists_no_volume(api, admin):
    _manager(api, snaps=SNAPS, cfg={'scsi0': 'ceph:vm-100-disk-0,size=32G', 'scsi1': 'nfs:100/vm-100-disk-1.qcow2'})
    d = admin.get(URL).get_json()
    assert d['snapshot_count'] == 2 and d['volumes'] == []


def test_a_container_carries_snapshots_on_zfs_only(api, admin):
    cfg = {'hostname': 'ct101', 'rootfs': 'local-lvm:vm-101-disk-0,size=8G',
           'mp0': 'local-zfs:subvol-101-disk-1,mp=/srv,size=8G',
           'mp1': '/mnt/host/data,mp=/data',
           'mp2': 'volume=local:101/vm-101-disk-2.raw,mp=/scratch,size=2G',
           'unused0': 'local-zfs:subvol-101-disk-3'}
    _manager(api, snaps=SNAPS, cfg=cfg, guests=(('lxc', 101),))
    r = admin.get(f'/api/clusters/{CID}/vms/pve1/lxc/101/migrate-check')
    assert r.status_code == 200, r.data
    assert [(v['key'], v['type'], v['family']) for v in r.get_json()['volumes']] == [
        ('mp0', 'zfspool', 'zfs'), ('mp2', 'dir', None), ('rootfs', 'lvmthin', None), ('unused0', 'zfspool', 'zfs')]


def test_a_qcow2_container_volume_does_not_count_as_a_vm_file(api, admin):
    # pct keeps no snapshots in a qcow2 file: the family is a VM thing
    _manager(api, snaps=SNAPS, cfg={'rootfs': 'local:101/vm-101-disk-0.qcow2,size=8G'}, guests=(('lxc', 101),))
    vols = admin.get(f'/api/clusters/{CID}/vms/pve1/lxc/101/migrate-check').get_json()['volumes']
    assert vols == [{'key': 'rootfs', 'storage': 'local', 'type': 'dir', 'format': 'qcow2', 'family': None}]


def test_many_snapshots_are_counted_and_the_newest_listed(api, admin):
    snaps = [{'name': f's{i:03d}', 'snaptime': 1000 + i} for i in range(120)]
    _manager(api, snaps=snaps)
    d = admin.get(URL).get_json()
    assert d['snapshot_count'] == 120 and len(d['snapshots']) == 50
    assert d['snapshots'][-1]['name'] == 's119' and d['snapshots'][0]['name'] == 's070'


@pytest.mark.parametrize('broken,status', [('/nodes/pve1/qemu/100/snapshot', 502),
                                           ('/nodes/pve1/qemu/100/config', 502)])
def test_a_failed_read_is_said_not_taken_as_no_snapshots(api, admin, broken, status):
    _manager(api, snaps=SNAPS, fail={broken})
    r = admin.get(URL)
    assert r.status_code == status and 'error' in r.get_json()


def test_unreadable_storages_warn_about_nothing(api, admin):
    m = _manager(api, snaps=SNAPS, fail={'/cluster/resources?type=storage'})
    d = admin.get(URL).get_json()
    assert d['snapshot_count'] == 2 and d['volumes'] == []
    assert '/cluster/replication' not in m.reads


def test_an_xcpng_pool_is_not_asked(api, admin):
    m = _manager(api, snaps=SNAPS, cluster_type='xcpng')
    r = admin.get(URL)
    assert r.status_code == 200 and r.get_json()['supported'] is False
    assert m.reads == []


def test_a_cluster_that_is_down(api, admin):
    m = _manager(api, snaps=SNAPS)
    m.is_connected = False
    assert admin.get(URL).status_code == 503
    assert m.reads == []


@pytest.mark.parametrize('path', [
    f'/api/clusters/{CID}/vms/pve1/foo/100/migrate-check',
    f'/api/clusters/{CID}/vms/pve_1/qemu/100/migrate-check',
    f'/api/clusters/{CID}/vms/..%2F..%2Fcluster/qemu/100/migrate-check',
])
def test_a_bad_type_or_node_is_refused_before_pve(api, admin, path):
    m = _manager(api, snaps=SNAPS)
    r = admin.get(path)
    assert r.status_code in (400, 404), (path, r.status_code)
    assert m.reads == []


def test_an_unknown_cluster(api, admin):
    assert admin.get('/api/clusters/nope/vms/pve1/qemu/100/migrate-check').status_code in (403, 404)


# --- who reaches it -------------------------------------------------------------------------

def _pool_user(seed, name, perms):
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=[CID])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=list(perms))
    seed.pool(CID, 'pool_1', name, ['pool.view'] + list(perms))
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'101:qemu': 'pool_1'}, 'timestamp': time.time(),
                                            'refreshing': False}
    return u


def test_the_check_by_identity(api, seed):
    seed.tenant('globex', ['cluster_globex'])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    who = {
        'admin': api.as_user(seed.user('root', role='admin')),
        'viewer': api.as_user(seed.user('watcher', role='viewer')),
        'confined_admin': api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}})),
        'other_tenant': api.as_user(seed.user('ac', role='user', tenant_id='acme',
                                              permissions=['vm.migrate', 'vm.view'])),
        'pool_confined': api.as_user(_pool_user(seed, 'mallory', ['vm.view', 'vm.migrate'])),
        'owning_tenant': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }
    m = _manager(api, snaps=SNAPS, guests=(('qemu', 100), ('qemu', 101)))
    expect = {'admin': 200, 'viewer': 403, 'confined_admin': 403, 'other_tenant': 403,
              'pool_confined': 403, 'owning_tenant': 200}
    for name, status in expect.items():
        before = len(m.reads)
        r = who[name].get(URL)
        assert r.status_code == status, (name, r.data)
        if status != 200:
            assert len(m.reads) == before, name
            assert 'volumes' not in (r.get_json() or {}), name
    # the pool user checks the guest of their pool
    r = who['pool_confined'].get(f'/api/clusters/{CID}/vms/pve1/qemu/101/migrate-check')
    assert r.status_code == 200, r.data
    assert r.get_json()['snapshot_count'] == 2


def test_a_pool_user_who_may_only_look_gets_no_check(api, seed):
    viewer = api.as_user(_pool_user(seed, 'eve', ['vm.view']))
    m = _manager(api, snaps=SNAPS, guests=(('qemu', 101),))
    r = viewer.get(f'/api/clusters/{CID}/vms/pve1/qemu/101/migrate-check')
    assert r.status_code == 403
    assert m.reads == []


def test_a_standby_reads_but_does_not_migrate(ha_env, seed):
    api = ha_env.api
    admin = api.as_user(seed.user('root', role='admin'))
    m = _manager(api, snaps=SNAPS)
    _standby_of_active(ha_env)
    # the check only reads, like every other read a standby with live view answers
    r = admin.get(URL)
    assert r.status_code == 200, r.data
    assert r.get_json()['snapshot_count'] == 2
    # the migration itself stays with the active instance
    r = admin.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/migrate', json={'target': 'pve2', 'online': True})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    m.migrate_vm_manual.assert_not_called()


def test_the_route_is_in_the_api_reference():
    with open('docs/openapi.json', encoding='utf-8') as fh:
        spec = json.load(fh)
    assert '/api/clusters/{cluster_id}/vms/{node}/{vm_type}/{vmid}/migrate-check' in spec['paths']
