"""A caller confined to some guests attaches no volume of a guest outside their reach.

PegaProx sends a config change on its own PVE account, which may use every volume of the
cluster, so PVE never asks whether the volume named in a drive belongs to the guest. A pool-
or ACL-confined user with vm.config on guest 100 could hang another tenant's disk into it
(or copy it with import-from) and read or overwrite it from inside the guest. The config
route and the CD-ROM route now check every volume a drive or mount point names.
"""
from unittest.mock import MagicMock

import pytest

from test_lxc_features_passthrough import FakePVE, CID, VM, ROOT_PW, TOKEN_ONLY
from test_root_changes_confined import _who, _config_manager

from pegaprox.api.vms import _volume_owner, _drive_volumes

CT = f'/api/clusters/{CID}/vms/pve1/lxc/101/config'
CDROM = f'{VM}/cdrom'
CLUSTERS = {'root_pw': ROOT_PW, 'token': TOKEN_ONLY}


def _manager(api, cluster, raw=None):
    m = _config_manager(api, FakePVE(), **CLUSTERS[cluster])
    m.get_vm_config = MagicMock(return_value={'success': True, 'config': {'raw': dict(raw or {})}})
    m.set_cdrom = MagicMock(return_value={'success': True, 'message': 'CD-ROM mounted'})
    return m


FOREIGN_QEMU = [
    {'scsi1': 'local-lvm:vm-200-disk-0'},
    {'scsi1': 'file=local-lvm:vm-200-disk-0,size=32G'},
    {'scsi1': 'volume=local-lvm:vm-200-disk-0'},
    {'scsi1': 'cache=none,local-lvm:vm-200-disk-0'},        # the volume need not come first
    {'scsi1': 'local-lvm:vm-100-disk-1,volume=local-lvm:vm-200-disk-0'},
    {'virtio1': 'ceph:vm-200-disk-1,iothread=1'},
    {'sata1': 'nfs:200/vm-200-disk-0.qcow2'},
    {'sata1': 'nfs:100/../200/vm-200-disk-0.qcow2'},
    {'unused0': 'local-lvm:vm-200-disk-0'},
    {'ide3': 'local-lvm:vm-200-disk-0,media=cdrom'},
    {'scsi1': 'local-lvm:0,import-from=local-lvm:vm-200-disk-0'},
    {'scsi1': 'local-lvm:0,import-from=nfs:200/vm-200-disk-0.qcow2'},
    {'efidisk0': 'local-lvm:vm-200-disk-1,efitype=4m'},
    {'tpmstate0': 'local-lvm:vm-200-disk-2,version=v2.0'},
    {'vmstate': 'local-lvm:vm-200-state-suspend-2026-11-26'},
    {'scsi1': 'rbd:base-99-disk-0/vm-200-disk-1'},
    {'scsi1': 'local:99/base-99-disk-0.qcow2/200/vm-200-disk-1.qcow2'},
    {'scsi1': 'iscsi:0.0.1.scsi-36001405aabbccdd'},          # no owner to read
    {'scsi1': 'local-lvm:vm-0100-disk-0'},
    {'scsi1': 'local:snippets/vm-100-disk-0.qcow2'},
    {'scsi2': 'local-lvm:8', 'scsi1': 'local-lvm:vm-200-disk-0'},
]
FOREIGN_LXC = [
    {'mp0': 'local-lvm:vm-200-disk-0,mp=/mnt/x'},
    {'mp0': 'mp=/mnt/x,local-zfs:subvol-200-disk-0'},
    {'mp0': 'volume=local-zfs:subvol-200-disk-0,mp=/mnt/x'},
    {'rootfs': 'local-lvm:vm-200-disk-0,size=8G'},
    {'unused1': 'local-zfs:subvol-200-disk-0'},
]


@pytest.mark.parametrize('cluster', sorted(CLUSTERS))
@pytest.mark.parametrize('body', FOREIGN_QEMU)
def test_a_confined_caller_attaches_no_foreign_volume_to_a_vm(api, seed, cluster, body):
    who = _who(api, seed)
    m = _manager(api, cluster)
    for caller in ('pool', 'acl'):
        r = who[caller].put(f'{VM}/config', json=dict(body))
        assert r.status_code == 403, (caller, body, r.data)
        assert r.get_json()['code'] == 'FOREIGN_VOLUME', (caller, body, r.data)
    assert not m.update_vm_config.called
    # the whole cluster may hang any disk into any guest
    for caller in ('owner', 'admin'):
        assert who[caller].put(f'{VM}/config', json=dict(body)).status_code == 200, (caller, body)


@pytest.mark.parametrize('body', FOREIGN_LXC)
def test_a_confined_caller_mounts_no_foreign_volume_into_a_container(api, seed, body):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    for caller in ('pool', 'acl'):
        r = who[caller].put(CT, json=dict(body))
        assert r.status_code == 403 and r.get_json()['code'] == 'FOREIGN_VOLUME', (caller, body, r.data)
    assert not m.update_vm_config.called
    assert who['admin'].put(CT, json=dict(body)).status_code == 200


@pytest.mark.parametrize('iso', ['local-lvm:vm-200-disk-0', 'nfs:200/vm-200-disk-0.qcow2',
                                 'rbd:base-99-disk-0/vm-200-disk-1', 'iscsi:0.0.1.scsi-3600'])
def test_the_cdrom_route_mounts_no_foreign_volume(api, seed, iso):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    for caller in ('pool', 'acl'):
        r = who[caller].put(CDROM, json={'iso': iso, 'drive': 'ide2'})
        assert r.status_code == 403 and r.get_json()['code'] == 'FOREIGN_VOLUME', (caller, iso, r.data)
    assert not m.set_cdrom.called
    assert who['owner'].put(CDROM, json={'iso': iso, 'drive': 'ide2'}).status_code == 200


OWN_QEMU = [
    {'scsi1': 'local-lvm:vm-100-disk-1'},
    {'scsi0': 'local-lvm:vm-100-disk-0,cache=writeback,discard=on'},
    {'scsi0': 'file=local-lvm:vm-100-disk-0,iothread=1'},
    {'sata1': 'local:100/vm-100-disk-1.qcow2'},
    {'scsi1': 'rbd:base-99-disk-0/vm-100-disk-1'},
    {'scsi1': 'local:99/base-99-disk-0.qcow2/100/vm-100-disk-1.qcow2'},
    {'unused0': 'local-lvm:vm-100-disk-3'},
    {'scsi1': 'local-lvm:vm-101-disk-0'},           # a container of the same caller
    {'scsi1': '32'},
    {'scsi1': 'local-lvm:8.5,iothread=1'},
    {'ide2': 'local-lvm:cloudinit'},
    {'efidisk0': 'local-lvm:1,efitype=4m,pre-enrolled-keys=1'},
    {'tpmstate0': 'local-lvm:1,version=v2.0'},
    {'ide2': 'local:iso/debian.iso,media=cdrom'},
    {'ide2': 'none,media=cdrom'},
    {'ide2': 'cdrom,media=cdrom'},
    {'scsi1': 'local-lvm:0,import-from=local:import/disk.qcow2'},
    {'scsi1': 'local-lvm:0,import-from=local-lvm:vm-100-disk-0'},
    {'vmstate': 'local-lvm:vm-100-state-suspend-2026-11-26'},
    {'memory': 4096, 'delete': 'scsi3'},
]


@pytest.mark.parametrize('body', OWN_QEMU)
def test_a_confined_caller_keeps_their_own_and_new_volumes(api, seed, body):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    # none of these needs the guest's config: an unreadable one changes nothing
    m.get_vm_config = MagicMock(return_value={'success': False, 'error': 'not read'})
    for caller in ('pool', 'acl'):
        r = who[caller].put(f'{VM}/config', json=dict(body))
        assert r.status_code == 200, (caller, body, r.data)
    assert m.update_vm_config.call_args[0][3] == body


def test_a_volume_the_guest_has_already_stays_editable(api, seed):
    """A disk an admin shared with the guest, or a raw LUN, carries no owner the caller holds,
    but changing its options is no new access."""
    who = _who(api, seed)
    m = _manager(api, 'root_pw', raw={'scsi1': 'iscsi:0.0.1.scsi-36001405aabbccdd,size=100G',
                                      'scsi2': 'local-lvm:vm-200-disk-0,size=8G,shared=1',
                                      'memory': 2048})
    for body in ({'scsi1': 'iscsi:0.0.1.scsi-36001405aabbccdd,cache=none'},
                 {'scsi3': 'local-lvm:vm-200-disk-0,cache=none'},
                 {'unused0': 'local-lvm:vm-200-disk-0'}):
        r = who['pool'].put(f'{VM}/config', json=body)
        assert r.status_code == 200, (body, r.data)
    # a volume the guest does not have stays refused next to one it has
    r = who['pool'].put(f'{VM}/config', json={'scsi2': 'local-lvm:vm-200-disk-0,cache=none',
                                              'scsi4': 'local-lvm:vm-300-disk-0'})
    assert r.status_code == 403 and 'vm-300-disk-0' in r.get_json()['error']


def test_an_unread_config_refuses_instead_of_guessing(api, seed):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    m.get_vm_config = MagicMock(return_value={'success': False, 'error': 'timeout'})
    r = who['pool'].put(f'{VM}/config', json={'scsi1': 'local-lvm:vm-200-disk-0'})
    assert r.status_code == 503, r.data
    m.get_vm_config = MagicMock(side_effect=RuntimeError('boom'))
    assert who['acl'].put(f'{VM}/config', json={'scsi1': 'iscsi:0.0.1.scsi-3600'}).status_code == 503
    assert not m.update_vm_config.called


def test_a_container_keeps_its_own_and_new_mount_points(api, seed):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    for body in ({'mp0': 'local-lvm:8,mp=/data'}, {'mp0': 'local-lvm:vm-101-disk-1,mp=/data'},
                 {'rootfs': 'local-zfs:subvol-101-disk-0,size=8G'}, {'mp1': 'local-lvm:vm-100-disk-2,mp=/b'}):
        r = who['pool'].put(CT, json=dict(body))
        assert r.status_code == 200, (body, r.data)


def test_the_cdrom_route_keeps_isos_the_host_drive_and_eject(api, seed):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    for body in ({'iso': 'local:iso/debian.iso', 'drive': 'ide2'}, {'iso': 'cdrom', 'drive': 'sata1'},
                 {'iso': None, 'drive': 'ide2'}, {'iso': 'cephfs:iso/win.iso'}):
        assert who['pool'].put(CDROM, json=body).status_code == 200, body
    assert m.set_cdrom.call_count == 4


@pytest.mark.parametrize('body', [
    {'scsi1': 'cache=none,/dev/sdb'},
    {'scsi1': 'volume=/dev/sdb'},
    {'scsi1': 'local-lvm:8, import-from=/srv/x.raw'},
    {'ide2': 'media=cdrom,/mnt/other.iso'},
])
def test_a_host_path_is_caught_wherever_the_volume_stands(api, seed, body):
    who = _who(api, seed)
    m = _manager(api, 'root_pw')
    for caller in ('pool', 'acl'):
        r = who[caller].put(f'{VM}/config', json=dict(body))
        assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE', (caller, body, r.data)
    r = who['pool'].put(CT, json={'mp0': 'mp=/data,/srv/other-tenant'})
    assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE', r.data
    assert not m.update_vm_config.called


@pytest.mark.parametrize('volid, owner', [
    ('local-lvm:vm-100-disk-0', 100),
    ('local-zfs:subvol-101-disk-0', 101),
    ('local-zfs:basevol-102-disk-0', 102),
    ('ceph:base-99-disk-0', 99),
    ('ceph:base-99-disk-0/vm-100-disk-1', 100),
    ('local:100/vm-100-disk-0.qcow2', 100),
    ('local:100/vm-200-disk-0.qcow2', 100),       # PVE reads the directory, not the name
    ('local:99/base-99-disk-0.qcow2/100/vm-100-disk-1.qcow2', 100),
    ('local-lvm:vm-0100-disk-0', None),
    ('local:0100/vm-100-disk-0.qcow2', None),
    ('local:100/../200/vm-200-disk-0.qcow2', None),
    ('local:./100/vm-100-disk-0.qcow2', None),
    ('local-lvm:vm-100-disk-0/../vm-200-disk-0', None),
    ('ceph:myimage', None),
    ('iscsi:0.0.1.scsi-36001405aabbccdd', None),
    ('local:iso/vm-100-disk-0.iso', None),
    ('local:snippets/vm-100-x.yml', None),
    ('vm-100-disk-0', None),
    ('/dev/pve/vm-100-disk-0', None),
    ('local-lvm:vm-١٠٠-disk-0', None),
    ('', None),
])
def test_the_owner_of_a_volume_id(volid, owner):
    assert _volume_owner(volid) == owner


def test_every_volume_of_a_drive_string_is_read():
    assert _drive_volumes('local-lvm:vm-1-disk-0,cache=none') == [('volume', 'local-lvm:vm-1-disk-0')]
    assert _drive_volumes('cache=none, a:b ,file=c:d,import-from=e:f,mp=/x') == [
        ('volume', 'a:b'), ('file', 'c:d'), ('import-from', 'e:f')]
    assert _drive_volumes(32) == [('volume', '32')]
    assert _drive_volumes(None) == [] and _drive_volumes(',,') == []
