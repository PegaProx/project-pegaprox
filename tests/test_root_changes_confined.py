"""A change Proxmox keeps for root@pam is no change for a caller confined to some guests (#1102).

The raw PCI/USB routes and the container feature flags send such a change on a root@pam
session: the cluster's own password login, or a fresh root@pam ticket when the cluster talks
through the token minted at the first login. PVE then asks nothing more about it, so a
pool- or ACL-confined user with vm.config on one guest could hand that guest a host device
(a disk controller holding other tenants' volumes, say) or flip root-only flags of a
privileged container. The generic config route does the same on a cluster connected with
root@pam's own password, for QEMU args, a hookscript, a host path or a host device.

Mappings, sockets, volumes and nesting on an unprivileged container stay open to them: PVE
gives those to a token. Admins and operators of the whole cluster keep everything.
"""
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.rbac as rbac
from test_lxc_features_passthrough import (FakePVE, _manager, CID, CT, VM, MAPPINGS,
                                           MINTED, ROOT_PW, TOKEN_ONLY)

ROOT_SESSIONS = {'minted': MINTED, 'root_pw': ROOT_PW}


def _who(api, seed):
    # every tenant before the first request: rbac loads the tenant table once
    seed.tenant('tenant_x', [CID])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    pool = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                     permissions=['vm.config', 'vm.view', 'cluster.view'])
    seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.config'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_1', '101:lxc': 'pool_1'},
                                            'timestamp': time.time(), 'refreshing': False}
    # reaches the cluster through a VM-ACL on its two guests only
    acl = seed.user('alice', role='user', tenant_id='acme')
    seed.vm_acl(CID, 100, ['alice'])
    seed.vm_acl(CID, 101, ['alice'])
    return {
        'pool': api.as_user(pool),
        'acl': api.as_user(acl),
        'admin': api.as_user(seed.user('root', role='admin')),
        'owner': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }


# --- the passthrough and feature routes ---------------------------------------------------------

@pytest.mark.parametrize('cluster', sorted(ROOT_SESSIONS))
@pytest.mark.parametrize('caller', ['pool', 'acl'])
def test_a_confined_caller_attaches_no_raw_device(api, seed, cluster, caller):
    who = _who(api, seed)
    pve = FakePVE(vm_config={'hostpci0': '0000:02:00.0', 'usb0': 'host=1-2'})
    _manager(api, pve, **ROOT_SESSIONS[cluster])
    c = who[caller]
    for path, body in ((f'{VM}/passthrough/pci', {'device_id': '0000:01:00.0'}),
                       (f'{VM}/passthrough/usb', {'vendorid': '096e', 'productid': '0006'}),
                       (f'{VM}/passthrough/usb', {'hostbus': '1', 'hostport': '2.3'})):
        r = c.post(path, json=body)
        assert r.status_code == 403, (path, body, r.data)
        assert r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE'
    for key in ('pci/hostpci0', 'usb/usb0'):
        r = c.delete(f'{VM}/passthrough/{key}')
        assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE', key
    assert not pve.puts
    assert pve.vm_config == {'hostpci0': '0000:02:00.0', 'usb0': 'host=1-2'}
    # no root@pam login was even opened for them
    assert not any(w == 'ticket' for w, _s in pve.sessions)


@pytest.mark.parametrize('cluster', sorted(ROOT_SESSIONS))
def test_a_confined_caller_still_attaches_through_a_mapping(api, seed, cluster):
    who = _who(api, seed)
    pve = FakePVE(mappings=MAPPINGS, vm_config={'hostpci0': 'mapping=gpu0', 'usb1': 'host=spice'})
    _manager(api, pve, **ROOT_SESSIONS[cluster])
    for caller in ('pool', 'acl'):
        c = who[caller]
        r = c.post(f'{VM}/passthrough/pci', json={'mapping': 'gpu0'})
        assert r.status_code == 200, (caller, r.data)
        r = c.post(f'{VM}/passthrough/usb', json={'mapping': 'dongle'})
        assert r.status_code == 200, (caller, r.data)
    assert who['pool'].delete(f'{VM}/passthrough/pci/hostpci0').status_code == 200
    assert who['acl'].delete(f'{VM}/passthrough/usb/usb1').status_code == 200   # spice is no host device
    assert not any(w == 'ticket' for w, _s in pve.sessions)


def test_the_whole_cluster_keeps_the_root_path(api, seed):
    who = _who(api, seed)
    for caller in ('admin', 'owner'):
        pve = FakePVE(vm_config={'hostpci0': '0000:02:00.0'})
        _manager(api, pve, **MINTED)
        r = who[caller].post(f'{VM}/passthrough/pci', json={'device_id': '0000:01:00.0'})
        assert r.status_code == 200, (caller, r.data)
        assert pve.puts[-1][0] == 'ticket' and pve.vm_config['hostpci1'] == '0000:01:00.0'
        assert who[caller].delete(f'{VM}/passthrough/pci/hostpci0').status_code == 200, caller
        pve2 = FakePVE(features='', running=False)
        _manager(api, pve2, **ROOT_PW)
        assert who[caller].put(CT, json={'keyctl': True}).status_code == 200, caller
        assert pve2.puts[-1][0] == 'session-root' and pve2.features == 'keyctl=1'


@pytest.mark.parametrize('cluster', sorted(ROOT_SESSIONS))
def test_a_confined_caller_flips_no_root_feature_flag(api, seed, cluster):
    who = _who(api, seed)
    pve = FakePVE(features='nesting=1')
    _manager(api, pve, **ROOT_SESSIONS[cluster])
    for caller in ('pool', 'acl'):
        r = who[caller].put(CT, json={'keyctl': True})
        assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE', (caller, r.data)
    assert not pve.puts and not any(w == 'ticket' for w, _s in pve.sessions)
    # nesting on an unprivileged container is no root@pam change: it goes through the token
    pve2 = FakePVE(features='')
    _manager(api, pve2, user='root@pam', has_pw=True, minted=True)
    r = who['pool'].put(CT, json={'nesting': True})
    assert r.status_code == 200, r.data
    assert [p[0] for p in pve2.puts] == ['session-token']
    # on a privileged one even nesting is
    pve3 = FakePVE(features='', unprivileged=False)
    _manager(api, pve3, **ROOT_SESSIONS[cluster])
    assert who['acl'].put(CT, json={'nesting': True}).status_code == 403
    assert not pve3.puts


def test_a_token_cluster_still_names_its_own_reason(api, seed):
    """Where no root@pam session exists, the refusal says why as before."""
    who = _who(api, seed)
    pve = FakePVE()
    _manager(api, pve, **TOKEN_ONLY)
    r = who['pool'].post(f'{VM}/passthrough/pci', json={'device_id': '0000:01:00.0'})
    assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_REQUIRED'


@pytest.mark.parametrize('caller', ['pool', 'acl'])
def test_a_confined_caller_passes_no_host_serial_device(api, seed, caller):
    who = _who(api, seed)
    pve = FakePVE()
    _manager(api, pve, **ROOT_PW)
    r = who[caller].post(f'{VM}/passthrough/serial', json={'type': '/dev/ttyS0'})
    assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE', r.data
    assert not pve.puts
    assert who[caller].post(f'{VM}/passthrough/serial', json={'type': 'socket'}).status_code == 200
    assert pve.puts[-1][2] == {'serial0': 'socket'}
    # the whole cluster keeps the host device
    assert who['owner'].post(f'{VM}/passthrough/serial', json={'type': '/dev/ttyS0'}).status_code == 200


# --- the generic config route on a cluster connected with root@pam's own password --------------

def _config_manager(api, pve, **how):
    m = _manager(api, pve, **how)
    m.update_vm_config = MagicMock(return_value={'success': True, 'message': 'Configuration updated'})
    m.get_vm_config = MagicMock(return_value={'success': True, 'config': {}})
    return m


QEMU_ROOT_ONLY = [
    {'args': '-chardev file,id=x,path=/etc/shadow'},
    {'hookscript': 'local:snippets/x.sh'},
    {'affinity': '0-3'},
    {'ivshmem': 'size=64,name=other'},
    {'parallel0': '/dev/parport0'},
    {'hostpci1': '0000:01:00.0'},
    {'hostpci1': 'mapping=gpu0,romfile=/tmp/x.rom'},
    {'usb1': 'host=1-2.3'},
    {'usb1': '096e:0006'},
    {'serial1': '/dev/ttyS0'},
    {'scsi1': '/dev/sdb'},
    {'virtio1': 'file=/dev/disk/by-id/other,size=10G'},
    {'scsi1': 'local-lvm:0,import-from=/var/lib/vz/images/200/vm-200-disk-0.raw'},
    {'ide2': '/mnt/other.iso,media=cdrom'},
    {'delete': 'args'},
    {'delete': 'net1,lock'},
]
QEMU_OPEN = [
    {'memory': 4096, 'name': 'web'},
    {'hostpci1': 'mapping=gpu0,pcie=1'},
    {'usb1': 'mapping=dongle'},
    {'usb1': 'spice'},
    {'serial1': 'socket'},
    {'scsi1': 'local-lvm:8,iothread=1'},
    {'ide2': 'local:iso/debian.iso,media=cdrom'},
    {'ide2': 'none,media=cdrom'},
    {'delete': 'net1'},
]


@pytest.mark.parametrize('body', QEMU_ROOT_ONLY)
def test_the_config_route_keeps_root_only_qemu_keys_from_a_confined_caller(api, seed, body):
    who = _who(api, seed)
    pve = FakePVE()
    m = _config_manager(api, pve, **ROOT_PW)
    for caller in ('pool', 'acl'):
        r = who[caller].put(f'{VM}/config', json=dict(body))
        assert r.status_code == 403, (caller, body, r.data)
        assert r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE'
    assert not m.update_vm_config.called
    # an operator of the whole cluster sends it on
    assert who['owner'].put(f'{VM}/config', json=dict(body)).status_code == 200, body
    assert m.update_vm_config.called


@pytest.mark.parametrize('body', QEMU_OPEN)
def test_the_config_route_leaves_a_confined_caller_the_rest(api, seed, body):
    who = _who(api, seed)
    pve = FakePVE()
    m = _config_manager(api, pve, **ROOT_PW)
    r = who['pool'].put(f'{VM}/config', json=dict(body))
    assert r.status_code == 200, (body, r.data)
    assert m.update_vm_config.call_args[0][3] == body


@pytest.mark.parametrize('body', [
    {'dev0': '/dev/sdb'},
    {'delete': 'dev0'},
    {'hookscript': 'local:snippets/x.sh'},
    {'mp0': '/srv/other-tenant,mp=/data'},
    {'mp0': 'volume=/dev/sdc,mp=/data'},
    {'rootfs': '/var/lib/other,size=8G'},
    {'features': 'nesting=1,keyctl=1'},
    {'delete': 'features'},
])
def test_the_config_route_keeps_root_only_container_keys_from_a_confined_caller(api, seed, body):
    who = _who(api, seed)
    pve = FakePVE(features='nesting=1,fuse=1')
    m = _config_manager(api, pve, **ROOT_PW)
    ct = f'/api/clusters/{CID}/vms/pve1/lxc/101/config'
    for caller in ('pool', 'acl'):
        r = who[caller].put(ct, json=dict(body))
        assert r.status_code == 403, (caller, body, r.data)
    assert not m.update_vm_config.called
    assert who['admin'].put(ct, json=dict(body)).status_code == 200


def test_the_config_route_leaves_container_volumes_and_nesting_open(api, seed):
    who = _who(api, seed)
    pve = FakePVE(features='keyctl=1')
    m = _config_manager(api, pve, **ROOT_PW)
    ct = f'/api/clusters/{CID}/vms/pve1/lxc/101/config'
    for body in ({'mp0': 'local-lvm:8,mp=/data'}, {'memory': 1024, 'hostname': 'ct101'},
                 {'features': 'keyctl=1,nesting=1'}, {'delete': 'mp0'}):
        r = who['pool'].put(ct, json=dict(body))
        assert r.status_code == 200, (body, r.data)
    assert m.update_vm_config.call_count == 4
    # a privileged container keeps even nesting for root@pam
    pve2 = FakePVE(features='', unprivileged=False)
    m2 = _config_manager(api, pve2, **ROOT_PW)
    assert who['pool'].put(ct, json={'features': 'nesting=1'}).status_code == 403
    assert not m2.update_vm_config.called


# --- the same config through its other doors, and the spellings a filter can miss -----------

@pytest.mark.parametrize('body', [
    {'delete': 'net1;lock'},           # PVE splits a delete list on ',', ';' and spaces
    {'delete': 'net1 hookscript'},
    {'revert': 'args'},
    {'skiplock': 1},
    {'hostpci1': 'mapping=gpu0,host=0000:01:00.0'},   # a mapping does not cover a host address
    {'usb1': 'mapping=dongle,host=1-2'},
])
def test_the_config_route_reads_every_spelling_of_a_root_only_change(api, seed, body):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    for caller in ('pool', 'acl'):
        r = who[caller].put(f'{VM}/config', json=dict(body))
        assert r.status_code == 403, (caller, body, r.data)
        assert r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE'
    assert not m.update_vm_config.called
    assert who['owner'].put(f'{VM}/config', json=dict(body)).status_code == 200, body


@pytest.mark.parametrize('body', [
    {'hostpci1': ['mapping=gpu0', '0000:01:00.0']},
    {'delete': ['net1', 'lock']},
    {'name': {'nested': 'x'}},
])
def test_a_config_value_is_a_string_or_a_number(api, seed, body):
    """A list goes out as the same key twice, and what PVE then takes is not what was checked."""
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    for caller in ('pool', 'owner', 'admin'):
        r = who[caller].put(f'{VM}/config', json=dict(body))
        assert r.status_code == 400, (caller, body, r.data)
    assert not m.update_vm_config.called


def test_spice_is_no_host_device_in_any_case(api, seed):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    for value in ('SPICE', 'host=Spice,usb3=1'):
        r = who['pool'].put(f'{VM}/config', json={'usb1': value})
        assert r.status_code == 200, (value, r.data)
    assert m.update_vm_config.call_count == 2


def test_the_filter_follows_the_endpoint_the_guest_type_picks(api, seed):
    """Anything but 'qemu' goes to the container endpoint, so it is read as a container."""
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    r = who['acl'].put(f'/api/clusters/{CID}/vms/pve1/QEMU/101/config', json={'dev0': '/dev/sdb'})
    assert r.status_code == 403, r.data
    assert not m.update_vm_config.called


DISKS = f'{VM}/disks'


@pytest.mark.parametrize('body', [
    {'disk_id': 'scsi1', 'storage': 'local-lvm', 'size': '8', 'cache': 'none,import-from=/srv/x.raw'},
    {'disk_id': 'scsi1', 'storage': 'local-lvm', 'size': '8,file=/srv/x.raw'},
    {'disk_id': 'scsi1', 'storage': '/srv/other', 'size': '8'},
    {'disk_id': 'scsi1', 'storage': 'local-lvm', 'size': '8', 'format': 'raw,file=/srv/x.raw'},
    {'disk_id': 'args', 'storage': 'local-lvm', 'size': '8'},
    {'disk_id': 'hookscript', 'storage': 'local', 'size': '8'},
])
def test_adding_a_disk_takes_no_option_or_key_of_its_own(api, seed, body):
    """The add-disk route builds the drive string from these fields as they come, so a comma
    or a key name there is a config change the config route would have refused."""
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    m.add_disk = MagicMock(return_value={'success': True, 'message': 'Disk added'})
    for caller in ('pool', 'acl', 'owner'):
        r = who[caller].post(DISKS, json=dict(body))
        assert r.status_code == 400, (caller, body, r.data)
    assert not m.add_disk.called


def test_adding_a_disk_still_works_for_a_confined_caller(api, seed):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    m.add_disk = MagicMock(return_value={'success': True, 'message': 'Disk added'})
    for body in ({'disk_id': 'scsi1', 'storage': 'local-lvm', 'size': 32, 'format': 'raw',
                  'discard': True, 'cache': 'writeback'},
                 {'disk_id': 'virtio2', 'storage': 'ceph_pool.fast', 'size': '8.5G'},
                 {'disk_id': 'sata1', 'storage': 'local', 'size': '16', 'format': 'qcow2', 'cache': ''}):
        r = who['pool'].post(DISKS, json=body)
        assert r.status_code == 200, (body, r.data)
    # a container mount point keeps its own slot logic in the manager
    r = who['acl'].post(f'/api/clusters/{CID}/vms/pve1/lxc/101/disks',
                        json={'storage': 'local-lvm', 'size': 4, 'mountpoint': '/data'})
    assert r.status_code == 200, r.data
    assert m.add_disk.call_count == 4


CDROM = f'{VM}/cdrom'


def test_the_cdrom_route_only_changes_a_cdrom_drive(api, seed):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    m.set_cdrom = MagicMock(return_value={'success': True, 'message': 'CD-ROM mounted'})
    for caller in ('pool', 'acl', 'owner'):
        for body in ({'iso': 'local:iso/a.iso', 'drive': 'hookscript'},
                     {'iso': 'local:iso/a.iso', 'drive': 'args'},
                     {'iso': 'local:iso/a.iso', 'drive': ['ide2']},
                     {'iso': 'local:iso/a.iso,file=/srv/x.raw', 'drive': 'ide2'},
                     {'iso': ['local:iso/a.iso'], 'drive': 'ide2'}):
            r = who[caller].put(CDROM, json=body)
            assert r.status_code == 400, (caller, body, r.data)
    assert not m.set_cdrom.called


def test_a_confined_caller_mounts_no_host_file_as_a_cdrom(api, seed):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    m.set_cdrom = MagicMock(return_value={'success': True, 'message': 'CD-ROM mounted'})
    for caller in ('pool', 'acl'):
        r = who[caller].put(CDROM, json={'iso': '/srv/other/disk.img', 'drive': 'ide2'})
        assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_CLUSTER_WIDE', (caller, r.data)
    assert not m.set_cdrom.called
    # an ISO of a storage, the host drive and an eject stay theirs
    for body in ({'iso': 'local:iso/debian.iso', 'drive': 'ide2'}, {'iso': 'cdrom', 'drive': 'sata1'},
                 {'iso': None, 'drive': 'ide2'}, {'iso': 'local:iso/debian.iso'}):
        assert who['pool'].put(CDROM, json=body).status_code == 200, body
    # the whole cluster keeps the host path
    assert who['owner'].put(CDROM, json={'iso': '/srv/other/disk.img', 'drive': 'ide2'}).status_code == 200
    assert m.set_cdrom.call_count == 5
