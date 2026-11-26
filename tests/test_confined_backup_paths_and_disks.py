"""The routes next to the config route that hand a confined caller a volume or a backup.

- Restore, verify and delete found the guest of a backup anywhere in the volid, so a path of
  the host with /ct/<own id>/ in it passed as a backup of the caller's own guest, and PVE
  restores a path as root when PegaProx signs in with root@pam's password.
- Moving a disk frees the source after the copy, whoever owns it.
- An ISO hung in as a disk instead of a CD is written to by the guest.
- XAPI puts any VDI into a CD drive.
- An efficient snapshot id named a snapshot of any guest.
"""
import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import backup_volid_guest
from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager
from test_lxc_features_passthrough import FakePVE, CID, VM, ROOT_PW
from test_root_changes_confined import _who, _config_manager

EVIL_CT = '/rpool/data/subvol-101-disk-0/ct/101/evil.tar'
EVIL_VM = '/rpool/data/subvol-101-disk-0/vm/100/evil.vma'
GOOD_CT = 'local:backup/vzdump-lxc-101-2026_11_26-10_00_00.tar.zst'
GOOD_PBS = 'pbs:backup/vm/100/2026-11-26T10:00:00Z'


class _Sess:
    def __init__(self, posts):
        self.posts = posts

    def post(self, url, data=None, **kw):
        self.posts.append((url, dict(data or {})))
        return MagicMock(status_code=200, json=lambda: {'data': 'UPID:pve1:0001:restore'}, text='')

    def get(self, url, **kw):
        return MagicMock(status_code=500, json=lambda: {}, text='')


def _restore_manager(api):
    m = api.make_fake_manager(CID)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    m.config = types.SimpleNamespace(name=CID, user='root@pam', pass_='p' * 12)
    m._api_token = None
    posts = []
    m._create_session = lambda: _Sess(posts)
    m._api_post = lambda url, data=None, **kw: _Sess(posts).post(url, data=data)
    m._api_get = lambda url, **kw: MagicMock(status_code=500, json=lambda: {}, text='')
    m.get_vm_resources = MagicMock(return_value=[
        {'vmid': 100, 'type': 'qemu', 'node': 'pve1'}, {'vmid': 101, 'type': 'lxc', 'node': 'pve1'},
        {'vmid': 200, 'type': 'qemu', 'node': 'pve1'}])
    m.get_node_status = MagicMock(return_value={'pve1': {'status': 'online'}})
    api.set_manager(CID, m)
    return m, posts


@pytest.mark.parametrize('volid', [EVIL_CT, '/srv/x/ct/101/x:evil.tar', 'local:backup/sub/vzdump-lxc-101-x.tar',
                                   'local:backup/vzdump-lxc-101-x.tar/../../etc', 'local:iso/ct/101/x.tar'])
def test_a_container_restore_takes_no_host_path(api, seed, volid):
    who = _who(api, seed)
    _m, posts = _restore_manager(api)
    for caller in ('pool', 'acl'):
        for body in ({'volid': volid, 'start': True}, {'volid': volid, 'target_vmid': 150}):
            r = who[caller].post(f'/api/clusters/{CID}/vms/pve1/lxc/101/backups/restore', json=body)
            assert r.status_code == 403, (caller, body, r.data)
        r = who[caller].post(f'/api/clusters/{CID}/backup-restore',
                             json={'volid': volid, 'target_node': 'pve1', 'target_vmid': 101, 'mode': 'overwrite'})
        assert r.status_code in (400, 403), (caller, r.data)   # a path without a colon is no volid at all
    assert not posts


def test_a_vm_restore_takes_no_host_path_and_verify_neither(api, seed, monkeypatch):
    who = _who(api, seed)
    _m, posts = _restore_manager(api)
    r = who['acl'].post(f'/api/clusters/{CID}/vms/pve1/qemu/100/backups/restore', json={'volid': EVIL_VM})
    assert r.status_code == 403, r.data
    started = []
    import pegaprox.core.backup_verify as bv
    monkeypatch.setattr(bv, 'start_verification', lambda mgr, params: started.append(params) or 'task1')
    r = who['acl'].post(f'/api/clusters/{CID}/backup-verify',
                        json={'node': 'pve1', 'vmid': 101, 'backup_volid': EVIL_CT})
    assert r.status_code == 403, r.data
    assert not posts and not started


def test_a_backup_of_the_callers_own_guest_still_restores(api, seed):
    who = _who(api, seed)
    _m, posts = _restore_manager(api)
    r = who['acl'].post(f'/api/clusters/{CID}/vms/pve1/lxc/101/backups/restore', json={'volid': GOOD_CT})
    assert r.status_code == 200, r.data
    assert posts[-1][1]['ostemplate'] == GOOD_CT
    r = who['acl'].post(f'/api/clusters/{CID}/vms/pve1/qemu/100/backups/restore', json={'volid': GOOD_PBS})
    assert r.status_code == 200, r.data
    assert posts[-1][1]['archive'] == GOOD_PBS


@pytest.mark.parametrize('volid, guest', [
    ('local:backup/vzdump-qemu-100-2026_11_26-10_00_00.vma.zst', (100, 'qemu')),
    ('nfs-b:backup/vzdump-lxc-101-2026_11_26-10_00_00.tar.zst', (101, 'lxc')),
    ('old:backup/vzdump-openvz-102-2019_01_01-00_00_00.tar', (102, 'lxc')),
    ('pbs:backup/vm/100/2026-11-26T10:00:00Z', (100, 'qemu')),
    ('pbs:backup/ct/101/2026-11-26T10:00:00Z', (101, 'lxc')),
    (EVIL_CT, None), (EVIL_VM, None),
    ('local:backup/sub/vzdump-qemu-100-x.vma', None),
    ('pbs:backup/vm/100/2026/../x', None),
    ('pbs:backup/vm/0100/2026-11-26T10:00:00Z', None),
    ('local:backup/vzdump-qemu-100.vma', None),
    ('', None), (None, None),
])
def test_the_guest_of_a_backup_volume_id(volid, guest):
    assert backup_volid_guest(volid) == guest


# --- move disk ----------------------------------------------------------------------------------

def test_moving_a_disk_the_guest_does_not_own_keeps_the_original(api, seed):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    m.get_vm_config = MagicMock(return_value={'success': True, 'config': {'raw': {
        'scsi0': 'local-lvm:vm-100-disk-0,size=8G', 'scsi2': 'local-lvm:vm-200-disk-0,size=8G,shared=1'}}})
    m.move_disk = MagicMock(return_value={'success': True, 'message': 'moved', 'task': 'UPID:x'})
    for caller in ('pool', 'acl'):
        r = who[caller].post(f'{VM}/disks/scsi2/move', json={'storage': 'ceph'})
        assert r.status_code == 403 and r.get_json()['code'] == 'FOREIGN_VOLUME', (caller, r.data)
        r = who[caller].post(f'{VM}/disks/scsi2/move', json={'storage': 'ceph', 'delete': True})
        assert r.status_code == 403, (caller, r.data)
    assert not m.move_disk.called
    # with the original kept it is a copy, and the guest's own disk moves as before
    assert who['pool'].post(f'{VM}/disks/scsi2/move', json={'storage': 'ceph', 'delete': False}).status_code == 200
    assert who['acl'].post(f'{VM}/disks/scsi0/move', json={'storage': 'ceph'}).status_code == 200
    assert who['owner'].post(f'{VM}/disks/scsi2/move', json={'storage': 'ceph'}).status_code == 200
    m.get_vm_config = MagicMock(return_value={'success': False, 'error': 'timeout'})
    assert who['pool'].post(f'{VM}/disks/scsi0/move', json={'storage': 'ceph'}).status_code == 503


# --- an ISO only as a CD ------------------------------------------------------------------------

@pytest.mark.parametrize('body', [
    {'scsi1': 'local:iso/debian.iso'},
    {'virtio1': 'local:iso/debian.iso,cache=writeback'},
    {'ide2': 'local:iso/debian.iso'},
    {'sata2': 'cephfs:iso/win.iso,media=disk'},
    {'unused0': 'local:iso/debian.iso'},
])
def test_an_iso_is_no_disk_for_a_confined_caller(api, seed, body):
    who = _who(api, seed)
    m = _config_manager(api, FakePVE(), **ROOT_PW)
    m.get_vm_config = MagicMock(return_value={'success': True, 'config': {'raw': {}}})
    r = who['pool'].put(f'{VM}/config', json=dict(body))
    assert r.status_code == 403 and r.get_json()['code'] == 'FOREIGN_VOLUME', (body, r.data)
    assert not m.update_vm_config.called
    for ok in ({'ide2': 'local:iso/debian.iso,media=cdrom'}, {'sata1': 'media=CDROM,local:iso/a.iso'},
               {'cdrom': 'local:iso/debian.iso'}):
        assert who['acl'].put(f'{VM}/config', json=ok).status_code == 200, ok


# --- XCP-ng CD drive ----------------------------------------------------------------------------

XVM = f'/api/clusters/{CID}/vms/xcp-host-1/qemu/100'
DISK_VDI = '7f0c1f9e-2b1a-4c55-9d1e-200200200200'
ISO_VDI = '1b2c3d4e-0000-4000-8000-150150150150'


class _FakeXapi:
    def __init__(self):
        self.vbds = {'OpaqueRef:vbd-100-cd': {'type': 'CD', 'empty': True, 'VDI': 'OpaqueRef:NULL',
                                              'VM': 'OpaqueRef:vm-100'}}
        self.vdis = {DISK_VDI: 'OpaqueRef:vdi-200', ISO_VDI: 'OpaqueRef:vdi-iso'}
        self.sr_of = {'OpaqueRef:vdi-200': 'OpaqueRef:sr-lvm', 'OpaqueRef:vdi-iso': 'OpaqueRef:sr-iso'}
        self.inserted = []
        x = self

        class VM:
            @staticmethod
            def get_VBDs(ref):
                return [k for k, v in x.vbds.items() if v['VM'] == ref]

        class VBD:
            get_record = staticmethod(lambda ref: dict(x.vbds[ref]))
            get_empty = staticmethod(lambda ref: x.vbds[ref]['empty'])
            eject = staticmethod(lambda ref: x.vbds[ref].update(empty=True))
            insert = staticmethod(lambda ref, vdi: x.inserted.append((ref, vdi)))
            create = staticmethod(lambda rec: x.inserted.append(('new', rec['VDI'])))

        class VDI:
            get_by_uuid = staticmethod(lambda u: x.vdis[u])
            get_SR = staticmethod(lambda ref: x.sr_of[ref])

        class SR:
            get_type = staticmethod(lambda ref: 'iso' if ref == 'OpaqueRef:sr-iso' else 'lvm')

        self.VM, self.VBD, self.VDI, self.SR = VM, VBD, VDI, SR


def _xcp_who(api, seed):
    seed.tenant('tenant_x', [CID])
    seed.tenant('acme', ['cluster_2'])
    pool = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                     permissions=['vm.config', 'vm.view', 'cluster.view', 'xapi.vm.config'])
    seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.config'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_1'},
                                            'timestamp': time.time(), 'refreshing': False}
    acl = seed.user('alice', role='user', tenant_id='acme')
    seed.vm_acl(CID, 100, ['alice'])
    return {'pool': api.as_user(pool), 'acl': api.as_user(acl),
            'admin': api.as_user(seed.user('root', role='admin'))}


def _xcp_manager(api, xapi):
    m = api.make_fake_manager(CID, cluster_type='xcpng')
    m.config = types.SimpleNamespace(name=CID)
    m.is_connected = True
    m.get_vm_config = MagicMock(return_value={'success': True, 'config': {}})
    me = types.SimpleNamespace(_api=lambda: xapi, _resolve_vm=lambda vmid: f'OpaqueRef:vm-{vmid}',
                               logger=MagicMock())
    m.set_cdrom = lambda node, vmid, iso, drive='ide2': XcpngManager.set_cdrom(me, node, vmid, iso, drive)
    m.vdi_on_iso_sr = lambda uuid: XcpngManager.vdi_on_iso_sr(me, uuid)
    api.set_manager(CID, m)
    return m


def test_an_xcp_cd_drive_takes_an_iso_and_no_disk_of_another_guest(api, seed):
    who = _xcp_who(api, seed)
    for caller in ('acl', 'pool'):
        xapi = _FakeXapi()
        _xcp_manager(api, xapi)
        for iso in (DISK_VDI, 'no-such-uuid'):
            r = who[caller].put(f'{XVM}/cdrom', json={'iso': iso})
            assert r.status_code == 403 and r.get_json()['code'] == 'FOREIGN_VOLUME', (caller, iso, r.data)
        assert not xapi.inserted
        assert who[caller].put(f'{XVM}/cdrom', json={'iso': ISO_VDI}).status_code == 200
        assert xapi.inserted == [('OpaqueRef:vbd-100-cd', 'OpaqueRef:vdi-iso')]
        assert who[caller].put(f'{XVM}/cdrom', json={'iso': None}).status_code == 200
    xapi = _FakeXapi()
    _xcp_manager(api, xapi)
    assert who['admin'].put(f'{XVM}/cdrom', json={'iso': DISK_VDI}).status_code == 200


# --- efficient snapshots ------------------------------------------------------------------------

SNAP_ID = 'aaaaaaaa-1111-2222-3333-444444444444'


def _snapshot(db, vmid):
    db.save_efficient_snapshot({
        'id': SNAP_ID, 'cluster_id': CID, 'node': 'pve1', 'vmid': vmid, 'vm_type': 'qemu',
        'snapname': 'before-upgrade', 'vg_name': 'pve',
        'disks': [{'disk_key': 'scsi0', 'snap_lv': f'vm-{vmid}-disk-0-esnap-x', 'origin_lv': f'vm-{vmid}-disk-0'}],
        'status': 'active', 'created_by': 'someone',
    })


def _snap_manager(api):
    m = api.make_fake_manager(CID)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    m.config = types.SimpleNamespace(name=CID)
    m.logger = MagicMock()
    ran = []

    def _exec(node, cmd, *a, **k):
        ran.append((node, cmd))
        if cmd.startswith('lvs '):
            return 0, 'vm-200-disk-0\nvm-200-disk-0-esnap-x\nvm-100-disk-0\nvm-100-disk-0-esnap-x\n', ''
        return 0, '', ''
    m._node_ssh_exec = _exec
    sess = MagicMock()
    sess.get.return_value = MagicMock(status_code=200, json=lambda: {'data': {'status': 'stopped'}})
    m._create_session = lambda: sess
    m.rollback_efficient_snapshot = types.MethodType(PegaProxManager.rollback_efficient_snapshot, m)
    m.delete_efficient_snapshot = types.MethodType(PegaProxManager.delete_efficient_snapshot, m)
    api.set_manager(CID, m)
    return m, ran


def test_an_efficient_snapshot_of_another_guest_is_not_found(api, seed):
    who = _who(api, seed)
    _snapshot(seed.db, 200)
    _m, ran = _snap_manager(api)
    assert who['acl'].post(f'{VM}/efficient-snapshots/{SNAP_ID}/rollback').status_code == 404
    assert who['acl'].delete(f'{VM}/efficient-snapshots/{SNAP_ID}').status_code == 404
    assert not ran and seed.db.get_efficient_snapshot(SNAP_ID) is not None


def test_an_efficient_snapshot_of_the_guest_itself_still_goes(api, seed):
    who = _who(api, seed)
    _snapshot(seed.db, 100)
    _m, ran = _snap_manager(api)
    r = who['acl'].delete(f'/api/clusters/{CID}/vms/other-node/qemu/100/efficient-snapshots/{SNAP_ID}')
    assert r.status_code == 200, r.data
    # on the node the snapshot was taken on, not the one in the URL
    assert ran and all(n == 'pve1' for n, _c in ran)
