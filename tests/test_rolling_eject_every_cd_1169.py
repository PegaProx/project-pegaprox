"""Before a live move the ISO comes out of every CD drive, not only ide2 (#1169).

A rolling update drains each node through maintenance, and migrate_vm ejected an ISO only
from ide2 (and 'cdrom', which PVE turns into ide2 when it reads the config). An ISO in a CD
drive on SCSI - the bus people pick because it hotplugs - or on SATA or another IDE slot
stayed in, Proxmox refused the move ("local cdrom image" or "storage is not available on
node") and the rolling update stopped on it. Every ide/sata/scsi drive with media=cdrom and
an image now gets "none,media=cdrom": the drive stays, the medium goes. Cloud-init drives,
the host's own drive and empty drives are not touched. The template check of the evacuation
names its local CD images with the same helper.

MK Oct 2026
"""
import logging
import types

from pegaprox.core.manager import PegaProxManager
from pegaprox.core.preflight import cdrom_images
from pegaprox.models.tasks import MaintenanceTask, PegaProxConfig

CONFIG = '/nodes/pve1/qemu/101/config'


def _resp(status=200, data=None, text=''):
    return types.SimpleNamespace(status_code=status, json=lambda: {'data': data}, text=text)


class _Pve:
    """One guest's config, the PUTs and the migrate POST in the order they were sent."""

    def __init__(self, config, put_status=None, put_raises=None):
        self.config = config
        self.put_status = put_status or {}
        self.put_raises = put_raises or {}
        self.calls = []

    def get(self, url, timeout=None, **kw):
        if '/capabilities/qemu/migration' in url:
            return _resp(501, None, 'Method not implemented')
        path = url.split('/api2/json', 1)[1]
        if path.endswith('/config'):
            return _resp(200, dict(self.config))
        return _resp(404)

    def put(self, url, data=None, timeout=None, **kw):
        path = url.split('/api2/json', 1)[1]
        data = dict(data or {})
        self.calls.append(('put', path, data))
        key = next(iter(data))
        if key in self.put_raises:
            raise self.put_raises[key]
        status = self.put_status.get(key, 200)
        return _resp(status, None, '' if status == 200 else f'{key}: unable to change media')

    def post(self, url, data=None, **kw):
        self.calls.append(('migrate', url.split('/api2/json', 1)[1], dict(data or {})))
        return _resp(200, 'UPID:pve1:0001:qmigrate')

    def ejected(self):
        return [next(iter(d)) for kind, _p, d in self.calls if kind == 'put']

    def migrations(self):
        return [(p, d) for kind, p, d in self.calls if kind == 'migrate']


def _manager(pve):
    m = object.__new__(PegaProxManager)
    m.id = 'cluster_1'
    m.current_host = None
    m.config = PegaProxConfig({'name': 'lab', 'host': 'pve1.lab', 'user': 'u', 'dry_run': False})
    m.per_node_timeout = 4
    m.is_connected = True
    m.logger = logging.getLogger('test.rolling_eject_1169')
    m._no_agent_vms = set()
    m._create_session = lambda: types.SimpleNamespace(get=pve.get, put=pve.put)
    m._api_post = pve.post
    m._wait_for_task = lambda node, upid, timeout=0: True
    m._note_migration = lambda *a, **k: None
    return m


def _guest(vm_type='qemu'):
    return {'vmid': 101, 'name': 'win-build', 'node': 'pve1', 'type': vm_type, 'status': 'running'}


def _move(config, **kw):
    pve = _Pve(config, **kw)
    ok = _manager(pve).migrate_vm(_guest(), 'pve2', dry_run=False)
    return pve, ok


# --- which drives come out -----------------------------------------------------------------------

def test_an_iso_on_scsi_sata_or_another_ide_slot_is_ejected_before_the_move():
    pve, ok = _move({
        'virtio0': 'local-lvm:vm-101-disk-0,iothread=1,size=64G',
        'scsi0': 'local:iso/virtio-win-0.1.262.iso,media=cdrom,size=708140K',
        'sata1': 'nfs-iso:iso/debian-12.7.0-amd64-netinst.iso,media=cdrom,size=631M',
        'ide0': 'local:iso/gparted-live-1.6.0-3-amd64.iso,media=cdrom',
        'ide2': 'none,media=cdrom',
        'scsihw': 'virtio-scsi-single', 'boot': 'order=virtio0;scsi0',
    })
    assert ok is True
    assert sorted(pve.ejected()) == ['ide0', 'sata1', 'scsi0'], (
        f"ejected {pve.ejected()}; the ISOs on scsi0, sata1 and ide0 stay in and Proxmox refuses the move")
    for kind, path, data in pve.calls[:-1]:
        assert (kind, path) == ('put', CONFIG) and list(data.values()) == ['none,media=cdrom']
    # the medium is out before the migrate call goes
    assert pve.calls[-1][0] == 'migrate' and len(pve.migrations()) == 1
    assert pve.migrations()[0][0] == '/nodes/pve1/qemu/101/migrate'


def test_an_iso_on_ide2_still_comes_out():
    pve, ok = _move({'scsi0': 'ceph:vm-101-disk-0,size=32G',
                     'ide2': 'local:iso/ubuntu-24.04.1-live-server-amd64.iso,media=cdrom,size=2708862K'})
    assert ok is True
    assert pve.calls[0] == ('put', CONFIG, {'ide2': 'none,media=cdrom'})
    assert len(pve.migrations()) == 1


def test_an_iso_given_by_path_still_comes_out_as_it_did_on_ide2():
    pve, _ok = _move({'scsi0': 'ceph:vm-101-disk-0,size=32G',
                      'ide2': '/mnt/pve/isos/template/iso/rescue.iso,media=cdrom'})
    assert pve.ejected() == ['ide2']


def test_cloud_init_the_host_drive_empty_drives_and_disks_are_left_alone():
    pve, ok = _move({
        'scsi0': 'local-lvm:vm-101-disk-0,size=32G',
        'scsi1': 'local:101/vm-101-isolated.qcow2,size=8G',      # a disk, "iso" in its name
        'ide2': 'local-lvm:vm-101-cloudinit,media=cdrom',
        'ide0': 'cdrom,media=cdrom',                              # the host's own drive
        'sata0': '/dev/sr0,media=cdrom',
        'sata1': 'none,media=cdrom',
        'scsi2': 'none,media=cdrom',
    })
    assert ok is True
    assert pve.ejected() == [], f"touched {pve.ejected()}"
    assert len(pve.migrations()) == 1


def test_a_container_config_is_not_read_or_changed():
    pve = _Pve({'rootfs': 'local-lvm:vm-101-disk-0,size=8G'})
    assert _manager(pve).migrate_vm(_guest('lxc'), 'pve2', dry_run=False) is True
    assert pve.ejected() == []
    assert pve.migrations()[0][0] == '/nodes/pve1/lxc/101/migrate'


# --- a failed eject is said and the move still goes ----------------------------------------------

def test_a_refused_eject_is_logged_the_other_drives_still_come_out_and_the_move_goes(caplog):
    caplog.set_level(logging.INFO, logger='test.rolling_eject_1169')
    pve, ok = _move({'scsi0': 'ceph:vm-101-disk-0,size=32G',
                     'sata1': 'local:iso/debian-12.iso,media=cdrom',
                     'scsi1': 'local:iso/virtio-win.iso,media=cdrom'},
                    put_status={'sata1': 500})
    assert ok is True
    assert pve.ejected() == ['sata1', 'scsi1']
    assert len(pve.migrations()) == 1
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any('couldnt unmount iso from sata1' in w and 'unable to change media' in w for w in warned), warned


def test_an_eject_that_does_not_answer_is_logged_and_the_move_goes(caplog):
    caplog.set_level(logging.INFO, logger='test.rolling_eject_1169')
    pve, ok = _move({'scsi0': 'ceph:vm-101-disk-0,size=32G',
                     'scsi1': 'local:iso/virtio-win.iso,media=cdrom'},
                    put_raises={'scsi1': ConnectionError('node went away')})
    assert ok is True
    assert len(pve.migrations()) == 1
    assert any('couldnt unmount iso from scsi1' in r.getMessage() and 'node went away' in r.getMessage()
               for r in caplog.records if r.levelno == logging.WARNING)


# --- the rolling update gets there through the evacuation ----------------------------------------

def test_the_maintenance_evacuation_takes_the_scsi_iso_out_before_it_moves_the_guest():
    pve = _Pve({'scsi0': 'local-lvm:vm-101-disk-0,size=32G',
                'scsi1': 'local:iso/virtio-win.iso,media=cdrom'})
    m = _manager(pve)
    where = {101: 'pve1'}
    sent_migrate = pve.post

    def post(url, data=None, **kw):
        where[101] = data['target']
        return sent_migrate(url, data=data, **kw)
    m._api_post = post
    m.get_vm_resources = lambda *a, **k: [dict(_guest(), node=where[101])]
    m.get_best_target_node = lambda *a, **k: 'pve2'
    # the evacuation reads the node list itself before it asks for a target
    m.get_node_status = lambda: {'pve1': {'status': 'online', 'score': 1}, 'pve2': {'status': 'online', 'score': 1}}
    m._evacuation_placement = lambda: ({}, {})
    m._derive_proxlb_tag_rules = lambda *a, **k: {'rules': [], 'pins': {}}
    m._count_vms_on_node = lambda node: 0
    task = MaintenanceTask('pve1')
    PegaProxManager._evacuate_node(m, 'pve1', task)
    assert task.status == 'completed' and task.failed_vms == []
    assert [c[0] for c in pve.calls] == ['put', 'migrate']
    assert pve.calls[0] == ('put', CONFIG, {'scsi1': 'none,media=cdrom'})


# --- the template check counts the same drives ---------------------------------------------------

def test_the_template_check_names_a_scsi_cd_image_on_local_storage():
    reads = {
        '/cluster/resources': [
            {'storage': s, 'node': n, 'status': 'available', 'shared': sh}
            for n in ('pve1', 'pve2') for s, sh in (('local', 0), ('local-lvm', 0), ('san', 1))],
        '/nodes/pve1/qemu/9000/config': {'scsi0': 'san:base-9000-disk-0,size=32G',
                                         'ide2': 'local-lvm:vm-9000-cloudinit,media=cdrom',
                                         'scsi1': 'local:iso/virtio-win.iso,media=cdrom'},
    }
    m = _manager(_Pve({}))
    m._api_get = lambda url, **kw: _resp(200, reads[url.split('/api2/json', 1)[1]])
    row = m.template_placement([{'vmid': 9000, 'name': 'tpl', 'node': 'pve1', 'type': 'qemu'}])[0]
    assert (row['code'], row['args']) == ('local_image', {'drive': 'scsi1', 'storage': 'local'})


def test_the_eject_and_the_preflight_count_the_same_storage_images():
    cfg = {'scsi1': 'local:iso/a.iso,media=cdrom', 'sata0': 'file=nfs-iso:iso/b.iso,media=cdrom',
           'ide1': 'local-lvm:vm-1-cloudinit,media=cdrom', 'ide2': '/var/lib/vz/x.iso,media=cdrom',
           'ide3': '/dev/sr0,media=cdrom', 'ide0': 'cdrom,media=cdrom', 'virtio0': 'local:iso/c.iso'}
    assert cdrom_images(cfg) == [('sata0', 'nfs-iso', 'nfs-iso:iso/b.iso'), ('scsi1', 'local', 'local:iso/a.iso')]
    # the eject also takes an image file set by path out, as the ide2 eject did
    assert cdrom_images(cfg, paths=True) == [('ide2', None, '/var/lib/vz/x.iso'),
                                             ('sata0', 'nfs-iso', 'nfs-iso:iso/b.iso'),
                                             ('scsi1', 'local', 'local:iso/a.iso')]
