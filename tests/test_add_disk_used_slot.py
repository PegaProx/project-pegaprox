"""Adding a disk to a VM never lands on a slot that is already in use.

The ID in the add-disk dialog is a free text field. PVE takes a config PUT on a used drive
key as a replacement: the old disk is unplugged (live, on a running guest) and parked as
unusedN, and the new empty disk takes its place.
"""
from test_vm_disk_unlock import _Resp, _mgr

CONFIG = {
    'scsi0': 'local-lvm:vm-100-disk-0,iothread=1,size=32G',
    'ide2': 'none,media=cdrom',
    'boot': 'order=scsi0;ide2;net0',
}


def _add(disk_id, config=CONFIG, status=200):
    m = _mgr()
    m._api_get.return_value = _Resp(status, data=config)
    m._api_put.return_value = _Resp(200, text='')
    return m, m.add_disk('pve1', 100, 'qemu', {'disk_id': disk_id, 'storage': 'local-lvm', 'size': 8})


def test_a_used_disk_slot_is_refused():
    m, res = _add('scsi0')
    assert res['success'] is False
    assert 'scsi0' in res['error'] and 'in use' in res['error']
    m._api_put.assert_not_called()


def test_a_used_cdrom_slot_is_refused():
    m, res = _add('ide2')
    assert res['success'] is False
    m._api_put.assert_not_called()


def test_a_free_slot_is_added():
    m, res = _add('scsi1')
    assert res['success'] is True, res
    assert m._api_put.call_args.kwargs['data'] == {'scsi1': 'local-lvm:8'}


def test_an_unreadable_config_adds_nothing():
    m, res = _add('scsi1', config={}, status=500)
    assert res['success'] is False
    m._api_put.assert_not_called()
