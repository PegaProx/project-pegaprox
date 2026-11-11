"""Add Disk puts SSD emulation only on a bus that has it.

PVE's drive schema has `ssd` on IDE, SATA and SCSI and not on VirtIO Block, and it refuses
the whole PUT when virtio1 carries it, so the disk is not added at all. add_disk counted
virtio among the buses with SSD emulation. IDE stays without it here, as before.

Drives the real PegaProxManager.add_disk with the HTTP helpers faked.
"""
from test_vm_disk_unlock import _Resp, _mgr


def _added(disk_id, **disk):
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'scsi0': 'local-lvm:vm-100-disk-0,size=32G'})
    m._api_put.return_value = _Resp(200, text='')
    res = m.add_disk('pve1', 100, 'qemu', {'disk_id': disk_id, 'storage': 'local-lvm', 'size': 8, **disk})
    assert res['success'] is True, res
    url = m._api_put.call_args.args[0]
    assert url.endswith('/nodes/pve1/qemu/100/config'), url
    data = m._api_put.call_args.kwargs['data']
    assert list(data) == [disk_id], data
    return data[disk_id].split(',')


def test_ssd_goes_on_scsi_and_sata_only():
    got = {bus: 'ssd=1' in _added(f'{bus}1', ssd=True) for bus in ('scsi', 'sata', 'virtio', 'ide')}
    assert got == {'scsi': True, 'sata': True, 'virtio': False, 'ide': False}


def test_a_virtio_disk_keeps_its_other_options():
    assert _added('virtio1', ssd=True, iothread=True, discard=True, cache='writeback') == [
        'local-lvm:8', 'cache=writeback', 'iothread=1', 'discard=on']
