"""SSD emulation of the create dialog lands only on a bus that has it.

PVE's drive schema has `ssd` on IDE, SATA and SCSI and not on VirtIO Block, and it refuses
the whole create when virtio0 carries it. The dialog offers the box for every bus, the main
disk and each additional one alike.
"""
import pytest

from test_start_after_create import VM, _manager


def _created(**config):
    m = _manager()
    assert m.create_vm('n1', dict(VM, storage='local-lvm', disk_size='8', **config))['success'] is True
    url, data = m.posted[0]
    assert url.endswith('/nodes/n1/qemu')
    return data


def _opts(drive):
    return drive.split(',')[1:]


@pytest.mark.parametrize('bus', ['scsi', 'sata', 'ide'])
def test_the_main_disk_takes_ssd_where_pve_has_it(bus):
    data = _created(disk_type=bus, disk_discard=True, disk_ssd=True)
    assert 'ssd=1' in _opts(data[f'{bus}0'])


def test_a_virtio_main_disk_is_created_without_ssd():
    data = _created(disk_type='virtio', disk_discard=True, disk_ssd=True)
    assert _opts(data['virtio0']) == ['discard=on']


@pytest.mark.parametrize('bus', ['scsi', 'sata', 'ide'])
def test_an_additional_disk_takes_ssd_where_pve_has_it(bus):
    data = _created(disk_type='scsi', additional_disks=[
        {'type': bus, 'size': '4', 'discard': False, 'iothread': False, 'ssd': True}])
    assert _opts(data[f'{bus}1']) == ['ssd=1']


def test_an_additional_virtio_disk_is_created_without_ssd():
    data = _created(disk_type='scsi', disk_ssd=True, additional_disks=[
        {'type': 'virtio', 'size': '4', 'discard': True, 'ssd': True}])
    assert _opts(data['virtio1']) == ['discard=on']
    # the SCSI main disk of the same VM keeps it
    assert 'ssd=1' in _opts(data['scsi0'])


@pytest.mark.parametrize('bus', ['scsi', 'sata', 'ide', 'virtio'])
def test_no_ssd_without_the_box(bus):
    data = _created(disk_type=bus, disk_ssd=False, additional_disks=[
        {'type': bus, 'size': '4', 'ssd': False}])
    assert not [d for d in (data[f'{bus}0'], data[f'{bus}1']) if 'ssd=1' in _opts(d)]
