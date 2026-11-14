"""Removing a disk with its data deletes that disk's volume and no other.

After the detach, remove_disk finds the unusedN slot holding the removed volume and deletes that
slot. The old lookup was a substring test, so disk-1 matched the unused disk-10 and Proxmox
destroyed disk-10. These drive the real PegaProxManager.remove_disk with the HTTP helpers faked:
the config is served in sequence (before the detach, then after it) and every write is recorded.
"""
import itertools
import types
from unittest.mock import call, patch

from pegaprox.core.manager import PegaProxManager
from test_vm_disk_unlock import _Resp, _mgr

BASE = 'https://pve.example:8006/api2/json/nodes/pve1'


def _url(vmid=100, vm_type='qemu'):
    return f'{BASE}/{vm_type}/{vmid}/config'


def _remove(reads, disk_id, vmid=100, vm_type='qemu', delete_data=True):
    """Serve the config reads in order, run remove_disk with the sleep skipped, return (result, mock)."""
    m = _mgr()
    m.remove_disk = types.MethodType(PegaProxManager.remove_disk, m)
    m.get_vm_config = types.MethodType(PegaProxManager.get_vm_config, m)
    m._parse_vm_config = lambda config, vm_type: {}  # remove_disk only reads 'raw' from the parsed config
    m._create_session.return_value.get.return_value = _Resp(200, data={'status': 'stopped'})
    m._api_get.side_effect = [_Resp(200, data=cfg) for cfg in reads]
    m._api_put.return_value = _Resp(200, text='')
    m._api_delete.return_value = _Resp(200, text='')
    with patch('time.sleep'):
        res = m.remove_disk('pve1', vmid, vm_type, disk_id, delete_data)
    return res, m


def test_removing_scsi1_deletes_unused1_and_leaves_the_longer_name_in_unused0_alone():
    """Removing scsi1 with its data destroys disk-1 (unused1) and leaves disk-10 (unused0) on the storage."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G', 'unused0': 'local-lvm:vm-100-disk-10'}
    after = {'unused0': 'local-lvm:vm-100-disk-10', 'unused1': 'local-lvm:vm-100-disk-1'}
    res, m = _remove([before, after], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, res
    assert m._api_put.call_args_list == [
        call(_url(), data={'delete': 'scsi1'}),
        call(_url(), data={'delete': 'unused1'}),
    ]
    assert m._api_delete.call_args_list == []


def test_the_chosen_slot_is_the_same_whichever_order_the_keys_come_in():
    """With disk-10 and disk-1 both unused, removing disk-1 destroys disk-1 whichever key is listed first."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G', 'unused0': 'local-lvm:vm-100-disk-10'}
    held = {'unused0': 'local-lvm:vm-100-disk-10', 'unused1': 'local-lvm:vm-100-disk-1'}
    for order in (('unused0', 'unused1'), ('unused1', 'unused0')):
        after = {k: held[k] for k in order}
        res, m = _remove([before, after], 'scsi1')
        assert res['success'] is True, (order, res)
        assert m._api_put.call_args_list == [
            call(_url(), data={'delete': 'scsi1'}),
            call(_url(), data={'delete': 'unused1'}),
        ], order
        assert m._api_delete.call_args_list == [], order


def test_three_unused_slots_with_prefix_names_destroy_only_disk_1_in_any_key_order():
    """Unused disk-100, disk-10 and disk-1 sit side by side, and removing disk-1 destroys only disk-1."""
    before = {'scsi2': 'local-lvm:vm-100-disk-1,size=4G',
              'unused0': 'local-lvm:vm-100-disk-100', 'unused1': 'local-lvm:vm-100-disk-10'}
    held = {'unused0': 'local-lvm:vm-100-disk-100', 'unused1': 'local-lvm:vm-100-disk-10',
            'unused2': 'local-lvm:vm-100-disk-1'}
    for order in itertools.permutations(('unused0', 'unused1', 'unused2')):
        after = {k: held[k] for k in order}
        res, m = _remove([before, after], 'scsi2')
        assert res['success'] is True, (order, res)
        assert m._api_put.call_args_list == [
            call(_url(), data={'delete': 'scsi2'}),
            call(_url(), data={'delete': 'unused2'}),
        ], order
        assert m._api_delete.call_args_list == [], order


def test_a_directory_file_is_matched_by_its_full_name_not_by_the_end_of_another_storage_name():
    """Removing local:100/vm-100-disk-1.qcow2 deletes that file, not the same name on ssd-local."""
    before = {'scsi1': 'local:100/vm-100-disk-1.qcow2,size=4G',
              'unused0': 'ssd-local:100/vm-100-disk-1.qcow2'}
    after = {'unused0': 'ssd-local:100/vm-100-disk-1.qcow2', 'unused1': 'local:100/vm-100-disk-1.qcow2'}
    res, m = _remove([before, after], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, res
    assert m._api_put.call_args_list == [
        call(_url(), data={'delete': 'scsi1'}),
        call(_url(), data={'delete': 'unused1'}),
    ]
    assert m._api_delete.call_args_list == []


def test_a_directory_file_next_to_a_longer_file_name_is_left_alone():
    """Removing disk-1.qcow2 deletes disk-1.qcow2 and leaves disk-10.qcow2 on the same storage."""
    before = {'scsi1': 'local:100/vm-100-disk-1.qcow2,size=4G',
              'unused0': 'local:100/vm-100-disk-10.qcow2'}
    after = {'unused0': 'local:100/vm-100-disk-10.qcow2', 'unused1': 'local:100/vm-100-disk-1.qcow2'}
    res, m = _remove([before, after], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, res
    assert m._api_put.call_args_list == [
        call(_url(), data={'delete': 'scsi1'}),
        call(_url(), data={'delete': 'unused1'}),
    ]
    assert m._api_delete.call_args_list == []


def test_options_after_the_comma_on_the_removed_disk_do_not_change_the_slot_picked():
    """Removing scsi1 with size, cache and iothread set destroys disk-1 (unused1) and leaves disk-10 alone."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=32G,cache=writeback,iothread=1',
              'unused0': 'local-lvm:vm-100-disk-10,size=8G'}
    after = {'unused0': 'local-lvm:vm-100-disk-10,size=8G', 'unused1': 'local-lvm:vm-100-disk-1'}
    res, m = _remove([before, after], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, res
    assert m._api_put.call_args_list == [
        call(_url(), data={'delete': 'scsi1'}),
        call(_url(), data={'delete': 'unused1'}),
    ]
    assert m._api_delete.call_args_list == []


def test_an_unused_value_with_options_or_spaces_still_matches_its_exact_id():
    """Removing disk-1 whose unused1 entry carries options or spaces destroys unused1 and leaves disk-10."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G', 'unused0': 'local-lvm:vm-100-disk-10'}
    for held in ('local-lvm:vm-100-disk-1,size=32G', ' local-lvm:vm-100-disk-1 '):
        after = {'unused0': 'local-lvm:vm-100-disk-10', 'unused1': held}
        res, m = _remove([before, after], 'scsi1')
        assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, (held, res)
        assert m._api_put.call_args_list == [
            call(_url(), data={'delete': 'scsi1'}),
            call(_url(), data={'delete': 'unused1'}),
        ], held
        assert m._api_delete.call_args_list == [], held


def test_with_no_unused_entry_at_all_the_storage_content_delete_is_the_only_delete():
    """A detach that leaves no unused entry sends the storage delete for the volume and no unused key."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G'}
    res, m = _remove([before, {}], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, res
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'scsi1'})]
    assert m._api_delete.call_args_list == [
        call(f'{BASE}/storage/local-lvm/content/local-lvm%3Avm-100-disk-1'),
    ]


def test_with_no_unused_slot_holding_the_volume_only_the_storage_content_delete_is_sent():
    """If no unused slot holds the removed volume, the storage delete removes it and disk-10 stays."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G', 'unused0': 'local-lvm:vm-100-disk-10'}
    after = {'unused0': 'local-lvm:vm-100-disk-10'}
    res, m = _remove([before, after], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 removed and deleted'}, res
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'scsi1'})]
    assert m._api_delete.call_args_list == [
        call(f'{BASE}/storage/local-lvm/content/local-lvm%3Avm-100-disk-1'),
    ]


def test_two_unused_slots_holding_the_same_volume_destroy_nothing_and_say_the_volume_is_kept():
    """If two unused slots hold the removed volume, nothing is destroyed and the answer says the volume is kept."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G', 'unused0': 'local-lvm:vm-100-disk-1'}
    after = {'unused0': 'local-lvm:vm-100-disk-1', 'unused1': 'local-lvm:vm-100-disk-1'}
    res, m = _remove([before, after], 'scsi1')
    assert res == {'success': True, 'message': 'Disk scsi1 detached (volume kept: local-lvm:vm-100-disk-1 is held '
                                               'by unused0, unused1)'}, res
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'scsi1'})]
    assert m._api_delete.call_args_list == []


def test_without_delete_data_the_disk_is_only_detached():
    """Removing a disk without its data only detaches it: the volume stays and nothing else is sent."""
    before = {'scsi1': 'local-lvm:vm-100-disk-1,size=4G', 'unused0': 'local-lvm:vm-100-disk-10'}
    res, m = _remove([before], 'scsi1', delete_data=False)
    assert res == {'success': True, 'message': 'Disk scsi1 detached'}, res
    assert m._api_get.call_count == 1
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'scsi1'})]
    assert m._api_delete.call_args_list == []


def test_removing_the_unused0_key_through_the_disks_route_never_sends_a_delete_for_unused1():
    """Removing unused0 (disk-1) through the disks route never sends a delete for unused1 (disk-10)."""
    before = {'unused0': 'local-lvm:vm-100-disk-1', 'unused1': 'local-lvm:vm-100-disk-10'}
    after = {'unused1': 'local-lvm:vm-100-disk-10'}
    res, m = _remove([before, after], 'unused0')
    assert res['success'] is True, res
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'unused0'})]
    assert m._api_delete.call_args_list == [
        call(f'{BASE}/storage/local-lvm/content/local-lvm%3Avm-100-disk-1'),
    ]


def test_a_container_mount_point_destroys_only_its_own_unused_volume():
    """Removing mp1 with its data from container 105 destroys disk-1 (unused1) and leaves disk-10 alone."""
    before = {'mp1': 'local-zfs:subvol-105-disk-1,mp=/srv,size=8G', 'unused0': 'local-zfs:subvol-105-disk-10'}
    after = {'unused0': 'local-zfs:subvol-105-disk-10', 'unused1': 'local-zfs:subvol-105-disk-1'}
    res, m = _remove([before, after], 'mp1', vmid=105, vm_type='lxc')
    assert res == {'success': True, 'message': 'Disk mp1 removed and deleted'}, res
    assert m._api_put.call_args_list == [
        call(_url(105, 'lxc'), data={'delete': 'mp1'}),
        call(_url(105, 'lxc'), data={'delete': 'unused1'}),
    ]
    assert m._api_delete.call_args_list == []


# When no unusedN slot holds the volume, remove_disk falls back to the storage content DELETE.
# PVE frees whatever volume that names, with no look at any guest config, and it parks only a
# volume of the guest itself in unusedN. So the fallback is for a volume named after this guest.

def test_a_disk_of_another_guest_is_detached_and_never_freed_on_the_storage():
    """VM 100 holds VM 200's disk: after the detach no slot holds it, and no storage delete is sent."""
    before = {'scsi1': 'local-lvm:vm-200-disk-0,size=4G'}
    res, m = _remove([before, {}], 'scsi1')
    assert res == {'success': True,
                   'message': 'Disk scsi1 detached (volume kept: local-lvm:vm-200-disk-0 does not belong to guest 100)'}, res
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'scsi1'})]
    assert m._api_delete.call_args_list == []


def test_an_iso_in_a_removed_cd_drive_stays_on_the_storage():
    """Removing ide2 with its data never deletes the ISO it had loaded, which other guests may use."""
    before = {'ide2': 'local:iso/debian-12.iso,media=cdrom,size=600M'}
    res, m = _remove([before, {}], 'ide2')
    assert res['success'] is True and 'volume kept' in res['message'], res
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'ide2'})]
    assert m._api_delete.call_args_list == []


def test_a_linked_clone_volume_belongs_to_the_guest_named_last():
    """base-99-disk-0/vm-100-disk-1 is VM 100's disk: freed when VM 100 drops it, kept when VM 99 does."""
    cases = (
        ('local-zfs:base-99-disk-0/vm-100-disk-1', 100, 'local-zfs'),
        ('local:99/base-99-disk-0.qcow2/100/vm-100-disk-1.qcow2', 100, 'local'),
        ('local:100/vm-100-disk-1.qcow2', 100, 'local'),
        ('local-zfs:subvol-100-disk-1', 100, 'local-zfs'),
        ('local-zfs:base-99-disk-0/vm-100-disk-1', 99, None),
        ('local:99/base-99-disk-0.qcow2/100/vm-100-disk-1.qcow2', 99, None),
        ('local:100/vm-100-disk-1.qcow2', 99, None),
        ('local:snippets/vm-100-cloudinit.yml', 100, None),
        ('local-lvm:vm-1000-disk-1', 100, None),
    )
    for volid, vmid, storage in cases:
        res, m = _remove([{'scsi1': f'{volid},size=4G'}, {}], 'scsi1', vmid=vmid)
        assert res['success'] is True, (volid, vmid, res)
        if storage:
            assert m._api_delete.call_args_list == [
                call(f'{BASE}/storage/{storage}/content/' + volid.replace(':', '%3A').replace('/', '%2F')),
            ], (volid, vmid)
        else:
            assert m._api_delete.call_args_list == [], (volid, vmid)
            assert res['message'] == f'Disk scsi1 detached (volume kept: {volid} does not belong to guest {vmid})', res


# On a running guest PVE unplugs a drive at once only where it can (scsi or virtio with disk
# hotplug). Otherwise the delete waits in the pending section until the next start, the volume
# stays in use, and the config read after the detach shows the key gone with no unusedN for it.

def _remove_running(before, disk_id, pending, vmid=100, vm_type='qemu', status=None):
    """remove_disk on a running guest: the config before and after the detach, then the pending read."""
    m = _mgr()
    m.remove_disk = types.MethodType(PegaProxManager.remove_disk, m)
    m.get_vm_config = types.MethodType(PegaProxManager.get_vm_config, m)
    m._parse_vm_config = lambda config, vm_type: {}
    m._create_session.return_value.get.return_value = status or _Resp(200, data={'status': 'running'})
    m._api_get.side_effect = [_Resp(200, data=before), _Resp(200, data={}), pending]
    m._api_put.return_value = _Resp(200, text='')
    m._api_delete.return_value = _Resp(200, text='')
    with patch('time.sleep'):
        res = m.remove_disk('pve1', vmid, vm_type, disk_id, True)
    return res, m


def test_a_detach_that_waits_for_the_next_start_keeps_the_volume_the_guest_still_uses():
    """sata1 of a running VM is only marked for removal: nothing is freed, and the answer says when it goes."""
    before = {'sata1': 'local:100/vm-100-disk-1.qcow2,size=4G'}
    pending = _Resp(200, data=[{'key': 'sata1', 'value': 'local:100/vm-100-disk-1.qcow2,size=4G', 'delete': 1},
                               {'key': 'memory', 'value': '2048'}])
    res, m = _remove_running(before, 'sata1', pending)
    assert res == {'success': True,
                   'message': 'Disk sata1 is detached at the next start of guest 100 (volume kept)'}, res
    assert m._api_get.call_args_list[-1] == call(f'{BASE}/qemu/100/pending')
    assert m._api_put.call_args_list == [call(_url(), data={'delete': 'sata1'})]
    assert m._api_delete.call_args_list == []

    # the same guest with no delete waiting for sata1: the storage delete goes out as before
    res, m = _remove_running(before, 'sata1', _Resp(200, data=[{'key': 'memory', 'value': '2048'}]))
    assert res == {'success': True, 'message': 'Disk sata1 removed and deleted'}, res
    assert m._api_delete.call_args_list == [
        call(f'{BASE}/storage/local/content/local%3A100%2Fvm-100-disk-1.qcow2'),
    ]


def test_a_mount_point_of_a_running_container_is_kept_until_its_next_start():
    """mp0 of running CT 105 is only marked for removal, so its subvolume stays on the storage."""
    before = {'mp0': 'local-zfs:subvol-105-disk-1,mp=/srv,size=8G'}
    pending = _Resp(200, data=[{'key': 'mp0', 'value': 'local-zfs:subvol-105-disk-1,mp=/srv,size=8G', 'delete': 1}])
    res, m = _remove_running(before, 'mp0', pending, vmid=105, vm_type='lxc')
    assert res == {'success': True,
                   'message': 'Disk mp0 is detached at the next start of guest 105 (volume kept)'}, res
    assert m._api_get.call_args_list[-1] == call(f'{BASE}/lxc/105/pending')
    assert m._api_delete.call_args_list == []


def test_a_running_guest_whose_pending_changes_cannot_be_read_keeps_the_volume():
    """Without the pending list there is no telling whether the guest still uses the disk, so it stays."""
    before = {'sata1': 'local-lvm:vm-100-disk-1,size=4G'}
    res, m = _remove_running(before, 'sata1', _Resp(403, text='{"data":null}'))
    assert res == {'success': True, 'message': 'Disk sata1 detach sent (volume kept: the pending changes of '
                                               'guest 100 could not be read)'}, res
    assert m._api_delete.call_args_list == []


def test_a_guest_whose_status_cannot_be_read_is_treated_as_running():
    """status/current fails right after the config read: the pending list still decides, so the disk stays."""
    before = {'sata1': 'local:100/vm-100-disk-1.qcow2,size=4G'}
    pending = _Resp(200, data=[{'key': 'sata1', 'delete': 1}])
    res, m = _remove_running(before, 'sata1', pending, status=_Resp(596, text=''))
    assert res == {'success': True,
                   'message': 'Disk sata1 is detached at the next start of guest 100 (volume kept)'}, res
    assert m._api_delete.call_args_list == []


def test_removing_the_only_boot_disk_of_a_vm_without_a_nic_drops_the_boot_order():
    """The order fell back to net0, which PVE refuses on a VM that has none."""
    before = {'boot': 'order=scsi0', 'scsi0': 'local-lvm:vm-100-disk-0,size=4G'}
    res, m = _remove([before], 'scsi0', delete_data=False)
    assert res['success'] is True, res
    assert m._api_put.call_args_list == [
        call(_url(), data={'delete': 'boot'}),
        call(_url(), data={'delete': 'scsi0'}),
    ]


def test_removing_the_only_boot_disk_of_a_vm_with_a_nic_boots_it_from_the_network():
    before = {'boot': 'order=scsi0', 'scsi0': 'local-lvm:vm-100-disk-0,size=4G',
              'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0'}
    res, m = _remove([before], 'scsi0', delete_data=False)
    assert res['success'] is True, res
    assert m._api_put.call_args_list == [
        call(_url(), data={'boot': 'order=net0'}),
        call(_url(), data={'delete': 'scsi0'}),
    ]
