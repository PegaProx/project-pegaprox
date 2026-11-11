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
