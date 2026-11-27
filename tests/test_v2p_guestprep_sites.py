"""Where the Windows preparation hooks into _run_v2p_migration (MK Nov 2026).

The run is one long function with a stop of the source at five places, three post-copy chains
and a planning step with a strict order (nothing installed, no VMID taken, no VM made before the
in-guest check). These read the source, so a new transfer mode or a moved block that loses a
hook fails here and not in a guest.
"""
import pathlib
import re

SRC = (pathlib.Path(__file__).resolve().parent.parent / 'pegaprox' / 'core' / 'v2p.py').read_text(encoding='utf-8')
RUN = SRC.split('def _run_v2p_migration(task):', 1)[1].split('\ndef ', 1)[0]
MIRROR = SRC.split('def _do_sshfs_boot_migration(', 1)[1].split('\ndef ', 1)[0]


def _block(start, end, text=RUN):
    a = text.index(start)
    return text[a:text.index(end, a)]


def test_every_stop_of_the_source_asks_the_in_guest_preparation_first():
    assert RUN.count('_source_off_for_cutover(vmware_mgr, pve_mgr, task)') == 5
    mirror = _block("if task.transfer_mode == 'sshfs_boot':", "vmware_mgr.vm_power_action(task.vm_id, 'stop')")
    assert 'is_running and _source_off_for_cutover' in mirror
    clone = _block("=== SWITCHOVER: stopping the source VM on ESXi", "vmware_mgr.vm_power_action(task.vm_id, 'stop')")
    assert "src_state == 'POWERED_ON' and _source_off_for_cutover" in clone
    offline = _block('=== TRANSFER MODE: Offline Copy ===', "vmware_mgr.vm_power_action(task.vm_id, 'stop')")
    assert 'is_running and _source_off_for_cutover' in offline
    fallback = _block('Pre-sync failed (VMDK locked) - switching to QEMU SSH boot', "vmware_mgr.vm_power_action(task.vm_id, 'stop')")
    assert 'if not _source_off_for_cutover' in fallback
    delta = _block('=== DELTA SYNC: DOWNTIME STARTS ===', "vmware_mgr.vm_power_action(task.vm_id, 'stop')")
    assert 'if _source_off_for_cutover' in delta


def test_stage_one_runs_while_the_source_still_serves():
    hold = RUN.index('task.await_cutover_confirmation(\n                    source_running=')
    assert RUN.rindex('_guest_prep_stage1(vmware_mgr, pve_mgr, task)', 0, hold) > RUN.rindex('Checksumming the copied disks', 0, hold)
    delta = RUN.index("task.set_phase('delta_sync')\n            task.log(\"=== DELTA SYNC: DOWNTIME STARTS ===\")")
    assert RUN.rindex('_guest_prep_stage1(vmware_mgr, pve_mgr, task)', 0, delta) > delta - 200


def test_a_cancel_or_a_failure_before_the_go_calls_the_waiting_guest_off():
    assert RUN.count('_guest_prep_abort(task)') >= 4
    for anchor in ('except V2PCutoverCancelled:\n', "except Exception as _vce:\n", 'except V2PCutoverCancelled as _cc:\n',
                   'except Exception as e:\n        _guest_prep_abort(task)'):
        at = RUN.index(anchor)
        assert '_guest_prep_abort(task)' in RUN[at:at + 400], anchor


def test_the_planning_order_keeps_every_check_before_anything_changes():
    plan = RUN.index('v2p_winprep.plan(pve_mgr, task, _fv_plan)')
    refusal = RUN.index('_pkg_refusal = _node_packages_refusal(pve_mgr, task)')
    probe = RUN.index('v2p_guestprep.probe(vmware_mgr, pve_mgr, task)')
    sshfs = RUN.index("_ensure_node_packages(pve_mgr, task, 'sshfs'")
    vmid = RUN.index('_tvmid.allocate(pve_mgr, task)')
    create = RUN.index("data=pve_config, timeout=120)")
    assert plan < refusal < probe < sshfs < vmid < create


def test_the_vm_is_made_for_virtio_only_where_the_drivers_will_be_there():
    create = RUN[RUN.index('scsihw = task.scsihw_override'):RUN.index('pve_config = {')]
    assert "_virtio_hw and task.scsihw_override in ('', 'auto', None)" in create
    assert "_virtio_hw and not nic_explicit" in create and 'task._nics_switched = True' in create
    assert "task._bus_switched = disk_bus != detected_bus" in create


def test_each_injection_is_followed_by_its_check_and_the_two_stage_boot_after_the_qcow2_move():
    injections = [m.start() for m in re.finditer(r'try: _inject_virtio_drivers\(pve_mgr, task\)', RUN)]
    assert len(injections) == 3
    for at in injections:
        assert '_after_injection(pve_mgr, task)' in RUN[at:at + 200]
    clone = _block('# must run while the VM is STILL stopped', "task.set_phase('cutover')")
    assert clone.index('_maybe_convert_disks_to_qcow2') < clone.index('_two_stage_on = _two_stage_stage(pve_mgr, task)')
    offline = _block('_maybe_convert_disks_to_qcow2(pve_mgr, task)\n\n            # MK Nov 2026', "task.set_phase('completed')")
    assert 'if _two_stage_stage(pve_mgr, task):' in offline
    assert 'if task.start_after or _two_stage_on:' in RUN
    auto = _block("_two_stage_on = _two_stage_stage(pve_mgr, task)\n        if _two_stage_on:", "task.set_phase('verify')")
    assert '_two_stage_boot(pve_mgr, task)' in auto


def test_live_mirror_restores_what_it_cannot_prepare():
    assert 'v2p_twostage.not_with_live_mirror(pve_mgr, task)' in MIRROR


def test_the_stop_paths_no_longer_refuse_to_power_the_source_on():
    # the first design kept a released source off; the owner wants it back on ESXi
    assert '_no_power_on' not in SRC and 'NO_POWER_ON' not in SRC
