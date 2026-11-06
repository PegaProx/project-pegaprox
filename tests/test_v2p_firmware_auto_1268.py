"""#1268 - firmware left on Auto gave an EFI source no efidisk0.

bios_override holds the string 'auto' by default, which is truthy, so it won over the firmware
the migration had detected. `bios` then was 'auto', the `if bios == 'ovmf'` blocks were skipped,
and the VM came up on OVMF with temporary efivars on every start.

Resolving it right also sends Auto through the blocks after a live pivot, where the VM keeps
running on the disk. So the fallback loader there may only look, and never mounts it writable.
"""
import ast
import inspect
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p


def _task(override, detected='ovmf'):
    task = SimpleNamespace(bios_override=override, proxmox_vmid=100, target_node='pve1', target_storage='local-lvm',
                           start_after=False, vm_name='web01', phases=[], log=lambda *a, **k: None)
    task.set_phase = lambda *a, **k: task.phases.append(a)
    if detected is not None:
        task._detected_bios = detected
    return task


def _offline_copy(monkeypatch, task):
    sent = []

    def node(mgr, node_name, cmd, timeout=None, **kw):
        sent.append(cmd)
        return 0, 'boot: order=scsi0\n' if cmd.startswith('qm config') else '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, '_setup_temp_ssh_key', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_qemu_img_ssh_copy', lambda *a, **k: True)
    monkeypatch.setattr(v2p, '_cleanup_sshfs', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_maybe_convert_disks_to_qcow2', lambda *a, **k: None)
    v2p._do_offline_qemuimg_copy(SimpleNamespace(), task, 'esxi', 'root', 'x', 'ds', 'dir', [], 'scsi', '/mnt/x')
    return sent


@pytest.mark.parametrize('override', ['auto', 'ovmf'])
def test_the_offline_copy_gives_an_efi_source_its_efidisk(monkeypatch, override):
    sent = _offline_copy(monkeypatch, _task(override))
    assert any('--efidisk0' in c for c in sent), sent
    assert any('--bios ovmf' in c for c in sent), sent


@pytest.mark.parametrize('override,detected', [('auto', 'seabios'), ('seabios', 'ovmf'), ('auto', None)])
def test_the_offline_copy_gives_no_efidisk_otherwise(monkeypatch, override, detected):
    """An explicit SeaBIOS wins over what was detected, and without a detection it stays SeaBIOS."""
    sent = _offline_copy(monkeypatch, _task(override, detected))
    assert not any('efidisk0' in c or '--bios' in c for c in sent), sent


@pytest.mark.parametrize('override,detected,want', [
    ('auto', 'ovmf', 'ovmf'), ('auto', 'seabios', 'seabios'), ('ovmf', 'seabios', 'ovmf'), ('seabios', 'ovmf', 'seabios'),
    (None, 'ovmf', 'ovmf'), ('', 'ovmf', 'ovmf'), ('auto', None, 'seabios'),
])
def test_what_each_override_resolves_to(override, detected, want):
    assert v2p._resolved_bios(_task(override, detected)) == want


@pytest.mark.parametrize('fn', [v2p._do_sshfs_boot_migration, v2p._do_offline_qemuimg_copy])
def test_both_paths_ask_the_same_question(fn):
    """The live mirror is too long to drive here, so this holds that it reads `bios` the same way."""
    tree = ast.parse(inspect.getsource(fn))
    values = [n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'bios' for t in n.targets)]
    assert len(values) == 1
    call = values[0]
    assert isinstance(call, ast.Call) and getattr(call.func, 'id', '') == '_resolved_bios'


def _fallback_script(monkeypatch, vol_path='/dev/vg/vm-100-disk-0', **kw):
    scripts, mapped = [], []
    logs = []

    def node(mgr, node_name, cmd, timeout=None, **k):
        return (0, vol_path, '') if cmd.startswith('pvesm path') else (0, 'fallback loader already in place', '')
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, '_write_node_script', lambda m, n, script, name: scripts.append(script) or '/tmp/x')
    monkeypatch.setattr(v2p, '_map_rbd_uri_to_device', lambda *a, **k: mapped.append(a) or None)
    task = _task('auto')
    task.boot_volume = lambda: 'store:vm-100-disk-0'
    task.log = logs.append
    v2p._register_uefi_fallback_loader(SimpleNamespace(), task, **kw)
    return scripts, mapped, logs


def test_a_stopped_vm_still_gets_the_fallback_loader_written(monkeypatch):
    scripts, _, _ = _fallback_script(monkeypatch)
    assert '-o rw' in scripts[0] and 'cp -f' in scripts[0], scripts[0]


def test_a_running_guest_has_its_boot_disk_only_looked_at(monkeypatch):
    scripts, _, logs = _fallback_script(monkeypatch, guest_running=True)
    script = scripts[0]
    assert 'losetup -r ' in script and '-o ro ' in script, script
    for writes in ('-o rw', 'cp -f', 'mkdir -p "$MNT/EFI/BOOT"'):
        assert writes not in script, writes
    assert not any('registering' in line for line in logs), logs


def test_a_running_guest_on_rbd_is_not_mapped_at_all(monkeypatch):
    scripts, mapped, logs = _fallback_script(monkeypatch, vol_path='rbd:pool/vm-100-disk-0:conf=/etc/pve/ceph.conf',
                                             guest_running=True)
    assert scripts == [] and mapped == [], (scripts, mapped)
    assert any('not checked' in line for line in logs), logs


def test_the_live_pivot_passes_that_the_guest_runs_and_the_restart_does_not():
    """Which call runs with the VM up is the order of the code: the restart path stops it first."""
    tree = ast.parse(inspect.getsource(v2p._do_sshfs_boot_migration))
    calls = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and getattr(n.func, 'id', '') == '_register_uefi_fallback_loader'), key=lambda n: n.lineno)
    assert [[(k.arg, k.value.value) for k in c.keywords] for c in calls] == [[('guest_running', True)], []]


def _offline_logs(monkeypatch, rc):
    logs = []
    task = _task('auto')
    task.log = logs.append

    def node(mgr, node_name, cmd, timeout=None, **kw):
        if '--efidisk0' in cmd:
            return rc, 'storage does not exist' if rc else '', ''
        return 0, 'boot: order=scsi0\n' if cmd.startswith('qm config') else '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, '_setup_temp_ssh_key', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_qemu_img_ssh_copy', lambda *a, **k: True)
    monkeypatch.setattr(v2p, '_cleanup_sshfs', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_maybe_convert_disks_to_qcow2', lambda *a, **k: None)
    v2p._do_offline_qemuimg_copy(SimpleNamespace(), task, 'esxi', 'root', 'x', 'ds', 'dir', [], 'scsi', '/mnt/x')
    return logs


def test_an_efidisk_that_failed_is_not_reported_as_allocated(monkeypatch):
    logs = _offline_logs(monkeypatch, 1)
    assert not any('EFI disk allocated' in line for line in logs), logs
    assert any('could not be allocated' in line and 'storage does not exist' in line for line in logs), logs


def test_an_efidisk_that_worked_says_so(monkeypatch):
    assert any('EFI disk allocated' in line for line in _offline_logs(monkeypatch, 0))


@pytest.mark.parametrize('pending,ostype,want', [({'pre_enrolled_keys': '1'}, 'l26', '1'), ({'pre_enrolled_keys': '0'}, 'l26', '0'),
                                                 (None, 'win11', '1'), (None, 'l26', '0'), ({}, 'l26', '0')])
def test_the_efi_keys_follow_what_was_decided_for_this_guest(pending, ostype, want):
    assert v2p._efidisk_pre_keys(SimpleNamespace(_pending_efidisk=pending, ostype=ostype)) == want


def test_the_live_pivot_asks_for_them():
    """The reporter's Secure Boot guest came up with pre-enrolled-keys=0 on this path."""
    tree = ast.parse(inspect.getsource(v2p._do_sshfs_boot_migration))
    assert [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, 'id', '') == '_efidisk_pre_keys']
