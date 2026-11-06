"""#1268 - firmware left on Auto gave an EFI source no efidisk0.

bios_override holds the string 'auto' by default, which is truthy, so it won over the firmware
the migration had detected. `bios` then was 'auto', the `if bios == 'ovmf'` blocks were skipped,
and the VM came up on OVMF with temporary efivars on every start.
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
