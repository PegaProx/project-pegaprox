"""Final disk settings through the real coordinator with fixture ESXi/PVE adapters."""
import re
import shlex
import pytest
import pegaprox.core.v2p as v2p
from test_v2p_tpm_and_folder_copy import Run, VMID


@pytest.mark.parametrize('mode', ['offline', 'vmkfstools_clone', 'auto', 'snapshot_zero', 'sshfs_boot'])
@pytest.mark.parametrize('bus,controller,enabled', [('', 'virtio-scsi-single', True), ('scsi', 'virtio-scsi-single', True), ('scsi', 'virtio-scsi-pci', False), ('scsi', 'pvscsi', False), ('virtio', 'pvscsi', True), ('sata', 'virtio-scsi-single', False), ('ide', 'virtio-scsi-single', False)])
@pytest.mark.parametrize('iothread', [True, False])
def test_final_disk_options_use_resolved_controller(monkeypatch, mode, bus, controller, enabled, iothread):
    """Each mode attaches two disks with compatible settings after Auto detection."""
    if mode == 'snapshot_zero':
        monkeypatch.setattr(v2p, '_snapshot_zero_v2p_delta_loop', lambda *a, **k: (True, 1, []))
    run = Run(monkeypatch, mode=mode, ssh_key='/tmp/v2p-key-fixed', config={'disk_bus': bus, 'scsihw': 'auto', 'disk_cache': 'writeback', 'disk_iothread': iothread, 'aio_mode': 'threads'})
    get_vm = run.esxi.get_vm

    def source_vm(vm_id):
        """Supply detected controller data to the actual migration coordinator."""
        result = get_vm(vm_id)
        result['data']['hardware']['scsi_controller_pve'] = controller
        return result

    monkeypatch.setattr(run.esxi, 'get_vm', source_vm)
    run.go()
    assert run.task.status == 'completed', run.task.error
    disks = [cmd for cmd in run.nodecmds() if re.match(rf'qm set {VMID} --{bus or "scsi"}\d+ ', cmd)]
    assert len(disks) >= 2, run.nodecmds()
    for cmd in disks:
        assert ',cache=writeback' in cmd, cmd
        assert (',iothread=1' in cmd) is (iothread and enabled), cmd
        assert ',aio=threads' in cmd and ',discard=on' in cmd, cmd
    assert run.vols[f'local-lvm:vm-{VMID}-disk-0'] == 'tpm'


@pytest.mark.parametrize('cache', ['none', 'directsync', 'writethrough', 'writeback', 'unsafe'])
@pytest.mark.parametrize('aio', ['', 'threads', 'native', 'io_uring'])
def test_cache_aio_compatibility_through_final_attachments(monkeypatch, cache, aio):
    """Native AIO needs direct I/O; other backends preserve the selected cache."""
    run = Run(monkeypatch, config={'disk_cache': cache, 'aio_mode': aio, 'scsihw': 'virtio-scsi-single'}).go()
    assert run.task.status == 'completed', run.task.error
    expected = 'threads' if aio == 'native' and cache in ('writethrough', 'writeback', 'unsafe') else aio
    for cmd in run.nodecmds():
        if re.match(rf'qm set {VMID} --scsi\d+ ', cmd):
            assert f',cache={cache}' in cmd and ',iothread=1' in cmd, cmd
            assert (f',aio={expected}' in cmd) if expected else ',aio=' not in cmd


@pytest.mark.parametrize('bus', ['', 'virtio'])
def test_live_pivot_persists_cache_thread_options(monkeypatch, bus):
    """Persist next-boot settings without changing temporary drives or restarting."""
    monkeypatch.setattr(v2p, '_drive_mirror_to_local', lambda *a, **k: True)
    monkeypatch.setattr(v2p, '_poll_drive_mirrors', lambda *a, **k: True)
    run = Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed', config={'disk_bus': bus, 'scsihw': 'virtio-scsi-single', 'disk_cache': 'directsync', 'aio_mode': 'native'}).go()
    assert run.task.status == 'completed', run.task.error
    lines = [shlex.split(cmd)[1] for cmd in run.nodecmds() if cmd.startswith(f"echo '{bus or 'scsi'}") and ' >> /etc/pve/' in cmd]
    assert len(lines) == 2, lines
    assert all(',cache=directsync' in line and ',iothread=1' in line and ',aio=native' in line for line in lines)
    temporary = [shlex.split(cmd)[1] for cmd in run.nodecmds() if cmd.startswith("echo 'args:")]
    assert temporary and all('iothread=' not in line and 'cache=directsync' not in line for line in temporary)
    assert len([post for post in run.posts() if post[1].endswith('/status/start')]) == 1


@pytest.mark.parametrize('cache,iothread', [('writeback;touch /tmp/no', 'true'), (None, 1), (['none'], {})])
def test_malformed_options_never_enter_shell_suffix(cache, iothread):
    """Malformed API values cannot add options to root node shell commands."""
    task = v2p.V2PMigrationTask('t', 'vw', 'vm', 'pve', 'node', 'local', config={'disk_cache': cache, 'disk_iothread': iothread})
    suffix = task._disk_attach_opts('virtio')
    assert 'cache=' not in suffix and 'iothread=' not in suffix
