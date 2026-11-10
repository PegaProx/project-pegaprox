"""Every package the injection staged, and every one it did not find, reaches the migration log (#1247).

The node script prints one line per staged package, `MSI_STAGED <name>`, the driver bundle
and the guest agent. The log took only the first line of each marker, so the agent's line
was dropped. `GUEST_AGENT_MSI_MISSING` had no marker of its own and showed up only through
the substring `MSI_MISSING`, so it was lost whenever the driver bundle was missing too.

The injection runs against a node that answers every probe and prints the given script
output for the injection run itself.
"""
import types

import pytest

import pegaprox.core.v2p as v2p

HEAD = ['WIN_PART=/dev/loop0p3', 'WDIR=/mnt/w/Windows', 'VER_BUILD=26100', 'SUBDIR=2k25/amd64',
        'COPIED vioscsi (/iso/vioscsi/2k25/amd64)']
TAIL = ['SVC_REGISTERED', 'INJECTION_OK']
STAGED = 'MSI_STAGED virtio-win-gt-x64.msi'
AGENT_STAGED = 'MSI_STAGED qemu-ga-x86_64.msi'
MISSING = 'MSI_MISSING (skipping bulk install)'
AGENT_MISSING = 'GUEST_AGENT_MSI_MISSING (skipping the guest agent)'


def _inject(monkeypatch, lines):
    out = '\n'.join(HEAD + lines + TAIL) + '\n'

    def node_exec(mgr, node, cmd, timeout=30, **kw):
        if cmd.startswith('bash /tmp/inject.sh') or ' bash /tmp/inject.sh' in cmd:
            return 0, out, ''
        if 'pvesm path' in cmd:
            return 0, '/dev/pve/vm-120-disk-0\n', ''
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node_exec)
    monkeypatch.setattr(v2p, '_write_node_script', lambda *a, **k: '/tmp/inject.sh')
    monkeypatch.setattr(v2p, '_pve_storage_type', lambda *a, **k: 'lvmthin')
    lines_logged = []
    task = types.SimpleNamespace(
        install_virtio_drivers=True, target_node='pve1', proxmox_vmid=120,
        target_storage='local-lvm', virtio_iso_path=None, ostype='win11',
        log=lines_logged.append, boot_volume=lambda: 'local-lvm:vm-120-disk-0',
        result_warnings=[])
    mgr = types.SimpleNamespace(host='pve1', api_port=8006,
                                _api_get=lambda *a, **k: (_ for _ in ()).throw(OSError('down')))
    v2p._inject_virtio_drivers(mgr, task)
    assert any('INJECTION_OK' in line for line in lines_logged), lines_logged
    return [line.replace('[VirtIO] ', '') for line in lines_logged]


def test_both_staged_packages_are_in_the_log(monkeypatch):
    log = _inject(monkeypatch, [STAGED, AGENT_STAGED])
    assert STAGED in log and AGENT_STAGED in log, log


@pytest.mark.parametrize('lines', [[STAGED, AGENT_MISSING], [MISSING, AGENT_MISSING]],
                         ids=['bundle-staged', 'bundle-missing'])
def test_a_missing_agent_package_is_in_the_log_once(monkeypatch, lines):
    log = _inject(monkeypatch, lines)
    assert log.count(AGENT_MISSING) == 1, log
    assert lines[0] in log, log
