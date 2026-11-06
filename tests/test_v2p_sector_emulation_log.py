"""The log says whether the 512 byte emulation was set.

Without it a guest whose GPT was written for 512 byte sectors does not boot from a 4Kn LUN, and the line said applied whatever qm set
answered.
"""
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p


@pytest.mark.parametrize('rc,says,not_says', [(0, 'Applied 512b sector emulation', 'could not be set'),
                                              (2, 'could not be set', 'Applied 512b sector emulation')])
def test_what_qm_set_answered(monkeypatch, rc, says, not_says):
    def node(mgr, name, cmd, timeout=None, **kw):
        if cmd.startswith('pvesm path'):
            return 0, '/dev/vg/vm-100-disk-0', ''
        if cmd.startswith('lsblk'):
            return 0, '4096\n', ''
        return rc, 'vm is locked' if rc else '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    logs = []
    task = SimpleNamespace(target_node='pve1', proxmox_vmid=100, log=logs.append, boot_volume=lambda: 'store:vm-100-disk-0')
    v2p._ensure_guest_sector_size_512(SimpleNamespace(), task, 'scsi', 1)
    assert any(says in line for line in logs), logs
    assert not any(not_says in line for line in logs), logs


def test_a_512_byte_lun_sets_nothing(monkeypatch):
    sent = []

    def node(mgr, name, cmd, timeout=None, **kw):
        sent.append(cmd)
        return (0, '/dev/x', '') if cmd.startswith('pvesm') else (0, '512\n', '')
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    task = SimpleNamespace(target_node='pve1', proxmox_vmid=100, log=lambda m: None, boot_volume=lambda: 'store:d')
    v2p._ensure_guest_sector_size_512(SimpleNamespace(), task, 'scsi', 1)
    assert not any('--args' in c for c in sent)
