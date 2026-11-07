"""The log says whether the 512 byte emulation was set.

Without it a guest whose GPT was written for 512 byte sectors does not boot from a 4Kn LUN, and the line said applied whatever qm set
answered.
"""
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p


def _set_args(monkeypatch, answer):
    """A 4Kn LUN, and `answer` as the (rc, out, err) of the qm set --args call."""
    def node(mgr, name, cmd, timeout=None, **kw):
        if cmd.startswith('pvesm path'):
            return 0, '/dev/vg/vm-100-disk-0', ''
        if cmd.startswith('lsblk'):
            return 0, '4096\n', ''
        return answer
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    logs = []
    task = SimpleNamespace(target_node='pve1', proxmox_vmid=100, log=logs.append, boot_volume=lambda: 'store:vm-100-disk-0')
    v2p._ensure_guest_sector_size_512(SimpleNamespace(), task, 'scsi', 1)
    return logs


@pytest.mark.parametrize('rc,says,not_says', [(0, 'Applied 512b sector emulation', 'could not be set'),
                                              (2, 'could not be set', 'Applied 512b sector emulation')])
def test_what_qm_set_answered(monkeypatch, rc, says, not_says):
    logs = _set_args(monkeypatch, (rc, 'vm is locked' if rc else '', ''))
    assert any(says in line for line in logs), logs
    assert not any(not_says in line for line in logs), logs


def test_the_failure_line_carries_what_qm_said(monkeypatch):
    logs = _set_args(monkeypatch, (2, 'x' * 500 + "\ntrying to acquire lock...\ncan't lock file - vm is locked\n", ''))
    line = next(line for line in logs if 'could not be set' in line)
    reason = line.split('from this LUN: ', 1)[1]
    assert reason.endswith('vm is locked') and len(reason) <= 200, line


def test_a_call_refused_before_qm_ran_says_why(monkeypatch):
    """The node call itself was refused, so there is no qm output and the reason sits in the error slot."""
    logs = _set_args(monkeypatch, (1, '', "node 'pve1' in circuit-breaker backoff (20s remaining)"))
    line = next(line for line in logs if 'could not be set' in line)
    assert line.endswith("node 'pve1' in circuit-breaker backoff (20s remaining)"), line


def test_the_args_rebuild_says_why_a_refused_call_failed(monkeypatch):
    def node(mgr, name, cmd, timeout=None, **kw):
        if cmd.startswith('cat /etc/pve/qemu-server/'):
            return 0, 'scsi0: store:vm-100-disk-0,size=32G\nargs: -set device.sata0.logical_block_size=512\n', ''
        return 1, '', "cannot run node commands on 'pve1': no SSH password is stored for this cluster"
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    changed, args, error = v2p._rebuild_sector_args(SimpleNamespace(), 'pve1', 100)
    assert changed is False and 'scsi0.logical_block_size=512' in args
    assert error == "qm set failed: cannot run node commands on 'pve1': no SSH password is stored for this cluster"


def test_a_512_byte_lun_sets_nothing(monkeypatch):
    sent = []

    def node(mgr, name, cmd, timeout=None, **kw):
        sent.append(cmd)
        return (0, '/dev/x', '') if cmd.startswith('pvesm') else (0, '512\n', '')
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    task = SimpleNamespace(target_node='pve1', proxmox_vmid=100, log=lambda m: None, boot_volume=lambda: 'store:d')
    v2p._ensure_guest_sector_size_512(SimpleNamespace(), task, 'scsi', 1)
    assert not any('--args' in c for c in sent)
