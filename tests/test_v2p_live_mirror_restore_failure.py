"""Live Mirror that cannot give the VM the source's controller and NICs back says so in the result.

Live Mirror boots the guest before drivers could be staged, so a guest not prepared in ESXi
keeps the disk controller and the NIC model of the source. When putting them back failed, the
run logged one line and ended COMPLETED without a warning, with a guest that may not boot on
the VirtIO devices it was left with.
"""
import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_twostage as ts

import test_v2p_tpm_and_folder_copy as farm


def test_a_controller_that_could_not_be_put_back_is_a_warning(monkeypatch):
    def refuse(pve, task):
        raise RuntimeError('qm set --scsihw pvscsi: VM is locked (create)')
    monkeypatch.setattr(ts, 'not_with_live_mirror', refuse)
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'completed', r.task.error
    assert any('could not give VM 120 the disk controller and NICs of the source' in w
               and 'VM is locked (create)' in w for w in r.task.warnings), r.task.warnings


def test_a_controller_put_back_is_no_warning(monkeypatch):
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'completed', r.task.error
    assert not any('disk controller and NICs of the source' in w for w in r.task.warnings), r.task.warnings
