"""Two lines of a real ESXi migration's log that said the wrong thing.

The offline copy logged "HTTPS test OK but VM is offline - using direct SSH dd pipe" and
right after it "HTTPS test 0 bytes - skipping HTTPS full download": the switch to the dd
pipe had set the test result to 0 to get there. And on a node without network, whose
apt-get for sshfs gave no answer in time, the run failed with "the log above has the
apt-get output", where there was none.
"""
import pytest

import test_v2p_tpm_and_folder_copy as farm
from pegaprox.core import v2p


class _HttpsNode(farm.Node):
    """the 1 MB test download over HTTPS works"""

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'curl' in cmd and 'FSIZE' in cmd:
            self.log.append(('node', node, cmd))
            return 0, 'HTTP=206 DL=1048576 FSIZE=1048576', ''
        return super().__call__(mgr, node, cmd, timeout, **kw)


def test_the_switch_to_the_dd_pipe_is_not_followed_by_a_test_that_got_nothing(monkeypatch):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False, power='POWERED_OFF')
    monkeypatch.setattr(v2p, '_pve_node_exec', _HttpsNode(r.log, r.vols))
    r.go()
    assert r.task.status == 'completed', r.task.error
    log = '\n'.join(r.task.log_lines)
    assert 'HTTPS test OK but VM is offline - using direct SSH dd pipe' in log
    assert 'HTTPS test 0 bytes' not in log
    assert 'SSH dd pipe' in log


def test_a_test_that_got_nothing_still_says_so(monkeypatch):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False, power='POWERED_OFF').go()
    assert 'HTTPS test 0 bytes - skipping HTTPS full download' in '\n'.join(r.task.log_lines)


class _NoNetworkNode(farm.Node):
    """apt-get for sshfs gets no answer in time: the read of the node's answer is cut off"""

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'command -v sshfs' in cmd and 'echo PRESENT' in cmd and 'apt-get install' in cmd:
            self.log.append(('node', node, cmd))
            return 124, '', 'no output from the node within 240s, the answer is incomplete'
        return super().__call__(mgr, node, cmd, timeout, **kw)


def test_sshfs_that_could_not_be_installed_points_at_the_line_that_says_why(monkeypatch):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False)
    monkeypatch.setattr(v2p, '_pve_node_exec', _NoNetworkNode(r.log, r.vols))
    r.go()
    assert r.task.status == 'failed'
    assert 'the log above has the apt-get output' not in r.task.error
    assert r.task.error.startswith('sshfs is not installed on pve1 and could not be installed there')
    assert 'no VM was created on Proxmox VE' in r.task.error
    assert not [p for p in r.posts() if p[1].endswith('/qemu')], 'a VM was created'
    assert any('Could not check sshfs on pve1' in l and 'no output from the node within 240s' in l
               for l in r.task.log_lines)
