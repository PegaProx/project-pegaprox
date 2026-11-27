"""Lines of a real ESXi migration's log that said the wrong thing, and the copy behind one.

The offline copy logged "HTTPS test OK but VM is offline - using direct SSH dd pipe" and
right after it "HTTPS test 0 bytes - skipping HTTPS full download": the switch to the dd
pipe had set the test result to 0 to get there. And on a node without network, whose
apt-get for sshfs gave no answer in time, the run failed with "the log above has the
apt-get output", where there was none.

The Live Clone logged the same "VM is offline" while the source ran: the copy read the
source's power state through a manager reference nothing ever set, so every source counted
as off. Behind it, a disk the pipe could not read (a running VM without a snapshot holds
it locked) never went back to the HTTPS download that had just read it. And dd's progress
line, rewritten with carriage returns, came into the log as a run cut mid-number.
"""
import re

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
    assert 'HTTPS test OK - copying over the SSH dd pipe (faster)' in log
    assert 'VM is offline' not in log
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


class _LockedNode(_HttpsNode):
    """the HTTPS test reads the file, the SSH pipe cannot open it (locked by the running VM),
    the HTTPS download copies it"""

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'sshpass -f ' in cmd and '| dd of=' in cmd:
            self.log.append(('node', node, cmd))
            return (0, 'PIPE=1/0\n0+0 records in\n0+0 records out\n0 bytes copied, 0.01 s, 0 kB/s\n',
                    "dd: can't open '/vmfs/volumes/ds1/app01/app01-flat.vmdk': Device or resource busy")
        if cmd.startswith('curl -sk') and '| dd of=' in cmd:
            self.log.append(('node', node, cmd))
            flat = re.search(r"/([^/?']+-flat\.vmdk)\?", cmd).group(1)
            dst = re.search(r"\| dd of=(\S+)", cmd).group(1).strip("'\"")
            self.copied_from[dst] = flat
            return 0, f'RC=0/0\n{farm.FLATS.get(flat, farm.GiB)} bytes (1 GB) copied, 9 s, 100 MB/s\n', ''
        return super().__call__(mgr, node, cmd, timeout, **kw)


def test_a_file_the_pipe_cannot_read_comes_over_https(monkeypatch):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False, power='POWERED_OFF')
    node = _LockedNode(r.log, r.vols)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    r.go()
    assert r.task.status == 'completed', r.task.error
    log = '\n'.join(r.task.log_lines)
    assert 'The SSH pipe could not read the whole file' in log
    assert 'HTTPS OK:' in log
    assert 'ALL methods failed' not in log
    cmds = [c for e in r.log if e[0] == 'node' for c in [e[-1]] if '| dd of=' in c]
    assert [('ssh' if 'sshpass' in c else 'https') for c in cmds] == ['ssh', 'https'], cmds


def test_a_pipe_that_read_the_file_is_not_followed_by_https(monkeypatch):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False, power='POWERED_OFF')
    monkeypatch.setattr(v2p, '_pve_node_exec', _HttpsNode(r.log, r.vols))
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert not [c for e in r.log if e[0] == 'node' for c in [e[-1]] if c.startswith('curl -sk') and '| dd of=' in c]


def test_the_copy_does_not_ask_a_manager_reference_nothing_sets():
    import inspect
    assert '_vmware_mgr_ref' not in inspect.getsource(v2p._ssh_pipe_transfer)


def test_the_dd_progress_line_comes_into_the_log_as_it_ended():
    out = ('PIPE=0/0\n\r1048576 bytes (1.0 MB, 1.0 MiB) copied, 1 s, 1 MB/s'
           '\r42812686336 bytes (43 GB, 40 GiB) copied, 622 s, 68.8 MB/s\n'
           '0+736453 records in\n0+736453 records out\n'
           '42949672960 bytes (43 GB, 40 GiB) copied, 634.248 s, 67.7 MB/s\n')
    tail = v2p._dd_tail(out)
    assert '\r' not in tail
    assert tail.split(' | ') == ['42812686336 bytes (43 GB, 40 GiB) copied, 622 s, 68.8 MB/s',
                                 '0+736453 records in', '0+736453 records out',
                                 '42949672960 bytes (43 GB, 40 GiB) copied, 634.248 s, 67.7 MB/s']
