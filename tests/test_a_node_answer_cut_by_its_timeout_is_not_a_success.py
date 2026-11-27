"""A node command whose output read ran out of time is not a command that ended well.

Seen on a lab node without internet access: the package check of an ESXi migration ran
apt-get for sshfs, the read of its output gave up after 240 seconds, the script ended a
moment later with the exit code of its last echo (0), and the run logged "sshfs OK".
The copy then failed on "sshfs: command not found", after the VM on Proxmox VE was
created. Three places took part: read_capped swallowed the timeout, the SSH helpers read
the exit status after it as if nothing happened, and parse_ensure read an answer without
its verdict line by the exit code.
"""
import inspect
import socket
import time

import pytest

from pegaprox.utils import ssh as sshmod
from pegaprox.core import v2p
from pegaprox.core import v2p_packages as pk


class _Chan:
    def __init__(self, rc=0, ready_after=0):
        self.rc = rc
        self.asked = 0
        self.ready_after = ready_after
        self.timeouts = []

    def settimeout(self, t):
        self.timeouts.append(t)

    def exit_status_ready(self):
        self.asked += 1
        return self.asked > self.ready_after

    def recv_exit_status(self):
        return self.rc


class _File:
    """a channel file: hands out its blocks, then EOF, or raises once they are gone"""
    def __init__(self, chan, blocks, then=None):
        self.channel = chan
        self.blocks = list(blocks)
        self.then = then

    def read(self, n):
        if self.blocks:
            return self.blocks.pop(0)
        if self.then is not None:
            raise self.then
        return b''


def test_read_capped_says_when_a_read_failed():
    cut = []
    out = sshmod.read_capped(_File(_Chan(), [b'first lines\n'], then=socket.timeout()), cut=cut)
    assert out == 'first lines\n'
    assert len(cut) == 1 and isinstance(cut[0], socket.timeout)


def test_read_capped_to_eof_reports_nothing():
    cut = []
    assert sshmod.read_capped(_File(_Chan(), [b'all of it']), cut=cut) == 'all of it'
    assert cut == []


def test_a_stdout_read_that_timed_out_answers_124_even_with_exit_code_0():
    ch = _Chan(rc=0)
    out_f = _File(ch, [b'Reading package lists...\n'], then=socket.timeout())
    rc, out, err = sshmod._collect(out_f, _File(ch, []), 240)
    assert rc == 124
    assert 'Reading package lists' in out
    assert 'no output from the node within 240s' in err
    assert ch.asked == 0, 'the exit status of a cut answer must not be asked at all'


def test_an_answer_read_to_its_end_keeps_its_exit_code():
    ch = _Chan(rc=3)
    rc, out, err = sshmod._collect(_File(ch, [b'FAILED sshfs\n']), _File(ch, [b'E: no network\n']), 30)
    assert (rc, out, err) == (3, 'FAILED sshfs\n', 'E: no network\n')


def test_a_chatty_command_past_the_deadline_still_gets_its_exit_status():
    # stdout took the whole deadline (output kept coming), the exit status lands a moment
    # after the last byte: that is a finished command, not a timeout
    ch = _Chan(rc=0, ready_after=2)
    rc, out, _err = sshmod._collect(_File(ch, [b'50%\n', b'100%\n']), _File(ch, []), 10,
                                    deadline=time.monotonic() - 1)
    assert rc == 0 and out == '50%\n100%\n'
    assert ch.timeouts and ch.timeouts[0] >= sshmod._SSH_TAIL_GRACE


def test_both_ssh_paths_read_through_collect():
    for fn in (sshmod._ssh_exec, sshmod._run_on_client):
        src = inspect.getsource(fn)
        assert '_collect(stdout, stderr, timeout' in src, fn.__name__
        assert 'recv_exit_status()' not in src, fn.__name__


@pytest.mark.parametrize('rc,out', [(0, ''), (0, 'Reading package lists...\n'), (124, '')])
def test_an_ensure_answer_without_its_verdict_is_unknown(rc, out):
    verdict, named, said = pk.parse_ensure(rc, out, ['sshfs'])
    assert verdict == 'UNKNOWN'
    assert named == ['sshfs']
    assert said


@pytest.mark.parametrize('out,verdict', [
    ('PRESENT\n', 'PRESENT'),
    ('apt output\nINSTALLED sshfs\n', 'INSTALLED'),
    ('E: Unable to locate package sshfs\nFAILED sshfs\n', 'FAILED'),
    ('MISSING sshfs\n', 'MISSING'),
])
def test_an_ensure_answer_with_its_verdict_reads_as_before(out, verdict):
    assert pk.parse_ensure(0, out, ['sshfs'])[0] == verdict


class _Task:
    def __init__(self):
        self.config = {}
        self.target_node = 'pve3'
        self.lines = []

    def log(self, line):
        self.lines.append(line)


def test_sshfs_cut_off_by_the_timeout_is_not_ok_and_the_log_says_why(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda *a, **k: (
        124, '', 'no output from the node within 240s, the answer is incomplete'))
    task = _Task()
    ok, missing = v2p._ensure_node_packages(object(), task, 'sshfs')
    assert ok is False and missing == ['sshfs']
    assert any('Could not check sshfs on pve3' in l and 'no output from the node within 240s' in l
               for l in task.lines), task.lines


def test_a_lost_answer_with_exit_code_0_is_not_ok(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda *a, **k: (0, '', ''))
    ok, missing = v2p._ensure_node_packages(object(), _Task(), 'sshfs')
    assert ok is False and missing == ['sshfs']
