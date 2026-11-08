"""The guest of a live mirror is paused only until QEMU takes the pivot (#1250).

The pause waited for the word "ready" in HMP `info block-jobs`. QEMU never prints it there
(only "Type mirror, device <id>: Completed <n> of <len> bytes, speed limit <n> bytes/s"), so
every pivot sat out the whole 10 s window with the guest stopped, plus fixed sleeps, about
24 s with the SSH round trips. QEMU refuses complete on a job that is not ready, so the pause
now asks it until it takes it and resumes the guest once the jobs are gone. A job that is gone
before QEMU took its pivot ended without one, and that fails the pivot.

The monitor below answers in QEMU's HMP wording (block/monitor/block-hmp-cmds.c, job.c,
blockdev.c, hmp_handle_error); every `qm monitor` over SSH costs a second.
"""
import time

import pytest

import pegaprox.core.v2p as v2p

VMID = 120
GiB = 1024 ** 3


class Clock:
    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, s):
        self.now += s


class Qemu:
    """The monitor of the running guest. A job takes complete from `ready_at` on (None:
    never) and is gone 0.3 s after it took it."""

    def __init__(self, clock, ready_at, ended=(), dies=()):
        self.clock = clock
        self.jobs = {d: {'len': 32 * GiB, 'ready_at': r, 'gone_at': None}
                     for d, r in ready_at.items() if d not in ended}
        self.dies = dies
        self.cmds = []
        self.stopped_at = self.resumed_at = None

    def _ready(self, j):
        return j['ready_at'] is not None and self.clock.now >= self.stopped_at + j['ready_at']

    def _listed(self):
        return {d: j for d, j in self.jobs.items() if j['gone_at'] is None or self.clock.now < j['gone_at']}

    def hmp(self, cmd):
        self.cmds.append((self.clock.now, cmd))
        verb, _, arg = cmd.partition(' ')
        if cmd == 'info block-jobs':
            jobs = self._listed()
            if not jobs:
                return 'No active jobs'
            return '\n'.join(f"Type mirror, device {d}: Completed {j['len']} of {j['len']} bytes, "
                             f"speed limit 0 bytes/s" for d, j in jobs.items())
        if cmd == 'stop':
            self.stopped_at = self.clock.now
            for d in self.dies:             # an I/O error ends the job without a pivot
                self.jobs[d]['gone_at'] = self.clock.now
            return ''
        if cmd == 'cont':
            self.resumed_at = self.clock.now
            return ''
        if verb == 'block_job_complete':
            j = self._listed().get(arg)
            if j is None:
                return f"Error: Block job '{arg}' not found"
            if not self._ready(j):
                return f"Error: Job '{arg}' in state 'running' cannot accept command verb 'complete'"
            j['gone_at'] = self.clock.now + 0.3
            return ''
        return ''

    def node_exec(self, mgr, node, cmd, timeout=30, **kw):
        self.clock.sleep(1)                 # the SSH round trip
        if not cmd.endswith(f'| qm monitor {VMID} 2>&1'):
            return 0, '', ''                # the QEMU log tail of a job that is gone
        hmp = v2p.shlex.split(cmd.split('|')[0])[1]
        return 0, f'qm> {hmp}\nqm> Entering QEMU Monitor for VM {VMID} - type \'help\' for help\n' \
                  f'{self.hmp(hmp)}\n', ''

    def completes(self):
        return [c for _, c in self.cmds if 'complete' in c]

    @property
    def paused(self):
        return self.resumed_at - self.stopped_at


class Task:
    def __init__(self):
        self.lines = []
        self.progress = {}

    def log(self, msg):
        self.lines.append(msg)

    def update_progress(self, key, done, total):
        self.progress[key] = (done, total)


def _pivot(monkeypatch, ready_at, **kw):
    clock = Clock()
    q = Qemu(clock, ready_at, **kw)
    monkeypatch.setattr(time, 'sleep', clock.sleep)
    monkeypatch.setattr(time, 'time', clock.time)
    monkeypatch.setattr(time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(v2p, '_pve_node_exec', q.node_exec)
    task = Task()
    mirrors = [(d, 32 * GiB, i) for i, d in enumerate(ready_at)]
    ok = v2p._poll_drive_mirrors(object(), task, 'pve1', VMID, mirrors, timeout=600)
    assert q.stopped_at is not None, task.lines
    return ok, q, task


def test_a_ready_mirror_pivots_within_a_few_seconds_of_pause(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 0})
    assert ok is True, task.lines
    # complete, one look at the jobs, cont: a round trip each
    assert q.paused <= 3, (q.paused, q.cmds)
    assert 'drive-scsi0' not in q._listed()


def test_two_disks_pivot_in_the_same_pause(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 0, 'drive-scsi1': 0})
    assert ok is True, task.lines
    assert q.paused <= 4, (q.paused, q.cmds)
    assert sorted(q.completes()) == ['block_job_complete drive-scsi0', 'block_job_complete drive-scsi1']


def test_a_mirror_that_needs_a_moment_is_asked_again_until_qemu_takes_it(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 3})
    assert ok is True, task.lines
    assert len(q.completes()) >= 2           # refused first, then taken
    assert q.paused <= 7, (q.paused, q.cmds)


def test_a_mirror_qemu_never_takes_resumes_the_guest_and_fails(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': None})
    assert ok is False
    assert [c for _, c in q.cmds].count('cont') == 1
    assert q.paused <= 13, (q.paused, q.cmds)
    assert not any(t > q.resumed_at and 'complete' in c for t, c in q.cmds)
    assert any("cannot accept command verb 'complete'" in line for line in task.lines), task.lines


def test_a_refused_pivot_is_not_reported_as_done(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 0, 'drive-scsi1': None})
    assert ok is False
    assert not any('Pause-pivot-resume complete' in line for line in task.lines)


def test_the_log_says_how_long_the_guest_was_paused(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 0})
    assert ok is True
    done = [line for line in task.lines if 'Pause-pivot-resume complete' in line]
    assert done and f'guest paused {q.paused:.1f}s' in done[0], (done, q.paused)


def test_a_job_that_ended_before_the_pause_gets_no_pivot(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 0, 'drive-scsi1': 0}, ended=('drive-scsi1',))
    assert ok is True, task.lines
    assert q.completes() == ['block_job_complete drive-scsi0']


def test_a_job_gone_without_its_pivot_fails_the_pivot(monkeypatch):
    ok, q, task = _pivot(monkeypatch, {'drive-scsi0': 0, 'drive-scsi1': 0}, dies=('drive-scsi1',))
    assert ok is False
    assert [c for _, c in q.cmds].count('cont') == 1
    assert any('drive-scsi1: the mirror job ended without a pivot' in line for line in task.lines), task.lines
    assert not any('Pause-pivot-resume complete' in line for line in task.lines)
