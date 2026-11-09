"""A live mirror whose job ended before anything completed it fails instead of reporting done.

The polling loop counted a drive-mirror job that was gone from HMP `info block-jobs` as ready,
unless the last lines of the QEMU log said "error". A mirror job ends only by complete, cancel
or an error, and nothing completes one before the pivot, so a gone job is a failed copy. With
one disk the loop then reported every pivot as done, and the migration pointed the guest's
config at the unfinished copy and unmounted its source.

The monitor answers in QEMU's HMP wording; every `qm monitor` over SSH costs a second.
"""
import time

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
    """The guest's monitor. `jobs` maps a drive to the second its job ends on its own (None:
    it runs until complete or cancel); every job sits at 100% and takes complete."""

    def __init__(self, clock, jobs, log='', garbled=None):
        self.clock = clock
        self.start = clock.now
        self.ends = dict(jobs)
        self.done = set()
        self.log = log
        self.garbled = garbled              # (from, to) seconds in which qm monitor prints an error
        self.cmds = []

    def _listed(self):
        return [d for d, end in self.ends.items()
                if d not in self.done and (end is None or self.clock.now < self.start + end)]

    def hmp(self, cmd):
        self.cmds.append(cmd)
        verb, _, arg = cmd.partition(' ')
        if cmd == 'info block-jobs':
            if self.garbled and self.garbled[0] <= self.clock.now - self.start < self.garbled[1]:
                return "ERROR: VM 120 qmp command 'human-monitor-command' failed - got timeout"
            jobs = self._listed()
            if not jobs:
                return 'No active jobs'
            return '\n'.join(f"Type mirror, device {d}: Completed {32 * GiB} of {32 * GiB} bytes, "
                             f"speed limit 0 bytes/s" for d in jobs)
        if verb in ('block_job_complete', 'block_job_cancel'):
            if arg not in self._listed():
                return f"Error: Block job '{arg}' not found"
            self.done.add(arg)
        return ''

    def node_exec(self, mgr, node, cmd, timeout=30, **kw):
        self.clock.sleep(1)                 # the SSH round trip
        if not cmd.endswith(f'| qm monitor {VMID} 2>&1'):
            return 0, self.log, ''          # the tail of the QEMU log
        hmp = v2p.shlex.split(cmd.split('|')[0])[1]
        return 0, f"qm> {hmp}\n{self.hmp(hmp)}\n", ''

    def sent(self, verb):
        return [c for c in self.cmds if c.split(' ')[0] == verb]


class Task:
    def __init__(self):
        self.lines = []

    def log(self, msg):
        self.lines.append(msg)

    def update_progress(self, *a):
        pass


def _poll(monkeypatch, jobs, log='', **kw):
    clock = Clock()
    q = Qemu(clock, jobs, log, **kw)
    monkeypatch.setattr(time, 'sleep', clock.sleep)
    monkeypatch.setattr(time, 'time', clock.time)
    monkeypatch.setattr(time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(v2p, '_pve_node_exec', q.node_exec)
    task = Task()
    mirrors = [(d, 32 * GiB, i) for i, d in enumerate(jobs)]
    ok = v2p._poll_drive_mirrors(object(), task, 'pve1', VMID, mirrors, timeout=600)
    return ok, q, task


def test_the_only_mirror_job_ending_on_its_own_fails_the_mirror(monkeypatch):
    ok, q, task = _poll(monkeypatch, {'drive-scsi0': 30})
    assert ok is False, task.lines
    assert q.sent('block_job_complete') == []
    assert q.sent('stop') == []
    assert not any('pivots complete' in line for line in task.lines), task.lines
    assert any('drive-scsi0' in line and 'ended without a pivot' in line for line in task.lines), task.lines


def test_a_mirror_job_ending_next_to_a_running_one_fails_the_mirror(monkeypatch):
    ok, q, task = _poll(monkeypatch, {'drive-scsi0': None, 'drive-scsi1': 30})
    assert ok is False, task.lines
    assert q.sent('stop') == []
    assert any('drive-scsi1' in line and 'ended without a pivot' in line for line in task.lines), task.lines


def test_the_qemu_log_of_a_gone_job_is_in_the_task_log(monkeypatch):
    msg = 'mirror job drive-scsi0: Input/output error'
    ok, q, task = _poll(monkeypatch, {'drive-scsi0': 30}, log=msg)
    assert ok is False
    assert any(msg in line for line in task.lines), task.lines


def test_a_mirror_job_still_running_reaches_the_pivot(monkeypatch):
    ok, q, task = _poll(monkeypatch, {'drive-scsi0': None, 'drive-scsi1': None})
    assert ok is True, task.lines
    assert sorted(q.sent('block_job_complete')) == ['block_job_complete drive-scsi0',
                                                     'block_job_complete drive-scsi1']


def test_an_error_text_in_place_of_the_job_list_is_no_news(monkeypatch):
    """A monitor that timed out for a few polls does not end a mirror that is still running."""
    ok, q, task = _poll(monkeypatch, {'drive-scsi0': None}, garbled=(20, 26))
    assert ok is True, task.lines
    assert not any('ended without a pivot' in line for line in task.lines), task.lines
