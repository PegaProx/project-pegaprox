"""A drive-mirror that answers late is a running mirror, not a failed one.

Live Mirror starts one drive_mirror per disk over `qm monitor`, 30 seconds each. A lab node
under load (a Windows guest booting from SSHFS) answered the second one after the 30 seconds
while the job ran. The run took it for a failure and retried without -f, which met the job's
own filter node ("Error: Need a root block node"), called the disk failed and cancelled every
mirror, falling back to a background copy. What runs is asked before a retry and after a
failure now.

MK Nov 2026
"""
import time

import pytest

import pegaprox.core.v2p as v2p

DRIVE = 'sshfs-disk1'


class Task:
    def __init__(self):
        self.log_lines = []

    def log(self, msg):
        self.log_lines.append(msg)


class Monitor:
    """qm monitor of one VM: `late` starts the job and gives no answer in time, `refuse` gives
    an error and starts nothing, `retry_says` is what the retry without -f answers"""

    def __init__(self, first, retry_says='', job_after_retry=False, other_job=None, silent=0):
        self.first, self.retry_says, self.job_after_retry = first, retry_says, job_after_retry
        self.jobs = [other_job] if other_job else []
        self.sent = []
        self.silent = silent   # how many `info block-jobs` get qm's timeout text instead of a reply

    def __call__(self, pve_mgr, node, vmid, command, timeout=15):
        self.sent.append(command)
        if command == 'info block':
            return True, f'sshfs-disk0 (#block101): /tmp/x0 (raw)\n{DRIVE} (#block102): /tmp/x1 (raw)\n'
        if command == 'info block-jobs':
            if self.silent:
                self.silent -= 1
                return True, "ERROR: VM 123 qmp command 'human-monitor-command' failed - got timeout"
            return True, '\n'.join(f'Type mirror, device {d}: Completed 0 of 4294967296 bytes, speed limit 0 bytes/s'
                                   for d in self.jobs) or 'No active jobs'
        if command.startswith('drive_mirror -n -f'):
            if self.first == 'late':
                self.jobs.append(DRIVE)
                return False, 'no output within 30s'
            return False, 'qm monitor exit=255: VM 123 qmp command failed - timeout'
        if command.startswith('drive_mirror -n '):
            if self.job_after_retry:
                self.jobs.append(DRIVE)
            return True, self.retry_says
        return True, ''


@pytest.fixture(autouse=True)
def no_waits(monkeypatch):
    monkeypatch.setattr(time, 'sleep', lambda s: None)


def _start(monkeypatch, mon):
    monkeypatch.setattr(v2p, '_qm_monitor_cmd', mon)
    task = Task()
    return v2p._drive_mirror_to_local(None, task, 'pve2', 123, DRIVE, '/dev/pve/vm-123-disk-3', 4 << 30), task


def test_a_mirror_that_answers_late_runs_and_is_not_started_twice(monkeypatch):
    mon = Monitor('late', retry_says='Error: Need a root block node')
    ok, task = _start(monkeypatch, mon)
    assert ok is True, task.log_lines
    assert not any(c.startswith('drive_mirror -n sshfs') for c in mon.sent), mon.sent
    assert any('answered late' in ln and 'the job runs' in ln for ln in task.log_lines)


def test_a_retry_that_errs_while_the_job_runs_counts_the_job(monkeypatch):
    mon = Monitor('refuse', retry_says='Error: Need a root block node', job_after_retry=True)
    ok, task = _start(monkeypatch, mon)
    assert ok is True, task.log_lines


def test_a_mirror_that_never_started_is_still_a_failure(monkeypatch):
    mon = Monitor('refuse', retry_says='Error: Need a root block node')
    ok, task = _start(monkeypatch, mon)
    assert ok is False
    assert any('drive-mirror error: Error: Need a root block node' in ln for ln in task.log_lines)


def test_the_job_of_another_disk_is_not_taken_for_this_one(monkeypatch):
    # sshfs-disk10 runs, sshfs-disk1 does not
    mon = Monitor('refuse', retry_says='Error: Need a root block node', other_job='sshfs-disk10')
    ok, _task = _start(monkeypatch, mon)
    assert ok is False


def test_a_qm_timeout_on_the_job_list_is_no_answer_and_is_asked_again(monkeypatch):
    # qm prints its own timeout and exits 0: that is no "no job", the next reply decides
    mon = Monitor('late', retry_says='Error: Need a root block node', silent=2)
    ok, task = _start(monkeypatch, mon)
    assert ok is True, task.log_lines
    assert [c for c in mon.sent if c.startswith('drive_mirror')] == ['drive_mirror -n -f sshfs-disk1 /dev/pve/vm-123-disk-3 raw']


def test_without_any_reply_of_qemu_nothing_is_retried_and_the_disk_is_not_mirrored(monkeypatch):
    mon = Monitor('late', silent=10 ** 6)
    ok, task = _start(monkeypatch, mon)
    assert ok is False
    assert [c for c in mon.sent if c.startswith('drive_mirror')] == ['drive_mirror -n -f sshfs-disk1 /dev/pve/vm-123-disk-3 raw']
    assert any('QEMU did not answer' in ln for ln in task.log_lines)


def test_live_mirror_cancels_the_job_of_a_disk_whose_start_it_took_for_failed(monkeypatch):
    # a drive_mirror answered too late may start its job after the checks: the disk is
    # cancelled like the started ones, or that job writes next to the fallback copy
    import test_v2p_tpm_and_folder_copy as farm
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')
    cancelled = []
    monkeypatch.setattr(v2p, '_drive_mirror_to_local', lambda *a, **k: False)
    monkeypatch.setattr(v2p, '_qm_block_job',
                        lambda pve, node, vmid, action, drive_id, **k: cancelled.append((action, drive_id)) or (True, ''))
    r.go()
    assert ('cancel', 'sshfs-disk0') in cancelled, cancelled
