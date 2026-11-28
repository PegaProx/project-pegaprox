"""The downtime of Live Mirror runs until the guest is up, not until its VM starts.

Seen on a lab run of Windows Server 2025 with the in-guest preparation: the log said
"STARTED via sshfs - DOWNTIME ENDS" 56s after the source went down and the result had no
downtime at all, while the guest booted from the ESXi datastore, restarted once for its new
devices and had its static addresses back almost 8 min after the stop. The pause of the pivot
(16s on that run) and a restart onto the local disks were not counted either.

Now the stop of a running source starts the clock. A guest prepared in ESXi has our guest
agent and a first boot report: a thread finds out when both are there while the mirror runs,
and the run joins it before it ends. Other guests are not seen booting, their stretch ends
with the start. The pause of the pivot and each restart add their own stretch.
"""
import inspect
import json
import re
import threading
import time

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_twostage as ts

import test_v2p_tpm_and_folder_copy as farm
from test_v2p_two_stage_boot import lab, _task, Resp  # noqa: F401 (lab: a fixture)

FB_PATH = r'C:\ProgramData\KVMMigration\firstboot.json'
FB = {'version': 1, 'run': 't1', 'platform': 'kvm', 'state': 'applied', 'boots': 1, 'tools': 'removed',
      'devices': 'removed', 'adapters': []}


_SLEEP = time.sleep


def _guest(lb, monkeypatch, agent_after=None, report_after=None):
    """The VM runs from now on; its agent answers `agent_after` seconds later, its first boot
    report is there `report_after` seconds later (None: never)"""
    monkeypatch.setattr(time, 'time', time.monotonic)      # the lab's clock
    # The lab's sleep only moves its clock, it never lets another greenlet run. A scanner the
    # app of an earlier test in this process started (multi-SDN, drift) sleeps through the same
    # module: once the join of a watch let it in, it spun on that sleep and the test hung. The
    # test and its watches sleep on the lab's clock, everybody else for real.
    lab_sleep = time.sleep

    def sleep(seconds):
        me = threading.current_thread()
        if me is threading.main_thread() or me.name.startswith('v2p-downtime-'):
            return lab_sleep(seconds)
        return _SLEEP(seconds)
    monkeypatch.setattr(time, 'sleep', sleep)
    t0 = time.monotonic()
    lb.pve.running = True
    lb.pve.boots = ['order=sata0']
    post, get = lb.pve._api_post, lb.pve._api_get

    def _post(url, data=None, **kw):
        if url.endswith('/agent/ping') and (agent_after is None or time.monotonic() < t0 + agent_after):
            return Resp(None, 500, 'QEMU guest agent is not running')
        return post(url, data, **kw)

    def _get(url, params=None, **kw):
        if url.endswith('/agent/file-read') and params.get('file') == FB_PATH:
            if report_after is None or time.monotonic() < t0 + report_after:
                return Resp(None, 500, 'no such file')
            return Resp({'content': json.dumps(FB)})
        return get(url, params, **kw)
    monkeypatch.setattr(lb.pve, '_api_post', _post)
    monkeypatch.setattr(lb.pve, '_api_get', _get)
    return t0


def _prepared():
    t = _task()
    t._guest_prep = {'on': True, 'state': 'shut_down'}
    return t


def test_a_prepared_guest_is_down_until_its_first_boot_reported(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=120, report_after=400)
    t = _prepared()
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped')
    # the start is known at once, the result shows it while the mirror runs
    assert any('The VM started 60s after the source stopped: the downtime runs until Windows is up' in ln
               for ln in t.log_lines), t.log_lines
    ts.live_wait(t)
    assert 460 <= t.total_downtime_seconds <= 475, t.total_downtime_seconds
    assert any(re.search(r'\]\s+Windows is up 4\d\ds after the source stopped, its first boot task reported$', ln)
               for ln in t.log_lines), t.log_lines
    assert t.downtime_start is not None and t.downtime_end is not None


def test_a_report_that_never_comes_counts_until_the_agent_answered(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=120, report_after=None)
    t = _prepared()
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped')
    ts.live_wait(t)
    assert 180 <= t.total_downtime_seconds <= 190, t.total_downtime_seconds
    assert any('its first boot task did not report: the downtime is that or more' in ln for ln in t.log_lines)


def test_an_agent_that_never_answers_leaves_the_start_and_says_so(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=None)
    t = _prepared()
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped')
    ts.live_wait(t)
    assert t.total_downtime_seconds == 60.0
    assert any('did not answer within 15 min of the start: the downtime after the source stopped is 60s or more'
               in ln for ln in t.log_lines), t.log_lines


def test_a_guest_not_prepared_in_esxi_is_not_watched(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=0, report_after=0)
    t = _task()
    ts.live_started(lb.pve, t, 'boot', t0 - 45, 'the source stopped')
    assert not getattr(t, '_down_watch', None)
    assert t.total_downtime_seconds == 45.0
    assert any('Downtime 45s until the VM started after the source stopped; without the guest agent' in ln
               for ln in t.log_lines), t.log_lines


def test_the_pause_and_a_restart_add_their_stretch(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=30, report_after=None)
    t = _prepared()
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped', report=False)
    ts.live_wait(t)
    boot = t.total_downtime_seconds
    assert 90 <= boot <= 95, boot
    # the pivot pauses the guest after it was up
    now = time.monotonic()
    ts.live_downtime(t, 'pivot', now + 100, now + 116)
    assert t.total_downtime_seconds == round(boot + 16.0, 1)
    # a restart onto the local disks: 40s until the start, the agent then answers at once
    lb.pve.running = True
    time.sleep(200)
    ts.live_started(lb.pve, t, 'restart', time.monotonic() - 40, 'the VM stopped for the switch', report=False)
    ts.live_wait(t)
    assert t.total_downtime_seconds == round(boot + 16.0 + 40.0, 1)
    assert t._down_parts.keys() == {'boot', 'pivot', 'restart'}


def test_a_pause_while_the_boot_is_still_measured_counts_once(lab, monkeypatch):
    # a small disk is mirrored before Windows is up: the pivot pauses a guest that is still
    # booting, and the boot stretch the watch measures has that pause in it already
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=120, report_after=400)
    t = _prepared()
    gate = __import__('threading').Event()
    real_ping = ts.agent_ping
    monkeypatch.setattr(ts, 'agent_ping', lambda *a, **k: gate.wait() and real_ping(*a, **k))
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped')
    ts.live_downtime(t, 'pivot', t0 + 200, t0 + 216)       # inside the boot, measured on
    assert t.total_downtime_seconds == 60.0 + 16.0, 'the start and a pause after it, all that is known yet'
    gate.set()
    ts.live_wait(t)
    assert 460 <= t.total_downtime_seconds <= 475, t.total_downtime_seconds


def test_a_watch_that_ends_after_the_run_failed_leaves_its_figure(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=120, report_after=400)
    t = _prepared()
    gate = __import__('threading').Event()
    real_ping = ts.agent_ping
    monkeypatch.setattr(ts, 'agent_ping', lambda *a, **k: gate.wait() and real_ping(*a, **k))
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped')
    t.set_phase('failed', 'Disk copy to local storage failed')
    gate.set()
    ts.live_wait(t)
    # the history wrote the failed run with this figure; the task keeps it
    assert t.total_downtime_seconds == 60.0


def test_a_run_that_failed_meanwhile_gets_no_line_from_the_watch(lab, monkeypatch):
    lb = lab()
    t0 = _guest(lb, monkeypatch, agent_after=120, report_after=400)
    t = _prepared()
    t.status = 'failed'
    ts.live_started(lb.pve, t, 'boot', t0 - 60, 'the source stopped')
    ts.live_wait(t)
    assert not any(re.search(r'\]\s+Windows is up \d', ln) for ln in t.log_lines), t.log_lines


# --------------------------------------------------------------------------- the run

def test_a_live_mirror_run_ends_with_its_downtime(monkeypatch):
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'completed', r.task.error
    assert r.task.total_downtime_seconds is not None
    assert not any('DOWNTIME ENDS' in ln for ln in r.task.log_lines), \
        [ln for ln in r.task.log_lines if 'DOWNTIME' in ln]
    assert any('Downtime' in ln and 'until the VM started after the source stopped' in ln for ln in r.task.log_lines)
    # the farm's mirror fails over to the copy and a restart onto the local disks
    assert any(ln.endswith(f'Migration used qemu-ssh boot + importdisk (downtime '
                           f'{r.task.total_downtime_seconds:.0f}s)') for ln in r.task.log_lines), r.task.log_lines[-5:]
    assert set(r.task._down_parts) == {'boot', 'restart'}
    # the guest ran from the source's disks: a rollback keeps that source off (v2p_guestprep.roll_back)
    assert r.task._source_disks_used is True
    # and the run's row says so, for the line of a run cut off by a stop of PegaProx
    assert r.task.to_dict()['guest_prep']['source_disks_used'] is True


def test_a_source_that_was_off_has_no_downtime(monkeypatch):
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed', power='POWERED_OFF').go()
    assert r.task.status == 'completed', r.task.error
    assert r.task.total_downtime_seconds is None
    assert any(ln.endswith('Migration used qemu-ssh boot + importdisk') for ln in r.task.log_lines)
    assert not any('Downtime' in ln for ln in r.task.log_lines)


def test_the_clock_starts_before_the_source_goes_down_on_both_ways_in():
    src = inspect.getsource(v2p._run_v2p_migration)
    for start in ("if task.transfer_mode == 'sshfs_boot':", "Pre-sync failed (VMDK locked) - switching to QEMU SSH boot"):
        block = src[src.index(start):]
        block = block[:block.index('_do_sshfs_boot_migration(')]
        assert block.index('task._live_down_t0 = ') < block.index('_source_off_for_cutover('), start


def test_every_start_of_the_live_mirror_counts_and_none_says_downtime_ends():
    src = inspect.getsource(v2p._do_sshfs_boot_migration)
    assert 'DOWNTIME ENDS' not in src
    assert src.count("_down_started('boot', _down_t0, 'the source stopped')") == 2
    assert src.count("_down_started('restart', _restart_t0,") == 2
    # each restart waits for the stretch before it, so the two never overlap
    for at in [i for i in range(len(src)) if src.startswith('_restart_t0 = time.time()', i)]:
        assert src.rfind('v2p_twostage.live_wait(task)', 0, at) > at - 120
    assert src.index('v2p_twostage.live_wait(task)\n    _dt = ') < src.index("task.set_phase('completed')")
    pause = inspect.getsource(v2p._poll_drive_mirrors)
    assert pause.index("v2p_twostage.live_downtime(task, 'pivot', _resumed - paused_for, _resumed)") > \
        pause.index('paused_for = ')
