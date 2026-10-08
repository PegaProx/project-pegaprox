"""The scheduled actions loop checks every minute once, on time (#625 lab re-test).

The same fault as in the scheduled tasks loop: check_schedules waited a flat 60 s after
its work, so its pass crept through the minute and sooner or later stepped over one. A
VM action, a one-time action or the 03:00 cleanup in that minute did not run, and
nothing said so.

Now the wait ends just after the next minute starts, a pass checks every minute since
the pass before (last_run keeps a minute from running twice, also after the clock
stepped back), and a gap longer than the catch-up limit is reported instead of run.

MK Oct 2026
"""
import types
from datetime import datetime

import pytest

import pegaprox.api.schedules as sched
from pegaprox.core import ha as _ha

DAY = datetime(2026, 10, 8)          # a Thursday


class _Clock:
    def __init__(self):
        self.t = DAY.replace(hour=10).timestamp() + 0.5
        self.mono = 1000.0

    def now(self):
        return datetime.fromtimestamp(self.t)

    def time(self):
        return self.t

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.t += seconds
        self.mono += seconds


class _Stop(BaseException):
    pass


@pytest.fixture
def run(monkeypatch):
    r = types.SimpleNamespace(actions=[], ran=[], audits=[], cleanups=0, clock=_Clock(),
                              plan=[])
    monkeypatch.setattr(sched, 'time', types.SimpleNamespace(
        time=r.clock.time, monotonic=r.clock.monotonic, sleep=r.clock.sleep))
    monkeypatch.setattr(_ha, 'schedule_now', r.clock.now)
    monkeypatch.setattr(sched, 'load_schedules', lambda: {'actions': [dict(a) for a in r.actions]})

    def record(aid, when, disable=False):
        for a in r.actions:
            if a['id'] == aid:
                a['last_run'] = when
                if disable:
                    a['enabled'] = False
    monkeypatch.setattr(sched, '_record_action_run', record)
    monkeypatch.setattr(sched, 'execute_scheduled_action',
                        lambda a: r.ran.append((a['id'], r.clock.now().strftime('%H:%M'))))
    monkeypatch.setattr(sched, 'check_scheduled_updates', lambda: None)

    def cleanup():
        r.cleanups += 1
    monkeypatch.setattr(sched, 'cleanup_deleted_scripts', cleanup)
    monkeypatch.setattr(sched, 'cleanup_orphaned_excluded_vms', lambda: None)
    monkeypatch.setattr(sched, 'log_audit', lambda user, action, text, **k: r.audits.append((action, text)))
    monkeypatch.setattr(sched, '_scheduler_running', True)

    real_wait = r.real_wait = sched._wait_a_minute

    def wait():
        # each entry of r.plan runs before the next pass: a callable that moves the
        # clock by hand, or None for the normal wait to the next minute
        if not r.plan:
            raise _Stop()
        step = r.plan.pop(0)
        if step is None:
            real_wait()
        else:
            step(r.clock)
    monkeypatch.setattr(sched, '_wait_a_minute', wait)

    def go(*plan):
        r.plan = list(plan)
        with pytest.raises(_Stop):
            sched.check_schedules()
    r.go = go
    return r


def _daily(aid, at, **kw):
    return dict({'id': aid, 'enabled': True, 'schedule_type': 'daily', 'time': at,
                 'action': 'start', 'vmid': 100}, **kw)


def _set(hour, minute, second=0.5):
    def step(clock):
        clock.t = DAY.replace(hour=hour, minute=minute).timestamp() + second
    return step


def test_the_wait_ends_just_after_the_next_minute_starts(run):
    run.clock.t = DAY.replace(hour=10, minute=4).timestamp() + 42.0
    run.real_wait()
    assert 0.5 <= run.clock.t - DAY.replace(hour=10, minute=5).timestamp() < 1.5


def test_a_minute_the_pass_slept_over_runs_once_with_its_own_stamp(run):
    run.actions = [_daily('a', '10:03')]
    # pass at 10:02 (late in the minute), the next one lands in 10:04: 10:03 was stepped over
    run.clock.t = DAY.replace(hour=10, minute=2).timestamp() + 59.0
    run.go(_set(10, 4, 1.0), None)

    assert [aid for aid, _ in run.ran] == ['a']
    assert run.actions[0]['last_run'] == '2026-10-08 10:03'


def test_the_same_minute_twice_runs_nothing_twice(run):
    run.actions = [_daily('a', '10:00')]
    run.go(_set(10, 0, 30.0))
    assert run.ran == [('a', '10:00')]


def test_a_clock_step_back_does_not_run_a_minute_again(run):
    run.actions = [_daily('a', '10:03')]
    run.clock.t = DAY.replace(hour=10, minute=3).timestamp() + 0.5
    # ran at 10:03, then the clock is set back to 10:01 and walks through 10:03 again
    run.go(_set(10, 1), _set(10, 2), _set(10, 3), _set(10, 4))
    assert run.ran == [('a', '10:03')]


def test_a_long_gap_is_reported_and_not_run_late(run):
    run.actions = [_daily('a', '10:03', name='start web')]
    run.clock.t = DAY.replace(hour=10, minute=1).timestamp() + 0.5
    # the clock steps from 10:01 to 10:11: ten minutes, beyond the catch-up limit
    run.go(_set(10, 11))

    assert run.ran == []
    assert [a for a, _ in run.audits] == ['scheduled_action.missed']
    assert 'start web' in run.audits[0][1]


def test_a_short_gap_within_the_limit_is_caught_up(run):
    run.actions = [_daily('a', '10:03')]
    run.clock.t = DAY.replace(hour=10, minute=1).timestamp() + 0.5
    run.go(_set(10, 5))
    assert [aid for aid, _ in run.ran] == ['a']
    assert run.audits == []


def test_a_one_time_action_in_a_stepped_over_minute_runs_and_switches_off(run):
    run.actions = [{'id': 'o', 'enabled': True, 'schedule_type': 'once', 'time': '10:03',
                    'date': '2026-10-08', 'action': 'stop', 'vmid': 101}]
    run.clock.t = DAY.replace(hour=10, minute=2).timestamp() + 59.0
    run.go(_set(10, 4, 1.0), None)
    assert [aid for aid, _ in run.ran] == ['o']
    assert run.actions[0]['enabled'] is False


def test_the_0300_cleanup_runs_when_its_minute_was_stepped_over(run):
    run.clock.t = DAY.replace(hour=3, minute=0).timestamp() - 1.0     # 02:59:59
    run.go(lambda c: setattr(c, 't', DAY.replace(hour=3, minute=1).timestamp() + 1.0))
    assert run.cleanups == 1


def test_an_old_iso_last_run_still_counts_as_that_minute(run):
    run.actions = [_daily('a', '10:00', last_run='2026-10-08T10:00:00')]
    run.go()
    assert run.ran == []
