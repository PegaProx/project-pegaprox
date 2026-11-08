"""The scheduled tasks loop checks every minute once, on time (#625 lab re-test).

The loop slept a flat 60 s after its work, so each pass started later in its minute by
what the work took (1.4-3 s per task that fired in automatic mode) until it stepped over
a minute, and that minute's tasks did not run. Hourly and weekly tasks compared their
last run to the second, so a pass early in the minute after one late in it (a restart, a
new leader) skipped the run. Minutes the leader's own clock jumped over were neither run
nor reported.

Now:
  * the loop wakes just after each minute starts, whatever the pass took
  * a pass checks every minute since the last one; last_run, to the minute, keeps a slot
    from running twice, also after the clock stepped back
  * more than CATCH_UP_MINUTES skipped beyond the pass's own work (a clock step forward,
    a suspended host, a stalled process) are reported, not run late; in an automatic
    group through the report of design 5.7, after a confirmed lease
  * summer time and a new group zone change nothing: the minute it lands in, as before

The clocks are driven by hand: the wall clock, schedule_now() and the monotonic clock of
the scheduler module.

MK Oct 2026
"""
import types
from datetime import datetime, timedelta

import pytest

from pegaprox.background import scheduler
from pegaprox.core import ha as _ha
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import auto  # noqa: F401

DAY = datetime(2026, 10, 8)          # a Thursday, no summer time change anywhere near


class _Clock:
    def __init__(self, start):
        self.t = start.timestamp()
        self.mono = 1000.0
        self.zone = 0.0              # what summer time moved schedule_now() by

    def now(self):
        return datetime.fromtimestamp(self.t) + timedelta(seconds=self.zone)

    def time(self):
        return self.t

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.t += seconds
        self.mono += seconds

    def step(self, seconds):
        """The wall clock is set: the monotonic clock does not move."""
        self.t += seconds

    def to(self, hour, minute, second=0.5):
        self.t = DAY.replace(hour=hour, minute=minute).timestamp() + second


class _Stop(BaseException):
    pass


@pytest.fixture
def run(monkeypatch):
    """Tasks in a store that load_scheduled_tasks reads afresh each pass, as from the
    database, and a clock by hand."""
    r = types.SimpleNamespace(store={}, ran=[], audits=[], cost=0.0, pass_cost=0.0,
                              clock=_Clock(DAY.replace(hour=10, microsecond=500000)))
    monkeypatch.setattr(scheduler, 'time', types.SimpleNamespace(
        time=r.clock.time, monotonic=r.clock.monotonic, sleep=r.clock.sleep))
    monkeypatch.setattr(_ha, 'schedule_now', r.clock.now)
    monkeypatch.setattr(scheduler, 'load_scheduled_tasks',
                        lambda: {'tasks': [dict(t) for t in r.store.values()]})
    monkeypatch.setattr(scheduler, '_touch_last_run',
                        lambda tid, when: r.store[tid].update(last_run=when))

    def execute(task):
        r.ran.append((task['id'], r.clock.now()))
        r.clock.sleep(r.cost)
    monkeypatch.setattr(scheduler, 'execute_scheduled_task', execute)
    monkeypatch.setattr(scheduler, 'log_audit',
                        lambda user, action, details: r.audits.append((action, details)))

    def add(name, kind, at, day=0, last_run=None):
        r.store[name] = {'id': name, 'name': name, 'enabled': True, 'schedule_type': kind,
                         'schedule_time': at, 'schedule_day': day, 'last_run': last_run}
    r.add = add
    r.names = lambda: [n for n, _ in r.ran]
    return r


def _passes(r, monkeypatch, count, is_active=None):
    """`count` passes of the real loop; returns when each pass began."""
    began, slept = [], []
    load = scheduler.load_scheduled_tasks

    def loading():
        began.append(r.clock.now())
        r.clock.sleep(r.pass_cost)
        return load()
    monkeypatch.setattr(scheduler, 'load_scheduled_tasks', loading)

    def sleep(seconds):
        slept.append(seconds)
        if len(slept) >= count:
            raise _Stop()
        r.clock.sleep(seconds)
    monkeypatch.setattr(scheduler, 'time', types.SimpleNamespace(
        time=r.clock.time, monotonic=r.clock.monotonic, sleep=sleep))
    monkeypatch.setattr(scheduler, '_scheduler_running', True)
    if is_active is not None:
        monkeypatch.setattr(_ha, 'is_active', lambda: is_active(r.clock.now()))
    with pytest.raises(_Stop):
        scheduler.scheduler_loop()
    return began


# --- the loop --------------------------------------------------------------------------

def test_a_slow_pass_does_not_creep_through_the_minute(run, monkeypatch):
    """Each pass costs 2.5 s. The next one still begins just after its minute does,
    minute after minute, three hours long."""
    run.pass_cost = 2.5
    began = _passes(run, monkeypatch, 180)
    assert {(b.second, b.microsecond) for b in began} == {(0, 500000)}
    assert [b - began[0] for b in began] == [timedelta(minutes=k) for k in range(180)]


def test_the_hourly_tasks_of_the_lab_run_every_hour_on_their_minute(run, monkeypatch):
    """The lab case (C1: an hourly task for every minute), each run 2.5 s. A flat 60 s
    after the work crept over a minute every 24 passes, and the task of that minute
    neither ran nor was reported."""
    run.cost = 2.5
    for m in range(60):
        run.add(f'm{m:02}', 'hourly', f'00:{m:02}')
    _passes(run, monkeypatch, 180)
    assert sorted((name, at.hour, at.minute) for name, at in run.ran) == \
        sorted((f'm{m:02}', h, m) for h in (10, 11, 12) for m in range(60))
    assert run.audits == []


def test_a_standby_that_takes_over_catches_up_nothing_of_the_time_it_stood_by(run, monkeypatch):
    """What fell due while it was a standby was the other instance's to run (in an
    automatic group 5.7 reports the gap); nothing is run late or reported here."""
    run.pass_cost = 0.0
    run.add('at 10:10', 'daily', '10:10')
    run.add('at 10:21', 'daily', '10:21')
    _passes(run, monkeypatch, 25, is_active=lambda now: not 1 <= now.minute <= 20)
    assert run.names() == ['at 10:21'] and run.audits == []


# --- minutes caught up -------------------------------------------------------------------

def test_a_minute_the_loop_slept_over_is_caught_up_once(run):
    run.add('at 10:14', 'daily', '10:14')
    run.add('at 10:15', 'daily', '10:15')
    run.clock.to(10, 13)
    state = scheduler.run_scheduled_tasks()
    run.clock.sleep(120)                     # the pass for 10:14 never came
    state = scheduler.run_scheduled_tasks(state)
    assert run.names() == ['at 10:14', 'at 10:15']
    # stamped with its own minute, the one that ran on time with its own time
    assert run.store['at 10:14']['last_run'] == '2026-10-08T10:14:00'
    assert run.store['at 10:15']['last_run'] == '2026-10-08T10:15:00.500000'
    # the same minute once more, and the minutes after it: nothing a second time
    for seconds in (20, 40, 60, 60):
        run.clock.sleep(seconds)
        state = scheduler.run_scheduled_tasks(state)
    assert run.names() == ['at 10:14', 'at 10:15'] and run.audits == []


def test_minutes_a_long_pass_spent_working_are_caught_up_not_reported(run):
    """50 tasks at 02:00 take 25 minutes; the one at 02:10 runs once they are done."""
    for k in range(50):
        run.add(f'nightly {k}', 'daily', '02:00')
    run.add('at 02:10', 'daily', '02:10')
    run.cost = 30.0
    run.clock.to(2, 0)
    state = scheduler.run_scheduled_tasks()
    run.cost = 0.0
    run.clock.sleep(scheduler._to_next_minute())
    state = scheduler.run_scheduled_tasks(state)
    assert run.names()[-1] == 'at 02:10' and len(run.ran) == 51
    assert run.store['at 02:10']['last_run'] == '2026-10-08T02:10:00'
    assert run.audits == []


def test_an_hourly_or_weekly_run_late_in_its_minute_does_not_push_the_next_one_out(run):
    """The last runs were stamped 40 s into the minute (a late pass, or a leader whose
    clock ran ahead); this pass is half a second into it (a restart, a new leader)."""
    run.add('hourly', 'hourly', '00:15', last_run='2026-10-08T09:15:40.200000')
    run.add('weekly', 'weekly', '10:15', day=DAY.weekday(), last_run='2026-10-01T10:15:40.200000')
    run.add('hourly, ran a minute ago', 'hourly', '00:15', last_run='2026-10-08T10:14:59')
    run.clock.to(10, 15)
    scheduler.run_scheduled_tasks()
    assert run.names() == ['hourly', 'weekly']


# --- clock steps ----------------------------------------------------------------------------

def test_a_clock_step_back_runs_no_slot_twice(run):
    run.add('hourly', 'hourly', '00:15')
    run.add('daily', 'daily', '10:16')
    run.add('weekly', 'weekly', '10:17', day=DAY.weekday())
    run.add('monthly', 'monthly', '10:17', day=DAY.day)
    run.clock.to(10, 14)
    state = None
    for k in range(12):
        if k == 5:
            run.clock.step(-330)             # 10:19:00 back to 10:13:30
        state = scheduler.run_scheduled_tasks(state)
        run.clock.sleep(scheduler._to_next_minute())
    assert sorted(run.names()) == ['daily', 'hourly', 'monthly', 'weekly']
    assert run.audits == []


def test_a_clock_step_forward_of_ten_minutes_is_reported_not_run(run, caplog):
    run.add('at 10:05', 'daily', '10:05')
    run.add('hourly at 07', 'hourly', '00:07')
    run.add('ran at 10:03 already', 'daily', '10:03', last_run='2026-10-08T10:03:00.400000')
    run.add('at 10:11', 'daily', '10:11')
    run.clock.to(10, 0)
    state = scheduler.run_scheduled_tasks()
    run.clock.step(600)
    run.clock.sleep(60)                      # 10:11:00.5, the monotonic clock says 60 s
    with caplog.at_level('WARNING'):
        state = scheduler.run_scheduled_tasks(state)
    assert run.names() == ['at 10:11']
    assert len(run.audits) == 1
    action, text = run.audits[0]
    assert action == 'scheduled_task.missed'
    assert text.startswith('2 scheduled tasks fell due between 2026-10-08 10:01:00 and '
                           '2026-10-08 10:10:59')
    assert 'at 10:05, hourly at 07' in text and 'clock step forward' in text
    assert 'stood still' in caplog.text
    # and they are not run late either
    for _ in range(3):
        run.clock.sleep(scheduler._to_next_minute())
        state = scheduler.run_scheduled_tasks(state)
    assert run.names() == ['at 10:11'] and len(run.audits) == 1


def test_a_skipped_minute_of_a_few_is_run_not_reported(run):
    """A step of two minutes (the C3 and C5 lab runs: 30 s ahead, a clock at double rate)."""
    run.add('at 10:02', 'daily', '10:02')
    run.clock.to(10, 0)
    state = scheduler.run_scheduled_tasks()
    run.clock.step(120)
    run.clock.sleep(60)
    scheduler.run_scheduled_tasks(state)
    assert run.names() == ['at 10:02'] and run.audits == []


def test_summer_time_skips_its_missing_hour_as_before(run):
    """02:00 to 02:59 does not exist on the day summer time starts: nothing ran there
    before, and nothing is reported for it now."""
    run.add('at 02:30', 'daily', '02:30')
    run.add('at 03:00', 'daily', '03:00')
    run.clock.to(1, 59)
    state = scheduler.run_scheduled_tasks()
    run.clock.sleep(60)
    run.clock.zone = 3600
    scheduler.run_scheduled_tasks(state)
    assert run.names() == ['at 03:00'] and run.audits == []


def test_the_due_rule_finds_the_latest_slot_of_each_kind():
    def due(kind, at, first, last, day=0):
        task = {'schedule_type': kind, 'schedule_time': at, 'schedule_day': day}
        return scheduler._last_due(task, first, last)
    t = lambda d, h, m: datetime(2026, 10, d, h, m)
    assert due('hourly', '00:15', t(8, 9, 0), t(8, 10, 14)) == t(8, 9, 15)
    assert due('hourly', '00:15', t(8, 9, 16), t(8, 10, 14)) is None
    assert due('daily', '23:59', t(8, 23, 58), t(9, 0, 1)) == t(8, 23, 59)
    assert due('weekly', '10:00', t(1, 0, 0), t(8, 9, 0), day=0) == t(5, 10, 0)    # Monday
    assert due('weekly', '10:00', t(1, 0, 0), t(8, 9, 0), day='0') is None
    # the 31st: September has none, so the last one before 1 October is in August
    assert due('monthly', '04:00', t(1, 0, 0) - timedelta(days=61), t(1, 0, 0), day=31) == \
        datetime(2026, 8, 31, 4, 0)
    assert due('monthly', '04:00', t(1, 0, 0) - timedelta(days=30), t(1, 0, 0), day=31) is None
    assert due('monthly', '04:00', t(1, 0, 0) - timedelta(days=30), t(1, 0, 0), day=0) is None
    assert due('daily', '24:00', t(8, 0, 0), t(9, 0, 0)) is None
    with pytest.raises(ValueError):
        due('daily', 'noon', t(8, 0, 0), t(9, 0, 0))


# --- in an automatic group ---------------------------------------------------------------

def test_a_minute_caught_up_inside_a_new_leaders_hold_is_not_fired(auto, seed, monkeypatch):
    """The hold (5.7) ends 30 s into the minute before this one: a task of that minute is
    caught up by no one, the 5.7 report names it; this minute's task runs."""
    auto.form(seed)
    wall = _ha._wall()
    wall -= wall % 60 - 20.5                  # 20.5 s into this minute
    minute = wall - wall % 60
    said = []
    monkeypatch.setattr(_ha, '_wall', lambda: wall)
    monkeypatch.setattr(_ha, 'schedule_now', lambda: _ha.schedule_at(wall))
    monkeypatch.setattr(_ha, 'missed_schedules', lambda kind, names, window, *a: said.append(names))
    monkeypatch.setattr(_ha, 'schedule_fired', lambda: None)
    ran, store = [], {}
    monkeypatch.setattr(scheduler, 'load_scheduled_tasks',
                        lambda: {'tasks': [dict(t) for t in store.values()]})
    monkeypatch.setattr(scheduler, '_touch_last_run', lambda tid, when: store[tid].update(last_run=when))
    monkeypatch.setattr(scheduler, 'execute_scheduled_task', lambda t: ran.append(t['id']))
    monkeypatch.setattr(scheduler, 'time', types.SimpleNamespace(
        time=lambda: wall, monotonic=lambda: 1000.0, sleep=None))
    for name, at in (('held', minute - 60), ('free', minute)):
        store[name] = {'id': name, 'name': name, 'enabled': True, 'schedule_type': 'daily',
                       'schedule_time': _ha.schedule_at(at).strftime('%H:%M')}
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        rt.came_up = True                     # took over
        rt.node.acting_from = ha.ha_clock() - (wall - (minute - 30 - ha._largest_skew()))
        assert ha.schedule_held() is False
        assert ha.schedule_held(ha.schedule_at(minute - 60)) is True
        assert ha.schedule_held(ha.schedule_at(minute)) is False
        before = (ha.schedule_at(minute - 120), wall - 120, 0.0)
        scheduler.run_scheduled_tasks(before)
    assert ran == ['free']
    assert said == [['held']]


def _auto_gap(run, monkeypatch, auto, seed, isolate=False):
    said = []
    monkeypatch.setattr(_ha, 'missed_schedules',
                        lambda kind, names, window, why='': said.append((kind, names, why)))
    monkeypatch.setattr(_ha, 'schedule_fired', lambda: None)
    run.add('at 10:05', 'daily', '10:05')
    run.add('at 10:11', 'daily', '10:11')
    auto.form(seed)
    with auto.at('a') as ha:
        ha._rts[IDS['a']].node.acting_from = ha.ha_clock() - 130
        run.clock.to(10, 0)
        state = scheduler.run_scheduled_tasks()
        run.clock.step(600)                   # the leader's clock leaps ahead
        run.clock.sleep(60)
        if isolate:
            auto.isolate('a')
        scheduler.run_scheduled_tasks(state)
    return said


def test_in_an_automatic_group_a_gap_goes_to_the_report_of_5_7(run, monkeypatch, auto, seed):
    said = _auto_gap(run, monkeypatch, auto, seed)
    assert len(said) == 1 and said[0][:2] == ('scheduled tasks', ['at 10:05'])
    assert 'clock step forward' in said[0][2]
    assert run.names() == ['at 10:11'] and run.audits == []


def test_a_leader_whose_clock_leapt_ahead_and_lost_its_lease_reports_and_runs_nothing(
        run, monkeypatch, auto, seed):
    """Its lease calls are refused from the step on (C1): the confirm says no, and the next
    leader reports the gap by the true clock."""
    said = _auto_gap(run, monkeypatch, auto, seed, isolate=True)
    assert said == [] and run.ran == [] and run.audits == []
