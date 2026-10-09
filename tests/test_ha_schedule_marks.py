"""Schedules across changes of leader, from the lab run on 3f43b7e (#625, design 5.7).

  * E6c: six leaders in a row each lost the lease before their first scheduler pass, and
    five minutes in which the group had no leader were neither run nor reported. The
    window of the report started at the last renewal the reporting leader could have
    heard, a guess of its own. It starts now after the minute the group's marks say was
    settled last: the minute the last pass got through (checked) or the last report
    covered (reported, on a majority before the report goes out). Nothing in between is
    left out, and no minute is reported twice
  * E6b_2: a task whose lease confirm failed after its last run went out was used up
    with a WARNING only, and the tasks due after it in the same pass were dropped without
    a line. It is reported as missed now, in both loops, and the ones after it try a
    round of their own; none of them runs twice
  * 5.7 says audit and alert: the report goes out as an alert as well

MK Oct 2026 (#625)
"""
import collections
import itertools
import random
import threading
import time
import types

import pytest

import pegaprox.api.schedules as actions_loop
from pegaprox.background import scheduler
from pegaprox.core import ha as _ha
from pegaprox.core.db import get_db as _ha_db
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture
from test_ha_api import _audit
from test_ha_members import IDS, group  # noqa: F401 - the fixture

# the start of the hour before this one: the wall clock the passes run by
HOUR = time.time() // 3600 * 3600 - 3600
GAP = 'while the group changed its leader'
LOST = 'while the lease of this instance could not be confirmed'


def _here(fn, elsewhere=lambda *a, **k: False):
    """fn on the thread of the test, `elsewhere` on any other. The app's own scheduler
    threads run in the test process, and a pass of theirs that falls into a test here
    would fire its tasks and move its marks."""
    me = threading.get_ident()
    return lambda *a, **k: (fn if threading.get_ident() == me else elsewhere)(*a, **k)


def _clock(wall):
    """A `time` for a scheduler module: the wall clock by hand on the test's thread."""
    return types.SimpleNamespace(time=_here(wall, time.time),
                                 monotonic=_here(lambda: 1000.0, time.monotonic), sleep=time.sleep)


@pytest.fixture(autouse=True)
def _no_background_passes(monkeypatch):
    monkeypatch.setattr(_ha, 'is_active', _here(_ha.is_active))


def _tasks(r, *minutes, prefix='m'):
    for m in minutes:
        name = f'{prefix}{m:02}'
        r.store[name] = {'id': name, 'name': name, 'enabled': True, 'schedule_type': 'hourly',
                         'schedule_time': f'00:{m:02}'}


@pytest.fixture
def loop(monkeypatch):
    """The tasks loop with its tasks in a dict and the wall clock by hand."""
    r = types.SimpleNamespace(wall=HOUR, store={}, ran=[], said=[])
    monkeypatch.setattr(_ha, '_wall', lambda: r.wall)
    monkeypatch.setattr(_ha, 'schedule_now', lambda: _ha.schedule_at(r.wall))
    monkeypatch.setattr(_ha, 'schedule_fired', lambda: None)
    monkeypatch.setattr(_ha, 'missed_schedules',
                        lambda kind, names, window, why=GAP: r.said.append((kind, list(names), why)))
    monkeypatch.setattr(scheduler, 'load_scheduled_tasks',
                        lambda: {'tasks': [dict(t) for t in r.store.values()]})
    monkeypatch.setattr(scheduler, '_touch_last_run', lambda tid, when: r.store[tid].update(last_run=when))
    monkeypatch.setattr(scheduler, 'execute_scheduled_task', lambda t: r.ran.append(t['id']))
    monkeypatch.setattr(scheduler, 'time', _clock(lambda: r.wall))
    r.reported = lambda why=GAP: [n for _k, names, w in r.said if w == why for n in names]
    return r


def _pass(auto, r, minute, acting_at=None, last=None):
    """One pass of the tasks loop on a, `minute` minutes into the hour. With `acting_at`
    (a wall time) a leads since then by a start of its process, as the winner of an
    election does; without it a leads since the switch, long ago."""
    r.wall = HOUR + 60 * minute + 0.5
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        rt.came_up = acting_at is not None
        rt.node.acting_from = ha.ha_clock() - (r.wall - acting_at if acting_at else 3000)
        return scheduler.run_scheduled_tasks(last)


def _names(*minutes):
    return [f'm{m:02}' for m in minutes]


# --- the window of the report (E6c) ------------------------------------------------------------

def test_minutes_no_leader_got_to_a_pass_in_are_reported_by_the_next_one(auto, seed, loop):
    """The pass of :00 is the last one; the leaders after it each lost the lease before a
    pass of their own. The leader acting from :07:20 reports :01 to :07 at its first pass
    and runs :08. The guess from the last renewal it heard reached back to :06."""
    auto.form(seed)
    _tasks(loop, *range(10))
    _pass(auto, loop, 0)
    assert loop.ran == ['m00'] and loop.said == []

    _pass(auto, loop, 8, acting_at=HOUR + 7 * 60 + 20)

    assert loop.said == [('scheduled tasks', _names(*range(1, 8)), GAP)]
    assert loop.ran == ['m00', 'm08']


def test_no_minute_is_reported_twice_by_leaders_one_after_the_other(auto, seed, loop):
    """The last pass is the one of :06. X acts from :07:20 and reports :07 at its pass of
    :08, where it runs :08. Y acts from :08:15: the minutes its hold skips were X's,
    settled. A window from the last renewal Y heard reached back to :07 and named it
    again."""
    auto.form(seed)
    _tasks(loop, *range(10))
    _pass(auto, loop, 6)
    _pass(auto, loop, 8, acting_at=HOUR + 7 * 60 + 20)
    assert loop.reported() == ['m07']
    # another acting_from: another leader (the harness turns no lease clock between them)
    _pass(auto, loop, 9, acting_at=HOUR + 8 * 60 + 15)

    assert loop.reported() == ['m07']
    assert loop.ran == ['m06', 'm08', 'm09']


def test_a_report_whose_confirm_fails_goes_out_with_the_next_pass_whole_and_once(
        auto, seed, loop, monkeypatch):
    """The new leader's round fails at its first pass: nothing is said yet, the mark is
    put back and the minute it checked is no mark either, so the gap stays in the
    window. The next pass says it, :01 to :07, once."""
    auto.form(seed)
    _tasks(loop, *range(10))
    _pass(auto, loop, 0)
    real = _ha.confirm_step
    cut = {'on': True}
    monkeypatch.setattr(_ha, 'confirm_step', lambda what, *a, **k: not cut['on'] and real(what, *a, **k))
    acting = HOUR + 7 * 60 + 20

    _pass(auto, loop, 8, acting_at=acting)

    assert loop.reported() == [] and loop.reported(LOST) == ['m08']
    with auto.at('a') as ha:
        # checked stays at :00, reported at nothing: whoever reports next starts at :01
        assert ha._marks('scheduled tasks') == (HOUR, None)
    cut['on'] = False
    _pass(auto, loop, 9, acting_at=acting)
    _pass(auto, loop, 10, acting_at=acting)

    assert loop.reported() == _names(*range(1, 8))
    # m08 went out first and is used up: reported as lost, never run
    assert loop.ran == ['m00', 'm09']
    with auto.at('a') as ha:
        assert ha._marks('scheduled tasks') == (HOUR + 600, HOUR + 7 * 60)


def test_checked_rides_along_and_reported_steps_the_config_version(auto, seed):
    """checked moves every minute and steps nothing: the members get it with whatever
    they pull next. reported steps the cv, and the round after it makes the voters pull
    before the report goes out."""
    auto.form(seed)
    with auto.at('a') as ha:
        ha.schedules_checked('scheduled tasks', HOUR + 30)
        # the row is new: one step for it
        ha.cv_tick(force=True)
        before = ha.cv_entry()
        ha.schedules_checked('scheduled tasks', HOUR + 600.5)
        assert ha.cv_tick(force=True) in ('clean', 'same') and ha.cv_entry() == before
        assert ha._marks('scheduled tasks') == (HOUR + 600, None)
        snap = ha.build_snapshot()['tables']['ha_schedule_marks']
        assert dict(zip(snap['columns'], snap['rows'][0]))['checked'] == HOUR + 600
        # a clock that went back does not move it back
        ha.schedules_checked('scheduled tasks', HOUR)
        assert ha._marks('scheduled tasks') == (HOUR + 600, None)
        auto.pulls.clear()
        assert ha.report_settled('scheduled tasks', HOUR + 630, 'the report of a gap')
        assert ha.cv_entry() != before
        assert ha._marks('scheduled tasks') == (HOUR + 600, HOUR + 600)
    assert set(auto.pulls) >= {'b', 'c'}


def test_a_mark_put_back_goes_out_as_the_mark_did(auto, seed, monkeypatch):
    """The round found no majority, but a member it reached pulled the mark: one that wins
    next (it holds the newest cv) would start its report after minutes nobody said. The
    mark put back goes to the members at once too; the cv tick of the lease loop does
    not run once the lease is gone."""
    auto.form(seed)
    with auto.at('a') as ha:
        ha.schedules_checked('scheduled tasks', HOUR)
        ha.cv_tick(force=True)
        real, sent = ha.send_on, []
        monkeypatch.setattr(ha, 'send_on', lambda what: sent.append(
            (ha._marks('scheduled tasks')[1], ha.cv_entry())) or real(what))
        monkeypatch.setattr(ha, 'confirm_step', lambda what, *a, **k: False)
        nudged = []
        monkeypatch.setattr(ha, 'nudge_members', lambda *a, **k: nudged.append(ha.cv_entry()))

        assert ha.report_settled('scheduled tasks', HOUR + 630, 'the report of a gap') is False

        assert ha._marks('scheduled tasks') == (HOUR, None)
        assert [mark for mark, _cv in sent] == [HOUR + 600, None]
        # a step for the mark and one for its way back, and the members told of both
        assert len({repr(cv) for _mark, cv in sent} | {repr(ha.cv_entry())}) == 3
        assert nudged == [sent[1][1], ha.cv_entry()]


def test_outside_an_automatic_group_no_mark_is_written(auto, seed):
    assert _ha.report_settled('scheduled tasks', HOUR, 'x') is True
    _ha.schedules_checked('scheduled tasks', HOUR)
    assert _ha._marks('scheduled tasks') == (None, None)
    auto.pair(seed)
    for n in 'ab':
        with auto.at(n) as ha:
            assert ha.report_settled('scheduled tasks', HOUR, 'x') is (n == 'a')
            ha.schedules_checked('scheduled tasks', HOUR)
    assert _ha._marks('scheduled tasks') == (None, None)
    assert 'ha_schedule_marks' not in _ha._existing_tables(_ha_db().conn.cursor())


def test_the_passes_of_a_manual_active_change_nothing_its_standbys_pull(auto, seed, loop, monkeypatch):
    """Manual mode as before: both loops run what is due and write no mark. A mark there
    made a shared table under every manual active, a new etag its standbys pulled, and a
    pass of the app's own scheduler threads stepped the cv in the middle of another test
    (test_the_tick_catches_up_on_a_table_made_on_first_use)."""
    from pegaprox.api.ha import current_etag
    auto.pair(seed)
    _tasks(loop, 5)
    acts = [_daily('web', HOUR + 300, 1)]
    loop.wall = HOUR + 300.5
    with auto.at('a') as ha:
        before = current_etag()
        scheduler.run_scheduled_tasks()
        _actions(monkeypatch, loop, acts)()
        assert loop.ran == ['m05', 'web'] and loop.said == []
        assert current_etag() == before
    assert 'ha_schedule_marks' not in _ha._existing_tables(_ha_db().conn.cursor())


def test_the_report_goes_out_as_an_alert_too(seed, monkeypatch):
    import pegaprox.globals as ppglobals
    import pegaprox.utils.webhooks as webhooks
    hooked, sent = [], []
    monkeypatch.setattr(ppglobals, '_notification_handlers',
                        list(ppglobals._notification_handlers) + [hooked.append])
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, channel_ids=None: sent.append(alert))
    monkeypatch.setattr(_ha, '_later', lambda delay, fn, name: fn())

    _ha.missed_schedules('scheduled tasks', ['nightly'], (HOUR, HOUR + 59))

    assert len(hooked) == 1 and sent == hooked
    alert = hooked[0]
    assert alert['metric'] == 'ha_schedules_missed' and alert['severity'] == 'warning'
    assert alert['current_value'] == '1 scheduled tasks' and 'nightly' in alert['message']
    assert [r['details'] for r in _audit('ha.schedules_missed')] == [alert['message']]


# --- a confirm that fails after the last run went out (E6b_2) ------------------------------------

@pytest.fixture
def guarded(loop, monkeypatch):
    """The tasks loop as on the leader of an automatic group, by its answers: written
    first, the round per task as `loop.confirms` says (True when it runs out), active as
    `loop.active` says."""
    loop.confirms, loop.active, loop.asked = [], True, []

    def confirm(what, *a, **k):
        loop.asked.append(what)
        return loop.confirms.pop(0) if loop.confirms else True
    monkeypatch.setattr(_ha, 'confirm_step', confirm)
    monkeypatch.setattr(_ha, 'schedule_fire_first', lambda: True)
    monkeypatch.setattr(_ha, 'is_active', _here(lambda: loop.active))
    monkeypatch.setattr(_ha, 'missed_schedule_window', lambda kind: None)
    monkeypatch.setattr(_ha, 'schedule_held', lambda at=None: False)
    checked = []
    # raising=False: the same tests ran against the code before the marks
    monkeypatch.setattr(_ha, 'schedules_checked', lambda kind, wall: checked.append((kind, wall)),
                        raising=False)
    loop.checked = checked
    return loop


def test_a_task_whose_round_fails_is_reported_and_the_one_after_it_runs(guarded):
    """The leader keeps its lease; the pass falls into a cut of 15 s. The first task's
    round fails, the next one's comes back: the first is reported, the next runs. Before,
    the first went with a WARNING and the next was dropped without a line."""
    r = guarded
    _tasks(r, 5, prefix='a')
    _tasks(r, 5, prefix='b')
    r.wall = HOUR + 5 * 60 + 0.5
    r.confirms = [False, True]

    scheduler.run_scheduled_tasks()

    assert r.said == [('scheduled tasks', ['a05'], LOST)]
    assert r.ran == ['b05']
    # a05 is used up: its run went out before the round
    assert r.store['a05']['last_run'].startswith(_ha.schedule_at(r.wall).strftime('%Y-%m-%dT%H:%M'))
    assert r.checked == [('scheduled tasks', r.wall)]
    # the same minute once more (a new process, a clock set back): it does not run late,
    # nor is it said again
    scheduler.run_scheduled_tasks(None)
    assert r.ran == ['b05'] and len(r.said) == 1


def test_all_of_a_pass_whose_rounds_fail_go_into_one_report(guarded):
    r = guarded
    _tasks(r, 5, prefix='a')
    _tasks(r, 5, prefix='b')
    r.wall = HOUR + 5 * 60 + 0.5
    r.confirms = [False, False]
    scheduler.run_scheduled_tasks()
    assert r.said == [('scheduled tasks', ['a05', 'b05'], LOST)] and r.ran == []


def test_once_the_lease_is_gone_the_rest_is_left_to_the_next_leader(guarded, monkeypatch):
    """The first round fails and the lease runs out: the task after it is not written
    first (the next leader's report names it), and the pass is no mark."""
    r = guarded
    _tasks(r, 5, prefix='a')
    _tasks(r, 5, prefix='b')
    r.wall = HOUR + 5 * 60 + 0.5

    def gone(what, *a, **k):
        r.active = False
        return False
    monkeypatch.setattr(_ha, 'confirm_step', gone)

    scheduler.run_scheduled_tasks()

    assert r.said == [('scheduled tasks', ['a05'], LOST)] and r.ran == []
    assert 'last_run' not in r.store['b05'] and r.checked == []


def test_outside_an_automatic_group_a_no_still_ends_the_pass_as_before(guarded, monkeypatch):
    """No lease: confirm_step is the role, and a no means a standby now. Nothing was
    written first, nothing is reported; what is left is the other instance's."""
    r = guarded
    monkeypatch.setattr(_ha, 'schedule_fire_first', lambda: False)
    _tasks(r, 5, prefix='a')
    _tasks(r, 5, prefix='b')
    r.wall = HOUR + 5 * 60 + 0.5
    r.confirms = [False]
    scheduler.run_scheduled_tasks()
    assert r.said == [] and r.ran == [] and r.asked == ['scheduled task a05']
    assert 'last_run' not in r.store['a05']


class _Stop(BaseException):
    pass


def _actions(monkeypatch, r, acts):
    """One pass of the actions loop at r.wall over `acts`; what it ran goes to r.ran."""
    monkeypatch.setattr(actions_loop, 'time', _clock(lambda: r.wall))
    monkeypatch.setattr(actions_loop, 'load_schedules', lambda: {'actions': [dict(a) for a in acts]})

    def record(aid, when, disable=False):
        next(a for a in acts if a['id'] == aid)['last_run'] = when
    monkeypatch.setattr(actions_loop, '_record_action_run', record)
    monkeypatch.setattr(actions_loop, 'execute_scheduled_action', lambda a: r.ran.append(a['name']))
    monkeypatch.setattr(actions_loop, 'check_scheduled_updates', lambda: None)
    monkeypatch.setattr(actions_loop, '_scheduler_running', True)

    def stop():
        raise _Stop()
    monkeypatch.setattr(actions_loop, '_wait_a_minute', _here(stop, lambda: time.sleep(1)))

    def one_pass():
        with pytest.raises(_Stop):
            actions_loop.check_schedules()
    return one_pass


def _daily(name, at, i):
    return {'id': i, 'name': name, 'enabled': True, 'schedule_type': 'daily', 'action': 'start',
            'vmid': 100 + i, 'time': _ha.schedule_at(at).strftime('%H:%M')}


def test_the_actions_loop_reports_a_failed_round_and_runs_the_next(guarded, monkeypatch):
    r = guarded
    acts = [_daily('web', HOUR + 300, 1), _daily('db', HOUR + 300, 2)]
    r.wall = HOUR + 300.5
    r.confirms = [False, True]

    _actions(monkeypatch, r, acts)()

    assert r.said == [('scheduled actions', ['web'], LOST)] and r.ran == ['db']
    assert acts[0]['last_run'] == _ha.schedule_at(HOUR + 300).strftime('%Y-%m-%d %H:%M')
    assert r.checked == [('scheduled actions', r.wall)]


def test_the_actions_loop_reports_the_gap_from_the_marks(auto, seed, loop, monkeypatch):
    """E6c in the actions loop: its pass of :00 is the last one, the leader acting from
    :07:20 reports :01 to :07 and runs :08. The report looks a day at a time."""
    auto.form(seed)
    acts = [_daily(f'a{m:02}', HOUR + 60 * m, m) for m in range(10)]
    acts.append(_daily('after the gap', HOUR + 1800, 99))
    one_pass = _actions(monkeypatch, loop, acts)
    for minute, acting_at in ((0, None), (8, HOUR + 7 * 60 + 20)):
        loop.wall = HOUR + 60 * minute + 0.5
        with auto.at('a') as ha:
            rt = ha._rts[IDS['a']]
            rt.came_up = acting_at is not None
            rt.node.acting_from = ha.ha_clock() - (loop.wall - acting_at if acting_at else 3000)
            one_pass()

    assert loop.said == [('scheduled actions', [f'a{m:02}' for m in range(1, 8)], GAP)]
    assert loop.ran == ['a00', 'a08']


# --- E6c through the elections ------------------------------------------------------------------

# after the leader is lost, one acting leader within this long (I6)
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5


def _driven(auto, loop, monkeypatch):
    """The wall clock turns with the lease clocks, and every member that may act runs its
    pass at :00.5 of each minute, as scheduler_loop does (one that may not starts over
    with the minute it acts again in). seen.step(seconds) drives it; seen.passes holds
    (name, minute, acting_from) of every pass, seen.leaders (name, acting_from) of every
    term that acted."""
    real = auto.advance

    def advance(dt):
        real(dt)
        loop.wall += dt
    monkeypatch.setattr(auto, 'advance', advance)
    seen = types.SimpleNamespace(passes=[], leaders=[], last={}, minute=None)

    def acting(n):
        node = auto.node(n)
        return node.acting_from if node is not None else None

    def tick():
        for n in auto.active():
            if (n, acting(n)) not in seen.leaders:
                seen.leaders.append((n, acting(n)))
        minute = int((loop.wall - 0.5 - HOUR) // 60)
        if minute == seen.minute:
            return
        seen.minute = minute
        for n in auto.members:
            with auto.at(n) as ha:
                if ha.is_active():
                    seen.passes.append((n, minute, acting(n)))
                    seen.last[n] = scheduler.run_scheduled_tasks(seen.last.get(n))
                else:
                    seen.last[n] = None

    def step(seconds, until=None):
        passed = 0.0
        while passed < seconds:
            auto.run(1.0, dt=1.0)
            passed += 1.0
            tick()
            if until is not None and until():
                break
        return passed
    seen.step, seen.acting = step, acting
    return seen


# wait: seconds after the pass of :00 before the first cut, which moves the passes
# against the elections. 0: five terms in a row that never get to a pass. 35: besides
# such terms, cut off ones that get to a pass and find no confirm, for their report of
# the gap nor for the task of the minute
@pytest.mark.parametrize('wait', [0, 35])
def test_leaders_cut_off_before_their_first_pass_leave_no_minute_out_and_none_twice(
        auto, seed, loop, monkeypatch, wait):
    """Lab E6c through real elections: each new leader is cut off from the majority after
    its first renewal round and loses the lease about 20 s later, most of them before a
    pass of their own. Then the group settles, and one more change of leader follows.
    Every minute of the run ran or was reported, none twice and none both; nothing ran
    twice. Before the marks, :01 to :03 were neither (wait 0)."""
    seeds = itertools.count(7)
    # the election timers draw from fixed seeds, so the run is the same every time
    monkeypatch.setattr(_ha, 'random', types.SimpleNamespace(Random=lambda: random.Random(next(seeds))))
    auto.form(seed)
    auto.past_the_hold()
    _tasks(loop, *range(60))
    loop.wall = HOUR + 0.5
    run = _driven(auto, loop, monkeypatch)
    run.step(1)
    assert run.passes == [('a', 0, run.acting('a'))] and loop.ran == ['m00']
    run.step(wait)

    cut = []
    for _ in range(6):
        term = run.leaders[-1]
        cut.append(term)
        # healed for one renewal round first: the others take the voter config of the
        # new leader (the harness pulls no data, so a member that never led stays behind)
        run.step(T.R + 1)
        auto.isolate(term[0])
        run.step(3 * BOUND, until=lambda: run.leaders[-1] not in cut)
        auto.heal()
        assert run.leaders[-1] not in cut, run.leaders
    run.step(4 * 60)
    settled = run.leaders[-1]
    auto.isolate(settled[0])
    run.step(3 * BOUND, until=lambda: run.leaders[-1] != settled)
    auto.heal()
    assert run.leaders[-1] != settled
    run.step(3 * 60)

    # the pattern: terms that acted and never got to a pass, two of them in a row
    passed = {(n, at) for n, _m, at in run.passes}
    idle = [t for t in run.leaders if t not in passed]
    assert any(a in idle and b in idle for a, b in zip(run.leaders, run.leaders[1:])), run.leaders
    if wait:
        assert any(why == LOST for _k, _n, why in loop.said), loop.said
    ran = collections.Counter(loop.ran)
    said = collections.Counter(n for _k, names, _w in loop.said for n in names)
    last = max(m for _n, m, _at in run.passes)
    left = {f'm{m:02}': ran[f'm{m:02}'] + said[f'm{m:02}'] for m in range(last + 1)}
    assert set(left.values()) == {1}, (left, loop.said, run.passes, run.leaders)
    assert max(ran.values()) == 1
