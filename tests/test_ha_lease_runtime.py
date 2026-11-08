"""What runs the lease in a process, and what goes with it (#625 stage 2): the lease
loop and its watchdog, the one-shot boot gates, the group's time zone, the reach of an
instance, and what a renewal round and a vote cost.

The loops are greenlets in the product. Nothing of them runs in a test unless the test
starts it (tests/conftest.py), and every one that is started here is ended here.

MK Oct 2026 (#625)
"""
import ast
import os
import re
import subprocess
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import gevent
import gevent.monkey
import pytest

from pegaprox.core import ha as _ha
from pegaprox.core import ha_vote as hv
from test_ha_api import ADMIN_PW
from test_ha_members import IDS, _built, _promote, _sync, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_SLEEP = gevent.monkey.get_original('time', 'sleep')


# --- the loops --------------------------------------------------------------------------

def test_nothing_of_the_lease_runs_by_itself_in_a_test(auto, seed):
    """conftest leaves every queued call in the queue and starts no loop: what a test
    does not deliver does not happen, in whatever state file a later test holds."""
    before = {t.name for t in threading.enumerate()}
    auto.form(seed)
    auto.advance(T.R + 1)
    with auto.at('a') as ha:
        ha.lease_step()
    rt = auto.rt('a')
    assert len(rt.outbox) == 2 and auto.ha._lease_dispatch(rt) is None and len(rt.outbox) == 2
    names = {t.name for t in threading.enumerate()} - before
    assert not [n for n in names if n.startswith('ha-')], names


def test_lease_start_starts_the_loops_once_and_only_with_lease_state(auto, seed, monkeypatch):
    ha = auto.ha
    spawned, dogs = [], []
    monkeypatch.setattr(ha, '_lease_spawn', lambda fn, name: spawned.append(name))
    monkeypatch.setattr(ha, '_watchdog_start', dogs.append)
    auto.pair(seed)
    with auto.at('a'):
        # a manual group that never switched: no loop, no watchdog, not even a runtime
        assert ha.lease_start() is False and spawned == [] and dogs == []
    auto.switch_on()
    spawned.clear(), dogs.clear()
    with auto.at('a'):
        rt = ha._rt()
        rt.loop = False
        assert ha.lease_start() is True
        assert spawned == ['ha-lease', 'ha-cv-tick'] and dogs == [rt]
        assert ha.lease_start() is False and len(spawned) == 2


def test_start_loop_starts_the_lease_loop_too(monkeypatch):
    started = []
    monkeypatch.setattr(_ha, '_loop_started', False)
    monkeypatch.setattr(_ha, '_loop', lambda: None)
    monkeypatch.setattr(_ha, 'lease_start', lambda: started.append(1))
    _ha.start_loop()
    _ha.start_loop()
    assert started == [1]


def test_the_lease_loop_runs_its_passes_and_ends_when_told(auto, seed, monkeypatch):
    ha = auto.ha
    auto.form(seed)
    passes = []
    monkeypatch.setattr(ha, 'lease_step', lambda: passes.append(1) or 0.01)
    with auto.at('a'):
        rt = ha._rt()
        loop = gevent.spawn(ha._lease_loop, rt)
        tick = gevent.spawn(ha._cv_loop, rt)
        for _ in range(250):
            if len(passes) >= 5:
                break
            gevent.sleep(0.02)
        assert len(passes) >= 5 and not loop.dead and not tick.dead
        ha.lease_stop()
        gevent.joinall([loop, tick], timeout=3)
    assert loop.dead and tick.dead and loop.exception is None and tick.exception is None
    n = len(passes)
    gevent.sleep(0.1)
    assert len(passes) == n


def test_a_pass_of_the_loop_does_not_wake_the_loop_again(auto, seed):
    """A call into the node wakes the loop so it works out its next pass. The pass
    itself must not, or the loop spins."""
    auto.form(seed)
    rt = auto.rt('a')
    rt.wake.clear()
    with auto.at('a') as ha:
        wait = ha.lease_step()
    assert not rt.wake.is_set() and 0 < wait <= T.R
    with auto.at('b') as ha:
        auto.rt('b').wake.clear()
        ha.lease_request(IDS['a'], 'renew', {'epoch': 1, 'leader': IDS['a'], 'lease_s': 20})
        assert auto.rt('b').wake.is_set()


def test_the_loop_notes_how_late_the_hub_let_it_run(auto, seed, monkeypatch):
    ha = auto.ha
    auto.form(seed)
    monkeypatch.setattr(ha, 'lease_step', lambda: 0.05)
    with auto.at('a'):
        rt = ha._rt()
        loop = gevent.spawn(ha._lease_loop, rt)
        gevent.sleep(0.12)
        before = rt.lag_max
        REAL_SLEEP(1.5)                  # the hub is blocked: nothing runs
        gevent.sleep(0.12)
        ha.lease_stop()
        loop.join(timeout=3)
        assert before < 1.0 < rt.lag_max and rt.boot_lag_max == rt.lag_max
        assert ha.lease_status()['hub_lag_max'] == round(rt.lag_max, 3)


def test_the_etag_tick_runs_on_the_leader_only_while_it_may_act(auto, seed, monkeypatch):
    ha = auto.ha
    auto.form(seed)
    ticks = []
    monkeypatch.setattr(ha, 'cv_tick', lambda: ticks.append(auto.g.name()) or 'clean')
    monkeypatch.setattr(ha, 'CV_TICK', 0.02)
    for n, want in (('a', True), ('b', False)):
        ticks.clear()
        with auto.at(n):
            rt = ha._rt()
            rt.stop = False
            rt.halt.clear()
            tick = gevent.spawn(ha._cv_loop, rt)
            gevent.sleep(0.15)
            ha.lease_stop()
            tick.join(timeout=3)
        assert bool(ticks) is want and tick.dead


# --- the watchdog -----------------------------------------------------------------------

def _leader_like(lease_until, acting=True, dead=False, lease=True):
    return types.SimpleNamespace(lease_until=lease_until, dead=dead, t=T,
                                 acting_process=lambda: acting, lease_mode=lambda: lease)


def test_the_watchdog_goes_by_the_lease_and_the_grace():
    rt = _ha._LeaseRuntime('x' * 32)
    now = 1000.0
    assert _ha._watchdog_due(rt, now) == ''                       # no node at all
    rt.node = _leader_like(now - 100)
    assert _ha._watchdog_due(rt, now) == ''                       # not armed: still starting
    rt.armed = True
    assert _ha._watchdog_due(rt, now) != ''
    rt.node = _leader_like(now - T.G + 0.1)
    assert _ha._watchdog_due(rt, now) == ''                       # inside the grace
    rt.node = _leader_like(now - T.G - 0.1)
    assert 'lease ran out' in _ha._watchdog_due(rt, now)
    rt.node = _leader_like(now - 100, acting=False)
    assert _ha._watchdog_due(rt, now) == ''                       # a standby has no lease to lose
    rt.node = _leader_like(now - 100, lease=False)
    assert _ha._watchdog_due(rt, now) == ''                       # nor has a manual active
    rt.node = _leader_like(now - 100, dead=True)
    assert _ha._watchdog_due(rt, now) == ''                       # the way out is taken already
    # ... unless it does not come: the restart thread never ran
    rt.exit_at = now - T.G + 0.1
    assert _ha._watchdog_due(rt, now) == ''
    rt.exit_at = now - T.G - 0.1
    assert 'did not come' in _ha._watchdog_due(rt, now)


def test_the_watchdog_fires_from_its_own_thread_while_the_hub_is_blocked(monkeypatch):
    """The lease loop cannot run when the hub is stuck. The watchdog is a native thread
    with the real sleep: it gets there all the same."""
    left = []
    monkeypatch.setattr(_ha, '_watchdog_leave', left.append)
    monkeypatch.setattr(_ha, 'WATCHDOG_TICK', 0.05)
    rt = _ha._LeaseRuntime('y' * 32)
    rt.armed = True
    rt.node = _leader_like(hv.ha_clock() - T.G - 1)
    before = threading.active_count()

    _ha._watchdog_start(rt)
    # not gevent.sleep: the hub does not get a turn
    for _ in range(100):
        if left:
            break
        REAL_SLEEP(0.05)

    assert left == ['the lease ran out and the process did not step down']
    # gevent's threading never saw it: a thread of the system, not of the hub
    assert threading.active_count() == before


def test_a_watchdog_with_nothing_to_do_ends_with_its_runtime(monkeypatch):
    left = []
    monkeypatch.setattr(_ha, '_watchdog_leave', left.append)
    monkeypatch.setattr(_ha, 'WATCHDOG_TICK', 0.02)
    rt = _ha._LeaseRuntime('z' * 32)
    rt.node = _leader_like(hv.ha_clock() + 100)
    rt.armed = True
    done = []
    sleep = REAL_SLEEP

    def run():
        _ha._watchdog_run(rt, sleep)
        done.append(1)
    gevent.monkey.get_original('_thread', 'start_new_thread')(run, ())
    REAL_SLEEP(0.2)
    assert left == [] and done == []
    rt.stop = True
    for _ in range(100):
        if done:
            break
        REAL_SLEEP(0.05)
    assert done == [1] and left == []


_LEAVE = '''
import os, subprocess, sys, time
sys.argv = ['x']
from pegaprox.core import ha
child = subprocess.Popen(['sleep', '60'], start_new_session=True)
ha.register_child_group(child.pid)
print(child.pid, flush=True)
ha._watchdog_leave('the lease ran out and the process did not step down')
'''


def test_the_watchdog_kills_the_children_says_one_line_and_exits_with_75(tmp_path):
    env = dict(os.environ, PEGAPROX_SUPERVISED='1', PYTHONPATH=ROOT)
    r = subprocess.run([sys.executable, '-c', _LEAVE], cwd=str(tmp_path), env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == _ha.EXIT_RESTART == 75, (r.returncode, r.stderr)
    assert r.stderr.strip().endswith(
        '[HA] watchdog: the lease ran out and the process did not step down - leaving')
    # with the time in front: the journal of a plain start has none of its own
    assert re.search(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[HA\] watchdog: ', r.stderr, re.M)
    pid = int(r.stdout.split()[0])
    for _ in range(50):
        if not os.path.exists(f'/proc/{pid}'):
            break
        REAL_SLEEP(0.05)
    assert not os.path.exists(f'/proc/{pid}') or 'Z' in open(f'/proc/{pid}/stat').read().split(')')[1]


def test_the_watchdog_arms_with_the_first_majority_round_of_the_lease_loop(auto, seed):
    auto.form(seed)
    rt = auto.rt('a')
    assert rt.loop and rt.armed
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        ha.check_peer_at_boot()
        fresh = ha._rt()
        # the boot round reached its majority, and the loop has not started: a start-up
        # that outlasts this lease must not be taken for a hub that hangs
        assert fresh.acting and not fresh.armed
        ha.lease_start()
    auto.advance(T.R)
    auto.step('a')
    assert auto.rt('a').armed


def test_the_watchdog_lets_a_leader_be_that_went_back_to_manual_mode(auto, seed):
    """It stops renewing then, and its last lease_until stays where the last round put
    it. Read as a lease that ran out, that kills a healthy manual active some twenty
    seconds after automatic failover was switched off."""
    from test_ha_api import ADMIN_PW
    ha = auto.ha
    auto.form(seed)
    auto.run(T.L, dt=1.0)
    rt = auto.rt('a')
    assert rt.armed is True and ha._watchdog_due(rt, auto.clock['a']) == ''

    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['result'] == 'off', r.data
    auto.run(2 * T.R, dt=1.0)
    assert all(auto.mode(n) == 'manual' for n in 'abc') and auto.file('a')['role'] == 'active'
    # disarmed with the lease, and the node says so too
    assert rt.armed is False and not rt.node.lease_mode()

    left = []
    for _ in range(60):
        auto.run(1.0, dt=1.0)
        ha._watchdog_run(rt, lambda seconds: setattr(rt, 'stop', True), leave=left.append)
        rt.stop = False
    assert left == [] and rt.node.lease_until + rt.node.t.G < auto.clock['a']
    # even if something armed it again: no lease is in force on this instance
    rt.armed = True
    assert ha._watchdog_due(rt, auto.clock['a']) == ''
    with auto.at('a') as h:
        assert h.is_active() and h.role() == 'active' and h.mode() == 'manual'


def test_the_loops_end_with_the_group(auto, seed, monkeypatch):
    """An active that unpairs does not restart: its lease loop, its etag tick and its
    watchdog would run on for as long as the process does."""
    from test_ha_api import ADMIN_PW
    from test_ha_members import _post
    ha = auto.ha
    auto.form(seed)
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    spawned, dogs = [], []
    monkeypatch.setattr(ha, '_lease_spawn', lambda fn, name: spawned.append((name, gevent.spawn(fn))))
    monkeypatch.setattr(ha, '_watchdog_start', dogs.append)
    monkeypatch.setattr(ha, 'CV_TICK', 0.05)
    monkeypatch.setattr(ha, 'LEASE_IDLE', 0.05)
    with auto.at('a') as h:
        rt = h._rt()
        rt.loop = False                  # the harness marked it started and spawned nothing
        assert h.lease_start() is True
        assert [name for name, _g in spawned] == ['ha-lease', 'ha-cv-tick'] and dogs == [rt]

        assert _post(auto.admin, '/api/ha/unpair', {'confirm': 'UNPAIR',
                                                    'user_password': ADMIN_PW}).status_code == 200
        assert auto.file('a')['role'] == 'standalone'
        gevent.joinall([g for _n, g in spawned], timeout=3)
    try:
        assert rt.stop is True and all(g.dead for _name, g in spawned)
        assert IDS['a'] not in ha._rts
        # the watchdog thread goes by the same flag
        done = []
        ha._watchdog_run(rt, lambda seconds: done.append(seconds), leave=done.append)
        assert done == []
    finally:
        rt.stop = True
        rt.wake.set()
        rt.halt.set()
        gevent.joinall([g for _n, g in spawned], timeout=2)


def test_an_instance_the_group_took_out_runs_no_lease_any_more(auto, seed):
    auto.form(seed)
    rt = auto.rt('c')
    assert rt is not None and not rt.stop
    with auto.at('c') as ha:
        assert ha._mark_removed(IDS['a'], 1) == 'standby'
    assert rt.stop and auto.rt('c') is None


# --- what is started once at boot -----------------------------------------------------------

def test_when_active_runs_at_once_later_or_never(monkeypatch):
    ran, spawned = [], []
    monkeypatch.setattr(_ha, '_lease_spawn', lambda fn, name: spawned.append((fn, name)))
    state = {'active': True, 'acting': True}
    monkeypatch.setattr(_ha, 'is_active', lambda: state['active'])
    monkeypatch.setattr(_ha, 'acting_process', lambda: state['acting'])

    assert _ha.when_active(lambda: ran.append('now'), 'x') is True and ran == ['now'] and not spawned

    # a standby: never, and nothing waits for it
    state.update(active=False, acting=False)
    assert _ha.when_active(lambda: ran.append('standby'), 'x') is False and not spawned

    # the leader's process during the takeover wait: once it may act
    state.update(active=False, acting=True)
    assert _ha.when_active(lambda: ran.append('later'), 'waiter') is False
    assert ran == ['now'] and spawned[0][1] == 'waiter'
    naps = []

    def nap(seconds):
        naps.append(seconds)
        if len(naps) == 3:
            state['active'] = True
    monkeypatch.setattr(_ha.time, 'sleep', nap)
    spawned[0][0]()
    assert ran == ['now', 'later'] and naps == [1, 1, 1]

    # the process stops leading before it ever may: the waiter ends without running it
    state.update(active=False, acting=True)
    _ha.when_active(lambda: ran.append('lost'), 'waiter')

    def lose(seconds):
        state['acting'] = False
    monkeypatch.setattr(_ha.time, 'sleep', lose)
    spawned[1][0]()
    assert ran == ['now', 'later']


@pytest.fixture
def taking_over(monkeypatch):
    """The leader's process of an automatic group while the takeover wait is on."""
    state = {'active': False, 'acting': True}
    monkeypatch.setattr(_ha, 'is_active', lambda: state['active'])
    monkeypatch.setattr(_ha, 'acting_process', lambda: state['acting'])
    waiting = []
    monkeypatch.setattr(_ha, 'when_active', lambda fn, name: waiting.append((fn, name)) and False)
    state['waiting'] = waiting
    return state


def test_the_ha_monitor_of_a_new_leader_starts_once_it_may_act(taking_over):
    """B1: it returned for good on a leader that was still taking over, and nothing
    ever started it again."""
    from pegaprox.core.manager import PegaProxManager
    fake = MagicMock()
    fake.ha_thread = None
    fake.start_ha_monitor = lambda: PegaProxManager.start_ha_monitor(fake)

    PegaProxManager.start_ha_monitor(fake)

    fake._ha_discover_fallback_hosts.assert_not_called()
    assert [name for _fn, name in taking_over['waiting']] == ['ha-monitor-start']
    # the wait is over: the same start, and now it goes through
    taking_over['active'] = True
    fake._ha_discover_fallback_hosts.side_effect = RuntimeError('past the gate')
    with pytest.raises(RuntimeError, match='past the gate'):
        taking_over['waiting'][0][0]()


def test_the_ha_monitor_loop_waits_for_the_lease_and_ends_with_the_lead(taking_over, monkeypatch):
    import pegaprox.core.manager as mgrmod
    naps = []

    def nap(seconds):
        naps.append(seconds)
        if len(naps) == 3:
            taking_over['active'] = True
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(sleep=nap))
    fake = MagicMock()
    fake.ha_enabled = True
    fake.stop_event.is_set.return_value = False
    fake._ha_interval.return_value = 0
    checks = []

    def check():
        checks.append(len(naps))
        if len(checks) == 2:
            # the lease is lost for good: no longer the leader's process
            taking_over.update(active=False, acting=False)
    fake._ha_check_nodes.side_effect = check

    mgrmod.PegaProxManager._ha_monitor_loop(fake)

    # three passes of waiting without a check, two checks, then the end
    assert naps == [1, 1, 1] and checks == [3, 3]


def test_the_plan_reset_and_the_plugin_backgrounds_wait_for_the_lease(taking_over, monkeypatch):
    import pegaprox.api.plugins as plugins
    import pegaprox.background.site_recovery as sr
    reset, spawned = [], []
    monkeypatch.setattr(sr, 'recover_orphan_runs', lambda: reset.append(1))
    monkeypatch.setattr(gevent, 'spawn', lambda fn, *a: spawned.append(fn))
    mod = types.SimpleNamespace(start_background_tasks=lambda: reset.append('plugin'))
    monkeypatch.setattr(plugins, '_loaded_plugins', {'p1': mod})

    sr.start_heartbeat()
    plugins.start_plugin_backgrounds()

    assert reset == [] and spawned == [sr.heartbeat_loop]
    assert [name for _fn, name in taking_over['waiting']] == ['sr-orphan-cleanup', 'plugin-backgrounds']
    taking_over['active'] = True
    for fn, _name in taking_over['waiting']:
        fn()
    assert reset == [1, 'plugin']


def test_in_a_manual_group_the_boot_starters_are_what_they_were(monkeypatch):
    """acting_process() and is_active() say the same there: nothing is ever deferred."""
    import pegaprox.api.plugins as plugins
    import pegaprox.background.site_recovery as sr
    deferred, reset = [], []
    monkeypatch.setattr(_ha, 'when_active', lambda fn, name: deferred.append(name))
    monkeypatch.setattr(sr, 'recover_orphan_runs', lambda: reset.append(1))
    monkeypatch.setattr(gevent, 'spawn', lambda fn, *a: None)
    mod = types.SimpleNamespace(start_background_tasks=lambda: reset.append('plugin'))
    monkeypatch.setattr(plugins, '_loaded_plugins', {'p1': mod})

    sr.start_heartbeat()
    plugins.start_plugin_backgrounds()

    assert deferred == [] and reset == [1, 'plugin']


@pytest.fixture
def plugin(monkeypatch):
    import pegaprox.api.plugins as plugins
    started = []
    mod = types.SimpleNamespace(start_background_tasks=lambda: started.append('started'))
    monkeypatch.setattr(plugins, '_loaded_plugins', {'probe': mod})
    return started


def test_a_leader_on_disk_that_is_not_the_acting_process_starts_no_plugin_background(
        auto, seed, plugin, monkeypatch):
    """A plugin's background task asks nobody. Where this instance may not act and its
    process did not come up to act either, nothing of it starts: a leader on disk whose
    node could not be built, and a state file that says automatic under a release that
    does not run it."""
    from pegaprox.api.plugins import start_plugin_backgrounds
    ha = auto.ha
    auto.form(seed)
    ha._rts.pop(IDS['a'], None)
    real = ha._signer

    def signer():
        if auto.g.name() == 'a':
            raise ha.HaError('The key pair in the HA state file cannot be read (ValueError)')
        return real()
    monkeypatch.setattr(ha, '_signer', signer)
    with auto.at('a') as h:
        assert h.check_peer_at_boot() == 'no lease state to run'
        # what main() asks before it calls it
        assert h.role() == 'active' and not h.is_standby()
        assert not h.is_active() and not h.acting_process()
        start_plugin_backgrounds()
    assert plugin == []

    monkeypatch.setattr(ha, '_signer', real)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    ha._rts.clear()
    with auto.at('a') as h:
        h.check_peer_at_boot()
        assert not h.is_standby() and not h.is_active() and not h.acting_process()
        start_plugin_backgrounds()
    assert plugin == []


def test_the_plugin_backgrounds_start_once_the_new_leader_may_act(auto, seed, plugin, monkeypatch):
    from pegaprox.api.plugins import start_plugin_backgrounds
    ha = auto.ha
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R + 2, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    waiting = []
    monkeypatch.setattr(ha, '_lease_spawn', lambda fn, name: waiting.append((fn, name)))
    with auto.at(winner) as h:
        assert h.acting_process() and not h.is_active()
        start_plugin_backgrounds()
        assert plugin == [] and [name for _fn, name in waiting] == ['plugin-backgrounds']
        with pytest.MonkeyPatch.context() as mp:
            # the waiter looks once a second: the group's clocks turn with it
            mp.setattr(ha.time, 'sleep', lambda seconds: auto.run(seconds, dt=1.0))
            waiting[0][0]()
        assert h.is_active()
    assert plugin == ['started']


def _calls_attr(func, name):
    return [n for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == name and isinstance(n.func.value, ast.Name) and n.func.value.id == 'ha']


@pytest.mark.parametrize('rel,qualname', [
    ('pegaprox/core/manager.py', 'PegaProxManager.start_ha_monitor'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_monitor_loop'),
    ('pegaprox/background/site_recovery.py', 'start_heartbeat'),
    ('pegaprox/api/plugins.py', 'start_plugin_backgrounds'),
])
def test_the_one_shot_boot_gates_ask_for_the_acting_process(rel, qualname):
    from test_ha_loop_gates import _find, _parse
    func = _find(_parse(rel), qualname)
    assert _calls_attr(func, 'acting_process'), f'{qualname} never asks ha.acting_process()'
    assert _calls_attr(func, 'is_active'), f'{qualname} never asks ha.is_active()'


# --- the group's time zone ------------------------------------------------------------------

FAR = 'Pacific/Kiritimati'          # UTC+14: never the zone of the machine this runs on


def _in_zone(name):
    return datetime.now(ZoneInfo(name)).replace(tzinfo=None)


def test_an_instance_of_its_own_evaluates_schedules_as_before(monkeypatch):
    """Byte for byte: datetime.now(), no zone, no argument."""
    marker = object()
    asked = []

    class _Now:
        @staticmethod
        def now(*args):
            asked.append(args)
            return marker
    monkeypatch.setattr(_ha, 'datetime', _Now)
    # even with a zone in the file: it has no group
    _ha._update(timezone=FAR)
    assert _ha.role() == 'standalone' and _ha.group_timezone() == ''
    assert _ha.schedule_now() is marker and asked == [()]


def test_a_group_formed_on_this_release_takes_the_zone_of_the_instance_that_formed_it(
        group, seed, monkeypatch):
    g = group
    monkeypatch.setattr(g.ha, '_local_zone', {'name': 'Europe/Vienna'})
    _built(g, seed, 'bc')

    for n in 'abc':
        assert g.state(n)['timezone'] == 'Europe/Vienna'
        with g.at(n) as ha:
            assert ha.group_timezone() == 'Europe/Vienna'
            assert abs((ha.schedule_now() - _in_zone('Europe/Vienna')).total_seconds()) < 2
            assert ha.schedule_now().tzinfo is None
            assert ha.public_status()['timezone'] == 'Europe/Vienna'
    # a member in another zone goes by the group's all the same: that is the point
    monkeypatch.setattr(g.ha, '_local_zone', {'name': 'America/New_York'})
    with g.at('b') as ha:
        assert ha.local_timezone() == 'America/New_York' and ha.group_timezone() == 'Europe/Vienna'
        assert ha.public_status()['timezone_local'] == 'America/New_York'


def test_a_group_from_before_has_no_zone_until_the_leader_sets_one(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    for n in 'abc':
        assert 'timezone' not in g.state(n)
        with g.at(n) as ha:
            # each instance by its own clock, as it was
            assert ha.group_timezone() == '' and abs((ha.schedule_now() - datetime.now()).total_seconds()) < 2

    with g.at('b'):
        r = admin.put('/api/ha/timezone', json={'timezone': FAR})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    with g.at('a') as ha:
        for bad in ('Mars/Olympus', '../etc/passwd', '', 5, 'Europe/Vienna; DROP'):
            assert admin.put('/api/ha/timezone', json={'timezone': bad}).status_code == 400, bad
        before = ha.snapshot_etag()
        r = admin.put('/api/ha/timezone', json={'timezone': FAR})
        assert r.status_code == 200 and r.get_json() == {'success': True, 'timezone': FAR, 'changed': True}
        # the members hear of it with their next poll: the etag moved
        assert ha.snapshot_etag() != before and ha.snapshot_meta()['timezone'] == FAR
        assert admin.put('/api/ha/timezone', json={'timezone': FAR}).get_json()['changed'] is False
        assert abs((ha.schedule_now() - _in_zone(FAR)).total_seconds()) < 2
        assert abs((ha.schedule_now() - datetime.now()).total_seconds()) > 3600
    for n in 'bc':
        assert _sync(g, admin, n) == 'applied'
        assert g.state(n)['timezone'] == FAR
        with g.at(n) as ha:
            assert abs((ha.schedule_now() - _in_zone(FAR)).total_seconds()) < 2


def test_an_unpaired_instance_goes_by_its_own_clock_again(group, seed, monkeypatch):
    from test_ha_api import ADMIN_PW
    from test_ha_members import _post
    g = group
    monkeypatch.setattr(g.ha, '_local_zone', {'name': FAR})
    admin = _built(g, seed, 'b')
    assert g.state('b')['timezone'] == FAR
    monkeypatch.setattr(g.ha, '_local_zone', {'name': ''})
    with g.at('b') as ha:
        assert _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW}).status_code == 200
        assert 'timezone' not in ha._load() and ha.group_timezone() == ''
        assert abs((ha.schedule_now() - datetime.now()).total_seconds()) < 2


# --- which zone this instance runs in ---------------------------------------------------------

@pytest.fixture
def process_zone(monkeypatch):
    """Set the zone this process runs by, the way a service file or a shell does."""
    def set_tz(value):
        if value is None:
            monkeypatch.delenv('TZ', raising=False)
        else:
            monkeypatch.setenv('TZ', value)
        time.tzset()
        monkeypatch.setattr(_ha, '_local_zone', {'name': None})
    yield set_tz
    monkeypatch.undo()
    time.tzset()


def _etc(monkeypatch, localtime, timezone):
    """What the two files of the system say: where /etc/localtime points, and the name
    in /etc/timezone (None: there is no such file)."""
    import builtins
    import io
    real_open, real_path = builtins.open, os.path.realpath

    def fake_open(path, *a, **kw):
        if path == '/etc/timezone':
            if timezone is None:
                raise FileNotFoundError(path)
            return io.StringIO(timezone + '\n')
        return real_open(path, *a, **kw)

    def fake_realpath(path, *a, **kw):
        return localtime if path == '/etc/localtime' else real_path(path, *a, **kw)
    monkeypatch.setattr(_ha, 'open', fake_open, raising=False)
    monkeypatch.setattr(_ha.os.path, 'realpath', fake_realpath)


def test_the_zone_of_this_instance_is_asked_the_way_libc_decides_it(process_zone, monkeypatch):
    # TZ decides when it is set, whatever the files say
    _etc(monkeypatch, '/usr/share/zoneinfo/Asia/Tokyo', 'Asia/Tokyo')
    process_zone('America/New_York')
    assert _ha.local_timezone() == 'America/New_York'
    process_zone(':America/New_York')
    assert _ha.local_timezone() == 'America/New_York'
    # without it, where /etc/localtime points - and the process runs by that
    process_zone(None)
    here = time.strftime('%z')
    for name in ('Europe/Vienna', 'America/New_York', 'Asia/Tokyo', 'UTC'):
        _etc(monkeypatch, f'/usr/share/zoneinfo/{name}', 'Pacific/Kiritimati')
        monkeypatch.setattr(_ha, '_local_zone', {'name': None})
        want = datetime.now(ZoneInfo(name)).strftime('%z') == here
        assert (_ha.local_timezone() == name) is want, name


def test_a_tz_that_names_no_zone_is_a_zone_without_a_name(process_zone, monkeypatch):
    """A POSIX string: libc runs by it, and no file says what the process runs by. The
    files of the system are not asked then."""
    _etc(monkeypatch, '/usr/share/zoneinfo/Europe/Vienna', 'Europe/Vienna')
    for value in ('<PGX>-7', 'CET-1CEST,M3.5.0,M10.5.0/3', '', '/usr/share/zoneinfo/Europe/Vienna'):
        process_zone(value)
        assert _ha.local_timezone() == '', value


def test_a_stale_etc_timezone_does_not_name_the_zone(process_zone, monkeypatch):
    """libc never reads /etc/timezone, and nothing keeps it in step with /etc/localtime
    any more. It is asked last, and a name there counts only when the process runs by
    that zone."""
    process_zone(None)
    here = os.path.realpath('/etc/localtime').partition('zoneinfo/')[2]
    if not here:
        pytest.skip('this machine names no zone in /etc/localtime')
    stale = 'America/New_York' if not _ha._runs_by(ZoneInfo('America/New_York')) else 'Asia/Tokyo'
    _etc(monkeypatch, f'/usr/share/zoneinfo/{here}', stale)
    monkeypatch.setattr(_ha, '_local_zone', {'name': None})
    assert _ha.local_timezone() == here
    # /etc/localtime a plain file: the stale name is all there is, and it is not taken
    _etc(monkeypatch, '/etc/localtime', stale)
    monkeypatch.setattr(_ha, '_local_zone', {'name': None})
    assert _ha.local_timezone() == ''
    # the right name in it is
    _etc(monkeypatch, '/etc/localtime', here)
    monkeypatch.setattr(_ha, '_local_zone', {'name': None})
    assert _ha.local_timezone() == here


def test_a_zone_that_only_shares_todays_offset_is_not_the_zone_of_the_process(process_zone):
    process_zone('Africa/Johannesburg')              # two hours east of UTC all year
    assert _ha._runs_by(ZoneInfo('Africa/Johannesburg'))
    # the same offset for half of the year, and another for the rest
    assert not _ha._runs_by(ZoneInfo('Europe/Vienna'))
    assert not _ha._runs_by(ZoneInfo('UTC'))


def test_a_group_formed_under_a_tz_without_a_name_has_no_zone(group, seed, process_zone):
    """It used to take the zone of a file libc had not read, and every schedule of the
    instance that formed the group jumped the moment the first standby paired."""
    g = group
    process_zone('<PGX>-7')
    with g.at('a') as ha:
        assert abs((ha.schedule_now() - datetime.now()).total_seconds()) < 2
    _built(g, seed, 'b')
    with g.at('a') as ha:
        assert 'timezone' not in ha._load() and ha.group_timezone() == ''
        assert abs((ha.schedule_now() - datetime.now()).total_seconds()) < 2


@pytest.mark.parametrize('name', ['localtime', 'posixrules', 'Factory', 'posix/Europe/Vienna',
                                  'right/Europe/Vienna'])
def test_the_groups_zone_is_the_name_of_a_place(group, seed, name):
    """localtime is each host's own zone - what the group's zone is there to end - and
    the others are no zone, or one that counts leap seconds."""
    g = group
    admin = _built(g, seed, 'b')
    assert _ha._zone(name) is None
    with g.at('a') as ha:
        r = admin.put('/api/ha/timezone', json={'timezone': name})
        assert r.status_code == 400, r.data
        assert 'timezone' not in ha._load()
    # and a member does not take it from a leader that sends it either
    with g.at('b') as ha:
        ha._adopt_group({'instance_id': IDS['a'], 'epoch': 1, 'timezone': name})
        assert 'timezone' not in ha._load()


# --- the zone and the switch to automatic failover ---------------------------------------------

def test_the_switch_gives_a_group_without_a_zone_the_zone_of_its_leader(auto, seed):
    """A group from before the group zone. Its schedules ran by the leader's clock so
    far and keep those hours, whichever member leads from now on."""
    from test_ha_api import _audit
    ha = auto.ha
    ha._local_zone['name'] = ''
    auto.pair(seed)
    assert 'timezone' not in auto.file('a')
    ha._local_zone['name'] = 'Europe/Vienna'

    r = auto.switch_on()

    assert r.status_code == 200, r.data
    assert auto.file('a')['timezone'] == 'Europe/Vienna'
    assert [e for e in _audit('ha.timezone_changed') if 'Europe/Vienna' in e['details']]
    for n in 'bc':
        assert _sync(auto.g, auto.admin, n) in ('applied', 'unchanged')
        assert auto.file(n)['timezone'] == 'Europe/Vienna'
    # the leader goes, and the member that takes over evaluates schedules as it did
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L + T.R, until=lambda: auto.holders() != [])
    with auto.at(auto.holders()[0]) as h:
        assert h.group_timezone() == 'Europe/Vienna'


def test_a_group_without_a_zone_does_not_switch_while_the_leaders_zone_cannot_be_told(auto, seed):
    from test_ha_api import ADMIN_PW
    ha = auto.ha
    ha._local_zone['name'] = ''
    auto.pair(seed)

    r = auto.switch_on()

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED', r.data
    found = {f['code']: f for f in r.get_json()['findings']}
    assert found['NO_GROUP_ZONE']['level'] == 'block' and auto.mode('a') == 'manual'
    # a block is nothing a tick takes away
    r = auto.put('a', '/api/ha/mode', {'mode': 'auto', 'user_password': ADMIN_PW,
                                       'accept': ['NO_GROUP_ZONE']})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'

    assert auto.put('a', '/api/ha/timezone', {'timezone': 'America/New_York'}).status_code == 200
    assert auto.switch_on().status_code == 200
    assert auto.file('a')['timezone'] == 'America/New_York' and auto.leader() == 'a'


def test_the_status_shows_the_zone_of_each_member_and_a_group_that_runs_without_one(
        auto, seed, monkeypatch):
    ha = auto.ha
    zones = {'a': 'Europe/Vienna', 'b': 'America/New_York', 'c': 'America/New_York'}
    auto.form(seed)
    monkeypatch.setattr(ha, 'local_timezone', lambda: zones.get(auto.g.name(), ''))
    auto.watch('a')
    with auto.at('a') as h:
        status = h.public_status()
        rows = {m['instance_id']: m['zone'] for m in status['auto']['members']}
        assert rows == {IDS['b']: 'America/New_York', IDS['c']: 'America/New_York'}
        assert status['timezone'] == 'Europe/Vienna'
        # members in another zone are allowed (Q11): something to know, nothing to tick
        assert {(f['code'], f['level'], f['member']) for f in status['auto']['findings']} == {
            ('TZ_MISMATCH', 'info', IDS['b']), ('TZ_MISMATCH', 'info', IDS['c'])}
        # a state from before the switch took a zone: said, and nothing blocks
        h._update(timezone=None)
        found = [f for f in h.auto_findings() if f['code'] == 'NO_GROUP_ZONE']
        assert [f['level'] for f in found] == ['warn']


# --- the last-run stamps move with the zone -----------------------------------------------------

class _Clock:
    """ha.datetime with now() at an instant the test sets."""

    def __init__(self, monkeypatch):
        self.at = None
        clock = self

        class Fixed(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock.at.astimezone(tz) if tz is not None else clock.at.astimezone().replace(tzinfo=None)
        monkeypatch.setattr(_ha, 'datetime', Fixed)


def _stamps(db):
    cur = db.conn.cursor()
    out = {}
    for table, key, col in _ha._SCHEDULE_STAMPS:
        cur.execute(f'SELECT "{key}", "{col}" FROM "{table}"')
        for row in cur.fetchall():
            out[(table, col, str(row[0]))] = row[1]
    return out


def _rows(db):
    """One row in each table whose stamp a schedule compares with the group's clock, as
    the schedulers of an instance in Europe/Vienna wrote them at 10:00 there."""
    c = db.conn
    c.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_value, schedule, last_run_at, "
              "created_at) VALUES ('p1', 'c1', 'hourly', 'x', 'hourly', '2026-10-05T10:00:30.250000', 'x')")
    c.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_value, schedule, created_at) "
              "VALUES ('p2', 'c1', 'never ran', 'x', 'hourly', 'x')")
    c.execute("INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, last_run) "
              "VALUES ('t1', 'c1', 'hourly', 'start', '{}', '2026-10-05T10:15:10')")
    c.execute("INSERT INTO scheduled_actions (cluster_id, vmid, action, schedule_type, last_run) "
              "VALUES ('c1', 100, 'start', 'daily', '2026-10-05 10:00')")
    c.execute("INSERT INTO update_schedules (cluster_id, last_run, next_run) "
              "VALUES ('c1', '2026-10-05T03:00:07', '2026-10-12 03:00:00')")
    c.commit()


def test_the_last_run_stamps_move_with_the_groups_zone(group, seed, db, monkeypatch):
    """They are wall times, compared with the group's clock. Left in the old zone after
    it moves west by six hours, an hourly schedule skips six runs; moved east, it fires
    again within the minute."""
    from pegaprox.api import snapshots
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': 'Europe/Vienna'})
    admin = _built(g, seed, 'b')
    _rows(db)
    clock = _Clock(monkeypatch)
    clock.at = datetime(2026, 10, 5, 8, 0, 30, tzinfo=timezone.utc)      # 10:00:30 in Vienna

    with g.at('a'):
        r = admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'})
        assert r.status_code == 200 and r.get_json()['changed'] is True, r.data
    assert _stamps(db) == {
        ('snapshot_policies', 'last_run_at', 'p1'): '2026-10-05T04:00:30.250000',
        ('snapshot_policies', 'last_run_at', 'p2'): None,
        ('scheduled_tasks', 'last_run', 't1'): '2026-10-05T04:15:10',
        ('scheduled_actions', 'last_run', '1'): '2026-10-05 04:00',
        ('update_schedules', 'last_run', 'c1'): '2026-10-04T21:00:07',
        ('update_schedules', 'next_run', 'c1'): '2026-10-11 21:00:00',
    }
    stamp = _stamps(db)[('snapshot_policies', 'last_run_at', 'p1')]
    policy = {'schedule': 'hourly', 'last_run_at': stamp, 'schedule_at': None,
              'schedule_cron': None, 'run_once_at': None, 'schedule_day': None}
    start, fired = clock.at, []
    with g.at('a'):
        # the same minute: it ran, so it is not due again in the new zone either
        clock.at = start + timedelta(seconds=60)
        assert not snapshots._is_due(policy)
        for k in range(1, 9):
            clock.at = start + timedelta(hours=k)
            fired.append(snapshots._is_due(policy))
    assert fired == [True] * 8

    # east again: back where they were, to the second
    with g.at('a'):
        assert admin.put('/api/ha/timezone', json={'timezone': 'Europe/Vienna'}).status_code == 200
        # a second call changes neither the zone nor a stamp
        assert admin.put('/api/ha/timezone', json={'timezone': 'Europe/Vienna'}).get_json()['changed'] is False
    assert _stamps(db)[('snapshot_policies', 'last_run_at', 'p1')] == '2026-10-05T10:00:30.250000'
    assert _stamps(db)[('scheduled_actions', 'last_run', '1')] == '2026-10-05 10:00'
    assert _stamps(db)[('update_schedules', 'next_run', 'c1')] == '2026-10-12 03:00:00'


def test_an_hourly_task_keeps_its_hours_when_the_zone_moves(group, seed, db, monkeypatch):
    from pegaprox.background import scheduler
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': 'Europe/Vienna'})
    admin = _built(g, seed, 'b')
    db.conn.execute("INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, config, "
                    "enabled) VALUES ('t1', 'c1', 'hourly', 'start', "
                    "'{\"schedule_type\": \"hourly\", \"schedule_time\": \"00:15\"}', '{}', 1)")
    db.conn.commit()
    clock = _Clock(monkeypatch)
    clock.at = datetime(2026, 10, 5, 8, 15, 10, tzinfo=timezone.utc)     # 10:15:10 in Vienna
    ran = []
    monkeypatch.setattr(scheduler, 'execute_scheduled_task', lambda t: ran.append(clock.at))
    with g.at('a'):
        scheduler.run_scheduled_tasks()
    assert len(ran) == 1

    with g.at('a'):
        assert admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'}).status_code == 200
    start = clock.at
    for k in range(1, 7):
        clock.at = start + timedelta(hours=k)
        with g.at('a'):
            scheduler.run_scheduled_tasks()
    # one run at each of the six hours, none skipped
    assert len(ran) == 7


def test_the_stamps_go_back_to_this_instances_clock_when_it_leaves_the_group(group, seed, db, monkeypatch):
    from test_ha_api import ADMIN_PW
    from test_ha_members import _post
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': FAR})
    # three, so the active keeps its group: the instances here share one database, and
    # only the one that leaves moves its stamps
    admin = _built(g, seed, 'bc')
    db.conn.execute("INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, last_run) "
                    "VALUES ('t1', 'c1', 'x', 'start', '{}', '2026-10-05T10:15:10')")
    db.conn.commit()
    want = datetime(2026, 10, 5, 10, 15, 10, tzinfo=ZoneInfo(FAR)).astimezone().replace(tzinfo=None)

    with g.at('b'):
        assert _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW}).status_code == 200

    assert _stamps(db)[('scheduled_tasks', 'last_run', 't1')] == want.isoformat()
    assert want != datetime(2026, 10, 5, 10, 15, 10)


def test_what_is_no_stamp_stays_as_it_is():
    vienna, tokyo = ZoneInfo('Europe/Vienna'), ZoneInfo('Asia/Tokyo')
    assert _ha._rezoned('2026-01-05T10:00:00', vienna, tokyo) == '2026-01-05T18:00:00'
    # by the offset of the day the stamp is of, not of today
    assert _ha._rezoned('2026-07-05T10:00:00', vienna, tokyo) == '2026-07-05T17:00:00'
    for value in (None, '', 'never', '2026-13-45T99:00', 5, '2026-01-05T10:00:00+01:00'):
        assert _ha._rezoned(value, vienna, tokyo) == value
    assert _ha._rezone_stamps('Europe/Vienna', 'Europe/Vienna') == 0
    assert _ha._rezone_stamps('Europe/Vienna', 'Mars/Olympus') == 0


def test_the_zone_stays_as_it_was_when_the_stamps_cannot_be_moved(group, seed, db, monkeypatch):
    """Another writer holds the database past the busy timeout: the stamps move first,
    and the zone only once they did. 500, and both are what they were."""
    from pegaprox.core import db as dbmod
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': 'Europe/Vienna'})
    admin = _built(g, seed, 'b')
    _rows(db)
    before = _stamps(db)
    db.conn.execute('PRAGMA busy_timeout = 200')
    other = dbmod.dbcrypto.connect(dbmod.DATABASE_FILE, timeout=1, check_same_thread=False)
    other.execute('BEGIN IMMEDIATE')
    try:
        with g.at('a') as ha:
            r = admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'})
            zone = ha.group_timezone()
    finally:
        other.rollback()
        other.close()
    assert r.status_code == 500 and 'stays as it was' in r.get_json()['error'], r.data
    assert zone == 'Europe/Vienna' and g.state('a')['timezone'] == 'Europe/Vienna'
    assert _stamps(db) == before
    from test_ha_api import _audit
    assert _audit('ha.timezone_changed') == []
    # and once the database is free again it goes through
    with g.at('a'):
        assert admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'}).status_code == 200
    assert _stamps(db)[('scheduled_tasks', 'last_run', 't1')] == '2026-10-05T04:15:10'


def test_a_change_of_the_zone_cut_short_after_the_stamps_moved_is_finished_by_the_next_look(
        group, seed, db, monkeypatch):
    """The process died between the two writes: the database holds the stamps in the
    new zone, and says so; the state file holds the old zone. The next look at the group
    of the instance that may act puts them where the state file says."""
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': 'Europe/Vienna'})
    _built(g, seed, 'b')
    _rows(db)
    before = _stamps(db)
    with g.at('a') as ha:
        assert ha._rezone_stamps('Europe/Vienna', 'America/New_York') == 5
        assert ha._stamps_zone() == 'America/New_York' and ha.group_timezone() == 'Europe/Vienna'
    assert _stamps(db) != before
    # a standby does not act, and moves nothing
    with g.at('b') as ha:
        assert ha.stamps_settle() == 0
    with g.at('a') as ha:
        assert ha.stamps_settle() == 5
        assert ha._stamps_zone() == 'Europe/Vienna' and ha.stamps_settle() == 0
    assert _stamps(db) == before


def test_a_settings_save_that_read_before_a_change_of_the_zone_leaves_the_stamps_alone(
        group, seed, db, monkeypatch):
    """A settings route reads every setting and writes them all back. One that read
    before a change of the zone and writes after it does not put back the zone the
    stamps were in: the next look would move stamps that are where they belong."""
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': 'Europe/Vienna'})
    admin = _built(g, seed, 'b')
    _rows(db)
    with g.at('a'):
        assert admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'}).status_code == 200
    read = load_server_settings()
    assert read[_ha.STAMPS_ZONE_SETTING] == 'America/New_York'
    with g.at('a'):
        assert admin.put('/api/ha/timezone', json={'timezone': 'Asia/Tokyo'}).status_code == 200
    moved = _stamps(db)
    assert save_server_settings(dict(read, session_timeout=7200))
    assert db.get_server_setting('session_timeout') == 7200
    with g.at('a') as ha:
        assert ha._stamps_zone() == 'Asia/Tokyo' and ha.stamps_settle() == 0
    assert _stamps(db) == moved


def test_a_member_without_zone_data_keeps_the_groups_zone_and_says_so(group, seed, db, monkeypatch):
    """No /usr/share/zoneinfo and no tzdata on b: it cannot read the group's zone. It
    keeps the name all the same (and hands it on once it leads), its status page names
    it as one this host cannot read, and a zone set there is refused for what it is."""
    g = group
    monkeypatch.setattr(_ha, '_local_zone', {'name': 'Europe/Vienna'})
    admin = _built(g, seed, 'b')
    with g.at('b') as ha:
        ha._update(timezone=None)
        ha._update_sync(etag=None)
    for name in ('Europe/Vienna', 'America/New_York', 'UTC'):
        monkeypatch.setitem(_ha._zones, name, None)
    monkeypatch.setattr(_ha, '_zones_unknown', set())
    assert _sync(g, admin, 'b') == 'applied'
    with g.at('b') as ha:
        assert ha._load()['timezone'] == 'Europe/Vienna' and ha.group_timezone() == ''
        status = admin.get('/api/ha/status').get_json()
    assert status['timezone'] == '' and status['timezone_unreadable'] == 'Europe/Vienna'
    with g.at('a') as ha:
        r = admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'})
        assert r.status_code == 400 and 'no time zone data - install tzdata' in r.get_json()['error']
        assert ha._load()['timezone'] == 'Europe/Vienna'
    # promoted, it hands the zone on with its snapshots, readable here or not
    assert _promote(g, admin, 'b').status_code == 200
    with g.at('b') as ha:
        assert ha.is_active() and ha.snapshot_meta()['timezone'] == 'Europe/Vienna'


def test_a_task_run_by_hand_is_stamped_by_the_groups_clock(group, seed, db, monkeypatch):
    """The scheduler compares last_run with the group's clock: the stamp of a run by hand
    is on that clock too, or the runs after it are skipped (or the day is taken as done)."""
    from pegaprox.api import history
    g = group
    admin = _built(g, seed, 'b')
    with g.at('a'):
        assert admin.put('/api/ha/timezone', json={'timezone': FAR}).status_code == 200
    db.conn.execute("INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, config, "
                    "enabled) VALUES ('t1', 'c1', 'hourly', 'start', "
                    "'{\"schedule_type\": \"hourly\", \"schedule_time\": \"00:15\"}', '{}', 1)")
    db.conn.commit()
    monkeypatch.setattr(history, 'execute_scheduled_task', lambda task: None)
    with g.at('a'):
        assert admin.post('/api/scheduled-tasks/t1/run').status_code == 200
    stamp = datetime.fromisoformat(_stamps(db)[('scheduled_tasks', 'last_run', 't1')])
    assert abs((stamp - _in_zone(FAR)).total_seconds()) < 5
    assert abs((stamp - datetime.now()).total_seconds()) > 3600


@pytest.fixture
def far_zone(monkeypatch):
    """This instance is the leader of a group whose schedules run in FAR."""
    _ha._update(role='active', epoch=1, timezone=FAR,
                members={'b' * 32: {'url': 'https://b.example:5000', 'public_key': ''}})
    now = _in_zone(FAR)
    assert abs((now - datetime.now()).total_seconds()) > 3600
    return now


def test_a_snapshot_policy_is_due_by_the_groups_clock(far_zone):
    import pegaprox.api.snapshots as snaps
    policy = {'schedule': 'daily', 'last_run_at': None, 'schedule_at': far_zone.strftime('%H:%M')}
    assert snaps._is_due(policy) is True
    # the same hour on this machine's own clock is another moment: not due
    policy['schedule_at'] = datetime.now().strftime('%H:%M')
    assert snaps._is_due(policy) is False
    # 'once', at a moment of the group's clock that has come
    once = {'schedule': 'once', 'last_run_at': None,
            'run_once_at': far_zone.replace(microsecond=0).isoformat()}
    assert snaps._is_due(once) is True


def test_a_scheduled_task_fires_and_is_stamped_by_the_groups_clock(far_zone, monkeypatch):
    import pegaprox.background.scheduler as scheduler
    ran, stamped = [], []
    tasks = [{'id': 't-group', 'enabled': True, 'schedule_type': 'daily',
              'schedule_time': far_zone.strftime('%H:%M'), 'last_run': None},
             {'id': 't-local', 'enabled': True, 'schedule_type': 'daily',
              'schedule_time': datetime.now().strftime('%H:%M'), 'last_run': None}]
    monkeypatch.setattr(scheduler, 'load_scheduled_tasks', lambda: {'tasks': tasks})
    monkeypatch.setattr(scheduler, 'execute_scheduled_task', lambda t: ran.append(t['id']))
    monkeypatch.setattr(scheduler, '_touch_last_run', lambda tid, when: stamped.append((tid, when)))

    scheduler.run_scheduled_tasks()

    assert ran == ['t-group'] and stamped[0][0] == 't-group'
    # the stamp is on the same clock the next comparison uses
    assert abs((datetime.fromisoformat(stamped[0][1]) - far_zone).total_seconds()) < 5


def test_a_scheduled_action_and_a_scheduled_update_fire_by_the_groups_clock(far_zone, monkeypatch):
    import pegaprox.api.schedules as sched

    class _Stop(BaseException):
        pass
    fired = []
    actions = [{'id': 'a-group', 'enabled': True, 'schedule_type': 'daily',
                'time': far_zone.strftime('%H:%M')},
               {'id': 'a-local', 'enabled': True, 'schedule_type': 'daily',
                'time': datetime.now().strftime('%H:%M')}]
    monkeypatch.setattr(sched, 'load_schedules', lambda: {'actions': actions})
    monkeypatch.setattr(sched, 'execute_scheduled_action', lambda a: fired.append(a['id']))
    monkeypatch.setattr(sched, '_record_action_run', lambda *a, **k: None)
    monkeypatch.setattr(sched, 'check_scheduled_updates', lambda: fired.append('updates'))
    monkeypatch.setattr(sched, 'cleanup_deleted_scripts', lambda: None)
    monkeypatch.setattr(sched, 'cleanup_orphaned_excluded_vms', lambda: None)
    monkeypatch.setattr(sched, '_scheduler_running', True)

    def stop():
        raise _Stop()
    monkeypatch.setattr(sched, '_wait_a_minute', stop)
    with pytest.raises(_Stop):
        sched.check_schedules()
    assert fired[0] == 'a-group' and 'a-local' not in fired
    assert actions[0]['last_run'] == far_zone.strftime('%Y-%m-%d %H:%M')

    # the next run of a scheduled update, worked out on the same clock
    nxt = datetime.strptime(sched.calculate_next_update_run('daily', far_zone.strftime('%H:%M')),
                            '%Y-%m-%d %H:%M:%S')
    assert 0 < (nxt - far_zone).total_seconds() <= 24 * 3600 + 60


@pytest.mark.parametrize('rel,qualname', [
    ('pegaprox/api/schedules.py', 'check_schedules'),
    ('pegaprox/api/schedules.py', 'check_scheduled_updates'),
    ('pegaprox/api/schedules.py', 'calculate_next_update_run'),
    ('pegaprox/background/scheduler.py', 'run_scheduled_tasks'),
    ('pegaprox/api/snapshots.py', '_is_due'),
    # a run by hand stamps last_run, which the scheduler compares with its clock
    ('pegaprox/api/history.py', 'run_scheduled_task_now'),
])
def test_every_schedule_is_evaluated_on_the_groups_clock(rel, qualname):
    """Where a schedule decides whether it is due, or stamps what it compares with, the
    time comes from ha.schedule_now() and from nowhere else."""
    from test_ha_loop_gates import _find, _parse
    func = _find(_parse(rel), qualname)
    assert _calls_attr(func, 'schedule_now'), f'{qualname} does not ask ha.schedule_now()'
    local = [n for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == 'now' and getattr(n.func.value, 'id', '') == 'datetime']
    assert not local, f'{qualname} line {local[0].lineno} reads datetime.now() next to it'


# --- reach ----------------------------------------------------------------------------------

def _mgr(ok, ha_enabled=True, hosts=('10.0.0.1',)):
    session = MagicMock()
    asked = []

    def get(url, timeout):
        asked.append(url)
        if ok is None:
            raise OSError('unreachable')
        return types.SimpleNamespace(status_code=ok)
    session.get = get
    return types.SimpleNamespace(ha_enabled=ha_enabled, host=hosts[0], api_port=8006, asked=asked,
                                 config=types.SimpleNamespace(fallback_hosts=list(hosts[1:])),
                                 _create_session=lambda: session)


def test_reach_is_one_version_call_per_cluster_with_node_ha(monkeypatch):
    import pegaprox.globals as ppglobals
    mgrs = {'c1': _mgr(200), 'c2': _mgr(None, hosts=('10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5')),
            'c3': _mgr(401), 'c4': _mgr(200, ha_enabled=False), 'c5': _mgr(500),
            'c6': MagicMock()}
    monkeypatch.setattr(ppglobals, 'cluster_managers', mgrs)
    monkeypatch.setattr(_ha, '_fan_out', lambda jobs, timeout: [(job(), None) for job in jobs])

    reach = _ha.measure_reach()

    # c4 has no node HA and c6 is no cluster manager with it either: neither is asked
    assert reach == {'c1': True, 'c2': False, 'c3': True, 'c5': False}
    assert mgrs['c1'].asked == ['https://10.0.0.1:8006/api2/json/version']
    # the hosts of a cluster one after the other, three at most
    assert len(mgrs['c2'].asked) == 3 and mgrs['c4'].asked == []
    assert _ha._rt().reach['clusters'] == reach


def test_a_candidate_that_reaches_fewer_clusters_waits_longer(auto, seed):
    auto.form(seed)
    with auto.at('b') as ha:
        rt = ha._rt()
        rt.reach = {'at': time.monotonic(), 'clusters': {'c1': True}}
        assert ha._lower_reach(rt) is False
        rt.seen[IDS['c']] = dict(rt.seen.get(IDS['c']) or {}, at=time.monotonic(),
                                 reach={'c1': True, 'c2': True})
        assert ha._lower_reach(rt) is True and auto.node('b').lower_reach() is True
        # what it heard two minutes ago says nothing any more
        rt.seen[IDS['c']]['at'] -= 121
        assert ha._lower_reach(rt) is False
    # and its election timer is later by half a lease
    auto.past_the_hold()
    auto.pause('a')
    auto.advance(T.P + 1)               # no promise runs any more: the timer alone decides
    node = auto.node('b')
    node.rng = types.SimpleNamespace(uniform=lambda a, b: a)
    node._arm_timer(auto.clock['b'])
    plain = node.election_at
    with auto.at('b') as ha:
        ha._rt().seen[IDS['c']]['at'] = time.monotonic()
        node._arm_timer(auto.clock['b'])
    assert node.election_at == pytest.approx(plain + T.L / 2)


def test_what_a_member_reaches_goes_out_with_its_status(auto, seed):
    auto.form(seed)
    with auto.at('b') as ha:
        ha._rt().reach = {'at': time.monotonic(), 'clusters': {'c1': True, 'c2': False}}
    auto.watch('a')
    with auto.at('a') as ha:
        assert ha._rt().seen[IDS['b']]['reach'] == {'c1': True, 'c2': False}
        rows = {m['instance_id']: m for m in ha.lease_status()['members']}
    assert rows[IDS['b']]['reach'] == {'c1': True, 'c2': False}


# --- a clock off the majority of the members (Q15) -----------------------------------------

def _measured(ha, rt, mid, skew, age=0.0, **extra):
    """What the watch notes for a member that answered with its wall clock `skew` seconds
    off ours, `age` seconds ago."""
    now = time.time()
    seen = {'mark': None}
    if skew is not None:
        seen = ha._lease_seen({'lease_mark': ha.LEASE_MARK, 'wall': now + skew}, now, now)
    rt.seen[mid] = dict(seen, at=time.monotonic() - age, **extra)


def test_a_clock_is_off_where_it_is_off_more_than_half_of_what_was_measured(auto, seed):
    """More than SKEW_LIMIT off more than half of the members measured within two minutes,
    the witness among them (its answer goes the same way, _ask_witness). Half is not more
    than half, and with nothing measured the clock is not off."""
    auto.form(seed)
    witness = 'f' * 32
    with auto.at('c') as ha:
        rt = ha._rt()
        rt.seen.clear()
        assert ha._clock_off(rt) is None
        _measured(ha, rt, IDS['a'], -30.0)
        _measured(ha, rt, IDS['b'], 0.4)
        assert ha._clock_off(rt) is None
        _measured(ha, rt, witness, -31.0)
        assert ha._clock_off(rt) == {'off_s': 30.0, 'members_off': 2, 'measured': 3}
        assert auto.node('c').skewed() is True
        # what it measured two minutes ago says nothing any more: one of two
        rt.seen[IDS['a']]['at'] -= 121
        assert ha._clock_off(rt) is None and auto.node('c').skewed() is False
        # a member that refused the call for its time is off (past the signature window)
        _measured(ha, rt, IDS['a'], None, clock='window')
        assert ha._clock_off(rt) == {'off_s': 31.0, 'members_off': 2, 'measured': 3}
        # one that answered from an older release says nothing about its clock
        rt.seen.clear()
        _measured(ha, rt, IDS['a'], None)
        assert ha._clock_off(rt) is None


def test_a_member_off_the_majority_loses_the_race_to_one_with_a_right_clock(auto, seed, caplog):
    """Lab C2: b's clock is 30 s ahead. Its timer fires first and it puts its campaign off
    by a lease; c, whose clock is right, campaigns later and wins. The status says why."""
    auto.form(seed)
    auto.past_the_hold()
    auto.skew['b'] = 30.0
    auto.watch('b', 'c')
    with auto.at('b') as ha:
        off = ha._clock_off(ha._rt())
        status = ha.lease_status()
    assert off['off_s'] == pytest.approx(30, abs=1) and (off['members_off'], off['measured']) == (2, 2)
    assert status['defers_campaigns'] == off
    with auto.at('c') as ha:
        assert ha._clock_off(ha._rt()) is None and ha.lease_status()['defers_campaigns'] is None
    # b's timer fires first, c's last; one renewal arms both
    auto.node('b').rng = types.SimpleNamespace(uniform=lambda lo, hi: lo)
    auto.node('c').rng = types.SimpleNamespace(uniform=lambda lo, hi: hi)
    auto.run(T.R + 0.5)

    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R + 2, until=lambda: auto.holders() != [])

    assert auto.holders() == ['c']
    assert 'waits one lease longer before it campaigns' in caplog.text


def test_the_leader_says_nothing_of_deferring_whatever_its_clock(auto, seed):
    """The leader runs no election timer: its status does not say it defers campaigns,
    even with its clock off the majority. A standby off the majority does say so."""
    auto.form(seed)
    auto.skew.update(a=60.0, b=30.0)
    auto.watch('a', 'b')
    with auto.at('a') as ha:
        assert ha._clock_off(ha._rt())['members_off'] == 2 and ha.holds_lease()
        assert ha.lease_status()['defers_campaigns'] is None
    with auto.at('b') as ha:
        off = ha._clock_off(ha._rt())
        assert off is not None and ha.lease_status()['defers_campaigns'] == off


def test_members_whose_clocks_all_drifted_apart_still_elect_one(auto, seed):
    """Each one is off the other and the leader that went: both put their campaigns off,
    and one of them leads a lease later all the same."""
    auto.form(seed)
    auto.past_the_hold()
    auto.skew.update(b=30.0, c=-30.0)
    auto.watch('b', 'c')
    for n in 'bc':
        with auto.at(n) as ha:
            assert ha._clock_off(ha._rt())['members_off'] == 2
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.L + T.R + 2, until=lambda: auto.holders() != [])
    assert len(auto.holders()) == 1


def test_a_manual_group_says_nothing_about_deferring(auto, seed):
    """Nobody campaigns in a manual group: no member says it defers, whatever its clock."""
    auto.pair(seed)
    auto.skew['b'] = 30.0
    auto.watch('b')
    with auto.at('b') as ha:
        assert ha._clock_off(ha._rt()) is not None
        assert ha.lease_status()['defers_campaigns'] is None
    # and switched off again, with a voter config of its own
    auto.skew.clear()
    auto.switch_on()
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    auto.skew['b'] = 30.0
    auto.watch('b')
    with auto.at('b') as ha:
        assert ha.mode() == 'manual' and auto.node('b') is not None
        assert ha._clock_off(ha._rt()) is not None
        assert ha.lease_status()['defers_campaigns'] is None


# --- what it costs ----------------------------------------------------------------------------

def _timed(fn, n):
    best, total = None, 0.0
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        dt = time.perf_counter() - t0
        total += dt
        best = dt if best is None or dt < best else best
    return best, total / n


def test_a_renewal_round_and_a_vote_do_not_hold_the_hub(auto, seed, capsys):
    """One renewal round is a tick on the leader and one call per member; a member takes
    it without a write. A vote is the one thing that waits for the disk. The numbers go
    to the report (-s shows them); the bounds here are loose, they catch a walk over the
    tables or a write per renewal, not a slow machine."""
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    ha = auto.ha
    out = {}

    # the leader's tick that starts a round: no I/O, the calls are only queued
    ticks = []

    def tick():
        auto.advance(T.R)
        with auto.at('a'):
            t0 = time.perf_counter()
            ha.lease_step()
            ticks.append(time.perf_counter() - t0)
        assert len(auto.rt('a').outbox) == 3
        auto.deliver('a')
    for _ in range(30):
        tick()
    out['leader tick that starts a round'] = (min(ticks), sum(ticks) / len(ticks))

    # a member takes a renewal: signature and route aside, the node and no write
    body = {'epoch': 1, 'leader': IDS['a'], 'lease_s': 20, 'cv': list(auto.node('a').cv),
            'wall': time.time(), 'floor_cv': [0, 0]}
    writes = []
    real = ha._write_locked
    ha._write_locked = lambda st: writes.append(1) or real(st)
    try:
        with auto.at('b'):
            out['a member takes a renewal'] = _timed(lambda: ha.lease_request(IDS['a'], 'renew', body), 200)
        assert writes == []
    finally:
        ha._write_locked = real

    # the whole round through the routes: three signed calls, three answers
    def round_trip():
        auto.advance(T.R)
        auto.step('a')
    out['a renewal round, three members, through the routes'] = _timed(round_trip, 20)

    # a vote: the epoch and who got it are on disk, file and directory, before the answer
    auto.pause('a')
    auto.advance(T.P + 1)
    epochs = iter(range(2, 200))

    def vote():
        e = next(epochs)
        with auto.at('b'):
            ans = ha.lease_request(IDS['c'], 'vote', {
                'epoch': e, 'candidate': IDS['c'], 'pre': False, 'why': 'timer',
                'cv': list(auto.node('c').cv), 'cfg_id': list(auto.node('c').view.id), 'lease_s': 20})
        assert ans['granted'] is True, ans
        auto.node('b').promise_until = -1
    out['a vote, written and synced'] = _timed(vote, 30)

    with capsys.disabled():
        for what, (best, mean) in out.items():
            print(f'\n  [lease cost] {what}: best {best * 1000:.2f} ms, mean {mean * 1000:.2f} ms', end='')
    assert out['leader tick that starts a round'][0] < 0.02
    assert out['a member takes a renewal'][0] < 0.02
    assert out['a renewal round, three members, through the routes'][0] < 1
    assert out['a vote, written and synced'][0] < 1
