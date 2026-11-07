"""A rolling update's own wait counts a node as back only once it really restarted.

The wait looked 120 s for an offline and then took the first "online". A node that had not gone
down yet said that, and on XCP-ng every host says it, since the pool master answers for its
members and each row reads online. After a slow host outlasted the update task's wait, the next
host was pulled about two minutes later while this one was still down.
"""
import threading
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.core.xcpng as xcpngmod
from pegaprox.core.manager import UpdateTask
from pegaprox.core.xcpng import XcpngManager
from pegaprox.models.tasks import UpdateTask as XcpUpdateTask

OLD_UPTIME = 3_000_000


class _Clock:
    """settings.time with sleeps that pass at once, on the real time line of the run's state."""
    def __init__(self):
        self.offset = 0.0

    def __getattr__(self, name):
        return getattr(time, name)

    def time(self):
        return time.time() + self.offset

    def sleep(self, seconds):
        self.offset += seconds
        time.sleep(0.001)   # the run spins otherwise and starves the hub


def _rebooted_task(waited=0):
    t = UpdateTask('blade1', reboot=True)
    t.status, t.phase = 'completed', 'done'
    t.reboot_issued, t.back_online = True, False
    t.reboot_waited = waited
    return t


def _run(api, seed, monkeypatch, row, xcpng=False, task_waited=0):
    """row(seconds since the task finished) is the node as the status read says, None for a read
    without its row; a run with its node's answers, up to where it stops or holds."""
    import pegaprox.api.settings as settings_mod
    clock = _Clock()
    monkeypatch.setattr(settings_mod, 'time', clock)
    fake = api.make_fake_manager()
    start = time.time()

    def answer(*_):
        got = row(time.time() + clock.offset - start)
        if isinstance(got, Exception):
            raise got
        return got
    if xcpng:
        fake.cluster_type = 'xcpng'
        fake.node_reboot_look.side_effect = answer
        # what the real manager's status says for each host, whatever is going on
        fake.get_node_status.return_value = {'blade1': {'status': 'online', 'uptime': OLD_UPTIME}}
    else:
        # the route and the quorum gate read it before the reboot too: nothing is going on yet
        def rows():
            got = answer() if fake.start_node_update.called else _up(OLD_UPTIME)
            return {'blade1': got} if got else {'blade2': _up(OLD_UPTIME)}
        fake.get_node_status.side_effect = rows
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in ('blade1', 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.start_node_update.return_value = _rebooted_task(task_waited)
    fake.exit_maintenance_mode.return_value = False
    fake.nodes_in_maintenance = {}
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    api.set_manager('cluster_1', fake)
    r = api.as_user(seed.user('root', role='admin')).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': True, 'skip_up_to_date': False, 'skip_evacuation': True, 'reboot_timeout': 600})
    assert r.status_code == 200, r.data
    deadline = time.time() + 20
    while time.time() < deadline and fake._rolling_update.get('status') == 'running':
        time.sleep(0.01)
    state = fake._rolling_update
    logs = '\n'.join(state['logs'])
    state['status'] = 'cancelled'
    return state, logs, clock


def _up(uptime):
    return {'status': 'online', 'uptime': uptime}


def _held_for_the_reboot(state, logs):
    assert state.get('paused_reason') == 'reboot_timeout', logs
    assert 'back online (' not in logs, logs


def test_a_node_that_never_went_down_is_not_back(api, seed, monkeypatch):
    state, logs, _ = _run(api, seed, monkeypatch, lambda t: _up(OLD_UPTIME + t))
    _held_for_the_reboot(state, logs)
    assert 'not seen restarting' in state['paused_details']['message']


def test_online_after_seen_down_counts(api, seed, monkeypatch):
    state, logs, clock = _run(api, seed, monkeypatch,
                              lambda t: {'status': 'offline', 'uptime': 0} if t < 300 else _up(0))
    assert state.get('paused_reason') is None, logs
    assert 'blade1 is now offline' in logs and 'blade1 back online' in logs, logs
    assert clock.offset >= 300


def test_a_slow_shutdown_is_waited_out(api, seed, monkeypatch):
    # still up past the 120 s look for an offline, then down, then back
    def row(t):
        if t < 200:
            return _up(OLD_UPTIME + t)
        return {'status': 'offline', 'uptime': 0} if t < 400 else _up(0)
    state, logs, clock = _run(api, seed, monkeypatch, row)
    assert state.get('paused_reason') is None, logs
    assert 'did not go offline within 120s' in logs and 'blade1 back online' in logs, logs
    assert clock.offset >= 400


def test_a_restart_between_two_looks_shows_in_the_uptime(api, seed, monkeypatch):
    state, logs, clock = _run(api, seed, monkeypatch, lambda t: _up(OLD_UPTIME + t) if t < 60 else _up(t - 55))
    assert state.get('paused_reason') is None, logs
    assert 'blade1 back online' in logs, logs
    assert 'did not go offline' not in logs, logs
    assert clock.offset >= 60


def test_no_answer_is_not_the_node_going_down(api, seed, monkeypatch):
    # the API read failing says nothing about this node, and its old uptime says it never left
    def row(t):
        return ConnectionError('api gone') if t < 100 else _up(OLD_UPTIME + t)
    state, logs, _ = _run(api, seed, monkeypatch, row)
    _held_for_the_reboot(state, logs)
    assert 'is now offline' not in logs, logs


def test_a_partial_read_is_not_the_node_going_down(api, seed, monkeypatch):
    # get_node_status drops a node whose details ran out of time; this one never left
    state, logs, _ = _run(api, seed, monkeypatch, lambda t: None if t < 100 else _up(OLD_UPTIME + t))
    _held_for_the_reboot(state, logs)
    assert 'is now offline' not in logs, logs


@pytest.mark.parametrize('status', ['unknown', 'maintenance'])
def test_only_offline_says_the_node_went_down(api, seed, monkeypatch, status):
    state, logs, _ = _run(api, seed, monkeypatch,
                          lambda t: {'status': status, 'uptime': 0} if t < 100 else _up(OLD_UPTIME + t))
    _held_for_the_reboot(state, logs)
    assert 'is now offline' not in logs, logs


def test_a_node_that_left_the_list_is_back_by_its_uptime(api, seed, monkeypatch):
    state, logs, clock = _run(api, seed, monkeypatch, lambda t: None if t < 100 else _up(t - 90))
    assert state.get('paused_reason') is None, logs
    assert 'blade1 back online' in logs, logs
    assert clock.offset >= 100


def test_a_down_xcpng_host_holds_the_run(api, seed, monkeypatch):
    # every status row says online: only the host's own look shows the truth
    state, logs, _ = _run(api, seed, monkeypatch, lambda t: {'status': 'offline', 'uptime': 0}, xcpng=True)
    _held_for_the_reboot(state, logs)


def test_an_xcpng_host_that_comes_back_goes_on(api, seed, monkeypatch):
    state, logs, clock = _run(api, seed, monkeypatch,
                              lambda t: {'status': 'offline', 'uptime': 0} if t < 500 else _up(20), xcpng=True)
    assert state.get('paused_reason') is None, logs
    assert 'blade1 back online' in logs, logs
    assert clock.offset >= 500


def test_a_host_the_task_already_waited_for_holds_at_once(api, seed, monkeypatch):
    # the whole reboot timeout went by in the task, a second one only keeps the operator waiting
    state, logs, clock = _run(api, seed, monkeypatch, lambda t: {'status': 'offline', 'uptime': 0},
                              xcpng=True, task_waited=600)
    _held_for_the_reboot(state, logs)
    assert clock.offset < 60, logs


def test_the_run_waits_what_the_task_left_of_the_timeout(api, seed, monkeypatch):
    state, logs, clock = _run(api, seed, monkeypatch, lambda t: {'status': 'offline', 'uptime': 0},
                              xcpng=True, task_waited=300)
    _held_for_the_reboot(state, logs)
    assert 300 <= clock.offset < 360, logs


def test_a_host_that_returns_in_what_is_left_goes_on(api, seed, monkeypatch):
    state, logs, clock = _run(api, seed, monkeypatch,
                              lambda t: {'status': 'offline', 'uptime': 0} if t < 200 else _up(20),
                              xcpng=True, task_waited=300)
    assert state.get('paused_reason') is None, logs
    assert 'blade1 back online' in logs, logs
    assert clock.offset >= 200


# -- the XCP-ng update task's own wait and its look at a host --------------------------------------

class _XcpClock:
    def __init__(self):
        self.now = 1000.0
        self.step = 0   # what the wall clock was moved by

    def __getattr__(self, name):
        return getattr(time, name)

    def time(self):
        return self.now + self.step

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


SHUT = object()


def _waiting(monkeypatch, answers):
    """answers(t) is the host t seconds into the wait: SHUT for a closed port, a row for an open
    one, an exception when XAPI fails. The pool master always has a row for it."""
    import socket
    clock = _XcpClock()
    monkeypatch.setattr(xcpngmod, 'time', clock)
    m = XcpngManager.__new__(XcpngManager)
    m.logger = MagicMock()
    m.is_connected = True
    m._get_host_ip = lambda node: '10.0.0.9'
    m._api = lambda: object()
    start = clock.now

    def connect(*a, **k):
        if answers(clock.now - start) is SHUT:
            raise ConnectionRefusedError()
        return MagicMock()

    def rows(_api):
        got = answers(clock.now - start)
        if isinstance(got, Exception):
            raise got
        return [dict(got, node='h1')]
    monkeypatch.setattr(socket, 'create_connection', connect)
    m._fetch_nodes = rows
    m.clock, m.start = clock, start
    m.nodes_updating = {}
    return m


def test_the_task_does_not_take_a_host_that_never_restarted(monkeypatch):
    m = _waiting(monkeypatch, lambda t: _up(OLD_UPTIME + t))
    assert XcpngManager._wait_for_host_online(m, 'h1', timeout=120) is False
    assert m.clock.now - m.start >= 120


def test_the_task_waits_out_a_slow_shutdown(monkeypatch):
    def answers(t):
        if t < 90:
            return _up(OLD_UPTIME + t)
        return SHUT if t < 200 else _up(OLD_UPTIME)
    m = _waiting(monkeypatch, answers)
    assert XcpngManager._wait_for_host_online(m, 'h1') is True
    assert m.clock.now - m.start >= 200


def test_the_task_sees_a_restart_between_two_looks(monkeypatch):
    m = _waiting(monkeypatch, lambda t: _up(OLD_UPTIME + t) if t < 100 else _up(t - 95))
    assert XcpngManager._wait_for_host_online(m, 'h1') is True
    assert m.clock.now - m.start >= 100


def test_the_task_notes_a_wait_that_ran_out(monkeypatch):
    m = _waiting(monkeypatch, lambda t: SHUT)
    task = XcpUpdateTask('h1', reboot=True)
    m.nodes_updating = {'h1': task}
    assert XcpngManager._wait_for_host_online(m, 'h1', timeout=120) is False
    assert task.reboot_waited == 120


def test_the_task_notes_nothing_for_a_host_that_came_back(monkeypatch):
    m = _waiting(monkeypatch, lambda t: SHUT if t < 50 else _up(OLD_UPTIME))
    task = XcpUpdateTask('h1', reboot=True)
    m.nodes_updating = {'h1': task}
    assert XcpngManager._wait_for_host_online(m, 'h1', timeout=120) is True
    assert task.reboot_waited == 0


def test_a_step_of_the_wall_clock_is_not_a_restart(monkeypatch):
    def answers(t):
        m.clock.step = 2 * OLD_UPTIME
        return _up(OLD_UPTIME + t)
    m = _waiting(monkeypatch, answers)
    assert XcpngManager._wait_for_host_online(m, 'h1', timeout=60) is False
    assert m.clock.now - m.start >= 60


def test_a_failing_read_proves_nothing(monkeypatch):
    m = _waiting(monkeypatch, lambda t: RuntimeError('xapi') if t < 50 else _up(OLD_UPTIME + t))
    assert XcpngManager._wait_for_host_online(m, 'h1', timeout=120) is False


def test_the_task_takes_a_host_that_went_down_and_came_back(monkeypatch):
    m = _waiting(monkeypatch, lambda t: SHUT if t < 150 else _up(0))
    assert XcpngManager._wait_for_host_online(m, 'h1') is True
    assert m.clock.now - m.start >= 150


def _looking(monkeypatch, connect, rows):
    m = XcpngManager.__new__(XcpngManager)
    m.logger = MagicMock()
    m.is_connected = True
    m._get_host_ip = lambda node: '10.0.0.9'
    m._api = lambda: object()
    m._fetch_nodes = rows
    import socket
    monkeypatch.setattr(socket, 'create_connection', connect)
    return m


def test_a_shut_port_says_down_whatever_the_master_says(monkeypatch):
    def shut(*a, **k):
        raise ConnectionRefusedError()
    m = _looking(monkeypatch, shut, lambda api: [{'node': 'h1', 'status': 'online', 'uptime': OLD_UPTIME}])
    assert XcpngManager.node_reboot_look(m, 'h1')['status'] == 'offline'


def test_an_open_port_gives_the_fresh_row(monkeypatch):
    m = _looking(monkeypatch, lambda *a, **k: MagicMock(), lambda api: [
        {'node': 'h0', 'status': 'online', 'uptime': 1}, {'node': 'h1', 'status': 'online', 'uptime': 42}])
    assert XcpngManager.node_reboot_look(m, 'h1')['uptime'] == 42


@pytest.mark.parametrize('rows', [lambda api: [], lambda api: [{'node': 'other'}]])
def test_a_host_not_in_the_answer_is_no_answer(monkeypatch, rows):
    m = _looking(monkeypatch, lambda *a, **k: MagicMock(), rows)
    assert XcpngManager.node_reboot_look(m, 'h1') is None


def test_a_session_the_master_forgot_is_opened_again(monkeypatch):
    def forgot(api):
        raise RuntimeError('SESSION_INVALID')
    m = _looking(monkeypatch, lambda *a, **k: MagicMock(), forgot)
    assert XcpngManager.node_reboot_look(m, 'h1') is None
    assert m.is_connected is False
