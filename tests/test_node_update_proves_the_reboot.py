"""A node counts as back from its reboot only once it really restarted.

The wait slept 30 s and then took the first "online". A node that needs longer to shut down
still answers online then, so the update finished, maintenance ended and a rolling update
pulled the next node while this one went down.
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager, UpdateTask

OLD_UPTIME = 3_000_000


class _Clock:
    def __init__(self):
        self.now = 1000.0
        self.step = 0   # what the wall clock was moved by, as NTP or a resumed VM do

    def time(self):
        return self.now + self.step

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _manager(monkeypatch, answers):
    """answers(t) is what the node looks like t seconds into the wait: its row, a whole list
    (no status key at the top), None for a read that failed, or an exception to raise."""
    clock = _Clock()
    monkeypatch.setattr(mgrmod, 'time', clock)
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.config = MagicMock()
    m.connect_to_proxmox = lambda: True
    start = clock.now

    def status():
        got = answers(clock.now - start)
        if isinstance(got, Exception):
            raise got
        if got is None:
            return {}
        return got if 'status' not in got else {'n1': got}
    m.get_node_status = status
    m.clock, m.start = clock, start
    return m


def _online(uptime):
    return {'status': 'online', 'uptime': uptime}


def test_a_node_that_never_restarts_is_not_back(monkeypatch):
    m = _manager(monkeypatch, lambda t: _online(OLD_UPTIME + t))
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=120) is False
    assert m.clock.now - m.start >= 120


def test_a_slow_shutdown_is_waited_out(monkeypatch):
    # online for 90 s with the old uptime, down until 200 s, then up again
    def answers(t):
        if t < 90:
            return _online(OLD_UPTIME + t)
        return {'status': 'offline', 'uptime': 0} if t < 200 else _online(5)
    m = _manager(monkeypatch, answers)
    assert PegaProxManager._wait_for_node_online(m, 'n1') is True
    assert m.clock.now - m.start >= 200


def test_a_partial_read_is_not_the_node_going_down(monkeypatch):
    # get_node_status drops a node whose details ran out of time; this one never left
    m = _manager(monkeypatch, lambda t: {'other': _online(9)} if t < 60 else _online(OLD_UPTIME + t))
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=120) is False


@pytest.mark.parametrize('status', ['unknown', 'maintenance'])
def test_only_offline_says_the_node_went_down(monkeypatch, status):
    m = _manager(monkeypatch, lambda t: {'status': status, 'uptime': 0} if t < 60 else _online(OLD_UPTIME + t))
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=120) is False


@pytest.mark.parametrize('status', ['unknown', 'maintenance'])
def test_a_row_that_is_not_online_is_not_back(monkeypatch, status):
    # seen down, and then neither online nor offline: not back yet
    def answers(t):
        if t < 60:
            return {'status': 'offline', 'uptime': 0}
        return {'status': status, 'uptime': 5}
    m = _manager(monkeypatch, answers)
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=120) is False


def test_a_node_that_left_the_list_is_back_by_its_uptime(monkeypatch):
    # gone from the answers while it reboots, the row that returns has a young uptime
    m = _manager(monkeypatch, lambda t: {'other': _online(9)} if t < 60 else _online(t - 50))
    assert PegaProxManager._wait_for_node_online(m, 'n1') is True
    assert m.clock.now - m.start >= 60


def test_a_failed_status_read_is_not_the_node_going_down(monkeypatch):
    # get_node_status answers {} when its request fails; the node never left
    m = _manager(monkeypatch, lambda t: None if t < 60 else _online(OLD_UPTIME + t))
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=120) is False


def test_a_reboot_between_two_looks_is_seen_in_the_uptime(monkeypatch):
    # never offline in any answer, the uptime alone shows it
    m = _manager(monkeypatch, lambda t: _online(OLD_UPTIME + t) if t < 100 else _online(t - 95))
    assert PegaProxManager._wait_for_node_online(m, 'n1') is True
    assert m.clock.now - m.start >= 100


def test_the_api_itself_going_away_and_coming_back(monkeypatch):
    # PegaProx talks to this node: no status at all while it reboots
    m = _manager(monkeypatch, lambda t: ConnectionError('gone') if t < 150 else _online(t - 140))
    assert PegaProxManager._wait_for_node_online(m, 'n1') is True
    assert m.clock.now - m.start >= 150


def test_a_step_of_the_wall_clock_is_not_a_restart(monkeypatch):
    def answers(t):
        m.clock.step = 2 * OLD_UPTIME
        return _online(OLD_UPTIME + t)
    m = _manager(monkeypatch, answers)
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=60) is False
    assert m.clock.now - m.start >= 60


def test_an_online_answer_without_an_uptime_proves_nothing(monkeypatch):
    m = _manager(monkeypatch, lambda t: _online(0))
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=60) is False


# -- the update task only waits for a reboot it sent ------------------------------------------------

def _task_manager(monkeypatch, ssh_execute, ssh=True):
    monkeypatch.setattr(mgrmod, 'time', _Clock())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    client = MagicMock()
    client.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.nodes_in_maintenance = {}
    m._get_node_ip = lambda node: '10.0.0.5'
    # the first connect is the update, the second one the reboot
    conns = iter([client, client if ssh else None])
    m._ssh_connect = lambda ip, **kw: next(conns)
    m._ssh_execute = ssh_execute
    m._schedule_update_clear = lambda node, task: None
    m.connect_to_proxmox = lambda: True
    # up the whole time with its old uptime, as a node that was not rebooted is
    m.get_node_status = lambda: {'n1': _online(OLD_UPTIME)}
    return m


def _run_task(m):
    task = UpdateTask('n1', reboot=True)
    PegaProxManager._perform_node_update(m, 'n1', task)
    return task


def test_a_node_that_needs_no_reboot_does_not_fail_the_update(monkeypatch):
    # needrestart is installed and says no restart: exit 0 on every command
    m = _task_manager(monkeypatch, lambda ssh, cmd, task=None: (0, '', ''))
    task = _run_task(m)
    assert task.status == 'completed', task.error
    assert task.reboot_issued is False and task.back_online is False
    assert not any('[ERROR]' in line['text'] for line in task.output_lines)


def test_no_connection_for_the_reboot_does_not_fail_the_update(monkeypatch):
    m = _task_manager(monkeypatch, lambda ssh, cmd, task=None: (0, '', ''), ssh=False)
    task = _run_task(m)
    assert task.status == 'completed', task.error
    assert task.reboot_issued is False
    # the update stands, but this reboot was wanted and did not happen: say so
    assert any('[ERROR]' in line['text'] and 'not rebooted' in line['text'] for line in task.output_lines)


def test_a_sent_reboot_is_still_waited_for(monkeypatch):
    # needrestart is not installed (exit 1): the reboot goes out, and this node never restarts
    m = _task_manager(monkeypatch, lambda ssh, cmd, task=None: (1 if 'dpkg -s needrestart' in cmd else 0, '', ''))
    task = _run_task(m)
    assert task.reboot_issued is True
    assert task.status == 'failed' and task.back_online is False


def test_a_reboot_done_before_the_wait_began_counts(monkeypatch):
    # up again within the seconds between the command and the wait, and never seen down
    m = _task_manager(monkeypatch, lambda ssh, cmd, task=None: (1 if 'dpkg -s needrestart' in cmd else 0, '', ''))
    clock = mgrmod.time
    channel = MagicMock()
    sent = []
    channel.exec_command.side_effect = lambda cmd: sent.append(clock.now)
    client = MagicMock()
    client.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())
    client.get_transport.return_value.open_session.return_value = channel
    m._ssh_connect = lambda ip, **kw: client
    m.get_node_status = lambda: {'n1': _online(clock.now - sent[0] - 1)}
    task = _run_task(m)
    assert sent and task.status == 'completed', task.error
    assert task.back_online is True
