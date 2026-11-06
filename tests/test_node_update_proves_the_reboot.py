"""A node counts as back from its reboot only once it really restarted.

The wait slept 30 s and then took the first "online". A node that needs longer to shut down
still answers online then, so the update finished, maintenance ended and a rolling update
pulled the next node while this one went down.
"""
from unittest.mock import MagicMock

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager

OLD_UPTIME = 3_000_000


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _manager(monkeypatch, answers):
    """answers(t) is what the node looks like t seconds into the wait: a dict, None for a
    node missing from the list, or an exception to raise."""
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
        return {} if got is None else {'n1': got}
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


def test_a_node_missing_from_the_list_counts_as_down(monkeypatch):
    m = _manager(monkeypatch, lambda t: None if t < 60 else {'status': 'online'})
    assert PegaProxManager._wait_for_node_online(m, 'n1') is True
    assert m.clock.now - m.start >= 60


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


def test_an_online_answer_without_an_uptime_proves_nothing(monkeypatch):
    m = _manager(monkeypatch, lambda t: _online(0))
    assert PegaProxManager._wait_for_node_online(m, 'n1', timeout=60) is False
