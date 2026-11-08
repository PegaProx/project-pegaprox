"""The look at an XCP-ng host after its reboot probes that host, and one lost connect is not a host going down.

The address came from _get_host_ip, which answers the pool's endpoint (config.host) when XAPI does not: with
the master away, a shut port there read as this member being down, and the next open port with its old uptime
was taken as back. A single connect that timed out did the same.
"""
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.xcpng as xcpngmod
from pegaprox.core.xcpng import XcpngManager

OLD_UPTIME = 3_000_000
ENDPOINT, MEMBER = '10.0.0.1', '10.0.0.7'


class _Clock:
    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __getattr__(self, name):
        import time
        return getattr(time, name)

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class _Xapi:
    """A pool master that knows h1 at MEMBER, until it stops answering."""
    def __init__(self):
        self.up = True
        self.host = self

    def _check(self):
        if not self.up:
            raise ConnectionRefusedError('master away')

    def get_all(self):
        self._check()
        return ['ref-h1']

    def get_hostname(self, ref):
        return 'h1'

    def get_name_label(self, ref):
        return 'h1'

    def get_address(self, ref):
        return MEMBER


def _manager(monkeypatch, port, xapi=None):
    """port(address, nth connect) raises for a shut port. The rows say h1 is online with an old uptime."""
    clock = _Clock()
    monkeypatch.setattr(xcpngmod, 'time', clock)
    m = XcpngManager.__new__(XcpngManager)
    m.logger = MagicMock()
    m.is_connected = True
    m.config = types.SimpleNamespace(host=ENDPOINT)
    m._api = lambda: xapi
    m._fetch_nodes = lambda api: [{'node': 'h1', 'status': 'online', 'uptime': OLD_UPTIME + clock.now}]
    m.nodes_updating = {}
    probed = []

    def connect(addr, timeout=None):
        probed.append(addr[0])
        port(addr[0], len(probed))
        return MagicMock()
    import socket
    monkeypatch.setattr(socket, 'create_connection', connect)
    return m, probed, clock


def _shut(*_):
    raise ConnectionRefusedError()


def test_no_address_from_xapi_is_no_answer_not_a_probe_of_the_endpoint(monkeypatch):
    m, probed, _ = _manager(monkeypatch, _shut, xapi=None)
    assert XcpngManager.node_reboot_look(m, 'h1') is None
    assert probed == []


def test_with_the_master_away_the_member_is_probed_where_xapi_last_had_it(monkeypatch):
    xapi = _Xapi()
    m, probed, _ = _manager(monkeypatch, lambda addr, n: None, xapi=xapi)
    assert XcpngManager.node_reboot_look(m, 'h1')['status'] == 'online'
    xapi.up = False
    probed.clear()

    def away(api):
        raise ConnectionRefusedError('master away')
    m._fetch_nodes = away
    assert XcpngManager.node_reboot_look(m, 'h1') is None
    assert probed == [MEMBER], probed


def test_a_shut_port_where_xapi_last_had_it_is_down(monkeypatch):
    xapi = _Xapi()
    state = {'shut': False}

    def port(addr, n):
        if state['shut'] and addr == MEMBER:
            raise ConnectionRefusedError()
    m, probed, _ = _manager(monkeypatch, port, xapi=xapi)
    XcpngManager.node_reboot_look(m, 'h1')
    xapi.up, state['shut'] = False, True
    probed.clear()
    assert XcpngManager.node_reboot_look(m, 'h1')['status'] == 'offline'
    assert probed == [MEMBER, MEMBER], probed


def test_one_failed_connect_is_not_a_host_going_down(monkeypatch):
    def once(addr, n):
        if n == 1:
            raise TimeoutError('timed out')
    m, probed, _ = _manager(monkeypatch, once, xapi=_Xapi())
    row = XcpngManager.node_reboot_look(m, 'h1')
    assert row and row['status'] == 'online', row
    assert len(probed) == 2


def test_two_failed_connects_a_moment_apart_are(monkeypatch):
    m, probed, clock = _manager(monkeypatch, _shut, xapi=_Xapi())
    assert XcpngManager.node_reboot_look(m, 'h1')['status'] == 'offline'
    assert probed == [MEMBER, MEMBER] and clock.slept == [2]


@pytest.mark.parametrize('blip_at', [1, 3])
def test_a_host_that_never_rebooted_is_not_waved_through_after_a_blip(monkeypatch, blip_at):
    def blip(addr, n):
        if n == blip_at:
            raise TimeoutError('timed out')
    m, _, clock = _manager(monkeypatch, blip, xapi=_Xapi())
    start = clock.now
    assert XcpngManager._wait_for_host_online(m, 'h1', timeout=120) is False
    assert clock.now - start >= 120
