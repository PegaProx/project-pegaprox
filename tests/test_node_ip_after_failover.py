"""In a failover the configured host is a member like any other.

The cluster is reached through pve1 (192.168.1.2) because its configured host 192.168.1.3,
pve2, dropped a connection. Node address resolution skipped every candidate equal to the
configured host, so pve2 had no address at all: no SSH to it, and its own root password
(#1136) was never offered or checked. What no other node may resolve to is the host the
manager is connected to.
"""
import logging
import types

import pytest

from pegaprox.core.manager import PegaProxManager


class _Answer:
    def __init__(self, code, data=None):
        self.status_code = code
        self._data = data

    def json(self):
        return {'data': self._data}


STATUS = [{'type': 'node', 'name': 'pve1', 'ip': '192.168.1.2', 'local': 1},
          {'type': 'node', 'name': 'pve2', 'ip': '192.168.1.3', 'local': 0},
          {'type': 'node', 'name': 'pve3', 'ip': '192.168.1.4', 'local': 0}]


def _manager(connected, configured):
    def api_get(url, **kw):
        if url.endswith('/cluster/status'):
            return _Answer(200, STATUS)
        return _Answer(595)
    return types.SimpleNamespace(
        id='lab', is_connected=True, host=connected, raw_host=connected, api_port=8006,
        logger=logging.getLogger('test'),
        config=types.SimpleNamespace(host=configured, ssh_port=22, ssh_disabled=False),
        _api_get=api_get)


@pytest.fixture
def ssh_answers(monkeypatch):
    """Every node's SSH port answers; DNS knows nothing."""
    import socket
    knocked = []

    class _Socket:
        def __init__(self, *a, **kw):
            pass

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            knocked.append(addr[0])
            return 0

        def close(self):
            pass

    def _no_dns(name, *a, **kw):
        raise socket.gaierror('no such name')
    monkeypatch.setattr(socket, 'socket', _Socket)
    monkeypatch.setattr(socket, 'getaddrinfo', _no_dns)
    return knocked


def test_the_configured_host_node_keeps_its_address_in_a_failover(ssh_answers):
    m = _manager(connected='192.168.1.2', configured='192.168.1.3')
    assert PegaProxManager._get_node_ip_impl(m, 'pve2') == '192.168.1.3'
    assert PegaProxManager._get_node_ip_impl(m, 'pve3') == '192.168.1.4'
    # the node it is connected through still answers with the connected host
    assert PegaProxManager._get_node_ip_impl(m, 'pve1') == '192.168.1.2'


def test_no_other_node_resolves_to_the_connected_host(ssh_answers):
    """Counterproof for the filter that stays: a member listed at the connected host's
    address is not handed that address."""
    m = _manager(connected='192.168.1.2', configured='192.168.1.3')
    rows = [dict(r) for r in STATUS]
    rows[2]['ip'] = '192.168.1.2'
    m._api_get = lambda url, **kw: _Answer(200, rows) if url.endswith('/cluster/status') else _Answer(595)
    assert PegaProxManager._get_node_ip_impl(m, 'pve3') != '192.168.1.2'


def test_without_a_failover_nothing_changes(ssh_answers):
    m = _manager(connected='192.168.1.3', configured='192.168.1.3')
    rows = [dict(r, local=1 if r['name'] == 'pve2' else 0) for r in STATUS]
    m._api_get = lambda url, **kw: _Answer(200, rows) if url.endswith('/cluster/status') else _Answer(595)
    assert PegaProxManager._get_node_ip_impl(m, 'pve2') == '192.168.1.3'
    assert PegaProxManager._get_node_ip_impl(m, 'pve1') == '192.168.1.2'
