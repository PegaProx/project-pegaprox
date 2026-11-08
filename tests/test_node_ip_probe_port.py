"""Finding a node's management address probes the SSH port only where SSH is used. With
SSH switched off for a cluster nothing ever connects there, and a knock on port 22 of a
hardened node is noise in its log: the API port says whether the address answers.

MK Oct 2026
"""
import logging
import socket
import types

import pytest

from pegaprox.core.manager import PegaProxManager


class _Answer:
    def __init__(self, code, data=None):
        self.status_code = code
        self._data = data

    def json(self):
        return {'data': self._data}


def _manager(ssh_disabled, ssh_port=22):
    def api_get(url, **kw):
        if url.endswith('/cluster/status'):
            return _Answer(200, [{'type': 'node', 'name': 'pve1', 'ip': '10.0.0.1', 'local': 1},
                                 {'type': 'node', 'name': 'pve2', 'ip': '10.0.0.2', 'local': 0}])
        return _Answer(404)
    return types.SimpleNamespace(
        is_connected=True, host='10.0.0.1', api_port=8006, logger=logging.getLogger('test'),
        config=types.SimpleNamespace(host='10.0.0.1', ssh_port=ssh_port, ssh_disabled=ssh_disabled),
        _api_get=api_get)


@pytest.fixture
def knocks(monkeypatch):
    seen = []

    class _Socket:
        def __init__(self, *a, **kw):
            pass

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            seen.append(addr[:2])
            return 0

        def close(self):
            pass
    monkeypatch.setattr(socket, 'socket', _Socket)
    return seen


@pytest.mark.parametrize('ssh_disabled,port', [(True, 8006), (False, 22)])
def test_the_probe_knocks_on_the_port_that_will_be_used(knocks, ssh_disabled, port):
    ip = PegaProxManager._get_node_ip_impl(_manager(ssh_disabled), 'pve2')
    assert ip == '10.0.0.2'
    assert knocks == [('10.0.0.2', port)]


def test_a_cluster_with_ssh_off_never_knocks_on_its_ssh_port(knocks):
    PegaProxManager._get_node_ip_impl(_manager(True, ssh_port=2222), 'pve2')
    assert knocks and all(port not in (22, 2222) for _, port in knocks)
