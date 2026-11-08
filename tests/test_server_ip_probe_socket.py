# The address PegaProx hands the nodes for its agent comes from a UDP socket pointed at the
# cluster. When connect failed (no route in that address family), the socket stayed open
# until the garbage collector found it.

import socket

from pegaprox.core.manager import PegaProxManager


class _Sock:
    made = []
    connect_fails = True

    def __init__(self, *a, **k):
        self.closed = False
        _Sock.made.append(self)

    def connect(self, addr):
        if _Sock.connect_fails:
            raise OSError(101, 'Network is unreachable')

    def getsockname(self):
        return ('192.0.2.5', 40000)

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _mgr(monkeypatch, fails):
    _Sock.made, _Sock.connect_fails = [], fails
    monkeypatch.setattr(socket, 'socket', _Sock)
    monkeypatch.setattr(socket, 'gethostname', lambda: 'pp-host')
    monkeypatch.setattr(PegaProxManager, 'raw_host', property(lambda self: '2001:db8::10'))
    mgr = object.__new__(PegaProxManager)
    mgr._resolve_host = lambda h: h if h == '2001:db8::10' else '192.0.2.7'
    return mgr


def test_the_probe_socket_is_closed_when_it_cannot_connect(monkeypatch):
    mgr = _mgr(monkeypatch, fails=True)
    assert mgr._get_pegaprox_server_ip() == '192.0.2.7'
    assert _Sock.made and all(s.closed for s in _Sock.made)


def test_the_probe_still_answers_the_outgoing_address(monkeypatch):
    mgr = _mgr(monkeypatch, fails=False)
    assert mgr._get_pegaprox_server_ip() == '192.0.2.5'
    assert _Sock.made and all(s.closed for s in _Sock.made)
