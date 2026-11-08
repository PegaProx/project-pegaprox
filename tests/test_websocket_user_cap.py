"""One account must not be able to hold the request pool open with WebSockets (#988).

A WebSocket on the main port is served by the request greenlet that accepted it, so it holds
a slot of the finite request pool for as long as it is open. SSE streams have had a cap per
account since the audit (MAX_SSE_STREAMS_PER_USER); the live-update socket and the consoles
had none, so any signed-in viewer could open sockets until nobody else got an answer.

Now every main-port WebSocket counts against its account. Past the cap the account's oldest
socket is hung up rather than the new one refused, like the SSE streams: a console that
reconnects must never lock its owner out.

The live-update socket runs over a real gevent server with the real app, and the cap is set
to two so a handful of sockets shows it.
"""
import json
import socket
import time

import gevent
import pytest
import websocket
from gevent.pool import Pool
from gevent.pywsgi import WSGIHandler, WSGIServer

import pegaprox.app as app_mod
import pegaprox.globals as ppglobals
import pegaprox.utils.realtime as rtu

CAP = 2
SLOTS = 16


@pytest.fixture
def serve(api, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', CAP, raising=False)
    monkeypatch.setattr(rtu, '_held_ws', {}, raising=False)
    ppglobals.ws_clients.clear()
    pool = Pool(SLOTS)
    # flask-sock routes are served by the plain pywsgi handler in production as well
    # (_should_bypass_gevent_upgrade)
    handler = type('Handler', (app_mod._IdleTimeoutMixin, WSGIHandler), {})
    srv = WSGIServer(('127.0.0.1', 0), api.app, handler_class=handler, spawn=pool,
                     log=None, error_log=None)
    srv.start()
    opened = []

    def connect(path):
        ws = websocket.create_connection(f'ws://127.0.0.1:{srv.server_port}{path}', timeout=5)
        opened.append(ws)
        return ws

    yield connect, pool
    for ws in opened:
        try:
            ws.close()
        except Exception:
            pass
    srv.stop(timeout=2)
    ppglobals.ws_clients.clear()


def _updates(connect, sid):
    ws = connect('/api/ws/updates')
    ws.send(json.dumps({'session_id': sid}))
    assert json.loads(ws.recv())['type'] == 'connected'
    return ws


def _alive(ws):
    end = time.monotonic() + 3
    try:
        ws.settimeout(3)
        ws.send(json.dumps({'type': 'ping'}))
        while time.monotonic() < end:
            if json.loads(ws.recv()).get('type') == 'pong':
                return True
    except Exception:
        pass
    return False


def _hung_up(ws, within=3):
    ws.settimeout(within)
    end = time.monotonic() + within
    try:
        while time.monotonic() < end:
            if not ws.recv():
                return True
    except Exception as e:
        return not isinstance(e, websocket.WebSocketTimeoutException)
    return False


def _sid(api, seed, name, role='user'):
    seed.user(name, role=role)
    return api.as_user({'username': name, 'role': role}).session_id


def _open_for(user):
    with ppglobals.ws_clients_lock:
        return sum(1 for c in ppglobals.ws_clients.values() if c.get('user') == user)


def test_the_oldest_socket_is_hung_up_past_the_cap(serve, api, seed):
    connect, pool = serve
    sid = _sid(api, seed, 'alice')
    first, second = _updates(connect, sid), _updates(connect, sid)

    third = _updates(connect, sid)

    assert _hung_up(first), 'the oldest socket of the account is still open past the cap'
    assert _alive(second) and _alive(third)
    end = time.monotonic() + 3
    while _open_for('alice') > CAP and time.monotonic() < end:
        gevent.sleep(0.05)
    assert _open_for('alice') == CAP


def test_a_hung_up_socket_gives_its_pool_slot_back(serve, api, seed):
    connect, pool = serve
    sid = _sid(api, seed, 'alice')
    for _ in range(CAP + 3):
        _updates(connect, sid)

    end = time.monotonic() + 3
    while pool.free_count() < SLOTS - CAP and time.monotonic() < end:
        gevent.sleep(0.05)

    assert pool.free_count() == SLOTS - CAP, \
        f'{SLOTS - pool.free_count()} slots held by one account with a cap of {CAP}'


def test_one_account_cannot_hang_up_another(serve, api, seed):
    connect, _ = serve
    bob = _updates(connect, _sid(api, seed, 'bob'))
    sid = _sid(api, seed, 'alice')
    for _ in range(CAP + 2):
        _updates(connect, sid)

    assert _alive(bob)


def test_a_console_counts_against_the_same_cap(serve, api, seed):
    """The VNC console of the main port: hanging around for hours is its job."""
    from pegaprox.utils.realtime import create_ws_token
    connect, _ = serve
    sid = _sid(api, seed, 'root2', role='admin')
    first, second = _updates(connect, sid), _updates(connect, sid)

    connect(f'/api/clusters/nowhere/vms/pve1/qemu/100/vncwebsocket'
            f'?token={create_ws_token("root2", "admin")}')

    assert _hung_up(first), 'opening a console did not count against the account'
    assert _alive(second)


def test_a_node_shell_counts_against_the_same_cap(serve, api, seed):
    connect, _ = serve
    sid = _sid(api, seed, 'root2', role='admin')
    first, second = _updates(connect, sid), _updates(connect, sid)

    shell = connect(f'/api/clusters/nowhere/nodes/pve1/shellws?session={sid}')
    shell.settimeout(3)
    shell.recv()                            # the route has run when it answers

    assert _hung_up(first), 'opening a node shell did not count against the account'
    assert _alive(second)


class _FakeWs:
    """A geventwebsocket socket as far as _hang_up looks: handler.socket."""

    def __init__(self):
        self.server_end, self.client_end = socket.socketpair()
        self.handler = type('H', (), {'socket': self.server_end})()


def test_the_gevent_websocket_console_counts_too(api, seed, monkeypatch):
    """vnc_websocket_route serves an upgrade geventwebsocket has already made."""
    import pegaprox.api.vms as vms
    from pegaprox.utils.realtime import create_ws_token
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 1, raising=False)
    monkeypatch.setattr(rtu, '_held_ws', {}, raising=False)
    seed.user('root2', role='admin')
    old, new = _FakeWs(), _FakeWs()
    with api.app.test_request_context('/'):
        rtu.hold_websocket('root2', old)

    token = create_ws_token('root2', 'admin')
    with api.app.test_request_context(f'/api/clusters/nowhere/vms/pve1/qemu/100/vncwebsocket'
                                      f'?token={token}', environ_base={'wsgi.websocket': new}):
        vms.vnc_websocket_route('nowhere', 'pve1', 'qemu', 100)

    old.client_end.settimeout(2)
    assert old.client_end.recv(1) == b'', 'the older socket of the account is still connected'
    new.client_end.setblocking(False)
    with pytest.raises(BlockingIOError):
        new.client_end.recv(1)
    for f in (old, new):
        f.server_end.close()
        f.client_end.close()


def test_a_released_socket_no_longer_counts(api, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 1, raising=False)
    monkeypatch.setattr(rtu, '_held_ws', {}, raising=False)
    old, new = _FakeWs(), _FakeWs()
    with api.app.test_request_context('/'):
        rtu.hold_websocket('carol', old)
        api.app.process_response(api.app.response_class())    # the route returned
    with api.app.test_request_context('/'):
        rtu.hold_websocket('carol', new)

    old.client_end.setblocking(False)
    with pytest.raises(BlockingIOError):
        old.client_end.recv(1)
    for f in (old, new):
        f.server_end.close()
        f.client_end.close()


def test_the_default_cap_leaves_room_for_everyone_else():
    """Several console tabs fit; and with the SSE streams and the one body past the cap
    (#1052) one account still cannot hold the smallest default pool, max(32, cpus * 16)."""
    from pegaprox.api.realtime import MAX_SSE_STREAMS_PER_USER
    assert rtu.MAX_WS_PER_USER >= 8
    assert rtu.MAX_WS_PER_USER + 1 + MAX_SSE_STREAMS_PER_USER < 32
