"""One account must not be able to hold the request pool open with WebSockets (#988), and
consoles must not be able to hold it at all (#777).

A WebSocket on the main port is served by the request greenlet that accepted it, so it holds
a slot of the finite request pool for as long as it is open. SSE streams have had a cap per
account since the audit (MAX_SSE_STREAMS_PER_USER); the live-update socket had none, so any
signed-in viewer could open sockets until nobody else got an answer. Every live-update
socket counts against its account now (MAX_WS_PER_USER, with the slow bodies). Past the cap
the account's oldest socket is hung up rather than the new one refused, like the SSE
streams: a page that reconnects must never lock its owner out.

The consoles (VNC, node shell, VM terminal) came over from ports of their own and stay open
for hours by design; a few operators with console tabs would fill the pool. So a signed-in
console leaves the request pool and counts on budgets of its own: MAX_CONSOLES_PER_SESSION
per session, where the oldest console is hung up as above, and MAX_CONSOLES_PER_USER per
account and MAX_CONSOLES for the instance, where the new one is refused (close 4429, 1013)
rather than somebody else's hung up (test_shared_account_consoles.py). They no longer count
against MAX_WS_PER_USER, and not against the slow bodies either.

The sockets run over a real gevent server with the real app; the VNC console's relay is a
stand-in that echoes until its browser leaves, everything before it is the route.
"""
import json
import socket
import struct
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
VNC = '/api/clusters/cluster_1/vms/pve1/qemu/{vmid}/vncwebsocket?token={token}'


def _echo_relay(ws, *a, **kw):
    """The VNC console past PVE's upgrade: open until the browser leaves, echoing."""
    while True:
        try:
            data = ws.receive(timeout=1)
        except Exception:
            return
        if data is None:
            if getattr(ws, 'connected', False):
                continue
            return
        ws.send(data)


@pytest.fixture
def budgets(monkeypatch):
    """Fresh books for the sockets of this test."""
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', CAP, raising=False)
    monkeypatch.setattr(rtu, '_held_ws', {}, raising=False)
    monkeypatch.setattr(rtu, '_held_ws_sid', {}, raising=False)
    monkeypatch.setattr(rtu, '_held_consoles', set(), raising=False)
    monkeypatch.setattr(rtu, '_held_bodies', {}, raising=False)
    monkeypatch.setattr(rtu, '_request_pools', [], raising=False)


@pytest.fixture
def serve(api, budgets, monkeypatch):
    import pegaprox.api.vms as vms
    monkeypatch.setattr(vms, '_vnc_relay', _echo_relay)
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = '10.0.0.1'
    mgr.nodes = {'pve1': {'node': 'pve1', 'status': 'online'}}
    mgr.member_node_ip.return_value = '10.0.0.11'
    mgr.connect_to_proxmox.return_value = True
    api.set_manager('cluster_1', mgr)
    ppglobals.ws_clients.clear()
    pool = Pool(SLOTS)
    rtu.register_request_pool(pool)
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


def _console(api, connect, user, vmid=100):
    """A VNC console of the account, signed in and relaying when this returns."""
    from pegaprox.utils.realtime import create_ws_token
    ws = connect(VNC.format(vmid=vmid, token=create_ws_token(user['username'], user['role'])))
    assert _echoes(ws), 'the console did not get past the route'
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


def _echoes(ws):
    try:
        ws.settimeout(3)
        ws.send_binary(b'RFB')
        return ws.recv() == b'RFB'
    except Exception:
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


def _closed_with(ws):
    """(code, reason) of the close frame the server ended the socket with."""
    ws.settimeout(3)
    opcode, data = ws.recv_data(control_frame=True)
    assert opcode == websocket.ABNF.OPCODE_CLOSE, (opcode, data)
    return struct.unpack('!H', data[:2])[0], data[2:].decode()


def _sid(api, seed, name, role='user'):
    seed.user(name, role=role)
    return api.as_user({'username': name, 'role': role}).session_id


def _open_for(user):
    with ppglobals.ws_clients_lock:
        return sum(1 for c in ppglobals.ws_clients.values() if c.get('user') == user)


def _settle(check):
    end = time.monotonic() + 3
    while not check() and time.monotonic() < end:
        gevent.sleep(0.05)
    return check()


# --- the live-update socket ---------------------------------------------------------------

def test_the_oldest_socket_is_hung_up_past_the_cap(serve, api, seed):
    connect, pool = serve
    sid = _sid(api, seed, 'alice')
    first, second = _updates(connect, sid), _updates(connect, sid)

    third = _updates(connect, sid)

    assert _hung_up(first), 'the oldest socket of the account is still open past the cap'
    assert _alive(second) and _alive(third)
    assert _settle(lambda: _open_for('alice') <= CAP)
    assert _open_for('alice') == CAP


def test_a_hung_up_socket_gives_its_pool_slot_back(serve, api, seed):
    connect, pool = serve
    sid = _sid(api, seed, 'alice')
    for _ in range(CAP + 3):
        _updates(connect, sid)

    _settle(lambda: pool.free_count() >= SLOTS - CAP)

    assert pool.free_count() == SLOTS - CAP, \
        f'{SLOTS - pool.free_count()} slots held by one account with a cap of {CAP}'


def test_one_account_cannot_hang_up_another(serve, api, seed):
    connect, _ = serve
    bob = _updates(connect, _sid(api, seed, 'bob'))
    sid = _sid(api, seed, 'alice')
    for _ in range(CAP + 2):
        _updates(connect, sid)

    assert _alive(bob)


# --- consoles on budgets of their own -----------------------------------------------------

def test_a_console_does_not_count_against_the_live_update_cap(serve, api, seed):
    """The VNC console of the main port: hanging around for hours is its job, and opening
    one must not hang up the page's own live-update socket."""
    connect, _ = serve
    sid = _sid(api, seed, 'root2', role='admin')
    first, second = _updates(connect, sid), _updates(connect, sid)

    consoles = [_console(api, connect, {'username': 'root2', 'role': 'admin'}, vmid)
                for vmid in (100, 101, 102)]

    assert not _hung_up(first, within=0.5), 'opening a console hung up a live-update socket'
    assert _alive(first) and _alive(second)
    assert all(_echoes(ws) for ws in consoles)
    assert _open_for('root2') == 2 and rtu.consoles_open() == 3


def test_a_node_shell_does_not_count_against_the_live_update_cap(serve, api, seed):
    """A node shell waiting in its login dialog is a console as well."""
    connect, _ = serve
    sid = _sid(api, seed, 'root2', role='admin')
    first, second = _updates(connect, sid), _updates(connect, sid)

    shell = connect(f'/api/clusters/cluster_1/nodes/pve1/shellws?session={sid}')
    shell.settimeout(3)
    assert json.loads(shell.recv())['status'] == 'need_credentials'

    assert rtu.consoles_open() == 1
    assert not _hung_up(first, within=0.5), 'opening a node shell hung up a live-update socket'
    assert _alive(first) and _alive(second)


def test_the_oldest_console_is_hung_up_past_the_console_cap(serve, api, seed, monkeypatch):
    connect, _ = serve
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 2)
    sid = _sid(api, seed, 'root2', role='admin')
    page = _updates(connect, sid)
    root2 = {'username': 'root2', 'role': 'admin'}
    first, second = _console(api, connect, root2, 100), _console(api, connect, root2, 101)

    third = _console(api, connect, root2, 102)

    assert _hung_up(first), 'the oldest console of the account is still open past its cap'
    assert _echoes(second) and _echoes(third)
    assert _settle(lambda: rtu.consoles_open() == 2)
    # the live-update socket is not on that budget
    assert _alive(page)


def test_one_account_cannot_hang_up_anothers_console(serve, api, seed, monkeypatch):
    connect, _ = serve
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 2)
    seed.user('bob', role='admin')
    seed.user('alice', role='admin')
    bob = _console(api, connect, {'username': 'bob', 'role': 'admin'})
    for vmid in (100, 101, 102, 103):
        _console(api, connect, {'username': 'alice', 'role': 'admin'}, vmid)

    assert _echoes(bob)


def test_a_full_instance_refuses_the_new_console(serve, api, seed, monkeypatch):
    """Past MAX_CONSOLES the new console is refused with 1013 and says why; nobody's open
    console is hung up for it."""
    from pegaprox.api.vms import CONSOLES_FULL_ERROR
    connect, _ = serve
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 2)
    for name in ('alice', 'bob', 'carol'):
        seed.user(name, role='admin')
    alice = _console(api, connect, {'username': 'alice', 'role': 'admin'})
    bob = _console(api, connect, {'username': 'bob', 'role': 'admin'})

    from pegaprox.utils.realtime import create_ws_token
    carol = connect(VNC.format(vmid=100, token=create_ws_token('carol', 'admin')))

    assert _closed_with(carol) == (1013, CONSOLES_FULL_ERROR)
    assert _echoes(alice) and _echoes(bob)
    assert rtu.consoles_open() == 2

    # counterproof: once one is closed there is room again
    alice.close()
    assert _settle(lambda: rtu.consoles_open() == 1)
    assert _echoes(_console(api, connect, {'username': 'carol', 'role': 'admin'}))


def test_a_console_leaves_the_request_pool(serve, api, seed):
    """#777. A signed-in console gives its request slot back, so the pool keeps answering
    whatever the consoles do; the live-update socket keeps its slot."""
    connect, pool = serve
    seed.user('root2', role='admin')
    consoles = [_console(api, connect, {'username': 'root2', 'role': 'admin'}, vmid)
                for vmid in range(100, 100 + SLOTS + 2)]

    assert _settle(lambda: pool.free_count() == SLOTS), \
        f'{SLOTS - pool.free_count()} slots held by {SLOTS + 2} consoles'

    # counterproof: a live-update socket does hold one
    _updates(connect, _sid(api, seed, 'alice'))
    assert pool.free_count() == SLOTS - 1

    # and a console that ends gives back no slot it no longer held
    for ws in consoles:
        ws.close()
    assert _settle(lambda: rtu.consoles_open() == 0)
    gevent.sleep(0.2)
    assert pool.free_count() == SLOTS - 1


class _FakeWs:
    """A socket as far as _hang_up looks: sock (simple-websocket)."""

    def __init__(self):
        self.server_end, self.client_end = socket.socketpair()
        self.sock = self.server_end

    def close(self):
        self.server_end.close()
        self.client_end.close()


def test_the_plain_http_console_route_holds_nothing(api, seed, budgets):
    """vnc_websocket_route served an upgrade geventwebsocket had already made and counted
    it. The upgrade is flask-sock's alone now: the plain route answers 426, counts nothing
    and hangs nobody up, whatever the environment carries."""
    import pegaprox.api.vms as vms
    from pegaprox.utils.realtime import create_ws_token
    seed.user('root2', role='admin')
    old, new = _FakeWs(), _FakeWs()
    with api.app.test_request_context('/'):
        rtu.hold_websocket('root2', old, console=True)

    token = create_ws_token('root2', 'admin')
    with api.app.test_request_context(f'/api/clusters/nowhere/vms/pve1/qemu/100/vncwebsocket'
                                      f'?token={token}', environ_base={'wsgi.websocket': new}):
        _body, status = vms.vnc_websocket_route('nowhere', 'pve1', 'qemu', 100)

    assert status == 426
    assert rtu.consoles_open() == 1 and len(rtu._held_ws) == 1
    old.client_end.setblocking(False)
    with pytest.raises(BlockingIOError):
        old.client_end.recv(1)
    for f in (old, new):
        f.close()


@pytest.mark.parametrize('console', [False, True], ids=['socket', 'console'])
def test_a_released_socket_no_longer_counts(api, budgets, monkeypatch, console):
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 1)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 1)
    old, new = _FakeWs(), _FakeWs()
    with api.app.test_request_context('/'):
        rtu.hold_websocket('carol', old, console=console)
        api.app.process_response(api.app.response_class())    # the route returned
    assert rtu.consoles_open() == 0
    with api.app.test_request_context('/'):
        assert rtu.hold_websocket('carol', new, console=console) is True

    old.client_end.setblocking(False)
    with pytest.raises(BlockingIOError):
        old.client_end.recv(1)
    for f in (old, new):
        f.close()


def test_consoles_and_slow_bodies_keep_their_own_budgets(api, budgets, monkeypatch):
    """A slow body of an account with consoles open still gets its slot, and a console
    past the live-update cap hangs up none of the account's other sockets."""
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 1)
    page, consoles = _FakeWs(), [_FakeWs() for _ in range(3)]
    with api.app.test_request_context('/'):
        for ws in consoles:
            assert rtu.hold_websocket('dave', ws, console=True) is True
        key = rtu.hold_body('dave')
    assert key is not None, 'consoles took the slow body its slot'
    rtu.release_body(key)

    with api.app.test_request_context('/'):
        rtu.hold_websocket('dave', page)
        # counterproof: the live-update socket does fill the cap
        assert rtu.hold_body('dave') is None
    for ws in [page] + consoles:
        ws.client_end.setblocking(False)
        with pytest.raises(BlockingIOError):
            ws.client_end.recv(1)
        ws.close()


def test_the_default_cap_leaves_room_for_everyone_else():
    """Several tabs with their live-update socket fit; and with the SSE streams and the one
    body past the cap (#1052) one account still cannot hold the smallest default pool,
    max(32, cpus * 16). Consoles are not in this sum, they leave the pool."""
    from pegaprox.api.realtime import MAX_SSE_STREAMS_PER_SESSION
    assert rtu.MAX_WS_PER_USER >= 8
    assert rtu.MAX_WS_PER_USER + 1 + MAX_SSE_STREAMS_PER_SESSION < 32


def test_the_default_console_budgets(monkeypatch):
    """Several console tabs per session fit, several sessions per account, and the instance
    keeps half of its file descriptors for everything else: four per console while its
    greenlet has a database connection, browser, PVE, the file and its WAL."""
    import resource
    assert rtu.MAX_CONSOLES_PER_SESSION >= 8
    assert rtu.MAX_CONSOLES_PER_USER >= 3 * rtu.MAX_CONSOLES_PER_SESSION
    for soft, expected in ((1024, 128), (100, 64), (1_000_000, 2000),
                           (resource.RLIM_INFINITY, 2000)):
        monkeypatch.setattr(resource, 'getrlimit', lambda _which, soft=soft: (soft, soft))
        assert rtu._default_max_consoles() == expected, soft

    def unreadable(_which):
        raise OSError('no limits here')
    monkeypatch.setattr(resource, 'getrlimit', unreadable)
    assert rtu._default_max_consoles() == 128
