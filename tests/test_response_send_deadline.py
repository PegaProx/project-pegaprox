"""A client that takes none of an answer gives its request slot back (#1052).

The mirror image of a body that never arrives. handle() clears the socket timeout, so a
client that asks for something large - index.html is 7 MB and needs no login - and then
reads none of it parked pywsgi's write, and the request slot, once the socket buffers were
full. `workers` such clients were the whole server, and the body deadline never saw them.

A write now has PEGAPROX_SEND_TIMEOUT to make progress. Like nginx's send_timeout the clock
is on progress, not on the whole answer, so a slow link still gets everything.
"""
import socket
import time

import gevent
import pytest
from flask import Flask
from gevent.pool import Pool
from gevent.pywsgi import WSGIHandler, WSGIServer

import pegaprox.app as app_mod

SEND = 0.5
# well past what the socket buffers of loopback take in
BIG = 16 * 1024 * 1024


def _app():
    web = Flask('send-deadline')
    blob = b'x' * BIG

    @web.route('/big')
    def big():
        return blob

    @web.route('/ping')
    def ping():
        return 'pong'
    return web


@pytest.fixture
def serve():
    servers = []

    def start(app, slots=2, send=SEND):
        handler = type('Handler', (app_mod._IdleTimeoutMixin, WSGIHandler), {'_send_timeout': send})
        srv = WSGIServer(('127.0.0.1', 0), app, handler_class=handler, spawn=Pool(slots),
                         log=None, error_log=None)
        srv.start()
        servers.append(srv)
        return srv.server_port

    yield start
    for srv in servers:
        srv.stop(timeout=1)


def _stalled(port, path):
    """Ask for `path` and read nothing, with a receive window as small as it gets."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.settimeout(5)
    s.connect(('127.0.0.1', port))
    s.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
    return s


def _get(port, path, within):
    s = socket.create_connection(('127.0.0.1', port), timeout=within)
    data = b''
    try:
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return data


def test_clients_that_read_nothing_do_not_hold_the_pool(serve):
    port = serve(_app())
    stalled = [_stalled(port, '/big') for _ in range(2)]
    gevent.sleep(0.3)                       # both answers are stuck in their writes now

    t0 = time.monotonic()
    answer = _get(port, '/ping', within=SEND + 4)

    assert answer.endswith(b'pong'), f'two stalled readers still hold a pool of two: {answer[:80]!r}'
    assert time.monotonic() - t0 < SEND + 4
    for s in stalled:
        s.close()


def test_index_html_needs_no_login_and_holds_no_slot(api, serve):
    """The finding as an anonymous client meets it: the real app's start page."""
    port = serve(api.app)
    stalled = [_stalled(port, '/') for _ in range(2)]
    gevent.sleep(0.3)

    answer = _get(port, '/api/health', within=SEND + 4)

    assert b' 200 ' in answer.split(b'\r\n', 1)[0], f'/api/health got {answer[:80]!r}'
    for s in stalled:
        s.close()


def test_a_slow_link_still_gets_the_whole_answer(serve):
    """Pauses shorter than the deadline, and the whole transfer many times longer."""
    port = serve(_app())
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(b'GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    data, pause_at, t0 = bytearray(), 1 << 20, time.monotonic()
    while True:
        chunk = s.recv(1 << 16)
        if not chunk:
            break
        data += chunk
        if len(data) >= pause_at:
            pause_at += 2 << 20
            gevent.sleep(SEND * 0.6)
    s.close()

    head, _, body = bytes(data).partition(b'\r\n\r\n')
    assert b' 200 ' in head.split(b'\r\n', 1)[0]
    assert len(body) == BIG, f'the answer was cut at {len(body)} of {BIG} bytes'
    assert time.monotonic() - t0 > 3 * SEND


def test_an_error_answer_pywsgi_writes_itself_is_on_the_clock_too():
    """A 400 for a broken request (or one past the header deadline) goes from pywsgi's
    handle() straight to the socket. A client that pipelined requests and read none of
    the answers has the buffers full by then."""
    from gevent import socket as gsocket
    ours, theirs = gsocket.socketpair()
    ours.settimeout(0)
    try:
        while True:
            ours.send(b'x' * 65536)
    except OSError:
        pass                                # full: the next write waits for a reader
    ours.settimeout(None)

    class _Base:
        def handle_one_request(self):
            return ('400', b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')

    class _H(app_mod._IdleTimeoutMixin, _Base):
        _send_timeout = SEND

    h = _H()
    h.socket = ours
    t0 = time.monotonic()
    with gevent.Timeout(SEND + 3):
        assert h.handle_one_request() is None, 'the connection has to close after it'
    assert time.monotonic() - t0 < SEND + 2
    ours.close()
    theirs.close()


def test_a_disabled_send_bound_leaves_writes_alone():
    """PEGAPROX_SEND_TIMEOUT=0 restores what was there before."""
    sent = []

    class _Base:
        def _sendall(self, data):
            sent.append(data)

    class _H(app_mod._IdleTimeoutMixin, _Base):
        _send_timeout = 0

    _H()._sendall(b'x' * 200000)

    assert sent == [b'x' * 200000]
