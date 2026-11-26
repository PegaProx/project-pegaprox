"""A websocket the server closes does not take the process down.

A flask-sock route returns and pywsgi has the connection back while simple-websocket's
reader may still wait on it, for the client's answer to our close frame. pywsgi ends a
connection by closing the raw descriptor under the gevent socket, past that reader's
watcher, and libev aborts the whole process on it ("I/O watcher with invalid fd found in
epoll_ctl"). The handler now waits for the reader first.

The real _start_gevent_server in a subprocess, over TLS, as test_production_server_deadlines
runs it. The clients end the four ways a browser, a script or a scanner does. MK
"""
import base64
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

import gevent
import pytest

import pegaprox.app as app_mod
from test_redirect_head_deadline import _free_port, _tls_files

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAMMER_SECONDS = 12

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
from flask import Flask, request
from flask_sock import Sock
import pegaprox.app as app_mod

app_mod._start_console_servers = lambda *a, **k: None
web = Flask('ws-end-test')
sock = Sock()


@web.route('/ping')
def ping():
    return 'pong'


@sock.route('/refuse')
def refuse(ws):
    if request.environ.get(app_mod._WS_SERVER_ENVIRON) is not ws:
        print('WEBSOCKET NOT NOTED', flush=True)
    # a route that refuses the connection
    ws.close(reason=1008, message='refused')


sock.init_app(web)
app_mod._start_gevent_server(web, '127.0.0.1', int(sys.argv[1]), (sys.argv[2], sys.argv[3]),
                             None, 32)
'''


def _tls(port, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=timeout))


def _ping(port):
    s = _tls(port, 3)
    try:
        s.sendall(b'GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                return data
            data += chunk
    finally:
        s.close()


def _close_frame():
    payload = struct.pack('!H', 1000)
    mask = os.urandom(4)
    return bytes([0x88, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def _refused_websocket(port, ending):
    s = _tls(port)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f'GET /refuse HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                   f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = s.recv(4096)
            if not chunk:
                return
            head += chunk
        if ending == 'answers':
            s.sendall(_close_frame())
            while s.recv(4096):
                pass
        elif ending == 'answers and hangs up':
            s.sendall(_close_frame())
        elif ending == 'answers and asks again':
            s.sendall(_close_frame() + b'GET /ping HTTP/1.1\r\nHost: x\r\n\r\n')
            s.recv(4096)
        # 'hangs up': nothing
    finally:
        s.close()


@pytest.fixture
def server(tmp_path):
    cert, key = _tls_files(tmp_path)
    port = _free_port()
    log = open(tmp_path / 'server.log', 'w')
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(tmp_path / 'config')}
    proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port), cert, key],
                            cwd=str(tmp_path), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        end = time.monotonic() + 60
        while True:
            try:
                if b'pong' in _ping(port):
                    break
            except OSError:
                pass
            if proc.poll() is not None or time.monotonic() > end:
                log.flush()
                pytest.fail('test server did not come up:\n' + (tmp_path / 'server.log').read_text())
            gevent.sleep(0.2)
        yield proc, port, tmp_path / 'server.log'
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
        log.close()


def test_refused_websockets_do_not_abort_the_server(server):
    proc, port, log = server
    endings = ['answers', 'answers and hangs up', 'hangs up', 'answers and asks again']
    stop = time.monotonic() + HAMMER_SECONDS
    done = []

    def client(n):
        rnd = random.Random(n)
        while time.monotonic() < stop and proc.poll() is None:
            try:
                _refused_websocket(port, rnd.choice(endings))
                done.append(1)
            except OSError:
                pass

    clients = [threading.Thread(target=client, args=(n,), daemon=True) for n in range(16)]
    for c in clients:
        c.start()
    for c in clients:
        c.join(HAMMER_SECONDS + 15)
    assert proc.poll() is None, (f'server died after {len(done)} refused websockets:\n'
                                 + log.read_text()[-2000:])
    assert len(done) > 100, f'only {len(done)} websockets got through, the test proved nothing'
    assert b'pong' in _ping(port)
    assert 'WEBSOCKET NOT NOTED' not in log.read_text()


# --- the wait itself, without the race ------------------------------------------------

class _Sock:
    closed = False

    def __init__(self, gone):
        self.gone = gone

    def close(self):
        self.closed = True
        self.gone.set()


class _Websocket:
    """simple-websocket's server as far as the handler sees it: its reader thread ends
    after `reads` seconds, or once the socket is closed."""

    def __init__(self, reads):
        gone = threading.Event()
        self.sock = _Sock(gone)
        self.thread = threading.Thread(target=gone.wait, args=(reads,), daemon=True)
        self.thread.start()


def _handler(ws):
    class _Base:
        environ = None
        close_connection = False

        def run_application(self):
            # flask-sock built the server, it noted itself, the route returned
            self.environ = {app_mod._WS_SERVER_ENVIRON: ws}
            return ['']

    class _H(app_mod._IdleTimeoutMixin, _Base):
        pass

    return _H()


def test_the_connection_goes_back_once_the_reader_is_done():
    ws = _Websocket(reads=0.3)
    h = _handler(ws)
    h.run_application()
    assert not ws.thread.is_alive()
    assert h.close_connection is True
    assert ws.sock.closed is False, 'a reader that ends by itself keeps its own close'


def test_a_reader_waiting_for_ever_is_ended_by_closing_the_socket():
    ws = _Websocket(reads=None)
    app_mod._settle_websocket(ws, timeout=0.1)
    assert ws.sock.closed is True
    assert not ws.thread.is_alive()


def test_a_plain_request_is_left_alone():
    class _Base:
        environ = None
        close_connection = False

        def run_application(self):
            self.environ = {'PATH_INFO': '/api/health'}
            return ['ok']

    class _H(app_mod._IdleTimeoutMixin, _Base):
        pass

    h = _H()
    assert h.run_application() == ['ok']
    assert h.close_connection is False
