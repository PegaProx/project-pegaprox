"""The body and send deadlines in the server production runs (#1052).

The other tests compose _IdleTimeoutMixin onto a bare pywsgi handler. Production puts it on
geventwebsocket's handler, sends flask-sock routes around it (_should_bypass_gevent_upgrade)
and speaks TLS, and the body clock now stands in wsgi.input for every request, an upgrade
included. Both WebSocket libraries have to keep finding their stream behind it.

The real _start_gevent_server runs in a subprocess with a pool of two and one-second
deadlines. MK
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import time

import gevent
import pytest
import websocket

from test_redirect_head_deadline import _free_port, _tls_files

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEADLINE = 1.0

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
from flask import Flask, request
from flask_sock import Sock
import pegaprox.app as app_mod

app_mod._start_console_servers = lambda *a, **k: None
web = Flask('deadline-test')
# as api/realtime.py does it: the routes land on flask-sock's own blueprint, which is how
# _should_bypass_gevent_upgrade tells them apart
sock = Sock()
big = b'x' * (16 * 1024 * 1024)


@web.route('/ping')
def ping():
    return 'pong'


@web.route('/login', methods=['POST'])
def login():
    return {'got': len(request.get_json(silent=True) or {})}


@web.route('/big')
def bigger():
    return big


@sock.route('/sock')
def echo_sock(ws):
    while True:
        msg = ws.receive(timeout=10)
        if msg is None:
            return
        ws.send('sock:' + msg)


@web.route('/gws', websocket=True)
def echo_gws():
    ws = request.environ.get('wsgi.websocket')
    if ws is None:
        return 'no websocket', 426
    while True:
        msg = ws.receive()
        if msg is None:
            return ''
        ws.send('gws:' + msg)


sock.init_app(web)
app_mod._start_gevent_server(web, '127.0.0.1', int(sys.argv[1]), (sys.argv[2], sys.argv[3]),
                             None, 2, http_redirect_port=-1)
'''


def _tls(port, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=timeout))


def _get(port, path, within=5):
    s = _tls(port, within)
    data = b''
    try:
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'.encode())
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    finally:
        s.close()
    return data


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    where = tmp_path_factory.mktemp('deadlines')
    cert, key = _tls_files(where)
    port = _free_port()
    log = open(where / 'server.log', 'w')
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(where / 'config'),
           'PEGAPROX_BODY_TIMEOUT': str(DEADLINE), 'PEGAPROX_SEND_TIMEOUT': str(DEADLINE)}
    proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port), cert, key],
                            cwd=str(where), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        end = time.monotonic() + 60
        while True:
            try:
                if b'pong' in _get(port, '/ping', 2):
                    break
            except OSError:
                pass
            if proc.poll() is not None or time.monotonic() > end:
                log.flush()
                pytest.fail('test server did not come up:\n' + (where / 'server.log').read_text())
            gevent.sleep(0.2)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
        log.close()


def _ws(port, path):
    return websocket.create_connection(f'wss://127.0.0.1:{port}{path}', timeout=5,
                                       sslopt={'cert_reqs': ssl.CERT_NONE})


@pytest.mark.parametrize('path,prefix', [('/sock', 'sock:'), ('/gws', 'gws:')])
def test_both_websocket_libraries_still_find_their_stream(server, path, prefix):
    """flask-sock takes the socket from wsgi.input, geventwebsocket the handler's rfile.
    Longer than the body deadline, so the clock is not what ends it."""
    ws = _ws(server, path)
    try:
        ws.send('one')
        assert ws.recv() == prefix + 'one'
        gevent.sleep(DEADLINE + 0.5)
        ws.send('two')
        assert ws.recv() == prefix + 'two'
    finally:
        ws.close()


@pytest.mark.parametrize('upgrade', ['Connection: Upgrade', 'Upgrade: websocket'])
def test_an_upgrade_header_on_a_withheld_body_does_not_hold_the_pool(server, upgrade):
    parked = []
    for _ in range(2):
        s = _tls(server)
        s.sendall((f'POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n'
                   f'{upgrade}\r\nContent-Length: 64\r\n\r\n').encode())
        parked.append(s)
    gevent.sleep(0.2)

    t0 = time.monotonic()
    answer = _get(server, '/ping', within=DEADLINE + 5)

    assert answer.endswith(b'pong'), f'two withheld bodies held a pool of two: {answer[:80]!r}'
    assert time.monotonic() - t0 < DEADLINE + 5
    for s in parked:
        s.close()


def test_a_prompt_body_with_an_upgrade_header_is_still_read(server):
    s = _tls(server)
    body = json.dumps({'a': 1, 'b': 2}).encode()
    s.sendall((f'POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n'
               f'Connection: Upgrade\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body)
    data = b''
    while b'}' not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()

    assert b'"got":2' in data.replace(b' ', b'')


def test_stalled_readers_over_tls_do_not_hold_the_pool(server):
    stalled = []
    for _ in range(2):
        raw = socket.socket()
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        raw.settimeout(5)
        raw.connect(('127.0.0.1', server))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw)
        s.sendall(b'GET /big HTTP/1.1\r\nHost: x\r\n\r\n')
        stalled.append(s)
    gevent.sleep(0.3)

    answer = _get(server, '/ping', within=DEADLINE + 5)

    assert answer.endswith(b'pong'), f'two stalled readers held a pool of two: {answer[:80]!r}'
    for s in stalled:
        s.close()
