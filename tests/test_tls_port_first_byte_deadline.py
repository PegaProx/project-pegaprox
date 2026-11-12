"""A TLS port drops a connection that sends nothing once the handshake timeout has passed.

Every TLS port runs DualProtocolWSGIServer now, which waits for the first byte of a
connection to tell TLS from plain HTTP before any handshake starts. That wait was bounded by
the keep-alive timeout (75 s), while the server the default ran before, which has no such
check, dropped a connection that sent nothing after the handshake timeout (30 s). So
`workers` sockets that only connect held the whole server more than twice as long.

The real server runs in a subprocess with a pool of two, PEGAPROX_HANDSHAKE_TIMEOUT at one
second and the keep-alive timeout at its default. MK
"""
import os
import socket
import ssl
import subprocess
import sys
import time

import gevent
import pytest

from test_redirect_head_deadline import _free_port, _https_get, _tls_files

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HANDSHAKE = 1.0
POOL = 2

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
from flask import Flask
import pegaprox.app as app_mod

app_mod._start_console_servers = lambda *a, **k: None
web = Flask('first-byte-test')


@web.route('/ping')
def ping():
    return 'pong'


app_mod._start_gevent_server(web, '127.0.0.1', int(sys.argv[1]), (sys.argv[2], sys.argv[3]),
                             None, int(sys.argv[4]))
'''


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    where = tmp_path_factory.mktemp('first-byte')
    cert, key = _tls_files(where)
    port = _free_port()
    log = open(where / 'server.log', 'w')
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(where / 'config'),
           'PEGAPROX_HANDSHAKE_TIMEOUT': str(HANDSHAKE)}
    env.pop('PEGAPROX_KEEPALIVE_TIMEOUT', None)
    proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port), cert, key, str(POOL)],
                            cwd=str(where), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        end = time.monotonic() + 60
        while True:
            try:
                if b'pong' in _https_get(port, timeout=2):
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


def _closed_by_server(s, within):
    """True when the server closes `s` inside `within` seconds."""
    s.settimeout(within)
    try:
        return s.recv(1) == b''
    except socket.timeout:
        return False
    except OSError:
        return True


def test_sockets_that_send_nothing_do_not_hold_the_pool(server):
    silent = [socket.create_connection(('127.0.0.1', server), timeout=5) for _ in range(POOL)]
    try:
        gevent.sleep(0.2)                   # both are holding their slot now
        t0 = time.monotonic()
        try:
            answer = _https_get(server, timeout=HANDSHAKE + 5)
        except OSError as e:
            answer = repr(e).encode()
        took = time.monotonic() - t0

        assert answer.endswith(b'pong'), f'{POOL} silent sockets held a pool of {POOL}: {answer[:120]!r}'
        assert took < HANDSHAKE + 3, f'answered after {took:.1f}s'
        assert all(_closed_by_server(s, 2) for s in silent)
    finally:
        for s in silent:
            s.close()


def test_a_client_that_waits_a_moment_before_its_hello_is_served(server):
    """The bound is the handshake's, not less: half of it before the hello still works."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(('127.0.0.1', server), timeout=5)
    gevent.sleep(HANDSHAKE / 2)
    s = ctx.wrap_socket(raw)
    try:
        s.sendall(b'GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()

    assert data.endswith(b'pong'), data[:120]
