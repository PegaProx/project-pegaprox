"""Plain HTTP on the HTTPS port is answered with a redirect, whatever http_redirect_port says.

With -1, the default of every install, _start_gevent_server ran its server without the
protocol check, and a browser that opened http://host:5000 got a connection reset instead
of a 301 (Chromium ERR_CONNECTION_RESET, curl exit code 56). A trusted proxy that forwards
plain HTTP with X-Forwarded-Proto: https got the same reset. -1 now means no extra port and
nothing else.

The real server runs in a subprocess, called the way main() calls it, with no redirect
setting at all: once on 127.0.0.1 and once on ::1. MK
"""
import os
import socket
import ssl
import subprocess
import sys
import time

import gevent
import pytest

from test_redirect_head_deadline import _tls_files

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = '/vms/101?tab=console&x=1'

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
from flask import Flask
import pegaprox.app as app_mod

app_mod._start_console_servers = lambda *a, **k: None
web = Flask('redirect-defaults')


@web.route('/ping')
def ping():
    return 'pong'


app_mod._start_gevent_server(web, sys.argv[1], int(sys.argv[2]), (sys.argv[3], sys.argv[4]),
                             None, 4)
'''


def _ipv6():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(('::1', 0))
        return True
    except OSError:
        return False


def _free_port(host):
    with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _connect(host, port, src=None, timeout=5):
    s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
    s.settimeout(timeout)
    if src:
        s.bind((src, 0))
    s.connect((host, port))
    return s


def _read_all(s):
    data = b''
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except ConnectionResetError:
        data += b'<reset>'
    finally:
        s.close()
    return data


def _plain(host, port, head, src=None, timeout=5):
    """Send a plain-HTTP request head, return everything that comes back. A reset reads as
    the marker <reset>, which no answer starts with."""
    s = _connect(host, port, src, timeout)
    s.sendall(head.encode())
    return _read_all(s)


def _tls_get(host, port, path='/ping', timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(_connect(host, port, timeout=timeout))
    s.sendall(f'GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'.encode())
    return _read_all(s)


def _location(answer):
    for line in answer.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]:
        name, _, value = line.partition(b':')
        if name.strip().lower() == b'location':
            return value.strip().decode()
    return None


def _start(where, host):
    cert, key = _tls_files(where)
    port = _free_port(host)
    log = open(where / 'server.log', 'w')
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(where / 'config')}
    proc = subprocess.Popen([sys.executable, '-c', _SERVER, host, str(port), cert, key],
                            cwd=str(where), env=env, stdout=log, stderr=subprocess.STDOUT)
    end = time.monotonic() + 60
    while True:
        try:
            if b'pong' in _tls_get(host, port, timeout=2):
                return proc, log, port
        except OSError:
            pass
        if proc.poll() is not None or time.monotonic() > end:
            log.flush()
            _stop(proc, log)
            pytest.fail('test server did not come up:\n' + (where / 'server.log').read_text())
        gevent.sleep(0.2)


def _stop(proc, log):
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)
    log.close()


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    proc, log, port = _start(tmp_path_factory.mktemp('redirect4'), '127.0.0.1')
    yield port
    _stop(proc, log)


@pytest.fixture(scope='module')
def server6(tmp_path_factory):
    if not _ipv6():
        pytest.skip('no IPv6 loopback here')
    proc, log, port = _start(tmp_path_factory.mktemp('redirect6'), '::1')
    yield port
    _stop(proc, log)


def test_plain_http_and_tls_share_the_port_by_default(server):
    answer = _plain('127.0.0.1', server,
                    f'GET {PATH} HTTP/1.1\r\nHost: 127.0.0.1:{server}\r\nConnection: close\r\n\r\n')

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://127.0.0.1:{server}{PATH}'
    assert _tls_get('127.0.0.1', server).endswith(b'pong')


def test_an_ipv6_client_is_sent_to_its_bracketed_address(server6):
    answer = _plain('::1', server6,
                    f'GET {PATH} HTTP/1.1\r\nHost: [::1]:{server6}\r\nConnection: close\r\n\r\n')

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://[::1]:{server6}{PATH}'
    assert _tls_get('::1', server6).endswith(b'pong')


def test_a_trusted_proxy_that_terminated_tls_is_served(server):
    """Loopback is always a trusted proxy (utils.audit._is_trusted_proxy)."""
    answer = _plain('127.0.0.1', server, 'GET /ping HTTP/1.1\r\nHost: pegaprox.example\r\n'
                                         'X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n')

    assert answer.startswith(b'HTTP/1.1 200'), answer[:120]
    assert answer.endswith(b'pong')
