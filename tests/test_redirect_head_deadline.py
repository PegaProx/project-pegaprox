"""The plain-HTTP redirect on the HTTPS port has one deadline for the whole request (#997).

DualProtocolWSGIServer looks at the first byte of a connection, and a plaintext one goes to
_handle_http_redirect, inside the request pool. That read had a 5 second timeout per recv()
and nothing over all of them, so a client sending one byte every few seconds kept its slot
for hours, and `workers` such clients made the instance unreachable without a login or a
certificate. The handshake and header timeouts of the TLS side never applied here.

The real server runs in a subprocess (gevent's monkey patching and the stderr filter it
installs belong to a process of their own), with a pool of two and PEGAPROX_HEADER_TIMEOUT
at 1.5 seconds. MK
"""
import datetime
import ipaddress
import os
import socket
import ssl
import subprocess
import sys
import time

import gevent
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEAD_DEADLINE = 1.5

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
from flask import Flask
import pegaprox.app as app_mod

app_mod._start_console_servers = lambda *a, **k: None
web = Flask('redirect-test')


@web.route('/ping')
def ping():
    return 'pong'


app_mod._start_gevent_server(web, '127.0.0.1', int(sys.argv[1]), (sys.argv[2], sys.argv[3]),
                             None, 2, http_redirect_port=0)
'''


def _tls_files(where):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'pegaprox-test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
    cf, kf = where / 'cert.pem', where / 'key.pem'
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cf), str(kf)


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _https_get(port, path='/ping', timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    s = ctx.wrap_socket(raw)
    try:
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'.encode())
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                return data
            data += chunk
    finally:
        s.close()


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    where = tmp_path_factory.mktemp('redirect')
    cert, key = _tls_files(where)
    port = _free_port()
    log = open(where / 'server.log', 'w')
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(where / 'config'),
           'PEGAPROX_HEADER_TIMEOUT': str(HEAD_DEADLINE)}
    proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port), cert, key],
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


def _drip(port, until):
    """Send a request head one byte at a time and never finish it. Returns how long the
    server kept the connection, or None if it was still open at the end."""
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    start = time.monotonic()
    head = b'GET / HTTP/1.1\r\nHost: x\r\nX-Pad: '
    i = 0
    try:
        while time.monotonic() - start < until:
            try:
                s.sendall(head[i:i + 1] if i < len(head) else b'a')
            except OSError:
                return time.monotonic() - start
            i += 1
            s.settimeout(0.3)
            try:
                if s.recv(1) == b'':
                    return time.monotonic() - start
            except socket.timeout:
                continue
            except OSError:
                return time.monotonic() - start
        return None
    finally:
        s.close()


def test_a_plain_http_request_is_still_redirected(server):
    s = socket.create_connection(('127.0.0.1', server), timeout=5)
    try:
        s.sendall(b'GET /dashboard HTTP/1.1\r\nHost: example.test\r\n\r\n')
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()

    assert data.startswith(b'HTTP/1.1 301')
    assert f'Location: https://example.test:{server}/dashboard'.encode() in data


def test_a_dripped_request_head_does_not_hold_the_pool(server):
    """Two clients dripping a byte every 0.3s were a pool of two, for hours."""
    drippers = [gevent.spawn(_drip, server, 10) for _ in range(2)]
    gevent.sleep(0.5)                       # both are holding their slot now
    t0 = time.monotonic()
    https = gevent.spawn(_https_get, server, '/ping', 8)
    gevent.joinall(drippers + [https], timeout=15)

    held = [d.value for d in drippers]
    assert all(h is not None and h < HEAD_DEADLINE + 3 for h in held), \
        f'the redirect handler kept a dripping client for {held} (deadline {HEAD_DEADLINE}s)'
    assert https.successful() and b'pong' in https.value, \
        f'the pool stayed full: an HTTPS request got {https.value or https.exception!r}'
    assert time.monotonic() - t0 < HEAD_DEADLINE + 5
