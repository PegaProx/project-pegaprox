"""A TLS listener serves the cert/key pair on disk, not only the one it started with.

The background renewal wrote a new pair into config/ssl and every listener kept the one
it had loaded at start, until somebody restarted by hand. The HTTPS port, the VNC console
port and the SSH console process take a new pair up with the next handshake now, and a
pair that does not load leaves the one they serve.

The HTTPS server with the VNC server next to it runs in a subprocess, the way
_start_gevent_server runs in production (gevent's monkey patching), and the SSH console
server is the script vms.py writes, run on its own. All on spare ports. MK
"""
import ast
import datetime
import logging
import os
import socket
import ssl
import subprocess
import sys
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pegaprox import app as app_module
from pegaprox.utils import served_pair

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pair(label, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def _install(where, label, broken=False):
    """Write a pair the way the ACME code does: the key first, then the cert, each by a rename.
    broken: the cert does not go with the key."""
    cert, key = _pair(label)
    if broken:
        key = _pair('other')[1]
    app_module._write_atomic(str(where / 'key.pem'), key, 0o600)
    app_module._write_atomic(str(where / 'cert.pem'), cert, 0o644)


def _served(port, timeout=5):
    """The CN a fresh TLS connection to 127.0.0.1:port gets, without a server name."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _https_get(port, path='/ping'):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with ctx.wrap_socket(raw) as tls:
            tls.sendall(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'.encode())
            data = b''
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    return data
                data += chunk


def _free_ports(count):
    """A first port with count-1 free ports after it."""
    for _ in range(50):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        base = s.getsockname()[1]
        s.close()
        if base + count > 65535:
            continue
        try:
            for p in range(base, base + count):
                t = socket.socket()
                t.bind(('127.0.0.1', p))
                t.close()
        except OSError:
            continue
        return base
    pytest.skip('no run of free ports')


def _wait(check, proc, log_path, what):
    end = time.monotonic() + 60
    while True:
        try:
            if check():
                return
        except OSError:
            pass
        if proc.poll() is not None or time.monotonic() > end:
            pytest.fail(f'{what} did not come up:\n' + log_path.read_text())
        time.sleep(0.2)


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)


# ---- the pair object on its own ----

@pytest.fixture
def pair_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(served_pair, '_listeners', [])
    _install(tmp_path, 'first')
    return tmp_path


def test_a_listener_reports_whether_it_serves_the_pair_on_disk(pair_dir, caplog):
    cert = str(pair_dir / 'cert.pem')
    assert served_pair.serves(cert) is None            # nothing listens with it yet
    listener = served_pair.ServedPair(cert, str(pair_dir / 'key.pem'))
    assert served_pair.serves(cert) is True

    _install(pair_dir, 'second')
    assert served_pair.serves(cert) is True
    assert listener._current is not listener.context

    caplog.set_level(logging.WARNING)
    _install(pair_dir, 'third', broken=True)
    assert served_pair.serves(cert) is False
    assert served_pair.serves(cert) is False
    assert served_pair.load_error(cert)
    warned = [r for r in caplog.records if 'still serving the previous certificate' in r.getMessage()]
    assert len(warned) == 1, [r.getMessage() for r in caplog.records]

    _install(pair_dir, 'fourth')
    assert served_pair.serves(cert) is True
    assert served_pair.load_error(cert) == ''


def test_a_pair_that_went_missing_is_reported_and_taken_up_once_back(pair_dir):
    cert = str(pair_dir / 'cert.pem')
    served_pair.ServedPair(cert, str(pair_dir / 'key.pem'))
    os.rename(cert, cert + '.away')
    assert served_pair.serves(cert) is False
    assert 'cannot be read' in served_pair.load_error(cert)
    os.rename(cert + '.away', cert)
    assert served_pair.serves(cert) is True
    assert served_pair.load_error(cert) == ''


def test_a_bad_pair_at_the_start_still_stops_the_start(pair_dir, monkeypatch):
    _install(pair_dir, 'first', broken=True)
    with pytest.raises(ssl.SSLError):
        served_pair.ServedPair(str(pair_dir / 'cert.pem'), str(pair_dir / 'key.pem'))


@pytest.mark.parametrize('broken', [False, True])
def test_an_issued_certificate_asks_for_a_restart_only_when_a_listener_kept_the_old_one(
        api, seed, monkeypatch, pair_dir, broken):
    import pegaprox.api.settings as settings_mod
    from pegaprox.core import acme

    monkeypatch.setattr(settings_mod, 'SSL_DIR', str(pair_dir))
    monkeypatch.setattr(settings_mod, 'SSL_CERT_FILE', str(pair_dir / 'cert.pem'))
    served_pair.ServedPair(str(pair_dir / 'cert.pem'), str(pair_dir / 'key.pem'))

    def issue(domain, email, ssl_dir, **kw):
        _install(type(pair_dir)(ssl_dir), 'issued', broken=broken)
        return {'success': True, 'message': f'Certificate issued for {domain}', 'expires': '2099-01-01'}

    monkeypatch.setattr(acme, 'request_certificate', issue)
    admin = seed.user('root', role='admin', tenant_id='default')
    r = api.as_user(admin).post('/api/settings/acme/request', json={
        'domain': 'pp.example.com', 'provider': 'custom', 'directory_url': 'https://ca.example/dir'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['success'] is True
    assert r.get_json()['restart_required'] is broken


# ---- the HTTPS port and the VNC console port, as production starts them ----

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
from flask import Flask
import pegaprox.app as app_mod
import pegaprox.api.vms as vms

# the SSH console server is a script of its own, tested below
vms.start_ssh_websocket_server = lambda *a, **k: None
web = Flask('pair-test')


@web.route('/ping')
def ping():
    return 'pong'


app_mod._start_gevent_server(web, '127.0.0.1', int(sys.argv[1]), (sys.argv[2], sys.argv[3]), None, 4)
'''


def test_the_https_and_vnc_ports_serve_a_renewal_without_a_restart(tmp_path):
    ssl_dir = tmp_path / 'ssl'
    ssl_dir.mkdir()
    _install(ssl_dir, 'first')
    port = _free_ports(2)
    log_path = tmp_path / 'server.log'
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(tmp_path / 'config')}
    with open(log_path, 'w') as log:
        proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port),
                                 str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem')],
                                cwd=str(tmp_path), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        _wait(lambda: b'pong' in _https_get(port) and _served(port + 1), proc, log_path, 'test server')
        assert (_served(port), _served(port + 1)) == ('first', 'first')

        _install(ssl_dir, 'second')
        assert (_served(port), _served(port + 1)) == ('second', 'second')
        assert b'pong' in _https_get(port)

        # a pair that does not load changes nothing, and the port keeps answering
        _install(ssl_dir, 'third', broken=True)
        assert (_served(port), _served(port + 1)) == ('second', 'second')
        assert b'pong' in _https_get(port)

        _install(ssl_dir, 'fourth')
        assert (_served(port), _served(port + 1)) == ('fourth', 'fourth')
    finally:
        _stop(proc)


# ---- the SSH console server, the script vms.py writes ----

def _ssh_server_script():
    """server_script as start_ssh_websocket_server writes it."""
    with open(os.path.join(REPO, 'pegaprox', 'api', 'vms.py'), encoding='utf-8') as f:
        tree = ast.parse(f.read())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == 'start_ssh_websocket_server')
    assign = next(n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                  and any(getattr(t, 'id', None) == 'server_script' for t in n.targets))
    return ast.literal_eval(assign.value)


def test_the_ssh_console_server_serves_a_renewal_without_a_restart(tmp_path):
    ssl_dir = tmp_path / 'ssl'
    ssl_dir.mkdir()
    _install(ssl_dir, 'first')
    script = tmp_path / 'ssh_ws.py'
    script.write_text(_ssh_server_script())
    port = _free_ports(1)
    log_path = tmp_path / 'ssh.log'
    env = {**os.environ, 'SSH_WS_PORT': str(port), 'SSH_WS_HOST': '127.0.0.1',
           'SSH_WS_SSL_CERT': str(ssl_dir / 'cert.pem'), 'SSH_WS_SSL_KEY': str(ssl_dir / 'key.pem'),
           'PEGAPROX_PKG_BASE': REPO, 'PEGAPROX_URL': 'https://127.0.0.1:9'}
    with open(log_path, 'w') as log:
        proc = subprocess.Popen([sys.executable, str(script)], cwd=str(tmp_path), env=env,
                                stdout=log, stderr=subprocess.STDOUT)
    try:
        _wait(lambda: _served(port), proc, log_path, 'SSH console server')
        assert _served(port) == 'first'

        _install(ssl_dir, 'second')
        assert _served(port) == 'second'

        _install(ssl_dir, 'third', broken=True)
        assert _served(port) == 'second'

        _install(ssl_dir, 'fourth')
        assert _served(port) == 'fourth'
    finally:
        _stop(proc)
