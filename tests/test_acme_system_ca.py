"""#314: custom ACME CAs installed in the system trust store must work."""

import json
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pegaprox.core import acme


@pytest.fixture
def local_acme_server(tmp_path):
    """Serve a minimal ACME order flow over TLS signed by a private test CA."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test ACME CA')])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder()
          .subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_file = tmp_path / 'ca.pem'
    cert_file = tmp_path / 'server.pem'
    key_file = tmp_path / 'server.key'
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    ca_dir = tmp_path / 'system-ca-dir'
    ca_dir.mkdir()
    cert_hash = crypto.X509.from_cryptography(ca).subject_name_hash()
    (ca_dir / f'{cert_hash:08x}.0').symlink_to(ca_file)

    class Handler(BaseHTTPRequestHandler):

        def log_message(self, *args):
            pass

        def respond(self, payload, status=200, **headers):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            for name, value in headers.items():
                self.send_header(name.replace('_', '-'), value)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(data)

        def do_GET(self):
            base = f'https://localhost:{self.server.server_port}'
            assert self.path == '/directory'
            self.respond({'newNonce': base + '/nonce',
                          'newAccount': base + '/account',
                          'newOrder': base + '/order'})

        def do_HEAD(self):
            assert self.path == '/nonce'
            self.respond({}, Replay_Nonce='nonce-1')

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            base = f'https://localhost:{self.server.server_port}'
            if self.path == '/account':
                self.respond({}, status=201, Replay_Nonce='nonce-2',
                             Location=base + '/account/1')
            elif self.path == '/order':
                self.respond({'authorizations': [base + '/authz']}, status=201,
                             Replay_Nonce='nonce-3', Location=base + '/order/1')
            else:
                assert self.path == '/authz'
                self.respond({'status': 'pending', 'challenges': []},
                             Replay_Nonce='nonce-4')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_file), str(key_file))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'https://localhost:{server.server_port}/directory', ca_file, ca_dir
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize('trust_source', ['system_file', 'system_dir',
                                          'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'])
def test_acme_flow_trusts_system_or_explicit_ca_bundle(
        monkeypatch, tmp_path, local_acme_server, trust_source):
    """Complete an ACME flow using system CA paths or a Requests override."""
    directory_url, ca_file, ca_dir = local_acme_server
    for name in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('NO_PROXY', 'localhost,127.0.0.1')
    monkeypatch.setenv('SSL_CERT_FILE', str(ca_file) if trust_source == 'system_file'
                       else requests.certs.where())
    monkeypatch.setenv('SSL_CERT_DIR', str(tmp_path / 'empty-ca-dir'))
    if trust_source == 'system_dir':
        monkeypatch.setenv('SSL_CERT_DIR', str(ca_dir))
    elif trust_source in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        monkeypatch.setenv(trust_source, str(ca_file))
    # Only the local test endpoint bypasses the production SSRF checks.
    monkeypatch.setattr('pegaprox.utils.url_security.sanitize_outbound_url',
                        lambda url, **kwargs: url)
    monkeypatch.setattr(acme, '_guard_acme_url', lambda url: url)

    result = acme._create_order('host.example.com', 'admin@example.com', str(tmp_path),
                                directory_url=directory_url)

    assert result['success'] is True
    assert result['authz']['status'] == 'pending'
    assert result['nonce'] == 'nonce-4'


def test_acme_rejects_an_untrusted_ca(monkeypatch, tmp_path, local_acme_server):
    """Keep TLS verification enabled when no custom CA is trusted."""
    directory_url, _, _ = local_acme_server
    for name in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('NO_PROXY', 'localhost,127.0.0.1')
    monkeypatch.setenv('SSL_CERT_FILE', requests.certs.where())
    monkeypatch.setenv('SSL_CERT_DIR', str(tmp_path / 'empty-ca-dir'))
    monkeypatch.setattr('pegaprox.utils.url_security.sanitize_outbound_url',
                        lambda url, **kwargs: url)
    monkeypatch.setattr(acme, '_guard_acme_url', lambda url: url)

    with pytest.raises(requests.exceptions.SSLError):
        acme._create_order('host.example.com', 'admin@example.com', str(tmp_path),
                           directory_url=directory_url)


def test_explicit_bundle_does_not_inherit_system_ca(monkeypatch, tmp_path,
                                                    local_acme_server):
    """Keep an explicit Requests CA bundle authoritative over the system store."""
    directory_url, ca_file, _ = local_acme_server
    monkeypatch.setenv('NO_PROXY', 'localhost,127.0.0.1')
    monkeypatch.setenv('SSL_CERT_FILE', str(ca_file))
    monkeypatch.setenv('SSL_CERT_DIR', str(tmp_path / 'empty-ca-dir'))
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', requests.certs.where())
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)
    monkeypatch.setattr('pegaprox.utils.url_security.sanitize_outbound_url',
                        lambda url, **kwargs: url)
    monkeypatch.setattr(acme, '_guard_acme_url', lambda url: url)

    with pytest.raises(requests.exceptions.SSLError):
        acme._create_order('host.example.com', 'admin@example.com', str(tmp_path),
                           directory_url=directory_url)
