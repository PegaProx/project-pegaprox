# How the ACME client takes the answers of a CA that does not answer the way it should.
#
# A CA that went away during the certificate download came back as the raw exception
# text, "('Connection aborted.', RemoteDisconnected(...))", without the step or the CA.
# It says both now, and the served pair stays as it was.
import datetime
import os
import socket
import ssl
import threading

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pegaprox.core import acme

DOMAIN = 'pp.example.com'
FINALIZE = 'https://ca.example/finalize/1'
_ACCOUNT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _Resp:
    def __init__(self, status, text='', js=None, headers=None):
        self.status_code = status
        self.text = text
        self._js = js
        self.headers = headers or {}

    def json(self):
        if self._js is None:
            raise ValueError('not json')
        return self._js


def _self_signed(cn, key, san=None, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return builder.sign(key, hashes.SHA256())


@pytest.fixture
def served(tmp_path):
    ssl_dir = tmp_path / 'ssl'
    ssl_dir.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    (ssl_dir / 'cert.pem').write_bytes(_self_signed(DOMAIN, key).public_bytes(serialization.Encoding.PEM))
    (ssl_dir / 'key.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ssl_dir


@pytest.fixture
def ca_that_hangs_up(tmp_path, monkeypatch):
    """A CA on localhost (trusted through SSL_CERT_FILE) that reads the request and
    closes the connection without an answer. Yields its certificate URL."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _self_signed('localhost', key, san='localhost', ca=True)
    cert_file, key_file = tmp_path / 'ca.pem', tmp_path / 'ca.key'
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_file), str(key_file))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(5)
                    data = b''
                    while b'\r\n\r\n' not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    for name in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'HTTPS_PROXY', 'https_proxy'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('NO_PROXY', 'localhost,127.0.0.1')
    monkeypatch.setenv('SSL_CERT_FILE', str(cert_file))
    monkeypatch.setenv('SSL_CERT_DIR', str(tmp_path / 'no-ca-dir'))
    monkeypatch.setattr(acme, '_guard_acme_url', lambda url: url)
    try:
        yield f'https://localhost:{port}/cert/1'
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)


def _order(monkeypatch, ssl_dir, cert_url, download=None):
    """request_certificate for a validated order whose download goes to cert_url, through
    the real _signed_request unless download answers it."""
    real = acme._signed_request

    def signed(url, payload, account_key, nonce, kid=None):
        if url == FINALIZE:
            return _Resp(200, js={'status': 'valid', 'certificate': cert_url})
        assert url == cert_url, url
        if download:
            return download()
        return real(url, payload, account_key, nonce, kid)

    monkeypatch.setattr(acme, '_create_order', lambda *a, **kw: {
        'success': True, 'account_key': _ACCOUNT_KEY, 'nonce': 'n1', 'kid': 'https://ca.example/acct/1',
        'order': {'finalize': FINALIZE}, 'order_url': 'https://ca.example/order/1',
        'authz_url': 'https://ca.example/authz/1',
        'authz': {'challenges': [{'type': 'http-01', 'token': 'tok', 'url': 'https://ca.example/chall/1'}]}})
    monkeypatch.setattr(acme, '_validate_challenge', lambda *a, **kw: {'success': True, 'nonce': 'n2'})
    monkeypatch.setattr(acme, '_signed_request', signed)
    return acme.request_certificate(DOMAIN, 'ops@example.com', str(ssl_dir))


def test_a_ca_that_hangs_up_on_the_download_is_named(served, monkeypatch, ca_that_hangs_up):
    before = (served / 'cert.pem').read_bytes(), (served / 'key.pem').read_bytes()

    res = _order(monkeypatch, served, ca_that_hangs_up)

    host = ca_that_hangs_up.split('/')[2]
    assert res == {'success': False, 'message': f'Certificate download failed: no answer from the CA '
                                                f'at {host}, the connection was closed or refused'}
    assert ((served / 'cert.pem').read_bytes(), (served / 'key.pem').read_bytes()) == before
    assert sorted(os.listdir(served)) == ['cert.pem', 'key.pem']


def test_a_ca_that_does_not_answer_in_time_is_named(served, monkeypatch):
    def slow():
        raise requests.exceptions.ReadTimeout('read timed out')

    res = _order(monkeypatch, served, 'https://ca.example/cert/1', download=slow)

    assert res['message'] == 'Certificate download failed: no answer from the CA at ca.example in time'
