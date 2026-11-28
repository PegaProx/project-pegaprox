"""A console through the cluster's SSH tunnel checks the certificate against the node's name.

With ssl_verify on for a cluster and the VNC SSH tunnel in use, the console websocket dials
127.0.0.1 (the tunnel's end) and verified the PVE certificate against that address, which no
node certificate holds: every console of such a cluster failed. The name it checks is the
node's own now, through the tunnel as well; without verification nothing changes.
"""
import base64
import datetime
import hashlib
import inspect
import re
import socket
import ssl
import threading

import pytest
import websocket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pegaprox.api import vms

NODE = 'pve-node.test'


def _pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def pki(tmp_path):
    """A CA and a server certificate that names the node only (no 127.0.0.1)"""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test PVE CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=7))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NODE)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(NODE)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / 'ca.pem').write_bytes(_pem(ca))
    (tmp_path / 'node.pem').write_bytes(_pem(cert))
    (tmp_path / 'node.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    return tmp_path


@pytest.fixture
def tunnel_end(pki):
    """What the tunnel's local end gives: the node's TLS websocket on 127.0.0.1"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pki / 'node.pem'), str(pki / 'node.key'))
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                raw, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn = ctx.wrap_socket(raw, server_side=True)
                req = conn.recv(4096).decode('latin-1')
                key = re.search(r'Sec-WebSocket-Key: (\S+)', req, re.I).group(1)
                accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
                                                       .encode()).digest()).decode()
                conn.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                              f'Sec-WebSocket-Accept: {accept}\r\n\r\n').encode())
                conn.close()
            except (ssl.SSLError, OSError, AttributeError):
                raw.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()
    t.join(2)


def _dial(port, sslopt, pki):
    ws = websocket.create_connection(f'wss://127.0.0.1:{port}/', timeout=5,
                                     sslopt=dict(sslopt, ca_certs=str(pki / 'ca.pem')))
    ws.close()


def test_through_the_tunnel_a_verified_console_checks_the_nodes_name(tunnel_end, pki):
    _dial(tunnel_end, vms._pve_ws_sslopt(True, NODE, '127.0.0.1'), pki)
    # what it sent before: the name checked was the tunnel's 127.0.0.1
    with pytest.raises(ssl.SSLCertVerificationError):
        _dial(tunnel_end, {}, pki)


def test_without_the_tunnel_or_verification_it_is_as_before():
    assert vms._pve_ws_sslopt(True, NODE, NODE) == {}
    assert vms._pve_ws_sslopt(False, NODE, '127.0.0.1') == {'cert_reqs': ssl.CERT_NONE}
    assert vms._pve_ws_sslopt(False, NODE, NODE) == {'cert_reqs': ssl.CERT_NONE}


def test_every_console_websocket_to_pve_takes_its_options_from_there():
    src = inspect.getsource(vms)
    dials = [m.start() for m in re.finditer(r'create_connection\(', src)]
    assert len(dials) >= 4
    for at in dials:
        call = src[at:at + 600]
        assert re.search(r'sslopt=_pve_ws_sslopt\(\w+, \w+, \w+\)', call), call
    # a tunnelled one names the node, not the end of the tunnel it dials
    assert src.count('sslopt=_pve_ws_sslopt(_verify_tls, host, target_host)') == 3
