"""The link of a kept session (#625 stage 2): the lease calls of automatic failover on
kept-alive TLS connections, without requests in the way (ha._LeaseLink).

A real TLS server on loopback answers as the test says. Pinned here: the pin is checked
before a byte of the call goes out, a CA-checked link checks the name, a kept connection
is used again and one the member closed is not, answers with a length, in chunks and up
to the close are read, nothing too large is, a header with a line break is not sent,
and a proxy from the environment or a pin that is not SHA-256 leaves the session as it
was. A call that got out and broke drops the kept session as before; one that never got
out keeps it.

MK Oct 2026 (#625)
"""
import datetime
import hashlib
import ipaddress
import json
import socket
import ssl
import threading
import time

import pytest

from pegaprox.core import ha


def _cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'member')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cf, kf = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    fp = ':'.join(f'{b:02X}' for b in hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest())
    return str(cf), str(kf), fp


class _Member:
    """A TLS server that answers each request with what `reply` returns (raw bytes)."""

    def __init__(self, tmp_path):
        self.cert, self.key, self.fp = _cert(tmp_path)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cert, self.key)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.url = f'https://127.0.0.1:{self.port}'
        self.connections, self.requests = 0, []
        self.reply = lambda req: self.answer(200, {'ok': True})
        self.close_after = False
        threading.Thread(target=self._accept, daemon=True).start()

    @staticmethod
    def answer(status, payload, extra=b''):
        raw = json.dumps(payload).encode()
        return (f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n'
                .encode() + extra + b'\r\n' + raw)

    def _accept(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            return
        buf = b''
        try:
            while True:
                while b'\r\n\r\n' not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b'\r\n\r\n')
                n = int([ln.split(b':')[1] for ln in head.split(b'\r\n')
                         if ln.lower().startswith(b'content-length')][0])
                while len(buf) < n:
                    buf += conn.recv(65536)
                body, buf = buf[:n], buf[n:]
                self.requests.append((head.decode(), body))
                conn.sendall(self.reply((head, body)))
                if self.close_after:
                    return
        finally:
            conn.close()

    def stop(self):
        self.sock.close()


@pytest.fixture
def member(tmp_path):
    m = _Member(tmp_path)
    yield m
    m.stop()


@pytest.fixture
def kept(monkeypatch):
    monkeypatch.setattr(ha, '_kept_sessions', {})
    monkeypatch.setattr(ha, '_peer_urls', {})
    for var in ('HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy',
                'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        monkeypatch.delenv(var, raising=False)
    yield
    for _fp, sess in list(ha._kept_sessions.values()):
        ha._close_kept(sess)


def _call(member, fp=None, body=None, path='/api/ha/peer/renew', headers=None):
    return ha._peer_call('POST', member.url, member.fp if fp is None else fp, path,
                         json_body=body or {'epoch': 1}, headers=headers, timeout=3, keep_alive=True)


def test_a_kept_call_goes_over_the_link_and_its_connection_is_kept(member, kept, monkeypatch):
    member.reply = lambda req: member.answer(200, {'ok': True, 'n': len(member.requests)},
                                             b'X-PegaProx-Peer-Keyed: 1\r\n')
    posts = []
    real = ha._LeaseLink.post
    monkeypatch.setattr(ha._LeaseLink, 'post', lambda self, *a: posts.append(a[1]) or real(self, *a))
    answers = [_call(member) for _ in range(5)]
    assert posts == ['/api/ha/peer/renew'] * 5
    assert 'python-requests' not in member.requests[0][0]
    assert [a.status_code for a in answers] == [200] * 5
    assert [a.json()['n'] for a in answers] == [1, 2, 3, 4, 5]
    assert answers[0].headers.get('x-pegaprox-peer-keyed') == '1'
    assert ha._answer_header(answers[0], 'X-PegaProx-Peer-Keyed') == '1'
    assert member.connections == 1
    sess = ha._kept_sessions[member.url][1]
    assert isinstance(sess.pegaprox_lean, ha._LeaseLink)
    head, body = member.requests[0]
    assert head.startswith('POST /api/ha/peer/renew HTTP/1.1\r\n') and f'Host: 127.0.0.1:{member.port}' in head
    assert json.loads(body) == {'epoch': 1}


def test_a_wrong_pin_sends_nothing_and_keeps_only_the_session(member, kept):
    """Refused before a byte went out: the socket that failed is closed, the session and
    its link stay (a PeerUnreachable, tests/test_ha_unreached_voters.py), and the next
    connection is checked against the pin again."""
    other = ':'.join(['AB'] * 32)
    for _ in range(2):
        with pytest.raises(ha.PeerUnreachable, match='pinned fingerprint'):
            _call(member, fp=other)
    time.sleep(0.05)
    assert member.requests == []
    link = ha._kept_sessions[member.url][1].pegaprox_lean
    assert link.idle == [] and member.connections == 2


def test_without_a_pin_the_link_checks_the_chain_and_the_name(member, kept, monkeypatch):
    with pytest.raises(ha.PeerUnreachable, match='not trusted by a CA'):
        _call(member, fp='')
    assert member.requests == []
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', member.cert)
    ha._kept_sessions.clear()
    assert _call(member, fp='').status_code == 200
    assert isinstance(ha._kept_sessions[member.url][1].pegaprox_lean, ha._LeaseLink)


def test_a_connection_the_member_closed_is_not_used_again(member, kept):
    member.close_after = True
    for _ in range(3):
        assert _call(member).status_code == 200
        time.sleep(0.05)
    assert member.connections == 3 and len(member.requests) == 3


def test_answers_in_chunks_and_up_to_the_close_are_read(member, kept):
    member.reply = lambda req: (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
                                b'4\r\n{"ok\r\n8;x=1\r\n": true}\r\n0\r\nX-Trailer: 1\r\n\r\n')
    assert _call(member).json() == {'ok': True}
    assert _call(member).json() == {'ok': True}
    assert member.connections == 1
    member.reply = lambda req: b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok": 2}'
    member.close_after = True
    assert _call(member).json() == {'ok': 2}


def test_an_answer_too_large_or_broken_is_no_answer(member, kept, monkeypatch):
    monkeypatch.setattr(ha, '_KEPT_ANSWER_MAX', 64)
    member.reply = lambda req: member.answer(200, {'pad': 'x' * 100})
    with pytest.raises(ha.PeerNoAnswer):
        _call(member)
    member.reply = lambda req: b'HTTP/1.1 2x0 OK\r\nContent-Length: 2\r\n\r\n{}'
    with pytest.raises(ha.PeerNoAnswer):
        _call(member)
    member.reply = lambda req: b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n{}'
    with pytest.raises(ha.PeerNoAnswer):
        _call(member)
    # a call that broke drops the session: the next one starts afresh, and gets through
    member.reply = lambda req: member.answer(200, {'ok': True})
    assert _call(member).status_code == 200



def test_an_interim_answer_is_no_answer_and_its_socket_is_not_used_again(member, kept):
    """The link sends no Expect, so a member that answers '100 Continue' anyway does not
    answer: the call ends as no answer and that socket is closed. Were it kept, the next
    call on it would read the final answer meant for this one."""
    def reply(req):
        n = len(member.requests)
        if n == 1:
            return b'HTTP/1.1 100 Continue\r\n\r\n'
        return member.answer(200, {'ok': True, 'n': n})
    member.reply = reply
    with pytest.raises(ha.PeerNoAnswer):
        _call(member)
    second = _call(member)
    assert second.status_code == 200 and second.json()['n'] == 2
    assert member.connections == 2

def test_a_header_with_a_line_break_is_not_sent(member, kept):
    with pytest.raises(ha.HaError, match='line break'):
        _call(member, headers={'X-Test': 'a\r\nX-Evil: 1'})
    time.sleep(0.05)
    assert member.requests == []


def test_a_proxy_or_a_pin_that_is_no_sha256_leaves_the_session_as_it_was(member, kept, monkeypatch):
    import requests
    sess = requests.Session()
    ha._lean_session(sess, member.url, member.fp)
    assert isinstance(sess.pegaprox_lean, ha._LeaseLink)
    for fp in (':'.join(['AB'] * 20), 'not-a-pin'):
        sess = requests.Session()
        ha._lean_session(sess, member.url, fp)
        assert not hasattr(sess, 'pegaprox_lean')
    monkeypatch.setenv('HTTPS_PROXY', 'http://10.9.9.9:3128')
    sess = requests.Session()
    ha._lean_session(sess, member.url, member.fp)
    assert not hasattr(sess, 'pegaprox_lean')
    monkeypatch.setenv('NO_PROXY', '127.0.0.1')
    sess = requests.Session()
    ha._lean_session(sess, member.url, member.fp)
    assert isinstance(sess.pegaprox_lean, ha._LeaseLink)


def test_a_call_that_is_not_kept_takes_requests_as_before(member, kept, monkeypatch):
    seen = []
    real = ha._kept_send
    monkeypatch.setattr(ha, '_kept_send', lambda *a, **kw: seen.append(a[2]) or real(*a, **kw))
    r = ha._peer_call('POST', member.url, member.fp, '/api/ha/peer/renew', json_body={'epoch': 1}, timeout=3)
    assert r.status_code == 200 and seen == []
    assert _call(member).status_code == 200 and len(seen) == 1


def test_the_address_check_of_a_kept_call_is_kept_for_a_while(member, kept, monkeypatch):
    import pegaprox.utils.url_security as us
    checks = []
    real = us.is_safe_outbound_url
    monkeypatch.setattr(us, 'is_safe_outbound_url', lambda url, **kw: checks.append(url) or real(url, **kw))
    for _ in range(5):
        _call(member)
    assert len(checks) == 1
    clock = [ha.ha_clock() + ha._PEER_URL_RECHECK + 1]
    monkeypatch.setattr(ha, 'ha_clock', lambda: clock[0])
    _call(member)
    assert len(checks) == 2
    # a call of its own is checked every time
    ha._peer_call('POST', member.url, member.fp, '/api/ha/peer/renew', json_body={}, timeout=3)
    ha._peer_call('POST', member.url, member.fp, '/api/ha/peer/renew', json_body={}, timeout=3)
    assert len(checks) == 4
