"""#713 - what ended healthy consoles on the PegaProx to pveproxy leg, and what they said.

Three things, each shown here on the real mechanism before the fix is held to it:

  * OpenSSL keeps one error queue per OS thread and SSL_get_error() reads it. Python's _ssl
    does not empty it before SSL_read, and under gevent every greenlet shares the thread,
    so one stale entry turns the relay's ordinary 10ms read timeout into an SSLError.
  * writes to PVE ran under that 10ms read slice. A write that times out halfway leaves the
    rest of its TLS record with OpenSSL, which takes the next write for the retry: the peer
    gets the old bytes and the new frame minus its head. The flask-sock leg swallowed that
    timeout and kept writing; the polling leg kept its session open for the next send.
  * why a session ended was a DEBUG line, or a print, so the drop in the field said nothing.

The VNC console had three relays then (the standalone server on 5001, the flask-sock and the
geventwebsocket routes); one is left, `_vnc_relay` behind the flask-sock route, and its
reader waits for PVE (a gevent watcher, select() stops at descriptor 1023) before it
takes the lock to read.

MK Oct 2026
"""
import base64
import ctypes
import datetime
import hashlib
import logging
import os
import socket
import ssl
import threading
import types

import gevent
import pytest
import websocket

from pegaprox.api import vms
from pegaprox.constants import VNC_PVE_RECV_SLICE, VNC_PVE_SEND_TIMEOUT
from pegaprox.utils import vnc_polling
from pegaprox.utils.vnc_polling import VncPollSession

from test_console_token_cluster_955 import _PATH, _PasswordManager, _Pve, _query


# --- a TLS peer on loopback --------------------------------------------------

@pytest.fixture(scope='module')
def tls_files(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'pve.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(713)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    d = tmp_path_factory.mktemp('tls713')
    (d / 'c.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / 'k.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return str(d / 'c.pem'), str(d / 'k.pem')


class _IdlePve:
    """Accepts one TLS websocket upgrade, then sends nothing - an idle console."""

    def __init__(self, tls_files):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls_files)
        self._ctx = ctx
        self._ls = socket.socket()
        self._ls.bind(('127.0.0.1', 0))
        self._ls.listen(1)
        self.port = self._ls.getsockname()[1]
        self._done = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        conn, _ = self._ls.accept()
        s = self._ctx.wrap_socket(conn, server_side=True)
        req = b''
        while b'\r\n\r\n' not in req:
            chunk = s.recv(4096)
            if not chunk:
                s.close()
                return
            req += chunk
        wskey = [ln.split(b':', 1)[1].strip() for ln in req.split(b'\r\n')
                 if ln.lower().startswith(b'sec-websocket-key')][0]
        accept = base64.b64encode(hashlib.sha1(
            wskey + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        s.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                  b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
        self._done.wait(10)
        s.close()

    def close(self):
        self._done.set()
        self._ls.close()


def _poison():
    """Leave an entry on this thread's OpenSSL error queue, the way a failed call
    elsewhere in the process does: a BIO for a file that is not there."""
    import _ssl
    lib = ctypes.CDLL(_ssl.__file__)
    lib.BIO_new_file.restype = ctypes.c_void_p
    lib.BIO_new_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    assert not lib.BIO_new_file(b'/nonexistent/pegaprox-713', b'r')


def test_a_stale_openssl_error_really_does_fail_a_healthy_read(tls_files):
    """The failure mode itself, on a plain TLS socket and nothing of ours: the guard
    below would be guarding nothing if this did not hold."""
    peer = _IdlePve(tls_files)
    cli = ssl.create_default_context()
    cli.check_hostname = False
    cli.verify_mode = ssl.CERT_NONE
    s = cli.wrap_socket(socket.create_connection(('127.0.0.1', peer.port)), server_hostname='pve.test')
    try:
        s.settimeout(0.02)
        with pytest.raises((TimeoutError, socket.timeout)):
            s.recv(1)                                   # an idle peer: a timeout, as it should be
        _poison()
        with pytest.raises(ssl.SSLError) as err:
            s.recv(1)
        assert 'timed out' not in str(err.value), err.value
        # and the same read with the queue emptied first is a timeout again
        assert vnc_polling.clear_tls_errors_before_io(s) is True
        _poison()
        with pytest.raises((TimeoutError, socket.timeout)):
            s.recv(1)
    finally:
        s.close()
        peer.close()


def test_a_relay_leg_survives_errors_other_connections_leave_behind(tls_files):
    """The polling leg, set up the way vnc_poll does it, over a real TLS websocket.
    While it idles, the process keeps leaving OpenSSL errors on the shared thread."""
    peer = _IdlePve(tls_files)
    pve_ws = websocket.create_connection(f'wss://127.0.0.1:{peer.port}/vncwebsocket',
                                         sslopt={'cert_reqs': ssl.CERT_NONE, 'check_hostname': False},
                                         timeout=5)
    vms._apply_vnc_socket_options(pve_ws.sock)
    sess = VncPollSession('poll-713-tls-queue', pve_ws, None, None, 'c1', 'qemu', 100, '127.0.0.1')
    try:
        for _ in range(40):
            _poison()
            gevent.sleep(0.01)
        assert not sess.closed, 'a stale OpenSSL error from elsewhere ended an idle console'
    finally:
        sess.stop()
        peer.close()


def test_the_queue_clearing_leaves_a_plain_socket_alone():
    s = socket.socket()
    try:
        assert vnc_polling.clear_tls_errors_before_io(s) is False
        assert vnc_polling.clear_tls_errors_before_io(None) is False
    finally:
        s.close()


# --- writes get their own deadline -------------------------------------------

class _SlowPve:
    """A PVE socket whose writes take longer than the read slice, like a full send buffer."""

    def __init__(self, fail_always=False):
        self.timeout = VNC_PVE_RECV_SLICE       # where every leg leaves its PVE socket
        self.fail_always = fail_always
        self.written = []
        self.timeouts_at_write = []

    def settimeout(self, t):
        self.timeout = t

    def recv(self):
        gevent.sleep(0.005)
        raise websocket.WebSocketTimeoutException('read slice')

    def _write(self, payload):
        self.timeouts_at_write.append(self.timeout)
        if self.fail_always or self.timeout < 0.5:
            raise websocket.WebSocketTimeoutException('The write operation timed out')
        self.written.append(payload)

    send = send_binary = _write

    def close(self):
        pass


def test_a_poll_write_is_not_held_to_the_read_slice():
    pve = _SlowPve()
    sess = VncPollSession('poll-713-deadline', pve, None, None, 'c1', 'qemu', 100, 'h')
    try:
        assert sess.send(base64.b64encode(b'key').decode()) == 3
        assert pve.timeouts_at_write == [VNC_PVE_SEND_TIMEOUT]
        assert pve.written == [b'key']
        assert pve.timeout == VNC_PVE_RECV_SLICE, 'the reader was left with the write deadline'
    finally:
        sess.stop()


def test_a_failed_poll_write_ends_the_session(caplog):
    """Anything written after a half-written frame lands behind it."""
    pve = _SlowPve(fail_always=True)
    sess = VncPollSession('poll-713-partial', pve, None, None, 'c1', 'qemu', 100, 'h')
    with caplog.at_level(logging.WARNING):
        with pytest.raises(Exception):
            sess.send(base64.b64encode(b'k1').decode())
    assert sess.closed
    with pytest.raises(Exception):
        sess.send(base64.b64encode(b'k2').decode())
    assert len(pve.timeouts_at_write) == 1, 'wrote again after a write that failed'
    assert any('reason=Client->PVE' in r.getMessage() and r.levelno == logging.WARNING
               for r in caplog.records), [r.getMessage() for r in caplog.records]


class _Browser3:
    """A flask-sock browser that types three keys and leaves."""

    def __init__(self):
        self.frames = [b'k1', b'k2', b'k3']

    @property
    def connected(self):
        return bool(self.frames)

    def receive(self, timeout=None):
        return self.frames.pop(0) if self.frames else None

    def send(self, data):
        pass

    def close(self, *a, **k):
        pass


class _OnceSlowPve(_SlowPve):
    """The first write runs out of time - whatever deadline it was given."""

    def _write(self, payload):
        self.timeouts_at_write.append(self.timeout)
        if len(self.timeouts_at_write) == 1:
            raise websocket.WebSocketTimeoutException('The write operation timed out')
        self.written.append(payload)

    send = send_binary = _write


@pytest.fixture
def cluster(api, seed, monkeypatch):
    """A password cluster whose login PVE accepts, so every leg gets as far as its relay."""
    seed.user('root', role='admin')
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', _Pve(password_ok=True).opener)
    return api.set_manager('c1', _PasswordManager())


@pytest.fixture
def pve_socket():
    """The socket under a PVE websocket, for the relay's wait: .idle has nothing to
    read, .ready always has a byte waiting."""
    idle, idle_peer = socket.socketpair()
    ready, ready_peer = socket.socketpair()
    ready_peer.send(b'x')
    yield types.SimpleNamespace(idle=idle, ready=ready)
    for s in (idle, idle_peer, ready, ready_peer):
        s.close()


def _vnc_socket(api, browser):
    view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__
    with api.app.test_request_context(f'{_PATH}?{_query(True)}'):
        view(browser, 'c1', 'pve1', 'qemu', 100)


def test_the_relay_stops_after_a_write_that_timed_out(api, cluster, monkeypatch, caplog, pve_socket):
    """The flask-sock relay used to read 'timed out' in the message, take it for its own
    receive timeout, and send the next key behind the partial frame."""
    pve = _OnceSlowPve()
    pve.sock = pve_socket.idle
    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: pve)
    with caplog.at_level(logging.INFO):
        _vnc_socket(api, _Browser3())
    assert pve.written == [], f'kept writing after a partial frame: {pve.written}'
    assert pve.timeouts_at_write == [VNC_PVE_SEND_TIMEOUT]
    ends = [r for r in caplog.records if 'session ended' in r.getMessage()]
    assert ends and ends[-1].levelno == logging.WARNING, [r.getMessage() for r in ends]
    assert 'reason=Client->PVE' in ends[-1].getMessage()


def test_the_relay_writes_with_the_deadline(api, cluster, monkeypatch, pve_socket):
    pve = _SlowPve()
    pve.sock = pve_socket.idle
    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: pve)
    _vnc_socket(api, _Browser3())
    assert pve.written == [b'k1', b'k2', b'k3']
    assert set(pve.timeouts_at_write) == {VNC_PVE_SEND_TIMEOUT}


# --- why it ended, at WARNING ------------------------------------------------

class _ResetPve:
    """PVE that resets the connection on the first read; the socket says there is one."""

    def __init__(self, sock):
        self.sock = sock

    def settimeout(self, t):
        pass

    def recv(self):
        raise ConnectionResetError(104, 'Connection reset by peer')

    def send(self, *a):
        pass

    send_binary = ping = send

    def close(self):
        pass


def _ended_lines(caplog):
    return [r for r in caplog.records if 'session ended' in r.getMessage()]


def test_the_relay_says_why_at_warning(api, cluster, monkeypatch, caplog, pve_socket):
    """The line the reporter could only see with --debug: '[VNC] PVE->Client: [Errno 104]'.
    It was the standalone server's; the one relay left says it the same way."""
    class _Waiting:
        """stays open until the reader has hit the reset"""
        connected = True

        def receive(self, timeout=None):
            gevent.sleep(0.05)
            return None

        def send(self, data):
            pass

        def close(self, *a, **k):
            pass

    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: _ResetPve(pve_socket.ready))
    with caplog.at_level(logging.INFO):
        _vnc_socket(api, _Waiting())
    ends = _ended_lines(caplog)
    assert ends and ends[-1].levelno == logging.WARNING, [r.getMessage() for r in caplog.records]
    assert 'reason=PVE->Client: [Errno 104] Connection reset by peer' in ends[-1].getMessage()


class _ScreenPve(_ResetPve):
    """PVE that sends one screen's worth of RFB, then nothing."""

    def __init__(self, sock):
        super().__init__(sock)
        self.frames = [b'\x00' * 8192]

    def recv(self):
        if self.frames:
            return self.frames.pop(0)
        gevent.sleep(0.005)
        raise websocket.WebSocketTimeoutException('read slice')


class _LeavesAfterTheScreen:
    """A browser that closes the tab once the screen has arrived."""

    def __init__(self):
        self.got = []

    @property
    def connected(self):
        return not self.got

    def receive(self, timeout=None):
        gevent.sleep(0.01)
        return None

    def send(self, data):
        self.got.append(data)

    def close(self, *a, **k):
        pass


def test_a_browser_closing_the_tab_is_no_warning(api, cluster, monkeypatch, caplog, pve_socket):
    """The counterweight: the WARNING is for a session that broke, not for every close."""
    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: _ScreenPve(pve_socket.ready))
    browser = _LeavesAfterTheScreen()
    with caplog.at_level(logging.INFO):
        _vnc_socket(api, browser)
    assert browser.got == [b'\x00' * 8192]
    ends = _ended_lines(caplog)
    assert ends and ends[-1].levelno == logging.INFO, [r.getMessage() for r in ends]
    assert 'reason=browser closed' in ends[-1].getMessage()
    assert 'SHORT_OR_EMPTY' not in ends[-1].getMessage()


def test_a_session_that_never_got_a_screen_is_a_warning(api, cluster, monkeypatch, caplog, pve_socket):
    """A tab closed within seconds before PVE sent anything is how a middlebox that eats
    the RFB stream looks from here; the standalone server flagged it, the relay does."""
    class _Leaves:
        connected = False

        def receive(self, timeout=None):
            return None

        def send(self, data):
            pass

        def close(self, *a, **k):
            pass

    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: _ScreenPve(pve_socket.idle))
    with caplog.at_level(logging.INFO):
        _vnc_socket(api, _Leaves())
    ends = _ended_lines(caplog)
    assert ends and ends[-1].levelno == logging.WARNING, [r.getMessage() for r in ends]
    assert 'reason=browser closed' in ends[-1].getMessage()
    assert 'recv=0B SHORT_OR_EMPTY' in ends[-1].getMessage()


@pytest.fixture
def pve_socket_past_1023():
    """pve_socket, but numbered above 1023: an instance with a few dozen consoles and its
    cluster connections holds that many descriptors, and select() refuses those."""
    resource = pytest.importorskip('resource')
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 1400
    if hard != resource.RLIM_INFINITY and hard < want:
        pytest.skip(f'hard descriptor limit {hard}')
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, want), hard))
    held = []
    try:
        while True:
            fd = os.open(os.devnull, os.O_RDONLY)
            held.append(fd)
            if fd >= 1100:
                break
        idle, idle_peer = socket.socketpair()
        ready, ready_peer = socket.socketpair()
        ready_peer.send(b'x')
        try:
            assert min(idle.fileno(), ready.fileno()) > 1023
            yield types.SimpleNamespace(idle=idle, ready=ready)
        finally:
            for s in (idle, idle_peer, ready, ready_peer):
                s.close()
    finally:
        for fd in held:
            os.close(fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_the_wait_for_pve_takes_a_descriptor_past_1023(pve_socket_past_1023):
    assert vms._pve_socket_readable(pve_socket_past_1023.idle, 0.05) is False
    assert vms._pve_socket_readable(pve_socket_past_1023.ready, 0.05) is True


def test_a_console_opened_past_descriptor_1023_gets_its_screen(api, cluster, monkeypatch, caplog,
                                                               pve_socket_past_1023):
    """With select() in the wait every such console ended in its first second, before
    PVE's first byte, as 'PVE->Client: filedescriptor out of range in select()'."""
    monkeypatch.setattr(websocket, 'create_connection',
                        lambda *a, **k: _ScreenPve(pve_socket_past_1023.ready))
    browser = _LeavesAfterTheScreen()
    with caplog.at_level(logging.INFO):
        _vnc_socket(api, browser)
    assert browser.got == [b'\x00' * 8192]
    ends = _ended_lines(caplog)
    assert ends and 'reason=browser closed' in ends[-1].getMessage(), [r.getMessage() for r in ends]
