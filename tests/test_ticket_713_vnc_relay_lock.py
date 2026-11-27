# #713 follow-up - the original fix serialised SSL on the standalone console leg only; the
# reverse-proxy / geventwebsocket consoles and the HTTP-poll layer (VncPollSession) still ran a
# concurrent SSL_read (reader) + SSL_write (sender) on the one pve_ws, which pveproxy tears down
# with a tlsv1 decode error. All of them funnel pve_ws ops through a single lock.
#
# The first proof holds the poll session's recv/send to it, in a subprocess that is
# monkey-patched from its first import. The others hold the one VNC relay left (_vnc_relay
# behind the flask-sock route, api/vms.py) to it in this process: conftest has patched gevent
# already, and the relay needs the app's request context. Its reader waits for PVE with select()
# outside the lock and only reads under it when there is something to read, so a still screen
# costs no read and the browser's input never queues behind one.

import os
import socket
import subprocess
import sys
import time
import types

import gevent
import pytest
import websocket

from pegaprox.api import vms
from test_console_token_cluster_955 import _PATH, _PasswordManager, _Pve, _query

_PROOF = r'''
import gevent.monkey; gevent.monkey.patch_all()
import gevent, base64, websocket
from pegaprox.utils.vnc_polling import VncPollSession

class FakePveWs:
    def __init__(self):
        self._in = 0; self.maxc = 0; self.frames = [b"F"*16 for _ in range(8)]
    def settimeout(self, t): pass
    def _op(self):
        self._in += 1; self.maxc = max(self.maxc, self._in)
        gevent.sleep(0.003)          # hold the "SSL op" to open an overlap window
        self._in -= 1
    def recv(self):
        if self.frames:
            self._op(); return self.frames.pop(0)
        gevent.sleep(0.002); raise websocket.WebSocketTimeoutException()
    def send_binary(self, raw):
        self._op(); return len(raw)

fake = FakePveWs()
sess = VncPollSession("poll1234abcd", fake, None, None, "c1", "qemu", 100, "h")

def spam_send():
    for _ in range(60):
        try: sess.send(base64.b64encode(b"k").decode())
        except Exception: pass
        gevent.sleep(0.001)

g = gevent.spawn(spam_send); g.join(timeout=4)
sess._closed = True; gevent.sleep(0.1)
assert fake.maxc == 1, "OVERLAP: recv+send raced on pve_ws (maxc=%d)" % fake.maxc
assert sess.bytes_sent == 60, sess.bytes_sent          # every send went through
print("OK")
'''


def test_vnc_poll_recv_send_are_mutually_exclusive():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=repo)
    r = subprocess.run([sys.executable, '-c', _PROOF], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip().endswith('OK'), \
        f"stdout={r.stdout!r} stderr={r.stderr[-800:]!r}"


# --- the VNC relay --------------------------------------------------------------------------

class _CountingPve:
    """A PVE websocket that notes how many operations run on it at once. `sock` is what the
    relay's select() looks at."""

    def __init__(self, sock, frames=8):
        self.sock = sock
        self.inside = self.most = self.reads = 0
        self.frames = [b'F' * 16 for _ in range(frames)]
        self.written = []

    def _op(self):
        self.inside += 1
        self.most = max(self.most, self.inside)
        gevent.sleep(0.003)          # an SSL call that takes a while: the window for a second one
        self.inside -= 1

    def settimeout(self, t):
        pass

    def recv(self):
        self.reads += 1
        if self.frames:
            self._op()
            if hasattr(self.sock, 'records'):
                self.sock.records -= 1
            return self.frames.pop(0)
        gevent.sleep(0.002)
        raise websocket.WebSocketTimeoutException('read slice')

    def send(self, data=b''):
        self._op()
        self.written.append(data)

    send_binary = ping = send

    def close(self):
        pass


class _Typist:
    """A browser that types `keys` keys a millisecond apart and leaves once it has
    `screen` frames from PVE, or after five seconds."""

    def __init__(self, keys, screen):
        self.keys = [b'k'] * keys
        self.screen = screen
        self.got = []
        self.until = time.monotonic() + 5

    @property
    def connected(self):
        if time.monotonic() > self.until:
            return False
        return bool(self.keys) or len(self.got) < self.screen

    def receive(self, timeout=None):
        gevent.sleep(0.001)
        return self.keys.pop() if self.keys else None

    def send(self, data):
        self.got.append(data)

    def close(self, *a, **k):
        pass


class _Buffered:
    """A TLS socket whose OpenSSL already holds decrypted records: select() sees nothing on
    the descriptor, pending() says there is more."""

    def __init__(self, sock, records):
        self._sock = sock
        self.records = records

    def fileno(self):
        return self._sock.fileno()

    def pending(self):
        return self.records


class _NoLock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def relay(api, seed, monkeypatch):
    """Runs the VNC socket against a PVE websocket of the test's making. Its sockets:
    .idle has nothing to read, .ready always a byte waiting."""
    seed.user('root', role='admin')
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', _Pve(password_ok=True).opener)
    api.set_manager('c1', _PasswordManager())
    idle, idle_peer = socket.socketpair()
    ready, ready_peer = socket.socketpair()
    ready_peer.send(b'x')
    view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__

    def run(pve, browser):
        monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: pve)
        with api.app.test_request_context(f'{_PATH}?{_query(True)}'):
            view(browser, 'c1', 'pve1', 'qemu', 100)
        return pve

    yield types.SimpleNamespace(run=run, idle=idle, ready=ready)
    for s in (idle, idle_peer, ready, ready_peer):
        s.close()


def test_the_vnc_relay_never_reads_and_writes_at_once(relay):
    browser = _Typist(60, screen=8)
    pve = relay.run(_CountingPve(relay.ready), browser)
    assert pve.most == 1, f'OVERLAP: a read and a write ran on pve_ws together ({pve.most})'
    assert len(pve.written) == 60 and len(browser.got) == 8


def test_the_counting_pve_sees_an_overlap_where_there_is_one(relay, monkeypatch):
    """Counterproof: the same session with the relay's lock taken out, so the proof above
    is not green for want of a race the fake could see."""
    monkeypatch.setattr(vms, 'threading', types.SimpleNamespace(Lock=_NoLock))
    pve = relay.run(_CountingPve(relay.ready), _Typist(60, screen=8))
    assert pve.most > 1


def test_a_still_screen_is_never_read(relay):
    """Nothing to read on the socket: the reader waits in select(), not in a read under
    the lock that every key would queue behind."""
    browser = _Typist(20, screen=0)
    pve = relay.run(_CountingPve(relay.idle), browser)
    assert pve.reads == 0
    assert len(pve.written) == 20


def test_records_openssl_already_holds_are_read(relay):
    """The descriptor shows nothing once OpenSSL has pulled the records off it; pending()
    still has them, and the reader takes them instead of waiting on select()."""
    browser = _Typist(1, screen=3)
    pve = relay.run(_CountingPve(_Buffered(relay.idle, 3), frames=3), browser)
    assert len(browser.got) == 3
    assert pve.reads == 3, 'read again although neither the socket nor OpenSSL had more'
