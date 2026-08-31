# #713 (ygutnik) follow-up — the original fix serialised SSL on the standalone vnc_handler leg
# only; the reverse-proxy / geventwebsocket console (vnc_websocket_proxy, handle_vnc_websocket) and
# the HTTP-poll layer (VncPollSession) still ran a concurrent SSL_read (reader) + SSL_write (sender)
# on the one pve_ws, which pveproxy tears down with a tlsv1 decode error. All three now funnel
# pve_ws ops through a single lock. This proves the poll session's recv/send are mutually exclusive.
#
# gevent.monkey.patch_all() has to run before threading/socket are imported and would pollute the
# rest of the pytest session, so the proof runs in an isolated subprocess.

import os
import subprocess
import sys

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
