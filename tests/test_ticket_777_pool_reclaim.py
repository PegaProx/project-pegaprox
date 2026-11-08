# #777 (Frisch12) — request-pool exhaustion. The gevent pywsgi pool holds one greenlet per
# CONNECTION: an idle keep-alive parks in read_requestline forever pinning its slot, and
# run_concurrent left stragglers running in the shared pool past its joinall timeout. Once the
# pool fills, gevent stops accepting and the instance is unreachable while idle. Two fixes:
#   1. _IdleTimeoutMixin bounds ONLY the idle read (a real request line passes straight through).
#   2. run_concurrent kills the greenlets it gave up on, handing their slots back.
#
# gevent.monkey.patch_all() must run before threading/socket import and would pollute the rest of
# the pytest session, so the proof runs in an isolated subprocess (same as test_ticket_713).

import os
import subprocess
import sys

_PROOF = r'''
import gevent.monkey; gevent.monkey.patch_all()
import gevent, time

# ---- 1. _IdleTimeoutMixin: idle read is bounded, a real request line passes through ----
from pegaprox.app import _IdleTimeoutMixin

class _Blocking:
    def read_requestline(self):
        gevent.sleep(10)                       # idle keep-alive that never sends the next request
        return b"GET / HTTP/1.1\r\n"

class _IdleH(_IdleTimeoutMixin, _Blocking):
    _idle_timeout = 0.2

t0 = time.time()
line = _IdleH().read_requestline()
dt = time.time() - t0
assert line == b"", "idle read should return b'' (clean close), got %r" % line
assert dt < 3, "idle read not bounded by the 0.2s timeout (took %.1fs)" % dt

class _Fast:
    def read_requestline(self):
        return b"GET /api/health HTTP/1.1\r\n"

class _FastH(_IdleTimeoutMixin, _Fast):
    _idle_timeout = 0.2

assert _FastH().read_requestline() == b"GET /api/health HTTP/1.1\r\n", "real request line must pass through"

# disabled (0) → unbounded: the read must NOT be cut off
class _DisabledH(_IdleTimeoutMixin, _Blocking):
    _idle_timeout = 0
_dg = gevent.spawn(_DisabledH().read_requestline)
_dg.join(timeout=0.5)
assert not _dg.ready(), "disabled timeout must NOT bound the read"
_dg.kill(block=False)

# ---- 2. run_concurrent reaps stragglers so the shared pool slot is returned ----
from pegaprox.utils import concurrent
pool = concurrent.GEVENT_POOL
free_before = pool.free_count()
killed = []

def _fast():
    return "ok"

def _hang():
    try:
        gevent.sleep(100)                      # never finishes within the timeout
    except gevent.GreenletExit:
        killed.append(1)
        raise
    return "never"

res = concurrent.run_concurrent([_fast, _hang, _fast], timeout=0.3)
assert res[0] == "ok" and res[2] == "ok", "fast tasks must return their value: %r" % res
assert res[1] is None, "hung task must come back None: %r" % res
gevent.sleep(0.15)                             # let the async kill propagate
assert pool.free_count() == free_before, "straggler leaked a pool slot (%d != %d)" % (
    pool.free_count(), free_before)
assert killed, "the hung greenlet was not reaped (no GreenletExit delivered)"

print("PROOF-OK")
'''


def test_777_idle_timeout_and_straggler_reaping():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, '-c', _PROOF],
        cwd=repo_root,
        env={**os.environ, 'PYTHONPATH': repo_root},
        capture_output=True, text=True, timeout=60,
    )
    assert 'PROOF-OK' in proc.stdout, (
        "proof failed:\nSTDOUT:\n%s\nSTDERR:\n%s" % (proc.stdout, proc.stderr))
