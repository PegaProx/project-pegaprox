"""HTTP long-polling fallback for VNC when the WebSocket leg is blocked.

Some corporate stacks (CrowdStrike Falcon, Zscaler with strict mode, Palo Alto
with WS DPI on) outright drop or terminate WebSocket upgrades — even after we've
wrapped the bytes with AES-GCM (Stable Mode) and tunnelled the second leg via
SSH. For those last-mile cases we expose a plain-HTTPS POST/GET-style transport
that no half-decent inspection product blocks.

Wire format on the browser side:
  POST /api/clusters/.../vnc-poll   action=open   -> { poll_id, ... }
  POST /api/clusters/.../vnc-poll   action=send   data_b64=..   -> { ok }
  POST /api/clusters/.../vnc-poll   action=recv                 -> { chunks: [b64..], closed? }
  POST /api/clusters/.../vnc-poll   action=close                -> { ok }

Latency is naturally higher than WSS (one HTTP round-trip per poll, ~30-80ms)
but it works through any firewall that allows normal HTTPS, which is the whole
point. Stable-Mode crypto is layered on top exactly the same as for WSS.

MK Apr 2026 — added as the third defensive layer alongside Stable Mode and the
SSH tunnel, after a customer reported their WSS was killed at the security
boundary even with both prior layers active.
"""
from pegaprox.constants import VNC_PVE_RECV_SLICE, VNC_PVE_SEND_TIMEOUT
import base64
import logging
import secrets
import threading
import time
from collections import deque
from typing import Optional

import gevent
import websocket   # #713 — WebSocketTimeoutException for the bounded pve_ws read slice

# defaults
SESSION_IDLE_TTL = 90.0          # seconds without activity → reaper closes
RECV_LONG_POLL_DEFAULT = 5.0     # block at most this long for new bytes
RECV_LONG_POLL_MAX = 25.0


# ─────────────────────────────────────────────────────────────────
# The PVE side of every relay leg (this one and the three in api/vms.py).
#
# MK Oct 2026 (#713) - OpenSSL keeps one error queue per OS thread, and SSL_get_error()
# reads it to tell "no data yet" from "connection broken". Python's _ssl never empties it
# before SSL_read/SSL_write, and under gevent every greenlet shares that one thread. So an
# entry some other connection left behind turns the relay's ordinary read timeout into an
# SSLError, and a healthy console ends. Neither ssl nor gevent expose ERR_clear_error, so
# it is taken from the libcrypto the _ssl module is linked against, and called right
# before each read and write on the PVE socket - also the retries gevent makes after
# waiting, which is where other greenlets got to run in between.
def _load_err_clear():
    try:
        import ctypes
        import _ssl
        fn = ctypes.CDLL(getattr(_ssl, '__file__', None)).ERR_clear_error
        fn.argtypes = []
        fn.restype = None
        fn()
        return fn
    except Exception as e:
        logging.debug(f"[VNC] ERR_clear_error not reachable ({e}) - relay reads stay as they are")
        return None


_err_clear = _load_err_clear()


class _ClearsErrorQueue:
    """Stands in for an SSL socket's _sslobj: empties the error queue, then reads or writes."""

    __slots__ = ('_obj',)

    def __init__(self, obj):
        object.__setattr__(self, '_obj', obj)

    def read(self, *args):
        _err_clear()
        return self._obj.read(*args)

    def write(self, data):
        _err_clear()
        return self._obj.write(data)

    def __getattr__(self, name):
        return getattr(self._obj, name)

    def __setattr__(self, name, value):
        setattr(self._obj, name, value)


def clear_tls_errors_before_io(sock):
    """Install the above on an SSL socket. False for a plain socket, or without libcrypto."""
    obj = getattr(sock, '_sslobj', None)
    if _err_clear is None or obj is None or isinstance(obj, _ClearsErrorQueue):
        return False
    try:
        sock._sslobj = _ClearsErrorQueue(obj)
    except Exception:
        return False
    return True


def write_with_deadline(pve_ws, write, *args):
    """One write to PVE under VNC_PVE_SEND_TIMEOUT, then back to the read slice.

    The caller holds the leg's io lock, so nobody reads while the timeout is changed.
    A write that times out halfway leaves the rest of its TLS record with OpenSSL, and
    OpenSSL takes the NEXT write for the retry of that one: it sends the pending bytes
    and skips as many of the new buffer. The stream behind it is garbage, so a write
    that raises here ends the session - nothing may be written after it. (#713)
    """
    pve_ws.settimeout(VNC_PVE_SEND_TIMEOUT)
    try:
        return write(*args)
    finally:
        try:
            pve_ws.settimeout(VNC_PVE_RECV_SLICE)
        except Exception:
            pass


class VncPollSession:
    """One browser↔PVE poll session.

    Owns a sync websocket-client connection (`pve_ws`) and an optional SSH tunnel
    endpoint (`tunnel_endpoint`). A pump greenlet copies bytes from PVE into a
    deque; recv() drains it. send() writes directly to PVE.
    """

    def __init__(self, poll_id: str, pve_ws, tunnel_endpoint, crypto_session,
                 cluster_id: str, vm_type: str, vmid: int, host: str):
        self.poll_id = poll_id
        self.pve_ws = pve_ws
        self.tunnel_endpoint = tunnel_endpoint
        self.crypto_session = crypto_session  # may be None (plain mode)
        self.cluster_id = cluster_id
        self.vm_type = vm_type
        self.vmid = vmid
        self.host = host
        self.created_at = time.monotonic()
        self.last_seen = time.monotonic()
        self.bytes_sent = 0       # browser → PVE
        self.bytes_recv = 0       # PVE → browser
        self._closed = False
        self._buf = deque()
        self._buf_lock = threading.Lock()
        self._buf_cond = threading.Condition(self._buf_lock)
        # #713 — serialise SSL_read (the pump) and SSL_write (send) on the one pve_ws
        self._pve_io_lock = threading.Lock()
        self._pump = gevent.spawn(self._pump_loop)

    # ─────────────────────────────────────────────────────────────────
    @property
    def closed(self) -> bool:
        return self._closed

    def touch(self):
        self.last_seen = time.monotonic()

    # ─────────────────────────────────────────────────────────────────
    def _pump_loop(self):
        """Copy bytes from PVE into buffer until the connection drops."""
        # #713 — bounded read slice (was settimeout(None), a blocking recv): pve_ws is
        # one SSL object and send() does an SSL_write on it; a concurrent SSL_read +
        # SSL_write splices a TLS record and pveproxy tears the session with a tlsv1
        # decode error. Funnel both through _pve_io_lock and release it between reads.
        # websocket-client's frame_buffer is resumable across a timed-out recv → no drop.
        try:
            self.pve_ws.settimeout(VNC_PVE_RECV_SLICE)
        except Exception:
            pass
        while not self._closed:
            try:
                with self._pve_io_lock:
                    data = self.pve_ws.recv()
            except websocket.WebSocketTimeoutException:
                gevent.sleep(0)   # empty slice — yield so a pending send() takes the lock
                continue
            except Exception as e:
                if not self._closed:
                    logging.warning(f"[VncPoll {self.poll_id[:8]}] session ended host={self.host} "
                                    f"vm={self.vm_type}/{self.vmid} reason=PVE->Client: {e}")
                break
            if not data:
                logging.info(f"[VncPoll {self.poll_id[:8]}] session ended reason=PVE closed")
                break
            if isinstance(data, str):
                data = data.encode('latin-1')
            self.bytes_recv += len(data)
            # Stable Mode: encrypt+seq before handing to the browser. Browser
            # decrypts with the same key it negotiated through /console?stable=1.
            if self.crypto_session is not None:
                try:
                    data = self.crypto_session.encrypt(data)
                except Exception as ce:
                    logging.warning(f"[VncPoll {self.poll_id[:8]}] encrypt failed: {ce}")
                    break
            with self._buf_cond:
                self._buf.append(data)
                self._buf_cond.notify_all()
        self._closed = True
        # Final wake-up so any pending recv() returns immediately.
        with self._buf_cond:
            self._buf_cond.notify_all()

    # ─────────────────────────────────────────────────────────────────
    def send(self, b64_payload: str) -> int:
        """Browser→PVE. Decrypts (Stable Mode) and forwards to PVE."""
        if self._closed:
            raise RuntimeError("session closed")
        raw = base64.b64decode(b64_payload)
        self.touch()
        if self.crypto_session is not None:
            raw = self.crypto_session.decrypt(raw)
        self.bytes_sent += len(raw)
        # send_binary on websocket-client = ws frame opcode 0x2. #713 — under the
        # shared lock so it never overlaps the pump's SSL_read on the same pve_ws.
        try:
            with self._pve_io_lock:
                write_with_deadline(self.pve_ws, self.pve_ws.send_binary, raw)
        except Exception as e:
            # the next send would land behind a partial frame, see write_with_deadline
            logging.warning(f"[VncPoll {self.poll_id[:8]}] session ended host={self.host} "
                            f"vm={self.vm_type}/{self.vmid} reason=Client->PVE: {e}")
            self.stop()
            raise
        return len(raw)

    def recv(self, max_wait: float = RECV_LONG_POLL_DEFAULT) -> list:
        """Drain pending PVE→browser chunks, blocking up to max_wait if empty."""
        max_wait = max(0.0, min(max_wait, RECV_LONG_POLL_MAX))
        deadline = time.monotonic() + max_wait
        self.touch()
        with self._buf_cond:
            if not self._buf and not self._closed and max_wait > 0:
                # block until pump appends something or session closes
                self._buf_cond.wait(timeout=max_wait)
            chunks = list(self._buf)
            self._buf.clear()
        return chunks

    def stop(self):
        if self._closed:
            return
        self._closed = True
        try: self.pve_ws.close()
        except Exception: pass
        try:
            if self.tunnel_endpoint is not None:
                self.tunnel_endpoint.stop()
        except Exception: pass
        try:
            self._pump.kill(block=False)
        except Exception: pass
        with self._buf_cond:
            self._buf_cond.notify_all()


# ─────────────────────────────────────────────────────────────────
# Pool: poll_id → VncPollSession. Plain dict + lock; sessions are short-lived.
_pool: dict[str, VncPollSession] = {}
_pool_lock = threading.Lock()
_reaper_started = False
_reaper_lock = threading.Lock()


def _start_reaper_once():
    global _reaper_started
    with _reaper_lock:
        if _reaper_started:
            return
        _reaper_started = True
        gevent.spawn(_reaper_loop)


def _reaper_loop():
    while True:
        gevent.sleep(15)
        now = time.monotonic()
        victims = []
        with _pool_lock:
            for pid, s in list(_pool.items()):
                if s.closed or (now - s.last_seen) > SESSION_IDLE_TTL:
                    victims.append((pid, s))
                    _pool.pop(pid, None)
        for pid, s in victims:
            try: s.stop()
            except Exception: pass
            logging.info(f"[VncPoll] reaped session {pid[:8]} (closed={s.closed} idle={int(now - s.last_seen)}s)")


def register(session: VncPollSession):
    _start_reaper_once()
    with _pool_lock:
        _pool[session.poll_id] = session


def get(poll_id: str) -> Optional[VncPollSession]:
    with _pool_lock:
        return _pool.get(poll_id)


def drop(poll_id: str):
    with _pool_lock:
        s = _pool.pop(poll_id, None)
    if s:
        try: s.stop()
        except Exception: pass


def new_poll_id() -> str:
    return secrets.token_urlsafe(18)


def stats() -> dict:
    with _pool_lock:
        n = len(_pool)
        ids = [pid[:8] for pid in list(_pool.keys())[:20]]
    return {'count': n, 'sample': ids}
