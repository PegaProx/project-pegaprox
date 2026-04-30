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
import base64
import logging
import secrets
import threading
import time
from collections import deque
from typing import Optional

import gevent

# defaults
SESSION_IDLE_TTL = 90.0          # seconds without activity → reaper closes
RECV_LONG_POLL_DEFAULT = 5.0     # block at most this long for new bytes
RECV_LONG_POLL_MAX = 25.0


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
        # Blocking recv. websocket-client is gevent-friendly thanks to monkey
        # patching, so this yields the greenlet during socket waits.
        try:
            self.pve_ws.settimeout(None)
        except Exception:
            pass
        while not self._closed:
            try:
                data = self.pve_ws.recv()
            except Exception as e:
                logging.debug(f"[VncPoll {self.poll_id[:8]}] pve recv ended: {e}")
                break
            if not data:
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
        # send_binary on websocket-client = ws frame opcode 0x2
        self.pve_ws.send_binary(raw)
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
