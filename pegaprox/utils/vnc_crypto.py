"""Per-session AES-256-GCM authenticated encryption for the VNC websocket stream.

Defends against middleboxes (TLS-inspection NGFW, EDR network filter, ...) that
re-encrypt the outer TLS and modify bytes. The browser still negotiates TLS with
PegaProx and the inspection engine still re-encrypts that, but inside the
WebSocket frames we put a SECOND layer of authenticated encryption with a
session key shared only between browser and PegaProx server.

The inspection engine sees: TLS-encrypted blobs → decrypt → opaque-encrypted
blobs (our AES-GCM) → can't recognize protocol → leaves bytes alone → re-encrypt
TLS → forward.

Without inner encryption the engine would see binary RFB and pattern-match it
as RAT traffic, applying mangling / dropping. With inner encryption the binary
RFB is hidden inside opaque ciphertext that no DPI engine can parse.

Frame format on the wire (after WebSocket framing strips its own header):

    [4-byte seq big-endian][12-byte IV][N-byte ciphertext][16-byte GCM tag]

  - seq: monotonic counter, also part of AAD → defends against frame replay /
         reorder.
  - IV:  4 bytes of seq + 8 bytes of CSPRNG → never collides for a session,
         AES-GCM safe up to 2**32 frames per key.
  - tag: GCM authentication tag → verifies the ciphertext + AAD weren't
         modified. If a middlebox flips even one bit, decrypt() raises and we
         can surface a clean "your network is interfering" error to the user.

MK Apr 2026 — split out from vms.py so it's importable + unit-testable.
"""
import os
import struct
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_BYTES = 32      # AES-256
IV_BYTES = 12
SEQ_BYTES = 4
TAG_BYTES = 16
HEADER_BYTES = SEQ_BYTES + IV_BYTES   # 16
MIN_FRAME_BYTES = HEADER_BYTES + TAG_BYTES   # 32 — empty plaintext still has tag


class VncCryptoError(Exception):
    """Raised on integrity-check failure or malformed frame."""


class VncCryptoSession:
    """One session = one shared AES-256 key, two independent sequence counters.

    Browser and server both create a VncCryptoSession with the same key; each
    side encrypts its outbound stream using its own send-counter and verifies
    the inbound stream against its own expected receive-counter.
    """

    def __init__(self, key: bytes):
        if len(key) != KEY_BYTES:
            raise ValueError(f"VNC crypto key must be {KEY_BYTES} bytes (AES-256)")
        self._aesgcm = AESGCM(key)
        self._send_seq = 0
        self._recv_seq = 0
        self._lock = threading.Lock()  # encrypt/decrypt are quick but we run async

    def encrypt(self, plaintext: bytes) -> bytes:
        """Wrap plaintext into a self-contained authenticated frame."""
        with self._lock:
            seq = self._send_seq & 0xFFFFFFFF
            self._send_seq = (self._send_seq + 1) & 0xFFFFFFFF
        seq_bytes = struct.pack('>I', seq)
        iv = seq_bytes + os.urandom(IV_BYTES - SEQ_BYTES)
        # AAD = seq → binds the auth tag to the ordinal position
        ciphertext_with_tag = self._aesgcm.encrypt(iv, plaintext, seq_bytes)
        return seq_bytes + iv + ciphertext_with_tag

    def decrypt(self, frame: bytes) -> bytes:
        """Verify + unwrap a frame. Raises VncCryptoError on any tampering."""
        if len(frame) < MIN_FRAME_BYTES:
            raise VncCryptoError(f"frame too short: {len(frame)} bytes")
        seq_bytes = frame[:SEQ_BYTES]
        iv = frame[SEQ_BYTES:HEADER_BYTES]
        ciphertext_with_tag = frame[HEADER_BYTES:]
        seq = struct.unpack('>I', seq_bytes)[0]
        with self._lock:
            expected = self._recv_seq & 0xFFFFFFFF
            if seq != expected:
                raise VncCryptoError(
                    f"out-of-order frame: got seq={seq}, expected {expected} "
                    "(possible replay / middlebox reorder)"
                )
            self._recv_seq = (self._recv_seq + 1) & 0xFFFFFFFF
        try:
            return self._aesgcm.decrypt(iv, ciphertext_with_tag, seq_bytes)
        except InvalidTag:
            raise VncCryptoError(
                "GCM auth tag mismatch — bytes were modified mid-stream "
                "(typical TLS-inspection / EDR symptom)"
            )


class _SessionStore:
    """Tiny in-memory key store with per-entry TTL.

    Maps session-id → key-bytes. Used by the /console endpoint to hand off a
    session key that the WebSocket handler later picks up. Keys expire after
    TTL so a stale entry never accidentally encrypts another user's session.
    """

    def __init__(self, ttl_seconds: int = 60):
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def put(self, session_id: str, key: bytes) -> None:
        with self._lock:
            self._gc_locked()
            self._store[session_id] = (key, time.monotonic() + self._ttl)

    def get_and_delete(self, session_id: str) -> bytes | None:
        with self._lock:
            self._gc_locked()
            entry = self._store.pop(session_id, None)
            if entry is None:
                return None
            key, expires = entry
            if time.monotonic() > expires:
                return None
            return key

    def _gc_locked(self) -> None:
        now = time.monotonic()
        stale = [sid for sid, (_k, exp) in self._store.items() if now > exp]
        for sid in stale:
            del self._store[sid]


# Module-level singleton — one process, one store.
_session_keys = _SessionStore(ttl_seconds=60)


def stash_session_key(session_id: str, key: bytes) -> None:
    """Stash a key for later retrieval by the WS handler."""
    _session_keys.put(session_id, key)


def claim_session_key(session_id: str) -> bytes | None:
    """One-shot retrieval — caller takes ownership, key is removed."""
    return _session_keys.get_and_delete(session_id)


def generate_session_key() -> bytes:
    """Random 256-bit key for a single VNC session."""
    return os.urandom(KEY_BYTES)


# ──────────────────────────────────────────────────────────
# Self-test (run directly: python -m pegaprox.utils.vnc_crypto)
# ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys

    def _ok(msg): print(f"  OK  {msg}")
    def _bad(msg):
        print(f"  FAIL {msg}")
        sys.exit(1)

    print("=== vnc_crypto self-test ===")

    # 1. Round-trip
    key = generate_session_key()
    server = VncCryptoSession(key)
    client = VncCryptoSession(key)
    msgs = [b'', b'hello', b'RFB 003.008\n', os.urandom(8192), b'\x00' * 100]
    for m in msgs:
        wire = server.encrypt(m)
        back = client.decrypt(wire)
        if back != m:
            _bad(f"round-trip {len(m)} bytes")
    _ok(f"round-trip ({len(msgs)} messages, sizes 0..8192)")

    # 2. Tampered ciphertext caught
    server2 = VncCryptoSession(key)
    client2 = VncCryptoSession(key)
    wire = server2.encrypt(b"sensitive RFB challenge")
    tampered = bytearray(wire)
    tampered[20] ^= 0x01  # flip one bit in the ciphertext
    try:
        client2.decrypt(bytes(tampered))
        _bad("tampered ciphertext was NOT caught")
    except VncCryptoError as e:
        if 'auth tag mismatch' in str(e).lower() or 'modified' in str(e).lower():
            _ok(f"tampered ciphertext caught: {str(e)[:60]}...")
        else:
            _bad(f"unexpected error: {e}")

    # 3. Tampered seq caught
    server3 = VncCryptoSession(key)
    client3 = VncCryptoSession(key)
    wire = server3.encrypt(b"x")
    tampered = bytearray(wire)
    tampered[0] ^= 0xFF  # flip seq
    try:
        client3.decrypt(bytes(tampered))
        _bad("tampered seq was NOT caught")
    except VncCryptoError as e:
        _ok(f"tampered seq caught: {str(e)[:60]}...")

    # 4. Out-of-order frames caught
    server4 = VncCryptoSession(key)
    client4 = VncCryptoSession(key)
    f1 = server4.encrypt(b"frame1")
    f2 = server4.encrypt(b"frame2")
    try:
        client4.decrypt(f2)  # skipping f1
        _bad("out-of-order was NOT caught")
    except VncCryptoError as e:
        _ok(f"out-of-order caught: {str(e)[:60]}...")

    # 5. Frame too short caught
    server5 = VncCryptoSession(key)
    try:
        server5.decrypt(b"tinytooshort")
        _bad("short frame was NOT caught")
    except VncCryptoError as e:
        _ok(f"short frame caught: {str(e)[:60]}...")

    # 6. Session store: put / get / TTL
    sid = 'test-session-id-abc'
    k = generate_session_key()
    stash_session_key(sid, k)
    got = claim_session_key(sid)
    if got != k:
        _bad("session-store get returned wrong key")
    if claim_session_key(sid) is not None:
        _bad("session-store get-and-delete didn't delete")
    _ok("session-store put/claim/one-shot")

    # 7. Throughput sanity (1MB / round-trip)
    import time as _t
    server7 = VncCryptoSession(key)
    client7 = VncCryptoSession(key)
    bulk = os.urandom(1024 * 1024)
    chunks = [bulk[i:i+4096] for i in range(0, len(bulk), 4096)]
    t0 = _t.monotonic()
    for c in chunks:
        client7.decrypt(server7.encrypt(c))
    elapsed = _t.monotonic() - t0
    mb_per_s = 1.0 / elapsed
    _ok(f"throughput ~{mb_per_s:.1f} MB/s ({elapsed*1000:.1f}ms for 1MB / 256 frames)")

    print("=== all tests passed ===")
