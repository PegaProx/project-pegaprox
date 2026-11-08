# -*- coding: utf-8 -*-
"""
PegaProx SSH Connection Pool & ControlMaster Helpers - Layer 4

NS Apr 2026 — Phase 2 SSH stabilization for big clusters (15+ nodes).
This module is PURELY ADDITIVE. Existing SSH paths in core/manager.py
(_ssh_run_command_*) and utils/ssh.py:_ssh_exec are not modified —
those are HA-critical and must keep their current latency profile.

Two primitives:
  1. controlmaster_args(host, user) — returns extra OpenSSH args that
     enable ControlMaster connection sharing (one TCP+crypto+auth, many
     command sessions). 90 % latency reduction on repeat ops to same node.
     Graceful fallback: if the master can't be opened, OpenSSH automatically
     falls back to a fresh connection — caller code doesn't need to handle it.

  2. ParamikoTransportPool — per-(host, user, auth_hash) cached paramiko
     Transports. LRU eviction, idle TTL, health-check on reuse, auto-evict
     on errors. Used opt-in by run_per_node-style fanouts ONLY. Falls back
     to creating a fresh Transport if anything goes wrong.

Safety contract:
  - Both primitives are pure optimizations — calling code MUST work even
    if these silently no-op or fail. Errors are logged at debug, never
    raised to the caller.
  - HA paths never go through this module.
  - Graceful degradation by design.
"""

import os
import logging
import threading
import time
import hashlib

# ──────────────────────────────────────────────────────────────────────
# OpenSSH ControlMaster
# ──────────────────────────────────────────────────────────────────────

# Socket dir — prefer /run (tmpfs, root-owned, auto-cleared on reboot) over /tmp.
# Falls back to /tmp if /run isn't writable (e.g. container without /run mount).
_CM_DIR_CANDIDATES = ['/run/pegaprox', '/var/run/pegaprox', '/tmp/pegaprox-cm']
_cm_dir = None
_cm_dir_lock = threading.Lock()

def _ensure_cm_dir():
    """Lazy-create the ControlMaster socket dir on first use. Idempotent."""
    global _cm_dir
    if _cm_dir:
        return _cm_dir
    with _cm_dir_lock:
        if _cm_dir:
            return _cm_dir
        for cand in _CM_DIR_CANDIDATES:
            try:
                os.makedirs(cand, mode=0o700, exist_ok=True)
                # Probe writability — bind-mounted /run on some hosts is read-only
                probe = os.path.join(cand, '.pp-write-test')
                with open(probe, 'w') as f:
                    f.write('1')
                os.unlink(probe)
                _cm_dir = cand
                logging.debug(f"[ssh_pool] ControlMaster socket dir: {cand}")
                return _cm_dir
            except Exception as e:
                logging.debug(f"[ssh_pool] cannot use {cand}: {e}")
        # All candidates failed → return None, caller will skip ControlMaster
        return None


def controlmaster_args(host, user, persist_seconds=300):
    """Return list of OpenSSH args that enable ControlMaster sharing.

    Caller does:
        cmd = ['ssh', *controlmaster_args(host, user), ...other args..., target, command]

    If the socket dir can't be created, returns [] — caller's ssh runs
    normally without sharing (graceful no-op).

    Persist=300s default: master stays alive 5 min after last command,
    re-used by follow-ups. Tuning higher would keep more connections open
    across operations but risks stale-connection issues after node reboot.
    """
    d = _ensure_cm_dir()
    if not d:
        return []
    # %h/%p/%r expand to host/port/remote-user — keeps sockets per-target
    socket_path = os.path.join(d, 'cm-%r@%h:%p')
    return [
        '-o', 'ControlMaster=auto',
        '-o', f'ControlPath={socket_path}',
        '-o', f'ControlPersist={persist_seconds}',
    ]


def cleanup_stale_cm_sockets(max_age_seconds=3600):
    """Best-effort cleanup of ControlMaster sockets older than max_age.

    Called opportunistically — not on a timer. Stale sockets shouldn't
    cause problems (OpenSSH tries to connect, fails, falls back to fresh)
    but cleaning them keeps the dir tidy.
    """
    d = _cm_dir
    if not d or not os.path.isdir(d):
        return
    try:
        now = time.time()
        for fname in os.listdir(d):
            if not fname.startswith('cm-'):
                continue
            path = os.path.join(d, fname)
            try:
                age = now - os.path.getmtime(path)
                if age > max_age_seconds:
                    os.unlink(path)
            except Exception:
                pass
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────
# Paramiko Transport Pool
# ──────────────────────────────────────────────────────────────────────

# Pool layout: { auth_key: (transport, last_used_ts, host, user) }
# auth_key = sha256(host + user + auth_material) so different users on the
# same host get different entries. Password/key are NOT stored, only their
# hash for the lookup key.

POOL_MAX_SIZE = 50
POOL_IDLE_TTL = 300  # 5 min
POOL_HEALTH_CHECK_INTERVAL = 30  # don't health-check on every reuse, only if last-used > 30s ago

_pool = {}  # auth_key → (transport, last_used_ts, host, user)
_pool_lock = threading.Lock()


def _auth_key(host, user, password=None, pkey_data=None):
    """Stable hash key for pool lookup — host + user + creds-fingerprint."""
    h = hashlib.sha256()
    h.update((host or '').encode())
    h.update(b'\0')
    h.update((user or '').encode())
    h.update(b'\0')
    if password:
        h.update(password.encode() if isinstance(password, str) else password)
    if pkey_data:
        h.update(pkey_data.encode() if isinstance(pkey_data, str) else pkey_data)
    return h.hexdigest()


def _is_transport_healthy(transport, last_used_ts):
    """Return True if transport looks usable. Cheap check — full handshake
    happened on creation. is_active() catches torn connections."""
    try:
        if not transport or not transport.is_active():
            return False
        # If recently used, trust it. Otherwise send a NOOP-ish probe.
        if (time.time() - last_used_ts) < POOL_HEALTH_CHECK_INTERVAL:
            return True
        # send_ignore is paramiko's keepalive ping — small + cheap
        try:
            transport.send_ignore()
            return True
        except Exception:
            return False
    except Exception:
        return False


def _evict_lru(needed_slots=1):
    """Drop the oldest entries to make room for new ones. Caller holds lock."""
    if len(_pool) + needed_slots <= POOL_MAX_SIZE:
        return
    sorted_items = sorted(_pool.items(), key=lambda kv: kv[1][1])
    drop_count = len(_pool) + needed_slots - POOL_MAX_SIZE
    for k, (t, _, _, _) in sorted_items[:drop_count]:
        try:
            t.close()
        except Exception:
            pass
        del _pool[k]


def _evict_idle():
    """Sweep entries idle longer than POOL_IDLE_TTL. Caller holds lock."""
    now = time.time()
    stale = [k for k, (_, ts, _, _) in _pool.items() if (now - ts) > POOL_IDLE_TTL]
    for k in stale:
        t, _, _, _ = _pool.pop(k)
        try:
            t.close()
        except Exception:
            pass


def get_pooled_transport(host, port, user, password=None, pkey=None, pkey_data=None,
                          connect_timeout=10):
    """Return a healthy paramiko Transport — pooled or fresh.

    Args:
        host, port, user — destination
        password — for password auth (optional)
        pkey — paramiko PKey object (already parsed) for key auth (optional)
        pkey_data — raw key bytes/string used to fingerprint for pool lookup
            (optional but improves pool hit rate when pkey is regenerated each call)
        connect_timeout — seconds for the underlying TCP connect

    Returns:
        (transport, was_pooled) — transport is ready for transport.open_session()
        Returns (None, False) on error. Caller must NOT close the transport
        unless they got was_pooled=False — pooled transports are owned by the
        pool. On exception during use, caller should call mark_transport_bad().
    """
    try:
        import paramiko
    except ImportError:
        return None, False

    key = _auth_key(host, user, password=password, pkey_data=pkey_data)

    with _pool_lock:
        _evict_idle()
        cached = _pool.get(key)
        if cached:
            transport, last_used, _, _ = cached
            if _is_transport_healthy(transport, last_used):
                _pool[key] = (transport, time.time(), host, user)
                return transport, True
            # Stale → drop and create fresh
            try:
                transport.close()
            except Exception:
                pass
            _pool.pop(key, None)

    # Create fresh outside the lock — connect can take seconds, don't block other callers.
    try:
        sock_args = (host, int(port or 22))
        transport = paramiko.Transport(sock_args)
        transport.banner_timeout = connect_timeout
        transport.start_client(timeout=connect_timeout)
        # verify the server key before sending credentials (manual Transport bypasses
        # the SSHClient host-key policy). Raises on changed/unknown key.
        from pegaprox.utils.ssh_security import verify_transport_host_key
        verify_transport_host_key(transport, host, paramiko, port=int(port or 22))
        if pkey is not None:
            transport.auth_publickey(user, pkey)
        elif password is not None:
            transport.auth_password(user, password)
        else:
            return None, False
        if not transport.is_authenticated():
            try: transport.close()
            except Exception: pass
            return None, False
    except Exception as e:
        logging.debug(f"[ssh_pool] new transport {user}@{host} failed: {e}")
        return None, False

    with _pool_lock:
        _evict_lru(needed_slots=1)
        _pool[key] = (transport, time.time(), host, user)
    return transport, False


def mark_transport_bad(host, user, password=None, pkey_data=None):
    """Caller signals the transport for this auth_key is unusable.
    Pool drops it so the next caller gets a fresh one."""
    key = _auth_key(host, user, password=password, pkey_data=pkey_data)
    with _pool_lock:
        cached = _pool.pop(key, None)
    if cached:
        try:
            cached[0].close()
        except Exception:
            pass


def pool_stats():
    """Observability — returns pool occupancy info."""
    with _pool_lock:
        now = time.time()
        return {
            'size': len(_pool),
            'max_size': POOL_MAX_SIZE,
            'idle_ttl': POOL_IDLE_TTL,
            'entries': [
                {
                    'host': host, 'user': user,
                    'idle_seconds': int(now - last_used),
                    'active': bool(t and t.is_active()),
                }
                for key, (t, last_used, host, user) in _pool.items()
            ],
        }
