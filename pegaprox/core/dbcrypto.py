"""
DB connection abstraction with optional SQLCipher full-DB encryption.

Why this module exists
----------------------
PegaProx 0.9.9.x encrypted *individual sensitive fields* (passwords, SSH keys,
TOTP secrets) with Fernet inside an otherwise plain SQLite database.  That
left a lot of operational data in cleartext: hostnames, audit metadata,
session tokens, plugin state.  A leaked DB backup gave an attacker enough
context to plan a follow-up attack — even without the secret.key.

This module adds a transparent SQLCipher backend.  When sqlcipher3 is
importable (Linux x86_64 via pip wheel today), every PegaProx DB connection
is automatically AES-256-CBC + HMAC-SHA512 encrypted at rest using the
master key resolved by `pegaprox.core.keystore`.

When sqlcipher3 is NOT importable (ARM, macOS, Windows — until they ship
wheels), we fall back to plain sqlite3.  In that case the existing
field-level encryption + the new Multi-Tier key-location protection still
apply — graceful degradation.

The public API is `connect(db_path)` — one entry point, all callers use it.

MK May 2026 — "Stufe 3" of the security review response.
"""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Optional


_LOG = logging.getLogger(__name__)


# ─── Backend detection ──────────────────────────────────────────────────────
# Try sqlcipher3 first; fall back to plain sqlite3 if unavailable.  The
# `BACKEND` constant + `is_encrypted()` helper let callers (e.g. the health
# pill) report which backend is active without re-importing.

try:
    import sqlcipher3 as _sqlite_module  # type: ignore
    BACKEND = 'sqlcipher'
except Exception as _e:
    import sqlite3 as _sqlite_module  # type: ignore
    BACKEND = 'sqlite-plain'
    _LOG.info("[DBCRYPTO] sqlcipher3 not available (%s) — DB will be plain "
              "SQLite. Field-level encryption (Fernet) still applies. To "
              "enable full-DB encryption, install sqlcipher3-binary (Linux "
              "x86_64) or build pysqlcipher3 from source.", _e)


# Re-export Row, IntegrityError etc. so callers can `from .dbcrypto import Row`
Row = _sqlite_module.Row
IntegrityError = _sqlite_module.IntegrityError
OperationalError = _sqlite_module.OperationalError
DatabaseError = _sqlite_module.DatabaseError


def is_encrypted() -> bool:
    return BACKEND == 'sqlcipher'


# ─── cipher_memory_security toggle (issue #509, davinkevin) ────────────────
# SQLCipher's default behaviour is to mlock() its internal page caches so
# plaintext page bytes don't get paged to swap. mlock(2) needs either root,
# CAP_IPC_LOCK, or a fat RLIMIT_MEMLOCK — none of which apply to a default
# non-root container in k3s, so the lock fails with ENOMEM on every open
# and SQLCipher emits a WARN line. Over ~2 connections/sec that drowns the
# log. The at-rest encryption is unaffected; only the in-memory page cache
# protection goes away.
#
# Decision:
#   PEGAPROX_CIPHER_MEMORY_SECURITY=on       force the PRAGMA on (bare-metal)
#   PEGAPROX_CIPHER_MEMORY_SECURITY=off      force off (rootless containers)
#   PEGAPROX_CIPHER_MEMORY_SECURITY=auto     (default) heuristic below

_CIPHER_MEMORY_SECURITY_ENV = (os.environ.get('PEGAPROX_CIPHER_MEMORY_SECURITY')
                               or 'auto').strip().lower()


def _mlock_likely_works() -> bool:
    """True if the process can plausibly mlock(): running as root, or has an
    RLIMIT_MEMLOCK soft limit above the page-cache footprint SQLCipher needs."""
    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        # geteuid not on Windows — fall through to the rlimit probe
        pass
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        # SQLCipher needs at least one page per locked region plus its
        # working set. 8 MB is comfortably above what we've seen it hold
        # and well below the typical bare-metal 64 MB / unlimited limit.
        return soft >= 8 * 1024 * 1024
    except Exception:
        return False


def _resolve_memory_security_setting() -> bool:
    if _CIPHER_MEMORY_SECURITY_ENV == 'on':
        return True
    if _CIPHER_MEMORY_SECURITY_ENV == 'off':
        return False
    # 'auto' or unrecognised — heuristic decides
    return _mlock_likely_works()


_MEMORY_SECURITY_ON = _resolve_memory_security_setting()

if BACKEND == 'sqlcipher':
    if not _MEMORY_SECURITY_ON:
        _LOG.info(
            "[DBCRYPTO] cipher_memory_security disabled (env=%r, euid=%s) — "
            "at-rest encryption unchanged, SQLCipher page caches just won't "
            "be mlock()-pinned. Set PEGAPROX_CIPHER_MEMORY_SECURITY=on to "
            "force-enable on bare-metal where the rlimit allows it.",
            _CIPHER_MEMORY_SECURITY_ENV,
            getattr(os, 'geteuid', lambda: 'n/a')(),
        )
    else:
        _LOG.debug(
            "[DBCRYPTO] cipher_memory_security enabled (env=%r)",
            _CIPHER_MEMORY_SECURITY_ENV,
        )


def backend_status() -> dict:
    """For the /api/security/db-status endpoint + admin health-indicator."""
    return {
        'backend': BACKEND,
        'encrypted_at_rest': BACKEND == 'sqlcipher',
        'cipher': 'AES-256-CBC + HMAC-SHA512 (SQLCipher 4)' if BACKEND == 'sqlcipher' else None,
        'note': (
            "Full database encryption is active." if BACKEND == 'sqlcipher'
            else "Full DB encryption unavailable on this platform. "
                 "Sensitive fields are still Fernet-encrypted individually."
        ),
    }


# ─── Connection ─────────────────────────────────────────────────────────────

def connect(db_path: str, *, timeout: float = 30.0, **kwargs):
    """Open a connection to the PegaProx DB.

    When the SQLCipher backend is active, this:
      1. Opens the underlying file
      2. Issues `PRAGMA key = "x'<hex>'"` with the master key from keystore
      3. Sets `PRAGMA cipher_compatibility = 4` for the latest format
      4. Verifies the key by running a sentinel query

    When the plain SQLite backend is active, the key step is a no-op.

    All standard sqlite3 kwargs (check_same_thread, isolation_level, etc.)
    are forwarded.
    """
    conn = _sqlite_module.connect(db_path, timeout=timeout, **kwargs)
    if BACKEND == 'sqlcipher':
        _apply_sqlcipher_pragmas(conn, db_path)
    return conn


def _apply_sqlcipher_pragmas(conn, db_path: str) -> None:
    """Apply the SQLCipher PRAGMAs required to unlock + harden the DB.

    Must be called *before* any other query on a new connection — SQLCipher
    will refuse subsequent statements until the key is set.
    """
    # Lazy import to avoid circular keystore <-> dbcrypto dependency at
    # module-load time (keystore doesn't pull dbcrypto, but be safe).
    from pegaprox.core.keystore import load_master_key

    mk = load_master_key()
    hex_key = mk.key_raw.hex()

    # SQLCipher requires PRAGMA key before any data access, but a handful of
    # *configuration* pragmas (cipher_memory_security, cipher_kdf_algorithm,
    # cipher_default_*) must come BEFORE the key — they configure the page-
    # cache mlock + the key-derivation path that the keying step then uses.
    # Using the x'...' form on PRAGMA key tells SQLCipher to use the literal
    # 32-byte key (skipping its internal PBKDF2 derivation from a passphrase,
    # which would otherwise add ~100ms to every connection open).
    cur = conn.cursor()
    try:
        # MK 2026-06-01 (#509 davinkevin re-open) — cipher_memory_security has
        # to be issued BEFORE PRAGMA key. SQLCipher does the page-cache
        # mlock() at key time, so setting OFF afterwards (as we did in the
        # v0.9.12 first-cut) was too late — the failing mlock + warning had
        # already fired by the time the pragma landed. Per-connection, since
        # the setting is per-connection.
        if not _MEMORY_SECURITY_ON:
            cur.execute("PRAGMA cipher_memory_security = OFF")
        cur.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        # Format version 4 = current SQLCipher format (2019+).  Locking us
        # to v4 means future SQLCipher upgrades don't silently change the
        # at-rest format.
        cur.execute("PRAGMA cipher_compatibility = 4")
        # Verify the key works — if wrong, SQLCipher returns OK on the
        # PRAGMA key but the next read throws "file is not a database".
        # The smoke read catches that immediately with a clearer message.
        try:
            cur.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except Exception as e:
            raise RuntimeError(
                f"[DBCRYPTO] SQLCipher could not unlock {db_path}: {e}. "
                f"Master key source: {mk.source}. "
                f"If you recently rotated the key, run "
                f"`pegaprox migrate-db --reencrypt` with both old and new "
                f"keys available."
            ) from e
    finally:
        cur.close()


# ─── Off-hub heavy reads (scaling) ───────────────────────────────────────────
# NS 2026-06-04 — measured scaling fix for large fleets (#526/#528 class).
# PegaProx runs on a single gevent hub thread: every greenlet (all per-cluster
# poll/balance loops + the WSGI request handlers) cooperatively shares ONE OS
# thread. A sqlite3/SQLCipher query is a C call that does NOT yield to gevent,
# so a heavy read freezes the ENTIRE hub for its full duration — measured at
# ~0.65s for a 30-day metrics_history scan on a 4-cluster dev box (the hub
# ticked 0 times during it), scaling linearly with cluster count (~5s+ at 10
# clusters). That stall is the lag/freeze big deployments hit when someone
# opens Insights / Cost / Power views.
#
# run_heavy_read runs the query on a FRESH, independent connection inside
# gevent's OS threadpool. SQLCipher releases the GIL during its work, so the
# hub thread keeps scheduling every other greenlet while the query runs in a
# worker thread (measured: hub ticked 62x during the same 0.65s query when
# offloaded — i.e. stayed fully responsive). Fresh-connection-per-call is
# deliberate: the connection is opened, used, and closed entirely within the
# one worker thread, so there is never cross-thread use of a shared sqlite
# connection (unsafe even with check_same_thread=False). WAL mode (already on)
# means this read connection doesn't lock-contend with the main writer.
def _heavy_read_offload(sql: str, params: tuple, transform=None):
    """Run the query (and optionally a transform of the rows) on a fresh
    independent connection inside gevent's OS threadpool — or inline if no hub.

    `transform(rows)` runs INSIDE the worker thread too, so CPU-heavy
    post-processing (e.g. json.loads of thousands of rows) also stays off the
    hub instead of being done by the calling greenlet."""
    def _work():
        from pegaprox.constants import DATABASE_FILE
        conn = connect(DATABASE_FILE, timeout=30, check_same_thread=False)
        try:
            conn.row_factory = Row
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return transform(rows) if transform is not None else rows
    try:
        from gevent import get_hub
        return get_hub().threadpool.apply(_work)
    except Exception:
        # No active hub (synchronous CLI context) — run inline.
        return _work()


# ─── Tier 2: result cache + single-flight + concurrency cap ──────────────────
# NS 2026-06-04 — Tier-1 (off-hub reads) keeps a single heavy query from
# freezing the hub, but under heavy CONCURRENT load (many users opening
# Insights/Cost/Power at once) the crypto worker threads still contend the GIL
# and the hub blips. Tier-2 closes that:
#   - TTL cache keyed by an explicit semantic key (not the raw SQL/params,
#     whose `cutoff` timestamp varies by microseconds per call). metrics_history
#     is 5-min cadence, so a short TTL is correct — "last 30d as of now" vs
#     "as of 60s ago" is identical data.
#   - Single-flight: while one greenlet is fetching a key, others wait on its
#     AsyncResult instead of each firing their own query (no stampede). The
#     heavy metrics_history query is cluster-AGNOSTIC (it loads every cluster
#     then filters in Python), so all clusters + all concurrent callers for a
#     given window share ONE query.
#   - Concurrency cap: a bounded semaphore limits how many DISTINCT heavy
#     queries hit the crypto threadpool at once, so distinct-key misses can't
#     GIL-storm the hub.
import time as _time
_HEAVY_TTL = float(os.environ.get('PEGAPROX_HEAVY_READ_TTL', '60') or '60')
_HEAVY_CACHE: dict = {}      # cache_key -> (expiry_monotonic, rows)
_HEAVY_INFLIGHT: dict = {}   # cache_key -> AsyncResult

def _heavy_sem():
    # Lazily build a gevent BoundedSemaphore (needs the hub). Cap concurrent
    # distinct heavy queries; default 4. Falls back to None if gevent absent.
    global _HEAVY_SEM_OBJ
    try:
        return _HEAVY_SEM_OBJ
    except NameError:
        try:
            from gevent.lock import BoundedSemaphore
            n = int(os.environ.get('PEGAPROX_HEAVY_READ_CONCURRENCY', '4') or '4')
            _HEAVY_SEM_OBJ = BoundedSemaphore(max(1, n))
        except Exception:
            _HEAVY_SEM_OBJ = None
        return _HEAVY_SEM_OBJ


def run_heavy_read(sql: str, params: tuple = (), cache_key: str = None, ttl: float = None, transform=None):  # noqa: ANN001
    """Execute a read-only query off the gevent hub. Returns a list of Row
    objects (column-name access preserved), or transform(rows) when given.

    cache_key — when provided, results are TTL-cached + single-flighted under
    this key (callers pass a stable semantic key like 'mh:30', NOT the raw
    cutoff which varies per call). Omit for uncached off-hub reads.
    ttl — override the cache TTL (seconds) for this key.
    transform — optional callable(rows)->value run INSIDE the worker thread, so
    CPU-heavy post-processing (json.loads of thousands of rows) also stays off
    the hub. The transformed value is what gets cached/returned.

    Falls back to a direct in-thread query when gevent isn't available.
    """
    if not cache_key:
        return _heavy_read_offload(sql, params, transform)

    now = _time.monotonic()
    ent = _HEAVY_CACHE.get(cache_key)
    if ent and ent[0] > now:
        return ent[1]

    # single-flight: if someone is already fetching this key, wait for them.
    inflight = _HEAVY_INFLIGHT.get(cache_key)
    if inflight is not None:
        try:
            return inflight.get()
        except Exception:
            # the in-flight fetch failed; fall through and try ourselves
            pass

    # we are the fetcher
    try:
        from gevent.event import AsyncResult
        ar = AsyncResult()
    except Exception:
        ar = None
    if ar is not None:
        _HEAVY_INFLIGHT[cache_key] = ar
    try:
        sem = _heavy_sem()
        if sem is not None:
            with sem:
                rows = _heavy_read_offload(sql, params, transform)
        else:
            rows = _heavy_read_offload(sql, params, transform)
        _HEAVY_CACHE[cache_key] = (now + (ttl if ttl is not None else _HEAVY_TTL), rows)
        if ar is not None:
            ar.set(rows)
        return rows
    except Exception as e:
        if ar is not None:
            ar.set_exception(e)
        raise
    finally:
        _HEAVY_INFLIGHT.pop(cache_key, None)


def run_heavy_write(statements=None, build=None):
    """Execute write statements on a FRESH connection inside gevent's threadpool
    so a big encrypt+INSERT (and any prune) doesn't freeze the hub.

    NS 2026-06-05 (#528 scaling): the metrics snapshot write json.dumps's a
    multi-MB blob, encrypts it (SQLCipher), INSERTs, then prunes — all of which
    used to run on the hub every 5 min. Offloading it keeps the event loop free.

    statements — iterable of (sql, params) run in one transaction.
    build       — optional callable() -> statements, run INSIDE the worker
                  thread so even CPU-heavy prep (json.dumps) stays off the hub.
    Returns True on success. WAL + the connection's busy timeout handle the rare
    contention with the main connection (this runs every 5 min)."""
    def _work():
        from pegaprox.constants import DATABASE_FILE
        conn = connect(DATABASE_FILE, timeout=30, check_same_thread=False)
        try:
            stmts = build() if build is not None else (statements or [])
            cur = conn.cursor()
            for sql, params in stmts:
                cur.execute(sql, params or ())
            conn.commit()
            return True
        finally:
            try:
                conn.close()
            except Exception:
                pass
    try:
        from gevent import get_hub
        return get_hub().threadpool.apply(_work)
    except Exception:
        # No active hub (CLI / migration) — run inline.
        return _work()


# ─── Auto-migration on app startup ──────────────────────────────────────────
# NS May 2026 — "nuklear" means auto-on-boot. The CLI tool is the manual
# escape hatch; normal operators never have to think about migration.

_AUTO_MIG_LOCK = threading.Lock()  # in-process serialisation
_AUTO_MIG_DONE: set = set()        # paths that have already been checked


def _shred_file(path: str) -> bool:
    """Best-effort secure delete: overwrite with random bytes, fsync, unlink.
    NS 2026-06-05 (audit H-5). A plain unlink leaves the cleartext blocks on
    disk; overwrite first so a plaintext DB copy (= all cluster passwords) can't
    be carved back. Falls back to a plain remove if the overwrite fails."""
    if '..' in path:
        raise Exception('Invalid file path')
    try:
        sz = os.path.getsize(path)
        with open(path, 'r+b', buffering=0) as fh:
            fh.seek(0)
            fh.write(os.urandom(sz))
            fh.flush()
            os.fsync(fh.fileno())
        os.remove(path)
        return True
    except Exception as e:
        try:
            os.remove(path)
        except Exception:
            pass
        _LOG.warning("[DBCRYPTO] shred of %s incomplete: %s", path, e)
        return False


def purge_stale_plain_backups(db_path: str, retention_s: int = None):
    """Securely remove plaintext migration backups (<db>.plain.bak.<ts>) once
    they're older than the retention window. H-5 (security audit): a plaintext
    copy of the SQLCipher DB is every stored cluster password in cleartext,
    sitting next to the keystore. The auto-migration keeps one for a short
    rollback window; this sweep (every startup) shreds anything past it. Default
    1h, PEGAPROX_PLAIN_BACKUP_RETENTION_S to override (0 = shred immediately)."""
    import glob
    import time as _time
    if retention_s is None:
        try:
            retention_s = int(os.environ.get('PEGAPROX_PLAIN_BACKUP_RETENTION_S', '3600'))
        except ValueError:
            retention_s = 3600
    now = _time.time()
    purged = []
    for p in glob.glob(f"{os.path.abspath(db_path)}.plain.bak.*"):
        try:
            age = now - os.path.getmtime(p)
        except OSError:
            continue
        if age >= retention_s:
            if _shred_file(p):
                purged.append(p)
                _LOG.warning("[DBCRYPTO] shredded stale plaintext backup (%.1fh old): %s",
                             age / 3600.0, p)
    return purged


def ensure_db_encrypted(db_path: str) -> dict:
    """Idempotent: encrypt the DB at `db_path` if it's still plain and the
    SQLCipher backend is available.  Called once per DB during app startup.

    Returns a dict with: action, state_before, state_after, [backup_path,
    duration_s, rows_copied].  Does NOT raise on routine cases; raises only
    for unrecoverable situations (corrupt DB, unknown-key encrypted DB).

    Opt-out: set PEGAPROX_DISABLE_AUTO_ENCRYPT=1 to keep a plain DB.
    """
    db_path = os.path.abspath(db_path)
    if db_path in _AUTO_MIG_DONE:
        return {'action': 'already-checked'}
    if os.environ.get('PEGAPROX_DISABLE_AUTO_ENCRYPT', '').lower() in ('1', 'true', 'yes'):
        _LOG.info("[DBCRYPTO] PEGAPROX_DISABLE_AUTO_ENCRYPT set — skipping auto-encrypt check")
        _AUTO_MIG_DONE.add(db_path)
        return {'action': 'opt-out'}
    if BACKEND != 'sqlcipher':
        # No sqlcipher3 → can't encrypt anyway. Field-level Fernet still applies.
        _AUTO_MIG_DONE.add(db_path)
        return {'action': 'no-backend', 'reason': 'sqlcipher3 not installed'}

    with _AUTO_MIG_LOCK:
        if db_path in _AUTO_MIG_DONE:
            return {'action': 'already-checked'}
        # H-5: sweep stale plaintext backups every startup (before we possibly
        # create a fresh one below — a backup made by THIS boot's migration is
        # younger than the retention window, so it survives this boot for
        # rollback and gets shredded on a later start).
        try:
            purge_stale_plain_backups(db_path)
        except Exception as _pe:
            _LOG.debug("[DBCRYPTO] plain-backup purge soft-fail: %s", _pe)
        state = detect_db_state(db_path)

        if state in ('missing', 'encrypted'):
            # missing → SQLCipher creates an encrypted DB on first connect()
            # encrypted → already done, nothing to do
            _AUTO_MIG_DONE.add(db_path)
            return {'action': 'noop', 'state_before': state, 'state_after': state}

        if state == 'unknown-key':
            raise RuntimeError(
                f"[DBCRYPTO] {db_path} is encrypted but the current master key "
                f"does not unlock it. Refusing to start. Check that the right "
                f"PEGAPROX_DB_KEY / secret.key file is in place, or restore a "
                f"matching backup. (See docs/SECURITY.md §4)"
            )
        if state == 'corrupt':
            raise RuntimeError(
                f"[DBCRYPTO] {db_path} is neither plain SQLite nor a valid "
                f"encrypted DB — refusing to start. Restore from backup."
            )

        # state == 'plain' → run the migration inline
        _LOG.warning("[DBCRYPTO] plain DB detected at %s — auto-encrypting before "
                     "first connection. This is a one-time operation.", db_path)
        result = _run_inline_migration(db_path)
        _AUTO_MIG_DONE.add(db_path)
        return result


def _run_inline_migration(db_path: str) -> dict:
    """Inline plain→encrypted migration. Mirrors `cli.migrate_db` but with
    no prompts, no argparse, and a per-DB on-disk lock file so two parallel
    starts (e.g. systemd restart-storm) don't fight each other."""
    import fcntl
    import time

    lock_path = f"{db_path}.migration.lock"
    backup_path = f"{db_path}.plain.bak.{int(time.time())}"
    new_path = f"{db_path}.encrypted.new"

    # Cross-process lock so a concurrent boot can't double-migrate.
    # Held until this function returns.
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # Another instance is migrating — wait for it.
            _LOG.info("[DBCRYPTO] another process is migrating %s — waiting", db_path)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            # By the time we get the lock, the other process should have
            # already swapped in the encrypted DB. Re-check state.
            new_state = detect_db_state(db_path)
            if new_state == 'encrypted':
                return {'action': 'waited-for-peer', 'state_after': 'encrypted'}
            # Otherwise fall through and try again.

        # Lazy imports to keep this module light
        import shutil
        from pegaprox.core.keystore import load_master_key
        # Reuse the CLI helpers — they're public-ish (underscore-prefixed but
        # stable within the package).
        from pegaprox.cli.migrate_db import (
            _encrypt_via_sqlcipher_export,
            _verify_row_counts,
        )

        mk = load_master_key()
        t0 = time.time()

        # 1. backup
        shutil.copy2(db_path, backup_path)
        os.chmod(backup_path, 0o600)
        _LOG.info("[DBCRYPTO] backup → %s", backup_path)

        # 2. encrypt
        rows = _encrypt_via_sqlcipher_export(db_path, new_path, mk.key_raw)
        _LOG.info("[DBCRYPTO] sqlcipher_export OK (%d rows)", rows)

        # 3. verify
        _verify_row_counts(db_path, new_path)
        _LOG.info("[DBCRYPTO] row-count verification OK")

        # 4. atomic swap
        os.replace(new_path, db_path)
        os.chmod(db_path, 0o600)
        dt = time.time() - t0
        _LOG.warning(
            "[DBCRYPTO] auto-encrypt complete: %s (%.1fs, %d rows). "
            "Plain backup retained at %s — delete manually after you've "
            "verified the encrypted DB works.",
            db_path, dt, rows, backup_path)
        return {
            'action': 'migrated',
            'state_before': 'plain',
            'state_after': 'encrypted',
            'backup_path': backup_path,
            'duration_s': round(dt, 2),
            'rows_copied': rows,
        }
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except Exception:
            pass
        os.close(lock_fd)
        # Best-effort cleanup of stale candidate file
        try:
            if os.path.exists(new_path):
                os.remove(new_path)
        except Exception:
            pass


# ─── Plain-vs-Encrypted detection on an existing file ──────────────────────

def detect_db_state(db_path: str) -> str:
    """Probe a DB file to detect whether it's:
      - 'missing'      — file doesn't exist
      - 'plain'        — readable as plain SQLite
      - 'encrypted'    — refuses to open without a key (SQLCipher)
      - 'corrupt'      — neither plain SQLite nor a valid encrypted DB
      - 'unknown-key'  — encrypted but our current key doesn't unlock it

    Used by the auto-migration trigger on startup and the CLI tool.
    """
    if not os.path.exists(db_path):
        return 'missing'

    # First try plain sqlite3 — cheapest test
    import sqlite3 as _plain
    try:
        c = _plain.connect(db_path)
        try:
            c.execute("SELECT count(*) FROM sqlite_master").fetchone()
            c.close()
            return 'plain'
        except Exception:
            c.close()
    except Exception:
        pass

    # Try SQLCipher if available
    if BACKEND != 'sqlcipher':
        return 'corrupt'  # encrypted-looking but we can't decrypt anyway

    try:
        c = connect(db_path)
        c.execute("SELECT count(*) FROM sqlite_master").fetchone()
        c.close()
        return 'encrypted'
    except RuntimeError:
        return 'unknown-key'
    except Exception:
        return 'corrupt'
