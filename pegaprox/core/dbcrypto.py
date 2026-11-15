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
importable (a pip wheel on Linux x86_64 and aarch64, macOS and Windows), every PegaProx DB connection
is automatically AES-256-CBC + HMAC-SHA512 encrypted at rest using the
master key resolved by `pegaprox.core.keystore`.

When sqlcipher3 is NOT importable (32-bit ARM, no SQLCipher package), we fall back to plain sqlite3.  In that case the existing
field-level encryption + the new Multi-Tier key-location protection still
apply — graceful degradation.

The public API is `connect(db_path)` — one entry point, all callers use it.

MK May 2026 — "Stufe 3" of the security review response.
"""
from __future__ import annotations

import contextlib
import errno
import logging
import math
import os
import platform
import threading
from pathlib import Path
from typing import Optional


_LOG = logging.getLogger(__name__)
# a name of its own so the tests can take the Windows branches on Linux
_WINDOWS = os.name == 'nt'


# MK Nov 2026 (#1226) - a sqlcipher3 built for another machine or another Python installs
# fine and then does not import (an x86_64 build in a deb that apt takes on arm64), and
# that fell back to plain SQLite with the INFO line meant for "not installed". Nobody sees
# that one: logging is not set up yet when this module loads. Installed but not loading
# is a WARNING now, and the reason stays here for the status output.
SQLCIPHER_ERROR: Optional[str] = None
_SQLCIPHER_AT: Optional[str] = None


def _load_failure(exc: BaseException) -> Optional[str]:
    """Why an installed sqlcipher3 did not import, None when there is none to import."""
    if isinstance(exc, ModuleNotFoundError) and exc.name == 'sqlcipher3':
        return None
    return f"{type(exc).__name__}: {' '.join(str(exc).split())}"


def _package_dir() -> Optional[str]:
    try:
        import importlib.util
        spec = importlib.util.find_spec('sqlcipher3')
        if spec is None:
            return None
        if spec.origin:
            return os.path.dirname(spec.origin)
        # a directory without __init__.py has no origin, only the places it was found
        found = list(spec.submodule_search_locations or ())
        return found[0] if found else None
    except Exception:
        return None


def sqlcipher_problem(encrypted: Optional[str] = None) -> Optional[str]:
    """What to tell an admin when sqlcipher3 is installed but does not load, else None.
    With `encrypted`, the path of a database encrypted before, it is about that one."""
    if not SQLCIPHER_ERROR:
        return None
    at = f' at {_SQLCIPHER_AT}' if _SQLCIPHER_AT else ''
    # the same CPU with another Python is this case too, so it names both
    fits = 'a package built for this machine and this Python version'
    said = (f"The SQLCipher package (sqlcipher3{at}) is installed but does not load on this "
            f"machine ({platform.machine() or 'unknown machine'}, Python "
            f"{platform.python_version()}): {SQLCIPHER_ERROR}.")
    if encrypted:
        return f"{said} {encrypted} is encrypted and does not open until {fits} is installed."
    return (f"{said} The database stays plain SQLite until {fits} is installed, and one "
            f"encrypted before does not open until then.")


# ─── Backend detection ──────────────────────────────────────────────────────
# Try sqlcipher3 first; fall back to plain sqlite3 if unavailable.  The
# `BACKEND` constant + `is_encrypted()` helper let callers (e.g. the health
# pill) report which backend is active without re-importing.

try:
    import sqlcipher3 as _sqlite_module  # type: ignore
    # MK Nov 2026 - an empty sqlcipher3/ directory (left when one of the two packages that
    # share it goes) imports as a namespace package with nothing in it
    if not hasattr(_sqlite_module, 'connect'):
        raise ImportError('the sqlcipher3 found has no driver in it')
    BACKEND = 'sqlcipher'
except Exception as _e:
    import sqlite3 as _sqlite_module  # type: ignore
    BACKEND = 'sqlite-plain'
    SQLCIPHER_ERROR = _load_failure(_e)
    if SQLCIPHER_ERROR is None:
        _LOG.info("[DBCRYPTO] sqlcipher3 not available (%s) - DB will be plain "
                  "SQLite. Field-level encryption (AES-256-GCM) still applies. To "
                  "enable full-DB encryption, install the SQLCipher package of "
                  "requirements.txt (sqlcipher3-binary on Linux x86_64, sqlcipher3 "
                  "on aarch64, macOS and Windows).", _e)
    else:
        _SQLCIPHER_AT = _package_dir()
        _LOG.warning("[DBCRYPTO] %s Field-level encryption (AES-256-GCM) still applies.",
                     sqlcipher_problem())


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


# MK Nov 2026 - the databases --keystore-status looks at, in CONFIG_DIR
STATUS_DB_FILES = ('pegaprox.db', 'syslog.db')
_SQLITE_MAGIC = b'SQLite format 3\x00'


def file_state(db_path: str) -> str:
    """'missing', 'empty', 'plain' or 'encrypted', from the first 16 bytes and without a
    key: a plain SQLite file starts with its magic, a SQLCipher one with a random salt.
    A file that is neither (truncated, not a database) reads as encrypted here too;
    detect_db_state, which needs the key, tells those apart."""
    try:
        with open(db_path, 'rb') as fh:
            head = fh.read(16)
    except FileNotFoundError:
        return 'missing'
    except OSError as e:
        return f'unreadable ({type(e).__name__})'
    if not head:
        return 'empty'
    return 'plain' if head == _SQLITE_MAGIC else 'encrypted'


def backend_status() -> dict:
    """What `pegaprox_multi_cluster.py --keystore-status` prints for the databases.

    MK Nov 2026 - encrypted_at_rest said whether the driver is there, so a database left
    plain (PEGAPROX_DISABLE_AUTO_ENCRYPT, or no start since sqlcipher3 came) read as
    encrypted. It now goes by the files in CONFIG_DIR, each listed with its state."""
    from pegaprox.constants import CONFIG_DIR
    files = {os.path.abspath(os.path.join(CONFIG_DIR, name)): file_state(os.path.join(CONFIG_DIR, name))
             for name in STATUS_DB_FILES}
    present = [s for s in files.values() if s not in ('missing', 'empty')]
    encrypted = BACKEND == 'sqlcipher' and bool(present) and all(s == 'encrypted' for s in present)
    if BACKEND != 'sqlcipher':
        note = ((sqlcipher_problem() or "Full DB encryption unavailable on this platform.")
                + " Sensitive fields are still encrypted individually with AES-256-GCM.")
    elif not present:
        note = "SQLCipher is available. No database found in this config directory."
    elif encrypted:
        note = "Full database encryption is active."
    else:
        note = ("SQLCipher is available, but a database is still plain. The next start "
                "encrypts it unless PEGAPROX_DISABLE_AUTO_ENCRYPT is set.")
    return {
        'backend': BACKEND,
        'encrypted_at_rest': encrypted,
        'cipher': 'AES-256-CBC + HMAC-SHA512 (SQLCipher 4)' if BACKEND == 'sqlcipher' else None,
        'files': files,
        'note': note,
        'sqlcipher_error': SQLCIPHER_ERROR,
    }


# ─── Connection ─────────────────────────────────────────────────────────────

def connect(db_path: str, *, timeout: float = 30.0, **kwargs):
    """Open a connection to the PegaProx DB.

    When the SQLCipher backend is active, this:
      1. Opens the underlying file
      2. Issues `PRAGMA key = "x'<hex>'"` with the master key from keystore
      3. Sets `PRAGMA cipher_compatibility = 4` for the latest format
      4. Verifies the key by running a sentinel query

    When the plain SQLite backend is active, the key step is a no-op. It is skipped as
    well for a plain file that stays plain (opens_plain).

    A database in WAL mode gets synchronous=NORMAL on the connection (wal_normal).

    All standard sqlite3 kwargs (check_same_thread, isolation_level, etc.)
    are forwarded.
    """
    conn = _sqlite_module.connect(db_path, timeout=timeout, **kwargs)
    if BACKEND == 'sqlcipher' and not opens_plain(db_path):
        try:
            _apply_sqlcipher_pragmas(conn, db_path)
        except BaseException:
            conn.close()
            raise
    wal_normal(conn)
    return conn


def auto_encrypt_disabled() -> bool:
    """PEGAPROX_DISABLE_AUTO_ENCRYPT is set: a plain database is not encrypted at the start
    and opens without the key, it stays plain SQLite."""
    return os.environ.get('PEGAPROX_DISABLE_AUTO_ENCRYPT', '').strip().lower() in ('1', 'true', 'yes')


# MK Nov 2026 - with sqlcipher3 every connection was keyed, and a keyed connection does not
# read a plain file ("file is not a database"). So PEGAPROX_DISABLE_AUTO_ENCRYPT left a plain
# database PegaProx could not open, and so did a start whose encryption failed (a full disk).
# A file opened without a key is plain SQLite to SQLCipher, so a plain database is opened that
# way where the opt-out is set or its encryption failed in this process. An encrypted file and
# a new one are keyed as before, so a new database is still created encrypted. Decided once
# per path, from the first 16 bytes of the file; later connections only look it up.
_OPENS_PLAIN: dict = {}         # the path as connect() got it -> True: no key
_CONVERSION_FAILED: set = set()  # absolute paths whose encryption failed in this process


def opens_plain(db_path) -> bool:
    """True when connect() opens `db_path` without the key: a plain file, with the opt-out
    set or after a failed encryption at this start."""
    try:
        return _OPENS_PLAIN[db_path]
    except KeyError:
        pass
    real = os.path.abspath(db_path)
    plain = ((real in _CONVERSION_FAILED or auto_encrypt_disabled())
             and file_state(real) == 'plain')
    _OPENS_PLAIN[db_path] = plain
    return plain


def _forget_open_modes() -> None:
    """After a database changed its state (encrypted, or left plain), decide afresh."""
    _OPENS_PLAIN.clear()


# MK Nov 2026 - SQLite's default synchronous=FULL syncs the WAL at every commit, 8 to 9 ms
# against 0.12 ms here, and a commit on the hub holds every greenlet for that long. In WAL
# mode NORMAL keeps the database consistent through a power cut and syncs at each
# checkpoint; what a power cut (not a crashed process) can take is the last commits before
# it. The setting is per connection, so every connection gets it here. Not in rollback-
# journal mode, where NORMAL is not safe against a power cut. A commit that something
# outside the database relies on is followed by sync_wal.
def wal_normal(conn) -> bool:
    """synchronous=NORMAL on `conn` when its database is in WAL mode. True when it set it;
    a connection it cannot ask keeps what SQLite gave it (FULL)."""
    try:
        mode = conn.execute('PRAGMA journal_mode').fetchone()[0]
        if str(mode).lower() != 'wal':
            return False
        conn.execute('PRAGMA synchronous = NORMAL')
        return True
    except Exception:
        return False


# MK Nov 2026 - on Windows os.fsync is FlushFileBuffers, which wants a handle that may write:
# on one opened read-only it fails with EBADF, so the plain copy before the encryption and a
# key a first start makes could not be synced there. Nor can a directory be opened to sync
# it (NTFS journals the name itself), so sync_file stops at the file there.
def _sync_flags() -> int:
    return os.O_RDWR if _WINDOWS else os.O_RDONLY


def sync_wal(db_path) -> bool:
    """fsync the WAL of `db_path`: for a commit made under NORMAL, what FULL does in the
    commit. Called after one that something outside the database relies on (a file
    written next, a peer or a SIEM target told, a key file already on disk), before that
    happens. The connections to a file share one WAL, so the commits of all of them up to
    now land. Without a WAL file nothing waits (the last connection checkpointed it into
    the database, with a sync), and it returns False. Raises OSError when the sync fails:
    what was to follow must not happen then."""
    try:
        # SQLite keeps the WAL beside the file a symlinked database points at
        fd = os.open(os.path.realpath(db_path) + '-wal', _sync_flags())
    except FileNotFoundError:
        return False
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def sync_file(path) -> None:
    """fsync the file `path` and the directory it is in, for a file just written that the
    database depends on (a key, the plain copy before the encryption): whole, and there by
    its name, after a power cut. Raises OSError when the file cannot be synced; a directory
    that cannot be is logged, some filesystems never sync one."""
    fd = os.open(path, _sync_flags())
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    if _WINDOWS:
        return
    parent = os.path.dirname(os.path.abspath(path))
    try:
        dfd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    except OSError as e:
        _LOG.warning("[DBCRYPTO] could not open %s to sync it: %s", parent, e)
        return
    try:
        os.fsync(dfd)
    except OSError as e:
        _LOG.warning("[DBCRYPTO] could not sync the directory %s: %s", parent, e)
    finally:
        os.close(dfd)


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
                f"Master key source: {mk.source}. {_unlock_hint(db_path)}"
            ) from e
    finally:
        cur.close()


def _unlock_hint(db_path) -> str:
    """What to do about a file a keyed connection did not open, by what the file is.

    It used to advise a re-encryption option of migrate-db that never existed, also where
    the file was simply still plain (a failed encryption, the opt-out)."""
    if file_state(db_path) == 'plain':
        return ("The file is still plain SQLite: the next start of PegaProx encrypts it "
                "(pegaprox_multi_cluster.py --migrate-db does it by hand, with PegaProx "
                "stopped), and PEGAPROX_DISABLE_AUTO_ENCRYPT=1 keeps it plain.")
    return ("This key does not open it, or the file is damaged. Put the key it was encrypted "
            "with in place (pegaprox_multi_cluster.py --keystore-status shows which key is "
            "used) or restore a backup together with its key.")


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
def _heavy_read_now(sql, params, transform=None):
    """The read of _heavy_read_offload, in the calling thread.

    sql may also be a list of (sql, params): MK Oct 2026 - they run in one read
    transaction, so every statement sees the same state of the database (a metrics
    snapshot row and its parts), and the rows come back as one list per statement."""
    from pegaprox.constants import DATABASE_FILE
    conn = connect(DATABASE_FILE, timeout=30, check_same_thread=False)
    try:
        conn.row_factory = Row
        cur = conn.cursor()
        if isinstance(sql, str):
            cur.execute(sql, params)
            rows = cur.fetchall()
        else:
            cur.execute('BEGIN')
            rows = []
            for one, args in sql:
                cur.execute(one, args or ())
                rows.append(cur.fetchall())
            conn.rollback()
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return transform(rows) if transform is not None else rows


# MK Oct 2026 - a history report or a heavy read makes tens to hundreds of MB that are
# freed again when it is done, but glibc keeps what is freed in the middle of its heaps:
# after a few history pages the process stayed hundreds of MB larger with nothing live in
# it. A job that ran this long hands it back when it is done. malloc_trim walks the heaps
# (a few to a hundred ms), in the worker thread and without the GIL (ctypes lets go of it).
_TRIM_AFTER = 0.25
_trim_fn = []


def trim_heap(took):
    """Hand the memory a finished job freed back to the system, where it ran `took`
    seconds or longer (a short one made little). True when it did."""
    if took < _TRIM_AFTER:
        return False
    if not _trim_fn:
        try:
            import ctypes
            fn = ctypes.CDLL(None).malloc_trim
            fn.argtypes, fn.restype = [ctypes.c_size_t], ctypes.c_int
        except Exception:
            fn = None       # not glibc (musl, macOS): nothing to hand back this way
        _trim_fn.append(fn)
    if _trim_fn[0] is None:
        return False
    try:
        _trim_fn[0](0)
    except Exception:
        return False
    return True


def _heavy_read_offload(sql: str, params: tuple, transform=None):
    """Run the query (and optionally a transform of the rows) on a fresh
    independent connection inside gevent's OS threadpool — or inline if no hub.

    `transform(rows)` runs INSIDE the worker thread too, so CPU-heavy
    post-processing (e.g. json.loads of thousands of rows) also stays off the
    hub instead of being done by the calling greenlet."""
    def _work():
        start = _time.monotonic()
        try:
            return _heavy_read_now(sql, params, transform)
        finally:
            trim_heap(_time.monotonic() - start)
    # MK Nov 2026 - only the hub lookup may fall back. The threadpool raises what the
    # read raised, and with the apply inside the except a failed read (a locked database,
    # a transform error) ran a second time, inline on the hub.
    try:
        from gevent import get_hub
        hub = get_hub()
    except Exception:
        # No active hub (synchronous CLI context) — run inline.
        return _work()
    return hub.threadpool.apply(_work)


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


def _ttl():
    # read at import like the key cap below: '60s' or 'off' must not keep PegaProx from
    # starting. nan and inf parse but are no time; the sweep never let go of an entry
    # stored with either
    try:
        ttl = float(os.environ.get('PEGAPROX_HEAVY_READ_TTL', '').strip() or 60)
    except ValueError:
        return 60.0
    return ttl if math.isfinite(ttl) else 60.0


_HEAVY_TTL = _ttl()
_HEAVY_CACHE: dict = {}      # cache_key -> (expiry_monotonic, rows)
_HEAVY_INFLIGHT: dict = {}   # cache_key -> AsyncResult
# MK Oct 2026 - an entry used to stay until the next read of its key replaced it, so a
# window nobody asked for again was held for good, and every `days` a caller ever passed
# kept one more. Expired entries go on every cached read (and after each metrics save),
# and past this many keys the ones that expire first make room.
def _max_keys():
    # read at import: a value that is no whole number must not keep PegaProx from starting
    try:
        return max(1, int(os.environ.get('PEGAPROX_HEAVY_READ_MAX_KEYS', '').strip() or 64))
    except ValueError:
        return 64


_HEAVY_MAX_KEYS = _max_keys()


def _heavy_cache_sweep(now=None):
    """Drop every cached heavy read whose time is up."""
    now = _time.monotonic() if now is None else now
    for key in [k for k, ent in list(_HEAVY_CACHE.items()) if ent[0] <= now]:
        _HEAVY_CACHE.pop(key, None)


def _heavy_cache_store(key, rows, ttl):
    # the TTL counts from now, when the value is there: a fetch of ten seconds got ten
    # seconds less of it when it counted from the start
    _HEAVY_CACHE[key] = (_time.monotonic() + ttl, rows)
    over = len(_HEAVY_CACHE) - max(1, _HEAVY_MAX_KEYS)
    if over > 0:
        older = sorted((k for k in _HEAVY_CACHE if k != key), key=lambda k: _HEAVY_CACHE[k][0])
        for k in older[:over]:
            _HEAVY_CACHE.pop(k, None)

def _heavy_concurrency():
    # a value that is no whole number keeps the default; it used to take the cap away
    try:
        return max(1, int(os.environ.get('PEGAPROX_HEAVY_READ_CONCURRENCY', '').strip() or 4))
    except ValueError:
        return 4


def _heavy_sem():
    # Lazily build a gevent BoundedSemaphore (needs the hub). Cap concurrent
    # distinct heavy queries; default 4. Falls back to None if gevent absent.
    global _HEAVY_SEM_OBJ
    try:
        return _HEAVY_SEM_OBJ
    except NameError:
        try:
            from gevent.lock import BoundedSemaphore
            _HEAVY_SEM_OBJ = BoundedSemaphore(_heavy_concurrency())
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
    sql may be a list of (sql, params) read in one transaction (_heavy_read_now).

    Falls back to a direct in-thread query when gevent isn't available.
    """
    if not cache_key:
        return _heavy_read_offload(sql, params, transform)

    now = _time.monotonic()
    _heavy_cache_sweep(now)
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
        _heavy_cache_store(cache_key, rows, ttl if ttl is not None else _HEAVY_TTL)
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
    # as in _heavy_read_offload: a failed transaction is not run again inline
    try:
        from gevent import get_hub
        hub = get_hub()
    except Exception:
        # No active hub (CLI / migration) — run inline.
        return _work()
    return hub.threadpool.apply(_work)


def run_off_hub(work, db_path, commit=False, durable=False):
    """work(conn) on a fresh connection to db_path inside gevent's threadpool, inline
    without a hub. MK Oct 2026 - for jobs that read and write in one transaction (the
    audit prune and the chain walk); commit=True commits what work did, an exception
    rolls it back. durable=True syncs the commit to disk before it returns (sync_wal),
    in the worker as well."""
    def _run():
        conn = connect(db_path, timeout=30, check_same_thread=False)
        try:
            conn.row_factory = Row
            out = work(conn)
            if commit:
                conn.commit()
                if durable:
                    sync_wal(db_path)
            return out
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass
    try:
        from gevent import get_hub
        hub = get_hub()
    except Exception:
        return _run()
    return hub.threadpool.apply(_run)


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


def plain_backup_retention() -> int:
    """Seconds a plain copy is kept: PEGAPROX_PLAIN_BACKUP_RETENTION_S, one hour by default."""
    try:
        return int(os.environ.get('PEGAPROX_PLAIN_BACKUP_RETENTION_S', '3600'))
    except ValueError:
        return 3600


def purge_stale_plain_backups(db_path: str, retention_s: int = None):
    """Securely remove plaintext migration backups (<db>.plain.bak.<ts>) once
    they're older than the retention window. H-5 (security audit): a plaintext
    copy of the SQLCipher DB is every stored cluster password in cleartext,
    sitting next to the keystore. The auto-migration keeps one for a short
    rollback window; this sweep (every startup) shreds anything past it. Default
    1h, PEGAPROX_PLAIN_BACKUP_RETENTION_S to override (0 = shred immediately).
    The age is that of the file's mtime, which make_plain_copy sets to the conversion."""
    import glob
    import time as _time
    if retention_s is None:
        retention_s = plain_backup_retention()
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


def plain_copy_note(backup_path: str) -> str:
    """What the log says about the plain copy a conversion keeps."""
    s = plain_backup_retention()
    if s <= 0:
        kept = 'is shredded at the next start of PegaProx'
    else:
        if s % 3600 == 0:
            span = 'about an hour' if s == 3600 else f'about {s // 3600} hours'
        elif s >= 60:
            span = f'about {round(s / 60)} minutes'
        else:
            span = f'{s} seconds'
        kept = f'is kept for {span}, then the first start of PegaProx after that shreds it'
    return (f"The plain copy {backup_path} {kept}. It holds every stored credential in the "
            f"clear: copy it somewhere safe if you want to keep it.")


def ensure_db_encrypted(db_path: str) -> dict:
    """Idempotent: encrypt the DB at `db_path` if it's still plain and the
    SQLCipher backend is available.  Called once per DB during app startup.

    Returns a dict with: action, state_before, state_after, [backup_path,
    duration_s, rows_copied].  Does NOT raise on routine cases; raises only
    for unrecoverable situations (corrupt DB, unknown-key encrypted DB, an
    encrypted DB without SQLCipher, a master key the key store refuses, a file
    this process cannot open at all: no permission, a full disk).

    A conversion that fails on its way (a full disk, any OS or SQLite error) changes
    nothing: the action is 'failed', the database stays plain and connect() opens it
    plain in this process, and the next start tries again.

    Opt-out: set PEGAPROX_DISABLE_AUTO_ENCRYPT=1 to keep a plain DB.
    """
    db_path = os.path.abspath(db_path)
    if db_path in _AUTO_MIG_DONE:
        return {'action': 'already-checked'}
    # MK Nov 2026 (#1226) - a database encrypted before (a config directory moved to arm64,
    # a pip install swapped for the deb) does not open on plain SQLite, opt-out or not.
    # Saying "stays plain" and failing at the first query with "file is not a database"
    # helps nobody, so the start refuses here with the reason.
    if BACKEND != 'sqlcipher' and file_state(db_path) == 'encrypted':
        raise RuntimeError(
            "[DBCRYPTO] " + (sqlcipher_problem(encrypted=db_path)
                             or f"{db_path} is encrypted and sqlcipher3 is not installed, so it does "
                                "not open. Install the SQLCipher package of requirements.txt "
                                "(python3-sqlcipher3 for the Debian package).")
            + " Refusing to start.")
    if auto_encrypt_disabled():
        return _keep_plain(db_path)
    if BACKEND != 'sqlcipher':
        # No sqlcipher3 → can't encrypt anyway. Field-level encryption still applies.
        _purge_plain_copies(db_path)
        _AUTO_MIG_DONE.add(db_path)
        return {'action': 'no-backend',
                'reason': 'sqlcipher3 does not load' if SQLCIPHER_ERROR else 'sqlcipher3 not installed'}

    with _AUTO_MIG_LOCK:
        if db_path in _AUTO_MIG_DONE:
            return {'action': 'already-checked'}
        # H-5: sweep stale plaintext backups every startup (before we possibly
        # create a fresh one below — a backup made by THIS boot's migration is
        # younger than the retention window, so it survives this boot for
        # rollback and gets shredded on a later start).
        _purge_plain_copies(db_path)
        state = _checked_state(db_path)

        if state in ('missing', 'encrypted'):
            # missing → SQLCipher creates an encrypted DB on first connect()
            # encrypted → already done, nothing to do
            _AUTO_MIG_DONE.add(db_path)
            return {'action': 'noop', 'state_before': state, 'state_after': state}

        # state == 'plain' → run the migration inline
        # the key on its own first: one the key store refuses (loose permissions,
        # unreadable) stops the start with that reason, as before. What fails after this is
        # the conversion's, and leaves the database as it was.
        _usable_key()
        _LOG.warning("[DBCRYPTO] plain DB detected at %s — auto-encrypting before "
                     "first connection. This is a one-time operation.", db_path)
        try:
            result = _run_inline_migration(db_path)
        except Exception as e:
            result = _conversion_failed(db_path, e)
        _AUTO_MIG_DONE.add(db_path)
        _forget_open_modes()
        return result


def _keep_plain(db_path: str) -> dict:
    """ensure_db_encrypted with PEGAPROX_DISABLE_AUTO_ENCRYPT set: only the conversion is
    skipped. A plain database stays plain and connect() opens it without the key; an
    encrypted one is checked as without the opt-out and opens with the key."""
    with _AUTO_MIG_LOCK:
        if db_path in _AUTO_MIG_DONE:
            return {'action': 'already-checked'}
        # a copy from a conversion before the opt-out was set goes after its window as well,
        # the log line of that conversion said so
        _purge_plain_copies(db_path)
        state = file_state(db_path)
        if BACKEND == 'sqlcipher' and state not in ('missing', 'empty', 'plain'):
            _checked_state(db_path)
        if state == 'plain':
            _LOG.info("[DBCRYPTO] PEGAPROX_DISABLE_AUTO_ENCRYPT is set: %s stays plain SQLite and "
                      "opens without the key. Field-level encryption (AES-256-GCM) still applies.",
                      db_path)
        else:
            _LOG.info("[DBCRYPTO] PEGAPROX_DISABLE_AUTO_ENCRYPT is set: nothing to encrypt in %s (%s)",
                      db_path, state)
        _AUTO_MIG_DONE.add(db_path)
        _forget_open_modes()
        return {'action': 'opt-out'}


def _purge_plain_copies(db_path: str) -> None:
    """purge_stale_plain_backups at a start; a sweep that fails does not stop the start."""
    try:
        purge_stale_plain_backups(db_path)
    except Exception as e:
        _LOG.debug("[DBCRYPTO] plain-backup purge soft-fail: %s", e)


def _usable_key():
    """The master key, or a RuntimeError that says why it cannot be used: the key store's
    own (loose permissions, not 32 bytes) or one for a key file it could not read or write."""
    from pegaprox.core.keystore import load_master_key
    try:
        return load_master_key()
    except OSError as e:
        raise RuntimeError(f"[KEYSTORE] the master key cannot be loaded: {e}.") from e


def _checked_state(db_path: str) -> str:
    """detect_db_state, raising the RuntimeError that refuses the start where the database
    is encrypted and this start cannot open it, or is no database at all."""
    try:
        state = detect_db_state(db_path)
    except FileUnusable as e:
        raise RuntimeError(f"[DBCRYPTO] {e} Refusing to start.") from e
    except RuntimeError as e:
        # a key file with loose permissions read as "the current master key does not
        # unlock it", and admins went looking for another key
        raise RuntimeError(f"[DBCRYPTO] {db_path} is encrypted, and its master key cannot be "
                           f"used: {e} Refusing to start.") from e
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
            f"encrypted DB - refusing to start. Restore from backup."
        )
    return state


class _ConversionFailed(Exception):
    """A conversion that stopped before the swap. `cause` is what stopped it, `stuck` what
    it made and could not remove again."""

    def __init__(self, cause: BaseException, stuck):
        super().__init__(str(cause))
        self.cause = cause
        self.stuck = list(stuck)


# MK Nov 2026 - a conversion that failed (a full disk, Windows without fcntl) was only logged
# as "auto-encrypt check failed", and then every connection keyed the plain file: nobody could
# sign in, the log advised a migrate-db option that does not exist, and each restart systemd
# made left one more plain copy. The database is intact at that point, so this start runs on
# it plain, as with the opt-out, says once why, and the next start tries again.
def _conversion_failed(db_path: str, exc: Exception) -> dict:
    cause = exc.cause if isinstance(exc, _ConversionFailed) else exc
    stuck = exc.stuck if isinstance(exc, _ConversionFailed) else []
    _CONVERSION_FAILED.add(db_path)
    _forget_open_modes()
    if _disk_full(cause, db_path):
        why = _space_words(db_path)
        then = "Free up that much there and restart PegaProx, the next start tries again."
    elif isinstance(cause, InUse):
        why = str(cause)
        then = "The next start tries again."
    else:
        why = f"{type(cause).__name__}: {' '.join(str(cause).split())}"
        then = "The next start tries again."
    msg = (f"could not encrypt {db_path} ({why}). Nothing was changed: it is still plain "
           f"SQLite and PegaProx runs on it, sensitive fields stay encrypted with AES-256-GCM. "
           f"{then} Until then pegaprox_multi_cluster.py --keystore-status lists it as plain.")
    if stuck:
        msg += (f" The failed attempt could not remove {', '.join(stuck)}: delete "
                f"{'it' if len(stuck) == 1 else 'them'} by hand.")
    _LOG.error("[DBCRYPTO] %s", msg)
    return {'action': 'failed', 'state_before': 'plain', 'state_after': 'plain', 'error': msg}


def _disk_full(e: BaseException, db_path: Optional[str] = None) -> bool:
    """`e` is what a full disk raised. With db_path, a plain SQLite "disk I/O error" counts
    too where the directory has less free than the conversion of db_path needs: SQLite
    reports some writes a full disk refused that way (a -shm it cannot grow, a page)."""
    full = {errno.ENOSPC}
    if hasattr(errno, 'EDQUOT'):
        full.add(errno.EDQUOT)
    if isinstance(e, OSError) and e.errno in full:
        return True
    # SQLITE_FULL, what sqlcipher_export and the row counts raise on a full disk
    if 'database or disk is full' in str(e):
        return True
    if db_path and 'disk I/O error' in str(e):
        free = _free_bytes(os.path.dirname(db_path))
        return free is not None and free < _space_needed(db_path)
    return False


def _free_bytes(where: str) -> Optional[int]:
    import shutil
    try:
        return shutil.disk_usage(where).free
    except OSError:
        return None


# the journal of the encrypted copy, a -shm and a few pages: what a small database needs on
# top of its two copies
_SPACE_MARGIN = 64 * 1024


def _space_needed(db_path: str) -> int:
    """Bytes the conversion of db_path writes: a plain copy and an encrypted one, which is a
    little larger (SQLCipher keeps 80 bytes of each 4 KB page for its IV and HMAC)."""
    size = 0
    for p in (db_path, db_path + '-wal'):
        try:
            size += os.path.getsize(p)
        except OSError:
            pass
    return 2 * size + size // 32 + _SPACE_MARGIN


def _space_words(db_path: str) -> str:
    """For the message of a full disk: how much the conversion of db_path needs, a plain
    copy plus an encrypted copy, and how much is free now. The free space is left out where
    it is not below that: it would contradict the reason (another writer filled the disk
    for a while, or a quota did)."""
    where = os.path.dirname(db_path)
    need = _space_needed(db_path)
    words = (f"not enough free space in {where}: the encryption writes a plain copy and an "
             f"encrypted copy of the database, so it needs about {_size_words(need)} free")
    free = _free_bytes(where)
    if free is not None and free < need:
        words += f", {_size_words(free)} are free now"
    return words


def _size_words(n: int) -> str:
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.1f} GB"
    # a decimal below 10 MB: "needs about 2 MB free, 2 MB are free now" was 2.3 against 1.9
    if n >= 10 * 1024 ** 2:
        return f"{n / 1024 ** 2:.0f} MB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    if n < 1024:
        return f"{n} bytes"
    return f"{round(n / 1024)} KB"


@contextlib.contextmanager
def _migration_lock(lock_path: str, db_path: str, wait: bool = True):
    """The cross-process lock of one database's conversion, held for the with block. Yields
    True when another process held it first: that one may have done the work by now. With
    wait=False it raises BlockingIOError instead of waiting for that process.

    MK Nov 2026 - this imported fcntl, which Windows does not have. Since 1.5.0 sqlcipher3
    is installed there too, so every Windows start with a plain database failed here. Windows
    locks the first byte of the lock file with msvcrt instead."""
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        try:
            import fcntl
        except ImportError:
            fcntl = None
        if fcntl is not None:
            waited = False
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if not wait:
                    raise
                _LOG.info("[DBCRYPTO] another process is encrypting %s, waiting for it", db_path)
                waited = True
                fcntl.flock(fd, fcntl.LOCK_EX)

            def unlock():
                fcntl.flock(fd, fcntl.LOCK_UN)
        else:
            import msvcrt
            waited = _lock_first_byte(msvcrt, fd, db_path, wait)

            def unlock():
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        try:
            yield waited
        finally:
            # closing the file lets go of the lock as well, on both
            with contextlib.suppress(OSError):
                unlock()
    finally:
        os.close(fd)


def _lock_first_byte(msvcrt, fd: int, db_path: str, wait: bool = True) -> bool:
    """Lock byte 0 of `fd` with msvcrt, waiting as long as another process holds it. True
    when it had to wait. With wait=False a held lock raises BlockingIOError."""
    busy = {errno.EACCES, getattr(errno, 'EDEADLOCK', errno.EDEADLK)}
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return False
    except OSError as e:
        if e.errno not in busy:
            raise
        if not wait:
            raise BlockingIOError(errno.EAGAIN, f'{db_path} is being converted by another process') from e
    _LOG.info("[DBCRYPTO] another process is encrypting %s, waiting for it", db_path)
    while True:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            # LK_LOCK gives up after ten tries a second apart, a big database takes longer
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            return True
        except OSError as e:
            if e.errno not in busy:
                raise


def make_plain_copy(db_path: str, backup_path: str) -> str:
    """The plain copy a conversion keeps: owner-only from its first byte, dated now, and on
    disk before the swap takes the plain file away (sync_file). A copy cut short is removed
    before the error goes on. Returns the path of the copy: backup_path, or backup_path.1,
    .2 and so on where a file of that name is there already.

    MK Nov 2026 - it was made with copy2, which keeps the mtime of the database, and
    purge_stale_plain_backups counts the hour from the mtime. A database last written more
    than an hour before the update (stopped for the backup the upgrade guide asks for) lost
    its copy at the next start, seconds after the conversion. The name only changes once a
    second, so a copy left from the same second (a start killed half way and started again
    at once) made the new one fail on O_EXCL; it takes the next free name now."""
    import shutil
    path = backup_path
    for n in range(1, 100):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0), 0o600)
            break
        except FileExistsError:
            path = f"{backup_path}.{n}"
    else:
        raise FileExistsError(errno.EEXIST, 'no free name for the plain copy', backup_path)
    os.close(fd)
    try:
        os.chmod(path, 0o600)
        shutil.copyfile(db_path, path)
        os.utime(path, None)
        sync_file(path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(path)
        raise
    return path


class InUse(RuntimeError):
    """The plain database is not this conversion's alone: another process has it open, or
    wrote to it while it was converted. Nothing was changed."""


def _file_mark(path: str):
    """What tells whether a database file was written: its inode, size and mtime, and the
    header, whose change counter every commit in rollback-journal mode moves on."""
    st = os.stat(path)
    with open(path, 'rb') as fh:
        head = fh.read(100)
    return st.st_ino, st.st_size, st.st_mtime_ns, head


# MK Nov 2026 - the conversion took the plain file as it found it. Another process with it
# open (a sqlite3 shell, a backup job, a PegaProx still running beside --migrate-db) kept
# commits in its -wal the copy did not get, and the swap put the encrypted file next to that
# plain -wal and -shm: the first connection after it wrote plain pages into the encrypted
# file, "database disk image is malformed" at every start from then on. Leaving WAL mode
# needs the database to itself, folds the -wal into the file and removes it and the -shm;
# with anybody else on it SQLite says "database is locked" at once. db.py puts the database
# back into WAL mode at its first connection, encrypted or, after a failure, plain.
def plain_alone(db_path: str):
    """Make sure nothing else has the plain database open and that all of it is in the one
    file, before the conversion copies it. Returns its _file_mark for check_before_swap.
    Raises InUse when another process has it open, or its -wal or -shm cannot be written;
    other errors (a full disk) go on as they are."""
    import sqlite3
    try:
        conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
        try:
            mode = str(conn.execute('PRAGMA journal_mode = DELETE').fetchone()[0]).lower()
        finally:
            conn.close()
    except sqlite3.OperationalError as e:
        text = ' '.join(str(e).split())
        if 'locked' in text or 'busy' in text:
            raise InUse(f"another process has {db_path} open (a PegaProx still running, a sqlite3 "
                        f"shell, a backup job) and the conversion needs it to itself: {text}") from e
        if 'readonly' in text:
            raise InUse(f"{db_path} or its -wal or -shm file cannot be written by this user, and "
                        f"the conversion has to fold the -wal into the database first: {text}") from e
        raise
    left = [p for p in _sqlite_files(db_path)[1:] if os.path.exists(p)]
    if mode != 'delete' or left:
        raise InUse(f"{db_path} could not be taken out of {mode} journal mode"
                    + (f", {', '.join(left)} stayed" if left else '')
                    + ": another process may have it open")
    return _file_mark(db_path)


def check_before_swap(db_path: str, mark) -> None:
    """Right before the encrypted file takes the place of the plain one: nothing opened the
    plain one for writing since plain_alone. A -wal, -shm or -journal left beside it would
    be read into the encrypted file, and a commit made meanwhile is not in it. Raises InUse."""
    left = [p for p in _sqlite_files(db_path)[1:] if os.path.exists(p)]
    if left:
        raise InUse(f"{', '.join(left)} turned up while {db_path} was converted: another "
                    f"process opened it")
    if _file_mark(db_path) != mark:
        raise InUse(f"another process wrote to {db_path} while it was converted")


def _sqlite_files(path: str) -> list:
    """`path` and the files SQLite keeps beside it."""
    return [path, path + '-journal', path + '-wal', path + '-shm']


def _remove_files(paths) -> list:
    """Remove each of `paths` that is there; returns those that stayed."""
    stuck = []
    for p in paths:
        if not p:
            continue
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
        except OSError:
            stuck.append(p)
    return stuck


def _run_inline_migration(db_path: str) -> dict:
    """Inline plain→encrypted migration. Mirrors `cli.migrate_db` but with
    no prompts, no argparse, and a per-DB on-disk lock file so two parallel
    starts (e.g. systemd restart-storm) don't fight each other.

    An attempt that stops before the swap removes what it made (the encrypted candidate,
    the plain copy) and raises _ConversionFailed; the database is then as it was."""
    import time

    lock_path = f"{db_path}.migration.lock"
    new_path = f"{db_path}.encrypted.new"

    # Cross-process lock so a concurrent boot can't double-migrate.
    # Held until this function returns.
    with _migration_lock(lock_path, db_path) as waited:
        if waited:
            # By the time we get the lock, the other process should have
            # already swapped in the encrypted DB. Re-check state.
            if detect_db_state(db_path) == 'encrypted':
                return {'action': 'waited-for-peer', 'state_after': 'encrypted'}
            # Otherwise fall through and try again.
        backup_path = None
        try:
            # Lazy imports to keep this module light
            from pegaprox.core.keystore import load_master_key
            # the CLI's helpers, underscored but stable within the package
            from pegaprox.cli.migrate_db import (
                _encrypt_via_sqlcipher_export,
                _verify_row_counts,
            )

            mk = load_master_key()
            t0 = time.time()
            mark = plain_alone(db_path)

            # 1. backup, on disk before the swap takes the plain file away: it is the
            # one copy that opens without the key
            backup_path = make_plain_copy(db_path, f"{db_path}.plain.bak.{int(t0)}")
            _LOG.info("[DBCRYPTO] backup → %s", backup_path)

            # 2. encrypt
            rows = _encrypt_via_sqlcipher_export(db_path, new_path, mk.key_raw)
            _LOG.info("[DBCRYPTO] sqlcipher_export OK (%d rows)", rows)

            # 3. verify
            _verify_row_counts(db_path, new_path)
            _LOG.info("[DBCRYPTO] row-count verification OK")

            # 4. atomic swap
            check_before_swap(db_path, mark)
            os.replace(new_path, db_path)
        except BaseException as e:
            stuck = _remove_files([backup_path] + _sqlite_files(new_path))
            if isinstance(e, Exception):
                raise _ConversionFailed(e, stuck) from e
            raise
    # swapped: the database is encrypted from here on, whatever follows
    try:
        os.chmod(db_path, 0o600)
    except OSError as e:
        _LOG.warning("[DBCRYPTO] could not make %s owner-only: %s", db_path, e)
    _remove_files(_sqlite_files(new_path))
    dt = time.time() - t0
    _LOG.warning("[DBCRYPTO] auto-encrypt complete: %s (%.1fs, %d rows). %s",
                 db_path, dt, rows, plain_copy_note(backup_path))
    return {
        'action': 'migrated',
        'state_before': 'plain',
        'state_after': 'encrypted',
        'backup_path': backup_path,
        'duration_s': round(dt, 2),
        'rows_copied': rows,
    }


# ─── Plain-vs-Encrypted detection on an existing file ──────────────────────

class FileUnusable(RuntimeError):
    """detect_db_state: a database file this process cannot open, for a reason that is
    neither the key nor damage (no permission, a full disk). The message names the file and
    the cause, and never advises a restore."""


# below this much free space an I/O error on opening is taken for a full disk: the -shm
# alone needs 32 KB
_OPEN_ROOM = 1024 * 1024


def _cannot_open_words(db_path: str, e: BaseException) -> str:
    where = os.path.dirname(os.path.abspath(db_path))
    cause = f"{type(e).__name__}: {' '.join(str(e).split())}"
    free = _free_bytes(where)
    if _disk_full(e) or ('disk I/O error' in str(e) and free is not None and free < _OPEN_ROOM):
        left = f"{_size_words(free)} free" if free is not None else 'no space left'
        return (f"{db_path} is plain SQLite, and it cannot be opened because {where} is full "
                f"({left}; {cause}). Free up space there.")
    if 'locked' in str(e):
        return (f"{db_path} is plain SQLite, and another process holds a lock on it ({cause}). "
                f"Stop that process.")
    return (f"{db_path} is plain SQLite, and SQLite cannot open it here ({cause}). The user "
            f"PegaProx runs as needs read and write access to it, to its -wal and -shm files and "
            f"to {where}" + (f", where {_size_words(free)} are free." if free is not None else "."))


def detect_db_state(db_path: str) -> str:
    """Probe a DB file to detect whether it's:
      - 'missing'      — file doesn't exist
      - 'plain'        — readable as plain SQLite
      - 'encrypted'    — refuses to open without a key (SQLCipher)
      - 'corrupt'      — neither plain SQLite nor a valid encrypted DB
      - 'unknown-key'  — encrypted but our current key doesn't unlock it

    Used by the auto-migration trigger on startup and the CLI tool. Raises RuntimeError
    with the key store's reason when a file that is not plain meets a master key that
    cannot be used (loose permissions, unreadable, not 32 bytes), and FileUnusable for a
    file this process cannot read, or a plain one SQLite cannot open here.
    """
    if not os.path.exists(db_path):
        return 'missing'
    try:
        with open(db_path, 'rb') as fh:
            head = 'plain' if fh.read(16) == _SQLITE_MAGIC else 'other'
    except OSError as e:
        # was 'neither plain SQLite nor a valid encrypted DB ... Restore from backup'
        raise FileUnusable(
            f"{db_path} cannot be read by this process ({type(e).__name__}: {e.strerror or e}). "
            f"The user PegaProx runs as needs read and write access to it, to its -wal and -shm "
            f"files and to {os.path.dirname(os.path.abspath(db_path))}.") from e

    # First try plain sqlite3 — cheapest test
    import sqlite3 as _plain
    plain_error = None
    try:
        c = _plain.connect(db_path)
        try:
            c.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return 'plain'
        except Exception as e:
            plain_error = e
        finally:
            c.close()
    except Exception as e:
        plain_error = e
    # MK Nov 2026 - a plain file SQLite could not open went on to the key, and the start
    # refused with "is encrypted but the current master key does not unlock it ... restore a
    # matching backup": on a full disk (no room for the -shm), and where the -wal or -shm
    # cannot be written. An OperationalError on a plain header is the place, not the file.
    # Damage (not a database, malformed) is a DatabaseError, and a damaged plain file is
    # 'corrupt': the keyed probe took it for 'unknown-key' as well.
    if head == 'plain':
        if isinstance(plain_error, _plain.OperationalError):
            raise FileUnusable(_cannot_open_words(db_path, plain_error))
        return 'corrupt'

    # Try SQLCipher if available
    if BACKEND != 'sqlcipher':
        return 'corrupt'  # encrypted-looking but we can't decrypt anyway

    # the key on its own first: the key store refuses a key file with loose permissions
    # with a RuntimeError, the same type as a key that does not unlock, and that was taken
    # for 'unknown-key'. It goes to the caller with its own reason now.
    _usable_key()
    try:
        c = connect(db_path)
        c.execute("SELECT count(*) FROM sqlite_master").fetchone()
        c.close()
        return 'encrypted'
    except RuntimeError:
        return 'unknown-key'
    except Exception:
        return 'corrupt'
