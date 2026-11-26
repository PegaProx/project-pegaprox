"""
Plain-SQLite → SQLCipher migration tool.

Usage (called via `pegaprox_multi_cluster.py --migrate-db`):
  1. Locate the live DB at CONFIG_DIR/pegaprox.db
  2. Detect its state (plain / encrypted / corrupt / missing)
  3. If plain:
       a. Hard-copy to pegaprox.db.plain.bak.<timestamp>, dated now
       b. Open the plain DB, sqlcipher_export into a new encrypted file
       c. Verify row counts match exactly per table
       d. Atomic rename: pegaprox.db.encrypted.new → pegaprox.db
       e. Keep the .plain.bak for the retention window (one hour by default,
          PEGAPROX_PLAIN_BACKUP_RETENTION_S); the first start of PegaProx after
          it shreds the copy

Safety properties:
  - PegaProx must be stopped. The tool refuses (exit code 7) while a PegaProx
    holds the lock of the config directory, or while any other process has
    the database open.
  - The plain copy holds every stored credential in the clear, so it is not
    kept for long (dbcrypto.purge_stale_plain_backups). The output says so,
    and to copy it somewhere safe to keep it.
  - Atomic rename means a crash mid-migration leaves you with EITHER the
    original plain DB OR the verified encrypted DB.  Never a corrupted mix.
  - Row-count verification per table catches any silent data loss.

MK May 2026 — automatable Stufe-3 migration.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List


# MK May 2026 — SQLite has no parameter placeholder for identifiers (table/column
# names), so they must be embedded into the query text. To stay safe we whitelist
# the SQL identifier syntax + apply standard double-quote escaping. A table name
# that doesn't match this pattern is dropped from the row-count sweep (with a
# warning) instead of being injected verbatim. Aikido SAST flagged the old f-
# string form as critical SQL-injection even though the source is sqlite_master
# (not HTTP input) — this hardening makes the trace clean.
_SAFE_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _safe_quote_ident(name: str) -> str | None:
    """Return a double-quoted SQL identifier if `name` matches the standard
    identifier syntax, else None. SQLite tolerates almost anything inside
    double quotes (only `"` needs escaping as `""`), but we additionally
    reject identifiers with non-ASCII / control / punctuation chars to
    keep the trace boring."""
    if not isinstance(name, str) or not _SAFE_IDENT_RE.match(name):
        return None
    return '"' + name.replace('"', '""') + '"'


_LOG = logging.getLogger(__name__)


def main(argv: List[str]) -> int:
    """Entry point.  Returns process exit code."""
    import argparse
    # the name it is called by; the usage line showed one that does not exist
    p = argparse.ArgumentParser(prog='pegaprox_multi_cluster.py --migrate-db',
                                description='Migrate the PegaProx DB to SQLCipher encryption.')
    p.add_argument('--db', help='Path to pegaprox.db (default: from constants)')
    p.add_argument('--dry-run', action='store_true', help='Detect + print plan, do not modify')
    p.add_argument('--yes', action='store_true', help='Skip the confirmation prompt')
    p.add_argument('--force', action='store_true',
                   help='Migrate even if the DB looks encrypted already (rare)')
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')

    from pegaprox.constants import CONFIG_DIR
    db_path = args.db or os.path.join(CONFIG_DIR, 'pegaprox.db')

    print(f"── PegaProx DB migration ──")
    print(f"target: {db_path}")

    # Detect backend availability
    from pegaprox.core import dbcrypto
    if dbcrypto.BACKEND != 'sqlcipher':
        print(f"\n[BLOCKED] sqlcipher3 not importable on this platform.")
        if dbcrypto.SQLCIPHER_ERROR:
            print(f"          {dbcrypto.sqlcipher_problem()}")
        print(f"          DB encryption cannot be enabled.  Install:")
        print(f"            pip install 'sqlcipher3-binary>=0.6.0'   (Linux x86_64)")
        print(f"            pip install 'sqlcipher3>=0.6.4'          (aarch64, macOS, Windows)")
        print(f"          never both: they install the same module.")
        return 2

    # MK Nov 2026 - this ran next to a running PegaProx as well. With the opt-out, or after
    # a conversion that failed, PegaProx runs on the plain file, and a swap under it left
    # its plain -wal beside the encrypted file (malformed from then on), lost what it wrote
    # after the copy, and its new connections failed until a restart. It holds a lock on its
    # config directory (ha.lock_config_dir); this run takes that lock too, or refuses.
    try:
        held = _hold_config_dir(os.path.dirname(os.path.abspath(db_path)))
    except RuntimeError as e:
        print(f"\n[BLOCKED] {e}. Nothing was changed.")
        print(f"          {_stop_first()}")
        return 7
    try:
        return _migrate(args, db_path, dbcrypto)
    finally:
        if held is not None:
            _let_go(held)


STOP_FIRST = "Stop PegaProx first (sudo systemctl stop pegaprox), then run this again."
# MK Nov 2026 - there is no systemctl on Windows
STOP_FIRST_WINDOWS = "Stop PegaProx first (its service, or the PegaProx process), then run this again."
_WINDOWS = os.name == 'nt'
# the lock file a running PegaProx holds in its config directory, ha.LOCK_FILE
_RUNNING_LOCK = '.pegaprox.lock'
# the byte of it a running PegaProx locks on Windows, ha.CONFIG_LOCK_BYTE
_RUNNING_LOCK_BYTE = 1 << 30


def _stop_first() -> str:
    return STOP_FIRST_WINDOWS if _WINDOWS else STOP_FIRST


def _hold_config_dir(folder: str):
    """Take the lock a running PegaProx holds on `folder` for the rest of this run, so none
    starts on it meanwhile either. Returns the descriptor, or None where there is no such
    lock to take (no lock file yet, a filesystem without locks, neither fcntl nor msvcrt).
    Raises RuntimeError naming the process that holds it."""
    try:
        import fcntl
    except ImportError:
        return _hold_config_dir_msvcrt(folder)
    try:
        # never created here: run as root it would be a file the service cannot open
        fd = os.open(os.path.join(folder, _RUNNING_LOCK), os.O_RDWR)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        try:
            holder = os.pread(fd, 16, 0).decode(errors='replace').strip()
        except OSError:
            holder = ''
        os.close(fd)
        who = f" (process {holder})" if holder.isdigit() else ''
        raise RuntimeError(f"PegaProx{who} is running on {folder}")
    except OSError:
        os.close(fd)
        return None
    try:
        # as ha.lock_config_dir does: a PegaProx started meanwhile names this process
        os.ftruncate(fd, 0)
        os.pwrite(fd, f'{os.getpid()}\n'.encode(), 0)
    except OSError:
        pass
    return fd


# MK Nov 2026 - on Windows this returned None at once, and the conversion ran under a live
# PegaProx. There ha.lock_config_dir locks one byte of the file with msvcrt, past its end
# so backup tools can still read it, and this locks the same one. The pid is at the start.
def _hold_config_dir_msvcrt(folder: str):
    try:
        import msvcrt
    except ImportError:
        return None
    try:
        fd = os.open(os.path.join(folder, _RUNNING_LOCK), os.O_RDWR | getattr(os, 'O_BINARY', 0))
    except OSError:
        return None
    from pegaprox.core import dbcrypto
    try:
        dbcrypto._lock_first_byte(msvcrt, fd, folder, wait=False, at=_RUNNING_LOCK_BYTE)
    except BlockingIOError:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            holder = os.read(fd, 16).decode(errors='replace').strip()
        except OSError:
            holder = ''
        os.close(fd)
        who = f" (process {holder})" if holder.isdigit() else ''
        raise RuntimeError(f"PegaProx{who} is running on {folder}")
    except OSError:
        os.close(fd)
        return None
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f'{os.getpid()}\n'.encode())
    except OSError:
        pass
    return fd


def _let_go(fd: int) -> None:
    """Closes what _hold_config_dir returned. A closed handle lets go of an msvcrt lock only
    when Windows gets round to it, so that one is undone first, as dbcrypto does."""
    try:
        import fcntl  # noqa: F401
    except ImportError:
        with contextlib.suppress(ImportError, OSError):
            import msvcrt
            os.lseek(fd, _RUNNING_LOCK_BYTE, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    os.close(fd)


def _migrate(args, db_path: str, dbcrypto) -> int:
    """main() from the state of the database on, with the config directory held."""
    try:
        state = dbcrypto.detect_db_state(db_path)
    except dbcrypto.FileUnusable as e:
        # a plain file that does not open here (no permission, a full disk) read as
        # "neither plain SQLite nor a valid encrypted DB, restore from backup"
        print(f"\n[BLOCKED] {e}")
        print(f"          Nothing was changed.")
        return 7
    except RuntimeError as e:
        # a key file the key store refuses (loose permissions) said "doesn't unlock it"
        # here, as at the start
        print(f"\n[BLOCKED] {db_path} is encrypted, and the master key cannot be used:")
        print(f"          {e}")
        return 6
    print(f"state:  {state}")

    if state == 'missing':
        print("\nDB doesn't exist yet — it will be created encrypted on first start.")
        return 0
    if state == 'encrypted':
        if not args.force:
            print("\nDB is already encrypted.  Nothing to do.")
            return 0
    if state == 'unknown-key':
        print(f"\n[BLOCKED] DB looks encrypted but our master key doesn't unlock it.")
        print(f"          This is dangerous — back up the file before doing anything.")
        print(f"          Common cause: master key rotated without re-encrypting the DB.")
        return 3
    if state == 'corrupt':
        print(f"\n[BLOCKED] DB file is neither plain SQLite nor a valid encrypted DB.")
        print(f"          Restore from backup before migration.")
        return 4
    # state == 'plain' — the happy path

    # Resolve master key + show source so the operator knows what's going on
    from pegaprox.core.keystore import load_master_key
    mk = load_master_key()
    print(f"master key source: {mk.source}{' (' + mk.source_path + ')' if mk.source_path else ''}")
    if mk.is_legacy:
        print("\n[WARN]  Master key is in the legacy CONFIG_DIR location.")
        print("        Consider moving it to /etc/pegaprox/secret.key first (mode 0640,")
        print("        owner root, group of the service user), outside the DB directory;")
        print("        --keystore-status names the steps.")
        print()

    # Plan summary
    plain_size = os.path.getsize(db_path)
    backup_path = f"{db_path}.plain.bak.{int(time.time())}"
    new_path = f"{db_path}.encrypted.new"
    print(f"\nplan:")
    print(f"  1. Backup plain DB         → {backup_path} ({plain_size//1024} KB)")
    print(f"  2. Encrypt to new file     → {new_path}")
    print(f"  3. Verify table row counts match")
    print(f"  4. Atomic rename           → {db_path}")
    print(f"  5. Keep the plain copy; PegaProx shreds it at its first start after the "
          f"retention window")

    if args.dry_run:
        print("\n[dry-run] no changes applied.")
        return 0

    if not args.yes:
        print()
        resp = input("Proceed? [y/N] ").strip().lower()
        if resp != 'y':
            print("Cancelled.")
            return 0

    # the lock of the conversion at a start as well: a PegaProx that starts now without the
    # directory lock (it could not open or lock the file) waits for this run and then finds
    # the database encrypted
    stack = contextlib.ExitStack()
    try:
        stack.enter_context(dbcrypto._migration_lock(f"{db_path}.migration.lock", db_path, wait=False))
    except BlockingIOError:
        print(f"\n[BLOCKED] a PegaProx start is encrypting {db_path} right now. Nothing was changed.")
        return 7
    with stack:
        try:
            # every other connection gone and the -wal folded in, or nothing is touched
            mark = dbcrypto.plain_alone(db_path)
        except dbcrypto.InUse as e:
            print(f"\n[BLOCKED] {e}. Nothing was changed.")
            print(f"          {_stop_first()}")
            return 7
        return _convert(db_path, backup_path, new_path, mk, mark, dbcrypto)


def _convert(db_path: str, backup_path: str, new_path: str, mk, mark, dbcrypto) -> int:
    """Steps 1 to 4 of main(), on a plain database nothing else has open."""
    # Step 1: backup
    print(f"\nStep 1/4 backup ... ", end='', flush=True)
    # MK Nov 2026 - copy2 kept the database's old mtime, and the next start shredded the
    # copy at once wherever the database was last written more than an hour before
    backup_path = dbcrypto.make_plain_copy(db_path, backup_path)
    print(f"OK ({os.path.getsize(backup_path)//1024} KB written)")

    # Step 2: export to encrypted
    print(f"Step 2/4 encrypt ... ", end='', flush=True)
    t0 = time.time()
    rows_plain = _encrypt_via_sqlcipher_export(db_path, new_path, mk.key_raw)
    dt = time.time() - t0
    print(f"OK ({dt:.1f}s, {rows_plain} rows across all tables)")

    # Step 3: verify
    print(f"Step 3/4 verify  ... ", end='', flush=True)
    try:
        _verify_row_counts(db_path, new_path)
    except Exception as e:
        print(f"FAIL\n   {e}")
        print(f"\n[ABORT] Verification failed. Original DB at {db_path} is untouched.")
        print(f"        Inspect the encrypted candidate at {new_path} before deleting.")
        return 5
    print("OK (per-table counts match)")

    # Step 4: atomic swap
    print(f"Step 4/4 swap    ... ", end='', flush=True)
    try:
        dbcrypto.check_before_swap(db_path, mark)
    except dbcrypto.InUse as e:
        print(f"FAIL\n   {e}")
        stuck = dbcrypto._remove_files([backup_path] + dbcrypto._sqlite_files(new_path))
        print(f"\n[ABORT] {db_path} is untouched, and the encrypted candidate and the plain copy "
              f"are removed{' except ' + ', '.join(stuck) if stuck else ''}.")
        print(f"        {_stop_first()}")
        return 7
    os.replace(new_path, db_path)
    os.chmod(db_path, 0o600)
    print("OK")

    print(f"\n✓ Migration complete.")
    print(f"  Encrypted DB:    {db_path}")
    print(f"  Plain backup:    {backup_path}")
    print(f"  Backend:         {dbcrypto.BACKEND}")
    print(f"  Cipher:          AES-256-CBC + HMAC-SHA512 (SQLCipher 4)")
    print(f"\nNext steps:")
    print(f"  • Start PegaProx again, it opens the encrypted DB with the master key.")
    print(f"  • {dbcrypto.plain_copy_note(backup_path)}")
    return 0


# ─── Implementation helpers ─────────────────────────────────────────────────

def _encrypt_via_sqlcipher_export(plain_path: str, encrypted_path: str, key_raw: bytes) -> int:
    """Use SQLCipher's built-in `sqlcipher_export` to copy schema + data
    from an attached plain DB into the new encrypted DB.  Returns total row
    count copied across all tables (for the log line)."""
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
    # MK Nov 2026 - created 0600 before SQLCipher opens it. A file SQLite creates gets
    # the umask (0644 as a rule), and the chmod meant for it sat after the return. The
    # journal SQLite writes next to it takes the same mode.
    os.close(os.open(encrypted_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    os.chmod(encrypted_path, 0o600)

    import sqlcipher3
    hex_key = key_raw.hex()

    enc = sqlcipher3.connect(encrypted_path)
    try:
        enc.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        enc.execute("PRAGMA cipher_compatibility = 4")
        # bound, not in the text: a quote in the path broke the statement
        enc.execute("ATTACH DATABASE ? AS plaintext KEY ''", (plain_path,))
        # sqlcipher_export copies everything (schema + data) from `plaintext`
        # to the main (encrypted) DB.
        enc.execute("SELECT sqlcipher_export('main', 'plaintext')")
        enc.execute("DETACH DATABASE plaintext")
        enc.commit()

        # Count rows for sanity reporting
        total = 0
        for (tname,) in enc.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
            quoted = _safe_quote_ident(tname)
            if not quoted:
                _LOG.warning("[MIGRATE] skipping table with unsafe name: %r", tname)
                continue
            try:
                total += enc.execute("SELECT COUNT(*) FROM " + quoted).fetchone()[0]
            except Exception:
                pass
        return total
    finally:
        enc.close()


def _verify_row_counts(plain_path: str, encrypted_path: str) -> None:
    """Compare per-table row counts between plain and encrypted DBs.
    Raises if any table mismatches."""
    import sqlite3
    import sqlcipher3
    from pegaprox.core.keystore import load_master_key

    plain_counts = _row_counts_plain(plain_path)
    mk = load_master_key()
    enc_counts = _row_counts_encrypted(encrypted_path, mk.key_raw)

    if set(plain_counts.keys()) != set(enc_counts.keys()):
        only_plain = set(plain_counts) - set(enc_counts)
        only_enc = set(enc_counts) - set(plain_counts)
        raise RuntimeError(f"table set mismatch: only-plain={only_plain} only-enc={only_enc}")

    for t, c_plain in plain_counts.items():
        c_enc = enc_counts.get(t)
        if c_plain != c_enc:
            raise RuntimeError(
                f"row count mismatch on table {t!r}: plain={c_plain} encrypted={c_enc}")


def _row_counts_plain(path: str) -> Dict[str, int]:
    import sqlite3
    c = sqlite3.connect(path)
    try:
        out = {}
        for (t,) in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'").fetchall():
            # MK 2026-05-31 — v0.9.10.1 hotfix added _safe_quote_ident to the
            # encrypted variant below but missed this plain-text path.
            # Same defense-in-depth treatment: route table name through the
            # whitelist+quote helper instead of raw f-stringing into SELECT.
            quoted = _safe_quote_ident(t)
            if not quoted:
                _LOG.warning("[MIGRATE] skipping table with unsafe name: %r", t)
                out[t] = -1
                continue
            try:
                out[t] = c.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
            except Exception:
                out[t] = -1   # unreadable, will mismatch and trigger error
        return out
    finally:
        c.close()


def _row_counts_encrypted(path: str, key_raw: bytes) -> Dict[str, int]:
    import sqlcipher3
    c = sqlcipher3.connect(path)
    try:
        c.execute(f"PRAGMA key = \"x'{key_raw.hex()}'\"")
        c.execute("PRAGMA cipher_compatibility = 4")
        out = {}
        for (t,) in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'").fetchall():
            quoted = _safe_quote_ident(t)
            if not quoted:
                _LOG.warning("[MIGRATE] skipping table with unsafe name: %r", t)
                out[t] = -1
                continue
            try:
                out[t] = c.execute("SELECT COUNT(*) FROM " + quoted).fetchone()[0]
            except Exception:
                out[t] = -1
        return out
    finally:
        c.close()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
