"""
Plain-SQLite → SQLCipher migration tool.

Usage (called via `pegaprox_multi_cluster.py --migrate-db`):
  1. Locate the live DB at CONFIG_DIR/pegaprox.db
  2. Detect its state (plain / encrypted / corrupt / missing)
  3. If plain:
       a. Hard-copy to pegaprox.db.plain.bak (timestamped)
       b. Open the plain DB, sqlcipher_export into a new encrypted file
       c. Verify row counts match exactly per table
       d. Atomic rename: pegaprox.db.new → pegaprox.db
       e. Retain the .plain.bak for 30 days (operator deletes manually)

Safety properties:
  - Plain DB is never deleted automatically.  Backup retention is the
    operator's choice (we just print "rm this file when you're confident").
  - Atomic rename means a crash mid-migration leaves you with EITHER the
    original plain DB OR the verified encrypted DB.  Never a corrupted mix.
  - Row-count verification per table catches any silent data loss.

MK May 2026 — automatable Stufe-3 migration.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
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
    p = argparse.ArgumentParser(prog='pegaprox migrate-db',
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
        print(f"          DB encryption cannot be enabled.  Install:")
        print(f"            pip install 'sqlcipher3-binary>=0.6.0'   (Linux x86_64)")
        print(f"          or build pysqlcipher3 from source (other platforms).")
        return 2

    state = dbcrypto.detect_db_state(db_path)
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
        print("        Consider running `pegaprox secure-key migrate` first to move it")
        print("        outside the DB directory before encrypting the DB itself.")
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
    print(f"  5. Retain backup; delete manually after verification")

    if args.dry_run:
        print("\n[dry-run] no changes applied.")
        return 0

    if not args.yes:
        print()
        resp = input("Proceed? [y/N] ").strip().lower()
        if resp != 'y':
            print("Cancelled.")
            return 0

    # Step 1: backup
    print(f"\nStep 1/4 backup ... ", end='', flush=True)
    shutil.copy2(db_path, backup_path)
    os.chmod(backup_path, 0o600)
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
    os.replace(new_path, db_path)
    os.chmod(db_path, 0o600)
    print("OK")

    print(f"\n✓ Migration complete.")
    print(f"  Encrypted DB:    {db_path}")
    print(f"  Plain backup:    {backup_path}")
    print(f"  Backend:         {dbcrypto.BACKEND}")
    print(f"  Cipher:          AES-256-CBC + HMAC-SHA512 (SQLCipher 4)")
    print(f"\nNext steps:")
    print(f"  • Restart PegaProx so connections pick up the encrypted DB.")
    print(f"  • Verify functionality for a day or two.")
    print(f"  • Then:  shred -u {backup_path}")
    print(f"           (or rotate it into a secure offline archive)")
    return 0


# ─── Implementation helpers ─────────────────────────────────────────────────

def _encrypt_via_sqlcipher_export(plain_path: str, encrypted_path: str, key_raw: bytes) -> int:
    """Use SQLCipher's built-in `sqlcipher_export` to copy schema + data
    from an attached plain DB into the new encrypted DB.  Returns total row
    count copied across all tables (for the log line)."""
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    import sqlcipher3
    hex_key = key_raw.hex()

    enc = sqlcipher3.connect(encrypted_path)
    try:
        enc.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        enc.execute("PRAGMA cipher_compatibility = 4")
        enc.execute(f"ATTACH DATABASE '{plain_path}' AS plaintext KEY ''")
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
    # tighten perms on the new file
    try:
        os.chmod(encrypted_path, 0o600)
    except Exception:
        pass


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
            try:
                out[t] = c.execute(f"SELECT COUNT(*) FROM \"{t}\"").fetchone()[0]
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
