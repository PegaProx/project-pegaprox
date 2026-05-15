# PegaProx — Encryption Architecture (Operator Guide)

> For **vulnerability reporting** see [`SECURITY.md`](../SECURITY.md) in the repo root.
> This document covers the technical design: how keys are loaded, where the DB
> is encrypted, what to do when things go wrong.

PegaProx persists secrets in two places:

1. **Application database** (`config/pegaprox.db`) — users, sessions, audit
   log, cluster credentials, scheduler state.
2. **Configuration files** under `config/` — TLS certificates, cluster JSON,
   plugin state, etc.

Both rely on a single 32-byte **master key**. Where that key lives is the
biggest determinant of how much an attacker who steals a backup actually gets.

---

## 1. Master-key loader (`pegaprox/core/keystore.py`)

The keystore resolves the master key from a priority-ordered list and caches
the first hit for the lifetime of the process.

| Tier | Source | Use case | Notes |
|------|--------|----------|-------|
| 1 | `PEGAPROX_DB_KEY` env var | Docker secrets, k8s, CI | Accepts urlsafe-base64 (44 chars) **or** hex (64 chars) |
| 2 | `${CREDENTIALS_DIRECTORY}/db-key` | systemd `LoadCredentialEncrypted=` | TPM2- or host-key-bound. Strongest at-rest option |
| 3 | `PEGAPROX_KEY_FILE` env var → file | Custom path, e.g. NFS mount | chmod 0600 (or 0640 root:pegaprox) |
| 4 | `/etc/pegaprox/secret.key` | **System-service install default** | chmod **0640** root:pegaprox — group-read required so the systemd unit (running as `pegaprox`) can load it. 0600 root:pegaprox is unreadable for the service. |
| 5 | `~/.config/pegaprox/secret.key` | Single-user / dev install | chmod 0600 (owner = user running PegaProx) |
| 6 | `config/.pegaprox.key` (CONFIG_DIR) | **Legacy** — pre-0.9.9.3 | Triggers deprecation warning on every boot |

The loader **rejects** any file-based tier whose permissions have group-write,
group-exec, or *any* other-user bits set — an accidentally chmod-755'd key file
never becomes the active key silently. The rejection is logged. Group-read is
**allowed** so the system-service install pattern (`root:pegaprox 0640`) works.

### Why the order matters

The 0.9.9.2 audit flagged the legacy default (Tier 6) for storing the key
*next to* the encrypted data. With backups typically including the whole
`config/` directory, key and DB travel together, defeating at-rest encryption.

Tiers 1–5 break that coupling: the key lives somewhere a `config/` snapshot
won't capture. Tier 2 is the strongest because the key is **only**
available to the running service unit and is wrapped against the host's TPM2
chip or host key — not even root can read it directly without unsealing.

### Inspecting the active tier

```bash
sudo -u pegaprox python3 pegaprox_multi_cluster.py --keystore-status
```

JSON output:

```json
{
  "keystore": {
    "ok": true,
    "source": "/etc/pegaprox/secret.key",
    "source_path": "/etc/pegaprox/secret.key",
    "is_legacy": false,
    "tier": 4,
    "recommendation": "Key is outside the DB directory which is good. Consider upgrading to systemd LoadCredentialEncrypted..."
  },
  "db": {
    "backend": "sqlcipher",
    "encrypted_at_rest": true,
    "cipher": "AES-256-CBC / HMAC-SHA512 (SQLCipher v4)"
  }
}
```

A green pill in the admin UI's *Security* card consumes the same data via
`GET /api/security/keystore-status`.

---

## 2. SQLCipher full-DB encryption (`pegaprox/core/dbcrypto.py`)

When the `sqlcipher3` Python module is importable, every connection acquired
through `dbcrypto.connect()` runs the SQLCipher v4 PRAGMA handshake before
the first query. The DB header is encrypted, all pages are AES-256-CBC, and
each page carries an HMAC-SHA512 tag.

### Platform matrix

| Platform | sqlcipher3-binary wheel | Encryption status |
|----------|------------------------|-------------------|
| Linux x86_64 | ✅ shipped | **Full DB encryption** |
| Linux aarch64 | ❌ no wheel | Plain SQLite + field-level Fernet |
| macOS (any) | ❌ no wheel | Plain SQLite + field-level Fernet |
| Windows | ❌ no wheel | Plain SQLite + field-level Fernet |
| Docker `python:3.12-slim` | ✅ (x86_64 base image) | **Full DB encryption** |

The fallback is *not* unencrypted — sensitive fields (cluster passwords,
2FA secrets, OIDC client secrets, API tokens) are still individually
Fernet-encrypted with the same master key. The fallback gives up on
metadata-at-rest (table names, audit-log timestamps, session IDs).

You can force-disable SQLCipher by uninstalling `sqlcipher3-binary` and
restarting — the connection layer detects the missing module and falls
back transparently. **Note**: any DB already encrypted will become
unreadable until the module is reinstalled — there is no automatic
decrypt-back-to-plain step.

### Cipher parameters

```
PRAGMA cipher_compatibility = 4
PRAGMA key = x'<64-hex-chars>'
```

We pass the key as a 32-byte hex literal so SQLCipher skips its
PBKDF2 key-derivation — the master key already has full entropy and
running 256k PBKDF2 rounds on every connection acquire is pointless
overhead. This matches the documented `cipher_default_kdf_iter = 0`
posture for high-entropy raw keys.

---

## 3. Migrating an existing install (plain → encrypted)

PegaProx 0.9.9.3+ **auto-encrypts on first boot** when:

- `sqlcipher3` is importable (Linux x86_64 default), **and**
- the master key resolves to a usable tier, **and**
- the existing DB is in the `plain` state.

The same four-step process runs in-process during startup, gated by an
on-disk lock file (`<db>.migration.lock`, `flock(2)`) so a systemd
restart-storm cannot double-migrate. Boot output:

```
✓ DB auto-encrypted (8121 rows, 8.7s)
  backup: config/pegaprox.db.plain.bak.1778613855
```

The plain backup is **retained** — delete it manually once you've
verified the encrypted DB works for a day or two.

### Opt-out

Set `PEGAPROX_DISABLE_AUTO_ENCRYPT=1` in the service environment to skip
the auto-encrypt step on boot. Useful for: taking your own backup first,
running custom pre-flight checks, or staying on plain SQLite for a
debugging window. With opt-out enabled, the field-level Fernet
encryption still applies and you can run the manual CLI tool whenever
you're ready.

### Manual / explicit path

The `--migrate-db` CLI remains as the explicit / manual control:

### Pre-flight

1. Stop the service: `sudo systemctl stop pegaprox`
2. Verify the keystore resolves a key:
   `sudo -u pegaprox python3 pegaprox_multi_cluster.py --keystore-status`
3. Verify `sqlcipher3` is importable:
   `python3 -c 'import sqlcipher3; print(sqlcipher3.dbapi2.version)'`

### Dry-run

```bash
sudo -u pegaprox python3 pegaprox_multi_cluster.py --migrate-db --dry-run
```

Reports which DB will be encrypted, the current size, and the per-table
row counts that will be verified post-migration. No files are touched.

### Execute

```bash
sudo -u pegaprox python3 pegaprox_multi_cluster.py --migrate-db --yes
```

The four-step process:

1. **Backup** — `config/pegaprox.db` → `config/pegaprox.db.plain.bak.<timestamp>`
2. **Encrypt** — new file `config/pegaprox.db.enc` built via SQLite's
   `ATTACH … KEY … AS encrypted; SELECT sqlcipher_export('encrypted');`
3. **Verify** — every table's row count is compared between the plain
   backup and the encrypted target. Any mismatch aborts the migration
   *before* the swap.
4. **Atomic swap** — `os.replace(pegaprox.db.enc, pegaprox.db)`. POSIX
   `rename(2)` is atomic on the same filesystem.

The `.plain.bak.<timestamp>` file is kept indefinitely — clean it up
manually once you've confirmed the encrypted DB works end-to-end. **Do
not delete it the same day** unless you have your own backups; this is
the only path back if the encrypted DB becomes inaccessible.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Migration successful, encrypted DB is now active |
| 2 | `sqlcipher3` not installed — install `sqlcipher3-binary` first |
| 3 | Existing DB already encrypted with a **different** key (refuses to clobber) |
| 4 | Source DB is corrupt — repair before retrying |
| 5 | Row-count verification failed — encrypted DB *not* swapped in |

---

## 4. Recovery / disaster scenarios

> **The master key is non-recoverable.** PegaProx does not implement key
> escrow or shamir-shared rebuilds. If the key is lost and the DB is
> encrypted, the DB is permanently unreadable.

### Backup discipline

If you take backups of `config/`, **also** back up the master key — but
*to a different location and with different access controls*. Examples:

- DB → encrypted nightly snapshot to S3 (versioned, KMS-encrypted bucket).
- Master key → printed once, sealed in a tamper-evident envelope, kept in
  the on-call lead's safe. Plus: stored in your password manager's shared
  vault under "Infra / PegaProx / master-key".

If both live in the same backup tarball, encrypting the DB bought you
nothing against backup theft.

### Lost master key, encrypted DB

There is no path back. Restore from the most recent `.plain.bak.*`
emitted by the migrator, or from a pre-migration full backup.

### Corrupted SQLCipher DB

`pegaprox_multi_cluster.py --keystore-status` will report
`"db": {"backend": "sqlcipher", "encrypted_at_rest": true}` even on a
corrupt DB — corruption manifests as `OperationalError: file is not a
database` at first query. Use `--migrate-db --dry-run` to detect the
`corrupt` state.

If you can still get an old backup readable: stop PegaProx, swap the
corrupt DB out, restore the backup, re-run `--migrate-db`.

---

## 5. systemd LoadCredentialEncrypted (Tier 2) — strongest at-rest

This is the recommended posture for production Linux deployments.

### Prerequisites

- `systemd >= 250` (Debian 12+, Ubuntu 22.04+, RHEL 9+).
- Either a TPM2 chip (`systemd-cryptenroll --tpm2-device=list` succeeds)
  or the default host-key (any systemd ≥ 250 has it).

### Setup

1. Generate the key (one-time):

   ```bash
   python3 -c 'import secrets, base64;
   print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())' \
     | sudo tee /tmp/pegaprox-key.txt
   ```

2. Wrap it with systemd-creds:

   ```bash
   # Host-key bound (works everywhere):
   sudo systemd-creds encrypt --name=db-key /tmp/pegaprox-key.txt \
        /etc/pegaprox/secret.key.cred

   # TPM2-bound (stronger, requires TPM2 chip):
   sudo systemd-creds encrypt --name=db-key --with-key=tpm2 \
        /tmp/pegaprox-key.txt /etc/pegaprox/secret.key.cred
   ```

3. **Shred the plaintext copy:**

   ```bash
   sudo shred -u /tmp/pegaprox-key.txt
   ```

4. Edit `/etc/systemd/system/pegaprox.service` and add to `[Service]`:

   ```ini
   LoadCredentialEncrypted=db-key:/etc/pegaprox/secret.key.cred
   ```

5. Reload + restart:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart pegaprox
   ```

6. Verify:

   ```bash
   journalctl -u pegaprox -n 50 | grep '\[KEYSTORE\]'
   # → [KEYSTORE] master key source: systemd-credential (/run/credentials/pegaprox.service/db-key)
   ```

7. Once verified, **delete the legacy file** if you migrated from Tier 6:

   ```bash
   sudo shred -u /etc/pegaprox/secret.key   # or config/.pegaprox.key
   ```

### Recovering from a TPM2 reset

A motherboard swap, BIOS reset, or `tpm2_clear` will permanently
invalidate a TPM2-bound credential. Keep an offline copy of the
plaintext key (Tier 1-style backup) in your password vault for
exactly this case.

---

## 6. Known limitations

1. **No automatic key rotation.** Auto-migration encrypts a plain DB once;
   rotating an existing encryption key still means: stop service, re-encrypt
   with new key via `--migrate-db --rotate-from=<old-key-file>`, restart.
   The `--rotate-from` flag is on the roadmap; for now it's manual ATTACH +
   `sqlcipher_export`.
2. **Field-level Fernet keys are not separately rotated.** Master key
   rotation does not re-wrap existing Fernet-encrypted fields. This is
   acceptable since both rely on the same master key — when the master
   key changes, both layers change together.
3. **No second-factor at the DB layer.** A compromised host running
   PegaProx can read the DB. Compartmentalization (running clusters in
   separate VMs with separate keys) is the only mitigation.
4. **Plugin compatibility.** First-party plugins use `dbcrypto.connect()`
   and work transparently. Third-party community plugins that call
   `sqlite3.connect()` directly will **not** be able to read an encrypted
   DB — they need to be updated.

---

*Maintainers: NS / MK. Last revised on the 0.9.9.3 SQLCipher rollout.*
