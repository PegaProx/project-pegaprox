# PegaProx - Encryption Architecture (Operator Guide)

> For **vulnerability reporting** see [`SECURITY.md`](../SECURITY.md) in the repo root.
> This document covers the technical design: how keys are loaded, where the DB
> is encrypted, what to do when things go wrong.

PegaProx persists secrets in two places:

1. **Application database** (`config/pegaprox.db`) - users, sessions, audit
   log, cluster credentials, scheduler state.
2. **Configuration files** under `config/` - TLS certificates, cluster JSON,
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
| 4 | `/etc/pegaprox/secret.key` | **`deploy.sh` and Debian package default** | chmod **0640** root:pegaprox - group-read required so the systemd unit (running as `pegaprox`) can load it. 0600 root:pegaprox is unreadable for the service. |
| 5 | `~/.config/pegaprox/secret.key` | Single-user / dev install | chmod 0600 (owner = user running PegaProx) |
| 6 | `config/.pegaprox.key` (CONFIG_DIR) | **Legacy** - pre-0.9.9.3 | Triggers deprecation warning on every boot. The same file is the Fernet key the database layer reads old field values with, so PegaProx creates it on every install |

The loader **rejects** any file-based tier whose permissions have group-write,
group-exec, or *any* other-user bits set - an accidentally chmod-755'd key file
never becomes the active key silently. The rejection is logged. Group-read is
**allowed** so the system-service install pattern (`root:pegaprox 0640`) works.

### Why the order matters

The 0.9.9.2 audit flagged the legacy default (Tier 6) for storing the key
*next to* the encrypted data. With backups typically including the whole
`config/` directory, key and DB travel together, defeating at-rest encryption.

Tiers 1–5 break that coupling: the key lives somewhere a `config/` snapshot
won't capture. Tier 2 is the strongest because the key is **only**
available to the running service unit and is wrapped against the host's TPM2
chip or host key - not even root can read it directly without unsealing.

### Inspecting the active tier

Run it as the service user from the directory the service runs in, because
`config/` is relative to it (`/opt/PegaProx` for deploy.sh, `/var/lib/pegaprox` for the
Debian package):

```bash
cd /opt/PegaProx && sudo -u pegaprox ./venv/bin/python pegaprox_multi_cluster.py --keystore-status
```

It only reads: where it finds no key it says so instead of creating one. JSON output:

```json
{
  "keystore": {
    "ok": true,
    "source": "/etc/pegaprox/secret.key",
    "source_path": "/etc/pegaprox/secret.key",
    "config_dir": "/opt/PegaProx/config",
    "is_legacy": false,
    "tier": 4,
    "recommendation": "Key is outside the DB directory which is good. Consider upgrading to systemd LoadCredentialEncrypted...",
    "sqlcipher_error": null
  },
  "db": {
    "backend": "sqlcipher",
    "encrypted_at_rest": true,
    "cipher": "AES-256-CBC + HMAC-SHA512 (SQLCipher 4)",
    "files": {
      "/opt/PegaProx/config/pegaprox.db": "encrypted",
      "/opt/PegaProx/config/syslog.db": "encrypted"
    },
    "note": "Full database encryption is active.",
    "sqlcipher_error": null
  }
}
```

`files` comes from each file's first 16 bytes (a plain SQLite file starts with
`SQLite format 3`), so it shows a database that is still plain even where SQLCipher is
installed; `encrypted_at_rest` is true only when every database found is encrypted.

### The Debian package

The package depends on `python3-sqlcipher3`, so its first start encrypts the database. With
no key in `/etc/pegaprox` that start would make one in `config/`, next to the database.
`packaging/debian/master_key.py` puts it there first: the unit runs it as root before every
start (`ExecStartPre=+`), and the postinst runs it on a host where systemd runs. An image
built with the package (the appliances) has no systemd running at build time, so each copy
makes its own key at its first start. What it does, by what it finds:

| State | What happens |
|---|---|
| `PEGAPROX_DB_KEY`, a `db-key` credential or an existing `PEGAPROX_KEY_FILE` in the unit (drop-ins included) | Nothing, the key is yours |
| `/etc/pegaprox/secret.key` there | Kept as it is. A root-owned key the service cannot read (0600, other group) gets 0640 root:pegaprox. A key others can read or write, or one that does not open an encrypted database, stops the start with the reason in the journal. A symlink (the file or `/etc/pegaprox`) is followed as the key store follows it, but what it points to is not changed: if the service cannot read it there, the start stops |
| No key, no database encrypted yet (fresh install, upgrade on a plain database) | A new key, 0640 root:pegaprox; the next start encrypts the database with it |
| No key, a database encrypted already (a start with sqlcipher3 before the package did this) | The key that opens it, `~/.config/pegaprox/secret.key` of the service user or `config/.pegaprox.key`, is copied to `/etc/pegaprox/secret.key` byte for byte, never a new one |
| Anything else (an encrypted database no known key opens, a database file it cannot read) | No key is written, and the start stops with the reason |

The config directory comes from the unit (`WorkingDirectory`, `PEGAPROX_CONFIG_DIR`), so a
moved one is found. It and the home of the service user are read as the service user, as
PegaProx reads them. After a copy `config/.pegaprox.key` stays where it is, and with it a
backup of `config/` still holds the database key. Deleting it makes PegaProx create a new
one at the next start; field values from before the switch to AES-256-GCM that are still
sealed with the old one can then no longer be read.

---

## 2. SQLCipher full-DB encryption (`pegaprox/core/dbcrypto.py`)

When the `sqlcipher3` Python module is importable, every connection acquired
through `dbcrypto.connect()` runs the SQLCipher v4 PRAGMA handshake before
the first query. The DB header is encrypted, all pages are AES-256-CBC, and
each page carries an HMAC-SHA512 tag.

### Platform matrix

| Platform | Package from requirements.txt | Encryption status |
|----------|-------------------------------|-------------------|
| Linux x86_64 | `sqlcipher3-binary` | **Full DB encryption** |
| Linux aarch64 | `sqlcipher3` (0.6.4 or later, wheels with SQLCipher built in) | **Full DB encryption** |
| macOS | `sqlcipher3` | **Full DB encryption** |
| Windows | `sqlcipher3` | **Full DB encryption** |
| 32-bit ARM (armv7) | none, no wheel | Plain SQLite + field-level AES-256-GCM |
| Docker image, amd64 and arm64 | as above | **Full DB encryption** |
| Docker image, arm/v7 | none | Plain SQLite + field-level AES-256-GCM |
| Debian package from apt.pegaprox.com, amd64 and arm64 | `python3-sqlcipher3`, built per architecture from the sqlcipher3 wheels | **Full DB encryption** |
| Debian package from the repository in the README, appliances, amd64 | `python3-sqlcipher3` of that repository | **Full DB encryption** |
| Debian package from the repository in the README, appliances, arm64 | that `python3-sqlcipher3` holds the x86_64 module only, the import fails | Plain SQLite + field-level AES-256-GCM |

The two packages install the same `sqlcipher3` module and must never be installed side by
side; the markers in requirements.txt give every platform one of them at most.

A SQLCipher package that is installed but does not load (the arm64 row above, or a build for
another Python) is not taken for a missing one. Every start writes a warning with the reason
and the machine and Python version to the service log, `--keystore-status` has the reason
in `sqlcipher_error` and says it in the `note` of `db` and in the `recommendation` or
`message` of `keystore`, and the Compliance tab of the settings lists it under
Recommendations. The key step of the Debian package names it too when it cannot check a key.
PegaProx then runs on plain SQLite as in the rows above, until a package built for that
machine is installed and PegaProx restarted.

The fallback is *not* unencrypted - sensitive fields (cluster passwords,
2FA secrets, OIDC client secrets, API tokens) are still individually
encrypted with AES-256-GCM, under their own key file `config/.pegaprox_aes256.key`. The fallback gives up on
metadata-at-rest (table names, audit-log timestamps, session IDs).

You can force-disable SQLCipher by uninstalling the SQLCipher package (`sqlcipher3-binary` or `sqlcipher3`) and
restarting - the connection layer detects the missing module and falls
back transparently. **Note**: any DB already encrypted will become
unreadable until the module is reinstalled - there is no automatic
decrypt-back-to-plain step.

### Cipher parameters

```
PRAGMA cipher_compatibility = 4
PRAGMA key = x'<64-hex-chars>'
```

We pass the key as a 32-byte hex literal so SQLCipher skips its
PBKDF2 key-derivation - the master key already has full entropy and
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

The plain backup is kept for a short rollback window only: every start
shreds (overwrites, then deletes) plaintext backups older than one hour.
Set `PEGAPROX_PLAIN_BACKUP_RETENTION_S` to change the window (`0` shreds
them on the next start). Take your own copy of it first if you want a
longer way back.

### Opt-out

Set `PEGAPROX_DISABLE_AUTO_ENCRYPT=1` in the service environment to skip
the auto-encrypt step on boot. Useful for: taking your own backup first,
running custom pre-flight checks, or staying on plain SQLite for a
debugging window. With opt-out enabled, the field-level AES-256-GCM
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

1. **Backup** - `config/pegaprox.db` → `config/pegaprox.db.plain.bak.<timestamp>`
2. **Encrypt** - new file `config/pegaprox.db.enc` built via SQLite's
   `ATTACH … KEY … AS encrypted; SELECT sqlcipher_export('encrypted');`
3. **Verify** - every table's row count is compared between the plain
   backup and the encrypted target. Any mismatch aborts the migration
   *before* the swap.
4. **Atomic swap** - `os.replace(pegaprox.db.enc, pegaprox.db)`. POSIX
   `rename(2)` is atomic on the same filesystem.

The `.plain.bak.<timestamp>` file holds every stored credential in the
clear, so it is not kept: the first start after the retention window
(default one hour, `PEGAPROX_PLAIN_BACKUP_RETENTION_S`) shreds it. If you
want it as a way back until you have checked the encrypted DB, copy it
somewhere safe right after the migration and delete that copy yourself.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Migration successful, encrypted DB is now active |
| 2 | `sqlcipher3` not installed - install the SQLCipher package of requirements.txt first |
| 3 | Existing DB already encrypted with a **different** key (refuses to clobber) |
| 4 | Source DB is corrupt - repair before retrying |
| 5 | Row-count verification failed - encrypted DB *not* swapped in |

---

## 4. Recovery / disaster scenarios

> **The master key is non-recoverable.** PegaProx does not implement key
> escrow or shamir-shared rebuilds. If the key is lost and the DB is
> encrypted, the DB is permanently unreadable.

### Backup discipline

If you take backups of `config/`, **also** back up the master key - but
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
corrupt DB - corruption manifests as `OperationalError: file is not a
database` at first query. Use `--migrate-db --dry-run` to detect the
`corrupt` state.

If you can still get an old backup readable: stop PegaProx, swap the
corrupt DB out, restore the backup, re-run `--migrate-db`.

---

## 5. systemd LoadCredentialEncrypted (Tier 2) - strongest at-rest

This is the recommended posture for production Linux deployments.

### Prerequisites

- `systemd >= 250` (Debian 12+, Ubuntu 22.04+, RHEL 9+).
- Either a TPM2 chip (`systemd-cryptenroll --tpm2-device=list` succeeds)
  or the default host-key (any systemd ≥ 250 has it).

### Setup

The credential has to hold the key the database is encrypted with now. An install that has
started with SQLCipher (`deploy.sh`, the Debian package, the appliances) has an encrypted
database already, and a new key in the credential locks it out: PegaProx then stops at the
start with `[FATAL] [DBCRYPTO] ... does not unlock it`. So wrap the key it uses. The commands
run as the service user in the directory the service runs in (`/var/lib/pegaprox` for the
Debian package, `/opt/PegaProx` for `deploy.sh`, see
[Inspecting the active tier](#inspecting-the-active-tier)).

1. See which key that is and which databases it encrypts:

   ```bash
   # Debian package, appliances:
   sudo -u pegaprox sh -c 'cd /var/lib/pegaprox && /usr/bin/pegaprox/pegaprox-wrapper --keystore-status'
   # deploy.sh:
   cd /opt/PegaProx && sudo -u pegaprox ./venv/bin/python pegaprox_multi_cluster.py --keystore-status
   ```

   `keystore.source_path` is the key file, `db.files` the state of each database.

2. Wrap that key with systemd-creds. `--print-key` prints it, so no plaintext copy is
   written on the way:

   ```bash
   # Host-key bound (works everywhere):
   sudo -u pegaprox sh -c 'cd /var/lib/pegaprox && /usr/bin/pegaprox/pegaprox-wrapper --print-key' \
     | sudo systemd-creds encrypt --name=db-key - /etc/pegaprox/secret.key.cred

   # TPM2-bound (stronger, requires TPM2 chip):
   sudo -u pegaprox sh -c 'cd /var/lib/pegaprox && /usr/bin/pegaprox/pegaprox-wrapper --print-key' \
     | sudo systemd-creds encrypt --name=db-key --with-key=tpm2 - /etc/pegaprox/secret.key.cred
   ```

   With `deploy.sh`, the first line is
   `cd /opt/PegaProx && sudo -u pegaprox ./venv/bin/python pegaprox_multi_cluster.py --print-key`.

3. **Keep an offline copy** of the key file from step 1 (password vault, see
   [Backup discipline](#backup-discipline)). After step 7 it is the only way back when the
   credential cannot be unsealed any more.

4. Edit `/etc/systemd/system/pegaprox.service` and add to `[Service]`:

   ```ini
   LoadCredentialEncrypted=db-key:/etc/pegaprox/secret.key.cred
   ```

   With the Debian package, put it in a drop-in (`sudo systemctl edit pegaprox`): the unit
   file is the package's. Its key step leaves the key alone while the unit loads `db-key`.

5. Reload + restart:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart pegaprox
   ```

6. Verify that PegaProx started with it. The `[KEYSTORE]` line alone does not show that: it is
   written before the database is opened.

   ```bash
   journalctl -u pegaprox --since -5min | grep -E '\[KEYSTORE\]|\[FATAL\]'
   # → [KEYSTORE] master key source: systemd-credential (/run/credentials/pegaprox.service/db-key)
   #   and no [FATAL] line
   systemctl is-active pegaprox
   # → active, and still a minute later
   ```

   Then log in to the web UI. `[FATAL] [DBCRYPTO] ... does not unlock it` means the credential
   holds another key: take the `LoadCredentialEncrypted=` line out again, restart, and go back
   to step 1.

7. Only when step 6 passed and the copy of step 3 is in place, remove the key file the
   credential replaces, if it is `/etc/pegaprox/secret.key`:

   ```bash
   sudo shred -u /etc/pegaprox/secret.key
   ```

   Never delete `config/.pegaprox.key`, even where it was the key in step 1: it is also the
   Fernet key the database layer reads old field values with (see
   [The Debian package](#the-debian-package)). Where it was the database key, a backup of
   `config/` still holds that key, so keep such backups as secret as the key.

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
2. **The field key is not rotated with the master key.** Sensitive fields
   are sealed with their own key file, `config/.pegaprox_aes256.key`, and
   master key rotation does not re-wrap them. A backup of `config/` holds
   that key file, so treat it as secret.
3. **No second-factor at the DB layer.** A compromised host running
   PegaProx can read the DB. Compartmentalization (running clusters in
   separate VMs with separate keys) is the only mitigation.
4. **Plugin compatibility.** First-party plugins use `dbcrypto.connect()`
   and work transparently. Third-party community plugins that call
   `sqlite3.connect()` directly will **not** be able to read an encrypted
   DB - they need to be updated.

---

*Maintainers: NS / MK. Last revised on the 0.9.9.3 SQLCipher rollout.*
