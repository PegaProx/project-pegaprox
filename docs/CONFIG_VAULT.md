# Configuration Vault

PegaProx can upload versioned, encrypted configuration backups to WebDAV or
Amazon S3/S3-compatible object storage. This is a disaster-recovery feature,
not multi-instance database replication.

## Security model

- Backup payloads are encrypted with AES-256-GCM before leaving PegaProx.
- New backup envelopes carry a format-version header and derive their AES key
  with PBKDF2-HMAC-SHA256 at 600,000 iterations. Headerless backups created by
  earlier builds remain readable through the legacy 100,000-iteration path.
- The administrator supplies a recovery key. PegaProx stores it encrypted with
  the installation key so scheduled backups can run unattended.
- WebDAV/S3 credentials are also encrypted in the local database and are never
  returned by the API after saving.
- Provider endpoints are HTTPS-only by default, TLS verification is enabled,
  redirects are refused, and public endpoints are protected by the outbound
  URL/SSRF guard.
- Private-network endpoints and plaintext HTTP require separate, explicit
  opt-ins. Cloud metadata endpoints remain blocked.
- Changing the recovery key affects future backup versions only. The random
  key ID included in each cloud filename helps identify the required key without
  exposing a password verifier.

Keep a copy of every recovery key outside PegaProx. A cloud backup cannot be
decrypted if both the installation and the external copy of its recovery key
are lost.

## Configure a provider

Open **Settings → Sync & Cloud**:

1. Set a recovery key of at least 12 characters.
2. Connect WebDAV or S3 Compatible Storage.
3. Save the endpoint and credentials after confirming your administrator
   password.
4. Use **Test** to verify access, then **Sync** for the first upload.
5. Optionally enable automatic sync, choose an interval (1–720 hours), and set
   how many versions to retain (1–100).

For WebDAV, the configured base collection/directory must already exist and
permit `PROPFIND`, `MKCOL`, `PUT`, and `DELETE`. PegaProx creates a child
collection for its installation ID so one machine's retention policy cannot
delete another machine's backups. Legacy flat backup objects remain visible.
For S3-compatible services, enable path-style URLs when required by MinIO,
Ceph RGW, or the storage vendor.

Enabling an automatic schedule makes the provider due immediately; later runs
use the configured interval. Retention cleanup happens only after a successful
upload and never turns an uploaded backup into a reported failure.

## Backup contents

Schema-v2 backups retain compatibility with the existing restore page and add
a manifest containing the backup ID, source instance ID, application version,
section counts, options, and content hash. The portable sections currently are:

- server settings;
- clusters and optional portable credentials;
- optional users, password hashes, and TOTP secrets;
- tenants and VM ACLs;
- affinity rules and cluster groups;
- custom scripts when secrets are explicitly included (script bodies and
  descriptions can contain inline credentials and cannot be reliably redacted);
- optional audit log (up to 10,000 entries).

Sessions, runtime metrics, temporary jobs, task output, and other transient
state are intentionally excluded. Secrets are excluded by default. When they
are included, plaintext exists only inside the outer encrypted backup payload;
restore re-encrypts it with the destination installation key.

## Restore

Restores are intentionally not automatic:

1. On the destination machine, connect the same WebDAV directory or S3 bucket.
2. Open **Settings → Sync & Cloud → Backup & Restore**.
3. Refresh the remote list and select the required version. WebDAV and S3
   listings include backups from other PegaProx instance directories.
4. Enter the destination administrator password and the recovery key used by
   that backup version.
5. Keep **Dry run** enabled and review the validation result.
6. Disable dry run and apply the restore only after validation succeeds.

The encrypted object is downloaded through PegaProx and passed to the existing
restore pipeline. Arbitrary object paths are rejected, downloads are limited to
100 MB, and restore still requires administrator re-authentication. Manual file
download/import remains available as a fallback.

Merge and overwrite modes preserve live server, cluster, and user credentials
when the backup excluded them. Hardware-monitoring consent settings remain
protected and cannot be changed by a generic configuration restore.

## Deliberate limitation

Backup creation remains one-way, but connected machines can browse and manually
restore remote versions. The vault does not continuously watch cloud files,
merge concurrent edits, or coordinate jobs between PegaProx instances. Running
two instances against one live configuration would require leases, task
ownership, tombstones, conflict resolution, and migration coordination; those
semantics are outside this disaster-recovery feature.
