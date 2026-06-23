# Archive Hash Generation for Update Security

## Overview

PegaProx 0.9.13.2+ verifies the cryptographic integrity of update archives using SHA256 hashes. This prevents code execution from tampered archives during the update process.

## For Release Maintainers

When preparing a new release, generate the SHA256 hash of the archive and add it to `version.json`:

### Step 1: Generate the hash

```bash
# For GitHub archive
./misc/generate-archive-hash.sh https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz

# For local archive
./misc/generate-archive-hash.sh /path/to/archive.tar.gz
```

### Step 2: Add to version.json

Add the `archive_sha256` field to `version.json`:

```json
{
  "version": "0.9.13.2",
  "build": "2026.06.19",
  "update_archive": "https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz",
  "archive_sha256": "a1b2c3d4e5f6789...",
  ...
}
```

### Step 3: Commit and push

```bash
git add version.json
git commit -m "Add archive SHA256 hash for v0.9.13.2"
git push
```

## For Mirror Operators

If you host a custom update mirror, you must provide the `archive_sha256` field in your `version.json`:

1. Generate the hash of your archive:
   ```bash
   sha256sum /path/to/your/archive.tar.gz
   ```

2. Add it to your mirror's `version.json`:
   ```json
   {
     "version": "0.9.13.2",
     "update_archive": "https://your-mirror.example.com/archive/main.tar.gz",
     "archive_sha256": "your-computed-hash-here",
     ...
   }
   ```

## Security Behavior

| Scenario | Behavior |
|----------|----------|
| Hash present and matches | ✅ Update proceeds normally |
| Hash present but mismatches | ❌ Update aborted, falls back to per-file download |
| Hash absent | ⚠️ Update proceeds with security warning logged |

## Audit Trail

When an archive is downloaded without verification:
- Application log: `[SECURITY] Archive downloaded without cryptographic verification`
- Audit log: `pegaprox.update_security_warning` event

Operators should monitor for these warnings and ensure their update sources provide hashes.

## See Also

- [docs/SECURITY.md](../docs/SECURITY.md) - Full security documentation
- [SECURITY.md](../SECURITY.md) - Vulnerability reporting
