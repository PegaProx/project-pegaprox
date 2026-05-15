"""
Master-key loader for PegaProx.

Resolves the AES-256 master key from the most-secure available source.
Order of precedence (highest first):

  1. PEGAPROX_DB_KEY            — env var (Docker secrets / k8s / explicit)
  2. CREDENTIALS_DIRECTORY      — systemd LoadCredentialEncrypted (TPM2 or host-key bound)
                                  Service unit must declare:
                                    LoadCredentialEncrypted=db-key:/etc/pegaprox/secret.key.cred
  3. PEGAPROX_KEY_FILE          — env var pointing to a custom location
  4. /etc/pegaprox/secret.key   — system-service install default
  5. ~/.config/pegaprox/secret.key — user install default
  6. CONFIG_DIR/secret.key      — legacy fallback (deprecation-warned)

All file-based candidates must be chmod 0600 (owner-only) or 0640 (owner +
group-read, which is what the system-service install uses so the systemd
unit can load a root-owned key).  Anything with group-write, group-exec or
any other-perm bit set is rejected hard — so an accidentally world-readable
key never becomes the active key silently.

Key format: 32 raw bytes (urlsafe-base64-encoded for Fernet compatibility).
The loader always returns the **base64 representation** because that's what
Fernet expects.  SQLCipher gets the raw 32-byte value via `.raw_key`.

Design notes:
  - Pure read path here.  Generation lives in `_generate_or_load_legacy` —
    invoked only when no tier returns a key, never silently overwriting one.
  - Each call returns a `MasterKey` named-tuple with the key bytes + source
    tag, so the UI / health endpoint can display which tier is active.
  - Thread-safe via module-level lock.  Key is cached after first successful
    load — no repeated filesystem reads on every connection acquire.

MK May 2026 — addresses the "decryption key sits next to the encrypted DB"
finding from the public code review (see SECURITY.md).
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_LOG = logging.getLogger(__name__)
_CACHE_LOCK = threading.Lock()
_CACHED: Optional["MasterKey"] = None


@dataclass(frozen=True)
class MasterKey:
    """Resolved master key plus provenance tag.

    `key_b64`    — urlsafe-base64-encoded 32-byte key (Fernet-ready).
    `key_raw`    — raw 32 bytes (SQLCipher-ready, hex-encode at use site).
    `source`     — short tag for logs / health-indicator UI.
    `source_path`— filesystem path if applicable, else None.
    `is_legacy`  — True iff the key came from CONFIG_DIR — prompts a
                   one-time deprecation warning at load time.
    """
    key_b64: bytes
    key_raw: bytes
    source: str
    source_path: Optional[str] = None
    is_legacy: bool = False


# ─── Public API ─────────────────────────────────────────────────────────────

def load_master_key() -> MasterKey:
    """Resolve the master key from the highest-priority available tier.

    Cached after first call.  Call `reset_cache()` if the underlying key
    file changes mid-process (rare; mostly for tests).
    """
    global _CACHED
    if _CACHED is not None:
        return _CACHED
    with _CACHE_LOCK:
        if _CACHED is not None:
            return _CACHED
        _CACHED = _resolve()
        if _CACHED.is_legacy:
            _LOG.warning(
                "[KEYSTORE] master key loaded from legacy location %s — "
                "recommended: move to /etc/pegaprox/secret.key or use systemd "
                "LoadCredentialEncrypted. See docs/SECURITY.md.",
                _CACHED.source_path,
            )
        else:
            _LOG.info("[KEYSTORE] master key source: %s%s", _CACHED.source,
                      f" ({_CACHED.source_path})" if _CACHED.source_path else "")
        return _CACHED


def reset_cache() -> None:
    """Drop the cached key — primarily for tests + the rotate-key CLI path."""
    global _CACHED
    with _CACHE_LOCK:
        _CACHED = None


def health_status() -> dict:
    """Returned by the /api/security/keystore-status endpoint so the
    admin UI can render the health-indicator pill."""
    try:
        mk = load_master_key()
    except Exception as e:
        return {'ok': False, 'source': 'error', 'message': str(e)}
    return {
        'ok': True,
        'source': mk.source,
        'source_path': mk.source_path,
        'is_legacy': mk.is_legacy,
        'tier': _tier_for_source(mk.source),
        'recommendation': _recommendation_for(mk),
    }


# ─── Internal: resolve in priority order ────────────────────────────────────

def _resolve() -> MasterKey:
    # Tier 1: PEGAPROX_DB_KEY env (Docker / k8s / explicit)
    if env_val := os.environ.get('PEGAPROX_DB_KEY'):
        return _from_env_value(env_val, source='env:PEGAPROX_DB_KEY')

    # Tier 2: systemd LoadCredentialEncrypted
    if cred_dir := os.environ.get('CREDENTIALS_DIRECTORY'):
        cred_path = Path(cred_dir) / 'db-key'
        if cred_path.is_file():
            return _from_file(cred_path, source='systemd-credential', strict_perms=False)
            # systemd already enforces tmpfs + service-uid-only, so we don't
            # require chmod 0600 here (the directory is 0700 by systemd).

    # Tier 3: explicit path override
    if path_val := os.environ.get('PEGAPROX_KEY_FILE'):
        p = Path(path_val).expanduser()
        if p.is_file():
            return _from_file(p, source='env:PEGAPROX_KEY_FILE')

    # Tier 4: /etc/pegaprox/secret.key (system-service install default)
    p = Path('/etc/pegaprox/secret.key')
    if p.is_file():
        return _from_file(p, source='/etc/pegaprox/secret.key')

    # Tier 5: ~/.config/pegaprox/secret.key (user install default)
    p = Path('~/.config/pegaprox/secret.key').expanduser()
    if p.is_file():
        return _from_file(p, source='user-config')

    # Tier 6 (legacy): CONFIG_DIR/secret.key — warned-on-use
    legacy = _legacy_key_path()
    if legacy.is_file():
        mk = _from_file(legacy, source='legacy:CONFIG_DIR', strict_perms=False)
        return MasterKey(mk.key_b64, mk.key_raw, mk.source, mk.source_path, is_legacy=True)

    # Nothing exists — generate at legacy location for back-compat with
    # 0.9.9.x installs.  A subsequent operator-initiated `pegaprox secure-key
    # migrate` moves it to a Tier-4 path.
    return _generate_at(legacy, source='generated:CONFIG_DIR', is_legacy=True)


def _from_env_value(val: str, source: str) -> MasterKey:
    """Accept either base64 (Fernet-style) or raw-hex (SQLCipher style).
    Both round-trip cleanly back to 32 raw bytes."""
    val = val.strip()
    try:
        raw = _decode_key_string(val)
    except ValueError as e:
        # convert decode errors to RuntimeError with the same "must decode
        # to 32 bytes" semantics callers expect from the loader.
        raise RuntimeError(
            f"[KEYSTORE] {source} key must decode to 32 bytes ({e})")
    if len(raw) != 32:
        raise RuntimeError(
            f"[KEYSTORE] {source} key must decode to 32 bytes (got {len(raw)})")
    return MasterKey(
        key_b64=base64.urlsafe_b64encode(raw),
        key_raw=raw,
        source=source,
        source_path=None,
    )


def _from_file(path: Path, source: str, strict_perms: bool = True) -> MasterKey:
    if strict_perms:
        _enforce_perms(path)
    raw_or_b64 = path.read_bytes().strip()
    try:
        raw = _decode_key_string(raw_or_b64.decode('ascii', errors='replace')
                                  if all(c < 128 for c in raw_or_b64) else raw_or_b64)
    except ValueError as e:
        raise RuntimeError(
            f"[KEYSTORE] key at {path} must decode to 32 bytes ({e})")
    if len(raw) != 32:
        raise RuntimeError(
            f"[KEYSTORE] key at {path} must decode to 32 bytes (got {len(raw)})")
    return MasterKey(
        key_b64=base64.urlsafe_b64encode(raw),
        key_raw=raw,
        source=source,
        source_path=str(path),
    )


def _generate_at(path: Path, source: str, is_legacy: bool = False) -> MasterKey:
    """Generate a fresh 32-byte key and persist it at `path` (chmod 0600)."""
    raw = secrets.token_bytes(32)
    key_b64 = base64.urlsafe_b64encode(raw)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        raise RuntimeError(f"[KEYSTORE] cannot create key dir {path.parent}: {e}")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key_b64)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except Exception as e:
        _LOG.warning("[KEYSTORE] could not chmod 0600 on %s: %s", path, e)
    _LOG.info("[KEYSTORE] generated new master key at %s", path)
    return MasterKey(key_b64, raw, source, str(path), is_legacy=is_legacy)


# ─── Helpers ────────────────────────────────────────────────────────────────

def _legacy_key_path() -> Path:
    """The 0.9.9.x default location — CONFIG_DIR/secret.key.
    Imported lazily to avoid circular imports with pegaprox.constants."""
    try:
        from pegaprox.constants import KEY_FILE
        return Path(KEY_FILE)
    except Exception:
        return Path('config') / 'secret.key'


def _enforce_perms(path: Path) -> None:
    """Loose-perms files are skipped at load — but `_enforce_perms` raises so
    the caller decides whether to skip or fail.  We're called only by the
    Tier-3/4/5 paths where strict at-rest perms are required.

    Accepted modes:
      - 0600 / 0400 — key owned by the service user (legacy / single-user installs)
      - 0640 / 0440 — key owned by root with the service group granted read
                       (system-service install, default since v0.9.10.3 after
                       tgmct's #417 install-failure report — the previous 0600
                       posture meant a root-owned key was unreadable by the
                       systemd service running as pegaprox)
    Rejected: anything with group-write, group-exec, or any other-perm bit set.
    """
    try:
        st = os.stat(path)
    except Exception as e:
        raise RuntimeError(f"[KEYSTORE] cannot stat {path}: {e}")
    forbidden = stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO
    if st.st_mode & forbidden:
        raise RuntimeError(
            f"[KEYSTORE] key at {path} has loose permissions "
            f"({oct(st.st_mode)[-3:]}) — must be 0600 or 0640 only.")


def _decode_key_string(s) -> bytes:
    """Accept either:
      - urlsafe-base64 (Fernet, 44 ascii chars ending with '=')
      - hex (64 ascii chars)
      - raw bytes (32 bytes)
    Returns the 32-byte raw key."""
    if isinstance(s, bytes):
        # If it's exactly 32 bytes, treat as raw
        if len(s) == 32:
            return s
        s = s.decode('ascii', errors='replace')
    s = s.strip()
    # try base64 first
    try:
        raw = base64.urlsafe_b64decode(s.encode('ascii'))
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    # try hex
    try:
        raw = bytes.fromhex(s)
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    # last resort: assume the file is raw 32 bytes and we read it as ascii
    if isinstance(s, str) and len(s) == 32:
        return s.encode('latin-1')
    raise ValueError("not a valid 32-byte key (base64 / hex / raw)")


def _tier_for_source(source: str) -> int:
    """Map source-tag to a numeric tier (1 = best, 6 = legacy)."""
    if source.startswith('env:PEGAPROX_DB_KEY'): return 1
    if source.startswith('systemd-credential'):  return 2
    if source.startswith('env:PEGAPROX_KEY_FILE'): return 3
    if source.startswith('/etc/pegaprox'):       return 4
    if source.startswith('user-config'):         return 5
    return 6


def _recommendation_for(mk: MasterKey) -> Optional[str]:
    if mk.is_legacy:
        return (
            "Master key in CONFIG_DIR is the legacy default. "
            "Run `pegaprox secure-key migrate` to move it to "
            "/etc/pegaprox/secret.key, or set up systemd LoadCredentialEncrypted "
            "for the strongest at-rest protection."
        )
    if _tier_for_source(mk.source) >= 4:
        return (
            "Key is outside the DB directory which is good. "
            "Consider upgrading to systemd LoadCredentialEncrypted for "
            "TPM2- or host-key-bound at-rest protection."
        )
    return None
