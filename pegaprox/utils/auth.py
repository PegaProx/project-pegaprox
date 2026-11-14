# -*- coding: utf-8 -*-
"""
PegaProx Authentication - Layer 4
Password hashing, sessions, API tokens, require_auth decorator.
"""
# NS: finally split this out, the monolith was getting ridiculous

import os
import json
import time
import logging
import hashlib
import hmac
import secrets
import threading
import uuid
import base64
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import request, jsonify

from typing import List, Optional

from pegaprox.constants import (
    SESSION_TIMEOUT, CONFIG_DIR,
    SESSIONS_FILE, SESSIONS_FILE_ENCRYPTED, ADMIN_INITIALIZED_FILE, SETUP_REOPEN_FILE,
    LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_TIME, LOGIN_ATTEMPT_WINDOW,
)
from pegaprox.globals import (
    active_sessions, users_db, login_attempts_by_ip, login_attempts_by_user,
    _auth_action_attempts, _auth_action_lock, SESSION_SECRET,
    task_pegaprox_users_cache, task_pegaprox_users_lock,
    sessions_lock,
)
from pegaprox.core.db import get_db, ENCRYPTION_AVAILABLE
from pegaprox.core.config import get_fernet
from pegaprox.models.permissions import ROLE_ADMIN, ROLE_USER, ROLE_VIEWER, PERMISSIONS, ROLE_PERMISSIONS
# MK: record the real client IP (XFF/X-Real-IP via trusted-proxy) for sessions/tokens,
# not request.remote_addr which is the reverse-proxy/Docker IP behind a proxy (#583)
from pegaprox.utils.audit import get_client_ip


def get_session_timeout():
    """Get session timeout from server settings (late import to avoid circular dependency)"""
    try:
        from pegaprox.api.helpers import load_server_settings
        settings = load_server_settings()
        return settings.get('session_timeout', SESSION_TIMEOUT)
    except Exception:
        return SESSION_TIMEOUT

# Argon2 support
ARGON2_AVAILABLE = False
try:
    import argon2
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    pass

# TOTP Support
TOTP_AVAILABLE = False
try:
    import pyotp
    import qrcode
    import io
    TOTP_AVAILABLE = True
except ImportError:
    pass

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    pass

def hash_password(password: str, salt: bytes = None) -> tuple:
    """hash pw with argon2 or pbkdf2 fallback
    
    MK: Always prefer argon2 - install with: pip install argon2-cffi
    """
    if ARGON2_AVAILABLE:
        # argon2 is way better - MK
        ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,  # 64mb, makes gpu cracking hard
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID
        )
        hash_string = ph.hash(password)
        return 'argon2', hash_string
    else:
        # fallback to pbkdf2 - still secure, just slower
        if salt is None:
            salt = os.urandom(32)
        
        # NS: 600k iterations now, was 310k before Jan 2026 - NIST SP 800-132 says min 10k
        #     but realistically anything under 500k is too fast on modern GPUs
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
        return base64.b64encode(salt).decode('utf-8'), base64.b64encode(key).decode('utf-8')


# H3 (scale audit 2026-06-05): argon2 (64MB) and pbkdf2 (600k) are CPU-heavy and
# would freeze the single gevent hub for ~80ms each — a login burst serializes
# into seconds of whole-process stall. Both release the GIL (verified), so we run
# the hash off-hub in the gevent threadpool. A bounded semaphore caps how many run
# at once so a burst of distinct logins can't oversubscribe the CPU (which would
# still jitter the hub even with the GIL released); excess logins queue (the
# calling greenlet waits on the semaphore, yielding the hub). Falls back inline
# with no hub (CLI / tests).
_PW_HASH_SEM = None

def _pw_hash_offload(fn, args):
    try:
        from gevent import get_hub
        from gevent.lock import BoundedSemaphore
    except Exception:
        return fn(*args)
    global _PW_HASH_SEM
    if _PW_HASH_SEM is None:
        try:
            n = int(os.environ.get('PEGAPROX_PW_HASH_CONCURRENCY', '8'))
        except (TypeError, ValueError):
            n = 8
        _PW_HASH_SEM = BoundedSemaphore(max(1, n))
    with _PW_HASH_SEM:
        return get_hub().threadpool.apply(fn, args)


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    """verify pw - handles both argon2 and old pbkdf2 (run off-hub, see H3 above)."""
    return _pw_hash_offload(_verify_password_sync, (password, salt_b64, hash_b64))


def _verify_password_sync(password: str, salt_b64: str, hash_b64: str) -> bool:
    """NS: Order matters! salt first, then hash"""
    try:
        # check for argon2
        if salt_b64 == 'argon2' or hash_b64.startswith('$argon2'):
            if not ARGON2_AVAILABLE:
                logging.error("argon2 hash but lib not installed??")
                return False
            
            ph = PasswordHasher()
            try:
                ph.verify(hash_b64, password)
                return True
            except VerifyMismatchError:
                return False
            except Exception as e:
                logging.error(f"argon2 error: {e}")
                return False
        
        # old pbkdf2
        salt = base64.b64decode(salt_b64)
        stored_hash = base64.b64decode(hash_b64)
        
        # MK: try new iteration count first, then old for backwards compat
        for iterations in [600000, 100000]:
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
            if hmac.compare_digest(key, stored_hash):  # NS: timing-safe compare (was == before, oops)
                return True
        
        return False
    except Exception as e:
        logging.error(f"pw verify error: {e}")
        return False


# NS 2026-04-24 — timing-safe unknown-user branch. Without this the login endpoint
# returns 100× faster on an unknown user than on a real one (dict miss vs. argon2 verify),
# which is a free username-enumeration oracle. Burn the same ~100ms by verifying the
# attacker-supplied password against a fixed dummy hash that never matches.
_DUMMY_ARGON2_HASH = None

def _dummy_verify_password_sync(password: str) -> None:
    global _DUMMY_ARGON2_HASH
    try:
        if _DUMMY_ARGON2_HASH is None:
            _DUMMY_ARGON2_HASH = PasswordHasher().hash('timing-equalizer-not-a-real-password')
        PasswordHasher().verify(_DUMMY_ARGON2_HASH, password if isinstance(password, str) else '')
    except Exception:
        # VerifyMismatchError is the expected outcome; swallow everything else too
        pass


def dummy_verify_password(password: str) -> None:
    """Run an Argon2 verify that always fails, to equalize login timing.
    H3: offloaded to the gevent threadpool like verify_password so the unknown-user
    branch doesn't freeze the hub either."""
    if not ARGON2_AVAILABLE:
        return
    _pw_hash_offload(_dummy_verify_password_sync, (password,))


def recheck_account_password(username: str, password: str, user: dict,
                             audit_action: str = None, context: str = '') -> tuple:
    """Is `password` this account's own password? Returns (ok, auth_source).

    For actions a session alone must not unlock. An LDAP account is checked with a bind
    against the directory, every other account against its local hash, so one without
    a local password never passes here. A failure goes into the audit trail as
    `audit_action` when one is given.

    MK Sep 2026 (#625) - lifted out of the config backup so the backup and the standby
    pairing routes ask this the same way and cannot drift apart.
    """
    auth_source = (user.get('auth_source') if isinstance(user, dict) else None) or 'local'
    ok = False
    if auth_source == 'ldap':
        # #355 - LDAP accounts have no local hash, the directory is the only judge
        try:
            from pegaprox.utils.ldap import ldap_authenticate
            res = ldap_authenticate(username, password)
            ok = bool(res and res.get('success'))
        except Exception as e:
            logging.warning(f"[AUTH] LDAP password re-check failed for {username}: {e}")
            ok = False
    else:
        salt = user.get('password_salt', '') if isinstance(user, dict) else ''
        pw_hash = user.get('password_hash', '') if isinstance(user, dict) else ''
        ok = verify_password(password, salt, pw_hash)
    if not ok and audit_action:
        from pegaprox.utils.audit import log_audit
        detail = f'Password verification failed (auth_source={auth_source})'
        log_audit(username, audit_action, f'{detail} for {context}' if context else detail)
    return ok, auth_source


def needs_password_rehash(salt_b64: str, hash_b64: str) -> bool:
    """check if pw needs upgrade to argon2"""
    if not ARGON2_AVAILABLE:
        return False
    
    # NS: SECURITY - Don't rehash empty passwords (LDAP/OIDC users have no local password!)
    # Without this check, LDAP passwords would get stored locally on login
    if not salt_b64 or not hash_b64:
        return False
    
    # already argon2?
    if salt_b64 == 'argon2' or (hash_b64 and hash_b64.startswith('$argon2')):
        return False
    
    # Old PBKDF2 format - should be upgraded
    return True


def _check_default_password_in_use() -> bool:
    """Check if any admin account still uses default password 'admin'
    
    NS: Security warning - default passwords are a major risk!
    This is called from security compliance check.
    """
    try:
        users_db = load_users()
        
        for username, user in users_db.items():
            # Only check admin accounts
            if user.get('role') != ROLE_ADMIN:
                continue
            
            # Check if password is 'admin'
            salt = user.get('password_salt', '')
            hash_val = user.get('password_hash', '')
            
            if salt and hash_val:
                if verify_password('admin', salt, hash_val):
                    logging.warning(f"SECURITY WARNING: Admin user '{username}' still uses default password!")
                    return True
        
        return False
    except Exception as e:
        logging.error(f"Error checking default passwords: {e}")
        return False  # Don't block on errors


def validate_password_policy(password: str) -> tuple:
    """check pw against configured policy, returns (valid, error_msg)"""
    from pegaprox.api.helpers import load_server_settings
    settings = load_server_settings()
    
    min_length = settings.get('password_min_length', 8)
    require_upper = settings.get('password_require_uppercase', True)
    require_lower = settings.get('password_require_lowercase', True)
    require_numbers = settings.get('password_require_numbers', True)
    require_special = settings.get('password_require_special', False)
    
    errors = []
    
    if len(password) < min_length:
        errors.append(f"at least {min_length} characters")
    
    if require_upper and not any(c.isupper() for c in password):
        errors.append("at least one uppercase letter")
    
    if require_lower and not any(c.islower() for c in password):
        errors.append("at least one lowercase letter")
    
    if require_numbers and not any(c.isdigit() for c in password):
        errors.append("at least one number")
    
    if require_special and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        errors.append("at least one special character")
    
    if errors:
        return False, "Password must contain: " + ", ".join(errors)
    
    return True, None


def load_users(readonly: bool = False) -> dict:
    """Load users from db.

    MK May 2026 — no longer auto-bootstraps a default admin. First-run installs
    go through the setup wizard at /api/auth/setup (which creates the first
    admin from operator-supplied creds, see `create_initial_admin`). Returning
    an empty dict here is now a *valid* "uninitialised" state — callers in the
    login path must check is_initialized() before assuming the absence of a
    user means corruption.
    """
    try:
        db = get_db()
        users = db.get_all_users()

        if users:
            # MK: sanity check - had issues with corrupt user data once
            for username, userdata in users.items():
                if not isinstance(userdata, dict):
                    logging.error(f"User {username} has invalid data type: {type(userdata)}")
            return users
    except Exception as e:
        # NS Oct 2026 (#1053) - this fell back to users.enc, a copy frozen at the SQLite
        # import: a DB that stopped answering signed people in with the old passwords and
        # roles, and accounts deleted since. An unreadable store has nobody to sign in.
        logging.error(f"db load failed: {e}")
        return {}

    # no users in db — uninitialised install, or admin deleted on purpose.
    # the previous code auto-bootstrapped pegaprox/admin here; that path is
    # gone for security reasons (Aikido finding: hardcoded creds, fresh
    # network-reachable install = remote admin takeover).
    return {}


def apply_token_role(user: dict, token_role: str) -> dict:
    """Return a COPY of `user` carrying the effective_role an API token acts under.

    One implementation for the two places that need it. build_authz_user does this for
    the object-level checks; check_cluster_access had its own inline copy so the cluster
    hot path would not have to load the whole users table — and the two drifted. The
    inline one collapsed a tenant CUSTOM role to a builtin level, which is exactly what
    NS removed from build_authz_user in Aug 2026 (Aikido 469089255): a builtin makes
    get_user_clusters skip its custom-role -> tenant remap, so the caller falls back to
    the default tenant, and THAT tenant's empty cluster list means "all clusters". A
    token deliberately scoped narrower than its owner therefore came out wider — it read
    every cluster on the installation, across tenants. Shared now so it cannot drift a
    third time. MK Sep 2026, Aikido 700488915.
    """
    _h = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}
    out = dict(user)
    if token_role and token_role not in _h:
        # a custom role keeps its NAME — see build_authz_user for why, and for what
        # _token_owner_capped then has to do about the missing numeric floor
        out['effective_role'] = token_role
    else:
        eff = min(_h.get(token_role, 1), _h.get(user.get('role'), 1))
        out['effective_role'] = next((r for r, lvl in _h.items() if lvl == eff), ROLE_VIEWER)
    # NS Oct 2026 (#1014) - a builtin token role too: the floor caps the role, not the
    # owner's extra grants, and only rbac._token_permissions leaves those out
    out['_token_owner_capped'] = True
    return out


def build_authz_user(username: str, session: dict) -> dict:
    # MK: user dict for object-level checks (user_can_access_vm & co). For API tokens the
    # stored account role would let an admin-owned 'viewer' token short-circuit those checks,
    # so carry the token's role here, floored to the owner's current role like require_auth
    # does so it can't outrank its owner.
    users = load_users()
    user = users.get(username, {})
    user['username'] = username
    if session.get('api_token'):
        # NS Aug 2026 (Aikido 469089255 core) — a token bound to a tenant CUSTOM role must KEEP that
        # role name, not collapse to a builtin level. The old collapse both under-privileged the token
        # (has_permission then only saw viewer perms) AND — the security bug — made get_user_clusters
        # see a builtin, SKIP its custom-role→tenant remap (rbac.py), fall back to the owner's
        # (default) tenant and return None = "all clusters". Keeping the name lets get_user_clusters
        # scope the token to the role's tenant and lets its real permissions resolve. It can't outrank
        # the owner: create_api_token binds a token at/below the owner's level and require_auth
        # re-floors the numeric role every request. A BUILTIN token role is still floored numerically.
        #
        # MK Sep 2026 - a CUSTOM token role keeps its name, so the numeric floor never runs for
        # it. The token therefore kept resolving through that role's permission list no matter
        # what happened to its owner afterwards: demote the owner to viewer, strip a permission
        # from their account, and a token they minted while they still held it carried on
        # working. _token_owner_capped marks the identity so get_user_permissions can intersect
        # with what the owner holds TODAY - it has to happen there, not here, because the
        # answer is per-tenant.
        #
        # MK Sep 2026 - the body moved into apply_token_role because check_cluster_access
        # carries the same decision on a path that must not load the whole users table, and
        # the two copies had already drifted apart once.
        user = apply_token_role(user, session.get('role'))
    return user


def resolve_authz_user(auth: dict):
    """The identity a console, shell or terminal is opened for, or None.

    `auth` is a session or the ws token minted from one: the user, the role it was
    issued with and whether an API token stood behind it.

    NS Oct 2026 (#1101) - read by the account's own row. The console handlers used
    load_users().get(name, {}), and that whole-table read comes back as {} when it
    fails; {} is a role-less viewer in the default tenant, whose empty cluster list
    means every cluster. An account we cannot read is a refusal, never a default.

    (#1116) - an API token acts under its own role, floored to the owner's, exactly as
    build_authz_user does for the REST routes. A ws token whose role is not the one
    stored on the account is floored the same way, so a role change inside its 60 s
    life cannot widen it either."""
    username = (auth or {}).get('user') or ''
    if not username:
        return None
    try:
        stored = get_db().get_user(username)
    except Exception as e:
        logging.warning(f"[AUTHZ] could not read account {username!r}: {type(e).__name__}")
        return None
    if not stored:
        return None
    user = dict(stored, username=username)
    role = auth.get('role')
    if auth.get('api_token') or (role and role != stored.get('role')):
        user = apply_token_role(user, role)
    return user


# Answers of initialization_state(). "unknown" is the one that matters: it is
# what every caller used to see as "uninitialised" and act on.
INIT_INITIALIZED = 'initialized'
INIT_UNINITIALIZED = 'uninitialized'
INIT_UNKNOWN = 'unknown'
# configuration but no account: lost its users, never was a fresh install (#991)
INIT_NO_ACCOUNTS = 'no_accounts'


def initialization_state() -> str:
    """Whether first-run setup has run, with "could not tell" as its own answer.

    Two ways an install counts as initialised:
      1. /api/auth/setup ran successfully and wrote ADMIN_INITIALIZED_FILE
      2. backfill_initialized_marker() observed pre-existing users on an
         upgrade from a pre-setup-wizard build

    MK Sep 2026 - this used to be a bare bool, and an unreadable user store
    collapsed into False, i.e. into "fresh install". A wrong SQLCipher key, a
    half-restored config volume or a permissions slip therefore re-opened
    /api/auth/setup on a *production* install while /login was refusing
    everyone: the operator is locked out and whoever reaches the port first
    becomes the administrator. Report the difference and let callers decide.

    Pure read, no side effects.
    """
    try:
        os.stat(ADMIN_INITIALIZED_FILE)
        return INIT_INITIALIZED
    except FileNotFoundError:
        pass                      # genuinely absent - ask the DB below
    except OSError as e:
        # os.path.exists() answers False for a marker that is there but cannot be
        # stat()ed (config/ not readable), which reads as "no marker" and hands the
        # decision to a store we almost certainly cannot read either.
        logging.error(f"cannot stat the initialisation marker: {e}")
        return INIT_UNKNOWN
    # second-opinion against the DB in case the marker file was wiped but
    # the user table survived (volume mount oddities, manual restore, etc.)
    try:
        db = get_db()
        if db.get_all_users():
            return INIT_INITIALIZED
        # NS Oct 2026 (#991) - and when both are gone, an empty users table alone does not
        # make a fresh install. With the clusters, their credentials and the issued tokens
        # still there, setup handed the first caller to reach the port an administrator
        # over all of it. Reopened only by the operator on the server (SETUP_REOPEN_FILE).
        if db.holds_configuration() and not os.path.exists(SETUP_REOPEN_FILE):
            return INIT_NO_ACCOUNTS
        return INIT_UNINITIALIZED
    except Exception as e:
        logging.error(f"cannot read the user store to decide first-run state: {e}")
        return INIT_UNKNOWN


def is_initialized() -> bool:
    """True unless this is *certainly* a fresh install.

    Fails closed on purpose: an unreadable user store answers True here, so the
    setup wizard stays shut. Callers that need to tell "fresh" from "broken"
    apart - the setup and login endpoints - ask initialization_state().
    """
    return initialization_state() != INIT_UNINITIALIZED


def backfill_initialized_marker():
    """Upgrade-safety: mark ADMIN_INITIALIZED_FILE if users already exist.

    Run once at app startup. Pre-setup-wizard installs have users in the DB
    but never wrote ADMIN_INITIALIZED_FILE — without this, after upgrade the
    /login path's is_initialized() second-opinion saves us, but writing the
    marker also avoids the every-call DB roundtrip and makes the post-upgrade
    state explicit on disk.
    """
    if os.path.exists(ADMIN_INITIALIZED_FILE):
        return
    try:
        db = get_db()
        if db.get_all_users():
            mark_admin_initialized()
            logging.info("backfilled ADMIN_INITIALIZED_FILE for pre-setup-wizard install")
    except Exception as e:
        logging.debug(f"backfill check skipped: {e}")


def save_single_user(username: str, data: dict):
    """Persist ONE account.

    sec/correctness (audit): every auth handler did `users_db = load_users()` (a full snapshot),
    mutated one entry and then `save_users(users_db)` — writing the whole table back. Two
    concurrent requests each hold a snapshot taken before the other's write, so the second
    save silently reverts the first: a password change can undo a role change, a 2FA enrolment
    can undo an account creation. Under gevent the password hashing in between is a generous
    window. Handlers that touch a single account use this instead.
    """
    try:
        get_db().save_user(username, data)
    except Exception as e:
        logging.error(f"save failed for '{username}': {e}")


def save_users(users: dict):
    """save users to db"""
    try:
        db = get_db()
        db.save_all_users(users)
        # logging.debug(f"saved {len(users)} users")
    except Exception as e:
        logging.error(f"save failed: {e}")

def claim_admin_initialization() -> bool:
    """Create the marker atomically. True only for the caller that created it.

    O_EXCL makes this the mutual exclusion for first-run setup. Two concurrent
    POSTs to /api/auth/setup both passed the is_initialized() check and both ran
    through to save_users(), which upserts - so a racing attacker ended up with a
    second, persistent administrator sitting next to the operator's, on an
    install the operator believes they just set up alone. MK Sep 2026
    """
    try:
        fd = os.open(ADMIN_INITIALIZED_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    except Exception as e:
        logging.error(f"couldnt claim admin init: {e}")
        return False
    try:
        # os.write/os.close rather than fdopen(): if fdopen() itself raises it never
        # takes ownership of the descriptor and we would leak it on every failure.
        os.write(fd, datetime.now().isoformat().encode())
    except Exception as e:
        # the claim is what counts; a missing timestamp is cosmetic
        logging.error(f"couldnt write admin init marker: {e}")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return True


def release_admin_initialization():
    """Give the claim back after a setup that failed to create the admin.

    Without this a failed save leaves the marker behind and the install is
    bricked: setup says "already initialised", login has nobody to log in as.
    """
    try:
        os.unlink(ADMIN_INITIALIZED_FILE)
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.error(f"couldnt release admin init: {e}")


def consume_setup_reopen():
    """Drop SETUP_REOPEN_FILE once a setup created the administrator: it opens the
    wizard for one setup, not for whenever the accounts are gone again (#991)."""
    try:
        os.unlink(SETUP_REOPEN_FILE)
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.error(f"[SETUP] could not remove {SETUP_REOPEN_FILE}, remove it by hand: {e}")


def mark_admin_initialized():
    """mark admin as customized so we dont recreate it"""
    try:
        with open(ADMIN_INITIALIZED_FILE, 'w') as f:
            f.write(datetime.now().isoformat())
        os.chmod(ADMIN_INITIALIZED_FILE, 0o600)
    except Exception as e:
        logging.error(f"couldnt mark admin init: {e}")

def create_initial_admin(username: str, password: str, display_name: str = '', email: str = '') -> dict:
    """Build the first-admin user record from setup-wizard input.

    Caller is responsible for is_initialized() check + password policy
    validation. This helper just shapes the dict; it does NOT save or mark
    the install as initialised.
    """
    salt, password_hash = hash_password(password)
    return {
        username: {
            'password_salt': salt,
            'password_hash': password_hash,
            'role': ROLE_ADMIN,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'display_name': display_name or username,
            'email': email or '',
            'enabled': True,
            # NS — these flags are kept for back-compat with downstream UI
            # ("Welcome banner" etc) but no longer carry a fixed-password risk
            # since the operator chose the password themselves.
            'is_default': False,
            'force_password_change': False,
            'password_changed_at': datetime.now().isoformat(),
        }
    }

def generate_session_id() -> str:
    """Generate a secure session ID"""
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

# =============================================================================
# SESSION PERSISTENCE - NS: Added Dec 2025
# Sessions are now encrypted and persisted to survive server restarts
# LW: Finally got around to this after MK's TODO sat there for months
# =============================================================================

def save_sessions():
    """Save active sessions to SQLite database
    
    SQLite migration
    """
    global active_sessions
    
    try:
        # Clean up expired sessions first
        timeout = get_session_timeout()
        now = time.time()
        expired = [sid for sid, sess in active_sessions.items() 
                   if now - sess.get('last_activity', 0) > timeout]
        for sid in expired:
            del active_sessions[sid]
        
        # Save to database - without the sessions of forwarded writes, which hold for
        # one request in this process and nowhere else
        db = get_db()
        db.save_all_sessions({sid: sess for sid, sess in active_sessions.items()
                              if not sess.get('ha_forward')})
        
    except Exception as e:
        logging.error(f"Failed to save sessions: {e}")


def load_sessions():
    """Load active sessions from SQLite database
    
    SQLite migration
    """
    global active_sessions
    
    try:
        db = get_db()
        active_sessions = db.get_all_sessions()
        
        # Clean up expired sessions
        timeout = get_session_timeout()
        now = time.time()
        expired = [sid for sid, sess in active_sessions.items() 
                   if now - sess.get('last_activity', 0) > timeout]
        for sid in expired:
            del active_sessions[sid]
            db.delete_session(sid)
        
        logging.info(f"Loaded {len(active_sessions)} sessions from SQLite")
        
    except Exception as e:
        logging.warning(f"Failed to load sessions from database: {e}")
        # Try legacy fallback
        _load_sessions_legacy()


def _load_sessions_legacy():
    """Legacy sessions loader - used as fallback"""
    global active_sessions
    fernet = get_fernet()
    
    if fernet and os.path.exists(SESSIONS_FILE_ENCRYPTED):
        try:
            with open(SESSIONS_FILE_ENCRYPTED, 'rb') as f:
                encrypted = f.read()
            decrypted = fernet.decrypt(encrypted)
            active_sessions = json.loads(decrypted.decode('utf-8'))
            logging.info(f"Loaded {len(active_sessions)} sessions from legacy encrypted file")
        except Exception as e:
            logging.debug(f"Could not load legacy encrypted sessions: {e}")
    elif os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, 'r') as f:
                active_sessions = json.load(f)
            logging.info(f"Loaded {len(active_sessions)} sessions from legacy JSON file")
        except Exception as e:
            logging.debug(f"Could not load legacy sessions file: {e}")

def create_session(username: str, role: str, remember: bool = False) -> str:
    """Create a new session for a user

    NS: Also does session rotation - invalidates old sessions for same user
    This prevents session fixation attacks and limits concurrent sessions
    """
    session_id = generate_session_id()

    # NS: Feb 2026 - SECURITY: lock dict mutations only, not I/O
    with sessions_lock:
        # Session rotation: invalidate existing sessions for this user
        # MK: keep max 3 sessions per user (browser, phone, etc)
        # not the one-request session of a write a standby forwarded (#625), it ends
        # on its own a moment later
        user_sessions = [(sid, sess) for sid, sess in active_sessions.items()
                         if sess.get('user') == username and not sess.get('ha_forward')]

        # Sort by last_activity, remove oldest if more than 2 (new one will be 3rd)
        rotated = []
        if len(user_sessions) >= 3:
            user_sessions.sort(key=lambda x: x[1].get('last_activity', 0))
            # Remove oldest sessions, keep 2
            for sid, _ in user_sessions[:-2]:
                del active_sessions[sid]
                rotated.append(sid)
                logging.debug(f"Session rotation: removed old session for {username}")

        active_sessions[session_id] = {
            'user': username,
            'role': role,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip': get_client_ip() if request else None,
            'user_agent': request.headers.get('User-Agent', '')[:200] if request else None,
            'remember': remember,  # NS: persistent session (30 days instead of default)
        }

    # Save sessions to disk (outside lock - I/O operation)
    save_sessions()
    if rotated:
        _end_channels(username, sids=rotated)

    return session_id


# NS Oct 2026 (#1076) - force_2fa held on the server, not only by the setup screen.
MFA_NOT_DUE = 'not_due'
MFA_DUE = 'due'
MFA_SKIPPED_ON_STANDBY = 'skipped_on_standby'

# What a session that still has to enrol may reach: the enrolment, the session check the
# setup screen reads, and signing out. Matched on the endpoint that serves the request.
MFA_ENROLMENT_ENDPOINTS = frozenset({
    'auth.setup_2fa', 'auth.verify_2fa_setup', 'auth.get_2fa_status',
    'auth.auth_check', 'auth.auth_logout',
})
# marks the request validate_session held back, so require_auth can say why
MFA_HELD_ENVIRON = 'pegaprox.mfa_enrolment_due'
_MFA_RECHECK_S = 30


def mfa_enrolment_state(user: dict, settings: dict) -> str:
    """Whether force_2fa still holds `user` back. MFA_SKIPPED_ON_STANDBY is an admin let
    past it on a standby that cannot hand the enrolment to the active (#625); the
    sign-in puts that on the record."""
    if not settings.get('force_2fa') or not TOTP_AVAILABLE:
        return MFA_NOT_DUE
    # enrolled = a code can be asked for, which is what auth_login asks
    if user.get('totp_enabled') and user.get('totp_secret'):
        return MFA_NOT_DUE
    # OIDC/Entra accounts use their IdP's MFA
    if user.get('auth_source', 'local') in ('oidc', 'entra'):
        return MFA_NOT_DUE
    # NS Oct 2026 (#1028) - an admin a tenant override lowers where they live is not
    # excused as an admin either
    from pegaprox.utils.rbac import acts_as_admin
    is_admin = acts_as_admin(user)
    if is_admin and settings.get('force_2fa_exclude_admins', False):
        return MFA_NOT_DUE
    if is_admin:
        from pegaprox.core import ha
        if ha.is_standby() and not ha.forwarding():
            return MFA_SKIPPED_ON_STANDBY
    return MFA_DUE


def _mfa_enrolment_lets_through(session: dict) -> bool:
    """May this session serve this request, as far as force_2fa goes?

    auth_login minted a full session and only returned requires_2fa_setup, so the setup
    screen was the whole enforcement: a client that ignored the flag, or anyone holding
    the password, used the API without ever enrolling. Asked from validate_session
    because every way in passes it - require_auth, the consoles, the live WebSocket,
    WebAuthn and the writes a standby hands on.

    The answer stays on the session. Re-read on every request while it holds, so the
    enrolment frees it at once, and every _MFA_RECHECK_S otherwise, so force_2fa
    switched on or a factor an admin cleared reaches sessions already open.
    """
    now = time.time()
    due = session.get('mfa_due')
    if due is None or due or now - session.get('mfa_checked_at', 0) >= _MFA_RECHECK_S:
        try:
            user = get_db().get_user(session.get('user', ''))
            from pegaprox.api.helpers import load_server_settings
            fresh = bool(user) and mfa_enrolment_state(user, load_server_settings()) == MFA_DUE
        except Exception as e:
            # keep the last answer; a session never judged stays held until it can be
            logging.warning(f"[2FA] cannot tell whether force_2fa holds "
                            f"{session.get('user')!r}: {e}")
            fresh = True if due is None else due
        due = fresh
        with sessions_lock:
            session['mfa_due'] = due
            session['mfa_checked_at'] = now
    if not due:
        return True
    try:
        from flask import has_request_context
        if has_request_context():
            if request.endpoint in MFA_ENROLMENT_ENDPOINTS:
                return True
            request.environ[MFA_HELD_ENVIRON] = True
    except Exception:
        pass
    return False


# MK Oct 2026 - portal_only held on the server too. The flag only told the UI where to send
# the account; the API itself answered it like any other account of its role. What it may
# reach now, by the endpoint that serves the request (like MFA_ENROLMENT_ENDPOINTS), and
# nothing else. The one list for require_auth and hold_portal_only_accounts (app.py).
PORTAL_ONLY_ENDPOINTS = frozenset({
    # signing in and out, and the session check the portal and / start with
    'auth.auth_login', 'auth.auth_logout', 'auth.auth_check',
    # SSO started from the portal (redirect_after=/portal) and the way back from the IdP
    'auth.oidc_get_public_config', 'auth.oidc_authorize', 'auth.oidc_login',
    'auth.oidc_callback', 'auth.oidc_callback_redirect',
    # a security key as second factor on the login page of /, before there is a session
    'webauthn.auth_begin', 'webauthn.auth_finish',
    # TOTP enrolment from the portal, forced 2FA included
    'auth.setup_2fa', 'auth.verify_2fa_setup',
    # the portal console on the main port (reverse proxy), with the ws token its vm/console
    # route mints; _console_authz keeps it to the account's own guests
    'vms.vnc_websocket_route', '__flask_sock.vnc_websocket_proxy',
})
# and the plugin API of this one plugin (plugins.plugin_proxy), not of any other
PORTAL_ONLY_PLUGIN = 'client_portal'
PORTAL_ONLY_ERROR = {'error': 'This account can only use the Client Portal', 'code': 'PORTAL_ONLY'}
# routes the hook leaves alone: they read no credential and answer everyone the same, and
# a probe hammers /api/health, which must not turn to a DB lookup or a 503 on a header.
# The interface lock (#1189) is read by every page load of /, a portal account's included
PORTAL_ONLY_UNREAD = frozenset({'auth.health_check', 'settings.get_interface_lock'})


def portal_only_may_serve() -> bool:
    """Is this request one a portal_only account may make?"""
    endpoint = request.endpoint
    if endpoint in PORTAL_ONLY_ENDPOINTS:
        return True
    return (endpoint == 'plugins.plugin_proxy'
            and (request.view_args or {}).get('plugin_id') == PORTAL_ONLY_PLUGIN)


def portal_only_refusal(user: dict):
    """The 403 for a portal_only account outside the portal, None otherwise."""
    from pegaprox.utils.rbac import portal_only_holds
    if not portal_only_holds(user) or portal_only_may_serve():
        return None
    return jsonify(PORTAL_ONLY_ERROR), 403


def _api_token_owner(token: str):
    """The account an API token belongs to, None for one we do not know."""
    row = get_db().conn.execute('SELECT username FROM api_tokens WHERE token_hash = ?',
                                (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    return row['username'] if row else None


def _request_accounts(look_up_tokens=True) -> set:
    """Who the credentials on this request name, whichever a route goes by: the session id
    in the header, either cookie (the SSH server sends `session`) or ?session=, an API
    token, a ws or SSE token in ?token=. Looked up, never used: a ws token is single-use
    and stays for the route, and no session is touched. look_up_tokens=False leaves an API
    token in the header alone (it costs a DB read)."""
    names = set()
    sids = (request.headers.get('X-Session-ID'), request.cookies.get('session_id'),
            request.cookies.get('session'), request.args.get('session'))
    with sessions_lock:
        for sid in sids:
            if sid:
                names.add((active_sessions.get(sid) or {}).get('user'))
    token = request.args.get('token')
    if token:
        from pegaprox.globals import ws_tokens, ws_tokens_lock, sse_tokens, sse_tokens_lock
        with ws_tokens_lock:
            names.add((ws_tokens.get(token) or {}).get('user'))
        with sse_tokens_lock:
            names.add((sse_tokens.get(token) or {}).get('user'))
    bearer = request.headers.get('Authorization', '')
    if look_up_tokens and bearer.startswith('Bearer pgx_'):
        names.add(_api_token_owner(bearer[7:]))
    names.discard(None)
    names.discard('')
    return names


def portal_only_request_refusal(look_up_tokens=True):
    """portal_only for a route without require_auth: one that finds its caller itself (the
    consoles, the live streams, the validate calls of the SSH server) or none at all.
    look_up_tokens=False for a request the API rate limit does not count: a made-up token
    must not buy an unlimited stream of DB reads, and no route there takes an API token."""
    if portal_only_may_serve() or request.endpoint in PORTAL_ONLY_UNREAD:
        return None
    try:
        users = [get_db().get_user(name) for name in _request_accounts(look_up_tokens)]
    except Exception as e:
        # an account we cannot read is not one we know to be free to go on
        logging.warning(f"[AUTH] cannot tell whether the caller is portal_only: {e}")
        return jsonify({'error': 'The account could not be read, try again',
                        'code': 'ACCOUNT_UNREADABLE'}), 503
    for user in users:
        # no record: the route refuses an account that is gone, as it always did
        refused = portal_only_refusal(user)
        if refused:
            return refused
    return None


def validate_session(session_id: str) -> dict:
    """Validate a session and return user info if valid"""
    if not session_id:
        return None

    expired = False
    session = None

    # NS: Feb 2026 - SECURITY: lock dict mutations only
    with sessions_lock:
        if session_id not in active_sessions:
            return None

        session = active_sessions[session_id]

        # check session has expired — remember sessions last 30 days
        timeout = 30 * 86400 if session.get('remember') else get_session_timeout()
        if time.time() - session['last_activity'] > timeout:
            del active_sessions[session_id]
            expired = True
        # NS: absolute session timeout (security audit: was 24h)
        # remember sessions: 7 days absolute, regular: 12h
        elif time.time() - session.get('created_at', session.get('last_activity', time.time())) > (7 * 86400 if session.get('remember') else 43200):
            del active_sessions[session_id]
            expired = True
        else:
            # Update last activity
            session['last_activity'] = time.time()

    if expired:
        save_sessions()
        return None

    # MK Sep 2026 (#625) - a session the active opened for a write a standby forwarded
    # holds inside that one request and nowhere else (open_forwarded_session)
    if session.get('ha_forward') and not _serves_forwarded_write(session_id):
        return None

    # MK: security audit — IP binding. Default: log-only (mobile roaming friendly).
    # NS 2026-04-24: when `strict_session_ip` is enabled in server settings, invalidate
    # the session on IP change so a hijacked cookie can't be used from a different
    # network. Default stays false — breaks mobile users otherwise.
    try:
        from flask import request as _req
        if _req and hasattr(_req, 'remote_addr'):
            current_ip = get_client_ip()  # MK: must match what create_session stored (#583), else proxy-vs-real false-trips
            session_ip = session.get('ip')
            if session_ip and current_ip and session_ip != current_ip:
                # MK: treat IPv4 vs IPv4-mapped-IPv6 of the same host as equal
                # so a dual-stack proxy flipping doesn't punt the user
                def _norm(ip):
                    if not ip: return ''
                    return ip[7:] if ip.startswith('::ffff:') else ip
                if _norm(session_ip) != _norm(current_ip):
                    strict = False
                    try:
                        from pegaprox.api.helpers import load_server_settings
                        strict = bool((load_server_settings() or {}).get('strict_session_ip', False))
                    except Exception:
                        pass
                    if strict:
                        logging.warning(f"[SECURITY] strict_session_ip: invalidating session for {session.get('user')} — IP changed {session_ip} → {current_ip}")
                        with sessions_lock:
                            active_sessions.pop(session_id, None)
                        save_sessions()
                        return None
                    logging.warning(f"[SECURITY] Session IP changed: {session_ip} → {current_ip} (user={session.get('user')})")
    except Exception:
        pass

    if not _mfa_enrolment_lets_through(session):
        return None

    return session

def open_forwarded_session(username: str, role: str, ip: str, via: str) -> str:
    """A session for one write a standby forwarded to this active instance (#625).

    The route runs the write as `username` under it, so require_auth and everything
    after it see an ordinary session: role and permissions come from our users table
    as for any other. Unlike create_session it ends none of the user's own sessions
    and saves nothing. validate_session takes it only inside the request that carries
    it (ha.FORWARD_ENVIRON), and end_forwarded_session drops it right after.
    """
    session_id = generate_session_id()
    now = time.time()
    with sessions_lock:
        active_sessions[session_id] = {
            'user': username,
            'role': role,
            'created_at': now,
            'last_activity': now,
            'ip': ip,
            'user_agent': f'via standby {via}'[:200],
            'remember': False,
            'ha_forward': via,
        }
    return session_id


def end_forwarded_session(session_id: str):
    with sessions_lock:
        active_sessions.pop(session_id, None)


def _serves_forwarded_write(session_id: str) -> bool:
    try:
        from flask import request as _req, has_request_context
        if not has_request_context():
            return False
        from pegaprox.core.ha import FORWARD_ENVIRON
        mark = _req.environ.get(FORWARD_ENVIRON)
        return isinstance(mark, dict) and mark.get('session') == session_id
    except Exception:
        return False


def invalidate_session(session_id: str):
    """Invalidate a session (logout)"""
    removed = None
    with sessions_lock:
        if session_id in active_sessions:
            removed = active_sessions.pop(session_id)
    if removed is not None:
        save_sessions()
        _end_channels(removed.get('user'), sids={session_id})


def _end_channels(username, **kw):
    """NS Oct 2026 (#1038) - what the ended sessions opened goes with them."""
    if not username:
        return
    try:
        from pegaprox.utils.realtime import end_session_channels
        end_session_channels(username, **kw)
    except Exception as e:
        logging.warning(f"could not end the live channels of {username!r}: {e}")


def session_alive(session_id: str) -> bool:
    """Whether a session still stands. Touches nothing, so an open stream asking this does
    not keep its session from idling out."""
    with sessions_lock:
        return bool(session_id) and session_id in active_sessions


def api_token_alive(token_id):
    """True while an API token stands, False once it is revoked, deleted or expired, None
    when the token table cannot be read."""
    try:
        cur = get_db().conn.cursor()
        cur.execute('SELECT revoked, expires_at FROM api_tokens WHERE id = ?', (token_id,))
        row = cur.fetchone()
        if not row or row['revoked']:
            return False
        return not (row['expires_at'] and datetime.now() > datetime.fromisoformat(row['expires_at']))
    except Exception as e:
        logging.warning(f"[APIToken] cannot tell whether token id={token_id} stands: {e}")
        return None


def request_credential():
    """(session id, API token id) this request is signed in with, one of them None. For a
    token or stream minted here, so it ends with what it was minted under."""
    sess = getattr(request, 'session', None) or {}
    if sess.get('api_token'):
        return None, sess.get('token_id')
    return request.headers.get('X-Session-ID') or request.cookies.get('session_id'), None


def invalidate_all_user_sessions(username: str, except_session: str = None):
    """Invalidate all sessions for a user (used when password changes)

    LW: This is important for security - when password changes, all sessions should die
    """
    global active_sessions
    sessions_removed = 0
    with sessions_lock:
        for sid in list(active_sessions.keys()):
            if active_sessions[sid].get('user') == username and sid != except_session:
                del active_sessions[sid]
                sessions_removed += 1

    if sessions_removed > 0:
        save_sessions()
        logging.info(f"Invalidated {sessions_removed} sessions for user '{username}'")
    # every caller is a credential change, a disable or a delete: whatever the user has open
    # elsewhere goes too, API token streams included
    _end_channels(username, keep=except_session)

    return sessions_removed


# =============================================================================
# MK: Feb 2026 - API Token Authentication
# Allows programmatic access without session cookies. Tokens are stored as
# SHA-256 hashes in the DB. The actual token is only shown once at creation.
# Format: pgx_<prefix>_<random> (e.g. pgx_ab12_8f3k...)
# =============================================================================

def generate_api_token() -> tuple:
    """Generate a new API token. Returns (token_string, token_hash, prefix)"""
    # NS: Token format: pgx_<4char_prefix>_<32char_random>
    prefix = secrets.token_hex(2)  # 4 hex chars
    random_part = secrets.token_urlsafe(32)
    token = f"pgx_{prefix}_{random_part}"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash, prefix


def create_api_token(username: str, token_name: str, role: str = None, 
                     permissions: list = None, expires_days: int = None) -> dict:
    """Create a new API token for a user
    
    LW: Token is only returned once - we only store the hash
    MK: Permissions inherit from user role if not specified
    """
    ensure_api_tokens_table()
    users = load_users()
    user = users.get(username)
    if not user:
        return {'error': 'User not found'}
    
    # Default to user's own role if not specified
    if not role:
        role = user.get('role', ROLE_VIEWER)
    # NS Oct 2026 - straight from the JSON body: a list or an object is no role name,
    # and the hierarchy lookup below died on it with a TypeError (500)
    if not isinstance(role, str):
        return {'error': 'Invalid role'}

    # NS: Don't allow creating tokens with higher privileges than the user
    # MK: custom roles default to level 2 (user) not 1 (viewer) — prevents escalation
    role_hierarchy = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}
    user_level = role_hierarchy.get(user.get('role', ROLE_VIEWER), 2 if user.get('role') not in role_hierarchy else 1)
    token_level = role_hierarchy.get(role, 2 if role not in role_hierarchy else 1)
    if token_level > user_level:
        return {'error': 'Cannot create token with higher privileges than your own role'}
    # non-admins can't create admin tokens at all
    if role == ROLE_ADMIN and user.get('role') != ROLE_ADMIN:
        return {'error': 'Only admins can create admin tokens'}
    # sec (audit): the numeric hierarchy above scores EVERY custom role as level 2, so a plain
    # ROLE_USER (also 2) passed the check for any custom role name — and build_authz_user keeps a
    # non-builtin token role verbatim, so the token then resolved that role's permissions. Role
    # names are discoverable (GET /api/roles has no perm), which made this a self-service upgrade.
    # Compare the actual permission sets instead: a token may never carry a permission its owner
    # lacks. Admins hold everything, so their custom-role tokens are unaffected.
    if role not in role_hierarchy:
        try:
            from pegaprox.utils.rbac import (get_user_permissions, token_role_tenant,
                                              get_role_permissions_for_user, DEFAULT_TENANT_ID)
            _owner = dict(user, username=username)
            # Resolve BOTH sides in the owner's tenant. get_role_permissions_for_user only
            # consults tenant custom roles when it is given a tenant_id (rbac.py:161) — calling
            # it without one fell through to the viewer fallback, so _extra came out empty and
            # this guard passed every TENANT custom role: exactly the case it was written to
            # catch. Request time resolves the same role WITH the tenant, so the token then
            # carried the elevated set.
            _tid = _owner.get('tenant_id') or DEFAULT_TENANT_ID
            # NS Oct 2026 - and the token's side where request time resolves it. Another
            # tenant's role resolved to nothing here, so it passed, and the token then
            # acted in that tenant's clusters.
            _role_tid = token_role_tenant(_owner, role)
            if _role_tid is None:
                return {'error': 'This role is not defined in your tenant'}
            _owner_perms = set(get_user_permissions(_owner, _tid))
            _token_perms = set(get_role_permissions_for_user(dict(_owner, role=role), _role_tid))
            _extra = _token_perms - _owner_perms
            if _extra:
                return {'error': 'Cannot create token with permissions beyond your own role: '
                                 + ', '.join(sorted(_extra)[:5])}
        except Exception as _e:
            logging.warning(f"[APIToken] custom-role scope check failed for '{username}': {_e}")
            return {'error': 'Cannot verify token role permissions'}
    
    token, token_hash, prefix = generate_api_token()
    
    expires_at = None
    if expires_days:
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
    
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('''
            INSERT INTO api_tokens (token_hash, token_prefix, username, name, role, permissions, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token_hash, prefix, username, token_name, role, 
              json.dumps(permissions or []), expires_at, datetime.now().isoformat()))
        db.conn.commit()
        
        token_id = cursor.lastrowid
        logging.info(f"[APIToken] Created token '{token_name}' (pgx_{prefix}_...) for user '{username}' role={role}")
        
        return {
            'success': True,
            'token': token,  # Only returned once!
            'token_id': token_id,
            'prefix': prefix,
            'name': token_name,
            'role': role,
            'expires_at': expires_at
        }
    except Exception as e:
        # MK Sep 2026 (audit) — the caller gets this straight back as the JSON body, so a
        # persistence error handed the client raw backend text. The detail is already in
        # the log line above; the response only needs to say it did not work.
        logging.error(f"[APIToken] Failed to create token: {e}")
        return {'error': 'Failed to create API token'}


def revoke_user_api_tokens(username: str) -> int:
    """Revoke ALL of a user's API tokens. sec (private disclosure Sep 2026 — audit): a password
    change / admin reset already invalidates the user's sessions but NOT their pgx_ tokens, so an
    exfiltrated token survived the standard 'lock the intruder out' action. Called alongside
    invalidate_all_user_sessions. Returns the number of tokens removed."""
    try:
        ensure_api_tokens_table()
        db = get_db()
        cur = db.conn.cursor()
        cur.execute('DELETE FROM api_tokens WHERE username = ?', (username,))
        db.conn.commit()
        n = cur.rowcount or 0
        if n:
            logging.info(f"[APIToken] Revoked {n} token(s) for '{username}' on credential change")
        return n
    except Exception as e:
        logging.error(f"[APIToken] Failed to revoke tokens for '{username}': {e}")
        return 0


def validate_api_token(token: str) -> dict:
    """Validate an API token and return user info if valid
    
    MK: Returns same structure as validate_session for compatibility with require_auth
    """
    if not token or not token.startswith('pgx_'):
        return None
    
    ensure_api_tokens_table()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('''
            SELECT id, username, name, role, permissions, expires_at, revoked
            FROM api_tokens WHERE token_hash = ?
        ''', (token_hash,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        row_dict = dict(row)
        
        # LW: Check if revoked
        if row_dict.get('revoked'):
            return None
        
        # Check expiry
        if row_dict.get('expires_at'):
            expires = datetime.fromisoformat(row_dict['expires_at'])
            if datetime.now() > expires:
                return None
        
        # NS Oct 2026 - and on every use, not only at mint: tokens minted before that
        # check, an owner moved off the role or a role deleted or redefined since.
        _role = row_dict.get('role')
        if _role and _role not in (ROLE_ADMIN, ROLE_USER, ROLE_VIEWER):
            from pegaprox.utils.rbac import token_role_tenant
            _owner = db.get_user(row_dict['username'])
            if _owner and token_role_tenant(_owner, _role) is None:
                logging.warning(f"[APIToken] refused token id={row_dict['id']} of "
                                f"{row_dict['username']!r}: its role does not resolve in "
                                f"the owner's tenant")
                return None

        # Update last used timestamp
        cursor.execute('''
            UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?
        ''', (datetime.now().isoformat(), get_client_ip(), row_dict['id']))
        db.conn.commit()
        
        # Return session-compatible dict
        return {
            'user': row_dict['username'],
            'role': row_dict['role'],
            'login_time': row_dict.get('created_at', 0),
            'last_activity': time.time(),
            'api_token': True,  # NS: Flag to identify token auth vs session auth
            'token_name': row_dict['name'],
            'token_id': row_dict['id']
        }
    except Exception as e:
        logging.error(f"[APIToken] Validation error: {e}")
        return None


def ensure_api_tokens_table():
    """Ensure the api_tokens table exists (for upgrades without restart)"""
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                username TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                permissions TEXT DEFAULT '[]',
                expires_at TEXT,
                last_used_at TEXT,
                last_used_ip TEXT,
                created_at TEXT NOT NULL,
                revoked INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(username)')
        db.conn.commit()
    except Exception as e:
        logging.error(f"[APIToken] Table creation error: {e}")


def list_user_tokens(username: str) -> list:
    """List all API tokens for a user (without the actual token hash)"""
    ensure_api_tokens_table()
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('''
            SELECT id, token_prefix, name, role, permissions, expires_at, 
                   last_used_at, last_used_ip, created_at, revoked
            FROM api_tokens WHERE username = ? ORDER BY created_at DESC
        ''', (username,))
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"[APIToken] List error: {e}")
        return []


def revoke_api_token(token_id: int, username: str) -> bool:
    """Revoke an API token
    
    LW: Soft delete - we keep the record for audit trail
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        # NS: Only allow revoking own tokens unless admin
        cursor.execute('''
            UPDATE api_tokens SET revoked = 1 WHERE id = ? AND username = ?
        ''', (token_id, username))
        db.conn.commit()
        
        if cursor.rowcount > 0:
            logging.info(f"[APIToken] Revoked token id={token_id} for user '{username}'")
            return True
        return False
    except Exception as e:
        logging.error(f"[APIToken] Revoke error: {e}")
        return False


# where app.py's request handler hangs the clock on a request body (_BodyDeadline, #1052)
BODY_DEADLINE_ENVIRON = 'pegaprox.body_deadline'
# a body this small comes with its headers and keeps its clock: only an upload needs more
_SMALL_BODY = 64 * 1024


def lift_body_deadline(owner=None):
    """This request is somebody's: its body may take as long as the link needs.

    Until then a body has PEGAPROX_BODY_TIMEOUT seconds to arrive, which is what bounds how
    long an anonymous client holds a request slot. Called where a request is known to be
    signed in or signed: require_auth, a standby's forwarded write, a group member's call.
    Outside a request, or without the gevent server's clock, it does nothing.

    owner: the account behind it. A signed-in account could otherwise hold every slot with
    bodies it never sends, so a large one counts against the account like a WebSocket
    (realtime.hold_body) and a small one keeps its clock.
    """
    try:
        clock = request.environ.get(BODY_DEADLINE_ENVIRON)
    except RuntimeError:
        return
    if clock is None or clock.lifted:
        return
    if owner is None:
        clock.lift()
        return
    chunked = 'chunked' in (request.headers.get('Transfer-Encoding') or '').lower()
    if not chunked and (request.content_length or 0) <= _SMALL_BODY:
        return
    from pegaprox.utils.realtime import hold_body, release_body
    key = hold_body(owner)
    if key is None:
        from pegaprox.utils.sanitization import sanitize_log_message
        logging.info(f"[auth] a large request body of '{sanitize_log_message(str(owner))}' keeps "
                     f"its clock - the account holds its share of long requests")
        return
    clock.lift(release=lambda: release_body(key))


def require_auth(roles: list = None, perms: list = None):
    """auth decorator for protected routes

    MK: main auth guard - use on all protected routes
    LW: Feb 2026 - now also accepts API tokens (Bearer pgx_...)
    """
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session = None
            
            # MK: Feb 2026 - Check API token first (Authorization: Bearer pgx_...)
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer pgx_'):
                token = auth_header[7:]  # Strip 'Bearer '
                session = validate_api_token(token)
            
            # Fall back to session auth (X-Session-ID header or cookie)
            if not session:
                session_id = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
                session = validate_session(session_id)
            
            if not session:
                if request.environ.get(MFA_HELD_ENVIRON):
                    return jsonify({'error': 'Set up two-factor authentication first',
                                    'code': 'MFA_ENROLMENT_REQUIRED'}), 403
                return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
            
            # NS: Feb 2026 - Check if user was disabled while session/token is still active
            # H2 (scale audit): fetch ONLY the acting user (indexed, O(1)) instead of
            # SELECT *-ing + decrypting the entire users table on every authed request.
            # get_user() builds the identical dict get_all_users() would for this row.
            try:
                user = get_db().get_user(session['user'])
            except Exception:
                user = load_users().get(session['user'])
            # NS Jul 2026 (CodeAnt exploitation / off-boarding bypass) — FAIL CLOSED when the
            # acting user's record is gone. The old `get_user() or {}` swallowed a DELETED user
            # into {}, so `{}.get('enabled', True)` == True passed the disabled-check and
            # `fresh_role` fell back to the stale session role → a deleted user (or their still
            # valid pgx_ API token) kept access until the session expired. A missing record now
            # means "no longer exists" → reject. This covers BOTH session and API-token auth,
            # since both resolve the acting user here.
            if user is None:
                return jsonify({'error': 'Account no longer exists', 'code': 'ACCOUNT_DELETED'}), 401
            # stash for check_cluster_access et al. so cluster-scoped routes don't refetch
            try:
                from flask import g as _g
                _g.current_user = user
            except Exception:
                pass
            if not user.get('enabled', True):
                return jsonify({'error': 'Account is disabled', 'code': 'ACCOUNT_DISABLED'}), 401
            # MK Oct 2026 - a portal_only account reaches the Client Portal and nothing else,
            # by session or by one of its API tokens (PORTAL_ONLY_ENDPOINTS)
            if user.get('portal_only'):
                refused = portal_only_refusal(user)
                if refused:
                    return refused

            # MK May 2026 (CodeAnt CWE-269) — DO NOT refresh role from the user record
            # when this is an API-token session. The token has its own role bound at
            # creation (e.g. an admin creating a 'viewer' token for CI/CD); refreshing
            # to user.role would silently escalate every restricted token to its
            # owner's current global role. For session-auth (interactive login) we
            # still refresh so an admin-side role change applies on the next request.
            if session.get('api_token'):
                # Floor at min(token_role, user_current_role) — if user got demoted
                # since token creation, follow them down so the token can't outrank
                # its owner. Won't auto-escalate.
                _hier = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}
                token_lvl = _hier.get(session.get('role'), 1)
                user_lvl = _hier.get(user.get('role'), 1)
                eff_lvl = min(token_lvl, user_lvl)
                fresh_role = next((r for r, lvl in _hier.items() if lvl == eff_lvl), ROLE_VIEWER)
                # Don't mutate session['role'] — keep the original token-bound value
                # in the session dict for audit/log purposes; fresh_role drives the
                # role check below.
            else:
                # NS Mar 2026 - refresh role from DB, session might be stale after admin change
                fresh_role = user.get('role', session['role'])
                if fresh_role != session['role']:
                    session['role'] = fresh_role

            # NS Oct 2026 (#1000, #1028) - an admin a tenant override lowers where they live is
            # that role here as well. has_permission already answered so, but roles=[ROLE_ADMIN]
            # compared the stored role and let them run every admin-only route, the scheduled
            # tasks against any cluster's guests among them. Published below as effective_role.
            _lowered = False
            if fresh_role == ROLE_ADMIN:
                from pegaprox.utils.rbac import _admin_is_capped_in_own_tenant, get_user_effective_role
                if _admin_is_capped_in_own_tenant(user):
                    fresh_role, _lowered = get_user_effective_role(user), True

            # Check role if specified
            if roles and fresh_role not in roles:
                if _lowered:
                    return jsonify({'error': 'Forbidden: a tenant mapping lowers this account '
                                             'below administrator',
                                    'code': 'INSUFFICIENT_PERMISSIONS'}), 403
                return jsonify({'error': 'Forbidden', 'code': 'INSUFFICIENT_PERMISSIONS'}), 403
            
            # check permissions if specified
            if perms:
                from pegaprox.utils.rbac import has_permission
                # H-3 (security audit): for API-token auth, evaluate perms against the
                # token's effective (floored) ROLE — never the owner's. has_permission()
                # short-circuits True for an admin user, so checking the owner dict let an
                # admin-owned 'viewer' token inherit every permission on perms=-guarded
                # routes (priv-esc). fresh_role already floors token_role to the owner's
                # current role (can't escalate, follows demotions). We scope to the role's
                # own permissions only — the owner's interactive extra perms / group grants
                # do NOT extend to a token — while still honouring the owner's denials.
                if session.get('api_token'):
                    # NS Oct 2026 (#1014) - the identity build_authz_user hands the route, so
                    # gate and route agree. The inline copy capped a tenant override's role by
                    # its builtin level only: a custom tenant role (level 1) went through whole,
                    # so a viewer token carried node.shell or admin.users wherever its owner's
                    # override granted them, and a custom-role token was judged as a viewer.
                    perm_user = apply_token_role(dict(user, username=session['user']),
                                                 session.get('role'))
                else:
                    perm_user = user
                for p in perms:
                    if not has_permission(perm_user, p):
                        return jsonify({'error': 'Permission denied', 'code': 'MISSING_PERMISSION', 'required': p}), 403
            
            # Add session info to request context
            # sec (audit): publish the floored role here. Several routes gate on
            # `session.get('effective_role', session.get('role'))` — for token auth session['role']
            # is deliberately left at the token's declared value (audit/logging), so without this
            # every one of those guards read a stale role and silently did nothing. fresh_role is
            # already min(token, owner) for tokens and the DB-refreshed role for sessions.
            # A non-builtin (custom) token role keeps its NAME here, matching build_authz_user
            # (auth.py:334) — collapsing it to a builtin level would make the two disagree about
            # the same request, and it is the name that lets get_user_clusters do the
            # custom-role -> tenant remap.
            _eff_pub = fresh_role
            if session.get('api_token'):
                _tr = session.get('role')
                if _tr and _tr not in (ROLE_ADMIN, ROLE_USER, ROLE_VIEWER):
                    _eff_pub = _tr
            session = {**session, 'effective_role': _eff_pub}
            request.session = session
            # signed in and allowed: the body is no longer an anonymous one (#1052)
            lift_body_deadline(session['user'])

            return f(*args, **kwargs)
        # MK Sep 2026 - publish what this route demands so the OpenAPI generator can
        # read it instead of re-deriving it from the decorator source. functools.wraps
        # copies __dict__ from f, so this has to be set AFTER the wrapper is built or
        # a stacked decorator underneath would overwrite it.
        decorated_function._pp_auth = {'roles': list(roles or []), 'perms': list(perms or [])}
        return decorated_function
    return decorator

def cleanup_expired_sessions():
    """Remove expired sessions

    PR #60 (ry-ops): Snapshot active_sessions into a list before filtering
    to prevent RuntimeError: dictionary changed size during iteration under
    concurrent load. Use pop() instead of del to handle sessions already
    removed by another thread.
    NS: Feb 2026 - Added sessions_lock for thread safety
    """
    current_time = time.time()
    timeout = get_session_timeout()
    with sessions_lock:
        expired = [sid for sid, session in list(active_sessions.items())
                   if current_time - session.get('last_activity', 0) > timeout]
        for sid in expired:
            active_sessions.pop(sid, None)
    if expired:
        logging.debug(f"Cleaned up {len(expired)} expired sessions")
