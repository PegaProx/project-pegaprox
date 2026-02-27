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
    SESSION_TIMEOUT, CONFIG_DIR, USERS_FILE_ENCRYPTED,
    SESSIONS_FILE, SESSIONS_FILE_ENCRYPTED, ADMIN_INITIALIZED_FILE,
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


def get_session_timeout():
    """Get session timeout from server settings (late import to avoid circular dependency)"""
    try:
        from pegaprox.api.helpers import load_server_settings
        settings = load_server_settings()
        return settings.get('session_timeout', SESSION_TIMEOUT)
    except:
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


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    """verify pw - handles both argon2 and old pbkdf2
    
    NS: Order matters! salt first, then hash
    """
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


def load_users() -> dict:
    """load users from db"""
    # MK: migrated from json files, was a pain
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
        logging.error(f"db load failed: {e}")
        return _load_users_legacy()  # fallback to old format
    
    # no users found
    if os.path.exists(ADMIN_INITIALIZED_FILE):
        # dont recreate admin if it was deleted on purpose
        logging.error("users missing but admin was initialized - wont recreate")
        return {}
    
    logging.info("no users, creating default admin")
    default_users = create_default_users()
    save_users(default_users)
    return default_users


def _load_users_legacy() -> dict:
    """old json loader, just for migration"""
    fernet = get_fernet()
    
    if fernet and os.path.exists(USERS_FILE_ENCRYPTED):
        try:
            with open(USERS_FILE_ENCRYPTED, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            users = json.loads(decrypted_data.decode('utf-8'))
            logging.info(f"loaded {len(users)} users from legacy file")
            return users
        except Exception as e:
            logging.error(f"legacy load failed: {e}")
    
    return {}


def save_users(users: dict):
    """save users to db"""
    try:
        db = get_db()
        db.save_all_users(users)
        # logging.debug(f"saved {len(users)} users")
    except Exception as e:
        logging.error(f"save failed: {e}")

def mark_admin_initialized():
    """mark admin as customized so we dont recreate it"""
    try:
        with open(ADMIN_INITIALIZED_FILE, 'w') as f:
            f.write(datetime.now().isoformat())
        os.chmod(ADMIN_INITIALIZED_FILE, 0o600)
    except Exception as e:
        logging.error(f"couldnt mark admin init: {e}")

def create_default_users() -> dict:
    """create default admin - pw is 'admin', should be changed obv"""
    salt, password_hash = hash_password('admin')
    
    return {
        'pegaprox': {
            'password_salt': salt,
            'password_hash': password_hash,
            'role': ROLE_ADMIN,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'display_name': 'PegaProx Admin',
            'email': '',
            'enabled': True,
            'is_default': True  # Flag to identify default admin
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
        
        # Save to database
        db = get_db()
        db.save_all_sessions(active_sessions)
        
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
        except:
            pass
    elif os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, 'r') as f:
                active_sessions = json.load(f)
            logging.info(f"Loaded {len(active_sessions)} sessions from legacy JSON file")
        except:
            pass

def create_session(username: str, role: str) -> str:
    """Create a new session for a user

    NS: Also does session rotation - invalidates old sessions for same user
    This prevents session fixation attacks and limits concurrent sessions
    """
    session_id = generate_session_id()

    # NS: Feb 2026 - SECURITY: lock dict mutations only, not I/O
    with sessions_lock:
        # Session rotation: invalidate existing sessions for this user
        # MK: keep max 3 sessions per user (browser, phone, etc)
        user_sessions = [(sid, sess) for sid, sess in active_sessions.items()
                         if sess.get('user') == username]

        # Sort by last_activity, remove oldest if more than 2 (new one will be 3rd)
        if len(user_sessions) >= 3:
            user_sessions.sort(key=lambda x: x[1].get('last_activity', 0))
            # Remove oldest sessions, keep 2
            for sid, _ in user_sessions[:-2]:
                del active_sessions[sid]
                logging.debug(f"Session rotation: removed old session for {username}")

        active_sessions[session_id] = {
            'user': username,
            'role': role,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip': request.remote_addr if request else None,  # track IP for auditing
            'user_agent': request.headers.get('User-Agent', '')[:200] if request else None
        }

    # Save sessions to disk (outside lock - I/O operation)
    save_sessions()

    return session_id

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

        # check session has expired
        if time.time() - session['last_activity'] > get_session_timeout():
            del active_sessions[session_id]
            expired = True
        else:
            # Update last activity
            session['last_activity'] = time.time()

    if expired:
        save_sessions()
        return None

    return session

def invalidate_session(session_id: str):
    """Invalidate a session (logout)"""
    removed = False
    with sessions_lock:
        if session_id in active_sessions:
            del active_sessions[session_id]
            removed = True
    if removed:
        save_sessions()

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
    
    # NS: Don't allow creating tokens with higher privileges than the user
    role_hierarchy = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}
    user_level = role_hierarchy.get(user.get('role', ROLE_VIEWER), 1)
    token_level = role_hierarchy.get(role, 1)
    if token_level > user_level:
        return {'error': 'Cannot create token with higher privileges than your own role'}
    
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
        logging.error(f"[APIToken] Failed to create token: {e}")
        return {'error': str(e)}


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
        
        # Update last used timestamp
        cursor.execute('''
            UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?
        ''', (datetime.now().isoformat(), request.remote_addr, row_dict['id']))
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
                return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
            
            # NS: Feb 2026 - Check if user was disabled while session/token is still active
            users = load_users()
            user = users.get(session['user'], {})
            if not user.get('enabled', True):
                return jsonify({'error': 'Account is disabled', 'code': 'ACCOUNT_DISABLED'}), 401
            
            # Check role if specified
            if roles and session['role'] not in roles:
                return jsonify({'error': 'Forbidden', 'code': 'INSUFFICIENT_PERMISSIONS'}), 403
            
            # check permissions if specified
            if perms:
                from pegaprox.utils.rbac import has_permission
                for p in perms:
                    if not has_permission(user, p):
                        return jsonify({'error': 'Permission denied', 'code': 'MISSING_PERMISSION', 'required': p}), 403
            
            # Add session info to request context
            request.session = session
            
            return f(*args, **kwargs)
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

