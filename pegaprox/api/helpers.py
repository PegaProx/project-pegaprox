# -*- coding: utf-8 -*-
"""shared helpers for all api routes - split from monolith dec 2025, NS"""

import os
import json
import time
import logging
from datetime import datetime

from pegaprox.constants import (
    SESSION_TIMEOUT, SERVER_SETTINGS_FILE,
    LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_TIME, LOGIN_ATTEMPT_WINDOW,
    TASK_USER_CACHE_TTL,
)
from pegaprox.globals import (
    cluster_managers, active_sessions, users_db,
    task_pegaprox_users_cache, task_pegaprox_users_lock,
)
from pegaprox.core.db import get_db

def load_server_settings():
    """Load server settings from SQLite database
    
    SQLite migration
    """
    defaults = {
        'domain': '',
        'port': 5000,  # Web server port
        'ssl_enabled': False,
        'logo_url': '',
        'app_name': 'PegaProx',
        # HTTP redirect port - NS Jan 2026
        # Now that we have protocol detection on the main port, this is only needed
        # if you want HTTP:80 → HTTPS:5000 redirect
        # 0 = auto (80 if root, disabled otherwise), -1 = disabled, or specific port
        'http_redirect_port': -1,  # Disabled by default - protocol detection handles same-port redirect
        # Brute force protection settings
        'login_max_attempts': 5,
        'login_lockout_time': 300,  # 5 min
        'login_attempt_window': 600,  # 10 min
        # Password policy settings
        'password_min_length': 8,
        'password_require_uppercase': True,
        'password_require_lowercase': True,
        'password_require_numbers': True,
        'password_require_special': False,  # too annoying for most users
        # LW: Password expiry - Dec 2025
        'password_expiry_enabled': False,  # disabled by default
        'password_expiry_days': 90,  # days until password expires
        'password_expiry_warning_days': 14,  # warn this many days before
        'password_expiry_email_enabled': True,  # send email notifications
        'password_expiry_include_admins': False,  # MK: opt-in for admins, otherwise they could lock themselves out
        # Session settings
        'session_timeout': SESSION_TIMEOUT,  # Use constant (8h HIPAA default)
        # NS: SMTP Settings - Dec 2025
        'smtp_enabled': False,
        'smtp_host': '',
        'smtp_port': 587,
        'smtp_user': '',
        'smtp_password': '',  # stored encrypted ideally
        'smtp_from_email': '',
        'smtp_from_name': 'PegaProx Alerts',
        'smtp_tls': True,
        'smtp_ssl': False,
        # Alert notification settings
        'alert_email_recipients': [],  # list of email addresses
        'alert_cooldown': 300,  # Don't send same alert within 5 min
        # IP Whitelisting - Jan 2026
        'ip_whitelist_enabled': False,
        'ip_whitelist': '',  # Comma-separated IPs/CIDRs
        'ip_blacklist': '',  # Comma-separated IPs/CIDRs (always blocked)
        # NS: Feb 2026 - LDAP defaults (must be here so get_ldap_settings always has values!)
        # Without these, a partial save (e.g. only ldap_enabled=True) causes "LDAP not configured"
        'ldap_enabled': False,
        'ldap_server': '',
        'ldap_port': 389,
        'ldap_use_ssl': False,
        'ldap_use_starttls': False,
        'ldap_bind_dn': '',
        'ldap_bind_password': '',
        'ldap_base_dn': '',
        'ldap_user_filter': '(&(objectClass=person)(sAMAccountName={username}))',
        'ldap_username_attribute': 'sAMAccountName',
        'ldap_email_attribute': 'mail',
        'ldap_display_name_attribute': 'displayName',
        'ldap_group_base_dn': '',
        'ldap_group_filter': '(&(objectClass=group)(member={user_dn}))',
        'ldap_admin_group': '',
        'ldap_user_group': '',
        'ldap_viewer_group': '',
        'ldap_default_role': 'viewer',
        'ldap_auto_create_users': True,
        'ldap_group_mappings': [],
        # OIDC defaults
        'oidc_enabled': False,
        'oidc_provider': 'entra',
        'oidc_cloud_environment': 'commercial',  # NS: commercial, gcc, gcc_high, dod
        'oidc_client_id': '',
        'oidc_client_secret': '',
        'oidc_tenant_id': '',
        'oidc_authority': '',
        'oidc_scopes': 'openid profile email',
        'oidc_redirect_uri': '',
        'oidc_admin_group_id': '',
        'oidc_user_group_id': '',
        'oidc_viewer_group_id': '',
        'oidc_default_role': 'viewer',
        'oidc_auto_create_users': True,
        'oidc_button_text': 'Sign in with Microsoft',
        'oidc_group_mappings': [],
    }
    
    try:
        db = get_db()
        saved = db.get_server_settings()
        if saved:
            # Merge with defaults (so new fields are always present)
            return {**defaults, **saved}
    except Exception as e:
        logging.error(f"Error loading server settings from database: {e}")
        # Try legacy fallback
        if os.path.exists(SERVER_SETTINGS_FILE):
            try:
                with open(SERVER_SETTINGS_FILE, 'r') as f:
                    saved = json.load(f)
                return {**defaults, **saved}
            except:
                pass
    
    return defaults


def save_server_settings(settings):
    """Save server settings to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        db.save_server_settings(settings)
        return True
    except Exception as e:
        logging.error(f"Error saving server settings: {e}")
        return False


def get_session_timeout():
    # get timeout from settings
    try:
        settings = load_server_settings()
        return settings.get('session_timeout', SESSION_TIMEOUT)
    except:
        return SESSION_TIMEOUT  # fallback

def _fmt_size(size_bytes):
    # NS: simple bytes formatter, nothing fancy
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/1024**2:.1f} MB"
    else:
        return f"{size_bytes/1024**3:.1f} GB"
    # TODO: add TB support? probably overkill

def get_login_settings():
    # MK: pulled these out to be configurable via settings
    try:
        settings = load_server_settings()
    except:
        settings = {}  # w/e just use defaults
    return {
        'max_attempts': settings.get('login_max_attempts', LOGIN_MAX_ATTEMPTS),
        'lockout_time': settings.get('login_lockout_time', LOGIN_LOCKOUT_TIME),
        'attempt_window': settings.get('login_attempt_window', LOGIN_ATTEMPT_WINDOW)
    }

def register_task_user(upid: str, username: str, cluster_id: str = None):
    """Register which PegaProx user initiated a task - persists to database"""
    if not upid or not username:
        return
    
    # Update in-memory cache
    with task_pegaprox_users_lock:
        task_pegaprox_users_cache[upid] = {'user': username, 'timestamp': time.time()}
    
    # Persist to database
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO task_users (upid, username, cluster_id, created_at)
            VALUES (?, ?, ?, ?)
        ''', (upid, username, cluster_id, datetime.now().isoformat()))
        db.conn.commit()
    except Exception as e:
        logging.debug(f"Failed to persist task user to DB: {e}")

def get_task_user(upid: str) -> str:
    """Get PegaProx user who initiated a task - checks cache first, then database"""
    if not upid:
        return None
    
    # Check in-memory cache first (fast path)
    with task_pegaprox_users_lock:
        data = task_pegaprox_users_cache.get(upid)
        if data:
            return data.get('user')
    
    # Check database (slow path, but persists across restarts)
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT username FROM task_users WHERE upid = ?', (upid,))
        row = cursor.fetchone()
        if row:
            username = row[0]
            # Update cache for future lookups
            with task_pegaprox_users_lock:
                task_pegaprox_users_cache[upid] = {'user': username, 'timestamp': time.time()}
            return username
    except Exception as e:
        logging.debug(f"Failed to get task user from DB: {e}")
    
    return None



def get_connected_manager(cluster_id):
    """Get a cluster manager, return (manager, None) if connected, (None, error_response) if not"""
    from flask import jsonify
    if cluster_id not in cluster_managers:
        return None, (jsonify({'error': 'Cluster not found'}), 404)
    manager = cluster_managers[cluster_id]
    if not manager.is_connected:
        return None, (jsonify({
            'error': 'Cluster not connected',
            'offline': True,
            'connection_error': manager.connection_error
        }), 503)
    return manager, None

def check_cluster_access(cluster_id):
    """Check if current user can access a cluster based on tenant.
    Returns (True, None) if allowed, (False, error_response) if not.
    """
    from flask import request, jsonify
    from pegaprox.utils.auth import load_users
    from pegaprox.utils.rbac import get_user_clusters
    users = load_users()
    user = users.get(request.session['user'], {})
    allowed = get_user_clusters(user)
    if allowed is not None and cluster_id not in allowed:
        return False, (jsonify({'error': 'Access denied to this cluster'}), 403)
    return True, None
