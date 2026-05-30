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
        # MK: Mar 2026 - ACME / Let's Encrypt auto-certs (#96)
        'acme_enabled': False,
        'acme_email': '',
        'acme_staging': False,  # use LE staging for testing
        'acme_challenge_type': 'http-01',
        'acme_dns_provider': 'manual',
        'acme_dns_rfc2136_nameserver': '',
        'acme_dns_rfc2136_port': 53,
        'acme_dns_rfc2136_zone': '',
        'acme_dns_rfc2136_key_name': '',
        'acme_dns_rfc2136_secret': '',
        'acme_dns_rfc2136_algorithm': 'hmac-sha512',
        'acme_dns_rfc2136_ttl': 60,
        'acme_dns_propagation_seconds': 30,
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
        # NS Apr 2026 (#331) — email notification when a new PegaProx release appears.
        # Opt-in; re-uses alert_email_recipients. Dedupes via last-notified-version.
        'alert_update_available': False,
        'alert_last_notified_version': '',
        # NS 2026-04-24 — when true, validate_session() invalidates a session if the
        # source IP changes. Default off because mobile roaming / carrier NAT
        # legitimately shifts IPs mid-session.
        'strict_session_ip': False,
        # MK Apr 2026 — when true, /api/metrics needs no auth. Useful for setups
        # where a reverse proxy/mutual-TLS already gates scrapes. Default off.
        'metrics_public': False,
        # When enabled, the Syslog viewer only shows hostnames belonging to
        # the currently selected cluster instead of all collected syslog rows.
        'syslog_filter_by_selected_cluster': False,
        # Webhook alert channels (Slack, Discord, Teams, ntfy, generic)
        # Each: {id, name, type, url, enabled, ...type-specific fields}
        'alert_webhooks': [],
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
        # NS: Mar 2026 - reverse proxy support (nginx/haproxy)
        'reverse_proxy_enabled': False,
        'trusted_proxies': '',  # comma-separated IPs/CIDRs, empty = loopback only
        'proxy_bind_address': '',  # custom bind addr when behind proxy on different host
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
        'oidc_skip_jwt_verification': False,  # NS: disable JWT sig check for broken JWKS envs
        'oidc_skip_ssl_verify': False,        # NS Apr 2026 (#188): self-signed-cert escape hatch
        # MK May 2026 (#412 SeeJayEmm): SSRF guard's default behaviour rejects
        # any discovery URL that resolves to a private/loopback IP. Internal IdPs
        # (Keycloak/Authentik/Authentik-on-LAN at 10.x or 192.168.x) are the
        # exact use case that breaks. Opt-in knob to relax the guard for the
        # OIDC discovery path SPECIFICALLY — metadata IPs (169.254.169.254
        # etc.) are still rejected, and the guard remains on for all other
        # outbound paths (webhook, SAML metadata fetch, plugin upstream).
        'oidc_allow_private_ip': False,
        # NS May 2026 (PVE 9.2 parity) — extra audiences (comma-separated)
        # accepted on the JWT verify alongside the client_id.
        'oidc_audiences': '',
    }
    
    try:
        db = get_db()
        saved = db.get_server_settings()
        if saved:
            # Merge with defaults (so new fields are always present)
            return {**defaults, **saved}
    except Exception as e:
        logging.error(f"Error loading server settings from database: {e}")
        # NS May 2026 - plain-JSON SERVER_SETTINGS_FILE fallback removed (encrypted DB only).

    return defaults


def decrypt_secret_setting(value, *, label='secret'):
    """Decrypt an encrypted server setting, preserving legacy plaintext values."""
    if not value or value == '********':
        return ''
    try:
        return get_db()._decrypt(str(value))
    except RuntimeError as e:
        logging.error(f"Failed to decrypt {label}: {e}")
        return ''
    except Exception as e:
        if str(value).startswith(('aes256:', 'gAAAA')):
            logging.error(f"Could not decrypt encrypted {label}: {e}")
            return ''
        logging.warning(f"Could not decrypt {label}; treating as legacy plaintext: {e}")
        return str(value)


def acme_dns_config_from_settings(settings):
    """Build an RFC 2136 DNS config, decrypting the TSIG secret only for use."""
    settings = settings or {}
    return {
        'nameserver': settings.get('acme_dns_rfc2136_nameserver', ''),
        'port': settings.get('acme_dns_rfc2136_port', 53),
        'zone': settings.get('acme_dns_rfc2136_zone', ''),
        'key_name': settings.get('acme_dns_rfc2136_key_name', ''),
        'secret': decrypt_secret_setting(
            settings.get('acme_dns_rfc2136_secret', ''),
            label='ACME RFC 2136 secret'
        ),
        'algorithm': settings.get('acme_dns_rfc2136_algorithm', 'hmac-sha512'),
        'ttl': settings.get('acme_dns_rfc2136_ttl', 60),
        'propagation_seconds': settings.get('acme_dns_propagation_seconds', 30),
    }


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
    """Check if current user can access a cluster based on tenant or VM ACLs.
    Returns (True, None) if allowed, (False, error_response) if not.
    """
    from flask import request, jsonify
    from pegaprox.utils.auth import load_users
    from pegaprox.utils.rbac import get_user_clusters
    users = load_users()
    user = users.get(request.session['user'], {})
    allowed = get_user_clusters(user)
    if allowed is not None and cluster_id not in allowed:
        # #248: check VM ACLs as fallback — users with VM-level access can reach the cluster
        username = request.session.get('user', '')
        from pegaprox.utils.rbac import load_vm_acls
        cluster_acls = load_vm_acls().get(cluster_id, {})
        for vmid, acl in cluster_acls.items():
            if username in acl.get('users', []) or '*' in acl.get('users', []):
                return True, None
        return False, (jsonify({'error': 'Access denied to this cluster'}), 403)
    return True, None


def check_pbs_access(pbs_id):
    """Check if current user can access a PBS server based on its linked clusters.
    Returns (True, None) if allowed, (False, error_response) if not.
    
    A PBS server is accessible if:
    - User is admin (full access), OR
    - PBS has no linked_clusters (backward compatibility - accessible to all), OR
    - User has access to at least one of the PBS's linked clusters
    """
    from flask import request, jsonify
    from pegaprox.utils.auth import load_users
    from pegaprox.utils.rbac import get_user_clusters
    from pegaprox.globals import pbs_managers
    from pegaprox.models.permissions import ROLE_ADMIN
    
    # Check if PBS exists
    if pbs_id not in pbs_managers:
        return False, (jsonify({'error': 'PBS server not found'}), 404)
    
    pbs_mgr = pbs_managers[pbs_id]
    users = load_users()
    user = users.get(request.session['user'], {})
    
    # Admins have full access
    if user.get('role') == ROLE_ADMIN:
        return True, None
    
    # Get PBS linked clusters
    pbs_linked = pbs_mgr.linked_clusters or []
    
    # If PBS has no linked clusters, allow access (backward compatibility)
    if not pbs_linked:
        return True, None
    
    # Get user's allowed clusters
    user_clusters = get_user_clusters(user)
    
    # If user has access to all clusters (None), allow
    if user_clusters is None:
        return True, None
    
    # Check if user has access to at least one linked cluster
    for cluster_id in pbs_linked:
        if cluster_id in user_clusters:
            return True, None
    
    return False, (jsonify({'error': 'Access denied to this PBS server'}), 403)


def safe_error(e, default_msg='An internal error occurred'):
    """Return a safe error message for API responses.
    MK Feb 2026 - logs full exception but returns generic message to client.
    Prevents leaking internal paths, stack traces, and DB details.
    """
    logging.error(f"[API] {default_msg}: {e}", exc_info=True)
    return default_msg


def parse_pve_error(response_text, fallback='Proxmox API error'):
    """Extract user-friendly error from Proxmox API response.
    PVE returns JSON like {"data":null,"message":"some error\\n"} or plain text.

    MK May 2026 — defense-in-depth: HTML-escape the extracted message before
    returning. Reflecting raw upstream response text into our JSON error
    field gets flagged by Snyk Code as reflected-XSS-via-JSON even though
    Flask's jsonify sets Content-Type: application/json (which prevents
    browser execution). Escaping makes the trace clean and gives us a
    safety net if a future code path returns this string as text/html.
    """
    import html
    if not response_text:
        return fallback
    try:
        import json
        # PVE often has literal newlines in JSON strings — strip them
        cleaned = response_text.replace('\n', ' ').replace('\r', '')
        data = json.loads(cleaned)
        msg = data.get('message') or data.get('errors') or data.get('error')
        if isinstance(msg, dict):
            msg = '; '.join(f"{k}: {v}" for k, v in msg.items())
        if msg:
            return html.escape(str(msg).strip()[:500])
    except (json.JSONDecodeError, ValueError, AttributeError):
        pass
    # plain text — truncate and clean
    text = response_text.strip()[:200]
    if '<html' in text.lower():
        return fallback
    return html.escape(text) if text else fallback
