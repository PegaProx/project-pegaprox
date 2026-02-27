# -*- coding: utf-8 -*-
"""user management, tenants, roles & ACL routes - split from monolith dec 2025, NS/MK"""

import json
import time
import logging
import re
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import (
    hash_password, verify_password, validate_password_policy,
    load_users, save_users, require_auth, ARGON2_AVAILABLE,
    mark_admin_initialized, invalidate_all_user_sessions,
)
from pegaprox.utils.audit import log_audit
from pegaprox.utils.rbac import (
    load_custom_roles, save_custom_roles, get_custom_roles, invalidate_roles_cache,
    get_role_permissions_for_user, load_tenants, save_tenants,
    get_user_permissions, has_permission, get_user_effective_role,
    get_user_clusters, filter_clusters_for_user,
    load_vm_acls, save_vm_acls, get_vm_acls, invalidate_vm_acls_cache,
    user_can_access_vm, get_user_vms,
    get_pool_membership_cache, invalidate_pool_cache, get_vm_pool_cached,
    DEFAULT_TENANT_ID, ROLE_TEMPLATES,
)
from pegaprox.api.helpers import load_server_settings, save_server_settings, get_login_settings, check_cluster_access

bp = Blueprint('users', __name__)

@bp.route('/api/user/preferences', methods=['GET'])
@require_auth()
def get_user_preferences():
    """Get current user's preferences (theme, language, ui_layout, taskbar_auto_expand)"""
    username = request.session['user']
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    settings = load_server_settings()
    default_theme = settings.get('default_theme', 'proxmoxDark')
    
    return jsonify({
        'theme': user.get('theme', '') or default_theme,
        'language': user.get('language', ''),
        'ui_layout': user.get('ui_layout', 'modern'),
        'taskbar_auto_expand': user.get('taskbar_auto_expand', True),  # NS: Default true for backward compat
        'default_theme': default_theme
    })


@bp.route('/api/user/preferences', methods=['PUT'])
@require_auth()
def update_user_preferences():
    """Update current user's preferences (theme, language, ui_layout)"""
    global users_db
    
    username = request.session['user']
    data = request.get_json() or {}
    
    logging.info(f"update_user_preferences: user={username}, data={data}")
    
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    
    logging.info(f"update_user_preferences: user before update: ui_layout={user.get('ui_layout')}")
    
    # Only allow specific fields to be updated
    allowed_themes = [
        'proxmoxDark', 'proxmoxLight', 'midnight', 'forest', 'rose', 'ocean',
        'highContrast', 'dracula', 'nord', 'monokai', 'matrix', 'sunset',
        'cyberpunk', 'github', 'solarizedDark', 'gruvbox',
        'corporateDark', 'corporateLight', 'enterpriseBlue'  # NS: Corporate themes
    ]
    
    if 'theme' in data:
        theme = data['theme']
        if theme == '' or theme in allowed_themes:
            user['theme'] = theme
        else:
            return jsonify({'error': f'Invalid theme: {theme}'}), 400
    
    if 'language' in data:
        # Allow common language codes
        lang = data['language']
        if lang == '' or lang in ['en', 'de', 'es', 'fr', 'it', 'pt', 'nl', 'pl', 'ru', 'zh', 'ja', 'ko']:
            user['language'] = lang
        else:
            return jsonify({'error': f'Invalid language: {lang}'}), 400
    
    # NS: UI Layout - Jan 2026
    if 'ui_layout' in data:
        layout = data['ui_layout']
        if layout in ['modern', 'classic', 'corporate']:
            user['ui_layout'] = layout
            logging.info(f"update_user_preferences: Setting ui_layout to '{layout}' for user '{username}'")
        else:
            return jsonify({'error': f'Invalid layout: {layout}'}), 400
    
    # NS: TaskBar auto-expand preference - Feb 2026
    if 'taskbar_auto_expand' in data:
        user['taskbar_auto_expand'] = bool(data['taskbar_auto_expand'])
    
    # Save only this user, not all users
    db = get_db()
    db.save_user(username, user)
    
    logging.info(f"User '{username}' updated preferences: theme={user.get('theme')}, language={user.get('language')}, ui_layout={user.get('ui_layout')}, taskbar_auto_expand={user.get('taskbar_auto_expand')}")
    log_audit(username, 'user.preferences_updated', f"Updated preferences: theme={user.get('theme')}, layout={user.get('ui_layout')}")
    
    settings = load_server_settings()
    default_theme = settings.get('default_theme', 'proxmoxDark')
    
    return jsonify({
        'success': True,
        'theme': user.get('theme', '') or default_theme,
        'language': user.get('language', ''),
        'ui_layout': user.get('ui_layout', 'modern'),
        'taskbar_auto_expand': user.get('taskbar_auto_expand', True),
        'default_theme': default_theme
    })


@bp.route('/api/users/<username>/2fa', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def admin_disable_2fa(username):
    """Admin: Disable 2FA for a user"""
    global users_db
    
    username = username.lower()
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    user['totp_enabled'] = False
    user.pop('totp_secret', None)
    user.pop('totp_pending_secret', None)
    save_users(users_db)
    
    logging.info(f"Admin '{request.session['user']}' disabled 2FA for user '{username}'")
    log_audit(request.session['user'], '2fa.admin_disabled', f"Admin disabled 2FA for user: {username}")
    
    return jsonify({'success': True, 'message': f'2FA for {username} disabled'})


@bp.route('/api/users/<username>/password', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def admin_change_password(username):
    """Admin: Change password for any user
    
    MK: Important - this invalidates ALL sessions for the user
    Even if admin is resetting their own password (edge case but possible)
    """
    global users_db
    
    username = username.lower()
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    new_password = data.get('password', '')
    
    # Validate password policy
    is_valid, error_msg = validate_password_policy(new_password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    user = users_db[username]
    
    # NS: Block password reset for LDAP/OIDC users - their password is managed externally
    if user.get('auth_source', 'local') in ('ldap', 'oidc', 'entra'):
        provider_name = {'ldap': 'LDAP/Active Directory', 'oidc': 'OIDC provider', 'entra': 'Microsoft Entra ID'}.get(user['auth_source'], 'identity provider')
        return jsonify({'error': f"This user authenticates via {provider_name}. Password must be changed there, or switch auth source to 'local' first."}), 400
    
    salt, password_hash = hash_password(new_password)
    user['password_salt'] = salt
    user['password_hash'] = password_hash
    user['password_changed_at'] = datetime.now().isoformat()  # LW: reset expiry
    
    # Mark that admin has been customized (prevents reset on restart)
    if user.get('is_default'):
        user['is_default'] = False
        mark_admin_initialized()
    
    save_users(users_db)
    
    # Invalidate ALL sessions for this user (security: force re-login)
    # NS: use helper function which also persists the change
    sessions_removed = invalidate_all_user_sessions(username)
    
    logging.info(f"Admin '{request.session['user']}' changed password for user '{username}'")
    log_audit(request.session['user'], 'user.password_reset', f"Admin reset password for user: {username} ({sessions_removed} sessions invalidated)")
    
    return jsonify({'success': True, 'message': f'Password for {username} changed', 'sessions_invalidated': sessions_removed})


# ============================================

# ============================================

@bp.route('/api/users', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_users():
    """Get list of all users (admin only)"""
    users_db = load_users()
    
    # Return users without password info
    users_list = []
    for username, user in users_db.items():
        users_list.append({
            'username': username,
            'role': user['role'],
            'display_name': user.get('display_name', username),
            'email': user.get('email', ''),
            'enabled': user.get('enabled', True),
            'totp_enabled': user.get('totp_enabled', False),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'tenant_id': user.get('tenant_id', DEFAULT_TENANT_ID),  # MK: Added for tenant display
            'auth_source': user.get('auth_source', 'local'),  # NS: For LDAP/Entra/OIDC badge in user list
            'permissions': user.get('permissions', []),  # LW: For permission display
        })
    
    return jsonify(users_list)


# ============================================
# Locked IPs Management (Brute Force Protection)
# ============================================

@bp.route('/api/security/locked-ips', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_locked_ips():
    """Get list of currently locked IPs and usernames (admin only)
    
    MK: Updated to show both IP and username lockouts
    """
    current_time = time.time()
    locked_ips = []
    locked_users = []
    
    # Get locked IPs
    for ip, info in login_attempts_by_ip.items():
        locked_until = info.get('locked_until', 0)
        if locked_until > current_time:
            locked_ips.append({
                'ip': ip,
                'locked_until': locked_until,
                'remaining_seconds': int(locked_until - current_time),
                'attempt_count': len(info.get('attempts', []))
            })
    
    # Get locked usernames
    for username, info in login_attempts_by_user.items():
        locked_until = info.get('locked_until', 0)
        if locked_until > current_time:
            locked_users.append({
                'username': username,
                'locked_until': locked_until,
                'remaining_seconds': int(locked_until - current_time),
                'attempt_count': len(info.get('attempts', []))
            })
    
    return jsonify({
        'locked_ips': locked_ips,
        'locked_users': locked_users,
        'total_tracked_ips': len(login_attempts_by_ip),
        'total_tracked_users': len(login_attempts_by_user)
    })


@bp.route('/api/security/locked-ips/<ip_address>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def unlock_ip(ip_address):
    # NS: admin-only endpoint to unlock IPs manually
    global login_attempts_by_ip
    
    # Normalize IP (replace URL-encoded dots if needed)
    ip_address = ip_address.replace('%2E', '.')
    
    if ip_address in login_attempts_by_ip:
        del login_attempts_by_ip[ip_address]
        logging.info(f"Admin manually unlocked IP: {ip_address}")
        log_audit(request.headers.get('X-Username', 'admin'), 'security.unlock_ip', f"Manually unlocked IP: {ip_address}")
        return jsonify({'success': True, 'message': f'IP {ip_address} unlocked'})
    else:
        return jsonify({'error': 'IP not found in locked list'}), 404


@bp.route('/api/security/locked-users/<username>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def unlock_user(username):
    """Unlock a specific username (admin only)
    
    MK: New endpoint for username-based lockout management
    """
    global login_attempts_by_user
    
    username = username.lower()
    
    if username in login_attempts_by_user:
        del login_attempts_by_user[username]
        logging.info(f"Admin manually unlocked user: {username}")
        log_audit(request.session.get('user', 'admin'), 'security.unlock_user', f"Manually unlocked user: {username}")
        return jsonify({'success': True, 'message': f'User {username} unlocked'})
    else:
        return jsonify({'error': 'User not found in locked list'}), 404


@bp.route('/api/security/locked-ips', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def unlock_all_ips():
    """Unlock all IP addresses (admin only)"""
    global login_attempts_by_ip
    
    count = len(login_attempts_by_ip)
    login_attempts_by_ip = {}
    
    logging.info(f"Admin manually unlocked all IPs ({count} entries cleared)")
    log_audit(request.session.get('user', 'admin'), 'security.unlock_all_ips', f"Cleared all {count} locked IPs")
    
    return jsonify({'success': True, 'message': f'All {count} IPs unlocked'})


@bp.route('/api/security/locked-users', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def unlock_all_users():
    """Unlock all usernames (admin only)
    
    MK: New endpoint for clearing all username lockouts
    """
    global login_attempts_by_user
    
    count = len(login_attempts_by_user)
    login_attempts_by_user = {}
    
    logging.info(f"Admin manually unlocked all users ({count} entries cleared)")
    log_audit(request.session.get('user', 'admin'), 'security.unlock_all_users', f"Cleared all {count} locked users")
    
    return jsonify({'success': True, 'message': f'All {count} users unlocked'})


# LW: Reset password expiry for all users - Dec 2025
# NS: Requested by admins who want to force everyone to change passwords after a breach
@bp.route('/api/security/password-expiry/reset-all', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def reset_all_password_expiry():
    """Reset password_changed_at for all users, forcing everyone to change passwords
    
    MK: This is useful after a security incident or when rotating passwords company-wide
    Can include admins too if the admin explicitly asks for it
    """
    data = request.json or {}
    include_admins = data.get('include_admins', False)  # opt-in for admins
    
    users_db = load_users()
    reset_count = 0
    skipped_admins = 0
    
    # Set password_changed_at to a date far in the past
    # this makes all passwords appear expired
    old_date = (datetime.now() - timedelta(days=9999)).isoformat()
    
    for username, user in users_db.items():
        if user.get('role') == ROLE_ADMIN and not include_admins:
            skipped_admins += 1
            continue
        if not user.get('enabled', True):
            continue  # skip disabled users
            
        user['password_changed_at'] = old_date
        reset_count += 1
    
    save_users(users_db)
    
    admin_user = request.session.get('user', 'unknown')
    log_audit(admin_user, 'security.password_reset_all', 
              f"Reset password expiry for {reset_count} users (include_admins={include_admins}, skipped={skipped_admins})")
    logging.info(f"Admin {admin_user} reset password expiry for {reset_count} users")
    
    return jsonify({
        'success': True,
        'reset_count': reset_count,
        'skipped_admins': skipped_admins,
        'message': f'Password expiry reset for {reset_count} users' + (f' ({skipped_admins} admins skipped)' if skipped_admins > 0 else '')
    })


@bp.route('/api/clusters/<cluster_id>/security/audit', methods=['GET'])
@require_auth(perms=['admin.audit'])
def get_security_audit(cluster_id):
    """Get security audit info for a cluster"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        
        # Get nodes
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = session.get(nodes_url, timeout=10)
        nodes = [n.get('node') for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
        
        result = {
            'firewall': {
                'cluster_enabled': False,
                'nodes': {}
            },
            'updates': {
                'total_security': 0,
                'nodes': {}
            },
            'ssh': {
                'issues': [],
                'nodes': {}
            },
            'fail2ban': {
                'total_banned': 0,
                'nodes': {}
            },
            'twoFactor': {
                'enabled': False
            }
        }
        
        # Check cluster firewall
        try:
            fw_url = f"https://{host}:8006/api2/json/cluster/firewall/options"
            fw_resp = session.get(fw_url, timeout=5)
            if fw_resp.status_code == 200:
                fw_data = fw_resp.json().get('data', {})
                result['firewall']['cluster_enabled'] = fw_data.get('enable', 0) == 1
        except Exception as e:
            logging.debug(f"Could not get cluster firewall: {e}")
        
        # Check each node
        for node in nodes:
            # Node firewall
            try:
                node_fw_url = f"https://{host}:8006/api2/json/nodes/{node}/firewall/options"
                node_fw_resp = session.get(node_fw_url, timeout=5)
                if node_fw_resp.status_code == 200:
                    node_fw_data = node_fw_resp.json().get('data', {})
                    
                    # Count rules
                    rules_url = f"https://{host}:8006/api2/json/nodes/{node}/firewall/rules"
                    rules_resp = session.get(rules_url, timeout=5)
                    rules_count = len(rules_resp.json().get('data', [])) if rules_resp.status_code == 200 else 0
                    
                    result['firewall']['nodes'][node] = {
                        'enabled': node_fw_data.get('enable', 0) == 1,
                        'rules': rules_count
                    }
            except Exception as e:
                logging.debug(f"Could not get firewall for {node}: {e}")
                result['firewall']['nodes'][node] = {'enabled': False, 'rules': 0}
            
            # Security updates
            try:
                updates = manager.get_node_apt_updates(node)
                security_pkgs = [
                    u.get('Package') for u in updates 
                    if u.get('Origin', '').lower().find('security') >= 0 or
                       u.get('Section', '').lower().find('security') >= 0 or
                       'security' in u.get('Package', '').lower()
                ]
                result['updates']['nodes'][node] = {
                    'total_updates': len(updates),
                    'security_updates': len(security_pkgs),
                    'security_packages': security_pkgs[:10]  # Limit to 10
                }
                result['updates']['total_security'] += len(security_pkgs)
            except Exception as e:
                logging.debug(f"Could not get updates for {node}: {e}")
                result['updates']['nodes'][node] = {'total_updates': 0, 'security_updates': 0, 'security_packages': []}
            
            # SSH config (via execute - requires SSH access)
            result['ssh']['nodes'][node] = {
                'permit_root_login': 'unknown',
                'password_auth': 'unknown',
                'port': '22',
                'pubkey_auth': 'unknown'
            }
            
            # Fail2ban status
            result['fail2ban']['nodes'][node] = {
                'installed': False,
                'jails': [],
                'total_banned': 0
            }
        
        # Check 2FA status
        try:
            tfa_url = f"https://{host}:8006/api2/json/access/tfa"
            tfa_resp = session.get(tfa_url, timeout=5)
            if tfa_resp.status_code == 200:
                tfa_data = tfa_resp.json().get('data', [])
                result['twoFactor']['enabled'] = len(tfa_data) > 0
                result['twoFactor']['users_with_2fa'] = len(tfa_data)
        except Exception as e:
            logging.debug(f"Could not get 2FA status: {e}")
        
        # Aggregate SSH issues
        for node, ssh_config in result['ssh']['nodes'].items():
            if ssh_config.get('permit_root_login') not in ['no', 'unknown']:
                if 'PermitRootLogin enabled' not in result['ssh']['issues']:
                    result['ssh']['issues'].append('PermitRootLogin enabled')
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Security audit error: {e}")
        return jsonify({'error': str(e)}), 500


def is_valid_role(role_id):
    """Check if a role is valid (builtin or custom)
    
    LW: Added to support custom roles in user management
    MK: Always reload from disk to avoid cache issues
    """
    # check builtin roles first
    if role_id in BUILTIN_ROLES:
        return True
    
    # check custom roles - reload fresh to avoid stale cache
    custom = load_custom_roles()
    
    # global custom roles
    if role_id in custom.get('global', {}):
        return True
    
    # tenant-specific custom roles
    for tenant_roles in custom.get('tenants', {}).values():
        if role_id in tenant_roles:
            return True
    
    return False


@bp.route('/api/users', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_user():
    """Create a new user (admin only)"""
    global users_db
    
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', ROLE_USER)
    display_name = data.get('display_name', username)
    email = data.get('email', '')
    tenant_id = data.get('tenant_id', DEFAULT_TENANT_ID)
    permissions = data.get('permissions', [])  # extra perms
    denied_permissions = data.get('denied_permissions', [])  # denied perms
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    # Validate password policy
    is_valid, error_msg = validate_password_policy(password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # NS: Updated to support custom roles
    if not is_valid_role(role):
        return jsonify({'error': 'Invalid role'}), 400
    
    # MK: Auto-set tenant_id if role belongs to a specific tenant
    if role not in BUILTIN_ROLES:
        custom_roles = load_custom_roles()
        for tid, roles in custom_roles.get('tenants', {}).items():
            if role in roles:
                tenant_id = tid  # override with role's tenant
                break
    
    # validate tenant exists
    tenants = load_tenants()
    if tenant_id not in tenants:
        return jsonify({'error': 'Invalid tenant_id'}), 400
    
    # validate permissions are valid
    for p in permissions + denied_permissions:
        if p not in PERMISSIONS:
            return jsonify({'error': f'Invalid permission: {p}'}), 400
    
    users_db = load_users()
    
    if username in users_db:
        return jsonify({'error': 'Username already exists'}), 409
    
    # Create user
    salt, password_hash = hash_password(password)
    users_db[username] = {
        'password_salt': salt,
        'password_hash': password_hash,
        'password_changed_at': datetime.now().isoformat(),  # LW: for expiry tracking
        'role': role,
        'display_name': display_name,
        'email': email,
        'enabled': True,
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'tenant_id': tenant_id,
        'permissions': permissions,
        'denied_permissions': denied_permissions,
    }
    
    save_users(users_db)
    
    logging.info(f"Admin '{request.session['user']}' created user '{username}' with role '{role}'")
    log_audit(request.session['user'], 'user.created', f"Created user: {username} (role: {role}, tenant: {tenant_id})")
    
    return jsonify({
        'success': True,
        'user': {
            'username': username,
            'role': role,
            'display_name': display_name,
            'email': email,
            'tenant_id': tenant_id,
            'permissions': permissions,
            'denied_permissions': denied_permissions,
        }
    })

@bp.route('/api/users/<username>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_user(username):
    """Update a user (admin only)"""
    global users_db
    
    username = username.lower()
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    user = users_db[username]
    
    # Update fields
    if 'role' in data:
        # NS: Updated to support custom roles
        if not is_valid_role(data['role']):
            return jsonify({'error': 'Invalid role'}), 400
        # Prevent last admin from losing admin role
        if user['role'] == ROLE_ADMIN and data['role'] != ROLE_ADMIN:
            admin_count = sum(1 for u in users_db.values() if u['role'] == ROLE_ADMIN and u.get('enabled', True))
            if admin_count <= 1:
                return jsonify({'error': 'Cannot remove admin role from last admin'}), 400
        user['role'] = data['role']
        
        # MK: Auto-set tenant_id when assigning a tenant-specific role
        # This ensures the user is properly associated with the tenant
        if data['role'] not in BUILTIN_ROLES:
            custom_roles = load_custom_roles()
            # check if role belongs to a tenant
            found_tenant = False
            for tid, roles in custom_roles.get('tenants', {}).items():
                if data['role'] in roles:
                    user['tenant_id'] = tid
                    found_tenant = True
                    logging.info(f"Auto-set tenant_id={tid} for user with role {data['role']}")
                    break
            
            # LW: Also check global roles (they don't change tenant)
            if not found_tenant and data['role'] in custom_roles.get('global', {}):
                logging.debug(f"Role {data['role']} is global, keeping existing tenant_id")
    
    if 'display_name' in data:
        user['display_name'] = data['display_name']
    
    if 'email' in data:
        user['email'] = data['email']
    
    if 'enabled' in data:
        # Prevent disabling last admin
        if user['role'] == ROLE_ADMIN and not data['enabled']:
            admin_count = sum(1 for u in users_db.values() if u['role'] == ROLE_ADMIN and u.get('enabled', True))
            if admin_count <= 1:
                return jsonify({'error': 'Cannot disable last admin'}), 400
        user['enabled'] = data['enabled']
    
    # NS: Added tenant_id update support
    if 'tenant_id' in data:
        tenants = load_tenants()
        if data['tenant_id'] not in tenants:
            return jsonify({'error': 'Invalid tenant_id'}), 400
        user['tenant_id'] = data['tenant_id']
    
    if 'password' in data and data['password']:
        # NS: Block password change for LDAP/OIDC users
        if user.get('auth_source', 'local') in ('ldap', 'oidc', 'entra'):
            return jsonify({'error': f"Cannot set password for {user['auth_source']} user. Password is managed by external identity provider."}), 400
        # Validate password policy
        is_valid, error_msg = validate_password_policy(data['password'])
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        salt, password_hash = hash_password(data['password'])
        user['password_salt'] = salt
        user['password_hash'] = password_hash
        user['password_changed_at'] = datetime.now().isoformat()  # LW: reset expiry
    
    save_users(users_db)
    
    logging.info(f"Admin '{request.session['user']}' updated user '{username}'")
    log_audit(request.session['user'], 'user.updated', f"Updated user: {username}")
    
    return jsonify({'success': True})

@bp.route('/api/users/<username>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_user(username):
    """Delete a user (admin only)"""
    global users_db
    
    username = username.lower()
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    # Prevent deleting self
    if username == request.session['user']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    # Prevent deleting last admin
    user = users_db[username]
    if user['role'] == ROLE_ADMIN:
        admin_count = sum(1 for u in users_db.values() if u['role'] == ROLE_ADMIN)
        if admin_count <= 1:
            return jsonify({'error': 'Cannot delete last admin'}), 400
    
    # Mark admin initialized if deleting the default admin
    if user.get('is_default') or username == 'pegaprox':
        mark_admin_initialized()
    
    # NS: Fix - actually delete from database! Jan 2026
    try:
        db = get_db()
        db.delete_user(username)
        logging.info(f"Deleted user '{username}' from database")
    except Exception as e:
        logging.error(f"Failed to delete user from DB: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500
    
    # Also remove from memory
    del users_db[username]
    
    # Invalidate any sessions for this user
    to_remove = [sid for sid, s in active_sessions.items() if s['user'] == username]
    for sid in to_remove:
        del active_sessions[sid]
    
    logging.info(f"Admin '{request.session['user']}' deleted user '{username}'")
    log_audit(request.session['user'], 'user.deleted', f"Deleted user: {username}")
    
    return jsonify({'success': True})


# ============================================
# Tenant Management API Routes
# Multi-tenancy - most requested feature on reddit
# on Reddit. MSPs use this to manage multiple customers separately.
# ============================================

@bp.route('/api/tenants', methods=['GET'])
@require_auth()
def get_tenants():
    """Get tenants - admin sees all, users see only their tenant
    
    NS: Updated Dec 2025 - filter based on user role
    MK: Fixed session access, added fallback for edge cases
    """
    global tenants_db
    tenants_db = load_tenants()
    
    # get user info from session
    username = request.session.get('user', '')
    user_role = request.session.get('role', ROLE_VIEWER)
    
    # admin always sees all tenants - no filtering
    if user_role == ROLE_ADMIN:
        result = []
        for tid, t in tenants_db.items():
            result.append({
                'id': tid,
                'name': t.get('name', tid),
                'clusters': t.get('clusters', []),
                'created': t.get('created', ''),
                'user_count': sum(1 for u in load_users().values() if u.get('tenant_id') == tid)
            })
        return jsonify(result)
    
    # non-admin: load user to get tenant_id
    users = load_users()
    user = users.get(username, {})
    user_tenant = user.get('tenant_id', DEFAULT_TENANT_ID)
    
    result = []
    for tid, t in tenants_db.items():
        # user sees only their tenant + default tenant
        if tid != user_tenant and tid != DEFAULT_TENANT_ID:
            continue
        
        result.append({
            'id': tid,
            'name': t.get('name', tid),
            'clusters': t.get('clusters', []),
            'created': t.get('created', ''),
            'user_count': sum(1 for u in users.values() if u.get('tenant_id') == tid)
        })
    
    return jsonify(result)

@bp.route('/api/tenants', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_tenant():
    """Create new tenant
    
    MK: Improved to handle duplicate names by adding suffix
    """
    global tenants_db
    
    data = request.json
    name = data.get('name', '').strip()
    clusters = data.get('clusters', [])
    
    if not name:
        return jsonify({'error': 'Name required'}), 400
    
    # generate ID from name
    import re
    base_tid = re.sub(r'[^a-z0-9]', '-', name.lower())
    base_tid = re.sub(r'-+', '-', base_tid).strip('-')
    
    if not base_tid:
        base_tid = 'tenant'
    
    tenants_db = load_tenants()
    
    # if ID exists, add numeric suffix
    tid = base_tid
    counter = 1
    while tid in tenants_db:
        tid = f"{base_tid}-{counter}"
        counter += 1
        if counter > 100:  # safety limit
            return jsonify({'error': 'Too many tenants with similar names'}), 409
    
    tenants_db[tid] = {
        'id': tid,
        'name': name,
        'clusters': clusters,
        'created': datetime.now().isoformat(),
    }
    
    save_tenants(tenants_db)
    log_audit(request.session['user'], 'tenant.created', f"Created tenant: {name} (id={tid})")
    
    return jsonify({'success': True, 'tenant': tenants_db[tid]})

@bp.route('/api/tenants/<tenant_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_tenant(tenant_id):
    """Update tenant"""
    global tenants_db
    
    tenants_db = load_tenants()
    
    if tenant_id not in tenants_db:
        return jsonify({'error': 'Tenant not found'}), 404
    
    data = request.json
    
    if 'name' in data:
        tenants_db[tenant_id]['name'] = data['name']
    if 'clusters' in data:
        tenants_db[tenant_id]['clusters'] = data['clusters']
    
    save_tenants(tenants_db)
    log_audit(request.session['user'], 'tenant.updated', f"Updated tenant: {tenant_id}")
    
    return jsonify({'success': True, 'tenant': tenants_db[tenant_id]})

@bp.route('/api/tenants/<tenant_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_tenant(tenant_id):
    """Delete tenant"""
    global tenants_db
    
    if tenant_id == DEFAULT_TENANT_ID:
        return jsonify({'error': 'Cannot delete default tenant'}), 400
    
    tenants_db = load_tenants()
    
    if tenant_id not in tenants_db:
        return jsonify({'error': 'Tenant not found'}), 404
    
    # check if users still assigned to this tenant
    users = load_users()
    users_in_tenant = [u for u, d in users.items() if d.get('tenant_id') == tenant_id]
    if users_in_tenant:
        return jsonify({'error': f'Tenant has {len(users_in_tenant)} users assigned. Reassign them first.'}), 400
    
    # Delete from database directly
    try:
        db = get_db()
        db.delete_tenant(tenant_id)
    except Exception as e:
        logging.error(f"Error deleting tenant from database: {e}")
        return jsonify({'error': 'Database error'}), 500
    
    # Update cache
    if tenant_id in tenants_db:
        del tenants_db[tenant_id]
    
    log_audit(request.session['user'], 'tenant.deleted', f"Deleted tenant: {tenant_id}")
    
    return jsonify({'success': True})


# ============================================
# Permission Management API Routes
# LW: For fine-grained access control
# ============================================

@bp.route('/api/permissions', methods=['GET'])
@require_auth()
def get_all_permissions():
    """Get all available permissions"""
    result = []
    for perm, desc in PERMISSIONS.items():
        category = perm.split('.')[0]
        result.append({
            'permission': perm,
            'description': desc,
            'category': category
        })
    return jsonify(result)

@bp.route('/api/permissions/roles', methods=['GET'])
@require_auth()
def get_role_permissions():
    """Get all roles - builtin + custom"""
    # builtin
    result = {
        'builtin': ROLE_PERMISSIONS,
        'custom': get_custom_roles()
    }
    return jsonify(result)


# ==================== CUSTOM ROLES API ====================
# custom role management

@bp.route('/api/roles', methods=['GET'])
@require_auth()
def list_all_roles():
    """List all available roles (builtin + custom)"""
    custom = get_custom_roles()
    
    roles = []
    # builtins
    for role_id in BUILTIN_ROLES:
        roles.append({
            'id': role_id,
            'name': role_id.capitalize(),
            'builtin': True,
            'permissions': ROLE_PERMISSIONS.get(role_id, []),
            'scope': 'global'
        })
    
    # global custom
    for role_id, data in custom.get('global', {}).items():
        roles.append({
            'id': role_id,
            'name': data.get('name', role_id),
            'builtin': False,
            'permissions': data.get('permissions', []),
            'scope': 'global',
            'created_by': data.get('created_by')
        })
    
    # tenant-specific
    for tenant_id, tenant_roles in custom.get('tenants', {}).items():
        for role_id, data in tenant_roles.items():
            roles.append({
                'id': role_id,
                'name': data.get('name', role_id),
                'builtin': False,
                'permissions': data.get('permissions', []),
                'scope': 'tenant',
                'tenant_id': tenant_id,
                'created_by': data.get('created_by')
            })
    
    return jsonify(roles)


@bp.route('/api/roles', methods=['POST'])
@require_auth(perms=['admin.roles'])
def create_custom_role():
    """Create a new custom role"""
    data = request.json or {}
    
    role_id = data.get('id', '').lower().strip()
    name = data.get('name', role_id)
    permissions = data.get('permissions', [])
    tenant_id = data.get('tenant_id')  # None = global role
    
    if not role_id:
        return jsonify({'error': 'Role ID required'}), 400
    
    # cant use builtin names
    if role_id in BUILTIN_ROLES:
        return jsonify({'error': 'Cannot use builtin role name'}), 400
    
    # validate role_id format
    if not role_id.replace('_', '').replace('-', '').isalnum():
        return jsonify({'error': 'Role ID must be alphanumeric'}), 400
    
    # validate perms
    for p in permissions:
        if p not in PERMISSIONS:
            return jsonify({'error': f'Invalid permission: {p}'}), 400
    
    custom = get_custom_roles()
    
    # Ensure tenants dict exists
    if 'tenants' not in custom:
        custom['tenants'] = {}
    if 'global' not in custom:
        custom['global'] = {}
    
    if tenant_id:
        # tenant-specific role
        if tenant_id not in custom['tenants']:
            custom['tenants'][tenant_id] = {}
        if role_id in custom['tenants'][tenant_id]:
            return jsonify({'error': 'Role already exists in this tenant'}), 400
        custom['tenants'][tenant_id][role_id] = {
            'name': name,
            'permissions': permissions,
            'created_by': request.session['user'],
            'created': datetime.now().isoformat()
        }
    else:
        # global role
        if role_id in custom['global']:
            return jsonify({'error': 'Global role already exists'}), 400
        custom['global'][role_id] = {
            'name': name,
            'permissions': permissions,
            'created_by': request.session['user'],
            'created': datetime.now().isoformat()
        }
    
    save_custom_roles(custom)
    invalidate_roles_cache()
    
    usr = request.session['user']
    scope = f"tenant:{tenant_id}" if tenant_id else "global"
    log_audit(usr, 'role.created', f"Created custom role: {role_id} ({scope})")
    
    return jsonify({'success': True, 'role_id': role_id})


@bp.route('/api/roles/<role_id>', methods=['PUT'])
@require_auth(perms=['admin.roles'])
def update_custom_role(role_id):
    """Update a custom role"""
    if role_id in BUILTIN_ROLES:
        return jsonify({'error': 'Cannot modify builtin roles'}), 400
    
    data = request.json or {}
    name = data.get('name')
    permissions = data.get('permissions')
    tenant_id = data.get('tenant_id')  # which tenant's role to update
    
    custom = get_custom_roles()
    
    # find the role
    found = False
    if tenant_id:
        tenant_roles = custom.get('tenants', {}).get(tenant_id, {})
        if role_id in tenant_roles:
            if name: tenant_roles[role_id]['name'] = name
            if permissions is not None:
                # validate
                for p in permissions:
                    if p not in PERMISSIONS:
                        return jsonify({'error': f'Invalid permission: {p}'}), 400
                tenant_roles[role_id]['permissions'] = permissions
            tenant_roles[role_id]['modified'] = datetime.now().isoformat()
            found = True
    else:
        global_roles = custom.get('global', {})
        if role_id in global_roles:
            if name: global_roles[role_id]['name'] = name
            if permissions is not None:
                for p in permissions:
                    if p not in PERMISSIONS:
                        return jsonify({'error': f'Invalid permission: {p}'}), 400
                global_roles[role_id]['permissions'] = permissions
            global_roles[role_id]['modified'] = datetime.now().isoformat()
            found = True
    
    if not found:
        return jsonify({'error': 'Role not found'}), 404
    
    save_custom_roles(custom)
    invalidate_roles_cache()
    
    log_audit(request.session['user'], 'role.updated', f"Updated role: {role_id}")
    return jsonify({'success': True})


@bp.route('/api/roles/<role_id>', methods=['DELETE'])
@require_auth(perms=['admin.roles'])
def delete_custom_role(role_id):
    """Delete a custom role"""
    if role_id in BUILTIN_ROLES:
        return jsonify({'error': 'Cannot delete builtin roles'}), 400
    
    tenant_id = request.args.get('tenant_id')
    
    custom = get_custom_roles()
    found = False
    
    if tenant_id:
        tenant_roles = custom.get('tenants', {}).get(tenant_id, {})
        if role_id in tenant_roles:
            del tenant_roles[role_id]
            found = True
    else:
        if role_id in custom.get('global', {}):
            del custom['global'][role_id]
            found = True
    
    if not found:
        return jsonify({'error': 'Role not found'}), 404
    
    save_custom_roles(custom)
    invalidate_roles_cache()
    
    log_audit(request.session['user'], 'role.deleted', f"Deleted role: {role_id}")
    return jsonify({'success': True})


# ==================== ROLE TEMPLATES API ====================
# predefined role configs for easy setup

@bp.route('/api/roles/templates', methods=['GET'])
@require_auth()
def get_role_templates():
    """Get available role templates"""
    templates = []
    for tid, tpl in ROLE_TEMPLATES.items():
        templates.append({
            'id': tid,
            'name': tpl['name'],
            'description': tpl.get('description', ''),
            'permissions': tpl['permissions'],
            'permission_count': len(tpl['permissions'])
        })
    return jsonify(templates)


@bp.route('/api/roles/templates/<template_id>/apply', methods=['POST'])
@require_auth(perms=['admin.roles'])
def apply_role_template(template_id):
    """Create a new role from a template"""
    if template_id not in ROLE_TEMPLATES:
        return jsonify({'error': 'Template not found'}), 404
    
    data = request.json or {}
    role_id = data.get('role_id', template_id)
    role_name = data.get('name', ROLE_TEMPLATES[template_id]['name'])
    tenant_id = data.get('tenant_id')  # None = global
    
    # validate role_id
    if role_id in BUILTIN_ROLES:
        return jsonify({'error': 'Cannot use builtin role name'}), 400
    
    custom = get_custom_roles()
    
    template = ROLE_TEMPLATES[template_id]
    role_data = {
        'name': role_name,
        'permissions': template['permissions'].copy(),
        'created_by': request.session['user'],
        'created': datetime.now().isoformat(),
        'from_template': template_id
    }
    
    if tenant_id:
        if 'tenants' not in custom:
            custom['tenants'] = {}
        if tenant_id not in custom['tenants']:
            custom['tenants'][tenant_id] = {}
        if role_id in custom['tenants'][tenant_id]:
            return jsonify({'error': 'Role already exists'}), 400
        custom['tenants'][tenant_id][role_id] = role_data
    else:
        if 'global' not in custom:
            custom['global'] = {}
        if role_id in custom['global']:
            return jsonify({'error': 'Role already exists'}), 400
        custom['global'][role_id] = role_data
    
    save_custom_roles(custom)
    invalidate_roles_cache()
    
    usr = request.session['user']
    scope = f"tenant:{tenant_id}" if tenant_id else "global"
    log_audit(usr, 'role.created_from_template', f"Created {role_id} from template {template_id} ({scope})")
    
    return jsonify({'success': True, 'role_id': role_id})


# ==================== VM ACCESS CONTROL API ====================
# per-VM permissions

@bp.route('/api/clusters/<cluster_id>/vm-acls', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_cluster_vm_acls(cluster_id):
    """Get VM ACLs for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    acls = get_vm_acls()
    cluster_acls = acls.get(cluster_id, {})
    
    # enrich with VM names if possible
    result = []
    for vmid, acl in cluster_acls.items():
        result.append({
            'vmid': int(vmid),
            'users': acl.get('users', []),
            'permissions': acl.get('permissions', []),
            'inherit_role': acl.get('inherit_role', True)
        })
    
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/vm-acls/<int:vmid>', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_vm_acl(cluster_id, vmid):
    """Get ACL for a specific VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    acls = get_vm_acls()
    cluster_acls = acls.get(cluster_id, {})
    vm_acl = cluster_acls.get(str(vmid), {})
    
    return jsonify({
        'vmid': vmid,
        'users': vm_acl.get('users', []),
        'permissions': vm_acl.get('permissions', []),
        'inherit_role': vm_acl.get('inherit_role', True),
        'exists': bool(vm_acl)
    })


@bp.route('/api/clusters/<cluster_id>/vm-acls/<int:vmid>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def set_vm_acl(cluster_id, vmid):
    """Set ACL for a specific VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.json or {}
    users = data.get('users', [])
    permissions = data.get('permissions', [])
    inherit_role = data.get('inherit_role', True)
    
    # validate permissions
    for p in permissions:
        if p not in PERMISSIONS:
            return jsonify({'error': f'Invalid permission: {p}'}), 400
    
    acls = get_vm_acls()
    if cluster_id not in acls:
        acls[cluster_id] = {}
    
    acls[cluster_id][str(vmid)] = {
        'users': users,
        'permissions': permissions,
        'inherit_role': inherit_role,
        'modified': datetime.now().isoformat(),
        'modified_by': request.session['user']
    }
    
    save_vm_acls(acls)
    invalidate_vm_acls_cache()
    
    cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
    log_audit(request.session['user'], 'vm.acl_updated', 
              f"VM {vmid} ACL updated: {len(users)} users, {len(permissions)} perms", 
              cluster=cluster_name)
    
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/vm-acls/<int:vmid>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_vm_acl(cluster_id, vmid):
    """Remove VM-specific ACL (use default permissions)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    # NS: Fixed - was only deleting from dict, not from DB!
    # Now we delete directly from DB
    try:
        db = get_db()
        deleted = db.delete_vm_acl(cluster_id, vmid)
        
        if deleted:
            invalidate_vm_acls_cache()
            cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
            log_audit(request.session['user'], 'vm.acl_deleted', f"VM {vmid} ACL removed", cluster=cluster_name)
        
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        logging.error(f"Failed to delete VM ACL: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== RESOURCE POOLS - MK Jan 2026 ====================

# Available pool permissions
POOL_PERMISSIONS = [
    'pool.view',        # View pool and members
    'vm.start',         # Start VMs in pool
    'vm.stop',          # Stop VMs in pool
    'vm.console',       # Access VM console
    'vm.config',        # Modify VM config
    'vm.snapshot',      # Create/delete snapshots
    'vm.backup',        # Create/restore backups
    'vm.migrate',       # Migrate VMs
    'vm.clone',         # Clone VMs
    'vm.delete',        # Delete VMs
    'pool.admin',       # Full admin access to pool
]


@bp.route('/api/clusters/<cluster_id>/pools', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_pools(cluster_id):
    """Get all resource pools from Proxmox"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    pools = mgr.get_pools()
    
    # Add pool member details
    for pool in pools:
        try:
            details = mgr.get_pool_members(pool['poolid'])
            members = details.get('members', [])
            pool['members'] = members  # Include full members list for UI
            pool['member_count'] = len(members)
            pool['vms'] = len([m for m in members if m.get('type') in ('qemu', 'lxc')])
            pool['storage'] = len([m for m in members if m.get('type') == 'storage'])
        except:
            pool['members'] = []
            pool['member_count'] = 0
            pool['vms'] = 0
            pool['storage'] = 0
    
    # NS: Prevent caching to ensure fresh data after pool modifications
    response = jsonify(pools)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_pool_details(cluster_id, pool_id):
    """Get pool details including members"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    pool_data = mgr.get_pool_members(pool_id)
    
    if not pool_data:
        return jsonify({'error': 'Pool not found'}), 404
    
    return jsonify(pool_data)


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>/permissions', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_pool_permissions_api(cluster_id, pool_id):
    """Get permissions for a pool"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    db = get_db()
    perms = db.get_pool_permissions(cluster_id, pool_id)
    
    return jsonify({
        'pool_id': pool_id,
        'permissions': perms,
        'available_permissions': POOL_PERMISSIONS
    })


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>/permissions', methods=['POST'])
@require_auth(perms=['admin.users'])
def add_pool_permission_api(cluster_id, pool_id):
    """Add or update pool permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.json or {}
    subject_type = data.get('subject_type')  # 'user' or 'group'
    subject_id = data.get('subject_id')      # username or group name
    permissions = data.get('permissions', [])
    
    if not subject_type or not subject_id:
        return jsonify({'error': 'subject_type and subject_id required'}), 400
    
    if subject_type not in ('user', 'group'):
        return jsonify({'error': 'subject_type must be "user" or "group"'}), 400
    
    # Validate permissions
    invalid_perms = [p for p in permissions if p not in POOL_PERMISSIONS]
    if invalid_perms:
        return jsonify({'error': f'Invalid permissions: {invalid_perms}'}), 400
    
    db = get_db()
    success = db.save_pool_permission(cluster_id, pool_id, subject_type, subject_id, permissions)
    
    if success:
        cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
        log_audit(request.session['user'], 'pool.permission_updated', 
                  f"Pool {pool_id}: {subject_type} '{subject_id}' permissions set to {permissions}", 
                  cluster=cluster_name)
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Failed to save permission'}), 500


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>/permissions/<subject_type>/<subject_id>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_pool_permission_api(cluster_id, pool_id, subject_type, subject_id):
    """Delete pool permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    db = get_db()
    deleted = db.delete_pool_permission(cluster_id, pool_id, subject_type, subject_id)
    
    if deleted:
        cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
        log_audit(request.session['user'], 'pool.permission_deleted', 
                  f"Pool {pool_id}: {subject_type} '{subject_id}' permission removed", 
                  cluster=cluster_name)
    
    return jsonify({'success': True, 'deleted': deleted})


@bp.route('/api/clusters/<cluster_id>/pool-permissions', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_all_pool_permissions_api(cluster_id):
    """Get all pool permissions for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    db = get_db()
    perms = db.get_pool_permissions(cluster_id)
    
    # Group by pool
    by_pool = {}
    for p in perms:
        pool_id = p['pool_id']
        if pool_id not in by_pool:
            by_pool[pool_id] = []
        by_pool[pool_id].append(p)
    
    return jsonify({
        'permissions': by_pool,
        'available_permissions': POOL_PERMISSIONS
    })


@bp.route('/api/clusters/<cluster_id>/pools/refresh-cache', methods=['POST'])
@require_auth(perms=['admin.users'])
def refresh_pool_cache_api(cluster_id):
    """Manually refresh the pool membership cache for a cluster
    
    MK: Useful when pools have been modified in Proxmox
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    # Invalidate and refresh
    invalidate_pool_cache(cluster_id)
    membership = get_pool_membership_cache(cluster_id)
    
    return jsonify({
        'success': True,
        'vms_in_pools': len(membership),
        'message': f'Cache refreshed - {len(membership)} VMs found in pools'
    })


# ============================================================================
# Pool Management API - NS Jan 2026

