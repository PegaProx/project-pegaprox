# -*- coding: utf-8 -*-
"""user management, tenants, roles & ACL routes - split from monolith dec 2025, NS/MK"""

import json
import time
import logging
import re
import base64
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db
from pegaprox.utils.sanitization import sanitize_username, sanitize_log_message as _sl

from pegaprox.utils.auth import (
    hash_password, verify_password, validate_password_policy,
    load_users, save_users, require_auth, ARGON2_AVAILABLE,
    mark_admin_initialized, invalidate_all_user_sessions, revoke_user_api_tokens,
    build_authz_user,
)
from pegaprox.utils.audit import log_audit
from pegaprox.utils.rbac import (
    invalidate_tenants_cache,
    load_custom_roles, save_custom_roles, get_custom_roles, invalidate_roles_cache,
    get_role_permissions_for_user, load_tenants, save_tenants,
    get_user_permissions, has_permission, get_user_effective_role,
    get_user_clusters, filter_clusters_for_user,
    load_vm_acls, save_vm_acls, get_vm_acls, invalidate_vm_acls_cache,
    user_can_access_vm, get_user_vms,
    get_pool_membership_cache, invalidate_pool_cache, get_vm_pool_cached,
    DEFAULT_TENANT_ID, ROLE_TEMPLATES,
)
from pegaprox.api.helpers import load_server_settings, save_server_settings, get_login_settings, check_cluster_access, safe_error

bp = Blueprint('users', __name__)

ALLOWED_AVATAR_MIMES = {'image/png', 'image/jpeg', 'image/webp', 'image/gif'}
MAX_AVATAR_BYTES = 512 * 1024


def _build_avatar_url(user: dict) -> str:
    avatar_mime = user.get('avatar_mime', '') or ''
    avatar_data = user.get('avatar_data', '') or ''
    if avatar_mime and avatar_data:
        return f"data:{avatar_mime};base64,{avatar_data}"
    return ''


def _caller_tenant_or_none():
    # MK Jun 2026 (sec-review): a global admin manages every tenant; a tenant-scoped admin
    # (custom role carrying admin.users) is confined to their own tenant. Returns the tenant
    # to scope to, or None when the caller is a global admin (no restriction).
    if request.session.get('role') == ROLE_ADMIN:
        return None
    caller = get_db().get_user(request.session.get('user', '')) or {}
    return caller.get('tenant_id', DEFAULT_TENANT_ID)


_ROLE_LEVEL = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}


def _role_at_or_below_caller(target_role):
    # MK: stop a delegate holding admin.users from minting/assigning a role above their own
    # tier. Unknown/custom roles map to the 'user' level.
    caller_lvl = _ROLE_LEVEL.get(request.session.get('role'), 2)
    return _ROLE_LEVEL.get(target_role, 2) <= caller_lvl


def _role_permissions(role):
    """All permissions a role grants — builtin (ROLE_PERMISSIONS) or custom (load_custom_roles).

    MK Sep 2026 (audit) — a custom role id can live in BOTH namespaces, and the two
    functions that resolve one walked them in opposite orders: this one took the global
    definition first, while rbac.get_role_permissions_for_user — the one that decides what
    the account may actually do — takes the tenant's. So with a harmless global `ops` and a
    powerful tenant `ops`, the ceiling check in _caller_can_grant_role weighed ['vm.view']
    and the account received admin.users and admin.settings.

    For a ceiling check the only safe reading of an ambiguous name is the UNION: cover both
    or assign neither. That holds however the runtime resolves it downstream, which is the
    point — matching the other order would just move the disagreement.
    """
    if role in ROLE_PERMISSIONS:
        return list(ROLE_PERMISSIONS.get(role, []))
    cr = load_custom_roles()
    perms = set((cr.get('global', {}).get(role) or {}).get('permissions', []) or [])
    for _tid, _roles in cr.get('tenants', {}).items():
        if role in _roles:
            perms.update((_roles.get(role) or {}).get('permissions', []) or [])
    return sorted(perms)


def _caller_can_grant_role(target_role):
    # NS Aug 2026 (Aikido pentest) — the tier map above collapses every custom role to the 'user'
    # level, so a custom role carrying admin.* perms would pass _role_at_or_below_caller for a
    # user-tier delegate. Require a non-global-admin caller to actually hold every permission the
    # role grants before assigning it. Global admins keep full delegation.
    if request.session.get('role') == ROLE_ADMIN:
        return True
    from pegaprox.utils.auth import build_authz_user
    caller = build_authz_user(request.session.get('user', ''), request.session)
    return all(has_permission(caller, p) for p in _role_permissions(target_role))


def _caller_can_grant_perms(permissions):
    # NS Aug 2026 (audit) — a non-global-admin defining/editing a custom role (or applying a
    # template) must not grant it permissions the caller doesn't hold; otherwise an admin.roles
    # delegate could rewrite its own tenant role to admin.settings/admin.users and self-escalate to
    # global-admin-equivalent. Global admins keep full delegation.
    if request.session.get('role') == ROLE_ADMIN:
        return True
    from pegaprox.utils.auth import build_authz_user
    caller = build_authz_user(request.session.get('user', ''), request.session)
    return all(has_permission(caller, p) for p in (permissions or []))


def _authz_object_write(cluster_id, subjects=(), permissions=(), groups=()):
    """sec (audit): vm-acls, pool permissions and the pools themselves are the authorization
    objects the per-VM gate
    consults — writing them IS granting access, so cluster reach is nowhere near enough. Every
    other grant path in this file already asks these questions; these routes asked none of them.
    Returns an error response, or None when the write is allowed.

    Global admins pass. Otherwise the caller must not be confined on this cluster (a pool-/ACL-
    scoped caller has no business authoring grants at all), the subjects must be inside their
    tenant, and they may not hand out permissions they do not hold themselves."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.api.helpers import caller_is_scoped
    caller = build_authz_user(request.session.get('user', ''), request.session)
    if caller.get('effective_role', caller.get('role')) == ROLE_ADMIN:
        return None
    if caller_is_scoped(caller, cluster_id):
        return jsonify({'error': 'Access denied: you cannot manage access rules on this cluster'}), 403
    _ct = _caller_tenant_or_none()
    if _ct is not None:
        # MK Sep 2026 - a GROUP subject is the wildcard case wearing a different hat. Group
        # names come from LDAP or OIDC and carry no tenant association at all; the grant is
        # matched by name, so a delegate can hand pool permissions to a group whose members
        # sit in somebody else's tenant, and neither they nor we can see how far it reaches.
        # Members who have never logged in are not even in our user table, so counting them
        # would only look like a check. Same answer as the wildcard below: not a tenant-scoped
        # decision.
        for g in groups:
            if g:
                return jsonify({'error': 'Access denied: group-based grants require a '
                                         'global admin'}), 403
        _users = load_users()
        for s in subjects:
            if not s or s == '*':
                # A wildcard row reaches every account, including other tenants'. That
                # holds whichever direction the write goes: creating one grants across the
                # boundary, deleting one revokes across it. Either way it is not a
                # tenant-scoped decision.
                return jsonify({'error': 'Access denied: wildcard rules require a global admin'}), 403
            _t = (_users.get(s) or {}).get('tenant_id', DEFAULT_TENANT_ID)
            if _t != _ct:
                return jsonify({'error': f'Access denied: {s} is not in your tenant'}), 403
    _over = [p for p in (permissions or []) if not has_permission(caller, p)]
    if _over:
        return jsonify({'error': 'Cannot grant permissions you do not hold: ' + ', '.join(_over)}), 403
    return None


def _caller_can_manage_user(target_user):
    # NS Aug 2026 (audit re-verify) — for account-takeover-capable ops (password reset, 2FA clear) the
    # guard must weigh the target's EFFECTIVE permissions (role + direct permissions +
    # tenant_permissions), not just the role label: a global admin can legitimately give a low-role
    # user direct admin.* grants, and a lesser delegate must not be able to reset such a peer and
    # inherit those grants. Global admins pass; otherwise the caller must hold every effective perm
    # the target has.
    if request.session.get('role') == ROLE_ADMIN:
        return True
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import get_user_permissions
    caller = build_authz_user(request.session.get('user', ''), request.session)
    return all(has_permission(caller, p) for p in get_user_permissions(target_user or {}))


def _parse_avatar_data_url(value: str):
    """Validate avatar data URL and return (mime, base64-data)."""
    if not isinstance(value, str) or not value.startswith('data:'):
        return None, None, 'Avatar must be a valid image data URL'

    match = re.fullmatch(r'data:(image/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)', value.strip())
    if not match:
        return None, None, 'Avatar must be a base64-encoded PNG, JPEG, GIF, or WebP image'

    avatar_mime = match.group(1).lower()
    avatar_data = re.sub(r'\s+', '', match.group(2))
    if avatar_mime not in ALLOWED_AVATAR_MIMES:
        return None, None, 'Unsupported avatar format. Use PNG, JPEG, GIF, or WebP'

    try:
        raw = base64.b64decode(avatar_data, validate=True)
    except Exception:
        return None, None, 'Avatar image is not valid base64 data'

    if not raw:
        return None, None, 'Avatar image is empty'

    if len(raw) > MAX_AVATAR_BYTES:
        return None, None, f'Avatar image must be {MAX_AVATAR_BYTES // 1024} KB or smaller'

    return avatar_mime, avatar_data, None

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
        'sidebar_show_vmid': user.get('sidebar_show_vmid', False),  # NS Jul 2026 — corporate sidebar VMIDs
        'default_theme': default_theme
    })


@bp.route('/api/user/avatar', methods=['PUT'])
@require_auth()
def update_user_avatar():
    """Upload or replace the current user's avatar."""
    username = request.session['user']
    data = request.get_json() or {}

    avatar_mime, avatar_data, error = _parse_avatar_data_url(data.get('avatar'))
    if error:
        return jsonify({'error': error}), 400

    users_db = load_users()
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404

    user = users_db[username]
    user['avatar_mime'] = avatar_mime
    user['avatar_data'] = avatar_data

    db = get_db()
    db.save_user(username, user)

    logging.info(f"User '{username}' updated avatar")
    log_audit(username, 'user.avatar_updated', 'Updated profile avatar')

    return jsonify({'success': True, 'avatar_url': _build_avatar_url(user)})


@bp.route('/api/user/avatar', methods=['DELETE'])
@require_auth()
def delete_user_avatar():
    """Remove the current user's avatar."""
    username = request.session['user']
    users_db = load_users()
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404

    user = users_db[username]
    user['avatar_mime'] = ''
    user['avatar_data'] = ''

    db = get_db()
    db.save_user(username, user)

    logging.info(f"User '{username}' removed avatar")
    log_audit(username, 'user.avatar_removed', 'Removed profile avatar')

    return jsonify({'success': True, 'avatar_url': ''})


@bp.route('/api/user/preferences', methods=['PUT'])
@require_auth()
def update_user_preferences():
    """Update current user's preferences (theme, language, ui_layout)"""
    global users_db
    
    username = request.session['user']
    data = request.get_json() or {}
    
    logging.info(f"update_user_preferences: user={_sl(username)}, data={_sl(data)}")
    
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
        'corporateDark', 'corporateLight', 'enterpriseBlue',  # NS: Corporate themes
        'cloud'  # NS 2026-06-05: Cloud skin (Preview)
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
        if layout in ['modern', 'classic', 'corporate', 'cloud']:
            user['ui_layout'] = layout
            logging.info(f"update_user_preferences: Setting ui_layout to '{_sl(layout)}' for user '{_sl(username)}'")
        else:
            return jsonify({'error': f'Invalid layout: {layout}'}), 400
    
    # NS: TaskBar auto-expand preference - Feb 2026
    if 'taskbar_auto_expand' in data:
        user['taskbar_auto_expand'] = bool(data['taskbar_auto_expand'])

    # NS Jul 2026 — opt-in VMIDs in the corporate sidebar tree.
    # Strict coercion so a stringy "false"/"0" doesn't flip the pref on (bool("false") is True).
    if 'sidebar_show_vmid' in data:
        user['sidebar_show_vmid'] = str(data['sidebar_show_vmid']).strip().lower() in ('true', '1', 'yes', 'on')

    # LW: Mar 2026 - track if user has explicitly chosen a layout
    if 'layout_chosen' in data:
        user['layout_chosen'] = bool(data['layout_chosen'])
    
    # Save only this user, not all users
    db = get_db()
    db.save_user(username, user)
    
    logging.info(f"User '{_sl(username)}' updated preferences: theme={_sl(user.get('theme'))}, language={_sl(user.get('language'))}, ui_layout={_sl(user.get('ui_layout'))}, taskbar_auto_expand={user.get('taskbar_auto_expand')}")
    log_audit(username, 'user.preferences_updated', f"Updated preferences: theme={user.get('theme')}, layout={user.get('ui_layout')}")
    
    settings = load_server_settings()
    default_theme = settings.get('default_theme', 'proxmoxDark')
    
    return jsonify({
        'success': True,
        'theme': user.get('theme', '') or default_theme,
        'language': user.get('language', ''),
        'ui_layout': user.get('ui_layout', 'modern'),
        'taskbar_auto_expand': user.get('taskbar_auto_expand', True),
        'sidebar_show_vmid': user.get('sidebar_show_vmid', False),
        'layout_chosen': user.get('layout_chosen', False),
        'default_theme': default_theme
    })


@bp.route('/api/users/<username>/2fa', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def admin_disable_2fa(username):
    """Admin: Disable 2FA for a user"""
    global users_db
    
    username = username.lower()
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    _ct = _caller_tenant_or_none()
    if _ct is not None and user.get('tenant_id', DEFAULT_TENANT_ID) != _ct:
        return jsonify({'error': 'Access denied: cannot manage 2FA for users in other tenants'}), 403
    # NS Aug 2026 (audit) — a same-tenant delegate must not clear 2FA on a peer whose EFFECTIVE perms
    # (role + direct grants) exceed the delegate's; combined with a password reset that is a takeover.
    if not _caller_can_manage_user(user):
        return jsonify({'error': 'Access denied: target has privileges beyond your own'}), 403
    user['totp_enabled'] = False
    user.pop('totp_secret', None)
    user.pop('totp_pending_secret', None)
    save_users(users_db)
    
    logging.info(f"Admin '{_sl(request.session['user'])}' disabled 2FA for user '{_sl(username)}'")
    log_audit(request.session['user'], '2fa.admin_disabled', f"Admin disabled 2FA for user: {username}")
    
    return jsonify({'success': True, 'message': f'2FA for {username} disabled'})


@bp.route('/api/users/<username>/password', methods=['PUT'])
@require_auth(perms=['admin.users'])
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
    _ct = _caller_tenant_or_none()
    if _ct is not None and user.get('tenant_id', DEFAULT_TENANT_ID) != _ct:
        return jsonify({'error': 'Access denied: cannot change passwords for users in other tenants'}), 403
    # NS Aug 2026 (audit) — a delegate must not reset the password of a same-tenant peer whose
    # EFFECTIVE perms (role + direct grants) exceed the delegate's; that is a vertical privesc
    # (reset, then log in as them).
    if not _caller_can_manage_user(user):
        return jsonify({'error': 'Access denied: target has privileges beyond your own'}), 403

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
    sessions_removed = invalidate_all_user_sessions(username)
    tokens_revoked = revoke_user_api_tokens(username)  # sec (audit): revoke API tokens too, not just sessions
    from pegaprox.utils.realtime import invalidate_user_sse_tokens
    invalidate_user_sse_tokens(username)               # ...and the SSE stream token

    admin_username = request.session['user']
    logging.info(f"Admin '{admin_username}' changed password for user '{username}' — {tokens_revoked} token(s) revoked")
    log_audit(admin_username, 'user.password_reset', f"Admin reset password for user: {username} ({sessions_removed} sessions invalidated)")

    # NS 2026-04-24 — if admin reset their OWN password, their session just died too
    # and the frontend needs to redirect to /login.
    relogin_required = (admin_username.lower() == username)
    resp = jsonify({
        'success': True,
        'message': f'Password for {username} changed',
        'sessions_invalidated': sessions_removed,
        'relogin_required': relogin_required,
    })
    if relogin_required:
        resp.delete_cookie('session_id')
    return resp


# ============================================

# ============================================

@bp.route('/api/users', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_users():
    """Get list of all users (admin only)"""
    users_db = load_users()
    _ct = _caller_tenant_or_none()  # tenant-scoped admins only see their own tenant

    # Return users without password info
    users_list = []
    for username, user in users_db.items():
        if _ct is not None and user.get('tenant_id', DEFAULT_TENANT_ID) != _ct:
            continue
        users_list.append({
            'username': username,
            'role': user['role'],
            'display_name': user.get('display_name', username),
            'email': user.get('email', ''),
            'avatar_url': _build_avatar_url(user),
            'enabled': user.get('enabled', True),
            'totp_enabled': user.get('totp_enabled', False),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'tenant_id': user.get('tenant_id', DEFAULT_TENANT_ID),  # MK: Added for tenant display
            'auth_source': user.get('auth_source', 'local'),  # NS: For LDAP/Entra/OIDC badge in user list
            'permissions': user.get('permissions', []),  # LW: For permission display
            'portal_only': user.get('portal_only', False),
            'user_folder': user.get('user_folder', ''),
            'granted_roles': [r['role_name'] for r in get_db().conn.execute(
                'SELECT role_name FROM user_roles WHERE username = ?', (username,)).fetchall()],
            # SRK (SPEC-2026-011 D6): explicit tenant memberships beyond home
            'granted_tenants': [r['tenant_id'] for r in get_db().conn.execute(
                'SELECT tenant_id FROM user_tenants WHERE username = ? '
                'ORDER BY granted_at, tenant_id', (username,)).fetchall()],
        })
    
    return jsonify(users_list)


# ============================================
# Locked IPs Management (Brute Force Protection)
# ============================================

@bp.route('/api/security/locked-ips', methods=['GET'])
@require_auth(perms=['security.lockout.view'])
def get_locked_ips():
    """Get list of currently locked IPs and usernames (admin only)
    
    MK: Updated to show both IP and username lockouts
    """
    current_time = time.time()
    locked_ips = []
    locked_users = []
    _ct = _caller_tenant_or_none()
    _users_db = load_users() if _ct is not None else {}

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
    
    # Get locked usernames (tenant-scoped admins only see their own tenant's users)
    for username, info in login_attempts_by_user.items():
        locked_until = info.get('locked_until', 0)
        if locked_until > current_time:
            if _ct is not None and _users_db.get(username, {}).get('tenant_id', DEFAULT_TENANT_ID) != _ct:
                continue
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
@require_auth(perms=['security.lockout.manage'])
def unlock_ip(ip_address):
    # NS: admin-only endpoint to unlock IPs manually
    global login_attempts_by_ip
    
    # Normalize IP (replace URL-encoded dots if needed)
    ip_address = ip_address.replace('%2E', '.')
    
    if ip_address in login_attempts_by_ip:
        del login_attempts_by_ip[ip_address]
        logging.info(f"Admin manually unlocked IP: {_sl(ip_address)}")
        # MK Sep 2026 (audit) — the actor used to come from an X-Username REQUEST HEADER,
        # which the caller sets and which app.py even lists in the CORS allow-list. The other
        # 24 log_audit calls in this file read request.session. Practical effect without any
        # attacker: every "manually unlocked IP" line in the trail said 'admin', the default.
        log_audit(request.session.get('user', 'admin'), 'security.unlock_ip', f"Manually unlocked IP: {ip_address}")
        return jsonify({'success': True, 'message': f'IP {ip_address} unlocked'})
    else:
        return jsonify({'error': 'IP not found in locked list'}), 404


@bp.route('/api/security/locked-users/<username>', methods=['DELETE'])
@require_auth(perms=['security.lockout.manage'])
def unlock_user(username):
    """Unlock a specific username (admin only)
    
    MK: New endpoint for username-based lockout management
    """
    global login_attempts_by_user

    username = username.lower()

    _ct = _caller_tenant_or_none()
    if _ct is not None:
        _target = load_users().get(username, {})
        if _target and _target.get('tenant_id', DEFAULT_TENANT_ID) != _ct:
            return jsonify({'error': 'Access denied: cannot unlock users in other tenants'}), 403

    if username in login_attempts_by_user:
        del login_attempts_by_user[username]
        logging.info(f"Admin manually unlocked user: {_sl(username)}")
        log_audit(request.session.get('user', 'admin'), 'security.unlock_user', f"Manually unlocked user: {username}")
        return jsonify({'success': True, 'message': f'User {username} unlocked'})
    else:
        return jsonify({'error': 'User not found in locked list'}), 404


@bp.route('/api/security/locked-ips', methods=['DELETE'])
@require_auth(perms=['security.lockout.manage'])
def unlock_all_ips():
    """Unlock all IP addresses (admin only)"""
    # MK: clear() the store, never rebind it. `global` here names THIS module's
    # copy of the import, so `= {}` left api/auth.py — the module the login path
    # reads — holding the old dict with every lockout still in it, and pointed the
    # listing and single-unlock routes at a detached empty one.
    count = len(login_attempts_by_ip)
    login_attempts_by_ip.clear()
    
    logging.info(f"Admin manually unlocked all IPs ({count} entries cleared)")
    log_audit(request.session.get('user', 'admin'), 'security.unlock_all_ips', f"Cleared all {count} locked IPs")
    
    return jsonify({'success': True, 'message': f'All {count} IPs unlocked'})


@bp.route('/api/security/locked-users', methods=['DELETE'])
@require_auth(perms=['security.lockout.manage'])
def unlock_all_users():
    """Unlock all usernames (admin only)
    
    MK: New endpoint for clearing all username lockouts
    """
    count = len(login_attempts_by_user)
    login_attempts_by_user.clear()
    
    logging.info(f"Admin manually unlocked all users ({count} entries cleared)")
    log_audit(request.session.get('user', 'admin'), 'security.unlock_all_users', f"Cleared all {count} locked users")
    
    return jsonify({'success': True, 'message': f'All {count} users unlocked'})


# LW: Reset password expiry for all users - Dec 2025
# NS: Requested by admins who want to force everyone to change passwords after a breach
@bp.route('/api/security/password-expiry/reset-all', methods=['POST'])
@require_auth(perms=['security.lockout.manage'])
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
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # MK Sep 2026 (audit) — and reachability is not enough for this one. It enumerates every
    # online node, the cluster firewall state, pending security updates, sshd findings and
    # fail2ban bans: whole-cluster posture with no per-object notion, which is exactly what
    # require_unconfined() exists for. A pool-/ACL-scoped caller holding admin.audit reached
    # it through the #248/#555 fallbacks.
    from pegaprox.api.helpers import require_unconfined
    _uerr = require_unconfined(cluster_id)
    if _uerr:
        return _uerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    try:
        host, port = manager.host, manager.api_port
        session = manager._create_session()
        
        # Get nodes
        nodes_url = f"https://{host}:{port}/api2/json/nodes"
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
            fw_url = f"https://{host}:{port}/api2/json/cluster/firewall/options"
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
                node_fw_url = f"https://{host}:{port}/api2/json/nodes/{node}/firewall/options"
                node_fw_resp = session.get(node_fw_url, timeout=5)
                if node_fw_resp.status_code == 200:
                    node_fw_data = node_fw_resp.json().get('data', {})
                    
                    # Count rules
                    rules_url = f"https://{host}:{port}/api2/json/nodes/{node}/firewall/rules"
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
            tfa_url = f"https://{host}:{port}/api2/json/access/tfa"
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
        return jsonify({'error': safe_error(e, 'User operation failed')}), 500


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
@require_auth(perms=['admin.users'])
def create_user():
    """Create a new user (admin only)"""
    global users_db
    
    data = request.get_json()
    username = sanitize_username(data.get('username', '').strip().lower())
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

    # tenant-scoped admins create only inside their own tenant, and nobody can mint a
    # user that outranks them
    _ct = _caller_tenant_or_none()
    if _ct is not None and tenant_id != _ct:
        return jsonify({'error': 'Access denied: cannot create users in other tenants'}), 403
    if not _role_at_or_below_caller(role):
        return jsonify({'error': 'Cannot create a user with a role higher than your own'}), 403
    if not _caller_can_grant_role(role):
        return jsonify({'error': 'Cannot assign a role that grants permissions beyond your own'}), 403

    # validate permissions are valid
    for p in permissions + denied_permissions:
        if p not in PERMISSIONS:
            return jsonify({'error': f'Invalid permission: {p}'}), 400
    # NS Aug 2026 (Aikido pentest) — a non-global-admin may only grant permissions it holds itself,
    # else admin.users lets a tenant delegate mint accounts with admin.roles/tenants/settings/etc.
    if _ct is not None:
        from pegaprox.utils.auth import build_authz_user
        _caller = build_authz_user(request.session.get('user', ''), request.session)
        _over = [p for p in permissions if not has_permission(_caller, p)]
        if _over:
            return jsonify({'error': 'Cannot grant permissions you do not hold: ' + ', '.join(_over)}), 403

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
        'portal_only': data.get('portal_only', False) if role != ROLE_ADMIN else False,
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
@require_auth(perms=['admin.users'])
def update_user(username):
    """Update a user (admin only)"""
    global users_db
    
    username = username.lower()
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    user = users_db[username]

    # tenant-scoped admins can only touch users in their own tenant, and can't move a user
    # out of it
    _ct = _caller_tenant_or_none()
    if _ct is not None:
        # SRK (SPEC-2026-011 D6): caller containment is now set-based over the
        # target's effective tenant set (home UNION user_tenants memberships).
        # The HOME-move rule below stays scalar on purpose (A8): membership
        # alone must never let a scoped admin re-home an account.
        import pegaprox.utils.rbac as _rbac_d6
        _tset = set(_rbac_d6.get_user_tenant_memberships(username))
        _tset.add(user.get('tenant_id', DEFAULT_TENANT_ID))
        if _ct not in _tset:
            return jsonify({'error': 'Access denied: cannot modify users in other tenants'}), 403
        if data.get('tenant_id', _ct) != _ct:
            return jsonify({'error': 'Access denied: cannot move users to other tenants'}), 403

    # Update fields
    if 'role' in data:
        # NS: Updated to support custom roles
        if not is_valid_role(data['role']):
            return jsonify({'error': 'Invalid role'}), 400
        # can't escalate yourself, and can't hand out a role above your own tier
        if username == request.session.get('user'):
            return jsonify({'error': 'Cannot modify your own role'}), 403
        if not _role_at_or_below_caller(data['role']):
            return jsonify({'error': 'Cannot assign a role with higher privileges than your own'}), 403
        if not _caller_can_grant_role(data['role']):
            return jsonify({'error': 'Cannot assign a role that grants permissions beyond your own'}), 403
        # MK Sep 2026 (audit) — and the caller has to outrank the target AS IT STANDS, not as
        # it will stand. Disabling an account already asks this question; re-roling one is the
        # stronger operation and asked nothing, so a delegate could demote an administrator it
        # could not touch and then reset that account's password on the next request. The same
        # gap in one request: the `enabled` branch below calls _caller_can_manage_user on the
        # dict this block has already mutated, and so does the last-admin check under it.
        if not _caller_can_manage_user(user):
            return jsonify({'error': 'Access denied: target has privileges beyond your own'}), 403
        # Prevent last admin from losing admin role
        if user['role'] == ROLE_ADMIN and data['role'] != ROLE_ADMIN:
            admin_count = sum(1 for u in users_db.values() if u['role'] == ROLE_ADMIN and u.get('enabled', True))
            if admin_count <= 1:
                return jsonify({'error': 'Cannot remove admin role from last admin'}), 400
        user['role'] = data['role']
        # clear portal_only if promoted to admin
        if data['role'] == ROLE_ADMIN and user.get('portal_only'):
            user['portal_only'] = False

        # MK: Auto-set tenant_id when assigning a tenant-specific role
        # This ensures the user is properly associated with the tenant
        if data['role'] not in BUILTIN_ROLES:
            custom_roles = load_custom_roles()
            # check if role belongs to a tenant
            found_tenant = False
            for tid, roles in custom_roles.get('tenants', {}).items():
                if data['role'] in roles:
                    # NS Aug 2026 (Aikido pentest) — a tenant-scoped admin must not assign a role
                    # owned by another tenant; it would silently move the account into that tenant.
                    if _ct is not None and tid != _ct:
                        return jsonify({'error': 'Cannot assign a role from another tenant'}), 403
                    user['tenant_id'] = tid
                    # SRK (SPEC-2026-011 D6/A8): home re-point also records a
                    # user_tenants row so the scalar stays inside the set.
                    try:
                        get_db().conn.cursor().execute(
                            'INSERT OR IGNORE INTO user_tenants '
                            '(username, tenant_id, granted_at, granted_by) VALUES (?, ?, ?, ?)',
                            (username, tid, datetime.now().isoformat(),
                             request.session.get('user', '')))
                        get_db().conn.commit()
                    except Exception as _e:
                        logging.warning(f"[d6] membership backfill on home re-point failed: {_e}")
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
    
    _disabled = False
    if 'enabled' in data:
        # sec (audit): same tier guard as the password/2FA paths — disabling is an availability
        # attack a delegate must not be able to run against a peer who outranks them.
        if not _caller_can_manage_user(user):
            return jsonify({'error': 'Access denied: target has privileges beyond your own'}), 403
        # Prevent disabling last admin
        if user['role'] == ROLE_ADMIN and not data['enabled']:
            admin_count = sum(1 for u in users_db.values() if u['role'] == ROLE_ADMIN and u.get('enabled', True))
            if admin_count <= 1:
                return jsonify({'error': 'Cannot disable last admin'}), 400
        # NS Aug 2026 (audit) — capture the enabled→disabled transition so we can drop live sessions
        # after save; validate_session (used by the decorator-less shell/VNC auth endpoints) has no
        # enabled recheck, so a stale session otherwise keeps node-shell access until it expires.
        _disabled = user.get('enabled', True) and not data['enabled']
        user['enabled'] = data['enabled']
    
    # NS: Apr 2026 — portal_only flag (user can only log in via /portal)
    if 'portal_only' in data:
        # MK: admins must never be portal_only — they'd lock themselves out of the dashboard
        if bool(data['portal_only']) and user.get('role') == ROLE_ADMIN:
            return jsonify({'error': 'Admin users cannot be set to portal-only'}), 400
        user['portal_only'] = bool(data['portal_only'])

    if 'user_folder' in data:
        user['user_folder'] = str(data['user_folder'] or '')

    # NS: Added tenant_id update support
    if 'tenant_id' in data:
        tenants = load_tenants()
        if data['tenant_id'] not in tenants:
            return jsonify({'error': 'Invalid tenant_id'}), 400
        user['tenant_id'] = data['tenant_id']
    
    _password_changed = False
    if 'password' in data and data['password']:
        # NS Aug 2026 (audit re-verify) — same tier guard as admin_change_password: a delegate must
        # not reset a same-tenant peer whose role grants perms beyond the delegate's (takeover). The
        # role-branch guard above only fires when 'role' is in the body, so a password-only PUT would
        # otherwise slip through this second-order path.
        if not _caller_can_manage_user(user):
            return jsonify({'error': 'Access denied: target has privileges beyond your own'}), 403
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
        _password_changed = True

    save_users(users_db)

    # NS Jul 2026 (CodeAnt session handling) — an admin password reset must invalidate the
    # target user's live sessions (mirrors admin_change_password); otherwise a stolen/old
    # session survives the reset. Scoped to the password branch so role/email/tenant edits
    # don't needlessly log the user out.
    if _password_changed:
        from pegaprox.utils.auth import invalidate_all_user_sessions
        invalidate_all_user_sessions(username)
        # sec (audit): the dedicated reset route revokes API tokens too; this one didn't, so an
        # exfiltrated pgx_ token survived the standard "lock the intruder out" action for up to a year.
        _revoked = revoke_user_api_tokens(username)
        from pegaprox.utils.realtime import invalidate_user_sse_tokens
        invalidate_user_sse_tokens(username)
        log_audit(request.session['user'], 'user.sessions_invalidated',
                  f"Invalidated sessions after password change for {username} "
                  f"({_revoked} API token(s) revoked)")

    # NS Aug 2026 (audit) — disabling an account must immediately drop its live sessions (root cause
    # of the "disabled operator keeps node-shell" gap); the enabled recheck added to the WS-auth
    # endpoints is the defence-in-depth backstop.
    if _disabled:
        from pegaprox.utils.auth import invalidate_all_user_sessions
        from pegaprox.utils.realtime import invalidate_user_ws_tokens, invalidate_user_sse_tokens
        invalidate_all_user_sessions(username)
        invalidate_user_ws_tokens(username)   # a pre-minted ws_token must not outlive the disable
        invalidate_user_sse_tokens(username)  # ...nor a pre-minted SSE token (audit)
        log_audit(request.session['user'], 'user.sessions_invalidated',
                  f"Invalidated sessions after disabling {username}")

    logging.info(f"Admin '{request.session['user']}' updated user '{username}'")
    log_audit(request.session['user'], 'user.updated', f"Updated user: {username}")
    
    return jsonify({'success': True})

@bp.route('/api/users/<username>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
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
    _ct = _caller_tenant_or_none()
    if _ct is not None and user.get('tenant_id', DEFAULT_TENANT_ID) != _ct:
        return jsonify({'error': 'Access denied: cannot delete users in other tenants'}), 403
    # sec (audit): same tier guard the password-reset and 2FA-clear paths use — a delegate must
    # not be able to remove a same-tenant peer whose grants exceed their own.
    if not _caller_can_manage_user(user):
        return jsonify({'error': 'Access denied: target has privileges beyond your own'}), 403
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
        # MK Sep 2026 (audit) — revoke the API tokens FIRST and treat a failure as a failed
        # deletion. This used to run after the account row was already gone, inside a
        # try/except that only warned, so a revocation error left live pgx_ bearer tokens
        # behind for a username that no longer existed. Tokens are keyed by username, and
        # the name is free again the moment the row goes: recreating it re-activated
        # somebody else's old tokens against the new account. Failing here leaves an
        # account whose tokens are revoked, which is the harmless direction.
        db.execute('UPDATE api_tokens SET revoked = 1 WHERE username = ?', (username,))
        db.delete_user(username)
        logging.info(f"Deleted user '{_sl(username)}' from database")
    except Exception as e:
        logging.error(f"Failed to delete user from DB: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500
    
    # Also remove from memory
    del users_db[username]

    # NS Jul 2026 (CodeAnt exploitation) — the previous inline purge mutated a STALE
    # `active_sessions` binding: auth.load_sessions() rebinds that module global to a fresh
    # dict after startup, so this imported name no longer points at the live store and the
    # loop removed 0 live sessions (validate_session kept accepting the deleted user's
    # cookie/token until it expired). Use the canonical helper, which locks + mutates the
    # LIVE store and persists. Also revoke the user's API tokens so a long-lived pgx_ token
    # can't outlive the account.
    from pegaprox.utils.auth import invalidate_all_user_sessions
    from pegaprox.utils.realtime import invalidate_user_ws_tokens, invalidate_user_sse_tokens
    invalidate_all_user_sessions(username)
    invalidate_user_ws_tokens(username)   # drop any pre-minted console/shell ws_token too
    invalidate_user_sse_tokens(username)  # and the SSE stream token (audit)

    logging.info(f"Admin '{_sl(request.session['user'])}' deleted user '{_sl(username)}'")
    log_audit(request.session['user'], 'user.deleted', f"Deleted user: {username}")
    
    return jsonify({'success': True})


# ============================================
# Tenant Management API Routes
# Multi-tenancy - most requested feature on reddit
# on Reddit. MSPs use this to manage multiple customers separately.
# ============================================

# NS Sep 2026 — the tenant limit fields are all "non-negative int, 0 = unlimited/none". They used
# to be read as int(data.get(k, 0) or 0), which raises on a non-numeric value and returns a bare
# 500; the update path swallowed it to 0 instead, which is worse for a LIMIT — a typo silently
# removed the ceiling. Parse once, refuse loudly. Found by the scan on this change: both routes
# were reachable with {"vmid_range_start": "abc"} and answered 500.
_TENANT_INT_FIELDS = ('quota_max_vms', 'quota_max_cores', 'quota_max_memory_gb',
                      'quota_max_disk_gb', 'vmid_range_start', 'vmid_range_end')


def _tenant_ints(data):
    """Return (values, error_response). values holds only the keys actually present."""
    out = {}
    for k in _TENANT_INT_FIELDS:
        if k not in data:
            continue
        v = data[k]
        if v in (None, ''):
            out[k] = 0
            continue
        try:
            iv = int(v)
        except (TypeError, ValueError):
            return None, (jsonify({'error': f'{k} must be a whole number'}), 400)
        if iv < 0:
            return None, (jsonify({'error': f'{k} must not be negative'}), 400)
        out[k] = iv
    return out, None


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
                'quota_max_vms': t.get('quota_max_vms', 0),
                'quota_max_cores': t.get('quota_max_cores', 0),
                'quota_max_memory_gb': t.get('quota_max_memory_gb', 0),
                'quota_max_disk_gb': t.get('quota_max_disk_gb', 0),
                'quota_enforcement': t.get('quota_enforcement', 'block'),
                'vmid_range_start': t.get('vmid_range_start', 0),
                'vmid_range_end': t.get('vmid_range_end', 0),
                'user_count': sum(1 for u in load_users().values() if u.get('tenant_id') == tid)
            })
        return jsonify(result)
    
    # non-admin: load user to get tenant_id
    users = load_users()
    user = users.get(username, {})
    user_tenant = user.get('tenant_id', DEFAULT_TENANT_ID)
    # SRK (SPEC-2026-011 D6): visible tenants = home UNION explicit
    # memberships UNION default. (Pre-D6 this was scalar-only, which hid
    # tenants like mmc from every dropdown even when roles were granted.)
    import pegaprox.utils.rbac as _rbac_d6
    _visible = {user_tenant, DEFAULT_TENANT_ID}
    _visible.update(_rbac_d6.get_user_tenant_memberships(username))
    
    result = []
    for tid, t in tenants_db.items():
        if tid not in _visible:
            continue
        
        result.append({
            'id': tid,
            'name': t.get('name', tid),
            'clusters': t.get('clusters', []),
            'created': t.get('created', ''),
            'quota_max_vms': t.get('quota_max_vms', 0),
            'quota_max_cores': t.get('quota_max_cores', 0),
            'quota_max_memory_gb': t.get('quota_max_memory_gb', 0),
            'quota_max_disk_gb': t.get('quota_max_disk_gb', 0),
            'quota_enforcement': t.get('quota_enforcement', 'block'),
            'vmid_range_start': t.get('vmid_range_start', 0),
            'vmid_range_end': t.get('vmid_range_end', 0),
            'user_count': sum(1 for u in users.values() if u.get('tenant_id') == tid)
        })

    return jsonify(result)


@bp.route('/api/me/tenants', methods=['GET'])
@require_auth()
def get_my_tenants():
    """The tenants the caller can act in — home tenant plus any they hold tenant_permissions for.

    NS Sep 2026 — /api/tenants answers "which tenants exist that you may SEE", and for a non-admin
    that is their home tenant plus default. It does not know about tenant_permissions, so someone
    delegated into a second tenant had no way to tell the UI about it. This is that list.

    Presentational ONLY. It grants nothing and no endpoint consumes it for a decision: everything
    downstream still derives the acting tenant from the session user, as it did before. Read this
    as "what should the switcher offer", never as "what is this caller allowed to do" — the moment
    something authorises off a client-chosen tenant id we are back to the class of bug the pool
    and ACL scoping already cost us twice."""
    from pegaprox.utils.auth import build_authz_user
    tenants = load_tenants() or {}
    user = build_authz_user(request.session.get('user', ''), request.session)
    home = user.get('tenant_id') or DEFAULT_TENANT_ID
    is_admin = user.get('effective_role', user.get('role')) == ROLE_ADMIN

    if is_admin:
        ids = list(tenants.keys())
    else:
        ids = [home] + [t for t in (user.get('tenant_permissions') or {}) if t != home]

    out = []
    for tid in ids:
        t = tenants.get(tid)
        if t is None:
            continue          # a stale tenant_permissions entry must not invent a tenant
        out.append({
            'id': tid,
            'name': t.get('name', tid),
            'is_home': tid == home,
            'effective_role': get_user_effective_role(user, tid),
        })
    return jsonify({'tenants': out, 'home': home})


@bp.route('/api/tenants', methods=['POST'])
@require_auth(perms=['admin.tenants'])
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

    _ints, _ierr = _tenant_ints(data)
    if _ierr:
        return _ierr

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
        # NS #502 — resource quotas (0 = unlimited); enforcement 'block' | 'warn'
        'quota_max_vms': _ints.get('quota_max_vms', 0),
        'quota_max_cores': _ints.get('quota_max_cores', 0),
        'quota_max_memory_gb': _ints.get('quota_max_memory_gb', 0),
        'quota_max_disk_gb': _ints.get('quota_max_disk_gb', 0),
        'quota_enforcement': data.get('quota_enforcement') or 'block',
        # NS Sep 2026 — 0/0 = no range, which is every tenant that does not ask for one
        'vmid_range_start': _ints.get('vmid_range_start', 0),
        'vmid_range_end': _ints.get('vmid_range_end', 0),
    }
    
    save_tenants(tenants_db)
    
    # new tenant, so the cached copy in rbac is stale either way
    invalidate_tenants_cache()
    log_audit(request.session['user'], 'tenant.created', f"Created tenant: {name} (id={tid})")
    
    return jsonify({'success': True, 'tenant': tenants_db[tid]})

@bp.route('/api/tenants/<tenant_id>', methods=['PUT'])
@require_auth(perms=['admin.tenants'])
def update_tenant(tenant_id):
    """Update tenant"""
    global tenants_db
    
    tenants_db = load_tenants()
    
    if tenant_id not in tenants_db:
        return jsonify({'error': 'Tenant not found'}), 404

    # snapshot before anything below writes into the dict — the range guard further down has to
    # compare against the STORED value, not against what the quota loop just put there
    _before = dict(tenants_db[tenant_id])

    # NS Aug 2026 (Aikido pentest) — mirror get_tenant_quota: a tenant-scoped admin.tenants holder
    # may only edit its OWN tenant, else one tenant rewrites another's name/clusters/quota.
    if request.session.get('role') != ROLE_ADMIN:
        _caller = get_db().get_user(request.session.get('user', '')) or {}
        if tenant_id != _caller.get('tenant_id', DEFAULT_TENANT_ID):
            return jsonify({'error': 'Access denied to this tenant'}), 403

    data = request.json

    # NS Sep 2026 — the VMID range is a boundary the PROVIDER draws between customers, so it sits
    # with `clusters` below rather than with the quotas: only a global admin may move it. A tenant
    # admin who could widen their own slice to 100-999999 would simply erase the separation the
    # range exists for. Checked BEFORE anything is written, so a refusal leaves the in-memory
    # tenants_db untouched rather than half-updated.
    _ints, _ierr = _tenant_ints(data)
    if _ierr:
        return _ierr
    for _rk in ('vmid_range_start', 'vmid_range_end'):
        if _rk in _ints and _ints[_rk] != int(_before.get(_rk, 0) or 0):
            if request.session.get('effective_role', request.session.get('role')) != ROLE_ADMIN:
                return jsonify({'error': 'Only a global admin can change a tenant\'s VMID range'}), 403

    if 'name' in data:
        tenants_db[tenant_id]['name'] = data['name']
    if 'clusters' in data:
        # sec (audit): tenant['clusters'] IS the list get_user_clusters reads, so a non-global
        # admin.tenants holder could append arbitrary cluster ids to their own tenant and become
        # a cluster-wide operator there. Only a global admin may change the cluster set.
        # Compare VALUES, not key presence — the tenant edit form posts the whole object every
        # time, so keying on presence 403'd a group_manager renaming a tenant or editing a quota.
        _cur = list(tenants_db[tenant_id].get('clusters') or [])
        _new = list(data['clusters'] or [])
        if sorted(map(str, _cur)) != sorted(map(str, _new)):
            if request.session.get('effective_role', request.session.get('role')) != ROLE_ADMIN:
                return jsonify({'error': 'Only a global admin can change a tenant\'s clusters'}), 403
            tenants_db[tenant_id]['clusters'] = _new
    # NS #502 — quota fields
    for _qk, _qv in _ints.items():
        tenants_db[tenant_id][_qk] = _qv
    # NS Sep 2026 — reject an inverted or reserved range rather than storing it: tenant_vmid_range
    # treats anything malformed as "no range", so a silently accepted 5000-100 would look saved in
    # the UI while enforcing nothing. PVE keeps VMIDs below 100 for itself.
    _rs = int(tenants_db[tenant_id].get('vmid_range_start', 0) or 0)
    _re_ = int(tenants_db[tenant_id].get('vmid_range_end', 0) or 0)
    if (_rs or _re_):
        if _rs < 100 or _re_ < 100:
            return jsonify({'error': 'VMID range must start at 100 or above'}), 400
        if _re_ < _rs:
            return jsonify({'error': 'VMID range end must not be below its start'}), 400
    if 'quota_enforcement' in data:
        tenants_db[tenant_id]['quota_enforcement'] = data['quota_enforcement'] or 'block'

    save_tenants(tenants_db)

    # a cluster removed here must stop being reachable now, not after the next restart
    invalidate_tenants_cache()
    log_audit(request.session['user'], 'tenant.updated', f"Updated tenant: {tenant_id}")
    
    return jsonify({'success': True, 'tenant': tenants_db[tenant_id]})

@bp.route('/api/tenants/<tenant_id>/quota', methods=['GET'])
@require_auth(perms=['admin.tenants'])
def get_tenant_quota(tenant_id):
    """#502 — live resource usage vs configured quota for a tenant"""
    try:
        # MK Jun 2026 (sec-review) — admin.tenants can be held by a tenant-scoped
        # custom role, so scope to the caller's own tenant unless a real admin —
        # otherwise one tenant could read another's live usage (BOLA).
        if request.session.get('role') != ROLE_ADMIN:
            _caller = get_db().get_user(request.session.get('user', '')) or {}
            if tenant_id != _caller.get('tenant_id', DEFAULT_TENANT_ID):
                return jsonify({'error': 'Access denied to this tenant'}), 403
        from pegaprox.utils.rbac import check_tenant_quota
        return jsonify(check_tenant_quota(tenant_id, add_cores=0, add_mem_gb=0, add_vms=0, force=True))
    except Exception as e:
        logging.error(f"tenant quota fetch failed: {e}")
        return jsonify({'usage': {}, 'quota': {}, 'enforce': 'block'})

@bp.route('/api/tenants/<tenant_id>', methods=['DELETE'])
@require_auth(perms=['admin.tenants'])
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
    
    # Update cache — this module's copy AND rbac's, which is the one get_user_clusters reads
    if tenant_id in tenants_db:
        del tenants_db[tenant_id]
    invalidate_tenants_cache()

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
    # MK Sep 2026 (audit) — this handed back the whole custom-roles tree to ANY authenticated
    # caller: every tenant's roles, their full permission lists, and the username that created
    # each one. list_all_roles() right below has filtered tenant roles to the caller's own
    # tenant since the multi-tenancy work; this endpoint never learned about tenants at all.
    custom = get_custom_roles()
    _u = build_authz_user(request.session.get('user', ''), request.session)
    if _u.get('effective_role', _u.get('role')) != ROLE_ADMIN:
        _ut = _u.get('tenant_id', DEFAULT_TENANT_ID)
        custom = {
            'global': custom.get('global', {}),
            'tenants': {t: r for t, r in (custom.get('tenants', {}) or {}).items() if t == _ut},
        }
    # builtin
    result = {
        'builtin': ROLE_PERMISSIONS,
        'custom': custom
    }
    return jsonify(result)


# ==================== CUSTOM ROLES API ====================
# custom role management

@bp.route('/api/roles', methods=['GET'])
@require_auth()
def list_all_roles():
    """List all available roles (builtin + custom)"""
    custom = get_custom_roles()
    
    # Get user's tenant for filtering
    user = build_authz_user(request.session.get('user', ''), request.session)
    user_tenant = user.get('tenant_id', DEFAULT_TENANT_ID)
    is_admin = user.get('effective_role', user.get('role')) == ROLE_ADMIN
    
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
    
    # tenant-specific - filter by user's tenant unless admin
    for tenant_id, tenant_roles in custom.get('tenants', {}).items():
        # Non-admins can only see roles from their own tenant
        if not is_admin and tenant_id != user_tenant:
            continue
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
    
    # Tenant validation: non-admins can only create roles for their own tenant
    user = build_authz_user(request.session.get('user', ''), request.session)
    if user.get('effective_role', user.get('role')) != ROLE_ADMIN:
        user_tenant = user.get('tenant_id', DEFAULT_TENANT_ID)
        if tenant_id and tenant_id != user_tenant:
            log_audit(request.session['user'], 'role.create_denied',
                     f"Access denied: attempted to create role '{role_id}' in tenant '{tenant_id}' (user tenant: '{user_tenant}')",
                     ip_address=request.remote_addr)
            return jsonify({'error': 'Access denied - cannot create roles in other tenants'}), 403
        # pin to own tenant — a non-admin must not create a global (cross-tenant) role
        tenant_id = user_tenant
        # NS Aug 2026 (audit) — and it must not mint a role granting perms it doesn't hold itself
        if not _caller_can_grant_perms(permissions):
            return jsonify({'error': 'Cannot grant permissions beyond your own'}), 403

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
    
    _saved = save_custom_roles(custom)
    # `custom` IS the live cached dict (get_custom_roles hands it back by reference)
    # and the edits above already went into it, so the cache has to go either way -
    # otherwise a refused write leaves a role that was never persisted sitting in
    # memory, granting permissions.
    invalidate_roles_cache()
    if not _saved:
        # save_custom_roles clears the table before rewriting it, so it refuses a
        # snapshot that never loaded. Do not audit this as done or report success.
        return jsonify({'error': 'Could not save the role - check the server logs',
                        'code': 'ROLE_WRITE_FAILED'}), 500
    
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
    
    # Tenant validation: non-admins can only update roles in their own tenant
    user = build_authz_user(request.session.get('user', ''), request.session)
    if user.get('effective_role', user.get('role')) != ROLE_ADMIN:
        user_tenant = user.get('tenant_id', DEFAULT_TENANT_ID)
        # Check if trying to update a role in a different tenant
        if tenant_id and tenant_id != user_tenant:
            log_audit(request.session['user'], 'role.update_denied',
                     f"Access denied: attempted to update role '{role_id}' in tenant '{tenant_id}' (user tenant: '{user_tenant}')",
                     ip_address=request.remote_addr)
            return jsonify({'error': 'Access denied - cannot update roles in other tenants'}), 403
        # pin to own tenant — a non-admin can't reach a global role this way
        tenant_id = user_tenant
        # NS Aug 2026 (audit) — a non-admin must not raise a role's perms above what it holds
        # itself; without this an admin.roles delegate rewrites its own role to admin.* and
        # self-escalates on the next request (require_auth re-resolves perms live).
        if permissions is not None and not _caller_can_grant_perms(permissions):
            return jsonify({'error': 'Cannot grant permissions beyond your own'}), 403

    # validate before touching anything: get_custom_roles hands back the live cached dict, and
    # the name used to be written into it before the permission list was checked — so a request
    # rejected with 400 still renamed the role for the rest of the process's life
    if permissions is not None:
        for p in permissions:
            if p not in PERMISSIONS:
                return jsonify({'error': f'Invalid permission: {p}'}), 400

    custom = get_custom_roles()
    roles = (custom.get('tenants', {}).get(tenant_id, {}) if tenant_id
             else custom.get('global', {}))
    if role_id not in roles:
        return jsonify({'error': 'Role not found'}), 404

    if name:
        roles[role_id]['name'] = name
    if permissions is not None:
        roles[role_id]['permissions'] = permissions
    roles[role_id]['modified'] = datetime.now().isoformat()
    
    _saved = save_custom_roles(custom)
    invalidate_roles_cache()   # `custom` is the live cache - drop it either way
    if not _saved:
        return jsonify({'error': 'Could not save the role - check the server logs',
                        'code': 'ROLE_WRITE_FAILED'}), 500
    
    log_audit(request.session['user'], 'role.updated', f"Updated role: {role_id}")
    return jsonify({'success': True})


@bp.route('/api/roles/<role_id>', methods=['DELETE'])
@require_auth(perms=['admin.roles'])
def delete_custom_role(role_id):
    """Delete a custom role"""
    if role_id in BUILTIN_ROLES:
        return jsonify({'error': 'Cannot delete builtin roles'}), 400
    
    tenant_id = request.args.get('tenant_id')
    
    # Tenant validation: non-admins can only delete roles in their own tenant
    user = build_authz_user(request.session.get('user', ''), request.session)
    if user.get('effective_role', user.get('role')) != ROLE_ADMIN:
        user_tenant = user.get('tenant_id', DEFAULT_TENANT_ID)
        # Check if trying to delete a role in a different tenant
        if tenant_id and tenant_id != user_tenant:
            log_audit(request.session['user'], 'role.delete_denied',
                     f"Access denied: attempted to delete role '{role_id}' in tenant '{tenant_id}' (user tenant: '{user_tenant}')",
                     ip_address=request.remote_addr)
            return jsonify({'error': 'Access denied - cannot delete roles in other tenants'}), 403
        # pin to own tenant — a non-admin can't delete a global role this way
        tenant_id = user_tenant

    custom = get_custom_roles()
    # look it up before touching anything: get_custom_roles hands back the live cached dict,
    # so deleting first and deciding afterwards drops the role out of the running process even
    # on a path that returns an error and never saves
    if tenant_id:
        found = role_id in custom.get('tenants', {}).get(tenant_id, {})
    else:
        found = role_id in custom.get('global', {})

    if not found:
        return jsonify({'error': 'Role not found'}), 404

    # sec (audit): deleting a role does not revoke it from the accounts holding it, and
    # get_role_permissions_for_user falls back to the ROLE_VIEWER defaults for a name it can no
    # longer resolve. So removing a deliberately narrow role WIDENED its holders — a role
    # granting vm.view left them with 31 permissions including the whole node, cluster and PBS
    # read surface. An admin deleting a role means "revoke this", never "promote them".
    # MK Sep 2026 (audit) — ask who holds THIS role, not who holds a role by this name.
    # The bare string was matched across every account, so deleting tenant A's 'ops' listed
    # the holders of tenant B's unrelated 'ops' — other tenants' usernames handed to the
    # caller, and a 409 blocking the delete over accounts they cannot see.
    def _holds(rec):
        rec = rec or {}
        _tp = rec.get('tenant_permissions', {}) or {}
        if tenant_id:
            # A tenant role lives in one namespace, so there are exactly two ways to hold
            # it: sit in that tenant, or carry an explicit override FOR that tenant from
            # anywhere else. The override is the one that is easy to miss — the account's
            # own tenant_id says nothing about it.
            if (_tp.get(tenant_id) or {}).get('role') == role_id:
                return True
            return (rec.get('tenant_id', DEFAULT_TENANT_ID) == tenant_id
                    and rec.get('role') == role_id)
        # a global role resolves for anyone, by role or by any override
        return (rec.get('role') == role_id
                or any((_ov or {}).get('role') == role_id for _ov in _tp.values()))

    _holders = sorted(u for u, rec in (load_users() or {}).items() if _holds(rec))
    if _holders:
        return jsonify({
            'error': 'Role still assigned',
            'detail': f"{len(_holders)} account(s) still hold '{role_id}' — reassign them "
                      f"before deleting, or they would silently fall back to viewer access.",
            'users': _holders[:20],
        }), 409

    if tenant_id:
        del custom['tenants'][tenant_id][role_id]
    else:
        del custom['global'][role_id]

    _saved = save_custom_roles(custom)
    invalidate_roles_cache()   # `custom` is the live cache - drop it either way
    if not _saved:
        return jsonify({'error': 'Could not save the role - check the server logs',
                        'code': 'ROLE_WRITE_FAILED'}), 500
    
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

    # NS Aug 2026 (audit) — mirror create_custom_role's boundary: a non-admin admin.roles delegate
    # must not inject a role into another tenant, create a global role, or mint a role granting
    # perms it doesn't hold (templates carry admin.* perms). create_custom_role guards this; the
    # template path did not.
    # sec (audit): read the role the way the create sibling does. request.session['role'] is the
    # value cached when the session was minted, so a demoted admin kept the old answer here until
    # they logged out — build_authz_user resolves it live and applies a token's floor.
    _caller = build_authz_user(request.session.get('user', ''), request.session)
    if _caller.get('effective_role', _caller.get('role')) != ROLE_ADMIN:
        _caller_tenant = _caller_tenant_or_none()
        if tenant_id and tenant_id != _caller_tenant:
            return jsonify({'error': 'Access denied - cannot create roles in other tenants'}), 403
        tenant_id = _caller_tenant  # pin; no global roles for a non-admin
        if not _caller_can_grant_perms(ROLE_TEMPLATES[template_id]['permissions']):
            return jsonify({'error': 'Cannot grant permissions beyond your own'}), 403

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
    
    _saved = save_custom_roles(custom)
    invalidate_roles_cache()   # `custom` is the live cache - drop it either way
    if not _saved:
        return jsonify({'error': 'Could not save the role - check the server logs',
                        'code': 'ROLE_WRITE_FAILED'}), 500
    
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

    # MK Sep 2026 (audit) — set_vm_acl got the per-VM gate; the reads beside it did not, and
    # this one returns the cluster's whole access map: which accounts reach which VM. An
    # ACL-scoped caller arrives here through the #248 fallback in check_cluster_access, so
    # cluster reach proves nothing. A plain cluster-wide operator still sees every row.
    from pegaprox.api.helpers import caller_is_scoped, scope_vm_rows
    _caller = build_authz_user(request.session.get('user', ''), request.session)
    if caller_is_scoped(_caller, cluster_id):
        result = scope_vm_rows(cluster_id, result)

    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/vm-acls/<int:vmid>', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_vm_acl(cluster_id, vmid):
    """Get ACL for a specific VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # same gap as the list route above, one object at a time
    from pegaprox.api.helpers import caller_is_scoped
    _caller = build_authz_user(request.session.get('user', ''), request.session)
    if caller_is_scoped(_caller, cluster_id) and not user_can_access_vm(
            _caller, cluster_id, vmid, 'vm.view'):
        return jsonify({'error': 'Access denied to this VM'}), 403

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

    # sec (Sep 2026): weigh what the row ACTUALLY hands out. inherit_role is the default
    # and grants a fixed ten-permission set (vm.config and vm.migrate among them) while
    # `permissions` goes unused - so the ceiling check was reading the wrong list, and a
    # delegate holding only vm.view could grant full VM control by leaving the default on.
    from pegaprox.utils.rbac import ACL_INHERITED_VM_PERMISSIONS
    _effective = list(ACL_INHERITED_VM_PERMISSIONS) if inherit_role else list(permissions)
    _err = _authz_object_write(cluster_id, subjects=users, permissions=_effective)
    if _err:
        return _err
    # and the caller must actually control the VM they are writing a rule for
    from pegaprox.utils.auth import build_authz_user as _bau
    from pegaprox.utils.rbac import user_can_access_vm as _ucav
    _caller = _bau(request.session.get('user', ''), request.session)
    if not _ucav(_caller, cluster_id, vmid, 'vm.config'):
        return jsonify({'error': 'Access denied to this VM'}), 403

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
    
    _saved = save_vm_acls(acls)
    invalidate_vm_acls_cache()
    if not _saved:
        return jsonify({'error': 'Could not save the VM ACL - check the server logs',
                        'code': 'ACL_WRITE_FAILED'}), 500
    
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
    # sec (Sep 2026): same gap as the pool-permission delete - the row's own members were
    # never weighed, so a tenant-scoped admin could drop an ACL granting access to another
    # tenant's user. Read the row first and hand its members to the gate.
    _existing = (get_vm_acls().get(cluster_id, {}) or {}).get(str(vmid), {}) or {}
    _err = _authz_object_write(cluster_id, subjects=list(_existing.get('users') or []))
    if _err:
        return _err
    
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
        return jsonify({'error': safe_error(e, 'User operation failed')}), 500


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


def _pool_visibility(cluster_id):
    """sec (private disclosure Sep 2026 — audit H3): pool list/detail were gated only by
    check_cluster_access (cluster reach), whose #555 pool fallback admits a pool-scoped user to the
    whole cluster — so they enumerated every pool's members, and /pools/<id> was a straight IDOR
    (pool-A user read pool-B). Gate at the POOL level: an admin or a plain cluster-wide operator sees
    all pools; a pool-/ACL-scoped caller sees only pools they hold a grant on. A pool grant authorizes
    viewing that pool's membership, so no per-member scoping is needed once the pool gate passes.

    Returns (confined, granted_pools): confined=True means restrict to granted_pools."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import _pool_perms_for
    user = build_authz_user(request.session.get('user', ''), request.session)
    if user.get('effective_role', user.get('role')) == ROLE_ADMIN:
        return False, set()
    _pp = _pool_perms_for(cluster_id, user.get('username', ''), user.get('groups', []))
    granted = {pid for pid, perms in (_pp or {}).items() if perms}
    # shared predicate — also catches the VM-ACL-scoped (Client Portal) caller the old inline
    # check missed; a plain cluster-wide operator on an owned cluster still keeps every pool.
    from pegaprox.api.helpers import caller_is_scoped
    return caller_is_scoped(user, cluster_id), granted


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

    _confined, _granted = _pool_visibility(cluster_id)
    if _confined:
        pools = [p for p in pools if p.get('poolid') in _granted]

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

    # sec (private disclosure Sep 2026 — audit H3): this was an IDOR — a pool-scoped caller could read
    # ANY pool's members by naming its id. Confine to pools the caller holds a grant on.
    _confined, _granted = _pool_visibility(cluster_id)
    if _confined and pool_id not in _granted:
        return jsonify({'error': 'Access denied to this pool'}), 403

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
    # MK Sep 2026 (audit) — the H3 disclosure gave get_pool_details() the pool-level gate
    # because check_cluster_access's #555 fallback admits a pool-scoped caller to the whole
    # cluster. This route sits directly beside it, answers for the same object, and was left
    # on cluster reach alone: pool-A's admin could read who holds what on pool B.
    _confined, _granted = _pool_visibility(cluster_id)
    if _confined and pool_id not in _granted:
        return jsonify({'error': 'Access denied to this pool'}), 403

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

    # sec (audit): pool_id and subject_id are attacker-chosen and POOL_PERMISSIONS includes
    # pool.admin, which short-circuits the per-VM gate for every VM in the pool — this is the
    # strongest grant primitive in the product and it had no object gate. _pool_visibility (the
    # H3 fix, ~100 lines up) gates pool READS; apply the same confinement to the write.
    # sec (Sep 2026): `permissions=[]` meant the ceiling check ran over nothing, so a
    # delegate could hand out pool permissions they do not hold - pool.admin included,
    # which short-circuits the per-VM gate for every VM in the pool.
    _err = _authz_object_write(cluster_id,
                               subjects=[subject_id] if subject_type == 'user' else [],
                               groups=[subject_id] if subject_type == 'group' else [],
                               permissions=permissions)
    if _err:
        return _err
    _confined, _granted = _pool_visibility(cluster_id)
    if _confined and pool_id not in _granted:
        return jsonify({'error': 'Access denied to this pool'}), 403

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
    # sec (Sep 2026): the subject was not passed, so a tenant-scoped admin could revoke
    # a grant belonging to another tenant's principal. Revoking is not granting, but it
    # is still reaching across the boundary - and it is how you lock a rival out.
    _err = _authz_object_write(cluster_id,
                               subjects=[subject_id] if subject_type == 'user' else [],
                               groups=[subject_id] if subject_type == 'group' else [])
    if _err:
        return _err
    _confined, _granted = _pool_visibility(cluster_id)
    if _confined and pool_id not in _granted:
        return jsonify({'error': 'Access denied to this pool'}), 403

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
    _perr = _authz_object_write(cluster_id)
    if _perr:
        return _perr
    
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
# MK: Mar 2026 - finally implemented the actual CRUD endpoints

# NS: Mar 2026 - pool CRUD endpoints
@bp.route('/api/clusters/<cluster_id>/pools', methods=['POST'])
@require_auth(perms=['admin.users'])
def create_pool_api(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _perr = _authz_object_write(cluster_id)
    if _perr:
        return _perr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json or {}
    poolid = data.get('poolid', '').strip()
    comment = data.get('comment', '').strip()
    if not poolid:
        return jsonify({'error': 'poolid is required'}), 400

    # proxmox pool IDs: alphanumeric + dash/underscore only
    if not re.match(r'^[a-zA-Z0-9_-]+$', poolid):
        return jsonify({'error': 'Pool ID: only letters, numbers, dash, underscore'}), 400

    mgr = cluster_managers[cluster_id]
    result = mgr.create_pool(poolid, comment)
    if not result.get('success'):
        return jsonify({'error': result.get('error', 'Failed')}), 400

    log_audit(request.session['user'], 'pool.created', f"Created pool '{poolid}'", cluster=mgr.config.name)
    invalidate_pool_cache(cluster_id)
    return jsonify({'success': True, 'message': f"Pool '{poolid}' created"})


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def update_pool_api(cluster_id, pool_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _perr = _authz_object_write(cluster_id)
    if _perr:
        return _perr
    _confined, _granted = _pool_visibility(cluster_id)
    if _confined and pool_id not in _granted:
        return jsonify({'error': 'Access denied to this pool'}), 403
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json or {}
    mgr = cluster_managers[cluster_id]
    result = mgr.update_pool(pool_id, comment=data.get('comment', ''),
                             members_to_add=data.get('add_members'),
                             members_to_remove=data.get('remove_members'))
    if not result.get('success'):
        return jsonify({'error': result.get('error', 'Update failed')}), 400

    log_audit(request.session['user'], 'pool.updated', f"Updated pool '{pool_id}'", cluster=mgr.config.name)
    invalidate_pool_cache(cluster_id)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def rm_pool(cluster_id, pool_id):
    # LW: intentionally different name than the others, we're not consistent lol
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _perr = _authz_object_write(cluster_id)
    if _perr:
        return _perr
    _confined, _granted = _pool_visibility(cluster_id)
    if _confined and pool_id not in _granted:
        return jsonify({'error': 'Access denied to this pool'}), 403
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    result = mgr.delete_pool(pool_id)
    if not result.get('success'):
        return jsonify({'error': result.get('error', 'Delete failed')}), 400

    log_audit(request.session['user'], 'pool.deleted', f"Deleted pool '{pool_id}'", cluster=mgr.config.name)
    invalidate_pool_cache(cluster_id)
    # clean up our permission records for this pool
    try:
        db = get_db()
        for p in db.get_pool_permissions(cluster_id, pool_id):
            db.delete_pool_permission(cluster_id, pool_id, p['subject_type'], p['subject_id'])
    except Exception as e:
        # MK Sep 2026 (audit) — "orphaned perms don't hurt" is not true: grants are keyed by
        # (cluster, pool_id) and a pool id is free to reuse, so a pool recreated under the same
        # name silently inherits whoever was granted on the old one. We cannot undo the PVE
        # delete at this point, so the honest thing is to say so loudly rather than swallow it.
        logging.error(f"[POOL] deleted pool '{_sl(pool_id)}' on {_sl(cluster_id)} but could not "
                      f"remove its permission rows - a pool recreated under this id would "
                      f"inherit them: {e}")
    return jsonify({'success': True})


# ─── User Folders ─── LW Apr 2026
# simple grouping for the user management UI

@bp.route('/api/user-folders', methods=['GET'])
@require_auth(perms=['admin.users'])
def list_user_folders():
    db = get_db()
    try:
        rows = db.conn.execute("SELECT * FROM user_folders ORDER BY sort_order, name").fetchall()
        return jsonify([dict(r) for r in rows])
    except:
        return jsonify([])


@bp.route('/api/user-folders', methods=['POST'])
@require_auth(perms=['admin.users'])
def create_user_folder():
    import uuid
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Folder name required'}), 400
    fid = uuid.uuid4().hex[:10]
    db = get_db()
    try:
        db.conn.execute(
            "INSERT INTO user_folders (id, name, color, sort_order, created_at) VALUES (?,?,?,?,?)",
            (fid, name, data.get('color', '#6b7280'), data.get('sort_order', 0), datetime.now().isoformat())
        )
        db.conn.commit()
        return jsonify({'success': True, 'id': fid})
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/user-folders/<folder_id>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def update_user_folder(folder_id):
    data = request.get_json() or {}
    db = get_db()
    sets, vals = [], []
    for k in ['name', 'color', 'sort_order']:
        if k in data:
            sets.append(f"{k} = ?")
            vals.append(data[k])
    if not sets:
        return jsonify({'error': 'No fields to update'}), 400
    vals.append(folder_id)
    try:
        db.conn.execute(f"UPDATE user_folders SET {', '.join(sets)} WHERE id = ?", vals)
        db.conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/user-folders/<folder_id>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_user_folder(folder_id):
    db = get_db()
    try:
        users_db = load_users()
        changed = False
        for u in users_db.values():
            if u.get('user_folder') == folder_id:
                u['user_folder'] = ''
                changed = True
        if changed:
            save_users(users_db)
        db.conn.execute("DELETE FROM user_folders WHERE id = ?", (folder_id,))
        db.conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


# ======================================================================
# SRK (SPEC-2026-010 P2): tenant-scoped multi-role management API.
# GET/PUT/DELETE /api/users/<username>/roles
# Guards (all server-side): require_auth(perms=['admin.users']) on every
# route; global admin (users.role == admin) bypasses tenant containment;
# a tenant-scoped admin.users holder may only manage users in their OWN
# tenant with roles of the SAME tenant. Grant validates the role exists
# and is tenant-pure (custom_roles.tenant_id). Revoking the PRIMARY role
# is rejected (it is managed via user edit, not the junction). Every
# mutation is audited (D8: user.role.grant / user.role.revoke). The P1
# resolvers are cache-free, so revocation bites on the next request.
# ======================================================================
def _roles_tenant_of(role_name):
    """Tenant of a custom role, or None if the role does not exist."""
    try:
        cur = get_db().conn.cursor()
        cur.execute('SELECT tenant_id FROM custom_roles WHERE name = ?', (role_name,))
        row = cur.fetchone()
        if row is None:
            return None
        row = row if isinstance(row, dict) else dict(zip(
            ['tenant_id'], [row[0]]))
        return row.get('tenant_id')
    except Exception as e:
        logging.error(f"[roles-api] role lookup failed for '{role_name}': {e}")
        return None


def _roles_guard(username, role_tenant=None):
    """Shared guard. Returns (target_user, None) or (None, (resp, status)).

    Containment: caller must exist; global admin passes; otherwise caller
    tenant must equal target tenant AND (when given) role tenant.
    """
    users = load_users()
    if username not in users:
        return None, (jsonify({'error': 'User not found'}), 404)
    target = users[username]
    sess = getattr(request, 'session', {}) or {}
    caller_name = sess.get('user', '')
    caller = users.get(caller_name)
    if not caller:
        # cannot establish containment -> deny (defense in depth; the
        # require_auth decorator has already authenticated the principal)
        return None, (jsonify({'error': 'Access denied'}), 403)
    if caller.get('role') == ROLE_ADMIN:
        return target, None
    caller_t = caller.get('tenant_id') or DEFAULT_TENANT_ID
    target_t = target.get('tenant_id') or DEFAULT_TENANT_ID
    if caller_t != target_t:
        return None, (jsonify({'error': 'Access denied'}), 403)
    if role_tenant is not None and role_tenant != caller_t:
        return None, (jsonify({'error': 'Access denied'}), 403)
    return target, None


def _roles_snapshot(username):
    import pegaprox.utils.rbac as _rb
    grants = _rb.get_user_role_grants(username)
    return grants


@bp.route('/api/users/<username>/roles', methods=['GET'])
@require_auth(perms=['admin.users'])
def roles_list(username):
    """List a user's granted junction roles + effective tenant set."""
    target, err = _roles_guard(username)
    if err:
        return err
    grants = _roles_snapshot(username)
    tset = sorted({g.get('tenant_id') for g in grants if g.get('tenant_id')})
    primary_t = target.get('tenant_id') or DEFAULT_TENANT_ID
    if target.get('role') != ROLE_ADMIN and primary_t not in tset:
        tset = [primary_t] + tset
    return jsonify({
        'username': username,
        'primary_role': target.get('role'),
        'granted_roles': grants,
        'role_tenants': tset,  # SRK (SPEC-2026-011 D6/A7): renamed from effective_tenants
        'effective_tenants': tset,  # deprecated alias, remove next release
    })


@bp.route('/api/users/<username>/roles', methods=['PUT'])
@require_auth(perms=['admin.users'])
def roles_grant(username):
    """Grant one tenant-pure role. Body: {"role": "<custom_role_name>"}"""
    body = request.get_json(silent=True) or {}
    role = (body.get('role') or '').strip()
    if not role:
        return jsonify({'error': 'role required'}), 400
    r_tenant = _roles_tenant_of(role)
    if r_tenant is None:
        # invariant 2: role must exist in custom_roles; no wildcard/derived
        return jsonify({'error': 'Unknown role'}), 404
    target, err = _roles_guard(username, role_tenant=r_tenant)
    if err:
        return err
    sess = getattr(request, 'session', {}) or {}
    caller_name = sess.get('user', '')
    db = get_db()
    cur = db.conn.cursor()
    # SRK (SPEC-2026-011 D6/A8): grant auto-memberships the role's tenant so
    # role_tenants stay inside the effective set. The GUARD above stays
    # home-pinned on purpose: membership alone never confers grant rights.
    try:
        import pegaprox.utils.rbac as _rbac_d6
        if r_tenant not in _rbac_d6.get_user_tenant_memberships(username):
            cur.execute(
                'INSERT OR IGNORE INTO user_tenants '
                '(username, tenant_id, granted_at, granted_by) VALUES (?, ?, ?, ?)',
                (username, r_tenant, datetime.now().isoformat(), caller_name))
            logging.info(f"[d6] auto-membership {username} -> {r_tenant}")
    except Exception as _e:
        logging.warning(f"[d6] auto-membership insert failed: {_e}")
    try:
        cur.execute(
            'INSERT OR IGNORE INTO user_roles '
            '(username, role_name, tenant_id, granted_at, granted_by) '
            'VALUES (?, ?, ?, ?, ?)',
            (username, role, r_tenant,
             datetime.now().isoformat(), caller_name)
        )
        db.conn.commit()
        inserted = cur.rowcount or 0
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500
    log_audit(caller_name, 'user.role.grant',
              f"user={username} role={role} tenant={r_tenant}")
    return jsonify({
        'success': True,
        'granted': bool(inserted),
        'granted_roles': _roles_snapshot(username),
    })


@bp.route('/api/users/<username>/roles', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def roles_revoke(username):
    """Revoke one granted role. Body: {"role": "<custom_role_name>"}"""
    body = request.get_json(silent=True) or {}
    role = (body.get('role') or '').strip()
    if not role:
        return jsonify({'error': 'role required'}), 400
    target, err = _roles_guard(username)
    if err:
        return err
    if target.get('role') == role:
        return jsonify({'error': 'Cannot revoke the primary role; '
                        'change it via user edit'}), 400
    sess = getattr(request, 'session', {}) or {}
    caller_name = sess.get('user', '')
    caller = load_users().get(caller_name, {})
    scoped = caller.get('role') != ROLE_ADMIN
    db = get_db()
    cur = db.conn.cursor()
    try:
        if scoped:
            cur.execute(
                'DELETE FROM user_roles WHERE username = ? AND role_name = ? '
                'AND tenant_id = ?',
                (username, role, caller.get('tenant_id') or DEFAULT_TENANT_ID))
        else:
            cur.execute(
                'DELETE FROM user_roles WHERE username = ? AND role_name = ?',
                (username, role))
        db.conn.commit()
        removed = cur.rowcount or 0
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500
    log_audit(caller_name, 'user.role.revoke',
              f"user={username} role={role} removed={bool(removed)}")
    return jsonify({
        'success': True,
        'revoked': bool(removed),
        'granted_roles': _roles_snapshot(username),
    })


# -- SRK (SPEC-2026-011 D6): explicit multi-tenant membership API -----------
@bp.route('/api/users/<username>/tenants', methods=['GET'])
@require_auth(perms=['admin.users'])
def tenants_list_d6(username):
    """List a user's explicit tenant memberships + home tenant."""
    target, err = _roles_guard(username)
    if err:
        return err
    import pegaprox.utils.rbac as _rbac_d6
    return jsonify({
        'username': username,
        'home_tenant': target.get('tenant_id', DEFAULT_TENANT_ID),
        'granted_tenants': _rbac_d6.get_user_tenant_memberships(username),
    })


@bp.route('/api/users/<username>/tenants', methods=['PUT'])
@require_auth(perms=['admin.users'])
def tenants_grant_d6(username):
    """Add a tenant membership. Body: {"tenant_id": "<id>"}"""
    body = request.get_json(silent=True) or {}
    tid = (body.get('tenant_id') or '').strip()
    if not tid:
        return jsonify({'error': 'tenant_id required'}), 400
    # Q1: tenant must exist
    if tid not in load_tenants():
        return jsonify({'error': 'Unknown tenant'}), 404
    target, err = _roles_guard(username)
    if err:
        return err
    sess = getattr(request, 'session', {}) or {}
    caller_name = sess.get('user', '')
    caller = load_users().get(caller_name, {})
    # Q1: non-admin caller needs a shared tenant with the target
    if caller.get('role') != ROLE_ADMIN:
        import pegaprox.utils.rbac as _rbac_d6
        _cset = set(_rbac_d6.get_user_tenant_memberships(caller_name)) | {caller.get('tenant_id', DEFAULT_TENANT_ID)}
        _tset = set(_rbac_d6.get_user_tenant_memberships(username)) | {target.get('tenant_id', DEFAULT_TENANT_ID)}
        if not (_cset & _tset):
            return jsonify({'error': 'Access denied: no shared tenant with this user'}), 403
    db = get_db()
    cur = db.conn.cursor()
    try:
        cur.execute(
            'INSERT OR IGNORE INTO user_tenants '
            '(username, tenant_id, granted_at, granted_by) VALUES (?, ?, ?, ?)',
            (username, tid, datetime.now().isoformat(), caller_name))
        db.conn.commit()
        inserted = cur.rowcount or 0
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500
    log_audit(caller_name, 'user.tenant.grant', f"user={username} tenant={tid}")
    import pegaprox.utils.rbac as _rbac_d6
    return jsonify({
        'success': True,
        'granted': bool(inserted),
        'granted_tenants': _rbac_d6.get_user_tenant_memberships(username),
    })


@bp.route('/api/users/<username>/tenants', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def tenants_revoke_d6(username):
    """Remove a tenant membership. Body: {"tenant_id": "<id>"}

    Role grants in the removed tenant stay in user_roles but go DORMANT (A10).
    Removing the HOME tenant re-points users.tenant to the oldest remaining
    membership (granted_at order) and re-adds the old home as a membership row
    so nothing is silently lost."""
    body = request.get_json(silent=True) or {}
    tid = (body.get('tenant_id') or '').strip()
    if not tid:
        return jsonify({'error': 'tenant_id required'}), 400
    target, err = _roles_guard(username)
    if err:
        return err
    home = target.get('tenant_id', DEFAULT_TENANT_ID)
    import pegaprox.utils.rbac as _rbac_d6
    memberships = _rbac_d6.get_user_tenant_memberships(username)
    remaining = [t for t in memberships if t != tid]
    if tid not in memberships:
        return jsonify({'error': 'Not a member of that tenant'}), 404
    sess = getattr(request, 'session', {}) or {}
    caller_name = sess.get('user', '')
    new_home = None
    if tid == home:
        if not remaining:
            return jsonify({'error': 'Cannot remove the last tenant'}), 400
        new_home = remaining[0]
        remaining = remaining[1:]
        users_db = load_users()
        users_db[username]['tenant_id'] = new_home
        save_users(users_db)
    db = get_db()
    cur = db.conn.cursor()
    try:
        if new_home:
            cur.execute(
                'INSERT OR IGNORE INTO user_tenants '
                '(username, tenant_id, granted_at, granted_by) VALUES (?, ?, ?, ?)',
                (username, home, datetime.now().isoformat(), caller_name))
        cur.execute('DELETE FROM user_tenants WHERE username = ? AND tenant_id = ?',
                    (username, tid))
        db.conn.commit()
        removed = cur.rowcount or 0
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500
    log_audit(caller_name, 'user.tenant.revoke',
              f"user={username} tenant={tid} removed={bool(removed)}"
              + (f" home_moved={home}->{new_home}" if new_home else ""))
    return jsonify({
        'success': True,
        'removed': bool(removed),
        'home_tenant': new_home or home,
        'granted_tenants': _rbac_d6.get_user_tenant_memberships(username),
    })
