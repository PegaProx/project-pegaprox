# -*- coding: utf-8 -*-
"""auth routes (login, logout, 2FA, OIDC, API tokens) - split from monolith dec 2025, NS"""

import time
import logging
import secrets
import base64
from datetime import datetime
from flask import Blueprint, jsonify, request, make_response

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import (
    hash_password, verify_password, needs_password_rehash,
    validate_password_policy, load_users, save_users, create_default_users,
    create_session, validate_session, invalidate_session,
    invalidate_all_user_sessions, cleanup_expired_sessions,
    generate_api_token, create_api_token, validate_api_token,
    list_user_tokens, revoke_api_token, require_auth,
    generate_session_id, mark_admin_initialized, ensure_api_tokens_table,
    ARGON2_AVAILABLE, TOTP_AVAILABLE,
)
from pegaprox.utils.audit import log_audit
from pegaprox.utils.ldap import get_ldap_settings, ldap_authenticate, ldap_provision_user
from pegaprox.utils.oidc import (
    get_oidc_settings, get_oidc_endpoints, oidc_build_auth_url,
    oidc_exchange_code, oidc_decode_id_token, oidc_get_user_info,
    oidc_get_user_groups, oidc_map_groups_to_role, oidc_provision_user,
)
from pegaprox.utils.rbac import get_user_permissions, DEFAULT_TENANT_ID
from pegaprox.api.helpers import load_server_settings, save_server_settings, get_login_settings, get_session_timeout
from pegaprox.utils.sanitization import sanitize_identifier
from pegaprox.utils.ssh import check_auth_action_rate_limit
from pegaprox.app import add_allowed_origin
import requests

try:
    import pyotp
    import qrcode
    import io as _io
except ImportError:
    pass

bp = Blueprint('auth', __name__)

# ============================================================================
    

@bp.route('/api/auth/oidc/authorize', methods=['GET'])
def oidc_authorize():
    """Initiate OIDC login flow - redirects user to identity provider
    
    NS: Generates CSRF state, stores in session, redirects to IdP
    """
    config = get_oidc_settings()
    if not config['enabled'] or not config['client_id']:
        return jsonify({'error': 'OIDC authentication is not configured'}), 400
    
    # NS: Auto-detect redirect URI if not configured
    if not config.get('redirect_uri'):
        # Build from request origin
        origin = request.headers.get('Origin') or request.host_url.rstrip('/')
        config['redirect_uri'] = f"{origin}/oidc/callback"
        logging.info(f"[OIDC] Auto-detected redirect_uri: {config['redirect_uri']}")
    
    # MK: Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    
    # Store state in a temporary way (cookie-based since no session yet)
    auth_url = oidc_build_auth_url(config, state)
    
    response = make_response(jsonify({'auth_url': auth_url}))  # NS: Don't return state in body - it's in the cookie
    # LW: Store state in secure cookie for callback verification
    is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
    response.set_cookie('oidc_state', state, httponly=True, secure=is_secure, samesite='Lax', max_age=600)
    return response


@bp.route('/api/auth/oidc/callback', methods=['POST'])
def oidc_callback():
    """Handle OIDC callback - exchange code for tokens and create session
    
    LW: Called by frontend after redirect back from IdP
    Frontend sends: {code, state} from URL query params
    """
    # NS: SECURITY - Basic rate limiting on callback (prevent brute-force code replay)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    oidc_cb_key = f'oidc_cb_{client_ip}'
    if oidc_cb_key in login_attempts_by_ip:
        attempts = login_attempts_by_ip[oidc_cb_key].get('attempts', [])
        recent = [t for t in attempts if time.time() - t < 60]
        if len(recent) >= 10:
            logging.warning(f"[OIDC] Rate limit hit for callback from {client_ip}")
            return jsonify({'error': 'Too many attempts. Try again later.'}), 429
        login_attempts_by_ip[oidc_cb_key] = {'attempts': recent + [time.time()]}
    else:
        login_attempts_by_ip[oidc_cb_key] = {'attempts': [time.time()]}
    
    config = get_oidc_settings()
    if not config['enabled']:
        return jsonify({'error': 'OIDC authentication is not configured'}), 400
    
    # NS: Auto-detect redirect URI if not configured (must match what was sent in authorize!)
    if not config.get('redirect_uri'):
        origin = request.headers.get('Origin') or request.host_url.rstrip('/')
        config['redirect_uri'] = f"{origin}/oidc/callback"
    
    data = request.get_json() or {}
    code = data.get('code', '')
    state = data.get('state', '')
    
    if not code:
        return jsonify({'error': 'Authorization code is required'}), 400
    
    # NS: Verify CSRF state
    stored_state = request.cookies.get('oidc_state', '')
    if not stored_state or stored_state != state:
        logging.warning(f"[OIDC] State mismatch - possible CSRF attack")
        return jsonify({'error': 'Invalid state parameter (CSRF protection)'}), 400
    
    # Step 1: Exchange code for tokens
    token_data = oidc_exchange_code(config, code)
    if 'error' in token_data:
        return jsonify({'error': token_data['error']}), 401
    
    access_token = token_data.get('access_token', '')
    id_token_raw = token_data.get('id_token', '')
    
    if not access_token:
        return jsonify({'error': 'No access token received'}), 401
    
    # Step 2: Decode ID token for claims
    id_claims = {}
    if id_token_raw:
        id_claims = oidc_decode_id_token(id_token_raw)
        if 'error' in id_claims:
            logging.warning(f"[OIDC] ID token decode warning: {id_claims['error']}")
            id_claims = {}
    
    # Step 3: Get user info from provider
    user_info = oidc_get_user_info(config, access_token)
    if not user_info:
        # MK: Fallback to ID token claims
        user_info = id_claims
    
    if not user_info or not (user_info.get('preferred_username') or user_info.get('email') or user_info.get('sub')):
        return jsonify({'error': 'Could not retrieve user information from provider'}), 401
    
    # Step 4: Get group memberships for role mapping
    groups = oidc_get_user_groups(config, access_token)
    role_mapping = oidc_map_groups_to_role(config, groups, id_claims)
    
    # Step 5: Provision/update local user
    if not config['auto_create_users']:
        # Check if user already exists
        # MK: this has to match the logic in oidc_provision_user or we get mismatches
        # (had a bug where "john.doe" here vs "johndoe" in provision caused 403s)
        email = user_info.get('email') or user_info.get('preferred_username', '')
        raw_username = user_info.get('preferred_username') or email
        check_username = raw_username.split('@')[0].lower() if '@' in raw_username else raw_username.lower()
        check_username = ''.join(c for c in check_username if c.isalnum() or c in '._-')
        if not check_username:
            check_username = f"oidc_{user_info.get('sub', 'unknown')[:12]}"
        users = load_users()
        if check_username not in users:
            return jsonify({'error': 'User account does not exist. Contact an administrator.'}), 403
    
    # Determine auth_source label
    provider = config.get('provider', 'oidc')
    auth_source = 'entra' if provider == 'entra' else 'oidc'
    
    user = oidc_provision_user(user_info, role_mapping, auth_source=auth_source)
    
    # NS: SECURITY - oidc_provision_user returns None if local account would be overwritten
    if not user:
        return jsonify({'error': 'A local account with this username already exists. Contact an administrator.'}), 403
    
    username = user.get('username', '')
    
    # Check if user is enabled
    users = load_users()
    if username in users and not users[username].get('enabled', True):
        return jsonify({'error': 'Account is disabled'}), 403
    
    # Step 6: Create session via create_session() for proper session rotation + limits
    # MK: create_session() handles max 3 sessions per user, session rotation, save_sessions()
    session_token = create_session(username, user.get('role', ROLE_VIEWER))
    
    log_audit(username, 'auth.oidc.login', f"OIDC login via {provider} from {request.remote_addr}")
    
    response = make_response(jsonify({
        'success': True,
        'user': username,
        'role': user.get('role', ROLE_VIEWER),
        'display_name': user.get('display_name', username),
        'auth_source': auth_source,
        'session_id': session_token,
    }))
    
    # Set session cookie (same pattern as regular login)
    is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
    response.set_cookie(
        'session_id',
        session_token,
        httponly=True,
        samesite='Strict',
        secure=is_secure,
        max_age=get_session_timeout()
    )
    # Clear OIDC state cookie
    response.delete_cookie('oidc_state')
    
    return response


@bp.route('/api/auth/oidc/config', methods=['GET'])
def oidc_get_public_config():
    """Return public OIDC config (non-sensitive) for login page
    
    NS: Frontend needs to know if OIDC is enabled and button text
    No auth required - this is used on the login page
    """
    config = get_oidc_settings()
    return jsonify({
        'enabled': config['enabled'],
        'provider': config.get('provider', 'entra'),
        'button_text': config.get('button_text', 'Sign in with Microsoft'),
    })


@bp.route('/api/settings/oidc/test', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def oidc_test_connection():
    """Test OIDC configuration by verifying endpoints are reachable
    
    MK: Tests connectivity to OIDC discovery and token endpoints
    """
    data = request.get_json() or {}
    config = get_oidc_settings()
    
    # Override with test data
    for key in ['oidc_client_id', 'oidc_tenant_id', 'oidc_provider', 'oidc_authority', 'oidc_cloud_environment']:
        if key in data:
            short_key = key.replace('oidc_', '')
            config[short_key] = data[key]
    
    results = []
    
    # Step 1: Check endpoints exist
    endpoints = get_oidc_endpoints(config)
    cloud_env = config.get('cloud_environment', 'commercial')
    env_label = {'commercial': 'Commercial', 'gcc': 'GCC', 'gcc_high': 'GCC High', 'dod': 'DoD'}.get(cloud_env, cloud_env)
    results.append({'step': 'Configuration', 'status': 'ok', 'detail': f"Provider: {config['provider']}, Tenant: {config.get('tenant_id', 'N/A')}, Cloud: {env_label}"})
    
    # Step 2: Test authorization endpoint
    try:
        resp = requests.get(endpoints['authorization'], allow_redirects=False, timeout=10)
        # Auth endpoint should return 200 or redirect
        if resp.status_code in [200, 302, 400]:
            results.append({'step': 'Authorization Endpoint', 'status': 'ok', 'detail': endpoints['authorization']})
        else:
            results.append({'step': 'Authorization Endpoint', 'status': 'error', 'detail': f"HTTP {resp.status_code}"})
    except Exception as e:
        results.append({'step': 'Authorization Endpoint', 'status': 'error', 'detail': str(e)})
    
    # Step 3: Test JWKS endpoint
    try:
        resp = requests.get(endpoints['jwks'], timeout=10)
        if resp.status_code == 200:
            keys = resp.json().get('keys', [])
            results.append({'step': 'JWKS Endpoint', 'status': 'ok', 'detail': f"Found {len(keys)} signing keys"})
        else:
            results.append({'step': 'JWKS Endpoint', 'status': 'error', 'detail': f"HTTP {resp.status_code}"})
    except Exception as e:
        results.append({'step': 'JWKS Endpoint', 'status': 'error', 'detail': str(e)})
    
    # Step 4: Check client_id is set
    if config['client_id']:
        results.append({'step': 'Client ID', 'status': 'ok', 'detail': f"{config['client_id'][:8]}..."})
    else:
        results.append({'step': 'Client ID', 'status': 'warning', 'detail': 'Not configured'})
    
    # Step 5: Check redirect URI
    if config.get('redirect_uri'):
        results.append({'step': 'Redirect URI', 'status': 'ok', 'detail': config['redirect_uri']})
    else:
        results.append({'step': 'Redirect URI', 'status': 'warning', 'detail': 'Not configured - will auto-detect'})
    
    all_ok = all(r['status'] == 'ok' for r in results)
    return jsonify({'success': all_ok, 'results': results})


@bp.route('/api/auth/login', methods=['POST'])
def auth_login():
    """login endpoint - MK"""
    global users_db, login_attempts_by_ip, login_attempts_by_user
    
    # get settings
    login_settings = get_login_settings()
    max_attempts = login_settings['max_attempts']
    lockout_time = login_settings['lockout_time']
    attempt_window = login_settings['attempt_window']
    
    # get ip (handle proxies)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    
    current_time = time.time()
    
    # check if ip is locked
    if client_ip in login_attempts_by_ip:
        attempt_info = login_attempts_by_ip[client_ip]
        if attempt_info.get('locked_until', 0) > current_time:
            remaining = int(attempt_info['locked_until'] - current_time)
            logging.warning(f"locked ip tried to login: {client_ip}")
            return jsonify({
                'error': f'Too many failed attempts. Try again in {remaining} seconds.',
                'locked': True,
                'retry_after': remaining
            }), 429
        # cleanup old attempts
        attempt_info['attempts'] = [t for t in attempt_info.get('attempts', []) 
                                    if current_time - t < attempt_window]
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    # sanitize inputs (security stuff)
    username = sanitize_identifier(data.get('username', '').strip().lower(), max_length=64)
    password = data.get('password', '')[:256]  # limit to prevent DoS
    totp_code = sanitize_identifier(data.get('totp_code', ''), max_length=10)
    
    # print(f"login: {username}")  # DEBUG - remove before commit!! - NS
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if len(username) < 2:
        return jsonify({'error': 'Username too short'}), 400
    
    # Check if username is locked out (additional protection against distributed attacks)
    if username in login_attempts_by_user:
        user_attempt_info = login_attempts_by_user[username]
        if user_attempt_info.get('locked_until', 0) > current_time:
            remaining = int(user_attempt_info['locked_until'] - current_time)
            logging.warning(f"Login attempt for locked user: {username} from {client_ip}, {remaining}s remaining")
            return jsonify({
                'error': f'Account temporarily locked. Try again in {remaining} seconds.',
                'locked': True,
                'retry_after': remaining
            }), 429
        # Clean up old attempts
        user_attempt_info['attempts'] = [t for t in user_attempt_info.get('attempts', []) 
                                          if current_time - t < attempt_window]
    
    # Helper function to record failed attempt (both IP and username)
    def record_failed_attempt(target_username=None):
        locked = False
        
        # Track by IP
        if client_ip not in login_attempts_by_ip:
            login_attempts_by_ip[client_ip] = {'attempts': [], 'locked_until': 0}
        login_attempts_by_ip[client_ip]['attempts'].append(current_time)
        recent_ip = [t for t in login_attempts_by_ip[client_ip]['attempts'] 
                     if current_time - t < attempt_window]
        if len(recent_ip) >= max_attempts:
            login_attempts_by_ip[client_ip]['locked_until'] = current_time + lockout_time
            logging.warning(f"IP {client_ip} locked out after {len(recent_ip)} failed attempts")
            locked = True
        
        # Track by username (if provided and valid)
        if target_username:
            if target_username not in login_attempts_by_user:
                login_attempts_by_user[target_username] = {'attempts': [], 'locked_until': 0}
            login_attempts_by_user[target_username]['attempts'].append(current_time)
            recent_user = [t for t in login_attempts_by_user[target_username]['attempts'] 
                          if current_time - t < attempt_window]
            # Use slightly higher threshold for username (10 attempts) to prevent username enumeration lockout
            if len(recent_user) >= max_attempts * 2:
                login_attempts_by_user[target_username]['locked_until'] = current_time + lockout_time
                logging.warning(f"User '{target_username}' locked out after {len(recent_user)} failed attempts")
                locked = True
        
        return locked
    
    # Reload users in case they were updated
    # NS: had a bug where user changes werent reflected until restart
    users_db = load_users()
    
    # =================================================================
    # MK: Feb 2026 - LDAP Authentication (tried before local auth)
    # Flow: LDAP enabled? → Try LDAP bind → JIT provision → session
    # If LDAP fails or disabled → fall through to local password auth
    # =================================================================
    ldap_config = get_ldap_settings()
    ldap_authenticated = False
    
    if ldap_config['enabled']:
        ldap_result = ldap_authenticate(username, password)
        
        if ldap_result.get('success'):
            # LW: LDAP auth succeeded - provision/update local user
            if ldap_config['auto_create_users'] or username in users_db:
                user = ldap_provision_user(ldap_result)
                if user is None:
                    # NS: Local account exists - fall through to local auth
                    logging.info(f"[LDAP] User '{username}' has local account, skipping LDAP provisioning")
                else:
                    users_db = load_users()  # Reload after provisioning
                    ldap_authenticated = True
                    logging.info(f"[LDAP] User '{username}' authenticated via LDAP from {client_ip}")
            else:
                logging.warning(f"[LDAP] User '{username}' found in LDAP but auto-create is disabled")
                return jsonify({'error': 'User not authorized in PegaProx. Contact admin.'}), 401
        elif ldap_result.get('error') == 'User not found in LDAP':
            # NS: User not in LDAP - fall through to local auth
            logging.debug(f"[LDAP] User '{username}' not in LDAP, trying local auth")
        elif 'Invalid LDAP credentials' in ldap_result.get('error', ''):
            # User found in LDAP but wrong password - check if also local user
            if username in users_db and users_db[username].get('auth_source') == 'ldap':
                # Pure LDAP user - don't fall through to local auth
                logging.warning(f"[LDAP] Failed login for LDAP user '{username}' from {client_ip}")
                locked = record_failed_attempt(username)
                if locked:
                    return jsonify({
                        'error': f'Too many failed attempts. Try again in {lockout_time} seconds.',
                        'locked': True, 'retry_after': lockout_time
                    }), 429
                return jsonify({'error': 'Invalid credentials'}), 401
            # Else: user exists locally too, fall through to local auth
        else:
            # LDAP server error - log but fall through to local auth
            logging.warning(f"[LDAP] Server error during auth: {ldap_result.get('error')}")
    
    # =================================================================
    # Local Authentication (skipped if LDAP already authenticated)
    # =================================================================
    if not ldap_authenticated:
        # check user exists
        if username not in users_db:
            logging.warning(f"Login attempt for unknown user: {username} from {client_ip}")
            locked = record_failed_attempt()  # Don't track by username for unknown users
            if locked:
                return jsonify({
                    'error': f'Too many failed attempts. Try again in {lockout_time} seconds.',
                    'locked': True,
                    'retry_after': lockout_time
                }), 429
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user = users_db[username]
        
        # check user is enabled
        if not user.get('enabled', True):
            logging.warning(f"Login attempt for disabled user: {username} from {client_ip}")
            return jsonify({'error': 'Account is disabled'}), 401
        
        # NS: LDAP-only users cannot login with local password
        if user.get('auth_source') == 'ldap' and not user.get('password_hash'):
            logging.warning(f"LDAP user '{username}' tried local login but has no local password")
            return jsonify({'error': 'Please use LDAP credentials to sign in'}), 401
        
        # Verify password
        if not verify_password(password, user['password_salt'], user['password_hash']):
            logging.warning(f"Failed login attempt for user: {username} from {client_ip}")
            locked = record_failed_attempt(username)
            if locked:
                return jsonify({
                    'error': f'Too many failed attempts. Try again in {lockout_time} seconds.',
                    'locked': True,
                    'retry_after': lockout_time
                }), 429
            return jsonify({'error': 'Invalid credentials'}), 401
    else:
        user = users_db[username]
        
        # check user is enabled (even LDAP users can be disabled locally)
        if not user.get('enabled', True):
            logging.warning(f"LDAP user '{username}' is disabled locally")
            return jsonify({'error': 'Account is disabled'}), 401
    
    # check 2FA is required
    if user.get('totp_enabled') and user.get('totp_secret'):
        if not totp_code:
            # Return that 2FA is required
            return jsonify({
                'requires_2fa': True,
                'message': '2FA code required'
            }), 200
        
        # Verify TOTP code
        if TOTP_AVAILABLE:
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code):
                logging.warning(f"Invalid 2FA code for user: {username} from {client_ip}")
                locked = record_failed_attempt(username)
                if locked:
                    return jsonify({
                        'error': f'Too many failed attempts. Try again in {lockout_time} seconds.',
                        'locked': True,
                        'retry_after': lockout_time
                    }), 429
                return jsonify({'error': 'Invalid 2FA code'}), 401
        else:
            return jsonify({'error': '2FA is enabled but pyotp is not installed on server'}), 500
    
    # Clear failed attempts on successful login (both IP and username)
    if client_ip in login_attempts_by_ip:
        del login_attempts_by_ip[client_ip]
    if username in login_attempts_by_user:
        del login_attempts_by_user[username]
    
    # NS: Auto-migrate password to Argon2id if using old PBKDF2 format - Jan 2026
    # Only rehash for locally-authenticated users - LDAP passwords must NEVER be stored locally
    if not ldap_authenticated and needs_password_rehash(user.get('password_salt', ''), user.get('password_hash', '')):
        try:
            new_salt, new_hash = hash_password(password)
            user['password_salt'] = new_salt
            user['password_hash'] = new_hash
            save_users(users_db)
            logging.info(f"Migrated password for user '{username}' to Argon2id (Military Grade)")
        except Exception as e:
            logging.warning(f"Failed to migrate password for {username}: {e}")
    
    # Create session
    session_id = create_session(username, user['role'])
    
    # Update last login
    user['last_login'] = datetime.now().isoformat()
    save_users(users_db)
    
    logging.info(f"User '{username}' logged in successfully")
    log_audit(username, 'user.login', f"User logged in" + (" (with 2FA)" if user.get('totp_enabled') else ""))
    
    # Auto-allow this origin for CORS (Open Source convenience)
    # Only authenticated users from valid origins get added
    origin = request.headers.get('Origin')
    if origin:
        add_allowed_origin(origin)
    
    # NS: Get default theme for response
    settings = load_server_settings()
    default_theme = settings.get('default_theme', 'proxmoxDark')
    
    # NS: Feb 2026 - Check if user needs to set up 2FA (force_2fa setting)
    requires_2fa_setup = False
    if settings.get('force_2fa') and TOTP_AVAILABLE:
        has_2fa = user.get('totp_enabled', False)
        is_external = user.get('auth_source', 'local') in ('oidc', 'entra')
        is_admin = user.get('role') == ROLE_ADMIN
        exclude_admins = settings.get('force_2fa_exclude_admins', False)
        if not has_2fa and not is_external and not (is_admin and exclude_admins):
            requires_2fa_setup = True
    
    # NS: Debug log for theme sync issues
    user_theme = user.get('theme', '') or default_theme
    logging.info(f"[LOGIN] User {username} theme from DB: '{user.get('theme', '')}', using: '{user_theme}'")
    
    response = jsonify({
        'success': True,
        'user': {
            'username': username,
            'role': user['role'],
            'display_name': user.get('display_name', username),
            'email': user.get('email', ''),
            'auth_source': user.get('auth_source', 'local'),  # NS: For LDAP/Entra/OIDC badge
            'permissions': get_user_permissions(user),  # LW: Frontend can hide/show buttons
            'tenant_id': user.get('tenant_id', DEFAULT_TENANT_ID),
            'totp_enabled': user.get('totp_enabled', False),
            'theme': user_theme,  # NS: Use default if empty
            'language': user.get('language', ''),
            'ui_layout': user.get('ui_layout', 'modern'),
            'taskbar_auto_expand': user.get('taskbar_auto_expand', True)  # NS: Feb 2026
        },
        'session_id': session_id,
        'default_theme': default_theme,  # NS: Include for frontend fallback
        'requires_2fa_setup': requires_2fa_setup,  # NS: Feb 2026 - Force 2FA
        # NS: Security warning if using default password
        'security_warning': 'DEFAULT_PASSWORD' if (user['role'] == ROLE_ADMIN and password == 'admin') else None
    })
    
    # Set session cookie with security flags
    # NS: Secure flag only when using HTTPS (important for production!)
    is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
    response.set_cookie(
        'session_id', 
        session_id, 
        httponly=True,       # JS cant access this cookie
        samesite='Strict',   # CSRF protection
        secure=is_secure,    # only send over HTTPS
        max_age=get_session_timeout()
    )
    
    return response

@bp.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    """Logout user and invalidate session"""
    session_id = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
    
    if session_id:
        session = validate_session(session_id)
        if session:
            logging.info(f"User '{session['user']}' logged out")
            log_audit(session['user'], 'user.logout', f"User logged out")
        invalidate_session(session_id)
    
    response = jsonify({'success': True})
    response.delete_cookie('session_id')
    return response

@bp.route('/api/auth/check', methods=['GET'])
def auth_check():
    """Check if current session is valid"""
    session_id = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
    
    session = validate_session(session_id)
    if not session:
        # NS: Feb 2026 - Include LDAP/OIDC status so login page can show indicators
        settings = load_server_settings()
        ldap_enabled = settings.get('ldap_enabled', False)
        oidc_enabled = settings.get('oidc_enabled', False)
        oidc_button_text = settings.get('oidc_button_text', 'Sign in with Microsoft')
        return jsonify({'authenticated': False, 'ldap_enabled': ldap_enabled, 'oidc_enabled': oidc_enabled, 'oidc_button_text': oidc_button_text}), 401
    
    # Get user info - always fresh from database
    users_db = load_users()
    user = users_db.get(session['user'], {})
    
    # NS: Feb 2026 - If user was disabled while session is active, force logout
    if not user or not user.get('enabled', True):
        logging.info(f"[AUTH_CHECK] User '{session['user']}' is disabled or deleted, invalidating session")
        invalidate_session(session_id)
        return jsonify({'authenticated': False, 'reason': 'account_disabled'}), 401
    
    logging.debug(f"auth_check for {session['user']}: ui_layout = {user.get('ui_layout')}")
    
    # LW: Check password expiry status - Dec 2025
    password_expiry = None
    settings = load_server_settings()
    
    # Check if user should be subject to password expiry
    # MK: admins are exempt by default, but can opt-in via settings
    # NS: LDAP/OIDC users are ALWAYS exempt - they don't have local passwords
    is_admin = session['role'] == ROLE_ADMIN
    is_external_auth = user.get('auth_source', 'local') in ('ldap', 'oidc', 'entra')
    include_admins = settings.get('password_expiry_include_admins', False)
    should_check_expiry = settings.get('password_expiry_enabled') and not is_external_auth and (not is_admin or include_admins)
    
    if should_check_expiry:
        expiry_days = settings.get('password_expiry_days', 90)
        warning_days = settings.get('password_expiry_warning_days', 14)
        
        changed_at = user.get('password_changed_at')
        if changed_at:
            try:
                changed_date = datetime.fromisoformat(changed_at.replace('Z', '+00:00'))
                # handle naive datetime
                if changed_date.tzinfo:
                    changed_date = changed_date.replace(tzinfo=None)
                days_since = (datetime.now() - changed_date).days
                days_until_expiry = expiry_days - days_since
                
                password_expiry = {
                    'enabled': True,
                    'days_until_expiry': days_until_expiry,
                    'expired': days_until_expiry <= 0,
                    'warning': days_until_expiry <= warning_days and days_until_expiry > 0,
                    'expiry_days': expiry_days
                }
            except:
                pass  # couldn't parse date, skip
        else:
            # no password_changed_at means old user, treat as expired
            password_expiry = {
                'enabled': True,
                'days_until_expiry': 0,
                'expired': True,
                'warning': False,
                'expiry_days': expiry_days
            }
    
    # Get default theme from settings
    default_theme = settings.get('default_theme', 'proxmoxDark')
    
    # NS: Debug log for theme sync issues
    user_theme = user.get('theme', '') or default_theme
    logging.debug(f"[AUTH_CHECK] User {session['user']} theme from DB: '{user.get('theme', '')}', using: '{user_theme}'")
    
    # NS: always check DB for latest role, session might be stale if admin changed it
    # This ensures role changes by admin take effect immediately
    fresh_role = user.get('role', session['role'])
    if fresh_role != session['role']:
        # MK: Update session to match DB (avoids stale role in session)
        old_role = session['role']
        session['role'] = fresh_role
        logging.info(f"[AUTH_CHECK] Updated stale session role for {session['user']}: {old_role} → {fresh_role}")
    
    # NS: Get effective permissions for UI visibility
    user_permissions = get_user_permissions(user)
    
    # NS: Feb 2026 - Check if user needs to set up 2FA (force_2fa setting)
    requires_2fa_setup = False
    if settings.get('force_2fa') and TOTP_AVAILABLE:
        has_2fa = user.get('totp_enabled', False)
        is_external = user.get('auth_source', 'local') in ('oidc', 'entra')
        is_admin = fresh_role == ROLE_ADMIN
        exclude_admins = settings.get('force_2fa_exclude_admins', False)
        # skip OIDC/Entra users (they use their IdP's MFA) and optionally admins
        if not has_2fa and not is_external and not (is_admin and exclude_admins):
            requires_2fa_setup = True
    
    return jsonify({
        'authenticated': True,
        'session_id': session_id,  # MK: Return session_id for WebSocket auth
        'user': {
            'username': session['user'],
            'role': fresh_role,
            'display_name': user.get('display_name', session['user']),
            'email': user.get('email', ''),
            'auth_source': user.get('auth_source', 'local'),  # NS: For LDAP/Entra/OIDC badge
            'tenant_id': user.get('tenant_id', DEFAULT_TENANT_ID),  # MK: For multi-tenant UI
            'permissions': user_permissions,  # LW: So frontend knows what buttons to show
            'theme': user_theme,
            'language': user.get('language', ''),
            'ui_layout': user.get('ui_layout', 'modern'),
            'taskbar_auto_expand': user.get('taskbar_auto_expand', True),  # NS: Feb 2026
            'totp_enabled': user.get('totp_enabled', False)
        },
        'password_expiry': password_expiry,
        'requires_2fa_setup': requires_2fa_setup,
        'default_theme': default_theme
    })


@bp.route('/api/auth/validate', methods=['GET'])
def auth_validate():
    """Simple session validation for WebSocket auth (shell, VNC)
    
    MK: Shell/VNC WebSocket needs a simple endpoint to validate session
    Returns 200 if valid, 401 if not
    """
    # Check both cookie (sent via requests.get with cookies=) and header
    session_id = request.cookies.get('session') or request.cookies.get('session_id') or request.headers.get('X-Session-ID')
    
    if not session_id:
        return jsonify({'valid': False, 'error': 'No session'}), 401
    
    session = validate_session(session_id)
    if not session:
        return jsonify({'valid': False, 'error': 'Invalid session'}), 401
    
    return jsonify({
        'valid': True,
        'user': session['user'],
        'role': session['role']
    })


@bp.route('/api/internal/cluster-creds/<cluster_id>', methods=['GET'])
def get_cluster_creds_internal(cluster_id):
    """Internal endpoint for shell/VNC WebSocket to get node connection info
    
    MK: Returns node IPs for SSH connections
    For single-node setups, we use the cluster host directly
    """
    # Check session from cookie
    session_id = request.cookies.get('session') or request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'No session'}), 401
    
    session = validate_session(session_id)
    if not session:
        return jsonify({'error': 'Invalid session'}), 401
    
    # Check if cluster exists
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]

    # Check cluster access and permissions for this user - NS Feb 2026
    users_db = load_users()
    user_data = users_db.get(session['user'], {})
    is_admin = user_data.get('role') == ROLE_ADMIN
    user_clusters = user_data.get('clusters', [])

    if not is_admin and user_clusters and cluster_id not in user_clusters:
        return jsonify({'error': 'Access denied to this cluster'}), 403

    # NS Feb 2026: Require admin role or node.shell permission (was missing - critical security fix)
    user_perms = get_user_permissions(user_data)
    if not is_admin and 'node.shell' not in user_perms:
        logging.warning(f"[CLUSTER-CREDS] User {session['user']} lacks node.shell permission")
        return jsonify({'error': 'Permission denied - requires admin or node.shell permission'}), 403
    
    # Get node IPs - the cluster_host is our reliable fallback
    node_ips = {}
    cluster_host = mgr.current_host or mgr.config.host
    
    logging.info(f"[CLUSTER-CREDS] Getting node IPs for cluster {cluster_id}, host={cluster_host}")
    
    try:
        host = cluster_host
        
        # Method 1: Get from Proxmox cluster status API (has IPs for clustered nodes)
        status_url = f"https://{host}:8006/api2/json/cluster/status"
        r = mgr._create_session().get(status_url, timeout=10)
        
        if r.status_code == 200:
            status_data = r.json().get('data', [])
            logging.info(f"[CLUSTER-CREDS] Cluster status returned {len(status_data)} items")
            for item in status_data:
                if item.get('type') == 'node':
                    node_name = item.get('name', '')
                    node_ip = item.get('ip')
                    logging.info(f"[CLUSTER-CREDS] Cluster status node: {node_name}, ip={node_ip}")
                    if node_name and node_ip:
                        # Store with original case and lowercase for matching
                        node_ips[node_name] = node_ip
                        node_ips[node_name.lower()] = node_ip
        
        # Method 2: Get all nodes and ensure they have IPs
        resources = mgr.get_cluster_resources()
        if resources.get('success'):
            for node in resources.get('nodes', []):
                node_name = node.get('node', '')
                node_lower = node_name.lower()
                
                # Already have IP?
                if node_lower in [k.lower() for k in node_ips.keys() if node_ips.get(k)]:
                    continue
                    
                logging.info(f"[CLUSTER-CREDS] Node {node_name} needs IP lookup")
                
                # Try network config API
                try:
                    net_url = f"https://{host}:8006/api2/json/nodes/{node_name}/network"
                    r = mgr._create_session().get(net_url, timeout=5)
                    if r.status_code == 200:
                        for iface in r.json().get('data', []):
                            # Look for interface with IP
                            iface_type = iface.get('type', '')
                            addr = iface.get('address', '')
                            cidr = iface.get('cidr', '')
                            
                            # Extract IP from CIDR if no address
                            if not addr and cidr:
                                addr = cidr.split('/')[0]
                            
                            if addr and iface_type in ['bridge', 'eth', 'bond', 'OVSBridge', 'vlan']:
                                node_ips[node_name] = addr
                                node_ips[node_lower] = addr
                                logging.info(f"[CLUSTER-CREDS] Node {node_name} IP from network: {addr}")
                                break
                except Exception as e:
                    logging.warning(f"[CLUSTER-CREDS] Network API failed for {node_name}: {e}")
                
                # Fallback: use cluster host (the host we connect to Proxmox API through)
                if node_name not in node_ips:
                    node_ips[node_name] = cluster_host
                    node_ips[node_lower] = cluster_host
                    logging.info(f"[CLUSTER-CREDS] Node {node_name} using cluster host: {cluster_host}")
                        
    except Exception as e:
        logging.error(f"[CLUSTER-CREDS] Error getting node IPs: {e}")
    
    # Final fallback: if no nodes found, use cluster host
    if not node_ips:
        node_ips['_default'] = cluster_host
        logging.info(f"[CLUSTER-CREDS] No nodes found, using default: {cluster_host}")
    
    # NS Feb 2026: Never expose Proxmox password via API - shell proxy handles auth server-side
    return jsonify({
        'host': cluster_host,
        'user': mgr.config.user,
        'node_ips': node_ips
    })


@bp.route('/api/auth/change-password', methods=['POST'])
@require_auth()
def auth_change_password():
    """Change current user's password
    
    NS: Security feature - invalidates all other sessions after password change
    This way if someone stole your session, changing password kicks them out
    """
    global users_db
    
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password required'}), 400
    
    # Validate password policy
    is_valid, error_msg = validate_password_policy(new_password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    username = request.session['user']
    
    # NS: rate limit this - someone with a stolen session could brute-force the current password
    if not check_auth_action_rate_limit(f'pwd_change:{username}', max_attempts=5, window=300):
        return jsonify({'error': 'Too many password change attempts. Try again in 5 minutes.'}), 429
    
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    
    # NS: LDAP/OIDC users cannot change their password here - they must change it in their identity provider
    if user.get('auth_source', 'local') in ('ldap', 'oidc', 'entra'):
        provider_name = {'ldap': 'LDAP/Active Directory', 'oidc': 'your OIDC provider', 'entra': 'Microsoft Entra ID'}.get(user['auth_source'], 'your identity provider')
        return jsonify({'error': f'Password is managed by {provider_name}. Please change it there.'}), 400
    
    # Verify current password
    if not verify_password(current_password, user['password_salt'], user['password_hash']):
        log_audit(username, 'user.password_change_failed', 'Incorrect current password')
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update password
    salt, password_hash = hash_password(new_password)
    user['password_salt'] = salt
    user['password_hash'] = password_hash
    user['password_changed_at'] = datetime.now().isoformat()  # LW: reset expiry timer
    
    # Mark admin initialized if this is the default admin
    if user.get('is_default'):
        user['is_default'] = False
        mark_admin_initialized()
    
    save_users(users_db)
    
    # Invalidate all other sessions for this user (keep current session)
    current_session_id = request.cookies.get('session_id') or request.headers.get('X-Session-ID')
    sessions_removed = invalidate_all_user_sessions(username, except_session=current_session_id)
    
    logging.info(f"User '{username}' changed their password")
    log_audit(username, 'user.password_changed', f"Password changed, {sessions_removed} other sessions invalidated")
    
    return jsonify({'success': True, 'sessions_invalidated': sessions_removed})


# ============================================
# TOTP 2FA API Routes
# ============================================

@bp.route('/api/auth/2fa/setup', methods=['POST'])
@require_auth()
def setup_2fa():
    """Generate TOTP secret and QR code for 2FA setup"""
    global users_db
    
    if not TOTP_AVAILABLE:
        return jsonify({'error': '2FA not available. Please install pyotp and qrcode: pip install pyotp qrcode[pil]'}), 500
    
    username = request.session['user']
    logging.info(f"2FA setup requested for user: {username}")  # MK: Debug
    users_db = load_users()
    
    if username not in users_db:
        logging.warning(f"2FA setup failed - user not found: {username}")
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    
    # NS: OIDC/Entra users should use their IdP's MFA, not PegaProx 2FA
    # PegaProx 2FA only works for login form (LDAP + local), not OIDC redirect flow
    if user.get('auth_source', 'local') in ('oidc', 'entra'):
        provider_name = 'Microsoft Entra ID' if user.get('auth_source') == 'entra' else 'your OIDC provider'
        return jsonify({'error': f'2FA is managed by {provider_name}. Please enable MFA there instead.'}), 400
    
    # Generate new secret
    secret = pyotp.random_base32()
    
    # Store pending secret (not activated yet)
    user['totp_pending_secret'] = secret
    save_users(users_db)
    logging.info(f"2FA setup: saved pending secret for user {username}")  # MK: Debug
    
    # Generate provisioning URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name='PegaProx')
    
    # Generate QR code as base64
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = _io.BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_base64}',
        'uri': uri
    })


@bp.route('/api/auth/2fa/verify', methods=['POST'])
@require_auth()
def verify_2fa_setup():
    """Verify TOTP code and activate 2FA"""
    global users_db
    
    if not TOTP_AVAILABLE:
        return jsonify({'error': '2FA not available'}), 500
    
    data = request.get_json()
    code = data.get('code', '') if data else ''
    
    if not code:
        logging.warning("2FA verify: no code provided")  # MK: Debug
        return jsonify({'error': 'TOTP code required'}), 400
    
    username = request.session['user']
    
    # NS: only 1M possible 6-digit codes, easy to brute force without this
    if not check_auth_action_rate_limit(f'totp_verify:{username}', max_attempts=5, window=300):
        return jsonify({'error': 'Too many verification attempts. Try again in 5 minutes.'}), 429
    
    logging.info(f"2FA verify requested for user: {username}, code length: {len(code)}")  # MK: Debug
    users_db = load_users()
    
    if username not in users_db:
        logging.warning(f"2FA verify: user not found: {username}")
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    pending_secret = user.get('totp_pending_secret')
    
    if not pending_secret:
        logging.warning(f"2FA verify: no pending secret for user {username}. User keys: {list(user.keys())}")  # MK: Debug
        return jsonify({'error': 'No pending 2FA setup'}), 400
    
    # Verify the code
    totp = pyotp.TOTP(pending_secret)
    if not totp.verify(code):
        return jsonify({'error': 'Invalid TOTP code'}), 401
    
    # Activate 2FA
    user['totp_secret'] = pending_secret
    user['totp_enabled'] = True
    del user['totp_pending_secret']
    save_users(users_db)
    
    logging.info(f"User '{username}' enabled 2FA")
    log_audit(username, '2fa.enabled', "User enabled 2FA")
    
    return jsonify({'success': True, 'message': '2FA erfolgreich aktiviert'})


@bp.route('/api/auth/2fa/disable', methods=['POST'])
@require_auth()
def disable_2fa():
    """Disable 2FA for current user"""
    global users_db
    
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password required to disable 2FA'}), 400
    
    username = request.session['user']
    
    # NS: same issue as pwd change - stolen session + unlimited guesses = bad
    if not check_auth_action_rate_limit(f'2fa_disable:{username}', max_attempts=5, window=300):
        return jsonify({'error': 'Too many attempts. Try again in 5 minutes.'}), 429
    
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    
    # NS: OIDC/Entra users manage MFA through their IdP - shouldn't have PegaProx 2FA
    if user.get('auth_source', 'local') in ('oidc', 'entra'):
        return jsonify({'error': '2FA is managed by your identity provider'}), 400
    
    # NS: Feb 2026 - LDAP users verify against LDAP (they have no local password hash)
    if user.get('auth_source') == 'ldap':
        ldap_result = ldap_authenticate(username, password)
        if not ldap_result.get('success'):
            return jsonify({'error': 'Invalid LDAP password'}), 401
    else:
        # Local users verify against local password hash
        if not verify_password(password, user['password_salt'], user['password_hash']):
            return jsonify({'error': 'Invalid password'}), 401
    
    # Disable 2FA
    user['totp_enabled'] = False
    user.pop('totp_secret', None)
    user.pop('totp_pending_secret', None)
    save_users(users_db)
    
    logging.info(f"User '{username}' disabled 2FA")
    log_audit(username, '2fa.disabled', "User disabled 2FA")
    
    return jsonify({'success': True, 'message': '2FA disabled'})


@bp.route('/api/auth/2fa/status', methods=['GET'])
@require_auth()
def get_2fa_status():
    """Get 2FA status for current user"""
    username = request.session['user']
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    
    return jsonify({
        'enabled': user.get('totp_enabled', False),
        'available': TOTP_AVAILABLE
    })


# =====================================================
# USER PREFERENCES - LW
# Per-user settings (theme, language)
# =====================================================

# =============================================================================
# NS: Feb 2026 - API Token Management Endpoints
# MK: Users can create tokens for CI/CD, scripts, monitoring integrations
# LW: Admins can see all tokens, users can only manage their own
# =============================================================================

@bp.route('/api/auth/tokens', methods=['GET'])
@require_auth()
def list_api_tokens():
    """List API tokens for current user (or all users for admin)"""
    ensure_api_tokens_table()
    username = request.session['user']
    role = request.session.get('role', ROLE_VIEWER)
    
    # MK: Admin can see all tokens if ?all=true
    if role == ROLE_ADMIN and request.args.get('all') == 'true':
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute('''
                SELECT id, token_prefix, username, name, role, permissions, expires_at,
                       last_used_at, last_used_ip, created_at, revoked
                FROM api_tokens ORDER BY created_at DESC
            ''')
            tokens = [dict(row) for row in cursor.fetchall()]
            return jsonify({'tokens': tokens})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    tokens = list_user_tokens(username)
    return jsonify({'tokens': tokens})


@bp.route('/api/auth/tokens', methods=['POST'])
@require_auth()
def create_api_token_endpoint():
    """Create a new API token for the current user"""
    username = request.session['user']
    data = request.get_json() or {}
    
    token_name = data.get('name', '').strip()
    if not token_name:
        return jsonify({'error': 'Token name is required'}), 400
    
    if len(token_name) > 64:
        return jsonify({'error': 'Token name too long (max 64 chars)'}), 400
    
    # LW: Check for duplicate names
    existing = list_user_tokens(username)
    active_names = [t['name'] for t in existing if not t.get('revoked')]
    if token_name in active_names:
        return jsonify({'error': f'Token name "{token_name}" already exists'}), 400
    
    # NS: Max 10 active tokens per user
    active_count = sum(1 for t in existing if not t.get('revoked'))
    if active_count >= 1:
        return jsonify({'error': 'You already have an active token. Revoke it first to create a new one.'}), 400
    
    role = data.get('role')
    expires_days = data.get('expires_days')
    
    if expires_days is not None:
        try:
            expires_days = int(expires_days)
            if expires_days < 1 or expires_days > 365:
                return jsonify({'error': 'Expiry must be between 1 and 365 days'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid expires_days value'}), 400
    
    result = create_api_token(username, token_name, role=role, expires_days=expires_days)
    
    if 'error' in result:
        return jsonify(result), 400
    
    # MK: Audit log
    log_audit(username, 'token.created', f"API token '{token_name}' created")
    
    return jsonify(result)


@bp.route('/api/auth/tokens/<int:token_id>', methods=['DELETE'])
@require_auth()
def revoke_api_token_endpoint(token_id):
    """Revoke an API token"""
    username = request.session['user']
    role = request.session.get('role', ROLE_VIEWER)
    
    # LW: Admin can revoke any token
    if role == ROLE_ADMIN:
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute('SELECT username, name FROM api_tokens WHERE id = ?', (token_id,))
            row = cursor.fetchone()
            if row:
                cursor.execute('UPDATE api_tokens SET revoked = 1 WHERE id = ?', (token_id,))
                db.conn.commit()
                token_owner = dict(row)['username']
                token_name = dict(row)['name']
                log_audit(username, 'token.revoked', f"Revoked API token '{token_name}' (user: {token_owner})")
                return jsonify({'success': True})
            return jsonify({'error': 'Token not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    if revoke_api_token(token_id, username):
        log_audit(username, 'token.revoked', f"Revoked API token id={token_id}")
        return jsonify({'success': True})
    return jsonify({'error': 'Token not found or not owned by you'}), 404


# GET /api/user/preferences is in users.py (has full implementation)
