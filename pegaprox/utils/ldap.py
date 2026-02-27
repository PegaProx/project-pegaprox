# -*- coding: utf-8 -*-
"""
PegaProx LDAP Authentication - Layer 4
"""

import json
import logging
import time
import hashlib
import base64
from datetime import datetime

from pegaprox.core.db import get_db
from pegaprox.globals import users_db
from pegaprox.models.permissions import ROLE_VIEWER, ROLE_ADMIN, ROLE_USER

def get_ldap_settings() -> dict:
    """Get LDAP configuration from server settings"""
    from pegaprox.api.helpers import load_server_settings
    settings = load_server_settings()
    config = {
        'enabled': settings.get('ldap_enabled', False),
        'server': settings.get('ldap_server', ''),
        'port': settings.get('ldap_port', 389),
        'use_ssl': settings.get('ldap_use_ssl', False),
        'use_starttls': settings.get('ldap_use_starttls', False),
        'bind_dn': settings.get('ldap_bind_dn', ''),
        'bind_password': get_db()._decrypt(settings.get('ldap_bind_password', '')),  # MK: Decrypt - stored encrypted since 0.6.5
        'base_dn': settings.get('ldap_base_dn', ''),
        'user_filter': settings.get('ldap_user_filter', '(&(objectClass=person)(sAMAccountName={username}))'),
        'username_attribute': settings.get('ldap_username_attribute', 'sAMAccountName'),
        'email_attribute': settings.get('ldap_email_attribute', 'mail'),
        'display_name_attribute': settings.get('ldap_display_name_attribute', 'displayName'),
        'group_base_dn': settings.get('ldap_group_base_dn', ''),
        'group_filter': settings.get('ldap_group_filter', '(&(objectClass=group)(member={user_dn}))'),
        'admin_group': settings.get('ldap_admin_group', ''),
        'user_group': settings.get('ldap_user_group', ''),
        'viewer_group': settings.get('ldap_viewer_group', ''),
        'default_role': settings.get('ldap_default_role', ROLE_VIEWER),
        'auto_create_users': settings.get('ldap_auto_create_users', True),
        'verify_tls': settings.get('ldap_verify_tls', False),  # NS: Feb 2026 - TLS cert verification (default off for backwards compat)
        # MK: Feb 2026 - Custom group→role mappings for custom roles & tenants
        # Format: [{"group_dn": "CN=...", "role": "custom_role_name", "tenant": "tenant_id", "permissions": [...]}]
        'group_mappings': settings.get('ldap_group_mappings', []),
    }
    # NS: Feb 2026 - Debug log when LDAP is enabled but looks misconfigured
    if config['enabled'] and (not config['server'] or not config['base_dn']):
        # Dump raw DB values for the missing fields
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute("SELECT key, value FROM server_settings WHERE key IN ('ldap_server', 'ldap_base_dn')")
            raw_rows = {row['key']: row['value'] for row in cursor.fetchall()}
            logging.warning(f"[LDAP] Settings loaded but incomplete: enabled={config['enabled']}, "
                           f"server='{config['server']}', base_dn='{config['base_dn']}'. "
                           f"Raw DB values: {raw_rows}")
        except Exception as e:
            logging.warning(f"[LDAP] Settings loaded but incomplete: enabled={config['enabled']}, "
                           f"server='{config['server']}', base_dn='{config['base_dn']}'. "
                           f"DB keys present: {[k for k in settings if k.startswith('ldap_')]} (raw dump failed: {e})")
    return config


def ldap_authenticate(username: str, password: str) -> dict:
    """Authenticate user against LDAP/Active Directory
    
    Returns dict with user info on success, or {'error': '...'} on failure.
    NS: We do a two-step bind: first with service account to find the user DN,
    then re-bind with the user's own credentials to verify password.
    """
    ldap_config = get_ldap_settings()
    
    if not ldap_config['enabled']:
        return {'error': 'LDAP not enabled'}
    
    if not ldap_config['server'] or not ldap_config['base_dn']:
        # NS: Feb 2026 - Better diagnostic: tell them WHAT is missing
        missing = []
        if not ldap_config['server']:
            missing.append('server')
        if not ldap_config['base_dn']:
            missing.append('base_dn')
        logging.warning(f"[LDAP] LDAP not configured - missing: {', '.join(missing)}. "
                       f"Check that LDAP settings have been saved (not just tested). "
                       f"enabled={ldap_config['enabled']}, server='{ldap_config['server']}', base_dn='{ldap_config['base_dn']}'")
        return {'error': 'LDAP not configured'}
    
    # NS: SECURITY - Reject empty passwords (LDAP servers allow unauthenticated bind with empty password!)
    if not password or not password.strip():
        logging.warning(f"[LDAP] Rejected empty password for user '{username}'")
        return {'error': 'Invalid LDAP credentials'}
    
    # MK: SECURITY - Sanitize username against LDAP injection
    # LDAP special chars that can manipulate filters: * ( ) \ / NUL
    ldap_dangerous_chars = ['*', '(', ')', '\\', '\x00', '/', '\n', '\r']
    for char in ldap_dangerous_chars:
        if char in username:
            logging.warning(f"[LDAP] Rejected username with LDAP injection chars: '{username[:20]}'")
            return {'error': 'Invalid username characters'}
    
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE, Tls
        from ldap3.utils.conv import escape_filter_chars  # NS: Proper LDAP escaping
        import ssl as ssl_module
    except ImportError:
        logging.error("[LDAP] ldap3 module not installed. Run: pip install ldap3")
        return {'error': 'LDAP module not installed'}
    
    server_url = ldap_config['server']
    port = int(ldap_config['port'])
    
    try:
        # MK: Build server with optional TLS
        # NS: Feb 2026 - SECURITY: configurable TLS cert verification (default CERT_NONE for backwards compat)
        tls_config = None
        if ldap_config['use_ssl'] or ldap_config['use_starttls']:
            verify_tls = ldap_config.get('verify_tls', False)
            validate = ssl_module.CERT_REQUIRED if verify_tls else ssl_module.CERT_NONE
            if validate == ssl_module.CERT_NONE:
                logging.warning("[LDAP] TLS certificate verification disabled - MITM risk")
            tls_config = Tls(validate=validate)
        
        server = Server(server_url, port=port, use_ssl=ldap_config['use_ssl'], 
                       tls=tls_config, get_info=ALL, connect_timeout=10)
        
        # Step 1: Bind with service account to search for user
        bind_dn = ldap_config['bind_dn']
        bind_password = ldap_config['bind_password']
        
        # NS: STARTTLS has to happen BEFORE bind! auto_bind was sending creds in plaintext
        # MK found this during the Feb audit... pretty bad tbh
        use_starttls = ldap_config['use_starttls'] and not ldap_config['use_ssl']
        
        if bind_dn and bind_password:
            conn = Connection(server, user=bind_dn, password=bind_password, raise_exceptions=True)
        else:
            # Anonymous bind (some LDAP servers allow this)
            conn = Connection(server, raise_exceptions=True)
        
        conn.open()
        if use_starttls:
            conn.start_tls()
        conn.bind()
        
        # Step 2: Search for user
        # NS: SECURITY - Use ldap3's escape_filter_chars to prevent LDAP injection
        safe_username = escape_filter_chars(username)
        user_filter = ldap_config['user_filter'].replace('{username}', safe_username)
        search_base = ldap_config['base_dn']
        
        attributes = [
            ldap_config['username_attribute'],
            ldap_config['email_attribute'],
            ldap_config['display_name_attribute'],
            'memberOf',  # NS: AD stores group membership directly on user
            # Issue #70 (abyss1): 'dn' is NOT a valid LDAP attribute -- AD rejects it.
            # entry_dn is always returned implicitly by ldap3.
        ]
        
        conn.search(search_base, user_filter, search_scope=SUBTREE, attributes=attributes)
        
        if not conn.entries:
            conn.unbind()
            logging.info(f"[LDAP] User '{username}' not found in directory")
            return {'error': 'User not found in LDAP'}
        
        user_entry = conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        
        # Extract user attributes
        email = str(user_entry[ldap_config['email_attribute']]) if ldap_config['email_attribute'] in user_entry else ''
        display_name = str(user_entry[ldap_config['display_name_attribute']]) if ldap_config['display_name_attribute'] in user_entry else username
        
        # Get group memberships from memberOf attribute (AD style)
        member_of = []
        if 'memberOf' in user_entry:
            member_of = [str(g) for g in user_entry['memberOf']]
        
        conn.unbind()
        
        # Step 3: Verify user's password by binding with their credentials
        # LW: This is the actual authentication step
        try:
            user_conn = Connection(server, user=user_dn, password=password, raise_exceptions=True)
            user_conn.open()
            if use_starttls:
                user_conn.start_tls()
            user_conn.bind()
            user_conn.unbind()
        except Exception as bind_err:
            logging.info(f"[LDAP] Password verification failed for '{username}': {bind_err}")
            return {'error': 'Invalid LDAP credentials'}
        
        # Step 4: If we also need to search for groups separately (not via memberOf)
        if not member_of and ldap_config['group_base_dn']:
            try:
                group_conn = Connection(server, user=bind_dn, password=bind_password, raise_exceptions=True)
                group_conn.open()
                if use_starttls:
                    group_conn.start_tls()
                group_conn.bind()
                group_filter = ldap_config['group_filter'].replace('{user_dn}', escape_filter_chars(user_dn))
                group_conn.search(ldap_config['group_base_dn'], group_filter, 
                                search_scope=SUBTREE, attributes=['cn'])  # Issue #70: removed 'dn' -- entry_dn is implicit
                member_of = [str(entry.entry_dn) for entry in group_conn.entries]
                group_conn.unbind()
            except Exception as e:
                logging.warning(f"[LDAP] Group search failed: {e}")
        
        # Step 5: Map LDAP groups to PegaProx roles
        role = ldap_config['default_role']
        tenant = None
        extra_permissions = []
        tenant_permissions = {}
        
        # NS: Case-insensitive group DN comparison (AD is case-insensitive)
        member_of_lower = [g.lower() for g in member_of]
        
        # MK: Check built-in group mappings first (admin > user > viewer priority)
        admin_group = ldap_config['admin_group'].strip()
        user_group = ldap_config['user_group'].strip()
        viewer_group = ldap_config['viewer_group'].strip()
        
        if admin_group and admin_group.lower() in member_of_lower:
            role = ROLE_ADMIN
        elif user_group and user_group.lower() in member_of_lower:
            role = ROLE_USER
        elif viewer_group and viewer_group.lower() in member_of_lower:
            role = ROLE_VIEWER
        
        # LW: Feb 2026 - Custom group mappings (override built-in if matched)
        # These can map to custom roles, assign tenants, and add specific permissions
        custom_mappings = ldap_config.get('group_mappings', [])
        for mapping in custom_mappings:
            map_group = (mapping.get('group_dn') or '').strip()
            if map_group and map_group.lower() in member_of_lower:
                # Custom mapping matched
                if mapping.get('role'):
                    role = mapping['role']
                if mapping.get('tenant'):
                    tenant = mapping['tenant']
                if mapping.get('permissions'):
                    extra_permissions.extend(mapping['permissions'])
                # NS: Support per-tenant role assignment
                if mapping.get('tenant') and mapping.get('tenant_role'):
                    tenant_permissions[mapping['tenant']] = {
                        'role': mapping['tenant_role'],
                        'extra': mapping.get('permissions', [])  # MK: Must be 'extra' to match get_user_permissions()
                    }
                logging.info(f"[LDAP] Custom group mapping matched: {map_group} → role={mapping.get('role')}, tenant={mapping.get('tenant')}")
        
        # Clean up display values
        if email and (email.startswith('[') or email == '[]'):
            email = ''
        if display_name and (display_name.startswith('[') or display_name == '[]'):
            display_name = username
        
        logging.info(f"[LDAP] User '{username}' authenticated successfully (role={role}, groups={len(member_of)})")
        
        return {
            'success': True,
            'username': username,
            'email': email,
            'display_name': display_name,
            'role': role,
            'tenant': tenant,
            'permissions': extra_permissions,
            'tenant_permissions': tenant_permissions,
            'groups': member_of,
            'user_dn': user_dn,
            'auth_source': 'ldap'
        }
        
    except Exception as e:
        logging.error(f"[LDAP] Authentication error: {e}")
        return {'error': 'LDAP authentication failed'}  # MK: Don't leak internal error details


def ldap_provision_user(ldap_result: dict) -> dict:
    from pegaprox.utils.auth import load_users, save_users
    """Create or update a local user from LDAP authentication result
    
    LW: JIT (Just-In-Time) provisioning - user account is created on first login
    MK: LDAP users have auth_source='ldap' and no local password
    NS: Feb 2026 - Also syncs tenant, permissions, and tenant_permissions from group mappings
    """
    username = ldap_result['username'].lower()
    users = load_users()
    
    if username in users:
        # NS: SECURITY - Don't overwrite local-only accounts with LDAP
        existing_source = users[username].get('auth_source', 'local')
        if existing_source == 'local' and users[username].get('password_hash'):
            logging.warning(f"[LDAP] Rejected provisioning for '{username}' - local account with password exists")
            return None  # Caller should handle None return
        
        # Update existing LDAP/OIDC user with fresh LDAP info
        user = users[username]
        user['display_name'] = ldap_result.get('display_name', username)
        user['email'] = ldap_result.get('email', user.get('email', ''))
        user['role'] = ldap_result.get('role', user.get('role', ROLE_VIEWER))
        user['auth_source'] = 'ldap'
        user['ldap_dn'] = ldap_result.get('user_dn', '')
        user['last_ldap_sync'] = datetime.now().isoformat()
        
        # MK: Sync tenant assignment from LDAP group mapping
        if ldap_result.get('tenant'):
            user['tenant_id'] = ldap_result['tenant']  # NS: Must be tenant_id (not tenant) for code compatibility
        
        # LW: Merge extra permissions from LDAP group mappings
        if ldap_result.get('permissions'):
            existing_perms = user.get('permissions', [])
            merged = list(set(existing_perms + ldap_result['permissions']))
            user['permissions'] = merged
        
        # NS: Sync tenant-specific roles/permissions
        if ldap_result.get('tenant_permissions'):
            if 'tenant_permissions' not in user:
                user['tenant_permissions'] = {}
            user['tenant_permissions'].update(ldap_result['tenant_permissions'])
        
        logging.info(f"[LDAP] Updated existing user '{username}' from LDAP (role={user['role']}, tenant={user.get('tenant')})")
    else:
        # Create new user
        users[username] = {
            'role': ldap_result.get('role', ROLE_VIEWER),
            'enabled': True,
            'display_name': ldap_result.get('display_name', username),
            'email': ldap_result.get('email', ''),
            'password_hash': '',  # NS: No local password for LDAP users
            'password_salt': '',
            'permissions': ldap_result.get('permissions', []),
            'tenant_id': ldap_result.get('tenant', ''),  # NS: Must be tenant_id
            'tenant_permissions': ldap_result.get('tenant_permissions', {}),
            'theme': '',
            'language': '',
            'auth_source': 'ldap',
            'ldap_dn': ldap_result.get('user_dn', ''),
            'last_ldap_sync': datetime.now().isoformat(),
            'created_at': datetime.now().isoformat()
        }
        logging.info(f"[LDAP] Provisioned new user '{username}' from LDAP (role={ldap_result.get('role', ROLE_VIEWER)}, tenant={ldap_result.get('tenant')})")
    
    save_users(users)
    return users[username]


