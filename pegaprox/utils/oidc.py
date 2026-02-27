# -*- coding: utf-8 -*-
"""
PegaProx OIDC/OAuth2 Authentication - Layer 4
"""

import json
import logging
import time
import hashlib
import base64
import secrets
import requests
from datetime import datetime
from urllib.parse import urlencode

from pegaprox.core.db import get_db
from pegaprox.globals import users_db
from pegaprox.models.permissions import ROLE_VIEWER, ROLE_ADMIN, ROLE_USER

# ============================================================================

# NS: Feb 2026 - Microsoft cloud environment endpoint mapping
# GCC High and DoD use separate sovereign cloud endpoints
ENTRA_CLOUD_ENDPOINTS = {
    'commercial': {
        'login_base': 'login.microsoftonline.com',
        'graph_base': 'graph.microsoft.com',
    },
    'gcc': {
        # GCC uses the same commercial endpoints
        'login_base': 'login.microsoftonline.com',
        'graph_base': 'graph.microsoft.com',
    },
    'gcc_high': {
        # US Government GCC High - sovereign cloud
        'login_base': 'login.microsoftonline.us',
        'graph_base': 'graph.microsoft.us',
    },
    'dod': {
        # US Department of Defense - sovereign cloud
        'login_base': 'login.microsoftonline.us',
        'graph_base': 'dod-graph.microsoft.us',
    },
}

def get_oidc_settings() -> dict:
    """Load OIDC/Entra ID configuration from server settings

    LW: Supports Microsoft Entra ID, Okta, Auth0, Keycloak, and any OIDC-compliant provider
    """
    from pegaprox.api.helpers import load_server_settings
    settings = load_server_settings()  # MK: Must use load_server_settings() NOT get_server_settings() (that's the route handler!)
    provider = settings.get('oidc_provider', 'entra')
    
    # NS: Entra needs User.Read + GroupMember.Read.All for Graph API
    # Default scopes differ by provider
    if provider == 'entra':
        default_scopes = 'openid profile email User.Read GroupMember.Read.All'
    else:
        default_scopes = 'openid profile email'
    
    return {
        'enabled': settings.get('oidc_enabled', False),
        'provider': provider,
        'cloud_environment': settings.get('oidc_cloud_environment', 'commercial'),  # NS: GCC High/DoD support
        'client_id': settings.get('oidc_client_id', ''),
        'client_secret': get_db()._decrypt(settings.get('oidc_client_secret', '')),  # MK: Encrypted
        'tenant_id': settings.get('oidc_tenant_id', ''),  # Entra-specific (Azure AD tenant)
        'authority': settings.get('oidc_authority', ''),    # Custom OIDC issuer URL
        'scopes': settings.get('oidc_scopes', '') or default_scopes,  # NS: Use provider-specific default if not configured
        'redirect_uri': settings.get('oidc_redirect_uri', ''),
        # Group → role mapping
        'admin_group_id': settings.get('oidc_admin_group_id', ''),
        'user_group_id': settings.get('oidc_user_group_id', ''),
        'viewer_group_id': settings.get('oidc_viewer_group_id', ''),
        'default_role': settings.get('oidc_default_role', ROLE_VIEWER),
        'auto_create_users': settings.get('oidc_auto_create_users', True),
        # Custom group mappings (same format as LDAP)
        'group_mappings': settings.get('oidc_group_mappings', []),
        # Display
        'button_text': settings.get('oidc_button_text', 'Sign in with Microsoft'),
    }


_oidc_discovery_cache = {}  # authority_url -> {'data': {...}, 'expires': timestamp}

def get_oidc_endpoints(config: dict) -> dict:
    """Build OIDC endpoint URLs based on provider
    
    NS: Entra uses tenant-specific URLs, generic OIDC uses discovery
    Supports GCC High and DoD sovereign cloud endpoints
    """
    provider = config.get('provider', 'entra')
    tenant_id = config.get('tenant_id', 'common')
    
    if provider == 'entra' and tenant_id:
        # NS: Feb 2026 - Use cloud environment to determine base URLs
        # GCC High/DoD use .us domains instead of .com
        cloud_env = config.get('cloud_environment', 'commercial')
        endpoints = ENTRA_CLOUD_ENDPOINTS.get(cloud_env, ENTRA_CLOUD_ENDPOINTS['commercial'])
        login_base = endpoints['login_base']
        graph_base = endpoints['graph_base']
        
        base = f"https://{login_base}/{tenant_id}/oauth2/v2.0"
        return {
            'authorization': f"{base}/authorize",
            'token': f"{base}/token",
            'jwks': f"https://{login_base}/{tenant_id}/discovery/v2.0/keys",
            'userinfo': f"https://{graph_base}/oidc/userinfo",
            'graph_me': f"https://{graph_base}/v1.0/me",
            'graph_groups': f"https://{graph_base}/v1.0/me/memberOf",
        }
    else:
        # Generic OIDC provider - try .well-known discovery first, fall back to authority URL
        authority = config.get('authority', '').rstrip('/')
        
        # NS: Feb 2026 - Try OpenID Connect Discovery (RFC 8414)
        # This works for Keycloak, Okta, Auth0, Google, and any standard OIDC provider
        # Cache discovery results for 1 hour to avoid network call on every request
        discovery_url = f"{authority}/.well-known/openid-configuration"
        cache_entry = _oidc_discovery_cache.get(authority)
        if cache_entry and cache_entry.get('expires', 0) > time.time():
            disco = cache_entry['data']
            return {
                'authorization': disco.get('authorization_endpoint', f"{authority}/authorize"),
                'token': disco.get('token_endpoint', f"{authority}/token"),
                'jwks': disco.get('jwks_uri', f"{authority}/.well-known/jwks.json"),
                'userinfo': disco.get('userinfo_endpoint', f"{authority}/userinfo"),
                'graph_me': '',
                'graph_groups': '',
            }
        
        try:
            resp = requests.get(discovery_url, timeout=5)
            if resp.status_code == 200:
                disco = resp.json()
                _oidc_discovery_cache[authority] = {'data': disco, 'expires': time.time() + 3600}
                return {
                    'authorization': disco.get('authorization_endpoint', f"{authority}/authorize"),
                    'token': disco.get('token_endpoint', f"{authority}/token"),
                    'jwks': disco.get('jwks_uri', f"{authority}/.well-known/jwks.json"),
                    'userinfo': disco.get('userinfo_endpoint', f"{authority}/userinfo"),
                    'graph_me': '',
                    'graph_groups': '',
                }
        except Exception as e:
            logging.debug(f"[OIDC] Discovery failed for {discovery_url}: {e}, using manual endpoints")
        
        # Fallback: construct from authority URL directly
        return {
            'authorization': f"{authority}/authorize",
            'token': f"{authority}/token",
            'jwks': f"{authority}/.well-known/jwks.json",
            'userinfo': f"{authority}/userinfo",
            'graph_me': '',
            'graph_groups': '',
        }


def oidc_build_auth_url(config: dict, state: str) -> str:
    """Build the OIDC authorization URL for redirect
    
    MK: state parameter prevents CSRF - stored in session before redirect
    """
    endpoints = get_oidc_endpoints(config)
    
    params = {
        'client_id': config['client_id'],
        'response_type': 'code',
        'redirect_uri': config['redirect_uri'],
        'scope': config['scopes'],
        'state': state,
        'response_mode': 'query',
        'nonce': secrets.token_urlsafe(32),
    }
    
    # Entra-specific: request group claims
    if config.get('provider') == 'entra':
        # Request groups in ID token (up to 200 groups)
        params['scope'] = config['scopes']
        if 'GroupMember.Read.All' not in params['scope']:
            # We'll use graph API for groups instead
            pass
    
    query = '&'.join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    return f"{endpoints['authorization']}?{query}"


def oidc_exchange_code(config: dict, code: str) -> dict:
    """Exchange authorization code for tokens
    
    LW: Returns access_token, id_token, and optionally refresh_token
    """
    endpoints = get_oidc_endpoints(config)
    
    data = {
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'code': code,
        'redirect_uri': config['redirect_uri'],
        'grant_type': 'authorization_code',
    }
    
    # NS: Entra needs scope in token request too
    if config.get('provider') == 'entra':
        data['scope'] = config['scopes']
    
    try:
        resp = requests.post(endpoints['token'], data=data, timeout=15)
        if resp.status_code != 200:
            logging.error(f"[OIDC] Token exchange failed: {resp.status_code} {resp.text[:300]}")
            return {'error': f'Token exchange failed: {resp.status_code}'}
        
        token_data = resp.json()
        if 'error' in token_data:
            logging.error(f"[OIDC] Token error: {token_data.get('error_description', token_data['error'])}")
            return {'error': token_data.get('error_description', token_data['error'])}
        
        return token_data
    except Exception as e:
        logging.error(f"[OIDC] Token exchange exception: {e}")
        return {'error': str(e)}


def oidc_decode_id_token(id_token: str) -> dict:
    """Decode JWT ID token without full verification
    
    MK: We trust the token because it came directly from the token endpoint over HTTPS.
    For production with untrusted tokens, verify signature against JWKS.
    """
    try:
        # JWT = header.payload.signature - we just need the payload
        parts = id_token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}
        
        # Base64url decode payload (add padding)
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        return claims
    except Exception as e:
        logging.error(f"[OIDC] JWT decode error: {e}")
        return {'error': str(e)}


def oidc_get_user_info(config: dict, access_token: str) -> dict:
    """Fetch user profile from OIDC provider
    
    NS: For Entra, uses Microsoft Graph API for richer data
    """
    headers = {'Authorization': f'Bearer {access_token}'}
    endpoints = get_oidc_endpoints(config)
    
    user_info = {}
    
    try:
        if config.get('provider') == 'entra' and endpoints.get('graph_me'):
            # LW: Microsoft Graph gives us more data than OIDC userinfo
            resp = requests.get(endpoints['graph_me'], headers=headers, timeout=10)
            if resp.status_code == 200:
                graph_data = resp.json()
                user_info = {
                    'sub': graph_data.get('id', ''),
                    'preferred_username': graph_data.get('userPrincipalName', ''),
                    'name': graph_data.get('displayName', ''),
                    'email': graph_data.get('mail') or graph_data.get('userPrincipalName', ''),
                    'given_name': graph_data.get('givenName', ''),
                    'family_name': graph_data.get('surname', ''),
                    'job_title': graph_data.get('jobTitle', ''),
                }
            else:
                logging.warning(f"[OIDC] Graph /me failed ({resp.status_code}), falling back to userinfo")
        
        # Fallback or generic OIDC: use standard userinfo endpoint
        if not user_info and endpoints.get('userinfo'):
            resp = requests.get(endpoints['userinfo'], headers=headers, timeout=10)
            if resp.status_code == 200:
                user_info = resp.json()
    except Exception as e:
        logging.warning(f"[OIDC] User info fetch error: {e}")
    
    return user_info


def oidc_get_user_groups(config: dict, access_token: str) -> list:
    """Fetch user's group memberships from OIDC provider
    
    MK: For Entra, uses Graph API /me/memberOf
    Returns list of group IDs (Entra) or group names (generic)
    """
    if config.get('provider') != 'entra':
        # Generic OIDC: groups should be in ID token claims
        return []
    
    endpoints = get_oidc_endpoints(config)
    headers = {'Authorization': f'Bearer {access_token}'}
    groups = []
    
    try:
        # NS: Entra Graph API for group memberships
        url = endpoints['graph_groups']
        while url:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                logging.warning(f"[OIDC] Group fetch failed: {resp.status_code}")
                break
            
            data = resp.json()
            for member in data.get('value', []):
                if member.get('@odata.type') == '#microsoft.graph.group':
                    groups.append({
                        'id': member.get('id', ''),
                        'name': member.get('displayName', ''),
                    })
            
            # LW: Handle pagination (Entra paginates at 100 groups)
            url = data.get('@odata.nextLink')
        
        logging.info(f"[OIDC] Fetched {len(groups)} group memberships")
    except Exception as e:
        logging.warning(f"[OIDC] Group fetch error: {e}")
    
    return groups


def oidc_map_groups_to_role(config: dict, groups: list, id_token_claims: dict = None) -> dict:
    """Map OIDC groups to PegaProx role, tenant, and permissions
    
    LW: Works with Entra group IDs and generic OIDC group claims
    Returns: {'role': str, 'tenant': str, 'permissions': [], 'tenant_permissions': {}}
    """
    result = {
        'role': config.get('default_role', ROLE_VIEWER),
        'tenant': '',
        'permissions': [],
        'tenant_permissions': {},
    }
    
    # Build list of group identifiers (IDs for Entra, names for generic)
    group_ids = set()
    group_names = set()
    for g in groups:
        if isinstance(g, dict):
            group_ids.add(g.get('id', '').lower())
            group_names.add(g.get('name', '').lower())
        elif isinstance(g, str):
            group_ids.add(g.lower())
            group_names.add(g.lower())
    
    # NS: Also check ID token 'groups' claim (Entra can embed group IDs in token)
    if id_token_claims:
        for gid in id_token_claims.get('groups', []):
            group_ids.add(str(gid).lower())
    
    # MK: Built-in group mappings (admin > user > viewer priority)
    admin_group = config.get('admin_group_id', '').strip().lower()
    user_group = config.get('user_group_id', '').strip().lower()
    viewer_group = config.get('viewer_group_id', '').strip().lower()
    
    if admin_group and (admin_group in group_ids or admin_group in group_names):
        result['role'] = ROLE_ADMIN
    elif user_group and (user_group in group_ids or user_group in group_names):
        result['role'] = ROLE_USER
    elif viewer_group and (viewer_group in group_ids or viewer_group in group_names):
        result['role'] = ROLE_VIEWER
    
    # LW: Custom group mappings (override built-in)
    for mapping in config.get('group_mappings', []):
        map_group = (mapping.get('group_id') or mapping.get('group_dn') or '').strip().lower()
        if map_group and (map_group in group_ids or map_group in group_names):
            if mapping.get('role'):
                result['role'] = mapping['role']
            if mapping.get('tenant'):
                result['tenant'] = mapping['tenant']
            if mapping.get('permissions'):
                result['permissions'].extend(mapping['permissions'])
            if mapping.get('tenant') and mapping.get('tenant_role'):
                result['tenant_permissions'][mapping['tenant']] = {
                    'role': mapping['tenant_role'],
                    'extra': mapping.get('permissions', [])  # MK: Must be 'extra' to match get_user_permissions()
                }
            logging.info(f"[OIDC] Custom group mapping matched: {map_group} → role={mapping.get('role')}")
    
    return result


def oidc_provision_user(user_info: dict, role_mapping: dict, auth_source: str = 'oidc') -> dict:
    from pegaprox.utils.auth import load_users, save_users
    """Create or update local user from OIDC authentication
    
    NS: JIT provisioning - same pattern as LDAP but for OIDC providers
    MK: username derived from email or preferred_username
    """
    # Derive username from OIDC claims
    email = user_info.get('email') or user_info.get('preferred_username', '')
    raw_username = user_info.get('preferred_username') or email
    
    # LW: Sanitize username - use part before @ for email-style usernames
    if '@' in raw_username:
        username = raw_username.split('@')[0].lower()
    else:
        username = raw_username.lower()
    
    # NS: Ensure we have a valid username
    username = ''.join(c for c in username if c.isalnum() or c in '._-')
    if not username:
        username = f"oidc_{user_info.get('sub', 'unknown')[:12]}"
    
    display_name = user_info.get('name') or user_info.get('given_name', '') 
    if not display_name:
        display_name = username
    
    users = load_users()
    
    if username in users:
        # NS: SECURITY - Don't allow OIDC to overwrite a local-only user
        # This prevents account takeover if someone creates an IdP account matching a local username
        existing_source = users[username].get('auth_source', 'local')
        if existing_source == 'local':
            logging.warning(f"[OIDC] Rejected login for '{username}' - local account exists, cannot overwrite with OIDC")
            return None  # Caller should handle None return
        
        # Update existing OIDC/LDAP user
        user = users[username]
        user['display_name'] = display_name
        user['email'] = email
        user['role'] = role_mapping.get('role', user.get('role', ROLE_VIEWER))
        user['auth_source'] = auth_source
        user['oidc_sub'] = user_info.get('sub', '')
        user['last_oidc_sync'] = datetime.now().isoformat()
        
        # Sync tenant/permissions from group mappings
        if role_mapping.get('tenant'):
            user['tenant_id'] = role_mapping['tenant']  # NS: Must be tenant_id
        if role_mapping.get('permissions'):
            existing_perms = user.get('permissions', [])
            user['permissions'] = list(set(existing_perms + role_mapping['permissions']))
        if role_mapping.get('tenant_permissions'):
            if 'tenant_permissions' not in user:
                user['tenant_permissions'] = {}
            user['tenant_permissions'].update(role_mapping['tenant_permissions'])
        
        logging.info(f"[OIDC] Updated user '{username}' (role={user['role']}, source={auth_source})")
    else:
        # Create new user
        users[username] = {
            'role': role_mapping.get('role', ROLE_VIEWER),
            'enabled': True,
            'display_name': display_name,
            'email': email,
            'password_hash': '',  # No local password for OIDC users
            'password_salt': '',
            'permissions': role_mapping.get('permissions', []),
            'tenant_id': role_mapping.get('tenant', ''),  # NS: Must be tenant_id
            'tenant_permissions': role_mapping.get('tenant_permissions', {}),
            'theme': '',
            'language': '',
            'auth_source': auth_source,
            'oidc_sub': user_info.get('sub', ''),
            'last_oidc_sync': datetime.now().isoformat(),
            'created_at': datetime.now().isoformat()
        }
        logging.info(f"[OIDC] Provisioned new user '{username}' (role={role_mapping.get('role', ROLE_VIEWER)}, source={auth_source})")
    
    save_users(users)
    return {**users[username], 'username': username}
