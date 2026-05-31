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
import re
import requests
from datetime import datetime
from urllib.parse import urlencode, urlparse, urlunparse

# NS May 2026 — SSRF guard for admin-supplied OIDC URLs (discovery / token / userinfo).
from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError


# MK May 2026 (CodeAnt #500) — pre-validate the authority URL before composing the
# discovery URL. The existing sanitize_outbound_url() catches the same family of
# attacks one step later, but doing the urlparse here means we never even *build*
# a string with a path-traversal sequence in it; we fail fast with a structured
# error before any I/O. Defence in depth.
def build_validated_discovery_url(authority: str) -> str:
    """Build the `.well-known/openid-configuration` URL from the admin-supplied
    authority. Raises ValueError on bad scheme / hostname / path-traversal.
    """
    if "/../" in authority or re.search(r"/%2e%2e/", authority, re.IGNORECASE):
        raise ValueError("path-traversal sequence in authority URL")
    parsed = urlparse(authority)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("authority URL has no hostname")
    new_path = parsed.path.rstrip('/') + "/.well-known/openid-configuration"
    return urlunparse(parsed._replace(path=new_path))

# MK Mar 2026 - PyJWT for proper signature verification
try:
    import jwt as pyjwt
    from jwt import PyJWKClient
    PYJWT_AVAILABLE = True
except ImportError:
    PYJWT_AVAILABLE = False
    logging.warning("[OIDC] PyJWT not installed - JWT signature verification disabled")

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
        # NS: allow disabling JWT sig verification for broken JWKS environments
        'oidc_skip_jwt_verification': settings.get('oidc_skip_jwt_verification', False),
        # NS Apr 2026 (#188) — let admins disable TLS verification for self-hosted
        # Authentik / Keycloak with self-signed certs. Default OFF (secure).
        'oidc_skip_ssl_verify': settings.get('oidc_skip_ssl_verify', False),
        # MK May 2026 (#412) — opt-in: skip the SSRF guard's private-IP check
        # for the OIDC discovery URL only. Metadata-IP blocklist (169.254.x.x
        # etc.) still binds. See helpers.py default-block for rationale.
        'oidc_allow_private_ip': settings.get('oidc_allow_private_ip', False),
    }


_oidc_discovery_cache = {}  # authority_url -> {'data': {...}, 'expires': timestamp}
_jwks_clients = {}  # jwks_uri -> PyJWKClient instance (has its own cache)

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

        # NS: Feb 2026 — Try OpenID Connect Discovery (RFC 8414)
        # This works for Keycloak, Okta, Auth0, Google, Authentik, and any standard OIDC provider.
        # NS Apr 2026 (#188) — bumped timeout 5→15s; loud-log discovery failures so admins notice
        # silent fallback (which builds wrong endpoints for Authentik because its issuer URL
        # is per-application but its authorize endpoint is one path level up).
        try:
            discovery_url = build_validated_discovery_url(authority)
        except ValueError as e:
            logging.warning(f"[OIDC] authority URL rejected pre-validation: {e}")
            return {
                'authorization': '', 'token': '', 'jwks': '', 'userinfo': '',
                'graph_me': '', 'graph_groups': '',
                '_discovery_used': False,
                '_error': 'invalid_authority_url',
                '_error_detail': f"Authority/issuer URL is invalid ({e}). Fix the OIDC settings and retry.",
            }
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
                '_discovery_used': True,
            }

        skip_ssl = bool(config.get('oidc_skip_ssl_verify', False))
        allow_private_ip = bool(config.get('oidc_allow_private_ip', False))
        try:
            try:
                # MK May 2026 (#412): pass allow_private through so internal
                # IdPs at 10.x / 192.168.x can be used when the operator
                # explicitly opted in. Metadata blocklist still binds.
                sanitize_outbound_url(discovery_url, allow_private=allow_private_ip)
            except SsrfError as guard_err:
                logging.warning(f"[OIDC] discovery_url rejected by SSRF guard: {guard_err}")
                # MK May 2026 (#188 follow-up): never return None — callers
                # crash with `'NoneType' object has no attribute 'get'`. Return
                # a structured dict with an `_error` flag so the test endpoint
                # can surface "your authority URL is malformed" instead of 500.
                hint = ""
                if not allow_private_ip and "private" in str(guard_err).lower():
                    hint = (" If your IdP is on an internal network and this is "
                            "intentional, enable `oidc_allow_private_ip` in OIDC "
                            "settings — metadata IPs stay blocked regardless.")
                return {
                    'authorization': '', 'token': '', 'jwks': '', 'userinfo': '',
                    'graph_me': '', 'graph_groups': '',
                    '_discovery_used': False,
                    '_error': 'ssrf_guard_rejected',
                    '_error_detail': f"Discovery URL '{discovery_url}' rejected by URL safety guard: {guard_err}. "
                                     f"Authority/issuer URL is probably empty, malformed, or pointing at a "
                                     f"local/private address. Fix the OIDC settings and retry.{hint}",
                }
            resp = requests.get(discovery_url, timeout=15, verify=not skip_ssl)
            if resp.status_code == 200:
                try:
                    disco = resp.json()
                except Exception as parse_err:
                    logging.warning(
                        f"[OIDC] Discovery URL {discovery_url} returned 200 but invalid JSON: {parse_err}. "
                        f"Falling back to manual endpoints — this likely BREAKS Authentik / non-trivial issuers."
                    )
                    disco = None
                if disco:
                    _oidc_discovery_cache[authority] = {'data': disco, 'expires': time.time() + 3600}
                    return {
                        'authorization': disco.get('authorization_endpoint', f"{authority}/authorize"),
                        'token': disco.get('token_endpoint', f"{authority}/token"),
                        'jwks': disco.get('jwks_uri', f"{authority}/.well-known/jwks.json"),
                        'userinfo': disco.get('userinfo_endpoint', f"{authority}/userinfo"),
                        'graph_me': '',
                        'graph_groups': '',
                        '_discovery_used': True,
                    }
            else:
                logging.warning(
                    f"[OIDC] Discovery {discovery_url} returned HTTP {resp.status_code}. "
                    f"Falling back to issuer-relative endpoints; check that the issuer URL is correct "
                    f"(Authentik issuers usually end with /application/o/<app-slug>/). "
                    f"Set oidc_skip_ssl_verify=true if your IdP uses a self-signed cert."
                )
        except requests.exceptions.SSLError as e:
            logging.warning(
                f"[OIDC] Discovery TLS error for {discovery_url}: {e}. "
                f"Set oidc_skip_ssl_verify=true if your IdP uses a self-signed cert."
            )
        except Exception as e:
            logging.warning(
                f"[OIDC] Discovery failed for {discovery_url}: {e}. "
                f"Authorization endpoint may be wrong for non-Microsoft providers (Authentik, etc.) — "
                f"PegaProx will guess {authority}/authorize which is often a 404."
            )

        # Fallback: construct from authority URL directly
        return {
            'authorization': f"{authority}/authorize",
            'token': f"{authority}/token",
            'jwks': f"{authority}/.well-known/jwks.json",
            'userinfo': f"{authority}/userinfo",
            'graph_me': '',
            'graph_groups': '',
            '_discovery_used': False,
        }


def oidc_build_auth_url(config: dict, state: str) -> tuple:
    """Build the OIDC authorization URL for redirect

    MK: state parameter prevents CSRF - stored in session before redirect
    Returns (url, nonce, code_verifier) tuple
    """
    endpoints = get_oidc_endpoints(config)

    nonce = secrets.token_urlsafe(32)

    # #188: PKCE (Proof Key for Code Exchange) - required by Authentik, optional for others
    code_verifier = secrets.token_urlsafe(96)  # 128 chars
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')

    params = {
        'client_id': config['client_id'],
        'response_type': 'code',
        'redirect_uri': config['redirect_uri'],
        'scope': config['scopes'],
        'state': state,
        'response_mode': 'query',
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    }

    # Entra-specific: request group claims
    if config.get('provider') == 'entra':
        params['scope'] = config['scopes']
        if 'GroupMember.Read.All' not in params['scope']:
            pass

    query = '&'.join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    return f"{endpoints['authorization']}?{query}", nonce, code_verifier


def oidc_exchange_code(config: dict, code: str, code_verifier: str = None) -> dict:
    """Exchange authorization code for tokens

    LW: Returns access_token, id_token, and optionally refresh_token
    """
    endpoints = get_oidc_endpoints(config)
    allow_private_ip = bool(config.get('oidc_allow_private_ip', False))

    data = {
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'code': code,
        'redirect_uri': config['redirect_uri'],
        'grant_type': 'authorization_code',
    }

    # NS: scope required by most providers (Authentik, Keycloak, Entra)
    data['scope'] = config.get('scopes', 'openid profile email')

    # #188: PKCE code_verifier — required by Authentik, optional for others
    if code_verifier:
        data['code_verifier'] = code_verifier

    try:
        try:
            # MK May 2026 (#412 follow-up from @robertjakub): thread the
            # allow_private flag into token sanitize too — discovery was fixed
            # last release but token + userinfo still tripped the strict guard
            sanitize_outbound_url(endpoints['token'], allow_private=allow_private_ip)
        except SsrfError as guard_err:
            logging.warning(f"[OIDC] token endpoint rejected by SSRF guard: {guard_err}")
            if not allow_private_ip and "private" in str(guard_err).lower():
                logging.warning(
                    "[OIDC] If your IdP token endpoint sits on a private IP "
                    "intentionally, enable `oidc_allow_private_ip` in OIDC "
                    "settings (covers discovery + token + userinfo)."
                )
            return {'error': 'Token endpoint failed pre-flight URL validation'}
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


def oidc_decode_id_token(id_token: str, expected_nonce: str = None,
                         config: dict = None) -> dict:
    """Decode and verify JWT ID token signature using JWKS

    MK Mar 2026: Now verifies signature via JWKS endpoint (PyJWT).
    Falls back to unsigned decode if PyJWT unavailable or JWKS fetch fails,
    so existing deployments don't break during upgrade.
    """
    # NS Mar 2026 - try proper signature verification first
    # can be disabled via settings for envs where JWKS is broken/unreachable
    skip_verify = config.get('oidc_skip_jwt_verification', False) if config else False
    if skip_verify:
        logging.warning("[OIDC] JWT signature verification DISABLED by admin setting")
    if PYJWT_AVAILABLE and config and not skip_verify:
        try:
            endpoints = get_oidc_endpoints(config)
            jwks_uri = endpoints.get('jwks', '')

            if jwks_uri:
                if jwks_uri not in _jwks_clients:
                    _jwks_clients[jwks_uri] = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)

                signing_key = _jwks_clients[jwks_uri].get_signing_key_from_jwt(id_token)

                # NS May 2026 — audience list: client_id is always accepted,
                # plus any additional audiences the admin configured. PVE 9.2's
                # OIDC realm gained the same `audiences` field — mirroring it
                # here lets us accept tokens issued for a logical audience
                # (e.g. "pegaprox-prod") that maps to multiple deployments.
                client_id = config.get('client_id')
                extra_auds = config.get('oidc_audiences', '') or ''
                if isinstance(extra_auds, str):
                    extra_auds = [a.strip() for a in extra_auds.split(',') if a.strip()]
                accepted = [client_id] + extra_auds if client_id else extra_auds or None

                # #188: support more algorithms (Authentik uses RS256, but others exist)
                # MK 2026-05-31 — `verify_iss=False` is INTENTIONAL, not a gap.
                # Real-world IdPs (Authentik, Keycloak, Entra ID) return `iss`
                # values that vary from the configured authority URL: trailing
                # slash, host-vs-FQDN, http-vs-https on internal IdPs. The
                # channel-binding is enforced at the JWKS layer instead —
                # `signing_key.key` came from the JWKS endpoint at the
                # operator-configured authority, so a token signed by someone
                # else fails signature verification before any claim is read.
                # `verify_aud=True` + `audience=accepted` still gates audience.
                # Nonce check below covers replay. Flipping verify_iss to True
                # breaks legitimate logins on the next IdP config tweak.
                claims = pyjwt.decode(
                    id_token,
                    signing_key.key,
                    algorithms=["RS256", "ES256", "PS256", "EdDSA"],
                    audience=accepted,
                    options={
                        "verify_exp": True,
                        "verify_aud": True,
                        "verify_iss": False,  # see comment above — intentional
                        "require": ["exp", "iat", "sub"],
                    },
                    leeway=300,  # 5 min clock skew
                )

                # #188: only validate nonce if token actually has one
                # some providers (Authentik in certain configs) don't include nonce
                if expected_nonce and claims.get('nonce') and claims['nonce'] != expected_nonce:
                    logging.warning(f"[OIDC] Nonce mismatch after sig verification")
                    return {'error': 'OIDC nonce mismatch - possible replay attack'}

                return claims

        except Exception as e:
            # MK: don't break login if JWKS is temporarily unreachable
            logging.warning(f"[OIDC] JWKS verification failed ({type(e).__name__}: {e}), falling back to unverified decode")

    # Fallback: decode without signature check (pre-PyJWT behavior)
    try:
        parts = id_token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}

        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)

        # LW Feb 2026 - validate expiry (5 min clock skew tolerance)
        exp = claims.get('exp')
        if exp and time.time() > exp + 300:
            logging.warning(f"[OIDC] ID token expired: exp={exp}, now={time.time():.0f}")
            return {'error': 'ID token has expired'}

        # #188: only fail on nonce mismatch if token has a nonce claim
        if expected_nonce and claims.get('nonce') and claims['nonce'] != expected_nonce:
            logging.warning(f"[OIDC] Nonce mismatch: expected={expected_nonce[:8]}..., got={str(claims.get('nonce', ''))[:8]}...")
            return {'error': 'OIDC nonce mismatch - possible replay attack'}

        return claims
    except Exception as e:
        logging.error(f"[OIDC] JWT decode error: {e}")
        return {'error': 'Failed to validate identity token'}


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
            allow_private_ip = bool(config.get('oidc_allow_private_ip', False))
            try:
                sanitize_outbound_url(endpoints['userinfo'], allow_private=allow_private_ip)
            except SsrfError as guard_err:
                logging.warning(f"[OIDC] userinfo endpoint rejected by SSRF guard: {guard_err}")
                return {'error': 'Userinfo endpoint failed pre-flight URL validation'}
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
    
    # LW: Custom group mappings — pick highest role when user matches multiple groups
    _role_prio = {ROLE_VIEWER: 0, ROLE_USER: 1, ROLE_ADMIN: 2}
    for mapping in config.get('group_mappings', []):
        map_group = (mapping.get('group_id') or mapping.get('group_dn') or '').strip().lower()
        if map_group and (map_group in group_ids or map_group in group_names):
            if mapping.get('role') and _role_prio.get(mapping['role'], 0) > _role_prio.get(result['role'], 0):
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
