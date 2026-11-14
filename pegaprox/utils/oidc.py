# -*- coding: utf-8 -*-
"""
PegaProx OIDC/OAuth2 Authentication - Layer 4
"""

import copy
import json
import logging
import time
import hashlib
import base64
import secrets
import re
import unicodedata
import requests
from datetime import datetime
from urllib.parse import urlencode, urlparse, urlunparse

# NS May 2026 — SSRF guard for admin-supplied OIDC URLs (discovery / token / userinfo).
from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError, resolve_and_pin_url

# auth_source values that mean "this row is owned by an OIDC-family IdP", i.e.
# the ones whose oidc_sub is meaningful. 'local' and 'ldap' rows are excluded on
# purpose -- they must never be adopted by an OIDC login.
OIDC_AUTH_SOURCES = ('oidc', 'entra')


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
# a directory (tenant) id as Entra writes it, the form its tokens carry in tid and iss
_ENTRA_TENANT_ID = re.compile(r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')

# NS Oct 2026 (#1149) - the claims an admin may pick to name the account. unique_name is not
# among them: AD FS fills it with DOMAIN\user, and the name filter would drop the backslash
# and run domain and user together.
OIDC_USERNAME_CLAIMS = ('preferred_username', 'email', 'upn')
# what a picked claim may hold, after lower-casing; anything else refuses the sign-in
_OIDC_NAME_CHARS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789._-@+')


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
        # MK Nov 2026 - the extra audiences oidc_decode_id_token accepts besides the client_id
        'oidc_audiences': settings.get('oidc_audiences', '') or '',
        # NS Apr 2026 (#188) — let admins disable TLS verification for self-hosted
        # Authentik / Keycloak with self-signed certs. Default OFF (secure).
        'oidc_skip_ssl_verify': settings.get('oidc_skip_ssl_verify', False),
        # MK May 2026 (#412) — opt-in: skip the SSRF guard's private-IP check
        # for the OIDC discovery URL only. Metadata-IP blocklist (169.254.x.x
        # etc.) still binds. See helpers.py default-block for rationale.
        'oidc_allow_private_ip': settings.get('oidc_allow_private_ip', False),
        # NS Oct 2026 (#1149) - the claim that names the account, '' = the old order
        'username_claim': (settings.get('oidc_username_claim') or '')
                          if settings.get('oidc_username_claim') in OIDC_USERNAME_CLAIMS else '',
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
        # MK Nov 2026 - the iss of a v2.0 ID token names the tenant by its id. A tenant set
        # by id is bound to it; 'common', 'organizations' or a domain name cannot be, so the
        # token's own tid fills the slot, the way Entra's discovery document spells it.
        issuer_tenant = tenant_id.lower() if _ENTRA_TENANT_ID.fullmatch(tenant_id) else '{tenantid}'
        return {
            'authorization': f"{base}/authorize",
            'token': f"{base}/token",
            'jwks': f"https://{login_base}/{tenant_id}/discovery/v2.0/keys",
            'userinfo': f"https://{graph_base}/oidc/userinfo",
            'graph_me': f"https://{graph_base}/v1.0/me",
            'graph_groups': f"https://{graph_base}/v1.0/me/memberOf",
            'issuer': f"https://{login_base}/{issuer_tenant}/v2.0",
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
                'issuer': disco.get('issuer') or authority,
                '_discovery_used': True,
            }

        skip_ssl = bool(config.get('oidc_skip_ssl_verify', False))
        allow_private_ip = bool(config.get('oidc_allow_private_ip', False))
        try:
            try:
                # MK May 2026 (#412): pass allow_private through so internal
                # IdPs at 10.x / 192.168.x can be used when the operator
                # explicitly opted in. Metadata blocklist still binds.
                #
                # MK Sep 2026 - the guard only CHECKED the host and then requests.get below
                # resolved it a second time, which is the rebinding window senti-man reported
                # against the shared guard (GHSA-hmcf-9q7f-vx35). Same treatment the webhook,
                # SIEM and download paths already got: pin the address we vetted. For plain
                # https this returns the URL untouched, because the certificate check already
                # defeats a rebind - it only rewrites for the installs that turned
                # oidc_skip_ssl_verify on, which are exactly the ones with nothing else
                # catching it. allowed_schemes stays at the default https-only on purpose:
                # the one thing NOT to do here is let discovery run over plain http, where
                # whoever answers picks the authorization and token endpoints.
                discovery_url = resolve_and_pin_url(
                    discovery_url,
                    allow_private=allow_private_ip,
                    tls_verified=not skip_ssl)
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
            # NS Sep 2026 - allow_redirects=False. The authority URL is validated hard
            # before we get here (build_validated_discovery_url + sanitize_outbound_url),
            # and then requests would happily follow a 302 to 169.254.169.254 or any
            # internal host, with none of that validation applied to the second hop. We
            # guard the front door and left the back one open. A discovery endpoint that
            # redirects is unusual enough that refusing it is the right default; the log
            # line names the target so an admin can point the setting at it directly.
            resp = requests.get(discovery_url, timeout=15, verify=not skip_ssl,
                                allow_redirects=False)
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                # CWE-117: Location comes from whatever answered the request, so it is
                # remote-controlled and must not reach the log raw - same treatment the
                # login path gives attacker-supplied usernames.
                from pegaprox.utils.sanitization import sanitize_log_message as _sl
                _loc = _sl(str(resp.headers.get('Location', '(no Location header)')))[:200]
                logging.warning(
                    f"[OIDC] discovery URL redirected to {_loc!r} - not following it. "
                    f"Set the authority/issuer to the final URL instead.")
                raise requests.RequestException('discovery redirect refused')
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
                        # the name the IdP gives itself, which its tokens carry as iss (OIDC
                        # Discovery 4.3); the configured authority can differ in host or slash
                        'issuer': disco.get('issuer') or authority,
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
            'issuer': authority,
            '_discovery_used': False,
        }


def oidc_idp_request_target(config: dict, url: str, allow_private: bool) -> tuple:
    """(url, extra requests kwargs) for a request to an endpoint the IdP's discovery named.

    MK Nov 2026 - oidc_skip_ssl_verify only ever reached the discovery GET, so a self-signed
    IdP got through discovery and then failed the token request on its certificate. With the
    switch on, the token, userinfo and JWKS requests go the way discovery does: unverified,
    and pinned to the address the guard vetted, since no certificate check is left to catch
    a rebind and the token request carries the client secret. With it off the URL comes back
    as it is and the request is made exactly as before. Entra's endpoints are Microsoft's and
    discovery never read the switch for them, so neither does this. Raises SsrfError like
    resolve_and_pin_url.
    """
    if not config.get('oidc_skip_ssl_verify') or config.get('provider', 'entra') == 'entra':
        return url, {}
    return resolve_and_pin_url(url, allow_private=allow_private, tls_verified=False), {'verify': False}


def _redirect_refused(what: str, resp) -> str:
    """Log where an IdP endpoint redirected to, and return the error that names it.

    MK Nov 2026 - the sign-in requests do not follow a redirect, as discovery and the JWKS
    step of the settings test already did not: its target is a URL the guard never saw,
    and a 307 from the token endpoint posts the client secret there again. The Location is
    whatever answered, so it is sanitised before it reaches the log (CWE-117).
    """
    from pegaprox.utils.sanitization import sanitize_log_message as _sl
    loc = _sl(str((getattr(resp, 'headers', None) or {}).get('Location', '(no Location header)')))[:200]
    logging.warning(f"[OIDC] the {what} answered HTTP {resp.status_code} redirecting to {loc!r} - "
                    f"not following it. The identity provider has to name the final URL.")
    return f"The {what} redirected (HTTP {resp.status_code}), which is not followed"


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
            token_url, tls_kw = oidc_idp_request_target(config, endpoints['token'], allow_private_ip)
        except SsrfError as guard_err:
            logging.warning(f"[OIDC] token endpoint rejected by SSRF guard: {guard_err}")
            if not allow_private_ip and "private" in str(guard_err).lower():
                logging.warning(
                    "[OIDC] If your IdP token endpoint sits on a private IP "
                    "intentionally, enable `oidc_allow_private_ip` in OIDC "
                    "settings (covers discovery + token + userinfo)."
                )
            return {'error': 'Token endpoint failed pre-flight URL validation'}
        resp = requests.post(token_url, data=data, timeout=15, allow_redirects=False, **tls_kw)
        if 300 <= resp.status_code < 400:
            return {'error': _redirect_refused('token endpoint', resp)}
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


class _VerifiedClaims(dict):
    """Claims of an ID token whose signature checked out against the IdP's JWKS.

    MK Oct 2026 (#1141) - a type and not a key: the unverified decode below hands back
    whatever JSON the token carries, so a key saying "verified" could come from the
    token itself. Copying into a plain dict drops the mark, which is the safe way round.
    """


def oidc_id_token_verified(claims) -> bool:
    """True when `claims` came out of the signature-checked path of oidc_decode_id_token."""
    return isinstance(claims, _VerifiedClaims)


# what the callback answers after "Authentication failed - "; the reason goes to the log
_ID_TOKEN_INVALID = 'Failed to validate identity token'
_ID_TOKEN_EXPIRED = 'ID token has expired'
_ID_TOKEN_NONCE = 'OIDC nonce mismatch - possible replay attack'

# every asymmetric algorithm PyJWT verifies. Keycloak, Authelia and Gitea let the admin
# pick RS512 or ES384, Authentik signs with what its key gives. HS* (a shared secret) and
# none stay out, and the key always comes from the IdP's JWKS.
_ID_TOKEN_ALGORITHMS = ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                        'ES256', 'ES384', 'ES512', 'EdDSA')
# the JWK key type ("kty") each family of them takes
_ID_TOKEN_KEY_TYPES = {'RS': 'RSA', 'PS': 'RSA', 'ES': 'EC', 'Ed': 'OKP'}


def _oidc_accepted_audiences(config: dict) -> list:
    """The client_id plus the extra audiences the admin saved in oidc_audiences.

    NS May 2026 - PVE 9.2's OIDC realm gained the same `audiences` field. Mirroring it lets
    us accept tokens issued for a logical audience (e.g. "pegaprox-prod") that maps to
    multiple deployments.
    """
    client_id = config.get('client_id')
    extra = config.get('oidc_audiences', '') or ''
    if isinstance(extra, str):
        extra = [a.strip() for a in extra.split(',') if a.strip()]
    return ([client_id] if client_id else []) + list(extra)


def _oidc_idp_tls_verified(config: dict) -> bool:
    """True when the token request of this sign-in went over a checked TLS connection.

    The rule oidc_idp_request_target applies: the switch only reaches the generic providers,
    Entra's endpoints are always verified. The token endpoint is https only (the URL guard's
    default scheme list), so there is no plain http case.
    """
    return not config.get('oidc_skip_ssl_verify') or config.get('provider', 'entra') == 'entra'


def _oidc_issuer_key(value: str) -> str:
    # a trailing slash is the one difference let through. Google writes iss without the
    # scheme ("accounts.google.com"), its discovery document with it.
    value = value.strip().rstrip('/')
    return value if '://' in value else 'https://' + value


def _oidc_claims_refusal(claims, config: dict, expected_nonce, issuer, check_iss=True):
    """(error, reason) when the claims of an ID token may not sign anyone in, else None.

    MK Nov 2026 - what every path checks, with or without the signature: the audience is
    the client_id or one of oidc_audiences, an azp names the client_id, the token is
    within its nbf and exp, it carries this sign-in's nonce and, with check_iss, the
    IdP's own issuer. `issuer` may hold Entra's {tenantid} slot, filled from the token's tid.
    """
    from pegaprox.utils.sanitization import sanitize_log_message as _sl

    def _number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    if not isinstance(claims, dict):
        return _ID_TOKEN_INVALID, 'its body is not a JSON object'
    aud = claims.get('aud')
    auds = {a for a in (aud if isinstance(aud, list) else [aud]) if isinstance(a, str)}
    if not auds & set(_oidc_accepted_audiences(config)):
        return _ID_TOKEN_INVALID, (f"its audience {_sl(str(aud))[:120]!r} is neither the "
                                   f"client_id nor one of oidc_audiences")
    # the party the token was issued to (OIDC Core 3.1.3.7): in the code flow that is us,
    # whatever extra audience it also names
    azp, client_id = claims.get('azp'), config.get('client_id')
    if azp is not None and client_id and azp != client_id:
        return _ID_TOKEN_INVALID, f"it was issued to another client (azp {_sl(str(azp))[:120]!r})"
    exp, nbf, now = claims.get('exp'), claims.get('nbf'), time.time()
    if not _number(exp):
        return _ID_TOKEN_INVALID, 'it carries no expiry'
    # LW Feb 2026 - 5 min clock skew, the leeway of the signed path too
    if now > exp + 300:
        return _ID_TOKEN_EXPIRED, f"it expired (exp={exp}, now={now:.0f})"
    if nbf is not None and not (_number(nbf) and nbf <= now + 300):
        return _ID_TOKEN_INVALID, f"it is not valid yet (nbf={_sl(str(nbf))[:40]}, now={now:.0f})"
    if check_iss:
        iss = claims.get('iss')
        expected = issuer or ''
        if '{tenantid}' in expected:
            tid = claims.get('tid')
            expected = expected.replace('{tenantid}', tid) if isinstance(tid, str) and tid else ''
        if not expected:
            return _ID_TOKEN_INVALID, 'there is no issuer to check its iss against'
        if not isinstance(iss, str) or _oidc_issuer_key(iss) != _oidc_issuer_key(expected):
            return _ID_TOKEN_INVALID, (f"its issuer {_sl(str(iss))[:200]!r} is not the "
                                       f"identity provider's {_sl(expected)[:200]!r}")
    # only a nonce the token carries is compared, some Authentik setups send none
    if expected_nonce and claims.get('nonce') and claims['nonce'] != expected_nonce:
        return _ID_TOKEN_NONCE, 'its nonce is not the one this sign-in sent'
    return None


def _oidc_refused(reason: str, error: str = _ID_TOKEN_INVALID) -> dict:
    logging.warning(f"[OIDC] ID token refused: {reason}")
    return {'error': error}


def _oidc_unverified_claims(id_token: str, expected_nonce, config: dict, issuer, check_iss=True) -> dict:
    """The claims of an ID token read without its signature, after the claim checks."""
    try:
        parts = id_token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}
        payload = parts[1] + '=' * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        logging.error(f"[OIDC] JWT decode error: {e}")
        return {'error': _ID_TOKEN_INVALID}
    refusal = _oidc_claims_refusal(claims, config, expected_nonce, issuer, check_iss)
    if refusal:
        return _oidc_refused(refusal[1], refusal[0])
    return claims


def _oidc_jwks_client(config: dict, jwks_uri: str):
    """The PyJWKClient for the IdP's key set. Raises SsrfError when the guard refuses the URI."""
    # NS Jul 2026 (CodeAnt SSRF) - gate the JWKS URI before fetching keys from it.
    # allow_private=True keeps internal IdPs (RFC1918) working while cloud-metadata
    # endpoints stay blocked (always) + control chars/bad schemes rejected.
    from pegaprox.utils.url_security import sanitize_outbound_url
    sanitize_outbound_url(jwks_uri, allow_private=True)
    jwks_fetch, jwks_tls = oidc_idp_request_target(config, jwks_uri, True)
    # MK Nov 2026 - an unverified client is kept apart, so a verified fetch never
    # reuses one after the TLS switch is turned off again
    jwks_key = ('unverified', jwks_fetch) if jwks_tls else jwks_uri
    if jwks_key not in _jwks_clients:
        if jwks_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _jwks_clients[jwks_key] = PyJWKClient(jwks_fetch, cache_keys=True, lifespan=3600,
                                                  ssl_context=ctx)
        else:
            _jwks_clients[jwks_key] = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)
    return _jwks_clients[jwks_key]


def _oidc_token_keys(client, jwk_set, header: dict) -> list:
    """The keys of the IdP's set the token may be signed with, of the type its alg takes.

    The one its kid names, fetching the set once more for a key rotated in since it was
    cached. PyJWKClient matches by kid alone, so a token without one, or a set whose keys
    carry none, never found its key: then each signing key of the set is a candidate.
    """
    kind = _ID_TOKEN_KEY_TYPES[header['alg'][:2]]
    signing = [k for k in jwk_set.keys if k.public_key_use in ('sig', None)]
    kid = header.get('kid')
    if kid and any(k.key_id for k in signing):
        named = [k for k in signing if k.key_id == kid] or [client.get_signing_key(kid)]
    else:
        named = signing
    keys = [k for k in named if k.key_type == kind]
    if not keys:
        raise pyjwt.PyJWKClientError(f'the key set holds no {kind} signing key'
                                     + (f' under the kid {kid!r}' if kid else ''))
    return keys


def oidc_decode_id_token(id_token: str, expected_nonce: str = None,
                         config: dict = None) -> dict:
    """Decode the ID token of a sign-in and check it. Returns the claims or {'error': ...}.

    MK Mar 2026: the signature is verified against the IdP's JWKS (PyJWT).
    MK Nov 2026: and the check fails closed. Every error in it used to fall back to reading
    the token unchecked, so a bad signature, an unknown key or another audience still
    signed the user in, with the groups of that token deciding the role. A token whose
    signature, audience (client_id or oidc_audiences), azp, issuer, nbf, expiry or nonce
    does not check out is refused now. Its signature goes unchecked in two cases only:

      * oidc_skip_jwt_verification, the admin's own switch for a broken JWKS. Audience,
        azp, nbf, expiry and nonce are still checked.
      * the key set itself cannot be loaded (network, it does not parse, no key) while TLS is
        verified. The token then came straight from the token endpoint over a checked
        connection, which OIDC Core 3.1.3.7 accepts in place of the signature, and
        audience, issuer, expiry and nonce are checked on its claims. With
        oidc_skip_ssl_verify on nothing vouches for it, so it is refused.

    A key set that loads but has no key for the token is a refusal, not an outage. The
    token may be signed with any asymmetric algorithm (_ID_TOKEN_ALGORITHMS).
    """
    from pegaprox.utils.sanitization import sanitize_log_message as _sl

    if not config:
        return _oidc_refused('there are no OIDC settings to check it against')
    if config.get('oidc_skip_jwt_verification', False):
        logging.warning("[OIDC] JWT signature verification DISABLED by admin setting")
        return _oidc_unverified_claims(id_token, expected_nonce, config, None, check_iss=False)
    if not PYJWT_AVAILABLE:
        return _oidc_refused('PyJWT is not installed, so its signature cannot be checked')

    endpoints = get_oidc_endpoints(config) or {}
    # the issuer discovery names (Entra: from the tenant), else the configured authority
    issuer = endpoints.get('issuer') or config.get('authority') or ''
    jwks_uri = endpoints.get('jwks', '')

    client = None
    if jwks_uri:
        try:
            client = _oidc_jwks_client(config, jwks_uri)
        except SsrfError as _se:
            logging.warning(f"[OIDC] jwks_uri rejected by SSRF guard: {_se}")
            return {'error': 'OIDC JWKS endpoint rejected by SSRF guard'}
        except Exception as e:
            return _oidc_refused(f"no client for its JWKS ({type(e).__name__}: {_sl(str(e))[:300]})")

    # the key set first, on its own: only when it cannot be had at all (network, no JSON,
    # no key in it) does the TLS connection the token came over stand in for the signature
    try:
        if client is None:
            raise pyjwt.PyJWKClientError('the identity provider names no JWKS endpoint')
        jwk_set = client.get_jwk_set()
    except (pyjwt.PyJWTError, ValueError, OSError) as e:
        why = f"{type(e).__name__}: {_sl(str(e))[:300]}"
        if not _oidc_idp_tls_verified(config):
            return _oidc_refused(f"its JWKS could not be loaded ({why}) and oidc_skip_ssl_verify "
                                 f"is on, so nothing vouches for the token without its signature")
        # MK: don't break login if JWKS is temporarily unreachable
        logging.warning(f"[OIDC] JWKS could not be loaded ({why}), falling back to unverified decode: "
                        f"the token came from the token endpoint over verified TLS, its audience, "
                        f"issuer, expiry and nonce are still checked")
        return _oidc_unverified_claims(id_token, expected_nonce, config, issuer)
    except Exception as e:
        return _oidc_refused(f"its JWKS could not be read ({type(e).__name__}: {_sl(str(e))[:300]})")

    try:
        header = pyjwt.get_unverified_header(id_token)
        if header.get('alg') not in _ID_TOKEN_ALGORITHMS:
            raise pyjwt.InvalidAlgorithmError(f"the alg {_sl(str(header.get('alg')))[:20]!r} is not allowed")
        claims = None
        for key in _oidc_token_keys(client, jwk_set, header):
            # verify_iss stays off here on purpose: iss is compared below with the issuer
            # discovery names, not the configured authority, which real IdPs (Authentik,
            # Keycloak) often spell with another host or slash. Same check on every path.
            try:
                claims = pyjwt.decode(
                    id_token,
                    key.key,
                    algorithms=list(_ID_TOKEN_ALGORITHMS),
                    audience=_oidc_accepted_audiences(config) or None,
                    options={
                        "verify_exp": True,
                        "verify_aud": True,
                        "verify_iss": False,
                        "require": ["exp", "iat", "sub"],
                    },
                    leeway=300,  # 5 min clock skew
                )
                break
            except (pyjwt.InvalidSignatureError, pyjwt.InvalidKeyError) as e:
                # without a kid to pick it, the next key of the set may be the one
                last = e
        if claims is None:
            raise last
    except Exception as e:
        expired = isinstance(e, pyjwt.ExpiredSignatureError)
        return _oidc_refused(f"it did not pass the signature and claim check "
                             f"({type(e).__name__}: {_sl(str(e))[:300]})",
                             _ID_TOKEN_EXPIRED if expired else _ID_TOKEN_INVALID)

    refusal = _oidc_claims_refusal(claims, config, expected_nonce, issuer)
    if refusal:
        return _oidc_refused(refusal[1], refusal[0])
    return _VerifiedClaims(claims)


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
            resp = requests.get(endpoints['graph_me'], headers=headers, timeout=10, allow_redirects=False)
            if resp.status_code == 200:
                graph_data = resp.json()
                user_info = {
                    'sub': graph_data.get('id', ''),
                    'preferred_username': graph_data.get('userPrincipalName', ''),
                    'upn': graph_data.get('userPrincipalName', ''),
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
                userinfo_url, tls_kw = oidc_idp_request_target(config, endpoints['userinfo'],
                                                               allow_private_ip)
            except SsrfError as guard_err:
                logging.warning(f"[OIDC] userinfo endpoint rejected by SSRF guard: {guard_err}")
                return {'error': 'Userinfo endpoint failed pre-flight URL validation'}
            resp = requests.get(userinfo_url, headers=headers, timeout=10, allow_redirects=False, **tls_kw)
            if 300 <= resp.status_code < 400:
                return {'error': _redirect_refused('userinfo endpoint', resp)}
            if resp.status_code == 200:
                user_info = resp.json()
    except Exception as e:
        logging.warning(f"[OIDC] User info fetch error: {e}")
    
    return user_info


def oidc_name_from_id_token(user_info: dict, id_claims: dict) -> dict:
    """user_info, with preferred_username and email from the ID token when it has neither.

    MK Oct 2026 (#1141) - Entra falls back to the userinfo endpoint when Graph /me is
    refused (no User.Read consent), and that answer has a sub but no name, so the account
    came out as oidc_<sub>. The ID token of the same sign-in does carry preferred_username.
    Only from a token whose signature was checked in this sign-in, never from the
    unverified decode, and only for the same subject (OIDC Core 5.3.2).
    """
    if user_info.get('preferred_username') or user_info.get('email'):
        return _with_token_email_flag(user_info, id_claims)
    if not oidc_id_token_verified(id_claims):
        return user_info
    sub = user_info.get('sub')
    if not sub or id_claims.get('sub') != sub:
        return user_info
    named = dict(user_info)
    for claim in ('preferred_username', 'email'):
        value = id_claims.get(claim)
        if isinstance(value, str) and value:
            named[claim] = value
    # the flag travels with the address it is about, oidc_derive_username reads it
    if named.get('email') and 'email_verified' in id_claims:
        named['email_verified'] = id_claims['email_verified']
    return named


def _claim_text(value):
    # as it came: padding is the name check's to refuse, not something to strip away here
    return value if isinstance(value, str) and value.strip() else None


# MK Nov 2026 - how the IdPs write "no": a JSON false, a 0, or one of these words in any case
_EMAIL_FLAG_NO = frozenset(('false', '0', 'no', 'n', 'off'))


def _email_unverified(source):
    flag = source.get('email_verified')
    if isinstance(flag, bool):
        return flag is False
    if isinstance(flag, (int, float)):
        return flag == 0
    return isinstance(flag, str) and flag.strip().lower() in _EMAIL_FLAG_NO


def _with_token_email_flag(userinfo: dict, id_claims) -> dict:
    """userinfo, with the email_verified of the verified ID token when it carries the same
    address without a flag of its own.

    MK Nov 2026 - a userinfo answer that leaves the flag out says nothing about the address,
    the token of the same subject may. Only ever turns a name off, so a userinfo answer
    without a sub counts as the token's subject here.
    """
    if 'email_verified' in userinfo or not oidc_id_token_verified(id_claims) \
            or 'email_verified' not in id_claims:
        return userinfo
    email, token_email, sub = userinfo.get('email'), id_claims.get('email'), userinfo.get('sub')
    if (not isinstance(email, str) or not isinstance(token_email, str)
            or email.strip().lower() != token_email.strip().lower()
            or (sub and sub != id_claims.get('sub'))):
        return userinfo
    return dict(userinfo, email_verified=id_claims['email_verified'])


def oidc_username_claim_value(userinfo: dict, id_claims: dict, claim: str):
    """The value of the username claim the admin picked, None when this sign-in has none.

    NS Oct 2026 (#1149) - AD FS answers userinfo with the sub alone and puts its claims in
    the tokens, so the claim is looked up in the userinfo answer first and then in the ID
    token. The ID token only counts when its signature was checked in this sign-in and,
    if userinfo answered, when it is about the same subject (as oidc_name_from_id_token).
    `userinfo` is the endpoint's answer itself, never the ID token standing in for it.
    """
    if claim not in OIDC_USERNAME_CLAIMS:
        return None
    userinfo = userinfo if isinstance(userinfo, dict) else {}
    value = _claim_text(userinfo.get(claim))
    if value:
        unverified = claim == 'email' and _email_unverified(_with_token_email_flag(userinfo, id_claims))
        return None if unverified else value
    if not isinstance(id_claims, dict) or not oidc_id_token_verified(id_claims):
        return None
    if userinfo:
        sub = userinfo.get('sub')
        if not sub or id_claims.get('sub') != sub:
            return None
    if claim == 'email' and _email_unverified(id_claims):
        return None
    return _claim_text(id_claims.get(claim))


def oidc_username_claim_refusal(userinfo: dict, id_claims: dict, claim: str) -> str:
    """Why oidc_username_claim_value had no value, for the log: the user only sees that
    the sign-in has no usable claim."""
    userinfo = userinfo if isinstance(userinfo, dict) else {}
    for source, label in ((userinfo, 'userinfo answer'), (id_claims or {}, 'ID token')):
        if claim == 'email' and _claim_text(source.get('email')) and _email_unverified(source):
            return f'the {label} marks the email as not verified'
    if _claim_text((id_claims or {}).get(claim)) and not oidc_id_token_verified(id_claims):
        return 'the ID token carries it, but its signature was not checked'
    if userinfo and _claim_text((id_claims or {}).get(claim)) and \
            userinfo.get('sub') != (id_claims or {}).get('sub'):
        return 'the ID token carries it, but is about another subject than the userinfo answer'
    return 'neither the userinfo answer nor the ID token carries it'


def oidc_get_user_groups(config: dict, access_token: str) -> list:
    """Fetch user's group memberships from OIDC provider.

    Kept for callers (incl. plugins) that only want the list. Use
    oidc_get_user_groups_ex() when the answer drives an authorization decision -
    this one cannot tell you whether the list is complete.
    """
    groups, _complete = oidc_get_user_groups_ex(config, access_token)
    return groups


def oidc_get_user_groups_ex(config: dict, access_token: str):
    """Fetch group memberships AND say whether the answer can be trusted.

    Returns (groups, complete). `complete` is False when we could not establish the
    full set - the Graph call failed, a page was lost mid-pagination, or the provider
    is a generic one that puts groups in the ID token instead of here.

    NS Sep 2026 - this split exists because the old function returned [] for three very
    different situations: the user genuinely has no groups, the Graph call failed, and
    "generic provider, ask the ID token". Provisioning then treated all three as "no
    groups". That was survivable while permissions could only ever grow; it is not
    survivable now that an empty mapping revokes, because one Graph hiccup would strip
    every Entra user on their next login. A failure has to look different from an empty
    answer, so callers can keep what they have and complain loudly instead.

    Note the partial case specifically: Entra pages at 100 groups, and the old loop broke
    out on a non-200 keeping whatever it had. Revoking against half a group list is worse
    than not revoking at all.
    """
    if config.get('provider') != 'entra':
        # Generic OIDC: groups live in the ID token claims, which the caller reads
        # separately. Nothing fetched here, so nothing authoritative here either.
        return [], False

    endpoints = get_oidc_endpoints(config)
    headers = {'Authorization': f'Bearer {access_token}'}
    groups = []
    # Start pessimistic. `complete` is what lets a caller REVOKE, so every way out of
    # this function that is not a finished walk has to leave it False. Initialising it
    # True was wrong for one specific reason: graph_groups is set to '' on five separate
    # discovery/config fallback paths in get_oidc_endpoints, and with an empty URL the
    # loop below never runs. That returned ([], True) - authoritative, zero groups - and
    # would have stripped every Entra user's permissions on their next login whenever
    # discovery had a bad morning.
    complete = False

    url = endpoints.get('graph_groups') or ''
    if not url:
        logging.warning("[OIDC] no Graph group endpoint resolved for this config "
                        "(discovery fallback?) - group membership is unknown, so this "
                        "login can grant but not revoke")
        return groups, False

    from urllib.parse import urlsplit as _urlsplit
    try:
        _first = _urlsplit(url)
        _origin = (_first.scheme, _first.netloc.lower())
    except ValueError:
        return groups, False
    if _origin[0] not in ('http', 'https') or not _origin[1]:
        return groups, False

    try:
        # NS: Entra Graph API for group memberships
        while url:
            # pagination links must stay on the same scheme/host as the configured endpoint
            try:
                _cur = _urlsplit(url)
                _cur_origin = (_cur.scheme, _cur.netloc.lower())
            except ValueError:
                _cur_origin = None
            if _cur_origin != _origin:
                logging.warning("[OIDC] Group fetch aborted: pagination link left the configured endpoint")
                complete = False
                break

            # a redirect is not followed (see _redirect_refused): any status but 200 is a failed fetch
            resp = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            if resp.status_code != 200:
                logging.warning(f"[OIDC] Group fetch failed: {resp.status_code}")
                complete = False
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
        else:
            # while/else: only reached when the loop ran out of pages on its own, i.e.
            # no break, no exception. That is the one path that saw the whole set.
            complete = True

        logging.info(f"[OIDC] Fetched {len(groups)} group memberships"
                     f"{'' if complete else ' (INCOMPLETE - fetch failed part way)'}")
    except Exception as e:
        logging.warning(f"[OIDC] Group fetch error: {e}")
        complete = False

    return groups, complete


def oidc_map_groups_to_role(config: dict, groups: list, id_token_claims: dict = None,
                            groups_complete: bool = None) -> dict:
    """Map OIDC groups to PegaProx role, tenant, and permissions

    LW: Works with Entra group IDs and generic OIDC group claims
    Returns: {'role': str, 'tenant': str, 'permissions': [], 'tenant_permissions': {},
              'groups': [], '_authoritative': bool}

    NS Sep 2026 - `_authoritative` says whether this mapping may be used to REVOKE, not
    just to grant. It is true only when we know the full group set: either the Entra
    fetch completed (groups_complete=True), or the validated ID token actually carried a
    `groups` claim. A provider that sends no groups claim at all is indistinguishable
    from a user who lost every group, so that case stays non-authoritative and
    provisioning leaves existing grants alone.
    """
    result = {
        'role': config.get('default_role', ROLE_VIEWER),
        'tenant': '',
        'permissions': [],
        'tenant_permissions': {},
        'groups': [],
        '_authoritative': False,
    }
    if groups_complete:
        result['_authoritative'] = True
    elif id_token_claims is not None and 'groups' in id_token_claims:
        # The ID token is signature-checked before it gets here, so a groups claim in it
        # is as good a source as the Graph call - including when it is an empty list.
        #
        # Except when the provider says it truncated it. Entra stops embedding the full
        # list once a user is in more groups than fit the token and emits _claim_names /
        # _claim_sources pointing at Graph instead ("groups overage"). The claim is then
        # present but partial, and deciding a revocation on a partial list is the thing
        # this whole mechanism exists to avoid. Grant from it, never revoke.
        _names = id_token_claims.get('_claim_names')
        if isinstance(_names, dict) and 'groups' in _names:
            logging.warning(
                "[OIDC] the ID token signals a groups overage - the claim is truncated, "
                "so this login can grant but not revoke. Give the app Graph group-read "
                "permission if you need memberships to be authoritative.")
        else:
            result['_authoritative'] = True
    
    # Build list of group identifiers (IDs for Entra, names for generic)
    group_ids = set()
    group_names = set()
    for g in groups:
        if isinstance(g, dict):
            # MK Oct 2026 (#962) - Graph sends "displayName": null for some groups, and
            # .get(k, '') only covers a missing key; the .lower() on None was a 500 at login
            gid = str(g.get('id') or '').strip().lower()
            gname = str(g.get('name') or '').strip().lower()
            if gid:
                group_ids.add(gid)
            if gname:
                group_names.add(gname)
        elif isinstance(g, str):
            group_ids.add(g.lower())
            group_names.add(g.lower())
    
    # NS: Also check ID token 'groups' claim (Entra can embed group IDs in token)
    if id_token_claims:
        for gid in id_token_claims.get('groups', []):
            group_ids.add(str(gid).lower())

    # MK Oct 2026 (#940) - the groups oidc_build_user_row stores on the user, which is what
    # a pool grant on a group is matched against. Entra groups go in by object id only: the
    # display name is the squattable identifier the name-match warning further down is
    # about, and a pool grant must not be claimable by creating a group of the right name.
    # A generic provider's groups claim is taken as the signed token carries it.
    _claim = (id_token_claims or {}).get('groups') or []
    if isinstance(_claim, str):
        _claim = [_claim]
    _seen = set()
    for g in list(groups or []) + (list(_claim) if isinstance(_claim, (list, tuple)) else []):
        v = g.get('id') if isinstance(g, dict) else g
        if isinstance(v, int) and not isinstance(v, bool):
            v = str(v)
        if isinstance(v, str) and v.strip() and v.strip().lower() not in _seen:
            _seen.add(v.strip().lower())
            result['groups'].append(v.strip())

    # MK: Built-in group mappings (admin > user > viewer priority)
    admin_group = config.get('admin_group_id', '').strip().lower()
    user_group = config.get('user_group_id', '').strip().lower()
    viewer_group = config.get('viewer_group_id', '').strip().lower()
    
    # KG Aug 2026 — track whether result['role'] is still only oidc_default_role. A group
    # that actually matched must always be able to replace the default, whatever its rank,
    # otherwise a custom default_role silently swallows every mapping below.
    role_from_default = True

    if admin_group and (admin_group in group_ids or admin_group in group_names):
        result['role'] = ROLE_ADMIN
        role_from_default = False
    elif user_group and (user_group in group_ids or user_group in group_names):
        result['role'] = ROLE_USER
        role_from_default = False
    elif viewer_group and (viewer_group in group_ids or viewer_group in group_names):
        result['role'] = ROLE_VIEWER
        role_from_default = False

    # LW: Custom group mappings — pick highest role when user matches multiple groups
    # KG Aug 2026 — custom roles used to be dropped here without a trace: they are absent
    # from _role_prio, so .get(role, 0) ranked them equal to viewer and the strict `>` never
    # fired — while the log line below still reported the mapping as matched. Rank them
    # between user and admin: an explicit mapping onto a custom (e.g. tenant-scoped) role
    # should beat the coarse viewer/user defaults, but must never demote an admin-group hit.
    _role_prio = {ROLE_VIEWER: 0, ROLE_USER: 1, ROLE_ADMIN: 3}
    _CUSTOM_ROLE_PRIO = 2

    def _role_rank(role):
        return _role_prio.get(role, _CUSTOM_ROLE_PRIO)

    # KG Aug 2026 — custom roles all share one rank, so when several of them match the
    # first one in the list wins and the rest tie out. That is deterministic and mirrors
    # how the mapping list reads top-down, but it IS order-dependent, so say so out loud
    # instead of quietly picking one: defining a real precedence between custom roles
    # would mean comparing their permission sets, which is a product decision, not
    # something to smuggle into a bug fix.
    matched_custom_roles = []

    for mapping in config.get('group_mappings', []):
        map_group = (mapping.get('group_id') or mapping.get('group_dn') or '').strip().lower()
        _by_id = bool(map_group) and map_group in group_ids
        _by_name = bool(map_group) and map_group in group_names
        if _by_name and not _by_id:
            # MK Sep 2026 - a group's display name is not a stable identifier. In an Entra
            # tenant where users may create security groups (the default in plenty of them),
            # anyone can make a group called whatever a mapping names and inherit the role it
            # grants. The id cannot be squatted that way. Removing name matching outright
            # would break every install that configured mappings by name - the field is even
            # called group_dn, so it was meant to be used that way - so for now say so, loudly
            # and per match, and leave the decision about a migration to a release.
            logging.warning(
                "[OIDC] group mapping '%s' matched on display NAME, not on group id, and "
                "granted role '%s'. Display names are not unique and are not stable - anyone "
                "who can create a group in the directory can claim this mapping. Re-point it "
                "at the group's object id.",
                map_group, mapping.get('role') or '(no role)')
        if _by_id or _by_name:
            if mapping.get('role') and mapping['role'] not in _role_prio:
                matched_custom_roles.append(mapping['role'])
            # The configured default stands for "no group matched" (that is how the setting
            # is labelled in the UI), so a group that DID match may replace it — except when
            # the default is admin: silently demoting a configured admin on a lower-privilege
            # match would lock installs out of admin-only workflows.
            if mapping.get('role') and (
                    (role_from_default and result['role'] != ROLE_ADMIN)
                    or _role_rank(mapping['role']) > _role_rank(result['role'])):
                result['role'] = mapping['role']
                role_from_default = False
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

    if len(matched_custom_roles) > 1:
        logging.warning(
            f"[OIDC] user matched {len(matched_custom_roles)} custom-role group mappings "
            f"({', '.join(matched_custom_roles)}); applied '{result['role']}' — custom roles "
            "share one precedence level, so the first match in the mapping list wins. "
            "Reorder the mappings if a different role should take precedence."
        )

    return result


def _oidc_fallback_username(sub, users: dict):
    """The key for a sign-in whose claims carry no usable name, or None to refuse it.

    MK Oct 2026 (#1141) - this was oidc_<first 12 chars of the sub>. It kept the case of
    the sub, and the admin routes lower-case the name they are given, so such an account
    could be neither edited nor deleted. And 12 characters of a sub are not the sub: two
    subjects sharing a prefix derived one key, and the second login took the account over.

    An OIDC account already bound to this sub keeps its key, whatever it looks like (the
    old upper-case ones included) - it is the same identity, as in the adoption rule
    below. Otherwise a lower-case hash of the sub, which is never adopted from someone
    else: a row under that key that is not this subject's refuses the login.
    """
    if not isinstance(sub, str) or not sub:
        logging.warning("[OIDC] sign-in without a name and without a sub claim - refused")
        return None
    # sorted: a standby has to arrive at the same key as the active, whatever row order
    mine = [key for key in sorted(users)
            if isinstance(users[key], dict)
            and users[key].get('auth_source', 'local') in OIDC_AUTH_SOURCES
            and users[key].get('oidc_sub') == sub]
    if mine:
        # a named account before an old fallback one: once the ID token names the user both
        # carry the sub, and the named one is what an admin looks after now. A sign-in that
        # loses the name again must not go back to the old one (disabled or not)
        named = [key for key in mine if not _oidc_is_fallback_row(key, users[key])]
        return (named or mine)[0]
    key = _oidc_fallback_key(sub)
    if key in users:
        logging.warning(f"[OIDC] '{key}' belongs to another identity - this sign-in has no "
                        f"name claim to tell them apart, refused")
        return None
    return key


def _oidc_fallback_key(sub: str) -> str:
    return 'oidc_' + hashlib.sha256(sub.encode('utf-8')).hexdigest()[:16]


def _oidc_is_fallback_row(username: str, row: dict) -> bool:
    """Whether `row` is the account a sign-in without a name made for its stored sub.

    Its key is then no name an IdP gave anyone, only the sub spelled differently - the
    hash, or oidc_<first 12 chars> from before #1141. A name claim that happens to spell
    it is not that identity.
    """
    sub = row.get('oidc_sub')
    if not isinstance(sub, str) or not sub:
        return False
    return username in (_oidc_fallback_key(sub), f"oidc_{sub[:12]}")


def oidc_key_names_a_subject(username: str, row: dict) -> bool:
    """Whether the account's key was made from a subject id, not from a name: the account
    of a sign-in without a name claim (_oidc_is_fallback_row), or a key of the hash's shape.

    MK Nov 2026 - such an account is found by its sub alone. Without one stored, its owner
    lands elsewhere and a sign-in whose name spells the key would get it.
    """
    return _oidc_is_fallback_row(username, row) or bool(re.fullmatch(r'oidc_[0-9a-f]{16}', username or ''))


def oidc_derive_username(user_info: dict, users: dict = None, name: str = None) -> str:
    """Derive the local username key from OIDC claims.

    LW: keep the full preferred_username including the domain. Truncating at
    '@' collapsed bob@corp.com and bob@partner.com onto one account, so the
    second one to log in inherited the first one's role and tenant.

    `users` is the already-loaded users table. Callers in the login path have
    one in hand; passing it avoids a second full-table read per login.

    None when the claims carry no name and the fallback key cannot be this
    identity's (see _oidc_fallback_username); the sign-in is refused then.

    `name` is the value of the username claim the admin picked (#1149). It replaces the
    claim order, and a name that filters down to nothing is None: no fallback key then.
    """
    from pegaprox.utils.auth import load_users

    if name is not None:
        # NS Oct 2026 (#1149) - the filter below drops or folds what it does not know (a
        # dotted capital I, a zero-width space, an apostrophe), and lower() turns the Kelvin
        # sign into a k, so two people at the IdP could come out as one name here. A picked
        # claim is plain ASCII without padding and goes through whole, or not at all.
        raw_username = name.lower() if name.isascii() and name == name.strip() else ''
        if not raw_username or any(c not in _OIDC_NAME_CHARS for c in raw_username):
            logging.warning("[OIDC] Sign-in refused: the picked username claim holds characters "
                            "a PegaProx username cannot carry")
            return None
    else:
        raw_username = (user_info.get('preferred_username')
                        or user_info.get('email', ''))
        # MK Nov 2026 - an address the IdP marks as not verified is one anybody could
        # have typed in at a self-service sign-up. It names nobody: the sign-in goes on
        # as one without a name, which finds the account already bound to its sub.
        # Only an explicit false - Entra and AD FS send no flag at all.
        if raw_username and not user_info.get('preferred_username') and _email_unverified(user_info):
            logging.warning("[OIDC] the email claim is marked as not verified, so it does not "
                            "name the account - going on as a sign-in without a name")
            raw_username = ''

    # Char set matches sanitize_username()'s allowlist. '+' belongs here for the
    # same reason '@' does: dropping it silently merges identities, so
    # a+b@example.com would derive onto a real ab@example.com account.
    username = ''.join(c for c in raw_username.lower()
                       if c.isalnum() or c in '._-@+')
    if not username and name is not None:
        return None
    if not username:
        return _oidc_fallback_username(user_info.get('sub'),
                                       users if users is not None else load_users())

    # Back-compat: installs before this change stored the part before '@'.
    # An existing account keeps its old key so it isn't orphaned -- but only if
    # it is provably the SAME identity. Reusing 'bob' merely because a local
    # part matches would re-open the very collision this function closed:
    # bob@partner.com would land on the 'bob' row that bob@corp.com created and
    # inherit its role and tenant. The stored oidc_sub is the IdP's stable,
    # non-reassignable identifier for the subject, so require it to match the
    # incoming one exactly. A sub is only unique within an issuer; installs that
    # repoint at a different IdP have to rekey manually (no issuer is recorded
    # on the user row to check against).
    if '@' in username:
        sub = user_info.get('sub', '')
        legacy = username.split('@')[0]
        if legacy and sub:
            existing = (users if users is not None else load_users()).get(legacy)
            if (existing
                    and existing.get('auth_source', 'local') in OIDC_AUTH_SOURCES
                    and existing.get('oidc_sub') == sub):
                return legacy

    return username


def _oidc_name_is_exact(raw, username: str) -> bool:
    """Whether the claim `raw` became the key `username` by lower-casing alone.

    The automatic order drops what the username filter does not know and lower() folds the
    Kelvin sign into a k, so 'Bob\u200b@corp.example', ' bob@corp.example', "bo'b@..." or a
    decomposed umlaut all come out as some other account's key.
    """
    return (isinstance(raw, str) and raw == raw.strip()
            and unicodedata.normalize('NFKC', raw) == raw and raw.lower() == username)


def oidc_new_account_refusal(username: str, user_info: dict, name: str = None):
    """Why this sign-in may not make the new account `username`, or None when it may.

    MK Nov 2026 - the same folds made a new account for a stranger: 'Bob\u200b@corp.example',
    'bob@corp.example ' or the Kelvin sign made bob@corp.example or kelvin@corp.example,
    bound to that sub, and the person of the name was refused from then on. Punctuation
    may still go (the apostrophe of an O'Brien address) and case folds as before; padding,
    what NFKC folds and what cannot be seen or combines with a letter may not.
    """
    raw = name if name is not None else (user_info.get('preferred_username') or user_info.get('email'))
    if not isinstance(raw, str) or not raw:
        return None
    lowered = raw.lower()
    dropped = [c for c in lowered if not (c.isalnum() or c in '._-@+')]
    if ''.join(c for c in lowered if c not in dropped) != username:
        return None  # the key is not this name's: a sign-in without one, keyed on its sub
    if raw != raw.strip():
        return 'padding around the name'
    if unicodedata.normalize('NFKC', raw) != raw:
        return 'characters NFKC folds into others'
    hidden = [c for c in dropped if c != ' ' and unicodedata.category(c)[0] in 'CMZ']
    if hidden:
        return ('characters that cannot be seen or combine with a letter ('
                + ', '.join(f'U+{ord(c):04X}' for c in hidden[:4]) + ')')
    return None


def oidc_subject_refusal(username: str, row: dict, user_info: dict, subjects=None, name: str = None):
    """Why this sign-in may not use the OIDC / Entra account `row`, or None when it may.

    `subjects` are the ids this one sign-in goes by besides user_info's sub: with Entra
    the Graph id when /me answered and the verified token's sub and oid, so a Graph
    hiccup does not lock anyone out. `name` is the picked username claim, as for
    oidc_derive_username.
    """
    sub = user_info.get('sub')
    # MK Oct 2026 (#1141) - a fallback key is lower case now, so a name claim can spell
    # one ("oidc_" + 16 hex). That row is its sub's, not whoever picks it as a username.
    if _oidc_is_fallback_row(username, row) and row.get('oidc_sub') != sub:
        return "that account was made for another subject's sign-in without a name"
    # NS Oct 2026 (#1149) - the account stays with the subject it was made for. Claims like
    # email can be changed or handed on at some identity providers, and the update would
    # give the row and its role to whoever carries the value now.
    # MK Nov 2026 - whatever names the account, the picked claim or the automatic order:
    # two subjects with one preferred_username (a renamed or recycled IdP account, a second
    # IdP) took turns on the row. A row with no subject stored (made by hand, or reset by
    # an admin) is bound by the next sign-in that carries a subject id and names it exactly.
    bound = row.get('oidc_sub')
    own = {s for s in [*(subjects or ()), sub] if isinstance(s, str) and s}
    if bound:
        if bound not in own:
            return ("the account belongs to another subject of the identity provider; an admin "
                    "can reset its sign-in binding if it is the same person (after a move to "
                    "another identity provider, for example)")
        return None
    if not own:
        return "the account is not bound yet and the sign-in carries no subject id to bind it to"
    raw = name if name is not None else (user_info.get('preferred_username') or user_info.get('email'))
    if not _oidc_name_is_exact(raw, username):
        return ("the account is not bound yet and is taken only by its exact name, while this "
                "sign-in's name reaches it only once characters are dropped or folded (padding, "
                "invisible or combining characters, punctuation, a look-alike letter). If it is "
                "the owner, an admin can delete the account and the next sign-in creates it again")
    return None


def oidc_build_user_row(user_info: dict, role_mapping: dict, auth_source: str, users: dict,
                        name: str = None, subjects=None):
    """The row an OIDC sign-in would store for this user, without storing it.

    `users` is the users table as loaded. Returns (username, row), or None where an
    account of another identity source owns the name; the caller leaves it alone then.

    MK Oct 2026 (#625) - split out of oidc_provision_user, as ldap_build_user_row was:
    a standby asks what the identity provider says without writing it down, its users
    table is the active's copy and the next sync puts that copy back.
    """
    # Derive username from OIDC claims
    email = user_info.get('email') or user_info.get('preferred_username', '')
    username = oidc_derive_username(user_info, users, name=name)
    if username is None:
        return None  # no name, and the fallback key is not this identity's (#1141)
    # MK Nov 2026 - in the automatic order too: a row made or updated without a sub is
    # bound to nobody, and an update wrote the empty sub over the stored one
    sub = user_info.get('sub')
    if not isinstance(sub, str) or not sub:
        logging.warning(f"[OIDC] Rejected login for '{username}' - the sign-in has no sub, "
                        f"so the account cannot be tied to it")
        return None

    display_name = user_info.get('name') or user_info.get('given_name', '')
    if not display_name:
        display_name = username

    if username in users:
        # NS: SECURITY - Don't allow OIDC to overwrite a local-only user
        # This prevents account takeover if someone creates an IdP account matching a local username
        # NS Sep 2026 - this checked only 'local', while the comment on OIDC_AUTH_SOURCES
        # says local AND ldap must never be adopted by an OIDC login. An LDAP row with a
        # matching username fell straight through to the update path below and had its
        # role and auth_source rewritten - the account takeover the local check was added
        # to prevent, one directory over. Reject anything this login does not own.
        existing_source = users[username].get('auth_source', 'local')
        if existing_source not in OIDC_AUTH_SOURCES:
            logging.warning(f"[OIDC] Rejected login for '{username}' - a {existing_source} "
                            f"account of that name exists and cannot be taken over by OIDC")
            return None  # Caller should handle None return
        refusal = oidc_subject_refusal(username, users[username], user_info, subjects, name=name)
        if refusal:
            logging.warning(f"[OIDC] Rejected login for '{username}' - {refusal}")
            return None

        # Update existing OIDC user - on a copy, so the table the caller handed in
        # stays what it was
        user = copy.deepcopy(users[username])
        user['display_name'] = display_name
        user['email'] = email
        user['auth_source'] = auth_source
        user['oidc_sub'] = user_info.get('sub', '')
        user['last_oidc_sync'] = datetime.now().isoformat()

        # NS Sep 2026 - this block used to be grant-only. `permissions` was a union with
        # what was already there, `tenant_permissions` was a dict .update(), and `role`
        # fell back to the stored one - all three guarded by `if role_mapping.get(...)`,
        # so an empty mapping did not even enter them. The effect: taking a user out of a
        # group in the IdP revoked nothing here. Someone who left the company kept every
        # permission they had until an admin noticed by hand, which is the opposite of
        # what wiring PegaProx to an IdP is for.
        #
        # The IdP is now authoritative - but only when we actually know the full group
        # set (see oidc_map_groups_to_role). On a failed or partial Graph fetch, or a
        # provider that sends no groups claim, we keep what is stored and say so at
        # WARNING level. Revoking on a network hiccup would turn a privilege bug into an
        # outage, and half a group list is worse to decide on than none.
        #
        # tenant_id is deliberately NOT cleared when unmapped: admins also set it by hand,
        # and dropping someone out of their tenant is a different decision from taking a
        # permission away. Assign when mapped, leave alone otherwise - as before.
        if role_mapping.get('_authoritative'):
            user['role'] = role_mapping.get('role', ROLE_VIEWER)
            user['permissions'] = list(role_mapping.get('permissions') or [])
            user['tenant_permissions'] = dict(role_mapping.get('tenant_permissions') or {})
            if role_mapping.get('tenant'):
                user['tenant_id'] = role_mapping['tenant']  # NS: Must be tenant_id
            # the full set (#940), so a group the IdP dropped stops granting pool
            # access with this sign-in
            user['groups'] = list(role_mapping.get('groups') or [])
        else:
            logging.warning(
                f"[OIDC] group set for '{username}' is not authoritative (fetch failed, "
                f"partial, or provider sends no groups claim) - keeping the stored role "
                f"and permissions. Nothing was revoked this login.")
            # Still honour anything the mapping DID produce, so a working grant path is
            # not broken by an unrelated fetch problem. NOT the role, though: the mapping
            # always carries one (default_role when nothing matched), so applying it here
            # would demote an admin on a failed fetch - the same outage this branch exists
            # to prevent, one field over. Permissions and tenant only appear when a group
            # actually matched, so those are safe to add.
            if role_mapping.get('tenant'):
                user['tenant_id'] = role_mapping['tenant']
            if role_mapping.get('permissions'):
                user['permissions'] = list(set((user.get('permissions') or [])
                                               + role_mapping['permissions']))
            if role_mapping.get('tenant_permissions'):
                if 'tenant_permissions' not in user:
                    user['tenant_permissions'] = {}
                user['tenant_permissions'].update(role_mapping['tenant_permissions'])
            # groups the same way as the permissions: add what this login saw, drop nothing.
            # The stored ones by username - the users table a caller hands in leaves them out.
            _held = get_db().get_user_directory_groups(username)
            _have = {g.lower() for g in _held if isinstance(g, str)}
            user['groups'] = _held + [g for g in (role_mapping.get('groups') or [])
                                      if isinstance(g, str) and g.lower() not in _have]
    else:
        refusal = oidc_new_account_refusal(username, user_info, name=name)
        if refusal:
            logging.warning(f"[OIDC] Rejected login for '{username}' - the sign-in's name reaches this "
                            f"key only through {refusal}; a new account takes a name only as the "
                            f"identity provider spells it")
            return None
        # Create new user
        user = {
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
            'created_at': datetime.now().isoformat(),
            'groups': list(role_mapping.get('groups') or []),
        }
    return username, user


def oidc_provision_user(user_info: dict, role_mapping: dict, auth_source: str = 'oidc',
                        name: str = None, subjects=None) -> dict:
    from pegaprox.utils.auth import load_users, save_users
    """Create or update local user from OIDC authentication
    
    NS: JIT provisioning - same pattern as LDAP but for OIDC providers
    MK: username derived from email or preferred_username
    """
    users = load_users()
    built = oidc_build_user_row(user_info, role_mapping, auth_source, users, name=name,
                                subjects=subjects)
    if built is None:
        return None  # Caller should handle None return
    username, user = built
    if username in users:
        logging.info(f"[OIDC] Updated user '{username}' (role={user['role']}, source={auth_source})")
    else:
        logging.info(f"[OIDC] Provisioned new user '{username}' (role={role_mapping.get('role', ROLE_VIEWER)}, source={auth_source})")
    users[username] = user
    
    save_users(users)
    return {**users[username], 'username': username}
