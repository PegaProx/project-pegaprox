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
from pegaprox.utils.rbac import acts_as_admin

def effective_reverse_proxy(settings=None):
    """#614 — the frontend builds console (VNC/SSH) WebSocket URLs from
    reverse_proxy_enabled. PEGAPROX_BEHIND_PROXY forces behind-proxy mode at boot
    (app.py) but is never persisted, so report the OR of the persisted setting and
    the env override — otherwise `PEGAPROX_BEHIND_PROXY=true` alone leaves consoles
    dialing port+1/+2, which the reverse proxy can't route."""
    if settings is None:
        settings = load_server_settings()
    return bool(settings.get('reverse_proxy_enabled', False)) or \
        os.environ.get('PEGAPROX_BEHIND_PROXY', '').lower() in ('1', 'true', 'yes')


def load_server_settings():
    """Load server settings from SQLite database
    
    SQLite migration
    """
    defaults = {
        'domain': '',
        'port': 5000,  # Web server port
        'ssl_enabled': False,
        # MK Jul 2026 — #612 Phase 2: auto-reconcile cross-cluster EVPN drift. OFF by
        # default → the drift scanner is detect-only (never writes to a production SDN
        # uninvited); opt in to let it re-push the desired definition to drifted members.
        'multi_sdn_drift_reconcile': False,
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
        'acme_dns_cloudflare_token': '',
        'acme_dns_cloudflare_zone': '',
        'acme_dns_cloudflare_zone_id': '',
        'acme_dns_cloudflare_account_id': '',
        'acme_allow_private_ca': False,  # #685 — opt-in to reach a private/internal ACME CA (mirrors oidc_allow_private_ip)
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
        # NS 2026-06-05 (audit N1): gate the syslog RECEIVER (UDP+TCP :1514).
        # Default True preserves the always-on behaviour; set False to close the
        # port on installs that don't ingest syslog. (DoS-safe either way now —
        # ingestion is bounded-queue + batched off-hub.)
        'syslog_enabled': True,
        # NS 2026-06-05 (S1): retention for the syslog receiver DB (syslog.db). The
        # receiver only INSERTs, so without a sweep it grows unbounded on the same
        # volume as the main DB. Pruned ~hourly by the drain loop.
        'syslog_retention_days': 30,
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
    """Build DNS-01 provider config, decrypting secrets only for use."""
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
        'token': decrypt_secret_setting(
            settings.get('acme_dns_cloudflare_token', ''),
            label='ACME Cloudflare token'
        ),
        'cloudflare_zone': settings.get('acme_dns_cloudflare_zone', ''),
        'zone_id': settings.get('acme_dns_cloudflare_zone_id', ''),
        'account_id': settings.get('acme_dns_cloudflare_account_id', ''),
    }


def save_server_settings(settings):
    """Save server settings to SQLite database
    
    SQLite migration
    """
    try:
        from pegaprox.core.ha import STAMPS_ZONE_SETTING
        # MK Oct 2026 (#625) - the zone the schedule stamps are in is written with the
        # stamps only. A caller read every setting before a change of the group zone, and
        # writing that value back would make the next look move stamps that are in place
        # MK Oct 2026 - nor the broadcast banners, which api/banners.py writes on its own:
        # the ACME request saves back what it read 30 s earlier, and a banner added in
        # between would be gone again
        from pegaprox.api.banners import BANNERS_KEY
        settings = {k: v for k, v in settings.items() if k not in (STAMPS_ZONE_SETTING, BANNERS_KEY)}
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
        # S2 (regression scan): this dict was never evicted (TASK_USER_CACHE_TTL was
        # dead) → slow unbounded RSS creep over weeks. Bound it: when over the cap,
        # drop the oldest ~10% by timestamp. The DB row remains the source of truth
        # (get_task_user falls back to the DB on a cache miss).
        if len(task_pegaprox_users_cache) > 50000:
            try:
                _old = sorted(task_pegaprox_users_cache.items(),
                              key=lambda kv: kv[1].get('timestamp', 0))[:5000]
                for _k, _ in _old:
                    task_pegaprox_users_cache.pop(_k, None)
            except Exception:
                task_pegaprox_users_cache.clear()
    
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

def acting_user():
    """The identity an authorization decision should be made against.

    require_auth stashes the RAW stored record in g.current_user. That record carries no
    effective_role, so handing it straight to get_user_clusters gives an API token its
    OWNER's scope — and for an admin owner get_user_clusters answers None, "all clusters",
    which makes a caller's own filtering a no-op rather than a refusal. Every route that
    scopes its own output wants this function, not g.current_user.

    #491 — for an API token, floor the acting role to the token's grant (like
    build_authz_user) so an admin-owned scoped token can't reach clusters outside its
    scope. H2 (scale audit): reuse the user require_auth already fetched, else fetch just
    that one — don't re-scan the whole users table per cluster route, which is also why
    this does not simply call build_authz_user. MK Sep 2026, Aikido 700487434.
    """
    from flask import request, g
    user = getattr(g, 'current_user', None)
    if user is None:
        try:
            user = get_db().get_user(request.session['user']) or {}
        except Exception:
            from pegaprox.utils.auth import load_users
            user = load_users().get(request.session['user'], {})
    if request.session.get('api_token') and isinstance(user, dict) and 'effective_role' not in user:
        from pegaprox.utils.auth import apply_token_role
        user = apply_token_role(user, request.session.get('role'))
    return user


def caller_acts_as_admin():
    """rbac.acts_as_admin for the caller of this request. request.session['role'] is the
    account's role as stored: neither a token's floor nor a tenant override lowers it, so it
    is no answer to "may this caller skip the tenant checks". NS Oct 2026 (#1060)"""
    return acts_as_admin(acting_user())


def find_user_key(users, name):
    """The key an account is stored under, for a username taken from a route, or None.

    The exact key first, then the lower-cased name. The admin routes used to lower-case
    first, and an OIDC fallback account kept the case of the subject id (oidc_Wd...), so
    it answered 404 everywhere: no edit, no delete, no 2FA reset (#1141). MK"""
    if not isinstance(name, str) or not name:
        return None
    if name in users:
        return name
    lowered = name.lower()
    return lowered if lowered in users else None


def check_cluster_access(cluster_id):
    """Check if current user can access a cluster based on tenant or VM ACLs.
    Returns (True, None) if allowed, (False, error_response) if not.
    """
    from flask import request, jsonify, g
    from pegaprox.utils.rbac import get_user_clusters
    user = acting_user()
    allowed = get_user_clusters(user)
    if allowed is not None and cluster_id not in allowed:
        # #248: check VM ACLs as fallback — users with VM-level access can reach the cluster
        username = request.session.get('user', '')
        from pegaprox.utils.rbac import load_vm_acls, acl_grants_user
        cluster_acls = load_vm_acls().get(cluster_id, {})
        for vmid, acl in cluster_acls.items():
            if acl_grants_user(acl, username):
                return True, None
        # #555: pool fallback — any pool grant in THIS cluster lets the user reach it
        # (per-VM gating still runs downstream via user_can_access_vm)
        try:
            groups = user.get('groups', []) if isinstance(user, dict) else []
            # sec-review: a {pool: []} row is truthy as a dict but grants nothing — match
            # the rest of the pool model (user_has_any_pool_access) and require a real perm.
            _pp = get_db().get_user_pool_permissions(cluster_id, username, groups)
            if any(p for p in _pp.values()):
                return True, None
        except Exception:
            pass
        return False, (jsonify({'error': 'Access denied to this cluster'}), 403)
    return True, None


def caller_is_scoped(user, cluster_id):
    """True when this caller is confined to specific resources in `cluster_id`.

    Confined means: they reached the cluster through a non-owning tenant (the #248 ACL / #555 pool
    fallback in check_cluster_access), OR they hold a pool grant here, OR they hold any VM-ACL entry
    here. Admins and plain cluster-wide operators (their tenant owns the cluster and they have no
    pool/ACL grant) are NOT confined and keep whole-cluster views.

    sec (private disclosure Sep 2026 — audit): the confinement predicate was open-coded in several
    endpoints as `(not is_owner) or user_has_any_pool_access(...)`, which misses the VM-ACL-scoped
    caller whose tenant DOES own the cluster — the Client Portal case. Those endpoints therefore
    treated a portal user as a cluster-wide operator and handed back the whole cluster. Centralised
    here so the rule can't drift between call sites again."""
    from pegaprox.utils.rbac import (get_user_clusters, user_has_any_pool_access, get_vm_acls,
                                     acls_unavailable, acl_grants_user)
    if not user:
        return True   # unknown identity → treat as confined (fail closed)
    if acts_as_admin(user):
        return False
    tenant_clusters = get_user_clusters(user, include_pools=False)
    if tenant_clusters is not None and cluster_id not in tenant_clusters:
        return True
    try:
        if user_has_any_pool_access(user, cluster_id):
            return True
    except Exception:
        return True
    username = user.get('username', '')
    try:
        _acls = get_vm_acls()
        if acls_unavailable(_acls):
            # the store no longer raises on a failed read, it answers with an empty
            # snapshot - which would walk past this loop and report "not confined".
            # Same answer as the except below: cannot tell, so treat as confined.
            return True
        for _vmid, acl in (_acls.get(cluster_id, {}) or {}).items():
            # the wildcard counts here too: a user whose only reach is a '*' row is
            # still confined to that row's VM, not a cluster-wide operator
            if acl_grants_user(acl, username):
                return True
    except Exception:
        return True
    return False


# MK Oct 2026 - what a confined caller does not get of a node's maintenance: the guests in it
# (moving, pending, failed, placed off their pin, the templates moved or left behind) and the
# HA rules held off over them, which the maintenance plan does not show such a caller either.
# Status, counts and the note stay; the note names no guest.
MAINTENANCE_GUEST_FIELDS = ('failed_vms', 'pending_vms', 'current_vm', 'off_pin_vms',
                            'templates_moved', 'templates_left', 'ha_rules_off', 'ha_rules_kept_on')


def sees_whole_maintenance(user, cluster_id):
    """Whether `user` gets the guests of a maintenance in `cluster_id`: when caller_is_scoped
    says no. An admin a tenant override lowers where they live is asked as that role (see
    rbac.acts_as_admin). Fails closed."""
    try:
        return not caller_is_scoped(user, cluster_id)
    except Exception as e:
        logging.warning(f"[MAINT] scope on {cluster_id} unknown, maintenance guests left out: {e}")
        return False


def maintenance_without_guests(task):
    """A maintenance task as to_dict() gives it, less MAINTENANCE_GUEST_FIELDS. A new dict."""
    if not isinstance(task, dict):
        return task
    return {k: v for k, v in task.items() if k not in MAINTENANCE_GUEST_FIELDS}


def nodes_in_maintenance_view(nodes):
    """Whether a node map of get_node_status() (or of /node-progress) has a maintenance on it."""
    return isinstance(nodes, dict) and any(
        isinstance(n, dict) and n.get('maintenance_task') for n in nodes.values())


def nodes_without_maintenance_guests(nodes):
    """The node map with every maintenance_task less its guests. get_node_status() answers
    from the manager's cache, which the broadcast loop shares: the nodes that change are
    copies, the map is never written to."""
    return {name: (dict(n, maintenance_task=maintenance_without_guests(n['maintenance_task']))
                   if isinstance(n, dict) and isinstance(n.get('maintenance_task'), dict) else n)
            for name, n in nodes.items()}


def node_maintenance_for_caller(cluster_id, nodes):
    """The node map as the caller of this request may see it. The caller is only looked up
    when a node is in maintenance: /metrics is polled from every open tab."""
    if not nodes_in_maintenance_view(nodes):
        return nodes
    from flask import request
    from pegaprox.utils.auth import build_authz_user
    if sees_whole_maintenance(build_authz_user(request.session.get('user', ''), request.session),
                              cluster_id):
        return nodes
    return nodes_without_maintenance_guests(nodes)


def scope_vm_rows(cluster_id, rows, *, vmid_key='vmid', type_key='type'):
    """Filter a list of per-VM row dicts to the VMs the current caller may actually see.

    MK Sep 2026 (#773 follow-up audit) — several read endpoints (costs / power / topology /
    top-vms) enumerate EVERY VM on a cluster via get_vm_resources() and hand back per-VM rows
    (vmid / name / node / usage / cost). check_cluster_access above only gates cluster
    REACHABILITY — its own #555 pool fallback (line 402) admits a pool-scoped user and defers
    "per-VM gating downstream" — so without this filter a pool-/ACL-scoped user received per-VM
    data for VMs outside their grant (the same class as the #773 /resources leak).

    Admins and plain cluster-wide operators keep every row (user_can_access_vm returns True for
    them); a pool-/ACL-scoped caller is confined to their VMs. A row whose vmid can't be parsed
    is dropped (fail closed). Cheap at scale: the pool-perm read behind user_can_access_vm is
    request-memoised (rbac._pool_perms_for), so this is one DB read for the whole list."""
    from flask import request
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    user = build_authz_user(request.session.get('user', ''), request.session)
    out = []
    for r in rows or []:
        try:
            vmid = int(r.get(vmid_key))
        except (TypeError, ValueError):
            continue
        if user_can_access_vm(user, cluster_id, vmid, 'vm.view', r.get(type_key)):
            out.append(r)
    return out


def check_pbs_access(pbs_id):
    """Check if current user can access a PBS server based on its linked clusters.
    Returns (True, None) if allowed, (False, error_response) if not.
    
    A PBS server is accessible if:
    - User is admin (full access), OR
    - PBS has no linked_clusters (backward compatibility - accessible to all), OR
    - User has access to at least one of the PBS's linked clusters
    """
    from flask import request, jsonify
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import get_user_clusters
    from pegaprox.globals import pbs_managers

    # Check if PBS exists
    if pbs_id not in pbs_managers:
        return False, (jsonify({'error': 'PBS server not found'}), 404)

    pbs_mgr = pbs_managers[pbs_id]
    # #491 — floor an admin-owned scoped API token to its effective_role so a viewer/user token
    # can't ride the owner's stored admin role past the linked-cluster tenant gate below (mirrors
    # check_cluster_access). get_user_clusters() already honors effective_role.
    user = build_authz_user(request.session.get('user', ''), request.session)

    # Admins have full access - not one a tenant override lowered where they live
    if acts_as_admin(user):
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


def bounded_limit(value, default=50, maximum=1000):
    """Clamp a caller-supplied row limit.

    NS Sep 2026 (audit) — several routes took ?limit= with Flask's type=int, which stops
    a string but not `?limit=99999999`, and handed it straight to a SQL LIMIT or to the
    upstream PVE/PBS API. type=int is a parser, not a bound.

    1000 is deliberately generous: the frontend's largest ask on these routes is 200.
    The audit CSV export is NOT routed through here — it documents ?limit=10000 in the
    UI and is a deliberate export, so capping it would break a feature rather than close
    a hole.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if n <= 0:
        return default
    return min(n, maximum)


def require_unconfined(cluster_id):
    """sec (audit): guard for a WHOLE-CLUSTER operation — one with no per-object notion, so
    user_can_access_vm has nothing to ask about: rebooting a node, draining it, rewriting the
    cluster's credentials or network, arming fencing, wiping a disk.

    check_cluster_access gates reachability and its #248/#555 fallbacks deliberately admit a
    pool-/ACL-scoped caller, deferring the real decision downstream. For these routes downstream
    is where the decision has to happen, and the only correct answer for a confined caller is no.

    Returns an error response to `return`, or None when the caller may proceed."""
    from flask import request, jsonify
    from pegaprox.utils.auth import build_authz_user
    user = build_authz_user(request.session.get('user', ''), request.session)
    if caller_is_scoped(user, cluster_id):
        return jsonify({'error': 'Access denied: this action affects the whole cluster'}), 403
    return None


def node_shell_address(mgr, node):
    """The address a shell for `node` logs in at, or None: then there is no shell.

    MK Oct 2026 (#1143) - both node shells fell back to the cluster's connection host
    when the node's own address was not found (the main port one always, its lookup
    read an undefined port), so the shell of every node opened on that one host under
    the clicked node's name. Only a member of the cluster resolves, through the
    manager's own lookup; nothing stands in for it, least of all an address the
    browser sends along.
    """
    if not node or not isinstance(node, str):
        return None
    try:
        # an XCP-ng pool answers membership from XAPI itself, its nodes are a poll cache
        if getattr(mgr, 'cluster_type', 'proxmox') != 'xcpng' and node not in (mgr.nodes or {}):
            return None
        return mgr.member_node_ip(node) or None
    except Exception as e:
        logging.warning(f"[SHELL] no address for node {node!r}: {e}")
        return None


# NS Oct 2026 - an XCP-ng pool asks for its own xapi.vm.* permission next to the vm.* one,
# as its power, config and migrate routes already did (#1110)
XAPI_TWINS = {'vm.config': 'xapi.vm.config', 'vm.snapshot': 'xapi.vm.snapshot',
              'vm.clone': 'xapi.vm.clone', 'vm.delete': 'xapi.vm.delete',
              'vm.migrate': 'xapi.vm.migrate'}


def xapi_permission_missing(cluster_id, user, perm):
    """The xapi.vm.* permission `user` lacks for `perm` when `cluster_id` is an XCP-ng
    pool, else None."""
    twin = XAPI_TWINS.get(perm)
    if not twin or getattr(cluster_managers.get(cluster_id), 'cluster_type', 'proxmox') != 'xcpng':
        return None
    from pegaprox.utils.rbac import has_permission
    return None if has_permission(user, twin) else twin


def check_vmware_access(vmware_id):
    """NS Jul 2026 (CodeAnt re-scan IDOR) — tenant gate for a VMware/ESXi server, mirroring
    check_pbs_access. Most vmware.py routes only had a role perm and never scoped to tenant, so
    any vmware.* holder could read/act on ANOTHER tenant's ESXi. A server is accessible if the
    caller is a global admin, the server has no linked_clusters (backward-compat), the caller is
    all-cluster (get_user_clusters None), or the caller reaches one of the server's linked clusters.
    Returns (True, None) or (False, error_response)."""
    from flask import request, jsonify
    from pegaprox.utils.rbac import get_user_clusters
    from pegaprox.globals import vmware_managers

    if vmware_id not in vmware_managers:
        return False, (jsonify({'error': 'VMware server not found'}), 404)
    # #491 — floor an admin-owned scoped API token to its effective_role (mirrors check_cluster_access).
    # NS Oct 2026 (#1101) - resolve by the account's own row through acting_user (g.current_user,
    # the record require_auth already fetched and refused when it was gone), not build_authz_user:
    # that re-read the whole users table, and the {} a failed read answers is a role-less
    # default-tenant identity get_user_clusters hands every cluster. A transient read therefore let
    # any vmware-view holder past this server gate onto another tenant's ESXi (detail, performance,
    # watch, the VM list) - the same empty-read hole closed for the console. No account, no reach.
    user = acting_user()
    if not user:
        return False, (jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401)
    if acts_as_admin(user):
        return True, None
    linked = getattr(vmware_managers[vmware_id], 'linked_clusters', None) or []
    if not linked:
        return True, None   # backward-compat: unlinked server is accessible to all
    # MK Sep 2026 - include_pools=False. get_user_clusters() with pools counts a cluster
    # the caller only REACHES through a pool grant, so holding one pool on a Proxmox
    # cluster that happens to be linked here handed them the ESXi server's whole
    # inventory. A pool grant is a claim on VMs inside that cluster, not a claim on the
    # server it is linked to; tenant ownership is the right question for that boundary.
    uc = get_user_clusters(user, include_pools=False)
    if uc is None:
        return True, None
    if any(c in uc for c in linked):
        return True, None
    return False, (jsonify({'error': 'Access denied to this VMware server'}), 403)


def vmware_server_reach(user):
    """check_vmware_access's answer for every ESXi server at once, for a caller that lists
    servers instead of naming one. Returns reaches(linked_clusters) -> bool.

    NS Oct 2026 - GET /api/vmware and the 'vmware_servers' stream frame asked for vmware.view
    and nothing else, so every holder read every tenant's servers (host, account, notes, last
    error). Same rule as the gate: a global admin, an unlinked server, an unconfined caller, or
    a linked cluster the caller owns - pool grants do not count. The caller's reach is resolved
    once, not once per server."""
    from pegaprox.utils.rbac import get_user_clusters

    if not user:
        return lambda linked: False
    if acts_as_admin(user):
        return lambda linked: True
    uc = get_user_clusters(user, include_pools=False)

    def reaches(linked):
        if not linked or uc is None:
            return True
        return any(c in uc for c in linked)
    return reaches


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


# MK Oct 2026 (#1142) - a 401 or 403 from a system behind PegaProx (Proxmox VE, PBS, an ESXi
# server) is about the credentials PegaProx keeps for it, never about the caller's session.
# Handed on as it came, the browser read the 401 as its own session running out and signed
# the user off at every click on a server whose stored password had stopped working.
UPSTREAM_AUTH = 'UPSTREAM_AUTH'
UPSTREAM_AUTH_STATUSES = (401, 403)


def upstream_status(status, default=500):
    """The status to answer for an upstream one: its 401 and 403 are a 502 (#1142)."""
    if status in UPSTREAM_AUTH_STATUSES:
        return 502
    return status or default


def upstream_failure(status, error='', system='Proxmox VE', default=500, **extra):
    """(response, status) for an upstream system that answered `status`.

    401 and 403 go out as 502 with code UPSTREAM_AUTH and say whose credentials were
    refused; everything else keeps its status, as before. extra: more fields of the body.
    """
    from flask import jsonify
    if status in UPSTREAM_AUTH_STATUSES:
        said = ('refused the stored credentials' if status == 401
                else 'does not allow this with the stored credentials')
        msg = f'{system} {said} (HTTP {status})'
        return jsonify({**extra, 'error': f'{msg}: {error}' if error else msg,
                        'code': UPSTREAM_AUTH, 'upstream_status': status}), 502
    return jsonify({**extra, 'error': error}), status or default


# MK Oct 2026 (#763, #954) - the two evacuation options of a rolling update. The run started
# by hand (settings.py) and the scheduled one (schedules.py) are two copies of the loop; what
# the options do in either of them is written down once, here. Each reads its flags from the
# state of the run, mgr._rolling_update, and changes it through rolling_runs.change.

def evacuation_options(mgr, data):
    """(migrate_templates, relax_anti_affinity) from a request body or a stored schedule: off
    unless set to a real true, and off on XCP-ng, which has neither the templates nor the HA
    rules meant here. Also for a node's maintenance."""
    data = data or {}
    is_pve = getattr(mgr, 'cluster_type', 'proxmox') == 'proxmox'
    return (is_pve and data.get('migrate_templates') is True,
            is_pve and data.get('relax_anti_affinity') is True)


def evacuation_options_said(migrate_templates, relax_anti_affinity):
    """': what the options change' for an audit line, '' with both off."""
    said = [o for o, on in (('templates move with the evacuation', migrate_templates),
                            ('negative affinity rules give way until it ends', relax_anti_affinity)) if on]
    return f": {'; '.join(said)}" if said else ''


def rolling_log(mgr, msg):
    """One line with its time in the log of the rolling update that runs."""
    from pegaprox.core import rolling_runs
    try:
        rolling_runs.change(mgr, log=msg)
    except Exception:
        pass


def rolling_options_intro(mgr):
    """What the options mean for this run, said once when it starts."""
    from pegaprox.core import rolling_runs
    state = rolling_runs.current(mgr) or {}
    if state.get('skip_evacuation'):
        return
    if state.get('migrate_templates'):
        rolling_log(mgr, "Templates: moved offline with each node's evacuation, only to a node that has every "
                         "storage they use. One that cannot move stays where it is and does not pause the run")
    if state.get('relax_anti_affinity'):
        rolling_log(mgr, "Negative affinity: guests that must run apart may share a node until the run ends. "
                         "Proxmox HA rules are switched off before the first evacuation and back on at the end; "
                         "PegaProx's own rules are enforced again by the balancer after the run")


def rolling_node_templates(mgr, vms_here):
    """#763 - said either way: without the option a template goes down with its node."""
    from pegaprox.core import rolling_runs
    tpls = [v for v in vms_here if v.get('template')]
    if tpls:
        names = ', '.join(f"{v.get('name') or v.get('vmid')} ({v.get('vmid')})" for v in tpls[:8])
        more = f" and {len(tpls) - 8} more" if len(tpls) > 8 else ''
        moving = (rolling_runs.current(mgr) or {}).get('migrate_templates')
        rolling_log(mgr, f"  → template(s) {'to move' if moving else 'staying here'}: {names}{more}")


def rolling_moved_templates(mgr, task):
    """#763 - what the evacuation of a node did with its templates."""
    for t in getattr(task, 'templates_moved', None) or []:
        rolling_log(mgr, f"  ✓ Template {t.get('name')} ({t.get('vmid')}) moved to {t.get('to')}")
    for t in getattr(task, 'templates_left', None) or []:
        rolling_log(mgr, f"  ⚠ Template {t.get('name')} ({t.get('vmid')}) stays on the node: {t.get('reason')}")
    # MK Oct 2026 (#811) - and the pinned guests none of their plb_pin_ nodes could take
    for o in getattr(task, 'off_pin_vms', None) or []:
        rolling_log(mgr, f"  ⚠ {o.get('name')} ({o.get('vmid')}) went to {o.get('target')}, off its pin "
                         f"({', '.join(o.get('pinned_nodes') or [])})")


def rolling_rules_give_way(mgr, who):
    """#954 - the negative affinity rules off, once, before the first evacuation of a run that
    lets them give way. From here the daemon loop keeps its hands off them."""
    from pegaprox.core import rolling_runs
    state = rolling_runs.current(mgr) or {}
    if not state.get('relax_anti_affinity') or state.get('ha_rules_held') is not None:
        return
    # in the run's row before the first rule is touched: whoever acts next keeps them off
    # for the run, or switches them on when it has ended
    rolling_runs.change(mgr, ha_rules_held=True)
    try:
        off, failed = mgr.suspend_negative_ha_rules(who=who)
    except Exception as e:
        off, failed = [], []
        rolling_log(mgr, f"⚠ Negative affinity rules could not be switched off ({e}) - evacuating with them on")
    if off:
        rolling_log(mgr, f"Negative affinity: {len(off)} Proxmox HA rule(s) switched off until the run ends: "
                         f"{', '.join(off)}")
    elif not failed:
        rolling_log(mgr, "Negative affinity: no enabled negative Proxmox HA rule to switch off")
    if failed:
        rolling_log(mgr, f"⚠ Proxmox kept these rules on, their guests may still not move: {', '.join(failed)}")
    rolling_runs.change(mgr, ha_rules_off=list(off), ha_rules_held=bool(off))


def rolling_rules_back_on(mgr, who):
    """#954 - on again when the run ends, however it ends. A rule a node's maintenance still
    holds stays off until that node leaves it. Returns the rules still off for the run."""
    from pegaprox.core import rolling_runs
    state = rolling_runs.current(mgr) or {}
    if not state.get('ha_rules_held'):
        return []
    try:
        on, left = mgr.restore_suspended_ha_rules(who=who)
        if on:
            rolling_log(mgr, f"✓ Negative affinity rules switched back on: {', '.join(on)} - Proxmox HA moves their "
                             f"guests apart again where a node is free")
        if left:
            rolling_log(mgr, f"✗ Still off: {', '.join(left)} - PegaProx keeps retrying; or run "
                             f"`ha-manager rules set resource-affinity <rule> --disable 0`")
    except Exception as e:
        left = None
        rolling_log(mgr, f"✗ Switching the negative affinity rules back on failed: {e} - PegaProx keeps retrying")
    finally:
        rolling_runs.change(mgr, ha_rules_held=False)
    if left is None:
        return list(state.get('ha_rules_off') or [])
    try:
        held = mgr.held_ha_rules()
    except Exception:
        held = None
    if not isinstance(held, dict):
        return list(left)
    for rule in sorted(r for r in (state.get('ha_rules_off') or []) if r not in left and r in held):
        nodes = sorted(str(o).split(':', 1)[1] for o in held[rule] if str(o).startswith('maintenance:'))
        if nodes:
            rolling_log(mgr, f"Negative affinity: {rule} stays off while {', '.join(nodes)} "
                             f"{'is' if len(nodes) == 1 else 'are'} in maintenance")
    return list(left)


def rolling_in_maintenance(mgr, node, node_status=None):
    """Whether a node is in maintenance as far as the manager knows: its own list, or the node
    status (an XCP-ng host stays disabled through a restart of PegaProx, its list does not)."""
    if node in (getattr(mgr, 'nodes_in_maintenance', None) or {}):
        return True
    if node_status is None:
        try:
            node_status = mgr.get_node_status() or {}
        except Exception:
            node_status = {}
    row = node_status.get(node) if isinstance(node_status, dict) else None
    return isinstance(row, dict) and row.get('maintenance_mode') is True


def rolling_moved_guests(mgr, node_name, before, task=None):
    """MK Oct 2026 - the guests the evacuation of a node took away, for the run's row: the ones
    that ran there before it, less those that failed to move. Where they went is the guest
    list as cached right now, one read for the node, never one per guest."""
    from pegaprox.core import rolling_runs
    failed = {str(v.get('vmid')) for v in (getattr(task, 'failed_vms', None) or [])}
    try:
        where = {str(r.get('vmid')): r.get('node') for r in (mgr.get_vm_resources() or [])}
    except Exception:
        where = {}
    moved = []
    for v in before:
        vmid = str(v.get('vmid'))
        if vmid in failed:
            continue
        to = where.get(vmid)
        moved.append({'vmid': v.get('vmid'), 'name': v.get('name') or '',
                      'to': to if to and to != node_name else None})
    rolling_runs.change(mgr, node=(node_name, {'moved': moved[:rolling_runs.MOVED_KEEP],
                                               'moved_count': len(moved)}))
    return moved


def rolling_guests_left_moved(mgr):
    """For the report of a cancel: the guests the evacuation of a node the run did not finish
    moved away. Nothing moves them back (a pinned one goes back with the pin reconciliation)."""
    from pegaprox.core import rolling_runs
    state = rolling_runs.current(mgr) or {}
    return [{'kind': 'guests_stay', 'node': n, 'count': int(s.get('moved_count') or 0)}
            for n, s in sorted((state.get('node_state') or {}).items())
            if s.get('result') not in ('done', 'skipped') and int(s.get('moved_count') or 0) > 0]


def rolling_wind_down(mgr, who, settle=15, sleep=time.sleep):
    """MK Oct 2026 - the end of a run, however it ends: each node this run put into maintenance
    and that is still in it gets one more try, and the negative affinity rules come back on.
    A node someone else put into maintenance is left alone. Returns what stays undone, for
    the log and the answer of a cancel: [{'kind': 'maintenance', 'node'}, {'kind': 'ha_rules',
    'rules'}]."""
    from pegaprox.core import rolling_runs
    state = rolling_runs.current(mgr) or {}
    try:
        node_status = mgr.get_node_status() or {}
    except Exception:
        node_status = {}
    # flagged when the run put it in; a node whose flag never got written (the process ended
    # while it went in) counts by the phase it was in
    between = ('maintenance', 'evacuating', 'updating', 'rebooting', 'finishing')
    ours = [n for n, s in sorted((state.get('node_state') or {}).items())
            if s.get('in_maintenance') or (s.get('in_maintenance') is None and not s.get('result')
                                           and s.get('phase') in between)]
    stuck = [n for n in ours if rolling_in_maintenance(mgr, n, node_status)]
    for n in ours:
        if n not in stuck:
            rolling_runs.change(mgr, node=(n, {'in_maintenance': False}))
    undone = []
    if stuck:
        rolling_log(mgr, f"Cleanup: {len(stuck)} node(s) still in maintenance, retrying"
                         + (f" after {settle}s settle..." if settle else "..."))
        if settle:
            sleep(settle)
        for nn in stuck:
            try:
                ok = bool(mgr.exit_maintenance_mode(nn))
            except Exception as e:
                logging.error(f"[RollingUpdate] exit of the maintenance of {nn} failed: {e}")
                ok = False
            if ok:
                rolling_runs.change(mgr, node=(nn, {'in_maintenance': False}),
                                    log=f"✓ {nn} maintenance cleared on retry")
            else:
                rolling_runs.change(mgr, add={'failed_nodes': {'node': nn, 'error': 'Stuck in maintenance after rolling update'}},
                                    log=f"✗ {nn} STILL stuck - run `ha-manager crm-command node-maintenance "
                                        f"disable {nn}` manually")
                undone.append({'kind': 'maintenance', 'node': nn})
    left = rolling_rules_back_on(mgr, who)
    if left:
        undone.append({'kind': 'ha_rules', 'rules': sorted(left)})
    return undone


# NS 2026-06-04 — shared metrics_history loader for insights/cost/power.
# The expensive part of these three endpoints isn't the SQL fetch, it's
# json.loads()'ing every snapshot blob (8.6k rows over 30d). Tier-1 moved the
# fetch off the gevent hub; this moves the PARSE off too AND caches the parsed
# result. The parse runs inside run_heavy_read's transform (worker thread), so
# even the cold-cache caller doesn't block the hub, and concurrent callers for
# the same window coalesce onto one fetch+parse (single-flight). Returns a list
# of (ts_unix, clusters_dict) for ALL clusters; callers filter for their own id.
def _history_stride(days):
    # Snapshots land ~every 5 min. Parsing thousands of them is the GIL-bound
    # ceiling (json.loads holds the GIL even in a worker thread), so for long
    # windows we decimate to a coarser cadence. All three consumers are
    # ratio/average/percentile based — sample COUNT doesn't change the result,
    # only the resolution — so this is lossless for cost/power numbers and only
    # smooths insights trends. Recent (<=2d) views keep full 5-min detail.
    if days <= 2:
        return 1     # 5-min, full resolution
    if days <= 14:
        return 3     # ~15-min
    return 12        # ~hourly for month+ windows


def load_metrics_window(days):
    from datetime import timedelta
    from pegaprox.core.dbcrypto import run_heavy_read
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    stride = _history_stride(days)

    def _parse(rows):
        out = []
        for row in rows:
            try:
                d = json.loads(row['data'])
                ts_unix = int(datetime.fromisoformat(row['timestamp']).timestamp())
                out.append((ts_unix, d.get('clusters') or {}))
            except Exception:
                continue
        return out

    # `id % stride = 0` picks ~every Nth snapshot. rowid lives in the timestamp
    # index, so SQLite evaluates the modulo without a table lookup and only
    # decrypts the `data` blob for rows it keeps — cuts BOTH decrypt and parse.
    if stride > 1:
        sql = ("SELECT timestamp, data FROM metrics_history "
               "WHERE timestamp >= ? AND id % ? = 0 ORDER BY timestamp ASC")
        sql_params = (cutoff, stride)
    else:
        sql = ("SELECT timestamp, data FROM metrics_history "
               "WHERE timestamp >= ? ORDER BY timestamp ASC")
        sql_params = (cutoff,)

    # cache_key shared across every cluster + across insights/cost/power.
    # NOTE: the returned dicts are the cached parsed structure — callers must
    # treat them as read-only (the aggregation paths only read, never mutate).
    return run_heavy_read(sql, sql_params, cache_key=f"mh_parsed:{days}", transform=_parse)
