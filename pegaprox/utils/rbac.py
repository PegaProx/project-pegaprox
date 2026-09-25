# -*- coding: utf-8 -*-
"""
PegaProx RBAC - Layer 4
Custom roles, tenants, VM ACLs, pool membership cache.
"""

import os
import json
import time
import logging
import threading
import uuid
from datetime import datetime

from pegaprox.constants import CONFIG_DIR, CUSTOM_ROLES_FILE
from pegaprox.globals import (
    cluster_managers, _custom_roles_cache, _custom_roles_cache_time,
    _vm_acls_cache, _vm_acls_cache_time,
    _pool_cache, _pool_cache_lock, _pool_cache_time,
)
from pegaprox.models.permissions import (
    ROLE_ADMIN, ROLE_USER, ROLE_VIEWER, BUILTIN_ROLES,
    PERMISSIONS, ROLE_PERMISSIONS,
)
from pegaprox.core.db import get_db

class _Snapshot(dict):
    """A snapshot of a store that knows whether it is real.

    Both loaders in this file answered `{}` for two different things: "this install
    has none configured" and "the store did not load". Read as the former, an empty
    answer WIDENS - an ACL-scoped user falls through to their role on the whole
    cluster - and, worse, the writers here start with a DELETE and hand that empty
    answer straight back to the table. MK Sep 2026
    """
    __slots__ = ('unavailable',)

    def __init__(self, *args, unavailable=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.unavailable = unavailable


def store_unavailable(snapshot) -> bool:
    """True when this is an "I could not read it", not an empty store.

    Tolerates a plain dict from a caller that built one itself.
    """
    return bool(getattr(snapshot, 'unavailable', False))


# the ACL paths were written against this name first; keep it reading naturally there
acls_unavailable = store_unavailable


def load_custom_roles() -> dict:
    """Load custom roles from SQLite database
    
    moved to SQLite
    
    Structure:
    {
        "global": {
            "role_id": {"name": "...", "permissions": [...], "created_by": "..."}
        },
        "tenants": {
            "tenant_id": {
                "role_id": {"name": "...", "permissions": [...]}
            }
        }
    }
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM custom_roles')
        
        global_roles = {}
        tenant_roles = {}
        
        for row in cursor.fetchall():
            # #167: name column = role ID (dict key), description = display name
            role_data = {
                'name': row['description'] or row['name'],
                'permissions': json.loads(row['permissions'] or '[]'),
                'description': ''
            }
            
            # Check if role has tenant_id (might not exist in old schema)
            tenant_id = None
            try:
                tenant_id = row['tenant_id']
            except (IndexError, KeyError):
                pass
            
            # Empty string or None means global role
            if tenant_id and tenant_id != '':
                # Tenant-specific role
                if tenant_id not in tenant_roles:
                    tenant_roles[tenant_id] = {}
                tenant_roles[tenant_id][row['name']] = role_data
            else:
                # Global role
                global_roles[row['name']] = role_data
        
        return _Snapshot({'global': global_roles, 'tenants': tenant_roles})
    except Exception as e:
        logging.error(f"Error loading custom roles from database: {e}")
        # NS May 2026 - plain-JSON CUSTOM_ROLES_FILE fallback removed (encrypted DB only).

    # NOT "this install has no custom roles" - we could not read them.
    return _Snapshot({'global': {}, 'tenants': {}}, unavailable=True)


def save_custom_roles(roles: dict):
    """Save custom roles to SQLite database. True when the table was rewritten.
    
    uses SQLite now
    """
    if store_unavailable(roles):
        # this starts with a DELETE; writing back a snapshot that never loaded would
        # drop every custom role in the installation, in every tenant, and leave the
        # accounts bound to them with nothing to resolve against.
        logging.error("[RBAC] refusing to rewrite custom_roles from a snapshot that "
                      "failed to load")
        return False

    # SRK (SPEC-2026-010 P1, 110lymph): role-deletion guard, BEFORE the try/except so a
    # blocked delete surfaces as an error instead of being swallowed into the
    # log. This function REWRITES custom_roles wholesale (DELETE+reinsert), so a
    # DB-level FK from user_roles is impossible; the "role with live grants must
    # fail loudly" invariant (SPEC-2026-010 D1 / Orion Q3) is enforced HERE.
    # Editing a granted role is fine: same (name, tenant) reinserted, grants
    # stay, the resolver picks up new permissions on the next request.
    try:
        _incoming = set()
        for _tid, _roles in (roles.get('tenants', {}) or {}).items():
            for _rid in _roles.keys():
                _incoming.add((_rid, _tid))
        for _rid in (roles.get('global', {}) or {}).keys():
            _incoming.add((_rid, ''))
        for _r in get_db().query('SELECT role_name, tenant_id, username FROM user_roles'):
            _key = (_r['role_name'], _r['tenant_id'])
            if _key not in _incoming:
                raise ValueError(
                    f"Cannot delete role '{_r['role_name']}' "
                    f"(tenant '{_r['tenant_id'] or 'global'}'): still granted to "
                    f"'{_r['username']}'. Revoke the grant first (audited), then retry.")
    except ValueError:
        raise
    except Exception as _e:
        logging.error(f"[user_roles] grant-guard check failed: {_e}")


    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Clear existing roles
        cursor.execute('DELETE FROM custom_roles')
        
        now = datetime.now().isoformat()
        
        # Save global roles (use empty string for tenant_id to work with composite key)
        for role_id, role_data in roles.get('global', {}).items():
            cursor.execute('''
                INSERT INTO custom_roles (name, permissions, description, tenant_id, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                role_id,
                json.dumps(role_data.get('permissions', [])),
                role_data.get('name', role_id),
                '',  # Empty string for global roles
                now
            ))
        
        # Save tenant-specific roles
        for tenant_id, tenant_roles in roles.get('tenants', {}).items():
            for role_id, role_data in tenant_roles.items():
                cursor.execute('''
                    INSERT INTO custom_roles (name, permissions, description, tenant_id, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    role_id,
                    json.dumps(role_data.get('permissions', [])),
                    role_data.get('name', role_id),
                    tenant_id,
                    now
                ))
        
        db.conn.commit()
        return True
    except Exception as e:
        try:
            get_db().conn.rollback()
        except Exception:
            pass
        logging.error(f"Failed to save custom roles: {e}")
        return False

# cache
_custom_roles_cache = None

def get_custom_roles():
    global _custom_roles_cache
    if _custom_roles_cache is None:
        fresh = load_custom_roles()
        if store_unavailable(fresh):
            # this cache has no TTL - it is filled once and kept until something
            # invalidates it. Pinning a failed load here would leave every
            # custom-role account with no permissions until the next restart, and
            # hand the empty snapshot to the next writer.
            return fresh
        _custom_roles_cache = fresh
    return _custom_roles_cache

def invalidate_roles_cache():
    global _custom_roles_cache
    _custom_roles_cache = None

def get_role_permissions_for_user(user: dict, tenant_id: str = None) -> list:
    """Get permissions for a role, considering custom roles
    
    Priority:
    1. Builtin role (admin/user/viewer)
    2. Tenant-specific custom role
    3. Global custom role
    """
    role = user.get('role', ROLE_VIEWER)
    
    # builtin role?
    if role in ROLE_PERMISSIONS:
        return ROLE_PERMISSIONS[role].copy()
    
    # check custom roles
    custom = get_custom_roles()
    
    # tenant specific first
    if tenant_id:
        tenant_roles = custom.get('tenants', {}).get(tenant_id, {})
        if role in tenant_roles:
            return tenant_roles[role].get('permissions', []).copy()
    
    # global custom role
    global_roles = custom.get('global', {})
    if role in global_roles:
        return global_roles[role].get('permissions', []).copy()

    # NS Sep 2026 (audit) — this used to fall back to the ROLE_VIEWER set, which is 31
    # permissions covering vm.view, cluster.view, node.view and the whole PBS read
    # surface. A custom role exists precisely because somebody wanted something NARROWER
    # than that, so an unresolvable role handed its holders MORE than the role ever
    # granted: delete a role that allowed only vm.view and its accounts silently gained
    # thirty permissions. Deleting a role means "revoke this", never "promote them".
    #
    # Both ways of getting here deserve the same answer. A genuinely deleted role is
    # gone, and an unreadable role store is a failure we must not resolve in the
    # caller's favour - store_unavailable() keeps that case out of the cache so it
    # retries, and until it succeeds nobody should be inheriting a default.
    logging.warning(
        f"[RBAC] role {role!r} did not resolve for "
        f"{user.get('username', '?')!r} (tenant={tenant_id!r}) - granting nothing. "
        f"Either the role was deleted while accounts still held it, or the custom-role "
        f"store could not be read."
    )
    return []

# =============================================================================
# MULTI-TENANCY
# Feature requested on Reddit (r/selfhosted) - MSPs wanted to manage multiple 
# customers from one PegaProx instance without them seeing each others VMs.
# Took about a weekend to implement properly.
#
# Tenants are like organizations - users belong to tenants
# Each tenant can only see clusters assigned to them
# =============================================================================

TENANTS_FILE = os.path.join(CONFIG_DIR, 'tenants.json')  # legacy, kept for migration
DEFAULT_TENANT_ID = 'default'  # fallback tenant for existing users

def load_tenants() -> dict:
    """Load tenants from SQLite database
    
    SQLite backend
    """
    try:
        db = get_db()
        tenants_list = db.get_all_tenants()
    except Exception as e:
        logging.error(f"Error loading tenants from database: {e}")
        # NS May 2026 - plain-JSON TENANTS_FILE fallback removed (encrypted DB only).
        # MK Sep 2026 - this used to fall through to "create the default tenant", and the
        # default tenant's empty cluster list is the one that means ALL clusters. So a
        # single unreadable row handed every default-tenant user the whole estate, and
        # then SAVED that invented tenant over whatever an operator had confined it to.
        # Unreadable is not empty. Say which one it was and let the callers decide.
        return _Snapshot(unavailable=True)

    if tenants_list:
        # Convert list to dict format
        return _Snapshot({t['id']: t for t in tenants_list})

    # nothing stored and the read succeeded, so this really is a fresh install
    default = {
        DEFAULT_TENANT_ID: {
            'id': DEFAULT_TENANT_ID,
            'name': 'Default',
            'clusters': [],  # empty = all clusters (for backwards compat)
            'created': datetime.now().isoformat(),
        }
    }
    save_tenants(default)
    return _Snapshot(default)


def save_tenants(tenants: dict):
    """Save tenants to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        # Convert dict to list format
        tenants_list = list(tenants.values())
        db.save_all_tenants(tenants_list)
    except Exception as e:
        logging.error(f"Failed to save tenants: {e}")

# tenant cache - reloaded on changes
tenants_db = {}

# No tenant id can contain a NUL, so this never collides with a real one. It is a
# tenant that does not exist on purpose — see the ambiguity branch below.
_AMBIGUOUS_ROLE_TENANT = '\x00ambiguous'


def _tenant_defining_role(role: str, tenant_id: str) -> str:
    """The tenant whose custom-role table defines `role`, or `tenant_id` unchanged.

    A user — or an API token — can sit in the default tenant while carrying a tenant-scoped
    custom role; get_user_clusters has remapped for that since Dec 2025. get_user_permissions
    never did, so the role resolved to nothing there and fell through to the VIEWER defaults:
    a custom role written to grant three permissions handed out the full viewer set of 31
    instead, which is the opposite of what someone builds a restrictive role for.

    Deliberately narrow, matching the remap it is factored out of: only a caller sitting in
    the DEFAULT tenant is remapped. A user placed in tenant A keeps tenant A's answer even if
    some other tenant happens to define a role by the same name. A name defined by two or
    more tenants has no single answer and is refused outright rather than guessed at."""
    if not role or role in BUILTIN_ROLES or tenant_id != DEFAULT_TENANT_ID:
        return tenant_id
    owners = [tid for tid, roles in get_custom_roles().get('tenants', {}).items()
              if role in roles]
    if len(owners) == 1:
        return owners[0]
    if owners:
        # MK Sep 2026 — more than one tenant defines this name, so "the tenant that
        # defines it" has no answer. The loop this replaces took whichever one dict
        # iteration happened to reach first, which made both the caller's permissions
        # and their cluster list depend on insertion order: the same account could
        # resolve into tenant A today and tenant B after a restart. Two tenants each
        # having an "ops" role is an ordinary thing for an MSP to do, so this is a
        # configuration to report, not a case to guess at.
        #
        # Answering with the DEFAULT tenant would be the wrong direction: an empty
        # cluster list there means "all clusters", so the ambiguous caller would come
        # out wider than either candidate. Hand back an id no tenant can hold instead —
        # the role then fails to resolve (get_role_permissions_for_user grants nothing
        # and says so) and the cluster lookup lands on the non-default empty branch,
        # which is []. The operator's fix is to put the account in the tenant they
        # meant; that takes the early return above and resolves cleanly.
        logging.warning(
            f"[RBAC] custom role {role!r} is defined by {len(owners)} tenants "
            f"({', '.join(sorted(owners))}) — refusing to guess which one a "
            f"default-tenant caller meant. Granting nothing; place the account in "
            f"the intended tenant to resolve it."
        )
        return _AMBIGUOUS_ROLE_TENANT
    return tenant_id


# -- SRK (SPEC-2026-010 P1): multi-role users --------------------------------
# One user may hold many tenant-scoped roles (junction user_roles). The PRIMARY
# role stays users.role; permission/visibility answers are the UNION of
# primary + granted roles. No DB-level FK: save_custom_roles() rewrites
# custom_roles wholesale (DELETE+reinsert), so grant integrity is enforced
# app-side (save_custom_roles guard, delete_user cleanup, grant API in P2).
# Reads go straight to SQL -- NO caching of resolved sets: revocation must
# bite on the NEXT request (M2 acceptance gate).

def get_user_role_grants(username: str) -> list:
    """Junction rows for a user: [{'role_name':..., 'tenant_id':...}, ...]."""
    try:
        rows = get_db().query(
            'SELECT role_name, tenant_id FROM user_roles WHERE username = ?',
            (username,))
        return [{'role_name': r['role_name'], 'tenant_id': r['tenant_id']}
                for r in rows]
    except Exception as e:
        logging.error(f"[user_roles] grant lookup failed for '{username}': {e}")
        return []


def get_role_grants(role_name: str, tenant_id: str = None) -> list:
    """Principals holding a granted role -- revoke tooling + delete guard."""
    try:
        if tenant_id is None:
            rows = get_db().query(
                'SELECT username FROM user_roles WHERE role_name = ?', (role_name,))
        else:
            rows = get_db().query(
                'SELECT username FROM user_roles WHERE role_name = ? AND tenant_id = ?',
                (role_name, tenant_id))
        return [r['username'] for r in rows]
    except Exception as e:
        logging.error(f"[user_roles] holder lookup failed for role '{role_name}': {e}")
        return []


def _effective_tenant_ids(user: dict) -> list:
    """Tenants whose resources the user may see: tenants of primary+granted roles.

    DEFAULT_TENANT_ID semantics are decided by the caller (get_user_clusters
    returns None = all clusters for a default leg) -- same contract as the
    single-role path."""
    tenants = []
    base = user.get('tenant_id', DEFAULT_TENANT_ID)
    if base and base not in tenants:
        tenants.append(base)
    role = user.get('effective_role', user.get('role', ROLE_VIEWER))
    base_defining = _tenant_defining_role(role, base)
    if base_defining and base_defining not in tenants:
        tenants.append(base_defining)
    for g in get_user_role_grants(user.get('username', '')):
        tid = g['tenant_id'] or _tenant_defining_role(g['role_name'], base)
        if tid and tid not in tenants:
            tenants.append(tid)
    return tenants


def get_user_tenant_memberships(username: str) -> list:
    """SRK (SPEC-2026-011 D6): explicit tenant memberships (user_tenants).

    Ordered by granted_at then tenant_id -- deterministic "first remaining"
    ordering for home re-pointing (A5 analogue).
    """
    try:
        cur = get_db().conn.cursor()
        cur.execute('SELECT tenant_id FROM user_tenants WHERE username = ? '
                    'ORDER BY granted_at, tenant_id', (username,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            v = r['tenant_id'] if isinstance(r, dict) else r[0]
            if v and v not in out:
                out.append(v)
        return out
    except Exception as e:
        logging.error(f"[d6] memberships lookup failed for {username}: {e}")
        return []


def get_user_permissions(user: dict, tenant_id: str = None) -> list:
    """Get effective permissions for a user
    
    NS: Updated Dec 2025 - now supports tenant-specific permissions
    
    User can have different permissions per tenant via 'tenant_permissions' field:
    {
        "tenant_permissions": {
            "tenant_a": {"role": "custom_role", "extra": [...], "denied": [...]},
            "tenant_b": {"role": "viewer"}
        }
    }
    """
    # figure out which tenant we're checking for
    if not tenant_id:
        tenant_id = user.get('tenant_id', DEFAULT_TENANT_ID)
    
    # check if user has tenant-specific settings
    tenant_perms = user.get('tenant_permissions', {})
    
    if tenant_id in tenant_perms:
        # use tenant-specific role/permissions
        tp = tenant_perms[tenant_id]
        role = tp.get('role', user.get('role', ROLE_VIEWER))
        extra = tp.get('extra', [])
        # sec (audit): the user's GLOBAL denies were dropped entirely in this branch, so an
        # explicit deny stopped applying the moment the user gained a tenant override — a
        # silent un-deny. They compose; a tenant override may add, never un-forbid.
        denied = list(tp.get('denied', []) or []) + list(user.get('denied_permissions', []) or [])
    else:
        # use global user settings — effective_role wins when set (API-token scoping)
        role = user.get('effective_role', user.get('role', ROLE_VIEWER))
        extra = user.get('permissions', [])
        denied = user.get('denied_permissions', [])
    
    # get base permissions from role (supports custom roles now)
    base_perms = get_role_permissions_for_user({'role': role}, _tenant_defining_role(role, tenant_id))

    # SRK (SPEC-2026-010 P1): union the user's GRANTED roles (user_roles junction).
    # Inserted BEFORE extra/deny so denies still win over any granted perm. API
    # tokens (effective_role set) are excluded here -- they stay single-role by
    # design (spec D5); the token cap below keeps clamping them regardless.
    _uname = user.get('username')
    if _uname and not user.get('effective_role'):
        for _g in get_user_role_grants(_uname):
            if _g['role_name'] in BUILTIN_ROLES:
                continue
            _gp = get_role_permissions_for_user(
                {'role': _g['role_name']},
                _tenant_defining_role(_g['role_name'], _g['tenant_id'] or tenant_id))
            for p in _gp:
                if p not in base_perms:
                    base_perms.append(p)

    # add extra
    for p in extra:
        if p not in base_perms:
            base_perms.append(p)
    
    # remove denied
    base_perms = [p for p in base_perms if p not in denied]

    # sec (audit): an API token must never out-grant its own role — but the tenant-override
    # branch above reads tp['role'] and never looked at effective_role, so an admin-owned
    # viewer-scoped token inherited the full tenant role wherever the owner had an override.
    # Cap the result by what the token's own role grants. Unset for session auth, so this is
    # a no-op there; an admin effective_role caps to everything, i.e. also a no-op.
    _eff = user.get('effective_role')
    if _eff and _eff != role:
        _cap = set(get_role_permissions_for_user({'role': _eff}, _tenant_defining_role(_eff, tenant_id)))
        base_perms = [p for p in base_perms if p in _cap]

    # MK Sep 2026 - and cap by what the OWNER holds right now. The block above caps by the
    # token's own role, which is the right ceiling only while the owner still outranks it.
    # A token bound to a custom role never went through the numeric floor in
    # build_authz_user, so demoting its owner, stripping one of their permissions, or
    # editing the custom role itself left the token resolving through the old, larger set.
    # require_auth re-floors BUILTIN token roles on every request; this is the same
    # promise for custom ones, and it is evaluated per-tenant because that is the only
    # place the answer is actually decidable.
    if user.get('_token_owner_capped'):
        _owner = {k: v for k, v in user.items()
                  if k not in ('effective_role', '_token_owner_capped')}
        _owner_perms = set(get_user_permissions(_owner, tenant_id))
        base_perms = [p for p in base_perms if p in _owner_perms]

    return base_perms

def _admin_is_capped_in_own_tenant(user: dict) -> bool:
    """True when a tenant override governs this caller's own tenant and downgrades them.

    tenant_permissions is written by the LDAP group mappings (utils/ldap.py), so an
    account whose global role is admin really can be mapped down to viewer or a custom
    role inside the tenant it lives in. get_user_permissions has always honoured that —
    it defaults tenant_id to the caller's own tenant and takes the override branch. The
    two admin fast paths below never looked, so the two disagreed: the permission list
    said viewer while the yes/no gate in front of it said admin, and the gate is the one
    routes actually ask. Same for the cluster scope. Only skip the shortcut when the
    override genuinely lowers them — an override that re-states admin is not a downgrade,
    and an account with no override at all (nearly all of them) takes the same path it
    always did. MK Sep 2026, Aikido 700487698.
    """
    tp = (user.get('tenant_permissions') or {}).get(user.get('tenant_id', DEFAULT_TENANT_ID))
    if not isinstance(tp, dict):
        return False
    return tp.get('role', user.get('role')) != ROLE_ADMIN


def has_permission(user: dict, permission: str, tenant_id: str = None) -> bool:
    """check if user has a specific permission
    
    NS: now tenant-aware
    """
    if not user:
        return False
    # admin always has access (safety net) - unless checking tenant-specific, or a
    # tenant override has downgraded them where they live
    if (user.get('effective_role', user.get('role')) == ROLE_ADMIN and not tenant_id
            and not _admin_is_capped_in_own_tenant(user)):
        return True
    return permission in get_user_permissions(user, tenant_id)

def get_user_effective_role(user: dict, tenant_id: str = None) -> str:
    """Get the effective role for a user in a specific tenant"""
    if not tenant_id:
        tenant_id = user.get('tenant_id', DEFAULT_TENANT_ID)
    
    tenant_perms = user.get('tenant_permissions', {})
    if tenant_id in tenant_perms:
        return tenant_perms[tenant_id].get('role', user.get('role', ROLE_VIEWER))
    return user.get('role', ROLE_VIEWER)

def invalidate_tenants_cache():
    """sec (audit): tenants_db is the cache get_user_clusters reads, and it was only ever
    populated (`if not tenants_db`) — never invalidated. So removing a cluster from a tenant
    did not revoke anything until the process restarted; the tenant's users kept working.
    costs.py already reloaded it inline for exactly this reason. Call this after every
    tenant write."""
    global tenants_db
    tenants_db = {}


def get_user_clusters(user: dict, include_pools: bool = True) -> list:
    """Get list of cluster IDs user can access based on tenant
    
    NS: Dec 2025 - Also checks role's tenant for tenant-specific roles
    NS: Jan 2026 - Added group-based access (tenant can be assigned to groups)
    """
    global tenants_db
    if not tenants_db:
        tenants_db = load_tenants()
    
    # admin sees all — honor the token-scoped effective_role (#491) so an admin-owned API token
    # restricted to viewer/user doesn't inherit the owner's all-cluster access, and the LDAP
    # tenant override for the same reason (see _admin_is_capped_in_own_tenant).
    if (user.get('effective_role', user.get('role')) == ROLE_ADMIN
            and not _admin_is_capped_in_own_tenant(user)):
        return None  # None means all clusters

    # MK Sep 2026 - we could not read the tenant table, so we do not know what this caller
    # is confined to. A default-tenant user would otherwise land on the empty-clusters
    # branch below and be handed every cluster. Nobody gets widened on a failed read; a
    # tenant with no clusters already answers [] and this matches it.
    if store_unavailable(tenants_db):
        tenants_db = {}      # never keep a failed read around
        return []

    tenant_id = user.get('tenant_id', DEFAULT_TENANT_ID)

    # MK: If user has default tenant but a tenant-specific role, use the role's tenant.
    # Shared with get_user_permissions — the two answered this differently for years, and the
    # permission side silently fell back to the viewer defaults because of it.
    role = user.get('effective_role', user.get('role', ROLE_VIEWER))
    tenant_id = _tenant_defining_role(role, tenant_id)
    
    tenant = tenants_db.get(tenant_id, {})
    clusters = list(tenant.get('clusters', []))

    # SRK (SPEC-2026-010 P1): a user with GRANTED roles sees every tenant their
    # role set spans (primary + granted). DEFAULT_TENANT_ID leg returns None
    # (= all clusters), preserving existing default-tenant semantics. Sessions
    # only: effective_role (token auth) keeps single-role visibility (spec D5).
    if not user.get('effective_role'):
        for _tid in _effective_tenant_ids(user):
            if _tid == DEFAULT_TENANT_ID:
                return None  # default-tenant leg sees all (unchanged semantics)
            _t = tenants_db.get(_tid, {})
            for _c in _t.get('clusters', []):
                if _c not in clusters:
                    clusters.append(_c)
    
    # NS Jan 2026: Also include clusters from groups assigned to this tenant
    try:
        db = get_db()
        # Get groups assigned to this tenant
        groups = db.query('SELECT id FROM cluster_groups WHERE tenant_id = ?', (tenant_id,))
        if groups:
            group_ids = [g['id'] for g in groups]
            # Get clusters in those groups
            group_clusters = db.query('SELECT id FROM clusters WHERE group_id IN ({})'.format(
                ','.join(['?'] * len(group_ids))
            ), tuple(group_ids))
            if group_clusters:
                clusters = list(set(clusters + [c['id'] for c in group_clusters]))
    except Exception as e:
        logging.error(f"Error getting group clusters for tenant {tenant_id}: {e}")
    
    # empty list means all clusters (backwards compat) - but only for default tenant
    # LW: Changed this - non-default tenants with empty clusters should see nothing, not everything
    # was confusing before when new tenants could suddenly see everything
    if not clusters:
        if tenant_id == DEFAULT_TENANT_ID:
            return None  # default tenant can see all
        else:
            return []  # other tenants with no clusters assigned see nothing

    # #555: a pool-only user (tenant+group gave them this list) must also reach
    # clusters where they hold pool perms. Only widen the non-None list — the None
    # (admin / default-tenant-all) paths above already see everything.
    # MK Jun 2026 (sec-review): callers that decide BLANKET per-cluster authority
    # (the role fall-through in user_can_access_vm) pass include_pools=False, so a
    # pool grant only reaches its pool's VMs — not every VM on the cluster.
    if include_pools:
        try:
            username = user.get('username', '')
            if username:
                pool_cids = get_db().get_user_pool_clusters(username, user.get('groups', []))
                if pool_cids:
                    clusters = list(set(clusters) | set(pool_cids))
        except Exception as e:
            logging.error(f"Error adding pool clusters for {user.get('username','')}: {e}")

    return clusters

def filter_clusters_for_user(clusters: dict, user: dict) -> dict:
    """Filter clusters dict to only show user's allowed clusters"""
    allowed = get_user_clusters(user)
    if allowed is None:
        return clusters  # user can see all
    
    return {k: v for k, v in clusters.items() if k in allowed}


def check_tenant_quota(tenant_id, add_cores=0, add_mem_gb=0, add_vms=1, add_disk_gb=0, force=False):
    """#502 — sum a tenant's current resource usage across its clusters and decide
    whether adding (add_cores, add_mem_gb, add_vms, add_disk_gb) would exceed its quota.
    Returns {'ok', 'enforce', 'violations', 'usage', 'quota'}. FAIL-OPEN: any error
    returns ok=True so a quota bug can never block a legitimate VM create.
    force=True computes usage even when no quota is set (for the usage display).

    NS Sep 2026 — disk joins cores/memory/vms as the fourth dimension. It is the one an MSP
    actually runs out of first, and it was the only one of the four a tenant could grow without
    limit. Same shape as the others: 0 = unlimited, same enforce mode, same fail-open."""
    try:
        global tenants_db
        # NS #502 — always refresh: the cached global goes stale after a quota edit,
        # and get_user_clusters() below reads the same global for cluster resolution.
        tenants_db = load_tenants()
        t = (tenants_db or {}).get(tenant_id) or {}
        qv = int(t.get('quota_max_vms', 0) or 0)
        qc = int(t.get('quota_max_cores', 0) or 0)
        qm = int(t.get('quota_max_memory_gb', 0) or 0)
        qd = int(t.get('quota_max_disk_gb', 0) or 0)
        enforce = t.get('quota_enforcement') or 'block'
        if not force and qv <= 0 and qc <= 0 and qm <= 0 and qd <= 0:
            return {'ok': True, 'enforce': enforce, 'violations': [], 'usage': {}, 'quota': {}}
        allowed = get_user_clusters({'role': ROLE_VIEWER, 'tenant_id': tenant_id})  # None = all clusters
        from pegaprox.globals import cluster_managers
        used_vms = 0
        used_cores = 0
        used_mem = 0.0
        used_disk = 0.0
        # iterate a copy — get_vm_resources() below is a live API call, and a
        # concurrent cluster add/remove used to blow up the walk. That lands in the
        # fail-open except at the bottom, so the quota just stopped being enforced.
        for cid, mgr in list(cluster_managers.items()):
            if allowed is not None and cid not in allowed:
                continue
            try:
                vms = mgr.get_vm_resources() if hasattr(mgr, 'get_vm_resources') else []
            except Exception:
                vms = []
            for vm in (vms or []):
                used_vms += 1
                used_cores += int(vm.get('maxcpu') or vm.get('cpus') or vm.get('cores') or 0)
                try:
                    used_mem += float(vm.get('maxmem') or 0) / (1024.0 ** 3)
                except (ValueError, TypeError):
                    pass
                try:
                    used_disk += float(vm.get('maxdisk') or 0) / (1024.0 ** 3)
                except (ValueError, TypeError):
                    pass
        violations = []
        if qv > 0 and used_vms + add_vms > qv:
            violations.append('vms')
        if qc > 0 and used_cores + add_cores > qc:
            violations.append('cores')
        if qm > 0 and used_mem + add_mem_gb > qm:
            violations.append('memory')
        if qd > 0 and used_disk + add_disk_gb > qd:
            violations.append('disk')
        return {
            'ok': not violations, 'enforce': enforce, 'violations': violations,
            'usage': {'vms': used_vms, 'cores': used_cores, 'memory_gb': round(used_mem, 1),
                      'disk_gb': round(used_disk, 1)},
            'quota': {'vms': qv, 'cores': qc, 'memory_gb': qm, 'disk_gb': qd},
        }
    except Exception as e:
        logging.warning(f"[quota] check failed, allowing create (fail-open): {e}")
        return {'ok': True, 'enforce': 'warn', 'violations': [], 'usage': {}, 'quota': {}}


def tenant_vmid_range(tenant_id):
    """(start, end) of the VMID slice a tenant may create in, or (0, 0) for no restriction.

    NS Sep 2026 — two tenants creating guests on a shared cluster otherwise compete for the same
    ids: PVE hands out the next free VMID globally, so whoever creates first takes it and the
    other's numbering drifts into their neighbour's block. Giving each tenant its own slice keeps
    a customer's guests recognisable by id alone, which is what makes per-tenant backup selectors
    and log greps usable at all."""
    try:
        t = (load_tenants() or {}).get(tenant_id) or {}
        start = int(t.get('vmid_range_start', 0) or 0)
        end = int(t.get('vmid_range_end', 0) or 0)
        if start <= 0 or end <= 0 or end < start:
            return 0, 0
        return start, end
    except Exception as e:
        logging.debug(f"[vmid-range] lookup failed for {tenant_id}: {e}")
        return 0, 0


def check_tenant_vmid(tenant_id, vmid):
    """Return (ok, message). A tenant with a configured range may only create inside it.

    Unlike the quota this does NOT honour quota_enforcement: a range is not a soft ceiling you
    can be over by one, it is the boundary that stops two tenants colliding on the same id. A
    'warn' here would just let the collision happen quietly. No range configured → always ok,
    which is every install that has not set one."""
    start, end = tenant_vmid_range(tenant_id)
    if not start:
        return True, ''
    try:
        v = int(vmid)
    except (TypeError, ValueError):
        return True, ''      # nothing to judge; PVE allocates and the id lands wherever it lands
    if start <= v <= end:
        return True, ''
    return False, f'VMID {v} is outside this tenant\'s range ({start}-{end})'


# =============================================================================
# VM-LEVEL ACCESS CONTROL
# Fine-grained permissions for individual VMs/CTs
# Users can be granted or denied access to specific VMs
#
# AI-assisted: Initial structure suggested by Claude, then customized
# =============================================================================

VM_ACLS_FILE = os.path.join(CONFIG_DIR, 'vm_acls.json')

# What an ACL row with inherit_role=True actually hands out. It is a fixed set, not the
# beneficiary's own role, and it is the DEFAULT for a new row - so the grant-ceiling check
# on the write path has to weigh THIS, not the (unused) explicit permission list. MK Sep 2026
ACL_INHERITED_VM_PERMISSIONS = ('vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console',
                                'vm.snapshot', 'vm.migrate', 'vm.clone', 'vm.config', 'vm.backup')


def acl_grants_user(acl, username: str) -> bool:
    """Does this one VM-ACL row grant `username` access?

    Nine places asked this question and one of them asked it differently:
    caller_is_scoped() tested `username in users` and left out the `'*'` wildcard
    that every other gate honours. So a user whose ONLY reach into a cluster was a
    wildcard ACL was classified as "not confined" and handed the whole-cluster
    views, while user_can_access_vm() correctly treated them as ACL-scoped. One
    definition now, so the two cannot drift apart again. MK Sep 2026

    Note this is the *membership* question. The narrower "is this caller confined
    to specific VMs" question in user_can_access_vm deliberately counts explicit
    names only - a wildcard row confines nobody - and is left alone.
    """
    if not isinstance(acl, dict):
        return False
    members = acl.get('users') or []
    return username in members or '*' in members


def load_vm_acls() -> dict:
    """Load VM access control lists from SQLite database
    
    SQLite migration
    
    Structure:
    {
        "cluster_id": {
            "100": {  # vmid
                "users": ["user1", "user2"],  # users with access
                "permissions": ["vm.view", "vm.console"],  # specific perms
                "inherit_role": true  # use user's role permissions
            }
        }
    }
    """
    try:
        db = get_db()
        return _Snapshot(db.get_all_vm_acls())
    except Exception as e:
        logging.error(f"Failed to load VM ACLs from database: {e}")
        # Legacy fallback
        if os.path.exists(VM_ACLS_FILE):
            try:
                with open(VM_ACLS_FILE, 'r') as f:
                    return _Snapshot(json.load(f))
            except Exception:
                pass
    # NOT an empty ACL table - we do not know what the ACLs are.
    return _Snapshot(unavailable=True)


def save_vm_acls(acls: dict):
    """Save VM ACLs to SQLite database. True when it wrote.
    
    SQLite migration
    """
    if store_unavailable(acls):
        # save_all_vm_acls only upserts, so this cannot clear the table the way the
        # role writer could - but writing back a snapshot that never loaded is still
        # writing a decision we did not make. Refuse, and keep the pair symmetric so
        # a future delete in save_all_vm_acls does not turn this into a wipe.
        logging.error("[RBAC] refusing to write VM ACLs from a snapshot that failed "
                      "to load")
        return False
    try:
        db = get_db()
        db.save_all_vm_acls(acls)
        return True
    except Exception as e:
        logging.error(f"Failed to save VM ACLs: {e}")
        return False

_vm_acls_cache = None

# MK: Pool membership cache - Jan 2026
# Structure: {cluster_id: {'data': {vmid: pool_id, ...}, 'timestamp': time, 'refreshing': bool}}
# TTL: 300 seconds (5 min) - pools don't change often
# Stale TTL: 30 seconds - return stale data while refreshing in background
_pool_membership_cache = {}
# Bumped by every invalidate_pool_cache(). A rebuild captures it before it starts reading and
# refuses to publish if it changed meanwhile — otherwise a revocation that lands during the
# seconds a rebuild spends on the network gets overwritten by the pre-revocation snapshot.
_pool_cache_generation = 0
POOL_CACHE_TTL = 300  # 5 minutes - pools rarely change
POOL_CACHE_STALE_TTL = 30  # Return stale data for 30s while refreshing
_pool_cache_lock = threading.Lock()
# MK Jun 2026 (#555) — when a build can't enumerate members (token lacks Pool.Audit,
# member fetch errored, or a remote cluster is mid-connect) it produced an EMPTY map
# that got pinned fresh for the full TTL — so every pool-only portal user resolved to
# nothing for 5 min with no signal and no retry. Cache such a result for only this
# short window so it self-heals, and shout once so the operator can fix the token.
POOL_CACHE_EMPTY_TTL = 25


def _stamp_pool_cache(cluster_id, pools, membership, had_error):
    """Return the timestamp to cache a freshly-built membership map under. A build
    that saw pools but resolved zero members (or hit a fetch error) is suspect —
    don't pin it as fresh; date it so it expires in POOL_CACHE_EMPTY_TTL and warn."""
    import time as _t
    now = _t.time()
    suspect = bool(pools) and (not membership or had_error)
    if suspect:
        logging.warning(
            f"[POOL-CACHE] cluster {cluster_id}: {len(pools)} pool(s) but {len(membership)} "
            f"member(s) resolved{' (member fetch errored)' if had_error else ''} — the cluster "
            f"API token likely lacks Pool.Audit; pool-based portal/console access won't work "
            f"until the token can enumerate pool members. Retrying soon."
        )
        # date it so age already exceeds (TTL - EMPTY_TTL) -> expires in ~EMPTY_TTL
        return now - (POOL_CACHE_TTL - POOL_CACHE_EMPTY_TTL)
    return now


def _refresh_pool_cache_async(cluster_id: str):
    """Background refresh of pool cache - doesn't block requests"""
    global _pool_membership_cache

    with _pool_cache_lock:
        _gen = _pool_cache_generation

    try:
        if cluster_id not in cluster_managers:
            return
        
        mgr = cluster_managers[cluster_id]
        pools = mgr.get_pools()
        
        membership = {}
        had_error = False
        for pool in pools:
            pool_id = pool.get('poolid')
            if not pool_id:
                continue

            try:
                pool_data = mgr.get_pool_members(pool_id)
                members = pool_data.get('members', [])

                for member in members:
                    vmid = member.get('vmid')
                    mtype = member.get('type')
                    if vmid and mtype in ('qemu', 'lxc'):
                        membership[f"{vmid}:{mtype}"] = pool_id
            except Exception as e:
                had_error = True
                logging.warning(f"[POOL-CACHE] Error getting members for pool {pool_id}: {e}")
                continue

        with _pool_cache_lock:
            if _pool_cache_generation != _gen:
                # someone revoked a grant while we were reading — our snapshot predates it
                _pool_membership_cache.pop(cluster_id, None)
                logging.info(f"[POOL-CACHE] Discarded refresh for {cluster_id} — invalidated mid-read")
                return
            _pool_membership_cache[cluster_id] = {
                'data': membership,
                'timestamp': _stamp_pool_cache(cluster_id, pools, membership, had_error),
                'refreshing': False
            }

        logging.info(f"[POOL-CACHE] Refreshed cache for cluster {cluster_id}: {len(membership)} VMs in pools")
        
    except Exception as e:
        logging.error(f"[POOL-CACHE] Error refreshing cache for {cluster_id}: {e}")
        with _pool_cache_lock:
            if cluster_id in _pool_membership_cache:
                _pool_membership_cache[cluster_id]['refreshing'] = False

def get_pool_membership_cache(cluster_id: str) -> dict:
    """Get cached pool memberships for a cluster
    
    Returns {vmid:type: pool_id, ...} mapping
    Uses stale-while-revalidate pattern for better performance
    """
    global _pool_membership_cache
    
    now = time.time()
    
    with _pool_cache_lock:
        cache_entry = _pool_membership_cache.get(cluster_id)
        
        # No cache at all - need synchronous refresh
        if not cache_entry:
            _pool_membership_cache[cluster_id] = {'data': {}, 'timestamp': 0, 'refreshing': True}
    
    if cache_entry:
        age = now - cache_entry.get('timestamp', 0)
        
        # Cache is fresh - return immediately
        if age < POOL_CACHE_TTL:
            return cache_entry.get('data', {})
        
        # Cache is stale but usable - return it and refresh in background
        if age < POOL_CACHE_TTL + POOL_CACHE_STALE_TTL:
            if not cache_entry.get('refreshing'):
                with _pool_cache_lock:
                    _pool_membership_cache[cluster_id]['refreshing'] = True
                threading.Thread(target=_refresh_pool_cache_async, args=(cluster_id,), daemon=True).start()
            return cache_entry.get('data', {})
    
    # Cache too old or missing - do synchronous refresh (only on first load)
    if cluster_id not in cluster_managers:
        return cache_entry.get('data', {}) if cache_entry else {}
    
    with _pool_cache_lock:
        _gen = _pool_cache_generation

    try:
        mgr = cluster_managers[cluster_id]
        pools = mgr.get_pools()
        
        membership = {}
        had_error = False
        for pool in pools:
            pool_id = pool.get('poolid')
            if not pool_id:
                continue

            try:
                pool_data = mgr.get_pool_members(pool_id)
                members = pool_data.get('members', [])

                for member in members:
                    vmid = member.get('vmid')
                    mtype = member.get('type')
                    if vmid and mtype in ('qemu', 'lxc'):
                        membership[f"{vmid}:{mtype}"] = pool_id
            except Exception:
                had_error = True
                continue

        with _pool_cache_lock:
            if _pool_cache_generation != _gen:
                _pool_membership_cache.pop(cluster_id, None)
                logging.info(f"[POOL-CACHE] Discarded initial build for {cluster_id} — invalidated mid-read")
                return membership          # answer THIS caller, but publish nothing
            _pool_membership_cache[cluster_id] = {
                'data': membership,
                'timestamp': _stamp_pool_cache(cluster_id, pools, membership, had_error),
                'refreshing': False
            }

        logging.info(f"[POOL-CACHE] Initial cache for cluster {cluster_id}: {len(membership)} VMs in pools")
        return membership
        
    except Exception as e:
        logging.error(f"[POOL-CACHE] Error getting pool cache for {cluster_id}: {e}")
        return cache_entry.get('data', {}) if cache_entry else {}

def invalidate_pool_cache(cluster_id: str = None):
    """Invalidate pool membership cache"""
    global _pool_membership_cache, _pool_cache_generation
    with _pool_cache_lock:
        # sec (audit): a rebuild reads every pool over the network, which takes seconds. An
        # admin who removed a VM from a pool in that window called this, we popped the entry —
        # and then the in-flight rebuild wrote its PRE-revocation snapshot back with a fresh
        # timestamp, re-pinning the revoked grant for another full TTL and silently undoing
        # the invalidation. Bump a generation so a refresh that started earlier is discarded.
        _pool_cache_generation += 1
        if cluster_id:
            _pool_membership_cache.pop(cluster_id, None)
        else:
            _pool_membership_cache = {}

def get_vm_pool_cached(cluster_id: str, vmid: int, vm_type: str = None) -> str:
    """Get pool for a VM using cache
    
    Much faster than direct API calls - uses cached membership data
    """
    membership = get_pool_membership_cache(cluster_id)
    
    if vm_type:
        # Exact match
        return membership.get(f"{vmid}:{vm_type}")
    else:
        # Try both types
        return membership.get(f"{vmid}:qemu") or membership.get(f"{vmid}:lxc")

def _pool_perms_for(cluster_id: str, username: str, groups=None) -> dict:
    """get_user_pool_permissions, memoised for the current request.

    MK Sep 2026 (#773 scale follow-up): the per-VM authz loop over a /resources read on a
    large cluster called get_user_pool_permissions once PER VM with identical args — up to
    ~10k indexed SELECTs to answer one list. The grant set is the same for a given
    (cluster, user, groups) throughout a request, so memoise it on Flask's request global.
    Outside a request context (background workers, tests) it reads straight through; the memo
    only ever lives for one request, so there's no stale-grant window across requests, and
    writers (api/users pool grant/revoke) don't need to invalidate anything. Callers only read
    the returned dict, never mutate it, so sharing the memoised object is safe."""
    db = get_db()
    key = (cluster_id, username, tuple(sorted(groups or [])))
    try:
        from flask import g, has_request_context
        if has_request_context():
            memo = getattr(g, '_pool_perms_memo', None)
            if memo is None:
                memo = {}
                g._pool_perms_memo = memo
            if key not in memo:
                memo[key] = db.get_user_pool_permissions(cluster_id, username, groups)
            return memo[key]
    except Exception:
        pass
    return db.get_user_pool_permissions(cluster_id, username, groups)


def user_has_any_pool_access(user: dict, cluster_id: str) -> bool:
    """#555 — does this user hold ANY pool permission in this cluster?
    One cheap DB read, no membership scan. For the cluster gates."""
    if user.get('role') == ROLE_ADMIN:
        return True
    username = user.get('username', '')
    if not username:
        return False
    try:
        perms = _pool_perms_for(cluster_id, username, user.get('groups', []))
    except Exception as e:
        # NS Sep 2026 (audit) — this used to answer False, and False here does not mean
        # "no pool grant", it means "not confined by a pool". helpers.caller_is_scoped
        # asks this question to decide whether the caller is a plain cluster-wide
        # operator, and it wraps the call in its own try/except precisely so a failure
        # falls closed — but swallowing the error in here meant that except never fired
        # and an unreadable pool-permission table silently promoted every pool-scoped
        # caller to unconfined. Let it out; the caller is the one that knows what a
        # failure should mean.
        logging.error(f"[POOL] any-access check failed for {username}@{cluster_id}: {e}")
        raise
    return any(p for p in perms.values())


def get_user_pool_vmids(user: dict, cluster_id: str, permission: str = None, _perms: dict = None) -> set:
    """#555 — set of int vmids the user can reach via pool perms in this cluster.
    Reuses the pool-membership cache + a single DB read. Empty set if none.
    Only consulted for non-admins (list callers handle admin-all separately).

    permission=None (default) = VISIBILITY: any non-empty pool grant counts. This
    matches the pool model where 'pool.view' (not 'vm.view') is the see-the-members
    permission — so the portal list shows a pool's VMs to anyone with a grant on it.
    Pass a specific action perm (e.g. 'vm.start') to filter to pools where the user
    holds that perm (or pool.admin)."""
    username = user.get('username', '')
    if not username:
        return set()
    if _perms is not None:
        user_pool_perms = _perms
    else:
        try:
            user_pool_perms = _pool_perms_for(cluster_id, username, user.get('groups', []))
        except Exception as e:
            logging.error(f"[POOL] vmid-list failed for {username}@{cluster_id}: {e}")
            return set()
    if not user_pool_perms:
        return set()
    if permission is None:
        # visibility: any pool the user holds at least one (non-empty) permission on
        ok_pools = {pid for pid, perms in user_pool_perms.items() if perms}
    else:
        # action-specific: pool.admin grants everything, else the perm must be present
        ok_pools = {pid for pid, perms in user_pool_perms.items()
                    if 'pool.admin' in perms or permission in perms}
    if not ok_pools:
        return set()
    try:
        membership = get_pool_membership_cache(cluster_id)  # {'vmid:type': pool_id}
    except Exception as e:
        logging.error(f"[POOL] membership lookup failed for {username}@{cluster_id}: {e}")
        return set()
    out = set()
    for key, pid in membership.items():
        if pid in ok_pools:
            try:
                out.add(int(key.split(':', 1)[0]))
            except (ValueError, IndexError):
                continue
    return out

# NS Jul 2026 (scale) — short TTL for the VM-ACL cache. user_can_access_vm() calls
# get_vm_acls() once per VM on the console/action/pbs/user-listing paths, so a non-admin
# op over 1000 VMs did ~1000 full SQLCipher-decrypted reloads of the whole vm_acls table
# (~1.6ms each ≈ 1.6s of pure waste per request). ACLs are security-critical, so this stays
# CORRECT via complete write-invalidation — every writer (api/users set+delete, settings
# import) calls invalidate_vm_acls_cache(). The TTL is only a secondary safety net that
# bounds any hypothetically-missed invalidation to a few seconds; it is short on purpose.
_VM_ACLS_TTL = 30.0

def get_vm_acls():
    """Get VM ACLs with a short TTL cache (security-critical; writes invalidate).

    MK: was "always reload" for safety. NS Jul 2026: re-enabled the pre-existing
    _vm_acls_cache behind a 30s TTL now that every write path invalidates it — this
    kills the per-VM reload storm at 1000+-VM scale without a stale-authz window
    (a write nulls the cache immediately; the TTL only caps a missed invalidation).
    """
    global _vm_acls_cache, _vm_acls_cache_time
    now = time.monotonic()
    if _vm_acls_cache is not None and (now - _vm_acls_cache_time) < _VM_ACLS_TTL:
        return _vm_acls_cache
    fresh = load_vm_acls()
    if acls_unavailable(fresh):
        # never cache a failed load: a momentary DB hiccup would otherwise deny
        # every scoped user for the whole TTL, and a stale success is no better.
        return fresh
    _vm_acls_cache = fresh
    _vm_acls_cache_time = now
    return _vm_acls_cache

def invalidate_vm_acls_cache():
    global _vm_acls_cache, _vm_acls_cache_time
    _vm_acls_cache = None
    _vm_acls_cache_time = 0

def _user_can_access_vm_uncapped(user: dict, cluster_id: str, vmid: int, permission: str = 'vm.view', vm_type: str = None) -> bool:
    """Check if user can access a specific VM
    
    NS: Dec 2025 - VM ACLs are ADDITIVE, not restrictive
    MK: Jan 2026 - Added Pool Permission support
    
    Logic:
    1. Admin always has access
    2. If user has VM-specific ACL entry:
       - inherit_role=True: User can do ALL VM operations (full access)
       - inherit_role=False: User can ONLY do operations listed in permissions
    3. Check Pool Permissions (if VM is in a pool)
    4. If user not in ACL: fall back to user's general role permissions
    
    LW: Changed inherit_role=True to mean "full VM access" instead of "use role perms"
    This is more intuitive - adding someone to a VM ACL should grant them access to that VM
    """
    # MK: effective_role (token-scoped) wins over the stored role so an admin-owned
    # restricted token doesn't get the admin VM bypass below
    if user.get('effective_role', user.get('role')) == ROLE_ADMIN:
        return True

    username = user.get('username', '')
    acls = get_vm_acls()
    if acls_unavailable(acls):
        # An unread ACL store is not an empty one. Reading it as empty lets this
        # function fall through to the role-wide grant below and hands a confined
        # user the whole cluster.
        logging.error(f"[VM-ACL] ACL store unavailable - denying {permission} for "
                      f"'{username}' on {cluster_id}/{vmid}")
        return False

    # LW: Debug logging to help troubleshoot ACL issues
    logging.debug(f"[VM-ACL] Checking access for user={username}, cluster={cluster_id}, vmid={vmid}, perm={permission}")
    logging.debug(f"[VM-ACL] Available ACLs for cluster: {list(acls.get(cluster_id, {}).keys())}")
    
    # check VM-specific acl
    cluster_acls = acls.get(cluster_id, {})
    vm_acl = cluster_acls.get(str(vmid), {})
    
    if vm_acl:
        allowed_users = vm_acl.get('users', [])
        logging.debug(f"[VM-ACL] VM {vmid} ACL found, allowed users: {allowed_users}")
        
        # MK: If user is in the ACL whitelist, check their ACL permissions
        if acl_grants_user(vm_acl, username):
            if vm_acl.get('inherit_role', True):
                # inherit_role=True: FULL VM access (start, stop, console, etc.)
                # This means "this user has access to this VM"
                result = permission in ACL_INHERITED_VM_PERMISSIONS
                logging.debug(f"[VM-ACL] User {username} in ACL with inherit_role=True, checking {permission}: {result}")
                return result
            else:
                # inherit_role=False: use ONLY the VM-specific permissions
                vm_perms = vm_acl.get('permissions', [])
                result = permission in vm_perms
                logging.debug(f"[VM-ACL] User {username} in ACL with custom perms {vm_perms}, checking {permission}: {result}")
                return result
        else:
            logging.debug(f"[VM-ACL] User {username} NOT in ACL whitelist {allowed_users}")
        
        # User not in ACL whitelist - fall through to check pool permissions
    else:
        logging.debug(f"[VM-ACL] No ACL found for VM {vmid} in cluster {cluster_id}")
    
    # MK: Check Pool Permissions - Jan 2026
    # If VM is in a pool, check if user has permission via pool
    # Uses cached pool membership data to avoid API calls on every permission check
    try:
        pool_id = get_vm_pool_cached(cluster_id, vmid, vm_type)
        
        if pool_id:
            logging.debug(f"[POOL-PERM] VM {vmid} is in pool '{pool_id}' (cached)")
            
            # Get user's groups
            user_groups = user.get('groups', [])
            
            # Get user's pool permissions (request-memoised — same grants for every VM in the loop)
            user_pool_perms = _pool_perms_for(cluster_id, username, user_groups)
            
            # Check if user has required permission for this pool
            pool_perms = user_pool_perms.get(pool_id, [])
            
            if pool_perms:
                # pool.admin grants all permissions
                if 'pool.admin' in pool_perms:
                    logging.debug(f"[POOL-PERM] User {username} has pool.admin for pool '{pool_id}'")
                    return True
                
                if permission in pool_perms:
                    logging.debug(f"[POOL-PERM] User {username} has {permission} for pool '{pool_id}'")
                    return True

                # NS Sep 2026 (#793) — a non-empty grant on the pool confers VISIBILITY of its
                # members. vm.view can't be stored in a grant at all: POOL_PERMISSIONS (users.py) is
                # the allowlist the grant endpoint validates against and has never carried it, so
                # for vm.view the exact match above could only ever be satisfied by pool.admin. Once
                # 6441b70 correctly stopped pool-scoped callers falling through to the blanket
                # role-level vm.view, every preset below Admin started listing an EMPTY pool, and
                # the only way to make a VM appear was to hand out pool.admin — which carries
                # vm.delete. get_user_pool_vmids already draws this line (its `permission is None`
                # arm); the inventory gate never learned it. Actions stay on the exact match above:
                # this only answers "may they SEE it".
                if permission in ('vm.view', 'pool.view'):
                    logging.debug(f"[POOL-PERM] {username} holds {pool_perms} on '{pool_id}' → visibility")
                    return True

                logging.debug(f"[POOL-PERM] User {username} has pool perms {pool_perms} but not {permission}")
            else:
                logging.debug(f"[POOL-PERM] User {username} has no permissions for pool '{pool_id}'")
    except Exception as e:
        logging.error(f"[POOL-PERM] Error checking pool permission: {e}")
    
    # no VM-specific ACL or pool permission matched.
    # MK Jun 2026 (sec-review): the general-role fall-through may ONLY grant blanket
    # access to VMs on clusters the user belongs to via their TENANT. A user who merely
    # *reached* this cluster through a VM-ACL or pool grant (cluster not in their tenant
    # set) must NOT inherit role-wide control of every VM here — only the specific ACL/
    # pool VMs handled above. Without this, #555's pool cluster-reach (and the older
    # #248 VM-ACL reach) let a pool-/ACL-scoped user drive every VM on the cluster.
    tenant_clusters = get_user_clusters(user, include_pools=False)
    if tenant_clusters is not None and cluster_id not in tenant_clusters:
        logging.debug(f"[VM-ACL] {username} reached {cluster_id} only via ACL/pool; no grant for VM {vmid} → deny {permission}")
        return False
    # MK Aug 2026 (sec-report, symplasson): a user EXPLICITLY scoped to specific VMs via VM-ACL
    # in this cluster (the Client Portal setup — an admin granted them "their" VMs) must not
    # fall through to the role-wide grant for a VM they were never granted, just because their
    # tenant happens to own the cluster. The ACL scope wins for per-VM ops — this keeps the
    # decision consistent with get_user_vms() (what the portal uses to decide what to SHOW).
    # Without it a portal user could substitute a foreign vmid on the console and reach a VM
    # outside their grant. Explicit membership only ('*' grants are handled at the top gate).
    acl_scoped = set(int(v) for v, a in cluster_acls.items()
                     if username in (a.get('users') or []) and str(v).lstrip('-').isdigit())
    scoped_vms = set(acl_scoped)
    # a user with ANY explicit per-resource grant (a VM-ACL row OR a pool permission) is confined
    # to their granted resources — even when live pool membership can't be resolved to concrete
    # vmids, so an unresolvable pool membership fails CLOSED (deny) instead of widening to the
    # whole tenant cluster. Pure operators (no ACL, no pool grant) keep cluster-wide access.
    # Resolve the pool grant ONCE and reuse it via _perms= below, so this per-VM authz path stays
    # a single lookup instead of two (and _pool_perms_for memoises the DB read across the request).
    has_pool_grant = False
    try:
        _pp = _pool_perms_for(cluster_id, username, user.get('groups', []))
        has_pool_grant = any(p for p in (_pp or {}).values())
        if has_pool_grant:
            scoped_vms |= get_user_pool_vmids(user, cluster_id, _perms=_pp)
    except Exception as _pe:
        logging.error(f"[VM-ACL] pool-scope lookup failed for {username}@{cluster_id}: {_pe} → fail closed")
        has_pool_grant = True   # unknown → treat as scoped (deny), never widen to the cluster
    try:
        _req_vmid = int(vmid)
    except (ValueError, TypeError):
        _req_vmid = None   # non-numeric vmid → out-of-scope for a scoped user (fail closed), no raise
    if (acl_scoped or has_pool_grant) and _req_vmid not in scoped_vms:
        logging.debug(f"[VM-ACL] {username} is ACL/pool-scoped on {cluster_id}; VM {vmid} not in {sorted(scoped_vms)} → deny {permission}")
        return False
    result = has_permission(user, permission)
    logging.debug(f"[VM-ACL] Fallback to general permission check for {permission}: {result}")
    return result


def _within_token_role(user: dict, permission: str) -> bool:
    """An API token must not exceed its own role through an object grant.

    NS Sep 2026 (audit) — effective_role exists only for API-token auth
    (utils/auth.build_authz_user sets it under `if session.get('api_token')`), and it is
    the role the token was minted with, floored to the owner's. Object grants ignored it:
    a VM ACL row or a pool grant on the OWNER's account returned True for vm.delete even
    on a token the owner had deliberately scoped to viewer. The token's whole point is
    being weaker than the account, and the ACL handed the difference straight back.

    Deliberately a no-op for anything that is not a reduced token. VM ACLs are ADDITIVE by
    design — that is the documented model — so capping an ordinary session by its role
    would delete the feature rather than fix a hole. Only a token whose effective_role
    differs from the stored role is capped, and only to what that role grants.
    """
    eff = user.get('effective_role')
    if not eff or eff == user.get('role'):
        return True
    # MK Sep 2026 — resolve a CUSTOM effective_role the same way everything else does. This
    # asked get_role_permissions_for_user for the caller's own tenant, while
    # get_user_permissions asks _tenant_defining_role first; for a token minted with a
    # tenant custom role whose holder sits in the default tenant the two then disagreed
    # outright. Measured: the permission list resolved 'ops' to vm.view/vm.start/vm.config
    # while this ceiling resolved it to nothing, so the route gate said yes and the object
    # gate said no to every per-VM operation — a custom-role token could touch no guest at
    # all. Fails closed, so it read as "tokens are broken" rather than as a hole, but the
    # two must give one answer. The owner ceiling still applies on top (_token_owner_capped
    # in get_user_permissions), so this cannot lift a token above the account that minted it.
    _tid = user.get('tenant_id')
    allowed = get_role_permissions_for_user({'role': eff, 'tenant_id': _tid},
                                            _tenant_defining_role(eff, _tid))
    return permission in (allowed or [])


def user_can_access_vm(user: dict, cluster_id: str, vmid: int, permission: str = 'vm.view', vm_type: str = None) -> bool:
    """Per-VM authorization, with the API-token ceiling applied to the result.

    The decision itself lives in _user_can_access_vm_uncapped. The cap is applied HERE,
    once, rather than at each of its five grant points — the #941 follow-up was a lesson
    in what happens when a guard is added to the path you happened to read instead of to
    the place every path passes through.
    """
    if not _user_can_access_vm_uncapped(user, cluster_id, vmid, permission, vm_type):
        return False
    if not _within_token_role(user, permission):
        logging.debug(f"[TOKEN-CEILING] {user.get('username','')} denied {permission} on "
                      f"{cluster_id}/{vmid}: token role {user.get('effective_role')!r} "
                      f"does not carry it")
        return False
    return True


def get_user_vms(user: dict, cluster_id: str) -> list:
    """Get list of VMIDs user can access in a cluster
    
    Returns None if user can access all VMs (admin or no restrictions)
    """
    if user.get('effective_role', user.get('role')) == ROLE_ADMIN:
        return None

    username = user.get('username', '')
    acls = get_vm_acls()
    if acls_unavailable(acls):
        # None here means "no restrictions at all" - the last thing to answer when
        # we could not read the restrictions.
        logging.error(f"[VM-ACL] ACL store unavailable - no VMs listed for "
                      f"'{username}' on {cluster_id}")
        return []
    cluster_acls = acls.get(cluster_id, {})
    
    # if no acls for this cluster, user can see all (based on general perms)
    if not cluster_acls:
        return None
    
    # collect VMs user has access to
    allowed_vms = []
    for vmid, acl in cluster_acls.items():
        if acl_grants_user(acl, username):
            allowed_vms.append(int(vmid))
    
    return allowed_vms if allowed_vms else None


# =============================================================================
# VMWARE VM-LEVEL ACCESS CONTROL
# Similar to Proxmox VM ACLs but for VMware VMs
# Security fix: Prevent unauthorized VM operations
# =============================================================================

def user_can_access_vmware_vm(user: dict, vmware_id: str, vm_id: str, permission: str = 'vmware.vm.view') -> bool:
    """Check if user can access a specific VMware VM
    
    Security fix for authorization bypass vulnerability.
    Implements VM-level authorization for VMware VMs similar to Proxmox.
    
    Logic:
    1. Admin always has access
    2. If user has VM-specific ACL entry for this VMware server:
       - inherit_role=True: User can do ALL VM operations (full access)
       - inherit_role=False: User can ONLY do operations listed in permissions
    3. If user not in ACL: fall back to user's general role permissions
    
    Args:
        user: User dict with username and role
        vmware_id: VMware server ID
        vm_id: VM identifier (string)
        permission: Required permission (e.g., 'vmware.vm.power', 'vmware.vm.view')
    
    Returns:
        bool: True if user has access, False otherwise
    """
    # NS Aug 2026 (Aikido pentest) — effective_role (token-scoped) wins over the stored role,
    # exactly like the Proxmox twin user_can_access_vm above; otherwise an admin-owned but
    # viewer-scoped API token gets the full-admin VMware VM bypass here.
    if user.get('effective_role', user.get('role')) == ROLE_ADMIN:
        return True

    username = user.get('username', '')
    acls = get_vm_acls()
    if acls_unavailable(acls):
        logging.error(f"[VM-ACL] ACL store unavailable - denying {permission} for "
                      f"'{username}' on vmware:{vmware_id}/{vm_id}")
        return False

    # Gate on the VMware server's tenant reach BEFORE anything else. NS Jul 2026 (CodeAnt BOLA)
    # added this for the no-ACL fallback only: the general role permission previously granted ANY
    # vmware.vm.* holder access to EVERY server's VMs regardless of tenant. MK Sep 2026 - an ACL
    # row returned True above it, so a row naming a tenant-A user (or carrying '*') on a server
    # that belongs to tenant B handed over full VM access across the boundary. An ACL is a grant
    # WITHIN a tenant's estate, never a way into somebody else's. Mirrors check_pbs_access: admin
    # already returned above; an unlinked server stays backward-compat open; otherwise the caller
    # must reach one of the server's linked clusters.
    # MK Sep 2026 (CodeAnt, same day) - this used to log the error and carry on. While the
    # gate only guarded the no-ACL fallback that merely reopened the older hole; now that it
    # guards the ACL path too, an exception here skips exactly the cross-tenant check this
    # function exists for. A gate that cannot run has not said yes. Matches the ACL-store
    # check a few lines above, which already denies when it cannot read.
    try:
        from pegaprox.globals import vmware_managers
        _mgr = vmware_managers.get(vmware_id)
        _linked = (getattr(_mgr, 'linked_clusters', None) or []) if _mgr else []
        # include_pools=False: a Proxmox POOL grant says nothing about the ESXi guests on a
        # server that happens to be linked to that cluster, and the default (True) let a
        # pool-scoped caller through. Tenant ownership is the right question here.
        _uc = get_user_clusters(user, include_pools=False) if _linked else None
    except Exception as _e:
        logging.error(f"[VMWARE-ACL] tenant gate could not run for {vmware_id}, denying "
                      f"{permission} for '{username}': {_e}")
        return False
    if _linked and _uc is not None and not any(c in _uc for c in _linked):
        logging.debug(f"[VMWARE-ACL] {username} cannot reach any linked cluster of "
                      f"{vmware_id} - deny {permission}")
        return False

    # VMware ACLs are stored under vmware_id as the cluster key
    vmware_acls = acls.get(f'vmware:{vmware_id}', {})
    vm_acl = vmware_acls.get(str(vm_id), {})
    
    if vm_acl:
        # one definition of what a row grants, wildcard included (acl_grants_user)
        if acl_grants_user(vm_acl, username):
            if vm_acl.get('inherit_role', True):
                # inherit_role=True: FULL VM access
                vmware_permissions = ['vmware.vm.view', 'vmware.vm.power', 'vmware.vm.manage', 
                                     'vmware.vm.snapshot', 'vmware.vm.migrate', 'vmware.vm.console']
                return permission in vmware_permissions
            else:
                # inherit_role=False: use ONLY the VM-specific permissions
                vm_perms = vm_acl.get('permissions', [])
                return permission in vm_perms
    
    # MK Aug 2026 (sec-report, symplasson) — mirror the Proxmox user_can_access_vm scope-wins
    # guard: a user EXPLICITLY scoped to specific VMware VMs via a vmware:<id> ACL must stay
    # confined to those VMs, not inherit every VM on the server once their tenant reaches a
    # linked cluster. Without this the tenant gate above only stops cross-tenant reach, never
    # per-VM scope, so a scoped user could substitute a foreign vm_id (power/config/delete/…).
    scoped_ids = [str(v) for v, a in vmware_acls.items() if username in (a.get('users') or [])]
    if scoped_ids and str(vm_id) not in scoped_ids:
        logging.debug(f"[VMWARE-ACL] {username} is VMware-ACL-scoped on {vmware_id}; VM {vm_id} not in {scoped_ids} → deny {permission}")
        return False

    # No VM-specific ACL - use general permissions (now tenant-gated + scope-confined)
    return has_permission(user, permission)


# =============================================================================
# ROLE TEMPLATES - MK jan 2026
# MK: preset roles for common use cases
# LW: updated jan 2026 - tenant_admin was missing some perms
# =============================================================================

ROLE_TEMPLATES = {
    'tenant_admin': {
        'name': 'Tenant Administrator',
        'description': 'Full tenant access - everything except global settings',
        'permissions': [
            # VMs - full control
            'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console', 'vm.migrate',
            'vm.clone', 'vm.delete', 'vm.create', 'vm.config', 'vm.snapshot', 'vm.backup', 'vm.template',
            # cluster - no add/delete/join (thats global admin stuff)
            'cluster.view', 'cluster.config',
            # nodes - LW: added shell/reboot jan 2026
            'node.view', 'node.shell', 'node.maintenance', 'node.reboot', 'node.network', 'node.config',
            # storage
            'storage.view', 'storage.upload', 'storage.download', 'storage.delete', 'storage.config',
            # backup - MK: tenant admins need full backup control
            'backup.view', 'backup.create', 'backup.restore', 'backup.delete', 'backup.schedule', 'backup.config',
            # HA
            'ha.view', 'ha.config', 'ha.groups', 'ha.resources',
            # firewall
            'firewall.view', 'firewall.edit', 'firewall.aliases',
            # pools + replication
            'pool.view', 'pool.manage', 'pool.assign',
            'replication.view', 'replication.manage',
            # site recovery - full access for tenant admins
            'site_recovery.view', 'site_recovery.manage', 'site_recovery.failover',
        ]
    },
    'tenant_operator': {
        'name': 'Tenant Operator',
        'description': 'Daily ops - VMs, backups, basic maintenance',
        'permissions': [
            # VMs - no delete/create/template
            'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console', 'vm.migrate',
            'vm.clone', 'vm.config', 'vm.snapshot', 'vm.backup',
            'cluster.view',
            'node.view', 'node.maintenance',
            'storage.view', 'storage.upload', 'storage.download',
            'backup.view', 'backup.create', 'backup.restore', 'backup.delete',  # LW: ops need to clean up old backups
            'ha.view',
            'firewall.view',
            'pool.view', 'pool.assign',
            'replication.view',
            'site_recovery.view',
        ]
    },
    'tenant_user': {
        'name': 'Tenant User',
        'description': 'Basic VM stuff - start/stop/console',
        'permissions': [
            'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console', 'vm.snapshot',
            'cluster.view',
            'node.view',
            'storage.view',
            'backup.view', 'backup.create', 'backup.restore',  # LW: let users backup their own stuff
            'ha.view',
            'firewall.view',
            'pool.view',
        ]
    },
    'tenant_viewer': {
        'name': 'Tenant Viewer',
        'description': 'Read-only + console',
        'permissions': [
            'vm.view', 'vm.console',
            'cluster.view',
            'node.view',
            'storage.view',
            'backup.view',
            'ha.view',
            'firewall.view',
            'pool.view',
            'replication.view',
            'site_recovery.view',
        ]
    },
    'vm_operator': {
        'name': 'VM Operator',
        'description': 'VMs only - no infra access',
        'permissions': [
            'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console',
            'vm.snapshot', 'vm.backup',
            'backup.view', 'backup.create', 'backup.restore',
            'storage.view',
        ]
    },
    'backup_operator': {
        'name': 'Backup Operator', 
        'description': 'Backups only - for backup admins',
        'permissions': [
            'vm.view',
            'storage.view', 'storage.upload',
            'backup.view', 'backup.create', 'backup.restore', 'backup.delete', 'backup.schedule', 'backup.config',
        ]
    },
    'storage_admin': {
        'name': 'Storage Administrator',
        'description': 'Storage + backup management',
        'permissions': [
            'vm.view',
            'cluster.view',
            'node.view',
            'storage.view', 'storage.upload', 'storage.delete', 'storage.config', 'storage.create', 'storage.download',
            'backup.view', 'backup.create', 'backup.restore', 'backup.delete', 'backup.config',
        ]
    },
    'network_admin': {
        'name': 'Network Administrator',
        'description': 'Network + firewall config',
        'permissions': [
            'vm.view', 'vm.config',  # need this for VM NICs
            'cluster.view',
            'node.view', 'node.network', 'node.config',
            'firewall.view', 'firewall.edit', 'firewall.aliases',
            'ha.view',
        ]
    },
    'monitoring': {
        'name': 'Monitoring',
        'description': 'Read-only for dashboards/alerting',
        'permissions': [
            'vm.view',
            'cluster.view',
            'node.view',
            'storage.view',
            'backup.view',
            'ha.view',
            'firewall.view',
            'pool.view',
            'replication.view',
            'site_recovery.view',
            'admin.audit',  # MK: monitoring tools need audit logs
        ]
    },
    'group_manager': {
        'name': 'Group Manager',
        'description': 'Cluster groups + tenant management',
        'permissions': [
            'vm.view',
            'cluster.view',
            'node.view',
            'storage.view',
            'pool.view', 'pool.manage', 'pool.assign',
            'admin.groups', 'admin.tenants',
        ]
    },
    'helpdesk': {
        'name': 'Helpdesk',
        'description': 'Support staff - basic VM help',
        'permissions': [
            'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console', 'vm.snapshot',
            'cluster.view',
            'node.view',
            'storage.view',
            'backup.view', 'backup.restore',  # can restore for users
            'ha.view',
        ]
    },
    'developer': {
        'name': 'Developer',
        'description': 'Dev access - own VMs + snapshots',
        'permissions': [
            'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console',
            'vm.snapshot', 'vm.clone', 'vm.config',
            'cluster.view',
            'node.view',
            'storage.view', 'storage.upload',
            'backup.view', 'backup.create', 'backup.restore',
        ]
    },
    'auditor': {
        'name': 'Auditor',
        'description': 'Compliance - read-only + audit logs',
        'permissions': [
            'vm.view',
            'cluster.view',
            'node.view',
            'storage.view',
            'backup.view',
            'ha.view',
            'firewall.view',
            'pool.view',
            'replication.view',
            'site_recovery.view',
            'admin.audit',
        ]
    },
}
