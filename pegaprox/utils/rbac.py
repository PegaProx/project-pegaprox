# -*- coding: utf-8 -*-
"""
PegaProx RBAC - Layer 4
Custom roles, tenants, VM ACLs, pool membership cache.
"""

import os
import re
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
# what a role resolving to no single tenant acts in, for callers outside this module
UNRESOLVED_TENANT = _AMBIGUOUS_ROLE_TENANT


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
    custom = get_custom_roles()
    # NS Oct 2026 (#1013) - a GLOBAL role of this name is the one a default-tenant caller
    # holds. Remapping past it let any tenant that defined the same name take over every
    # default-tenant holder: their permissions and their clusters became that tenant's.
    if role in (custom.get('global') or {}):
        return tenant_id
    owners = [tid for tid, roles in custom.get('tenants', {}).items()
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
    # NS Oct 2026 - and a name nobody defines (a role deleted while held, or a role store
    # that did not load) has no tenant either. It grants nothing, and the default tenant
    # it fell back to answered every cluster when that tenant has no list (#1061).
    return _AMBIGUOUS_ROLE_TENANT


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
    
    if user.get('_token_owner_capped'):
        return _token_permissions(user, tenant_id)

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

    return base_perms


def _token_permissions(user: dict, tenant_id: str) -> list:
    """What an API token may do in `tenant_id`: its own role, of what its owner holds today.

    MK Sep 2026 - the owner half: a token bound to a custom role never went through the
    numeric floor, so demoting its owner, stripping one of their permissions, or editing
    the custom role itself left the token resolving through the old, larger set.

    NS Oct 2026 (#1014) - and the token half has to be the role alone. The cap above only
    ran when the tenant override named another role than the token's, so the owner's
    extra grants - global or in a tenant override naming that same role - came along
    unasked. Every identity apply_token_role builds lands here, the route gate in
    require_auth included, so both answer alike. Per tenant, because that is where the
    owner's side is decidable.
    """
    eff = user.get('effective_role') or ROLE_VIEWER
    own = get_role_permissions_for_user({'role': eff}, _tenant_defining_role(eff, tenant_id))
    owner = {k: v for k, v in user.items() if k not in ('effective_role', '_token_owner_capped')}
    held = set(get_user_permissions(owner, tenant_id))
    return [p for p in own if p in held]

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


def acts_as_admin(user: dict) -> bool:
    """The admin fast path of a gate: the role (an API token's effective one) is admin and
    no tenant override lowers the account inside its own tenant.

    NS Oct 2026 (#1028, #1031) - has_permission and get_user_clusters have asked both since
    Aikido 700487698, the other shortcuts compared the role alone. An admin mapped down to
    viewer where they live then still passed caller_is_scoped, the per-VM gates and the PBS
    checks, and so reached every tenant's guests and backups. Every admin shortcut asks this.
    """
    if not user or user.get('effective_role', user.get('role')) != ROLE_ADMIN:
        return False
    return not _admin_is_capped_in_own_tenant(user)


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
    # NS Oct 2026 - an API token resolves its own role, which a builtin never remaps and a
    # custom one may remap elsewhere than its owner's. Its permissions were capped to the
    # owner's already, its clusters were not: a token reaches none its owner cannot (#1049).
    eff = user.get('effective_role')
    if eff and eff != user.get('role'):
        owner = {k: v for k, v in user.items() if k not in ('effective_role', '_token_owner_capped')}
        own = get_user_clusters(owner, include_pools)
        mine = _role_clusters(user, include_pools)
        if own is None:
            return mine
        if mine is None:
            return list(own)
        return [c for c in mine if c in own]
    return _role_clusters(user, include_pools)


def _cluster_role(user: dict) -> str:
    """The role whose tenant an account's clusters come from.

    NS Oct 2026 (#992) - the override of the tenant an account lives in is the role it acts
    under there: get_user_permissions takes its permissions from it, so a custom role named
    there has to pick the clusters too. Only a lowered admin read it here, anyone else in the
    default tenant got another tenant's permissions on the default tenant's scope, all
    clusters when it has no list. An override naming a builtin remaps nothing and leaves the
    account's own role to decide. A token acting under a role of its own keeps that one;
    get_user_clusters holds it inside its owner's clusters.
    """
    own = user.get('role', ROLE_VIEWER)
    role = user.get('effective_role') or own
    if role not in (ROLE_ADMIN, own):
        return role
    tp = (user.get('tenant_permissions') or {}).get(user.get('tenant_id', DEFAULT_TENANT_ID))
    home = tp.get('role', own) if isinstance(tp, dict) else own
    if role == ROLE_ADMIN or home not in BUILTIN_ROLES:
        return home
    return role


def acting_tenant(user: dict):
    """The tenant whose clusters `user` acts on, or None for an administrator.

    Its own tenant, or for a default-tenant account the one its role is defined by, as
    get_user_clusters resolves it. A token acting under a role of its own answers for its
    owner as well: the narrower of the two, and where they name two different tenants
    UNRESOLVED_TENANT, which owns nothing. NS Oct 2026 (#1008)
    """
    if acts_as_admin(user or {}):
        return None
    user = user or {}
    tid = _tenant_defining_role(_cluster_role(user), user.get('tenant_id') or DEFAULT_TENANT_ID)
    eff = user.get('effective_role')
    if not eff or eff == user.get('role'):
        return tid
    owner = acting_tenant({k: v for k, v in user.items()
                           if k not in ('effective_role', '_token_owner_capped')})
    if owner is None or owner == tid or owner == DEFAULT_TENANT_ID:
        return tid
    return owner if tid == DEFAULT_TENANT_ID else _AMBIGUOUS_ROLE_TENANT


def _role_clusters(user: dict, include_pools: bool = True) -> list:
    global tenants_db
    if not tenants_db:
        tenants_db = load_tenants()
    
    # admin sees all — honor the token-scoped effective_role (#491) so an admin-owned API token
    # restricted to viewer/user doesn't inherit the owner's all-cluster access, and the LDAP
    # tenant override for the same reason (see _admin_is_capped_in_own_tenant).
    if acts_as_admin(user):
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
    tenant_id = _tenant_defining_role(_cluster_role(user), tenant_id)

    tenant = tenants_db.get(tenant_id, {})
    clusters = tenant.get('clusters', [])
    
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


def check_tenant_quota(tenant_id, add_cores=0, add_mem_gb=0, add_vms=1, add_disk_gb=0, force=False,
                       counted=None):
    """#502 — sum a tenant's current resource usage across its clusters and decide
    whether adding (add_cores, add_mem_gb, add_vms, add_disk_gb) would exceed its quota.
    Returns {'ok', 'enforce', 'violations', 'usage', 'quota'}. FAIL-OPEN: any error
    returns ok=True so a quota bug can never block a legitimate VM create.
    force=True computes usage even when no quota is set (for the usage display).

    NS Sep 2026 — disk joins cores/memory/vms as the fourth dimension. It is the one an MSP
    actually runs out of first, and it was the only one of the four a tenant could grow without
    limit. Same shape as the others: 0 = unlimited, same enforce mode, same fail-open.

    MK Oct 2026 - a guest's disk is what its volumes hold on the storages, not maxdisk alone
    (the boot disk of a VM, the rootfs of a container), and what an earlier check let
    through that the cluster does not show yet is counted on top (the holds below, under
    'pending' in the answer). counted: a dict to fill with {cluster: {vmid: footprint}} of
    the clusters that were read."""
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
        seen = {}
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
            alloc = guest_disk_allocations(cid, mgr) if (qd > 0 or force) and vms else None
            # a cluster that did not answer cannot show that a held guest arrived
            rows = None if getattr(vms, 'unavailable', False) is True else {}
            for vm in (vms or []):
                fp = guest_footprint(vm, alloc)
                used_vms += 1
                used_cores += fp['cores']
                used_mem += fp['memory_gb']
                used_disk += fp['disk_gb']
                if rows is not None:
                    try:
                        rows[int(vm.get('vmid'))] = fp
                    except (TypeError, ValueError):
                        pass
            if rows is not None:
                seen[cid] = rows
        pending = _pending_usage(tenant_id, seen)
        used_vms += pending['vms']
        used_cores += pending['cores']
        used_mem += pending['memory_gb']
        used_disk += pending['disk_gb']
        if counted is not None:
            counted.update(seen)
        violations = []
        if qv > 0 and used_vms + add_vms > qv:
            violations.append('vms')
        if qc > 0 and used_cores + add_cores > qc:
            violations.append('cores')
        if qm > 0 and used_mem + add_mem_gb > qm:
            violations.append('memory')
        if qd > 0 and used_disk + add_disk_gb > qd:
            violations.append('disk')
        out = {
            'ok': not violations, 'enforce': enforce, 'violations': violations,
            'usage': {'vms': used_vms, 'cores': int(round(used_cores)), 'memory_gb': round(used_mem, 1),
                      'disk_gb': round(used_disk, 1)},
            'quota': {'vms': qv, 'cores': qc, 'memory_gb': qm, 'disk_gb': qd},
        }
        if any(pending.values()):
            out['pending'] = {'vms': pending['vms'], 'cores': int(round(pending['cores'])),
                              'memory_gb': round(pending['memory_gb'], 1),
                              'disk_gb': round(pending['disk_gb'], 1)}
        return out
    except Exception as e:
        logging.warning(f"[quota] check failed, allowing create (fail-open): {e}")
        return {'ok': True, 'enforce': 'warn', 'violations': [], 'usage': {}, 'quota': {}}


# MK Oct 2026 - the quota stood guard on create only; a clone, a restore into a new VMID, a
# template deploy, a guest landing from ESXi or another hypervisor and a resize grew a
# tenant past it unasked. These are what those paths share.

GIB = 1024.0 ** 3
# a growth whose size cannot be told (an image imported into a new disk, a container whose
# core limit is lifted on a node of unknown size): more than any quota holds
QUOTA_UNKNOWN = 10 ** 9


def quota_tenant(user):
    """The tenant an operation counts against: the caller's own, as the create routes take it."""
    return (user or {}).get('tenant_id') or DEFAULT_TENANT_ID


def tenant_has_quota(tenant_id):
    """Whether any of the four quotas is set, without walking a cluster"""
    t = (load_tenants() or {}).get(tenant_id) or {}
    return any(int(t.get(k, 0) or 0) > 0 for k in
               ('quota_max_vms', 'quota_max_cores', 'quota_max_memory_gb', 'quota_max_disk_gb'))


def tenant_counts_cluster(tenant_id, cluster_id):
    """Whether check_tenant_quota counts the guests of this cluster for the tenant"""
    allowed = get_user_clusters({'role': ROLE_VIEWER, 'tenant_id': tenant_id})
    return allowed is None or cluster_id in allowed


def _num(v):
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def guest_footprint(row, alloc=None):
    """{cores, memory_gb, disk_gb} of a guest as check_tenant_quota counts it, from a
    /cluster/resources row (maxcpu, maxmem, maxdisk). maxdisk is the boot disk of a VM and
    the rootfs of a container only; alloc ({vmid: GB}, guest_disk_allocations) has all of
    its volumes, and the bigger of the two counts."""
    row = row or {}
    disk = _num(row.get('maxdisk')) / GIB
    if alloc:
        try:
            disk = max(disk, float(alloc.get(int(row.get('vmid')), 0) or 0))
        except (TypeError, ValueError):
            pass
    return {'cores': int(_num(row.get('maxcpu') or row.get('cpus') or row.get('cores'))),
            'memory_gb': _num(row.get('maxmem')) / GIB, 'disk_gb': disk}


# ---- the volumes of every guest, from the storages ------------------------------------------

_DISK_ALLOC_TTL = 300
_DISK_ALLOC_RETRY = 60
_disk_alloc_cache = {}      # (cluster id, id(manager)) -> (read at, {vmid: GB} or None)


def guest_disk_allocations(cluster_id, mgr, max_age=_DISK_ALLOC_TTL):
    """{vmid: GB} of the volumes each guest has on the cluster's storages (every disk of a
    VM, every mount point of a container, detached ones too), from the storage content
    lists: one call per shared storage and one per node for a local one, run 8 at a time,
    kept max_age seconds. None for a cluster that is not Proxmox VE, or whose lists did not
    answer (then maxdisk is all there is, as before)."""
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None
    key = (cluster_id, id(mgr))
    hit = _disk_alloc_cache.get(key)
    now = time.time()
    if hit and now - hit[0] < max_age:
        return hit[1]
    try:
        got = _read_disk_allocations(mgr)
    except Exception as e:
        logging.debug(f"[quota] storage contents of {cluster_id} unreadable: {e}")
        got = None
    if got is None:
        # the last good answer beats none; asked again in a minute, not on every check
        got = hit[1] if hit else None
        _disk_alloc_cache[key] = (now - max_age + _DISK_ALLOC_RETRY, got)
        return got
    _disk_alloc_cache[key] = (now, got)
    return got


def _read_disk_allocations(mgr):
    base = f"https://{mgr.host}:{mgr.api_port}/api2/json"
    r = mgr._api_get(f"{base}/cluster/resources", params={'type': 'storage'}, timeout=15)
    if getattr(r, 'status_code', None) != 200:
        return None
    stores = (r.json() or {}).get('data')
    if not isinstance(stores, list):
        return None
    lists, shared = [], set()
    for s in stores:
        if not isinstance(s, dict) or s.get('status') != 'available':
            continue
        content = str(s.get('content') or '')
        name, node = s.get('storage'), s.get('node')
        if not name or not node or ('images' not in content and 'rootdir' not in content):
            continue
        if s.get('shared'):
            if name in shared:
                continue
            shared.add(name)
        lists.append((node, name))
    if not lists:
        return {}

    def _content(node, name):
        rr = mgr._api_get(f"{base}/nodes/{node}/storage/{name}/content", timeout=20)
        if getattr(rr, 'status_code', None) != 200:
            return None
        data = (rr.json() or {}).get('data')
        return data if isinstance(data, list) else None

    from pegaprox.utils.concurrent import run_per_node
    got = run_per_node({f'{n}/{s}': (lambda _k, n=n, s=s: _content(n, s)) for n, s in lists},
                       max_concurrent=8, timeout=60)
    vols = {}
    for where, items in got.items():
        for v in (items or []):
            if not isinstance(v, dict) or v.get('content') not in ('images', 'rootdir'):
                continue
            try:
                vmid = int(v.get('vmid'))
            except (TypeError, ValueError):
                continue
            # a shared storage is listed once; a local volume is the node's own
            vols[(where, v.get('volid'))] = (vmid, _num(v.get('size')) / GIB)
    out = {}
    for vmid, gb in vols.values():
        out[vmid] = out.get(vmid, 0.0) + gb
    return out


# ---- reading a guest config -----------------------------------------------------------------

QUOTA_DISK_KEY_RE = re.compile(r'(?:ide|sata|scsi|virtio|efidisk|tpmstate|mp)\d+|rootfs')
QUOTA_SIZE_RE = re.compile(r'(?:^|,)size=(\d+(?:\.\d+)?)([KMGT]?)', re.I)
_QUOTA_UNIT_GB = {'': 1.0 / 1024 ** 3, 'K': 1.0 / 1024 ** 2, 'M': 1.0 / 1024, 'G': 1.0, 'T': 1024.0}
# STORAGE:SIZE asks Proxmox VE for a new volume of SIZE GiB
_NEW_VOLUME_RE = re.compile(r'([A-Za-z][\w.-]*):(\d+(?:\.\d+)?)')
# an EFI vars disk or a TPM state is a few MiB whatever number it was given
_SMALL_VOLUME_GB = 4.0 / 1024


def size_to_gb(num, unit):
    return float(num) * _QUOTA_UNIT_GB.get((unit or '').upper(), 1.0)


def raw_guest_config(got):
    """The guest's own config keys out of what get_vm_config answers ({'config': {...,
    'raw': {...}}} on Proxmox VE), out of that 'config' alone, or a config that is flat
    already. A dict without them is taken as it is."""
    if not isinstance(got, dict):
        return {}
    cfg = got['config'] if isinstance(got.get('config'), dict) else got
    raw = cfg.get('raw')
    return raw if isinstance(raw, dict) else cfg


def property_string(value, default_key):
    """(value of the default key, {other key: value}) of a property string: 'x,ssd=1' and
    'file=x,ssd=1' are the same drive"""
    main, opts = None, {}
    for i, part in enumerate(str(value if value is not None else '').split(',')):
        if '=' in part:
            k, v = part.split('=', 1)
            opts[k.strip()] = v.strip()
        elif i == 0 and part.strip():
            main = part.strip()
    if main is None:
        main = opts.pop(default_key, None)
    return main, opts


def memory_mb(value, default=512):
    """Memory in MB from a config value: '2048', 2048 or 'current=2048' (PVE 8.1 on)"""
    main, _ = property_string(value, 'current')
    try:
        return int(float(main))
    except (TypeError, ValueError):
        return default


def drive_new_gb(key, value):
    """GB a drive or mount point value allocates: 'STORAGE:SIZE' in any spelling of the
    property string ('file=' / 'volume=' written out or not) is a new volume of SIZE GB;
    with import-from it is filled from an image of a size the value does not say
    (QUOTA_UNKNOWN). A volume that exists, a bind mount, a CD-ROM allocate nothing."""
    key = str(key)
    if not QUOTA_DISK_KEY_RE.fullmatch(key):
        return 0.0
    vol, opts = property_string(value, 'volume' if key.startswith(('mp', 'rootfs')) else 'file')
    if not vol or opts.get('media') == 'cdrom':
        return 0.0
    m = _NEW_VOLUME_RE.fullmatch(vol)
    if not m:
        return 0.0
    if opts.get('import-from'):
        return float(QUOTA_UNKNOWN)
    if key.startswith(('efidisk', 'tpmstate')):
        return _SMALL_VOLUME_GB
    return float(m.group(2))


def config_footprint(cfg, kind='qemu', node_cores=None):
    """{cores, memory_gb, disk_gb} of a guest config: what get_vm_config answers (its raw
    keys), a flat dict, or the text of one (a backup's, from vzdump/extractconfig, or a
    snapshot's). Snapshot sections are not the guest, a CD-ROM is no disk of its own. A
    container without a core limit runs on every core of its node (node_cores, when
    known)."""
    if isinstance(cfg, str):
        parsed = {}
        for line in cfg.splitlines():
            line = line.strip()
            if line.startswith('['):
                break
            if not line or line.startswith('#') or ':' not in line:
                continue
            k, v = line.split(':', 1)
            parsed[k.strip()] = v.strip()
        cfg = parsed
    else:
        cfg = raw_guest_config(cfg)

    def _i(key, default):
        try:
            return int(float(cfg.get(key) or default))
        except (TypeError, ValueError):
            return default
    if kind == 'qemu':
        cores = _i('cores', 1) * _i('sockets', 1)
    elif cfg.get('cores') in (None, ''):
        cores = int(node_cores) if node_cores else 1
    else:
        cores = _i('cores', 1)
    disk = 0.0
    for k, v in cfg.items():
        if not QUOTA_DISK_KEY_RE.fullmatch(str(k)) or 'media=cdrom' in str(v):
            continue
        m = QUOTA_SIZE_RE.search(str(v))
        if m:
            disk += size_to_gb(m.group(1), m.group(2))
    return {'cores': cores, 'memory_gb': memory_mb(cfg.get('memory'), 512) / 1024.0, 'disk_gb': disk}


def landing_adds(tenant_id, target_cluster, footprint, source_cluster=None, source_removed=False):
    """What a guest arriving on target_cluster (a migration, a replica) adds to the tenant: a
    guest of that footprint where the target is counted for it, nothing where the guest only
    moves between clusters that are both counted (the source goes once the copy lands)."""
    from pegaprox.globals import cluster_managers
    if not tenant_counts_cluster(tenant_id, target_cluster):
        return None
    if (source_removed and source_cluster in cluster_managers
            and tenant_counts_cluster(tenant_id, source_cluster)):
        return None
    return dict(footprint or {}, vms=1)


def quota_verdict(tenant_id, add_vms=0, add_cores=0, add_mem_gb=0.0, add_disk_gb=0.0, counted=None):
    """check_tenant_quota for an operation, narrowed to what it grows: None when it adds
    nothing or fits, else the answer with only those violations. A dimension the operation
    does not add to is not its violation, even where the tenant is over already (a quota
    lowered later); a shrink in one does not pay for growth in another."""
    adds = {'vms': max(0, int(add_vms or 0)), 'cores': max(0, int(add_cores or 0)),
            'memory': max(0.0, float(add_mem_gb or 0)), 'disk': max(0.0, float(add_disk_gb or 0))}
    if not any(adds.values()):
        return None
    q = check_tenant_quota(tenant_id, add_cores=adds['cores'], add_mem_gb=adds['memory'],
                           add_vms=adds['vms'], add_disk_gb=adds['disk'], counted=counted)
    viol = [d for d in (q.get('violations') or []) if adds.get(d)]
    if not viol:
        return None
    return dict(q, violations=viol)


# ---- what a check let through that the cluster does not show yet -----------------------------
# A clone, a deploy, a migration create their guest seconds to hours after the check, and
# /cluster/resources shows a change some seconds after it is made (a new volume up to
# _DISK_ALLOC_TTL later). Every check that lets an operation through keeps a hold on what
# it adds, taken under one lock per tenant together with the check, and check_tenant_quota
# counts a tenant's holds on top of what it reads. A hold goes once the new guest shows on
# its cluster, once the growth shows on the guest, when the work behind it reports a
# failure, or when it runs out. Kept in memory: a restart forgets them.

_QUOTA_HOLD_TTL = 6 * 3600
_quota_holds = {}           # token -> hold
_quota_tenant_locks = {}    # tenant -> the lock around a check and the hold it leaves
_HOLD_DIMS = ('vms', 'cores', 'memory_gb', 'disk_gb')


def quota_tenant_lock(tenant_id):
    lk = _quota_tenant_locks.get(tenant_id)
    if lk is None:
        lk = _quota_tenant_locks.setdefault(tenant_id, threading.RLock())
    return lk


def quota_hold(tenant_id, cluster_id, adds, vmids=(), grow=False, base=None, ttl=None,
               key=None, alive=None):
    """Hold what an operation adds to a tenant until the cluster shows it. vmids: where it
    lands (the new guests, or the one guest that grows); grow: base is that guest's
    footprint as counted before. alive: a callable that answers False once the work behind
    the hold failed. Returns the token, None when it adds nothing."""
    a = {d: max(0.0, _num((adds or {}).get(d))) for d in _HOLD_DIMS}
    if grow:
        a['vms'] = 0.0
    if not any(a.values()):
        return None
    ids = set()
    for v in (vmids or ()):
        try:
            ids.add(int(v))
        except (TypeError, ValueError):
            pass
    tok = uuid.uuid4().hex
    _quota_holds[tok] = {'tenant': tenant_id, 'cluster': cluster_id, 'adds': a, 'vmids': ids,
                         'total': len(ids), 'grow': bool(grow) and len(ids) == 1,
                         'base': {d: _num((base or {}).get(d)) for d in _HOLD_DIMS},
                         'until': time.time() + (ttl or _QUOTA_HOLD_TTL), 'key': key, 'alive': alive}
    return tok


def quota_hold_update(token, vmids=None, alive=None, key=None):
    h = _quota_holds.get(token)
    if h is None:
        return
    if vmids is not None:
        h['vmids'] = {int(v) for v in vmids}
        h['total'] = len(h['vmids'])
    if alive is not None:
        h['alive'] = alive
    if key is not None:
        h['key'] = key


def quota_release(token):
    if token:
        _quota_holds.pop(token, None)


def quota_release_key(key):
    for tok, h in list(_quota_holds.items()):
        if h.get('key') == key:
            _quota_holds.pop(tok, None)


def _pending_usage(tenant_id, seen):
    """What the tenant's holds add to what check_tenant_quota read. seen: {cluster: {vmid:
    footprint}} of the clusters it read; a cluster it could not read keeps its holds."""
    tot = {d: 0.0 for d in _HOLD_DIMS}
    now = time.time()
    for tok, h in list(_quota_holds.items()):
        if h['tenant'] != tenant_id:
            continue
        if h['until'] < now:
            _quota_holds.pop(tok, None)
            continue
        try:
            if h['alive'] is not None and not h['alive']():
                _quota_holds.pop(tok, None)
                continue
        except Exception:
            pass
        rows = seen.get(h['cluster'])
        add = dict(h['adds'])
        if rows is not None and h['vmids']:
            if h['grow']:
                fp = rows.get(next(iter(h['vmids'])))
                if fp is None:
                    _quota_holds.pop(tok, None)          # the guest went
                    continue
                # what of the growth the guest does not show yet
                add = {d: max(0.0, h['base'][d] + h['adds'][d] - _num(fp.get(d)))
                       for d in ('cores', 'memory_gb', 'disk_gb')}
                add['vms'] = 0.0
            else:
                left = [v for v in h['vmids'] if v not in rows]
                share = len(left) / float(h['total'] or 1)
                add = {d: h['adds'][d] * share for d in _HOLD_DIMS}
            if not any(add.values()):
                _quota_holds.pop(tok, None)
                continue
        for d in _HOLD_DIMS:
            tot[d] += add[d]
    tot['vms'] = int(round(tot['vms']))
    return tot


class TenantRangeUnknown(Exception):
    """The tenant table did not load, so whether a tenant has a VMID range is unknown."""


def tenant_vmid_range(tenant_id):
    """(start, end) of the VMID slice a tenant may create in, or (0, 0) for no restriction.

    NS Sep 2026 — two tenants creating guests on a shared cluster otherwise compete for the same
    ids: PVE hands out the next free VMID globally, so whoever creates first takes it and the
    other's numbering drifts into their neighbour's block. Giving each tenant its own slice keeps
    a customer's guests recognisable by id alone, which is what makes per-tenant backup selectors
    and log greps usable at all.

    Raises TenantRangeUnknown when the tenant table could not be read: that is not "no range"."""
    tenants = load_tenants()
    if store_unavailable(tenants):
        raise TenantRangeUnknown(tenant_id)
    try:
        t = (tenants or {}).get(tenant_id) or {}
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
    try:
        start, end = tenant_vmid_range(tenant_id)
    except TenantRangeUnknown:
        # NS Oct 2026 - an unreadable tenant table read as "no range" and let every VMID
        # through. Judged below as if a range were set, and a VMID to judge is refused.
        start = end = None
    if start == 0:
        return True, ''
    _unknown = 'Cannot verify the tenant VMID range right now - check the server logs'
    # NS Oct 2026 - a list or an object passed for "nothing to judge" below, and a list still
    # reaches PVE as a VMID once it is form-encoded (#1081, #1056). A string PVE cannot read
    # as a number it refuses itself.
    if vmid is not None and not isinstance(vmid, (int, str)):
        if start is None:
            return False, _unknown
        return False, f'A VMID here is one whole number inside this tenant\'s range ({start}-{end})'
    try:
        v = int(vmid)
    except (TypeError, ValueError):
        return True, ''      # nothing to judge; PVE allocates and the id lands wherever it lands
    if start is None:
        logging.error(f"[vmid-range] tenant table unreadable, refusing VMID {v} for {tenant_id!r}")
        return False, _unknown
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
    finally:
        # NS Oct 2026 - the writer drops the cached copy itself, so a caller that forgets
        # to cannot leave a revoked or a new grant unseen for the TTL (#1007)
        invalidate_vm_acls_cache()

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
    if acts_as_admin(user):
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
    if acts_as_admin(user):
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


def token_role_tenant(owner: dict, role: str):
    """The tenant an API token of `owner` resolves `role` in, or None when the token may
    not carry that role.

    NS Oct 2026 - a custom role is found by name, and _tenant_defining_role moves a
    default-tenant caller into whichever tenant defines it. For an account an admin put
    on a tenant role that is the point. A token's role is picked by its owner, so a
    default-tenant user minted one with another tenant's role and acted in that tenant's
    clusters. The role has to resolve where the owner does: in their own tenant, or in
    the one their own role already places them in. A global admin is not confined to a
    tenant and may name any role that resolves.
    """
    tid = owner.get('tenant_id') or DEFAULT_TENANT_ID
    if not role or role in BUILTIN_ROLES:
        return tid
    custom = get_custom_roles()
    if store_unavailable(custom):
        return None
    used = _tenant_defining_role(role, tid)
    # deleted, misspelt, or defined by more than one tenant
    if (role not in ((custom.get('tenants') or {}).get(used) or {})
            and role not in (custom.get('global') or {})):
        return None
    if owner.get('role') == ROLE_ADMIN and not _admin_is_capped_in_own_tenant(owner):
        return used
    home = _tenant_defining_role(owner.get('role') or ROLE_VIEWER, tid)
    return used if used in (tid, home) else None


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
    if acts_as_admin(user):
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
    if acts_as_admin(user):
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
