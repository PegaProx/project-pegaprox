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
            role_data = {
                'name': row['name'],
                'permissions': json.loads(row['permissions'] or '[]'),
                'description': row['description'] or ''
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
        
        return {'global': global_roles, 'tenants': tenant_roles}
    except Exception as e:
        logging.error(f"Error loading custom roles from database: {e}")
        # Legacy fallback
        if os.path.exists(CUSTOM_ROLES_FILE):
            try:
                with open(CUSTOM_ROLES_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
    
    return {'global': {}, 'tenants': {}}


def save_custom_roles(roles: dict):
    """Save custom roles to SQLite database
    
    uses SQLite now
    """
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
                role_data.get('description', ''),
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
                    role_data.get('description', ''),
                    tenant_id,
                    now
                ))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to save custom roles: {e}")

# cache
_custom_roles_cache = None

def get_custom_roles():
    global _custom_roles_cache
    if _custom_roles_cache is None:
        _custom_roles_cache = load_custom_roles()
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
    
    # fallback to viewer
    return ROLE_PERMISSIONS[ROLE_VIEWER].copy()

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
        
        if tenants_list:
            # Convert list to dict format
            return {t['id']: t for t in tenants_list}
    except Exception as e:
        logging.error(f"Error loading tenants from database: {e}")
        # Legacy fallback
        if os.path.exists(TENANTS_FILE):
            try:
                with open(TENANTS_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
    
    # Create default tenant
    default = {
        DEFAULT_TENANT_ID: {
            'id': DEFAULT_TENANT_ID,
            'name': 'Default',
            'clusters': [],  # empty = all clusters (for backwards compat)
            'created': datetime.now().isoformat(),
        }
    }
    save_tenants(default)
    return default


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
        denied = tp.get('denied', [])
    else:
        # use global user settings
        role = user.get('role', ROLE_VIEWER)
        extra = user.get('permissions', [])
        denied = user.get('denied_permissions', [])
    
    # get base permissions from role (supports custom roles now)
    base_perms = get_role_permissions_for_user({'role': role}, tenant_id)
    
    # add extra
    for p in extra:
        if p not in base_perms:
            base_perms.append(p)
    
    # remove denied
    base_perms = [p for p in base_perms if p not in denied]
    
    return base_perms

def has_permission(user: dict, permission: str, tenant_id: str = None) -> bool:
    """check if user has a specific permission
    
    NS: now tenant-aware
    """
    if not user:
        return False
    # admin always has access (safety net) - unless checking tenant-specific
    if user.get('role') == ROLE_ADMIN and not tenant_id:
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

def get_user_clusters(user: dict) -> list:
    """Get list of cluster IDs user can access based on tenant
    
    NS: Dec 2025 - Also checks role's tenant for tenant-specific roles
    NS: Jan 2026 - Added group-based access (tenant can be assigned to groups)
    """
    global tenants_db
    if not tenants_db:
        tenants_db = load_tenants()
    
    # admin sees all
    if user.get('role') == ROLE_ADMIN:
        return None  # None means all clusters
    
    tenant_id = user.get('tenant_id', DEFAULT_TENANT_ID)
    
    # MK: If user has default tenant but a tenant-specific role, use the role's tenant
    role = user.get('role', ROLE_VIEWER)
    if tenant_id == DEFAULT_TENANT_ID and role not in BUILTIN_ROLES:
        custom_roles = load_custom_roles()
        for tid, roles in custom_roles.get('tenants', {}).items():
            if role in roles:
                tenant_id = tid
                break
    
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
    
    return clusters

def filter_clusters_for_user(clusters: dict, user: dict) -> dict:
    """Filter clusters dict to only show user's allowed clusters"""
    allowed = get_user_clusters(user)
    if allowed is None:
        return clusters  # user can see all
    
    return {k: v for k, v in clusters.items() if k in allowed}


# =============================================================================
# VM-LEVEL ACCESS CONTROL
# Fine-grained permissions for individual VMs/CTs
# Users can be granted or denied access to specific VMs
#
# AI-assisted: Initial structure suggested by Claude, then customized
# =============================================================================

VM_ACLS_FILE = os.path.join(CONFIG_DIR, 'vm_acls.json')

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
        return db.get_all_vm_acls()
    except Exception as e:
        logging.error(f"Failed to load VM ACLs from database: {e}")
        # Legacy fallback
        if os.path.exists(VM_ACLS_FILE):
            try:
                with open(VM_ACLS_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
    return {}


def save_vm_acls(acls: dict):
    """Save VM ACLs to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        db.save_all_vm_acls(acls)
    except Exception as e:
        logging.error(f"Failed to save VM ACLs: {e}")

_vm_acls_cache = None

# MK: Pool membership cache - Jan 2026
# Structure: {cluster_id: {'data': {vmid: pool_id, ...}, 'timestamp': time, 'refreshing': bool}}
# TTL: 300 seconds (5 min) - pools don't change often
# Stale TTL: 30 seconds - return stale data while refreshing in background
_pool_membership_cache = {}
POOL_CACHE_TTL = 300  # 5 minutes - pools rarely change
POOL_CACHE_STALE_TTL = 30  # Return stale data for 30s while refreshing
_pool_cache_lock = threading.Lock()

def _refresh_pool_cache_async(cluster_id: str):
    """Background refresh of pool cache - doesn't block requests"""
    global _pool_membership_cache
    
    try:
        if cluster_id not in cluster_managers:
            return
        
        mgr = cluster_managers[cluster_id]
        pools = mgr.get_pools()
        
        membership = {}
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
                logging.warning(f"[POOL-CACHE] Error getting members for pool {pool_id}: {e}")
                continue
        
        with _pool_cache_lock:
            _pool_membership_cache[cluster_id] = {
                'data': membership,
                'timestamp': time.time(),
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
    
    try:
        mgr = cluster_managers[cluster_id]
        pools = mgr.get_pools()
        
        membership = {}
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
            except:
                continue
        
        with _pool_cache_lock:
            _pool_membership_cache[cluster_id] = {
                'data': membership,
                'timestamp': now,
                'refreshing': False
            }
        
        logging.info(f"[POOL-CACHE] Initial cache for cluster {cluster_id}: {len(membership)} VMs in pools")
        return membership
        
    except Exception as e:
        logging.error(f"[POOL-CACHE] Error getting pool cache for {cluster_id}: {e}")
        return cache_entry.get('data', {}) if cache_entry else {}

def invalidate_pool_cache(cluster_id: str = None):
    """Invalidate pool membership cache"""
    global _pool_membership_cache
    with _pool_cache_lock:
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

def get_vm_acls():
    """Get VM ACLs - always reload from disk to avoid stale cache issues
    
    MK: Changed to always reload since ACLs are critical for security
    """
    global _vm_acls_cache
    # always reload from disk for security-critical data
    _vm_acls_cache = load_vm_acls()
    return _vm_acls_cache

def invalidate_vm_acls_cache():
    global _vm_acls_cache
    _vm_acls_cache = None

def user_can_access_vm(user: dict, cluster_id: str, vmid: int, permission: str = 'vm.view', vm_type: str = None) -> bool:
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
    if user.get('role') == ROLE_ADMIN:
        return True
    
    username = user.get('username', '')
    acls = get_vm_acls()
    
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
        if username in allowed_users or '*' in allowed_users:
            if vm_acl.get('inherit_role', True):
                # inherit_role=True: FULL VM access (start, stop, console, etc.)
                # This means "this user has access to this VM"
                vm_permissions = ['vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console', 
                                  'vm.snapshot', 'vm.migrate', 'vm.clone', 'vm.config', 'vm.backup']
                result = permission in vm_permissions
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
            
            # Get user's pool permissions from DB (not API)
            db = get_db()
            user_pool_perms = db.get_user_pool_permissions(cluster_id, username, user_groups)
            
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
                
                logging.debug(f"[POOL-PERM] User {username} has pool perms {pool_perms} but not {permission}")
            else:
                logging.debug(f"[POOL-PERM] User {username} has no permissions for pool '{pool_id}'")
    except Exception as e:
        logging.error(f"[POOL-PERM] Error checking pool permission: {e}")
    
    # no VM-specific ACL or pool permission - use general permissions
    result = has_permission(user, permission)
    logging.debug(f"[VM-ACL] Fallback to general permission check for {permission}: {result}")
    return result

def get_user_vms(user: dict, cluster_id: str) -> list:
    """Get list of VMIDs user can access in a cluster
    
    Returns None if user can access all VMs (admin or no restrictions)
    """
    if user.get('role') == ROLE_ADMIN:
        return None
    
    username = user.get('username', '')
    acls = get_vm_acls()
    cluster_acls = acls.get(cluster_id, {})
    
    # if no acls for this cluster, user can see all (based on general perms)
    if not cluster_acls:
        return None
    
    # collect VMs user has access to
    allowed_vms = []
    for vmid, acl in cluster_acls.items():
        users = acl.get('users', [])
        if username in users or '*' in users:
            allowed_vms.append(int(vmid))
    
    return allowed_vms if allowed_vms else None


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
            'admin.audit',
        ]
    },
}
