# -*- coding: utf-8 -*-
"""pool management & permissions routes - split from monolith dec 2025, NS"""

import logging
import re
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users, save_users
from pegaprox.utils.audit import log_audit
from pegaprox.utils.rbac import (
    get_user_permissions, get_vm_acls,
    get_pool_membership_cache, invalidate_pool_cache,
    get_user_effective_role, get_role_permissions_for_user,
    DEFAULT_TENANT_ID,
)
from pegaprox.api.helpers import check_cluster_access

bp = Blueprint('static_files', __name__)


# Pool Management API - NS Jan 2026
# Create, edit, delete pools and manage pool members directly from PegaProx
# ============================================================================

@bp.route('/api/clusters/<cluster_id>/pools', methods=['POST'])
@require_auth(perms=['admin.users'])
def create_pool(cluster_id):
    """Create a new resource pool in Proxmox"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.get_json() or {}
    poolid = data.get('poolid', '').strip()
    comment = data.get('comment', '').strip()
    
    if not poolid:
        return jsonify({'error': 'Pool ID is required'}), 400
    
    # validate pool ID
    if not re.match(r'^[a-zA-Z0-9_-]+$', poolid):
        return jsonify({'error': 'Pool ID can only contain letters, numbers, dashes and underscores'}), 400
    
    manager = cluster_managers.get(cluster_id)
    if not manager:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Ensure connected
    if not manager.is_connected:
        if not manager.connect_to_proxmox():
            return jsonify({'error': 'Failed to connect to Proxmox cluster'}), 503
    
    try:
        # Create pool via Proxmox API
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/pools"
        
        api_data = {'poolid': poolid}
        if comment:
            api_data['comment'] = comment
        
        response = manager._api_post(url, data=api_data)
        
        if response.status_code not in [200, 201]:
            error_text = response.text
            if 'already exists' in error_text.lower():
                return jsonify({'error': f'Pool "{poolid}" already exists'}), 409
            return jsonify({'error': f'Proxmox API error: {error_text}'}), 500
        
        # Invalidate cache
        invalidate_pool_cache(cluster_id)
        
        audit_log(request.session.get('user'), 'pool.create', f'Created pool {poolid}', {'cluster': cluster_id, 'poolid': poolid})
        
        return jsonify({'success': True, 'poolid': poolid, 'message': f'Pool "{poolid}" created successfully'})
    except Exception as e:
        error_msg = str(e)
        if 'already exists' in error_msg.lower():
            return jsonify({'error': f'Pool "{poolid}" already exists'}), 409
        return jsonify({'error': f'Failed to create pool: {error_msg}'}), 500


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def update_pool(cluster_id, pool_id):
    """Update a pool's comment"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.get_json() or {}
    comment = data.get('comment', '')
    
    manager = cluster_managers.get(cluster_id)
    if not manager:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Ensure connected
    if not manager.is_connected:
        if not manager.connect_to_proxmox():
            return jsonify({'error': 'Failed to connect to Proxmox cluster'}), 503
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/pools/{pool_id}"
        response = manager._api_put(url, data={'comment': comment})
        
        if response.status_code != 200:
            return jsonify({'error': f'Proxmox API error: {response.text}'}), 500
        
        audit_log(request.session.get('user'), 'pool.update', f'Updated pool {pool_id}', {'cluster': cluster_id, 'poolid': pool_id})
        
        return jsonify({'success': True, 'message': f'Pool "{pool_id}" updated successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to update pool: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_pool(cluster_id, pool_id):
    """Delete a resource pool"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager = cluster_managers.get(cluster_id)
    if not manager:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Ensure connected
    if not manager.is_connected:
        if not manager.connect_to_proxmox():
            return jsonify({'error': 'Failed to connect to Proxmox cluster'}), 503
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/pools/{pool_id}"
        response = manager._api_delete(url)
        
        if response.status_code != 200:
            error_text = response.text
            if 'not empty' in error_text.lower() or 'contains' in error_text.lower():
                return jsonify({'error': 'Cannot delete pool - it still contains VMs or storage. Remove all members first.'}), 400
            return jsonify({'error': f'Proxmox API error: {error_text}'}), 500
        
        # Invalidate cache
        invalidate_pool_cache(cluster_id)
        
        # Also remove any PegaProx permissions for this pool
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM pool_permissions WHERE cluster_id = ? AND pool_id = ?', (cluster_id, pool_id))
        conn.commit()
        conn.close()
        
        audit_log(request.session.get('user'), 'pool.delete', f'Deleted pool {pool_id}', {'cluster': cluster_id, 'poolid': pool_id})
        
        return jsonify({'success': True, 'message': f'Pool "{pool_id}" deleted successfully'})
    except Exception as e:
        error_msg = str(e)
        if 'not empty' in error_msg.lower() or 'contains' in error_msg.lower():
            return jsonify({'error': 'Cannot delete pool - it still contains VMs or storage. Remove all members first.'}), 400
        return jsonify({'error': f'Failed to delete pool: {error_msg}'}), 500


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>/members', methods=['POST'])
@require_auth(perms=['admin.users'])
def add_pool_member(cluster_id, pool_id):
    """Add a VM/CT to a pool"""
    logging.info(f"add_pool_member called: cluster={cluster_id}, pool={pool_id}")
    
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.get_json() or {}
    vmid = data.get('vmid')
    vm_type = data.get('type', 'qemu')  # qemu or lxc
    
    logging.info(f"Request data: vmid={vmid}, type={vm_type}")
    
    if not vmid:
        return jsonify({'error': 'VMID is required'}), 400
    
    manager = cluster_managers.get(cluster_id)
    if not manager:
        logging.error(f"Cluster {cluster_id} not found in cluster_managers")
        return jsonify({'error': 'Cluster not found'}), 404
    
    logging.info(f"Manager found: is_connected={manager.is_connected}")
    
    # Ensure connected
    if not manager.is_connected:
        logging.info("Manager not connected, attempting to connect...")
        if not manager.connect_to_proxmox():
            logging.error("Failed to connect to Proxmox")
            return jsonify({'error': 'Failed to connect to Proxmox cluster'}), 503
    
    try:
        # Add VM to pool - Proxmox uses 'vms' parameter
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/pools/{pool_id}"
        
        logging.info(f"Adding VM {vmid} to pool {pool_id} on {host}")
        
        # Proxmox expects form data with string values
        response = manager._api_put(url, data={
            'vms': str(vmid)
        })
        
        logging.info(f"Proxmox response: {response.status_code} - {response.text[:200] if response.text else 'empty'}")
        
        if response.status_code != 200:
            error_text = response.text
            # Try to parse JSON error
            try:
                error_json = response.json()
                error_text = error_json.get('errors', {}).get('vms', error_text)
            except:
                pass
            return jsonify({'error': f'Proxmox API error: {error_text}'}), 500
        
        # Invalidate cache
        invalidate_pool_cache(cluster_id)
        
        audit_log(request.session.get('user'), 'pool.member.add', f'Added VM {vmid} to pool {pool_id}', 
                  {'cluster': cluster_id, 'poolid': pool_id, 'vmid': vmid})
        
        return jsonify({'success': True, 'message': f'VM {vmid} added to pool "{pool_id}"'})
    except Exception as e:
        return jsonify({'error': f'Failed to add VM to pool: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/pools/<pool_id>/members/<int:vmid>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def remove_pool_member(cluster_id, pool_id, vmid):
    """Remove a VM/CT from a pool"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager = cluster_managers.get(cluster_id)
    if not manager:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Ensure connected
    if not manager.is_connected:
        if not manager.connect_to_proxmox():
            return jsonify({'error': 'Failed to connect to Proxmox cluster'}), 503
    
    try:
        # Remove VM from pool using DELETE parameter
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/pools/{pool_id}"
        response = manager._api_put(url, data={
            'vms': str(vmid),
            'delete': 1
        })
        
        if response.status_code != 200:
            return jsonify({'error': f'Proxmox API error: {response.text}'}), 500
        
        # Invalidate cache
        invalidate_pool_cache(cluster_id)
        
        audit_log(request.session.get('user'), 'pool.member.remove', f'Removed VM {vmid} from pool {pool_id}', 
                  {'cluster': cluster_id, 'poolid': pool_id, 'vmid': vmid})
        
        return jsonify({'success': True, 'message': f'VM {vmid} removed from pool "{pool_id}"'})
    except Exception as e:
        return jsonify({'error': f'Failed to remove VM from pool: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/vms-without-pool', methods=['GET'])
@require_auth()
def get_vms_without_pool(cluster_id):
    """Get all VMs that are not in any pool - useful for pool assignment UI"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager = cluster_managers.get(cluster_id)
    if not manager:
        return jsonify({'error': 'Cluster not found'}), 404
    
    try:
        # Get all VMs
        all_vms = manager.get_vm_resources()
        
        # Get pool membership
        membership = get_pool_membership_cache(cluster_id)
        
        # Filter VMs not in any pool
        vms_without_pool = []
        for vm in all_vms:
            vmid = vm.get('vmid')
            vm_type = vm.get('type', 'qemu')
            key = f"{vmid}:{vm_type}"
            
            if key not in membership:
                vms_without_pool.append({
                    'vmid': vmid,
                    'name': vm.get('name', f'VM {vmid}'),
                    'type': vm_type,
                    'status': vm.get('status', 'unknown'),
                    'node': vm.get('node', '')
                })
        
        return jsonify(vms_without_pool)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def check_pool_permission(cluster_id: str, vmid: int, vm_type: str, required_perm: str, user: str = None) -> bool:
    """Check if user has permission for a VM via pool permissions
    
    Returns True if user has the required permission through pool membership
    """
    if user is None:
        user = getattr(request, 'session', {}).get('user')
    
    if not user:
        return False
    
    # Admins always have access
    users = load_users()
    user_data = users.get(user, {})
    if user_data.get('role') == ROLE_ADMIN:
        return True
    
    # Get the pool this VM belongs to
    if cluster_id not in cluster_managers:
        return False
    
    mgr = cluster_managers[cluster_id]
    pool_id = mgr.get_vm_pool(vmid, vm_type)
    
    if not pool_id:
        return False  # VM not in any pool
    
    # Get user's groups
    user_groups = user_data.get('groups', [])
    
    # Get user's pool permissions
    db = get_db()
    user_pool_perms = db.get_user_pool_permissions(cluster_id, user, user_groups)
    
    # Check if user has required permission for this pool
    pool_perms = user_pool_perms.get(pool_id, [])
    
    # pool.admin grants all permissions
    if 'pool.admin' in pool_perms:
        return True
    
    return required_perm in pool_perms


@bp.route('/api/users/<username>/vm-access', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_user_vm_access(username):
    """Get all VMs a user has explicit access to"""
    users = load_users()
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    acls = get_vm_acls()
    access = []
    
    for cluster_id, cluster_acls in acls.items():
        for vmid, acl in cluster_acls.items():
            if username in acl.get('users', []) or '*' in acl.get('users', []):
                access.append({
                    'cluster_id': cluster_id,
                    'vmid': int(vmid),
                    'permissions': acl.get('permissions', []),
                    'inherit_role': acl.get('inherit_role', True)
                })
    
    return jsonify(access)


# ==================== PER-TENANT USER PERMISSIONS ====================

@bp.route('/api/users/<username>/permissions', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_user_perms(username):
    """Get effective permissions for a user"""
    users = load_users()
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    user = users[username]
    tenant_id = request.args.get('tenant_id', user.get('tenant_id', DEFAULT_TENANT_ID))
    
    effective = get_user_permissions(user, tenant_id)
    effective_role = get_user_effective_role(user, tenant_id)
    
    return jsonify({
        'username': username,
        'role': user.get('role'),
        'effective_role': effective_role,
        'tenant_id': tenant_id,
        'tenant_permissions': user.get('tenant_permissions', {}),
        'role_permissions': get_role_permissions_for_user(user, tenant_id),
        'extra_permissions': user.get('permissions', []),
        'denied_permissions': user.get('denied_permissions', []),
        'effective_permissions': effective
    })

@bp.route('/api/users/<username>/permissions', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_user_perms(username):
    """Set user-specific permissions (global or per-tenant)"""
    global users_db
    
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.json or {}
    tenant_id = data.get('tenant_id')  # if set, update tenant-specific perms
    
    if tenant_id:
        # per-tenant permissions
        role = data.get('role')
        extra = data.get('extra', [])
        denied = data.get('denied', [])
        
        # validate
        for p in extra + denied:
            if p not in PERMISSIONS:
                return jsonify({'error': f'Invalid permission: {p}'}), 400
        
        if 'tenant_permissions' not in users_db[username]:
            users_db[username]['tenant_permissions'] = {}
        
        users_db[username]['tenant_permissions'][tenant_id] = {
            'role': role or users_db[username].get('role', ROLE_VIEWER),
            'extra': extra,
            'denied': denied
        }
        
        log_audit(request.session['user'], 'user.tenant_perms_changed', 
                  f"Changed tenant permissions for {username} in {tenant_id}")
    else:
        # global permissions (old behavior)
        extra = data.get('permissions', [])
        denied = data.get('denied_permissions', [])
        
        for p in extra + denied:
            if p not in PERMISSIONS:
                return jsonify({'error': f'Invalid permission: {p}'}), 400
        
        users_db[username]['permissions'] = extra
        users_db[username]['denied_permissions'] = denied
        
        log_audit(request.session['user'], 'user.permissions_changed', 
                  f"Changed permissions for: {username}")
    
    save_users(users_db)
    
    return jsonify({
        'success': True,
        'effective_permissions': get_user_permissions(users_db[username], tenant_id)
    })


@bp.route('/api/users/<username>/tenant-permissions/<tenant_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def remove_user_tenant_perms(username, tenant_id):
    """Remove tenant-specific permissions for a user (revert to global)"""
    global users_db
    users_db = load_users()
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    tp = users_db[username].get('tenant_permissions', {})
    if tenant_id in tp:
        del tp[tenant_id]
        save_users(users_db)
        log_audit(request.session['user'], 'user.tenant_perms_removed', 
                  f"Removed tenant permissions for {username} in {tenant_id}")
    
    return jsonify({'success': True})

@bp.route('/api/me/permissions', methods=['GET'])
@require_auth()
def get_my_permissions():
    """Get current user's permissions"""
    users = load_users()
    user = users.get(request.session['user'], {})
    tenant_id = request.args.get('tenant_id', user.get('tenant_id', DEFAULT_TENANT_ID))
    
    return jsonify({
        'role': user.get('role'),
        'effective_role': get_user_effective_role(user, tenant_id),
        'tenant_id': tenant_id,
        'tenant_permissions': user.get('tenant_permissions', {}),
        'permissions': get_user_permissions(user, tenant_id)
    })



