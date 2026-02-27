# -*- coding: utf-8 -*-
"""cluster groups & rename routes - NS jan 2026"""

import logging
import uuid
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import load_server_settings, save_server_settings, check_cluster_access

bp = Blueprint('groups', __name__)

# =============================================================================
# CLUSTER GROUPS & RENAME - NS: Jan 2026
# Organize clusters into collapsible groups with tenant assignment
# =============================================================================

def get_user_tenant(username: str) -> str:
    """Get tenant_id for a user, returns None for admins/no tenant"""
    users = load_users()
    user = users.get(username, {})
    return user.get('tenant')


@bp.route('/api/cluster-groups', methods=['GET'])
@require_auth()
def get_cluster_groups():
    """Get all cluster groups (filtered by tenant)"""
    try:
        db = get_db()
        usr = getattr(request, 'session', {}).get('user', 'system')
        users = load_users()
        user = users.get(usr, {})
        tenant_id = user.get('tenant')
        
        # Admins see all groups, tenant users only see their tenant's groups + global groups
        if user.get('role') == ROLE_ADMIN or not tenant_id:
            groups = db.query('SELECT * FROM cluster_groups ORDER BY sort_order, name')
        else:
            # Tenant users see: their tenant's groups + groups without tenant (global)
            groups = db.query(
                'SELECT * FROM cluster_groups WHERE tenant_id = ? OR tenant_id IS NULL ORDER BY sort_order, name',
                (tenant_id,)
            )
        
        return jsonify([dict(g) for g in groups] if groups else [])
    except Exception as e:
        logging.error(f"Error loading cluster groups: {e}")
        return jsonify([])


@bp.route('/api/cluster-groups', methods=['POST'])
@require_auth(perms=['admin.groups'])
def create_cluster_group():
    """Create a new cluster group - requires admin.groups permission"""
    data = request.json or {}
    
    if not data.get('name'):
        return jsonify({'error': 'Name required'}), 400
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    users = load_users()
    user = users.get(usr, {})
    ip = request.remote_addr
    
    # Non-admins can only create groups for their own tenant
    tenant_id = data.get('tenant_id')
    if user.get('role') != ROLE_ADMIN:
        tenant_id = user.get('tenant')  # Force to user's tenant
    
    db = get_db()
    group_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    
    db.execute('''
        INSERT INTO cluster_groups (id, name, description, color, tenant_id, sort_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        group_id,
        data.get('name'),
        data.get('description', ''),
        data.get('color', '#E86F2D'),
        tenant_id,
        data.get('sort_order', 0),
        now, now
    ))
    
    tenant_info = f" (Tenant: {tenant_id})" if tenant_id else " (Global)"
    log_audit(usr, 'cluster_group.created', f"Created cluster group '{data.get('name')}' (ID: {group_id}){tenant_info}", ip_address=ip)
    
    return jsonify({'success': True, 'id': group_id})


@bp.route('/api/cluster-groups/<group_id>', methods=['PUT'])
@require_auth(perms=['admin.groups'])
def update_cluster_group(group_id):
    """Update a cluster group - requires admin.groups permission"""
    data = request.json or {}
    db = get_db()
    
    row = db.query_one('SELECT * FROM cluster_groups WHERE id = ?', (group_id,))
    if not row:
        return jsonify({'error': 'Group not found'}), 404
    group = dict(row)

    usr = getattr(request, 'session', {}).get('user', 'system')
    users = load_users()
    user = users.get(usr, {})
    ip = request.remote_addr

    # Check tenant access - non-admins can only edit their tenant's groups
    if user.get('role') != ROLE_ADMIN:
        user_tenant = user.get('tenant')
        if group['tenant_id'] and group['tenant_id'] != user_tenant:
            log_audit(usr, 'cluster_group.update_denied', f"Access denied to group '{group['name']}' (ID: {group_id}) - tenant mismatch", ip_address=ip)
            return jsonify({'error': 'Access denied - group belongs to different tenant'}), 403
    
    # Non-admins cannot change tenant_id
    tenant_id = data.get('tenant_id', group['tenant_id'])
    if user.get('role') != ROLE_ADMIN:
        tenant_id = group['tenant_id']  # Keep original tenant
    
    # NS: Feb 2026 - added cross-cluster LB fields to group update
    db.execute('''
        UPDATE cluster_groups SET
            name = ?,
            description = ?,
            color = ?,
            tenant_id = ?,
            sort_order = ?,
            collapsed = ?,
            cross_cluster_lb_enabled = ?,
            cross_cluster_threshold = ?,
            cross_cluster_interval = ?,
            cross_cluster_dry_run = ?,
            cross_cluster_target_storage = ?,
            cross_cluster_target_bridge = ?,
            cross_cluster_max_migrations = ?,
            cross_cluster_include_containers = ?,
            updated_at = ?
        WHERE id = ?
    ''', (
        data.get('name', group['name']),
        data.get('description', group['description']),
        data.get('color', group['color']),
        tenant_id,
        data.get('sort_order', group['sort_order']),
        1 if data.get('collapsed') else 0,
        1 if data.get('cross_cluster_lb_enabled', group.get('cross_cluster_lb_enabled', 0)) else 0,
        int(data.get('cross_cluster_threshold', group.get('cross_cluster_threshold', 30))),
        int(data.get('cross_cluster_interval', group.get('cross_cluster_interval', 600))),
        1 if data.get('cross_cluster_dry_run', group.get('cross_cluster_dry_run', 1)) else 0,
        data.get('cross_cluster_target_storage', group.get('cross_cluster_target_storage', '')),
        data.get('cross_cluster_target_bridge', group.get('cross_cluster_target_bridge', 'vmbr0')),
        int(data.get('cross_cluster_max_migrations', group.get('cross_cluster_max_migrations', 1))),
        1 if data.get('cross_cluster_include_containers', group.get('cross_cluster_include_containers', 0)) else 0,
        datetime.now().isoformat(),
        group_id
    ))
    
    log_audit(usr, 'cluster_group.updated', f"Updated cluster group '{data.get('name', group['name'])}' (ID: {group_id})", ip_address=ip)
    
    return jsonify({'success': True})


@bp.route('/api/cluster-groups/<group_id>', methods=['DELETE'])
@require_auth(perms=['admin.groups'])
def delete_cluster_group(group_id):
    """Delete a cluster group (clusters will become ungrouped) - requires admin.groups permission"""
    db = get_db()
    
    group = db.query_one('SELECT * FROM cluster_groups WHERE id = ?', (group_id,))
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    users = load_users()
    user = users.get(usr, {})
    ip = request.remote_addr
    
    # Check tenant access
    if user.get('role') != ROLE_ADMIN:
        user_tenant = user.get('tenant')
        if group['tenant_id'] and group['tenant_id'] != user_tenant:
            log_audit(usr, 'cluster_group.delete_denied', f"Access denied to delete group '{group['name']}' (ID: {group_id}) - tenant mismatch", ip_address=ip)
            return jsonify({'error': 'Access denied - group belongs to different tenant'}), 403
    
    # Count affected clusters for audit
    affected = db.query_one('SELECT COUNT(*) as cnt FROM clusters WHERE group_id = ?', (group_id,))
    affected_count = affected['cnt'] if affected else 0
    
    # Remove group assignment from all clusters in this group
    db.execute('UPDATE clusters SET group_id = NULL WHERE group_id = ?', (group_id,))
    
    # Delete the group
    db.execute('DELETE FROM cluster_groups WHERE id = ?', (group_id,))
    
    log_audit(usr, 'cluster_group.deleted', f"Deleted cluster group '{group['name']}' (ID: {group_id}) - {affected_count} clusters ungrouped", ip_address=ip)
    
    return jsonify({'success': True, 'ungrouped_clusters': affected_count})


@bp.route('/api/clusters/<cluster_id>/rename', methods=['PUT'])
@require_auth(perms=['admin.groups'])
def rename_cluster(cluster_id):
    """Rename a cluster (set display_name) - requires admin.groups permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.json or {}
    
    if not data.get('display_name'):
        return jsonify({'error': 'display_name required'}), 400
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    db = get_db()
    usr = getattr(request, 'session', {}).get('user', 'system')
    ip = request.remote_addr
    
    # Get old name for audit
    cluster = db.query_one('SELECT name, display_name FROM clusters WHERE id = ?', (cluster_id,))
    old_name = cluster['display_name'] or cluster['name'] if cluster else cluster_id
    new_name = data.get('display_name')
    
    db.execute('''
        UPDATE clusters SET display_name = ?, updated_at = ? WHERE id = ?
    ''', (new_name, datetime.now().isoformat(), cluster_id))
    
    log_audit(usr, 'cluster.renamed', f"Renamed cluster from '{old_name}' to '{new_name}' (ID: {cluster_id})", ip_address=ip)
    
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/group', methods=['PUT'])
@require_auth(perms=['admin.groups'])
def assign_cluster_to_group(cluster_id):
    """Assign a cluster to a group (or remove from group with null) - requires admin.groups permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.json or {}
    group_id = data.get('group_id')  # Can be None to ungroup
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    db = get_db()
    usr = getattr(request, 'session', {}).get('user', 'system')
    users = load_users()
    user = users.get(usr, {})
    ip = request.remote_addr
    
    # Verify group exists and user has access to it
    if group_id:
        group = db.query_one('SELECT name, tenant_id FROM cluster_groups WHERE id = ?', (group_id,))
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        
        # Check tenant access to target group
        if user.get('role') != ROLE_ADMIN:
            user_tenant = user.get('tenant')
            if group['tenant_id'] and group['tenant_id'] != user_tenant:
                log_audit(usr, 'cluster.group_assign_denied', f"Access denied to assign cluster {cluster_id} to group '{group['name']}' - tenant mismatch", ip_address=ip)
                return jsonify({'error': 'Access denied - group belongs to different tenant'}), 403
        
        group_name = group['name']
    else:
        group_name = 'Ungrouped'
    
    # Get old group for audit
    old_group = db.query_one('''
        SELECT cg.name FROM clusters c 
        LEFT JOIN cluster_groups cg ON c.group_id = cg.id 
        WHERE c.id = ?
    ''', (cluster_id,))
    old_group_name = old_group['name'] if old_group and old_group['name'] else 'Ungrouped'
    
    db.execute('''
        UPDATE clusters SET group_id = ?, updated_at = ? WHERE id = ?
    ''', (group_id, datetime.now().isoformat(), cluster_id))
    
    cluster = db.query_one('SELECT name, display_name FROM clusters WHERE id = ?', (cluster_id,))
    cluster_name = cluster['display_name'] or cluster['name'] if cluster else cluster_id
    
    log_audit(usr, 'cluster.group_changed', f"Moved cluster '{cluster_name}' from '{old_group_name}' to '{group_name}'", ip_address=ip)
    
    return jsonify({'success': True})


@bp.route('/api/cluster-groups/<group_id>/collapse', methods=['PUT'])
@require_auth()
def toggle_group_collapse(group_id):
    """Toggle collapsed state of a group (user preference, no audit needed)"""
    data = request.json or {}
    db = get_db()
    
    # Verify group exists
    group = db.query_one('SELECT id FROM cluster_groups WHERE id = ?', (group_id,))
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    db.execute('''
        UPDATE cluster_groups SET collapsed = ? WHERE id = ?
    ''', (1 if data.get('collapsed') else 0, group_id))
    
    return jsonify({'success': True})


# NS: Feb 2026 - cross-cluster LB status endpoint
# MK: aggregates across all clusters in the group
@bp.route('/api/cluster-groups/<group_id>/status', methods=['GET'])
@require_auth()
def get_cluster_group_status(group_id):
    """Get aggregated metrics for a cluster group, including xclb status"""
    try:
        db = get_db()
        group = db.query_one('SELECT * FROM cluster_groups WHERE id = ?', (group_id,))
        if not group:
            return jsonify({'error': 'Group not found'}), 404

        # tenant check - same logic as the list endpoint
        usr = getattr(request, 'session', {}).get('user', 'system')
        users = load_users()
        user = users.get(usr, {})
        tenant_id = user.get('tenant')
        if tenant_id and user.get('role') != ROLE_ADMIN:
            if group['tenant_id'] and group['tenant_id'] != tenant_id:
                return jsonify({'error': 'Access denied'}), 403

        clusters = db.query('SELECT id FROM clusters WHERE group_id = ?', (group_id,))
        cluster_ids = [c['id'] for c in clusters] if clusters else []

        # aggregate stats across all clusters in group
        total_nodes_online = 0
        total_nodes_offline = 0
        total_vms_running = 0
        total_vms_stopped = 0
        total_cpu = 0.0
        total_mem_used = 0
        total_mem_total = 0
        total_disk_used = 0
        total_disk_total = 0
        cluster_details = []

        for cid in cluster_ids:
            c_info = {'id': cid, 'connected': False, 'nodes_online': 0, 'nodes_offline': 0,
                       'vms_running': 0, 'vms_stopped': 0}

            if cid not in cluster_managers:
                cluster_details.append(c_info)
                continue

            mgr = cluster_managers[cid]
            if not mgr.is_connected:
                cluster_details.append(c_info)
                continue

            c_info['connected'] = True

            # node stats
            try:
                nodes = mgr.get_node_status()
                for nname, ndata in nodes.items():
                    if ndata.get('offline') or ndata.get('status') == 'offline':
                        total_nodes_offline += 1
                        c_info['nodes_offline'] += 1
                    else:
                        total_nodes_online += 1
                        c_info['nodes_online'] += 1
                        total_cpu += ndata.get('cpu_percent', 0)
                        total_mem_used += ndata.get('mem_used', 0)
                        total_mem_total += ndata.get('mem_total', 0)
                        total_disk_used += ndata.get('disk_used', 0)
                        total_disk_total += ndata.get('disk_total', 0)
            except Exception:
                pass  # don't break if one cluster fails

            # vm stats
            try:
                vms = mgr.get_vm_resources()
                for vm in vms:
                    if vm.get('status') == 'running':
                        total_vms_running += 1
                        c_info['vms_running'] += 1
                    else:
                        total_vms_stopped += 1
                        c_info['vms_stopped'] += 1
            except Exception:
                pass

            cluster_details.append(c_info)

        # build result - include xclb config from group row
        group_dict = dict(group)
        result = {
            'group_id': group_id,
            'group_name': group_dict.get('name', ''),
            'clusters': cluster_details,
            'totals': {
                'nodes_online': total_nodes_online,
                'nodes_offline': total_nodes_offline,
                'vms_running': total_vms_running,
                'vms_stopped': total_vms_stopped,
                'cpu_avg': round(total_cpu / total_nodes_online, 1) if total_nodes_online > 0 else 0,
                'mem_used': total_mem_used,
                'mem_total': total_mem_total,
                'mem_percent': round((total_mem_used / total_mem_total) * 100, 1) if total_mem_total > 0 else 0,
                'disk_used': total_disk_used,
                'disk_total': total_disk_total,
                'disk_percent': round((total_disk_used / total_disk_total) * 100, 1) if total_disk_total > 0 else 0,
            },
            'cross_cluster_lb': {
                'enabled': bool(group_dict.get('cross_cluster_lb_enabled', 0)),
                'threshold': group_dict.get('cross_cluster_threshold', 30),
                'interval': group_dict.get('cross_cluster_interval', 600),
                'dry_run': bool(group_dict.get('cross_cluster_dry_run', 1)),
                'target_storage': group_dict.get('cross_cluster_target_storage', ''),
                'target_bridge': group_dict.get('cross_cluster_target_bridge', 'vmbr0'),
                'max_migrations': group_dict.get('cross_cluster_max_migrations', 1),
                'last_run': group_dict.get('cross_cluster_last_run', ''),
            }
        }

        return jsonify(result)
    except Exception as e:
        logging.error(f"Error getting group status for {group_id}: {e}")
        return jsonify({'error': 'Failed to get group status'}), 500


# NS: cross-cluster LB audit trail
@bp.route('/api/cluster-groups/<group_id>/lb-history', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_group_lb_history(group_id):
    """Returns the last 50 xclb-related audit events for this group"""
    db = get_db()

    group = db.query_one('SELECT id FROM cluster_groups WHERE id = ?', (group_id,))
    if not group:
        return jsonify({'error': 'Group not found'}), 404

    # MK: grab anything tagged with xclb.* that mentions this group
    events = db.query(
        "SELECT * FROM audit_log WHERE action LIKE 'xclb.%' AND details LIKE ? ORDER BY timestamp DESC LIMIT 50",
        (f'%{group_id}%',)
    )

    return jsonify([dict(e) for e in events] if events else [])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/options', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_options_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_node_options(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/options', methods=['PUT'])
@require_auth(perms=['node.maintenance'])
def update_node_options_api(cluster_id, node):
    """Update node options"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    result = manager.update_node_options(node, request.json or {})
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/apt/updates', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_apt_updates_api(cluster_id, node):
    """Get available APT updates"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    try:
        return jsonify(manager.get_node_apt_updates(node))
    except Exception as e:
        return jsonify({'error': f'Failed to check updates: {str(e)}', 'updates': []}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/apt/refresh', methods=['POST'])
@require_auth(perms=['node.update'])
def refresh_node_apt_api(cluster_id, node):
    """Refresh APT package database"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    result = manager.refresh_node_apt(node)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


# ==================== NODE DISK MANAGEMENT ====================

