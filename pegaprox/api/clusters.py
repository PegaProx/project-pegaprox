# -*- coding: utf-8 -*-
"""cluster CRUD, HA & maintenance routes - split from monolith dec 2025, NS"""

import json
import logging
import threading
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.models.tasks import PegaProxConfig
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.audit import log_audit
from pegaprox.utils.rbac import (
    has_permission, get_user_clusters, filter_clusters_for_user,
    user_can_access_vm, invalidate_pool_cache, get_vm_acls,
)
from pegaprox.utils.realtime import broadcast_sse, broadcast_update, push_immediate_update
from pegaprox.core.config import load_config, save_config
from pegaprox.core.manager import PegaProxManager
from pegaprox.api.helpers import load_server_settings, get_connected_manager, check_cluster_access

# MK: this used to be 200 lines down in the monolith, good luck finding anything there
bp = Blueprint('clusters', __name__)

@bp.route('/api/clusters', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_clusters():
    """Get all configured clusters (filtered by tenant)
    
    NS: Clusters are now sorted by sort_order, then by name for consistent ordering
    """
    # get user's allowed clusters
    users = load_users()
    user = users.get(request.session['user'], {})
    allowed = get_user_clusters(user)
    
    # Get cluster metadata from database (display_name, group_id, sort_order)
    db = get_db()
    cluster_meta = {}
    try:
        meta_rows = db.query('SELECT id, display_name, group_id, sort_order FROM clusters')
        for row in meta_rows:
            cluster_meta[row['id']] = {
                'display_name': row['display_name'],
                'group_id': row['group_id'],
                'sort_order': row['sort_order'] if row['sort_order'] is not None else 0
            }
    except:
        pass
    
    clusters = []
    for cluster_id, mgr in cluster_managers.items():
        # filter by tenant
        if allowed is not None and cluster_id not in allowed:
            continue
        
        meta = cluster_meta.get(cluster_id, {})
        display_name = meta.get('display_name') or ''
            
        clusters.append({
            'id': cluster_id,
            'name': mgr.config.name,
            'display_name': display_name,
            'group_id': meta.get('group_id'),
            'sort_order': meta.get('sort_order', 0),
            'host': mgr.config.host,
            'status': 'running' if mgr.running else 'stopped',
            'connected': mgr.is_connected,
            'connection_error': mgr.connection_error,
            'migration_threshold': mgr.config.migration_threshold,
            'check_interval': mgr.config.check_interval,
            'auto_migrate': mgr.config.auto_migrate,
            'balance_containers': getattr(mgr.config, 'balance_containers', False),
            'balance_local_disks': getattr(mgr.config, 'balance_local_disks', False),
            'dry_run': mgr.config.dry_run,
            'enabled': mgr.config.enabled,
            'ha_enabled': mgr.config.ha_enabled,
            'fallback_hosts': mgr.config.fallback_hosts,
            'excluded_nodes': getattr(mgr.config, 'excluded_nodes', []),  # LW: Nodes excluded from balancing
            'current_host': getattr(mgr, 'current_host', None),
            'last_run': mgr.last_run.isoformat() if mgr.last_run else None
        })
    
    # MK: Sort clusters by sort_order first, then by name for consistent ordering
    clusters.sort(key=lambda c: (c.get('sort_order', 0), c.get('name', '').lower()))
    
    return jsonify(clusters)


@bp.route('/api/clusters', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def add_cluster():
    """Add a new cluster"""
    data = request.json
    
    # Validate required fields
    required = ['name', 'host', 'user', 'pass']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Generate unique ID
    cluster_id = str(uuid.uuid4())[:8]
    
    # Create config
    config = PegaProxConfig(data)
    
    # Create and start manager
    manager = PegaProxManager(cluster_id, config)
    
    # Test connection
    if not manager.connect_to_proxmox():
        return jsonify({'error': 'Failed to connect to Proxmox cluster'}), 400
    
    manager.start()
    cluster_managers[cluster_id] = manager
    
    # Save configuration
    save_config()
    
    # Audit log
    log_audit(request.session['user'], 'cluster.added', f"Added cluster: {data.get('name')} ({data.get('host')})")
    
    return jsonify({'id': cluster_id, 'message': 'Cluster added successfully'}), 201


@bp.route('/api/clusters/<cluster_id>/nodes', methods=['GET'])
@require_auth(perms=['node.view'])
def get_cluster_nodes(cluster_id):
    """Get list of nodes in a cluster
    
    NS: Made more resilient - returns cached/last known nodes if connection fails
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    # Try to get live data
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/nodes"
        r = manager._create_session().get(url, timeout=10)
        
        if r.status_code == 200:
            nodes = r.json().get('data', [])
            # Cache the nodes data
            manager._cached_nodes = nodes
            return jsonify(nodes)
    except Exception as e:
        logging.debug(f"Failed to get nodes for {cluster_id}: {e}")
    
    # If live data failed, return cached data with offline status
    if hasattr(manager, '_cached_nodes') and manager._cached_nodes:
        cached = manager._cached_nodes
        # Mark all as potentially stale
        for node in cached:
            if 'connection_status' not in node:
                node['connection_status'] = 'stale'
        return jsonify(cached)
    
    # If HA is tracking nodes, return those
    if manager.ha_node_status:
        nodes = []
        for name, data in manager.ha_node_status.items():
            nodes.append({
                'node': name,
                'status': data.get('status', 'unknown'),
                'connection_status': 'from_ha_cache'
            })
        return jsonify(nodes)
    
    # Last resort - return empty but with error info
    return jsonify({
        'error': 'Connection temporarily unavailable',
        'nodes': [],
        'offline': not manager.is_connected
    }), 503


@bp.route('/api/clusters/<cluster_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.delete'])
def delete_cluster(cluster_id):
    """Delete a cluster"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    cluster_name = mgr.config.name
    mgr.stop()
    del cluster_managers[cluster_id]
    
    # MK: Delete cluster and all related data from database
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Delete cluster
        db.delete_cluster(cluster_id)
        
        # Clean up related tables
        cursor.execute('DELETE FROM vm_acls WHERE cluster_id = ?', (cluster_id,))
        cursor.execute('DELETE FROM affinity_rules WHERE cluster_id = ?', (cluster_id,))
        cursor.execute('DELETE FROM cluster_alerts WHERE cluster_id = ?', (cluster_id,))
        db.conn.commit()
        
        logging.info(f"Deleted cluster {cluster_id} and related data from database")
    except Exception as e:
        logging.error(f"Failed to delete cluster from database: {e}")
    
    log_audit(request.session['user'], 'cluster.deleted', f"Deleted cluster: {cluster_name}")
    
    return jsonify({'message': 'Cluster deleted successfully'})


@bp.route('/api/clusters/reorder', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def reorder_clusters():
    """Update cluster sort order for sidebar display
    
    NS: Allows admins to reorder clusters via drag-and-drop in UI
    Request body: { "order": ["cluster_id_1", "cluster_id_2", ...] }
    """
    data = request.get_json()
    order = data.get('order', [])
    
    if not order:
        return jsonify({'error': 'No order provided'}), 400
    
    db = get_db()
    cursor = db.conn.cursor()
    
    try:
        for idx, cluster_id in enumerate(order):
            cursor.execute(
                'UPDATE clusters SET sort_order = ? WHERE id = ?',
                (idx, cluster_id)
            )
        db.conn.commit()
        
        log_audit(request.session['user'], 'cluster.reordered', f"Reordered {len(order)} clusters")
        
        return jsonify({'message': 'Cluster order updated', 'order': order})
    except Exception as e:
        logging.error(f"Failed to reorder clusters: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/sort-order', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def update_cluster_sort_order(cluster_id):
    """Update a single cluster's sort order
    
    Request body: { "sort_order": 5 }
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.get_json()
    sort_order = data.get('sort_order', 0)
    
    db = get_db()
    cursor = db.conn.cursor()
    
    try:
        cursor.execute(
            'UPDATE clusters SET sort_order = ? WHERE id = ?',
            (sort_order, cluster_id)
        )
        db.conn.commit()
        
        return jsonify({'message': 'Sort order updated', 'sort_order': sort_order})
    except Exception as e:
        logging.error(f"Failed to update sort order: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/metrics', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_metrics(cluster_id):
    """Get cluster node metrics
    
    NS: Made more resilient - returns cached/HA data if connection fails
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    # Try to get live metrics
    if mgr.is_connected:
        try:
            metrics = mgr.get_node_status()
            if metrics:
                # Cache the metrics
                mgr._cached_metrics = metrics
                return jsonify(metrics)
        except Exception as e:
            logging.debug(f"Error getting metrics for {cluster_id}: {e}")
    
    # If live data failed, try cached data
    if hasattr(mgr, '_cached_metrics') and mgr._cached_metrics:
        return jsonify(mgr._cached_metrics)
    
    # If HA is tracking nodes, build metrics from HA data
    if mgr.ha_node_status:
        ha_metrics = {}
        for name, data in mgr.ha_node_status.items():
            ha_metrics[name] = {
                'status': data.get('status', 'unknown'),
                'cpu': 0,
                'memory': {'used': 0, 'total': 0},
                'disk': {'used': 0, 'total': 0},
                'from_ha_cache': True
            }
        return jsonify(ha_metrics)
    
    # Return error with empty metrics - frontend will keep old data
    return jsonify({'error': 'Connection temporarily unavailable', 'offline': True}), 503

@bp.route('/api/clusters/<cluster_id>/resources', methods=['GET'])
@require_auth()
def get_cluster_resources(cluster_id):
    """Get cluster VM resources - filtered by VM ACLs
    
    NS: Dec 2025 - Now filters based on VM-specific ACLs
    Admin sees all VMs, others see only VMs they have access to
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster not connected', 'offline': True}), 503
    
    # get all resources
    all_resources = mgr.get_vm_resources()
    
    # check if user is admin - admin sees everything
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    
    if user.get('role') == ROLE_ADMIN:
        return jsonify(all_resources)
    
    # LW: Filter VMs based on ACLs - only show VMs user can access
    acls = get_vm_acls()
    cluster_acls = acls.get(cluster_id, {})
    
    # if no ACLs defined for this cluster, check if user has general vm.view permission
    if not cluster_acls:
        if has_permission(user, 'vm.view'):
            return jsonify(all_resources)
        else:
            return jsonify([])  # no vm.view permission and no ACLs
    
    # filter resources - show VMs user has ACL access to OR general vm.view permission
    filtered = []
    has_general_view = has_permission(user, 'vm.view')
    
    for vm in all_resources:
        vmid = str(vm.get('vmid', ''))
        vm_acl = cluster_acls.get(vmid, {})
        
        if vm_acl:
            # VM has specific ACL - check if user is in whitelist
            allowed_users = vm_acl.get('users', [])
            if user['username'] in allowed_users or '*' in allowed_users:
                filtered.append(vm)
        elif has_general_view:
            # No specific ACL but user has general view permission
            filtered.append(vm)
    
    return jsonify(filtered)

# NS: Feb 2026 - SECURITY: explicit allowlist prevents mass assignment attacks
# Password/key changes must go through dedicated endpoints with their own auth
# MK: also keeps 'sort_order' out because that was causing issues with drag-and-drop
ALLOWED_CONFIG_FIELDS = {
    'name', 'host', 'user', 'ssl_verification', 'migration_threshold',
    'check_interval', 'auto_migrate', 'balance_containers', 'balance_local_disks',
    'dry_run', 'enabled', 'ha_enabled', 'fallback_hosts', 'ssh_user', 'ssh_port',
    'ha_settings', 'excluded_nodes',
}

@bp.route('/api/clusters/<cluster_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def update_cluster_config(cluster_id):
    """Update cluster configuration"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json
    mgr = cluster_managers[cluster_id]

    # update config - only allowed fields
    updated = []
    for key, value in data.items():
        if key in ALLOWED_CONFIG_FIELDS and hasattr(mgr.config, key):
            old = getattr(mgr.config, key)
            setattr(mgr.config, key, value)
            updated.append(key)

    save_config()

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'cluster.config_changed', f"Cluster {mgr.config.name} config updated: {', '.join(updated)}")

    return jsonify({'message': 'Configuration updated successfully', 'updated_fields': updated})

@bp.route('/api/clusters/<cluster_id>/config', methods=['PATCH'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def update_cluster_config_live(cluster_id):
    """Update cluster configuration without restart"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json
    mgr = cluster_managers[cluster_id]

    updated = []
    for key, value in data.items():
        if key in ALLOWED_CONFIG_FIELDS and hasattr(mgr.config, key):
            setattr(mgr.config, key, value)
            updated.append(key)

    save_config()

    return jsonify({'message': 'Configuration updated successfully', 'updated_fields': updated})


@bp.route('/api/clusters/<cluster_id>/excluded-nodes', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_excluded_nodes(cluster_id):
    """Get list of nodes excluded from balancing
    
    NS: Feature request - allow excluding specific nodes from VM balancing
    Similar to ProxLB's exclude hosts feature
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    excluded = getattr(mgr.config, 'excluded_nodes', []) or []
    
    return jsonify({
        'excluded_nodes': excluded,
        'cluster_id': cluster_id
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def set_excluded_nodes(cluster_id):
    """Set list of nodes excluded from balancing
    
    NS: Feature request - allow excluding specific nodes from VM balancing
    Request body: { "excluded_nodes": ["node1", "node2"] }
    
    Excluded nodes will:
    - NOT be targets for automatic VM balancing
    - NOT be targets for balancing-related live migrations
    - NOT be included in balancing score calculations
    
    Note: Manual migrations TO excluded nodes are still allowed
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.get_json() or {}
    excluded_nodes = data.get('excluded_nodes', [])
    
    # Validate it's a list of strings
    if not isinstance(excluded_nodes, list):
        return jsonify({'error': 'excluded_nodes must be a list'}), 400
    
    excluded_nodes = [str(n) for n in excluded_nodes]  # Ensure strings
    
    mgr = cluster_managers[cluster_id]
    mgr.config.excluded_nodes = excluded_nodes
    
    # Save to database
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute(
            'UPDATE clusters SET excluded_nodes = ? WHERE id = ?',
            (json.dumps(excluded_nodes), cluster_id)
        )
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to save excluded_nodes: {e}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    log_audit(request.session['user'], 'cluster.excluded_nodes_changed', 
              f"Cluster {mgr.config.name}: excluded nodes set to {excluded_nodes}")
    
    return jsonify({
        'success': True,
        'excluded_nodes': excluded_nodes,
        'message': f'{len(excluded_nodes)} node(s) excluded from balancing'
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes/<node>', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def add_excluded_node(cluster_id, node):
    """Add a single node to the exclusion list"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    excluded = getattr(mgr.config, 'excluded_nodes', []) or []
    
    if node not in excluded:
        excluded.append(node)
        mgr.config.excluded_nodes = excluded
        
        # Save to database
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute(
                'UPDATE clusters SET excluded_nodes = ? WHERE id = ?',
                (json.dumps(excluded), cluster_id)
            )
            db.conn.commit()
        except Exception as e:
            logging.error(f"Failed to save excluded_nodes: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        
        log_audit(request.session['user'], 'cluster.node_excluded', 
                  f"Node {node} excluded from balancing in cluster {mgr.config.name}")
    
    return jsonify({
        'success': True,
        'excluded_nodes': excluded,
        'message': f'Node {node} excluded from balancing'
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes/<node>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def remove_excluded_node(cluster_id, node):
    """Remove a node from the exclusion list"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    excluded = getattr(mgr.config, 'excluded_nodes', []) or []
    
    if node in excluded:
        excluded.remove(node)
        mgr.config.excluded_nodes = excluded
        
        # Save to database
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute(
                'UPDATE clusters SET excluded_nodes = ? WHERE id = ?',
                (json.dumps(excluded), cluster_id)
            )
            db.conn.commit()
        except Exception as e:
            logging.error(f"Failed to save excluded_nodes: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        
        log_audit(request.session['user'], 'cluster.node_included', 
                  f"Node {node} re-included in balancing for cluster {mgr.config.name}")
    
    return jsonify({
        'success': True,
        'excluded_nodes': excluded,
        'message': f'Node {node} re-included in balancing'
    })


# ============================================
# Excluded VMs from Balancing API
# MK: VMs that should not be auto-migrated
# ============================================

@bp.route('/api/clusters/<cluster_id>/excluded-vms', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_excluded_vms(cluster_id):
    """Get list of VMs excluded from load balancing"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # MK: Ensure table exists (migration for existing databases)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS balancing_excluded_vms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                vmid INTEGER NOT NULL,
                reason TEXT,
                created_by TEXT,
                created_at TEXT,
                UNIQUE(cluster_id, vmid)
            )
        ''')
        
        cursor.execute(
            'SELECT vmid, reason, created_by, created_at FROM balancing_excluded_vms WHERE cluster_id = ?',
            (cluster_id,)
        )
        excluded = []
        for row in cursor.fetchall():
            excluded.append({
                'vmid': row['vmid'],
                'reason': row['reason'],
                'created_by': row['created_by'],
                'created_at': row['created_at']
            })
        
        # Get VM names for display
        vms = mgr.get_vm_resources() if mgr.is_connected else []
        vm_names = {vm['vmid']: vm.get('name', f"VM {vm['vmid']}") for vm in vms}
        
        for ex in excluded:
            ex['name'] = vm_names.get(ex['vmid'], f"VM {ex['vmid']}")
        
        return jsonify({
            'excluded_vms': excluded,
            'cluster_id': cluster_id
        })
    except Exception as e:
        logging.error(f"Error getting excluded VMs: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/excluded-vms/<int:vmid>', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def add_excluded_vm(cluster_id, vmid):
    """Add a VM to the exclusion list for load balancing"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    reason = data.get('reason', 'Manually excluded')
    user = request.session.get('user', 'system')
    
    if mgr.set_vm_balancing_excluded(vmid, True, reason, user):
        log_audit(user, 'cluster.vm_excluded', 
                  f"VM {vmid} excluded from balancing for cluster {mgr.config.name} (reason: {reason})")
        return jsonify({
            'success': True,
            'vmid': vmid,
            'message': f'VM {vmid} excluded from balancing'
        })
    else:
        return jsonify({'error': 'Failed to exclude VM'}), 500


@bp.route('/api/clusters/<cluster_id>/excluded-vms/<int:vmid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def remove_excluded_vm(cluster_id, vmid):
    """Remove a VM from the exclusion list"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    user = request.session.get('user', 'system')
    
    if mgr.set_vm_balancing_excluded(vmid, False, user=user):
        log_audit(user, 'cluster.vm_included', 
                  f"VM {vmid} re-included in balancing for cluster {mgr.config.name}")
        return jsonify({
            'success': True,
            'vmid': vmid,
            'message': f'VM {vmid} re-included in balancing'
        })
    else:
        return jsonify({'error': 'Failed to include VM'}), 500


@bp.route('/api/clusters/<cluster_id>/fallback-hosts', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_fallback_hosts(cluster_id):
    """Get list of fallback hosts for HA"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    fallback = getattr(mgr.config, 'fallback_hosts', []) or []
    
    return jsonify({
        'fallback_hosts': fallback,
        'cluster_id': cluster_id
    })


@bp.route('/api/clusters/<cluster_id>/fallback-hosts', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN], perms=['cluster.config'])
def set_fallback_hosts(cluster_id):
    """Set list of fallback hosts for HA
    
    Request body: { "fallback_hosts": ["192.168.1.2", "192.168.1.3"] }
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.get_json() or {}
    fallback_hosts = data.get('fallback_hosts', [])
    
    if not isinstance(fallback_hosts, list):
        return jsonify({'error': 'fallback_hosts must be a list'}), 400
    
    fallback_hosts = [str(h) for h in fallback_hosts if h]
    
    mgr = cluster_managers[cluster_id]
    mgr.config.fallback_hosts = fallback_hosts
    
    # Save to database
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute(
            'UPDATE clusters SET fallback_hosts = ? WHERE id = ?',
            (json.dumps(fallback_hosts), cluster_id)
        )
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to save fallback_hosts: {e}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    log_audit(request.session['user'], 'cluster.fallback_hosts_changed', 
              f"Cluster {mgr.config.name}: fallback hosts set to {fallback_hosts}")
    
    return jsonify({
        'success': True,
        'fallback_hosts': fallback_hosts,
        'message': f'{len(fallback_hosts)} fallback host(s) configured'
    })


@bp.route('/api/clusters/<cluster_id>/migrations', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_migration_log(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].last_migration_log)


@bp.route('/api/clusters/<cluster_id>/tasks', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_tasks(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    if not mgr.is_connected:
        return jsonify([])
    
    limit = request.args.get('limit', 50, type=int)
    return jsonify(mgr.get_tasks(limit=limit))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/tasks/<path:upid>', methods=['DELETE'])
@require_auth(perms=['vm.stop'])  # cancelling task is like stopping
def cancel_task(cluster_id, node, upid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        result = mgr.stop_task(node, upid)
        if result:
            # Log the action
            log_audit(
                request.session.get('user', 'system'),
                'task.cancelled',
                f'Task {upid} on {node}',
                request.remote_addr,
                cluster=mgr.config.name
            )
            return jsonify({'success': True, 'message': 'Task cancelled'})
        else:
            return jsonify({'error': 'Failed to cancel task'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# High Availability (HA) API Routes
@bp.route('/api/clusters/<cluster_id>/ha', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_ha_status(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_ha_status())


@bp.route('/api/clusters/<cluster_id>/ha/status', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_ha_status_detailed(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_ha_status())


@bp.route('/api/clusters/<cluster_id>/ha/enable', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['ha.config'])
def enable_ha(cluster_id):
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    mgr.start_ha_monitor()
    mgr.config.ha_enabled = True
    save_config()
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ha.enabled', f"HA enabled for cluster {mgr.config.name}", cluster=mgr.config.name)
    
    return jsonify({
        'message': 'High Availability aktiviert',
        'status': mgr.get_ha_status()
    })


@bp.route('/api/clusters/<cluster_id>/ha/disable', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['ha.config'])
def disable_ha(cluster_id):
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    mgr.stop_ha_monitor()
    mgr.config.ha_enabled = False
    save_config()
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.disabled', f"High Availability disabled for cluster {mgr.config.name}", cluster=mgr.config.name)
    
    return jsonify({
        'message': 'High Availability disabled',
        'status': mgr.get_ha_status()
    })


@bp.route('/api/clusters/<cluster_id>/ha/config', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_ha_config(cluster_id):
    """Update HA configuration including split-brain prevention settings"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    # Update HA config
    if 'quorum_enabled' in data:
        manager.ha_config['quorum_enabled'] = data['quorum_enabled']
    if 'quorum_hosts' in data:
        manager.ha_config['quorum_hosts'] = data['quorum_hosts']
    if 'quorum_gateway' in data:
        manager.ha_config['quorum_gateway'] = data['quorum_gateway']
    if 'quorum_required_votes' in data:
        manager.ha_config['quorum_required_votes'] = data['quorum_required_votes']
    if 'self_fence_enabled' in data:
        manager.ha_config['self_fence_enabled'] = data['self_fence_enabled']
    if 'watchdog_enabled' in data:
        manager.ha_config['watchdog_enabled'] = data['watchdog_enabled']
    if 'verify_network' in data:
        manager.ha_config['verify_network_before_recovery'] = data['verify_network']
    if 'recovery_delay' in data:
        manager.ha_config['recovery_delay'] = data['recovery_delay']
    if 'failure_threshold' in data:
        manager.ha_failure_threshold = data['failure_threshold']
    
    # 2-Node Cluster Mode - NS Jan 2026
    if 'two_node_mode' in data:
        manager.ha_config['two_node_mode'] = data['two_node_mode']
    if 'force_quorum_on_failure' in data:
        manager.ha_config['force_quorum_on_failure'] = data['force_quorum_on_failure']
    
    # Storage-based Split-Brain Protection - NS Jan 2026
    if 'storage_heartbeat_enabled' in data:
        manager.ha_config['storage_heartbeat_enabled'] = data['storage_heartbeat_enabled']
    
    if 'storage_heartbeat_path' in data:
        manager.ha_config['storage_heartbeat_path'] = data['storage_heartbeat_path']
        
        # Auto-enable storage heartbeat when path is provided
        if data['storage_heartbeat_path']:
            manager.ha_config['storage_heartbeat_enabled'] = True
            manager.ha_config['dual_network_mode'] = True
            
            # Auto-install node agents when storage path is configured
            def install_agents():
                try:
                    manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
                    manager.logger.info("[HA] AUTO-INSTALLING NODE AGENTS FOR STORAGE HEARTBEAT")
                    manager.logger.info(f"[HA] Storage path: {data['storage_heartbeat_path']}")
                    manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
                    results = manager._ha_install_agents_on_all_nodes()
                    success_count = sum(1 for v in results.values() if v)
                    manager.logger.info(f"[HA] ✓ Agent installation complete: {success_count}/{len(results)} nodes")
                except Exception as e:
                    manager.logger.error(f"[HA] ✗ Agent installation failed: {e}")
            
            threading.Thread(target=install_agents, daemon=True).start()
    
    if 'storage_heartbeat_timeout' in data:
        manager.ha_config['storage_heartbeat_timeout'] = data['storage_heartbeat_timeout']
    if 'poison_pill_enabled' in data:
        manager.ha_config['poison_pill_enabled'] = data['poison_pill_enabled']
    if 'strict_fencing' in data:
        manager.ha_config['strict_fencing'] = data['strict_fencing']
    
    # Enable/disable HA if specified
    if 'enabled' in data:
        if data['enabled'] and not manager.ha_enabled:
            manager.start_ha_monitor()
        elif not data['enabled'] and manager.ha_enabled:
            manager.stop_ha_monitor()
    
    # Save to config
    # Store HA settings in cluster config for persistence
    if not hasattr(manager.config, 'ha_settings'):
        manager.config.ha_settings = {}
    
    manager.config.ha_settings = {
        'quorum_enabled': manager.ha_config.get('quorum_enabled', True),
        'quorum_hosts': manager.ha_config.get('quorum_hosts', []),
        'quorum_gateway': manager.ha_config.get('quorum_gateway', ''),
        'quorum_required_votes': manager.ha_config.get('quorum_required_votes', 2),
        'self_fence_enabled': manager.ha_config.get('self_fence_enabled', True),
        'watchdog_enabled': manager.ha_config.get('watchdog_enabled', False),
        'verify_network': manager.ha_config.get('verify_network_before_recovery', True),
        'recovery_delay': manager.ha_config.get('recovery_delay', 30),
        'failure_threshold': manager.ha_failure_threshold,
        # 2-Node Cluster Mode
        'two_node_mode': manager.ha_config.get('two_node_mode', False),
        'force_quorum_on_failure': manager.ha_config.get('force_quorum_on_failure', False),
        # Storage-based Split-Brain Protection - NS Jan 2026
        'storage_heartbeat_enabled': manager.ha_config.get('storage_heartbeat_enabled', False),
        'storage_heartbeat_path': manager.ha_config.get('storage_heartbeat_path', ''),
        'storage_heartbeat_timeout': manager.ha_config.get('storage_heartbeat_timeout', 30),
        'poison_pill_enabled': manager.ha_config.get('poison_pill_enabled', True),
        'strict_fencing': manager.ha_config.get('strict_fencing', False),
    }
    
    save_config()
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.config_updated', f"HA configuration updated for cluster {manager.config.name}", cluster=manager.config.name)
    
    return jsonify({
        'message': 'HA-Konfiguration gespeichert',
        'status': manager.get_ha_status()
    })


def _save_ha_config_to_db(cluster_id: str, manager):
    """Helper to persist ha_config changes to database
    
    NS: Called after self-fence install/uninstall so status survives restart
    """
    try:
        db = get_db()
        cluster = db.get_cluster(cluster_id)
        if cluster:
            # Update ha_settings with current ha_config
            ha_settings = cluster.get('ha_settings', {})
            ha_settings['self_fence_installed'] = manager.ha_config.get('self_fence_installed', False)
            ha_settings['self_fence_nodes'] = manager.ha_config.get('self_fence_nodes', [])
            ha_settings['node_agent_installed'] = manager.ha_config.get('node_agent_installed', {})
            cluster['ha_settings'] = ha_settings
            db.save_cluster(cluster_id, cluster)
            logging.info(f"[HA] Persisted ha_config to database for {cluster_id}")
    except Exception as e:
        logging.error(f"[HA] Failed to persist ha_config: {e}")


@bp.route('/api/clusters/<cluster_id>/ha/install-self-fence', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def install_self_fence_agent(cluster_id):
    """Install self-fence agent on all cluster nodes"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    # Run installation in background
    def do_install():
        try:
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            manager.logger.info("[HA] INSTALLING SELF-FENCE AGENTS ON ALL NODES")
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            results = manager._ha_install_self_fence_on_all_nodes()
            success_count = sum(1 for v in results.values() if v)
            manager.logger.info(f"[HA] ✓ Self-fence installation complete: {success_count}/{len(results)} nodes")
            
            # Store installation status
            manager.ha_config['self_fence_installed'] = success_count > 0
            manager.ha_config['self_fence_nodes'] = [k for k, v in results.items() if v]
            
            # NS: Persist to database so it survives restart
            _save_ha_config_to_db(cluster_id, manager)
        except Exception as e:
            manager.logger.error(f"[HA] ✗ Self-fence installation failed: {e}")
    
    threading.Thread(target=do_install, daemon=True).start()
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.self_fence_install', f"Self-fence agent installation started for cluster {manager.config.name}", cluster=manager.config.name)
    
    return jsonify({
        'message': 'Self-fence agent installation started',
        'status': 'installing'
    })


@bp.route('/api/clusters/<cluster_id>/ha/uninstall-self-fence', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def uninstall_self_fence_agent(cluster_id):
    """Uninstall self-fence agent from all cluster nodes"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    # Run uninstallation in background
    def do_uninstall():
        try:
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            manager.logger.info("[HA] UNINSTALLING SELF-FENCE AGENTS FROM ALL NODES")
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            results = manager._ha_uninstall_self_fence_on_all_nodes()
            success_count = sum(1 for v in results.values() if v)
            manager.logger.info(f"[HA] ✓ Self-fence uninstallation complete: {success_count}/{len(results)} nodes")
            
            # Update status
            manager.ha_config['self_fence_installed'] = False
            manager.ha_config['self_fence_nodes'] = []
            
            # NS: Persist to database
            _save_ha_config_to_db(cluster_id, manager)
        except Exception as e:
            manager.logger.error(f"[HA] ✗ Self-fence uninstallation failed: {e}")
    
    threading.Thread(target=do_uninstall, daemon=True).start()
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.self_fence_uninstall', f"Self-fence agent uninstallation started for cluster {manager.config.name}", cluster=manager.config.name)
    
    return jsonify({
        'message': 'Self-fence agent uninstallation started',
        'status': 'uninstalling'
    })


@bp.route('/api/clusters/<cluster_id>/ha', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_ha_status(cluster_id):
    """Enable or disable HA for a cluster (legacy endpoint)"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    enable = data.get('enable', True)
    
    if enable:
        manager.start_ha_monitor()
        manager.config.ha_enabled = True
        save_config()
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'ha.enabled', f"High Availability enabled for cluster {manager.config.name}", cluster=manager.config.name)
        return jsonify({
            'message': 'High Availability aktiviert',
            'status': manager.get_ha_status()
        })
    else:
        manager.stop_ha_monitor()
        manager.config.ha_enabled = False
        save_config()
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'ha.disabled', f"High Availability disabled for cluster {manager.config.name}", cluster=manager.config.name)
        return jsonify({
            'message': 'High Availability disabled',
            'status': manager.get_ha_status()
        })


# Proxmox Native HA API Routes
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_proxmox_ha_resources(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_proxmox_ha_resources())


@bp.route('/api/clusters/<cluster_id>/proxmox-ha/groups', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_proxmox_ha_groups(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_proxmox_ha_groups())


# MK: Create HA Group
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/groups', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['ha.config'])
def create_proxmox_ha_group(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    group_name = data.get('group')
    nodes = data.get('nodes')
    
    if not group_name or not nodes:
        return jsonify({'error': 'group and nodes required'}), 400
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/ha/groups"
        
        payload = {
            'group': group_name,
            'nodes': nodes
        }
        if data.get('restricted'):
            payload['restricted'] = 1
        if data.get('nofailback'):
            payload['nofailback'] = 1
        if data.get('comment'):
            payload['comment'] = data['comment']
        
        resp = manager._api_post(url, data=payload)
        
        if resp.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ha.group_created', f"HA group '{group_name}' created", cluster=manager.config.name)
            return jsonify({'success': True})
        else:
            return jsonify({'error': resp.text}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# MK: Delete HA Group
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/groups/<group_name>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN], perms=['ha.config'])
def delete_proxmox_ha_group(cluster_id, group_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/ha/groups/{group_name}"
        
        resp = manager._api_delete(url)
        
        if resp.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ha.group_deleted', f"HA group '{group_name}' deleted", cluster=manager.config.name)
            return jsonify({'success': True})
        else:
            return jsonify({'error': resp.text}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['ha.config'])
def add_to_proxmox_ha(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    
    logging.debug(f"[HA] Add resource request: {data}")
    
    # MK: Support both sid format (vm:100) and separate vmid/type
    sid = data.get('sid', '').strip()
    if sid and ':' in sid:
        parts = sid.split(':')
        vm_type = parts[0]  # vm or ct
        vmid = parts[1]
    else:
        vmid = data.get('vmid')
        vm_type = data.get('type', 'vm')
    
    group = data.get('group')
    max_restart = data.get('max_restart', 1)
    max_relocate = data.get('max_relocate', 1)
    state = data.get('state', 'started')
    comment = data.get('comment', '')
    
    if not vmid:
        logging.warning(f"[HA] Add resource failed: no vmid/sid in request data: {data}")
        return jsonify({'error': 'vmid or sid required (format: vm:100 or ct:101)'}), 400
    
    result = mgr.add_vm_to_proxmox_ha(vmid, vm_type, group, max_restart, max_relocate, state, comment)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'ha.vm_added', f"{vm_type.upper()} {vmid} added to HA" + (f" (group: {group})" if group else ""), cluster=mgr.config.name)
        return jsonify(result)
    else:
        return jsonify(result), 400


@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources/<vm_type>:<int:vmid>', methods=['DELETE'])
@require_auth(perms=['ha.config'])
def remove_from_proxmox_ha(cluster_id, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.remove_vm_from_proxmox_ha(vmid, vm_type)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'ha.vm_removed', f"{vm_type.upper()} {vmid} removed from HA", cluster=mgr.config.name)
        return jsonify(result)
    else:
        return jsonify(result), 400


# MK: Alternative DELETE endpoint that accepts full sid string like "vm:100"
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources/<sid>', methods=['DELETE'])
@require_auth(perms=['ha.config'])
def remove_from_proxmox_ha_by_sid(cluster_id, sid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    # Parse sid (vm:100 or ct:101)
    if ':' in sid:
        vm_type, vmid = sid.split(':', 1)
        try:
            vmid = int(vmid)
        except ValueError:
            return jsonify({'error': f'Invalid VMID in sid: {sid}'}), 400
    else:
        return jsonify({'error': f'Invalid sid format: {sid}. Expected vm:VMID or ct:VMID'}), 400
    
    result = mgr.remove_vm_from_proxmox_ha(vmid, vm_type)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'ha.vm_removed', f"{vm_type.upper()} {vmid} removed from HA", cluster=mgr.config.name)
        return jsonify(result)
    else:
        return jsonify(result), 400



