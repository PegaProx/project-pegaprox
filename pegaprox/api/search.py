# -*- coding: utf-8 -*-
"""search, favorites & tags routes - split from monolith dec 2025, NS/LW"""

import os
import json
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.audit import log_audit

from pegaprox.utils.rbac import (
    has_permission, filter_clusters_for_user, user_can_access_vm,
)
from pegaprox.api.helpers import get_connected_manager

bp = Blueprint('search', __name__)

# ============================================

# User favorites storage
FAVORITES_FILE = os.path.join(CONFIG_DIR, 'user_favorites.json')  # Legacy

def load_favorites():
    """Load user favorites from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM user_favorites')
        
        favorites = {}
        for row in cursor.fetchall():
            username = row['username']
            if username not in favorites:
                favorites[username] = []
            favorites[username].append({
                'cluster_id': row['cluster_id'],
                'vmid': row['vmid'],
                'vm_type': row['vm_type'],
                'vm_name': row['vm_name'],
            })
        
        return favorites
    except Exception as e:
        logging.error(f"Error loading favorites from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(FAVORITES_FILE):
                with open(FAVORITES_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
    return {}


def save_favorites(favorites):
    """Save user favorites to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Clear existing favorites
        cursor.execute('DELETE FROM user_favorites')
        
        now = datetime.now().isoformat()
        for username, user_favs in favorites.items():
            for fav in user_favs:
                cursor.execute('''
                    INSERT INTO user_favorites 
                    (username, cluster_id, vmid, vm_type, vm_name, added_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    fav.get('cluster_id'),
                    fav.get('vmid'),
                    fav.get('vm_type', fav.get('type', '')),
                    fav.get('vm_name', fav.get('name', '')),
                    now
                ))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving favorites: {e}")


@bp.route('/api/global/search', methods=['GET'])
@require_auth()
def global_search():
    """Search across all clusters for VMs, containers, and nodes
    
    Query params:
    - q: search query (name, vmid, ip, node name, tags)
    - type: filter by type (vm, ct, node, all) - default: all
    
    Also supports prefix filters like tag:web, node:pve1, ip:192.168, status:running
    You can combine tags with comma: tag:web,production (AND logic)
    
    LW: This is one of the most used features - people love being able
    to find a VM without knowing which cluster its on.
    NS: added tag search in Feb 2026, users kept asking for it
    MK: Claude + ChatGPT helped optimize the search logic and prefix filters
    """
    raw_query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all').lower()
    
    if not raw_query or len(raw_query) < 2:
        return jsonify({'error': 'Search query must be at least 2 characters'}), 400
    
    # MK: prefix filters - type tag:xxx to search only tags, node:xxx for nodes etc
    prefix_filter = None
    query = raw_query.lower()
    for prefix in ['tag:', 'node:', 'ip:', 'status:']:
        if query.startswith(prefix):
            prefix_filter = prefix[:-1]  # 'tag', 'node', 'ip', 'status'
            query = query[len(prefix):].strip()
            break
    
    if not query:
        return jsonify({'error': 'Search query is empty after prefix'}), 400
    
    # LW: you can do tag:web,production to filter by multiple tags at once
    tag_queries = [t.strip() for t in query.split(',')] if prefix_filter == 'tag' else [query]
    
    results = []
    user = request.session.get('user', '')
    users_db = load_users()
    user_data = users_db.get(user, {})
    user_data['username'] = user
    is_admin = user_data.get('role') == ROLE_ADMIN
    
    # Get user's accessible clusters (respect RBAC)
    user_clusters = user_data.get('clusters', [])
    
    # MK: collect tags for the autocomplete dropdown in the frontend
    all_tags = set()
    
    for cluster_id, mgr in cluster_managers.items():
        # Check cluster access - NS: important for multi-tenant setups
        if not is_admin and user_clusters and cluster_id not in user_clusters:
            continue
        
        if not mgr.is_connected:
            continue
        
        cluster_name = mgr.config.name or cluster_id
        
        # Search VMs and Containers
        if search_type in ['all', 'vm', 'ct']:
            try:
                resources = mgr.get_vm_resources()
                for r in resources:
                    name = (r.get('name') or '').lower()
                    vmid = str(r.get('vmid', ''))
                    node = (r.get('node') or '').lower()
                    ip = (r.get('ip') or '').lower()
                    tags_str = (r.get('tags') or '').lower()
                    tags_list = [t.strip() for t in tags_str.split(';') if t.strip()] if tags_str else []
                    status = (r.get('status') or '').lower()
                    
                    # collect tags for autocomplete
                    for t in tags_list:
                        all_tags.add(t)
                    
                    # Match based on prefix filter or global search
                    matched = False
                    match_field = None
                    
                    if prefix_filter == 'tag':
                        # All tag queries must match (AND logic for multi-tag)
                        matched = all(any(tq in tag for tag in tags_list) for tq in tag_queries)
                        if matched:
                            match_field = 'tag'
                    elif prefix_filter == 'node':
                        matched = query in node
                        if matched:
                            match_field = 'node'
                    elif prefix_filter == 'ip':
                        matched = query in ip
                        if matched:
                            match_field = 'ip'
                    elif prefix_filter == 'status':
                        matched = status.startswith(query)
                        if matched:
                            match_field = 'status'
                    else:
                        # Global search: match name, vmid, node, ip, AND tags
                        if query in name:
                            matched, match_field = True, 'name'
                        elif query == vmid or query in vmid:
                            matched, match_field = True, 'vmid'
                        elif query in node:
                            matched, match_field = True, 'node'
                        elif query in ip:
                            matched, match_field = True, 'ip'
                        elif any(query in tag for tag in tags_list):
                            matched, match_field = True, 'tag'
                    
                    if not matched:
                        continue
                    
                    # Type filter
                    vm_type = r.get('type', 'qemu')
                    if search_type == 'vm' and vm_type != 'qemu':
                        continue
                    if search_type == 'ct' and vm_type != 'lxc':
                        continue
                    
                    results.append({
                        'type': 'vm' if vm_type == 'qemu' else 'ct',
                        'cluster_id': cluster_id,
                        'cluster_name': cluster_name,
                        'vmid': r.get('vmid'),
                        'name': r.get('name'),
                        'node': r.get('node'),
                        'status': r.get('status'),
                        'ip': r.get('ip'),
                        'tags': r.get('tags', ''),
                        'cpu': r.get('cpu'),
                        'mem': r.get('mem'),
                        'maxmem': r.get('maxmem'),
                        'match_field': match_field,
                    })
            except Exception as e:
                logging.debug(f"Error searching cluster {cluster_id}: {e}")
        
        # Search Nodes
        if search_type in ['all', 'node'] and prefix_filter in [None, 'node']:
            try:
                for node_name, node_data in (mgr.nodes or {}).items():
                    if query in node_name.lower():
                        results.append({
                            'type': 'node',
                            'cluster_id': cluster_id,
                            'cluster_name': cluster_name,
                            'name': node_name,
                            'status': node_data.get('status', 'unknown'),
                            'cpu': node_data.get('cpu'),
                            'mem': node_data.get('mem'),
                            'maxmem': node_data.get('maxmem'),
                            'match_field': 'name',
                        })
            except Exception as e:
                logging.debug(f"Error searching nodes in {cluster_id}: {e}")
    
    # Sort by relevance (exact matches first, then partial)
    def sort_key(r):
        name = (r.get('name') or str(r.get('vmid', ''))).lower()
        mf = r.get('match_field', '')
        # Exact name matches first, then name prefix, then tag matches, then rest
        if name == query:
            return (0, name)
        elif name.startswith(query):
            return (1, name)
        elif mf == 'tag':
            return (2, name)
        elif mf == 'vmid':
            return (3, name)
        else:
            return (4, name)
    
    results.sort(key=sort_key)
    
    # NS: show matching tags as clickable suggestions in the UI
    tag_suggestions = sorted([t for t in all_tags if query in t])[:10] if not prefix_filter or prefix_filter == 'tag' else []
    
    return jsonify({
        'query': raw_query,
        'count': len(results),
        'results': results[:100],  # Limit to 100 results
        'tag_suggestions': tag_suggestions,
    })


@bp.route('/api/global/summary', methods=['GET'])
@require_auth()
def global_summary():
    """Get summary statistics across all accessible clusters
    
    Returns aggregate stats for a datacenter-level overview
    """
    try:
        user = request.session.get('user', '')
        users_db = load_users()
        user_data = users_db.get(user, {})
        is_admin = user_data.get('role') == ROLE_ADMIN
        user_clusters = user_data.get('clusters', [])
        
        summary = {
            'clusters': {
                'total': 0,
                'online': 0,
                'offline': 0
            },
            'nodes': {
                'total': 0,
                'online': 0,
                'offline': 0
            },
            'vms': {
                'total': 0,
                'running': 0,
                'stopped': 0,
                'paused': 0
            },
            'containers': {
                'total': 0,
                'running': 0,
                'stopped': 0
            },
            'resources': {
                'cpu_total': 0,
                'cpu_used': 0,
                'mem_total': 0,
                'mem_used': 0,
                'storage_total': 0,
                'storage_used': 0
            },
            'by_cluster': []
        }
        
        for cluster_id, mgr in cluster_managers.items():
            # Check cluster access
            if not is_admin and user_clusters and cluster_id not in user_clusters:
                continue
            
            summary['clusters']['total'] += 1
            
            cluster_stats = {
                'id': cluster_id,
                'name': getattr(mgr.config, 'name', None) or cluster_id,
                'online': mgr.is_connected if mgr else False,
                'nodes': 0,
                'vms': 0,
                'containers': 0
            }
            
            if mgr and mgr.is_connected:
                summary['clusters']['online'] += 1
                
                # Count nodes - safely handle None
                nodes = getattr(mgr, 'nodes', None) or {}
                for node_name, node_data in nodes.items():
                    if not node_data:
                        continue
                    summary['nodes']['total'] += 1
                    cluster_stats['nodes'] += 1
                    
                    if node_data.get('status') == 'online':
                        summary['nodes']['online'] += 1
                        # Aggregate resources from online nodes
                        summary['resources']['cpu_total'] += node_data.get('maxcpu', 0) or 0
                        cpu_val = node_data.get('cpu', 0) or 0
                        maxcpu_val = node_data.get('maxcpu', 0) or 0
                        summary['resources']['cpu_used'] += cpu_val * maxcpu_val
                        summary['resources']['mem_total'] += node_data.get('maxmem', 0) or 0
                        summary['resources']['mem_used'] += node_data.get('mem', 0) or 0
                    else:
                        summary['nodes']['offline'] += 1
                
                # Count VMs
                try:
                    resources = mgr.get_vm_resources() or []
                    for r in resources:
                        if not r:
                            continue
                        if r.get('type') == 'qemu':
                            summary['vms']['total'] += 1
                            cluster_stats['vms'] += 1
                            status = (r.get('status') or '').lower()
                            if status == 'running':
                                summary['vms']['running'] += 1
                            elif status == 'paused':
                                summary['vms']['paused'] += 1
                            else:
                                summary['vms']['stopped'] += 1
                        else:
                            summary['containers']['total'] += 1
                            cluster_stats['containers'] += 1
                            status = (r.get('status') or '').lower()
                            if status == 'running':
                                summary['containers']['running'] += 1
                            else:
                                summary['containers']['stopped'] += 1
                except Exception as e:
                    logging.warning(f"Error getting VM resources for {cluster_id}: {e}")
            else:
                summary['clusters']['offline'] += 1
            
            summary['by_cluster'].append(cluster_stats)
        
        return jsonify(summary)
    except Exception as e:
        logging.error(f"global_summary error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/user/favorites', methods=['GET'])
@require_auth()
def get_favorites():
    """Get user's favorite/pinned VMs and nodes"""
    user = request.session.get('user', '')
    favorites = load_favorites()
    
    user_favs = favorites.get(user, {
        'vms': [],      # [{cluster_id, vmid, type}]
        'nodes': [],    # [{cluster_id, node}]
        'clusters': []  # [cluster_id]
    })
    
    return jsonify(user_favs)


@bp.route('/api/user/favorites', methods=['POST'])
@require_auth()
def update_favorites():
    """Add or remove a favorite
    
    Body:
    - action: 'add' or 'remove'
    - type: 'vm', 'node', or 'cluster'
    - cluster_id: Cluster ID
    - vmid: (for vm) VM ID
    - vm_type: (for vm) 'qemu' or 'lxc'
    - node: (for node) Node name
    """
    user = request.session.get('user', '')
    data = request.json or {}
    
    action = data.get('action', 'add')
    fav_type = data.get('type')
    cluster_id = data.get('cluster_id')
    
    if not fav_type or not cluster_id:
        return jsonify({'error': 'type and cluster_id required'}), 400
    
    favorites = load_favorites()
    
    if user not in favorites:
        favorites[user] = {'vms': [], 'nodes': [], 'clusters': []}
    
    user_favs = favorites[user]
    
    if fav_type == 'vm':
        vmid = data.get('vmid')
        vm_type = data.get('vm_type', 'qemu')
        if not vmid:
            return jsonify({'error': 'vmid required for vm favorites'}), 400
        
        fav_entry = {'cluster_id': cluster_id, 'vmid': vmid, 'type': vm_type}
        
        if action == 'add':
            # Check if already exists
            if not any(f['cluster_id'] == cluster_id and f['vmid'] == vmid for f in user_favs['vms']):
                user_favs['vms'].append(fav_entry)
        else:
            user_favs['vms'] = [f for f in user_favs['vms'] 
                               if not (f['cluster_id'] == cluster_id and f['vmid'] == vmid)]
    
    elif fav_type == 'node':
        node = data.get('node')
        if not node:
            return jsonify({'error': 'node required for node favorites'}), 400
        
        fav_entry = {'cluster_id': cluster_id, 'node': node}
        
        if action == 'add':
            if not any(f['cluster_id'] == cluster_id and f['node'] == node for f in user_favs['nodes']):
                user_favs['nodes'].append(fav_entry)
        else:
            user_favs['nodes'] = [f for f in user_favs['nodes']
                                 if not (f['cluster_id'] == cluster_id and f['node'] == node)]
    
    elif fav_type == 'cluster':
        if action == 'add':
            if cluster_id not in user_favs['clusters']:
                user_favs['clusters'].append(cluster_id)
        else:
            user_favs['clusters'] = [c for c in user_favs['clusters'] if c != cluster_id]
    
    else:
        return jsonify({'error': 'Invalid type. Use vm, node, or cluster'}), 400
    
    save_favorites(favorites)
    
    return jsonify({'success': True, 'favorites': user_favs})


# ============================================
# VM Tags / Labels
# should have added this sooner tbh
# Tags are stored per-cluster, per-VM in a simple JSON file
# ============================================

TAGS_FILE = os.path.join(CONFIG_DIR, 'vm_tags.json')  # Legacy

def load_vm_tags():
    """Load VM tags from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM vm_tags')
        
        tags = {}
        for row in cursor.fetchall():
            cluster_id = row['cluster_id']
            vmid = str(row['vmid'])
            
            if cluster_id not in tags:
                tags[cluster_id] = {}
            if vmid not in tags[cluster_id]:
                tags[cluster_id][vmid] = []
            
            tags[cluster_id][vmid].append({
                'name': row['tag_name'],
                'color': row['tag_color'] or TAG_COLORS[hash(row['tag_name']) % len(TAG_COLORS)]
            })
        
        return tags
    except Exception as e:
        logging.error(f"Error loading VM tags from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(TAGS_FILE):
                with open(TAGS_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
    return {}


def save_vm_tags(tags):
    """Save VM tags to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Clear existing tags
        cursor.execute('DELETE FROM vm_tags')
        
        # Insert all tags
        for cluster_id, vms in tags.items():
            for vmid, vm_tags in vms.items():
                for tag in vm_tags:
                    tag_name = tag.get('name', tag) if isinstance(tag, dict) else tag
                    tag_color = tag.get('color', '') if isinstance(tag, dict) else ''
                    
                    cursor.execute('''
                        INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color)
                        VALUES (?, ?, ?, ?)
                    ''', (cluster_id, int(vmid), tag_name, tag_color))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving VM tags: {e}")

# LW: Global tag colors - keeps things consistent
TAG_COLORS = [
    '#ef4444', '#f97316', '#eab308', '#22c55e', '#14b8a6', 
    '#3b82f6', '#8b5cf6', '#ec4899', '#6b7280', '#78716c'
]

@bp.route('/api/clusters/<cluster_id>/tags', methods=['GET'])
@require_auth()
def get_cluster_tags(cluster_id):
    """Get all tags used in this cluster
    
    Returns unique tags with their colors and usage count
    """
    tags_db = load_vm_tags()
    cluster_tags = tags_db.get(cluster_id, {})
    
    # Count tag usage
    tag_counts = {}
    for vm_key, vm_tags in cluster_tags.items():
        for tag in vm_tags:
            tag_name = tag.get('name', tag) if isinstance(tag, dict) else tag
            if tag_name not in tag_counts:
                tag_counts[tag_name] = {
                    'name': tag_name,
                    'color': tag.get('color', TAG_COLORS[hash(tag_name) % len(TAG_COLORS)]) if isinstance(tag, dict) else TAG_COLORS[hash(tag_name) % len(TAG_COLORS)],
                    'count': 0
                }
            tag_counts[tag_name]['count'] += 1
    
    return jsonify(list(tag_counts.values()))


@bp.route('/api/clusters/<cluster_id>/vms/<vmid>/tags', methods=['GET'])
@require_auth()
def get_vm_tags(cluster_id, vmid):
    """Get tags for a specific VM"""
    tags_db = load_vm_tags()
    cluster_tags = tags_db.get(cluster_id, {})
    vm_tags = cluster_tags.get(str(vmid), [])
    
    return jsonify(vm_tags)


@bp.route('/api/clusters/<cluster_id>/vms/<vmid>/tags', methods=['POST'])
@require_auth(perms=['vm.config'])
def update_vm_tags(cluster_id, vmid):
    """Add or update tags for a VM
    
    Body:
    - tags: Array of tag objects [{name: 'prod', color: '#ef4444'}, ...]
    
    Or simple add:
    - tag: Single tag name to add
    - color: Optional color for the tag
    """
    data = request.json or {}
    tags_db = load_vm_tags()
    
    if cluster_id not in tags_db:
        tags_db[cluster_id] = {}
    
    vm_key = str(vmid)
    
    # Full replacement
    if 'tags' in data:
        tags_db[cluster_id][vm_key] = data['tags']
    # Single tag add
    elif 'tag' in data:
        tag_name = data['tag'].strip()
        if not tag_name:
            return jsonify({'error': 'Tag name required'}), 400
        
        current_tags = tags_db[cluster_id].get(vm_key, [])
        
        # Check if tag already exists
        existing = next((t for t in current_tags if (t.get('name') if isinstance(t, dict) else t) == tag_name), None)
        if not existing:
            new_tag = {
                'name': tag_name,
                'color': data.get('color', TAG_COLORS[hash(tag_name) % len(TAG_COLORS)])
            }
            current_tags.append(new_tag)
            tags_db[cluster_id][vm_key] = current_tags
    
    save_vm_tags(tags_db)
    
    user = request.session.get('user', 'system')
    cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
    log_audit(user, 'vm.tags_updated', f"Updated tags for VM {vmid}", cluster=cluster_name)
    
    return jsonify({
        'success': True,
        'tags': tags_db[cluster_id].get(vm_key, [])
    })


@bp.route('/api/clusters/<cluster_id>/vms/<vmid>/tags/<tag_name>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def remove_vm_tag(cluster_id, vmid, tag_name):
    """Remove a tag from a VM"""
    tags_db = load_vm_tags()
    
    if cluster_id not in tags_db:
        return jsonify({'error': 'No tags for this cluster'}), 404
    
    vm_key = str(vmid)
    if vm_key not in tags_db[cluster_id]:
        return jsonify({'error': 'No tags for this VM'}), 404
    
    # Remove the tag
    current_tags = tags_db[cluster_id][vm_key]
    tags_db[cluster_id][vm_key] = [
        t for t in current_tags 
        if (t.get('name') if isinstance(t, dict) else t) != tag_name
    ]
    
    # Cleanup empty entries
    if not tags_db[cluster_id][vm_key]:
        del tags_db[cluster_id][vm_key]
    
    save_vm_tags(tags_db)
    
    return jsonify({'success': True})


@bp.route('/api/tags/search', methods=['GET'])
@require_auth()
def search_vms_by_tag():
    """Search VMs across all clusters by tag
    
    Query params:
    - tag: Tag name to search for
    - cluster_id: Optional - limit to specific cluster
    """
    tag_name = request.args.get('tag', '').strip()
    filter_cluster = request.args.get('cluster_id')
    
    if not tag_name:
        return jsonify({'error': 'Tag parameter required'}), 400
    
    tags_db = load_vm_tags()
    results = []
    
    user = request.session.get('user', '')
    users_db = load_users()
    user_data = users_db.get(user, {})
    is_admin = user_data.get('role') == ROLE_ADMIN
    user_clusters = user_data.get('clusters', [])
    
    for cluster_id, cluster_tags in tags_db.items():
        # Check access
        if not is_admin and user_clusters and cluster_id not in user_clusters:
            continue
        if filter_cluster and cluster_id != filter_cluster:
            continue
        
        mgr = cluster_managers.get(cluster_id)
        cluster_name = mgr.config.name if mgr else cluster_id
        
        for vm_key, vm_tags in cluster_tags.items():
            # Check if this VM has the tag
            has_tag = any(
                (t.get('name') if isinstance(t, dict) else t) == tag_name 
                for t in vm_tags
            )
            
            if has_tag:
                # Try to get VM details
                vm_info = {'vmid': vm_key, 'cluster_id': cluster_id, 'cluster_name': cluster_name}
                
                if mgr and mgr.is_connected:
                    try:
                        resources = mgr.get_vm_resources()
                        vm_data = next((r for r in resources if str(r.get('vmid')) == vm_key), None)
                        if vm_data:
                            vm_info.update({
                                'name': vm_data.get('name'),
                                'node': vm_data.get('node'),
                                'status': vm_data.get('status'),
                                'type': vm_data.get('type')
                            })
                    except:
                        pass
                
                vm_info['tags'] = vm_tags
                results.append(vm_info)
    
    return jsonify(results)


# ============================================

