# -*- coding: utf-8 -*-
"""storage management & ESXi import routes - split from monolith dec 2025, NS"""

import os
import json
import time
import logging
import threading
import uuid
import hashlib
import re
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.core.cache import APIRateLimiter, StorageDataCache
from pegaprox.api.helpers import get_connected_manager, check_cluster_access
from pegaprox.utils.ssh import get_paramiko, _ssh_track_connection
from pegaprox import globals as _g

bp = Blueprint('storage', __name__)

# ============================================
# NS: ESXi Integration - Dec 2025
# Uses native Proxmox ESXi storage import feature (PVE 8+)
# Much better than custom implementation - lets proxmox handle the heavy lifting
# ============================================

# Track ESXi storages we've added to proxmox clusters
# format: { cluster_id: { storage_id: { host, username, storage_name } } }
esxi_storages = {}

ESXI_CONFIG_FILE = os.path.join(CONFIG_DIR, 'esxi_storages.json')

def load_esxi_config():
    """Load ESXi storage config from SQLite database
    
    LW: this was added for vmware migration support
    useful for vmware to proxmox migrations
    NS: migrated to sqlite jan 2026
    """
    global esxi_storages
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM esxi_storages WHERE enabled = 1')
        
        esxi_storages = {}
        for row in cursor.fetchall():
            try:
                config = json.loads(row['config'] or '{}')
                cluster_id = config.get('cluster_id', 'default')
                storage_id = row['name']
                
                if cluster_id not in esxi_storages:
                    esxi_storages[cluster_id] = {}
                
                esxi_storages[cluster_id][storage_id] = {
                    'host': row['host'],
                    'username': row['username'],
                    'datastore': row['datastore'],
                    'storage_name': storage_id,
                    **config
                }
            except:
                pass  # corrupted entries happen sometimes
        
    except Exception as e:
        logging.debug(f"Loading ESXi config from DB: {e}")
        # Fallback to JSON for backwards compat
        try:
            if os.path.exists(ESXI_CONFIG_FILE):
                with open(ESXI_CONFIG_FILE, 'r') as f:
                    esxi_storages = json.load(f)
        except:
            esxi_storages = {}

def save_esxi_config():
    """Save ESXi storage config to SQLite database
    
    NS: no passwords stored here, those are handled separately with encryption
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        for cluster_id, storages in esxi_storages.items():
            for storage_id, info in storages.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO esxi_storages 
                    (name, host, username, datastore, enabled, config)
                    VALUES (?, ?, ?, ?, 1, ?)
                ''', (
                    storage_id,
                    info.get('host', ''),
                    info.get('username', ''),
                    info.get('datastore', ''),
                    json.dumps({'cluster_id': cluster_id, **{k:v for k,v in info.items() if k not in ['host', 'username', 'datastore']}})
                ))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Couldn't save ESXi config to DB: {e}")

load_esxi_config()


@bp.route('/api/clusters/<cluster_id>/esxi-hosts', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_esxi_hosts(cluster_id):
    """Get all ESXi storages configured for this cluster

    MK: Returns the esxi storages we've added to proxmox, not direct connections
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    hosts = esxi_storages.get(cluster_id, {})
    
    result = []
    for storage_id, info in hosts.items():
        # check if storage is actualy online in proxmox
        connected = False
        try:
            # LW: query proxmox to see if the esxi storage is working
            storage_status = mgr._api_get(
                f"https://{mgr.host}:8006/api2/json/storage/{storage_id}"
            )
            if storage_status and storage_status.status_code == 200:
                connected = True
        except:
            pass
        
        result.append({
            'id': storage_id,
            'host': info.get('host', ''),
            'connected': connected,
            'storage_name': info.get('storage_name', storage_id)
        })
    
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/esxi-hosts', methods=['POST'])
@require_auth(perms=['admin.cluster'])
def connect_esxi_host(cluster_id):
    """Add ESXi host as Proxmox storage

    NS: This registers the ESXi as a storage in Proxmox using the native import feature
    Way more reliable than trying to do it ourselves with pyvmomi
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    
    host = data.get('host', '').strip()
    username = data.get('username', 'root')
    password = data.get('password', '')
    skip_verify = data.get('skip_cert_verification', True)
    
    if not host or not password:
        return jsonify({'error': 'Host and password required'}), 400
    
    # generate storage name from host
    # MK: proxmox storage names can't have dots so we replace them
    storage_name = 'esxi-' + host.replace('.', '-').replace(':', '-')[:20]
    
    try:
        # Add ESXi as storage via Proxmox API
        # this is what the GUI does when you add an ESXi storage
        storage_data = {
            'storage': storage_name,
            'type': 'esxi',
            'server': host,
            'username': username,
            'password': password,
            'content': 'import',  # only for importing VMs
        }
        
        if skip_verify:
            storage_data['skip-cert-verification'] = 1
        
        response = mgr._api_post(
            f"https://{mgr.host}:8006/api2/json/storage",
            data=storage_data
        )
        
        if response.status_code not in [200, 201]:
            # might already exist or other error
            err_text = response.text
            if 'already exists' in err_text.lower():
                logging.info(f"[ESXI] Storage {storage_name} already exists, reusing")
            else:
                logging.error(f"[ESXI] Failed to add storage: {err_text}")
                return jsonify({'error': f'Failed to add ESXi storage: {err_text}'}), 500
        
        # store in our config
        if cluster_id not in esxi_storages:
            esxi_storages[cluster_id] = {}
        
        storage_id = hashlib.md5(host.encode()).hexdigest()[:8]
        esxi_storages[cluster_id][storage_id] = {
            'host': host,
            'username': username,
            'storage_name': storage_name
            # no password stored
        }
        save_esxi_config()
        
        usr = request.session.get('user', 'system')
        log_audit(usr, 'esxi.storage_added', f"Added ESXi storage: {host} as {storage_name}")
        
        logging.info(f"[ESXI] Successfully added ESXi storage {storage_name} for {host}")
        
        return jsonify({
            'success': True,
            'id': storage_id,
            'storage_name': storage_name
        })
        
    except Exception as e:
        logging.error(f"[ESXI] Error adding storage: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/esxi-hosts/<host_id>', methods=['DELETE'])
@require_auth(perms=['admin.cluster'])
def disconnect_esxi_host(cluster_id, host_id):
    """Remove ESXi storage from Proxmox"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    hosts = esxi_storages.get(cluster_id, {})
    
    if host_id not in hosts:
        return jsonify({'error': 'ESXi storage not found'}), 404
    
    storage_name = hosts[host_id].get('storage_name', '')
    host = hosts[host_id].get('host', '')
    
    try:
        # remove storage from proxmox
        if storage_name:
            response = mgr._api_delete(
                f"https://{mgr.host}:8006/api2/json/storage/{storage_name}"
            )
            # dont care too much if it fails, maybe already removed
            if response.status_code not in [200, 404]:
                logging.warning(f"[ESXI] Storage removal returned {response.status_code}")
    except Exception as e:
        logging.warning(f"[ESXI] Error removing storage: {e}")
    
    # remove from our config either way
    del esxi_storages[cluster_id][host_id]
    save_esxi_config()
    
    usr = request.session.get('user', 'system')
    log_audit(usr, 'esxi.storage_removed', f"Removed ESXi storage: {host}")
    
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/esxi-hosts/<host_id>/vms', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_esxi_vms(cluster_id, host_id):
    """Get VMs from ESXi host via Proxmox storage API

    LW: This queries proxmox which queries esxi - we dont talk to esxi directly
    Much cleaner and handles auth/rate limiting for us
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    hosts = esxi_storages.get(cluster_id, {})
    
    if host_id not in hosts:
        return jsonify({'error': 'ESXi storage not found'}), 404
    
    storage_name = hosts[host_id].get('storage_name', '')
    if not storage_name:
        return jsonify({'error': 'Storage name not configured'}), 400
    
    try:
        # get a node to query from (any node works for shared storage queries)
        host = mgr.current_host or mgr.config.host
        nodes_resp = mgr._api_get(f"https://{host}:8006/api2/json/nodes")
        nodes = []
        if nodes_resp.status_code == 200:
            nodes = [n['node'] for n in nodes_resp.json().get('data', [])]
        
        if not nodes:
            return jsonify({'error': 'No nodes available'}), 500
        
        node = nodes[0]
        
        # query storage content from proxmox
        # NS: this returns the VMs available for import
        response = mgr._api_get(
            f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_name}/content"
        )
        
        if response.status_code != 200:
            logging.error(f"[ESXI] Failed to get storage content: {response.text}")
            return jsonify({'error': 'Failed to get VM list from ESXi'}), 500
        
        content = response.json().get('data', [])
        
        vms = []
        for item in content:
            # each item is a VM that can be imported
            volid = item.get('volid', '')
            
            # try to get more details via import-metadata
            vm_info = {
                'id': volid,
                'name': item.get('name', volid.split('/')[-1] if '/' in volid else volid),
                'volid': volid,
                'power_state': 'unknown',  # proxmox doesnt tell us this directly
                'guest_os': 'Unknown',
                'num_cpu': 0,
                'memory_mb': 0
            }
            
            # MK: try to get import metadata for more details
            try:
                meta_resp = mgr._api_get(
                    f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_name}/import-metadata",
                    params={'volume': volid}
                )
                if meta_resp.status_code == 200:
                    meta = meta_resp.json().get('data', {})
                    
                    # parse the create-args for hardware info
                    create_args = meta.get('create-args', {})
                    vm_info['num_cpu'] = create_args.get('cores', create_args.get('sockets', 1))
                    vm_info['memory_mb'] = create_args.get('memory', 0)
                    vm_info['guest_os'] = create_args.get('ostype', 'Unknown')
                    
                    # use the proper name if available
                    if create_args.get('name'):
                        vm_info['name'] = create_args['name']
            except:
                pass  # metadata is optional, dont fail if we cant get it
            
            vms.append(vm_info)
        
        return jsonify(vms)
        
    except Exception as e:
        logging.error(f"[ESXI] Error listing VMs: {e}")
        return jsonify({'error': f'Failed to list VMs: {e}'}), 500



# ============================================
# Storage Balancing with Storage Clusters
# ============================================
# LW: Refactored Dec 2025 for enterprise scale (2000+ VMs, multiple clusters)
# NS: Added threading locks, rate limiting, caching - we had issues with race conditions

# Storage clusters configuration - saved per proxmox cluster
# Format: { cluster_id: { 'clusters': [ { id, name, storages: [], threshold, enabled, auto_balance, max_concurrent } ] } }
storage_clusters_config = {}
STORAGE_CLUSTERS_FILE = 'storage_clusters.json'

# Thread safety locks - MK: learned this the hard way with concurrent migrations
_storage_config_lock = threading.RLock()  # RLock allows same thread to acquire multiple times
_migration_lock = threading.Lock()
_cache_lock = threading.Lock()

# Track active auto-balance migrations to prevent duplicates
active_auto_migrations = {}

from pegaprox.core.cache import APIRateLimiter, StorageDataCache

# Global rate limiter instance
_api_rate_limiter = APIRateLimiter(calls_per_second=10, burst_limit=20)

# Global cache instance
_storage_cache = StorageDataCache()


def load_storage_clusters():
    """load storage cluster config from sqlite

    NS: storage clusters = ceph/gluster/etc pooled across nodes
    MK: migrated to sqlite jan 2026
    """
    global storage_clusters_config
    with _storage_config_lock:
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute('SELECT * FROM storage_clusters WHERE enabled = 1')
            
            storage_clusters_config = {}
            for row in cursor.fetchall():
                cluster_id = row['cluster_id']
                if cluster_id not in storage_clusters_config:
                    storage_clusters_config[cluster_id] = {'clusters': []}
                
                storage_clusters_config[cluster_id]['clusters'].append({
                    'name': row['name'],
                    'type': row['storage_type'],
                    'nodes': json.loads(row['nodes'] or '[]'),
                    **json.loads(row['config'] or '{}')
                })
        except Exception as e:
            logging.debug(f"Loading storage clusters from DB: {e}")
            # Fallback to JSON for backwards compat
            try:
                if os.path.exists(STORAGE_CLUSTERS_FILE):
                    with open(STORAGE_CLUSTERS_FILE, 'r') as f:
                        storage_clusters_config = json.load(f)
            except:
                storage_clusters_config = {}

def save_storage_clusters():
    """save storage cluster config to sqlite"""
    with _storage_config_lock:
        try:
            db = get_db()
            cursor = db.conn.cursor()
            
            for cluster_id, config in storage_clusters_config.items():
                clusters = config.get('clusters', [])
                for sc in clusters:
                    cursor.execute('''
                        INSERT OR REPLACE INTO storage_clusters 
                        (cluster_id, name, storage_type, nodes, config, enabled)
                        VALUES (?, ?, ?, ?, ?, 1)
                    ''', (
                        cluster_id,
                        sc.get('name', ''),
                        sc.get('type', 'ceph'),
                        json.dumps(sc.get('nodes', [])),
                        json.dumps({k:v for k,v in sc.items() if k not in ['name', 'type', 'nodes']})
                    ))
            
            db.conn.commit()
        except Exception as e:
            logging.error(f"Error saving storage clusters to DB: {e}")

# Load on startup
load_storage_clusters()


@bp.route('/api/clusters/<cluster_id>/storage-clusters', methods=['GET'])
@require_auth(perms=["storage.view"])
def get_storage_clusters(cluster_id):
    """Get all storage clusters for a proxmox cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    with _storage_config_lock:
        config = storage_clusters_config.get(cluster_id, {'clusters': []})
        # Return copy to prevent modification
        return jsonify(list(config.get('clusters', [])))


@bp.route('/api/clusters/<cluster_id>/storage-clusters', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_storage_cluster(cluster_id):
    """Create a new storage cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.json or {}
    name = data.get('name', '').strip()
    storages = data.get('storages', [])
    threshold = data.get('threshold', 20)
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if len(storages) < 2:
        return jsonify({'error': 'At least 2 storages required'}), 400
    
    with _storage_config_lock:
        if cluster_id not in storage_clusters_config:
            storage_clusters_config[cluster_id] = {'clusters': []}
        
        # Generate unique ID
        import uuid
        new_cluster = {
            'id': str(uuid.uuid4())[:8],
            'name': name,
            'storages': storages,
            'threshold': threshold,
            'enabled': True,
            'auto_balance': data.get('auto_balance', False),
            'max_concurrent': data.get('max_concurrent', 1),
            'check_interval': data.get('check_interval', 3600),  # seconds
            'last_auto_run': None,
            'created': datetime.now().isoformat()
        }
        
        storage_clusters_config[cluster_id]['clusters'].append(new_cluster)
        save_storage_clusters()
    
    # Invalidate cache for this cluster
    _storage_cache.invalidate(cluster_id)
    
    # NS: Fixed audit log call - was causing 500 error
    user = request.session.get('user', 'unknown')
    manager = cluster_managers.get(cluster_id)
    cluster_name = manager.config.name if manager else cluster_id
    log_audit(user, 'storage_cluster.created', f"Created storage cluster '{name}' with storages: {', '.join(storages)}", cluster=cluster_name)
    
    return jsonify(new_cluster), 201


@bp.route('/api/clusters/<cluster_id>/storage-clusters/<sc_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_storage_cluster(cluster_id, sc_id):
    """Update a storage cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    with _storage_config_lock:
        if cluster_id not in storage_clusters_config:
            return jsonify({'error': 'Storage cluster not found'}), 404
        
        clusters = storage_clusters_config[cluster_id].get('clusters', [])
        
        for i, sc in enumerate(clusters):
            if sc['id'] == sc_id:
                # Update fields
                if 'name' in data:
                    sc['name'] = data['name']
                if 'storages' in data:
                    sc['storages'] = data['storages']
                if 'threshold' in data:
                    sc['threshold'] = data['threshold']
                if 'enabled' in data:
                    sc['enabled'] = data['enabled']
                if 'auto_balance' in data:
                    sc['auto_balance'] = data['auto_balance']
                if 'max_concurrent' in data:
                    sc['max_concurrent'] = data['max_concurrent']
                if 'check_interval' in data:
                    sc['check_interval'] = data['check_interval']
                
                storage_clusters_config[cluster_id]['clusters'][i] = sc
                save_storage_clusters()
                
                # Invalidate cache
                _storage_cache.invalidate(cluster_id)
                
                user = request.session.get('user', 'unknown')
                log_audit(user, 'storage_cluster.updated', f"Updated storage cluster '{sc['name']}'", cluster=manager.config.name)
                
                return jsonify(sc)
    
    return jsonify({'error': 'Storage cluster not found'}), 404


@bp.route('/api/clusters/<cluster_id>/storage-clusters/<sc_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_storage_cluster(cluster_id, sc_id):
    """Delete a storage cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    with _storage_config_lock:
        if cluster_id not in storage_clusters_config:
            return jsonify({'error': 'Storage cluster not found'}), 404
        
        clusters = storage_clusters_config[cluster_id].get('clusters', [])
        for i, sc in enumerate(clusters):
            if sc['id'] == sc_id:
                deleted = clusters.pop(i)
                storage_clusters_config[cluster_id]['clusters'] = clusters
                save_storage_clusters()
                
                # Invalidate cache
                _storage_cache.invalidate(cluster_id)
                
                user = request.session.get('user', 'unknown')
                log_audit(user, 'storage_cluster.deleted', f"Deleted storage cluster '{deleted['name']}'", cluster=manager.config.name)
                
                return jsonify({'success': True})
    
    return jsonify({'error': 'Storage cluster not found'}), 404


@bp.route('/api/clusters/<cluster_id>/storage-clusters/<sc_id>/status', methods=['GET'])
@require_auth(perms=["storage.view"])
def get_storage_cluster_status(cluster_id, sc_id):
    """get status + rebalancing recommendations for a storage cluster - LW Dec 2025"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    # Find the storage cluster config    sc_config = None
    with _storage_config_lock:
        if cluster_id in storage_clusters_config:
            for sc in storage_clusters_config[cluster_id].get('clusters', []):
                if sc['id'] == sc_id:
                    sc_config = dict(sc)  # Copy to avoid holding lock
                    break
    
    if not sc_config:
        return jsonify({'error': 'Storage cluster not found'}), 404
    
    try:
        host = manager.current_host or manager.config.host
        
        # Try to get storage stats from cache first
        cache_key = f"storage_stats:{sc_id}"
        storage_stats, cache_hit = _storage_cache.get(cluster_id, cache_key)
        
        if not cache_hit:
            # Rate limit API calls
            if not _api_rate_limiter.acquire(cluster_id):
                return jsonify({'error': 'API rate limit exceeded, please try again'}), 429
            
            storage_stats = []
            nodes = []
            
            # Get nodes
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=10)
            if nodes_response.status_code == 200:
                nodes = [n['node'] for n in nodes_response.json().get('data', [])]
            
            # Get storage info from first node
            if nodes:
                if not _api_rate_limiter.acquire(cluster_id):
                    return jsonify({'error': 'API rate limit exceeded'}), 429
                
                node = nodes[0]
                storage_url = f"https://{host}:8006/api2/json/nodes/{node}/storage"
                storage_response = manager._create_session().get(storage_url, timeout=10)
                
                if storage_response.status_code == 200:
                    for storage in storage_response.json().get('data', []):
                        # Only include storages that are in this storage cluster
                        if storage['storage'] not in sc_config['storages']:
                            continue
                        
                        total = storage.get('total', 0)
                        used = storage.get('used', 0)
                        usage_percent = (used / total * 100) if total > 0 else 0
                        
                        storage_stats.append({
                            'storage': storage['storage'],
                            'type': storage.get('type'),
                            'total': total,
                            'used': used,
                            'avail': storage.get('avail', 0),
                            'usage_percent': round(usage_percent, 1)
                        })
            
            # Cache storage stats for 30 seconds
            _storage_cache.set(cluster_id, cache_key, storage_stats, ttl_seconds=30)
        
        # Calculate imbalance within this storage cluster
        if len(storage_stats) >= 2:
            usages = [s['usage_percent'] for s in storage_stats]
            imbalance = max(usages) - min(usages)
        else:
            imbalance = 0
        
        # Generate recommendations if imbalance exceeds threshold
        recommendations = []
        threshold = sc_config.get('threshold', 20)
        max_recommendations = int(request.args.get('max_recommendations', 10))  # configurable
        
        if imbalance > threshold and len(storage_stats) >= 2 and sc_config.get('enabled', True):
            # Find most and least used storage in THIS cluster
            sorted_stats = sorted(storage_stats, key=lambda x: x['usage_percent'], reverse=True)
            source_storage = sorted_stats[0]
            target_storage = sorted_stats[-1]
            
            # Try to get VM list from cache
            vm_cache_key = f"vm_list:{cluster_id}"
            all_vms, vm_cache_hit = _storage_cache.get(cluster_id, vm_cache_key)
            
            if not vm_cache_hit:
                if not _api_rate_limiter.acquire(cluster_id):
                    # Return what we have so far without recommendations
                    return jsonify({
                        'id': sc_config['id'],
                        'name': sc_config['name'],
                        'enabled': sc_config.get('enabled', True),
                        'storages': storage_stats,
                        'imbalance': round(imbalance, 1),
                        'threshold': threshold,
                        'recommendations': [],
                        'rate_limited': True
                    })
                
                # Find VMs on the source storage that could be moved
                resources_url = f"https://{host}:8006/api2/json/cluster/resources?type=vm"
                resources_response = manager._create_session().get(resources_url, timeout=15)
                
                if resources_response.status_code == 200:
                    all_vms = resources_response.json().get('data', [])
                    # Cache VM list for 60 seconds (VMs don't change that often)
                    _storage_cache.set(cluster_id, vm_cache_key, all_vms, ttl_seconds=60)
                else:
                    all_vms = []
            
            # NS: Process VMs in batches to avoid blocking too long
            # and to spread out API calls over time
            vms_checked = 0
            max_vms_to_check = 100  # Don't check more than 100 VMs per request
            
            for vm in all_vms:
                if len(recommendations) >= max_recommendations:
                    break
                if vms_checked >= max_vms_to_check:
                    break
                
                vm_node = vm.get('node')
                vmid = vm.get('vmid')
                vm_type = 'qemu' if vm.get('type') == 'qemu' else 'lxc'
                vm_status = vm.get('status', '')
                
                # Try to get VM config from cache
                config_cache_key = f"vm_config:{vmid}"
                vm_config, config_cache_hit = _storage_cache.get(cluster_id, config_cache_key)
                
                if not config_cache_hit:
                    # Rate limit each config fetch
                    if not _api_rate_limiter.acquire(cluster_id, timeout=5):
                        continue  # Skip this VM if rate limited
                    
                    vms_checked += 1
                    
                    # Check VM has active tasks (snapshot, backup, etc.)
                    try:
                        status_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/status/current"
                        status_response = manager._create_session().get(status_url, timeout=5)
                        if status_response.status_code == 200:
                            status_data = status_response.json().get('data', {})
                            if status_data.get('lock'):
                                continue  # Skip VMs with active operations
                    except:
                        pass
                    
                    # Get VM config to find disks
                    config_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/config"
                    config_response = manager._create_session().get(config_url, timeout=5)
                    
                    if config_response.status_code == 200:
                        vm_config = config_response.json().get('data', {})
                        # Cache VM config for 5 minutes
                        _storage_cache.set(cluster_id, config_cache_key, vm_config, ttl_seconds=300)
                    else:
                        continue
                
                if not vm_config:
                    continue
                
                for key, value in vm_config.items():
                    if not isinstance(value, str):
                        continue
                    if not any(key.startswith(prefix) for prefix in ['scsi', 'sata', 'virtio', 'ide', 'rootfs', 'mp']):
                        continue
                    
                    # Check disk is on source storage (must be in this storage cluster)
                    if value.startswith(source_storage['storage'] + ':'):
                        disk_size = 0
                        if 'size=' in value:
                            try:
                                size_match = value.split('size=')[1].split(',')[0]
                                if 'G' in size_match:
                                    disk_size = float(size_match.replace('G', '')) * 1024**3
                                elif 'M' in size_match:
                                    disk_size = float(size_match.replace('M', '')) * 1024**2
                                elif 'T' in size_match:
                                    disk_size = float(size_match.replace('T', '')) * 1024**4
                            except:
                                pass
                        
                        recommendations.append({
                            'type': 'move_disk',
                            'vmid': vmid,
                            'vm_name': vm.get('name', f'VM {vmid}'),
                            'vm_status': vm_status,
                            'disk': key,
                            'source': source_storage['storage'],
                            'target': target_storage['storage'],
                            'disk_size': disk_size,
                            'reason': f"Balance: {source_storage['storage']} ({source_storage['usage_percent']}%) → {target_storage['storage']} ({target_storage['usage_percent']}%)"
                        })
                        
                        if len(recommendations) >= max_recommendations:
                            break
        
        # Include rate limiter stats for monitoring
        rate_stats = _api_rate_limiter.get_stats(cluster_id)
        cache_stats = _storage_cache.get_stats()
        
        return jsonify({
            'id': sc_config['id'],
            'name': sc_config['name'],
            'enabled': sc_config.get('enabled', True),
            'storages': storage_stats,
            'imbalance': round(imbalance, 1),
            'threshold': threshold,
            'recommendations': recommendations,
            # MK: Include stats for debugging large clusters
            '_stats': {
                'rate_limiter': rate_stats,
                'cache': cache_stats,
                'cache_hit': cache_hit if 'cache_hit' in dir() else False
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting storage cluster status: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/storage-balancing/migrate', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def execute_storage_migration(cluster_id):
    """Execute a storage migration (move disk to different storage)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    vmid = data.get('vmid')
    disk = data.get('disk')
    target_storage = data.get('target')
    
    if not all([vmid, disk, target_storage]):
        return jsonify({'error': 'Missing required parameters: vmid, disk, target'}), 400
    
    try:
        host = manager.current_host or manager.config.host
        
        # Find the VM
        resources_url = f"https://{host}:8006/api2/json/cluster/resources?type=vm"
        resources_response = manager._create_session().get(resources_url, timeout=5)
        
        vm_node = None
        vm_type = None
        
        if resources_response.status_code == 200:
            for vm in resources_response.json().get('data', []):
                if vm.get('vmid') == vmid:
                    vm_node = vm.get('node')
                    vm_type = 'qemu' if vm.get('type') == 'qemu' else 'lxc'
                    
                    # Check for lock
                    status_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/status/current"
                    status_response = manager._create_session().get(status_url, timeout=5)
                    if status_response.status_code == 200:
                        status_data = status_response.json().get('data', {})
                        if status_data.get('lock'):
                            return jsonify({
                                'error': f'VM {vmid} is locked ({status_data.get("lock")})'
                            }), 400
                    break
        
        if not vm_node or not vm_type:
            return jsonify({'error': f'VM {vmid} not found'}), 404

        # NS: Feb 2026 - Block if disk has active efficient snapshot
        try:
            existing = get_db().get_efficient_snapshots(cluster_id, vmid)
            for snap in existing:
                if snap['status'] in ('invalidated', 'error'):
                    continue
                for d in snap['disks']:
                    if d['disk_key'] == disk:
                        return jsonify({'error': f"Disk has active efficient snapshot '{snap['snapname']}', delete it first"}), 400
        except Exception as e:
            logging.warning(f"Could not check efficient snapshots for VM {vmid}: {e}")

        # Execute disk move
        move_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/move_disk"
        move_data = {
            'disk': disk,
            'storage': target_storage,
            'delete': 1  # Delete source after move
        }
        
        response = manager._create_session().post(move_url, data=move_data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage_balancing.disk_moved', f"Moved {disk} of VM {vmid} to {target_storage}")
            
            return jsonify({
                'success': True,
                'message': f'Disk migration started',
                'upid': result.get('data')
            })
        else:
            error_msg = response.json().get('errors', response.text) if response.text else 'Migration failed'
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error executing storage migration: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/storage-balancing/stats', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_storage_balancing_stats(cluster_id):
    """Get storage balancing stats for monitoring large clusters

    MK: Added Dec 2025 for enterprise deployments
    Shows rate limiter status, cache stats, active migrations
    Useful for debugging performance issues
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Get rate limiter stats
    rate_stats = _api_rate_limiter.get_stats(cluster_id)
    
    # Get cache stats
    cache_stats = _storage_cache.get_stats()
    
    # Get active migrations for this cluster
    active_migrations = []
    with _migration_lock:
        for key, migrations in active_auto_migrations.items():
            if key.startswith(cluster_id + ':'):
                for m in migrations:
                    active_migrations.append({
                        'storage_cluster': key.split(':')[1],
                        'vmid': m.get('vmid'),
                        'disk': m.get('disk'),
                        'started': m.get('started'),
                        'active': m.get('active', False)
                    })
    
    # Get storage cluster configs
    with _storage_config_lock:
        clusters = storage_clusters_config.get(cluster_id, {}).get('clusters', [])
        cluster_info = [{
            'id': sc['id'],
            'name': sc['name'],
            'enabled': sc.get('enabled', True),
            'auto_balance': sc.get('auto_balance', False),
            'last_auto_run': sc.get('last_auto_run'),
            'check_interval': sc.get('check_interval', 3600)
        } for sc in clusters]
    
    return jsonify({
        'rate_limiter': rate_stats,
        'cache': cache_stats,
        'active_migrations': active_migrations,
        'storage_clusters': cluster_info,
        # NS: Performance tuning info
        'config': {
            'rate_limit_calls_per_second': 10,
            'rate_limit_burst': 20,
            'cache_ttl_storage': 30,
            'cache_ttl_vms': 60,
            'cache_ttl_vm_config': 300,
            'max_vms_per_status_check': 100,
            'max_vms_per_auto_balance_cycle': 50
        }
    })


def run_auto_storage_balance():
    """background worker for auto storage balancing - LW Dec 2025"""
    logging.info("Auto-balance worker started")
    
    while True:
        try:
            time.sleep(60)  # Check every minute
            
            # Get a snapshot of config
            with _storage_config_lock:
                config_snapshot = dict(storage_clusters_config)
            
            for cluster_id, config in config_snapshot.items():
                if cluster_id not in cluster_managers:
                    continue
                    
                manager = cluster_managers[cluster_id]
                if not manager.is_connected:
                    continue
                
                for sc in config.get('clusters', []):
                    if not sc.get('enabled') or not sc.get('auto_balance'):
                        continue
                    
                    # Check interval
                    check_interval = sc.get('check_interval', 3600)
                    last_run = sc.get('last_auto_run')
                    if last_run:
                        try:
                            last_run_time = datetime.fromisoformat(last_run)
                            if (datetime.now() - last_run_time).total_seconds() < check_interval:
                                continue
                        except:
                            pass
                    
                    # Check active migrations for this cluster                    # NS: Feb 2026 - also verify Proxmox task status to clean up finished ones (#83)
                    active_key = f"{cluster_id}:{sc['id']}"
                    with _migration_lock:
                        if active_key in active_auto_migrations:
                            still_active = []
                            for m in active_auto_migrations[active_key]:
                                age = (datetime.now() - datetime.fromisoformat(m['started'])).total_seconds()
                                if age > 7200:
                                    continue  # expired, drop it
                                # check proxmox task status if we have a upid and manager
                                upid = m.get('upid')
                                if upid and manager.is_connected:
                                    try:
                                        host = manager.current_host or manager.config.host
                                        # UPID format: UPID:node:..., extract node
                                        parts = upid.split(':')
                                        task_node = parts[1] if len(parts) > 1 else None
                                        if task_node:
                                            task_url = f"https://{host}:8006/api2/json/nodes/{task_node}/tasks/{upid}/status"
                                            resp = manager._create_session().get(task_url, timeout=5)
                                            if resp.status_code == 200:
                                                task_status = resp.json().get('data', {}).get('status')
                                                if task_status and task_status != 'running':
                                                    continue  # task finished, drop from active list
                                    except:
                                        pass  # can't check, keep it active to be safe
                                still_active.append(m)
                            active_auto_migrations[active_key] = still_active
                            if len(still_active) >= sc.get('max_concurrent', 1):
                                continue
                    
                    try:
                        # Rate limit - wait for token before making API calls
                        if not _api_rate_limiter.acquire(cluster_id, timeout=10):
                            logging.debug(f"Auto-balance skipped for {sc['name']} - rate limited")
                            continue
                        
                        host = manager.current_host or manager.config.host
                        
                        # Try to get storage stats from cache first
                        cache_key = f"auto_balance_storage:{sc['id']}"
                        storage_stats, cache_hit = _storage_cache.get(cluster_id, cache_key)
                        
                        if not cache_hit:
                            storage_stats = []
                            nodes_url = f"https://{host}:8006/api2/json/nodes"
                            nodes_response = manager._create_session().get(nodes_url, timeout=10)
                            nodes = []
                            if nodes_response.status_code == 200:
                                nodes = [n['node'] for n in nodes_response.json().get('data', [])]
                            
                            if nodes:
                                if not _api_rate_limiter.acquire(cluster_id, timeout=5):
                                    continue
                                    
                                storage_url = f"https://{host}:8006/api2/json/nodes/{nodes[0]}/storage"
                                storage_response = manager._create_session().get(storage_url, timeout=10)
                                
                                if storage_response.status_code == 200:
                                    for storage in storage_response.json().get('data', []):
                                        if storage['storage'] not in sc['storages']:
                                            continue
                                        total = storage.get('total', 0)
                                        used = storage.get('used', 0)
                                        usage_percent = (used / total * 100) if total > 0 else 0
                                        storage_stats.append({
                                            'storage': storage['storage'],
                                            'usage_percent': usage_percent
                                        })
                            
                            # Cache for 60 seconds
                            _storage_cache.set(cluster_id, cache_key, storage_stats, ttl_seconds=60)
                        
                        if len(storage_stats) < 2:
                            continue
                        
                        # Calculate imbalance
                        usages = [s['usage_percent'] for s in storage_stats]
                        imbalance = max(usages) - min(usages)
                        
                        if imbalance <= sc.get('threshold', 20):
                            # Update last run time
                            with _storage_config_lock:
                                # Re-find the cluster in case it changed
                                for sc_update in storage_clusters_config.get(cluster_id, {}).get('clusters', []):
                                    if sc_update['id'] == sc['id']:
                                        sc_update['last_auto_run'] = datetime.now().isoformat()
                                        break
                                save_storage_clusters()
                            continue
                        
                        # Find source and target
                        sorted_stats = sorted(storage_stats, key=lambda x: x['usage_percent'], reverse=True)
                        source_storage = sorted_stats[0]['storage']
                        target_storage = sorted_stats[-1]['storage']
                        
                        # Get VM list from cache or API
                        vm_cache_key = f"auto_balance_vms:{cluster_id}"
                        all_vms, vm_cache_hit = _storage_cache.get(cluster_id, vm_cache_key)
                        
                        if not vm_cache_hit:
                            if not _api_rate_limiter.acquire(cluster_id, timeout=5):
                                continue
                            
                            resources_url = f"https://{host}:8006/api2/json/cluster/resources?type=vm"
                            resources_response = manager._create_session().get(resources_url, timeout=15)
                            
                            if resources_response.status_code == 200:
                                all_vms = resources_response.json().get('data', [])
                                _storage_cache.set(cluster_id, vm_cache_key, all_vms, ttl_seconds=120)
                            else:
                                continue
                        
                        # Get node storage availability (cached)
                        node_storages_key = f"node_storages:{cluster_id}"
                        node_storages, ns_cache_hit = _storage_cache.get(cluster_id, node_storages_key)
                        
                        if not ns_cache_hit:
                            node_storages = {}
                            nodes_url = f"https://{host}:8006/api2/json/nodes"
                            nodes_resp = manager._create_session().get(nodes_url, timeout=10)
                            if nodes_resp.status_code == 200:
                                for node_info in nodes_resp.json().get('data', []):
                                    node = node_info['node']
                                    if not _api_rate_limiter.acquire(cluster_id, timeout=2):
                                        break
                                    node_storage_url = f"https://{host}:8006/api2/json/nodes/{node}/storage"
                                    ns_resp = manager._create_session().get(node_storage_url, timeout=5)
                                    if ns_resp.status_code == 200:
                                        node_storages[node] = [s['storage'] for s in ns_resp.json().get('data', [])]
                            _storage_cache.set(cluster_id, node_storages_key, node_storages, ttl_seconds=300)
                        
                        # NS: Process max 50 VMs per cycle to prevent blocking
                        vms_checked = 0
                        max_vms_per_cycle = 50
                        migration_done = False

                        # NS: Feb 2026 - skip VMs with active efficient snapshots (move would orphan them)
                        eff_snap_vmids = set()
                        try:
                            for s in get_db().get_all_efficient_snapshots(cluster_id):
                                if s['status'] not in ('invalidated', 'error'):
                                    eff_snap_vmids.add(s['vmid'])
                        except Exception as e:
                            logging.warning(f"Auto-balance: Could not check efficient snapshots: {e}")

                        # NS: Feb 2026 - collect VMIDs with active migrations to skip them (#83)
                        # This prevents "can't lock file" errors when we try to move another disk
                        # on a VM that already has a disk migration running
                        actively_migrating_vmids = set()
                        with _migration_lock:
                            for mig in active_auto_migrations.get(active_key, []):
                                if mig.get('active'):
                                    actively_migrating_vmids.add(mig.get('vmid'))

                        for vm in all_vms:
                            if migration_done or vms_checked >= max_vms_per_cycle:
                                break

                            vm_node = vm.get('node')
                            vmid = vm.get('vmid')
                            vm_type = 'qemu' if vm.get('type') == 'qemu' else 'lxc'

                            # NS: Feb 2026 - skip VMs that already have an active migration (#83)
                            if vmid in actively_migrating_vmids:
                                continue

                            # NS: Feb 2026 - skip VMs with active efficient snapshots
                            if vmid in eff_snap_vmids:
                                continue

                            # Check if target storage is available on this VM's node
                            if vm_node in node_storages:
                                if target_storage not in node_storages[vm_node]:
                                    continue

                            # Rate limit before checking VM status
                            if not _api_rate_limiter.acquire(cluster_id, timeout=2):
                                break

                            vms_checked += 1

                            # Check for lock (API-level lock field)
                            try:
                                status_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/status/current"
                                status_response = manager._create_session().get(status_url, timeout=5)
                                if status_response.status_code == 200:
                                    status_data = status_response.json().get('data', {})
                                    if status_data.get('lock'):
                                        actively_migrating_vmids.add(vmid)  # remember for rest of cycle
                                        continue
                            except:
                                continue
                            
                            # Get VM config (try cache first)
                            config_cache_key = f"vm_config:{vmid}"
                            vm_config, config_hit = _storage_cache.get(cluster_id, config_cache_key)
                            
                            if not config_hit:
                                if not _api_rate_limiter.acquire(cluster_id, timeout=2):
                                    break
                                config_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/config"
                                config_response = manager._create_session().get(config_url, timeout=5)
                                
                                if config_response.status_code == 200:
                                    vm_config = config_response.json().get('data', {})
                                    _storage_cache.set(cluster_id, config_cache_key, vm_config, ttl_seconds=300)
                                else:
                                    continue
                            
                            if not vm_config:
                                continue
                            
                            for key, value in vm_config.items():
                                if not isinstance(value, str):
                                    continue
                                if not any(key.startswith(p) for p in ['scsi', 'sata', 'virtio', 'ide', 'rootfs', 'mp']):
                                    continue
                                
                                if value.startswith(source_storage + ':'):
                                    # Execute migration
                                    if not _api_rate_limiter.acquire(cluster_id, timeout=5):
                                        break
                                    
                                    move_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/move_disk"
                                    move_data = {
                                        'disk': key,
                                        'storage': target_storage,
                                        'delete': 1
                                    }
                                    
                                    move_response = manager._create_session().post(move_url, data=move_data, timeout=10)
                                    
                                    if move_response.status_code == 200:
                                        logging.info(f"Auto-balance: Migrated {key} of VM {vmid} from {source_storage} to {target_storage}")
                                        log_audit('system', 'storage_balancing.auto_migrate',
                                                 f"Auto-migrated {key} of VM {vmid} from {source_storage} to {target_storage}")

                                        # Track migration
                                        with _migration_lock:
                                            if active_key not in active_auto_migrations:
                                                active_auto_migrations[active_key] = []
                                            active_auto_migrations[active_key].append({
                                                'vmid': vmid,
                                                'disk': key,
                                                'upid': move_response.json().get('data'),
                                                'active': True,
                                                'started': datetime.now().isoformat()
                                            })

                                        # Don't touch this VM again in the same cycle
                                        actively_migrating_vmids.add(vmid)

                                        # Invalidate cache after migration
                                        _storage_cache.invalidate(cluster_id, config_cache_key)
                                        _storage_cache.invalidate(cluster_id, cache_key)

                                        migration_done = True
                                    else:
                                        # NS: Feb 2026 - handle lock errors gracefully (#83)
                                        err_text = move_response.text or ''
                                        if "lock" in err_text.lower() or "locked" in err_text.lower():
                                            logging.info(f"Auto-balance: VM {vmid} is locked (disk migration in progress?), skipping")
                                            actively_migrating_vmids.add(vmid)
                                        else:
                                            logging.warning(f"Auto-balance: Failed to migrate {key} of VM {vmid}: {err_text}")
                                    
                                    break  # Only do one migration per check
                            
                            if migration_done:
                                break
                        
                        # Update last run time
                        with _storage_config_lock:
                            for sc_update in storage_clusters_config.get(cluster_id, {}).get('clusters', []):
                                if sc_update['id'] == sc['id']:
                                    sc_update['last_auto_run'] = datetime.now().isoformat()
                                    break
                            save_storage_clusters()
                        
                    except Exception as e:
                        logging.error(f"Error in auto-balance for {sc['name']}: {e}")
                        
        except Exception as e:
            logging.error(f"Error in auto-balance worker: {e}")
            time.sleep(60)

# Start auto-balance thread
auto_balance_thread = threading.Thread(target=run_auto_storage_balance, daemon=True)
auto_balance_thread.start()


@bp.route('/api/clusters/<cluster_id>/datacenter/storage', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_storage(cluster_id):
    """create new storage on proxmox - NS Dec 2025"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/storage"
        data = request.json or {}
        
        # Validate required fields
        storage_type = data.get('type')
        storage_id = data.get('storage')
        
        if not storage_type:
            return jsonify({'error': 'Storage type is required'}), 400
        if not storage_id:
            return jsonify({'error': 'Storage ID is required'}), 400
        
        # Validate storage ID format (Proxmox requirements)
        import re
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9\-\_\.]*$', storage_id):
            return jsonify({'error': 'Storage ID must start with a letter and contain only letters, numbers, -, _, .'}), 400
        
        # Define required fields per storage type
        required_fields = {
            'dir': ['path'],
            'nfs': ['server', 'export'],
            'cifs': ['server', 'share'],
            'lvm': ['vgname'],
            'lvmthin': ['vgname', 'thinpool'],
            'iscsi': ['portal', 'target'],
            'iscsidirect': ['portal', 'target'],
            'rbd': ['pool', 'monhost'],
            'cephfs': ['monhost'],
            'zfspool': ['pool'],
            'zfs': ['portal', 'target', 'pool'],
            'pbs': ['server', 'datastore', 'username', 'password'],
            'btrfs': ['path'],
        }
        
        # Check required fields for storage type
        if storage_type in required_fields:
            missing = [f for f in required_fields[storage_type] if not data.get(f)]
            if missing:
                return jsonify({'error': f'Missing required fields for {storage_type}: {", ".join(missing)}'}), 400
        
        # Build Proxmox-compatible request data
        # Proxmox expects form-data, and 'type' must be included
        pve_data = {}
        
        # Copy all non-empty fields
        for key, value in data.items():
            if value is not None and value != '':
                # Convert Python booleans to Proxmox format
                if isinstance(value, bool):
                    pve_data[key] = 1 if value else 0
                else:
                    pve_data[key] = value
        
        # Ensure type is set
        pve_data['type'] = storage_type
        
        logging.info(f"Creating storage {storage_id} of type {storage_type}")
        logging.debug(f"Storage data: {pve_data}")
        
        response = manager._create_session().post(url, data=pve_data, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage.created', f"Created storage '{storage_id}' of type {storage_type}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Storage created', 'data': result.get('data')})
        else:
            # Parse Proxmox error
            try:
                error_data = response.json()
                error_msg = error_data.get('errors', {})
                if isinstance(error_msg, dict):
                    error_msg = ', '.join([f"{k}: {v}" for k, v in error_msg.items()])
                elif not error_msg:
                    error_msg = error_data.get('message', response.text)
            except:
                error_msg = response.text
            
            logging.error(f"Failed to create storage: {error_msg}")
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error creating storage: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/storage/<storage_id>', methods=['GET'])
@require_auth(perms=["storage.view"])
def get_storage_config(cluster_id, storage_id):
    """Get configuration for a specific storage"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/storage/{storage_id}"
        
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', {}))
        return jsonify({'error': 'Storage not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/storage/<storage_id>', methods=['PUT'])
@require_auth(perms=["storage.config"])
def update_storage(cluster_id, storage_id):
    """Update storage configuration

    MK: Note that you cannot change the storage type after creation
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/storage/{storage_id}"
        data = request.json or {}
        
        # Remove fields that cannot be updated
        data.pop('storage', None)  # Can't change ID
        data.pop('type', None)     # Can't change type
        
        # Build Proxmox-compatible request data
        pve_data = {}
        for key, value in data.items():
            if value is not None and value != '':
                if isinstance(value, bool):
                    pve_data[key] = 1 if value else 0
                else:
                    pve_data[key] = value
        
        # Handle the 'delete' parameter for removing optional settings
        # Proxmox uses 'delete' param with comma-separated field names
        delete_fields = data.get('delete', '')
        if delete_fields:
            pve_data['delete'] = delete_fields
        
        response = manager._create_session().put(url, data=pve_data, timeout=10)
        
        if response.status_code == 200:
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage.updated', f"Updated storage '{storage_id}'", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Storage updated'})
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get('errors', error_data.get('message', response.text))
                if isinstance(error_msg, dict):
                    error_msg = ', '.join([f"{k}: {v}" for k, v in error_msg.items()])
            except:
                error_msg = response.text
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error updating storage: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/storage/<storage_id>', methods=['DELETE'])
@require_auth(perms=["storage.delete"])
def delete_storage(cluster_id, storage_id):
    """Delete storage

    LW: This only removes the storage configuration, it does NOT delete any data!
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/storage/{storage_id}"
        
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage.deleted', f"Deleted storage '{storage_id}'", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Storage deleted'})
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get('errors', error_data.get('message', response.text))
            except:
                error_msg = response.text
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error deleting storage: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/storage/<storage_id>/status', methods=['GET'])
@require_auth(perms=["storage.view"])
def get_storage_status(cluster_id, storage_id):
    """Get storage status including usage from all nodes

    NS: This is useful for checking if storage is actually accessible
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # Get storage config first
        config_url = f"https://{host}:8006/api2/json/storage/{storage_id}"
        config_resp = manager._create_session().get(config_url, timeout=5)
        config = {}
        if config_resp.status_code == 200:
            config = config_resp.json().get('data', {})
        
        # Get nodes
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = manager._create_session().get(nodes_url, timeout=5)
        nodes = []
        if nodes_resp.status_code == 200:
            nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
        
        # Get status from each node
        node_status = []
        for node in nodes:
            try:
                status_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_id}/status"
                status_resp = manager._create_session().get(status_url, timeout=5)
                if status_resp.status_code == 200:
                    status = status_resp.json().get('data', {})
                    status['node'] = node
                    node_status.append(status)
            except:
                pass
        
        return jsonify({
            'storage': storage_id,
            'config': config,
            'status': node_status
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/storage/<storage_id>/rescan', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def rescan_storage(cluster_id, storage_id):
    """Rescan storage to detect new LUNs, volumes, or refresh status

    NS: Feb 2026 - Useful for iSCSI, Shared LVM, FC storage after adding new LUNs
    Performs rescan on all nodes where the storage is available

    Options:
    - deep_scan: true = Use SSH to run system-level rescan commands (for LUN resize)
    - pvresize: true = Auto-resize LVM PVs after SCSI rescan
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    username = request.session.get('user', 'unknown')
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        data = request.json or {}
        target_nodes = data.get('nodes', [])  # Optional: specific nodes to rescan
        deep_scan = data.get('deep_scan', False)  # Use SSH for deeper rescan
        auto_pvresize = data.get('pvresize', True)  # Auto pvresize for LVM
        
        # Get storage config to determine type
        config_url = f"https://{host}:8006/api2/json/storage/{storage_id}"
        config_resp = session.get(config_url, timeout=5)
        if config_resp.status_code != 200:
            return jsonify({'error': f'Storage {storage_id} not found'}), 404
        
        storage_config = config_resp.json().get('data', {})
        storage_type = storage_config.get('type', '')
        vgname = storage_config.get('vgname', '')  # For LVM
        base_path = storage_config.get('base', '')  # For iscsi LVM base device
        
        # Get online nodes
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = session.get(nodes_url, timeout=5)
        if nodes_resp.status_code != 200:
            return jsonify({'error': 'Could not get nodes'}), 500
        
        all_nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
        
        # Filter to target nodes if specified
        if target_nodes:
            nodes = [n for n in all_nodes if n in target_nodes]
        else:
            nodes = all_nodes
        
        if not nodes:
            return jsonify({'error': 'No online nodes available for rescan'}), 400
        
        results = []
        paramiko = get_paramiko() if deep_scan else None
        
        for node in nodes:
            node_result = {'node': node, 'actions': [], 'success': True}
            
            try:
                # Deep scan using SSH for more thorough rescan
                if deep_scan and paramiko:
                    ssh_acquired = False
                    try:
                        # Use SSH rate limiting like update manager
                        ssh_acquired = _g._ssh_semaphore.acquire(timeout=60)
                        if not ssh_acquired:
                            node_result['actions'].append({
                                'action': 'ssh_queue',
                                'status': 'failed',
                                'error': 'SSH queue timeout - too many concurrent connections'
                            })
                        else:
                            _ssh_track_connection('normal', +1)
                            
                            # Get SSH config from cluster
                            ssh_user = manager.config.ssh_user if hasattr(manager.config, 'ssh_user') and manager.config.ssh_user else 'root'
                            ssh_port = getattr(manager.config, 'ssh_port', 22) or 22
                            ssh_key = getattr(manager.config, 'ssh_key', '')
                            ssh_pass = manager.config.pass_ if hasattr(manager.config, 'pass_') else None
                            
                            # Determine node hostname
                            node_host = host if node == nodes[0] else f"{node}.{host.split('.', 1)[1] if '.' in host else host}"
                            
                            # Try to connect via SSH
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            
                            connect_kwargs = {
                                'hostname': node_host,
                                'port': ssh_port,
                                'username': ssh_user,
                                'timeout': 30,
                                'banner_timeout': 30,
                                'allow_agent': False,
                                'look_for_keys': False
                            }
                            
                            # Use SSH key if configured, otherwise password
                            if ssh_key:
                                import io
                                key_file = io.StringIO(ssh_key)
                                pkey = None
                                for key_name, key_class in [
                                    ('RSA', paramiko.RSAKey),
                                    ('Ed25519', paramiko.Ed25519Key),
                                    ('ECDSA', paramiko.ECDSAKey),
                                    ('DSA', getattr(paramiko, 'DSSKey', None))
                                ]:
                                    if key_class is None:
                                        continue
                                    try:
                                        key_file.seek(0)
                                        pkey = key_class.from_private_key(key_file)
                                        break
                                    except:
                                        continue
                                if pkey:
                                    connect_kwargs['pkey'] = pkey
                                else:
                                    connect_kwargs['password'] = ssh_pass
                            else:
                                connect_kwargs['password'] = ssh_pass
                            
                            try:
                                ssh.connect(**connect_kwargs)
                                
                                # 1. SCSI bus rescan (detects new LUNs AND size changes)
                                if storage_type in ['iscsi', 'iscsidirect', 'lvm', 'lvmthin']:
                                    stdin, stdout, stderr = ssh.exec_command(
                                        'for host in /sys/class/scsi_host/host*; do echo "- - -" > "$host/scan" 2>/dev/null; done && '
                                        'for device in /sys/class/scsi_device/*/device/rescan; do echo 1 > "$device" 2>/dev/null; done',
                                        timeout=30
                                    )
                                    exit_code = stdout.channel.recv_exit_status()
                                    node_result['actions'].append({
                                        'action': 'scsi_bus_rescan',
                                        'status': 'success' if exit_code == 0 else 'partial',
                                        'ssh': True
                                    })
                                    
                                    # 1b. Multipath reconfigure (if multipath is installed)
                                    # This updates multipath maps after SCSI rescan
                                    stdin, stdout, stderr = ssh.exec_command(
                                        'if command -v multipathd >/dev/null 2>&1; then '
                                        '  multipathd reconfigure 2>/dev/null && '
                                        '  sleep 1 && '
                                        '  multipathd show maps 2>/dev/null | grep -c mpath || echo 0; '
                                        'else echo "no_multipath"; fi',
                                        timeout=30
                                    )
                                    mp_output = stdout.read().decode().strip()
                                    mp_exit_code = stdout.channel.recv_exit_status()
                                    if mp_output != "no_multipath":
                                        node_result['actions'].append({
                                            'action': 'multipath_reconfigure',
                                            'status': 'success' if mp_exit_code == 0 else 'partial',
                                            'maps_count': mp_output if mp_output.isdigit() else None,
                                            'ssh': True
                                        })
                                    
                                    # 1c. Resize multipath devices (for LUN expansion)
                                    stdin, stdout, stderr = ssh.exec_command(
                                        'if command -v multipathd >/dev/null 2>&1; then '
                                        '  for map in $(multipathd show maps raw format "%n" 2>/dev/null); do '
                                        '    multipathd resize map "$map" 2>/dev/null; '
                                        '  done && echo "resized"; '
                                        'else echo "no_multipath"; fi',
                                        timeout=60
                                    )
                                    resize_output = stdout.read().decode().strip()
                                    resize_exit_code = stdout.channel.recv_exit_status()
                                    if resize_output != "no_multipath":
                                        node_result['actions'].append({
                                            'action': 'multipath_resize',
                                            'status': 'success' if resize_exit_code == 0 else 'partial',
                                            'ssh': True
                                        })
                                
                                # 2. LVM pvresize (auto-resize PVs to use new LUN size)
                                if storage_type in ['lvm', 'lvmthin'] and auto_pvresize and vgname:
                                    stdin, stdout, stderr = ssh.exec_command(
                                        f'pvs --noheadings -o pv_name -S vgname={vgname} 2>/dev/null | xargs -r -n1 pvresize 2>&1',
                                        timeout=60
                                    )
                                    output = stdout.read().decode()
                                    exit_code = stdout.channel.recv_exit_status()
                                    node_result['actions'].append({
                                        'action': 'pvresize',
                                        'status': 'success' if exit_code == 0 else 'failed',
                                        'vgname': vgname,
                                        'output': output.strip()[:200] if output else None,
                                        'ssh': True
                                    })
                                
                                # 3. ZFS autoexpand
                                if storage_type in ['zfspool', 'zfs']:
                                    pool = storage_config.get('pool', storage_id)
                                    stdin, stdout, stderr = ssh.exec_command(
                                        f'zpool online -e {pool} 2>&1 || zpool scrub {pool} 2>&1',
                                        timeout=30
                                    )
                                    exit_code = stdout.channel.recv_exit_status()
                                    node_result['actions'].append({
                                        'action': 'zfs_expand',
                                        'status': 'success' if exit_code == 0 else 'partial',
                                        'pool': pool,
                                        'ssh': True
                                    })
                                
                                ssh.close()
                                
                            except Exception as ssh_err:
                                node_result['actions'].append({
                                    'action': 'ssh_connect',
                                    'status': 'failed',
                                    'error': str(ssh_err)[:100]
                                })
                    except Exception as e:
                        node_result['actions'].append({
                            'action': 'deep_scan',
                            'status': 'failed',
                            'error': str(e)[:100]
                        })
                    finally:
                        # Always release SSH semaphore
                        if ssh_acquired:
                            _ssh_track_connection('normal', -1)
                            _g._ssh_semaphore.release()
                
                # API-based rescan (always run as fallback/supplement)
                
                # 1. For iSCSI storage: rescan iSCSI sessions via API
                if storage_type in ['iscsi', 'iscsidirect']:
                    scsi_url = f"https://{host}:8006/api2/json/nodes/{node}/disks/scsi"
                    scsi_resp = session.post(scsi_url, timeout=30)
                    if scsi_resp.status_code in [200, 204]:
                        node_result['actions'].append({'action': 'scsi_rescan_api', 'status': 'success'})
                    else:
                        node_result['actions'].append({'action': 'scsi_rescan_api', 'status': 'failed', 'error': scsi_resp.text[:100]})
                
                # 2. For LVM/shared LVM: trigger LVM rescan via API
                if storage_type in ['lvm', 'lvmthin']:
                    lvm_url = f"https://{host}:8006/api2/json/nodes/{node}/disks/lvm"
                    lvm_resp = session.get(lvm_url, timeout=30)
                    if lvm_resp.status_code == 200:
                        node_result['actions'].append({'action': 'lvm_scan_api', 'status': 'success'})
                    else:
                        node_result['actions'].append({'action': 'lvm_scan_api', 'status': 'failed', 'error': lvm_resp.text[:100]})
                
                # 3. For ZFS: refresh pool status via API
                if storage_type in ['zfspool', 'zfs']:
                    zfs_url = f"https://{host}:8006/api2/json/nodes/{node}/disks/zfs"
                    zfs_resp = session.get(zfs_url, timeout=30)
                    if zfs_resp.status_code == 200:
                        node_result['actions'].append({'action': 'zfs_scan_api', 'status': 'success'})
                    else:
                        node_result['actions'].append({'action': 'zfs_scan_api', 'status': 'failed', 'error': zfs_resp.text[:100]})
                
                # 4. Always: Refresh storage status to update cache
                status_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_id}/status"
                status_resp = session.get(status_url, timeout=10)
                if status_resp.status_code == 200:
                    status_data = status_resp.json().get('data', {})
                    node_result['actions'].append({
                        'action': 'status_refresh', 
                        'status': 'success',
                        'storage_active': status_data.get('active', False),
                        'storage_enabled': status_data.get('enabled', False),
                        'total': status_data.get('total', 0),
                        'used': status_data.get('used', 0),
                        'avail': status_data.get('avail', 0),
                    })
                else:
                    node_result['actions'].append({'action': 'status_refresh', 'status': 'failed'})
                    node_result['success'] = False
                    
            except Exception as e:
                node_result['success'] = False
                node_result['error'] = str(e)
            
            results.append(node_result)
        
        # Log the action
        log_audit(username, 'storage.rescan', f'Rescanned storage {storage_id} on {len(nodes)} nodes (deep_scan={deep_scan})', cluster_id)
        
        success_count = sum(1 for r in results if r['success'])
        
        return jsonify({
            'success': success_count > 0,
            'storage': storage_id,
            'type': storage_type,
            'vgname': vgname if storage_type in ['lvm', 'lvmthin'] else None,
            'deep_scan': deep_scan,
            'nodes_scanned': len(results),
            'nodes_successful': success_count,
            'results': results
        })
        
    except Exception as e:
        logging.error(f"Error rescanning storage {storage_id}: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/storage/scan', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def scan_storage(cluster_id):
    """Scan/discover storage targets (for iSCSI, NFS exports, etc.)

    MK: This is useful for discovering available targets before adding storage
    NS: Changed route to not require storage_id since we're scanning BEFORE creating storage
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        storage_type = data.get('type', 'iscsi')
        
        # Get a node to run the scan on
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = manager._create_session().get(nodes_url, timeout=5)
        if nodes_resp.status_code != 200:
            return jsonify({'error': 'Could not get nodes'}), 500
        
        nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
        if not nodes:
            return jsonify({'error': 'No online nodes available'}), 500
        
        node = nodes[0]
        
        # Different scan endpoints for different storage types
        if storage_type == 'iscsi':
            portal = data.get('portal')
            if not portal:
                return jsonify({'error': 'Portal address required for iSCSI scan'}), 400
            scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/iscsi"
            scan_resp = manager._create_session().get(scan_url, params={'portal': portal}, timeout=30)
            
        elif storage_type == 'nfs':
            server = data.get('server')
            if not server:
                return jsonify({'error': 'Server address required for NFS scan'}), 400
            scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/nfs"
            scan_resp = manager._create_session().get(scan_url, params={'server': server}, timeout=30)
            
        elif storage_type == 'cifs':
            server = data.get('server')
            if not server:
                return jsonify({'error': 'Server address required for CIFS scan'}), 400
            params = {'server': server}
            if data.get('username'):
                params['username'] = data['username']
            if data.get('password'):
                params['password'] = data['password']
            if data.get('domain'):
                params['domain'] = data['domain']
            scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/cifs"
            scan_resp = manager._create_session().get(scan_url, params=params, timeout=30)
            
        elif storage_type == 'lvm':
            scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/lvm"
            scan_resp = manager._create_session().get(scan_url, timeout=30)
            
        elif storage_type == 'lvmthin':
            vgname = data.get('vgname')
            if not vgname:
                return jsonify({'error': 'Volume group name required for LVM-thin scan'}), 400
            scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/lvmthin"
            scan_resp = manager._create_session().get(scan_url, params={'vg': vgname}, timeout=30)
            
        elif storage_type == 'zfs':
            scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/zfs"
            scan_resp = manager._create_session().get(scan_url, timeout=30)
            
        else:
            return jsonify({'error': f'Scan not supported for storage type: {storage_type}'}), 400
        
        if scan_resp.status_code == 200:
            return jsonify({
                'success': True,
                'type': storage_type,
                'node': node,
                'data': scan_resp.json().get('data', [])
            })
        else:
            try:
                error_msg = scan_resp.json().get('errors', scan_resp.text)
            except:
                error_msg = scan_resp.text
            return jsonify({'error': error_msg}), scan_resp.status_code
            
    except Exception as e:
        logging.error(f"Error scanning storage: {e}")
        return jsonify({'error': str(e)}), 500


# Template Download API
# template downloads from Proxmox repo and ISOs from Proxmox appliance repository

@bp.route('/api/clusters/<cluster_id>/templates/available', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_available_templates(cluster_id):
    """Get available templates from Proxmox appliance repository

    Query params:
    - type: 'lxc' (default), 'iso', or 'all'
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        template_type = request.args.get('type', 'lxc')
        
        # Get a node to query
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = manager._create_session().get(nodes_url, timeout=5)
        if nodes_resp.status_code != 200:
            return jsonify({'error': 'Could not get nodes'}), 500
        
        nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
        if not nodes:
            return jsonify({'error': 'No online nodes available'}), 500
        
        node = nodes[0]
        templates = []
        
        # Get LXC container templates (aplinfo)
        if template_type in ['lxc', 'all']:
            apl_url = f"https://{host}:8006/api2/json/nodes/{node}/aplinfo"
            apl_resp = manager._create_session().get(apl_url, timeout=30)
            if apl_resp.status_code == 200:
                for tmpl in apl_resp.json().get('data', []):
                    templates.append({
                        'type': 'lxc',
                        'template': tmpl.get('template'),
                        'package': tmpl.get('package'),
                        'headline': tmpl.get('headline'),
                        'description': tmpl.get('description', ''),
                        'os': tmpl.get('os'),
                        'version': tmpl.get('version'),
                        'section': tmpl.get('section'),
                        'source': tmpl.get('source'),
                        'sha512sum': tmpl.get('sha512sum'),
                        'infopage': tmpl.get('infopage'),
                        'location': tmpl.get('location'),
                    })
        
        # Sort by section then package name
        templates.sort(key=lambda x: (x.get('section', ''), x.get('package', '')))
        
        return jsonify(templates)
        
    except Exception as e:
        logging.error(f"Error getting available templates: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/templates/download', methods=['POST'])
@require_auth(perms=['storage.download'])
def download_template(cluster_id):
    """Download a template to storage

    Body:
    - storage: Target storage name (must support vztmpl content)
    - template: Template filename (e.g., 'debian-12-standard_12.2-1_amd64.tar.zst')
    - node: Optional - specific node to download on
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        storage = data.get('storage')
        template = data.get('template')
        target_node = data.get('node')
        
        if not storage:
            return jsonify({'error': 'Storage is required'}), 400
        if not template:
            return jsonify({'error': 'Template is required'}), 400
        
        # Get a node if not specified
        if not target_node:
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_resp = manager._create_session().get(nodes_url, timeout=5)
            if nodes_resp.status_code != 200:
                return jsonify({'error': 'Could not get nodes'}), 500
            
            nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
            if not nodes:
                return jsonify({'error': 'No online nodes available'}), 500
            target_node = nodes[0]
        
        # Download template using aplinfo/download endpoint
        download_url = f"https://{host}:8006/api2/json/nodes/{target_node}/aplinfo"
        download_data = {
            'storage': storage,
            'template': template
        }
        
        logging.info(f"Downloading template {template} to {storage} on {target_node}")
        resp = manager._create_session().post(download_url, data=download_data, timeout=60)
        
        if resp.status_code == 200:
            result = resp.json()
            user = request.session.get('user', 'unknown')
            log_audit(user, 'template.downloaded', f"Downloaded template '{template}' to storage '{storage}'", cluster=manager.config.name)
            return jsonify({
                'success': True,
                'message': f'Download started for {template}',
                'data': result.get('data'),
                'upid': result.get('data')  # Usually returns task UPID
            })
        else:
            try:
                error_msg = resp.json().get('errors', resp.text)
            except:
                error_msg = resp.text
            return jsonify({'error': error_msg}), resp.status_code
            
    except Exception as e:
        logging.error(f"Error downloading template: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/storage/<storage>/content', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_node_storage_content(cluster_id, node, storage):
    """Get storage content for a specific node and storage

    Query params:
    - content: Filter by content type (images, iso, vztmpl, backup, rootdir)

    MK: Added for Import Disk feature
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        content_type = request.args.get('content', '')
        
        url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage}/content"
        if content_type:
            url += f"?content={content_type}"
        
        resp = manager._create_session().get(url, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json().get('data', [])
            return jsonify(data)
        else:
            return jsonify([])
    except Exception as e:
        logging.error(f"Error getting storage content: {e}")
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/storage/<storage>/download-url', methods=['POST'])
@require_auth(perms=['storage.download'])
def download_from_url(cluster_id, node, storage):
    """Download file from URL to storage

    Body:
    - url: URL to download from
    - filename: Target filename
    - content: Content type (iso, vztmpl)
    - checksum: Optional checksum (format: algorithm:hash)
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = data.get('url')
        filename = data.get('filename')
        content = data.get('content', 'iso')
        checksum = data.get('checksum')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        if not filename:
            return jsonify({'error': 'Filename is required'}), 400
        
        # Use Proxmox download-url API
        download_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage}/download-url"
        download_data = {
            'url': url,
            'filename': filename,
            'content': content
        }
        
        if checksum:
            # Format: algorithm:hash (e.g., sha256:abc123...)
            if ':' in checksum:
                algo, hash_value = checksum.split(':', 1)
                download_data['checksum-algorithm'] = algo
                download_data['checksum'] = hash_value
        
        logging.info(f"Downloading {url} as {filename} to {storage}")
        resp = manager._create_session().post(download_url, data=download_data, timeout=60)
        
        if resp.status_code == 200:
            result = resp.json()
            user = request.session.get('user', 'unknown')
            log_audit(user, 'file.downloaded', f"Downloaded '{filename}' from URL to storage '{storage}'", cluster=manager.config.name)
            return jsonify({
                'success': True,
                'message': f'Download started for {filename}',
                'upid': result.get('data')
            })
        else:
            try:
                error_msg = resp.json().get('errors', resp.text)
            except:
                error_msg = resp.text
            return jsonify({'error': error_msg}), resp.status_code
            
    except Exception as e:
        logging.error(f"Error downloading from URL: {e}")
        return jsonify({'error': str(e)}), 500


# Backup API
@bp.route('/api/clusters/<cluster_id>/datacenter/backup', methods=['GET'])
@require_auth(perms=['backup.view'])
def get_backup_jobs(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/backup"
        r = manager._create_session().get(url, timeout=5)
        
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/datacenter/backup', methods=['POST'])
@require_auth(perms=['backup.schedule'])
def create_backup_job(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/backup"
        data = request.json or {}
        
        r = manager._create_session().post(url, data=data, timeout=10)
        
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'backup.job_created', f"Created backup job", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Backup job created'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/backup/<job_id>', methods=['PUT'])
@require_auth(perms=['backup.schedule'])
def update_backup_job(cluster_id, job_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/backup/{job_id}"
        data = request.json or {}
        
        r = manager._create_session().put(url, data=data, timeout=10)
        
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'backup.job_updated', f"Updated backup job {job_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Backup job updated'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/backup/<job_id>', methods=['DELETE'])
@require_auth(perms=['backup.delete'])
def delete_backup_job(cluster_id, job_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/backup/{job_id}"
        
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'backup.job_deleted', f"Deleted backup job {job_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Backup job deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================

