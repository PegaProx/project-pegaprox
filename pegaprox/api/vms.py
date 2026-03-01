# -*- coding: utf-8 -*-
"""VM operations, snapshots, backups, replication & console routes - split from monolith dec 2025, NS/MK"""

import os
import sys
import json
import time
import logging
import threading
import uuid
import hashlib
import re
import ssl
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users, validate_session
from pegaprox.utils.audit import log_audit
from pegaprox.utils.rbac import user_can_access_vm, get_user_permissions
from pegaprox.utils.realtime import broadcast_sse, broadcast_action, push_immediate_update
from pegaprox.core.config import save_config
from pegaprox.api.helpers import get_connected_manager, check_cluster_access, register_task_user, safe_error
from pegaprox.utils.ssh import get_paramiko
from urllib.parse import urlencode, quote as url_quote
import signal
from pegaprox.api.realtime import sock

bp = Blueprint('vms', __name__)

# =====================================================
# DATACENTER / CLUSTER CONFIGURATION API
# =====================================================

@bp.route('/api/clusters/<cluster_id>/datacenter/status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_datacenter_status(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # get cluster status
        status_url = f"https://{host}:8006/api2/json/cluster/status"
        status_resp = manager._create_session().get(status_url, timeout=10)

        # get resources
        resources_url = f"https://{host}:8006/api2/json/cluster/resources"
        resources_resp = manager._create_session().get(resources_url, timeout=10)
        
        status_data = status_resp.json().get('data', []) if status_resp.status_code == 200 else []
        resources_data = resources_resp.json().get('data', []) if resources_resp.status_code == 200 else []
        
        # calc summary
        nodes_online = sum(1 for s in status_data if s.get('type') == 'node' and s.get('online', 0) == 1)
        nodes_offline = sum(1 for s in status_data if s.get('type') == 'node' and s.get('online', 0) == 0)
        cluster_info = next((s for s in status_data if s.get('type') == 'cluster'), None)
        is_standalone = cluster_info is None

        vms_running = sum(1 for r in resources_data if r.get('type') == 'qemu' and r.get('status') == 'running')
        vms_stopped = sum(1 for r in resources_data if r.get('type') == 'qemu' and r.get('status') == 'stopped')
        cts_running = sum(1 for r in resources_data if r.get('type') == 'lxc' and r.get('status') == 'running')
        cts_stopped = sum(1 for r in resources_data if r.get('type') == 'lxc' and r.get('status') == 'stopped')

        # Calculate total resources
        total_cpu = sum(r.get('maxcpu', 0) for r in resources_data if r.get('type') == 'node')
        used_cpu = sum(r.get('cpu', 0) * r.get('maxcpu', 0) for r in resources_data if r.get('type') == 'node')
        total_mem = sum(r.get('maxmem', 0) for r in resources_data if r.get('type') == 'node')
        used_mem = sum(r.get('mem', 0) for r in resources_data if r.get('type') == 'node')
        total_disk = sum(r.get('maxdisk', 0) for r in resources_data if r.get('type') == 'storage')
        used_disk = sum(r.get('disk', 0) for r in resources_data if r.get('type') == 'storage')

        # NS: single-node Proxmox doesn't return a cluster entry, was showing red X for no reason (#90)
        if is_standalone:
            node_name = next((s.get('name', '') for s in status_data if s.get('type') == 'node'), manager.config.name)
            cluster_result = {
                'name': node_name,
                'quorate': None,
                'standalone': True,
                'version': 0
            }
        else:
            cluster_result = {
                'name': cluster_info.get('name', 'Unknown'),
                'quorate': cluster_info.get('quorate', 0) == 1,
                'standalone': False,
                'version': cluster_info.get('version', 0)
            }

        return jsonify({
            'cluster': cluster_result,
            'nodes': {
                'online': nodes_online,
                'offline': nodes_offline,
                'total': nodes_online + nodes_offline
            },
            'guests': {
                'vms': {'running': vms_running, 'stopped': vms_stopped},
                'containers': {'running': cts_running, 'stopped': cts_stopped}
            },
            'resources': {
                'cpu': {'total': total_cpu, 'used': used_cpu, 'percent': round(used_cpu / total_cpu * 100, 1) if total_cpu > 0 else 0},
                'memory': {'total': total_mem, 'used': used_mem, 'percent': round(used_mem / total_mem * 100, 1) if total_mem > 0 else 0},
                'storage': {'total': total_disk, 'used': used_disk, 'percent': round(used_disk / total_disk * 100, 1) if total_disk > 0 else 0}
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_cluster_vms_list(cluster_id):
    """Get all VMs and containers in a cluster
    
    NS: Added Dec 2025 for VM ACL management
    Returns simple list with vmid, name, node, type
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        resources_url = f"https://{host}:8006/api2/json/cluster/resources"
        resp = manager._create_session().get(resources_url, timeout=10)
        
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to fetch resources'}), 500
        
        resources = resp.json().get('data', [])
        
        # filter VMs and containers
        vms = []
        for r in resources:
            if r.get('type') in ['qemu', 'lxc']:
                vms.append({
                    'vmid': r.get('vmid'),
                    'name': r.get('name', ''),
                    'node': r.get('node'),
                    'type': r.get('type'),
                    'status': r.get('status', 'unknown')
                })
        
        # sort by vmid
        vms.sort(key=lambda x: x['vmid'])
        
        return jsonify({'vms': vms})
    except Exception as e:
        logging.error(f"Error fetching VMs for cluster {cluster_id}: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/cluster-info', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_info(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()

        # Try corosync config first (has ring0_addr for join info)
        nodes = []
        try:
            url = f"https://{host}:8006/api2/json/cluster/config/nodes"
            r = session.get(url, timeout=5)
            if r.status_code == 200:
                nodes = r.json().get('data', [])
        except:
            pass

        # Merge with /nodes to get online status (corosync config doesn't have it)
        # Also serves as fallback for standalone nodes without corosync
        try:
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nr = session.get(nodes_url, timeout=5)
            if nr.status_code == 200:
                api_nodes = {n.get('node', n.get('name', '')): n for n in nr.json().get('data', [])}

                if nodes:
                    # Merge online status into corosync nodes
                    for node in nodes:
                        name = node.get('name', '')
                        if name in api_nodes:
                            node['online'] = 1 if api_nodes[name].get('status') == 'online' else 0
                            node['node'] = name
                else:
                    # No corosync data - use /nodes as primary source
                    nodes = [{
                        'name': n.get('node', ''),
                        'node': n.get('node', ''),
                        'online': 1 if n.get('status') == 'online' else 0,
                    } for n in nr.json().get('data', [])]
        except:
            pass

        return jsonify(nodes)
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/datacenter/join-info', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_join_info(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # try to get join info
        url = f"https://{host}:8006/api2/json/cluster/config/join"
        r = manager._create_session().get(url, timeout=5)
        
        if r.status_code == 200:
            data = r.json().get('data', {})
            if 'preferred_node' not in data:
                data['preferred_node'] = host
            # LW: Feb 2026 - Proxmox returns fingerprint as 'pve_fp' per node,
            # but frontend expects top-level 'fingerprint'. Extract it.
            if not data.get('fingerprint'):
                for node_entry in data.get('nodelist', []):
                    if isinstance(node_entry, dict) and node_entry.get('pve_fp'):
                        data['fingerprint'] = node_entry['pve_fp']
                        break
            # Still no fingerprint? Get from SSL cert
            if not data.get('fingerprint'):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, 8006), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            cert_der = ssock.getpeercert(binary_form=True)
                            fp_hex = hashlib.sha256(cert_der).hexdigest()
                            data['fingerprint'] = ':'.join(fp_hex[i:i+2].upper() for i in range(0, len(fp_hex), 2))
                except:
                    pass
            return jsonify(data)
        
        # fallback
        result = {
            'cluster_name': None,
            'fingerprint': None,
            'preferred_node': host,
            'nodelist': []
        }
        
        status_url = f"https://{host}:8006/api2/json/cluster/status"
        status_resp = manager._create_session().get(status_url, timeout=5)
        
        if status_resp.status_code == 200:
            status_data = status_resp.json().get('data', [])
            cluster_info = next((s for s in status_data if s.get('type') == 'cluster'), {})
            nodes = [s for s in status_data if s.get('type') == 'node']
            
            result['cluster_name'] = cluster_info.get('name', 'Unknown')
            result['nodelist'] = [{'name': n.get('name'), 'ip': n.get('ip'), 'online': n.get('online', 0)} for n in nodes]
        
        # get nodes config
        nodes_url = f"https://{host}:8006/api2/json/cluster/config/nodes"
        nodes_resp = manager._create_session().get(nodes_url, timeout=5)
        
        if nodes_resp.status_code == 200:
            nodes_data = nodes_resp.json().get('data', [])
            for node in nodes_data:
                # Update nodelist with ring0_addr
                for n in result['nodelist']:
                    if n['name'] == node.get('name'):
                        n['ring0_addr'] = node.get('ring0_addr')
                        n['pve_addr'] = node.get('pve_addr')
        
        # Try to get fingerprint via SSL certificate
        try:
            import socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, 8006), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(cert_der).hexdigest()
                    # Format as colon-separated uppercase
                    result['fingerprint'] = ':'.join(fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2))
        except Exception as e:
            logging.debug(f"Could not get SSL fingerprint: {e}")
            result['fingerprint'] = f'Run "pvecm status" on {host} to get fingerprint'
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/options', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_datacenter_options(cluster_id):
    """Get datacenter options"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/options"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', {}))
        return jsonify({})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/options', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_datacenter_options(cluster_id):
    """Update datacenter options"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    # LW Feb 2026 - allowlist of valid datacenter options to prevent mass assignment
    ALLOWED_DC_OPTIONS = {
        'keyboard', 'language', 'console', 'email_from', 'max_workers',
        'migration', 'migration_unsecure', 'ha', 'fencing', 'mac_prefix',
        'bwlimit', 'u2f', 'webauthn', 'description', 'tag-style',
        'notify', 'registered-tags', 'user-tag-access', 'crs',
    }
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/options"
        raw_data = request.json or {}
        data = {k: v for k, v in raw_data.items() if k in ALLOWED_DC_OPTIONS}

        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Options updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Storage API
@bp.route('/api/clusters/<cluster_id>/datacenter/storage', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_storage_list(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/storage"
        r = manager._create_session().get(url, timeout=5)
        
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/datastores', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_datastores(cluster_id):
    """Get all datastores with usage info"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # get storage configs
        storage_url = f"https://{host}:8006/api2/json/storage"
        storage_resp = manager._create_session().get(storage_url, timeout=5)
        storage_configs = {}
        if storage_resp.status_code == 200:
            for s in storage_resp.json().get('data', []):
                storage_configs[s['storage']] = s
        
        # get nodes
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = manager._create_session().get(nodes_url, timeout=5)
        nodes = []
        if nodes_resp.status_code == 200:
            nodes = [n['node'] for n in nodes_resp.json().get('data', [])]
        
        shared_storages = {}
        local_storages = {}
        
        for node in nodes:
            node_storage_url = f"https://{host}:8006/api2/json/nodes/{node}/storage"
            node_storage_response = manager._create_session().get(node_storage_url, timeout=5)
            
            if node_storage_response.status_code == 200:
                for storage in node_storage_response.json().get('data', []):
                    storage_name = storage.get('storage')
                    config = storage_configs.get(storage_name, {})
                    is_shared = config.get('shared', 0) == 1
                    
                    storage_info = {
                        'storage': storage_name,
                        'type': storage.get('type', config.get('type', 'unknown')),
                        'content': storage.get('content', config.get('content', '')),
                        'total': storage.get('total', 0),
                        'used': storage.get('used', 0),
                        'avail': storage.get('avail', 0),
                        'used_fraction': storage.get('used_fraction', 0),
                        'active': storage.get('active', 1),
                        'enabled': storage.get('enabled', 1),
                        'shared': is_shared,
                        'path': config.get('path', ''),
                        'nodes': config.get('nodes', ''),
                    }
                    
                    if is_shared:
                        if storage_name not in shared_storages:
                            shared_storages[storage_name] = storage_info
                    else:
                        if node not in local_storages:
                            local_storages[node] = []
                        local_storages[node].append(storage_info)
        
        return jsonify({
            'shared': list(shared_storages.values()),
            'local': local_storages,
            'nodes': nodes
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/content', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_datastore_content(cluster_id, storage_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        node = request.args.get('node')
        
        # If no node specified, find first node that has this storage
        if not node:
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        # Get storage content
        content_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_name}/content"
        response = manager._create_session().get(content_url, timeout=5)
        
        if response.status_code == 200:
            content = response.json().get('data', [])
            # Enhance with additional info
            for item in content:
                item['storage'] = storage_name
                item['node'] = node
                # Calculate size in human readable format
                size = item.get('size') or 0
                if size > 1024**3:
                    item['size_human'] = f"{size / 1024**3:.2f} GB"
                elif size > 1024**2:
                    item['size_human'] = f"{size / 1024**2:.2f} MB"
                else:
                    item['size_human'] = f"{size / 1024:.2f} KB"
                
                # check item is in use by a VM
                item['in_use'] = False
                if item.get('vmid'):
                    item['in_use'] = True
                    
            return jsonify(content)
        return jsonify([])
    except Exception as e:
        logging.error(f"Error getting datastore content: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/content/<path:volid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_datastore_content(cluster_id, storage_name, volid):
    """Delete content from a datastore (ISO, backup, etc.)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        node = request.args.get('node')
        
        if not node:
            # Find a node that has this storage
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        # check volume is in use by any VM or Container
        resources_url = f"https://{host}:8006/api2/json/cluster/resources?type=vm"
        resources_response = manager._create_session().get(resources_url, timeout=5)
        
        if resources_response.status_code == 200:
            for vm in resources_response.json().get('data', []):
                vm_node = vm.get('node')
                vmid = vm.get('vmid')
                vm_type = 'qemu' if vm.get('type') == 'qemu' else 'lxc'
                
                # Get VM/CT config to check disks and mounted ISOs
                config_url = f"https://{host}:8006/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/config"
                config_response = manager._create_session().get(config_url, timeout=5)
                if config_response.status_code == 200:
                    config = config_response.json().get('data', {})
                    
                    # Check all config entries for volume reference
                    for key, value in config.items():
                        if not isinstance(value, str):
                            continue
                        
                        # Check for disk images
                        if volid in value:
                            resource_name = 'VM' if vm_type == 'qemu' else 'Container'
                            return jsonify({
                                'error': f'Volume is in use by {resource_name} {vmid} ({key})',
                                'in_use': True,
                                'vmid': vmid,
                                'type': vm_type
                            }), 400
                        
                        # Check for mounted ISOs (ide*, sata*, scsi* with media=cdrom)
                        if volid.endswith('.iso'):
                            # check this ISO is mounted
                            iso_name = volid.split('/')[-1] if '/' in volid else volid
                            if iso_name in value or volid in value:
                                return jsonify({
                                    'error': f'ISO is mounted in VM {vmid} ({key})',
                                    'in_use': True,
                                    'vmid': vmid,
                                    'type': 'qemu'
                                }), 400
                    
                    # For containers, also check mount points
                    if vm_type == 'lxc':
                        for key, value in config.items():
                            if key.startswith('mp') and isinstance(value, str) and volid in value:
                                return jsonify({
                                    'error': f'Volume is mounted in Container {vmid} ({key})',
                                    'in_use': True,
                                    'vmid': vmid,
                                    'type': 'lxc'
                                }), 400
        
        # Delete the volume
        # URL encode the volid properly
        encoded_volid = volid.replace('/', '%2F')
        delete_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_name}/content/{encoded_volid}"
        response = manager._create_session().delete(delete_url, timeout=10)
        
        if response.status_code == 200:
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage.content_deleted', f"Deleted {volid} from {storage_name}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': f'Deleted {volid}'})
        else:
            error_msg = response.json().get('errors', response.text) if response.text else 'Delete failed'
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error deleting content: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/upload', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def upload_to_datastore(cluster_id, storage_name):
    """Upload ISO or other content to a datastore"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        node = request.form.get('node') or request.args.get('node')
        content_type = request.form.get('content', 'iso')  # iso, vztmpl, etc.
        
        if not node:
            # Find a node that has this storage
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        filename = file.filename
        if content_type == 'iso' and not filename.lower().endswith('.iso'):
            return jsonify({'error': 'File must be an ISO image'}), 400
        
        # Upload to Proxmox
        upload_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_name}/upload"
        
        files = {
            'filename': (filename, file.stream, 'application/octet-stream')
        }
        data = {
            'content': content_type
        }
        
        # NS: Feb 2026 - large files (ISOs) need a long timeout, 10s was way too short (#82)
        response = manager._create_session().post(upload_url, files=files, data=data, timeout=3600)
        
        if response.status_code == 200:
            result = response.json()
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage.upload', f"Uploaded {filename} to {storage_name}", cluster=manager.config.name)
            return jsonify({
                'success': True, 
                'message': f'Upload started: {filename}',
                'upid': result.get('data')
            })
        else:
            error_msg = response.json().get('errors', response.text) if response.text else 'Upload failed'
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error uploading: {e}")
        return jsonify({'error': str(e)}), 500


# NS: Download ISO from URL - Jan 2026
# Like Proxmox's "Download from URL" feature
# Tracks download progress in memory (for status polling)
_url_downloads = {}  # task_id -> { status, percent, message, ... }

@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/download-url', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def download_iso_from_url(cluster_id, storage_name):
    """Download ISO/image from URL to storage (like Proxmox)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        data = request.json or {}
        url = data.get('url', '').strip()
        filename = data.get('filename', '').strip()
        node = data.get('node', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Validate URL
        if not url.startswith('http://') and not url.startswith('https://'):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400
        
        # Extract filename from URL if not provided
        if not filename:
            from urllib.parse import urlparse, unquote
            parsed = urlparse(url)
            filename = unquote(parsed.path.split('/')[-1]) or 'download.iso'
        
        # Ensure proper extension
        if not any(filename.lower().endswith(ext) for ext in ['.iso', '.img', '.qcow2', '.raw']):
            filename += '.iso'
        
        host = manager.current_host or manager.config.host
        
        # Find node if not specified
        if not node:
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        # Try using Proxmox's native download-url API (PVE 7.0+)
        download_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage_name}/download-url"
        
        download_data = {
            'url': url,
            'filename': filename,
            'content': 'iso'
        }
        
        # Check if it's HTTPS and might need checksum verification disabled
        if url.startswith('https://'):
            download_data['verify-certificates'] = 0  # Skip SSL verification for downloads
        
        response = manager._create_session().post(download_url, data=download_data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            upid = result.get('data')
            
            # Generate task ID for tracking
            task_id = f"dl_{int(time.time())}_{os.urandom(4).hex()}"
            
            _url_downloads[task_id] = {
                'status': 'downloading',
                'percent': 0,
                'message': f'Downloading {filename}...',
                'upid': upid,
                'cluster_id': cluster_id,
                'node': node,
                'filename': filename,
                'started': time.time()
            }
            
            # Start background thread to poll Proxmox task status
            def poll_download_status():
                try:
                    while task_id in _url_downloads:
                        task_info = _url_downloads[task_id]
                        if task_info['status'] in ['completed', 'error']:
                            break
                        
                        # Poll Proxmox task status
                        status_url = f"https://{host}:8006/api2/json/nodes/{node}/tasks/{upid}/status"
                        try:
                            status_resp = manager._create_session().get(status_url, timeout=10)
                            if status_resp.status_code == 200:
                                status_data = status_resp.json().get('data', {})
                                
                                if status_data.get('status') == 'stopped':
                                    if status_data.get('exitstatus') == 'OK':
                                        _url_downloads[task_id] = {
                                            'status': 'completed',
                                            'percent': 100,
                                            'message': f'Download complete: {filename}'
                                        }
                                    else:
                                        _url_downloads[task_id] = {
                                            'status': 'error',
                                            'percent': 0,
                                            'message': status_data.get('exitstatus', 'Download failed')
                                        }
                                    break
                                else:
                                    # Still running - try to get progress from task log
                                    log_url = f"https://{host}:8006/api2/json/nodes/{node}/tasks/{upid}/log"
                                    log_resp = manager._create_session().get(log_url, timeout=10)
                                    if log_resp.status_code == 200:
                                        log_data = log_resp.json().get('data', [])
                                        for entry in reversed(log_data):
                                            text = entry.get('t', '')
                                            # Look for progress percentage in log
                                            import re
                                            match = re.search(r'(\d+(?:\.\d+)?)\s*%', text)
                                            if match:
                                                _url_downloads[task_id]['percent'] = float(match.group(1))
                                                _url_downloads[task_id]['message'] = f'Downloading... {match.group(1)}%'
                                                break
                        except Exception as e:
                            logging.debug(f"Error polling download status: {e}")
                        
                        time.sleep(2)
                    
                    # Cleanup old entries after 5 minutes
                    time.sleep(300)
                    if task_id in _url_downloads:
                        del _url_downloads[task_id]
                        
                except Exception as e:
                    logging.error(f"Error in download status poll: {e}")
                    if task_id in _url_downloads:
                        _url_downloads[task_id] = {
                            'status': 'error',
                            'percent': 0,
                            'message': str(e)
                        }
            
            import threading
            threading.Thread(target=poll_download_status, daemon=True).start()
            
            user = request.session.get('user', 'unknown')
            log_audit(user, 'storage.download', f"Started download: {filename} from {url[:50]}...", cluster=manager.config.name)
            
            return jsonify({
                'success': True,
                'task_id': task_id,
                'message': f'Download started: {filename}'
            })
        else:
            # Proxmox API error
            try:
                error_data = response.json()
                error_msg = error_data.get('errors', {})
                if isinstance(error_msg, dict):
                    error_msg = ', '.join(f"{k}: {v}" for k, v in error_msg.items())
                elif not error_msg:
                    error_msg = response.text or 'Download failed'
            except:
                error_msg = response.text or 'Download failed'
            
            return jsonify({'error': f'Proxmox API error: {error_msg}'}), response.status_code
            
    except Exception as e:
        logging.error(f"Error starting download: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/download-status/<task_id>', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_download_status(cluster_id, storage_name, task_id):
    """Get status of URL download task"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if task_id not in _url_downloads:
        return jsonify({'status': 'unknown', 'message': 'Task not found'}), 404
    
    return jsonify(_url_downloads[task_id])


# ============================================

# NS: VM Backup Management - Dec 2025
# Get backups for a specific VM, restore, delete
# ============================================

@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/backups', methods=['GET'])
@require_auth(perms=['backup.view'])
def get_vm_backups(cluster_id, node, vm_type, vmid):
    """Get all backups for a specific VM
    
    LW: Scans all backup-capable storages for vzdump files matching the vmid
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        
        backups = []
        
        # get all storages that can hold backups
        # NS: this is kinda slow if you have lots of storages but whatever
        storage_url = f"https://{host}:8006/api2/json/nodes/{node}/storage"
        stor_resp = session.get(storage_url, timeout=5)
        
        if stor_resp.status_code != 200:
            return jsonify([])
        
        storages = stor_resp.json().get('data', [])
        
        for storage in storages:
            # MK: only check storages that can hold backups
            content = storage.get('content', '')
            if 'backup' not in content:
                continue
            
            stor_name = storage.get('storage')
            # print(f"checking storage {stor_name}")  # debug - remove later
            content_url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{stor_name}/content"
            content_resp = session.get(content_url, params={'content': 'backup'}, timeout=10)
            
            if content_resp.status_code != 200:
                continue  # meh just skip it
            
            items = content_resp.json().get('data', [])
            
            for item in items:
                # vzdump naming: vzdump-{type}-{vmid}-{date}_{time}.{ext}
                # LW: proxmox naming conventions are weird but ok
                volid = item.get('volid', '')
                filename = volid.split('/')[-1] if '/' in volid else volid.split(':')[-1]
                
                # check if this backup belongs to our VM
                # format is like: vzdump-qemu-100-2025_01_15-12_00_00.vma.zst
                if f'-{vmid}-' in filename or filename.startswith(f'vzdump-{vm_type[:4]}-{vmid}'):
                    backups.append({
                        'volid': volid,
                        'storage': stor_name,
                        'filename': filename,
                        'size': item.get('size', 0),
                        'ctime': item.get('ctime', 0),  # creation time
                        'format': item.get('format', 'unknown'),
                        'notes': item.get('notes', '')
                    })
        
        # sort by creation time, newest first
        backups.sort(key=lambda x: x.get('ctime', 0), reverse=True)
        
        return jsonify(backups)
        
    except Exception as e:
        logging.error(f"[BACKUP] Error getting VM backups: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/backups/create', methods=['POST'])
@require_auth(perms=['backup.create'])
def create_vm_backup(cluster_id, node, vm_type, vmid):
    """Create a backup of a VM
    
    NS: Uses vzdump to create a backup
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    # MK: Check pool permission for vm.backup
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.backup', vm_type):
        return jsonify({'error': 'Permission denied: vm.backup'}), 403
    
    data = request.json or {}
    storage = data.get('storage', 'local')
    mode = data.get('mode', 'snapshot')  # stop, suspend, snapshot
    compress = data.get('compress', 'zstd')
    notes = data.get('notes', '')
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        
        # vzdump endpoint
        url = f"https://{host}:8006/api2/json/nodes/{node}/vzdump"
        
        backup_params = {
            'vmid': vmid,
            'storage': storage,
            'mode': mode,
            'compress': compress
        }
        
        if notes:
            backup_params['notes-template'] = notes
        
        response = session.post(url, data=backup_params, timeout=30)
        
        if response.status_code == 200:
            task = response.json().get('data', '')
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'backup.created', f"Started backup for {vm_type}/{vmid}", cluster=manager.config.name)
            return jsonify({'success': True, 'task': task})
        
        return jsonify({'error': response.text}), response.status_code
        
    except Exception as e:
        logging.error(f"[BACKUP] Error creating backup: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/backups/restore', methods=['POST'])
@require_auth(perms=['backup.restore'])
def restore_vm_backup(cluster_id, node, vm_type, vmid):
    """Restore a VM from backup
    
    MK: Can restore to same VMID (overwrite) or new VMID
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    # MK: Check pool permission for vm.backup
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.backup', vm_type):
        return jsonify({'error': 'Permission denied: vm.backup'}), 403
    
    data = request.json or {}
    volid = data.get('volid')
    target_vmid = data.get('target_vmid', vmid)  # default: restore to same vmid
    target_storage = data.get('storage', '')
    start_after = data.get('start', False)
    
    if not volid:
        return jsonify({'error': 'Backup volume ID required'}), 400
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        
        # restore endpoint depends on vm type
        # MK: why does proxmox have different endpoints for this?? annoying
        if vm_type == 'qemu':
            url = f"https://{host}:8006/api2/json/nodes/{node}/qemu"
        else:
            url = f"https://{host}:8006/api2/json/nodes/{node}/lxc"
        
        restore_params = {
            'vmid': target_vmid,
            'archive': volid,
            'force': 1 if target_vmid == vmid else 0  # force overwrite if same vmid
        }
        
        if target_storage:
            restore_params['storage'] = target_storage
        
        if start_after:
            restore_params['start'] = 1
        
        # TODO: add option to restore with different name?
        # logging.debug(f"restore params: {restore_params}")
        
        response = session.post(url, data=restore_params, timeout=30)
        
        if response.status_code == 200:
            task = response.json().get('data', '')
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'backup.restored', f"Restored {volid} to VMID {target_vmid}", cluster=manager.config.name)
            return jsonify({'success': True, 'task': task, 'vmid': target_vmid})
        
        # NS: proxmox sometimes returns weird error messages, should probably parse them better
        return jsonify({'error': response.text}), response.status_code
        
    except Exception as e:
        logging.error(f"[BACKUP] Error restoring backup: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/backups/<path:volid>', methods=['DELETE'])
@require_auth(perms=['backup.delete'])
def delete_vm_backup(cluster_id, node, vm_type, vmid, volid):
    """Delete a specific backup

    LW: Deletes from the storage where the backup is located
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # LW Feb 2026 - check VM-level backup permission
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.backup', vm_type):
        return jsonify({'error': 'Permission denied: vm.backup'}), 403
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error

    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        
        # volid format is usually: storage:backup/vzdump-xxx.vma.zst
        # we need to extract storage name
        if ':' in volid:
            storage = volid.split(':')[0]
        else:
            return jsonify({'error': 'Invalid volume ID format'}), 400
        
        # URL encode the volid for the path
        encoded_volid = url_quote(volid, safe='')
        
        url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{storage}/content/{encoded_volid}"
        
        response = session.delete(url, timeout=30)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'backup.deleted', f"Deleted backup {volid}", cluster=manager.config.name)
            return jsonify({'success': True})
        
        return jsonify({'error': response.text}), response.status_code
        
    except Exception as e:
        logging.error(f"[BACKUP] Error deleting backup: {e}")
        return jsonify({'error': str(e)}), 500
@bp.route('/api/clusters/<cluster_id>/datacenter/replication', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_replication_jobs(cluster_id):
    """Get all replication jobs"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/replication"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# MK: HA Manager Status API
@bp.route('/api/clusters/<cluster_id>/datacenter/ha/status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_ha_manager_status(cluster_id):
    """Get Proxmox HA manager status (quorum, master, lrm nodes)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # Get manager status (quorum, master, lrm for each node)
        url = f"https://{host}:8006/api2/json/cluster/ha/status/manager_status"
        resp = manager._create_session().get(url, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return jsonify(data)
        else:
            # Fallback to current status
            url2 = f"https://{host}:8006/api2/json/cluster/ha/status/current"
            resp2 = manager._create_session().get(url2, timeout=30)
            if resp2.status_code == 200:
                return jsonify(resp2.json().get('data', []))
            return jsonify([])
    except Exception as e:
        logging.error(f"Error getting HA manager status: {e}")
        return jsonify([])


# Firewall API
@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/options', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_firewall_options(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/options"
        r = manager._create_session().get(url, timeout=5)
        
        if r.status_code == 200:
            return jsonify(r.json().get('data', {}))
        return jsonify({})
    except:
        return jsonify({})


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/options', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def set_firewall_options(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/options"
        data = request.json or {}
        
        r = manager._create_session().put(url, data=data, timeout=10)
        
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'firewall.options_changed', f"Firewall options updated", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Firewall options updated'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_firewall_rules(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/rules"
        r = manager._create_session().get(url, timeout=5)
        
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules', methods=['POST'])
@require_auth(perms=['cluster.config'])
def create_firewall_rule(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/rules"
        data = request.json or {}
        
        r = manager._create_session().post(url, data=data, timeout=10)
        
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'firewall.rule_created', f"Firewall rule created", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Firewall rule created'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules/<int:pos>', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def update_firewall_rule(cluster_id, pos):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/rules/{pos}"
        data = request.json or {}
        
        r = manager._create_session().put(url, data=data, timeout=10)
        
        if r.status_code == 200:
            return jsonify({'success': True, 'message': 'Firewall rule updated'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules/<int:pos>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_firewall_rule(cluster_id, pos):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/rules/{pos}"
        
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Firewall rule deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/groups', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_firewall_groups(cluster_id):
    """Get firewall security groups"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/groups"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/aliases', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_firewall_aliases(cluster_id):
    """Get firewall aliases"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/aliases"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/ipset', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_firewall_ipsets(cluster_id):
    """Get firewall IP sets"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/firewall/ipset"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# Per-VM/CT Firewall API
# ============================================

def _vm_fw_url(manager, node, vmtype, vmid, sub=''):
    host = manager.current_host or manager.config.host
    return f"https://{host}:8006/api2/json/nodes/{node}/{vmtype}/{vmid}/firewall{sub}"


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/options', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_options(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_vm_fw_url(manager, node, vmtype, vmid, '/options'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', {}))
        return jsonify({})
    except:
        return jsonify({})


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/options', methods=['PUT'])
@require_auth(perms=['vm.config'])
def set_vm_firewall_options(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().put(_vm_fw_url(manager, node, vmtype, vmid, '/options'), data=data, timeout=10)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'vm.firewall.options', f"VM {vmid} firewall options updated", cluster=manager.config.name)
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/rules', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_rules(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        url = _vm_fw_url(manager, node, vmtype, vmid, '/rules')
        r = manager._create_session().get(url, timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        logging.warning(f"VM FW rules GET failed: {r.status_code} {r.text[:200]}")
        return jsonify([])
    except Exception as e:
        logging.warning(f"VM FW rules GET exception: {e}")
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/rules', methods=['POST'])
@require_auth(perms=['vm.config'])
def create_vm_firewall_rule(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        url = _vm_fw_url(manager, node, vmtype, vmid, '/rules')
        r = manager._create_session().post(url, data=data, timeout=10)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'vm.firewall.rule_created', f"VM {vmid} firewall rule created", cluster=manager.config.name)
            return jsonify({'success': True})
        # Extract Proxmox error message
        try:
            pve_err = r.json().get('errors', r.json().get('data', r.text))
        except:
            pve_err = r.text
        logging.warning(f"VM FW rule create failed: {r.status_code} data={data} pve_response={r.text[:300]}")
        return jsonify({'error': pve_err, 'status': r.status_code}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/rules/<int:pos>', methods=['PUT'])
@require_auth(perms=['vm.config'])
def update_vm_firewall_rule(cluster_id, node, vmtype, vmid, pos):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().put(_vm_fw_url(manager, node, vmtype, vmid, f'/rules/{pos}'), data=data, timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/rules/<int:pos>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def delete_vm_firewall_rule(cluster_id, node, vmtype, vmid, pos):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_vm_fw_url(manager, node, vmtype, vmid, f'/rules/{pos}'), timeout=10)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'vm.firewall.rule_deleted', f"VM {vmid} firewall rule {pos} deleted", cluster=manager.config.name)
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/aliases', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_aliases(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_vm_fw_url(manager, node, vmtype, vmid, '/aliases'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/aliases', methods=['POST'])
@require_auth(perms=['vm.config'])
def create_vm_firewall_alias(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_vm_fw_url(manager, node, vmtype, vmid, '/aliases'), data=data, timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/aliases/<name>', methods=['PUT'])
@require_auth(perms=['vm.config'])
def update_vm_firewall_alias(cluster_id, node, vmtype, vmid, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().put(_vm_fw_url(manager, node, vmtype, vmid, f'/aliases/{name}'), data=data, timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/aliases/<name>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def delete_vm_firewall_alias(cluster_id, node, vmtype, vmid, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_vm_fw_url(manager, node, vmtype, vmid, f'/aliases/{name}'), timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/ipset', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_ipsets(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_vm_fw_url(manager, node, vmtype, vmid, '/ipset'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/ipset', methods=['POST'])
@require_auth(perms=['vm.config'])
def create_vm_firewall_ipset(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_vm_fw_url(manager, node, vmtype, vmid, '/ipset'), data=data, timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/ipset/<name>', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_ipset_content(cluster_id, node, vmtype, vmid, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_vm_fw_url(manager, node, vmtype, vmid, f'/ipset/{name}'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/ipset/<name>', methods=['POST'])
@require_auth(perms=['vm.config'])
def add_vm_firewall_ipset_entry(cluster_id, node, vmtype, vmid, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_vm_fw_url(manager, node, vmtype, vmid, f'/ipset/{name}'), data=data, timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/ipset/<name>/<path:cidr>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def delete_vm_firewall_ipset_entry(cluster_id, node, vmtype, vmid, name, cidr):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_vm_fw_url(manager, node, vmtype, vmid, f'/ipset/{name}/{cidr}'), timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/ipset/<name>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def delete_vm_firewall_ipset(cluster_id, node, vmtype, vmid, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_vm_fw_url(manager, node, vmtype, vmid, f'/ipset/{name}'), timeout=10)
        if r.status_code == 200:
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/refs', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_refs(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_vm_fw_url(manager, node, vmtype, vmid, '/refs'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vmtype>/<vmid>/firewall/log', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_firewall_log(cluster_id, node, vmtype, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        params = {}
        if request.args.get('limit'):
            params['limit'] = request.args['limit']
        if request.args.get('start'):
            params['start'] = request.args['start']
        r = manager._create_session().get(_vm_fw_url(manager, node, vmtype, vmid, '/log'), params=params, timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


# Resource Mappings API
@bp.route('/api/clusters/<cluster_id>/datacenter/mapping/pci', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_pci_mappings(cluster_id):
    """Get PCI device mappings"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/mapping/pci"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/mapping/usb', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_usb_mappings(cluster_id):
    """Get USB device mappings"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/mapping/usb"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Maintenance Mode API Routes
@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/maintenance', methods=['PUT'])
@require_auth(perms=['node.maintenance'])
def set_maintenance_mode(cluster_id, node_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    enable = data.get('enable', True)
    skip_evacuation = data.get('skip_evacuation', False)  # MK: for non-reboot updates
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    if enable:
        task = mgr.enter_maintenance_mode(node_name, skip_evacuation=skip_evacuation)
        
        if skip_evacuation:
            log_audit(usr, 'node.maintenance_entered', f"Node {node_name} entered maintenance mode (skip_evacuation=True)", cluster=mgr.config.name)
            broadcast_action('maintenance_enter', 'node', node_name, {'status': 'completed', 'skip_evacuation': True}, cluster_id, usr)
        else:
            log_audit(usr, 'node.maintenance_entered', f"Node {node_name} entered maintenance mode", cluster=mgr.config.name)
            broadcast_action('maintenance_enter', 'node', node_name, {'status': 'evacuating'}, cluster_id, usr)
        
        return jsonify({
            'message': f'Entering maintenance mode for {node_name}',
            'skip_evacuation': skip_evacuation,
            'warning': 'VMs not evacuated - they may be affected if update fails!' if skip_evacuation else None,
            'task': task.to_dict()
        })
    else:
        success = mgr.exit_maintenance_mode(node_name)
        if success:
            log_audit(usr, 'node.maintenance_exited', f"Node {node_name} exited maintenance mode", cluster=mgr.config.name)
            broadcast_action('maintenance_exit', 'node', node_name, {}, cluster_id, usr)
            return jsonify({'message': f'Exited maintenance mode for {node_name}'})
        else:
            return jsonify({'error': f'Node {node_name} is not in maintenance mode'}), 400

@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/maintenance', methods=['GET'])
@require_auth(perms=['node.view'])
def get_maintenance_status(cluster_id, node_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    status = mgr.get_maintenance_status(node_name)
    
    return jsonify(status if status else {'maintenance_mode': False})

@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/maintenance', methods=['DELETE'])
@require_auth(perms=['node.maintenance'])
def exit_maintenance_mode_api(cluster_id, node_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    success = mgr.exit_maintenance_mode(node_name)
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    if success:
        log_audit(usr, 'node.maintenance_exited', f"Node {node_name} exited maintenance mode", cluster=mgr.config.name)
        broadcast_action('maintenance_exit', 'node', node_name, {}, cluster_id, usr)
        return jsonify({'message': f'Exited maintenance mode for {node_name}'})
    else:
        return jsonify({'error': f'Node {node_name} is not in maintenance mode'}), 400


@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/maintenance/acknowledge', methods=['POST'])
@require_auth(perms=['node.maintenance'])
def acknowledge_maintenance_warning(cluster_id, node_name):
    """Acknowledge maintenance warning (e.g., when some VMs couldn't migrate)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    # Store acknowledgment in maintenance task
    if node_name in manager.nodes_in_maintenance:
        manager.nodes_in_maintenance[node_name].acknowledged = True
        
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'node.maintenance_acknowledged', f"User acknowledged maintenance warning for {node_name}", cluster=manager.config.name)
        
        # Broadcast update
        broadcast_action('maintenance_acknowledged', 'node', node_name, {}, cluster_id, user)
        
        return jsonify({'message': f'Maintenance warning acknowledged for {node_name}'})
    else:
        return jsonify({'error': f'Node {node_name} is not in maintenance mode'}), 400


# =============================================================================
# NODE CLUSTER MANAGEMENT API - Join/Remove nodes from cluster
# Added by Node Management Integration
# =============================================================================

@bp.route('/api/clusters/<cluster_id>/nodes/join/test', methods=['POST'])
@require_auth(perms=['cluster.admin'])
def test_node_connection(cluster_id):
    """Test SSH connection to a new node and gather system info"""
    # LW: Feb 2026 - Pre-flight check before join, also detects orphaned cluster configs
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    paramiko = get_paramiko()
    if not paramiko:
        return jsonify({'error': 'SSH not available. Install paramiko: pip install paramiko'}), 500
    
    data = request.get_json() or {}
    node_ip = data.get('node_ip', '').strip()
    username = data.get('username', 'root')
    password = data.get('password', '')
    ssh_port = int(data.get('ssh_port', 22))
    
    if not node_ip:
        return jsonify({'success': False, 'error': 'Node IP is required'}), 400
    if not password:
        return jsonify({'success': False, 'error': 'SSH password is required'}), 400
    
    try:
        # Connect via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(node_ip, port=ssh_port, username=username, password=password, timeout=15)
        
        # Get hostname
        stdin, stdout, stderr = ssh.exec_command('hostname')
        hostname = stdout.read().decode().strip()
        
        # Check if Proxmox is installed
        stdin, stdout, stderr = ssh.exec_command('pveversion 2>/dev/null || echo "NOT_INSTALLED"')
        pve_output = stdout.read().decode().strip()
        proxmox_installed = 'NOT_INSTALLED' not in pve_output
        proxmox_version = pve_output if proxmox_installed else None
        
        # Check if already in a cluster
        stdin, stdout, stderr = ssh.exec_command('pvecm status 2>/dev/null || echo "NO_CLUSTER"')
        cluster_output = stdout.read().decode().strip()
        already_in_cluster = 'NO_CLUSTER' not in cluster_output and 'Cluster information' in cluster_output
        
        current_cluster = None
        if already_in_cluster:
            # Extract cluster name
            for line in cluster_output.split('\n'):
                if 'Cluster Name:' in line:
                    current_cluster = line.split(':')[1].strip()
                    break
        
        # NS: Feb 2026 - Check for orphaned cluster config files
        # LW: /etc/pve/ is a FUSE mount (pmxcfs), test -f doesn't always work there
        # so we also use ls and check for leftover node directories
        stdin, stdout, stderr = ssh.exec_command(
            'test -f /etc/corosync/authkey && echo HAS_AUTHKEY; '
            'test -f /etc/corosync/corosync.conf && echo HAS_COROSYNC; '
            'ls /etc/pve/corosync.conf 2>/dev/null && echo HAS_PVE_COROSYNC; '
            'ls /etc/pve/nodes/ 2>/dev/null | wc -l'
        )
        orphan_output = stdout.read().decode().strip()
        has_old_config = 'HAS_AUTHKEY' in orphan_output or 'HAS_COROSYNC' in orphan_output or 'HAS_PVE_COROSYNC' in orphan_output
        
        # Check if /etc/pve/nodes/ has dirs for other nodes (leftover from old cluster)
        try:
            lines = orphan_output.strip().split('\n')
            node_dir_count = int(lines[-1]) if lines[-1].isdigit() else 0
            if node_dir_count > 1:
                has_old_config = True
        except:
            pass
        
        ssh.close()
        
        return jsonify({
            'success': True,
            'info': {
                'hostname': hostname,
                'ip': node_ip,
                'proxmox_installed': proxmox_installed,
                'proxmox_version': proxmox_version,
                'already_in_cluster': already_in_cluster,
                'current_cluster': current_cluster,
                'has_old_config': has_old_config
            }
        })
        
    except paramiko.AuthenticationException:
        return jsonify({'success': False, 'error': 'Authentication failed. Check username/password.'}), 401
    except paramiko.SSHException as e:
        return jsonify({'success': False, 'error': f'SSH error: {str(e)}'}), 500
    except socket.timeout:
        return jsonify({'success': False, 'error': 'Connection timeout. Check IP and network.'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': f'Connection failed: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/join', methods=['POST'])
@require_auth(perms=['cluster.admin'])
def join_node_to_cluster(cluster_id):
    """Add a new node to the Proxmox cluster"""
    # MK: Feb 2026 - This uses SSH + interactive shell because pvecm add prompts for password
    # LW: Force rejoin option added to handle nodes removed via pvecm delnode that still have stale configs
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    paramiko = get_paramiko()
    if not paramiko:
        return jsonify({'error': 'SSH not available. Install paramiko: pip install paramiko'}), 500
    
    mgr = cluster_managers[cluster_id]
    data = request.get_json() or {}
    
    node_ip = data.get('node_ip', '').strip()
    username = data.get('username', 'root')
    password = data.get('password', '')
    ssh_port = int(data.get('ssh_port', 22))
    link0_address = data.get('link0_address', '').strip()
    force_rejoin = data.get('force', False)  # LW: Feb 2026 - Clean old cluster config before join
    
    if not node_ip or not password:
        return jsonify({'success': False, 'error': 'Node IP and password are required'}), 400
    
    try:
        # Get join information from existing cluster
        # MK: Feb 2026 - Use direct API call (same as get_join_info which works)
        # instead of api_request() wrapper which was silently failing
        host = mgr.current_host or mgr.config.host
        join_url = f"https://{host}:8006/api2/json/cluster/config/join"
        join_resp = mgr._create_session().get(join_url, timeout=10)
        
        if join_resp.status_code != 200:
            logging.error(f"Join info API returned {join_resp.status_code}: {join_resp.text[:500]}")
            return jsonify({'success': False, 'error': f'Could not get cluster join information (HTTP {join_resp.status_code})'}), 500
        
        join_info = join_resp.json().get('data', {})
        logging.info(f"[Join] Got join info keys: {list(join_info.keys()) if isinstance(join_info, dict) else type(join_info)}")
        
        # Extract fingerprint and join address from nodelist
        # Proxmox returns fingerprint per-node as 'pve_fp', not top-level
        fingerprint = ''
        join_addr = None
        
        # Check top-level first (some PVE versions)
        if isinstance(join_info, dict):
            fingerprint = join_info.get('fingerprint', '') or ''
        
        # Iterate nodelist for pve_fp and ring0_addr
        nodelist = join_info.get('nodelist', []) if isinstance(join_info, dict) else []
        for node_data in nodelist:
            if isinstance(node_data, dict):
                # Get fingerprint from first node that has it
                if not fingerprint and node_data.get('pve_fp'):
                    fingerprint = node_data['pve_fp']
                # Find best node to join to
                if not join_addr and node_data.get('ring0_addr'):
                    join_addr = node_data['ring0_addr']
                # Also try pve_addr as fallback for join address
                if not join_addr and node_data.get('pve_addr'):
                    join_addr = node_data['pve_addr']
        
        if not join_addr:
            # Fallback to cluster host
            join_addr = mgr.config.host
        
        if not fingerprint:
            # Fallback: extract fingerprint from Proxmox SSL certificate
            # Same method as get_join_info uses - this is the cert fingerprint
            # that pvecm add --fingerprint expects
            logging.warning(f"[Join] No pve_fp in API response, extracting from SSL certificate of {host}")
            try:
                import ssl
                import socket
                import hashlib
                
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, 8006), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        fp_hex = hashlib.sha256(cert_der).hexdigest()
                        fingerprint = ':'.join(fp_hex[i:i+2].upper() for i in range(0, len(fp_hex), 2))
                        logging.info(f"[Join] Got SSL fingerprint: {fingerprint[:20]}...")
            except Exception as ssl_err:
                logging.error(f"[Join] SSL fingerprint extraction failed: {ssl_err}")
        
        if not fingerprint:
            logging.error(f"[Join] No fingerprint found! join_info type={type(join_info).__name__}, "
                         f"nodelist={len(nodelist)} entries, "
                         f"first_node_keys={list(nodelist[0].keys()) if nodelist and isinstance(nodelist[0], dict) else 'N/A'}")
            return jsonify({'success': False, 'error': 'Could not get cluster fingerprint. Check server logs for details.'}), 500
        
        # Connect to new node via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(node_ip, port=ssh_port, username=username, password=password, timeout=30)
        
        # NS: Feb 2026 - Clean old cluster config if force rejoin
        # This is needed when a node was removed from a cluster but still has
        # old corosync/pve config files (authkey, corosync.conf, etc.)
        if force_rejoin:
            logging.info(f"[Join] Force rejoin: cleaning old cluster config on {node_ip}")
            channel = ssh.invoke_shell()
            time.sleep(0.5)
            if channel.recv_ready():
                channel.recv(4096)
            
            cleanup_commands = [
                'systemctl stop pve-cluster corosync 2>/dev/null',
                'sleep 1',
                'killall -9 pmxcfs 2>/dev/null',
                'sleep 1',
                'rm -f /var/lock/pve-cluster.lck /var/lock/pvecm.lock /var/lib/pve-cluster/.pmxcfs.lockfile',
                'pmxcfs -l &',
                'sleep 3',
                'rm -f /etc/corosync/authkey',
                'rm -f /etc/corosync/corosync.conf',
                'rm -f /etc/pve/corosync.conf',
                'killall -9 pmxcfs 2>/dev/null',
                'sleep 1',
                'rm -f /var/lock/pve-cluster.lck /var/lock/pvecm.lock /var/lib/pve-cluster/.pmxcfs.lockfile',
                'systemctl start pve-cluster',
                'sleep 3',
                'echo CLEANUP_DONE',
            ]
            for cmd in cleanup_commands:
                channel.send(cmd + '\n')
                time.sleep(0.5)
            
            time.sleep(5)
            cleanup_output = ''
            for _ in range(20):
                if channel.recv_ready():
                    cleanup_output += channel.recv(4096).decode('utf-8', errors='ignore')
                if 'CLEANUP_DONE' in cleanup_output:
                    break
                time.sleep(0.5)
            
            channel.close()
            logging.info(f"[Join] Cleanup output: {cleanup_output[-500:]}")
            
            # Reconnect SSH after pve-cluster restart
            ssh.close()
            time.sleep(2)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
            ssh.connect(node_ip, port=ssh_port, username=username, password=password, timeout=30)
        
        # Use interactive shell for pvecm add (it prompts for password)
        channel = ssh.invoke_shell()
        time.sleep(0.5)
        
        # Clear initial output
        if channel.recv_ready():
            channel.recv(4096)
        
        # Build and send the join command
        join_cmd = f'pvecm add {join_addr} --fingerprint {fingerprint}'
        if force_rejoin:
            join_cmd += ' --force'
        if link0_address:
            join_cmd += f' --link0 {link0_address}'
        
        channel.send(join_cmd + '\n')
        time.sleep(2)  # Wait for password prompt
        
        # Read output to check for password prompt
        output = ''
        for _ in range(10):
            if channel.recv_ready():
                output += channel.recv(4096).decode('utf-8', errors='ignore')
            time.sleep(0.5)
            if 'password' in output.lower() or 'Password' in output:
                break
        
        # Send password for the cluster root user
        channel.send(password + '\n')
        
        # Wait for completion (join can take 30-60 seconds)
        time.sleep(5)
        full_output = output
        for _ in range(60):  # Wait up to 60 seconds
            if channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                full_output += chunk
                if 'successfully' in chunk.lower() or 'joined' in chunk.lower():
                    break
                if 'error' in chunk.lower() or 'failed' in chunk.lower():
                    break
            time.sleep(1)
        
        channel.close()
        ssh.close()
        
        # Check result
        if 'error' in full_output.lower() or 'failed' in full_output.lower():
            # Extract error message
            error_lines = [l for l in full_output.split('\n') if 'error' in l.lower() or 'failed' in l.lower()]
            error_msg = error_lines[0] if error_lines else 'Join command failed'
            return jsonify({'success': False, 'error': error_msg}), 500
        
        # Log the action
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'cluster.node_joined', f"Node {node_ip} joined cluster", cluster=mgr.config.name)
        
        # NS: Feb 2026 - Update fallback hosts and HA after node join
        # Without this, the new node won't be a fallback target until HA's periodic 60s refresh
        def _post_join_update():
            """Background task: update fallback hosts + HA after join settles"""
            time.sleep(15)  # Wait for Proxmox cluster to sync the new node
            try:
                # Refresh connection to discover new node
                mgr.connect_to_proxmox()
                
                # Rediscover fallback hosts (includes the new node)
                if hasattr(mgr, '_auto_discover_fallback_hosts'):
                    old_fallbacks = list(mgr.config.fallback_hosts or [])
                    mgr._auto_discover_fallback_hosts()
                    new_fallbacks = list(mgr.config.fallback_hosts or [])
                    if old_fallbacks != new_fallbacks:
                        logging.info(f"[Join] Updated fallback hosts after node join: {old_fallbacks} → {new_fallbacks}")
                
                # If HA is active, update its node tracking
                if hasattr(mgr, 'ha_enabled') and mgr.ha_enabled:
                    if hasattr(mgr, '_ha_update_fallback_hosts'):
                        mgr._ha_update_fallback_hosts()
                    logging.info(f"[Join] HA fallback hosts updated after node join")
                
            except Exception as e:
                logging.warning(f"[Join] Post-join update error (non-critical): {e}")
        
        threading.Thread(target=_post_join_update, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Node joined cluster'
        })
        
    except paramiko.AuthenticationException:
        return jsonify({'success': False, 'error': 'SSH authentication failed'}), 401
    except Exception as e:
        logging.error(f"Error joining node to cluster: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/can-remove', methods=['GET'])
@require_auth(perms=['cluster.admin'])
def check_can_remove_node(cluster_id, node_name):
    """Check if a node can be safely removed from the cluster"""
    # NS: Feb 2026 - Blockers vs warnings: blockers prevent removal, warnings are recommendations
    # MK: Offline check is a warning not a blocker because pvecm delnode runs on another node
    try:
        ok, err = check_cluster_access(cluster_id)
        if not ok: return err
        
        if cluster_id not in cluster_managers:
            return jsonify({'can_remove': False, 'error': 'Cluster not found', 'blockers': ['Cluster not found']}), 200
        
        mgr = cluster_managers[cluster_id]
        
        # Check maintenance status
        in_maintenance = node_name in mgr.nodes_in_maintenance
        maintenance_complete = False
        if in_maintenance:
            task = mgr.nodes_in_maintenance[node_name]
            maintenance_complete = getattr(task, 'status', None) in ['completed', 'completed_with_errors']
        
        # Check if node is offline
        is_offline = True
        try:
            host = mgr.current_host or mgr.config.host
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_resp = mgr._create_session().get(nodes_url, timeout=10)
            nodes_list = nodes_resp.json().get('data', []) if nodes_resp.status_code == 200 else []
            for n in nodes_list:
                if n.get('node') == node_name:
                    is_offline = n.get('status') != 'online'
                    break
        except Exception as e:
            logging.debug(f"[RemoveNode] Could not check node status: {e}")
        
        # Check for VMs/CTs on the node
        has_vms = False
        vm_count = 0
        try:
            host = mgr.current_host or mgr.config.host
            session = mgr._create_session()
            resources = []
            for endpoint in [f"/nodes/{node_name}/qemu", f"/nodes/{node_name}/lxc"]:
                try:
                    r = session.get(f"https://{host}:8006/api2/json{endpoint}", timeout=10)
                    if r.status_code == 200:
                        resources += r.json().get('data', [])
                except:
                    pass
            vm_count = len(resources)
            has_vms = vm_count > 0
        except:
            pass
        
        # Determine blockers
        # MK: Feb 2026 - pvecm delnode runs on a REMAINING online node,
        # so the target node doesn't need to be offline.
        # It just needs VMs evacuated (maintenance complete).
        blockers = []
        warnings = []
        if not in_maintenance:
            blockers.append('Node must be in maintenance mode first')
        if not maintenance_complete and in_maintenance:
            blockers.append('Maintenance/evacuation must be complete')
        if has_vms:
            blockers.append(f'Node still has {vm_count} VM(s)/Container(s) - evacuate first')
        if not is_offline:
            warnings.append('Node is still online - it will be removed from cluster config. Recommended: shutdown node after removal.')
        
        can_remove = len(blockers) == 0
        
        return jsonify({
            'can_remove': can_remove,
            'in_maintenance': in_maintenance,
            'maintenance_complete': maintenance_complete,
            'is_offline': is_offline,
            'has_vms': has_vms,
            'vm_count': vm_count,
            'blockers': blockers,
            'warnings': warnings
        })
    except Exception as e:
        logging.error(f"[RemoveNode] check_can_remove error: {e}")
        return jsonify({'can_remove': False, 'error': str(e), 'blockers': [str(e)]}), 200


@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/cluster-membership', methods=['DELETE'])
@require_auth(perms=['cluster.admin'])
def remove_node_from_cluster(cluster_id, node_name):
    """Remove a node from the Proxmox cluster"""
    # LW: Feb 2026 - Runs pvecm delnode on a remaining online node, then SSHs into the
    # removed node to clean up stale configs (authkey, corosync.conf, lock files)
    # MK: IP must be resolved BEFORE delnode or we might wipe the wrong node!
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    paramiko = get_paramiko()
    if not paramiko:
        return jsonify({'error': 'SSH not available. Install paramiko: pip install paramiko'}), 500
    
    mgr = cluster_managers[cluster_id]
    data = request.get_json() or {}
    
    if not data.get('confirm'):
        return jsonify({'success': False, 'error': 'Confirmation required'}), 400
    
    # LW: Feb 2026 - Maintenance is recommended but not strictly required
    # pvecm delnode runs on another node, not on the target
    in_maintenance = node_name in mgr.nodes_in_maintenance
    if not in_maintenance:
        logging.warning(f"[RemoveNode] {node_name} not in maintenance mode - proceeding anyway")
    
    try:
        # Get cluster credentials for SSH - same pattern as HA
        cluster_config = mgr.config
        ssh_user = getattr(cluster_config, 'ssh_user', None) or ''
        if not ssh_user:
            api_user = cluster_config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
        ssh_password = getattr(cluster_config, 'pass_', '') or ''
        ssh_key_content = getattr(cluster_config, 'ssh_key', '') or ''
        
        # Find an online node to execute the removal from
        host = mgr.current_host or mgr.config.host
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = mgr._create_session().get(nodes_url, timeout=10)
        nodes = nodes_resp.json().get('data', []) if nodes_resp.status_code == 200 else []
        
        online_node = None
        online_node_ip = None
        
        for node in nodes:
            if node.get('node') != node_name and node.get('status') == 'online':
                online_node = node.get('node')
                online_node_ip = mgr._get_node_ip(online_node) or cluster_config.host
                break
        
        if not online_node:
            return jsonify({'success': False, 'error': 'No online node found to execute removal'}), 500
        
        # MK: Feb 2026 - CRITICAL: Resolve the target node's IP BEFORE removal
        # After pvecm delnode, the node is gone from cluster config and _get_node_ip
        # would return wrong/stale data, potentially wiping another node's config!
        removed_node_ip = mgr._get_node_ip(node_name) if hasattr(mgr, '_get_node_ip') else None
        logging.info(f"[RemoveNode] Pre-resolved IP for {node_name}: {removed_node_ip}")
        
        # Connect to an online node via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        
        # Try SSH key first, then password
        connected = False
        if ssh_key_content:
            try:
                import io
                key_file = io.StringIO(ssh_key_content)
                pkey = None
                for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, getattr(paramiko, 'DSSKey', None)]:
                    if key_class is None:
                        continue
                    try:
                        key_file.seek(0)
                        pkey = key_class.from_private_key(key_file)
                        break
                    except:
                        continue
                if pkey:
                    ssh.connect(online_node_ip, port=22, username=ssh_user, pkey=pkey, timeout=30)
                    connected = True
            except Exception as key_err:
                logging.debug(f"[RemoveNode] SSH key auth failed: {key_err}")
        
        if not connected and ssh_password:
            ssh.connect(online_node_ip, port=22, username=ssh_user, password=ssh_password, timeout=30)
            connected = True
        
        if not connected:
            return jsonify({'success': False, 'error': 'Could not authenticate via SSH. Configure SSH key or password.'}), 500
        
        # Execute pvecm delnode command
        cmd = f'pvecm delnode {node_name}'
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        
        ssh.close()
        
        if exit_code != 0:
            error_msg = stderr_text or stdout_text or 'Unknown error'
            return jsonify({'success': False, 'error': f'Failed to remove node: {error_msg}'}), 500
        
        # NS: Feb 2026 - SSH into the REMOVED node and clean up old cluster config
        # pvecm delnode only updates the remaining nodes' config, the removed node
        # still has stale corosync/authkey/pve config that blocks future joins
        # IMPORTANT: removed_node_ip was resolved BEFORE pvecm delnode (see above)
        # LW: Lock files (.pmxcfs.lockfile) are the #1 reason pve-cluster won't start after cleanup
        cleanup_result = {'success': False, 'message': 'Skipped - could not determine node IP'}
        
        if removed_node_ip:
            try:
                logging.info(f"[RemoveNode] Cleaning up cluster config on removed node {node_name} ({removed_node_ip})")
                ssh_cleanup = paramiko.SSHClient()
                ssh_cleanup.set_missing_host_key_policy(paramiko.WarningPolicy())
                
                # Try to connect to the removed node
                cleanup_connected = False
                if ssh_key_content:
                    try:
                        import io
                        key_file = io.StringIO(ssh_key_content)
                        pkey = None
                        for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, getattr(paramiko, 'DSSKey', None)]:
                            if key_class is None:
                                continue
                            try:
                                key_file.seek(0)
                                pkey = key_class.from_private_key(key_file)
                                break
                            except:
                                continue
                        if pkey:
                            ssh_cleanup.connect(removed_node_ip, port=22, username=ssh_user, pkey=pkey, timeout=15)
                            cleanup_connected = True
                    except:
                        pass
                if not cleanup_connected and ssh_password:
                    try:
                        ssh_cleanup.connect(removed_node_ip, port=22, username=ssh_user, password=ssh_password, timeout=15)
                        cleanup_connected = True
                    except:
                        pass
                
                if cleanup_connected:
                    # SAFETY CHECK: Verify we're on the correct node before wiping config!
                    stdin, stdout, stderr = ssh_cleanup.exec_command('hostname', timeout=10)
                    actual_hostname = stdout.read().decode().strip()
                    
                    # LW: Case-insensitive compare - Proxmox uses lowercase node names
                    # but hostname might be "Pve1" while node_name is "pve1"
                    if actual_hostname.lower() != node_name.lower():
                        cleanup_result = {'success': False, 'message': f'Hostname mismatch! Expected {node_name} but got {actual_hostname} - cleanup ABORTED to protect wrong node'}
                        logging.error(f"[RemoveNode] CRITICAL: Hostname mismatch on {removed_node_ip}! Expected '{node_name}', got '{actual_hostname}'. Cleanup aborted!")
                        ssh_cleanup.close()
                    else:
                        # MK: Feb 2026 - Use invoke_shell for cleanup because:
                        # /etc/pve/ is a FUSE mount (pmxcfs). exec_command can't properly
                        # background pmxcfs -l. invoke_shell handles this correctly.
                        channel = ssh_cleanup.invoke_shell()
                        time.sleep(0.5)
                        if channel.recv_ready():
                            channel.recv(4096)  # clear prompt
                        
                        cleanup_commands = [
                            'systemctl stop pve-cluster corosync 2>/dev/null',
                            'sleep 1',
                            'killall -9 pmxcfs 2>/dev/null',
                            'sleep 1',
                            'rm -f /var/lock/pve-cluster.lck /var/lock/pvecm.lock /var/lib/pve-cluster/.pmxcfs.lockfile',
                            'pmxcfs -l &',
                            'sleep 3',
                            'rm -f /etc/corosync/authkey',
                            'rm -f /etc/corosync/corosync.conf', 
                            'rm -f /etc/pve/corosync.conf',
                            'killall -9 pmxcfs 2>/dev/null',
                            'sleep 1',
                            'rm -f /var/lock/pve-cluster.lck /var/lock/pvecm.lock /var/lib/pve-cluster/.pmxcfs.lockfile',
                            'systemctl start pve-cluster',
                            'echo CLEANUP_DONE',
                        ]
                        
                        for cmd in cleanup_commands:
                            channel.send(cmd + '\n')
                            time.sleep(0.5)
                        
                        # Wait for completion
                        time.sleep(5)
                        cleanup_output = ''
                        for _ in range(20):
                            if channel.recv_ready():
                                cleanup_output += channel.recv(4096).decode('utf-8', errors='ignore')
                            if 'CLEANUP_DONE' in cleanup_output:
                                break
                            time.sleep(0.5)
                        
                        channel.close()
                        ssh_cleanup.close()
                        
                        logging.info(f"[RemoveNode] Cleanup output on {node_name}: {cleanup_output[-500:]}")
                        
                        if 'CLEANUP_DONE' in cleanup_output:
                            cleanup_result = {'success': True, 'message': 'Old cluster config cleaned up'}
                            logging.info(f"[RemoveNode] Cleanup on {node_name} successful")
                        else:
                            cleanup_result = {'success': False, 'message': f'Cleanup uncertain - check node manually. Output: {cleanup_output[-200:]}'}
                            logging.warning(f"[RemoveNode] Cleanup on {node_name} uncertain")
                else:
                    cleanup_result = {'success': False, 'message': 'Could not SSH into removed node for cleanup'}
                    logging.warning(f"[RemoveNode] Could not connect to {removed_node_ip} for cleanup")
            except Exception as cleanup_ex:
                cleanup_result = {'success': False, 'message': str(cleanup_ex)}
                logging.warning(f"[RemoveNode] Cleanup error on {node_name}: {cleanup_ex}")
        
        # Clean up maintenance task
        if node_name in mgr.nodes_in_maintenance:
            del mgr.nodes_in_maintenance[node_name]
        
        # MK: Clean up excluded_nodes - remove the deleted node
        excluded = getattr(mgr.config, 'excluded_nodes', []) or []
        if node_name in excluded:
            excluded.remove(node_name)
            mgr.config.excluded_nodes = excluded
            logging.info(f"Removed {node_name} from excluded_nodes")
        
        # MK: Clean up fallback_hosts - remove IPs of deleted node
        # NS: Feb 2026 - Use pre-resolved IP (removed_node_ip) instead of _get_node_ip()
        # because _get_node_ip() queries Proxmox API which no longer knows this node after pvecm delnode!
        fallback = getattr(mgr.config, 'fallback_hosts', []) or []
        if removed_node_ip and removed_node_ip in fallback:
            fallback.remove(removed_node_ip)
            mgr.config.fallback_hosts = fallback
            logging.info(f"Removed {removed_node_ip} from fallback_hosts")
        
        # NS: Feb 2026 - Clean up HA node status for removed node
        if hasattr(mgr, 'ha_node_status') and node_name in mgr.ha_node_status:
            with mgr.ha_lock:
                del mgr.ha_node_status[node_name]
            logging.info(f"[RemoveNode] Cleaned up HA tracking for {node_name}")
        
        # Clean up HA recovery state
        if hasattr(mgr, 'ha_recovery_in_progress'):
            mgr.ha_recovery_in_progress.pop(node_name, None)
        
        # Save changes to database
        save_config()
        
        # NS: Feb 2026 - Full fallback rediscovery in background
        # This ensures the fallback list is fully accurate after removal
        def _post_remove_update():
            """Background: rediscover fallback hosts after node removal"""
            time.sleep(5)  # Wait for cluster to settle
            try:
                mgr.connect_to_proxmox()
                if hasattr(mgr, '_auto_discover_fallback_hosts'):
                    mgr.config.fallback_hosts = []  # Clear and rediscover
                    mgr._auto_discover_fallback_hosts()
                    logging.info(f"[RemoveNode] Rediscovered fallback hosts: {mgr.config.fallback_hosts}")
                    save_config()
                if hasattr(mgr, 'ha_enabled') and mgr.ha_enabled and hasattr(mgr, '_ha_update_fallback_hosts'):
                    mgr._ha_update_fallback_hosts()
            except Exception as e:
                logging.warning(f"[RemoveNode] Post-remove update error (non-critical): {e}")
        
        threading.Thread(target=_post_remove_update, daemon=True).start()
        
        # Log the action
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'cluster.node_removed', f"Node {node_name} removed from cluster", cluster=mgr.config.name)
        
        # Broadcast the change
        broadcast_action('node_removed', 'cluster', node_name, {}, cluster_id, user)
        
        return jsonify({
            'success': True,
            'message': f'Node {node_name} has been removed from the cluster',
            'cleanup': cleanup_result
        })
        
    except paramiko.AuthenticationException:
        return jsonify({'success': False, 'error': 'SSH authentication failed. Check cluster credentials.'}), 401
    except Exception as e:
        logging.error(f"Error removing node from cluster: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Node Action API (reboot/shutdown)
@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/action/<action>', methods=['POST'])
@require_auth(perms=['node.reboot'])
def node_action_api(cluster_id, node_name, action):
    """Perform action on node (reboot, shutdown) - requires maintenance mode"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    if action not in ['reboot', 'shutdown']:
        return jsonify({'error': f'Invalid action: {action}. Valid: reboot, shutdown'}), 400
    
    paramiko = get_paramiko()
    if not paramiko:
        return jsonify({'error': 'SSH not available. Install paramiko: pip install paramiko'}), 500
    
    mgr = cluster_managers[cluster_id]
    
    # check node is in maintenance
    if node_name not in mgr.nodes_in_maintenance:
        return jsonify({'error': f'Node {node_name} not in maintenance mode'}), 400
    
    maintenance_task = mgr.nodes_in_maintenance[node_name]
    if maintenance_task.status not in ['completed', 'completed_with_errors']:
        return jsonify({'error': 'Evacuation still in progress'}), 400
    
    user = getattr(request, 'session', {}).get('user', 'system')
    
    try:
        node_ip = mgr._get_node_ip(node_name)
        if not node_ip:
            return jsonify({'error': f'Could not determine IP for {node_name}'}), 500
        
        ssh = mgr._ssh_connect(node_ip)
        if not ssh:
            if not getattr(mgr.config, 'ssh_key', ''):
                return jsonify({'error': 'SSH connection failed'}), 500
            return jsonify({'error': 'SSH connection failed.'}), 500
        
        try:
            # Check if we're already root (common on Proxmox)
            stdin, stdout, stderr = ssh.exec_command('id -u')
            uid = stdout.read().decode().strip()
            is_root = (uid == '0')
            
            # Always use PTY for reliable execution
            transport = ssh.get_transport()
            channel = transport.open_session()
            channel.get_pty()
            channel.settimeout(10)
            
            # Use shutdown commands which are more reliable
            if is_root:
                if action == 'reboot':
                    channel.exec_command('shutdown -r now')
                else:
                    channel.exec_command('shutdown -h now')
            else:
                if action == 'reboot':
                    channel.exec_command('sudo shutdown -r now')
                else:
                    channel.exec_command('sudo shutdown -h now')
            
            # Wait briefly for command to be sent
            time.sleep(2)
            
            # Try to read any output
            try:
                output = channel.recv(1024).decode()
                logging.info(f"Node {action} output: {output}")
            except:
                pass
            
            channel.close()
            ssh.close()
            
            # Audit log
            log_audit(user, f'node.{action}', f"Node {node_name} {action} initiated")
            
            # Broadcast to all clients
            broadcast_action(f'node_{action}', 'node', node_name, {}, cluster_id, user)
            
            return jsonify({
                'success': True,
                'message': f'Node {node_name} {action} initiated'
            })
            
        except Exception as e:
            ssh.close()
            logging.error(f"Error executing {action} on {node_name}: {e}")
            return jsonify({'error': str(e)}), 500
            
    except Exception as e:
        logging.error(f"Node action error: {e}")
        return jsonify({'error': str(e)}), 500


# Node Update API Routes
@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/update', methods=['POST'])
@require_auth(perms=['node.update'])
def start_node_update(cluster_id, node_name):
    """Start updating a node (must be in maintenance mode unless force=true)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    paramiko = get_paramiko()
    if not paramiko:
        return jsonify({'error': 'SSH nicht verfuegbar. Bitte installiere paramiko'}), 500
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    reboot = data.get('reboot', True)
    force = data.get('force', False)
    
    # check maintenance mode (unless force)
    if not force:
        if node_name not in mgr.nodes_in_maintenance:
            return jsonify({'error': f'Node {node_name} ist nicht im Wartungsmodus.'}), 400
        
        maintenance_task = mgr.nodes_in_maintenance[node_name]
        if maintenance_task.status not in ['completed', 'completed_with_errors']:
            return jsonify({'error': f'Evacuation in progress.'}), 400
    
    task = mgr.start_node_update(node_name, reboot, force)
    
    if task:
        usr = getattr(request, 'session', {}).get('user', 'system')
        mode = "(forced)" if force else "(maintenance)"
        log_audit(usr, 'node.update_started', f"Node {node_name} update started {mode}", cluster=mgr.config.name)
        return jsonify({
            'success': True,
            'message': f'Update started for {node_name}',
            'task': task.to_dict()
        })
    else:
        return jsonify({'error': 'Update konnte nicht gestartet werden'}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/update', methods=['GET'])
@require_auth(perms=['node.view'])
def get_update_status(cluster_id, node_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    status = mgr.get_update_status(node_name)
    
    return jsonify(status if status else {'is_updating': False})


@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/update', methods=['DELETE'])
@require_auth(perms=['node.update'])
def clear_update_status_api(cluster_id, node_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    success = mgr.clear_update_status(node_name)
    
    if success:
        return jsonify({'message': f'Update status cleared for {node_name}'})
    return jsonify({'error': f'No completed update found for {node_name}'}), 400


# VM Control API Routes
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/<action>', methods=['POST'])
@require_auth()
def vm_action_api(cluster_id, node, vm_type, vmid, action):
    """Perform action on VM (start, stop, shutdown, reboot, reset, suspend, resume)
    
    NS: Updated Dec 2025 - Now checks VM-specific ACLs
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    logging.info(f"[VM-ACTION] Received: {action} on {vm_type}/{vmid} at {node}, cluster={cluster_id}")
    
    # check cluster access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    valid_actions = ['start', 'stop', 'shutdown', 'reboot', 'reset', 'suspend', 'resume']
    if action not in valid_actions:
        return jsonify({'error': f'Invalid action. Valid actions: {valid_actions}'}), 400
    
    # check permission for action - now uses VM ACLs
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']  # MK: make sure username is set
    
    perm_map = {
        'start': 'vm.start',
        'stop': 'vm.stop',
        'shutdown': 'vm.stop',
        'reboot': 'vm.restart',
        'reset': 'vm.restart',
        'suspend': 'vm.stop',
        'resume': 'vm.start'
    }
    required_perm = perm_map.get(action, 'vm.start')
    
    # LW: Use VM-specific ACL check instead of general permission
    # MK: Added vm_type for pool permission check
    if not user_can_access_vm(user, cluster_id, vmid, required_perm, vm_type):
        logging.warning(f"[VM-ACTION] Permission denied for {request.session['user']}: {required_perm} on VM {vmid}")
        return jsonify({'error': f'Permission denied: {required_perm}'}), 403
    
    # Check for force parameter (for force stop) - handle empty body gracefully
    force = False
    try:
        if request.is_json and request.data:
            data = request.get_json(silent=True) or {}
            force = data.get('force', False)
            logging.info(f"[VM-ACTION] Force parameter: {force}, raw data: {request.data}")
    except Exception as e:
        logging.warning(f"[VM-ACTION] Error parsing body: {e}")
    
    logging.info(f"[VM-ACTION] Executing {action} with force={force}")
    manager = cluster_managers[cluster_id]
    try:
        result = manager.vm_action(node, vmid, vm_type, action, force=force)
    except Exception as e:
        logging.error(f"[VM-ACTION] Unhandled error: {action} on {vm_type}/{vmid}: {e}", exc_info=True)
        return jsonify({'error': f'{action} failed: {str(e)}'}), 500

    if result['success']:
        # Audit log
        usr = getattr(request, 'session', {}).get('user', 'system')
        action_map = {'start': 'vm.started', 'stop': 'vm.stopped', 'shutdown': 'vm.stopped',
                      'reboot': 'vm.restarted', 'reset': 'vm.restarted', 'suspend': 'vm.suspended', 'resume': 'vm.resumed'}
        log_audit(usr, action_map.get(action, f'vm.{action}'), f"{vm_type.upper()} {vmid} on {node} - {action}" + (" (force)" if force else ""), cluster=manager.config.name)

        # Broadcast action to all clients for real-time updates
        broadcast_action(action, vm_type, str(vmid), {'node': node, 'force': force}, cluster_id, usr)

        # NS: Push immediate resource update for faster UI feedback
        push_immediate_update(cluster_id, delay=0.5)

        # NS: Register which PegaProx user initiated this task
        upid = result.get('data')
        if upid:
            register_task_user(upid, usr, cluster_id)

        return jsonify({'message': f'{action} successful for VM {vmid}', 'data': result.get('data')})
    else:
        # Return 400 for client errors (like LXC reset), 500 for server errors
        error_msg = result.get('error', 'Unknown error')
        status_code = 400 if 'not supported' in error_msg.lower() else 500
        return jsonify({'error': error_msg}), status_code


@bp.route('/api/clusters/<cluster_id>/nextid', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_next_vmid_api(cluster_id):
    # check cluster access
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.get_next_vmid()
    
    if result['success']:
        return jsonify({'vmid': result['vmid']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/clone', methods=['POST'])
@require_auth(perms=['vm.clone'])
def clone_vm_api(cluster_id, node, vm_type, vmid):
    """Clone a VM or container"""
    # tenant check
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check pool permission for vm.clone
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.clone', vm_type):
        return jsonify({'error': 'Permission denied: vm.clone'}), 403
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    newid = data.get('newid')
    if not newid:
        # Get next available VMID
        next_result = manager.get_next_vmid()
        if next_result['success']:
            newid = next_result['vmid']
        else:
            return jsonify({'error': 'Could not get next VMID'}), 500
    
    result = manager.clone_vm(
        node=node,
        vmid=vmid,
        vm_type=vm_type,
        newid=int(newid),
        name=data.get('name'),
        full=data.get('full', True),
        target_node=data.get('target_node'),
        target_storage=data.get('target_storage'),
        description=data.get('description')
    )
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.cloned', f"{vm_type.upper()} {vmid} cloned to {newid}" + (f" as '{data.get('name')}'" if data.get('name') else ""), cluster=manager.config.name)
        
        # NS: Register PegaProx user for this task
        upid = result.get('data')
        if upid:
            register_task_user(upid, user, cluster_id)
        
        # NS: Push immediate update for live UI
        push_immediate_update(cluster_id, delay=0.5)
        
        return jsonify({
            'message': f'Clone gestartet: {vmid} -> {newid}',
            'newid': newid,
            'data': result.get('data')
        })
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/console', methods=['GET'])
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vnc', methods=['GET'])
@require_auth()
def get_console_ticket(cluster_id, node, vm_type, vmid):
    """Get VNC console ticket for VM - NS: Now uses VM ACLs"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check VM-specific access
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    
    # MK: Added vm_type for pool permission check
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.console', vm_type):
        return jsonify({'error': 'Permission denied: vm.console'}), 403
    
    mgr = cluster_managers[cluster_id]
    result = mgr.get_vnc_ticket(node, vmid, vm_type)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result.get('error', 'Failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/shell', methods=['POST'])
@require_auth(perms=['node.shell'])
def get_node_shell_ticket(cluster_id, node):
    """Get shell ticket for node - requires node.shell permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.get_node_shell_ticket(node)
    
    # audit - shell access is sensitive
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'node.shell_access', f"Shell access requested for node {node}", cluster=mgr.config.name)
    
    if result['success']:
        return jsonify(result)
    else:
        return jsonify({'error': result['error']}), 500


# VM Config API Routes
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/config', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_config_api(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.get_vm_config(node, vmid, vm_type)
    
    if result['success']:
        return jsonify(result['config'])
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/lock', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_lock_status_api(cluster_id, node, vm_type, vmid):
    """Get lock status of a VM/CT"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        result = mgr.get_vm_lock_status(node, vmid, vm_type)
        
        if result.get('success'):
            return jsonify({
                'locked': result.get('locked', False),
                'lock_reason': result.get('lock_reason'),
                'lock_description': result.get('lock_description'),
                'unlock_command': f"qm unlock {vmid}" if vm_type == 'qemu' else f"pct unlock {vmid}"
            })
        else:
            # MK: Return not-locked instead of error for better UX
            # The VM config might not be accessible but that doesn't mean it's locked
            logging.warning(f"Could not get lock status for {vm_type}/{vmid}: {result.get('error')}")
            return jsonify({
                'locked': False,
                'lock_reason': None,
                'lock_description': None,
                'unlock_command': None,
                'note': 'Could not determine lock status'
            })
    except Exception as e:
        logging.error(f"Error getting lock status for {vm_type}/{vmid}: {e}")
        return jsonify({
            'locked': False,
            'lock_reason': None,
            'lock_description': None,
            'unlock_command': None
        })


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/unlock', methods=['POST'])
@require_auth(perms=['vm.power'])
def unlock_vm_api(cluster_id, node, vm_type, vmid):
    """Unlock a VM/CT - use with caution!"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.unlock_vm(node, vmid, vm_type)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'vm.unlock', f"Unlocked {vm_type}/{vmid} on {node} (was: {result.get('lock_reason', 'unknown')})", cluster=mgr.config.name)
        return jsonify({
            'message': result['message'],
            'was_locked': result.get('was_locked', False),
            'lock_reason': result.get('lock_reason')
        })
    else:
        return jsonify({'error': result['error']}), 500


# NS: Issue #50 - Guest Agent info (hostname, OS, kernel)
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/guest-info', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_guest_info_api(cluster_id, node, vm_type, vmid):
    """Get QEMU Guest Agent info (hostname, OS version, kernel)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    if vm_type != 'qemu':
        return jsonify({'agent_running': False}), 200
    
    mgr = cluster_managers[cluster_id]
    result = {'agent_running': False, 'hostname': None, 'os_pretty_name': None,
              'os_id': None, 'os_version': None, 'os_kernel': None, 'os_machine': None}
    
    try:
        session = mgr._create_session()
        base = f"https://{mgr.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent"
        
        try:
            resp = session.get(f"{base}/get-host-name", timeout=8)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('result', {})
                result['hostname'] = data.get('host-name')
                result['agent_running'] = True
        except Exception:
            pass
        
        try:
            resp = session.get(f"{base}/get-osinfo", timeout=8)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('result', {})
                result['os_pretty_name'] = data.get('pretty-name')
                result['os_id'] = data.get('id')
                result['os_version'] = data.get('version-id') or data.get('version')
                result['os_kernel'] = data.get('kernel-release')
                result['os_machine'] = data.get('machine')
                result['agent_running'] = True
        except Exception:
            pass
    except Exception as e:
        result['error'] = str(e)
    
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/rrd/<timeframe>', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_rrd_api(cluster_id, node, vm_type, vmid, timeframe):
    """Get VM RRD metrics data for graphs
    
    Timeframes: hour, day, week, month, year
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    valid_timeframes = ['hour', 'day', 'week', 'month', 'year']
    if timeframe not in valid_timeframes:
        return jsonify({'error': f'Invalid timeframe. Valid: {valid_timeframes}'}), 400
    
    mgr = cluster_managers[cluster_id]
    result = mgr.get_vm_rrd(node, vmid, vm_type, timeframe)
    
    if result['success']:
        return jsonify(result['data'])
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/config', methods=['PUT'])
@require_auth(perms=['vm.config'])
def update_vm_config_api(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check pool permission for vm.config
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.config', vm_type):
        return jsonify({'error': 'Permission denied: vm.config'}), 403
    
    manager = cluster_managers[cluster_id]
    config_updates = request.json or {}
    
    result = manager.update_vm_config(node, vmid, vm_type, config_updates)
    
    if result['success']:
        # NS: Broadcast VM config change via SSE for live UI updates
        try:
            updated_config = manager.get_vm_config(node, vmid, vm_type)
            if updated_config.get('success'):
                broadcast_sse('vm_config', {
                    'vmid': vmid,
                    'node': node,
                    'vm_type': vm_type,
                    'config': updated_config.get('config', {})
                }, cluster_id)
        except Exception as e:
            logging.debug(f"Failed to broadcast vm_config SSE: {e}")
        
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        changes = ', '.join([f"{k}={v}" for k, v in config_updates.items()][:5])
        log_audit(user, 'vm.config_changed', f"{vm_type.upper()} {vmid} config updated: {changes}", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/sanitize-boot-order', methods=['POST'])
@require_auth(perms=['vm.config'])
def sanitize_boot_order_api(cluster_id, node, vm_type, vmid):
    """Sanitize boot order by removing non-existent devices.
    
    NS: Feb 2026 - Fixes 'invalid bootorder: device does not exist' errors.
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.config', vm_type):
        return jsonify({'error': 'Permission denied: vm.config'}), 403
    
    manager = cluster_managers[cluster_id]
    result = manager.sanitize_boot_order(node, vmid, vm_type)
    
    if result['success']:
        if result.get('changed'):
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.boot_order_sanitized', f"{vm_type.upper()} {vmid} boot order sanitized", cluster=manager.config.name)
        return jsonify(result)
    else:
        return jsonify({'error': result['error']}), 500


# =====================================================
# PCI / USB / SERIAL PASSTHROUGH API
# =====================================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hardware/pci', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_pci_devices(cluster_id, node):
    """Get available PCI devices on a node for passthrough"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/nodes/{node}/hardware/pci"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            devices = response.json().get('data', [])
            # Enhance device info with friendly names
            for device in devices:
                device['display_name'] = f"{device.get('vendor_name', 'Unknown')} {device.get('device_name', device.get('id', 'Unknown'))}"
                device['passthrough_capable'] = device.get('iommugroup', -1) >= 0
            return jsonify(devices)
        return jsonify([])
    except Exception as e:
        logging.error(f"Error getting PCI devices: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hardware/usb', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_usb_devices(cluster_id, node):
    """Get available USB devices on a node for passthrough"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/nodes/{node}/hardware/usb"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            devices = response.json().get('data', [])
            # Add display name
            for device in devices:
                vendor = device.get('manufacturer', device.get('vendid', 'Unknown'))
                product = device.get('product', device.get('prodid', 'Unknown'))
                device['display_name'] = f"{vendor} - {product}"
            return jsonify(devices)
        return jsonify([])
    except Exception as e:
        logging.error(f"Error getting USB devices: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/passthrough', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_passthrough_devices(cluster_id, node, vmid):
    """Get current passthrough devices configured for a VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        r = manager._create_session().get(url, timeout=10)
        
        if r.status_code != 200:
            return jsonify({'error': 'Failed: VM config'}), 500
        
        config = r.json().get('data', {})
        
        # extract passthrough devices
        passthrough = {
            'pci': [],
            'usb': [],
            'serial': []
        }
        
        for key, value in config.items():
            # PCI devices
            if key.startswith('hostpci'):
                slot = key.replace('hostpci', '')
                passthrough['pci'].append({
                    'slot': slot,
                    'key': key,
                    'value': value,
                    'parsed': _parse_pci_config(value)
                })
            
            # USB devices
            if key.startswith('usb') and key[3:].isdigit():
                slot = key.replace('usb', '')
                passthrough['usb'].append({
                    'slot': slot,
                    'key': key,
                    'value': value,
                    'parsed': _parse_usb_config(value)
                })
            
            # Serial ports
            if key.startswith('serial'):
                slot = key.replace('serial', '')
                passthrough['serial'].append({
                    'slot': slot,
                    'key': key,
                    'value': value
                })
        
        return jsonify(passthrough)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/passthrough/pci', methods=['POST'])
@require_auth(perms=['vm.config'])
def add_pci_passthrough(cluster_id, node, vmid):
    """Add a PCI device passthrough to a VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    
    try:
        host = manager.current_host or manager.config.host
        
        # Find next available hostpci slot
        config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        config_response = manager._create_session().get(config_url, timeout=10)
        config = config_response.json().get('data', {}) if config_response.status_code == 200 else {}
        
        # Find free slot (0-15)
        used_slots = [int(k.replace('hostpci', '')) for k in config.keys() if k.startswith('hostpci')]
        next_slot = 0
        while next_slot in used_slots and next_slot < 16:
            next_slot += 1
        
        if next_slot >= 16:
            return jsonify({'error': 'No free PCI slots available'}), 400
        
        # Build PCI passthrough config
        pci_config = device_id
        if data.get('pcie'):
            pci_config += ',pcie=1'
        if data.get('rombar') is False:
            pci_config += ',rombar=0'
        if data.get('x-vga'):
            pci_config += ',x-vga=1'
        
        # Update VM config
        update_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {f'hostpci{next_slot}': pci_config}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.pci_added', f"VM {vmid}: Added PCI device {device_id} at slot {next_slot}", cluster=manager.config.name)
            return jsonify({'message': f'PCI device added at hostpci{next_slot}', 'slot': next_slot})
        else:
            return jsonify({'error': response.text}), 500
            
    except Exception as e:
        logging.error(f"Error adding PCI passthrough: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/passthrough/usb', methods=['POST'])
@require_auth(perms=['vm.config'])
def add_usb_passthrough(cluster_id, node, vmid):
    """Add a USB device passthrough to a VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    
    # USB can be specified by vendor:product ID or by host bus/port
    vendor_id = data.get('vendorid')
    product_id = data.get('productid')
    host_bus = data.get('hostbus')
    host_port = data.get('hostport')
    
    if not ((vendor_id and product_id) or (host_bus and host_port)):
        return jsonify({'error': 'Either vendorid+productid or hostbus+hostport required'}), 400
    
    try:
        host = manager.current_host or manager.config.host
        
        # Find next available usb slot
        config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        config_response = manager._create_session().get(config_url, timeout=10)
        config = config_response.json().get('data', {}) if config_response.status_code == 200 else {}
        
        # Find free slot (0-4)
        used_slots = [int(k.replace('usb', '')) for k in config.keys() if k.startswith('usb') and k[3:].isdigit()]
        next_slot = 0
        while next_slot in used_slots and next_slot < 5:
            next_slot += 1
        
        if next_slot >= 5:
            return jsonify({'error': 'No free USB slots available (max 5)'}), 400
        
        # Build USB config
        if vendor_id and product_id:
            usb_config = f"host={vendor_id}:{product_id}"
        else:
            usb_config = f"host={host_bus}-{host_port}"
        
        if data.get('usb3'):
            usb_config += ',usb3=1'
        
        # Update VM config
        update_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {f'usb{next_slot}': usb_config}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.usb_added', f"VM {vmid}: Added USB device at slot {next_slot}", cluster=manager.config.name)
            return jsonify({'message': f'USB device added at usb{next_slot}', 'slot': next_slot})
        else:
            return jsonify({'error': response.text}), 500
            
    except Exception as e:
        logging.error(f"Error adding USB passthrough: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/passthrough/serial', methods=['POST'])
@require_auth(perms=['vm.config'])
def add_serial_port(cluster_id, node, vmid):
    """Add a serial port to a VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    serial_type = data.get('type', 'socket')  # socket, pty, or /dev/xxx
    
    try:
        host = manager.current_host or manager.config.host
        
        # Find next available serial slot
        config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        config_response = manager._create_session().get(config_url, timeout=10)
        config = config_response.json().get('data', {}) if config_response.status_code == 200 else {}
        
        # Find free slot (0-3)
        used_slots = [int(k.replace('serial', '')) for k in config.keys() if k.startswith('serial')]
        next_slot = 0
        while next_slot in used_slots and next_slot < 4:
            next_slot += 1
        
        if next_slot >= 4:
            return jsonify({'error': 'No free serial slots available (max 4)'}), 400
        
        # Update VM config
        update_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {f'serial{next_slot}': serial_type}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.serial_added', f"VM {vmid}: Added serial port at slot {next_slot}", cluster=manager.config.name)
            return jsonify({'message': f'Serial port added at serial{next_slot}', 'slot': next_slot})
        else:
            return jsonify({'error': response.text}), 500
            
    except Exception as e:
        logging.error(f"Error adding serial port: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/passthrough/<device_type>/<key>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def remove_passthrough_device(cluster_id, node, vmid, device_type, key):
    """Remove a passthrough device from a VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    # Validate device type and key
    valid_prefixes = {'pci': 'hostpci', 'usb': 'usb', 'serial': 'serial'}
    if device_type not in valid_prefixes:
        return jsonify({'error': 'Invalid device type'}), 400
    
    # Key should be like hostpci0, usb1, serial0
    expected_prefix = valid_prefixes[device_type]
    if not key.startswith(expected_prefix):
        return jsonify({'error': f'Invalid key for {device_type}'}), 400
    
    try:
        host = manager.current_host or manager.config.host
        
        # Delete by setting to empty/delete
        update_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {'delete': key}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, f'vm.{device_type}_removed', f"VM {vmid}: Removed {key}", cluster=manager.config.name)
            return jsonify({'message': f'Device {key} removed'})
        else:
            return jsonify({'error': response.text}), 500
            
    except Exception as e:
        logging.error(f"Error removing passthrough device: {e}")
        return jsonify({'error': str(e)}), 500


def _parse_pci_config(config_str):
    """Parse PCI passthrough config string"""
    result = {'device': None, 'options': {}}
    if not config_str:
        return result
    
    parts = config_str.split(',')
    result['device'] = parts[0]
    
    for part in parts[1:]:
        if '=' in part:
            key, value = part.split('=', 1)
            result['options'][key] = value
    
    return result


def _parse_usb_config(config_str):
    """Parse USB passthrough config string"""
    result = {'host': None, 'options': {}}
    if not config_str:
        return result
    
    parts = config_str.split(',')
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            if key == 'host':
                result['host'] = value
            else:
                result['options'][key] = value
    
    return result


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/resize', methods=['PUT'])
@require_auth(perms=['vm.config'])
def resize_vm_disk_api(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    disk = data.get('disk')
    size = data.get('size')
    
    if not disk or not size:
        return jsonify({'error': 'disk and size required'}), 400
    
    result = manager.resize_vm_disk(node, vmid, vm_type, disk, size)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.disk_resized', f"{vm_type.upper()} {vmid} disk {disk} resized to {size}", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/storage', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_storage_list_api(cluster_id, node):
    """Get available storage on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    storage = manager.get_storage_list(node)
    return jsonify(storage)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/networks', methods=['GET'])
@require_auth(perms=['node.view'])
def get_network_list_api(cluster_id, node):
    """Get available networks on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    networks = manager.get_network_list(node)
    return jsonify(networks)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/isos', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_iso_list_api(cluster_id, node):
    """Get available ISO images on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    storage = request.args.get('storage')
    isos = manager.get_iso_list(node, storage)
    return jsonify(isos)


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/disks', methods=['POST'])
@require_auth(perms=['vm.config'])
def add_disk_api(cluster_id, node, vm_type, vmid):
    """Add a disk to VM or container"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    disk_config = request.json or {}
    
    result = manager.add_disk(node, vmid, vm_type, disk_config)
    
    if result['success']:
        # NS: Broadcast VM config change via SSE for live UI updates
        try:
            updated_config = manager.get_vm_config(node, vmid, vm_type)
            if updated_config.get('success'):
                broadcast_sse('vm_config', {
                    'vmid': vmid,
                    'node': node,
                    'vm_type': vm_type,
                    'config': updated_config.get('config', {})
                }, cluster_id)
        except Exception as e:
            logging.debug(f"Failed to broadcast vm_config SSE: {e}")
        
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.disk_added', f"{vm_type.upper()} {vmid} - disk added: {disk_config.get('size', 'unknown')}GB on {disk_config.get('storage', 'default')}", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/disks/<disk_id>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def remove_disk_api(cluster_id, node, vm_type, vmid, disk_id):
    """Remove disk from VM - boot order cleanup is now handled in remove_disk method"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    delete_data = request.args.get('delete_data', 'false').lower() == 'true'
    
    result = manager.remove_disk(node, vmid, vm_type, disk_id, delete_data)
    
    if result['success']:
        # NS: Broadcast VM config change via SSE for live UI updates
        try:
            updated_config = manager.get_vm_config(node, vmid, vm_type)
            if updated_config.get('success'):
                broadcast_sse('vm_config', {
                    'vmid': vmid,
                    'node': node,
                    'vm_type': vm_type,
                    'config': updated_config.get('config', {})
                }, cluster_id)
        except Exception as e:
            logging.debug(f"Failed to broadcast vm_config SSE: {e}")
        
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.disk_removed', f"{vm_type.upper()} {vmid} - disk {disk_id} removed" + (" (data deleted)" if delete_data else ""), cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/disks/<disk_id>/move', methods=['POST'])
@require_auth(perms=['vm.config'])
def move_disk_api(cluster_id, node, vm_type, vmid, disk_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    target_storage = data.get('storage')
    delete_original = data.get('delete', True)
    
    if not target_storage:
        return jsonify({'error': 'Target storage required'}), 400
    
    result = manager.move_disk(node, vmid, vm_type, disk_id, target_storage, delete_original)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.disk_moved', f"{vm_type.upper()} {vmid} - disk {disk_id} moved to {target_storage}", cluster=manager.config.name)
        
        # NS: Register PegaProx user for this task
        upid = result.get('task') or result.get('upid')
        if upid:
            register_task_user(upid, user, cluster_id)
        
        return jsonify({'message': result['message'], 'task': result.get('task')})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/cdrom', methods=['PUT'])
@require_auth(perms=['vm.config'])
def set_cdrom_api(cluster_id, node, vmid):
    """Set or eject CD-ROM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    iso_path = data.get('iso')  # None to eject
    drive = data.get('drive', 'ide2')
    
    result = manager.set_cdrom(node, vmid, iso_path, drive)
    
    if result['success']:
        # NS: Broadcast VM config change via SSE for live UI updates
        try:
            updated_config = manager.get_vm_config(node, vmid, 'qemu')
            if updated_config.get('success'):
                broadcast_sse('vm_config', {
                    'vmid': vmid,
                    'node': node,
                    'vm_type': 'qemu',
                    'config': updated_config.get('config', {})
                }, cluster_id)
        except Exception as e:
            logging.debug(f"Failed to broadcast vm_config SSE: {e}")
        
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/networks', methods=['POST'])
@require_auth(perms=['vm.config'])
def add_network_api(cluster_id, node, vm_type, vmid):
    """Add a network interface"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    net_config = request.json or {}
    
    result = manager.add_network(node, vmid, vm_type, net_config)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.network_added', f"{vm_type.upper()} {vmid} - network added: bridge={net_config.get('bridge', 'default')}", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/networks/<net_id>', methods=['PUT'])
@require_auth(perms=['vm.config'])
def update_network_api(cluster_id, node, vm_type, vmid, net_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    net_config = request.json or {}
    
    result = manager.update_network(node, vmid, vm_type, net_id, net_config)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.network_updated', f"{vm_type.upper()} {vmid} - network {net_id} updated", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/networks/<net_id>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def remove_network_api(cluster_id, node, vm_type, vmid, net_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    result = manager.remove_network(node, vmid, vm_type, net_id)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'vm.network_removed', f"{vm_type.upper()} {vmid} - network {net_id} removed", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/networks/<net_id>/link', methods=['PUT'])
@require_auth(perms=['vm.config'])
def toggle_network_link_api(cluster_id, node, vm_type, vmid, net_id):
    """Toggle network link_down state - simulates cable unplug
    
    NS: This is a hot-pluggable operation for QEMU VMs (no reboot needed)
    LW: Very useful for testing network failover scenarios
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Only QEMU supports link_down toggle
    if vm_type != 'qemu':
        return jsonify({'error': 'Network disconnect only supported for QEMU VMs'}), 400
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    link_down = data.get('link_down', False)
    
    result = manager.toggle_network_link(node, vmid, net_id, link_down)
    
    if result['success']:
        user = getattr(request, 'session', {}).get('user', 'system')
        action = 'disconnected' if link_down else 'connected'
        log_audit(user, 'vm.network_link_toggle', f"QEMU {vmid} - network {net_id} {action}", cluster=manager.config.name)
        return jsonify({'message': result['message']})
    else:
        return jsonify({'error': result['error']}), 500


# ==================== SNAPSHOT API ROUTES ====================

@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshot-capability', methods=['GET'])
@require_auth(perms=['vm.view'])
def check_snapshot_capability_api(cluster_id, node, vm_type, vmid):
    """Check if VM/CT can create snapshots and why not"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    result = manager.check_snapshot_capability(node, vmid, vm_type)
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshots', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_snapshots_api(cluster_id, node, vm_type, vmid):
    """Get list of snapshots for a VM/CT"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    snapshots = manager.get_snapshots(node, vmid, vm_type)
    return jsonify(snapshots)


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshots', methods=['POST'])
@require_auth(perms=['vm.snapshot'])
def create_snapshot_api(cluster_id, node, vm_type, vmid):
    # tenant check
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check pool permission for vm.snapshot
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    
    snapname = data.get('snapname', f'snap_{int(time.time())}')
    description = data.get('description', '')
    vmstate = data.get('vmstate', False)
    
    result = mgr.create_snapshot(node, vmid, vm_type, snapname, description, vmstate)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'snapshot.created', f"{vm_type.upper()} {vmid} - snapshot '{snapname}' created" + (" (with RAM)" if vmstate else ""), cluster=mgr.config.name)
        return jsonify({'message': f'Snapshot {snapname} erstellt', 'task': result.get('task')})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshots/<snapname>', methods=['DELETE'])
@require_auth(perms=['vm.snapshot'])
def delete_snapshot_api(cluster_id, node, vm_type, vmid, snapname):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check pool permission for vm.snapshot
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403
    
    mgr = cluster_managers[cluster_id]
    result = mgr.delete_snapshot(node, vmid, vm_type, snapname)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'snapshot.deleted', f"{vm_type.upper()} {vmid} - snapshot '{snapname}' deleted", cluster=mgr.config.name)
        return jsonify({'message': f'Snapshot deleted', 'task': result.get('task')})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshots/<snapname>/rollback', methods=['POST'])
@require_auth(perms=['vm.snapshot'])
def rollback_snapshot_api(cluster_id, node, vm_type, vmid, snapname):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check pool permission for vm.snapshot
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403
    
    mgr = cluster_managers[cluster_id]
    result = mgr.rollback_snapshot(node, vmid, vm_type, snapname)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'snapshot.restored', f"{vm_type.upper()} {vmid} - rolled back to snapshot '{snapname}'", cluster=mgr.config.name)
        return jsonify({'message': f'Rollback zu {snapname} gestartet', 'task': result.get('task')})
    else:
        return jsonify({'error': result['error']}), 500


# ==================== EFFICIENT (LVM COW) SNAPSHOT API ====================
# NS: Feb 2026 - Space-efficient snapshot endpoints

@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/efficient-snapshots', methods=['GET'])
@require_auth(perms=['vm.snapshot'])
def get_efficient_snapshots_api(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403

    mgr = cluster_managers[cluster_id]
    refresh = request.args.get('refresh', 'false').lower() == 'true'
    snapshots = mgr.get_efficient_snapshots(cluster_id, vmid, refresh_usage=refresh)
    return jsonify(snapshots)


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/efficient-snapshots', methods=['POST'])
@require_auth(perms=['vm.snapshot'])
def create_efficient_snapshot_api(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403

    mgr = cluster_managers[cluster_id]
    data = request.json or {}

    snapname = data.get('snapname', f'snap_{int(time.time())}')
    description = data.get('description', '')
    snap_size_gb = data.get('snap_size_gb')

    result = mgr.create_efficient_snapshot(node, vmid, vm_type, snapname, description, snap_size_gb)

    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        savings = result.get('space_savings', {})
        log_audit(usr, 'snapshot.efficient_created',
                  f"{vm_type.upper()} {vmid} - efficient snapshot '{snapname}' created "
                  f"({savings.get('efficient_size_gb', 0):.1f} GB vs {savings.get('normal_size_gb', 0):.1f} GB normal, "
                  f"{savings.get('savings_percent', 0)}% savings)",
                  cluster=mgr.config.name)
        return jsonify({
            'message': f'Platzsparender Snapshot {snapname} erstellt',
            'snap_id': result['snap_id'],
            'space_savings': result['space_savings']
        })
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/efficient-snapshots/<snap_id>', methods=['DELETE'])
@require_auth(perms=['vm.snapshot'])
def delete_efficient_snapshot_api(cluster_id, node, vm_type, vmid, snap_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403

    mgr = cluster_managers[cluster_id]
    result = mgr.delete_efficient_snapshot(node, vmid, snap_id)

    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'snapshot.efficient_deleted',
                  f"{vm_type.upper()} {vmid} - efficient snapshot deleted",
                  cluster=mgr.config.name)
        return jsonify({'message': 'Platzsparender Snapshot gelöscht'})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/efficient-snapshots/<snap_id>/rollback', methods=['POST'])
@require_auth(perms=['vm.snapshot'])
def rollback_efficient_snapshot_api(cluster_id, node, vm_type, vmid, snap_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.snapshot', vm_type):
        return jsonify({'error': 'Permission denied: vm.snapshot'}), 403

    mgr = cluster_managers[cluster_id]
    result = mgr.rollback_efficient_snapshot(node, vmid, vm_type, snap_id)

    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'snapshot.efficient_rollback',
                  f"{vm_type.upper()} {vmid} - efficient snapshot rollback started",
                  cluster=mgr.config.name)
        return jsonify({'message': result.get('message', 'Rollback gestartet')})
    else:
        return jsonify({'error': result['error']}), 500


# ==================== SNAPSHOT OVERVIEW API @gyptazy ====================

@bp.route('/api/snapshots/overview', methods=['GET', 'POST'])
@require_auth(perms=['vm.view'])
def snapshots_overview():
    """Get overview of old snapshots across all clusters or a specific cluster
    
    Returns snapshots older than specified date, sorted by age
    
    LW: Added cluster_id filter - when provided, only shows snapshots from that cluster
    """
    snapshots = []
    user = request.session.get('user', '')
    users_db = load_users()
    user_data = users_db.get(user, {})
    user_data['username'] = user
    cutoff_date = None
    data = request.get_json(silent=True) or {}
    date_compare = data.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filter_limit = data.get("limit", 100)  # LW: Increased default limit
    filter_cluster = data.get("cluster_id")  # MK: Optional cluster filter
    is_admin = user_data.get('role') == ROLE_ADMIN
    user_clusters = user_data.get('clusters', [])

    for cluster_id, mgr in cluster_managers.items():
        if not mgr.is_connected:
            continue

        # LW: Filter by specific cluster if provided
        if filter_cluster and cluster_id != filter_cluster:
            continue

        if not is_admin and user_clusters and cluster_id not in user_clusters:
            continue

        try:
            resources = mgr.get_vm_resources()

            for r in resources:
                vmid = r.get('vmid')
                node = r.get('node')
                vm_name = r.get('name') or ''
                vm_type = r.get('type', 'qemu')

                if not vmid or not node:
                    continue

                manager = cluster_managers[cluster_id]
                snapshots_present = manager.get_snapshots(node, vmid, vm_type)

                for snap in snapshots_present:
                    snap_name = snap.get('name')
                    snap_ts = snap.get('snaptime')

                    # skip invalid + implicit snapshot
                    if not snap_name or not snap_ts or snap_name == 'current':
                        continue

                    snap_dt = datetime.fromtimestamp(snap_ts, tz=timezone.utc)
                    now = datetime.now(timezone.utc)
                    age_seconds = int((now - snap_dt).total_seconds())
                    cutoff_date = datetime.strptime(date_compare, "%Y-%m-%d").replace(tzinfo=timezone.utc)

                    if snap_dt >= cutoff_date:
                        continue

                    if age_seconds < 3600:
                        age = f"{age_seconds // 60} min"
                    elif age_seconds < 86400:
                        age = f"{age_seconds // 3600} h"
                    else:
                        age = f"{age_seconds // 86400} days"

                    snapshots.append({
                        "vmid": vmid,
                        "vm_name": vm_name,
                        "vm_type": vm_type,
                        "node": node,
                        "snapshot_name": snap_name,
                        "snapshot_date": snap_dt.strftime('%Y-%m-%d %H:%M'),
                        "age": age,
                        "cluster_id": cluster_id
                    })

        except Exception as e:
            logging.debug(f"Snapshot gathering failed for cluster {cluster_id}: {e}")

    # Sort and filter snapshots
    snapshots.sort(key=lambda s: s["snapshot_date"], reverse=False)
    snapshots = snapshots[:filter_limit]

    return jsonify({
        "snapshots": snapshots
    })


@bp.route('/api/snapshots/delete', methods=['POST'])
@require_auth(perms=['vm.view', 'vm.snapshot'])
def snapshots_overview_delete():
    """Delete multiple snapshots at once
    
    Bulk delete for snapshot cleanup
    """
    user = request.session.get('user', '')
    users_db = load_users()
    user_data = users_db.get(user, {})
    user_data['username'] = user
    data = request.get_json(silent=True) or {}
    snapshots = data.get('snapshots', [])
    is_admin = user_data.get('role') == ROLE_ADMIN
    user_clusters = user_data.get('clusters', [])
    
    deleted_count = 0
    errors = []
    result = {'success': False}

    for snapshot in snapshots:
        try:
            cluster_id = snapshot.get('cluster_id')
            node = snapshot.get('node')
            vmid = snapshot.get('vmid')
            snapname = snapshot.get('snapshot_name')
            vm_type = snapshot.get('vm_type', 'qemu')
            
            if cluster_id not in cluster_managers:
                errors.append(f"Cluster {cluster_id} not found")
                continue
                
            mgr = cluster_managers[cluster_id]
            
            if not mgr.is_connected:
                errors.append(f"Cluster {cluster_id} not connected")
                continue

            if not is_admin and user_clusters and cluster_id not in user_clusters:
                errors.append(f"No access to cluster {cluster_id}")
                continue

            # MK Feb 2026 - VM-level ACL check for snapshot delete
            if not user_can_access_vm(user_data, cluster_id, vmid, 'vm.snapshot', vm_type):
                errors.append(f"Permission denied: vm.snapshot for VM {vmid}")
                continue

            result = mgr.delete_snapshot(node, vmid, vm_type, snapname)
            
            if result.get('success'):
                deleted_count += 1
                log_audit(user, 'snapshot.deleted', f"{vm_type.upper()} {vmid} - snapshot '{snapname}' deleted", cluster=mgr.config.name)
            else:
                errors.append(f"Failed to delete {snapname}: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            errors.append(f"Error deleting snapshot: {e}")
            logging.debug(f"Snapshot deletion failed: {e}")

    if deleted_count > 0:
        return jsonify({
            'success': True,
            'message': f'{deleted_count} snapshot(s) deleted',
            'deleted': deleted_count,
            'errors': errors if errors else None
        })
    else:
        return jsonify({
            'success': False,
            'error': 'No snapshots deleted',
            'errors': errors
        }), 500


# ==================== REPLICATION API ROUTES ====================

@bp.route('/api/clusters/<cluster_id>/replication', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_replication_jobs_api(cluster_id):
    """Get all replication jobs"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    vmid = request.args.get('vmid', type=int)
    jobs = manager.get_replication_jobs(vmid)
    return jsonify(jobs)


@bp.route('/api/clusters/<cluster_id>/replication', methods=['POST'])
@require_auth(perms=['cluster.config'])
def create_replication_job_api(cluster_id):
    """Create a replication job"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    vmid = data.get('vmid')
    target_node = data.get('target')
    schedule = data.get('schedule', '*/15')
    rate = data.get('rate')
    comment = data.get('comment', '')
    
    if not vmid or not target_node:
        return jsonify({'error': 'vmid and target are required'}), 400
    
    result = manager.create_replication_job(vmid, target_node, schedule, rate, comment)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'replication.created', f"VM {vmid} replication to {target_node} (schedule: {schedule})", cluster=manager.config.name)
        return jsonify({'message': 'Replication Job erstellt', 'job_id': result.get('job_id')})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/replication/<job_id>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_replication_job_api(cluster_id, job_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    keep = data.get('keep', False)
    force = data.get('force', False)
    
    result = manager.delete_replication_job(job_id, keep, force)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'replication.deleted', f"Replication job {job_id} deleted", cluster=manager.config.name)
        return jsonify({'message': f'Replication Job deleted'})
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/replication/<job_id>/run', methods=['POST'])
@require_auth(perms=['cluster.config'])
def run_replication_now_api(cluster_id, job_id):
    """Trigger immediate replication"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    result = manager.run_replication_now(job_id)
    
    if result['success']:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'replication.triggered', f"Replication job {job_id} manually triggered", cluster=manager.config.name)
        return jsonify({'message': 'Replication gestartet'})
    else:
        return jsonify({'error': result['error']}), 500


# ==================== CROSS-CLUSTER REPLICATION ====================
# MK: Feb 2026 - snapshot-based replication between clusters
# Proxmox native replication only works intra-cluster, so for DR across
# separate clusters we use snapshot + clone + remote-migrate approach.

def _execute_replication(job):
    """
    Run a single cross-cluster replication cycle for one job.

    Steps: snapshot source VM -> clone from snapshot -> remote-migrate clone
    to target cluster -> cleanup snapshot + clone on source.

    NS: This is basically the same flow as manual cross-cluster migration,
    but we snapshot first so the source VM stays untouched. The clone gets
    migrated and then deleted on the source side.
    """
    db = get_db()
    job_id = job['id']
    vmid = int(job['vmid'])
    vm_type = job.get('vm_type', 'qemu') or 'qemu'
    source_cid = job['source_cluster']
    target_cid = job['target_cluster']
    target_storage = job.get('target_storage', '') or 'local-lvm'
    target_bridge = job.get('target_bridge', 'vmbr0') or 'vmbr0'

    source_mgr = cluster_managers.get(source_cid)
    target_mgr = cluster_managers.get(target_cid)

    if not source_mgr or not target_mgr:
        _update_repl_status(db, job_id, 'error', 'Source or target cluster not found')
        return

    if not source_mgr.is_connected or not target_mgr.is_connected:
        _update_repl_status(db, job_id, 'error', 'Cluster not connected')
        return

    snap_name = f"xcrepl-{job_id}-{int(time.time())}"
    clone_vmid = None

    try:
        # 1. find which node the VM lives on
        source_node = None
        resources = source_mgr._api_get(
            f"https://{source_mgr.host}:8006/api2/json/cluster/resources",
            params={'type': 'vm'}
        )
        if resources.status_code == 200:
            for r in resources.json().get('data', []):
                if int(r.get('vmid', 0)) == vmid:
                    source_node = r.get('node')
                    break

        if not source_node:
            _update_repl_status(db, job_id, 'error', f'VM {vmid} not found on source cluster')
            return

        logging.info(f"[XCREPL] Job {job_id}: starting replication of {vm_type}/{vmid} on {source_node}")

        # 2. create snapshot
        snap_url = (
            f"https://{source_mgr.host}:8006/api2/json/nodes/{source_node}"
            f"/{vm_type}/{vmid}/snapshot"
        )
        snap_resp = source_mgr._api_post(snap_url, data={
            'snapname': snap_name,
            'description': f'Cross-cluster replication {job_id}'
        })
        if snap_resp.status_code != 200:
            _update_repl_status(db, job_id, 'error', f'Snapshot failed: {snap_resp.text}')
            return

        snap_task = snap_resp.json().get('data')
        if not _wait_for_task(source_mgr, snap_task):
            _update_repl_status(db, job_id, 'error', 'Snapshot task did not complete')
            return

        logging.info(f"[XCREPL] Job {job_id}: snapshot '{snap_name}' created")

        # 3. get next free VMID for clone
        nextid_resp = source_mgr._api_get(
            f"https://{source_mgr.host}:8006/api2/json/cluster/nextid"
        )
        if nextid_resp.status_code != 200:
            _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', 'Could not get next VMID')
            return

        clone_vmid = int(nextid_resp.json().get('data'))
        logging.debug(f"[XCREPL] Using clone VMID {clone_vmid}")

        # 4. clone from snapshot (full clone, not linked)
        clone_url = (
            f"https://{source_mgr.host}:8006/api2/json/nodes/{source_node}"
            f"/{vm_type}/{vmid}/clone"
        )
        clone_data = {
            'newid': clone_vmid,
            'snapname': snap_name,
            'full': 1,
            'name': f'xcrepl-{vmid}-tmp',
        }
        if target_storage:
            clone_data['target'] = target_storage

        clone_resp = source_mgr._api_post(clone_url, data=clone_data)
        if clone_resp.status_code != 200:
            _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', f'Clone failed: {clone_resp.text}')
            return

        clone_task = clone_resp.json().get('data')
        if not _wait_for_task(source_mgr, clone_task, timeout=1800):
            _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', 'Clone task timed out (30 min)')
            return

        logging.info(f"[XCREPL] Job {job_id}: clone {clone_vmid} created from snapshot")

        # 5. remote-migrate clone to target cluster
        # same token/fingerprint flow as cross_cluster_lb.py
        token_name = f"xcrepl-{job_id}-{int(time.time()) % 100000}"
        token = target_mgr.create_api_token(token_name)
        if not token.get('success'):
            _cleanup_clone_and_snap(source_mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', f'Token creation failed: {token.get("error")}')
            return

        try:
            fp = target_mgr.get_cluster_fingerprint()
            if not fp.get('success'):
                target_mgr.delete_api_token(token_name)
                _cleanup_clone_and_snap(source_mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
                _update_repl_status(db, job_id, 'error', f'Fingerprint failed: {fp.get("error")}')
                return

            endpoint = (
                f"apitoken=PVEAPIToken={token['token_id']}={token['token_value']},"
                f"host={fp['host']},fingerprint={fp['fingerprint']}"
            )

            # migrate the clone (offline, delete source clone after)
            result = source_mgr.remote_migrate_vm(
                node=source_node, vmid=clone_vmid, vm_type=vm_type,
                target_endpoint=endpoint, target_storage=target_storage,
                target_bridge=target_bridge, target_vmid=vmid,
                online=False, delete_source=True,
            )

            if result.get('success'):
                mig_task = result.get('task')
                _wait_for_task(source_mgr, mig_task, timeout=3600)
                logging.info(f"[XCREPL] Job {job_id}: migration complete")
                _update_repl_status(db, job_id, 'ok', '')
            else:
                _update_repl_status(db, job_id, 'error', f'Migration failed: {result.get("error")}')

        except Exception as e:
            logging.error(f"[XCREPL] Job {job_id}: migration error: {e}")
            _update_repl_status(db, job_id, 'error', str(e))
        finally:
            # always clean up token
            try:
                target_mgr.delete_api_token(token_name)
            except Exception:
                pass

        # 6. cleanup snapshot on source (clone auto-deleted by delete_source=True)
        _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)

        # LW: handle retention - delete oldest replicas on target if over limit
        retention = int(job.get('retention', 3) or 3)
        _enforce_retention(target_mgr, vmid, vm_type, snap_name, retention)

    except Exception as e:
        logging.error(f"[XCREPL] Job {job_id}: unexpected error: {e}")
        _update_repl_status(db, job_id, 'error', str(e))
        # best-effort cleanup
        if clone_vmid:
            try:
                _cleanup_clone_and_snap(source_mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
            except Exception:
                pass


def _update_repl_status(db, job_id, status, error=''):
    """Update job status in DB after a replication run."""
    try:
        db.execute(
            'UPDATE cross_cluster_replications SET last_run = ?, last_status = ?, last_error = ?, updated_at = ? WHERE id = ?',
            (datetime.now().isoformat(), status, error or '', datetime.now().isoformat(), job_id)
        )
    except Exception as e:
        logging.warning(f"[XCREPL] Could not update status for {job_id}: {e}")


def _wait_for_task(mgr, task_upid, timeout=600, poll=5):
    """Poll Proxmox task status until it finishes or times out.
    MK: similar to the cleanup thread logic but blocking.
    """
    if not task_upid:
        return False
    elapsed = 0
    while elapsed < timeout:
        try:
            tasks = mgr.get_tasks(limit=100)
            for t in tasks:
                if t and t.get('upid') == task_upid:
                    st = t.get('status', '')
                    if st and st != 'running':
                        return st == 'OK'
                    break
        except Exception:
            pass
        time.sleep(poll)
        elapsed += poll
    return False


def _cleanup_snapshot(mgr, node, vmid, vm_type, snap_name):
    """Delete a snapshot, best-effort."""
    try:
        url = (
            f"https://{mgr.host}:8006/api2/json/nodes/{node}"
            f"/{vm_type}/{vmid}/snapshot/{snap_name}"
        )
        mgr._api_delete(url)
        logging.debug(f"[XCREPL] Deleted snapshot {snap_name} on {vmid}")
    except Exception as e:
        logging.warning(f"[XCREPL] Could not delete snapshot {snap_name}: {e}")


def _cleanup_clone_and_snap(mgr, node, clone_vmid, orig_vmid, vm_type, snap_name):
    """Remove leftover clone VM + snapshot after failure."""
    # delete clone
    try:
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/{vm_type}/{clone_vmid}"
        mgr._api_delete(url)
    except Exception:
        pass
    # delete snapshot
    _cleanup_snapshot(mgr, node, orig_vmid, vm_type, snap_name)


def _enforce_retention(target_mgr, vmid, vm_type, current_snap, retention):
    """
    Remove old xcrepl snapshots on target if we exceed retention count.
    NS: We only manage snapshots we created (prefixed with 'xcrepl-').
    """
    try:
        # find the target node for this VM
        resources = target_mgr._api_get(
            f"https://{target_mgr.host}:8006/api2/json/cluster/resources",
            params={'type': 'vm'}
        )
        if resources.status_code != 200:
            return

        target_node = None
        for r in resources.json().get('data', []):
            if int(r.get('vmid', 0)) == vmid:
                target_node = r.get('node')
                break
        if not target_node:
            return

        snap_url = (
            f"https://{target_mgr.host}:8006/api2/json/nodes/{target_node}"
            f"/{vm_type}/{vmid}/snapshot"
        )
        snap_resp = target_mgr._api_get(snap_url)
        if snap_resp.status_code != 200:
            return

        xcrepl_snaps = [
            s for s in snap_resp.json().get('data', [])
            if s.get('name', '').startswith('xcrepl-') and s.get('name') != 'current'
        ]
        # sort by name (contains timestamp) so oldest first
        xcrepl_snaps.sort(key=lambda s: s.get('name', ''))

        while len(xcrepl_snaps) > retention:
            oldest = xcrepl_snaps.pop(0)
            try:
                del_url = (
                    f"https://{target_mgr.host}:8006/api2/json/nodes/{target_node}"
                    f"/{vm_type}/{vmid}/snapshot/{oldest['name']}"
                )
                target_mgr._api_delete(del_url)
                logging.info(f"[XCREPL] Retention: deleted old snapshot {oldest['name']} on target")
            except Exception as e:
                logging.warning(f"[XCREPL] Retention cleanup failed for {oldest['name']}: {e}")
    except Exception as e:
        logging.debug(f"[XCREPL] Retention check skipped: {e}")


@bp.route('/api/cross-cluster-replications', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cross_cluster_replications():
    """List cross-cluster replication jobs, optionally filtered by vmid."""
    db = get_db()
    vmid = request.args.get('vmid', type=int)

    if vmid:
        rows = db.query('SELECT * FROM cross_cluster_replications WHERE vmid = ?', (vmid,))
    else:
        rows = db.query('SELECT * FROM cross_cluster_replications')

    return jsonify([dict(r) for r in rows])


@bp.route('/api/cross-cluster-replications', methods=['POST'])
@require_auth(perms=['cluster.config'])
def create_cross_cluster_replication():
    """Create a new cross-cluster replication job."""
    data = request.json or {}

    source_cluster = data.get('source_cluster')
    target_cluster = data.get('target_cluster')
    vmid = data.get('vmid')

    if not source_cluster or not target_cluster or not vmid:
        return jsonify({'error': 'source_cluster, target_cluster and vmid are required'}), 400

    if source_cluster not in cluster_managers:
        return jsonify({'error': 'Source cluster not found'}), 404
    if target_cluster not in cluster_managers:
        return jsonify({'error': 'Target cluster not found'}), 404
    if source_cluster == target_cluster:
        return jsonify({'error': 'Source and target cluster must be different'}), 400

    job_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    db = get_db()

    db.execute('''
        INSERT INTO cross_cluster_replications
        (id, source_cluster, target_cluster, vmid, vm_type, schedule, retention,
         target_storage, target_bridge, enabled, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    ''', (
        job_id,
        source_cluster,
        target_cluster,
        int(vmid),
        data.get('vm_type', 'qemu'),
        data.get('schedule', '0 */6 * * *'),
        int(data.get('retention', 3)),
        data.get('target_storage', ''),
        data.get('target_bridge', 'vmbr0'),
        getattr(request, 'session', {}).get('user', 'system'),
        now, now,
    ))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'replication.created',
              f"Cross-cluster replication {job_id}: VM {vmid} from {source_cluster} to {target_cluster}")

    return jsonify({'success': True, 'id': job_id})


@bp.route('/api/cross-cluster-replications/<job_id>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_cross_cluster_replication(job_id):
    """Delete a cross-cluster replication job."""
    db = get_db()
    existing = db.query_one('SELECT id FROM cross_cluster_replications WHERE id = ?', (job_id,))
    if not existing:
        return jsonify({'error': 'Replication job not found'}), 404

    db.execute('DELETE FROM cross_cluster_replications WHERE id = ?', (job_id,))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'replication.deleted', f"Cross-cluster replication {job_id} deleted")

    return jsonify({'success': True})


@bp.route('/api/cross-cluster-replications/<job_id>/run', methods=['POST'])
@require_auth(perms=['cluster.config'])
def run_cross_cluster_replication(job_id):
    """Trigger a cross-cluster replication job immediately (async)."""
    db = get_db()
    job = db.query_one('SELECT * FROM cross_cluster_replications WHERE id = ?', (job_id,))
    if not job:
        return jsonify({'error': 'Replication job not found'}), 404

    # kick off in background so the API responds right away
    threading.Thread(target=_execute_replication, args=(dict(job),), daemon=True).start()

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'replication.triggered', f"Cross-cluster replication {job_id} manually triggered")

    return jsonify({'success': True, 'message': 'Replication started'})


@bp.route('/api/hardware-options', methods=['GET'])
@require_auth(perms=['node.view'])
def get_hardware_options():
    """Get available hardware options (CPU types, SCSI controllers, etc.)

    NS: Extended Dec 2025 with machine types
    """
    # Use any manager to get options
    if cluster_managers:
        manager = list(cluster_managers.values())[0]
        return jsonify({
            'cpu_types': manager.get_cpu_types(),
            'scsi_controllers': manager.get_scsi_controllers(),
            'network_models': manager.get_network_models(),
            'disk_bus_types': manager.get_disk_bus_types(),
            'cache_modes': manager.get_cache_modes(),
            'machine_types': manager.get_machine_types()
        })
    else:
        # Return defaults if no cluster configured
        return jsonify({
            'cpu_types': ['host', 'kvm64', 'qemu64', 'x86-64-v2-AES'],
            'scsi_controllers': [{'value': 'virtio-scsi-pci', 'label': 'VirtIO SCSI'}],
            'network_models': [{'value': 'virtio', 'label': 'VirtIO'}],
            'disk_bus_types': [{'value': 'scsi', 'label': 'SCSI', 'max': 30}],
            'cache_modes': [{'value': '', 'label': 'Default'}],
            'machine_types': [
                {'value': '', 'label': 'Default'},
                {'value': 'q35', 'label': 'q35 (Latest)'},
                {'value': 'pc-q35-10.1', 'label': 'q35 10.1'},
                {'value': 'pc-q35-9.2+pve1', 'label': 'q35 9.2+pve1'},
                {'value': 'pc-q35-8.2', 'label': 'q35 8.2'},
                {'value': 'i440fx', 'label': 'i440fx (Latest)'},
                {'value': 'pc-i440fx-10.1', 'label': 'i440fx 10.1'},
                {'value': 'pc-i440fx-9.2+pve1', 'label': 'i440fx 9.2+pve1'},
                {'value': 'pc-i440fx-8.2', 'label': 'i440fx 8.2'},
            ]
        })


# WebSocket proxy for VNC - using geventwebsocket
def handle_vnc_websocket(ws, cluster_id, node, vm_type, vmid):
    """Handle VNC WebSocket connection"""
    print(f"\n{'='*60}")
    print(f"VNC WEBSOCKET: {vm_type}/{vmid} on {node}")
    print(f"{'='*60}")
    
    if cluster_id not in cluster_managers:
        print(f"ERROR: Cluster {cluster_id} not found")
        return
    
    manager = cluster_managers[cluster_id]
    host = manager.current_host or manager.config.host
    
    print(f"Target host: {host}")
    
    pve_ws = None
    running = True
    
    try:
        import gevent
        from gevent import spawn, sleep as gsleep
        import urllib.parse
        import urllib.request
        import json
        import websocket
        
        # Create SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Step 1: Login
        print(f"Step 1: Login...")
        login_data = urlencode({
            'username': manager.config.user,
            'password': manager.config.pass_
        }).encode('utf-8')
        
        login_req = urllib.request.Request(
            f"https://{host}:8006/api2/json/access/ticket",
            data=login_data, method='POST'
        )
        
        with urllib.request.urlopen(login_req, context=ssl_context, timeout=10) as response:
            login_result = json.loads(response.read().decode('utf-8'))
        
        pve_ticket = login_result['data']['ticket']
        csrf_token = login_result['data']['CSRFPreventionToken']
        print(f"Got PVE ticket")
        
        # Step 2: Get VNC ticket
        print(f"Step 2: Get VNC ticket...")
        if vm_type == 'qemu':
            vnc_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
        else:
            vnc_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
        
        vnc_data = urlencode({'websocket': '1'}).encode('utf-8')
        vnc_req = urllib.request.Request(vnc_url, data=vnc_data, method='POST')
        vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
        vnc_req.add_header('CSRFPreventionToken', csrf_token)
        
        with urllib.request.urlopen(vnc_req, context=ssl_context, timeout=10) as response:
            vnc_result = json.loads(response.read().decode('utf-8'))
        
        vnc_ticket = vnc_result['data']['ticket']
        port = vnc_result['data']['port']
        print(f"Got VNC ticket, port={port}")
        
        # Step 3: Connect to Proxmox WebSocket
        print(f"Step 3: Connect to Proxmox...")
        encoded_vnc_ticket = url_quote(vnc_ticket, safe='')
        
        if vm_type == 'qemu':
            pve_ws_path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        else:
            pve_ws_path = f"/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        
        pve_ws_url = f"wss://{host}:8006{pve_ws_path}"
        
        pve_ws = websocket.create_connection(
            pve_ws_url,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            header={"Cookie": f"PVEAuthCookie={pve_ticket}"},
            timeout=5
        )
        
        print(f"✓ Connected to Proxmox!")
        pve_ws.settimeout(0.1)
        
        bytes_sent = 0
        bytes_received = 0
        
        # Greenlet to read from Proxmox and send to client
        def proxmox_to_client():
            nonlocal bytes_received, running
            try:
                while running:
                    try:
                        data = pve_ws.recv()
                        if data:
                            bytes_received += len(data)
                            ws.send(data)
                    except websocket.WebSocketTimeoutException:
                        gsleep(0.01)
                    except websocket.WebSocketConnectionClosedException:
                        print("Proxmox closed")
                        running = False
                        break
                    except Exception as e:
                        if running:
                            print(f"PVE->Client error: {e}")
                        running = False
                        break
            except Exception as e:
                print(f"proxmox_to_client crashed: {e}")
                running = False
        
        # Start the proxmox reader greenlet
        pve_reader = spawn(proxmox_to_client)
        
        print(f"Step 4: Proxy running...")
        
        # Main loop: read from client, send to Proxmox
        while running:
            try:
                data = ws.receive()
                if data is None:
                    print("Client disconnected")
                    running = False
                    break
                if data:
                    bytes_sent += len(data)
                    pve_ws.send(data)
            except Exception as e:
                if running:
                    err_str = str(e)
                    if 'closed' not in err_str.lower():
                        print(f"Client->PVE error: {e}")
                running = False
                break
        
        running = False
        pve_reader.kill()
        
        print(f"Session ended: sent {bytes_sent}, received {bytes_received}")
        
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        running = False
        if pve_ws:
            try:
                pve_ws.close()
            except:
                pass
        print(f"{'='*60}\n")


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vncwebsocket')
def vnc_websocket_route(cluster_id, node, vm_type, vmid):
    """WebSocket endpoint for VNC - redirect to dedicated WS port
    
    NS: Auth via query param since WebSocket can't send custom headers
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # Auth check via query param
    session_id = request.args.get('session')
    if not session_id:
        return jsonify({'error': 'Session required', 'code': 'AUTH_REQUIRED'}), 401
    
    session = validate_session(session_id)
    if not session:
        return jsonify({'error': 'Invalid session', 'code': 'INVALID_SESSION'}), 401
    
    # Check permissions
    users = load_users()
    user = users.get(session['user'], {})
    user_perms = get_user_permissions(user)
    if 'vm.console' not in user_perms and session['role'] != ROLE_ADMIN:
        return jsonify({'error': 'Permission denied', 'code': 'INSUFFICIENT_PERMISSIONS'}), 403
    
    # This route is just a fallback - actual WebSocket handling is done by the 
    # dedicated WebSocket server started in start_vnc_websocket_server()
    from flask import request
    
    print(f"\n*** VNC ROUTE HIT (HTTP): {vm_type}/{vmid} on {node} ***")
    print(f"HTTP_UPGRADE: {request.environ.get('HTTP_UPGRADE', 'NONE')}")
    print(f"wsgi.websocket: {request.environ.get('wsgi.websocket', 'NONE')}")
    
    # Try geventwebsocket first
    ws = request.environ.get('wsgi.websocket')
    if ws is not None:
        print("Using geventwebsocket handler...")
        handle_vnc_websocket(ws, cluster_id, node, vm_type, vmid)
        return ''
    
    # If not a websocket, return error
    return jsonify({'error': 'WebSocket connection required'}), 426


# Standalone VNC WebSocket Server using websockets library
def start_vnc_websocket_server(port=5001, ssl_cert=None, ssl_key=None, host='0.0.0.0'):
    """Start a dedicated WebSocket server for VNC proxying"""
    import asyncio
    import re
    import threading
    import subprocess

    try:
        import websockets
    except ImportError:
        print("WARNING: 'websockets' library not installed. VNC console will not work.")
        print("Install with: pip install websockets")
        return

    # MK Feb 2026 - kill stale processes on port before binding (same as SSH server)
    try:
        result = subprocess.run(['fuser', '-k', f'{port}/tcp'], capture_output=True, timeout=5)
        if result.returncode == 0:
            print(f"Killed existing process on VNC port {port}")
            time.sleep(0.5)
    except Exception:
        try:
            result = subprocess.run(['lsof', '-t', f'-i:{port}'], capture_output=True, text=True, timeout=5)
            if result.stdout.strip():
                for pid in result.stdout.strip().split('\n'):
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                        print(f"Killed existing VNC process {pid} on port {port}")
                    except (ProcessLookupError, ValueError):
                        pass
                time.sleep(0.5)
        except Exception:
            pass

    # Event to signal server is ready
    server_ready = threading.Event()
    
    async def vnc_handler(websocket):
        """Handle VNC WebSocket connections
        
        NS: Auth via query param since WebSocket can't send custom headers
        """
        # Get path from websocket
        path = websocket.request.path if hasattr(websocket, 'request') else websocket.path
        
        print(f"\n{'='*60}")
        print(f"VNC WebSocket connected: {path}")
        print(f"{'='*60}")
        
        # Extract session from query params
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(path)
        query_params = parse_qs(parsed.query)
        session_id = query_params.get('session', [None])[0]
        
        if not session_id:
            print("ERROR: No session provided")
            await websocket.close(1002, "Authentication required")
            return
        
        session = validate_session(session_id)
        if not session:
            print("ERROR: Invalid session")
            await websocket.close(1002, "Invalid session")
            return
        
        # Check permissions
        users = load_users()
        user = users.get(session['user'], {})
        user_perms = get_user_permissions(user)
        if 'vm.console' not in user_perms and session['role'] != ROLE_ADMIN:
            print(f"ERROR: User {session['user']} lacks vm.console permission")
            await websocket.close(1002, "Permission denied")
            return
        
        print(f"User {session['user']} authenticated for VNC")
        
        # Parse path: /api/clusters/{cluster_id}/vms/{node}/{vm_type}/{vmid}/vncwebsocket
        import re
        match = re.match(r'/api/clusters/([^/]+)/vms/([^/]+)/(qemu|lxc)/(\d+)/vncwebsocket', parsed.path)
        if not match:
            print(f"ERROR: Invalid path: {parsed.path}")
            await websocket.close(1002, "Invalid path")
            return
        
        cluster_id, node, vm_type, vmid = match.groups()
        vmid = int(vmid)
        
        print(f"Cluster: {cluster_id}, Node: {node}, Type: {vm_type}, VMID: {vmid}")
        
        if cluster_id not in cluster_managers:
            print(f"ERROR: Cluster {cluster_id} not found")
            await websocket.close(1002, "Cluster not found")
            return
        
        manager = cluster_managers[cluster_id]
        host = manager.current_host or manager.config.host
        
        print(f"Target host: {host}")
        
        pve_ws = None
        
        try:
            import urllib.parse
            import urllib.request
            import json
            import websocket as ws_client  # websocket-client for connecting to Proxmox
            
            # Create SSL context
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            # Step 1: Login to Proxmox
            print("Step 1: Login to Proxmox...")
            login_data = urlencode({
                'username': manager.config.user,
                'password': manager.config.pass_
            }).encode('utf-8')
            
            login_req = urllib.request.Request(
                f"https://{host}:8006/api2/json/access/ticket",
                data=login_data, method='POST'
            )
            
            with urllib.request.urlopen(login_req, context=ssl_ctx, timeout=10) as response:
                login_result = json.loads(response.read().decode('utf-8'))
            
            pve_ticket = login_result['data']['ticket']
            csrf_token = login_result['data']['CSRFPreventionToken']
            print("Got PVE ticket")
            
            # Step 2: Get VNC ticket
            print("Step 2: Get VNC ticket...")
            if vm_type == 'qemu':
                vnc_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
            else:
                vnc_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
            
            vnc_data = urlencode({'websocket': '1'}).encode('utf-8')
            vnc_req = urllib.request.Request(vnc_url, data=vnc_data, method='POST')
            vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
            vnc_req.add_header('CSRFPreventionToken', csrf_token)
            
            with urllib.request.urlopen(vnc_req, context=ssl_ctx, timeout=10) as response:
                vnc_result = json.loads(response.read().decode('utf-8'))
            
            vnc_ticket = vnc_result['data']['ticket']
            port = vnc_result['data']['port']
            print(f"Got VNC ticket, port={port}")
            
            # Step 3: Connect to Proxmox WebSocket
            print("Step 3: Connect to Proxmox WebSocket...")
            encoded_vnc_ticket = url_quote(vnc_ticket, safe='')
            
            if vm_type == 'qemu':
                pve_ws_path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
            else:
                pve_ws_path = f"/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
            
            pve_ws_url = f"wss://{host}:8006{pve_ws_path}"
            
            pve_ws = ws_client.create_connection(
                pve_ws_url,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                header={"Cookie": f"PVEAuthCookie={pve_ticket}"},
                timeout=5
            )
            
            print("Connected to Proxmox!")
            pve_ws.settimeout(0.05)  # Short timeout for non-blocking
            
            bytes_sent = 0
            bytes_received = 0
            
            print("Step 4: Starting proxy loop...")
            
            import asyncio
            
            bytes_sent = 0
            bytes_received = 0
            running = True
            
            # Set Proxmox socket to very short timeout for non-blocking behavior
            pve_ws.settimeout(0.001)
            
            async def proxmox_to_client():
                """Forward data from Proxmox to browser"""
                nonlocal bytes_received, running
                while running:
                    try:
                        # Non-blocking receive
                        try:
                            data = pve_ws.recv()
                            if data:
                                bytes_received += len(data)
                                if isinstance(data, str):
                                    data = data.encode('latin-1')
                                await websocket.send(data)
                        except ws_client.WebSocketTimeoutException:
                            # No data available, yield control
                            await asyncio.sleep(0.005)
                    except ws_client.WebSocketConnectionClosedException:
                        print("Proxmox closed connection")
                        running = False
                        break
                    except Exception as e:
                        if running:
                            print(f"PVE->Client error: {e}")
                        running = False
                        break
            
            async def client_to_proxmox():
                """Forward data from browser to Proxmox"""
                nonlocal bytes_sent, running
                try:
                    async for message in websocket:
                        if not running:
                            break
                        bytes_sent += len(message)
                        if isinstance(message, str):
                            message = message.encode('latin-1')
                        pve_ws.send(message)
                except Exception as e:
                    if running and 'close' not in str(e).lower():
                        print(f"Client->PVE error: {e}")
                    running = False
            
            # Run both directions concurrently
            task1 = asyncio.create_task(proxmox_to_client())
            task2 = asyncio.create_task(client_to_proxmox())
            
            done, pending = await asyncio.wait(
                [task1, task2],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            running = False
            
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            print(f"Session ended: sent {bytes_sent}, received {bytes_received}")
            
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if pve_ws:
                try:
                    pve_ws.close()
                except:
                    pass
            print(f"{'='*60}\n")
    
    async def main():
        nonlocal server_ready
        ssl_context = None
        if ssl_cert and ssl_key:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(ssl_cert, ssl_key)
            proto = "wss"
        else:
            proto = "ws"
        
        # LW: suppress websocket error logs from bots/scanners
        import logging as ws_logging
        ws_logging.getLogger('websockets').setLevel(ws_logging.CRITICAL)
        
        # NS: added ping keepalive like ssh server has, was causing random disconnects (#92)
        # LW Feb 2026: host='' means all interfaces (asyncio creates IPv4+IPv6 listeners)
        ws_host = host if host else None
        display_host = host or '0.0.0.0'
        try:
            async with websockets.serve(vnc_handler, ws_host, port, ssl=ssl_context, ping_interval=20, ping_timeout=10):
                print(f"VNC WebSocket Server ready on {proto}://{display_host}:{port}", flush=True)
                server_ready.set()
                await asyncio.Future()  # Run forever
        except OSError as bind_err:
            # Issue #71: IPv6 bind failed, fall back to 0.0.0.0
            if ':' in str(host):
                print(f"VNC WebSocket: IPv6 bind failed ({bind_err}), falling back to 0.0.0.0", flush=True)
                async with websockets.serve(vnc_handler, '0.0.0.0', port, ssl=ssl_context, ping_interval=20, ping_timeout=10):
                    print(f"VNC WebSocket Server ready on {proto}://0.0.0.0:{port}", flush=True)
                    server_ready.set()
                    await asyncio.Future()
            else:
                raise
    
    # LW Feb 2026 - run in thread, with proper fallback for gevent environments
    def run_server():
        try:
            # Try asyncio.run() first (clean Python, no gevent)
            asyncio.run(main())
        except RuntimeError as e:
            if "cannot be called from a running event loop" in str(e):
                # NS: gevent monkey-patches asyncio, need explicit event loop
                print("VNC WebSocket: gevent detected, using new event loop", flush=True)
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(main())
                finally:
                    loop.close()
            else:
                print(f"ERROR: VNC WebSocket Server RuntimeError: {e}", flush=True)
                import traceback
                traceback.print_exc()
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as e:
            print(f"ERROR: VNC WebSocket Server crashed: {type(e).__name__}: {e}", flush=True)
            import traceback
            traceback.print_exc()

    ws_thread = threading.Thread(target=run_server, daemon=True)
    ws_thread.start()

    # Wait for server to be ready (max 5 seconds)
    if server_ready.wait(timeout=5):
        print(f"VNC WebSocket Server started successfully", flush=True)
    else:
        print(f"WARNING: VNC WebSocket Server may not be ready yet (check logs above for errors)", flush=True)


# Keep flask-sock version as backup (renamed)
@sock.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vncwebsocket')
def vnc_websocket_proxy(ws, cluster_id, node, vm_type, vmid):
    """WebSocket proxy for VNC connection via Flask-Sock (same port as main app)"""
    import gevent
    from gevent import spawn, sleep as gsleep
    
    print(f"\n{'='*60}")
    print(f"VNC WEBSOCKET: {vm_type}/{vmid} on {node}")
    print(f"{'='*60}")
    
    # Authenticate via session from query params
    session_id = request.args.get('session')
    if not session_id:
        print("ERROR: No session provided")
        try:
            ws.send('Authentication required')
        except:
            pass
        return
    
    session = validate_session(session_id)
    if not session:
        print("ERROR: Invalid session")
        try:
            ws.send('Invalid session')
        except:
            pass
        return
    
    # Check permissions
    users = load_users()
    user = users.get(session['user'], {})
    user_perms = get_user_permissions(user)
    if 'vm.console' not in user_perms and session['role'] != ROLE_ADMIN:
        print(f"ERROR: User {session['user']} lacks vm.console permission")
        try:
            ws.send('Permission denied')
        except:
            pass
        return
    
    print(f"User {session['user']} authenticated for VNC")
    
    if cluster_id not in cluster_managers:
        print(f"ERROR: Cluster {cluster_id} not found")
        return
    
    manager = cluster_managers[cluster_id]
    host = manager.current_host or manager.config.host
    
    print(f"Target host: {host}")
    
    pve_ws = None
    running = True
    
    try:
        import urllib.parse
        import urllib.request
        import json
        import websocket
        
        # Create SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Step 1: Login
        print(f"Step 1: Login...")
        login_data = urlencode({
            'username': manager.config.user,
            'password': manager.config.pass_
        }).encode('utf-8')
        
        login_req = urllib.request.Request(
            f"https://{host}:8006/api2/json/access/ticket",
            data=login_data, method='POST'
        )
        
        with urllib.request.urlopen(login_req, context=ssl_context, timeout=10) as response:
            login_result = json.loads(response.read().decode('utf-8'))
        
        pve_ticket = login_result['data']['ticket']
        csrf_token = login_result['data']['CSRFPreventionToken']
        print(f"Got PVE ticket")
        
        # Step 2: Get VNC ticket
        print(f"Step 2: Get VNC ticket...")
        if vm_type == 'qemu':
            vnc_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
        else:
            vnc_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
        
        vnc_data = urlencode({'websocket': '1'}).encode('utf-8')
        vnc_req = urllib.request.Request(vnc_url, data=vnc_data, method='POST')
        vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
        vnc_req.add_header('CSRFPreventionToken', csrf_token)
        
        with urllib.request.urlopen(vnc_req, context=ssl_context, timeout=10) as response:
            vnc_result = json.loads(response.read().decode('utf-8'))
        
        vnc_ticket = vnc_result['data']['ticket']
        port = vnc_result['data']['port']
        print(f"Got VNC ticket, port={port}")
        
        # Step 3: Connect to Proxmox WebSocket
        print(f"Step 3: Connect to Proxmox...")
        encoded_vnc_ticket = url_quote(vnc_ticket, safe='')
        
        if vm_type == 'qemu':
            pve_ws_path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        else:
            pve_ws_path = f"/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        
        pve_ws_url = f"wss://{host}:8006{pve_ws_path}"
        
        pve_ws = websocket.create_connection(
            pve_ws_url,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            header={"Cookie": f"PVEAuthCookie={pve_ticket}"},
            timeout=5
        )
        
        print(f"✓ Connected!")
        pve_ws.settimeout(0.1)
        
        bytes_sent = 0
        bytes_received = 0
        
        # Greenlet to read from Proxmox and send to client
        def proxmox_to_client():
            nonlocal bytes_received, running
            try:
                while running:
                    try:
                        data = pve_ws.recv()
                        if data:
                            bytes_received += len(data)
                            ws.send(data)
                    except websocket.WebSocketTimeoutException:
                        gsleep(0.01)
                    except websocket.WebSocketConnectionClosedException:
                        print("Proxmox closed")
                        running = False
                        break
                    except Exception as e:
                        if running:
                            print(f"PVE->Client error: {e}")
                        running = False
                        break
            except Exception as e:
                print(f"proxmox_to_client crashed: {e}")
                running = False
        
        # Start the proxmox reader greenlet
        pve_reader = spawn(proxmox_to_client)
        
        print(f"Step 4: Proxy running...")
        
        # Main loop: read from client, send to Proxmox
        while running:
            try:
                data = ws.receive(timeout=0.1)
                if data is None:
                    print("Client disconnected")
                    running = False
                    break
                if data:
                    bytes_sent += len(data)
                    pve_ws.send(data)
            except TimeoutError:
                gsleep(0.01)
            except Exception as e:
                if "timed out" not in str(e).lower() and "timeout" not in str(e).lower():
                    print(f"Client->PVE error: {e}")
                    running = False
                    break
                gsleep(0.01)
        
        running = False
        pve_reader.kill()
        
        print(f"Session ended: sent {bytes_sent}, received {bytes_received}")
        
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        running = False
        if pve_ws:
            try:
                pve_ws.close()
            except:
                pass
        print(f"{'='*60}\n")


def start_ssh_websocket_server(port=5002, ssl_cert=None, ssl_key=None, host='0.0.0.0'):
    """Start a dedicated WebSocket server for SSH terminal proxying
    
    runs as separate process to avoid gevent/asyncio conflicts.
    Gevent monkey-patches asyncio which breaks the websockets library.
    By using a subprocess, we get a clean Python interpreter.
    """
    import subprocess
    import sys
    import os
    
    # Create a standalone script that runs the SSH WebSocket server
    server_script = '''#!/usr/bin/env python3
"""Standalone SSH WebSocket Server - runs without gevent"""
import asyncio
import ssl
import json
import re
import sys
import os
import warnings
warnings.filterwarnings('ignore')

PORT = int(os.environ.get('SSH_WS_PORT', 5002))
BIND_HOST = os.environ.get('SSH_WS_HOST', '0.0.0.0')
SSL_CERT = os.environ.get('SSH_WS_SSL_CERT', '')
SSL_KEY = os.environ.get('SSH_WS_SSL_KEY', '')
PEGAPROX_URL = os.environ.get('PEGAPROX_URL', 'http://127.0.0.1:5000')

try:
    import websockets
    import paramiko
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError as e:
    print(f"Missing library: {e}")
    sys.exit(1)

async def ssh_handler(websocket):
    """SSH WebSocket handler with user credential prompt and SSH key support
    
    MK: Supports both password and SSH key authentication
    Frontend can pre-fetch the IP and pass it as query parameter
    """
    path = websocket.request.path if hasattr(websocket, 'request') else websocket.path
    print(f"SSH WebSocket connection: {path}")
    
    from urllib.parse import urlparse, parse_qs, unquote
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    session_id = query.get('session', [None])[0]
    prefetched_ip = query.get('ip', [None])[0]  # IP pre-fetched by frontend
    if prefetched_ip:
        prefetched_ip = unquote(prefetched_ip)
        print(f"Frontend provided IP: {prefetched_ip}")
    
    # Match both /shell and /shellws
    match = re.match(r'/api/clusters/([^/]+)/nodes/([^/]+)/shell(?:ws)?', parsed.path)
    if not match:
        print(f"Invalid path: {parsed.path}")
        await websocket.send('{"status":"error","message":"Invalid path"}')
        await websocket.close(1008, "Invalid path")
        return
    
    cluster_id, node = match.groups()
    print(f"Cluster: {cluster_id}, Node: {node}")
    
    # Validate session (just to ensure user is logged in to PegaProx)
    if not session_id:
        print("No session provided")
        await websocket.send('{"status":"error","message":"No session provided"}')
        await websocket.close(1008, "No session")
        return
    
    print(f"Session ID received: {session_id[:20]}..." if len(session_id) > 20 else f"Session ID: {session_id}")
    
    try:
        print(f"Validating session with: {PEGAPROX_URL}/api/auth/validate")
        # Try both cookie and header-based auth
        headers = {'X-Session-ID': session_id}
        r = requests.get(f"{PEGAPROX_URL}/api/auth/validate", 
                        cookies={'session': session_id}, 
                        headers=headers,
                        timeout=5, verify=False)
        print(f"Session validation response: {r.status_code}")
        if r.status_code != 200:
            print(f"Session validation failed: {r.status_code} - {r.text[:100] if r.text else 'no body'}")
            await websocket.send('{"status":"error","message":"Session ungültig - bitte neu einloggen"}')
            await websocket.close(1008, "Invalid session")
            return
        print("Session validation successful")
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error to main server: {e}")
        # NS Feb 2026 - never skip auth, even if main server is unreachable
        await websocket.send('{"status":"error","message":"Authentifizierung fehlgeschlagen - Server nicht erreichbar"}')
        await websocket.close(1011, "Auth server unreachable")
        return
    except Exception as e:
        print(f"Auth error: {e}")
        await websocket.send('{"status":"error","message":"Authentifizierungsfehler"}')
        await websocket.close(1011, "Auth error")
        return
    
    # Get node IP - use pre-fetched IP if available
    node_ip = prefetched_ip if prefetched_ip else None
    cluster_host = None
    
    # Only try API if we don't have a pre-fetched IP
    if not node_ip:
        # Method 1: Try API endpoint
        try:
            print(f"Fetching cluster creds from: {PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}")
            r = requests.get(f"{PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}", cookies={'session': session_id}, timeout=10, verify=False)
            print(f"Cluster creds response: {r.status_code}")
            if r.status_code == 200:
                creds = r.json()
                cluster_host = creds.get('host')
                node_ips = creds.get('node_ips', {})
                
                # Try exact match first, then case-insensitive
                node_ip = node_ips.get(node) or node_ips.get(node.lower())
                
                print(f"Got node_ips: {node_ips}, looking for: {node}, found: {node_ip}, cluster_host: {cluster_host}")
            else:
                print(f"Cluster creds failed: {r.status_code} - {r.text[:200] if r.text else 'no body'}")
        except Exception as e:
            print(f"Could not get node IP from API: {e}")
        
        # Method 2: Fallback - read directly from clusters config file
        if not cluster_host:
            try:
                import os
                # Try common config locations
                config_paths = [
                    'config/clusters.json',  # Relative to working dir
                    './config/clusters.json',
                    '/home/admin_321/pegaprox/config/clusters.json',
                    '/home/admin_321/pegaprox/data/clusters.json',
                    './data/clusters.json',
                    os.path.expanduser('~/.pegaprox/clusters.json'),
                    '/var/lib/pegaprox/clusters.json'
                ]
                print(f"Trying config file fallback, cwd={os.getcwd()}")
                for config_path in config_paths:
                    if os.path.exists(config_path):
                        print(f"Found config at: {config_path}")
                        with open(config_path, 'r') as f:
                            clusters = json.load(f)
                        if cluster_id in clusters:
                            cluster_host = clusters[cluster_id].get('host')
                            print(f"Got cluster_host from config file: {cluster_host}")
                            break
                        else:
                            print(f"Cluster {cluster_id} not in config, available: {list(clusters.keys())}")
            except Exception as e:
                print(f"Config file fallback failed: {e}")
        
        # Use cluster_host as fallback for node_ip
        if not node_ip and cluster_host:
            node_ip = cluster_host
            print(f"Using cluster host as fallback: {cluster_host}")
    
    # If we still don't have an IP, allow manual entry
    allow_manual_ip = False
    if not node_ip:
        print(f"No IP found - allowing manual entry")
        node_ip = ""  # Empty - user must provide
        allow_manual_ip = True
    
    print(f"Final node IP for {node}: {node_ip or '(manual entry required)'}")
    
    # Send need_credentials status - frontend will show login dialog
    await websocket.send(json.dumps({
        'status': 'need_credentials',
        'node': node,
        'ip': node_ip,
        'allowManualIp': allow_manual_ip
    }))
    
    # Wait for credentials from user
    try:
        creds_msg = await asyncio.wait_for(websocket.recv(), timeout=300)  # 5 min timeout
        creds = json.loads(creds_msg)
        ssh_user = creds.get('username', 'root')
        ssh_pass = creds.get('password', '')
        ssh_key = creds.get('privateKey', '')  # SSH private key (PEM format)
        
        # Allow user to override IP (for manual entry)
        user_ip = creds.get('host', '').strip()
        if user_ip:
            node_ip = user_ip
            print(f"Using user-provided IP: {node_ip}")
        
        if not node_ip:
            await websocket.send('{"status":"error","message":"Host/IP address required"}')
            return
        
        if not ssh_pass and not ssh_key:
            await websocket.send('{"status":"error","message":"Password or SSH key required"}')
            return
            
    except asyncio.TimeoutError:
        await websocket.send('{"status":"error","message":"Login timeout"}')
        await websocket.close(1008, "Timeout")
        return
    except Exception as e:
        print(f"Credentials receive error: {e}")
        await websocket.send('{"status":"error","message":"Failed to receive credentials"}')
        return
    
    # Send connecting status
    await websocket.send('{"status":"connecting"}')
    
    # Connect SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
    
    try:
        print(f"Connecting SSH to {ssh_user}@{node_ip}...")
        
        # Try SSH key authentication first if provided
        if ssh_key:
            try:
                import io
                # Parse the private key
                key_file = io.StringIO(ssh_key)
                
                # Try different key types
                pkey = None
                for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, getattr(paramiko, 'DSSKey', None)]:
                    if key_class is None:
                        continue
                    try:
                        key_file.seek(0)
                        pkey = key_class.from_private_key(key_file, password=ssh_pass if ssh_pass else None)
                        break
                    except:
                        continue
                
                if pkey:
                    print(f"Using SSH key authentication")
                    ssh.connect(node_ip, port=22, username=ssh_user, pkey=pkey, timeout=10, look_for_keys=False, allow_agent=False)
                else:
                    raise Exception("Could not parse SSH key - unsupported format")
                    
            except Exception as key_error:
                print(f"SSH key auth failed: {key_error}")
                await websocket.send(f'{{"status":"error","message":"SSH key error: {str(key_error)}"}}')
                return
        else:
            # Password authentication
            ssh.connect(node_ip, port=22, username=ssh_user, password=ssh_pass, timeout=10, look_for_keys=False, allow_agent=False)
        
        channel = ssh.invoke_shell(term='xterm-256color', width=120, height=40)
        channel.settimeout(0.1)
        
        print(f"SSH connected: {cluster_id}/{node}")
        
        # Send connected status - frontend will clear terminal
        await websocket.send('{"status":"connected"}')
        
        async def ssh_to_ws():
            while True:
                try:
                    if channel.recv_ready():
                        data = channel.recv(4096)
                        if data:
                            await websocket.send(data.decode('utf-8', errors='replace'))
                    await asyncio.sleep(0.01)
                except:
                    break
        
        async def ws_to_ssh():
            try:
                async for message in websocket:
                    if isinstance(message, str):
                        if message.startswith('{"type":"resize"'):
                            try:
                                data = json.loads(message)
                                if data.get('type') == 'resize':
                                    channel.resize_pty(width=data.get('cols', 120), height=data.get('rows', 40))
                            except:
                                pass
                        elif message.startswith('{'):
                            # Ignore other JSON messages (like old credential format)
                            pass
                        else:
                            channel.send(message)
                    else:
                        channel.send(message)
            except:
                pass
        
        await asyncio.gather(ssh_to_ws(), ws_to_ssh(), return_exceptions=True)
    except paramiko.AuthenticationException as e:
        print(f"SSH auth failed: {e}")
        await websocket.send(f'\\r\\n\\x1b[31mSSH Authentication Failed\\x1b[0m\\r\\nCheck cluster credentials.\\r\\n')
    except Exception as e:
        print(f"SSH error: {e}")
        try:
            await websocket.send(f"\\r\\n\\x1b[31mSSH Error: {e}\\x1b[0m\\r\\n")
        except:
            pass
    finally:
        try:
            ssh.close()
        except:
            pass
        print(f"SSH disconnected: {cluster_id}/{node}")

async def main():
    ssl_context = None
    if SSL_CERT and SSL_KEY and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)
    
    # Issue #71/#95: empty host = all interfaces (dual-stack IPv4+IPv6)
    ws_host = None if not BIND_HOST else BIND_HOST
    display_host = BIND_HOST or '0.0.0.0'
    try:
        async with websockets.serve(ssh_handler, ws_host, PORT, ssl=ssl_context, ping_interval=30, ping_timeout=10):
            print(f"SSH WebSocket server ready on {display_host}:{PORT}")
            await asyncio.Future()
    except OSError as e:
        if ':' in str(display_host):
            print(f"SSH WebSocket: IPv6 bind failed ({e}), falling back to 0.0.0.0")
            async with websockets.serve(ssh_handler, '0.0.0.0', PORT, ssl=ssl_context, ping_interval=30, ping_timeout=10):
                print(f"SSH WebSocket server ready on 0.0.0.0:{PORT}")
                await asyncio.Future()
        else:
            raise

if __name__ == '__main__':
    asyncio.run(main())
'''
    
    # Write the script to a file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, '.ssh_ws_server.py')
    
    try:
        # kill existing process on port if any on this port first
        try:
            result = subprocess.run(
                ['fuser', '-k', f'{port}/tcp'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"Killed existing process on port {port}")
                time.sleep(0.5)  # Give it time to release the port
        except Exception as e:
            # fuser might not be available, try lsof
            try:
                result = subprocess.run(
                    ['lsof', '-t', f'-i:{port}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.stdout.strip():
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        try:
                            os.kill(int(pid), signal.SIGTERM)
                            print(f"Killed existing process {pid} on port {port}")
                        except:
                            pass
                    time.sleep(0.5)
            except:
                pass  # Neither fuser nor lsof available, hope for the best
        
        with open(script_path, 'w') as f:
            f.write(server_script)
        
        # Set environment variables for the subprocess
        env = os.environ.copy()
        env['SSH_WS_PORT'] = str(port)
        env['SSH_WS_HOST'] = host  # Issue #71: IPv6 support
        main_port = port - 2
        env['PEGAPROX_URL'] = f"https://127.0.0.1:{main_port}" if ssl_cert else f"http://127.0.0.1:{main_port}"
        if ssl_cert:
            env['SSH_WS_SSL_CERT'] = ssl_cert
        if ssl_key:
            env['SSH_WS_SSL_KEY'] = ssl_key
        
        # Start as subprocess (completely separate process, no gevent)
        # Use same working directory as main server
        proc = subprocess.Popen(
            [sys.executable, script_path],
            env=env,
            cwd=os.getcwd(),  # MK: Ensure same working dir for config file access
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True
        )
        
        # Read output in background
        def read_output():
            for line in proc.stdout:
                line = line.decode('utf-8', errors='replace').strip()
                if line:
                    print(f"[SSH-WS] {line}")
        
        import threading
        output_thread = threading.Thread(target=read_output, daemon=True)
        output_thread.start()
        
        print(f"SSH WebSocket server subprocess started (PID: {proc.pid})", flush=True)

    except Exception as e:
        print(f"Failed to start SSH WebSocket server: {e}", flush=True)


# Terminal/Shell WebSocket proxy (legacy - flask-sock version, kept for non-gevent setups)
@sock.route('/api/clusters/<cluster_id>/nodes/<node>/shellwebsocket')
def node_shell_websocket_proxy(ws, cluster_id, node):
    """WebSocket proxy for node shell via SSH"""

    # NS Feb 2026: Authentication + authorization (was missing entirely - critical security fix)
    session_id = request.args.get('session')
    if not session_id:
        logging.error("SHELL WS: No session provided")
        try:
            ws.send('{"status":"error","message":"Authentication required"}')
        except:
            pass
        return

    session = validate_session(session_id)
    if not session:
        logging.error("SHELL WS: Invalid session")
        try:
            ws.send('{"status":"error","message":"Invalid session"}')
        except:
            pass
        return

    # Check permissions - require node.shell or admin role
    users = load_users()
    user = users.get(session['user'], {})
    user_perms = get_user_permissions(user)
    if 'node.shell' not in user_perms and session['role'] != ROLE_ADMIN:
        logging.error(f"SHELL WS: User {session['user']} lacks node.shell permission")
        try:
            ws.send('{"status":"error","message":"Permission denied"}')
        except:
            pass
        return

    # Check cluster access based on user's allowed clusters
    from pegaprox.utils.rbac import get_user_clusters
    allowed_clusters = get_user_clusters(user)
    if allowed_clusters is not None and cluster_id not in allowed_clusters:
        logging.error(f"SHELL WS: User {session['user']} denied access to cluster {cluster_id}")
        try:
            ws.send('{"status":"error","message":"Access denied to this cluster"}')
        except:
            pass
        return

    logging.info(f"SHELL WS: User {session['user']} authenticated for shell on {cluster_id}/{node}")

    logging.info(f"")
    logging.info(f"========================================")
    logging.info(f"SSH SHELL: {cluster_id}/{node}")
    logging.info(f"========================================")

    # Check paramiko availability first
    try:
        import paramiko
    except ImportError:
        logging.error("paramiko not installed!")
        try:
            ws.send('{"status":"error","message":"SSH library (paramiko) not installed on server"}')
        except:
            pass
        return
    
    if cluster_id not in cluster_managers:
        logging.error(f"Cluster {cluster_id} not found")
        try:
            ws.send('{"status":"error","message":"Cluster not found"}')
        except:
            pass
        return
    
    manager = cluster_managers[cluster_id]
    cluster_host = manager.config.host
    
    # Get node IP address from cluster status
    logging.info(f"Step 1: Getting IP for node {node}...")
    
    # First authenticate with cluster
    if not manager.connect_to_proxmox():
        logging.error("Failed to authenticate with cluster!")
        try:
            ws.send('{"status":"error","message":"Cluster auth failed"}')
        except:
            pass
        return
    
    node_ip = None
    try:
        cluster_url = f"https://{cluster_host}:8006/api2/json/cluster/status"
        cluster_response = manager._create_session().get(cluster_url, timeout=5)
        if cluster_response.status_code == 200:
            cluster_data = cluster_response.json().get('data', [])
            for item in cluster_data:
                if item.get('type') == 'node' and item.get('name') == node:
                    node_ip = item.get('ip')
                    logging.info(f"  Found node IP: {node_ip}")
                    break
    except Exception as e:
        logging.error(f"  Error getting cluster status: {e}")
    
    if not node_ip:
        node_ip = cluster_host
        logging.info(f"  Using cluster host: {node_ip}")
    
    # Request credentials from client
    try:
        ws.send(f'{{"status":"need_credentials","node":"{node}","ip":"{node_ip}"}}')
    except Exception as e:
        logging.error(f"Failed to send need_credentials: {e}")
        return
    
    logging.info(f"Step 2: Waiting for SSH credentials...")
    
    # Wait for credentials from client
    try:
        cred_msg = ws.receive(timeout=60)
        if not cred_msg:
            logging.error("No credentials received")
            return
        
        creds = json.loads(cred_msg)
        ssh_user = creds.get('username', 'root')
        ssh_pass = creds.get('password', '')
        
        logging.info(f"  Got credentials for user: {ssh_user}")
        
    except Exception as e:
        logging.error(f"Error receiving credentials: {e}")
        try:
            ws.send('{"status":"error","message":"Credentials timeout"}')
        except:
            pass
        return
    
    # Tell client we're connecting
    try:
        ws.send('{"status":"connecting"}')
    except:
        return
    
    logging.info(f"Step 3: Connecting SSH to {ssh_user}@{node_ip}...")
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        
        # Connect
        ssh.connect(
            hostname=node_ip,
            port=22,
            username=ssh_user,
            password=ssh_pass,
            timeout=30,
            allow_agent=False,
            look_for_keys=False
        )
        
        logging.info(f"Step 4: SSH connected! Opening shell...")
        
        # Get interactive shell
        channel = ssh.invoke_shell(term='xterm-256color', width=120, height=40)
        channel.settimeout(0.1)
        
        ws.send('{"status":"connected"}')
        logging.info(f"Step 5: Shell ready!")
        
        stop_event = threading.Event()
        
        # Thread: SSH -> WebSocket
        def ssh_to_ws():
            try:
                while not stop_event.is_set():
                    try:
                        if channel.recv_ready():
                            data = channel.recv(4096)
                            if data:
                                ws.send(data)
                        else:
                            import time
                            time.sleep(0.01)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"SSH recv error: {e}")
                        break
            except:
                pass
            finally:
                stop_event.set()
        
        ssh_thread = threading.Thread(target=ssh_to_ws)
        ssh_thread.daemon = True
        ssh_thread.start()
        
        # Main loop: WebSocket -> SSH
        while not stop_event.is_set():
            try:
                data = ws.receive()
                if data is None:
                    logging.info("Client disconnected")
                    break
                
                # Handle JSON messages
                if isinstance(data, str) and data.startswith('{'):
                    try:
                        msg = json.loads(data)
                        # Handle resize
                        if msg.get('type') == 'resize':
                            channel.resize_pty(
                                width=msg.get('cols', 120),
                                height=msg.get('rows', 40)
                            )
                        continue
                    except:
                        pass
                
                # Send to SSH
                if isinstance(data, str):
                    channel.send(data)
                else:
                    channel.send(data)
                    
            except Exception as e:
                logging.error(f"WS recv error: {e}")
                break
        
        stop_event.set()
        
    except paramiko.AuthenticationException:
        logging.error("SSH authentication failed!")
        ws.send('{"status":"error","message":"SSH Login fehlgeschlagen - falscher Username oder Passwort"}')
    except paramiko.SSHException as e:
        logging.error(f"SSH error: {e}")
        ws.send(f'{{"status":"error","message":"SSH Fehler: {str(e)}"}}')
    except Exception as e:
        logging.error(f"Shell error: {e}")
        import traceback
        traceback.print_exc()
        ws.send(f'{{"status":"error","message":"{str(e)}"}}')
    finally:
        try:
            channel.close()
        except:
            pass
        try:
            ssh.close()
        except:
            pass
        logging.info(f"========================================")
        logging.info(f"SSH SESSION ENDED: {node}")
        logging.info(f"========================================")


# Migration API Routes
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/migrate', methods=['POST'])
@require_auth(perms=['vm.migrate'])
def migrate_vm_api(cluster_id, node, vm_type, vmid):
    """Migrate a VM or container to another node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    # MK: Check pool permission for vm.migrate
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.migrate', vm_type):
        return jsonify({'error': 'Permission denied: vm.migrate'}), 403

    try:
        manager = cluster_managers[cluster_id]
        data = request.json or {}
        target_node = data.get('target')
        online = data.get('online', True)
        target_storage = data.get('targetstorage')
        with_local_disks = data.get('with-local-disks', False)
        force = data.get('force', False)  # For conntrack state in containers

        if not target_node:
            return jsonify({'error': 'Target node is required'}), 400

        # NS: Feb 2026 - Affinity rule enforcement (Issue #73)
        from pegaprox.api.history import check_affinity_violation
        aff = check_affinity_violation(cluster_id, vmid, target_node)
        if aff.get('violation'):
            if aff.get('enforce'):
                return jsonify({
                    'error': f"Migration blocked by affinity rule '{aff['rule']}': {aff['message']}",
                    'affinity_violation': True, 'rule': aff['rule']
                }), 409
            else:
                # MK: just warn, don't block
                logging.warning(f"Affinity warning for VMID {vmid} -> {target_node}: {aff['message']} (not enforced)")

        # Build migration options
        migrate_options = {
            'online': online,
            'targetstorage': target_storage,
            'with_local_disks': with_local_disks,
            'force': force
        }

        result = manager.migrate_vm_manual(node, vmid, vm_type, target_node, online, migrate_options)

        if result.get('success'):
            # Audit log
            user = getattr(request, 'session', {}).get('user', 'system')
            details = f"{vm_type.upper()} {vmid} migrated from {node} to {target_node}"
            if online:
                details += " (online)"
            if target_storage:
                details += f" to storage {target_storage}"
            log_audit(user, 'vm.migrated', details, cluster=manager.config.name)

            # NS: Register PegaProx user for this task
            upid = result.get('upid') or result.get('data')
            if upid:
                register_task_user(upid, user, cluster_id)

            # NS: Push immediate update for live UI
            push_immediate_update(cluster_id, delay=0.5)

            return jsonify(result)
        else:
            return jsonify(result), 400
    except Exception as e:
        # NS: Mar 2026 - catch-all so frontend gets JSON, not HTML 500
        logging.error(f"[MIGRATE] Unhandled error migrating {vm_type}/{vmid}: {e}", exc_info=True)
        return jsonify({'error': f'Migration failed: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>', methods=['DELETE'])
@require_auth(perms=['vm.delete'])
def delete_vm_api(cluster_id, node, vm_type, vmid):
    # tenant check
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # MK: Check pool permission for vm.delete
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    if not user_can_access_vm(user, cluster_id, vmid, 'vm.delete', vm_type):
        return jsonify({'error': 'Permission denied: vm.delete'}), 403
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    purge = data.get('purge', False)
    destroy_unreferenced = data.get('destroyUnreferenced', False)
    
    result = manager.delete_vm(node, vmid, vm_type, purge, destroy_unreferenced)
    
    if result.get('success'):
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'vm.deleted', f"{vm_type.upper()} {vmid} deleted from {node}" + (" (purged)" if purge else ""), cluster=manager.config.name)
        broadcast_action('delete', vm_type, str(vmid), {'node': node, 'purge': purge}, cluster_id, usr)
        
        # NS: Register PegaProx user for this task
        upid = result.get('task') or result.get('upid') or result.get('data')
        if upid:
            register_task_user(upid, usr, cluster_id)
        
        # NS: Push immediate update for live UI
        push_immediate_update(cluster_id, delay=0.5)
        
        return jsonify({'message': f'{vm_type.upper()} {vmid} deleted', 'task': result.get('task')})
    else:
        return jsonify({'error': result.get('error', 'Delete failed')}), 500


@bp.route('/api/clusters/<cluster_id>/vms/bulk-migrate', methods=['POST'])
@require_auth(perms=['vm.migrate'])
def bulk_migrate_api(cluster_id):
    """Migrate multiple VMs at once"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    vms = data.get('vms', [])  # List of {node, vmid, type}
    target_node = data.get('target')
    online = data.get('online', True)
    
    if not target_node:
        return jsonify({'error': 'Target node is required'}), 400
    
    if not vms:
        return jsonify({'error': 'No VMs specified'}), 400
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'vm.bulk_migrated', f"Bulk migration of {len(vms)} VMs to {target_node}", cluster=mgr.config.name)
    
    # LW: Feb 2026 - enforced violations skip that VM but don't abort the whole batch
    from pegaprox.api.history import check_affinity_violation

    results = []
    for vm in vms:
        # NS: affinity check per VM
        aff = check_affinity_violation(cluster_id, vm['vmid'], target_node)
        if aff.get('violation') and aff.get('enforce'):
            results.append({
                'vmid': vm['vmid'], 'success': False, 'task': None,
                'error': f"Blocked by affinity rule '{aff['rule']}': {aff['message']}"
            })
            continue
        elif aff.get('violation'):
            logging.warning(f"Affinity warning for VMID {vm['vmid']} -> {target_node}: {aff['message']} (not enforced)")

        result = mgr.migrate_vm_manual(vm['node'], vm['vmid'], vm['type'], target_node, online)

        # NS: Register PegaProx user for each migration task
        if result.get('task') or result.get('upid'):
            register_task_user(result.get('task') or result.get('upid'), user, cluster_id)

        results.append({
            'vmid': vm['vmid'],
            'success': result.get('success', False),
            'task': result.get('task'),
            'error': result.get('error')
        })
    
    # NS: Push immediate update for live UI (all migrations started)
    push_immediate_update(cluster_id, delay=0.5)
    
    return jsonify({
        'results': results,
        'total': len(vms),
        'successful': sum(1 for r in results if r['success'])
    })


@bp.route('/api/clusters/<cluster_id>/fingerprint', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_fingerprint_api(cluster_id):
    """Get cluster SSL fingerprint for remote migration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    result = manager.get_cluster_fingerprint()
    
    if result.get('success'):
        return jsonify(result)
    else:
        return jsonify({'error': result.get('error', 'Failed: fingerprint')}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/remote-migrate', methods=['POST'])
@require_auth(perms=['vm.migrate'])
def remote_migrate_vm_api(cluster_id, node, vm_type, vmid):
    """Cross-cluster remote migration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    target_endpoint = data.get('target_endpoint')
    target_storage = data.get('target_storage')
    target_bridge = data.get('target_bridge')
    target_vmid = data.get('target_vmid')
    online = data.get('online', True)
    delete_source = data.get('delete_source', True)
    bwlimit = data.get('bwlimit')
    
    if not all([target_endpoint, target_storage, target_bridge]):
        return jsonify({'error': 'target_endpoint, target_storage, and target_bridge are required'}), 400
    
    result = manager.remote_migrate_vm(
        node, vmid, vm_type, 
        target_endpoint, target_storage, target_bridge,
        target_vmid, online, delete_source, bwlimit
    )
    
    if result.get('success'):
        # NS: Register PegaProx user for this task
        user = getattr(request, 'session', {}).get('user', 'system')
        upid = result.get('task') or result.get('upid')
        if upid:
            register_task_user(upid, user, cluster_id)
        
        # NS: Push immediate update for live UI
        push_immediate_update(cluster_id, delay=0.5)
        
        return jsonify({'message': f'Remote migration started for {vm_type}/{vmid}', 'task': result.get('task')})
    else:
        return jsonify({'error': result.get('error', 'Remote migration failed')}), 500


@bp.route('/api/cross-cluster-migrate', methods=['POST'])
@require_auth(perms=['vm.migrate'])
def cross_cluster_migrate_api():
    """
    High-level cross-cluster migration API
    
    MK: This is the fancy one - migrates VMs between completely separate
    Proxmox clusters using SSH tunnels. Takes care of:
    - Creating temp API tokens on target
    - Setting up SSH tunnel for migration traffic
    - Cleaning up tokens after migration
    
    Known issue: For large VMs (>50GB disk), online migration may fail with
    "401 Unauthorized" during RAM sync due to Proxmox WebSocket ticket timeout.
    Workaround: Use offline migration for large VMs.
    """
    data = request.json or {}
    
    source_cluster_id = data.get('source_cluster')
    target_cluster_id = data.get('target_cluster')
    vmid = data.get('vmid')
    vm_type = data.get('vm_type', 'qemu')
    source_node = data.get('source_node')
    target_node = data.get('target_node')
    target_storage = data.get('target_storage')
    target_bridge = data.get('target_bridge', 'vmbr0')
    target_vmid = data.get('target_vmid')
    online = data.get('online', True)
    force_online = data.get('force_online', False)  # Override automatic offline for large disks
    delete_source = data.get('delete_source', True)
    bwlimit = data.get('bwlimit', 0)  # 0 = no limit (maximum speed to beat ticket timeout)
    
    if not target_node:
        return jsonify({'error': 'Target node is required for cross-cluster migration'}), 400
    
    if source_cluster_id not in cluster_managers:
        return jsonify({'error': 'Source cluster not found'}), 404
    if target_cluster_id not in cluster_managers:
        return jsonify({'error': 'Target cluster not found'}), 404
    # MK Feb 2026 - check access to BOTH source and target cluster
    ok, err = check_cluster_access(source_cluster_id)
    if not ok:
        return err
    ok, err = check_cluster_access(target_cluster_id)
    if not ok:
        return err

    source_manager = cluster_managers[source_cluster_id]
    target_manager = cluster_managers[target_cluster_id]
    
    # MK: Check VM disk size and warn about potential issues with online migration
    warnings = []
    try:
        vm_info = source_manager.get_vm_config(source_node, vmid, vm_type)
        if vm_info.get('success'):
            config = vm_info.get('config', {})
            total_disk_gb = 0
            for key, value in config.items():
                if key.startswith(('scsi', 'virtio', 'sata', 'ide')) and 'size' in str(value):
                    # Extract size from disk config
                    import re
                    size_match = re.search(r'size=(\d+)([GMT])', str(value))
                    if size_match:
                        size_val = int(size_match.group(1))
                        size_unit = size_match.group(2)
                        if size_unit == 'G':
                            total_disk_gb += size_val
                        elif size_unit == 'T':
                            total_disk_gb += size_val * 1024
                        elif size_unit == 'M':
                            total_disk_gb += size_val / 1024
            
            if total_disk_gb > 100 and online and not force_online:
                # MK: Proxmox WebSocket tickets have internal timeout (~5 min)
                # Large disk migrations take longer than this, causing 401 errors
                # during RAM sync phase. Auto-switch to offline migration.
                # 
                # Math: 100GB in 5 min = 333 MB/s = ~2.7 Gbit/s sustained
                # Most cross-cluster links can't sustain this.
                required_speed_mbps = (total_disk_gb * 1024) / 300  # MB/s needed for 5 min
                warnings.append(f"VM has {total_disk_gb:.0f}GB disk. Would need {required_speed_mbps:.0f} MB/s ({required_speed_mbps*8/1000:.1f} Gbit/s) to complete in 5 min. Automatically using offline migration.")
                logging.warning(f"[CROSS-MIGRATE] Large VM ({total_disk_gb}GB) - forcing offline migration due to Proxmox WebSocket ticket timeout limitation")
                online = False  # Force offline migration for large disks
            elif total_disk_gb > 100 and online and force_online:
                required_speed_mbps = (total_disk_gb * 1024) / 300
                warnings.append(f"VM has {total_disk_gb:.0f}GB disk with forced online migration. Need {required_speed_mbps:.0f} MB/s sustained to avoid timeout. Migration may fail with '401 Unauthorized'.")
                logging.warning(f"[CROSS-MIGRATE] Large VM ({total_disk_gb}GB) - online migration forced by user, may fail")
    except Exception as e:
        logging.debug(f"Could not check VM size: {e}")
    
    # Generate unique token name
    import time
    token_name = f"pegaprox-migrate-{int(time.time())}"
    target_token = None
    
    try:
        # Step 1: Create temporary API token on TARGET cluster (without privilege separation)
        logging.info(f"Creating temporary API token on target cluster ({target_cluster_id}) for user {target_manager.config.user}...")
        token_result = target_manager.create_api_token(token_name)
        if not token_result.get('success'):
            return jsonify({'error': f'Could not create API token on target cluster: {token_result.get("error")}'}), 500
        
        target_token = token_result
        logging.info(f"Created token on target cluster: {target_token['token_id']}")
        
        # Step 2: Get target cluster fingerprint
        fp_result = target_manager.get_cluster_fingerprint()
        if not fp_result.get('success'):
            raise Exception(f'Could not get target fingerprint: {fp_result.get("error")}')
        
        # Step 3: Build target endpoint string
        # MK: Format must be exact - Proxmox is picky about this
        # Format: apitoken=PVEAPIToken=<user>!<tokenname>=<secret>,host=<host>,fingerprint=<fp>
        target_endpoint = (
            f"apitoken=PVEAPIToken={target_token['token_id']}={target_token['token_value']},"
            f"host={fp_result['host']},"
            f"fingerprint={fp_result['fingerprint']}"
        )
        
        logging.info(f"Starting remote migration of {vm_type}/{vmid} from {source_cluster_id} to {target_cluster_id}...")
        logging.info(f"Target host: {fp_result['host']}, Token user: {target_token['token_id'].split('!')[0]}, Online: {online}")
        
        # Step 4: Perform the migration
        result = source_manager.remote_migrate_vm(
            source_node, vmid, vm_type,
            target_endpoint, target_storage, target_bridge,
            target_vmid, online, delete_source, bwlimit
        )
        
        if result.get('success'):
            # Log to audit
            user = request.session.get('user', 'system')
            log_audit(
                user,
                'vm.cross_cluster_migrate',
                f"Cross-cluster migration: {vm_type}/{vmid} from {source_cluster_id} to {target_cluster_id}/{target_node}",
                request.remote_addr
            )
            
            # NS: Register PegaProx user for this task
            task_upid = result.get('task')
            if task_upid:
                register_task_user(task_upid, user, source_cluster_id)
            
            # NS: Push immediate update for live UI (source cluster)
            push_immediate_update(source_cluster_id, delay=0.5)
            
            # Schedule intelligent token cleanup - monitors task status
            def cleanup_token_when_done():
                import time
                max_wait = 7200  # Maximum 2 hours (large VMs can take a long time!)
                poll_interval = 15  # Check every 15 seconds
                elapsed = 0
                min_wait_before_assuming_done = 300  # MK: Wait at least 5 minutes before assuming task is done
                
                logging.info(f"[TOKEN-CLEANUP] Monitoring task {task_upid} for completion...")
                
                while elapsed < max_wait:
                    try:
                        # Get task status from source cluster (where the migration task runs)
                        tasks = source_manager.get_tasks(limit=100)
                        task_found = False
                        
                        for task in tasks:
                            if task and task.get('upid') == task_upid:
                                task_found = True
                                status = task.get('status', '')
                                
                                # check task is finished
                                if status and status != 'running':
                                    if status == 'OK':
                                        logging.info(f"[TOKEN-CLEANUP] Migration task completed successfully!")
                                    else:
                                        logging.warning(f"[TOKEN-CLEANUP] Migration task ended with status: {status}")
                                    
                                    # MK: Wait a bit more after task completion to be safe
                                    # The VM might still be syncing final state
                                    time.sleep(30)
                                    
                                    # Task finished - delete token
                                    target_manager.delete_api_token(token_name)
                                    logging.info(f"[TOKEN-CLEANUP] Deleted migration token: {token_name}")
                                    return
                                break
                        
                        # MK: Fix for Issue #19 - Don't delete token too early!
                        # If task not found, it might have completed and scrolled out of task list
                        # BUT we need to wait much longer to be safe (was 60s, now 5 min minimum)
                        if not task_found and elapsed > min_wait_before_assuming_done:
                            # Double-check: Try to verify VM exists on target cluster
                            try:
                                # Check if VM exists on target (migration successful)
                                target_vms = target_manager.get_vm_resources()
                                vm_on_target = any(
                                    v.get('vmid') == vmid or v.get('vmid') == target_vmid
                                    for v in (target_vms or [])
                                )
                                if vm_on_target:
                                    logging.info(f"[TOKEN-CLEANUP] VM found on target cluster, migration likely successful")
                                else:
                                    logging.info(f"[TOKEN-CLEANUP] VM not yet on target, waiting longer...")
                                    time.sleep(poll_interval)
                                    elapsed += poll_interval
                                    continue
                            except Exception as e:
                                logging.warning(f"[TOKEN-CLEANUP] Could not verify VM on target: {e}")
                            
                            logging.info(f"[TOKEN-CLEANUP] Task no longer in task list after {elapsed}s, assuming completed")
                            target_manager.delete_api_token(token_name)
                            logging.info(f"[TOKEN-CLEANUP] Deleted migration token: {token_name}")
                            return
                            
                    except Exception as e:
                        logging.warning(f"[TOKEN-CLEANUP] Error checking task status: {e}")
                    
                    time.sleep(poll_interval)
                    elapsed += poll_interval
                
                # Timeout - delete token anyway
                logging.warning(f"[TOKEN-CLEANUP] Timeout after {max_wait}s waiting for task, deleting token anyway")
                target_manager.delete_api_token(token_name)
                logging.info(f"[TOKEN-CLEANUP] Deleted migration token: {token_name}")
            
            cleanup_thread = threading.Thread(target=cleanup_token_when_done, daemon=True)
            cleanup_thread.start()
            
            response = {
                'message': f'Cross-cluster migration started: {vm_type}/{vmid} from {source_cluster_id} to {target_cluster_id}/{target_node}',
                'task': result.get('task'),
                'online': online,
                'info': 'Temporary API token will be automatically cleaned up after migration completes.'
            }
            if warnings:
                response['warnings'] = warnings
            
            return jsonify(response)
        else:
            # Migration failed - cleanup token immediately
            error_msg = result.get('error', 'Cross-cluster migration failed')
            
            # MK: Add helpful hint for 401 errors
            if '401' in error_msg or 'Unauthorized' in error_msg or 'Broken pipe' in error_msg:
                error_msg += ". If this persists, check PegaProx version (token cleanup timing was fixed in 0.6.2)"
            
            target_manager.delete_api_token(token_name)
            return jsonify({'error': error_msg}), 500
            
    except Exception as e:
        # Cleanup token on any error
        if target_token:
            target_manager.delete_api_token(token_name)
        logging.error(f"Cross-cluster migration error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes-status', methods=['GET'])
@require_auth(perms=["node.view"])
def get_cluster_nodes_status_api(cluster_id):
    """Get list of nodes with status info - LW: alternative endpoint with more details"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    node_status = manager.get_node_status()
    
    # Return just the node names and basic info
    nodes = []
    for node_name, status in node_status.items():
        nodes.append({
            'node': node_name,
            'status': status.get('status', 'unknown'),
            'cpu_percent': status.get('cpu_percent', 0),
            'mem_percent': status.get('mem_percent', 0)
        })
    
    return jsonify(nodes)


# VM/CT Creation API Routes
@bp.route('/api/clusters/<cluster_id>/nodes/<node>/nextid', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_next_vmid_for_node_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    result = manager.get_next_vmid()
    
    if result.get('success'):
        return jsonify({'vmid': result['vmid']})
    else:
        return jsonify(result), 400


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/templates', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_templates_api(cluster_id, node):
    """Get available templates for VM/CT creation"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    templates = manager.get_templates(node)
    return jsonify(templates)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/qemu', methods=['POST'])
@require_auth(perms=["vm.create"])
def create_vm_api(cluster_id, node):
    """Create a new VM on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    vm_config = request.json or {}
    
    result = manager.create_vm(node, vm_config)
    
    if result.get('success'):
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'unknown')
        vmid = vm_config.get('vmid') or result.get('data', {}).get('vmid', 'unknown')
        vm_name = vm_config.get('name', f'vm-{vmid}')
        log_audit(user, 'vm.create', f"Created VM {vmid} ({vm_name}) on {node}", cluster=manager.config.name)
        
        # Broadcast to all clients
        broadcast_action('create', 'qemu', str(vmid), {'node': node, 'name': vm_name}, cluster_id, user)
        
        # NS: Push immediate update for live UI
        push_immediate_update(cluster_id, delay=0.5)
        
        return jsonify(result)
    else:
        return jsonify(result), 400


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/lxc', methods=['POST'])
@require_auth(perms=["vm.create"])
def create_container_api(cluster_id, node):
    """Create a new container on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    ct_config = request.json or {}
    
    result = manager.create_container(node, ct_config)
    
    if result.get('success'):
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'unknown')
        vmid = ct_config.get('vmid') or result.get('data', {}).get('vmid', 'unknown')
        ct_name = ct_config.get('hostname', f'ct-{vmid}')
        log_audit(user, 'container.create', f"Created CT {vmid} ({ct_name}) on {node}", cluster=manager.config.name)
        
        # Broadcast to all clients
        broadcast_action('create', 'lxc', str(vmid), {'node': node, 'name': ct_name}, cluster_id, user)
        
        # NS: Push immediate update for live UI
        push_immediate_update(cluster_id, delay=0.5)
        
        return jsonify(result)
    else:
        return jsonify(result), 400



