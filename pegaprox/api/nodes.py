# -*- coding: utf-8 -*-
"""node management, updates, SMBIOS & scripts routes - split from monolith dec 2025, NS/MK"""

import os
import json
import time
import logging
import uuid
import re
import shlex
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users, verify_password
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import check_cluster_access

bp = Blueprint('nodes', __name__)

# ==================== NODE MANAGEMENT API ENDPOINTS ====================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/summary', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_summary_api(cluster_id, node):
    """Get node summary"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_summary(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ip', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_ip_api(cluster_id, node):
    """Get node IP address for SSH connections

    MK: Tries multiple methods to get the node's IP:
    1. Cluster status API (for clustered nodes)
    2. Network configuration API
    3. Fallback to cluster host
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    cluster_host = mgr.current_host or mgr.config.host
    node_ip = None
    source = None
    
    try:
        host = cluster_host
        
        # Method 1: Cluster status API (has IPs for clustered nodes)
        status_url = f"https://{host}:8006/api2/json/cluster/status"
        r = mgr._create_session().get(status_url, timeout=10)
        
        if r.status_code == 200:
            for item in r.json().get('data', []):
                if item.get('type') == 'node':
                    item_name = item.get('name', '')
                    if item_name.lower() == node.lower() and item.get('ip'):
                        node_ip = item.get('ip')
                        source = 'cluster_status'
                        break
        
        # Method 2: Network configuration API
        if not node_ip:
            net_url = f"https://{host}:8006/api2/json/nodes/{node}/network"
            r = mgr._create_session().get(net_url, timeout=5)
            if r.status_code == 200:
                for iface in r.json().get('data', []):
                    iface_type = iface.get('type', '')
                    addr = iface.get('address', '')
                    cidr = iface.get('cidr', '')
                    
                    if not addr and cidr:
                        addr = cidr.split('/')[0]
                    
                    # Look for bridge or main interface with IP
                    if addr and iface_type in ['bridge', 'eth', 'bond', 'OVSBridge', 'vlan']:
                        node_ip = addr
                        source = f'network_{iface.get("iface", "unknown")}'
                        break
        
        # Method 3: Fallback to cluster host
        if not node_ip:
            node_ip = cluster_host
            source = 'cluster_host_fallback'
            
    except Exception as e:
        logging.error(f"Error getting node IP: {e}")
        node_ip = cluster_host
        source = 'error_fallback'
    
    return jsonify({
        'ip': node_ip,
        'node': node,
        'source': source
    })


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/rrddata', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_rrddata_api(cluster_id, node):
    """Get node performance metrics (RRD data) for charts

    Query params:
    - timeframe: hour, day, week, month, year (default: hour)
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    timeframe = request.args.get('timeframe', 'hour')
    return jsonify(manager.get_node_rrddata(node, timeframe))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/network', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_network_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_network_config(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/network/<iface>', methods=['PUT'])
@require_auth(perms=['node.network'])
def update_node_network_api(cluster_id, node, iface):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.update_node_network(node, iface, request.json or {})
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/network', methods=['POST'])
@require_auth(perms=['node.network'])
def create_node_network_api(cluster_id, node):
    """Create a new network interface"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    iface = data.get('iface', '')
    iface_type = data.get('type', 'bridge')
    
    if not iface:
        return jsonify({'error': 'Interface name required'}), 400
    
    config = {k: v for k, v in data.items() if k not in ['iface', 'type']}
    result = mgr.create_node_network(node, iface, iface_type, config)
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/network/<iface>', methods=['DELETE'])
@require_auth(perms=['node.network'])
def delete_node_network_api(cluster_id, node, iface):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.delete_node_network(node, iface)
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/network', methods=['PUT'])
@require_auth(perms=['node.network'])
def apply_node_network_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.apply_node_network(node)
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/network', methods=['DELETE'])
@require_auth(perms=['node.network'])
def revert_node_network_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.revert_node_network(node)
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/dns', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_dns_api(cluster_id, node):
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_dns(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/dns', methods=['PUT'])
@require_auth(perms=['node.network'])
def update_node_dns_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    result = mgr.update_node_dns(node, request.json or {})
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hosts', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_hosts_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify({'data': cluster_managers[cluster_id].get_node_hosts(node)})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hosts', methods=['POST'])
@require_auth(perms=['node.network'])
def update_node_hosts_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    result = mgr.update_node_hosts(node, data.get('data', ''))
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/time', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_time_api(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_node_time(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/time', methods=['PUT'])
@require_auth(perms=['node.network'])
def update_node_time_api(cluster_id, node):
    """Update node timezone"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    result = mgr.update_node_time(node, data.get('timezone', 'UTC'))
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/syslog', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_syslog_api(cluster_id, node):
    """Get node system log"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    start = request.args.get('start', 0, type=int)
    limit = request.args.get('limit', 500, type=int)
    return jsonify(manager.get_node_syslog(node, start, limit))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/certificates', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_certificates_api(cluster_id, node):
    """Get node certificates"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_certificates(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/certificates/renew', methods=['POST'])
@require_auth(perms=['node.network'])
def renew_node_certificate_api(cluster_id, node):
    """Renew node certificate"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    force = request.json.get('force', False) if request.json else False
    result = manager.renew_node_certificate(node, force)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/certificates/custom', methods=['POST'])
@require_auth(perms=['node.network'])
def upload_node_certificate_api(cluster_id, node):
    """Upload custom certificate to node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    certificates = data.get('certificates', '')
    key = data.get('key', '')
    restart = data.get('restart', True)
    force = data.get('force', False)
    
    if not certificates or not key:
        return jsonify({'error': 'Certificate and key are required'}), 400
    
    result = manager.upload_node_certificate(node, certificates, key, restart, force)
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/certificates/custom', methods=['DELETE'])
@require_auth(perms=['node.network'])
def delete_node_certificate_api(cluster_id, node):
    """Delete custom certificate from node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    restart = request.args.get('restart', 'true').lower() == 'true'
    result = mgr.delete_node_certificate(node, restart)
    
    if result['success']:
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/replication', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_node_replication_api(cluster_id, node):
    """Get replication jobs for node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_replication(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/tasks', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_tasks_api(cluster_id, node):
    """Get task history for node, optionally filtered by vmid"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    start = request.args.get('start', 0, type=int)
    limit = request.args.get('limit', 50, type=int)
    errors = request.args.get('errors', 'false').lower() == 'true'
    vmid = request.args.get('vmid', None, type=int)
    
    tasks = manager.get_node_tasks(node, start, limit * 3 if vmid else limit, errors)  # Get more if filtering
    
    # Filter by vmid if specified
    if vmid and tasks:
        filtered = [t for t in tasks if t.get('id') == str(vmid) or str(vmid) in str(t.get('upid', ''))]
        return jsonify(filtered[:limit])
    
    return jsonify(tasks)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/tasks/<path:upid>/log', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_task_log_api(cluster_id, node, upid):
    """Get log for a specific task

    NS: Fixed Dec 2025 - frontend expects { log: "..." } format
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    start = request.args.get('start', 0, type=int)
    limit = request.args.get('limit', 500, type=int)
    
    log_lines = manager.get_node_task_log(node, upid, start, limit)
    # Join lines into a single string for display
    log_text = '\n'.join(log_lines) if log_lines else ''
    
    return jsonify({'log': log_text})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/subscription', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_subscription_api(cluster_id, node):
    """Get node subscription status"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_subscription(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/subscription', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def update_node_subscription_api(cluster_id, node):
    """Update subscription key - admin only"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    result = mgr.update_node_subscription(node, data.get('key', ''))
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'subscription.updated', f"Subscription key updated for {node}", cluster=mgr.config.name)
        return jsonify({'message': result['message']})
    return jsonify({'error': result['error']}), 500


# =============================================================================
# SMBIOS Auto-Configurator Feature
# MK: Automatically sets SMBIOS data on new VMs for Windows licensing etc.
# MK: this was surprisingly tricky to get right, proxmox smbios format is picky
# =============================================================================

SMBIOS_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""
SMBIOS Auto-Configurator for Proxmox VE
Deployed by PegaProx - automatically configures SMBIOS for new VMs

Runs as a systemd service, monitors for new VMs and sets SMBIOS data.
"""

import subprocess
import time
import os
import random
from datetime import datetime

# Configuration - set by PegaProx when deployed
MANUFACTURER = "{manufacturer}"
PRODUCT = "{product}"
VERSION = "{version}"
FAMILY = "{family}"

# Paths
LOG_FILE = "/var/log/pegaprox-smbios.log"
PROCESSED_VMS_FILE = "/var/lib/pegaprox-smbios-processed.txt"  # keeps track of what we already did

def log_message(message):
    """write to log file, nothing fancy"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{{timestamp}}] {{message}}"
    print(log_entry)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry + "\\n")
    except:
        pass  # if we cant log, oh well

def get_all_vms():
    """get vmids from qm list"""
    try:
        result = subprocess.run(['qm', 'list'], capture_output=True, text=True)
        vms = []
        for line in result.stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if parts:
                vms.append(parts[0])
        return vms
    except Exception as e:
        log_message(f"Error fetching VM list: {{e}}")
        return []

def load_processed_vms():
    """Load already processed VMs"""
    if os.path.exists(PROCESSED_VMS_FILE):
        with open(PROCESSED_VMS_FILE, 'r') as f:
            return set(f.read().splitlines())
    return set()

def save_processed_vm(vmid):
    """Mark VM as processed"""
    with open(PROCESSED_VMS_FILE, 'a') as f:
        f.write(f"{{vmid}}\\n")

def get_current_smbios(vmid):
    """Get current SMBIOS settings"""
    try:
        result = subprocess.run(['qm', 'config', vmid], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('smbios1:'):
                return line.split(':', 1)[1].strip()
        return None
    except:
        return None

def parse_smbios_string(smbios_str):
    """Parse SMBIOS string into dictionary"""
    params = {{}}
    if not smbios_str:
        return params
    for part in smbios_str.split(','):
        if '=' in part:
            key, value = part.split('=', 1)
            params[key.strip()] = value.strip()
    return params

def needs_smbios_update(vmid):
    """Check if VM needs SMBIOS configuration"""
    smbios_str = get_current_smbios(vmid)
    if not smbios_str:
        return True
    
    params = parse_smbios_string(smbios_str)
    relevant_params = {{k: v for k, v in params.items() if k != 'uuid'}}
    
    if not relevant_params:
        return True
    
    if ('manufacturer' in params or 'product' in params or 
        'version' in params or 'serial' in params or 'family' in params):
        log_message(f"VM {{vmid}} already has SMBIOS configuration")
        return False
    
    return True

def generate_unique_serial():
    """Generate unique serial number"""
    timestamp = datetime.now().strftime("%y%m%d%H%M%S")
    random_part = random.randint(1000, 9999)
    return f"PVE{{timestamp}}{{random_part}}"

def set_smbios(vmid):
    """Set SMBIOS configuration"""
    current_smbios_str = get_current_smbios(vmid)
    current_params = parse_smbios_string(current_smbios_str) if current_smbios_str else {{}}
    uuid_value = current_params.get('uuid', '')
    serial = generate_unique_serial()
    
    smbios_parts = [
        f"manufacturer={{MANUFACTURER}}",
        f"product={{PRODUCT}}",
        f"version={{VERSION}}",
        f"serial={{serial}}",
    ]
    if uuid_value:
        smbios_parts.append(f"uuid={{uuid_value}}")
    smbios_parts.append(f"family={{FAMILY}}")
    
    smbios_string = ",".join(smbios_parts)
    cmd = ['qm', 'set', vmid, '-smbios1', smbios_string]
    
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        log_message(f"Set SMBIOS for VM {{vmid}} | Serial: {{serial}}")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"Error setting SMBIOS for VM {{vmid}}: {{e.stderr if e.stderr else e}}")
        return False

def check_vm_exists(vmid):
    """Check if VM exists"""
    try:
        result = subprocess.run(['qm', 'status', vmid], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def cleanup_processed_list(processed):
    """Remove VMs that no longer exist"""
    current_vms = set(get_all_vms())
    removed_vms = processed - current_vms
    
    if removed_vms:
        for vmid in removed_vms:
            log_message(f"VM {{vmid}} no longer exists, removing from tracking")
            processed.remove(vmid)
        with open(PROCESSED_VMS_FILE, 'w') as f:
            for vmid in processed:
                f.write(f"{{vmid}}\\n")
    return processed

def main():
    log_message("=== PegaProx SMBIOS Auto-Configurator started ===")
    log_message(f"Config: {{MANUFACTURER}} | {{PRODUCT}} | {{VERSION}} | {{FAMILY}}")
    
    processed = load_processed_vms()
    cleanup_counter = 0
    
    while True:
        try:
            cleanup_counter += 1
            if cleanup_counter >= 30:
                processed = cleanup_processed_list(processed)
                cleanup_counter = 0
            
            current_vms = get_all_vms()
            
            for vmid in current_vms:
                if vmid not in processed:
                    if check_vm_exists(vmid):
                        if needs_smbios_update(vmid):
                            log_message(f"Configuring SMBIOS for new VM {{vmid}}")
                            if set_smbios(vmid):
                                save_processed_vm(vmid)
                                processed.add(vmid)
                        else:
                            save_processed_vm(vmid)
                            processed.add(vmid)
            
            time.sleep(2)
            
        except KeyboardInterrupt:
            log_message("=== SMBIOS Auto-Configurator stopped ===")
            break
        except Exception as e:
            log_message(f"Error: {{e}}")
            time.sleep(10)

if __name__ == "__main__":
    main()
'''

SMBIOS_SERVICE_TEMPLATE = '''[Unit]
Description=PegaProx SMBIOS Auto-Configurator
After=pve-cluster.service
Wants=pve-cluster.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/pegaprox-smbios-autoconfig.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''

@bp.route('/api/clusters/<cluster_id>/smbios-autoconfig', methods=['GET'])
@require_auth(perms=['node.view'])
def get_smbios_autoconfig(cluster_id):
    """get smbios settings for the cluster, returns defaults if not configured yet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    try:
        if cluster_id not in cluster_managers:
            return jsonify({'error': 'Cluster not found'}), 404
        
        # defaults if nothing configured - NS: proxmox doesnt allow underscores so no spaces either
        mgr = cluster_managers[cluster_id]
        settings = getattr(mgr.config, 'smbios_autoconfig', None) or {
            'enabled': False,
            'manufacturer': 'Proxmox',
            'product': 'PegaProxManagment',
            'version': 'v1',
            'family': 'ProxmoxVE'
        }
        
        return jsonify(settings)
    except Exception as e:
        logging.error(f"Error getting SMBIOS config: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/smbios-autoconfig', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def update_smbios_autoconfig(cluster_id):
    """save smbios settings - gets deployed to nodes when they click deploy"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.json or {}
    mgr = cluster_managers[cluster_id]

    # NS Feb 2026: Validate SMBIOS values to prevent template injection
    for key in ['manufacturer', 'product', 'version', 'family']:
        val = data.get(key, '')
        if val and not re.match(r'^[a-zA-Z0-9 ._-]{1,64}$', val):
            return jsonify({'error': f'Invalid {key}: only alphanumeric, spaces, dots, hyphens allowed (max 64 chars)'}), 400

    # Update settings
    mgr.config.smbios_autoconfig = {
        'enabled': data.get('enabled', False),
        'manufacturer': data.get('manufacturer', 'Proxmox'),
        'product': data.get('product', 'Virtual Machine'),
        'version': data.get('version', 'PVE8'),
        'family': data.get('family', 'ProxmoxVE')
    }
    
    # Save to database
    db = get_db()
    db.update_cluster(cluster_id, {'smbios_autoconfig': json.dumps(mgr.config.smbios_autoconfig)})
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'smbios_autoconfig.updated', f"SMBIOS auto-config updated", cluster=mgr.config.name)
    
    return jsonify({'success': True, 'message': 'Settings saved'})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/smbios-autoconfig/status', methods=['GET'])
@require_auth(perms=['node.view'])
def get_smbios_autoconfig_status(cluster_id, node):
    """Check if SMBIOS auto-config service is running on node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        # Get node IP and connect via SSH
        # For single-node, use cluster host; for multi-node, resolve from cluster status
        node_ip = mgr.current_host or mgr.config.host
        
        # Try to get actual node IP from cluster status
        try:
            status_url = f"https://{node_ip}:8006/api2/json/cluster/status"
            r = mgr._create_session().get(status_url, timeout=10)
            if r.status_code == 200:
                for item in r.json().get('data', []):
                    if item.get('type') == 'node' and item.get('name', '').lower() == node.lower():
                        if item.get('ip'):
                            node_ip = item.get('ip')
                            break
        except:
            pass
        
        ssh = mgr._ssh_connect(node_ip)
        if not ssh:
            return jsonify({'installed': False, 'running': False, 'error': 'SSH not available - check SSH key in cluster settings'})
        
        # Check if script exists
        stdin, stdout, stderr = ssh.exec_command('test -f /opt/pegaprox-smbios-autoconfig.py && echo exists')
        installed = 'exists' in stdout.read().decode()
        
        # Check if service is running
        stdin, stdout, stderr = ssh.exec_command('systemctl is-active pegaprox-smbios-autoconfig 2>/dev/null || echo inactive')
        status = stdout.read().decode().strip()
        running = status == 'active'
        
        # Get last log entries
        stdin, stdout, stderr = ssh.exec_command('tail -5 /var/log/pegaprox-smbios.log 2>/dev/null || echo "No logs yet"')
        logs = stdout.read().decode().strip()
        
        ssh.close()
        
        return jsonify({
            'installed': installed,
            'running': running,
            'status': status,
            'logs': logs
        })
        
    except Exception as e:
        logging.error(f"Error checking SMBIOS autoconfig status: {e}")
        return jsonify({'installed': False, 'running': False, 'error': str(e)})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/smbios-autoconfig/deploy', methods=['POST'])
@require_auth(perms=['admin.settings'])
def deploy_smbios_autoconfig(cluster_id, node):
    """Deploy SMBIOS auto-config script to node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    settings = getattr(mgr.config, 'smbios_autoconfig', None) or {}
    
    try:
        # Get node IP
        node_ip = mgr.current_host or mgr.config.host
        try:
            status_url = f"https://{node_ip}:8006/api2/json/cluster/status"
            r = mgr._create_session().get(status_url, timeout=10)
            if r.status_code == 200:
                for item in r.json().get('data', []):
                    if item.get('type') == 'node' and item.get('name', '').lower() == node.lower():
                        if item.get('ip'):
                            node_ip = item.get('ip')
                            break
        except:
            pass
        
        ssh = mgr._ssh_connect(node_ip)
        if not ssh:
            return jsonify({'error': 'SSH connection failed - check SSH key in cluster settings'}), 500
        
        # Generate script with settings (defense-in-depth: strip quotes/backslashes - NS Feb 2026)
        def _sanitize_smbios(val):
            """Strip characters dangerous in Python string literals as defense-in-depth."""
            return re.sub(r'[^a-zA-Z0-9 ._-]', '', str(val))[:64]
        script = SMBIOS_SCRIPT_TEMPLATE.format(
            manufacturer=_sanitize_smbios(settings.get('manufacturer', 'Proxmox')),
            product=_sanitize_smbios(settings.get('product', 'PegaProxManagment')),
            version=_sanitize_smbios(settings.get('version', 'v1')),
            family=_sanitize_smbios(settings.get('family', 'ProxmoxVE'))
        )
        
        # Write script to node
        sftp = ssh.open_sftp()
        with sftp.file('/opt/pegaprox-smbios-autoconfig.py', 'w') as f:
            f.write(script)
        sftp.chmod('/opt/pegaprox-smbios-autoconfig.py', 0o755)
        
        # Write systemd service
        with sftp.file('/etc/systemd/system/pegaprox-smbios-autoconfig.service', 'w') as f:
            f.write(SMBIOS_SERVICE_TEMPLATE)
        
        sftp.close()
        
        # Enable and start service
        # NS: clear processed list so ALL vms get checked (not just new ones)
        commands = [
            'rm -f /var/lib/pegaprox-smbios-processed.txt',
            'systemctl daemon-reload',
            'systemctl enable pegaprox-smbios-autoconfig',
            'systemctl restart pegaprox-smbios-autoconfig'
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            stdout.read()  # Wait for completion
        
        ssh.close()
        
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'smbios_autoconfig.deployed', f"SMBIOS auto-config deployed to {node}", cluster=mgr.config.name)
        
        return jsonify({'success': True, 'message': f'SMBIOS Auto-Config deployed to {node}'})
        
    except Exception as e:
        logging.error(f"Error deploying SMBIOS autoconfig: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/smbios-autoconfig', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def remove_smbios_autoconfig(cluster_id, node):
    """Remove SMBIOS auto-config from node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        # Get node IP
        node_ip = mgr.current_host or mgr.config.host
        try:
            status_url = f"https://{node_ip}:8006/api2/json/cluster/status"
            r = mgr._create_session().get(status_url, timeout=10)
            if r.status_code == 200:
                for item in r.json().get('data', []):
                    if item.get('type') == 'node' and item.get('name', '').lower() == node.lower():
                        if item.get('ip'):
                            node_ip = item.get('ip')
                            break
        except:
            pass
        
        ssh = mgr._ssh_connect(node_ip)
        if not ssh:
            return jsonify({'error': 'SSH connection failed - check SSH key in cluster settings'}), 500
        
        # Stop and disable service, remove files
        commands = [
            'systemctl stop pegaprox-smbios-autoconfig 2>/dev/null || true',
            'systemctl disable pegaprox-smbios-autoconfig 2>/dev/null || true',
            'rm -f /etc/systemd/system/pegaprox-smbios-autoconfig.service',
            'rm -f /opt/pegaprox-smbios-autoconfig.py',
            'rm -f /var/lib/pegaprox-smbios-processed.txt',
            'systemctl daemon-reload'
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            stdout.read()
        
        ssh.close()
        
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'smbios_autoconfig.removed', f"SMBIOS auto-config removed from {node}", cluster=mgr.config.name)
        
        return jsonify({'success': True, 'message': f'SMBIOS Auto-Config removed from {node}'})
        
    except Exception as e:
        logging.error(f"Error removing SMBIOS autoconfig: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/smbios-autoconfig/control', methods=['POST'])
@require_auth(perms=['admin.settings'])
def control_smbios_autoconfig(cluster_id, node):
    """Start/Stop/Rescan SMBIOS auto-config service on node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.get_json() or {}
    action = data.get('action')  # 'start', 'stop', 'restart', 'rescan'
    
    if action not in ['start', 'stop', 'restart', 'rescan']:
        return jsonify({'error': 'Invalid action. Use start, stop, restart, or rescan'}), 400
    
    mgr = cluster_managers[cluster_id]
    
    try:
        # Get node IP
        node_ip = mgr.current_host or mgr.config.host
        try:
            status_url = f"https://{node_ip}:8006/api2/json/cluster/status"
            r = mgr._create_session().get(status_url, timeout=10)
            if r.status_code == 200:
                for item in r.json().get('data', []):
                    if item.get('type') == 'node' and item.get('name', '').lower() == node.lower():
                        if item.get('ip'):
                            node_ip = item.get('ip')
                            break
        except:
            pass
        
        ssh = mgr._ssh_connect(node_ip)
        if not ssh:
            return jsonify({'error': 'SSH connection failed'}), 500
        
        # NS: rescan = nuke the processed list and restart, forces re-check of all VMs
        if action == 'rescan':
            cmd = 'rm -f /var/lib/pegaprox-smbios-processed.txt && systemctl restart pegaprox-smbios-autoconfig'
        else:
            cmd = f'systemctl {action} pegaprox-smbios-autoconfig'
        
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.read()
        err_output = stderr.read().decode()
        
        ssh.close()
        
        if err_output and 'not found' in err_output.lower():
            return jsonify({'error': 'Service not installed on this node'}), 404
        
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, f'smbios_autoconfig.{action}', f"SMBIOS auto-config {action} on {node}", cluster=mgr.config.name)
        
        return jsonify({'success': True, 'message': f'Service {action}ed on {node}'})
        
    except Exception as e:
        logging.error(f"Error controlling SMBIOS autoconfig: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/smbios-autoconfig/status-all', methods=['GET'])
@require_auth(perms=['node.view'])
def get_smbios_autoconfig_status_all(cluster_id):
    """Get SMBIOS auto-config status for ALL nodes in cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        # Get all nodes - try different methods
        try:
            node_status = mgr.get_node_status()
            node_names = list(node_status.keys()) if node_status else []
        except:
            try:
                nodes = mgr.get_nodes()
                node_names = [n.get('node', n.get('name', '')) for n in nodes if n]
            except:
                node_names = []
        
        if not node_names:
            return jsonify({'error': 'No nodes available'}), 400
        
        results = {}
        
        for node_name in node_names:
            if not node_name:
                continue
                
            try:
                # Get node IP
                node_ip = mgr._get_node_ip(node_name)
                if not node_ip:
                    results[node_name] = {'installed': False, 'running': False, 'error': 'Could not determine node IP'}
                    continue
                
                ssh = mgr._ssh_connect(node_ip)
                if not ssh:
                    results[node_name] = {'installed': False, 'running': False, 'error': 'SSH not available'}
                    continue
                
                try:
                    # Check if script exists
                    stdin, stdout, stderr = ssh.exec_command('test -f /opt/pegaprox-smbios-autoconfig.py && echo exists')
                    installed = 'exists' in stdout.read().decode()
                    
                    # Check if service is running
                    stdin, stdout, stderr = ssh.exec_command('systemctl is-active pegaprox-smbios-autoconfig 2>/dev/null || echo inactive')
                    status = stdout.read().decode().strip()
                    running = status == 'active'
                    
                    results[node_name] = {
                        'installed': installed,
                        'running': running,
                        'status': status
                    }
                finally:
                    ssh.close()
                    
            except Exception as e:
                results[node_name] = {'installed': False, 'running': False, 'error': str(e)}
        
        return jsonify(results)
        
    except Exception as e:
        logging.error(f"Error getting SMBIOS autoconfig status: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/smbios-autoconfig/deploy-all', methods=['POST'])
@require_auth(perms=['admin.settings'])
def deploy_smbios_autoconfig_all(cluster_id):
    """Deploy SMBIOS auto-config script to ALL nodes in cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    settings = getattr(mgr.config, 'smbios_autoconfig', None) or {}
    
    # Get all nodes in cluster
    nodes = []
    node_ips = {}
    try:
        cluster_host = mgr.current_host or mgr.config.host
        status_url = f"https://{cluster_host}:8006/api2/json/cluster/status"
        r = mgr._create_session().get(status_url, timeout=10)
        if r.status_code == 200:
            for item in r.json().get('data', []):
                if item.get('type') == 'node':
                    node_name = item.get('name')
                    nodes.append(node_name)
                    node_ips[node_name] = item.get('ip') or cluster_host
        else:
            # Single node cluster - just use cluster host
            nodes = [mgr.config.host.split('.')[0]]
            node_ips[nodes[0]] = cluster_host
    except Exception as e:
        logging.error(f"Error getting cluster nodes: {e}")
        return jsonify({'error': f'Could not get cluster nodes: {e}'}), 500
    
    if not nodes:
        return jsonify({'error': 'No nodes found in cluster'}), 404
    
    results = []
    def _sanitize_smbios_val(val):
        """Strip characters dangerous in Python string literals as defense-in-depth."""
        return re.sub(r'[^a-zA-Z0-9 ._-]', '', str(val))[:64]
    script = SMBIOS_SCRIPT_TEMPLATE.format(
        manufacturer=_sanitize_smbios_val(settings.get('manufacturer', 'Proxmox')),
        product=_sanitize_smbios_val(settings.get('product', 'PegaProxManagment')),
        version=_sanitize_smbios_val(settings.get('version', 'v1')),
        family=_sanitize_smbios_val(settings.get('family', 'ProxmoxVE'))
    )

    for node in nodes:
        node_ip = node_ips.get(node, mgr.config.host)
        try:
            # NS: Staggered connections to prevent SSH server overload
            if results:  # Not the first node
                time.sleep(1.0)
            
            ssh = mgr._ssh_connect(node_ip)
            if not ssh:
                results.append({'node': node, 'success': False, 'error': 'SSH connection failed'})
                continue
            
            # Write script
            sftp = ssh.open_sftp()
            with sftp.file('/opt/pegaprox-smbios-autoconfig.py', 'w') as f:
                f.write(script)
            sftp.chmod('/opt/pegaprox-smbios-autoconfig.py', 0o755)
            
            # Write systemd service
            with sftp.file('/etc/systemd/system/pegaprox-smbios-autoconfig.service', 'w') as f:
                f.write(SMBIOS_SERVICE_TEMPLATE)
            sftp.close()
            
            # Enable and start service
            # NS: clear processed list so ALL vms get checked
            for cmd in ['rm -f /var/lib/pegaprox-smbios-processed.txt', 'systemctl daemon-reload', 'systemctl enable pegaprox-smbios-autoconfig', 'systemctl restart pegaprox-smbios-autoconfig']:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                stdout.read()
            
            ssh.close()
            results.append({'node': node, 'success': True})
            
        except Exception as e:
            results.append({'node': node, 'success': False, 'error': str(e)})
    
    success_count = sum(1 for r in results if r['success'])
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'smbios_autoconfig.deployed_all', f"SMBIOS auto-config deployed to {success_count}/{len(nodes)} nodes", cluster=mgr.config.name)
    
    return jsonify({
        'success': success_count == len(nodes),
        'message': f'Deployed to {success_count}/{len(nodes)} nodes',
        'results': results
    })


# =============================================================================
# Custom Scripts Feature
# MK: Run custom .sh/.py scripts on cluster nodes with permission control
# =============================================================================

@bp.route('/api/clusters/<cluster_id>/scripts', methods=['GET'])
@require_auth(perms=['admin.scripts'])
def get_custom_scripts(cluster_id):
    """Get all custom scripts for a cluster (excludes soft-deleted)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    try:
        db = get_db()
        # Ensure table exists with soft delete support
        db.execute('''
            CREATE TABLE IF NOT EXISTS custom_scripts (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                type TEXT DEFAULT 'bash',
                content TEXT NOT NULL,
                target_nodes TEXT DEFAULT 'all',
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                last_status TEXT,
                last_output TEXT,
                created_at TEXT,
                updated_at TEXT,
                created_by TEXT,
                deleted_at TEXT,
                deleted_by TEXT
            )
        ''')
        # Add columns if they don't exist (migration for existing tables)
        try:
            db.execute('ALTER TABLE custom_scripts ADD COLUMN deleted_at TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE custom_scripts ADD COLUMN deleted_by TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE custom_scripts ADD COLUMN created_by TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE custom_scripts ADD COLUMN last_output TEXT')
        except: pass
        
        # Only return non-deleted scripts
        scripts = db.query(
            'SELECT * FROM custom_scripts WHERE cluster_id = ? AND deleted_at IS NULL ORDER BY name',
            (cluster_id,)
        )
        return jsonify([dict(s) for s in scripts] if scripts else [])
    except Exception as e:
        logging.error(f"Error loading scripts: {e}")
        return jsonify({'error': str(e)}), 500


# Cleanup job for permanently deleting scripts after 20 days
def cleanup_deleted_scripts():
    """Permanently delete scripts that have been soft-deleted for 20+ days"""
    try:
        db = get_db()
        cutoff = (datetime.now() - timedelta(days=20)).isoformat()
        deleted = db.query(
            'SELECT id, name, cluster_id, deleted_by FROM custom_scripts WHERE deleted_at IS NOT NULL AND deleted_at < ?',
            (cutoff,)
        )
        for script in deleted:
            db.execute('DELETE FROM custom_scripts WHERE id = ?', (script['id'],))
            log_audit('system', 'script.purged', f"Permanently deleted script '{script['name']}' after 20-day retention", cluster=script['cluster_id'])
        if deleted:
            logging.info(f"Purged {len(deleted)} scripts after 20-day retention period")
    except Exception as e:
        logging.error(f"Error cleaning up deleted scripts: {e}")


def cleanup_orphaned_excluded_vms():
    """Remove excluded VM entries for VMs that no longer exist
    
    MK: This runs daily to clean up stale entries from balancing_excluded_vms
    when VMs are deleted through other means (e.g. directly in Proxmox UI)
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Get all excluded VM entries
        cursor.execute('SELECT cluster_id, vmid FROM balancing_excluded_vms')
        excluded_entries = cursor.fetchall()
        
        if not excluded_entries:
            return
        
        removed_count = 0
        
        for entry in excluded_entries:
            cluster_id = entry['cluster_id']
            vmid = entry['vmid']
            
            # Check if cluster still exists and is connected
            if cluster_id not in cluster_managers:
                # Cluster no longer exists, remove entry
                cursor.execute(
                    'DELETE FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                    (cluster_id, vmid)
                )
                removed_count += 1
                continue
            
            mgr = cluster_managers[cluster_id]
            if not mgr.is_connected:
                continue  # Skip if we can't verify
            
            # Check if VM still exists
            try:
                vms = mgr.get_vm_resources()
                vm_exists = any(vm.get('vmid') == vmid for vm in vms)
                
                if not vm_exists:
                    cursor.execute(
                        'DELETE FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                        (cluster_id, vmid)
                    )
                    removed_count += 1
                    logging.info(f"Removed orphaned excluded VM entry: cluster={cluster_id}, vmid={vmid}")
            except Exception as e:
                logging.debug(f"Could not verify VM {vmid} in cluster {cluster_id}: {e}")
        
        if removed_count > 0:
            db.conn.commit()
            logging.info(f"[CLEANUP] Removed {removed_count} orphaned excluded VM entries")
            
    except Exception as e:
        logging.error(f"Error cleaning up orphaned excluded VMs: {e}")


@bp.route('/api/clusters/<cluster_id>/scripts', methods=['POST'])
@require_auth(perms=['admin.scripts'])
def create_custom_script(cluster_id):
    """Create a new custom script - requires admin.scripts permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.json or {}
    
    if not data.get('name') or not data.get('content'):
        return jsonify({'error': 'Name and content required'}), 400
    
    script_type = data.get('type', 'bash')
    if script_type not in ['bash', 'python']:
        return jsonify({'error': 'Type must be bash or python'}), 400
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    db = get_db()
    script_id = str(uuid.uuid4())[:8]
    
    db.execute('''
        INSERT INTO custom_scripts (id, cluster_id, name, description, type, content, target_nodes, enabled, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        script_id,
        cluster_id,
        data.get('name'),
        data.get('description', ''),
        script_type,
        data.get('content'),
        data.get('target_nodes', 'all'),
        1 if data.get('enabled', True) else 0,
        datetime.now().isoformat(),
        usr
    ))
    
    # Get cluster name for audit log
    cluster_name = cluster_managers.get(cluster_id, {})
    if hasattr(cluster_name, 'config'):
        cluster_name = cluster_name.config.name
    else:
        cluster_name = cluster_id
    
    log_audit(usr, 'script.created', f"Created script '{data.get('name')}' (ID: {script_id}, Type: {script_type})", cluster=cluster_name)
    
    return jsonify({'success': True, 'id': script_id})


@bp.route('/api/clusters/<cluster_id>/scripts/<script_id>', methods=['PUT'])
@require_auth(perms=['admin.scripts'])
def update_custom_script(cluster_id, script_id):
    """Update a custom script - requires admin.scripts permission"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    data = request.json or {}
    db = get_db()
    
    # Check script exists and not deleted
    script = db.query_one('SELECT * FROM custom_scripts WHERE id = ? AND cluster_id = ? AND deleted_at IS NULL', (script_id, cluster_id))
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    db.execute('''
        UPDATE custom_scripts SET
            name = ?,
            description = ?,
            type = ?,
            content = ?,
            target_nodes = ?,
            enabled = ?,
            updated_at = ?
        WHERE id = ? AND cluster_id = ?
    ''', (
        data.get('name', script['name']),
        data.get('description', script['description']),
        data.get('type', script['type']),
        data.get('content', script['content']),
        data.get('target_nodes', script['target_nodes']),
        1 if data.get('enabled', script['enabled']) else 0,
        datetime.now().isoformat(),
        script_id,
        cluster_id
    ))
    
    # Get cluster name for audit log
    cluster_name = cluster_managers.get(cluster_id, {})
    if hasattr(cluster_name, 'config'):
        cluster_name = cluster_name.config.name
    else:
        cluster_name = cluster_id
    
    log_audit(usr, 'script.updated', f"Updated script '{data.get('name', script['name'])}' (ID: {script_id})", cluster=cluster_name)
    
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/scripts/<script_id>', methods=['DELETE'])
@require_auth(perms=['admin.scripts'])
def delete_custom_script(cluster_id, script_id):
    """Soft-delete a custom script - will be permanently deleted after 20 days"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    db = get_db()
    
    # Check script exists
    script = db.query_one('SELECT * FROM custom_scripts WHERE id = ? AND cluster_id = ? AND deleted_at IS NULL', (script_id, cluster_id))
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    # Soft delete - mark as deleted but keep for 20 days
    db.execute('''
        UPDATE custom_scripts SET deleted_at = ?, deleted_by = ? WHERE id = ? AND cluster_id = ?
    ''', (datetime.now().isoformat(), usr, script_id, cluster_id))
    
    # Get cluster name for audit log
    cluster_name = cluster_managers.get(cluster_id, {})
    if hasattr(cluster_name, 'config'):
        cluster_name = cluster_name.config.name
    else:
        cluster_name = cluster_id
    
    log_audit(usr, 'script.deleted', f"Soft-deleted script '{script['name']}' (ID: {script_id}) - will be purged in 20 days", cluster=cluster_name)
    
    return jsonify({'success': True, 'message': 'Script marked for deletion. Will be permanently removed in 20 days.'})


@bp.route('/api/clusters/<cluster_id>/scripts/<script_id>/run', methods=['POST'])
@require_auth(perms=['admin.scripts'])
def run_custom_script(cluster_id, script_id):
    """Run a custom script on target nodes - REQUIRES PASSWORD CONFIRMATION
    
    This is a sensitive operation that executes arbitrary code on nodes.
    Password confirmation is required to prevent accidental or unauthorized execution.
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # SECURITY: Require password confirmation before running any script
    data = request.json or {}
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'Password confirmation required to run scripts'}), 401
    
    # Verify password against current user
    usr = getattr(request, 'session', {}).get('user', 'system')
    users = load_users()
    user_data = users.get(usr)
    
    if not user_data:
        return jsonify({'error': 'User not found'}), 401
    
    # Check password
    stored_salt = user_data.get('password_salt', '')
    stored_hash = user_data.get('password_hash', '')
    if not stored_salt or not stored_hash or not verify_password(password, stored_salt, stored_hash):
        cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
        log_audit(usr, 'script.run_denied', f"Failed password verification for script execution (ID: {script_id})", cluster=cluster_name)
        return jsonify({'error': 'Invalid password'}), 401
    
    db = get_db()
    script = db.query_one('SELECT * FROM custom_scripts WHERE id = ? AND cluster_id = ? AND deleted_at IS NULL', (script_id, cluster_id))
    
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    
    if not script['enabled']:
        return jsonify({'error': 'Script is disabled'}), 400
    
    mgr = cluster_managers[cluster_id]
    
    # Get cluster name for audit log
    cluster_name = mgr.config.name if hasattr(mgr, 'config') else cluster_id
    
    # Get target nodes
    target_nodes = script['target_nodes']
    nodes_to_run = []
    node_ips = {}
    
    try:
        cluster_host = mgr.current_host or mgr.config.host
        status_url = f"https://{cluster_host}:8006/api2/json/cluster/status"
        r = mgr._create_session().get(status_url, timeout=10)
        if r.status_code == 200:
            for item in r.json().get('data', []):
                if item.get('type') == 'node':
                    node_name = item.get('name')
                    if target_nodes == 'all' or node_name in target_nodes.split(','):
                        nodes_to_run.append(node_name)
                        node_ips[node_name] = item.get('ip') or cluster_host
    except Exception as e:
        logging.error(f"Error getting cluster nodes: {e}")
        return jsonify({'error': f'Could not get cluster nodes: {e}'}), 500
    
    if not nodes_to_run:
        return jsonify({'error': 'No target nodes found'}), 404
    
    # Log the execution attempt BEFORE running
    log_audit(usr, 'script.execution_started', f"Starting execution of script '{script['name']}' (ID: {script_id}) on {len(nodes_to_run)} nodes: {', '.join(nodes_to_run)}", cluster=cluster_name)
    
    results = []
    script_ext = '.py' if script['type'] == 'python' else '.sh'
    interpreter = 'python3' if script['type'] == 'python' else 'bash'
    all_output = []
    
    for node in nodes_to_run:
        node_ip = node_ips.get(node, mgr.config.host)
        try:
            ssh = mgr._ssh_connect(node_ip)
            if not ssh:
                results.append({'node': node, 'success': False, 'error': 'SSH connection failed', 'output': ''})
                all_output.append(f"=== {node} ===\nSSH connection failed\n")
                continue
            
            # Upload script to temp location
            script_path = f'/tmp/pegaprox_script_{script_id}{script_ext}'
            sftp = ssh.open_sftp()
            with sftp.file(script_path, 'w') as f:
                f.write(script['content'])
            sftp.chmod(script_path, 0o755)
            sftp.close()
            
            # Run script with timeout
            stdin, stdout, stderr = ssh.exec_command(f'{interpreter} {script_path} 2>&1', timeout=300)
            output = stdout.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            # Clean up
            ssh.exec_command(f'rm -f {script_path}')
            ssh.close()
            
            all_output.append(f"=== {node} (exit: {exit_code}) ===\n{output}\n")
            
            results.append({
                'node': node,
                'success': exit_code == 0,
                'exit_code': exit_code,
                'output': output[:10000] if output else ''  # Limit output size
            })
            
        except Exception as e:
            error_msg = str(e)
            results.append({'node': node, 'success': False, 'error': error_msg, 'output': ''})
            all_output.append(f"=== {node} ===\nError: {error_msg}\n")
    
    # Update last run info with output
    success_count = sum(1 for r in results if r['success'])
    status = 'success' if success_count == len(nodes_to_run) else ('partial' if success_count > 0 else 'failed')
    combined_output = '\n'.join(all_output)[:50000]  # Limit stored output
    
    db.execute('''
        UPDATE custom_scripts SET last_run = ?, last_status = ?, last_output = ? WHERE id = ?
    ''', (datetime.now().isoformat(), status, combined_output, script_id))
    
    # Detailed audit log of execution result
    log_audit(usr, 'script.executed', f"Script '{script['name']}' completed: {success_count}/{len(nodes_to_run)} nodes succeeded ({status})", cluster=cluster_name)
    
    return jsonify({
        'success': success_count == len(nodes_to_run),
        'message': f'Ran on {success_count}/{len(nodes_to_run)} nodes',
        'status': status,
        'results': results
    })


@bp.route('/api/clusters/<cluster_id>/scripts/<script_id>/output', methods=['GET'])
@require_auth(perms=['admin.scripts'])
def get_script_output(cluster_id, script_id):
    """Get the last execution output of a script"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    db = get_db()
    script = db.query_one('SELECT name, last_run, last_status, last_output FROM custom_scripts WHERE id = ? AND cluster_id = ? AND deleted_at IS NULL', (script_id, cluster_id))
    
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    
    return jsonify({
        'name': script['name'],
        'last_run': script['last_run'],
        'last_status': script['last_status'],
        'output': script['last_output'] or 'No output available'
    })


@bp.route('/api/clusters/<cluster_id>/scripts/deleted', methods=['GET'])
@require_auth(perms=['admin.scripts'])
def get_deleted_scripts(cluster_id):
    """Get list of soft-deleted scripts (pending permanent deletion)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    try:
        db = get_db()
        scripts = db.query(
            '''SELECT id, name, description, type, deleted_at, deleted_by, 
               datetime(deleted_at, '+20 days') as purge_date
               FROM custom_scripts 
               WHERE cluster_id = ? AND deleted_at IS NOT NULL 
               ORDER BY deleted_at DESC''',
            (cluster_id,)
        )
        return jsonify([dict(s) for s in scripts] if scripts else [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/scripts/<script_id>/restore', methods=['POST'])
@require_auth(perms=['admin.scripts'])
def restore_deleted_script(cluster_id, script_id):
    """Restore a soft-deleted script before it's permanently purged"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    db = get_db()
    script = db.query_one('SELECT * FROM custom_scripts WHERE id = ? AND cluster_id = ? AND deleted_at IS NOT NULL', (script_id, cluster_id))
    
    if not script:
        return jsonify({'error': 'Deleted script not found'}), 404
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    db.execute('''
        UPDATE custom_scripts SET deleted_at = NULL, deleted_by = NULL WHERE id = ? AND cluster_id = ?
    ''', (script_id, cluster_id))
    
    # Get cluster name for audit log
    cluster_name = cluster_managers.get(cluster_id, {})
    if hasattr(cluster_name, 'config'):
        cluster_name = cluster_name.config.name
    else:
        cluster_name = cluster_id
    
    log_audit(usr, 'script.restored', f"Restored deleted script '{script['name']}' (ID: {script_id})", cluster=cluster_name)
    
    return jsonify({'success': True, 'message': f"Script '{script['name']}' restored"})



