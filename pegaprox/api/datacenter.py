# -*- coding: utf-8 -*-
"""datacenter routes (SDN, firewall, multipath, disks) - split from monolith dec 2025, NS"""

import json
import logging
import base64
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import get_connected_manager, check_cluster_access

bp = Blueprint('datacenter', __name__)

# ============================================
# NS: Multipath Easy Setup - Feb 2026
# Redundant SAN/iSCSI with multipath
# ============================================

def _get_node_multipath_data(manager, node):
    """Internal helper: Get multipath status for a node. Returns raw dict, never Flask Response.

    NS: Feb 2026 - Uses paramiko via manager._ssh_connect() for reliable SSH auth.
    Subprocess+sshpass fails when KbdInteractiveAuthentication is disabled (Proxmox default).
    """
    result = {
        'installed': False,
        'running': False,
        'devices': [],
        'paths_total': 0,
        'paths_active': 0,
        'paths_failed': 0,
        'config_exists': False
    }

    ssh = None
    try:
        # Resolve node IP from Proxmox API (node name might not be in DNS)
        node_ip = manager._get_node_ip(node) or node
        logging.debug(f"[Multipath] Resolved {node} → {node_ip}")

        # Connect via paramiko (handles SSH key + password auth correctly)
        ssh = manager._ssh_connect(node_ip, retries=2, retry_delay=1.0)
        if not ssh:
            result['error'] = f'SSH connection failed to {node} ({node_ip}). Check credentials.'
            return result

        # Helper: run command on existing SSH connection
        def ssh_run(command, timeout=15):
            try:
                stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
                return stdout.read().decode('utf-8', errors='replace')
            except Exception as e:
                logging.debug(f"[Multipath] exec failed on {node}: {e}")
                return None

        # Check if multipathd is installed and running
        check_output = ssh_run('command -v multipathd && systemctl is-active multipathd 2>/dev/null || echo inactive')

        if check_output is None:
            result['error'] = f'SSH command failed on {node} ({node_ip}).'
            return result

        if '/multipathd' in check_output:
            result['installed'] = True
        if 'active' in check_output and 'inactive' not in check_output:
            result['running'] = True

        # Check if multipath.conf exists
        conf_output = ssh_run('test -f /etc/multipath.conf && echo exists || echo missing')
        result['config_exists'] = conf_output and 'exists' in conf_output

        if not result['running']:
            return result

        # Get multipath topology with detailed path info
        topo_output = ssh_run('multipathd show maps raw format "%n %w %d %N" 2>/dev/null')

        devices = []
        if topo_output:
            for line in topo_output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    dev_name = parts[0]
                    wwid = parts[1]
                    dm_dev = parts[2]
                    nr_active = int(parts[3]) if parts[3].isdigit() else 0

                    # Get paths for this device
                    paths_output = ssh_run(f'multipathd show paths raw format "%m %d %t %T %s" 2>/dev/null | grep "^{dev_name}"')

                    paths = []
                    if paths_output:
                        for path_line in paths_output.strip().split('\n'):
                            if not path_line.strip():
                                continue
                            path_parts = path_line.split()
                            if len(path_parts) >= 5:
                                paths.append({
                                    'device': path_parts[1],
                                    'dm_state': path_parts[2],
                                    'path_state': path_parts[3],
                                    'host': path_parts[4] if len(path_parts) > 4 else ''
                                })

                                if path_parts[2] == 'active':
                                    result['paths_active'] += 1
                                elif path_parts[2] == 'failed':
                                    result['paths_failed'] += 1
                                result['paths_total'] += 1

                    # Get size of the multipath device
                    size_output = ssh_run(f'lsblk -b -n -o SIZE /dev/mapper/{dev_name} 2>/dev/null | head -1')
                    size_bytes = 0
                    if size_output and size_output.strip().isdigit():
                        size_bytes = int(size_output.strip())

                    devices.append({
                        'name': dev_name,
                        'wwid': wwid,
                        'dm_device': dm_dev,
                        'active_paths': nr_active,
                        'total_paths': len(paths),
                        'paths': paths,
                        'size_bytes': size_bytes,
                        'size_gb': round(size_bytes / (1024**3), 2) if size_bytes else 0,
                        'status': 'healthy' if nr_active >= 2 else ('degraded' if nr_active == 1 else 'failed')
                    })

        result['devices'] = devices

    except Exception as e:
        logging.error(f"Error getting multipath status for {node}: {e}")
        result['error'] = str(e)
    finally:
        if ssh:
            try:
                ssh.close()
            except:
                pass

    return result


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/multipath', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_multipath_status(cluster_id, node):
    """Get multipath status for a node - all devices, paths, and their states"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    result = _get_node_multipath_data(manager, node)
    
    if 'error' in result and result['error']:
        return jsonify(result), 200
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/datacenter/multipath/status', methods=['GET'])
@require_auth(perms=['node.view'])
def get_cluster_multipath_status(cluster_id):
    """Get multipath status for entire cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # Get all nodes
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nodes_resp = manager._create_session().get(nodes_url, timeout=10)
        
        if nodes_resp.status_code != 200:
            return jsonify({'error': 'Failed to get nodes'}), 500
        
        nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']
        
        cluster_status = {
            'nodes': {},
            'summary': {
                'total_nodes': len(nodes),
                'nodes_with_multipath': 0,
                'total_devices': 0,
                'healthy_devices': 0,
                'degraded_devices': 0,
                'failed_devices': 0
            }
        }
        
        # MK: Feb 2026 - Call internal helper directly instead of Flask route
        # Old code called the route function which returns Response/tuples that
        # couldn't be parsed → always showed "not installed"
        for node in nodes:
            try:
                node_data = _get_node_multipath_data(manager, node)
                cluster_status['nodes'][node] = node_data
                
                if node_data.get('running'):
                    cluster_status['summary']['nodes_with_multipath'] += 1
                
                for dev in node_data.get('devices', []):
                    cluster_status['summary']['total_devices'] += 1
                    status = dev.get('status', 'unknown')
                    if status == 'healthy':
                        cluster_status['summary']['healthy_devices'] += 1
                    elif status == 'degraded':
                        cluster_status['summary']['degraded_devices'] += 1
                    elif status == 'failed':
                        cluster_status['summary']['failed_devices'] += 1
            except Exception as e:
                cluster_status['nodes'][node] = {'error': str(e), 'installed': False, 'running': False, 'devices': []}
        
        return jsonify(cluster_status)
        
    except Exception as e:
        logging.error(f"Error getting cluster multipath status: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/multipath/setup', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def setup_multipath(cluster_id):
    """Easy Setup: Install and configure multipath on all nodes

    This will:
    1. Install multipath-tools package
    2. Generate optimized multipath.conf (unless skipExistingConfig and config exists)
    3. Enable and start multipathd service
    4. Scan for devices

    Once multipathd is running, ALL new iSCSI/FC connections will automatically
    use multipath if multiple paths are available!
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error

    data = request.json or {}
    target_nodes = data.get('nodes', [])  # Empty = all nodes
    vendor = data.get('vendor', 'default')  # default, netapp, emc, hpe, pure, dell
    policy = data.get('policy', 'service-time')  # round-robin, service-time, queue-length
    skip_existing_config = data.get('skipExistingConfig', False)  # Don't overwrite existing config

    try:
        host = manager.current_host or manager.config.host

        # Get nodes if not specified
        if not target_nodes:
            nodes_url = f"https://{host}:8006/api2/json/nodes"
            nodes_resp = manager._create_session().get(nodes_url, timeout=10)
            if nodes_resp.status_code == 200:
                target_nodes = [n['node'] for n in nodes_resp.json().get('data', []) if n.get('status') == 'online']

        # Generate multipath.conf based on vendor
        multipath_conf = generate_multipath_conf(vendor, policy)

        results = []

        for node in target_nodes:
            node_result = {'node': node, 'steps': [], 'success': True, 'skipped_config': False}
            ssh = None

            # Resolve node IP
            node_ip = manager._get_node_ip(node) or node

            try:
                # Connect via paramiko (handles SSH key + password auth correctly)
                ssh = manager._ssh_connect(node_ip, retries=2, retry_delay=1.0)
                if not ssh:
                    node_result['success'] = False
                    node_result['error'] = f'SSH connection failed to {node} ({node_ip}). Check credentials.'
                    results.append(node_result)
                    continue

                def _exec(cmd, timeout=30):
                    """Run command, return (rc, stdout, stderr)"""
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
                    out = stdout.read().decode('utf-8', errors='replace')
                    err = stderr.read().decode('utf-8', errors='replace')
                    rc = stdout.channel.recv_exit_status()
                    return rc, out, err

                # Step 1: Check if already installed
                rc, out, _ = _exec('dpkg -l | grep -q multipath-tools && echo installed || echo not_installed')
                already_installed = 'installed' in out and 'not_installed' not in out

                # Step 2: Install multipath-tools (if not installed)
                if not already_installed:
                    rc, out, err = _exec('DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y multipath-tools 2>&1', timeout=120)
                    node_result['steps'].append({
                        'action': 'install',
                        'success': rc == 0,
                        'output': (out or err)[-500:]
                    })
                else:
                    node_result['steps'].append({
                        'action': 'install',
                        'success': True,
                        'output': 'Already installed'
                    })

                # Step 3: Check if config exists
                rc, out, _ = _exec('test -f /etc/multipath.conf && cat /etc/multipath.conf | head -5 || echo NO_CONFIG')
                config_exists = 'NO_CONFIG' not in out

                # Step 4: Handle config
                if config_exists and skip_existing_config:
                    node_result['skipped_config'] = True
                    node_result['steps'].append({
                        'action': 'config',
                        'success': True,
                        'output': 'Existing config preserved'
                    })
                else:
                    if config_exists:
                        _exec('cp /etc/multipath.conf /etc/multipath.conf.bak.$(date +%Y%m%d%H%M%S)')

                    # Write new multipath.conf via base64 for safe transfer
                    conf_b64 = base64.b64encode(multipath_conf.encode()).decode()
                    rc, out, err = _exec(f'echo {conf_b64} | base64 -d > /etc/multipath.conf')
                    node_result['steps'].append({
                        'action': 'config',
                        'success': rc == 0,
                        'output': 'Config written' if rc == 0 else err[:200]
                    })

                # Step 5: Enable and restart multipathd
                rc, out, err = _exec('systemctl enable multipathd && systemctl restart multipathd && sleep 2 && systemctl is-active multipathd')
                node_result['steps'].append({
                    'action': 'service',
                    'success': 'active' in out,
                    'status': out.strip()
                })

                # Step 6: Scan for devices
                rc, out, _ = _exec('multipathd reconfigure && sleep 1 && multipath -ll 2>/dev/null | head -20 || echo "No multipath devices found"')
                node_result['steps'].append({
                    'action': 'scan',
                    'success': rc == 0,
                    'devices': out[:1000]
                })

                # Check if critical steps succeeded (install and service)
                critical_steps = [s for s in node_result['steps'] if s['action'] in ['install', 'service']]
                node_result['success'] = all(s.get('success', False) for s in critical_steps)

            except Exception as e:
                node_result['success'] = False
                node_result['error'] = str(e)
            finally:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass

            results.append(node_result)

        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        success_count = sum(1 for r in results if r['success'])
        skipped_count = sum(1 for r in results if r.get('skipped_config'))
        log_audit(user, 'multipath.setup', f"Multipath Easy Setup on {success_count}/{len(results)} nodes (vendor={vendor}, policy={policy}, configs_skipped={skipped_count})", cluster=manager.config.name)

        return jsonify({
            'success': all(r['success'] for r in results),
            'results': results,
            'config_used': multipath_conf if not skip_existing_config else None,
            'message': 'Multipath is now active. All new iSCSI/FC LUNs will automatically use redundant paths!'
        })

    except Exception as e:
        logging.error(f"Error in multipath setup: {e}")
        return jsonify({'error': str(e)}), 500


def generate_multipath_conf(vendor: str, policy: str) -> str:
    """Generate optimized multipath.conf for different storage vendors"""
    
    # Common defaults section
    defaults = f'''defaults {{
    user_friendly_names yes
    find_multipaths yes
    path_grouping_policy failover
    path_selector "{policy} 0"
    failback immediate
    no_path_retry 5
    polling_interval 5
}}

blacklist {{
    devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"
    devnode "^hd[a-z]"
    devnode "^vd[a-z]"
    device {{
        vendor "VBOX"
        product "HARDDISK"
    }}
}}

blacklist_exceptions {{
    device {{
        vendor ".*"
        product ".*"
    }}
}}
'''
    
    # Vendor-specific device sections
    vendor_configs = {
        'default': '',
        
        'netapp': '''
devices {
    device {
        vendor "NETAPP"
        product "LUN.*"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        failback immediate
        no_path_retry 5
        rr_weight uniform
        rr_min_io 128
        dev_loss_tmo infinity
    }
}
''',
        
        'emc': '''
devices {
    device {
        vendor "EMC"
        product ".*"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio emc
        failback immediate
        no_path_retry 5
        hardware_handler "1 emc"
    }
    device {
        vendor "DGC"
        product ".*"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        failback immediate
        no_path_retry 5
    }
}
''',
        
        'hpe': '''
devices {
    device {
        vendor "HP"
        product ".*"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        failback immediate
        no_path_retry 5
    }
    device {
        vendor "3PARdata"
        product "VV"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        failback immediate
        no_path_retry 5
    }
}
''',
        
        'pure': '''
devices {
    device {
        vendor "PURE"
        product "FlashArray"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        failback immediate
        no_path_retry 5
        fast_io_fail_tmo 10
        dev_loss_tmo 60
    }
}
''',
        
        'dell': '''
devices {
    device {
        vendor "DELL"
        product ".*"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        failback immediate
        no_path_retry 5
    }
    device {
        vendor "COMPELNT"
        product "Compellent Vol"
        path_grouping_policy multibus
        path_selector "service-time 0"
        failback immediate
        no_path_retry 5
    }
}
'''
    }
    
    device_config = vendor_configs.get(vendor, vendor_configs['default'])
    
    return f'''# Multipath configuration - Generated by PegaProx
# Vendor: {vendor}
# Policy: {policy}
# Generated: {datetime.now().isoformat()}

{defaults}
{device_config}'''


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/multipath/reconfigure', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def reconfigure_multipath(cluster_id, node):
    """Reconfigure multipath on a specific node (rescan devices)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    ssh = None
    try:
        # Resolve node IP
        node_ip = manager._get_node_ip(node) or node

        # Connect via paramiko
        ssh = manager._ssh_connect(node_ip, retries=2, retry_delay=1.0)
        if not ssh:
            return jsonify({'error': f'SSH connection failed to {node} ({node_ip}). Check credentials.'}), 500

        # Reconfigure multipath
        stdin, stdout, stderr = ssh.exec_command('multipathd reconfigure && sleep 2 && multipath -ll', timeout=60)
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        rc = stdout.channel.recv_exit_status()

        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'multipath.reconfigure', f"Reconfigured multipath on {node}", cluster=manager.config.name)

        return jsonify({
            'success': rc == 0,
            'output': out,
            'error': err if rc != 0 else None
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if ssh:
            try:
                ssh.close()
            except:
                pass


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/iscsi/discover', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def discover_iscsi_targets(cluster_id, node):
    """Discover iSCSI targets on a portal - for Easy Setup"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    portal = data.get('portal', '')  # IP:port or just IP
    
    if not portal:
        return jsonify({'error': 'Portal address required'}), 400
    
    # Add default port if not specified
    if ':' not in portal:
        portal = f"{portal}:3260"
    
    try:
        host = manager.current_host or manager.config.host
        
        # Use Proxmox API to scan iSCSI targets
        scan_url = f"https://{host}:8006/api2/json/nodes/{node}/scan/iscsi"
        response = manager._create_session().get(scan_url, params={'portal': portal}, timeout=30)
        
        if response.status_code == 200:
            targets = response.json().get('data', [])
            return jsonify({
                'portal': portal,
                'targets': targets
            })
        else:
            return jsonify({'error': response.text}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/iscsi/login', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def login_iscsi_target(cluster_id, node):
    """Login to an iSCSI target - creates persistent connection"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    portal = data.get('portal', '')
    target = data.get('target', '')
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not portal or not target:
        return jsonify({'error': 'Portal and target required'}), 400
    
    ssh = None
    try:
        # Resolve node IP
        node_ip = manager._get_node_ip(node) or node

        # Connect via paramiko
        ssh = manager._ssh_connect(node_ip, retries=2, retry_delay=1.0)
        if not ssh:
            return jsonify({'error': f'SSH connection failed to {node} ({node_ip}). Check credentials.'}), 400

        def _exec(cmd, timeout=30):
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            rc = stdout.channel.recv_exit_status()
            return rc, out, err

        # If CHAP credentials provided, set them first
        if username and password:
            _exec(f'''iscsiadm -m node -T {target} -p {portal} --op update -n node.session.auth.authmethod -v CHAP && \
                iscsiadm -m node -T {target} -p {portal} --op update -n node.session.auth.username -v {username} && \
                iscsiadm -m node -T {target} -p {portal} --op update -n node.session.auth.password -v {password}''')

        # Discovery
        _exec(f'iscsiadm -m discovery -t sendtargets -p {portal}')

        # Login
        login_rc, login_out, login_err = _exec(f'iscsiadm -m node -T {target} -p {portal} --login')

        # Make persistent
        _exec(f'iscsiadm -m node -T {target} -p {portal} --op update -n node.startup -v automatic')

        # Trigger multipath rescan
        _exec('multipathd reconfigure 2>/dev/null || true')

        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'iscsi.login', f"Logged into iSCSI target {target} on {node}", cluster=manager.config.name)

        return jsonify({
            'success': login_rc == 0,
            'output': login_out,
            'error': login_err if login_rc != 0 else None
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if ssh:
            try:
                ssh.close()
            except:
                pass


# ============================================
# LW: SDN (Software Defined Networking) - Feb 2026
# View and manage SDN zones, vnets, subnets
# GitHub Issue #38 - requested by multiple users
# MK: Proxmox SDN API is a bit inconsistent, some endpoints return
# different formats depending on PVE version. We normalize everything here.
# ============================================

@bp.route('/api/clusters/<cluster_id>/datacenter/sdn', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_overview(cluster_id):
    """Get complete SDN overview including zones, vnets, subnets, controllers, IPAM, DNS"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()
        
        result = {
            'available': False,
            'zones': [],
            'vnets': [],
            'subnets': [],
            'controllers': [],
            'ipams': [],
            'dns': [],
            'pending': False,
            'digest': None,
            'debug': {}  # Debug info for troubleshooting
        }
        
        # Check if SDN is available
        sdn_url = f"https://{host}:8006/api2/json/cluster/sdn"
        try:
            sdn_resp = session.get(sdn_url, timeout=10)
            result['debug']['sdn_status'] = sdn_resp.status_code
            logging.info(f"SDN API response: status={sdn_resp.status_code}")
            
            if sdn_resp.status_code == 501:
                # SDN not installed/configured - this is normal for clusters without SDN
                logging.info("SDN not available (501 - not installed)")
                return jsonify(result)
            
            if sdn_resp.status_code == 200:
                result['available'] = True
                sdn_data = sdn_resp.json().get('data', {})
                result['digest'] = sdn_data.get('digest')
                logging.info(f"SDN available, digest={result['digest']}")
            elif sdn_resp.status_code == 403:
                # Permission denied - SDN exists but user can't access
                logging.warning("SDN permission denied (403)")
                result['available'] = True  # Mark as available, permissions issue
                result['error'] = 'Permission denied - check SDN.Audit permission'
            else:
                # Other error - try to continue anyway
                logging.warning(f"SDN API returned {sdn_resp.status_code}: {sdn_resp.text[:200]}")
                # Still try to get zones/vnets - they might work
                result['available'] = True
        except Exception as e:
            logging.error(f"SDN availability check failed: {e}")
            # Try to continue - maybe zones endpoint works
            result['available'] = True
        
        # Get zones
        zones_url = f"https://{host}:8006/api2/json/cluster/sdn/zones"
        try:
            zones_resp = session.get(zones_url, timeout=10)
            result['debug']['zones_status'] = zones_resp.status_code
            logging.info(f"SDN zones response: status={zones_resp.status_code}")
            if zones_resp.status_code == 200:
                result['zones'] = zones_resp.json().get('data', [])
                result['available'] = True  # If zones works, SDN is available
                logging.info(f"Found {len(result['zones'])} SDN zones")
            elif zones_resp.status_code == 501:
                # Definitely no SDN
                result['available'] = False
                result['debug']['error'] = 'SDN not installed (501 from zones endpoint)'
                logging.info("SDN zones returned 501 - SDN not installed")
                return jsonify(result)
            else:
                result['debug']['zones_error'] = zones_resp.text[:200] if zones_resp.text else 'No response body'
        except Exception as e:
            logging.error(f"SDN zones fetch failed: {e}")
            result['debug']['zones_exception'] = str(e)
        
        # Get vnets
        vnets_url = f"https://{host}:8006/api2/json/cluster/sdn/vnets"
        vnets_resp = session.get(vnets_url, timeout=10)
        if vnets_resp.status_code == 200:
            result['vnets'] = vnets_resp.json().get('data', [])
        
        # Get subnets for each vnet
        subnets = []
        for vnet in result['vnets']:
            vnet_name = vnet.get('vnet', '')
            if vnet_name:
                subnets_url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_name}/subnets"
                subnets_resp = session.get(subnets_url, timeout=10)
                if subnets_resp.status_code == 200:
                    for subnet in subnets_resp.json().get('data', []):
                        subnet['vnet'] = vnet_name
                        subnets.append(subnet)
        result['subnets'] = subnets
        
        # Get controllers
        try:
            ctrl_url = f"https://{host}:8006/api2/json/cluster/sdn/controllers"
            ctrl_resp = session.get(ctrl_url, timeout=10)
            if ctrl_resp.status_code == 200:
                result['controllers'] = ctrl_resp.json().get('data', [])
        except:
            pass
        
        # Get IPAM configurations
        try:
            ipam_url = f"https://{host}:8006/api2/json/cluster/sdn/ipams"
            ipam_resp = session.get(ipam_url, timeout=10)
            if ipam_resp.status_code == 200:
                result['ipams'] = ipam_resp.json().get('data', [])
        except:
            pass
        
        # Get DNS configurations
        try:
            dns_url = f"https://{host}:8006/api2/json/cluster/sdn/dns"
            dns_resp = session.get(dns_url, timeout=10)
            if dns_resp.status_code == 200:
                result['dns'] = dns_resp.json().get('data', [])
        except:
            pass
        
        # Check for pending changes
        try:
            pending_url = f"https://{host}:8006/api2/json/cluster/sdn"
            pending_resp = session.get(pending_url, timeout=10)
            if pending_resp.status_code == 200:
                # If there are pending changes, the running config differs from pending
                pending_data = pending_resp.json().get('data', {})
                result['pending'] = bool(pending_data.get('pending'))
        except:
            pass
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error getting SDN overview: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/zones', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_zones(cluster_id):
    """Get SDN zones"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # MK: 501 means SDN not enabled on this cluster - return empty list instead of error
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/zones"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        elif response.status_code == 501:
            return jsonify([])
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/zones', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_sdn_zone(cluster_id):
    # NS: Zone types: simple, vlan, qinq, vxlan, evpn - each has different required params
    """Create a new SDN zone"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/zones"
        response = manager._create_session().post(url, data=data, timeout=10)
        
        if response.status_code in [200, 201]:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.zone_created', f"Created SDN zone: {data.get('zone', 'unknown')}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Zone created'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/zones/<zone_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_sdn_zone(cluster_id, zone_id):
    """Update an SDN zone"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/zones/{zone_id}"
        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.zone_updated', f"Updated SDN zone: {zone_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Zone updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/zones/<zone_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_sdn_zone(cluster_id, zone_id):
    """Delete an SDN zone"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/zones/{zone_id}"
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.zone_deleted', f"Deleted SDN zone: {zone_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Zone deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_vnets(cluster_id):
    """Get SDN VNets"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # LW: VNets are the main abstraction layer - each vnet belongs to exactly one zone
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        elif response.status_code == 501:
            return jsonify([])
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_sdn_vnet(cluster_id):
    """Create a new SDN VNet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets"
        response = manager._create_session().post(url, data=data, timeout=10)
        
        if response.status_code in [200, 201]:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.vnet_created', f"Created SDN VNet: {data.get('vnet', 'unknown')}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'VNet created'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_sdn_vnet(cluster_id, vnet_id):
    """Update an SDN VNet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}"
        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.vnet_updated', f"Updated SDN VNet: {vnet_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'VNet updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_sdn_vnet(cluster_id, vnet_id):
    """Delete an SDN VNet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}"
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.vnet_deleted', f"Deleted SDN VNet: {vnet_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'VNet deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>/subnets', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_subnets(cluster_id, vnet_id):
    # MK: Subnets are nested under vnets in the API but stored flat in PVE config
    """Get subnets for a VNet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}/subnets"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        elif response.status_code == 501:
            return jsonify([])
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>/subnets', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_sdn_subnet(cluster_id, vnet_id):
    """Create a subnet in a VNet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}/subnets"
        response = manager._create_session().post(url, data=data, timeout=10)
        
        if response.status_code in [200, 201]:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.subnet_created', f"Created subnet in VNet {vnet_id}: {data.get('subnet', 'unknown')}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Subnet created'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>/subnets/<subnet_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_sdn_subnet(cluster_id, vnet_id, subnet_id):
    """Delete a subnet from a VNet"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        # Subnet ID needs URL encoding as it contains CIDR notation
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}/subnets/{subnet_id}"
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.subnet_deleted', f"Deleted subnet {subnet_id} from VNet {vnet_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Subnet deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/apply', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def apply_sdn_config(cluster_id):
    """Apply pending SDN configuration changes to all nodes"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        url = f"https://{host}:8006/api2/json/cluster/sdn"
        response = manager._create_session().put(url, timeout=30)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.config_applied', "Applied SDN configuration to cluster", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'SDN configuration applied'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# SDN Controllers (BGP, EVPN, ISIS)
# ============================================

@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/controllers', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_controllers(cluster_id):
    # LW: Controllers are optional - only needed for EVPN/BGP setups
    """Get SDN controllers"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/controllers"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        elif response.status_code == 501:
            return jsonify([])
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/controllers', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_sdn_controller(cluster_id):
    """Create a new SDN controller (BGP, EVPN, ISIS)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/controllers"
        response = manager._create_session().post(url, data=data, timeout=10)
        
        if response.status_code in [200, 201]:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.controller_created', f"Created SDN controller: {data.get('controller', 'unknown')} ({data.get('type', '')})", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Controller created'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/controllers/<controller_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_sdn_controller(cluster_id, controller_id):
    """Update an SDN controller"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/controllers/{controller_id}"
        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.controller_updated', f"Updated SDN controller: {controller_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Controller updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/controllers/<controller_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_sdn_controller(cluster_id, controller_id):
    """Delete an SDN controller"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/controllers/{controller_id}"
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.controller_deleted', f"Deleted SDN controller: {controller_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Controller deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# SDN IPAM (IP Address Management)
# ============================================

@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/ipams', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_ipams(cluster_id):
    # NS: IPAM = IP Address Management, default is pve-internal but can use phpIPAM or Netbox
    """Get SDN IPAM configurations"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/ipams"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        elif response.status_code == 501:
            return jsonify([])
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/ipams', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_sdn_ipam(cluster_id):
    """Create a new IPAM configuration (pve, netbox, phpipam)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/ipams"
        response = manager._create_session().post(url, data=data, timeout=10)
        
        if response.status_code in [200, 201]:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.ipam_created', f"Created IPAM: {data.get('ipam', 'unknown')} ({data.get('type', '')})", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'IPAM created'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/ipams/<ipam_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_sdn_ipam(cluster_id, ipam_id):
    """Update an IPAM configuration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/ipams/{ipam_id}"
        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.ipam_updated', f"Updated IPAM: {ipam_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'IPAM updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/ipams/<ipam_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_sdn_ipam(cluster_id, ipam_id):
    """Delete an IPAM configuration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/ipams/{ipam_id}"
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.ipam_deleted', f"Deleted IPAM: {ipam_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'IPAM deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# SDN DNS
# ============================================

@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/dns', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_dns(cluster_id):
    # MK: DNS integration for auto-registration of VMs in zones
    """Get SDN DNS configurations"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/dns"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        elif response.status_code == 501:
            return jsonify([])
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/dns', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_sdn_dns(cluster_id):
    """Create a new DNS configuration (powerdns)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/dns"
        response = manager._create_session().post(url, data=data, timeout=10)
        
        if response.status_code in [200, 201]:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.dns_created', f"Created DNS: {data.get('dns', 'unknown')}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'DNS created'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/dns/<dns_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_sdn_dns(cluster_id, dns_id):
    """Update a DNS configuration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/dns/{dns_id}"
        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.dns_updated', f"Updated DNS: {dns_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'DNS updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/dns/<dns_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_sdn_dns(cluster_id, dns_id):
    """Delete a DNS configuration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/dns/{dns_id}"
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.dns_deleted', f"Deleted DNS: {dns_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'DNS deleted'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# SDN Zone Details (for editing all options)
# ============================================

@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/zones/<zone_id>', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_zone_details(cluster_id, zone_id):
    """Get detailed zone configuration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/zones/{zone_id}"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', {}))
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>', methods=['GET'])
@require_auth(perms=['node.view'])
def get_sdn_vnet_details(cluster_id, vnet_id):
    """Get detailed VNet configuration"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}"
        response = manager._create_session().get(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', {}))
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/sdn/vnets/<vnet_id>/subnets/<path:subnet_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_sdn_subnet(cluster_id, vnet_id, subnet_id):
    """Update a subnet (DHCP range, gateway, etc.)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host = manager.current_host or manager.config.host
        data = request.json or {}
        
        # URL encode the subnet ID (contains /)
        from urllib.parse import quote
        encoded_subnet = quote(subnet_id, safe='')
        
        url = f"https://{host}:8006/api2/json/cluster/sdn/vnets/{vnet_id}/subnets/{encoded_subnet}"
        response = manager._create_session().put(url, data=data, timeout=10)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'sdn.subnet_updated', f"Updated subnet {subnet_id} in VNet {vnet_id}", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Subnet updated'})
        return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_disks_api(cluster_id, node):
    """Get physical disks on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    disks = manager.get_node_disks(node)
    return jsonify(disks)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/<path:disk>/smart', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_disk_smart_api(cluster_id, node, disk):
    """Get SMART data for a disk"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    # Decode disk path (e.g., /dev/sda -> %2Fdev%2Fsda)
    smart_data = manager.get_node_disk_smart(node, '/' + disk if not disk.startswith('/') else disk)
    return jsonify(smart_data)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/lvm', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_lvm_api(cluster_id, node):
    """Get LVM volume groups on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_lvm(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/lvm', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_node_lvm_api(cluster_id, node):
    """Create LVM volume group"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    device = data.get('device')
    name = data.get('name')
    add_storage = data.get('add_storage', True)
    
    if not device or not name:
        return jsonify({'error': 'Device and name required'}), 400
    
    result = manager.create_node_lvm(node, device, name, add_storage)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/lvmthin', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_lvmthin_api(cluster_id, node):
    """Get LVM-Thin pools on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_lvmthin(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/lvmthin', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_node_lvmthin_api(cluster_id, node):
    """Create LVM-Thin pool"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    device = data.get('device')
    name = data.get('name')
    add_storage = data.get('add_storage', True)
    
    if not device or not name:
        return jsonify({'error': 'Device and name required'}), 400
    
    result = manager.create_node_lvmthin(node, device, name, add_storage)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/zfs', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_zfs_api(cluster_id, node):
    """Get ZFS pools on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    return jsonify(manager.get_node_zfs(node))


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/zfs', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_node_zfs_api(cluster_id, node):
    """Create ZFS pool"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    name = data.get('name')
    devices = data.get('devices', [])
    raidlevel = data.get('raidlevel', 'single')
    compression = data.get('compression', 'on')
    ashift = data.get('ashift', 12)
    add_storage = data.get('add_storage', True)
    
    if not name or not devices:
        return jsonify({'error': 'Name and devices required'}), 400
    
    result = manager.create_node_zfs(node, name, devices, raidlevel, compression, ashift, add_storage)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/directory', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_node_directory_api(cluster_id, node):
    """Create directory storage"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    device = data.get('device')
    name = data.get('name')
    filesystem = data.get('filesystem', 'ext4')
    add_storage = data.get('add_storage', True)
    
    if not device or not name:
        return jsonify({'error': 'Device and name required'}), 400
    
    result = manager.create_node_directory(node, device, name, filesystem, add_storage)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/initgpt', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def init_node_disk_gpt_api(cluster_id, node):
    """Initialize disk with GPT partition table"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    disk = data.get('disk')
    uuid = data.get('uuid')
    
    if not disk:
        return jsonify({'error': 'Disk required'}), 400
    
    result = manager.init_disk_gpt(node, disk, uuid)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/disks/wipe', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def wipe_node_disk_api(cluster_id, node):
    """Wipe disk (delete partition table)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    
    disk = data.get('disk')
    
    if not disk:
        return jsonify({'error': 'Disk required'}), 400

    # NS: Feb 2026 - SECURITY: require confirmation for destructive disk wipe
    if data.get('confirm_name') != disk:
        return jsonify({'error': 'Confirmation required: send confirm_name matching the disk name'}), 400

    result = manager.wipe_disk(node, disk)
    
    if result['success']:
        return jsonify(result)
    return jsonify({'error': result['error']}), 500



