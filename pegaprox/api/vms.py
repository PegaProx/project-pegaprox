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
import shlex
import ssl
import socket
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
from pegaprox.api.helpers import get_connected_manager, check_cluster_access, register_task_user, safe_error, parse_pve_error
from pegaprox.utils.ssh import get_paramiko
from pegaprox.utils.sanitization import sanitize_int
from urllib.parse import urlencode, quote as url_quote
import signal
import requests.exceptions
from pegaprox.api.realtime import sock

bp = Blueprint('vms', __name__)


# MK Apr 2026 — VNC connection hardening helpers. We keep the proxy path through
# pegaprox (most customer browsers can't reach the PVE node directly), so the
# resilience has to come from the proxy code itself. These helpers apply OS-level
# keepalive and a shared connect timeout that's long enough for slow corporate
# inspection middleboxes (TLS DPI, Falcon-style EDR scoring) to finish their work.
VNC_PVE_CONNECT_TIMEOUT = int(os.environ.get('PEGAPROX_VNC_CONNECT_TIMEOUT', '15'))


# NS 2026-05-06: cluster-add / -join nehmen frei eingegebene node-targets
# entgegen. Semgrep flagt das als tainted-flask-input -> paramiko.connect.
# Paramiko's connect() ist zwar nicht shell-injectable, aber wir wollen auch
# nicht dass jemand der admin.cluster perm hat hier internal network scans
# triggert via 192.168.1.255 oder so. Strikte regex auf hostname/ipv4/ipv6.
_HOST_RE = re.compile(r'^(?:'
                      r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                          r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)'
                      r'|'
                      r'(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                      r'|'
                      r'(?:\[[0-9a-fA-F:]+\])'
                      r')$')


def _validate_host(value):
    """Return value if it looks like a hostname/IPv4/IPv6, else None.
    Used at the boundary where flask request input flows into paramiko.connect."""
    v = (value or '').strip()
    if not v or len(v) > 253:
        return None
    return v if _HOST_RE.match(v) else None


def _apply_vnc_socket_options(sock):
    """Apply TCP_NODELAY + aggressive TCP keepalive to a VNC-forwarding socket.

    Stateful firewalls / EDR-network-filters often drop "established" TCP sessions
    that look idle. RFB has natural quiet periods (user reading, no mouse/key
    activity). Default Linux keepalive is 2h idle which doesn't help. 15s idle +
    5s probe interval + 3 misses survives most enterprise conntrack timeouts.
    Best-effort — failures are logged debug, not raised."""
    try:
        import socket as _s
        sock.setsockopt(_s.IPPROTO_TCP, _s.TCP_NODELAY, 1)
        sock.setsockopt(_s.SOL_SOCKET, _s.SO_KEEPALIVE, 1)
        if hasattr(_s, 'TCP_KEEPIDLE'):
            sock.setsockopt(_s.IPPROTO_TCP, _s.TCP_KEEPIDLE, 15)
        if hasattr(_s, 'TCP_KEEPINTVL'):
            sock.setsockopt(_s.IPPROTO_TCP, _s.TCP_KEEPINTVL, 5)
        if hasattr(_s, 'TCP_KEEPCNT'):
            sock.setsockopt(_s.IPPROTO_TCP, _s.TCP_KEEPCNT, 3)
    except Exception as _e:
        logging.debug(f"[VNC] socket options not fully applied: {_e}")


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

    # MK: XCP-ng clusters build status from their own cached data
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        try:
            st = manager.get_cluster_status()
            nodes = manager.get_nodes()
            vms = manager.get_vms()
            storages = manager.get_storages()
            nodes_online = sum(1 for n in nodes if n.get('status') == 'online')
            total_disk = sum(s.get('total', 0) for s in storages)
            used_disk = sum(s.get('used', 0) for s in storages)
            vms_running = len([v for v in vms if v.get('status') == 'running'])
            vms_stopped = len([v for v in vms if v.get('status') == 'stopped'])
            return jsonify({
                'cluster': {'name': manager.config.name, 'quorate': None, 'standalone': False, 'version': 0, 'cluster_type': 'xcpng'},
                'nodes': {'online': nodes_online, 'offline': len(nodes) - nodes_online, 'total': len(nodes)},
                'guests': {'vms': {'running': vms_running, 'stopped': vms_stopped}, 'containers': {'running': 0, 'stopped': 0}},
                'resources': {
                    'cpu': {'total': st.get('total_cpu', 0), 'used': 0, 'percent': 0},
                    'memory': {'total': st.get('total_mem', 0), 'used': st.get('used_mem', 0), 'percent': round(st['used_mem'] / st['total_mem'] * 100, 1) if st.get('total_mem') else 0},
                    'storage': {'total': total_disk, 'used': used_disk, 'percent': round(used_disk / total_disk * 100, 1) if total_disk else 0},
                }
            })
        except Exception as e:
            return jsonify({'error': safe_error(e, 'Failed to get XCP-ng status')}), 500

    try:
        host, port = manager.host, manager.api_port

        # MK May 2026 — cluster-wide aggregates ([cluster/status] + [cluster/resources])
        # are genuinely expensive on big clusters (PVE walks every node to build the
        # response). 10s was too tight; bump to 15s and mark the host as cold on
        # timeout so subsequent calls roll over to a fallback host via the
        # connect_to_proxmox skip-cache.
        status_url = f"https://{host}:{port}/api2/json/cluster/status"
        resources_url = f"https://{host}:{port}/api2/json/cluster/resources"
        try:
            status_resp = manager._create_session().get(status_url, timeout=15)
            resources_resp = manager._create_session().get(resources_url, timeout=15)
        except requests.exceptions.Timeout:
            # Mark host cold AND force an immediate reconnect so manager.host
            # pivots to a warm fallback for the next request. Without the
            # reconnect, _mark_host_failure only affects later
            # connect_to_proxmox() calls — but the current manager.host
            # pointer still points at the dead primary.
            manager._mark_host_failure(host)
            try:
                manager.is_connected = False
                manager.connect_to_proxmox()
            except Exception:
                pass  # best-effort; user will see the timeout this round
            raise

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
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logging.warning(f"[API] Cluster {cluster_id} unreachable for datacenter/status: {e}")
        return jsonify({'error': 'Cluster temporarily unreachable', 'offline': True}), 503
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get datacenter status')}), 500


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

    # MK: XCP-ng clusters use their own get_vms()
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        try:
            vms = manager.get_vms()
            vms.sort(key=lambda x: x.get('vmid', 0))
            return jsonify({'vms': vms})
        except Exception as e:
            return jsonify({'error': safe_error(e, 'Failed to list XCP-ng VMs')}), 500

    # NS: use manager method instead of raw API call - handles timeouts gracefully
    resources = manager.get_vm_resources()
    vms = []
    for r in resources:
        if r.get('type') in ['qemu', 'lxc'] and r.get('vmid'):
            vms.append({
                'vmid': r.get('vmid'),
                'name': r.get('name', ''),
                'node': r.get('node'),
                'type': r.get('type'),
                'status': r.get('status', 'unknown')
            })
    vms.sort(key=lambda x: x.get('vmid', 0))
    return jsonify({'vms': vms})


@bp.route('/api/clusters/<cluster_id>/datacenter/cluster-info', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_info(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host, port = manager.host, manager.api_port
        session = manager._create_session()

        # Try corosync config first (has ring0_addr for join info)
        nodes = []
        try:
            url = f"https://{host}:{port}/api2/json/cluster/config/nodes"
            r = session.get(url, timeout=5)
            if r.status_code == 200:
                nodes = r.json().get('data', [])
        except:
            pass

        # Merge with /nodes to get online status (corosync config doesn't have it)
        # Also serves as fallback for standalone nodes without corosync
        try:
            nodes_url = f"https://{host}:{port}/api2/json/nodes"
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
        host, port = manager.host, manager.api_port
        
        # try to get join info
        url = f"https://{host}:{port}/api2/json/cluster/config/join"
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
        
        status_url = f"https://{host}:{port}/api2/json/cluster/status"
        status_resp = manager._create_session().get(status_url, timeout=5)
        
        if status_resp.status_code == 200:
            status_data = status_resp.json().get('data', [])
            cluster_info = next((s for s in status_data if s.get('type') == 'cluster'), {})
            nodes = [s for s in status_data if s.get('type') == 'node']
            
            result['cluster_name'] = cluster_info.get('name', 'Unknown')
            result['nodelist'] = [{'name': n.get('name'), 'ip': n.get('ip'), 'online': n.get('online', 0)} for n in nodes]
        
        # get nodes config
        nodes_url = f"https://{host}:{port}/api2/json/cluster/config/nodes"
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

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logging.warning(f"[API] Cluster {cluster_id} unreachable for join-info: {e}")
        return jsonify({'error': 'Cluster temporarily unreachable', 'offline': True}), 503
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get cluster info')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/options"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', {}))
        return jsonify({})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get datacenter options')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/options"
        raw_data = request.json or {}
        data = {k: v for k, v in raw_data.items() if k in ALLOWED_DC_OPTIONS}

        # MK May 2026 — version-gate the crs sub-keys. Live-probed PVE 9.2.2:
        #   scheduling=basic  → 400 "property is not defined in schema"
        #   ha-rebalance-on-start=1 → 200 OK
        #   ha-auto-rebalance=1     → 200 OK
        #   ha-auto-rebalance-{threshold,method,margin,hold-duration} → 200 OK
        # Any one rejected sub-key tanks the whole crs PUT — so a UI that
        # picks "Basic" in the Scheduling Mode dropdown blocked every other
        # CRS field too. Strip `scheduling=` on 9.2+ so admins can still
        # save the auto-rebalance settings.
        # (Pre-9.2 keeps scheduling — it's still in the schema there.)
        if 'crs' in data and isinstance(data['crs'], str) and data['crs']:
            pve_ver = manager.get_pve_version_tuple()
            if pve_ver is not None and pve_ver >= (9, 2):
                kept = []
                dropped = []
                for part in data['crs'].split(','):
                    key = part.split('=', 1)[0].strip()
                    if key == 'scheduling':
                        dropped.append(part)
                        continue
                    kept.append(part)
                if dropped:
                    data['crs'] = ','.join(kept)
                    if not data['crs']:
                        data.pop('crs', None)
                    try:
                        from pegaprox.utils.audit import log_audit
                        log_audit(request.session.get('user', 'system'),
                                  'datacenter.crs.stripped',
                                  f"PVE {pve_ver[0]}.{pve_ver[1]} — dropped {dropped}",
                                  cluster=manager.config.name)
                    except Exception:
                        pass

        # MK May 2026 — /cluster/options PUT can legitimately take 15-25s on
        # busy clusters (PVE writes datacenter.cfg, ipcc-syncs to all nodes,
        # restarts pveproxy on each). The old 10s was tight enough to fail
        # consistently on the ESXi-Test-Env lab; bump to 30s. If it still
        # times out the host is genuinely wedged — mark it cold so the next
        # request goes via fallback instead of waiting 30s again.
        try:
            response = manager._create_session().put(url, data=data, timeout=30)
        except requests.exceptions.Timeout:
            manager._mark_host_failure(host)
            try:
                manager.is_connected = False
                manager.connect_to_proxmox()
            except Exception:
                pass
            raise

        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Options updated'})
        return jsonify({'error': parse_pve_error(response.text)}), response.status_code
    except requests.exceptions.Timeout:
        # Map to 504 so the frontend knows it's a slow-PVE thing, not a code bug.
        # Settings *may* have applied — pveproxy on busy clusters sometimes
        # commits the write but doesn't reply in time. Operator should re-load.
        return jsonify({
            'error': 'PVE took too long to apply datacenter options. The change may still have been written — reload the page to verify.',
            'timeout': True,
        }), 504
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to set datacenter options')}), 500


# Storage API
@bp.route('/api/clusters/<cluster_id>/datacenter/storage', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_storage_list(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error

    # XCP-ng storage list
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        return jsonify(manager.get_storages())

    try:
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/storage"
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

    # XCP-ng: return SR list as datastores
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        storages = manager.get_storages()
        return jsonify({'shared': storages, 'local': {}})

    try:
        host, port = manager.host, manager.api_port
        sess = manager._create_session()

        # get storage configs
        storage_url = f"https://{host}:{port}/api2/json/storage"
        storage_resp = sess.get(storage_url, timeout=5)
        storage_configs = {}
        if storage_resp.status_code == 200:
            for s in storage_resp.json().get('data', []):
                storage_configs[s['storage']] = s

        # NS May 2026 — fetch nodes via /cluster/resources to get the *online* flag.
        # /api2/json/nodes alone doesn't tell us which are reachable; if we then
        # try to fetch /storage from a dead node we waste 10s per offline node.
        nodes = []          # [(name, status), ...]
        try:
            cr_resp = sess.get(f"https://{host}:{port}/api2/json/cluster/resources",
                               params={'type': 'node'}, timeout=5)
            if cr_resp.status_code == 200:
                for n in cr_resp.json().get('data', []):
                    nm = n.get('node')
                    if nm:
                        nodes.append((nm, n.get('status', 'unknown')))
        except Exception:
            pass
        if not nodes:
            # fallback to /nodes (no online flag, still iterate but trust try/except)
            nodes_resp = sess.get(f"https://{host}:{port}/api2/json/nodes", timeout=5)
            if nodes_resp.status_code == 200:
                nodes = [(n['node'], n.get('status', 'unknown')) for n in nodes_resp.json().get('data', [])]

        online_nodes = [n for n, st in nodes if st == 'online']
        offline_nodes = [n for n, st in nodes if st != 'online']
        all_node_names = [n for n, _ in nodes]

        shared_storages = {}
        local_storages = {}

        # NS May 2026 — fetch all online nodes' storage in parallel; gevent
        # patches threading so this is cheap. Each call has its own short
        # timeout so a slow node doesn't drag the whole response.
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def _probe_node(node):
            try:
                u = f"https://{host}:{port}/api2/json/nodes/{node}/storage"
                r = sess.get(u, timeout=8)
                if r.status_code == 200:
                    return node, r.json().get('data', []), None
                return node, [], f'HTTP {r.status_code}'
            except Exception as e:
                return node, [], str(e)

        results = []
        if online_nodes:
            with ThreadPoolExecutor(max_workers=min(8, len(online_nodes))) as ex:
                futures = [ex.submit(_probe_node, n) for n in online_nodes]
                for fut in as_completed(futures, timeout=15):
                    try:
                        results.append(fut.result())
                    except Exception as e:
                        logging.debug(f"[datastores] future error: {e}")

        for node, storages, err in results:
            if err:
                logging.debug(f"[datastores] node {node} unreachable: {err}")
                continue
            for storage in storages:
                storage_name = storage.get('storage')
                config = storage_configs.get(storage_name, {})
                is_shared = config.get('shared', 0) == 1
                is_active_here = storage.get('active', 1) == 1 and storage.get('enabled', 1) == 1

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
                        shared_storages[storage_name] = dict(storage_info)
                        shared_storages[storage_name]['active_on'] = []
                        shared_storages[storage_name]['inactive_on'] = []
                    entry = shared_storages[storage_name]
                    (entry['active_on'] if is_active_here else entry['inactive_on']).append(node)
                    # NS May 2026 — always prefer the largest-known total (any reachable
                    # node should report the same number for shared, but rounding +
                    # transient zero values can flap).
                    if is_active_here and storage.get('total', 0) > entry.get('total', 0):
                        entry.update({
                            'total': storage.get('total', 0),
                            'used': storage.get('used', 0),
                            'avail': storage.get('avail', 0),
                            'used_fraction': storage.get('used_fraction', 0),
                        })
                    if is_active_here:
                        entry['active'] = 1
                        entry['enabled'] = 1
                else:
                    if node not in local_storages:
                        local_storages[node] = []
                    local_storages[node].append(storage_info)

        # NS May 2026 — for offline nodes: surface their last-known storages from the
        # cluster's storage config so the UI can render "this node has these storages,
        # node is currently offline" instead of an empty space. We can't get current
        # used/avail without contacting the node, so we mark them as `node_offline`.
        for off_node in offline_nodes:
            local_storages.setdefault(off_node, [])
            for sname, cfg in storage_configs.items():
                if cfg.get('shared', 0) == 1:
                    continue
                node_filter = cfg.get('nodes', '')
                # apply if node_filter is empty (= all nodes) or contains this node
                if node_filter and off_node not in node_filter.split(','):
                    continue
                local_storages[off_node].append({
                    'storage': sname, 'type': cfg.get('type', 'unknown'),
                    'content': cfg.get('content', ''), 'total': 0, 'used': 0, 'avail': 0,
                    'used_fraction': 0, 'active': 0, 'enabled': cfg.get('disable', 0) != 1,
                    'shared': False, 'path': cfg.get('path', ''), 'nodes': node_filter,
                    'node_offline': True,
                })

        # also include shared storages from config that didn't appear (no online node mounted them)
        for sname, cfg in storage_configs.items():
            if sname not in shared_storages and cfg.get('shared', 0) == 1:
                shared_storages[sname] = {
                    'storage': sname, 'type': cfg.get('type', 'unknown'),
                    'content': cfg.get('content', ''), 'total': 0, 'used': 0, 'avail': 0,
                    'used_fraction': 0, 'active': 0, 'enabled': cfg.get('disable', 0) != 1,
                    'shared': True, 'path': cfg.get('path', ''), 'nodes': cfg.get('nodes', ''),
                    'active_on': [], 'inactive_on': list(all_node_names),
                }

        return jsonify({
            'shared': list(shared_storages.values()),
            'local': local_storages,
            'nodes': all_node_names,
            'offline_nodes': offline_nodes,
        })
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logging.warning(f"[API] Cluster {cluster_id} unreachable for datastores: {e}")
        return jsonify({'error': 'Cluster temporarily unreachable', 'offline': True}), 503
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get storage list')}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/content', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_datastore_content(cluster_id, storage_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host, port = manager.host, manager.api_port
        node = request.args.get('node')
        
        # If no node specified, find first node that has this storage
        if not node:
            nodes_url = f"https://{host}:{port}/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        # Get storage content
        content_url = f"https://{host}:{port}/api2/json/nodes/{node}/storage/{storage_name}/content"
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
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logging.warning(f"[API] Cluster {cluster_id} unreachable for storage content: {e}")
        return jsonify({'error': 'Cluster temporarily unreachable', 'offline': True}), 503
    except Exception as e:
        logging.error(f"Error getting datastore content: {e}")
        return jsonify({'error': safe_error(e, 'Failed to get datastore content')}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/content/<path:volid>', methods=['DELETE'])
@require_auth(perms=['storage.delete'])
def delete_datastore_content(cluster_id, storage_name, volid):
    """Delete content from a datastore (ISO, backup, etc.)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host, port = manager.host, manager.api_port
        node = request.args.get('node')
        
        if not node:
            # Find a node that has this storage
            nodes_url = f"https://{host}:{port}/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        # check volume is in use by any VM or Container
        resources_url = f"https://{host}:{port}/api2/json/cluster/resources?type=vm"
        resources_response = manager._create_session().get(resources_url, timeout=5)
        
        if resources_response.status_code == 200:
            for vm in resources_response.json().get('data', []):
                vm_node = vm.get('node')
                vmid = vm.get('vmid')
                vm_type = 'qemu' if vm.get('type') == 'qemu' else 'lxc'
                
                # Get VM/CT config to check disks and mounted ISOs
                config_url = f"https://{host}:{port}/api2/json/nodes/{vm_node}/{vm_type}/{vmid}/config"
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
        delete_url = f"https://{host}:{port}/api2/json/nodes/{node}/storage/{storage_name}/content/{encoded_volid}"
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
        return jsonify({'error': safe_error(e, 'Failed to delete datastore content')}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/upload', methods=['POST'])
@require_auth(perms=['storage.upload'])
def upload_to_datastore(cluster_id, storage_name):
    """Upload ISO or other content to a datastore"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error

    # XCP-ng upload handled separately
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        file = request.files['file']
        content_type = request.form.get('content', 'iso')
        node = request.form.get('node') or ''
        result = manager.upload_to_storage(node, storage_name, file.filename, file.stream, content_type)
        if result.get('success'):
            return jsonify(result)
        return jsonify({'error': result.get('error', 'Upload failed')}), 500

    tmp_path = None
    try:
        host, port = manager.host, manager.api_port
        node = request.form.get('node') or request.args.get('node')
        content_type = request.form.get('content', 'iso')  # iso, vztmpl, etc.

        if not node:
            # NS: pick an online node, not just the first one
            try:
                nodes_resp = manager._api_get(f"https://{host}:{port}/api2/json/nodes")
                if nodes_resp.status_code == 200:
                    for n in nodes_resp.json().get('data', []):
                        if n.get('status') == 'online':
                            node = n['node']
                            break
                    # fallback: first node if none reported online
                    if not node:
                        ndata = nodes_resp.json().get('data', [])
                        if ndata:
                            node = ndata[0]['node']
            except Exception as e:
                logging.warning(f"Node lookup for upload failed: {e}")

        if not node:
            return jsonify({'error': 'No node available'}), 400

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400

        # MK: Mar 2026 - allow disk images alongside ISOs (#115)
        filename = os.path.basename(file.filename)  # strip directory components
        if not filename or filename.startswith('.') or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        _allowed_ext = {
            'iso': ('.iso',),
            'import': ('.vmdk', '.qcow2', '.img', '.raw'),
            'vztmpl': ('.tar.gz', '.tar.xz', '.tar.zst'),
        }
        allowed = _allowed_ext.get(content_type)
        if allowed and not filename.lower().endswith(allowed):
            return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed)}'}), 400
        # NS: reject filenames with null bytes or shell metacharacters
        if any(c in filename for c in '\x00;|&$`'):
            return jsonify({'error': 'Invalid characters in filename'}), 400

        # NS: Mar 2026 - save to temp file first, SpooledTemporaryFile + requests is unreliable
        # across werkzeug versions. Temp file is cleaned up in finally block.
        # #119: use app dir for temp, not /tmp (LXC tmpfs is often too small for ISOs)
        import tempfile
        upload_tmp_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tmp')
        os.makedirs(upload_tmp_dir, mode=0o700, exist_ok=True)
        # don't include user extension in temp filename
        fd, tmp_path = tempfile.mkstemp(dir=upload_tmp_dir)
        try:
            file.save(tmp_path)
        except Exception as e:
            os.close(fd)
            raise
        else:
            os.close(fd)

        upload_url = f"https://{host}:{port}/api2/json/nodes/{node}/storage/{storage_name}/upload"

        with open(tmp_path, 'rb') as fh:
            files = {
                'filename': (filename, fh, 'application/octet-stream')
            }
            data = {
                'content': content_type
            }
            # NS: use _api_post for auto-reconnect tracking, 1h timeout for large ISOs
            response = manager._api_post(upload_url, files=files, data=data, timeout=3600)

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
            # MK: Mar 2026 - safe error parsing, Proxmox sometimes returns HTML on 5xx
            try:
                error_msg = response.json().get('errors', response.text)
            except Exception:
                error_msg = response.text[:500] if response.text else 'Upload failed'
            logging.error(f"Upload to {storage_name} failed: HTTP {response.status_code} - {error_msg}")
            return jsonify({'error': error_msg}), response.status_code

    except Exception as e:
        logging.error(f"Error uploading to {storage_name}: {e}")
        return jsonify({'error': safe_error(e, 'Failed to upload to datastore')}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


# NS: Download ISO from URL - Jan 2026
# Like Proxmox's "Download from URL" feature
# Tracks download progress in memory (for status polling)
_url_downloads = {}  # task_id -> { status, percent, message, ... }

@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/download-url', methods=['POST'])
@require_auth(perms=['storage.upload'])
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

        # NS: Mar 2026 - block internal/metadata URLs to prevent SSRF
        import ipaddress as _ipaddr
        from urllib.parse import urlparse as _urlparse
        try:
            _parsed_host = _urlparse(url).hostname or ''
            # resolve hostname to check if it points to internal IP
            import socket as _sock
            _resolved = _sock.getaddrinfo(_parsed_host, None, 0, _sock.SOCK_STREAM)
            for _fam, _type, _proto, _canon, _addr in _resolved:
                _ip = _ipaddr.ip_address(_addr[0])
                if _ip.is_private or _ip.is_loopback or _ip.is_link_local or _ip.is_reserved:
                    return jsonify({'error': 'Download from internal/private networks is not allowed'}), 400
        except (ValueError, _sock.gaierror):
            pass  # can't resolve = let proxmox handle it
        
        # Extract filename from URL if not provided
        if not filename:
            from urllib.parse import urlparse, unquote
            parsed = urlparse(url)
            filename = unquote(parsed.path.split('/')[-1]) or 'download.iso'
        
        # Ensure proper extension
        if not any(filename.lower().endswith(ext) for ext in ['.iso', '.img', '.qcow2', '.raw']):
            filename += '.iso'
        
        host, port = manager.host, manager.api_port
        
        # Find node if not specified
        if not node:
            nodes_url = f"https://{host}:{port}/api2/json/nodes"
            nodes_response = manager._create_session().get(nodes_url, timeout=5)
            if nodes_response.status_code == 200:
                for n in nodes_response.json().get('data', []):
                    node = n['node']
                    break
        
        if not node:
            return jsonify({'error': 'No node available'}), 400
        
        # Try using Proxmox's native download-url API (PVE 7.0+)
        download_url = f"https://{host}:{port}/api2/json/nodes/{node}/storage/{storage_name}/download-url"
        
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
                        status_url = f"https://{host}:{port}/api2/json/nodes/{node}/tasks/{upid}/status"
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
                                    log_url = f"https://{host}:{port}/api2/json/nodes/{node}/tasks/{upid}/log"
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
        return jsonify({'error': safe_error(e, 'Failed to start URL download')}), 500


@bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/download-status/<task_id>', methods=['GET'])
@require_auth(perms=['storage.upload'])
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
        host, port = manager.host, manager.api_port
        session = manager._create_session()
        
        backups = []
        
        # get all storages that can hold backups
        # NS: this is kinda slow if you have lots of storages but whatever
        storage_url = f"https://{host}:{port}/api2/json/nodes/{node}/storage"
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
            content_url = f"https://{host}:{port}/api2/json/nodes/{node}/storage/{stor_name}/content"
            try:
                # #143: pass vmid filter — critical for PBS storages which can have
                # thousands of backups. Without it PVE returns ALL backups and we hang
                content_resp = session.get(content_url, params={'content': 'backup', 'vmid': vmid}, timeout=(5, 30))
            except Exception:
                continue

            if content_resp.status_code != 200:
                continue

            items = content_resp.json().get('data', [])

            for item in items:
                # vzdump naming: vzdump-{type}-{vmid}-{date}_{time}.{ext}
                # LW: proxmox naming conventions are weird but ok
                volid = item.get('volid', '')
                filename = volid.split('/')[-1] if '/' in volid else volid.split(':')[-1]

                # double-check vmid match (PVE filter isn't always exact)
                # #143: PBS volids use path format backup/vm/{vmid}/ instead of vzdump filename
                if (f'-{vmid}-' in filename or filename.startswith(f'vzdump-{vm_type[:4]}-{vmid}')
                        or f'/vm/{vmid}/' in volid or f'/ct/{vmid}/' in volid):
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
        return jsonify({'error': safe_error(e, 'Failed to get VM backups')}), 500


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
        host, port = manager.host, manager.api_port
        session = manager._create_session()
        
        # vzdump endpoint
        url = f"https://{host}:{port}/api2/json/nodes/{node}/vzdump"
        
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
        
        return jsonify({'error': parse_pve_error(response.text)}), response.status_code
        
    except Exception as e:
        logging.error(f"[BACKUP] Error creating backup: {e}")
        return jsonify({'error': safe_error(e, 'Failed to create backup')}), 500


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
        host, port = manager.host, manager.api_port
        session = manager._create_session()
        
        # restore endpoint depends on vm type
        # MK: why does proxmox have different endpoints for this?? annoying
        if vm_type == 'qemu':
            url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu"
        else:
            url = f"https://{host}:{port}/api2/json/nodes/{node}/lxc"
        
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
        return jsonify({'error': parse_pve_error(response.text)}), response.status_code
        
    except Exception as e:
        logging.error(f"[BACKUP] Error restoring backup: {e}")
        return jsonify({'error': safe_error(e, 'Failed to restore backup')}), 500


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
        host, port = manager.host, manager.api_port
        session = manager._create_session()
        
        # volid format is usually: storage:backup/vzdump-xxx.vma.zst
        # we need to extract storage name
        if ':' in volid:
            storage = volid.split(':')[0]
        else:
            return jsonify({'error': 'Invalid volume ID format'}), 400
        
        # URL encode the volid for the path
        encoded_volid = url_quote(volid, safe='')
        
        url = f"https://{host}:{port}/api2/json/nodes/{node}/storage/{storage}/content/{encoded_volid}"
        
        response = session.delete(url, timeout=30)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'backup.deleted', f"Deleted backup {volid}", cluster=manager.config.name)
            return jsonify({'success': True})
        
        return jsonify({'error': parse_pve_error(response.text)}), response.status_code
        
    except Exception as e:
        logging.error(f"[BACKUP] Error deleting backup: {e}")
        return jsonify({'error': safe_error(e, 'Failed to delete backup')}), 500
@bp.route('/api/clusters/<cluster_id>/datacenter/replication', methods=['GET'])
@require_auth(perms=["cluster.view"])
def get_replication_jobs(cluster_id):
    """Get all replication jobs (datacenter-level view)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    # MK May 2026 (#333) — go through manager.get_replication_jobs() which merges
    # per-node runtime data (last_sync/last_try/state/error/fail_count) onto the
    # cluster-level job definitions. The plain /cluster/replication endpoint
    # only returns config so the datacenter view used to show "Last sync = Never"
    # for jobs that were running fine.
    try:
        return jsonify(manager.get_replication_jobs())
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get replication jobs')}), 500


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
        host, port = manager.host, manager.api_port
        
        # Get manager status (quorum, master, lrm for each node)
        url = f"https://{host}:{port}/api2/json/cluster/ha/status/manager_status"
        resp = manager._create_session().get(url, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return jsonify(data)
        else:
            # Fallback to current status
            url2 = f"https://{host}:{port}/api2/json/cluster/ha/status/current"
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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/options"
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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/options"
        data = request.json or {}
        
        r = manager._create_session().put(url, data=data, timeout=10)
        
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'firewall.options_changed', f"Firewall options updated", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Firewall options updated'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to set firewall options')}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_firewall_rules(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/rules"
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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/rules"
        data = request.json or {}
        
        r = manager._create_session().post(url, data=data, timeout=10)
        
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'firewall.rule_created', f"Firewall rule created", cluster=manager.config.name)
            return jsonify({'success': True, 'message': 'Firewall rule created'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to create firewall rule')}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules/<int:pos>', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def update_firewall_rule(cluster_id, pos):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/rules/{pos}"
        data = request.json or {}
        
        r = manager._create_session().put(url, data=data, timeout=10)
        
        if r.status_code == 200:
            return jsonify({'success': True, 'message': 'Firewall rule updated'})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to update firewall rule')}), 500


@bp.route('/api/clusters/<cluster_id>/datacenter/firewall/rules/<int:pos>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_firewall_rule(cluster_id, pos):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    try:
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/rules/{pos}"
        
        response = manager._create_session().delete(url, timeout=10)
        
        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Firewall rule deleted'})
        return jsonify({'error': parse_pve_error(response.text)}), response.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to delete firewall rule')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/groups"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get firewall groups')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/aliases"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get firewall aliases')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/firewall/ipset"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get firewall IP sets')}), 500


# ============================================
# Per-VM/CT Firewall API
# ============================================

def _vm_fw_url(manager, node, vmtype, vmid, sub=''):
    host, port = manager.host, manager.api_port
    return f"https://{host}:{port}/api2/json/nodes/{node}/{vmtype}/{vmid}/firewall{sub}"


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
        return jsonify({'error': safe_error(e, 'Failed to set VM firewall options')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to create VM firewall rule')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to update VM firewall rule')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to delete VM firewall rule')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to create VM firewall alias')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to update VM firewall alias')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to delete VM firewall alias')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to create VM firewall IP set')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to add IP set entry')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to delete IP set entry')}), 500


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
        return jsonify({'error': safe_error(e, 'Failed to delete VM firewall IP set')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/mapping/pci"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get PCI mappings')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/cluster/mapping/usb"
        response = manager._create_session().get(url, timeout=5)
        
        if response.status_code == 200:
            return jsonify(response.json().get('data', []))
        return jsonify([])
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to get USB mappings')}), 500


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
    # NS: force-refresh from PVE so we don't return stale data (#141)
    mgr.refresh_maintenance_status()
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
    node_ip = _validate_host(data.get('node_ip', ''))
    username = data.get('username', 'root')
    password = data.get('password', '')
    ssh_port = sanitize_int(data.get('ssh_port', 22), default=22, min_val=1, max_val=65535)

    if not node_ip:
        return jsonify({'success': False, 'error': 'Node IP is required (must be a valid hostname or IP address)'}), 400
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
        return jsonify({'success': False, 'error': safe_error(e, 'SSH error')}), 500
    except socket.timeout:
        return jsonify({'success': False, 'error': 'Connection timeout. Check IP and network.'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': safe_error(e, 'Connection failed')}), 500


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
    
    node_ip = _validate_host(data.get('node_ip', ''))
    username = data.get('username', 'root')
    password = data.get('password', '')
    ssh_port = sanitize_int(data.get('ssh_port', 22), default=22, min_val=1, max_val=65535)
    link0_address = data.get('link0_address', '').strip()
    force_rejoin = data.get('force', False)  # LW: Feb 2026 - Clean old cluster config before join

    if not node_ip or not password:
        return jsonify({'success': False, 'error': 'Node IP and password are required'}), 400
    
    try:
        # Get join information from existing cluster
        # MK: Feb 2026 - Use direct API call (same as get_join_info which works)
        # instead of api_request() wrapper which was silently failing
        host, port = mgr.host, mgr.api_port
        join_url = f"https://{host}:{port}/api2/json/cluster/config/join"
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
        return jsonify({'success': False, 'error': safe_error(e, 'Failed to join node to cluster')}), 500


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
            host, port = mgr.host, mgr.api_port
            nodes_url = f"https://{host}:{port}/api2/json/nodes"
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
            host, port = mgr.host, mgr.api_port
            session = mgr._create_session()
            resources = []
            for endpoint in [f"/nodes/{node_name}/qemu", f"/nodes/{node_name}/lxc"]:
                try:
                    r = session.get(f"https://{host}:{port}/api2/json{endpoint}", timeout=10)
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
        return jsonify({'can_remove': False, 'error': safe_error(e, 'Failed to check node removal'), 'blockers': [safe_error(e, 'Failed to check node removal')]}), 200


@bp.route('/api/clusters/<cluster_id>/nodes/<node_name>/cluster-membership', methods=['DELETE'])
@require_auth(perms=['cluster.admin'])
def remove_node_from_cluster(cluster_id, node_name):
    """Remove a node from the Proxmox cluster"""
    # LW: Feb 2026 - Runs pvecm delnode on a remaining online node, then SSHs into the
    # removed node to clean up stale configs (authkey, corosync.conf, lock files)
    # MK: IP must be resolved BEFORE delnode or we might wipe the wrong node!
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # MK Apr 2026 — Validate node_name strictly. URL-routed param flows into
    # `pvecm delnode {node_name}` via SSH (line ~2617). Without validation, a
    # request like .../nodes/pve1;curl%20attacker/cluster-membership becomes a
    # shell-injection chain even though the route is gated to cluster.admin.
    # PVE/Debian node names follow RFC-1035-ish DNS rules: letter-led, then
    # letters/digits/hyphens, max ~63 chars. Reject anything else.
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$', node_name or ''):
        return jsonify({'success': False, 'error': 'Invalid node name'}), 400

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
        host, port = mgr.host, mgr.api_port
        nodes_url = f"https://{host}:{port}/api2/json/nodes"
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
        
        # Execute pvecm delnode command. MK Apr 2026: shlex.quote belt-and-braces
        # — node_name is already regex-validated at the top of the function,
        # but the second layer keeps things safe if the regex ever loosens.
        cmd = f'pvecm delnode {shlex.quote(node_name)}'
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
        return jsonify({'success': False, 'error': safe_error(e, 'Failed to remove node from cluster')}), 500


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
            return jsonify({'error': safe_error(e, 'Failed to execute node action')}), 500

    except Exception as e:
        logging.error(f"Node action error: {e}")
        return jsonify({'error': safe_error(e, 'Node action failed')}), 500


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
    
    # NS: xapi.vm.power covers all power actions for XCP-ng clusters
    manager = cluster_managers[cluster_id]
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        required_perm = 'xapi.vm.power'
    else:
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
        return jsonify({'error': f'{action} failed'}), 500

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
        # #194: apply Cloud-Init config to cloned QEMU VM (before first boot)
        if vm_type == 'qemu':
            ci_params = {}
            for ci_key in ('ciuser', 'cipassword', 'sshkeys', 'ipconfig0', 'ipconfig1', 'nameserver', 'searchdomain'):
                if data.get(ci_key):
                    ci_params[ci_key] = data[ci_key]
            if ci_params:
                try:
                    upid = result.get('data')
                    if upid:
                        manager._wait_for_task(node, upid, timeout=600)
                    clone_node = data.get('target_node') or node
                    ci_url = f"https://{manager.host}:{manager.api_port}/api2/json/nodes/{clone_node}/qemu/{newid}/config"
                    manager._api_post(ci_url, data=ci_params)
                    logging.info(f"[CLONE] Applied Cloud-Init config to VM {newid}: {list(ci_params.keys())}")
                except Exception as e:
                    logging.warning(f"[CLONE] Cloud-Init config failed for {newid}: {e}")

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

    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']

    mgr = cluster_managers[cluster_id]
    console_perm = 'xapi.vm.view' if getattr(mgr, 'cluster_type', 'proxmox') == 'xcpng' else 'vm.console'
    if not user_can_access_vm(user, cluster_id, vmid, console_perm, vm_type):
        return jsonify({'error': f'Permission denied: {console_perm}'}), 403

    result = mgr.get_vnc_ticket(node, vmid, vm_type)

    if result.get('success'):
        # NS: log who opened the console
        usr = request.session.get('user', 'unknown')
        log_audit(usr, 'vm.console', f'VNC console opened: {vm_type}/{vmid} on {node}', cluster=mgr.config.name)

        # MK Apr 2026 — Stable VNC Mode (D). Frontend opt-in via ?stable=1.
        # Returns an additional AES-256-GCM session key + handle the WS handler
        # picks up on connect. Inner-encryption layer survives TLS-inspection
        # middleboxes that re-encrypt the outer TLS and modify binary RFB bytes.
        if request.args.get('stable') == '1':
            try:
                from pegaprox.utils import vnc_crypto
                import base64 as _b64
                import secrets as _secrets
                key = vnc_crypto.generate_session_key()
                sid = _secrets.token_urlsafe(16)
                vnc_crypto.stash_session_key(sid, key)
                result['stable'] = {
                    'session_id': sid,
                    'key_b64': _b64.b64encode(key).decode('ascii'),
                    'frame_format': 'aes256-gcm-seq32-iv96',
                    'protocol_version': 1,
                }
            except Exception as _enc_err:
                logging.warning(f"[VNC] stable-mode key generation failed (falling back to plain): {_enc_err}")

        return jsonify(result)
    return jsonify({'error': result.get('error', 'Failed')}), 500


# MK Apr 2026 — HTTP-polling fallback for the VNC proxy. Used when the WS
# leg between browser and PegaProx is killed by a security middlebox (rare
# but real: CrowdStrike with WS DPI on, Zscaler strict mode). Same auth, same
# Stable-Mode crypto, same SSH tunnel for the second leg — only the transport
# changes from "one persistent WSS" to "many short HTTPS POSTs". Higher latency,
# but goes through anything that allows plain HTTPS.
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vnc-poll', methods=['POST'])
@require_auth()
def vnc_poll(cluster_id, node, vm_type, vmid):
    """Action-dispatched HTTP-polling endpoint for VNC.

    Body shapes:
      {action: 'open',  enc_session?: '...'}    -> {ok, poll_id, ...}
      {action: 'send',  poll_id, data_b64}      -> {ok, sent}
      {action: 'recv',  poll_id, max_wait?}     -> {ok, chunks_b64, closed}
      {action: 'close', poll_id}                -> {ok}
    """
    from pegaprox.utils import vnc_polling as _poll
    body = request.get_json(silent=True) or {}
    action = body.get('action')

    # All actions need cluster + perm checks
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    mgr = cluster_managers[cluster_id]
    console_perm = 'xapi.vm.view' if getattr(mgr, 'cluster_type', 'proxmox') == 'xcpng' else 'vm.console'
    if not user_can_access_vm(user, cluster_id, vmid, console_perm, vm_type):
        return jsonify({'error': f'Permission denied: {console_perm}'}), 403

    if vm_type not in ('qemu', 'lxc'):
        return jsonify({'error': 'invalid vm_type'}), 400

    # ───── action: open ─────
    if action == 'open':
        # acquire PVE auth + vncproxy ticket (mirrors the WS handler flow)
        import urllib.request, urllib.parse, json as _json, ssl as _ssl
        import websocket as ws_client
        import base64 as _b64
        host, port = mgr.host, mgr.api_port

        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = _ssl.CERT_NONE

        try:
            login_data = urllib.parse.urlencode({
                'username': mgr.config.user,
                'password': mgr.config.pass_,
            }).encode('utf-8')
            login_req = urllib.request.Request(
                f"https://{host}:{port}/api2/json/access/ticket", data=login_data, method='POST'
            )
            with urllib.request.urlopen(login_req, context=ssl_ctx, timeout=10) as r:
                login_result = _json.loads(r.read().decode('utf-8'))
            pve_ticket = login_result['data']['ticket']
            csrf_token = login_result['data']['CSRFPreventionToken']

            # MK Apr 2026 (#352 follow-up) — same single-vncproxy fix applies
            # to the polling endpoint. If JS provides pve_port + pve_ticket in
            # the open body, reuse them so noVNC's RFB password matches PVE's.
            pve_port_q = body.get('pve_port')
            pve_ticket_q = body.get('pve_ticket')
            if pve_port_q and pve_ticket_q:
                vnc_ticket = pve_ticket_q
                vnc_port = pve_port_q
            else:
                vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{vmid}/vncproxy"
                vnc_req = urllib.request.Request(vnc_url, data=urllib.parse.urlencode({'websocket': '1'}).encode('utf-8'), method='POST')
                vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
                vnc_req.add_header('CSRFPreventionToken', csrf_token)
                with urllib.request.urlopen(vnc_req, context=ssl_ctx, timeout=10) as r:
                    vnc_result = _json.loads(r.read().decode('utf-8'))
                vnc_ticket = vnc_result['data']['ticket']
                vnc_port = vnc_result['data']['port']
        except Exception as e:
            return jsonify({'error': f'pve auth/proxy failed: {e}'}), 502

        encoded_ticket = url_quote(vnc_ticket, safe='')
        pve_ws_path = f"/api2/json/nodes/{node}/{vm_type}/{vmid}/vncwebsocket?port={vnc_port}&vncticket={encoded_ticket}"

        # Optional SSH tunnel (same path as WS handler)
        tunnel_endpoint = None
        target_host = host
        target_port = 8006
        try:
            if bool(getattr(mgr.config, 'vnc_tunnel', False)):
                from pegaprox.utils import vnc_tunnel as _vt
                _ssh_user = getattr(mgr.config, 'ssh_user', None) or (mgr.config.user or 'root').split('@')[0]
                _ssh_port = getattr(mgr.config, 'ssh_port', 22) or 22
                tunnel_endpoint = _vt.acquire(
                    cluster_id=cluster_id, pve_host=host,
                    ssh_user=_ssh_user, ssh_port=_ssh_port,
                    ssh_key_content=getattr(mgr.config, 'ssh_key', '') or '',
                    ssh_password=getattr(mgr.config, 'pass_', '') or '',
                    target_host='127.0.0.1', target_port=8006,
                )
                target_host = '127.0.0.1'
                target_port = tunnel_endpoint.local_port
                logging.info(f"[VncPoll] tunnel routed via 127.0.0.1:{target_port} → SSH → {host}:{port}")
        except Exception as te:
            logging.warning(f"[VncPoll] tunnel setup failed ({te}) — direct WSS to PVE")
            tunnel_endpoint = None
            target_host = host
            target_port = 8006

        pve_ws_url = f"wss://{target_host}:{target_port}{pve_ws_path}"
        try:
            pve_ws = ws_client.create_connection(
                pve_ws_url,
                sslopt={"cert_reqs": _ssl.CERT_NONE},
                header={"Cookie": f"PVEAuthCookie={pve_ticket}", "Host": f"{host}:{port}"},
                timeout=VNC_PVE_CONNECT_TIMEOUT,
            )
            _apply_vnc_socket_options(pve_ws.sock)
        except Exception as e:
            try:
                if tunnel_endpoint: tunnel_endpoint.stop()
            except Exception: pass
            return jsonify({'error': f'pve ws connect failed: {e}'}), 502

        # Optional Stable-Mode crypto
        crypto_session = None
        enc_sid = body.get('enc_session')
        if enc_sid:
            try:
                from pegaprox.utils import vnc_crypto as _vc
                key = _vc.claim_session_key(enc_sid)
                if key:
                    crypto_session = _vc.VncCryptoSession(key)
            except Exception as ce:
                logging.warning(f"[VncPoll] crypto setup failed ({ce}) — plain mode")

        sess = _poll.VncPollSession(
            poll_id=_poll.new_poll_id(),
            pve_ws=pve_ws,
            tunnel_endpoint=tunnel_endpoint,
            crypto_session=crypto_session,
            cluster_id=cluster_id,
            vm_type=vm_type,
            vmid=vmid,
            host=host,
        )
        _poll.register(sess)
        log_audit(request.session.get('user', 'unknown'), 'vm.console',
                  f'VNC poll session opened: {vm_type}/{vmid} on {node}', cluster=mgr.config.name)
        logging.info(f"[VncPoll] open id={sess.poll_id[:8]} {vm_type}/{vmid}@{node} crypto={'on' if crypto_session else 'off'} tunnel={'on' if tunnel_endpoint else 'off'}")
        return jsonify({
            'ok': True,
            'poll_id': sess.poll_id,
            'transport': 'http-polling',
            'recv_max_wait': _poll.RECV_LONG_POLL_DEFAULT,
        })

    # All other actions require an existing poll_id
    poll_id = body.get('poll_id') or ''
    sess = _poll.get(poll_id)
    if not sess:
        return jsonify({'error': 'unknown or expired poll session'}), 404
    if sess.cluster_id != cluster_id or sess.vm_type != vm_type or sess.vmid != vmid:
        return jsonify({'error': 'poll session does not match resource'}), 403

    if action == 'send':
        try:
            n = sess.send(body.get('data_b64', ''))
        except Exception as e:
            return jsonify({'error': f'send failed: {e}', 'closed': sess.closed}), 502
        return jsonify({'ok': True, 'sent': n})

    if action == 'recv':
        max_wait = float(body.get('max_wait', 5.0) or 5.0)
        chunks = sess.recv(max_wait=max_wait)
        import base64 as _b64
        return jsonify({
            'ok': True,
            'chunks_b64': [_b64.b64encode(c).decode('ascii') for c in chunks],
            'closed': sess.closed,
        })

    if action == 'close':
        _poll.drop(poll_id)
        return jsonify({'ok': True})

    return jsonify({'error': f'unknown action {action!r}'}), 400


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


def _get_vm_config_response(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    try:
        result = mgr.get_vm_config(node, vmid, vm_type)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logging.warning(f"[API] Cluster {cluster_id} unreachable for vm config: {e}")
        return jsonify({'error': 'Cluster temporarily unreachable', 'offline': True}), 503

    if result['success']:
        config = result['config']
        if isinstance(config, dict) and not config.get('tags') and not config.get('tag'):
            raw = config.get('raw') if isinstance(config.get('raw'), dict) else {}
            general = config.get('general') if isinstance(config.get('general'), dict) else {}
            vm_tags = raw.get('tags') or general.get('tags')
            if vm_tags:
                config['tags'] = vm_tags
        return jsonify(config)
    else:
        return jsonify({'error': result['error']}), 500


def _resolve_vm_location(mgr, vmid, requested_node=None, requested_type=None):
    """Find the current node/type for a VMID so shorthand VM routes can work."""
    requested_node = (requested_node or '').strip() or None
    requested_type = (requested_type or '').strip() or None
    if requested_type == 'ct':
        requested_type = 'lxc'

    try:
        if getattr(mgr, 'cluster_type', 'proxmox') == 'xcpng':
            resources = mgr.get_vms() or []
        else:
            resources = mgr.get_vm_resources() or []
    except Exception as e:
        logging.warning(f"[API] Failed to resolve VM {vmid} location: {e}")
        return None, None, jsonify({'error': safe_error(e, 'Failed to resolve VM location')}), 500

    matches = []
    for item in resources:
        if str(item.get('vmid')) != str(vmid):
            continue
        item_type = item.get('type') or 'qemu'
        item_node = item.get('node') or requested_node
        if requested_type and item_type != requested_type:
            continue
        if requested_node and item_node != requested_node:
            continue
        matches.append((item_node, item_type))

    if not matches:
        return None, None, jsonify({'error': f'VM {vmid} not found'}), 404

    unique = []
    for match in matches:
        if match not in unique:
            unique.append(match)

    if len(unique) > 1:
        return None, None, jsonify({
            'error': f'VM {vmid} is ambiguous; use /vms/<node>/<type>/{vmid}/config',
            'matches': [{'node': node, 'type': vm_type} for node, vm_type in unique],
        }), 409

    node, vm_type = unique[0]
    if not node:
        node = requested_node or 'xcpng'
    return node, vm_type, None, None


# VM Config API Routes
@bp.route('/api/clusters/<cluster_id>/vms/<int:vmid>/config', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_config_by_id_api(cluster_id, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    node, vm_type, error_body, status = _resolve_vm_location(
        mgr,
        vmid,
        requested_node=request.args.get('node'),
        requested_type=request.args.get('type') or request.args.get('vm_type'),
    )
    if error_body is not None:
        return error_body, status

    return _get_vm_config_response(cluster_id, node, vm_type, vmid)


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/config', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_config_api(cluster_id, node, vm_type, vmid):
    return _get_vm_config_response(cluster_id, node, vm_type, vmid)


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
@require_auth(perms=['vm.config'])
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
# MK May 2026 — additive enrichment for the monitoring panel: kernel_version,
# interfaces[] (with MAC + per-NIC IPs), filesystems[], users[], guest_time_ns.
# All existing fields stay unchanged — old UI consumers render exactly as before.
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/guest-info', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_guest_info_api(cluster_id, node, vm_type, vmid):
    """Get QEMU Guest Agent info (hostname, OS, kernel, NICs, filesystems, users, clock)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    if vm_type != 'qemu':
        return jsonify({'agent_running': False}), 200

    mgr = cluster_managers[cluster_id]
    result = {'agent_running': False, 'hostname': None, 'os_pretty_name': None,
              'os_id': None, 'os_version': None, 'os_kernel': None, 'os_machine': None,
              'ip_addresses': [],
              'kernel_version': None,
              'interfaces': [],
              'users': [],
              'filesystems': [],
              'guest_time_ns': None}

    try:
        session = mgr._create_session()
        base = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{vmid}/agent"

        try:
            resp = session.get(f"{base}/get-host-name", timeout=8)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('result', {})
                result['hostname'] = data.get('host-name')
                result['agent_running'] = True
            elif resp.status_code == 500 and 'not running' in (resp.text or '').lower():
                # short-circuit: agent down, skip the 5 follow-up calls
                return jsonify(result)
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
                result['kernel_version'] = data.get('kernel-version')
                result['agent_running'] = True
        except Exception:
            pass

        # NS: #159 - reuse centralized IP fetch method
        try:
            ips = mgr._fetch_qemu_ips(node, vmid)
            result['ip_addresses'] = ips
            if ips:
                result['agent_running'] = True
        except Exception:
            pass

        # MK: per-NIC detail (name + MAC + IPs from inside the guest)
        try:
            resp = session.get(f"{base}/network-get-interfaces", timeout=8)
            if resp.status_code == 200:
                nics = resp.json().get('data', {}).get('result', []) or []
                ifaces = []
                for nic in nics:
                    nic_ips = [{'address': ip.get('ip-address'),
                                'family': ip.get('ip-address-type'),
                                'prefix': ip.get('prefix')}
                               for ip in (nic.get('ip-addresses') or [])]
                    ifaces.append({
                        'name': nic.get('name'),
                        'mac': nic.get('hardware-address'),
                        'ips': nic_ips,
                    })
                result['interfaces'] = ifaces
        except Exception:
            pass

        # MK: filesystems with real fill — same data as /guest-fsinfo, mirrored
        # here so the detail panel does one round-trip instead of two.
        try:
            resp = session.get(f"{base}/get-fsinfo", timeout=8)
            if resp.status_code == 200:
                fsraw = resp.json().get('data', {}).get('result', []) or []
                fslist = []
                for fs in fsraw:
                    total = fs.get('total-bytes'); used = fs.get('used-bytes')
                    mt = fs.get('mountpoint')
                    if not mt:
                        continue
                    pct = round((used / total) * 100, 1) if (isinstance(total,(int,float)) and total > 0 and isinstance(used,(int,float))) else None
                    fslist.append({
                        'name': fs.get('name'),
                        'mountpoint': mt,
                        'type': fs.get('type'),
                        'used_bytes': used,
                        'total_bytes': total,
                        'used_pct': pct,
                    })
                result['filesystems'] = fslist
        except Exception:
            pass

        # MK: logged-in users — "who's on this VM right now"
        try:
            resp = session.get(f"{base}/get-users", timeout=8)
            if resp.status_code == 200:
                ur = resp.json().get('data', {}).get('result', []) or []
                if isinstance(ur, list):
                    result['users'] = [{'user': u.get('user'),
                                        'domain': u.get('domain'),
                                        'login_time': u.get('login-time')}
                                       for u in ur]
        except Exception:
            pass

        # MK: guest clock vs host (ns since epoch) — ntp sanity check
        try:
            resp = session.get(f"{base}/get-time", timeout=8)
            if resp.status_code == 200:
                t = resp.json().get('data', {}).get('result')
                if isinstance(t, (int, float)):
                    result['guest_time_ns'] = t
        except Exception:
            pass

    except Exception as e:
        result['error'] = str(e)

    return jsonify(result)


# MK #334 — surface the guest agent's fsinfo so scripts can monitor mountpoint
# usage without having to call both PegaProx + Proxmox. Returns [] + agent_running=False
# when the agent isn't installed / the VM isn't running — callers treat it as "no data".
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/guest-fsinfo', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_guest_fsinfo_api(cluster_id, node, vm_type, vmid):
    """Proxy for qemu-agent get-fsinfo — list mounted filesystems with used/total bytes."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    # LXC doesn't speak qemu-agent — no-op response keeps the frontend uniform
    if vm_type != 'qemu':
        return jsonify({'agent_running': False, 'filesystems': [], 'reason': 'lxc_not_supported'}), 200

    mgr = cluster_managers[cluster_id]
    payload = {'agent_running': False, 'filesystems': [], 'reason': None}

    try:
        session = mgr._create_session()
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{vmid}/agent/get-fsinfo"
        resp = session.get(url, timeout=10)
        if resp.status_code == 200:
            data = (resp.json().get('data') or {}).get('result') or []
            out = []
            for fs in data:
                total = fs.get('total-bytes')
                used = fs.get('used-bytes')
                mount = fs.get('mountpoint')
                if not mount:
                    continue
                pct = None
                if isinstance(total, (int, float)) and total > 0 and isinstance(used, (int, float)):
                    pct = round((used / total) * 100, 1)
                out.append({
                    'name': fs.get('name'),
                    'mountpoint': mount,
                    'type': fs.get('type'),
                    'used_bytes': used,
                    'total_bytes': total,
                    'used_pct': pct,
                })
            payload['agent_running'] = True
            payload['filesystems'] = out
        elif resp.status_code == 500:
            # Proxmox returns 500 with "QEMU guest agent is not running" in body
            body = (resp.text or '').lower()
            if 'not running' in body or 'not installed' in body:
                payload['reason'] = 'agent_not_running'
            else:
                payload['reason'] = f'proxmox_{resp.status_code}'
        else:
            payload['reason'] = f'proxmox_{resp.status_code}'
    except Exception as e:
        payload['reason'] = f'error: {e}'

    return jsonify(payload)


# NS May 2026 — read a file from a running VM via the qemu-guest-agent.
# PVE 9.2 added optional `count`, `offset`, `decode` (base64) params so you
# can stream large files in chunks without dragging the whole thing through
# memory. We pass them through; older PVE silently ignores extras.
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/guest-file-read', methods=['POST'])
@require_auth(perms=['vm.view'])
def get_vm_guest_file_read_api(cluster_id, node, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    if vm_type != 'qemu':
        return jsonify({'error': 'Guest-agent file-read is QEMU-only'}), 400

    mgr = cluster_managers[cluster_id]
    body = request.json or {}
    file_path = body.get('file')
    if not file_path:
        return jsonify({'error': 'file path required'}), 400

    params = {'file': file_path}
    # 9.2 optional params — accept ints + a base64 toggle
    for k in ('count', 'offset'):
        if k in body and body[k] not in (None, ''):
            try:
                params[k] = int(body[k])
            except (TypeError, ValueError):
                return jsonify({'error': f'{k} must be an integer'}), 400
    if body.get('decode'):
        # PVE expects '1' / '0', accept boolean or string
        params['decode'] = 1 if body['decode'] in (True, 1, '1', 'true') else 0

    try:
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{vmid}/agent/file-read"
        resp = mgr._api_post(url, data=params)
        if resp.status_code == 200:
            data = (resp.json().get('data') or {})
            return jsonify({
                'content': data.get('content'),
                'truncated': bool(data.get('truncated', False)),
                'bytes_read': data.get('bytes-read') or data.get('content-size'),
            })
        return jsonify({'error': resp.text or f'HTTP {resp.status_code}'}), resp.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


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

    manager = cluster_managers[cluster_id]

    # MK: Check pool permission for vm.config (+ xapi.vm.config for XCP-ng)
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']

    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        from pegaprox.utils.rbac import has_permission
        if not has_permission(user, 'xapi.vm.config'):
            return jsonify({'error': 'Permission denied: xapi.vm.config'}), 403
    else:
        if not user_can_access_vm(user, cluster_id, vmid, 'vm.config', vm_type):
            return jsonify({'error': 'Permission denied: vm.config'}), 403

    config_updates = request.json or {}

    result = manager.update_vm_config(node, vmid, vm_type, config_updates)

    if result['success']:
        # NS: Broadcast VM config change via SSE for live UI updates
        try:
            updated_config = manager.get_vm_config(node, vmid, vm_type)
            # XCP-ng returns flat dict, Proxmox wraps in {'success': ..., 'config': ...}
            if isinstance(updated_config, dict):
                cfg = updated_config.get('config', updated_config)
                broadcast_sse('vm_config', {
                    'vmid': vmid, 'node': node,
                    'vm_type': vm_type, 'config': cfg
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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/nodes/{node}/hardware/pci"
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
        return jsonify({'error': safe_error(e, 'Failed to get PCI devices')}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/nodes/{node}/hardware/usb"
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
        return jsonify({'error': safe_error(e, 'Failed to get USB devices')}), 500


# MK May 2026 — Recover the QEMU --args after the user changed disk bus type
# (scsi0 → sata0 etc.) via the Proxmox UI. The static sector-size args we wrote
# at V2P-migration time reference the original bus, so QEMU refuses to start
# ("there is no device 'scsi0' defined"). This endpoint reads the current VM
# config, regenerates the matching -set device.<bus><idx>.{logical,physical}_block_size
# from the actual disk attachments, and writes them back via `qm set --args`.
# No node-side artifacts (deliberately not a hookscript), one-shot recovery.
@bp.route('/api/clusters/<cluster_id>/vms/<node>/qemu/<int:vmid>/fix-args', methods=['POST'])
@require_auth(perms=['vm.config'])
def fix_vm_qemu_args(cluster_id, node, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    try:
        from pegaprox.core.v2p import _rebuild_sector_args
        changed, new_args, problem = _rebuild_sector_args(manager, node, vmid)
        if problem:
            return jsonify({'ok': False, 'error': problem, 'args': new_args}), 400
        log_audit(request.session.get('user', 'admin'), 'vm.fix_args',
                  f'vmid={vmid} node={node} cluster={cluster_id} changed={changed}')
        return jsonify({
            'ok': True,
            'changed': changed,
            'args': new_args,
            'message': 'args updated' if changed else 'args already match current disks'
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': safe_error(e)}), 500


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
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
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
        return jsonify({'error': safe_error(e, 'Failed to get passthrough devices')}), 500


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
        host, port = manager.host, manager.api_port
        
        # Find next available hostpci slot
        config_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
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
        update_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {f'hostpci{next_slot}': pci_config}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.pci_added', f"VM {vmid}: Added PCI device {device_id} at slot {next_slot}", cluster=manager.config.name)
            return jsonify({'message': f'PCI device added at hostpci{next_slot}', 'slot': next_slot})
        else:
            return jsonify({'error': parse_pve_error(response.text)}), 500
            
    except Exception as e:
        logging.error(f"Error adding PCI passthrough: {e}")
        return jsonify({'error': safe_error(e, 'Failed to add PCI passthrough')}), 500


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
        host, port = manager.host, manager.api_port
        
        # Find next available usb slot
        config_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
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
        update_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {f'usb{next_slot}': usb_config}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.usb_added', f"VM {vmid}: Added USB device at slot {next_slot}", cluster=manager.config.name)
            return jsonify({'message': f'USB device added at usb{next_slot}', 'slot': next_slot})
        else:
            return jsonify({'error': parse_pve_error(response.text)}), 500
            
    except Exception as e:
        logging.error(f"Error adding USB passthrough: {e}")
        return jsonify({'error': safe_error(e, 'Failed to add USB passthrough')}), 500


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
        host, port = manager.host, manager.api_port
        
        # Find next available serial slot
        config_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
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
        update_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {f'serial{next_slot}': serial_type}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, 'vm.serial_added', f"VM {vmid}: Added serial port at slot {next_slot}", cluster=manager.config.name)
            return jsonify({'message': f'Serial port added at serial{next_slot}', 'slot': next_slot})
        else:
            return jsonify({'error': parse_pve_error(response.text)}), 500
            
    except Exception as e:
        logging.error(f"Error adding serial port: {e}")
        return jsonify({'error': safe_error(e, 'Failed to add serial port')}), 500


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
        host, port = manager.host, manager.api_port
        
        # Delete by setting to empty/delete
        update_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
        update_data = {'delete': key}
        response = manager._create_session().put(update_url, data=update_data, timeout=15)
        
        if response.status_code == 200:
            user = getattr(request, 'session', {}).get('user', 'system')
            log_audit(user, f'vm.{device_type}_removed', f"VM {vmid}: Removed {key}", cluster=manager.config.name)
            return jsonify({'message': f'Device {key} removed'})
        else:
            return jsonify({'error': parse_pve_error(response.text)}), 500
            
    except Exception as e:
        logging.error(f"Error removing passthrough device: {e}")
        return jsonify({'error': safe_error(e, 'Failed to remove passthrough device')}), 500


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


# LW May 2026 — snapshot config + diff endpoints. Backs the Snapshot Comparison
# UI: pick two snapshots of the same VM, see config-level diff.
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshots/<snapname>/config', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_snapshot_config_api(cluster_id, node, vm_type, vmid, snapname):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster offline'}), 503
    if vm_type not in ('qemu', 'lxc'):
        return jsonify({'error': 'Invalid vm_type'}), 400
    try:
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot/{snapname}/config"
        r = mgr._api_get(url)
        if r is None or r.status_code != 200:
            return jsonify({'error': f'Failed to fetch snapshot config (status {getattr(r, "status_code", "?")})'}), 502
        return jsonify(r.json().get('data', {}) or {})
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/snapshots/diff', methods=['GET'])
@require_auth(perms=['vm.view'])
def diff_snapshots_api(cluster_id, node, vm_type, vmid):
    """Compare two snapshot configs. Query: ?a=<snapA>&b=<snapB>"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    a = (request.args.get('a') or '').strip()
    b = (request.args.get('b') or '').strip()
    if not a or not b:
        return jsonify({'error': 'Both ?a and ?b query params are required'}), 400
    # disallow path-traversal-ish stuff
    for s in (a, b):
        if '/' in s or '\x00' in s or len(s) > 64:
            return jsonify({'error': 'Invalid snapshot name'}), 400

    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster offline'}), 503
    if vm_type not in ('qemu', 'lxc'):
        return jsonify({'error': 'Invalid vm_type'}), 400

    def _fetch(snap):
        # 'current' is a synthetic name in PVE — request via ?current=1 endpoint
        if snap.lower() == 'current':
            url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/config?current=1"
        else:
            url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot/{snap}/config"
        r = mgr._api_get(url)
        if r is None or r.status_code != 200:
            return None, f'fetch failed for {snap} (status {getattr(r, "status_code", "?")})'
        return r.json().get('data') or {}, None

    cfg_a, err_a = _fetch(a)
    if err_a:
        return jsonify({'error': err_a}), 502
    cfg_b, err_b = _fetch(b)
    if err_b:
        return jsonify({'error': err_b}), 502

    keys = sorted(set(cfg_a.keys()) | set(cfg_b.keys()))
    diffs = []
    for k in keys:
        va = cfg_a.get(k)
        vb = cfg_b.get(k)
        if va == vb:
            kind = 'same'
        elif k not in cfg_a:
            kind = 'added'
        elif k not in cfg_b:
            kind = 'removed'
        else:
            kind = 'changed'
        diffs.append({'key': k, 'a': va, 'b': vb, 'kind': kind})

    summary = {
        'added':   sum(1 for d in diffs if d['kind'] == 'added'),
        'removed': sum(1 for d in diffs if d['kind'] == 'removed'),
        'changed': sum(1 for d in diffs if d['kind'] == 'changed'),
        'same':    sum(1 for d in diffs if d['kind'] == 'same'),
    }
    return jsonify({
        'a': a, 'b': b,
        'config_a': cfg_a, 'config_b': cfg_b,
        'diffs': diffs,
        'summary': summary,
    })


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
    from pegaprox.utils.concurrent import run_concurrent
    user = request.session.get('user', '')
    users_db = load_users()
    user_data = users_db.get(user, {})
    user_data['username'] = user
    data = request.get_json(silent=True) or {}
    # NS: don't filter by date unless user explicitly sets one — old default hid today's snapshots
    date_filter = data.get("date")
    filter_limit = data.get("limit", 200)
    filter_cluster = data.get("cluster_id")
    is_admin = user_data.get('role') == ROLE_ADMIN
    user_clusters = user_data.get('clusters', [])

    cutoff_date = None
    if date_filter:
        try:
            cutoff_date = datetime.strptime(date_filter, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    all_vms = []
    for cluster_id, mgr in cluster_managers.items():
        if not mgr.is_connected:
            continue
        if filter_cluster and cluster_id != filter_cluster:
            continue
        if not is_admin and user_clusters and cluster_id not in user_clusters:
            continue
        try:
            for r in mgr.get_vm_resources():
                vmid = r.get('vmid')
                node = r.get('node')
                if vmid and node:
                    all_vms.append((cluster_id, node, vmid, r.get('name', ''), r.get('type', 'qemu')))
        except Exception as e:
            logging.warning(f"[Snapshots] Failed to list VMs for {cluster_id}: {e}")

    # MK: fetch snapshots in parallel instead of sequential — huge speedup
    def _fetch_snap(args):
        cid, node, vmid, vm_name, vm_type = args
        try:
            mgr = cluster_managers.get(cid)
            if not mgr:
                return []
            raw = mgr.get_snapshots(node, vmid, vm_type)
            results = []
            now = datetime.now(timezone.utc)
            for snap in raw:
                snap_name = snap.get('name')
                snap_ts = snap.get('snaptime')
                if not snap_name or not snap_ts or snap_name == 'current':
                    continue
                snap_dt = datetime.fromtimestamp(snap_ts, tz=timezone.utc)
                if cutoff_date and snap_dt >= cutoff_date:
                    continue
                age_s = int((now - snap_dt).total_seconds())
                age = f"{age_s // 60} min" if age_s < 3600 else f"{age_s // 3600} h" if age_s < 86400 else f"{age_s // 86400} days"
                results.append({
                    "vmid": vmid, "vm_name": vm_name, "vm_type": vm_type, "node": node,
                    "snapshot_name": snap_name, "snapshot_date": snap_dt.strftime('%Y-%m-%d %H:%M'),
                    "age": age, "cluster_id": cid
                })
            return results
        except Exception:
            return []

    tasks = [lambda a=vm: _fetch_snap(a) for vm in all_vms]
    parallel_results = run_concurrent(tasks, timeout=25.0)

    snapshots = []
    for batch in parallel_results:
        if batch:
            snapshots.extend(batch)

    snapshots.sort(key=lambda s: s["snapshot_date"], reverse=False)
    snapshots = snapshots[:filter_limit]

    return jsonify({"snapshots": snapshots})


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
# NS: Mar 2026 - same-cluster snapshot replication for non-ZFS storage (#103)
# Proxmox native replication needs ZFS, this works with any storage backend
# Flow: snapshot -> clone to target storage -> migrate clone to target node -> cleanup
def _execute_local_replication(job):
    """Run snapshot-based replication within the same cluster (no ZFS needed)."""
    db = get_db()
    job_id = job['id']
    vmid = int(job['vmid'])
    vm_type = job.get('vm_type', 'qemu') or 'qemu'
    cluster_id = job['source_cluster']
    target_node = job.get('target_node', '')
    target_storage = job.get('target_storage', '') or 'local-lvm'

    mgr = cluster_managers.get(cluster_id)
    if not mgr:
        _update_repl_status(db, job_id, 'error', 'Cluster not found')
        return

    if not mgr.is_connected:
        _update_repl_status(db, job_id, 'error', 'Cluster not connected')
        return

    snap_name = f"repl-{job_id}-{int(time.time())}"
    clone_vmid = None
    source_node = None

    try:
        # 1. find source node
        res = mgr._api_get(
            f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/resources",
            params={'type': 'vm'}
        )
        if res.status_code == 200:
            for r in res.json().get('data', []):
                if int(r.get('vmid', 0)) == vmid:
                    source_node = r.get('node')
                    break

        if not source_node:
            _update_repl_status(db, job_id, 'error', f'VM {vmid} not found')
            return

        if not target_node:
            _update_repl_status(db, job_id, 'error', 'No target node configured')
            return

        logging.info(f"[REPL] Job {job_id}: replicating {vm_type}/{vmid} from {source_node} to {target_node}")

        # 2. create snapshot
        snap_url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{source_node}/{vm_type}/{vmid}/snapshot"
        snap_resp = mgr._api_post(snap_url, data={
            'snapname': snap_name,
            'description': f'Snapshot replication {job_id}'
        })
        if snap_resp.status_code != 200:
            _update_repl_status(db, job_id, 'error', f'Snapshot failed: {snap_resp.text}')
            return

        snap_task = snap_resp.json().get('data')
        snap_ok, snap_detail = _wait_for_task(mgr, snap_task)
        if not snap_ok:
            _update_repl_status(db, job_id, 'error', f'Snapshot failed: {snap_detail}')
            return

        # 3. get next free VMID
        nextid_resp = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/nextid")
        if nextid_resp.status_code != 200:
            _cleanup_snapshot(mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', 'Could not get next VMID')
            return

        clone_vmid = int(nextid_resp.json().get('data'))

        # 4. clone — check storage type for snapshot compatibility (#192)
        clone_url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{source_node}/{vm_type}/{vmid}/clone"
        # MK: verified against PVE storage plugins (copy+snap feature matrix)
        # rbd DOES support snap clone. lvm only supports qcow2 snap clone (VMs are raw).
        # zfs (iSCSI) and zfspool (local) both lack snap support. LXC uses rsync, not affected.
        _no_snap_clone_types = {'zfspool', 'zfs', 'lvm', 'iscsi', 'iscsidirect'}
        use_snap_clone = True
        try:
            stor_resp = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/storage")
            if stor_resp.status_code == 200:
                stor_types = {s['storage']: s.get('type', '') for s in stor_resp.json().get('data', [])}
                vm_stor = mgr._get_vm_storage(source_node, vmid, vm_type)
                if vm_type == 'qemu' and vm_stor and stor_types.get(vm_stor) in _no_snap_clone_types:
                    use_snap_clone = False
                    logging.info(f"[REPL] Storage '{vm_stor}' is {stor_types.get(vm_stor)} — direct clone (#192)")
        except:
            pass

        # MK May 2026 (#448) — same hostname-vs-name fix as the xcrepl path.
        clone_data = {
            'newid': clone_vmid,
            'full': 1,
        }
        clone_label = f'repl-{vmid}-{target_node}'
        if vm_type == 'lxc':
            clone_data['hostname'] = clone_label
        else:
            clone_data['name'] = clone_label
        if use_snap_clone:
            clone_data['snapname'] = snap_name
        if target_storage:
            clone_data['storage'] = target_storage

        clone_resp = mgr._api_post(clone_url, data=clone_data)
        if clone_resp.status_code != 200:
            _cleanup_snapshot(mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', f'Clone failed: {clone_resp.text}')
            return

        clone_task = clone_resp.json().get('data')
        clone_ok, clone_detail = _wait_for_task(mgr, clone_task, timeout=1800)
        if not clone_ok:
            _cleanup_snapshot(mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', f'Clone failed: {clone_detail}')
            return

        logging.info(f"[REPL] Job {job_id}: clone {clone_vmid} created")

        # 5. migrate clone to target node (if on different node)
        if source_node != target_node:
            mig_result = mgr.migrate_vm_manual(
                node=source_node, vmid=clone_vmid, vm_type=vm_type,
                target_node=target_node, online=False,
                options={'targetstorage': target_storage} if target_storage else {}
            )
            if not mig_result.get('success'):
                # cleanup clone + snap
                _cleanup_clone_and_snap(mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
                _update_repl_status(db, job_id, 'error', f'Migration failed: {mig_result.get("error")}')
                return

            mig_task = mig_result.get('task')
            if mig_task:
                mig_ok, mig_detail = _wait_for_task(mgr, mig_task, timeout=3600)
                if not mig_ok:
                    _cleanup_clone_and_snap(mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
                    _update_repl_status(db, job_id, 'error', f'Migration failed: {mig_detail}')
                    return

        logging.info(f"[REPL] Job {job_id}: clone migrated to {target_node}")

        # 6. delete old replica if exists, rename new one
        # check for previous replica VMs with name pattern repl-{vmid}-{target_node}
        try:
            all_vms = mgr._api_get(
                f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/resources",
                params={'type': 'vm'}
            )
            if all_vms.status_code == 200:
                for v in all_vms.json().get('data', []):
                    vname = v.get('name', '')
                    vid = int(v.get('vmid', 0))
                    # delete previous replicas but not the one we just created
                    if vname == f'repl-{vmid}-{target_node}' and vid != clone_vmid:
                        old_node = v.get('node', target_node)
                        try:
                            # stop if running
                            if v.get('status') == 'running':
                                mgr._api_post(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{old_node}/{vm_type}/{vid}/status/stop", data={})
                                time.sleep(5)
                            mgr._api_delete(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{old_node}/{vm_type}/{vid}")
                            logging.info(f"[REPL] Deleted old replica VM {vid}")
                        except Exception as del_e:
                            logging.warning(f"[REPL] Could not delete old replica {vid}: {del_e}")
        except Exception:
            pass

        # 7. cleanup snapshot on source
        _cleanup_snapshot(mgr, source_node, vmid, vm_type, snap_name)
        _update_repl_status(db, job_id, 'ok', '')
        logging.info(f"[REPL] Job {job_id}: replication complete")

    except Exception as e:
        logging.error(f"[REPL] Job {job_id}: error: {e}")
        _update_repl_status(db, job_id, 'error', str(e))
        if clone_vmid:
            try:
                _cleanup_clone_and_snap(mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
            except Exception:
                pass


# MK: Feb 2026 - snapshot-based replication between clusters
# Proxmox native replication only works intra-cluster, so for DR across
# separate clusters we use snapshot + clone + remote-migrate approach.

# MK May 2026 (#456 @DarmokNoob) — net interface MAC tokens vary by VM type:
# LXC uses `hwaddr=<mac>`, QEMU uses `<model>=<mac>` where model is virtio/e1000/etc.
_QEMU_NIC_MODELS = ('virtio', 'e1000', 'e1000-82540em', 'e1000-82544gc', 'e1000-82545em',
                    'e1000e', 'i82551', 'i82557b', 'i82559er', 'ne2k_isa', 'ne2k_pci',
                    'pcnet', 'rtl8139', 'vmxnet3')


def _extract_nic_mac(nic_value):
    """Return the MAC from a PVE net interface config string (or None)."""
    if not isinstance(nic_value, str):
        return None
    for part in nic_value.split(','):
        if '=' not in part:
            continue
        key, val = part.split('=', 1)
        if key == 'hwaddr':
            return val
        if key in _QEMU_NIC_MODELS:
            return val
    return None


def _swap_nic_mac(nic_value, new_mac):
    """Rewrite a PVE net interface config to use new_mac, preserving every other token."""
    if not isinstance(nic_value, str) or not new_mac:
        return nic_value
    parts = []
    replaced = False
    for part in nic_value.split(','):
        if '=' not in part:
            parts.append(part)
            continue
        key, val = part.split('=', 1)
        if key == 'hwaddr':
            parts.append(f'hwaddr={new_mac}')
            replaced = True
        elif key in _QEMU_NIC_MODELS:
            parts.append(f'{key}={new_mac}')
            replaced = True
        else:
            parts.append(part)
    return ','.join(parts) if replaced else nic_value


def _capture_vm_identity(mgr, node, vmid, vm_type):
    """Pull hostname/name + per-NIC MAC from a VM's config so the xcrepl flow can
    restore them on the target replica after clone+migrate destroyed both."""
    out = {'hostname': None, 'name': None, 'nets': {}}
    try:
        cfg_url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/config"
        resp = mgr._api_get(cfg_url)
        if resp.status_code != 200:
            logging.debug(f"[XCREPL] _capture_vm_identity: GET {cfg_url} -> {resp.status_code}")
            return out
        cfg = resp.json().get('data', {})
        if vm_type == 'lxc':
            out['hostname'] = cfg.get('hostname')
        else:
            out['name'] = cfg.get('name')
        for k, v in cfg.items():
            if k.startswith('net') and k[3:].isdigit():
                mac = _extract_nic_mac(v)
                if mac:
                    out['nets'][k] = mac
    except Exception as e:
        logging.debug(f"[XCREPL] _capture_vm_identity error: {e}")
    return out


def _restore_vm_identity(mgr, node, vmid, vm_type, identity):
    """Apply the source's hostname/name + per-NIC MAC to a freshly-migrated replica.

    Reads the target's current net config so we preserve bridge / firewall / VLAN-tag /
    rate-limit tokens that the migration set — only the MAC token gets swapped back to
    the source value.
    """
    if not identity:
        return
    cfg_url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/config"
    payload = {}

    if vm_type == 'lxc' and identity.get('hostname'):
        payload['hostname'] = identity['hostname']
    elif vm_type == 'qemu' and identity.get('name'):
        payload['name'] = identity['name']

    if identity.get('nets'):
        try:
            cur_resp = mgr._api_get(cfg_url)
            if cur_resp.status_code == 200:
                cur_cfg = cur_resp.json().get('data', {})
                for netname, src_mac in identity['nets'].items():
                    cur_val = cur_cfg.get(netname)
                    if cur_val:
                        rebuilt = _swap_nic_mac(cur_val, src_mac)
                        if rebuilt != cur_val:
                            payload[netname] = rebuilt
        except Exception as e:
            logging.debug(f"[XCREPL] could not read target config for MAC restore: {e}")

    if not payload:
        return

    put_resp = mgr._api_put(cfg_url, data=payload)
    if put_resp.status_code == 200:
        logging.info(f"[XCREPL] Restored identity on {vm_type}/{vmid}: "
                     f"{'hostname' if vm_type == 'lxc' else 'name'}={payload.get('hostname') or payload.get('name')}, "
                     f"{sum(1 for k in payload if k.startswith('net'))} NIC(s) MAC-swapped")
    else:
        logging.warning(f"[XCREPL] Identity PUT returned {put_resp.status_code}: {put_resp.text[:200]}")


# MK May 2026 (#413 @blackshocks) — Replica safety gate. The earlier xcrepl flow
# deleted any VM on the target that happened to share the source VMID, on the
# assumption that the VMID-collision had to be a previous run of this same job.
# Real-world scenario: two freshly-paired clusters where the target already had
# an UNRELATED VM at the same VMID — the delete destroyed user data.
#
# Replicas are now tagged with a job-specific marker after a successful migration,
# and the safety gate refuses to delete anything that isn't tagged for THIS job.
# That also prevents cross-job blast: two unrelated xcrepl jobs colliding on the
# same target VMID won't nuke each other's replicas.
PEGAPROX_REPLICA_TAG = 'pegaprox-replica'


def _job_tag(job_id):
    return f'xcrepl-job-{job_id}'


def _read_target_tags(mgr, node, vmid, vm_type):
    """Return the set of tags on a VM, or None if config fetch failed."""
    try:
        cfg_url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/config"
        resp = mgr._api_get(cfg_url)
        if resp.status_code != 200:
            return None
        cfg = resp.json().get('data', {})
        tags_raw = cfg.get('tags', '') or ''
        # PVE separates tags by ';' for both LXC and QEMU.
        return {t.strip() for t in tags_raw.split(';') if t.strip()}
    except Exception:
        return None


def _is_replica_of_job(mgr, node, vmid, vm_type, job_id):
    """True iff the target VM is tagged as a replica of THIS specific xcrepl job."""
    tags = _read_target_tags(mgr, node, vmid, vm_type)
    if tags is None:
        return False
    return _job_tag(job_id) in tags


def _tag_as_replica(mgr, node, vmid, vm_type, job_id):
    """Mark the freshly-migrated replica with the job-specific + general
    pegaprox-replica tags. Preserves any pre-existing tags so users' own
    organisation tags stay intact."""
    cfg_url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/config"
    try:
        resp = mgr._api_get(cfg_url)
        if resp.status_code != 200:
            return
        cfg = resp.json().get('data', {})
        tags_raw = cfg.get('tags', '') or ''
        existing = [t.strip() for t in tags_raw.split(';') if t.strip()]
        want = [PEGAPROX_REPLICA_TAG, _job_tag(job_id)]
        merged = list(existing)
        for t in want:
            if t not in merged:
                merged.append(t)
        if merged == existing:
            return  # nothing to do
        new_tags = ';'.join(merged)
        put = mgr._api_put(cfg_url, data={'tags': new_tags})
        if put.status_code == 200:
            logging.info(f"[XCREPL] Tagged replica {vm_type}/{vmid} on {node} with {want}")
        else:
            logging.warning(f"[XCREPL] tag PUT returned {put.status_code}: {put.text[:200]}")
    except Exception as e:
        logging.warning(f"[XCREPL] Could not tag replica {vmid}: {e}")


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
    target_node = job.get('target_node', '')

    source_mgr = cluster_managers.get(source_cid)
    target_mgr = cluster_managers.get(target_cid)

    if not source_mgr or not target_mgr:
        _update_repl_status(db, job_id, 'error', 'Source or target cluster not found')
        return

    if not source_mgr.is_connected or not target_mgr.is_connected:
        _update_repl_status(db, job_id, 'error', 'Cluster not connected')
        return

    # NS: auto-detect target node if not configured
    if not target_node:
        try:
            nodes_resp = target_mgr._api_get(
                f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/nodes"
            )
            if nodes_resp.status_code == 200:
                for n in nodes_resp.json().get('data', []):
                    if n.get('status') == 'online':
                        target_node = n['node']
                        break
        except Exception:
            pass
        if not target_node:
            _update_repl_status(db, job_id, 'error', 'No online node found on target cluster')
            return

    snap_name = f"xcrepl-{job_id}-{int(time.time())}"
    clone_vmid = None

    try:
        # 1. find which node the VM lives on
        source_node = None
        resources = source_mgr._api_get(
            f"https://{source_mgr.host}:{source_mgr.api_port}/api2/json/cluster/resources",
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

        logging.info(f"[XCREPL] Job {job_id}: replicating {vm_type}/{vmid} from {source_node} -> {target_node} ({target_cid})")

        # MK May 2026 (#456 @DarmokNoob) — capture source identity (hostname/name +
        # per-NIC hwaddr) BEFORE the clone overwrites the label and PVE re-rolls the MAC.
        # Replica is supposed to be a drop-in copy of the source for DR — the replica's
        # hostname + DHCP-MAC need to match or Site Recovery failover lands on the wrong
        # network identity.
        source_identity = _capture_vm_identity(source_mgr, source_node, vmid, vm_type)

        # 2. create snapshot
        snap_url = (
            f"https://{source_mgr.host}:{source_mgr.api_port}/api2/json/nodes/{source_node}"
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
        snap_ok, snap_detail = _wait_for_task(source_mgr, snap_task)
        if not snap_ok:
            _update_repl_status(db, job_id, 'error', f'Snapshot failed: {snap_detail}')
            return

        logging.info(f"[XCREPL] Job {job_id}: snapshot '{snap_name}' created")

        # 3. get next free VMID for clone
        nextid_resp = source_mgr._api_get(
            f"https://{source_mgr.host}:{source_mgr.api_port}/api2/json/cluster/nextid"
        )
        if nextid_resp.status_code != 200:
            _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', 'Could not get next VMID')
            return

        clone_vmid = int(nextid_resp.json().get('data'))
        logging.debug(f"[XCREPL] Using clone VMID {clone_vmid}")

        # 4. clone — detect storage type first to choose correct strategy (#192)
        # ZFS and RBD don't support full clone from snapshot, must clone directly
        clone_url = (
            f"https://{source_mgr.host}:{source_mgr.api_port}/api2/json/nodes/{source_node}"
            f"/{vm_type}/{vmid}/clone"
        )
        # MK: Apr 2026 — check if storage supports full clone from snapshot
        # MK: verified against PVE storage plugins (copy+snap feature matrix)
        # rbd DOES support snap clone. lvm only supports qcow2 snap clone (VMs are raw).
        # zfs (iSCSI) and zfspool (local) both lack snap support. LXC uses rsync, not affected.
        _no_snap_clone_types = {'zfspool', 'zfs', 'lvm', 'iscsi', 'iscsidirect'}
        use_snap_clone = True
        try:
            stor_resp = source_mgr._api_get(f"https://{source_mgr.host}:{source_mgr.api_port}/api2/json/storage")
            if stor_resp.status_code == 200:
                stor_types = {s['storage']: s.get('type', '') for s in stor_resp.json().get('data', [])}
                # get the VM's primary storage
                vm_stor = source_mgr._get_vm_storage(source_node, vmid, vm_type)
                if vm_type == 'qemu' and vm_stor and stor_types.get(vm_stor) in _no_snap_clone_types:
                    use_snap_clone = False
                    logging.info(f"[XCREPL] Storage '{vm_stor}' is {stor_types.get(vm_stor)} — using direct clone without snapshot (#192)")
        except Exception as e:
            logging.debug(f"[XCREPL] Could not detect storage type: {e}")

        # MK May 2026 (#448 @DarmokNoob) — PVE clone schema differs by VM type:
        # QEMU (`/qemu/{vmid}/clone`) accepts `name=` for the clone label;
        # LXC  (`/lxc/{vmid}/clone`)  rejects `name=` as "property is not
        # defined in schema" and wants `hostname=` instead. Confirmed via
        # pvesh + curl by the reporter. Earlier this function always sent
        # `name`, so every cross-cluster LXC DR job 400'd at the clone step.
        clone_data = {
            'newid': clone_vmid,
            'full': 1,
        }
        clone_label = f'xcrepl-{vmid}-tmp'
        if vm_type == 'lxc':
            clone_data['hostname'] = clone_label
        else:
            clone_data['name'] = clone_label
        if use_snap_clone:
            clone_data['snapname'] = snap_name

        clone_resp = source_mgr._api_post(clone_url, data=clone_data)
        if clone_resp.status_code != 200:
            _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', f'Clone failed: {clone_resp.text}')
            return

        clone_task = clone_resp.json().get('data')
        clone_ok, clone_detail = _wait_for_task(source_mgr, clone_task, timeout=1800)
        if not clone_ok:
            _cleanup_snapshot(source_mgr, source_node, vmid, vm_type, snap_name)
            _update_repl_status(db, job_id, 'error', f'Clone failed: {clone_detail}')
            return

        logging.info(f"[XCREPL] Job {job_id}: clone {clone_vmid} created from snapshot")

        # 5. build storage mapping from clone's actual disks -> target storage
        # NS Mar 2026: PVE remote_migrate needs "source_stor:target_stor" format
        # when source and target storage names differ (#192)
        storage_mapping = target_storage  # fallback: plain name
        try:
            cfg_url = f"https://{source_mgr.host}:{source_mgr.api_port}/api2/json/nodes/{source_node}/{vm_type}/{clone_vmid}/config"
            cfg_resp = source_mgr._api_get(cfg_url)
            if cfg_resp.status_code == 200:
                clone_cfg = cfg_resp.json().get('data', {})
                source_storages = set()
                for k, v in clone_cfg.items():
                    if k.startswith(('scsi', 'virtio', 'ide', 'sata', 'efidisk', 'tpmstate', 'rootfs', 'mp')) and isinstance(v, str) and ':' in v:
                        stor = v.split(':')[0]
                        if stor and stor != 'none':
                            source_storages.add(stor)
                if source_storages:
                    # map each source storage to the target
                    mappings = [f"{s}:{target_storage}" for s in source_storages]
                    storage_mapping = ','.join(mappings)
                    logging.info(f"[XCREPL] Job {job_id}: storage mapping: {storage_mapping}")
        except Exception as e:
            logging.warning(f"[XCREPL] Job {job_id}: could not build storage mapping, using plain: {e}")

        # remote-migrate clone to target cluster
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

            # NS Apr 2026: #321 - second+ replication run fails because VM exists on target.
            # A replication job's whole point is to REPLACE the old copy, so remove it here
            # before remote_migrate tries to create-from-empty (which errors on existing VMID).
            existing_target_node = None
            try:
                tgt_res = target_mgr._api_get(
                    f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/cluster/resources",
                    params={'type': 'vm'}
                )
                if tgt_res.status_code == 200:
                    for r in tgt_res.json().get('data', []):
                        if int(r.get('vmid', 0)) == vmid:
                            existing_target_node = r.get('node')
                            break
            except Exception as e:
                logging.warning(f"[XCREPL] Job {job_id}: target existence check failed: {e}")

            if existing_target_node:
                # MK May 2026 (#413 @blackshocks) — refuse to delete unless the existing
                # target VM is tagged as a replica of THIS job. Without this gate, freshly
                # paired clusters with an unrelated VM at the matching VMID lose data.
                if not _is_replica_of_job(target_mgr, existing_target_node, vmid, vm_type, job_id):
                    target_mgr.delete_api_token(token_name)
                    _cleanup_clone_and_snap(source_mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
                    err_msg = (f"Target VM {vmid} on node {existing_target_node} is not tagged as a replica "
                               f"of this job ({_job_tag(job_id)} tag missing). Refusing to overwrite to "
                               f"prevent data loss. If this is a stranded replica from a previous run or "
                               f"manual clone, tag it with `{_job_tag(job_id)}` and re-run. If it is an "
                               f"unrelated VM, pick a different target VMID for the job.")
                    _update_repl_status(db, job_id, 'error', err_msg)
                    logging.error(f"[XCREPL] Job {job_id}: ABORT — {err_msg}")
                    return

                logging.info(f"[XCREPL] Job {job_id}: VM {vmid} already on target node {existing_target_node}, removing old replica (tag verified)")
                try:
                    # stop first so PVE lets us delete it (ignore errors if already stopped)
                    stop_url = (
                        f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/nodes/{existing_target_node}"
                        f"/{vm_type}/{vmid}/status/stop"
                    )
                    try:
                        stop_resp = target_mgr._api_post(stop_url, data={})
                        if stop_resp.status_code == 200:
                            stop_task = stop_resp.json().get('data')
                            if stop_task:
                                _wait_for_task(target_mgr, stop_task, timeout=60)
                    except Exception:
                        pass

                    # delete the VM and its disks (purge removes replication jobs, destroy removes unreferenced disks)
                    del_url = (
                        f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/nodes/{existing_target_node}"
                        f"/{vm_type}/{vmid}"
                    )
                    del_resp = target_mgr._api_delete(del_url, params={'purge': 1, 'destroy-unreferenced-disks': 1})
                    if del_resp.status_code == 200:
                        del_task = del_resp.json().get('data')
                        if del_task:
                            del_ok, del_detail = _wait_for_task(target_mgr, del_task, timeout=600)
                            if not del_ok:
                                raise RuntimeError(f"delete task failed: {del_detail}")
                        logging.info(f"[XCREPL] Job {job_id}: old replica {vmid} removed from target")
                    else:
                        raise RuntimeError(f"delete request failed: {del_resp.status_code} {del_resp.text[:200]}")
                except Exception as e:
                    logging.error(f"[XCREPL] Job {job_id}: could not remove old replica: {e}")
                    target_mgr.delete_api_token(token_name)
                    _cleanup_clone_and_snap(source_mgr, source_node, clone_vmid, vmid, vm_type, snap_name)
                    _update_repl_status(db, job_id, 'error', f'Could not remove old replica on target: {e}')
                    return

            # migrate the clone (offline, delete source clone after)
            result = source_mgr.remote_migrate_vm(
                node=source_node, vmid=clone_vmid, vm_type=vm_type,
                target_endpoint=endpoint, target_storage=storage_mapping,
                target_bridge=target_bridge, target_vmid=vmid,
                online=False, delete_source=True,
            )

            if result.get('success'):
                mig_task = result.get('task')
                mig_ok, mig_detail = _wait_for_task(source_mgr, mig_task, timeout=3600)
                if mig_ok:
                    logging.info(f"[XCREPL] Job {job_id}: migration complete")
                    # MK May 2026 (#456) — restore source identity on the replica so
                    # DR failover lands on the right hostname + DHCP-MAC. Best-effort —
                    # don't fail the whole replication if this trips.
                    try:
                        _restore_vm_identity(target_mgr, target_node, vmid, vm_type, source_identity)
                    except Exception as e:
                        logging.warning(f"[XCREPL] Job {job_id}: identity restoration failed: {e}")
                    # MK May 2026 (#413) — tag the replica so the safety gate on the next
                    # run recognises it as ours and can cycle it without operator action.
                    try:
                        _tag_as_replica(target_mgr, target_node, vmid, vm_type, job_id)
                    except Exception as e:
                        logging.warning(f"[XCREPL] Job {job_id}: replica-tag write failed: {e}")
                    _update_repl_status(db, job_id, 'ok', '')
                else:
                    logging.error(f"[XCREPL] Job {job_id}: migration task failed: {mig_detail}")
                    _update_repl_status(db, job_id, 'error', f'Migration task failed: {mig_detail}')
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
    # MK May 2026 (audit completeness) — emit terminal audit event so the bundle's
    # audit_log captures the outcome of every xcrepl run, not just `replication.triggered`.
    # Mirrors the gap that surfaced via #438 on the v2p side: started-only audit forces
    # log archaeology on every silent-failure investigation.
    try:
        if status == 'ok':
            log_audit('system', 'replication.completed', f'xcrepl job {job_id} succeeded')
        elif status == 'error':
            log_audit('system', 'replication.failed',
                      f'xcrepl job {job_id} failed: {error or "no detail"}')
    except Exception:
        pass


def _wait_for_task(mgr, task_upid, timeout=600, poll=5):
    """Poll Proxmox task status until it finishes or times out.
    MK: similar to the cleanup thread logic but blocking.
    Returns (success: bool, detail: str) — detail has PVE status or error info.
    """
    if not task_upid:
        return (False, 'no task UPID')
    elapsed = 0
    while elapsed < timeout:
        try:
            tasks = mgr.get_tasks(limit=100)
            for t in tasks:
                if t and t.get('upid') == task_upid:
                    st = t.get('status', '')
                    if st and st != 'running':
                        ok = st in ('OK', 'WARNINGS')
                        detail = st if ok else (t.get('exitstatus') or st)
                        return (ok, detail)
                    break
        except Exception:
            pass
        time.sleep(poll)
        elapsed += poll
    return (False, f'timed out after {timeout}s')


def _cleanup_snapshot(mgr, node, vmid, vm_type, snap_name):
    """Delete a snapshot, best-effort, with NFS/ESTALE recovery.

    MK May 2026 (#422 depedro-ai): On NetApp / NFS qcow2 storage, the underlying
    `qemu-img snapshot -d` can fail with ESTALE ("Stale file handle") even
    though PVE issued the DELETE successfully. When that happens, PVE leaves
    the VM in `lock = snapshot-delete` state and refuses *all* subsequent
    operations (shutdown, migrate, failover) with "VM is locked
    (snapshot-delete)" — which is exactly the silent-failure depedro-ai hit.

    Fix: always pass `force=1` so PVE removes the snapshot config entry even
    if the on-disk delete fails. Then, if the VM is still locked afterwards
    (defence in depth), explicitly unlock via the PVE API. xcrepl snapshots
    are ours from end to end — operator never cares about the orphan .qcow2
    internal slot that may be left on storage; what matters is the VM gets
    out of the locked state cleanly.
    """
    url = (
        f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}"
        f"/{vm_type}/{vmid}/snapshot/{snap_name}"
    )
    try:
        # `force=1` tells PVE: remove config entry even if qemu-img delete fails.
        # Without it, NFS ESTALE → VM stuck at lock=snapshot-delete indefinitely.
        mgr._api_delete(url, params={'force': 1})
        logging.debug(f"[XCREPL] Deleted snapshot {snap_name} on {vmid} (force=1)")
    except Exception as e:
        logging.warning(f"[XCREPL] Could not delete snapshot {snap_name}: {e}")

    # Defence in depth: explicitly check + clear the lock if still set.
    # `qm unlock` via the API is `POST /nodes/<node>/<type>/<vmid>/status/current`
    # with `lock=` body — actually no, that's setting. The right one is the
    # config endpoint with `delete=lock`. Use that.
    try:
        cfg_url = (
            f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}"
            f"/{vm_type}/{vmid}/config"
        )
        cfg_resp = mgr._api_get(cfg_url)
        if cfg_resp is not None and cfg_resp.status_code == 200:
            cfg = (cfg_resp.json() or {}).get('data', {}) or {}
            current_lock = cfg.get('lock')
            if current_lock == 'snapshot-delete':
                logging.warning(
                    f"[XCREPL] VM {vmid} still locked at 'snapshot-delete' after cleanup — "
                    f"clearing lock so subsequent operations don't silently fail (#422)"
                )
                # PUT /config with delete=lock removes the lock field
                from pegaprox.utils.audit import log_audit
                try:
                    mgr._api_put(cfg_url, data={'delete': 'lock'})
                    log_audit(user='system', action='vm.unlock_after_xcrepl',
                              details=f'vmid={vmid} lock=snapshot-delete cleared after cross-cluster replication cleanup',
                              ip_address='127.0.0.1')
                except Exception as unlock_err:
                    logging.warning(f"[XCREPL] Could not auto-unlock VM {vmid}: {unlock_err}")
    except Exception as e:
        logging.debug(f"[XCREPL] Lock-state recheck on {vmid} failed (non-fatal): {e}")


def _cleanup_clone_and_snap(mgr, node, clone_vmid, orig_vmid, vm_type, snap_name):
    """Remove leftover clone VM + snapshot after failure."""
    # delete clone
    try:
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{clone_vmid}"
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
            f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/cluster/resources",
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
            f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/nodes/{target_node}"
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
                    f"https://{target_mgr.host}:{target_mgr.api_port}/api2/json/nodes/{target_node}"
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

    # NS: Mar 2026 - same-cluster snapshot replication for non-ZFS (Issue #103)
    # target_node required when source == target cluster
    target_node = data.get('target_node', '')
    if source_cluster == target_cluster and not target_node:
        return jsonify({'error': 'target_node is required for same-cluster replication'}), 400

    job_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    db = get_db()

    db.execute('''
        INSERT INTO cross_cluster_replications
        (id, source_cluster, target_cluster, vmid, vm_type, schedule, retention,
         target_storage, target_bridge, target_node, enabled, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
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
        target_node,
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

    # MK May 2026 (#455 @DarmokNoob) — block duplicate triggers while a previous
    # run is still in-flight. The scheduler uses the same _claim_job() guard.
    from pegaprox.background.cross_cluster_replication import _claim_job, _release_job, _tracked_run
    if not _claim_job(job_id):
        return jsonify({
            'error': 'Replication job is already running',
            'detail': 'Wait for the current run to finish, then retry.'
        }), 409

    # kick off in background so the API responds right away
    # NS: detect same-cluster -> use local replication
    job_dict = dict(job)
    is_local = job_dict.get('source_cluster') == job_dict.get('target_cluster')
    handler = _execute_local_replication if is_local else _execute_replication
    try:
        threading.Thread(target=_tracked_run, args=(handler, job_dict), daemon=True).start()
    except Exception as e:
        _release_job(job_id)
        return jsonify({'error': f'Failed to start replication: {e}'}), 500

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'replication.triggered', f"{'Local' if is_local else 'Cross-cluster'} replication {job_id} manually triggered")

    return jsonify({'success': True, 'message': 'Replication started'})


# NS: Mar 2026 - get snapshot replication jobs filtered by cluster (#103)
@bp.route('/api/clusters/<cluster_id>/snapshot-replications', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_snapshot_replications_for_cluster(cluster_id):
    """Get snapshot-based replication jobs where this cluster is source or target."""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    db = get_db()
    rows = db.query(
        'SELECT * FROM cross_cluster_replications WHERE source_cluster = ? OR target_cluster = ?',
        (cluster_id, cluster_id)
    )
    return jsonify([dict(r) for r in rows])


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
    host, port = manager.host, manager.api_port
    
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
            f"https://{host}:{port}/api2/json/access/ticket",
            data=login_data, method='POST'
        )
        
        with urllib.request.urlopen(login_req, context=ssl_context, timeout=10) as response:
            login_result = json.loads(response.read().decode('utf-8'))

        pve_ticket = login_result['data']['ticket']
        csrf_token = login_result['data']['CSRFPreventionToken']
        print(f"Got PVE ticket")

        # MK Apr 2026 (#352 follow-up) — single-vncproxy mode. If the JS
        # already got a vncproxy ticket+port via /console, reuse it so the VNC
        # password noVNC uses matches the password PVE's vncterm expects. PVE
        # 9.1.x generates fresh random VNC password per vncproxy call.
        pve_port_q = request.args.get('pve_port')
        pve_ticket_q = request.args.get('pve_ticket')
        if pve_port_q and pve_ticket_q:
            vnc_ticket = pve_ticket_q
            port = pve_port_q
            print(f"Reusing JS-issued vncproxy ticket port={port}")
        else:
            print(f"Step 2: Get VNC ticket...")
            if vm_type == 'qemu':
                vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
            else:
                vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
            vnc_data = urlencode({'websocket': '1'}).encode('utf-8')
            vnc_req = urllib.request.Request(vnc_url, data=vnc_data, method='POST')
            vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
            vnc_req.add_header('CSRFPreventionToken', csrf_token)
            with urllib.request.urlopen(vnc_req, context=ssl_context, timeout=10) as response:
                vnc_result = json.loads(response.read().decode('utf-8'))
            vnc_ticket = vnc_result['data']['ticket']
            port = vnc_result['data']['port']
            print(f"Got VNC ticket, port={port} (no JS pass-through — PVE 9.1.x users may hit issue #352)")
        
        # Step 3: Connect to Proxmox WebSocket
        print(f"Step 3: Connect to Proxmox...")
        encoded_vnc_ticket = url_quote(vnc_ticket, safe='')
        
        if vm_type == 'qemu':
            pve_ws_path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        else:
            pve_ws_path = f"/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        
        pve_ws_url = f"wss://{host}:{port}{pve_ws_path}"

        pve_ws = websocket.create_connection(
            pve_ws_url,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            header={"Cookie": f"PVEAuthCookie={pve_ticket}"},
            timeout=VNC_PVE_CONNECT_TIMEOUT
        )
        # MK Apr 2026 — TCP_NODELAY + keepalive: survives idle conntrack drops
        _apply_vnc_socket_options(pve_ws.sock)

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
        logging.exception(f"VNC proxy error: {type(e).__name__}: {e}")
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
    # NS: Mar 2026 - prefer WS token, session as fallback
    from pegaprox.utils.realtime import validate_ws_token
    ws_token = request.args.get('token')
    session_id = request.args.get('session')

    auth_user = None
    auth_role = None
    if ws_token:
        token_data = validate_ws_token(ws_token)
        if not token_data:
            return jsonify({'error': 'Invalid token', 'code': 'INVALID_TOKEN'}), 401
        auth_user = token_data['user']
        auth_role = token_data['role']
    elif session_id:
        session = validate_session(session_id)
        if not session:
            return jsonify({'error': 'Invalid session', 'code': 'INVALID_SESSION'}), 401
        auth_user = session['user']
        auth_role = session['role']
    else:
        return jsonify({'error': 'Auth required', 'code': 'AUTH_REQUIRED'}), 401

    # Check permissions
    users = load_users()
    user = users.get(auth_user, {})
    user_perms = get_user_permissions(user)
    if 'vm.console' not in user_perms and auth_role != ROLE_ADMIN:
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
        
        # NS: Mar 2026 - authenticate via single-use WS token (not session in URL)
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(path)
        query_params = parse_qs(parsed.query)
        ws_token = query_params.get('token', [None])[0]
        # LW: backwards compat, accept session= too for now
        session_id = query_params.get('session', [None])[0]

        # MK Apr 2026 — Stable VNC Mode (D): if frontend asked for an encrypted
        # tunnel via /console?stable=1, it gets back an enc_session id which it
        # then passes here. We claim the matching AES-256-GCM key (one-shot,
        # auto-expires after 60s if never claimed) and use it to wrap forwarded
        # frames in both directions. None → plain mode (default, backwards-compat).
        crypto_session = None
        enc_sid = query_params.get('enc_session', [None])[0]
        if enc_sid:
            try:
                from pegaprox.utils import vnc_crypto as _vc
                _key = _vc.claim_session_key(enc_sid)
                if _key:
                    crypto_session = _vc.VncCryptoSession(_key)
                    print(f"[VNC] stable mode active for sid={enc_sid[:8]}...")
                else:
                    print(f"[VNC] enc_session={enc_sid[:8]}... not found / expired — falling back to plain mode")
            except Exception as _e:
                print(f"[VNC] crypto setup failed ({_e}) — falling back to plain mode")

        if ws_token:
            from pegaprox.utils.realtime import validate_ws_token
            token_data = validate_ws_token(ws_token)
            if not token_data:
                print("ERROR: Invalid or expired WS token")
                await websocket.close(1002, "Invalid token")
                return
            # check perms from token
            users = load_users()
            user = users.get(token_data['user'], {})
            user_perms = get_user_permissions(user)
            if 'vm.console' not in user_perms and token_data['role'] != ROLE_ADMIN:
                print(f"ERROR: User {token_data['user']} lacks vm.console permission")
                await websocket.close(1002, "Permission denied")
                return
            print(f"User {token_data['user']} authenticated for VNC (ws_token)")
        elif session_id:
            session = validate_session(session_id)
            if not session:
                print("ERROR: Invalid session")
                await websocket.close(1002, "Invalid session")
                return
            users = load_users()
            user = users.get(session['user'], {})
            user_perms = get_user_permissions(user)
            if 'vm.console' not in user_perms and session['role'] != ROLE_ADMIN:
                print(f"ERROR: User {session['user']} lacks vm.console permission")
                await websocket.close(1002, "Permission denied")
                return
            print(f"User {session['user']} authenticated for VNC (session)")
        else:
            print("ERROR: No token or session provided")
            await websocket.close(1002, "Authentication required")
            return
        
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
        host, port = manager.host, manager.api_port
        
        pve_ws = None

        try:
            import urllib.parse
            import urllib.request
            import json
            import websocket as ws_client

            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            # Login to Proxmox to get auth ticket
            login_data = urlencode({
                'username': manager.config.user,
                'password': manager.config.pass_
            }).encode('utf-8')

            login_req = urllib.request.Request(
                f"https://{host}:{port}/api2/json/access/ticket",
                data=login_data, method='POST'
            )

            # MK Apr 2026 — wrap synchronous urllib.urlopen in asyncio.to_thread
            # so concurrent VNC handlers don't serialize on the TLS handshake.
            import asyncio as _aiowrap
            def _do_urlopen(req):
                with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as r:
                    return r.read()
            login_body = await _aiowrap.to_thread(_do_urlopen, login_req)
            login_result = json.loads(login_body.decode('utf-8'))

            pve_ticket = login_result['data']['ticket']
            csrf_token = login_result['data']['CSRFPreventionToken']

            # MK Apr 2026 — issue #352 follow-up. Single-vncproxy fast path.
            # If the JS already obtained a vncproxy ticket+port via /console
            # (which it always does — that's where it gets the VNC RFB password
            # for noVNC), reuse THAT ticket here instead of issuing a fresh
            # vncproxy call. PVE 9.1.x generates a random VNC password per
            # vncproxy call. Two calls = two different passwords; noVNC sends
            # DES(password_A) but PVE's vncterm is initialised with password_B,
            # so RFB auth fails (the customer-visible recv=60B + ttfb≈1s pattern).
            # Older PVE was tolerant because passwords were derived from the
            # ticket prefix. Newer PVE is strict.
            pve_port_q = query_params.get('pve_port', [None])[0]
            pve_ticket_q = query_params.get('pve_ticket', [None])[0]
            if pve_port_q and pve_ticket_q:
                # Single-vncproxy mode: trust the caller-supplied port+ticket.
                vnc_ticket = pve_ticket_q
                port = pve_port_q
                logging.info(f"[VNC] reusing JS-issued vncproxy ticket port={port} (single-call mode)")
            else:
                # Backwards-compat fallback: issue our own vncproxy. This still
                # works on older PVE where two vncproxy calls produce matching
                # passwords (or where noVNC isn't used in the browser).
                if vm_type == 'qemu':
                    vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
                else:
                    vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
                vnc_data = urlencode({'websocket': '1'}).encode('utf-8')
                vnc_req = urllib.request.Request(vnc_url, data=vnc_data, method='POST')
                vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
                vnc_req.add_header('CSRFPreventionToken', csrf_token)
                vnc_body = await _aiowrap.to_thread(_do_urlopen, vnc_req)
                vnc_result = json.loads(vnc_body.decode('utf-8'))
                vnc_ticket = vnc_result['data']['ticket']
                port = vnc_result['data']['port']
                logging.warning(f"[VNC] no pve_port/pve_ticket in URL — issued fresh vncproxy (port={port}). Update the frontend to pass JS-issued ticket through to avoid PVE 9.1.x password-mismatch (issue #352).")

            encoded_vnc_ticket = url_quote(vnc_ticket, safe='')

            if vm_type == 'qemu':
                pve_ws_path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
            else:
                pve_ws_path = f"/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"

            # MK Apr 2026 — VNC SSH-Tunnel-Mode (D2 / second leg).
            # If the cluster is flagged with vnc_tunnel=True, we open a persistent
            # SSH connection to the PVE node and forward localhost:RAND→pve:8006
            # through it. The WSS connection then goes to localhost:RAND instead
            # of pve:8006, so the WSS bytes ride inside SSH which TLS-inspection
            # engines can't decrypt (no trust-anchor for the SSH host key).
            # Multi-user: each session gets its own ephemeral local port.
            tunnel_endpoint = None
            tunnel_target_host = host
            tunnel_target_port = 8006
            try:
                _use_tunnel = bool(getattr(manager.config, 'vnc_tunnel', False))
            except Exception:
                _use_tunnel = False

            if _use_tunnel:
                try:
                    from pegaprox.utils import vnc_tunnel as _vt
                    _ssh_user = getattr(manager.config, 'ssh_user', None) or (manager.config.user or 'root').split('@')[0]
                    _ssh_port = getattr(manager.config, 'ssh_port', 22) or 22
                    _ssh_key = getattr(manager.config, 'ssh_key', '') or ''
                    _ssh_pass = getattr(manager.config, 'pass_', '') or ''
                    # MK Apr 2026 — _vt.acquire() is sync. On the *first* call for a
                    # cluster it builds the SSH transport (~1-2s on a fast LAN, more
                    # over WAN). If we ran it directly on the event loop, that 1-2s
                    # blocks websockets.serve from completing opening handshakes for
                    # other concurrent connections — which is exactly the "5/5 timed
                    # out during opening handshake" we saw in the multi-user test.
                    # Offload to a worker so the event loop stays free.
                    import asyncio as _aio_acq
                    tunnel_endpoint = await _aio_acq.to_thread(
                        _vt.acquire,
                        cluster_id=cluster_id,
                        pve_host=host,
                        ssh_user=_ssh_user,
                        ssh_port=_ssh_port,
                        ssh_key_content=_ssh_key,
                        ssh_password=_ssh_pass,
                        target_host='127.0.0.1',
                        target_port=8006,
                    )
                    # Reroute the WSS through the local listener
                    tunnel_target_host = '127.0.0.1'
                    tunnel_target_port = tunnel_endpoint.local_port
                    logging.info(
                        f"[VNC] SSH tunnel mode active for cluster={cluster_id}: "
                        f"WSS routed via 127.0.0.1:{tunnel_target_port} → SSH → {host}:{port}"
                    )
                except Exception as _tun_err:
                    logging.warning(
                        f"[VNC] SSH tunnel setup failed ({_tun_err}) — falling back "
                        f"to direct WSS to {host}:{port}. Customer may still see "
                        "TLS-inspection issues until SSH is fixed."
                    )
                    tunnel_endpoint = None
                    tunnel_target_host = host
                    tunnel_target_port = 8006

            pve_ws_url = f"wss://{tunnel_target_host}:{tunnel_target_port}{pve_ws_path}"

            # MK Apr 2026 (#352 follow-up) — auth-context for the PVE WS upgrade.
            # When we're REUSING the JS-issued vncproxy ticket, the ticket was
            # bound to the manager's existing auth context (API token or stored
            # access cookie). Using a fresh login's cookie produces "permission
            # denied - invalid PVEVNC ticket" on PVE 9.1.x. Reuse the manager's
            # stored auth instead. Backwards-compat path keeps the fresh login.
            ws_auth_header = {"Host": f"{host}:{port}"}
            if pve_port_q and pve_ticket_q:
                if getattr(manager, '_using_api_token', False) and getattr(manager, '_api_token', None):
                    ws_auth_header['Authorization'] = f"PVEAPIToken={manager._api_token}"
                elif getattr(manager, '_ticket', None):
                    ws_auth_header['Cookie'] = f"PVEAuthCookie={manager._ticket}"
                else:
                    ws_auth_header['Cookie'] = f"PVEAuthCookie={pve_ticket}"
            else:
                ws_auth_header['Cookie'] = f"PVEAuthCookie={pve_ticket}"

            # MK Apr 2026 — ws_client.create_connection is synchronous; offload to
            # a worker thread so concurrent VNC handlers don't serialize on the
            # TLS+WS-Upgrade handshake (~1-2s each) on the event loop.
            import asyncio as _asyncio_for_connect
            import time as _t_connect
            _connect_started = _t_connect.monotonic()
            pve_ws = await _asyncio_for_connect.to_thread(
                ws_client.create_connection,
                pve_ws_url,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                header=ws_auth_header,
                timeout=VNC_PVE_CONNECT_TIMEOUT,
            )
            _connect_ms = int((_t_connect.monotonic() - _connect_started) * 1000)

            # MK Apr 2026: TCP_NODELAY + aggressive keepalive (replaces older NS comment).
            # Nagle off = no 40ms input lag for keystrokes/mouse; keepalive on = stateful
            # firewalls don't drop the session during natural idle periods.
            _apply_vnc_socket_options(pve_ws.sock)

            logging.info(f"[VNC] connected to {host} for {vm_type}/{vmid} in {_connect_ms}ms")
            if _connect_ms > 3000:
                logging.warning(f"[VNC] slow PVE connect: {_connect_ms}ms — possible TLS-inspection / EDR latency on the path to {host}")

            import asyncio

            bytes_sent = 0
            bytes_received = 0
            running = True
            stop_evt = asyncio.Event()
            # MK Apr 2026 — time-to-first-byte from PVE side; helps distinguish
            # "couldn't connect" from "connected but stuck mid-handshake" in support
            _ttfb_ms = None
            _session_started = _t_connect.monotonic()

            # NS Apr 2026 (#312/#92): the old loop used settimeout(0.001) + asyncio.sleep(0.005)
            # to fake non-blocking recv. That's a busy-wait that blocks the event loop on every
            # recv() call — under load or network jitter it drops bytes and the session dies after
            # a few minutes. Switch to blocking recv in a worker thread via asyncio.to_thread.
            pve_ws.settimeout(None)  # blocking mode — to_thread handles the blocking call

            async def proxmox_to_client():
                """Forward data from Proxmox to browser (blocking recv handled in thread).

                In Stable VNC Mode (crypto_session is not None): plain RFB bytes
                from PVE are wrapped in an AES-256-GCM frame before they hit the
                browser-side WebSocket. The middlebox can re-encrypt our outer
                TLS but sees opaque ciphertext inside, so it can't pattern-match
                or modify the binary RFB.
                """
                nonlocal bytes_received, running, _ttfb_ms
                while running:
                    try:
                        data = await asyncio.to_thread(pve_ws.recv)
                        if not data:
                            running = False
                            break
                        if _ttfb_ms is None:
                            _ttfb_ms = int((_t_connect.monotonic() - _session_started) * 1000)
                        bytes_received += len(data)
                        if isinstance(data, str):
                            data = data.encode('latin-1')
                        if crypto_session is not None:
                            data = crypto_session.encrypt(data)
                        await websocket.send(data)
                    except ws_client.WebSocketConnectionClosedException:
                        running = False
                        break
                    except Exception as e:
                        if running:
                            logging.debug(f"[VNC] PVE->Client: {e}")
                        running = False
                        break
                stop_evt.set()

            async def client_to_proxmox():
                """Forward data from browser to Proxmox (blocking send handled in thread).

                In Stable VNC Mode: each browser-side WebSocket frame is an
                AES-256-GCM ciphertext blob. We unwrap it (which also verifies
                the auth tag — if a middlebox modified bytes mid-flight, decrypt
                raises and we close the session with code 4099 and a clear
                'integrity check failed' reason instead of letting RFB later
                fail with a confusing 'Authentication failed').
                """
                nonlocal bytes_sent, running
                try:
                    async for message in websocket:
                        if not running:
                            break
                        bytes_sent += len(message)
                        if isinstance(message, str):
                            message = message.encode('latin-1')
                        if crypto_session is not None:
                            try:
                                message = crypto_session.decrypt(message)
                            except Exception as _crypto_err:
                                logging.warning(
                                    f"[VNC] integrity check FAILED on browser→PVE frame "
                                    f"(host={host} vm={vm_type}/{vmid}): {_crypto_err}. "
                                    "TLS-inspection / EDR is modifying packets mid-flight."
                                )
                                running = False
                                try:
                                    await websocket.close(4099, f"integrity_check_failed: {_crypto_err}")
                                except Exception:
                                    pass
                                break
                        await asyncio.to_thread(pve_ws.send, message)
                except Exception as e:
                    if running and 'close' not in str(e).lower():
                        logging.debug(f"[VNC] Client->PVE: {e}")
                finally:
                    running = False
                    stop_evt.set()

            async def pve_keepalive():
                """Keepalive for pvedaemon idle timeout (#312).

                Two-layer: WS ping every 15s AND an RFB-level FramebufferUpdateRequest
                every 20s. pveproxy sits between us and qemu and can timeout based on
                RFB traffic, not WS frames — the browser's WS ping alone doesn't always
                count as activity on the qemu side. By injecting an RFB incremental
                update request we produce real RFB traffic that flows end-to-end.

                RFB FramebufferUpdateRequest wire format (8 bytes, Big-Endian):
                  U8  message-type = 3
                  U8  incremental  = 1   (only changed regions -> cheap)
                  U16 x            = 0
                  U16 y            = 0
                  U16 width        = 0xFFFF  (server clamps to FB size)
                  U16 height       = 0xFFFF

                15s grace before first RFB frame so the RFB handshake completes first —
                injecting our bytes into the handshake would confuse qemu.
                """
                import time as _time
                RFB_FB_UPDATE_REQUEST = b'\x03\x01\x00\x00\x00\x00\xff\xff\xff\xff'
                session_start = _time.monotonic()
                ws_ping_interval = 15
                rfb_interval = 20
                next_rfb_at = session_start + 15 + rfb_interval  # 15s grace + 20s first interval
                while running:
                    try:
                        await asyncio.wait_for(stop_evt.wait(), timeout=ws_ping_interval)
                        break  # stop_evt was set — session ending
                    except asyncio.TimeoutError:
                        pass
                    if not running:
                        break
                    # WS-layer ping (cheap, keeps any websocket-aware intermediary happy)
                    try:
                        await asyncio.to_thread(pve_ws.ping)
                    except Exception:
                        break
                    # RFB-layer keepalive (keeps pveproxy/qemu from declaring the session idle)
                    now = _time.monotonic()
                    if now >= next_rfb_at:
                        try:
                            await asyncio.to_thread(pve_ws.send_binary, RFB_FB_UPDATE_REQUEST)
                            next_rfb_at = now + rfb_interval
                        except Exception as e:
                            logging.debug(f"[VNC] RFB keepalive send failed: {e}")
                            break

            task1 = asyncio.create_task(proxmox_to_client())
            task2 = asyncio.create_task(client_to_proxmox())
            task3 = asyncio.create_task(pve_keepalive())

            done, pending = await asyncio.wait(
                [task1, task2, task3],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            running = False
            
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            # MK Apr 2026 — richer session-end diagnostic. Helps support correlate
            # short / weird sessions with network / inspection issues. Format is
            # easy to grep + machine-parseable.
            _duration_ms = int((_t_connect.monotonic() - _session_started) * 1000)
            _ttfb_str = f"{_ttfb_ms}ms" if _ttfb_ms is not None else "never"
            _short_session = _duration_ms < 5000 and bytes_received < 4096
            _level = logging.WARNING if _short_session else logging.INFO
            logging.log(
                _level,
                f"[VNC] session ended host={host} vm={vm_type}/{vmid} "
                f"connect={_connect_ms}ms ttfb={_ttfb_str} duration={_duration_ms}ms "
                f"sent={bytes_sent}B recv={bytes_received}B "
                f"{'SHORT_OR_EMPTY — middlebox/EDR may be interfering' if _short_session else ''}"
            )
            
        except Exception as e:
            logging.exception(f"VNC WS handler error: {type(e).__name__}: {e}")
        finally:
            # MK Apr 2026 — pve_ws.close() is a SYNC call from the websocket-client
            # library. It runs the TLS close handshake which on a tunneled SSH leg
            # can block when the far end is gone. If we run it on the event loop,
            # ALL subsequent VNC handshakes on this server queue behind it (we hit
            # this in the multi-user concurrency test: 1st session OK, then 5 in
            # parallel all timeout). Offload to a worker with a short upper bound.
            if pve_ws:
                try:
                    import asyncio as _aio_close
                    await _aio_close.wait_for(
                        _aio_close.to_thread(pve_ws.close), timeout=2.0
                    )
                except Exception:
                    pass
            try:
                if 'tunnel_endpoint' in locals() and tunnel_endpoint is not None:
                    tunnel_endpoint.stop()
            except Exception as _tend:
                logging.debug(f"[VNC] tunnel cleanup error: {_tend}")
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
        # MK Apr 2026 (#352): lenient Connection-header recovery for PVE 9.1.8-9 hosts
        # and middlebox-stripped Upgrade tokens. See pegaprox/utils/ws_lenient.py.
        from pegaprox.utils.ws_lenient import lenient_process_request as _lpr_vnc
        ws_host = host if host else None
        display_host = host or '0.0.0.0'
        try:
            async with websockets.serve(vnc_handler, ws_host, port, ssl=ssl_context, ping_interval=20, ping_timeout=10, process_request=_lpr_vnc):
                print(f"VNC WebSocket Server ready on {proto}://{display_host}:{port}", flush=True)
                server_ready.set()
                await asyncio.Future()  # Run forever
        except OSError as bind_err:
            # Issue #71: IPv6 bind failed, fall back to 0.0.0.0
            if ':' in str(host):
                print(f"VNC WebSocket: IPv6 bind failed ({bind_err}), falling back to 0.0.0.0", flush=True)
                async with websockets.serve(vnc_handler, '0.0.0.0', port, ssl=ssl_context, ping_interval=20, ping_timeout=10, process_request=_lpr_vnc):
                    print(f"VNC WebSocket Server ready on {proto}://0.0.0.0:{port}", flush=True)
                    server_ready.set()
                    await asyncio.Future()
            else:
                raise
    
    # LW Feb 2026 - run in thread, with proper fallback for gevent environments
    # NS May 2026 (#388 follow-up) — capture exception into a shared box so the
    # caller waiting on server_ready can surface it loudly in the journal
    # instead of just "may not be ready yet". Silent thread death is the
    # hardest pattern to debug at the customer.
    thread_err = {}  # exception sink — populated if the thread crashes pre-bind

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
                logging.exception(f"VNC WebSocket Server RuntimeError: {e}")
                thread_err['err'] = ('RuntimeError', str(e))
        except (KeyboardInterrupt, SystemExit):
            pass
        except OSError as e:
            # bind failures land here — port in use, permission denied, AppArmor block, etc.
            logging.exception(f"VNC WebSocket Server bind failed (port {port}): {e}")
            thread_err['err'] = ('OSError', f"bind error: {e}")
        except TypeError as e:
            # signature mismatches with websockets library (e.g. older websockets)
            logging.exception(f"VNC WebSocket Server TypeError (likely websockets lib version mismatch): {e}")
            thread_err['err'] = ('TypeError', str(e))
        except Exception as e:
            logging.exception(f"VNC WebSocket Server crashed: {type(e).__name__}: {e}")
            thread_err['err'] = (type(e).__name__, str(e))

    print(f"VNC WebSocket: starting thread, target port {port}", flush=True)
    ws_thread = threading.Thread(target=run_server, daemon=True, name=f'vnc-ws:{port}')
    ws_thread.start()

    # NS May 2026 (#388): if the thread is dead at this point and never set
    # server_ready, surface WHY in the log so support can act. Silent failure
    # was the customer-visible symptom that hid the underlying cause.
    if server_ready.wait(timeout=5):
        print(f"VNC WebSocket Server started successfully on port {port}", flush=True)
    else:
        # Wait briefly for the thread to fully die so thread_err has a chance to populate
        ws_thread.join(timeout=1)
        if thread_err.get('err'):
            etype, emsg = thread_err['err']
            logging.error(
                f"[VNC] startup failed — thread died with {etype}: {emsg}. "
                f"Port {port} will NOT be bound. Console connections to this server will fail. "
                f"Most common causes: (a) port already in use by another process, "
                f"(b) websockets library version mismatch (need ≥11.0; we expect "
                f"the post-13.x process_request signature), "
                f"(c) AppArmor/SELinux blocking the bind, "
                f"(d) SSL cert path missing or unreadable. "
                f"Run: ss -tlnp | grep ':{port}'  +  pip show websockets  +  journalctl -u pegaprox -p err"
            )
        elif not ws_thread.is_alive():
            logging.error(
                f"[VNC] startup timed out — thread died silently within 5s without setting "
                f"server_ready and without raising an exception we could capture. "
                f"Port {port} will NOT be bound. Probable causes: SystemExit / os._exit "
                f"in a downstream import or a fatal C-level signal. "
                f"Run: journalctl -u pegaprox --since '1 minute ago'"
            )
        else:
            logging.warning(
                f"[VNC] startup slow — server_ready not set after 5s but thread is still alive. "
                f"Port {port} may bind shortly. If it never does, the asyncio event loop "
                f"is likely blocked at startup."
            )


# Keep flask-sock version as backup (renamed)
@sock.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vncwebsocket')
def vnc_websocket_proxy(ws, cluster_id, node, vm_type, vmid):
    """WebSocket proxy for VNC connection via Flask-Sock (same port as main app)"""
    import gevent
    from gevent import spawn, sleep as gsleep
    
    print(f"\n{'='*60}")
    print(f"VNC WEBSOCKET: {vm_type}/{vmid} on {node}")
    print(f"{'='*60}")
    
    # NS: Mar 2026 - prefer WS token, session as legacy fallback
    from pegaprox.utils.realtime import validate_ws_token
    ws_token = request.args.get('token')
    session_id = request.args.get('session')

    auth_user = None
    if ws_token:
        token_data = validate_ws_token(ws_token)
        if not token_data:
            try: ws.send('Invalid or expired token')
            except: pass
            return
        users = load_users()
        user = users.get(token_data['user'], {})
        user_perms = get_user_permissions(user)
        if 'vm.console' not in user_perms and token_data['role'] != ROLE_ADMIN:
            try: ws.send('Permission denied')
            except: pass
            return
        auth_user = token_data['user']
    elif session_id:
        session = validate_session(session_id)
        if not session:
            try: ws.send('Invalid session')
            except: pass
            return
        users = load_users()
        user = users.get(session['user'], {})
        user_perms = get_user_permissions(user)
        if 'vm.console' not in user_perms and session['role'] != ROLE_ADMIN:
            try: ws.send('Permission denied')
            except: pass
            return
        auth_user = session['user']
    else:
        try: ws.send('Authentication required')
        except: pass
        return

    print(f"User {auth_user} authenticated for VNC")
    
    if cluster_id not in cluster_managers:
        print(f"ERROR: Cluster {cluster_id} not found")
        return
    
    manager = cluster_managers[cluster_id]
    host, port = manager.host, manager.api_port
    
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
            f"https://{host}:{port}/api2/json/access/ticket",
            data=login_data, method='POST'
        )
        
        with urllib.request.urlopen(login_req, context=ssl_context, timeout=10) as response:
            login_result = json.loads(response.read().decode('utf-8'))

        pve_ticket = login_result['data']['ticket']
        csrf_token = login_result['data']['CSRFPreventionToken']
        print(f"Got PVE ticket")

        # MK Apr 2026 (#352 follow-up) — single-vncproxy mode. If the JS
        # already got a vncproxy ticket+port via /console, reuse it so the VNC
        # password noVNC uses matches the password PVE's vncterm expects. PVE
        # 9.1.x generates fresh random VNC password per vncproxy call.
        pve_port_q = request.args.get('pve_port')
        pve_ticket_q = request.args.get('pve_ticket')
        if pve_port_q and pve_ticket_q:
            vnc_ticket = pve_ticket_q
            port = pve_port_q
            print(f"Reusing JS-issued vncproxy ticket port={port}")
        else:
            print(f"Step 2: Get VNC ticket...")
            if vm_type == 'qemu':
                vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
            else:
                vnc_url = f"https://{host}:{port}/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
            vnc_data = urlencode({'websocket': '1'}).encode('utf-8')
            vnc_req = urllib.request.Request(vnc_url, data=vnc_data, method='POST')
            vnc_req.add_header('Cookie', f'PVEAuthCookie={pve_ticket}')
            vnc_req.add_header('CSRFPreventionToken', csrf_token)
            with urllib.request.urlopen(vnc_req, context=ssl_context, timeout=10) as response:
                vnc_result = json.loads(response.read().decode('utf-8'))
            vnc_ticket = vnc_result['data']['ticket']
            port = vnc_result['data']['port']
            print(f"Got VNC ticket, port={port} (no JS pass-through — PVE 9.1.x users may hit issue #352)")
        
        # Step 3: Connect to Proxmox WebSocket
        print(f"Step 3: Connect to Proxmox...")
        encoded_vnc_ticket = url_quote(vnc_ticket, safe='')
        
        if vm_type == 'qemu':
            pve_ws_path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        else:
            pve_ws_path = f"/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port={port}&vncticket={encoded_vnc_ticket}"
        
        pve_ws_url = f"wss://{host}:{port}{pve_ws_path}"

        pve_ws = websocket.create_connection(
            pve_ws_url,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            header={"Cookie": f"PVEAuthCookie={pve_ticket}"},
            timeout=VNC_PVE_CONNECT_TIMEOUT
        )
        # MK Apr 2026 — TCP_NODELAY + keepalive (consolidated helper)
        _apply_vnc_socket_options(pve_ws.sock)

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
        logging.exception(f"SSH proxy error: {type(e).__name__}: {e}")
    finally:
        running = False
        if pve_ws:
            try:
                pve_ws.close()
            except:
                pass
        print(f"{'='*60}\n")


# NS May 2026 — Proxmox built-in termproxy (xterm.js) for LXC + QEMU.
# Same idea as the VNC proxy above but talks PVE's text-frame termproxy
# protocol instead of RFB. No second login: the PegaProx session is
# already trusted to act as the cluster admin user, so we log into PVE
# server-side, fetch the termproxy ticket, send the `user:ticket\n`
# handshake to PVE on behalf of the browser, then bidirectionally proxy
# bytes between the PegaProx client WS and the PVE WS.
#
# Wire protocol (verbatim from pve-xtermjs/src/www/main.js):
#   client → PVE  (after auth):  "0:<len>:<data>"  (xterm input bytes)
#                                "1:<cols>:<rows>:" (resize, no body)
#                                "2"               (keepalive, optional)
#   PVE → client (after auth):   raw text bytes (TTY output, no framing)
#                                first message after handshake: "OK"
#
# Our wrapper handles the framing on both sides so the browser-side
# component is plain xterm.js with no PVE-specific glue.
@bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/termproxy', methods=['POST'])
@require_auth(perms=['vm.console'])
def get_termproxy_ticket_api(cluster_id, node, vm_type, vmid):
    """NS May 2026 — issues a PVE termproxy ticket for a VM/CT.

    Server-side: log into PVE with cluster credentials (NOT API token, since
    termproxy needs a real session cookie), POST /termproxy, return both the
    auth_ticket (used as PVEAuthCookie) and the termproxy_ticket (used as
    ?vncticket=) so the standalone WS server can complete the handshake.
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    if vm_type not in ('qemu', 'lxc'):
        return jsonify({'error': 'Unsupported vm_type'}), 400

    mgr = cluster_managers[cluster_id]
    pve_pwd = getattr(mgr.config, 'pass_', None) or getattr(mgr.config, 'password', None)
    pve_usr = getattr(mgr.config, 'user', None) or 'root@pam'
    if not pve_pwd:
        return jsonify({'error': 'Cluster has no stored password — termproxy needs user/pass auth (API tokens cannot mint termproxy tickets).'}), 400

    import ssl as _ssl
    import urllib.request as _urlreq
    from urllib.parse import urlencode as _urlencode
    ssl_ctx = _ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = _ssl.CERT_NONE
    host, port = mgr.host, mgr.api_port

    # Step 1: real PVE session login
    try:
        login_req = _urlreq.Request(
            f"https://{host}:{port}/api2/json/access/ticket",
            data=_urlencode({'username': pve_usr, 'password': pve_pwd}).encode('utf-8'),
            method='POST'
        )
        with _urlreq.urlopen(login_req, context=ssl_ctx, timeout=10) as resp:
            login_result = json.loads(resp.read().decode('utf-8'))
        auth_ticket = login_result['data']['ticket']
        csrf_token = login_result['data']['CSRFPreventionToken']
        pve_login_user = login_result['data'].get('username') or pve_usr
    except Exception as e:
        logging.exception(f"[TERMPROXY-API] PVE login failed: {e}")
        return jsonify({'error': f'PVE login failed: {type(e).__name__}'}), 500

    # Step 2: POST /termproxy with the session cookie
    try:
        if vm_type == 'qemu':
            tp_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/termproxy"
        else:
            tp_url = f"https://{host}:{port}/api2/json/nodes/{node}/lxc/{vmid}/termproxy"
        tp_req = _urlreq.Request(tp_url, data=b'', method='POST')
        tp_req.add_header('Cookie', f'PVEAuthCookie={auth_ticket}')
        tp_req.add_header('CSRFPreventionToken', csrf_token)
        with _urlreq.urlopen(tp_req, context=ssl_ctx, timeout=10) as resp:
            tp_result = json.loads(resp.read().decode('utf-8'))
        term_ticket = tp_result['data']['ticket']
        term_port = tp_result['data']['port']
        term_user = tp_result['data'].get('user') or pve_login_user
    except Exception as e:
        logging.exception(f"[TERMPROXY-API] termproxy ticket failed: {e}")
        return jsonify({'error': f'termproxy ticket failed: {type(e).__name__}'}), 500

    log_audit(request.session.get('user', 'unknown'), 'vm.terminal',
              f'Terminal opened: {vm_type}/{vmid} on {node}',
              cluster=getattr(mgr.config, 'name', cluster_id))

    return jsonify({
        'success': True,
        'host': host,
        'port': term_port,
        'ticket': term_ticket,
        'user': term_user,
        # auth_ticket is sent to the WS server, NOT held by the browser long-term.
        # Used to set PVEAuthCookie: header on the PVE WS connect.
        'auth_ticket': auth_ticket,
        'node': node,
        'vmid': vmid,
        'vm_type': vm_type,
    })


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
    
    from urllib.parse import urlparse, parse_qs, unquote, quote_plus
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    ws_token = query.get('token', [None])[0]
    session_id = query.get('session', [None])[0]  # LW: backwards compat
    prefetched_ip = query.get('ip', [None])[0]  # IP pre-fetched by frontend
    if prefetched_ip:
        prefetched_ip = unquote(prefetched_ip)
        print(f"Frontend provided IP: {prefetched_ip}")

    # NS May 2026 — accept both shell and termproxy paths.
    # termproxy: /api/clusters/<cid>/vms/<node>/<vm_type>/<vmid>/termwebsocket
    #            with ?ticket=, ?port=, ?user=, ?host= from the frontend.
    m_term = re.match(r'/api/clusters/([^/]+)/vms/([^/]+)/(qemu|lxc)/([0-9]+)/termwebsocket', parsed.path)
    if m_term:
        await termproxy_handler(websocket, query, m_term, ws_token, session_id)
        return

    # Match both /shell and /shellws
    match = re.match(r'/api/clusters/([^/]+)/nodes/([^/]+)/shell(?:ws)?', parsed.path)
    if not match:
        print(f"Invalid path: {parsed.path}")
        await websocket.send('{"status":"error","message":"Invalid path"}')
        await websocket.close(1008, "Invalid path")
        return

    cluster_id, node = match.groups()
    print(f"Cluster: {cluster_id}, Node: {node}")

    # NS: Mar 2026 - prefer WS token auth (single-use, doesn't leak session)
    auth_token = ws_token or session_id
    if not auth_token:
        print("No token or session provided")
        await websocket.send('{"status":"error","message":"No auth token provided"}')
        await websocket.close(1008, "No auth")
        return

    # Validate via main server. MK May 2026 - when called with ws_token + cluster_id,
    # the response now also carries `cluster_context` (host/node_ips/ssh_port) so we
    # don't need a second authenticated round-trip. The WS subprocess holds only the
    # consumed ws-token, no session cookie, so cluster-creds was previously
    # unreachable from here.
    node_ip = None
    cluster_host = None
    node_ips = {}
    try:
        if ws_token:
            validate_url = (
                f"{PEGAPROX_URL}/api/ws/token/validate"
                f"?token={ws_token}&cluster_id={quote_plus(cluster_id)}&node={quote_plus(node)}"
            )
            print(f"Validating WS token (cluster={cluster_id}, node={node})...")
        else:
            validate_url = f"{PEGAPROX_URL}/api/auth/validate"
            print("Validating session (legacy)...")

        headers = {'X-Session-ID': session_id} if session_id else {}
        cookies = {'session': session_id} if session_id else {}
        r = requests.get(validate_url, cookies=cookies, headers=headers, timeout=8, verify=False)

        if r.status_code == 403:
            print(f"Auth failed: 403 (no access to cluster {cluster_id})")
            await websocket.send(json.dumps({'status': 'error', 'message': f'No access to cluster {cluster_id}'}))
            await websocket.close(1008, "Forbidden")
            return
        if r.status_code != 200:
            print(f"Auth failed: {r.status_code}")
            await websocket.send('{"status":"error","message":"Session ungültig - bitte neu einloggen"}')
            await websocket.close(1008, "Invalid auth")
            return

        # Pull the cluster context out of the validate response (ws-token path only)
        if ws_token:
            try:
                payload = r.json() or {}
                ctx = payload.get('cluster_context') or {}
                cluster_host = ctx.get('host')
                node_ips = ctx.get('node_ips') or {}
                node_ip = node_ips.get(node) or node_ips.get(node.lower())
                print(f"validate→ host={cluster_host} node_ips={node_ips} resolved_node_ip={node_ip}")
            except Exception as e:
                print(f"Could not parse validate payload: {e}")

        # Legacy session path: fall back to cluster-creds with the session cookie.
        if not ws_token and session_id:
            try:
                print(f"Fetching cluster creds from: {PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}")
                rc = requests.get(f"{PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}",
                                  cookies={'session': session_id}, timeout=10, verify=False)
                if rc.status_code == 200:
                    creds = rc.json()
                    cluster_host = creds.get('host')
                    node_ips = creds.get('node_ips', {})
                    node_ip = node_ips.get(node) or node_ips.get(node.lower())
            except Exception as e:
                print(f"Could not get node IP from API: {e}")

        print("Auth successful")
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

    # cluster_host fallback for node_ip (single-node setups where only the host
    # was registered).
    if not node_ip and cluster_host:
        node_ip = cluster_host
        print(f"Using cluster host as fallback: {cluster_host}")

    # MK May 2026 (CodeAnt CWE-918) - build the SSH allow-list. prefetched_ip from
    # URL and user-supplied creds.host below must both be in this set; otherwise
    # an authenticated user could turn PegaProx into an SSH jump host for any
    # internal IP. Set comes from server-side resolution only.
    allowed_hosts = set()
    if cluster_host:
        allowed_hosts.add(cluster_host)
    allowed_hosts.update(v for v in (node_ips or {}).values() if v)

    if prefetched_ip:
        if prefetched_ip in allowed_hosts:
            node_ip = prefetched_ip
            print(f"Using prefetched IP (allow-list match): {node_ip}")
        else:
            print(f"REJECT prefetched ?ip={prefetched_ip!r} not in {sorted(allowed_hosts)}")
            await websocket.send(json.dumps({
                'status': 'error',
                'message': f"Prefetched IP {prefetched_ip!r} is not a known node of cluster {cluster_id}."
            }))
            await websocket.close(1008, "prefetched ip not allowed")
            return

    # If we still don't have an IP, allow manual entry (but allow-list still applies)
    allow_manual_ip = False
    if not node_ip:
        print(f"No IP found - allowing manual entry")
        node_ip = ""  # Empty - user must provide
        allow_manual_ip = True

    print(f"Final node IP for {node}: {node_ip or '(manual entry required)'}")
    print(f"Allow-list for host override: {sorted(allowed_hosts) or '(empty - no manual override permitted)'}")

    # Send need_credentials status - frontend will show login dialog
    await websocket.send(json.dumps({
        'status': 'need_credentials',
        'node': node,
        'ip': node_ip,
        'allowManualIp': allow_manual_ip
    }))

    # Wait for credentials from user
    try:
        creds_msg = await asyncio.wait_for(websocket.recv(), timeout=300)
        creds = json.loads(creds_msg)
        ssh_user = creds.get('username', 'root')
        ssh_pass = creds.get('password', '')
        ssh_key = creds.get('privateKey', '')

        # MK May 2026 (CodeAnt CWE-918) - host override is gated by allow_hosts.
        # Empty set rejects all overrides (no-resolved-cluster case).
        user_ip = creds.get('host', '').strip()
        if user_ip:
            if user_ip not in allowed_hosts:
                print(f"REJECT user host override: {user_ip!r} not in {sorted(allowed_hosts)}")
                await websocket.send(json.dumps({
                    'status': 'error',
                    'message': f"Host {user_ip!r} is not a known node of cluster {cluster_id}. Manual override blocked."
                }))
                await websocket.close(1008, "host not allowed")
                return
            node_ip = user_ip
            print(f"Using user-provided IP (allow-list match): {node_ip}")

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


# NS May 2026 — Proxmox termproxy proxy.
# Frontend has already POSTed /termproxy on the main app and got a ticket.
# It sends the ticket+port+host+user as query params on the WS open.
# We connect to PVE's vncwebsocket with that ticket, send the
# `user:ticket\\n` handshake, wait for "OK", then proxy bytes both ways.
# No SSH, no second login — the cluster auth happens server-side at the
# /termproxy POST step.
async def termproxy_handler(client_ws, query, m_term, ws_token, session_id):
    from urllib.parse import unquote, quote_plus
    cluster_id, node, vm_type, vmid_str = m_term.groups()
    print(f"[TERMPROXY] {vm_type}/{vmid_str} on {node} cluster={cluster_id}")

    auth_token = ws_token or session_id
    if not auth_token:
        await client_ws.send('{"status":"error","message":"No auth token"}')
        await client_ws.close(1008, "No auth")
        return

    # Validate via main server (cluster-scope check + inline cluster context)
    # MK May 2026 - response carries cluster_context so we don't need a second
    # authenticated round-trip from the WS subprocess.
    validate_payload = {}
    try:
        if ws_token:
            validate_url = (
                f"{PEGAPROX_URL}/api/ws/token/validate"
                f"?token={ws_token}&cluster_id={quote_plus(cluster_id)}&node={quote_plus(node)}"
            )
        else:
            validate_url = f"{PEGAPROX_URL}/api/auth/validate"
        headers = {'X-Session-ID': session_id} if session_id else {}
        cookies = {'session': session_id} if session_id else {}
        r = requests.get(validate_url, cookies=cookies, headers=headers, timeout=8, verify=False)
        if r.status_code == 403:
            await client_ws.send(json.dumps({'status': 'error', 'message': f'No access to cluster {cluster_id}'}))
            await client_ws.close(1008, "Forbidden")
            return
        if r.status_code != 200:
            await client_ws.send('{"status":"error","message":"Invalid session"}')
            await client_ws.close(1008, "auth")
            return
        try:
            validate_payload = r.json() or {}
        except Exception:
            validate_payload = {}
    except Exception as e:
        print(f"[TERMPROXY] auth validate failed: {e}")
        await client_ws.send('{"status":"error","message":"Auth server unreachable"}')
        await client_ws.close(1011, "auth")
        return

    # Frontend gave us the termproxy ticket+port already (via POST /termproxy)
    # plus the PVE session auth_ticket (used as PVEAuthCookie header).
    pve_ticket = query.get('ticket', [None])[0]
    pve_port = query.get('port', [None])[0]
    pve_host = query.get('host', [None])[0]
    pve_user = query.get('user', [None])[0]
    pve_auth = query.get('auth_ticket', [None])[0]
    if not (pve_ticket and pve_port and pve_host and pve_user and pve_auth):
        print(f"[TERMPROXY] missing query params; got: ticket={bool(pve_ticket)} port={pve_port} host={pve_host} user={pve_user} auth={bool(pve_auth)}")
        await client_ws.send('{"status":"error","message":"Missing termproxy params"}')
        await client_ws.close(1008, "params")
        return

    pve_ticket = unquote(pve_ticket)
    pve_user = unquote(pve_user)
    pve_host = unquote(pve_host)
    pve_auth = unquote(pve_auth)

    # MK May 2026 (CodeAnt CWE-918) - SSRF gate. Use the cluster_context already
    # returned by the validate call; fall back to cluster-creds only on the legacy
    # session-cookie path (ws-token flow has no session cookie to authenticate it).
    allowed_hosts = set()
    ctx = (validate_payload or {}).get('cluster_context') or {}
    if ctx.get('host'):
        allowed_hosts.add(ctx['host'])
    allowed_hosts.update(v for v in (ctx.get('node_ips') or {}).values() if v)
    if not allowed_hosts and session_id:
        try:
            cr = requests.get(f"{PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}",
                              cookies={'session': session_id}, timeout=10, verify=False)
            if cr.status_code == 200:
                cr_data = cr.json() or {}
                if cr_data.get('host'):
                    allowed_hosts.add(cr_data['host'])
                allowed_hosts.update(v for v in (cr_data.get('node_ips') or {}).values() if v)
            else:
                print(f"[TERMPROXY] cluster-creds non-200 ({cr.status_code}); allow-list empty")
        except Exception as e:
            print(f"[TERMPROXY] cluster-creds legacy fetch failed: {e}")

    if pve_host not in allowed_hosts:
        print(f"[TERMPROXY] REJECT host {pve_host!r} (not in {sorted(allowed_hosts)})")
        await client_ws.send(json.dumps({
            'status': 'error',
            'message': f"Host {pve_host!r} is not a known node of cluster {cluster_id}."
        }))
        await client_ws.close(1008, "host not allowed")
        return

    # Connect to PVE WS — Cookie uses session auth ticket; URL uses termproxy ticket.
    pve_path = f"/api2/json/nodes/{node}/{vm_type}/{vmid_str}/vncwebsocket?port={pve_port}&vncticket={quote_plus(pve_ticket)}"
    pve_url = f"wss://{pve_host}:8006{pve_path}"
    print(f"[TERMPROXY] connecting to PVE: {pve_url}")
    pve_ssl = ssl.create_default_context()
    pve_ssl.check_hostname = False
    pve_ssl.verify_mode = ssl.CERT_NONE
    try:
        pve_ws = await websockets.connect(
            pve_url,
            additional_headers={'Cookie': f'PVEAuthCookie={pve_auth}'},
            ssl=pve_ssl,
            open_timeout=10,
        )
    except Exception as e:
        print(f"[TERMPROXY] PVE WS connect failed: {type(e).__name__}: {e}")
        await client_ws.send(f'{{"status":"error","message":"PVE WS connect failed: {type(e).__name__}"}}')
        await client_ws.close(1011, "pve")
        return

    # Send PVE auth handshake: user:ticket\\n
    try:
        await pve_ws.send(f"{pve_user}:{pve_ticket}\\n")
        first = await asyncio.wait_for(pve_ws.recv(), timeout=5.0)
        first_str = first.decode('utf-8', errors='replace') if isinstance(first, (bytes, bytearray)) else (first or '')
        if not first_str.startswith('OK'):
            print(f"[TERMPROXY] PVE rejected handshake: {first_str!r}")
            await client_ws.send(f'{{"status":"error","message":"PVE rejected: {first_str[:80]!r}"}}')
            await pve_ws.close()
            await client_ws.close(1011, "pve-auth")
            return
        print(f"[TERMPROXY] PVE handshake OK")
    except Exception as e:
        print(f"[TERMPROXY] handshake error: {type(e).__name__}: {e}")
        await client_ws.send(f'{{"status":"error","message":"handshake error: {type(e).__name__}"}}')
        try: await pve_ws.close()
        except: pass
        await client_ws.close(1011, "handshake")
        return

    await client_ws.send('{"status":"connected"}')

    # Bidirectional proxy
    async def pve_to_client():
        try:
            async for msg in pve_ws:
                # PVE termproxy sends raw bytes (TTY output)
                if isinstance(msg, (bytes, bytearray)):
                    await client_ws.send(msg.decode('utf-8', errors='replace'))
                else:
                    await client_ws.send(msg)
        except Exception as e:
            print(f"[TERMPROXY] PVE→client: {type(e).__name__}: {e}")

    async def client_to_pve():
        try:
            async for msg in client_ws:
                if isinstance(msg, str):
                    # Resize protocol: JSON {type:'resize', cols, rows}
                    if msg.startswith('{'):
                        try:
                            j = json.loads(msg)
                            if j.get('type') == 'resize':
                                cols = int(j.get('cols', 80))
                                rows = int(j.get('rows', 24))
                                await pve_ws.send(f"1:{cols}:{rows}:")
                                continue
                        except Exception:
                            pass
                    payload_len = len(msg.encode('utf-8'))
                    await pve_ws.send(f"0:{payload_len}:{msg}")
                else:
                    try: text = msg.decode('utf-8')
                    except Exception: text = msg.decode('latin-1', errors='replace')
                    await pve_ws.send(f"0:{len(msg)}:{text}")
        except Exception as e:
            print(f"[TERMPROXY] client→PVE: {type(e).__name__}: {e}")

    try:
        await asyncio.gather(pve_to_client(), client_to_pve(), return_exceptions=True)
    finally:
        try: await pve_ws.close()
        except: pass
        print(f"[TERMPROXY] session ended {vm_type}/{vmid_str}")


async def main():
    ssl_context = None
    if SSL_CERT and SSL_KEY and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)
    
    # Issue #71/#95: empty host = all interfaces (dual-stack IPv4+IPv6)
    ws_host = None if not BIND_HOST else BIND_HOST
    display_host = BIND_HOST or '0.0.0.0'
    # NS May 2026 (#388): wire the lenient_process_request hook so PVE 9.1.x
    # hosts (and any middlebox that strips the Upgrade token from Connection)
    # don't trigger InvalidUpgrade at SSH WS handshake. Was only on VNC before.
    # crcro on issue #388 reported the exact SSH-WS InvalidUpgrade trace this fixes.
    _lpr_ssh = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from pegaprox.utils.ws_lenient import lenient_process_request as _lpr_ssh
    except Exception as _e:
        print(f"[SSH-WS] WARNING: lenient_process_request not importable ({_e}) — strict handshake only")
    serve_kwargs = {'ssl': ssl_context, 'ping_interval': 30, 'ping_timeout': 10}
    if _lpr_ssh is not None:
        serve_kwargs['process_request'] = _lpr_ssh
    try:
        async with websockets.serve(ssh_handler, ws_host, PORT, **serve_kwargs):
            print(f"SSH WebSocket server ready on {display_host}:{PORT} (lenient-hook={_lpr_ssh is not None})")
            await asyncio.Future()
    except OSError as e:
        if ':' in str(display_host):
            print(f"SSH WebSocket: IPv6 bind failed ({e}), falling back to 0.0.0.0")
            async with websockets.serve(ssh_handler, '0.0.0.0', PORT, **serve_kwargs):
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
@sock.route('/api/clusters/<cluster_id>/nodes/<node>/shellws')
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
        cluster_url = f"https://{cluster_host}:{cluster_port}/api2/json/cluster/status"
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
        logging.exception(f"Shell error: {e}")
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

        if not target_node:
            return jsonify({'error': 'Target node is required'}), 400

        # NS Mar 2026: xapi.vm.migrate for XCP-ng clusters
        if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
            from pegaprox.utils.rbac import has_permission
            if not has_permission(user, 'xapi.vm.migrate'):
                return jsonify({'error': 'Permission denied: xapi.vm.migrate'}), 403

            result = manager.migrate_vm_manual(node, vmid, vm_type, target_node, online)
        else:
            target_storage = data.get('targetstorage')
            with_local_disks = data.get('with-local-disks', False)
            force = data.get('force', False)  # For conntrack state in containers

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
            log_audit(user, 'vm.migrated', details, cluster=manager.config.name)

            # NS: Register PegaProx user for this task
            upid = result.get('upid') or result.get('task') or result.get('data')
            if upid:
                register_task_user(upid, user, cluster_id)

            push_immediate_update(cluster_id, delay=0.5)
            return jsonify(result)
        else:
            return jsonify(result), 400
    except Exception as e:
        logging.error(f"[MIGRATE] Unhandled error migrating {vm_type}/{vmid}: {e}", exc_info=True)
        return jsonify({'error': 'Migration failed'}), 500


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
    # per-storage mapping: {"local-lvm": "ceph-pool", "local": "nfs-stor"} → PVE format "local-lvm:ceph-pool,local:nfs-stor"
    storage_map = data.get('target_storage_map')
    if storage_map and isinstance(storage_map, dict):
        target_storage = ','.join(f"{s}:{t}" for s, t in storage_map.items())
    # per-NIC bridge mapping: {"vmbr0": "vmbr1", "vmbr1": "vmbr2"} → PVE format "vmbr0:vmbr1,vmbr1:vmbr2"
    # NS: Apr 2026 - was using = instead of : (#274), PVE remote_migrate uses same format as target-storage
    bridge_map = data.get('target_bridge_map')
    if bridge_map and isinstance(bridge_map, dict):
        target_bridge = ','.join(f"{s}:{t}" for s, t in bridge_map.items())
    else:
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
                if key.startswith(('scsi', 'virtio', 'sata', 'ide', 'efidisk', 'tpmstate')) and 'size' in str(value):
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
        return jsonify({'error': safe_error(e, 'Cross-cluster migration failed')}), 500


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

    # LW: XCP-ng templates need xapi.template.view permission
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        from pegaprox.utils.rbac import has_permission
        users = load_users()
        u = users.get(request.session['user'], {})
        u['username'] = request.session['user']
        if not has_permission(u, 'xapi.template.view'):
            return jsonify({'error': 'Permission denied: xapi.template.view'}), 403

    templates = manager.get_templates(node)
    return jsonify(templates)


@bp.route('/api/clusters/<cluster_id>/xcp/os-types', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_xcp_os_types(cluster_id):
    """OS types for XCP-ng VM creation from scratch"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not hasattr(mgr, 'get_os_types'):
        return jsonify([])
    return jsonify(mgr.get_os_types())


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/qemu', methods=['POST'])
@require_auth(perms=["vm.create"])
def create_vm_api(cluster_id, node):
    """Create a new VM on a node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    manager = cluster_managers[cluster_id]

    # NS Mar 2026: XCP-ng clusters need xapi.vm.create permission
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        users = load_users()
        u = users.get(request.session['user'], {})
        u['username'] = request.session['user']
        from pegaprox.utils.rbac import has_permission
        if not has_permission(u, 'xapi.vm.create'):
            return jsonify({'error': 'Permission denied: xapi.vm.create'}), 403

    vm_config = request.json or {}

    result = manager.create_vm(node, vm_config)

    if result.get('success'):
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'unknown')
        vmid = vm_config.get('vmid') or result.get('vmid') or result.get('data', {}).get('vmid', 'unknown')
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

