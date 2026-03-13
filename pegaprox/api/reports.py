# -*- coding: utf-8 -*-
"""reports + legacy tags routes - split from monolith dec 2025, NS"""

import time
import logging
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *

from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.rbac import get_user_clusters
from pegaprox.api.helpers import check_cluster_access
from pegaprox.background.metrics import load_metrics_history, start_metrics_collector
from pegaprox.api.schedules import start_scheduler

bp = Blueprint('reports', __name__)

@bp.route('/api/reports/summary', methods=['GET'])
@require_auth()
def get_reports_summary():
    """Get summary report across all clusters

    Query params:
    - period: 'hour', 'day', 'week' (default: day)
    """
    period = request.args.get('period', 'day')

    # NS: Feb 2026 - tenant filtering for multi-tenant security
    usr = getattr(request, 'session', {}).get('user', 'system')
    users_db = load_users()
    user_data = users_db.get(usr, {})
    accessible_clusters = get_user_clusters(user_data)  # None = admin (all clusters)

    history = load_metrics_history()
    snapshots = history.get('snapshots', [])

    if not snapshots:
        return jsonify({'error': 'No historical data available yet'}), 404

    # Filter by period
    now = datetime.now()
    if period == 'hour':
        cutoff = now - timedelta(hours=1)
    elif period == 'week':
        cutoff = now - timedelta(days=7)
    else:  # day
        cutoff = now - timedelta(days=1)

    cutoff_str = cutoff.isoformat()
    filtered = [s for s in snapshots if s.get('timestamp', '') >= cutoff_str]

    if not filtered:
        return jsonify({'error': f'No data for the last {period}'}), 404

    # Calculate averages and trends
    report = {
        'period': period,
        'data_points': len(filtered),
        'start_time': filtered[0].get('timestamp'),
        'end_time': filtered[-1].get('timestamp'),
        'clusters': {}
    }

    # Aggregate per cluster
    for snapshot in filtered:
        for cluster_id, cluster_data in snapshot.get('clusters', {}).items():
            # Skip clusters the user cannot access
            if accessible_clusters is not None and cluster_id not in accessible_clusters:
                continue
            if cluster_id not in report['clusters']:
                report['clusters'][cluster_id] = {
                    'name': cluster_data.get('name', cluster_id),
                    'cpu_samples': [],
                    'mem_samples': [],
                    'vm_samples': []
                }
            
            totals = cluster_data.get('totals', {})
            if totals.get('cpu_total', 0) > 0:
                cpu_percent = totals['cpu_used'] / totals['cpu_total'] * 100
                report['clusters'][cluster_id]['cpu_samples'].append(cpu_percent)
            
            if totals.get('mem_total', 0) > 0:
                mem_percent = totals['mem_used'] / totals['mem_total'] * 100
                report['clusters'][cluster_id]['mem_samples'].append(mem_percent)
            
            vm_count = totals.get('vms_running', 0) + totals.get('cts_running', 0)
            report['clusters'][cluster_id]['vm_samples'].append(vm_count)
    
    # Calculate stats
    for cluster_id, data in report['clusters'].items():
        cpu = data.pop('cpu_samples', [])
        mem = data.pop('mem_samples', [])
        vms = data.pop('vm_samples', [])
        
        data['cpu'] = {
            'avg': round(sum(cpu) / len(cpu), 1) if cpu else 0,
            'min': round(min(cpu), 1) if cpu else 0,
            'max': round(max(cpu), 1) if cpu else 0,
            'current': round(cpu[-1], 1) if cpu else 0
        }
        
        data['memory'] = {
            'avg': round(sum(mem) / len(mem), 1) if mem else 0,
            'min': round(min(mem), 1) if mem else 0,
            'max': round(max(mem), 1) if mem else 0,
            'current': round(mem[-1], 1) if mem else 0
        }
        
        data['vms_running'] = {
            'avg': round(sum(vms) / len(vms), 1) if vms else 0,
            'min': min(vms) if vms else 0,
            'max': max(vms) if vms else 0,
            'current': vms[-1] if vms else 0
        }
    
    return jsonify(report)


@bp.route('/api/reports/timeline', methods=['GET'])
@require_auth()
def get_reports_timeline():
    """Get timeline data for charts

    Query params:
    - period: 'hour', 'day', 'week'
    - cluster_id: Optional - filter to specific cluster
    - metric: 'cpu', 'memory', 'vms' (default: all)
    """
    period = request.args.get('period', 'day')
    filter_cluster = request.args.get('cluster_id')
    metric = request.args.get('metric', 'all')

    # NS: Feb 2026 - tenant filtering for multi-tenant security
    usr = getattr(request, 'session', {}).get('user', 'system')
    users_db = load_users()
    user_data = users_db.get(usr, {})
    accessible_clusters = get_user_clusters(user_data)  # None = admin (all clusters)

    history = load_metrics_history()
    snapshots = history.get('snapshots', [])

    if not snapshots:
        return jsonify({'error': 'No historical data available'}), 404

    # Filter by period
    now = datetime.now()
    if period == 'hour':
        cutoff = now - timedelta(hours=1)
    elif period == 'week':
        cutoff = now - timedelta(days=7)
    else:
        cutoff = now - timedelta(days=1)

    cutoff_str = cutoff.isoformat()
    filtered = [s for s in snapshots if s.get('timestamp', '') >= cutoff_str]

    # Build timeline
    timeline = {
        'period': period,
        'timestamps': [],
        'data': {}
    }

    for snapshot in filtered:
        timestamp = snapshot.get('timestamp', '')
        timeline['timestamps'].append(timestamp)

        for cluster_id, cluster_data in snapshot.get('clusters', {}).items():
            if filter_cluster and cluster_id != filter_cluster:
                continue
            # Skip clusters the user cannot access
            if accessible_clusters is not None and cluster_id not in accessible_clusters:
                continue
            
            if cluster_id not in timeline['data']:
                timeline['data'][cluster_id] = {
                    'name': cluster_data.get('name', cluster_id),
                    'cpu': [],
                    'memory': [],
                    'vms': []
                }
            
            totals = cluster_data.get('totals', {})
            
            # CPU
            if metric in ['all', 'cpu']:
                cpu = 0
                if totals.get('cpu_total', 0) > 0:
                    cpu = round(totals['cpu_used'] / totals['cpu_total'] * 100, 1)
                timeline['data'][cluster_id]['cpu'].append(cpu)
            
            # Memory
            if metric in ['all', 'memory']:
                mem = 0
                if totals.get('mem_total', 0) > 0:
                    mem = round(totals['mem_used'] / totals['mem_total'] * 100, 1)
                timeline['data'][cluster_id]['memory'].append(mem)
            
            # VMs
            if metric in ['all', 'vms']:
                vms = totals.get('vms_running', 0) + totals.get('cts_running', 0)
                timeline['data'][cluster_id]['vms'].append(vms)
    
    return jsonify(timeline)


@bp.route('/api/reports/top-vms', methods=['GET'])
@require_auth()
def get_top_vms():
    """Get top VMs by resource usage

    Query params:
    - metric: 'cpu' or 'memory' (default: cpu)
    - limit: Number of results (default: 10)
    """
    metric = request.args.get('metric', 'cpu')
    limit = int(request.args.get('limit', 10))

    # NS: Feb 2026 - tenant filtering for multi-tenant security
    usr = getattr(request, 'session', {}).get('user', 'system')
    users_db = load_users()
    user_data = users_db.get(usr, {})
    accessible_clusters = get_user_clusters(user_data)  # None = admin (all clusters)

    vms = []

    for cluster_id, mgr in cluster_managers.items():
        # Skip clusters the user cannot access
        if accessible_clusters is not None and cluster_id not in accessible_clusters:
            continue
        if not mgr.is_connected:
            continue
        
        try:
            resources = mgr.get_vm_resources()
            for r in resources:
                if r.get('status') != 'running':
                    continue
                
                vm_data = {
                    'cluster_id': cluster_id,
                    'cluster_name': mgr.config.name,
                    'vmid': r.get('vmid'),
                    'name': r.get('name'),
                    'node': r.get('node'),
                    'type': r.get('type'),
                    'cpu': r.get('cpu', 0),
                    'mem': r.get('mem', 0),
                    'maxmem': r.get('maxmem', 0),
                    'mem_percent': round(r.get('mem', 0) / max(r.get('maxmem', 1), 1) * 100, 1)
                }
                vms.append(vm_data)
        except:
            pass
    
    # Sort by metric
    if metric == 'memory':
        vms.sort(key=lambda x: x.get('mem_percent', 0), reverse=True)
    else:
        vms.sort(key=lambda x: x.get('cpu', 0), reverse=True)
    
    return jsonify(vms[:limit])


# Start background threads when server starts
# MK: Move this to main() later, for now it's fine here
threading.Thread(target=lambda: (time.sleep(5), start_scheduler()), daemon=True).start()
threading.Thread(target=lambda: (time.sleep(10), start_metrics_collector()), daemon=True).start()


# ============================================
# Legacy Fallback Endpoints
# old tags endpoints, kept for compat, these prevent 404s
# ============================================

@bp.route('/api/tags', methods=['GET'])
@require_auth()
def get_tags_legacy():
    """Legacy: Returns empty for old Settings UI"""
    return jsonify({'tags': {}, 'available_tags': []})

@bp.route('/api/tags/available', methods=['GET'])
@require_auth()
def get_available_tags_legacy():
    """Legacy: Returns empty list"""
    return jsonify([])

@bp.route('/api/tags/available', methods=['POST'])
@require_auth()
def create_tag_legacy():
    """Legacy: Redirect to cluster-based tags"""
    return jsonify({'error': 'Please use VM-based tags (click tag icon on VMs)'}), 400

@bp.route('/api/tags/available/<tag_name>', methods=['DELETE'])
@require_auth()
def delete_tag_legacy(tag_name):
    """Legacy: No-op"""
    return jsonify({'success': True})


# ============================================
# Cluster-Based Reports Endpoint
# reports are now per-cluster, not global
# ============================================

@bp.route('/api/clusters/<cluster_id>/reports/summary', methods=['GET'])
@require_auth()
def get_cluster_report_summary(cluster_id):
    """Get report summary for a specific cluster

    Returns both historical data (if available) and current live data
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    period = request.args.get('period', 'day')

    # Get LIVE current data from cluster using get_node_status()
    live_cpu = 0
    live_vms = 0
    live_cts = 0
    cpu_total = 0
    mem_total = 0
    mem_used = 0
    nodes_online = 0

    if mgr.is_connected:
        try:
            # Use get_node_status which actually fetches live data from Proxmox
            node_status = mgr.get_node_status()

            for node_name, node_data in node_status.items():
                if not node_data:
                    continue
                # Check status
                status = node_data.get('status', '')
                if status in ['online', 'running']:
                    nodes_online += 1
                    # CPU and memory from get_node_status are already percentages
                    cpu_pct = node_data.get('cpu_percent', 0) or 0
                    mem_pct = node_data.get('mem_percent', 0) or 0
                    mem_t = node_data.get('mem_total', 0) or 0
                    mem_u = node_data.get('mem_used', 0) or 0

                    # Accumulate (we'll average later)
                    live_cpu += cpu_pct
                    mem_total += mem_t
                    mem_used += mem_u

            # Average CPU across nodes
            if nodes_online > 0:
                live_cpu = live_cpu / nodes_online
        except Exception as e:
            logging.error(f"Error getting node status for reports: {e}")

        # Count running VMs
        try:
            resources = mgr.get_vm_resources() or []
            for r in resources:
                if r and r.get('status') == 'running':
                    if r.get('type') == 'qemu':
                        live_vms += 1
                    else:
                        live_cts += 1
        except Exception as e:
            logging.error(f"Error getting VM resources: {e}")

    # Calculate live percentages
    live_cpu_pct = round(live_cpu, 1)
    live_mem_pct = round(mem_used / max(mem_total, 1) * 100, 1) if mem_total > 0 else 0

    # Load historical metrics
    history = load_metrics_history()
    snapshots = history.get('snapshots', [])

    # Filter by period
    now = datetime.now()
    if period == 'hour':
        cutoff = now - timedelta(hours=1)
    elif period == 'week':
        cutoff = now - timedelta(days=7)
    else:
        cutoff = now - timedelta(days=1)

    cutoff_str = cutoff.isoformat()
    filtered = [s for s in snapshots if s.get('timestamp', '') >= cutoff_str]

    # Extract data for this cluster only
    report = {
        'period': period,
        'cluster_id': cluster_id,
        'cluster_name': getattr(mgr.config, 'name', None) or cluster_id,
        'data_points': 0,
        'cpu': {'avg': live_cpu_pct, 'min': live_cpu_pct, 'max': live_cpu_pct, 'current': live_cpu_pct, 'samples': []},
        'memory': {'avg': live_mem_pct, 'min': live_mem_pct, 'max': live_mem_pct, 'current': live_mem_pct, 'samples': []},
        'vms_running': {'avg': live_vms + live_cts, 'min': live_vms + live_cts, 'max': live_vms + live_cts, 'current': live_vms + live_cts, 'samples': []},
        'timestamps': [],
        # Add live data section
        'live': {
            'cpu_percent': live_cpu_pct,
            'mem_percent': live_mem_pct,
            'vms_running': live_vms,
            'cts_running': live_cts,
            'cpu_total': cpu_total,
            'mem_total': mem_total,
            'mem_used': mem_used
        }
    }

    for snapshot in filtered:
        cluster_data = snapshot.get('clusters', {}).get(cluster_id)
        if not cluster_data:
            continue

        report['timestamps'].append(snapshot.get('timestamp', ''))
        report['data_points'] += 1

        totals = cluster_data.get('totals', {})

        # CPU
        if totals.get('cpu_total', 0) > 0:
            cpu = round(totals['cpu_used'] / totals['cpu_total'] * 100, 1)
            report['cpu']['samples'].append(cpu)

        # Memory
        if totals.get('mem_total', 0) > 0:
            mem = round(totals['mem_used'] / totals['mem_total'] * 100, 1)
            report['memory']['samples'].append(mem)

        # VMs
        vms = totals.get('vms_running', 0) + totals.get('cts_running', 0)
        report['vms_running']['samples'].append(vms)

    # Calculate stats from historical data (if available)
    for metric in ['cpu', 'memory', 'vms_running']:
        samples = report[metric].pop('samples', [])
        if samples:
            report[metric]['avg'] = round(sum(samples) / len(samples), 1)
            report[metric]['min'] = round(min(samples), 1)
            report[metric]['max'] = round(max(samples), 1)
            report[metric]['current'] = round(samples[-1], 1) if samples else report[metric]['current']

    return jsonify(report)
