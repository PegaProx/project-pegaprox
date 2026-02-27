# -*- coding: utf-8 -*-
"""alerts & cluster affinity rules routes - split from monolith dec 2025, NS/MK"""

import os
import json
import logging
import uuid
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import check_cluster_access
from pegaprox.background.alerts import load_alerts_config, save_alerts_config

bp = Blueprint('alerts', __name__)

# NOTE: get_cluster_report_summary is in reports.py (no duplicate here)

@bp.route('/api/clusters/<cluster_id>/reports/top-vms', methods=['GET'])
@require_auth()
def get_cluster_top_vms(cluster_id):
    """Get top VMs by resource usage for a specific cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: 
        return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    metric = request.args.get('metric', 'cpu')
    limit = int(request.args.get('limit', 10))
    
    if not mgr.is_connected:
        return jsonify([])
    
    vms = []
    try:
        resources = mgr.get_vm_resources()
        for r in resources:
            if r.get('status') != 'running':
                continue
            
            vm_data = {
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


# ============================================
# Cluster-Based Alerts Endpoints
# moved to per-cluster
# ============================================

def load_cluster_alerts():
    """Load alerts config from SQLite database
    
    NS: Migrated from JSON to SQLite Jan 2026
    MK: keeps falling back to json if db fails which is kinda nice for debugging
    
    Returns: {cluster_id: [list of alert objects]}
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM cluster_alerts WHERE enabled = 1')
        
        alerts = {}
        for row in cursor.fetchall():
            cluster_id = row['cluster_id']
            if cluster_id not in alerts:
                alerts[cluster_id] = []
            
            try:
                # config contains the full alert object as JSON
                alert_data = json.loads(row['config'] or '{}')
                # ensure id is present
                if 'id' not in alert_data:
                    alert_data['id'] = row['alert_type']
                alerts[cluster_id].append(alert_data)
            except:
                # fallback for old format where config was just settings
                alerts[cluster_id].append({
                    'id': row['alert_type'],
                    'name': row['alert_type'],
                    'config': row['config']
                })
        
        return alerts
    except Exception as e:
        logging.error(f"Error loading cluster alerts from DB: {e}")
        # Fallback to JSON for backwards compat
        try:
            alerts_file = os.path.join(CONFIG_DIR, 'cluster_alerts.json')
            if os.path.exists(alerts_file):
                with open(alerts_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

def save_cluster_alerts(alerts):
    """Save alerts config to SQLite database
    
    NS: stores each alert as a row with config containing full alert object
    
    Expects: {cluster_id: [list of alert objects]}
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        now = datetime.now().isoformat()
        
        for cluster_id, alert_list in alerts.items():
            # Handle list format (from API)
            if isinstance(alert_list, list):
                for alert in alert_list:
                    alert_id = alert.get('id', str(uuid.uuid4())[:8])
                    cursor.execute('''
                        INSERT OR REPLACE INTO cluster_alerts 
                        (cluster_id, alert_type, config, enabled, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        cluster_id,
                        alert_id,
                        json.dumps(alert),
                        1 if alert.get('enabled', True) else 0,
                        now
                    ))
            # Handle dict format (legacy)
            elif isinstance(alert_list, dict):
                for alert_type, config in alert_list.items():
                    cursor.execute('''
                        INSERT OR REPLACE INTO cluster_alerts 
                        (cluster_id, alert_type, config, enabled, updated_at)
                        VALUES (?, ?, ?, 1, ?)
                    ''', (
                        cluster_id,
                        alert_type,
                        json.dumps(config) if isinstance(config, dict) else str(config),
                        now
                    ))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving cluster alerts to DB: {e}")

@bp.route('/api/clusters/<cluster_id>/alerts', methods=['GET'])
@require_auth()
def get_cluster_alerts(cluster_id):
    """Get alerts for a specific cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    try:
        alerts = load_cluster_alerts()
        cluster_alerts = alerts.get(cluster_id, [])
        return jsonify({'alerts': cluster_alerts})
    except Exception as e:
        logging.error(f"Error getting cluster alerts: {e}")
        return jsonify({'alerts': [], 'error': str(e)})

@bp.route('/api/clusters/<cluster_id>/alerts', methods=['POST'])
@require_auth(perms=['cluster.config'])
def create_cluster_alert(cluster_id):
    """Create a new alert for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    alerts = load_cluster_alerts()
    if cluster_id not in alerts:
        alerts[cluster_id] = []
    
    alert = {
        'id': str(uuid.uuid4())[:8],
        'name': data.get('name', 'Unnamed Alert'),
        'metric': data.get('metric', 'cpu'),
        'operator': data.get('operator', '>'),
        'threshold': data.get('threshold', 80),
        'target_type': data.get('target_type', 'cluster'),
        'target_id': data.get('target_id'),
        'action': data.get('action', 'log'),
        'enabled': data.get('enabled', True),
        'created_at': datetime.now().isoformat()
    }
    
    alerts[cluster_id].append(alert)
    save_cluster_alerts(alerts)
    
    return jsonify({'success': True, 'alert': alert})

@bp.route('/api/clusters/<cluster_id>/alerts/<alert_id>', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def update_cluster_alert(cluster_id, alert_id):
    """Update an alert"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    data = request.get_json()
    alerts = load_cluster_alerts()
    cluster_alerts = alerts.get(cluster_id, [])
    
    for alert in cluster_alerts:
        if alert['id'] == alert_id:
            if 'enabled' in data:
                alert['enabled'] = data['enabled']
            if 'name' in data:
                alert['name'] = data['name']
            if 'threshold' in data:
                alert['threshold'] = data['threshold']
            save_cluster_alerts(alerts)
            return jsonify({'success': True, 'alert': alert})
    
    return jsonify({'error': 'Alert not found'}), 404

@bp.route('/api/clusters/<cluster_id>/alerts/<alert_id>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_cluster_alert(cluster_id, alert_id):
    """Delete an alert"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    # NS: delete directly from DB for efficiency
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('DELETE FROM cluster_alerts WHERE cluster_id = ? AND alert_type = ?',
                      (cluster_id, alert_id))
        db.conn.commit()
        deleted = cursor.rowcount > 0
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        logging.error(f"Error deleting cluster alert: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# Cluster-Based Affinity Rules Endpoints
# moved to per-cluster
# ============================================

def load_cluster_affinity_rules():
    """Load affinity rules from SQLite database
    
    MK: affinity = keep VMs together, anti-affinity = keep them apart
    useful for HA where you want replicas on different hosts
    NS: reuses the affinity_rules table we already had
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM affinity_rules WHERE enabled = 1')
        
        rules = {}
        for row in cursor.fetchall():
            cluster_id = row['cluster_id']
            if cluster_id not in rules:
                rules[cluster_id] = []
            
            vms_list = json.loads(row['vms'] or '[]')
            rules[cluster_id].append({
                'id': row['id'],
                'name': row['name'],
                'type': row['type'],
                'vms': vms_list,
                'vm_ids': vms_list,  # NS: alias for frontend compatibility
                'enabled': bool(row['enabled']),
                'enforce': bool(row.get('enforce', 0)),
                'created_at': row['created_at']
            })
        
        return rules
    except Exception as e:
        logging.error(f"Error loading affinity rules from DB: {e}")
        # Fallback to JSON for backwards compat
        try:
            rules_file = os.path.join(CONFIG_DIR, 'cluster_affinity_rules.json')
            if os.path.exists(rules_file):
                with open(rules_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

def save_cluster_affinity_rules(rules):
    """Save affinity rules to SQLite database
    
    NS: uses upsert pattern, handles both 'vms' and 'vm_ids' field names
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        now = datetime.now().isoformat()
        
        for cluster_id, cluster_rules in rules.items():
            for rule in cluster_rules:
                # generate id if missing (old rules might not have one)
                rule_id = rule.get('id', str(uuid.uuid4()))
                # NS: handle both 'vms' and 'vm_ids' field names
                vms_data = rule.get('vms') or rule.get('vm_ids') or []
                cursor.execute('''
                    INSERT OR REPLACE INTO affinity_rules
                    (id, cluster_id, name, type, vms, enabled, enforce, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule_id,
                    cluster_id,
                    rule.get('name', ''),
                    rule.get('type', 'affinity'),
                    json.dumps(vms_data),
                    1 if rule.get('enabled', True) else 0,
                    1 if rule.get('enforce', False) else 0,
                    rule.get('created_at', now)
                ))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving affinity rules to DB: {e}")

@bp.route('/api/clusters/<cluster_id>/affinity-rules', methods=['GET'])
@require_auth()
def get_cluster_affinity_rules(cluster_id):
    """Get affinity rules for a specific cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    try:
        rules = load_cluster_affinity_rules()
        cluster_rules = rules.get(cluster_id, [])
        return jsonify({'rules': cluster_rules})
    except Exception as e:
        logging.error(f"Error getting affinity rules: {e}")
        return jsonify({'rules': [], 'error': str(e)})

@bp.route('/api/clusters/<cluster_id>/affinity-rules', methods=['POST'])
@require_auth(perms=['cluster.config'])
def create_cluster_affinity_rule(cluster_id):
    """Create a new affinity rule for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    rules = load_cluster_affinity_rules()
    if cluster_id not in rules:
        rules[cluster_id] = []
    
    # NS: get vms from either 'vm_ids' or 'vms' field
    vms_data = data.get('vm_ids') or data.get('vms') or []
    
    rule = {
        'id': str(uuid.uuid4())[:8],
        'name': data.get('name', f"Rule {len(rules[cluster_id]) + 1}"),
        'type': data.get('type', 'together'),  # 'together' or 'separate'
        'vms': vms_data,
        'vm_ids': vms_data,  # alias for frontend
        'enforce': data.get('enforce', False),
        'enabled': True,
        'created_at': datetime.now().isoformat()
    }
    
    rules[cluster_id].append(rule)
    save_cluster_affinity_rules(rules)
    
    return jsonify({'success': True, 'rule': rule})

@bp.route('/api/clusters/<cluster_id>/affinity-rules/<rule_id>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_cluster_affinity_rule(cluster_id, rule_id):
    """Delete an affinity rule"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    
    # NS: Delete directly from DB instead of load/filter/save
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('DELETE FROM affinity_rules WHERE id = ? AND cluster_id = ?', 
                      (rule_id, cluster_id))
        db.conn.commit()
        deleted = cursor.rowcount > 0
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        logging.error(f"Error deleting affinity rule: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================

@bp.route('/api/alerts', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_alerts():
    """Get all alert configurations"""
    return jsonify(load_alerts_config())

@bp.route('/api/alerts', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_alert():
    """Create a new alert"""
    data = request.json or {}
    config = load_alerts_config()
    
    import uuid
    new_alert = {
        'id': str(uuid.uuid4())[:8],
        'name': data.get('name', 'New Alert'),
        'cluster_id': data.get('cluster_id', ''),
        'target_type': data.get('target_type', 'cluster'),
        'target_id': data.get('target_id', ''),
        'metric': data.get('metric', 'cpu'),
        'operator': data.get('operator', '>'),
        'threshold': data.get('threshold', 80),
        'enabled': data.get('enabled', True),
        'created': datetime.now().isoformat()
    }
    
    config['alerts'].append(new_alert)
    save_alerts_config(config)
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'alert.created', f"Created alert: {new_alert['name']}")
    
    return jsonify(new_alert), 201

@bp.route('/api/alerts/<alert_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_alert(alert_id):
    """Update an alert"""
    data = request.json or {}
    config = load_alerts_config()
    
    for alert in config['alerts']:
        if alert['id'] == alert_id:
            alert.update({
                'name': data.get('name', alert['name']),
                'cluster_id': data.get('cluster_id', alert['cluster_id']),
                'target_type': data.get('target_type', alert['target_type']),
                'target_id': data.get('target_id', alert['target_id']),
                'metric': data.get('metric', alert['metric']),
                'operator': data.get('operator', alert['operator']),
                'threshold': data.get('threshold', alert['threshold']),
                'enabled': data.get('enabled', alert['enabled']),
            })
            save_alerts_config(config)
            return jsonify(alert)
    
    return jsonify({'error': 'Alert not found'}), 404

@bp.route('/api/alerts/<alert_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_alert(alert_id):
    """Delete an alert"""
    config = load_alerts_config()
    config['alerts'] = [a for a in config['alerts'] if a['id'] != alert_id]
    save_alerts_config(config)
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'alert.deleted', f"Deleted alert: {alert_id}")
    
    return jsonify({'success': True})


# =====================================================

