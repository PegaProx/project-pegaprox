# -*- coding: utf-8 -*-
"""migration history, affinity rules & scheduled tasks - split from monolith dec 2025, LW/NS"""

import os
import json
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.background.scheduler import load_scheduled_tasks, save_scheduled_tasks, execute_scheduled_task
from pegaprox.api.helpers import get_connected_manager, check_cluster_access

bp = Blueprint('history', __name__)

@bp.route('/api/scheduled-tasks', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_scheduled_tasks():
    """Get all scheduled tasks"""
    return jsonify(load_scheduled_tasks())

@bp.route('/api/scheduled-tasks', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_scheduled_task():
    """Create a new scheduled task"""
    data = request.json or {}
    config = load_scheduled_tasks()
    
    import uuid
    new_task = {
        'id': str(uuid.uuid4())[:8],
        'name': data.get('name', 'New Task'),
        'cluster_id': data.get('cluster_id', ''),
        'target_type': data.get('target_type', 'qemu'),
        'target_id': data.get('target_id', ''),
        'target_node': data.get('target_node', ''),
        'action': data.get('action', 'snapshot'),  # start, stop, restart, snapshot, backup
        'schedule_type': data.get('schedule_type', 'daily'),  # hourly, daily, weekly, monthly
        'schedule_time': data.get('schedule_time', '02:00'),
        'schedule_day': data.get('schedule_day', 0),
        'backup_storage': data.get('backup_storage', 'local'),
        'enabled': data.get('enabled', True),
        'last_run': None,
        'created': datetime.now().isoformat()
    }
    
    config['tasks'].append(new_task)
    save_scheduled_tasks(config)
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'scheduled_task.created', f"Created scheduled task: {new_task['name']}")
    
    return jsonify(new_task), 201

@bp.route('/api/scheduled-tasks/<task_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_scheduled_task(task_id):
    """Update a scheduled task"""
    data = request.json or {}
    config = load_scheduled_tasks()
    
    for task in config['tasks']:
        if task['id'] == task_id:
            task.update({
                'name': data.get('name', task['name']),
                'cluster_id': data.get('cluster_id', task['cluster_id']),
                'target_type': data.get('target_type', task['target_type']),
                'target_id': data.get('target_id', task['target_id']),
                'target_node': data.get('target_node', task['target_node']),
                'action': data.get('action', task['action']),
                'schedule_type': data.get('schedule_type', task['schedule_type']),
                'schedule_time': data.get('schedule_time', task['schedule_time']),
                'schedule_day': data.get('schedule_day', task['schedule_day']),
                'backup_storage': data.get('backup_storage', task.get('backup_storage', 'local')),
                'enabled': data.get('enabled', task['enabled']),
            })
            save_scheduled_tasks(config)
            return jsonify(task)
    
    return jsonify({'error': 'Task not found'}), 404

@bp.route('/api/scheduled-tasks/<task_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_scheduled_task(task_id):
    """Delete a scheduled task"""
    config = load_scheduled_tasks()
    config['tasks'] = [t for t in config['tasks'] if t['id'] != task_id]
    save_scheduled_tasks(config)
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'scheduled_task.deleted', f"Deleted scheduled task: {task_id}")
    
    return jsonify({'success': True})

@bp.route('/api/scheduled-tasks/<task_id>/run', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def run_scheduled_task_now(task_id):
    """Run a scheduled task immediately"""
    config = load_scheduled_tasks()
    
    for task in config['tasks']:
        if task['id'] == task_id:
            execute_scheduled_task(task)
            task['last_run'] = datetime.now().isoformat()
            save_scheduled_tasks(config)
            return jsonify({'success': True, 'message': f"Task '{task['name']}' executed"})
    
    return jsonify({'error': 'Task not found'}), 404


# =====================================================
# MIGRATION HISTORY - LW: Dec 2025
# SQLite version
# =====================================================

def load_migration_history():
    """Load migration history from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM migration_history ORDER BY timestamp DESC LIMIT 1000')
        
        migrations = []
        for row in cursor.fetchall():
            migrations.append({
                'id': row['id'],
                'cluster_id': row['cluster_id'],
                'vmid': row['vmid'],
                'vm_name': row['vm_name'],
                'source_node': row['source_node'],
                'target_node': row['target_node'],
                'reason': row['reason'],
                'status': row['status'],
                'duration': row['duration_seconds'],
                'timestamp': row['timestamp'],
            })
        
        return {'migrations': migrations}
    except Exception as e:
        logging.error(f"Error loading migration history from database: {e}")
        # Legacy fallback
        if os.path.exists(MIGRATION_HISTORY_FILE):
            try:
                with open(MIGRATION_HISTORY_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
    return {'migrations': []}


def save_migration_history(config):
    """Save migration history - now handled per-entry via log_migration()
    
    saves directly to db
    This function is kept for backwards compatibility
    """
    # In SQLite version, saving is handled per-entry in log_migration()
    pass


def log_migration(cluster_id: str, vmid: int, vm_name: str, vm_type: str, 
                  source_node: str, target_node: str, migration_type: str,
                  status: str, user: str = 'system', duration: float = 0):
    """Log a VM migration event to SQLite database
    
    MK: Called from migrate_vm and HA failover functions
    writes to db now
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        cursor.execute('''
            INSERT INTO migration_history
            (cluster_id, vmid, vm_name, source_node, target_node, 
             reason, status, duration_seconds, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cluster_id,
            vmid,
            vm_name,
            source_node,
            target_node,
            f"{migration_type} by {user}",
            status,
            duration,
            datetime.now().isoformat()
        ))
        
        db.conn.commit()
        
        # Cleanup old entries (keep last 1000)
        cursor.execute('''
            DELETE FROM migration_history 
            WHERE id NOT IN (
                SELECT id FROM migration_history 
                ORDER BY timestamp DESC LIMIT 1000
            )
        ''')
        db.conn.commit()
        
    except Exception as e:
        logging.error(f"Error logging migration: {e}")
    
    return {
        'cluster_id': cluster_id,
        'vmid': vmid,
        'vm_name': vm_name,
        'source_node': source_node,
        'target_node': target_node,
        'migration_type': migration_type,
        'status': status,
        'user': user,
        'duration': duration,
        'timestamp': datetime.now().isoformat()
    }

@bp.route('/api/migration-history', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_migration_history():
    """Get migration history"""
    config = load_migration_history()
    
    # Optional filters
    cluster_id = request.args.get('cluster_id')
    vmid = request.args.get('vmid')
    limit = int(request.args.get('limit', 100))
    
    migrations = config.get('migrations', [])
    
    if cluster_id:
        migrations = [m for m in migrations if m.get('cluster_id') == cluster_id]
    if vmid:
        migrations = [m for m in migrations if str(m.get('vmid')) == str(vmid)]
    
    return jsonify(migrations[:limit])

@bp.route('/api/clusters/<cluster_id>/vms/<int:vmid>/migration-history', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_vm_migration_history(cluster_id, vmid):
    """Get migration history for a specific VM"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    config = load_migration_history()
    
    migrations = [m for m in config.get('migrations', []) 
                  if m.get('cluster_id') == cluster_id and m.get('vmid') == vmid]
    
    return jsonify(migrations)


# =====================================================
# AFFINITY RULES - keeps VMs together or apart
# =====================================================

def load_affinity_rules():
    """Load affinity rules from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        rules_by_cluster = db.get_affinity_rules()
        
        # Convert to flat list format
        all_rules = []
        for cluster_id, rules in rules_by_cluster.items():
            for rule in rules:
                rule['cluster_id'] = cluster_id
                all_rules.append(rule)
        
        return {'rules': all_rules}
    except Exception as e:
        logging.error(f"Error loading affinity rules: {e}")
        # Legacy fallback
        if os.path.exists(AFFINITY_RULES_FILE):
            try:
                with open(AFFINITY_RULES_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
    return {'rules': []}


def save_affinity_rules(config):
    """Save affinity rules to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        
        # Group rules by cluster_id
        rules_by_cluster = {}
        for rule in config.get('rules', []):
            cluster_id = rule.get('cluster_id', 'default')
            if cluster_id not in rules_by_cluster:
                rules_by_cluster[cluster_id] = []
            rules_by_cluster[cluster_id].append(rule)
        
        db.save_all_affinity_rules(rules_by_cluster)
        return True
    except Exception as e:
        logging.error(f"Error saving affinity rules: {e}")
        return False

def check_affinity_violation(cluster_id: str, vmid: int, target_node: str) -> dict:
    """Check if moving a VM/CT to a node would violate affinity rules

    NS: Feb 2026 - returns enforce flag so callers can block or just warn.
    Works for both QEMU and LXC now (Issue #73).
    """
    config = load_affinity_rules()
    
    if cluster_id not in cluster_managers:
        return {'violation': False}
    
    manager = cluster_managers[cluster_id]
    resources = manager.get_resources()
    
    # Build map of VM -> current node
    vm_nodes = {}
    for res in resources:
        if res.get('type') in ['qemu', 'lxc']:
            vm_nodes[str(res.get('vmid'))] = res.get('node')
    
    for rule in config.get('rules', []):
        if rule.get('cluster_id') != cluster_id or not rule.get('enabled', True):
            continue

        rule_type = rule.get('type', 'together')  # together, separate
        # MK: db stores as 'vms', frontend sends 'vm_ids' - was always reading empty list before
        vm_ids = [str(v) for v in (rule.get('vm_ids') or rule.get('vms', []))]

        if str(vmid) not in vm_ids:
            continue

        # Get nodes of other VMs/CTs in this rule
        other_nodes = set()
        for vid in vm_ids:
            if vid != str(vmid) and vid in vm_nodes:
                other_nodes.add(vm_nodes[vid])

        if rule_type == 'together':
            # All VMs/CTs should be on same node
            if other_nodes and target_node not in other_nodes:
                return {
                    'violation': True,
                    'enforce': rule.get('enforce', False),
                    'rule': rule.get('name', 'Affinity Rule'),
                    'message': f"VM/CT must stay with IDs {', '.join([v for v in vm_ids if v != str(vmid)])} on node {list(other_nodes)[0]}"
                }

        elif rule_type == 'separate':
            # VMs/CTs should be on different nodes
            if target_node in other_nodes:
                return {
                    'violation': True,
                    'enforce': rule.get('enforce', False),
                    'rule': rule.get('name', 'Anti-Affinity Rule'),
                    'message': f"VM/CT must not be on the same node as IDs {', '.join([v for v in vm_ids if v != str(vmid) and vm_nodes.get(v) == target_node])}"
                }

    return {'violation': False}

@bp.route('/api/affinity-rules', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_affinity_rules():
    """Get all affinity rules"""
    return jsonify(load_affinity_rules())

@bp.route('/api/affinity-rules', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_affinity_rule():
    """Create a new affinity rule"""
    data = request.json or {}
    config = load_affinity_rules()
    
    import uuid
    # MK: frontend sends vm_ids, db column is vms - accept both
    vms_data = data.get('vm_ids') or data.get('vms', [])
    new_rule = {
        'id': str(uuid.uuid4())[:8],
        'name': data.get('name', 'New Rule'),
        'cluster_id': data.get('cluster_id', ''),
        'type': data.get('type', 'together'),  # together, separate
        'vms': vms_data,
        'vm_ids': vms_data,  # keep both so frontend doesn't break
        'enabled': data.get('enabled', True),
        'enforce': data.get('enforce', False),
        'created': datetime.now().isoformat()
    }
    
    config['rules'].append(new_rule)
    save_affinity_rules(config)
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'affinity_rule.created', f"Created affinity rule: {new_rule['name']}")
    
    return jsonify(new_rule), 201

@bp.route('/api/affinity-rules/<rule_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_affinity_rule(rule_id):
    """Update an affinity rule"""
    data = request.json or {}
    config = load_affinity_rules()
    
    for rule in config['rules']:
        if rule['id'] == rule_id:
            # MK: try every possible source for the vm list
            vms_data = data.get('vm_ids') or data.get('vms') or rule.get('vms') or rule.get('vm_ids', [])
            rule.update({
                'name': data.get('name', rule['name']),
                'cluster_id': data.get('cluster_id', rule['cluster_id']),
                'type': data.get('type', rule['type']),
                'vms': vms_data,
                'vm_ids': vms_data,
                'enabled': data.get('enabled', rule['enabled']),
                'enforce': data.get('enforce', rule.get('enforce', False)),
            })
            save_affinity_rules(config)
            return jsonify(rule)
    
    return jsonify({'error': 'Rule not found'}), 404

@bp.route('/api/affinity-rules/<rule_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_affinity_rule(rule_id):
    """Delete an affinity rule"""
    config = load_affinity_rules()
    config['rules'] = [r for r in config['rules'] if r['id'] != rule_id]
    save_affinity_rules(config)
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'affinity_rule.deleted', f"Deleted affinity rule: {rule_id}")
    
    return jsonify({'success': True})

@bp.route('/api/clusters/<cluster_id>/vms/<int:vmid>/check-affinity/<target_node>', methods=['GET'])
@require_auth(perms=['vm.view'])
def check_vm_affinity(cluster_id, vmid, target_node):
    """Check if moving VM to target node would violate affinity rules"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    result = check_affinity_violation(cluster_id, vmid, target_node)
    return jsonify(result)


