# -*- coding: utf-8 -*-
"""scheduler + update schedule routes - split from monolith dec 2025, MK/NS"""

import os
import json
import time
import logging
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import check_cluster_access
from pegaprox.api.nodes import cleanup_deleted_scripts, cleanup_orphaned_excluded_vms

bp = Blueprint('schedules', __name__)

# ============================================

SCHEDULES_FILE = os.path.join(CONFIG_DIR, 'scheduled_actions.json')
_scheduler_thread = None
_scheduler_running = False

def load_schedules():
    """Load scheduled actions from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM scheduled_actions')
        
        actions = []
        last_id = 0
        for row in cursor.fetchall():
            if row['id'] > last_id:
                last_id = row['id']
            actions.append({
                'id': row['id'],
                'cluster_id': row['cluster_id'],
                'vmid': row['vmid'],
                'action': row['action'],
                'schedule_type': row['schedule_type'],
                'time': row['schedule_time'],
                'days': json.loads(row['schedule_days'] or '[]'),
                'date': row['schedule_date'],
                'enabled': bool(row['enabled']),
                'last_run': row['last_run'],
                'created_by': row['created_by'],
            })
        
        return {'actions': actions, 'last_id': last_id}
    except Exception as e:
        logging.error(f"Error loading schedules from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(SCHEDULES_FILE):
                with open(SCHEDULES_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
    return {'actions': [], 'last_id': 0}


def save_schedules(schedules):
    """Save scheduled actions to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Clear existing schedules
        cursor.execute('DELETE FROM scheduled_actions')
        
        now = datetime.now().isoformat()
        for action in schedules.get('actions', []):
            cursor.execute('''
                INSERT INTO scheduled_actions 
                (id, cluster_id, vmid, action, schedule_type, schedule_time, 
                 schedule_days, schedule_date, enabled, last_run, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action.get('id'),
                action.get('cluster_id'),
                action.get('vmid'),
                action.get('action', ''),
                action.get('schedule_type', 'daily'),
                action.get('time', ''),
                json.dumps(action.get('days', [])),
                action.get('date'),
                1 if action.get('enabled', True) else 0,
                action.get('last_run'),
                action.get('created_by'),
                now
            ))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving schedules: {e}")


def check_schedules():
    """Check if any scheduled actions need to run
    
    Called every minute by the scheduler thread
    This is deliberately simple - no cron expressions, just specific times
    """
    global _scheduler_running
    
    while _scheduler_running:
        try:
            schedules = load_schedules()
            now = datetime.now()
            current_time = now.strftime('%H:%M')
            current_day = now.strftime('%A').lower()
            current_date = now.strftime('%Y-%m-%d')
            
            modified = False
            
            for action in schedules.get('actions', []):
                if not action.get('enabled', True):
                    continue
                
                should_run = False
                schedule_type = action.get('schedule_type', 'daily')
                schedule_time = action.get('time', '')
                
                # Check if it's time to run
                if schedule_time == current_time:
                    if schedule_type == 'once':
                        # One-time schedule - check date
                        if action.get('date') == current_date:
                            should_run = True
                            action['enabled'] = False  # Disable after running
                            modified = True
                    
                    elif schedule_type == 'daily':
                        should_run = True
                    
                    elif schedule_type == 'weekly':
                        # Check if today is in the selected days
                        days = action.get('days', [])
                        if current_day in days:
                            should_run = True
                    
                    elif schedule_type == 'weekdays':
                        if current_day not in ['saturday', 'sunday']:
                            should_run = True
                    
                    elif schedule_type == 'weekends':
                        if current_day in ['saturday', 'sunday']:
                            should_run = True
                
                if should_run:
                    # Check if we already ran this minute (prevent double execution)
                    last_run = action.get('last_run', '')
                    if last_run == f"{current_date} {current_time}":
                        continue
                    
                    # Execute the action
                    execute_scheduled_action(action)
                    action['last_run'] = f"{current_date} {current_time}"
                    action['run_count'] = action.get('run_count', 0) + 1
                    modified = True
            
            if modified:
                save_schedules(schedules)
            
            # MK: Check for scheduled rolling updates
            try:
                check_scheduled_updates()
            except Exception as e:
                logging.error(f"[SCHEDULER] Scheduled updates check error: {e}")
            
            # Daily cleanup tasks at 03:00
            if current_time == '03:00':
                try:
                    # Cleanup soft-deleted scripts after 20 days
                    cleanup_deleted_scripts()
                    # MK: Cleanup orphaned excluded VMs (VMs that no longer exist)
                    cleanup_orphaned_excluded_vms()
                    logging.info("[SCHEDULER] Daily cleanup completed")
                except Exception as e:
                    logging.error(f"[SCHEDULER] Daily cleanup error: {e}")
        
        except Exception as e:
            logging.error(f"Scheduler error: {e}")
        
        # Sleep for 60 seconds (check every minute)
        for _ in range(60):
            if not _scheduler_running:
                break
            time.sleep(1)


def execute_scheduled_action(action):
    """Execute a scheduled VM action
    
    LW: This is basically the same as the manual action endpoints
    but called from the scheduler
    
    MK: Added rolling_update for automatic node updates
    """
    cluster_id = action.get('cluster_id')
    vmid = action.get('vmid')
    vm_type = action.get('vm_type', 'qemu')
    action_type = action.get('action')
    
    logging.info(f"[SCHEDULER] Executing {action_type} on {vm_type}/{vmid} in {cluster_id}")
    
    if cluster_id not in cluster_managers:
        logging.error(f"[SCHEDULER] Cluster {cluster_id} not found")
        return
    
    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        logging.error(f"[SCHEDULER] Cluster {cluster_id} not connected")
        return
    
    try:
        # MK: Handle rolling_update action type separately
        if action_type == 'rolling_update':
            execute_scheduled_rolling_update(mgr, cluster_id, action)
            return
        
        # Find the node where the VM is running
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == vmid), None)
        
        if not vm:
            logging.error(f"[SCHEDULER] VM {vmid} not found")
            return
        
        node = vm.get('node')
        host = mgr.current_host or mgr.config.host
        
        # Build the API URL based on action
        if action_type == 'start':
            url = f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/start"
        elif action_type == 'stop':
            url = f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/stop"
        elif action_type == 'shutdown':
            url = f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/shutdown"
        elif action_type == 'reboot':
            url = f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/reboot"
        elif action_type == 'snapshot':
            # Create a snapshot with timestamp
            snap_name = f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M')}"
            url = f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot"
            response = mgr._create_session().post(url, data={'snapname': snap_name})
            logging.info(f"[SCHEDULER] Snapshot result: {response.status_code}")
            return
        else:
            logging.error(f"[SCHEDULER] Unknown action: {action_type}")
            return
        
        response = mgr._create_session().post(url)
        logging.info(f"[SCHEDULER] {action_type} result: {response.status_code}")
        
        # Log the action
        log_audit('scheduler', f'scheduled.{action_type}', 
                 f"Scheduled {action_type} executed on VM {vmid} in {cluster_id}")
        
    except Exception as e:
        logging.error(f"[SCHEDULER] Failed to execute {action_type}: {e}")


def execute_scheduled_rolling_update(mgr, cluster_id: str, action: dict):
    """Execute a scheduled rolling update on a cluster
    
    MK: This runs the same rolling update logic but triggered by scheduler
    """
    try:
        # Get update config from action
        config = action.get('config', {})
        include_reboot = config.get('include_reboot', False)
        skip_evacuation = config.get('skip_evacuation', False)
        skip_up_to_date = config.get('skip_up_to_date', True)
        evacuation_timeout = config.get('evacuation_timeout', 1800)
        wait_for_reboot = config.get('wait_for_reboot', True)
        
        logging.info(f"[SCHEDULER] Starting scheduled rolling update for cluster {cluster_id}")
        logging.info(f"[SCHEDULER] Config: reboot={include_reboot}, skip_evacuation={skip_evacuation}")
        
        # Check if already running
        if hasattr(mgr, '_rolling_update') and mgr._rolling_update and mgr._rolling_update.get('status') == 'running':
            logging.warning(f"[SCHEDULER] Rolling update already in progress, skipping")
            return
        
        # Get nodes
        node_status = mgr.get_node_status()
        nodes_to_update = list(node_status.keys()) if node_status else []
        
        if not nodes_to_update:
            logging.warning(f"[SCHEDULER] No nodes available for update")
            return
        
        # Initialize rolling update state
        mgr._rolling_update = {
            'status': 'running', 'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'include_reboot': include_reboot, 'skip_up_to_date': skip_up_to_date,
            'skip_evacuation': skip_evacuation, 'wait_for_reboot': wait_for_reboot,
            'pause_on_evacuation_error': False, 'force_all': False,
            'evacuation_timeout': evacuation_timeout, 'update_timeout': 900, 'reboot_timeout': 600,
            'nodes': nodes_to_update, 'current_index': 0, 'current_node': nodes_to_update[0],
            'current_step': 'starting', 'completed_nodes': [], 'skipped_nodes': [],
            'failed_nodes': [], 'rebooting_nodes': [], 'paused_reason': None, 'paused_details': None,
            'logs': [f"[{time.strftime('%H:%M:%S')}] Scheduled rolling update started"], 'scheduled': True
        }
        
        def run_scheduled_update():
            try:
                for idx, node_name in enumerate(nodes_to_update):
                    if not hasattr(mgr, '_rolling_update') or mgr._rolling_update.get('status') != 'running':
                        break
                    mgr._rolling_update['current_index'] = idx
                    mgr._rolling_update['current_node'] = node_name
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Processing {node_name}")
                    if skip_up_to_date:
                        try:
                            mgr.refresh_node_apt(node_name); time.sleep(3)
                            if not mgr.get_node_apt_updates(node_name):
                                mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] {node_name} up-to-date, skipping")
                                mgr._rolling_update['skipped_nodes'].append(node_name); continue
                        except Exception as e:
                            logging.warning(f"[SCHEDULER] Check failed for {node_name}: {e}")
                    mgr._rolling_update['current_step'] = 'maintenance'
                    mgr.enter_maintenance_mode(node_name, skip_evacuation=skip_evacuation)
                    if not skip_evacuation:
                        mgr._rolling_update['current_step'] = 'evacuating'
                        waited = 0; evacuation_ok = False
                        while waited < evacuation_timeout:
                            if node_name in mgr.nodes_in_maintenance:
                                task = mgr.nodes_in_maintenance[node_name]
                                if task.status == 'completed':
                                    evacuation_ok = True; break
                                elif task.status == 'completed_with_errors':
                                    fv = getattr(task, 'failed_vms', [])
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⚠️ Evacuation: {getattr(task,'migrated_vms',0)}/{getattr(task,'total_vms',0)} migrated, {len(fv)} failed - continuing")
                                    evacuation_ok = True; break
                                elif task.status == 'failed': break
                            time.sleep(5); waited += 5
                        if not evacuation_ok:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✗ Evacuation failed on {node_name}, skipping")
                            mgr._rolling_update['failed_nodes'].append({'node': node_name, 'error': 'Evacuation failed'})
                            mgr.exit_maintenance_mode(node_name); continue
                    mgr._rolling_update['current_step'] = 'updating'
                    update_task = mgr.start_node_update(node_name, reboot=include_reboot, force=True)
                    if update_task:
                        waited = 0
                        while waited < (1800 if include_reboot else 900):
                            if update_task.status in ['completed', 'failed']: break
                            time.sleep(10); waited += 10
                        if update_task.status == 'completed':
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✓ {node_name} updated")
                            mgr._rolling_update['completed_nodes'].append(node_name)
                            if include_reboot:
                                mgr._rolling_update['current_step'] = 'rebooting'
                                mgr._rolling_update['rebooting_nodes'].append(node_name)
                                if wait_for_reboot:
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Waiting for {node_name} to reboot...")
                                    ow = 0
                                    while ow < 120:
                                        try:
                                            ns = mgr.get_node_status()
                                            if node_name not in ns or ns[node_name].get('status') != 'online': break
                                        except: break
                                        time.sleep(5); ow += 5
                                    rw = 0
                                    while rw < 600:
                                        try:
                                            ns = mgr.get_node_status()
                                            if node_name in ns and ns[node_name].get('status') == 'online':
                                                mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✓ {node_name} back online")
                                                if node_name in mgr._rolling_update['rebooting_nodes']:
                                                    mgr._rolling_update['rebooting_nodes'].remove(node_name)
                                                time.sleep(10); break
                                        except: pass
                                        time.sleep(10); rw += 10
                                else:
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] {node_name} rebooting (wait_for_reboot=False)")
                        else:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✗ {node_name} update failed")
                            mgr._rolling_update['failed_nodes'].append({'node': node_name, 'error': 'Update failed'})
                    mgr.exit_maintenance_mode(node_name)
                
                # Finished
                mgr._rolling_update['status'] = 'completed'
                mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Scheduled rolling update completed")
                
                # Log audit
                log_audit('scheduler', 'scheduled.rolling_update', 
                         f"Scheduled rolling update completed: {len(mgr._rolling_update['completed_nodes'])} updated, "
                         f"{len(mgr._rolling_update['skipped_nodes'])} skipped, "
                         f"{len(mgr._rolling_update['failed_nodes'])} failed")
                
            except Exception as e:
                logging.error(f"[SCHEDULER] Rolling update error: {e}")
                if hasattr(mgr, '_rolling_update'):
                    mgr._rolling_update['status'] = 'failed'
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ERROR: {e}")
        
        update_thread = threading.Thread(target=run_scheduled_update, daemon=True)
        update_thread.start()
        
        logging.info(f"[SCHEDULER] Rolling update thread started for {cluster_id}")
        
    except Exception as e:
        logging.error(f"[SCHEDULER] Failed to start scheduled rolling update: {e}")


def start_scheduler():
    """Start the scheduler background thread"""
    global _scheduler_thread, _scheduler_running
    
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    
    _scheduler_running = True
    _scheduler_thread = threading.Thread(target=check_schedules, daemon=True)
    _scheduler_thread.start()
    logging.info("Scheduler started")


def stop_scheduler():
    """Stop the scheduler"""
    global _scheduler_running
    _scheduler_running = False


# API endpoints for scheduled actions

@bp.route('/api/schedules', methods=['GET'])
@require_auth()
def get_schedules():
    """Get all scheduled actions
    
    Filters by user's accessible clusters unless admin
    """
    schedules = load_schedules()
    
    user = request.session.get('user', '')
    users_db = load_users()
    user_data = users_db.get(user, {})
    is_admin = user_data.get('role') == ROLE_ADMIN
    user_clusters = user_data.get('clusters', [])
    
    # Filter actions by accessible clusters
    if is_admin:
        return jsonify(schedules.get('actions', []))
    
    filtered = [
        a for a in schedules.get('actions', [])
        if not user_clusters or a.get('cluster_id') in user_clusters
    ]
    
    return jsonify(filtered)


@bp.route('/api/schedules', methods=['POST'])
@require_auth(perms=['vm.start'])  # Need at least VM start permission
def create_schedule():
    """Create a new scheduled action
    
    Body:
    - cluster_id: Cluster ID
    - vmid: VM ID
    - vm_type: 'qemu' or 'lxc'
    - action: 'start', 'stop', 'shutdown', 'reboot', 'snapshot'
    - schedule_type: 'once', 'daily', 'weekly', 'weekdays', 'weekends'
    - time: 'HH:MM' format
    - date: (for once) 'YYYY-MM-DD' format
    - days: (for weekly) ['monday', 'wednesday', 'friday']
    - name: Optional friendly name
    """
    data = request.json or {}
    
    required = ['cluster_id', 'vmid', 'action', 'schedule_type', 'time']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    # NS: Feb 2026 - verify tenant has access to this cluster
    ok, err = check_cluster_access(data['cluster_id'])
    if not ok: return err

    # Validate time format
    time_str = data.get('time', '')
    try:
        datetime.strptime(time_str, '%H:%M')
    except ValueError:
        return jsonify({'error': 'Time must be in HH:MM format'}), 400
    
    # Validate action
    valid_actions = ['start', 'stop', 'shutdown', 'reboot', 'snapshot']
    if data['action'] not in valid_actions:
        return jsonify({'error': f'Action must be one of: {valid_actions}'}), 400
    
    # Validate schedule type
    valid_types = ['once', 'daily', 'weekly', 'weekdays', 'weekends']
    if data['schedule_type'] not in valid_types:
        return jsonify({'error': f'Schedule type must be one of: {valid_types}'}), 400
    
    # For 'once' type, require date
    if data['schedule_type'] == 'once' and not data.get('date'):
        return jsonify({'error': 'Date is required for one-time schedules'}), 400
    
    # For 'weekly' type, require days
    if data['schedule_type'] == 'weekly' and not data.get('days'):
        return jsonify({'error': 'Days are required for weekly schedules'}), 400
    
    schedules = load_schedules()
    
    # Generate new ID
    new_id = schedules.get('last_id', 0) + 1
    schedules['last_id'] = new_id
    
    # Create the schedule
    new_schedule = {
        'id': new_id,
        'cluster_id': data['cluster_id'],
        'vmid': int(data['vmid']),
        'vm_type': data.get('vm_type', 'qemu'),
        'action': data['action'],
        'schedule_type': data['schedule_type'],
        'time': time_str,
        'date': data.get('date'),
        'days': data.get('days', []),
        'name': data.get('name', f"{data['action']} VM {data['vmid']}"),
        'enabled': True,
        'created_by': request.session.get('user', 'unknown'),
        'created_at': datetime.now().isoformat(),
        'run_count': 0
    }
    
    if 'actions' not in schedules:
        schedules['actions'] = []
    
    schedules['actions'].append(new_schedule)
    save_schedules(schedules)
    
    log_audit(request.session.get('user', 'system'), 'schedule.created', 
             f"Created schedule '{new_schedule['name']}' for VM {data['vmid']}")
    
    return jsonify({'success': True, 'schedule': new_schedule})


@bp.route('/api/schedules/<int:schedule_id>', methods=['PUT'])
@require_auth(perms=['vm.start'])
def update_schedule(schedule_id):
    """Update a scheduled action"""
    data = request.json or {}
    schedules = load_schedules()

    # Find the schedule
    schedule = next((s for s in schedules.get('actions', []) if s.get('id') == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404

    # NS: Feb 2026 - verify tenant has access to this schedule's cluster
    ok, err = check_cluster_access(schedule.get('cluster_id', ''))
    if not ok: return err

    # Update fields
    updatable = ['name', 'action', 'schedule_type', 'time', 'date', 'days', 'enabled']
    for field in updatable:
        if field in data:
            schedule[field] = data[field]
    
    save_schedules(schedules)
    
    return jsonify({'success': True, 'schedule': schedule})


@bp.route('/api/schedules/<int:schedule_id>', methods=['DELETE'])
@require_auth(perms=['vm.start'])
def delete_schedule(schedule_id):
    """Delete a scheduled action"""
    schedules = load_schedules()
    
    original_len = len(schedules.get('actions', []))
    schedules['actions'] = [s for s in schedules.get('actions', []) if s.get('id') != schedule_id]
    
    if len(schedules['actions']) == original_len:
        return jsonify({'error': 'Schedule not found'}), 404
    
    save_schedules(schedules)
    
    log_audit(request.session.get('user', 'system'), 'schedule.deleted', 
             f"Deleted schedule ID {schedule_id}")
    
    return jsonify({'success': True})


# ============================================

# ============================================
# Scheduled Updates API
# MK: Automatic rolling update scheduling (SQLite storage)
# ============================================

def load_update_schedule(cluster_id: str) -> dict:
    """Load update schedule for a cluster from SQLite"""
    default = {
        'enabled': False,
        'schedule_type': 'recurring',
        'day': 'sunday',
        'time': '03:00',
        'include_reboot': True,
        'skip_evacuation': False,
        'skip_up_to_date': True,
        'evacuation_timeout': 1800,
        'last_run': None,
        'next_run': None
    }
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # MK: Ensure table exists (migration for existing databases)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS update_schedules (
                cluster_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 0,
                schedule_type TEXT DEFAULT 'recurring',
                day TEXT DEFAULT 'sunday',
                time TEXT DEFAULT '03:00',
                include_reboot INTEGER DEFAULT 1,
                skip_evacuation INTEGER DEFAULT 0,
                skip_up_to_date INTEGER DEFAULT 1,
                evacuation_timeout INTEGER DEFAULT 1800,
                last_run TEXT,
                next_run TEXT,
                created_by TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        cursor.execute('SELECT * FROM update_schedules WHERE cluster_id = ?', (cluster_id,))
        row = cursor.fetchone()
        if row:
            return {
                'enabled': bool(row['enabled']),
                'schedule_type': row['schedule_type'] or 'recurring',
                'day': row['day'] or 'sunday',
                'time': row['time'] or '03:00',
                'include_reboot': bool(row['include_reboot']),
                'skip_evacuation': bool(row['skip_evacuation']),
                'skip_up_to_date': bool(row['skip_up_to_date']),
                'evacuation_timeout': row['evacuation_timeout'] or 1800,
                'last_run': row['last_run'],
                'next_run': row['next_run']
            }
    except Exception as e:
        logging.error(f"Error loading update schedule: {e}")
    return default


def save_update_schedule(cluster_id: str, schedule: dict, user: str = 'system'):
    """Save update schedule for a cluster to SQLite"""
    try:
        db = get_db()
        cursor = db.conn.cursor()
        now = datetime.now().isoformat()
        
        # MK: Use INSERT OR REPLACE for older SQLite compatibility
        cursor.execute('''
            INSERT OR REPLACE INTO update_schedules 
            (cluster_id, enabled, schedule_type, day, time, include_reboot, skip_evacuation, 
             skip_up_to_date, evacuation_timeout, last_run, next_run, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cluster_id,
            1 if schedule.get('enabled') else 0,
            schedule.get('schedule_type', 'recurring'),
            schedule.get('day', 'sunday'),
            schedule.get('time', '03:00'),
            1 if schedule.get('include_reboot', True) else 0,
            1 if schedule.get('skip_evacuation', False) else 0,
            1 if schedule.get('skip_up_to_date', True) else 0,
            schedule.get('evacuation_timeout', 1800),
            schedule.get('last_run'),
            schedule.get('next_run'),
            user,
            now,
            now
        ))
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving update schedule: {e}")


def update_schedule_last_run(cluster_id: str, last_run: str, next_run: str):
    """Update last_run and next_run for a schedule"""
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('''
            UPDATE update_schedules SET last_run = ?, next_run = ?, updated_at = ?
            WHERE cluster_id = ?
        ''', (last_run, next_run, datetime.now().isoformat(), cluster_id))
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error updating schedule last_run: {e}")


def load_all_update_schedules() -> dict:
    """Load all enabled update schedules from SQLite"""
    schedules = {}
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM update_schedules WHERE enabled = 1')
        for row in cursor.fetchall():
            schedules[row['cluster_id']] = {
                'enabled': bool(row['enabled']),
                'schedule_type': row['schedule_type'] or 'recurring',
                'day': row['day'] or 'sunday',
                'time': row['time'] or '03:00',
                'include_reboot': bool(row['include_reboot']),
                'skip_evacuation': bool(row['skip_evacuation']),
                'skip_up_to_date': bool(row['skip_up_to_date']),
                'evacuation_timeout': row['evacuation_timeout'] or 1800,
                'last_run': row['last_run'],
                'next_run': row['next_run']
            }
    except Exception as e:
        logging.error(f"Error loading all update schedules: {e}")
    return schedules


@bp.route('/api/clusters/<cluster_id>/updates/schedule', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_update_schedule(cluster_id):
    """Get the scheduled update configuration for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    schedule = load_update_schedule(cluster_id)
    return jsonify(schedule)


@bp.route('/api/clusters/<cluster_id>/updates/schedule', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def set_update_schedule(cluster_id):
    """Set the scheduled update configuration for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.json or {}
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    schedule = {
        'enabled': data.get('enabled', False),
        'schedule_type': data.get('schedule_type', 'recurring'),
        'day': data.get('day', 'sunday'),
        'time': data.get('time', '03:00'),
        'include_reboot': data.get('include_reboot', True),
        'skip_evacuation': data.get('skip_evacuation', False),
        'skip_up_to_date': data.get('skip_up_to_date', True),
        'evacuation_timeout': data.get('evacuation_timeout', 1800),
        'wait_for_reboot': data.get('wait_for_reboot', True),
        'last_run': None,
        'next_run': None
    }
    
    # Calculate next run time
    if schedule['enabled']:
        schedule['next_run'] = calculate_next_update_run(schedule['day'], schedule['time'])
    
    save_update_schedule(cluster_id, schedule, usr)
    
    # Log audit
    mgr = cluster_managers[cluster_id]
    log_audit(usr, 'update.schedule', f"Update schedule {'enabled' if schedule['enabled'] else 'disabled'} for {mgr.config.name}", cluster=mgr.config.name)
    
    return jsonify({'success': True, 'schedule': schedule})


@bp.route('/api/clusters/<cluster_id>/updates/schedule', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_update_schedule(cluster_id):
    """Delete/disable the scheduled update for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('DELETE FROM update_schedules WHERE cluster_id = ?', (cluster_id,))
        db.conn.commit()
        
        usr = getattr(request, 'session', {}).get('user', 'system')
        mgr = cluster_managers[cluster_id]
        log_audit(usr, 'update.schedule.deleted', f"Update schedule deleted for {mgr.config.name}", cluster=mgr.config.name)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def calculate_next_update_run(day: str, time_str: str) -> str:
    """Calculate the next scheduled run time"""
    try:
        now = datetime.now()
        hour, minute = map(int, time_str.split(':'))
        
        day_map = {
            'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
            'friday': 4, 'saturday': 5, 'sunday': 6, 'daily': -1
        }
        
        target_day = day_map.get(day.lower(), -1)
        
        if target_day == -1:  # Daily
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
        else:
            days_ahead = target_day - now.weekday()
            if days_ahead < 0:
                days_ahead += 7
            next_run = now + timedelta(days=days_ahead)
            next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=7)
        
        return next_run.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        logging.error(f"Error calculating next run: {e}")
        return None


def check_scheduled_updates():
    """Check if any scheduled updates should run - called by scheduler"""
    try:
        schedules = load_all_update_schedules()
        now = datetime.now()
        
        for cluster_id, schedule in schedules.items():
            if not schedule.get('enabled'):
                continue
            
            if cluster_id not in cluster_managers:
                continue
            
            mgr = cluster_managers[cluster_id]
            if not mgr.is_connected:
                continue
            
            # Check schedule_type - 'once' schedules that already ran should be skipped
            schedule_type = schedule.get('schedule_type', 'recurring')
            if schedule_type == 'once' and schedule.get('last_run'):
                continue
            
            # Check if it's time to run
            day = schedule.get('day', 'sunday')
            time_str = schedule.get('time', '03:00')
            
            try:
                hour, minute = map(int, time_str.split(':'))
            except:
                continue
            
            day_map = {
                'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
                'friday': 4, 'saturday': 5, 'sunday': 6
            }
            
            is_correct_day = (day == 'daily' or now.weekday() == day_map.get(day.lower(), -1))
            is_correct_time = now.hour == hour and now.minute == minute
            
            if is_correct_day and is_correct_time:
                # Check if already ran today (for recurring)
                if schedule_type == 'recurring':
                    last_run = schedule.get('last_run')
                    if last_run:
                        try:
                            last_run_date = datetime.fromisoformat(last_run).date()
                            if last_run_date == now.date():
                                continue  # Already ran today
                        except:
                            pass
                
                # Check if rolling update already running
                if hasattr(mgr, '_rolling_update') and mgr._rolling_update:
                    if mgr._rolling_update.get('status') == 'running':
                        continue
                
                logging.info(f"[SCHEDULER] Starting scheduled update for cluster {cluster_id} (type: {schedule_type})")
                
                # Execute the scheduled rolling update
                action = {
                    'cluster_id': cluster_id,
                    'action': 'rolling_update',
                    'config': {
                        'include_reboot': schedule.get('include_reboot', True),
                        'skip_evacuation': schedule.get('skip_evacuation', False),
                        'skip_up_to_date': schedule.get('skip_up_to_date', True),
                        'evacuation_timeout': schedule.get('evacuation_timeout', 1800)
                    }
                }
                
                execute_scheduled_rolling_update(mgr, cluster_id, action)
                
                # Update last run time
                last_run_str = now.isoformat()
                next_run_str = calculate_next_update_run(day, time_str) if schedule_type == 'recurring' else None
                update_schedule_last_run(cluster_id, last_run_str, next_run_str)
                
                # Disable 'once' schedules after running
                if schedule_type == 'once':
                    schedule['enabled'] = False
                    schedule['last_run'] = last_run_str
                    save_update_schedule(cluster_id, schedule)
                    logging.info(f"[SCHEDULER] One-time schedule disabled for {cluster_id}")
                
    except Exception as e:
        logging.error(f"Error checking scheduled updates: {e}")



