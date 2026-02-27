# -*- coding: utf-8 -*-
"""
PegaProx Task Scheduler - Layer 7
Background scheduled task execution.
"""

import os
import time
import json
import logging
import threading
import uuid
from datetime import datetime, timedelta

from pegaprox.constants import SCHEDULED_TASKS_FILE
from pegaprox.globals import cluster_managers, _scheduler_running, _scheduler_thread
from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit

# NS: this was buried somewhere around line 40k in the monolith, nobody could find it
def load_scheduled_tasks():
    """Load scheduled tasks from SQLite database

    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM scheduled_tasks')
        
        tasks = []
        for row in cursor.fetchall():
            tasks.append({
                'id': row['id'],
                'cluster_id': row['cluster_id'],
                'name': row['name'],
                'task_type': row['task_type'],
                'schedule': row['schedule'],
                'config': json.loads(row['config'] or '{}'),
                'enabled': bool(row['enabled']),
                'last_run': row['last_run'],
                'next_run': row['next_run'],
            })
        
        return {'tasks': tasks}
    except Exception as e:
        logging.error(f"Error loading scheduled tasks from database: {e}")
        # Legacy fallback
        if os.path.exists(SCHEDULED_TASKS_FILE):
            try:
                with open(SCHEDULED_TASKS_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
    return {'tasks': []}


def save_scheduled_tasks(config):
    """Save scheduled tasks to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        now = datetime.now().isoformat()
        
        # Clear existing tasks (simple approach)
        cursor.execute('DELETE FROM scheduled_tasks')
        
        for task in config.get('tasks', []):
            task_id = task.get('id', str(uuid.uuid4())[:8])
            cursor.execute('''
                INSERT INTO scheduled_tasks
                (id, cluster_id, name, task_type, schedule, config, 
                 enabled, last_run, next_run, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task_id,
                task.get('cluster_id'),
                task.get('name', ''),
                task.get('task_type', task.get('action', '')),
                json.dumps({
                    'schedule_type': task.get('schedule_type', 'daily'),
                    'schedule_time': task.get('schedule_time', '02:00'),
                    'schedule_day': task.get('schedule_day', 0),
                }),
                json.dumps(task.get('config', {})),
                1 if task.get('enabled', True) else 0,
                task.get('last_run'),
                task.get('next_run'),
                now
            ))
        
        db.conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error saving scheduled tasks: {e}")
        return False

def run_scheduled_tasks():
    """Check and execute due scheduled tasks
    
    LW: Runs every minute, checks if any tasks are due
    Supported actions: start, stop, restart, snapshot, backup
    """
    config = load_scheduled_tasks()
    current_time = datetime.now()
    
    for task in config.get('tasks', []):
        if not task.get('enabled', True):
            continue
        
        # Check if task is due
        schedule_type = task.get('schedule_type', 'daily')
        schedule_time = task.get('schedule_time', '02:00')
        schedule_day = task.get('schedule_day', 0)  # 0=Monday for weekly
        last_run = task.get('last_run')
        
        should_run = False
        
        try:
            hour, minute = map(int, schedule_time.split(':'))
            
            if schedule_type == 'hourly':
                # Run every hour at specified minute
                if current_time.minute == minute:
                    if not last_run or (datetime.fromisoformat(last_run) + timedelta(hours=1)) <= current_time:
                        should_run = True
                        
            elif schedule_type == 'daily':
                # Run once a day at specified time
                if current_time.hour == hour and current_time.minute == minute:
                    if not last_run or datetime.fromisoformat(last_run).date() < current_time.date():
                        should_run = True
                        
            elif schedule_type == 'weekly':
                # Run once a week on specified day and time
                if current_time.weekday() == schedule_day and current_time.hour == hour and current_time.minute == minute:
                    if not last_run or (datetime.fromisoformat(last_run) + timedelta(days=7)) <= current_time:
                        should_run = True
                        
            elif schedule_type == 'monthly':
                # Run on specified day of month
                if current_time.day == schedule_day and current_time.hour == hour and current_time.minute == minute:
                    if not last_run or datetime.fromisoformat(last_run).month != current_time.month:
                        should_run = True
                        
        except Exception as e:
            logging.error(f"Error parsing schedule for task {task.get('id')}: {e}")
            continue
        
        if should_run:
            execute_scheduled_task(task)
            # Update last_run
            task['last_run'] = current_time.isoformat()
            save_scheduled_tasks(config)

def execute_scheduled_task(task):
    """Execute a scheduled task"""
    cluster_id = task.get('cluster_id', '')
    action = task.get('action', '')
    target_type = task.get('target_type', 'vm')
    target_id = task.get('target_id', '')
    target_node = task.get('target_node', '')
    
    if cluster_id not in cluster_managers:
        logging.error(f"Scheduled task failed: Cluster {cluster_id} not found")
        return
    
    manager = cluster_managers[cluster_id]
    logging.info(f"Executing scheduled task: {task.get('name')} - {action} on {target_type}/{target_id}")
    
    try:
        if action == 'start':
            manager.start_vm(target_node, int(target_id), target_type)
        elif action == 'stop':
            manager.stop_vm(target_node, int(target_id), target_type)
        elif action == 'restart':
            manager.restart_vm(target_node, int(target_id), target_type)
        elif action == 'shutdown':
            manager.shutdown_vm(target_node, int(target_id), target_type)
        elif action == 'snapshot':
            snap_name = f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M')}"
            manager.create_snapshot(target_node, int(target_id), target_type, snap_name, 'Scheduled snapshot', False)
        elif action == 'backup':
            # Trigger backup job
            storage = task.get('backup_storage', 'local')
            manager.backup_vm(target_node, int(target_id), target_type, storage)
        
        log_audit('scheduler', 'scheduled_task.executed', f"Task '{task.get('name')}' executed: {action} on {target_type}/{target_id}")
        
    except Exception as e:
        logging.error(f"Scheduled task failed: {e}")
        log_audit('scheduler', 'scheduled_task.failed', f"Task '{task.get('name')}' failed: {e}")

# Scheduler thread
_scheduler_thread = None
_scheduler_running = False

def scheduler_loop():
    """Background thread that runs scheduled tasks"""
    global _scheduler_running
    _scheduler_running = True
    
    while _scheduler_running:
        try:
            run_scheduled_tasks()
        except Exception as e:
            logging.error(f"Scheduler error: {e}")
        
        # Check every 60 seconds (was 30 but that caused duplicate executions when tasks
        # took longer than the interval - we lost 4h debugging that one)
        time.sleep(60)

def start_scheduler_thread():
    global _scheduler_thread
    if _scheduler_thread is None or not _scheduler_thread.is_alive():
        _scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        _scheduler_thread.start()
        logging.info("Task scheduler thread started")

