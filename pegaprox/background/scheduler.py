# -*- coding: utf-8 -*-
"""
PegaProx Task Scheduler - Layer 7
Background scheduled task execution.
"""

import os
import time
import json
import logging
from pegaprox.utils.sanitization import sanitize_log_message as _sl  # CWE-117 tainted-log sanitiser
import threading
import uuid
from datetime import datetime, timedelta

from pegaprox.constants import SCHEDULED_TASKS_FILE
from pegaprox.globals import cluster_managers, _scheduler_running, _scheduler_thread
from pegaprox.core.db import get_db
from pegaprox.core import ha
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
            # the schedule fields go in as a JSON blob and used to come back as the raw
            # string, so _calc_next_run fell through to its defaults ('daily' 02:00) for every
            # task on every restart. Unpack both blobs here.
            try:
                _sched = json.loads(row['schedule'] or '{}')
            except (TypeError, ValueError):
                _sched = {}
            try:
                _blob = json.loads(row['config'] or '{}')
            except (TypeError, ValueError):
                _blob = {}
            # rows written before this fix hold the bare config dict and carry the action in
            # the task_type column — keep reading those correctly
            _new_shape = isinstance(_blob, dict) and 'action' in _blob
            tasks.append({
                'id': row['id'],
                'cluster_id': row['cluster_id'],
                'name': row['name'],
                'task_type': row['task_type'],
                'schedule': row['schedule'],
                'schedule_type': _sched.get('schedule_type', 'daily'),
                'schedule_time': _sched.get('schedule_time', '02:00'),
                'schedule_day': _sched.get('schedule_day', 0),
                'action': (_blob.get('action') if _new_shape else '') or row['task_type'] or '',
                'target_type': _blob.get('target_type', 'vm') if _new_shape else 'vm',
                'target_id': _blob.get('target_id', '') if _new_shape else '',
                'target_node': _blob.get('target_node', '') if _new_shape else '',
                'config': (_blob.get('config') or {}) if _new_shape else _blob,
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
            task_id = task.get('id', str(uuid.uuid4()))
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
                # fix (audit): the executor dispatches on action/target_type/target_id/
                # target_node, and none of them had a column — so after a restart every task
                # loaded with empty values, did nothing, and still logged as executed. Carry
                # them in the config blob rather than migrating the schema.
                json.dumps({
                    'config': task.get('config', {}),
                    'action': task.get('action', task.get('task_type', '')),
                    'target_type': task.get('target_type', 'vm'),
                    'target_id': task.get('target_id', ''),
                    'target_node': task.get('target_node', ''),
                }),
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
    # the group's zone when this instance is in one, so a failover does not shift a
    # schedule; datetime.now() on an instance of its own (#625)
    current_time = ha.schedule_now()
    # automatic failover (design 5.7): what fell due while the group had no leader is
    # said, not run late, and a new leader fires nothing in a minute the former one may
    # have fired already. Neither does anything anywhere else
    _report_missed(config.get('tasks', []))
    if ha.schedule_held():
        return

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
            if ha.schedule_fire_first():
                # at most once: the run is written and on its way to the members before
                # the task acts, so a leader that takes over does not run it again
                task['last_run'] = current_time.isoformat()
                _touch_last_run(task.get('id'), task['last_run'])
                ha.schedule_fired()
            if not ha.confirm_step(f"scheduled task {_sl(task.get('name'))}"):
                return
            execute_scheduled_task(task)
            # fix (audit): this used to write the WHOLE config back — a snapshot taken before
            # the tick began. execute_scheduled_task starts and stops VMs, so it can run for a
            # while, and any task an admin deleted or edited in that window was resurrected or
            # reverted by this save. Touch just this task's last_run instead.
            task['last_run'] = current_time.isoformat()
            _touch_last_run(task.get('id'), task['last_run'])


def _due_minute(task, at):
    """Whether `task` falls due in the minute `at`, its last run aside. For the report of
    what a change of leader missed (5.7); run_scheduled_tasks decides as it always did."""
    try:
        hour, minute = map(int, str(task.get('schedule_time', '02:00')).split(':'))
    except (TypeError, ValueError):
        return False
    kind, day = task.get('schedule_type', 'daily'), task.get('schedule_day', 0)
    if kind == 'hourly':
        return at.minute == minute
    if (at.hour, at.minute) != (hour, minute):
        return False
    return (kind == 'daily' or (kind == 'weekly' and at.weekday() == day)
            or (kind == 'monthly' and at.day == day))


def _report_missed(tasks):
    """Once a new leader of an automatic group acts: the tasks that fell due in the gap."""
    window = ha.missed_schedule_window('scheduled tasks')
    if not window:
        return
    missed = set()
    at = window[0] - window[0] % 60
    while at <= window[1]:
        when = ha.schedule_at(at)
        # a last run from that minute on: the former leader got to it
        missed.update(str(t.get('name') or t.get('id')) for t in tasks
                      if t.get('enabled', True) and _due_minute(t, when)
                      and str(t.get('last_run') or '') < when.isoformat())
        at += 60
    ha.missed_schedules('scheduled tasks', sorted(missed), window)

def _touch_last_run(task_id, when):
    """Record a single task's last_run without rewriting the table around it."""
    if not task_id:
        return
    try:
        db = get_db()
        db.conn.execute('UPDATE scheduled_tasks SET last_run = ? WHERE id = ?', (when, task_id))
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to record last_run for scheduled task {task_id}: {e}")


def execute_scheduled_task(task):
    """Execute a scheduled task
    
    sec: Legacy scheduled_tasks have no created_by or tenant scope. Since we cannot verify
    current authorization, we refuse to execute them. Operators must recreate schedules via
    the newer scheduled_actions API (which stores created_by and enforces authorization at
    execution time). This prevents persisted schedules from bypassing authorization revocation.
    """
    cluster_id = task.get('cluster_id', '')
    action = task.get('action', '')
    target_type = task.get('target_type', 'vm')
    target_id = task.get('target_id', '')
    target_node = task.get('target_node', '')
    
    logging.error(f"Scheduled task '{_sl(task.get('name'))}' uses the legacy scheduled_tasks "
                  f"schema which lacks authorization metadata. Refusing to execute {action} on "
                  f"{target_type}/{target_id}. Please recreate this schedule via the API to "
                  f"establish proper authorization tracking.")
    return
    
    # The code below is unreachable but preserved to document what the legacy path did.
    # It must not be re-enabled without adding authorization checks equivalent to those in
    # execute_scheduled_action() in api/schedules.py.
    
    if cluster_id not in cluster_managers:
        logging.error(f"Scheduled task failed: Cluster {cluster_id} not found")
        return
    
    manager = cluster_managers[cluster_id]
    logging.info(f"Executing scheduled task: {_sl(task.get('name'))} - {action} on {target_type}/{target_id}")
    
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
            # standby: the tasks run on the active instance, not twice
            if ha.is_active():
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

