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

# MK Oct 2026 - a pass checked only the minute it woke up in, so a minute it slept over
# never ran its tasks. Every minute since the last pass is checked now; a gap of more
# than this beyond the pass's own work (clock step forward, suspended host, stalled
# process) is reported instead of run late.
CATCH_UP_MINUTES = 5
# summer time or a new group zone moves schedule_now() by 15 min or more while the wall
# clock does not: as before, only the minute it lands in is checked
_ZONE_MOVED = 600
_MINUTE = timedelta(minutes=1)


def _minute(at):
    return at.replace(second=0, microsecond=0)


def run_scheduled_tasks(last=None):
    """Check and execute due scheduled tasks
    
    LW: Runs every minute, checks if any tasks are due
    Supported actions: start, stop, restart, snapshot, backup

    `last` is what the pass before returned, None checks this minute only. Returns what
    the next pass gets: the minute checked up to, the wall time and how long this took.
    """
    started = time.monotonic()
    config = load_scheduled_tasks()
    tasks = config.get('tasks', [])
    # the group's zone when this instance is in one, so a failover does not shift a
    # schedule; datetime.now() on an instance of its own (#625)
    current_time = ha.schedule_now()
    now, wall = _minute(current_time), time.time()
    # automatic failover (design 5.7): what fell due while the group had no leader is
    # said, not run late, and a new leader fires nothing in a minute the former one may
    # have fired already. Neither does anything anywhere else
    _report_missed(tasks)
    if ha.schedule_held():
        return now, wall, 0.0

    first, skipped = _first_minute(last, now, wall)
    if skipped:
        # a leader whose clock leapt ahead has its lease calls refused from then on: the
        # confirm says no, and the next leader reports the gap by the true clock (5.7).
        # In an automatic group the gap is the group's mark first, so that one does not
        # report it again
        if not ha.report_settled('scheduled tasks', wall - 60,
                                 'the report of the minutes the scheduler stepped over'):
            return now, wall, 0.0
        _report_skipped(tasks, *skipped)

    lost, through = [], True
    for task in tasks:
        if not task.get('enabled', True):
            continue
        try:
            slot = _last_due(task, first, now)
            if slot is None or _ran_for(task, slot):
                continue
        except Exception as e:
            logging.error(f"Error parsing schedule for task {task.get('id')}: {e}")
            continue
        # a minute caught up that a new leader still holds (5.7)
        if slot < now and ha.schedule_held(slot):
            continue
        # one caught up is stamped with its own minute, or the next run comes late
        stamp = (current_time if slot == now else slot).isoformat()

        first_run = ha.schedule_fire_first()
        if first_run:
            if not ha.is_active():
                # the lease went during this pass: the rest is the next leader's, and its
                # report covers them (the mark below stays where it was)
                through = False
                break
            # at most once: the run is written and on its way to the members before
            # the task acts, so a leader that takes over does not run it again
            task['last_run'] = stamp
            _touch_last_run(task.get('id'), task['last_run'])
            ha.schedule_fired()
        if not ha.confirm_step(f"scheduled task {_sl(task.get('name'))}"):
            if not first_run:
                through = False
                break
            # MK Oct 2026 - lab E6b_2: written first and then not started, and only a
            # WARNING said so. Used up (no leader runs it now), so it is reported; the
            # ones after it try a round of their own instead of being dropped
            lost.append((task, slot))
            continue
        execute_scheduled_task(task)
        # fix (audit): this used to write the WHOLE config back - a snapshot taken before
        # the tick began. execute_scheduled_task starts and stops VMs, so it can run for a
        # while, and any task an admin deleted or edited in that window was resurrected or
        # reverted by this save. Touch just this task's last_run instead.
        task['last_run'] = stamp
        _touch_last_run(task.get('id'), task['last_run'])
    if lost:
        _report_lost(lost)
    if through:
        # the group's mark for the report of the next leader (5.7)
        ha.schedules_checked('scheduled tasks', wall)
    return now, wall, time.monotonic() - started


def _first_minute(last, now, wall):
    """The first minute this pass checks, and the minutes it reports instead of running
    them as (first, last), or None."""
    if not last:
        return now, None
    seen, seen_wall, busy = last
    ahead = (now - seen).total_seconds()
    if ahead <= 0 or abs(ahead - (wall - seen_wall)) >= _ZONE_MOVED:
        # the same minute again: nothing new. The clock stepped back (last_run keeps a
        # slot from running twice) or the zone moved: this minute only
        return (now + _MINUTE if ahead == 0 else now), None
    skipped = int(ahead // 60) - 1
    if skipped <= CATCH_UP_MINUTES + int(busy // 60):
        return seen + _MINUTE, None
    return now, (seen + _MINUTE, now - _MINUTE)


def _whole(x):
    """schedule_day as the int it equals; None for anything else ('3' never matched)."""
    try:
        return int(x) if int(x) == x else None
    except (TypeError, ValueError):
        return None


def _last_due(task, first, last):
    """The latest minute from `first` to `last` at which `task` falls due, its last run
    aside; None when there is none. Raises when schedule_time is no time."""
    hour, minute = map(int, str(task.get('schedule_time', '02:00')).split(':'))
    kind, day = task.get('schedule_type', 'daily'), _whole(task.get('schedule_day', 0))
    if not 0 <= minute < 60:
        return None
    if kind == 'hourly':
        at = last.replace(minute=minute)
        if at > last:
            at -= timedelta(hours=1)
        return at if at >= first else None
    if kind not in ('daily', 'weekly', 'monthly') or not 0 <= hour < 24:
        return None
    at = last.replace(hour=hour, minute=minute)
    if at > last:
        at -= timedelta(days=1)
    if kind == 'weekly':
        if day is None or not 0 <= day <= 6:    # 0 = Monday
            return None
        at -= timedelta(days=(at.weekday() - day) % 7)
    elif kind == 'monthly':
        if day is None or not 1 <= day <= 31:
            return None
        # back to the latest month that has the day; of any two in a row one does
        y, m = at.year, at.month
        for _ in range(3):
            try:
                found = at.replace(year=y, month=m, day=day)
                if found <= at:
                    return found if found >= first else None
            except ValueError:
                pass
            y, m = (y, m - 1) if m > 1 else (y - 1, 12)
        return None
    return at if at >= first else None


def _ran_for(task, slot):
    """Whether the last run of `task` took the slot `slot` already. To the minute: a stamp
    a few seconds into its minute (a late pass, a leader whose clock ran ahead) does not
    push the next hourly or weekly run out by a whole slot."""
    if not task.get('last_run'):
        return False
    ran = _minute(datetime.fromisoformat(task['last_run']))
    kind = task.get('schedule_type', 'daily')
    if kind == 'hourly':
        return ran + timedelta(hours=1) > slot
    if kind == 'weekly':
        return ran + timedelta(days=7) > slot
    if kind == 'monthly':
        return (ran.year, ran.month) >= (slot.year, slot.month)
    return ran.date() >= slot.date()


def _report_skipped(tasks, first, last):
    """Say and audit the tasks that fell due in the minutes from `first` to `last`, which
    the loop stepped over, and did not run."""
    names = set()
    for task in tasks:
        try:
            slot = _last_due(task, first, last) if task.get('enabled', True) else None
            if slot is not None and not _ran_for(task, slot):
                names.add(str(task.get('name') or task.get('id')))
        except Exception:
            continue
    why = ('while the scheduler stood still (a clock step forward, a suspended host '
           'or a stalled process)')
    window = (first, last + timedelta(seconds=59))
    if ha.guard_on():
        # the same report as for a change of leader
        ha.missed_schedules('scheduled tasks', sorted(names), window, why)
        return
    if not names:
        return
    a, b = window
    text = (f"{len(names)} scheduled tasks fell due between {a:%Y-%m-%d %H:%M:%S} and "
            f"{b:%Y-%m-%d %H:%M:%S} {why} and did not run: {', '.join(sorted(names)[:20])}")
    logging.warning(f"[Scheduler] {_sl(text)}")
    log_audit('system', 'scheduled_task.missed', text)


def _report_missed(tasks):
    """Once a new leader of an automatic group acts: the tasks that fell due in the gap."""
    window = ha.missed_schedule_window('scheduled tasks')
    if not window:
        return
    # the latest slot of each task in the gap (the marks let it reach back days, so not
    # minute by minute); a last run from that minute on: the former leader got to it
    first, last = (_minute(ha.schedule_at(w)) for w in window)
    missed = set()
    for t in tasks:
        try:
            slot = _last_due(t, first, last) if t.get('enabled', True) else None
        except (TypeError, ValueError):
            continue
        if slot is not None and str(t.get('last_run') or '') < slot.isoformat():
            missed.add(str(t.get('name') or t.get('id')))
    # the end of the gap is the group's mark before the report goes out: the next leader
    # starts after it. A no leaves it to the next pass
    if missed and not ha.missed_settled('scheduled tasks', window):
        return
    ha.missed_schedules('scheduled tasks', sorted(missed), window)


def _report_lost(lost):
    """Tasks whose last run went out and whose lease confirm then failed: no leader runs
    them now, so they are reported as missed (5.7), not run late."""
    slots = [slot for _task, slot in lost]
    names = sorted({str(t.get('name') or t.get('id')) for t, _slot in lost})
    ha.missed_schedules('scheduled tasks', names, (min(slots), max(slots) + timedelta(seconds=59)),
                        'while the lease of this instance could not be confirmed')

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

def _to_next_minute():
    """Seconds to just after the start of the next minute."""
    return 60 - time.time() % 60 + 0.5


def scheduler_loop():
    """Background thread that runs scheduled tasks"""
    global _scheduler_running
    _scheduler_running = True
    last = None
    
    while _scheduler_running:
        try:
            # standby: the tasks run on the active instance, not twice
            if ha.is_active():
                last = run_scheduled_tasks(last)
            else:
                # nothing to catch up once it acts: what fell due meanwhile was the
                # other instance's (5.7 reports it in an automatic group)
                last = None
        except Exception as e:
            logging.error(f"Scheduler error: {e}")
        
        # Once a minute, just after it starts: a flat 60 s after the work let the pass
        # creep through the minute. (Was 30 s once, which ran tasks twice when they took
        # longer than that - each minute is checked once now.)
        time.sleep(_to_next_minute())

def start_scheduler_thread():
    global _scheduler_thread
    if _scheduler_thread is None or not _scheduler_thread.is_alive():
        _scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        _scheduler_thread.start()
        logging.info("Task scheduler thread started")

