# -*- coding: utf-8 -*-
"""scheduler + update schedule routes - split from monolith dec 2025, MK/NS"""

import os
import re
import json
import time
import logging
import threading
from datetime import datetime, timedelta
from urllib.parse import quote
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db
from pegaprox.core import ha, rolling_runs
from pegaprox.background.scheduler import _first_minute, _minute

from pegaprox.utils.auth import require_auth, load_users, build_authz_user
from pegaprox.utils.rbac import has_permission
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import (check_cluster_access, safe_error, require_unconfined, evacuation_options,
                                  evacuation_options_said, rolling_log, rolling_options_intro,
                                  rolling_node_templates, rolling_moved_templates, rolling_rules_give_way,
                                  rolling_rules_back_on, rolling_moved_guests, rolling_wind_down,
                                  rolling_guests_left_moved)
from pegaprox.api.nodes import cleanup_deleted_scripts, cleanup_orphaned_excluded_vms

bp = Blueprint('schedules', __name__)


def _perm_for_action(action):
    # MK: scheduling an action requires the same permission as running it by hand
    return {'start': 'vm.start', 'stop': 'vm.stop', 'shutdown': 'vm.stop',
            'reboot': 'vm.restart', 'snapshot': 'vm.snapshot'}.get(action, 'vm.start')


def _require_action_perm(action):
    # returns an error response if the caller can't perform `action`, else None
    user = build_authz_user(request.session.get('user', ''), request.session)
    perm = _perm_for_action(action)
    if not has_permission(user, perm):
        return jsonify({'error': f'Permission denied: {perm} required to schedule a {action} action'}), 403
    return None


# NS Oct 2026 - vm_type went from the request into the row and from the row into the PVE path
# (nodes/<node>/<vm_type>/<vmid>/...), unchecked. The per-VM check does not look at it on the
# ACL path, so one VM's start/stop grant scheduled 'qemu/<other>/status/stop#' and the scheduler
# sent it with the cluster's own credentials (#1023). A row names a guest by type and number.
VM_ACTIONS = ('start', 'stop', 'shutdown', 'reboot', 'snapshot')
VM_TYPES = ('qemu', 'lxc')


def _schedule_vmid(value):
    """`value` as a VMID, None when it is not one. int() alone takes True, 100.9, ' 100' and '1_00'."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,9}', value):
        value = int(value)
    return value if isinstance(value, int) and 100 <= value <= 999999999 else None


def _schedule_target_error(action):
    """Why `action` cannot run as a scheduled VM action, '' when it can."""
    if action.get('action') not in VM_ACTIONS:
        return f"action must be one of {list(VM_ACTIONS)}"
    if action.get('vm_type') not in VM_TYPES:
        return "vm_type must be 'qemu' or 'lxc'"
    if _schedule_vmid(action.get('vmid')) is None:
        return 'vmid must be a VM ID (100 - 999999999)'
    return ''


def _creator(row):
    """The account a stored schedule acts for, as it stands now, or None.

    NS Oct 2026 - a schedule acts with the cluster's own credentials long after the request
    that made it. Its creator may since have been demoted, moved to another tenant, lost the
    VM grant or been removed (#1093), so every run asks again. Read by the account's own row:
    one that is gone, unreadable or switched off acts for nobody."""
    from pegaprox.utils.auth import resolve_authz_user
    user = resolve_authz_user({'user': row.get('created_by') or ''})
    if not user or not user.get('enabled', True):
        return None
    return user


def _creator_may_update(cluster_id, schedule):
    """Whether the creator of a rolling-update schedule may still arm it: the gates of
    set_update_schedule, asked again at run time."""
    from pegaprox.api.helpers import caller_is_scoped
    creator = _creator(schedule)
    if not creator or not has_permission(creator, 'node.update') or caller_is_scoped(creator, cluster_id):
        return False
    return not schedule.get('include_reboot', True) or has_permission(creator, 'node.reboot')


_bad_targets_said = set()


def _disable_bad_target(action):
    """A stored row that names no guest (written before the checks above) stays, so it can be
    seen, fixed or deleted, but it is switched off and never fires. Logged once per row."""
    why = _schedule_target_error(action)
    if not why:
        return
    action['enabled'] = False
    if action.get('id') not in _bad_targets_said:
        _bad_targets_said.add(action.get('id'))
        logging.warning(f"[SCHEDULER] scheduled action {action.get('id')} switched off: {why}")

# ============================================

SCHEDULES_FILE = os.path.join(CONFIG_DIR, 'scheduled_actions.json')
_scheduler_thread = None
_scheduler_running = False

class _ScheduleSnapshot(dict):
    """A schedule snapshot that knows whether it really came from the table.

    load_schedules() answered `{'actions': [], 'last_id': 0}` both for "no schedules
    configured" and for "the table did not load", and save_schedules() starts with an
    unconditional DELETE. So one failed read followed by an ordinary create request
    rewrote the table to contain that single new row - every scheduled action in the
    installation, across every tenant, gone and committed. MK Sep 2026

    Same lesson _record_action_run() already learned below: never hand a snapshot back
    to a writer that clears the table first.
    """
    __slots__ = ('unavailable',)

    def __init__(self, *args, unavailable=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.unavailable = unavailable


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
        # MK Apr 2026 (#337): name + vm_type are persisted via columns added in the
        # db migration block. On legacy rows both come back as NULL — fall back
        # to a sensible default so the frontend form doesn't render blank.
        row_keys = [d[0] for d in cursor.description] if cursor.description else []
        has_name = 'name' in row_keys
        has_vm_type = 'vm_type' in row_keys
        for row in cursor.fetchall():
            if row['id'] > last_id:
                last_id = row['id']
            actions.append({
                'id': row['id'],
                'cluster_id': row['cluster_id'],
                'vmid': row['vmid'],
                'vm_type': (row['vm_type'] if has_vm_type and row['vm_type'] else 'qemu'),
                'action': row['action'],
                'schedule_type': row['schedule_type'],
                'time': row['schedule_time'],
                'days': json.loads(row['schedule_days'] or '[]'),
                'date': row['schedule_date'],
                'enabled': bool(row['enabled']),
                'last_run': row['last_run'],
                'name': (row['name'] if has_name and row['name'] else ''),
                'created_by': row['created_by'],
            })
            _disable_bad_target(actions[-1])
        
        return _ScheduleSnapshot(actions=actions, last_id=last_id)
    except Exception as e:
        logging.error(f"Error loading schedules from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(SCHEDULES_FILE):
                with open(SCHEDULES_FILE, 'r') as f:
                    legacy = _ScheduleSnapshot(json.load(f))
                for a in legacy.get('actions', []):
                    a['vm_type'] = a.get('vm_type') or 'qemu'   # same default as a table row
                    _disable_bad_target(a)
                return legacy
        except Exception:
            pass
    # NOT an empty schedule table - we do not know what is in it.
    return _ScheduleSnapshot(actions=[], last_id=0, unavailable=True)


def _record_action_run(action_id, last_run, disable=False):
    """Record one action's run without rewriting the table around it.

    The tick used to reload every row, execute (which blocks on the cluster API for as long as
    a VM takes to start or stop), then hand the whole pre-tick snapshot to save_schedules —
    which is a DELETE followed by a re-INSERT. So a schedule an operator added during that
    window disappeared, and one they deleted came back and kept firing. Same shape, and the
    same fix, as _touch_last_run in background/scheduler.py."""
    if not action_id:
        return
    try:
        db = get_db()
        if disable:
            db.conn.execute('UPDATE scheduled_actions SET last_run = ?, enabled = 0 WHERE id = ?',
                            (last_run, action_id))
        else:
            db.conn.execute('UPDATE scheduled_actions SET last_run = ? WHERE id = ?',
                            (last_run, action_id))
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to record run for scheduled action {action_id}: {e}")


def save_schedules(schedules):
    """Save scheduled actions to SQLite database. True when the table was rewritten.

    SQLite migration
    """
    if getattr(schedules, 'unavailable', False):
        # the snapshot never loaded; writing it back would clear the table
        logging.error("[Schedules] refusing to rewrite the table from a snapshot "
                      "that failed to load")
        return False
    try:
        db = get_db()
        cursor = db.conn.cursor()

        # Clear existing schedules. The insert loop below is part of the same
        # transaction - committing the DELETE on its own would leave an empty table
        # behind if a single row failed to write.
        cursor.execute('DELETE FROM scheduled_actions')
        
        now = datetime.now().isoformat()
        # MK Apr 2026 (#337): include name + vm_type — previously dropped silently
        for action in schedules.get('actions', []):
            cursor.execute('''
                INSERT INTO scheduled_actions
                (id, cluster_id, vmid, vm_type, action, schedule_type, schedule_time,
                 schedule_days, schedule_date, enabled, last_run, name, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action.get('id'),
                action.get('cluster_id'),
                action.get('vmid'),
                action.get('vm_type', 'qemu'),
                action.get('action', ''),
                action.get('schedule_type', 'daily'),
                action.get('time', ''),
                json.dumps(action.get('days', [])),
                action.get('date'),
                1 if action.get('enabled', True) else 0,
                action.get('last_run'),
                action.get('name') or None,
                action.get('created_by'),
                now
            ))
        
        db.conn.commit()
        return True
    except Exception as e:
        try:
            get_db().conn.rollback()
        except Exception:
            pass
        logging.error(f"Error saving schedules: {e}")
        return False


def check_schedules():
    """Check if any scheduled actions need to run
    
    Called every minute by the scheduler thread
    This is deliberately simple - no cron expressions, just specific times
    """
    global _scheduler_running
    # what the pass before checked: (minute, wall time, seconds it took); None checks the
    # current minute only
    last = None

    while _scheduler_running:
        # a standby keeps ticking but fires nothing: VM actions, scheduled rolling
        # updates and the 03:00 cleanup all belong to the active instance (#625)
        if not ha.is_active():
            # nothing to catch up once it acts: what fell due meanwhile was the other
            # instance's (5.7 reports it in an automatic group)
            last = None
            _wait_a_minute()
            continue
        try:
            started = time.monotonic()
            schedules = load_schedules()
            actions = schedules.get('actions', [])
            # the group's zone when this instance is in one, so a failover does not
            # shift a schedule; datetime.now() on an instance of its own (#625)
            now = _minute(ha.schedule_now())
            wall = time.time()
            # automatic failover (design 5.7): what fell due without a leader is said, and
            # a new leader fires nothing in a minute the former one may have fired. Neither
            # does anything anywhere else
            _report_missed(actions)
            if ha.schedule_held():
                last = (now, wall, 0.0)
                _wait_a_minute()
                continue

            # MK Oct 2026 - every minute since the pass before, not just the one it woke
            # in: a minute the loop slept over never ran its actions. A long gap (clock
            # step forward, suspended host) is reported instead of run late, as in
            # background/scheduler.py
            first, skipped = _first_minute(last, now, wall)
            if skipped:
                # in an automatic group the gap is the group's mark first (5.7)
                if not ha.report_settled('scheduled actions', wall - 60,
                                         'the report of the minutes the scheduled actions stepped over'):
                    last = (now, wall, 0.0)
                    _wait_a_minute()
                    continue
                _report_skipped(actions, *skipped)
            minutes = []
            at = first
            while at <= now:
                minutes.append(at)
                at += timedelta(minutes=1)

            lost, through = [], True
            for action in actions:
                if not action.get('enabled', True):
                    continue
                slot = next((m for m in reversed(minutes) if _due_minute(action, m)), None)
                if slot is None:
                    continue
                stamp = slot.strftime('%Y-%m-%d %H:%M')
                # ran in this minute or later already (prevent double execution; a clock
                # step back must not run a minute twice)
                if _stamp(action.get('last_run')) >= stamp:
                    continue
                # a minute caught up that a new leader still holds (5.7)
                if slot < now and ha.schedule_held(slot):
                    continue
                if action.get('schedule_type') == 'once':
                    action['enabled'] = False  # Disable after running

                first_run = ha.schedule_fire_first()
                if first_run:
                    if not ha.is_active():
                        # the lease went during this pass: the rest is the next leader's
                        through = False
                        break
                    # at most once: written and on its way to the members before it acts
                    _record_action_run(action.get('id'), stamp,
                                       disable=not action.get('enabled', True))
                    ha.schedule_fired()
                if not ha.confirm_step(f"scheduled {action.get('action')} of {action.get('vmid')}"):
                    if not first_run:
                        through = False
                        break
                    # used up and reported (lab E6b_2), the ones after it try again
                    lost.append((action, slot))
                    continue
                # Execute the action
                execute_scheduled_action(action)
                action['last_run'] = stamp
                _record_action_run(action.get('id'), action['last_run'],
                                   disable=not action.get('enabled', True))
            if lost:
                _report_lost(lost)
            if through:
                # the group's mark for the report of the next leader (5.7)
                ha.schedules_checked('scheduled actions', wall)

            # MK: Check for scheduled rolling updates
            try:
                check_scheduled_updates()
            except Exception as e:
                logging.error(f"[SCHEDULER] Scheduled updates check error: {e}")
            
            # Daily cleanup tasks at 03:00
            if any(m.hour == 3 and m.minute == 0 for m in minutes):
                try:
                    # Cleanup soft-deleted scripts after 20 days
                    cleanup_deleted_scripts()
                    # MK: Cleanup orphaned excluded VMs (VMs that no longer exist)
                    cleanup_orphaned_excluded_vms()
                    logging.info("[SCHEDULER] Daily cleanup completed")
                except Exception as e:
                    logging.error(f"[SCHEDULER] Daily cleanup error: {e}")
            last = (now, wall, time.monotonic() - started)
        
        except Exception as e:
            logging.error(f"Scheduler error: {e}")
        
        _wait_a_minute()


def _stamp(value):
    """A last run as 'YYYY-MM-DD HH:MM', the form the tick writes ('' for none)."""
    return str(value or '').replace('T', ' ')[:16]


def _due_minute(action, at):
    """Whether `action` falls due in the minute `at`, its last run aside."""
    if action.get('time', '') != at.strftime('%H:%M'):
        return False
    kind, day = action.get('schedule_type', 'daily'), at.strftime('%A').lower()
    if kind == 'once':
        return action.get('date') == at.strftime('%Y-%m-%d')
    return (kind == 'daily' or (kind == 'weekly' and day in (action.get('days') or []))
            or (kind == 'weekdays' and day not in ('saturday', 'sunday'))
            or (kind == 'weekends' and day in ('saturday', 'sunday')))


# a week of minutes at most is looked through for the report of a gap
_REPORT_SPAN = 7 * 24 * 60


def _report_skipped(actions, first, last):
    """Say and audit the actions that fell due in the minutes from `first` to `last`,
    which the loop stepped over, and did not run."""
    names = set()
    at, n = first, 0
    while at <= last and n < _REPORT_SPAN:
        stamp = at.strftime('%Y-%m-%d %H:%M')
        names.update(str(a.get('name') or f"{a.get('action')} {a.get('vmid')}") for a in actions
                     if a.get('enabled', True) and _due_minute(a, at)
                     and _stamp(a.get('last_run')) < stamp)
        at += timedelta(minutes=1)
        n += 1
    why = ('while the scheduler stood still (a clock step forward, a suspended host '
           'or a stalled process)')
    window = (first, last + timedelta(seconds=59))
    if ha.guard_on():
        ha.missed_schedules('scheduled actions', sorted(names), window, why)
        return
    if not names:
        return
    a, b = window
    text = (f"{len(names)} scheduled actions fell due between {a:%Y-%m-%d %H:%M:%S} and "
            f"{b:%Y-%m-%d %H:%M:%S} {why} and did not run: {', '.join(sorted(names)[:20])}")
    logging.warning(f"[SCHEDULER] {text}")
    log_audit('system', 'scheduled_action.missed', text)


def _report_missed(actions):
    """Once a new leader of an automatic group acts: the actions that fell due in the gap."""
    window = ha.missed_schedule_window('scheduled actions')
    if not window:
        return
    first, last = (ha.schedule_at(w).replace(second=0, microsecond=0) for w in window)
    missed = set()
    for a in actions:
        slot = _latest_due(a, first, last) if a.get('enabled', True) else None
        # a last run in that minute or later: the former leader got to it
        if slot is not None and _stamp(a.get('last_run')) < slot.strftime('%Y-%m-%d %H:%M'):
            missed.add(_action_name(a))
    # the end of the gap is the group's mark before the report goes out: the next leader
    # starts after it. A no leaves it to the next pass
    if missed and not ha.missed_settled('scheduled actions', window):
        return
    ha.missed_schedules('scheduled actions', sorted(missed), window)


def _action_name(action):
    return str(action.get('name') or f"{action.get('action')} {action.get('vmid')}")


def _latest_due(action, first, last):
    """The latest minute from `first` to `last` at which `action` falls due, its last run
    aside; None for none. A day at a time: the marks of 5.7 let the gap reach back days."""
    try:
        hour, minute = map(int, str(action.get('time', '')).split(':'))
        day = last.replace(hour=hour, minute=minute)
    except (TypeError, ValueError):
        return None
    if day > last:
        day -= timedelta(days=1)
    while day >= first:
        if _due_minute(action, day):
            return day
        day -= timedelta(days=1)
    return None


def _report_lost(lost):
    """Actions whose last run went out and whose lease confirm then failed: no leader runs
    them now, so they are reported as missed (5.7), not run late."""
    slots = [slot for _action, slot in lost]
    ha.missed_schedules('scheduled actions', sorted({_action_name(a) for a, _slot in lost}),
                        (min(slots), max(slots) + timedelta(seconds=59)),
                        'while the lease of this instance could not be confirmed')


def _wait_a_minute():
    # to just after the start of the next minute, in 1 s steps so a stop is quick. A flat
    # 60 s after the work let the pass creep through the minute until it stepped over one
    until = time.time() + 60 - time.time() % 60 + 0.5
    while _scheduler_running and time.time() < until:
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
        
        # the row is checked again here, whatever wrote it, and the path is built from the
        # guest PVE lists under that number: its type must be the row's (#1023)
        why = _schedule_target_error(dict(action, vm_type=vm_type))
        if why:
            logging.error(f"[SCHEDULER] Refusing scheduled action {action.get('id')}: {why}")
            return
        vmid = _schedule_vmid(vmid)
        from pegaprox.utils.rbac import user_can_access_vm
        creator = _creator(action)
        if not creator or not user_can_access_vm(creator, cluster_id, vmid,
                                                 _perm_for_action(action_type), vm_type):
            logging.warning(f"[SCHEDULER] Not running scheduled action {action.get('id')}: "
                            f"{action.get('created_by')!r} may no longer {action_type} {vm_type}/{vmid}")
            log_audit('scheduler', 'scheduled.refused',
                      f"Scheduled {action_type} of VM {vmid} in {cluster_id} not run: its creator "
                      f"{action.get('created_by')!r} may no longer do it")
            return

        # Find the node where the VM is running
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == vmid), None)
        
        if not vm:
            logging.error(f"[SCHEDULER] VM {vmid} not found")
            return
        if vm.get('type') != vm_type:
            logging.error(f"[SCHEDULER] Refusing scheduled {action_type} of {vmid}: "
                          f"the schedule says {vm_type}, the guest is {vm.get('type')}")
            return
        
        node = quote(str(vm.get('node') or ''), safe='')
        host, port = mgr.host, mgr.api_port
        
        # Build the API URL based on action
        if action_type == 'start':
            url = f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/start"
        elif action_type == 'stop':
            url = f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/stop"
        elif action_type == 'shutdown':
            url = f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/shutdown"
        elif action_type == 'reboot':
            url = f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/reboot"
        elif action_type == 'snapshot':
            # Create a snapshot with timestamp
            snap_name = f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M')}"
            url = f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot"
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

    MK Oct 2026 - kept in rolling_update_runs like a run started by hand: not started while
    one of the cluster is running or paused, and a run a restart interrupted is paused there
    and goes on (or is cancelled) through the routes of settings.py.
    """
    try:
        # Get update config from action
        config = action.get('config', {})
        include_reboot = config.get('include_reboot', False)
        skip_evacuation = config.get('skip_evacuation', False)
        skip_up_to_date = config.get('skip_up_to_date', True)
        evacuation_timeout = config.get('evacuation_timeout', 1800)
        # MK #630: reboot timeout was hardcoded 600 here — now carried per-schedule. Clamp it the
        # same way the manual rolling-update path does (60s..2h) so a bad stored value can't wedge.
        try:
            reboot_timeout = max(60, min(7200, int(config.get('reboot_timeout', 600) or 600)))
        except (TypeError, ValueError):
            reboot_timeout = 600
        wait_for_reboot = config.get('wait_for_reboot', True)
        # NS #630 - scheduled updates run unattended, so default local-disk
        # evacuation ON: a run that pauses at 3am waiting for a human because one
        # local-disk VM couldn't live-migrate is the worst possible outcome for an
        # automatic update. On shared-storage clusters it's a no-op anyway. Honour a
        # per-schedule override if one is ever stored, else evacuate everything.
        allow_local_disks = action.get('allow_local_disks', True) is not False
        # MK Oct 2026 (#763, #954) - the two evacuation options of the schedule, off on one
        # saved before they existed and on XCP-ng, as for a run started by hand
        migrate_templates, relax_anti_affinity = evacuation_options(mgr, config)

        logging.info(f"[SCHEDULER] Starting scheduled rolling update for cluster {cluster_id}")
        logging.info(f"[SCHEDULER] Config: reboot={include_reboot}, skip_evacuation={skip_evacuation}")
        
        # Check if already running - or paused, which waits for an admin
        why = rolling_runs.busy(mgr, cluster_id)
        if why:
            logging.warning(f"[SCHEDULER] Rolling update not started on {cluster_id}: {why}")
            return
        
        # Get nodes
        node_status = mgr.get_node_status()
        nodes_to_update = list(node_status.keys()) if node_status else []
        
        if not nodes_to_update:
            logging.warning(f"[SCHEDULER] No nodes available for update")
            return
        
        # Initialize rolling update state, in the table before the first step
        state = rolling_runs.begin(mgr, cluster_id, {
            'status': 'running', 'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'include_reboot': include_reboot, 'skip_up_to_date': skip_up_to_date,
            'skip_evacuation': skip_evacuation, 'wait_for_reboot': wait_for_reboot,
            'pause_on_evacuation_error': False, 'force_all': False, 'allow_local_disks': allow_local_disks,
            'migrate_templates': migrate_templates, 'relax_anti_affinity': relax_anti_affinity,
            'evacuation_timeout': evacuation_timeout, 'update_timeout': 900, 'reboot_timeout': reboot_timeout,
            'nodes': nodes_to_update, 'current_index': 0, 'current_node': nodes_to_update[0],
            'current_step': 'starting', 'completed_nodes': [], 'skipped_nodes': [],
            'failed_nodes': [], 'rebooting_nodes': [], 'paused_reason': None, 'paused_details': None,
            'logs': [f"[{time.strftime('%H:%M:%S')}] Scheduled rolling update started"], 'scheduled': True
        }, 'scheduler')
        if state is None:
            logging.warning(f"[SCHEDULER] Rolling update not started on {cluster_id}: another run came first")
            return
        log_audit('scheduler', 'node.rolling_update_started',
                  f"Scheduled rolling update of {len(nodes_to_update)} node(s) started"
                  + evacuation_options_said(migrate_templates, relax_anti_affinity),
                  cluster=getattr(mgr.config, 'name', cluster_id))

        def run_scheduled_update():
            def _set(**kw):
                return rolling_runs.change(mgr, **kw)

            def _status():
                return (rolling_runs.current(mgr) or {}).get('status')

            def _quorum_stop(idx, node_name, phase):
                """MK Oct 2026 - the quorum gate of settings.run_rolling_update. This worker waits
                for nobody: a node that would cost the cluster its quorum pauses the run (reason
                'quorum') and this worker ends - a Continue hands the run to the worker of a run
                started by hand, which looks again. 'paused', 'cancelled' or None to go on."""
                verdict = rolling_runs.quorum_gate(mgr, node_name, sleep=time.sleep,
                                                   stop=lambda: _status() != 'running')
                if verdict['ok']:
                    if not verdict.get('skipped'):
                        rolling_log(mgr, rolling_runs.quorum_said(verdict))
                    return None
                if _status() != 'running':
                    return 'cancelled'
                details, line = rolling_runs.quorum_hold(verdict, phase)
                logging.warning(f"[SCHEDULER] Rolling update of {cluster_id} paused before {node_name}: "
                                f"quorum {verdict.get('reason')}")
                _set(status='paused', current_step='paused_quorum', paused_reason=rolling_runs.QUORUM,
                     paused_details=details, resume_at={'index': idx, 'phase': phase}, log=line)
                return 'paused'

            rolling_log(mgr, f"Settings: skip_up_to_date={skip_up_to_date}, skip_evacuation={skip_evacuation}, "
                             f"evacuation_timeout={evacuation_timeout}s, reboot_timeout={reboot_timeout}s, "
                             f"migrate_templates={migrate_templates}, relax_anti_affinity={relax_anti_affinity}")
            rolling_options_intro(mgr)
            try:
                for idx, node_name in enumerate(nodes_to_update):
                    if _status() != 'running':
                        break
                    _set(current_index=idx, current_node=node_name, current_step='checking',
                         node=(node_name, {'phase': 'checking'}), log=f"Processing {node_name}")
                    if skip_up_to_date:
                        try:
                            mgr.refresh_node_apt(node_name); time.sleep(3)
                            if not mgr.get_node_apt_updates(node_name):
                                _set(add={'skipped_nodes': node_name},
                                     node=(node_name, {'phase': 'done', 'result': 'skipped'}),
                                     log=f"{node_name} up-to-date, skipping")
                                continue
                        except Exception as e:
                            logging.warning(f"[SCHEDULER] Check failed for {node_name}: {e}")
                    _set(current_step='maintenance', node=(node_name, {'phase': 'maintenance'}))
                    gate = _quorum_stop(idx, node_name, 'maintenance')
                    if gate == 'paused':
                        return
                    if gate:
                        break
                    running = []
                    if not skip_evacuation:
                        try:
                            here = [r for r in (mgr.get_vm_resources() or [])
                                    if r.get('node') == node_name and r.get('type') in ('qemu', 'lxc')]
                            running = [v for v in here if (v.get('status') or '').lower() == 'running']
                            rolling_node_templates(mgr, here)
                        except Exception:
                            pass
                        rolling_rules_give_way(mgr, 'scheduler')   # #954, once, before the first evacuation
                    # before each node's evacuation and its update (design 5.2)
                    if not ha.confirm_step(f'rolling update of {node_name}'):
                        rolling_log(mgr, "stopped: this instance does not hold the lease")
                        break
                    mgr.enter_maintenance_mode(node_name, skip_evacuation=skip_evacuation,
                                               allow_local_disks=allow_local_disks,
                                               **({'migrate_templates': True} if migrate_templates else {}))  # #763
                    _set(node=(node_name, {'in_maintenance': True}))
                    if not skip_evacuation:
                        _set(current_step='evacuating', node=(node_name, {'phase': 'evacuating'}))
                        waited = 0; evacuation_ok = False; task = None
                        while waited < evacuation_timeout and _status() != 'cancelled':
                            if node_name in mgr.nodes_in_maintenance:
                                task = mgr.nodes_in_maintenance[node_name]
                                if task.status == 'completed':
                                    rolling_moved_templates(mgr, task)
                                    evacuation_ok = True; break
                                elif task.status == 'completed_with_errors':
                                    rolling_moved_templates(mgr, task)
                                    fv = getattr(task, 'failed_vms', [])
                                    rolling_log(mgr, f"⚠️ Evacuation: {getattr(task,'migrated_vms',0)}/{getattr(task,'total_vms',0)} migrated, {len(fv)} failed - continuing")
                                    evacuation_ok = True; break
                                elif task.status == 'failed': break
                            time.sleep(5); waited += 5
                        if _status() == 'cancelled':
                            break
                        if not evacuation_ok:
                            _set(add={'failed_nodes': {'node': node_name, 'error': 'Evacuation failed'}},
                                 node=(node_name, {'result': 'failed'}),
                                 log=f"✗ Evacuation failed on {node_name}, skipping")
                            if mgr.exit_maintenance_mode(node_name):
                                _set(node=(node_name, {'in_maintenance': False}))
                            continue
                        rolling_moved_guests(mgr, node_name, running, task)
                    _set(current_step='updating', node=(node_name, {'phase': 'updating'}))
                    gate = _quorum_stop(idx, node_name, 'updating')
                    if gate == 'paused':
                        return
                    if gate:
                        break
                    if not ha.confirm_step(f'update of {node_name}'):
                        rolling_log(mgr, "stopped: this instance does not hold the lease")
                        break
                    update_task = mgr.start_node_update(node_name, reboot=include_reboot, force=True)
                    if update_task:
                        waited = 0
                        while waited < (1800 if include_reboot else 900):
                            if update_task.status in ['completed', 'failed']: break
                            time.sleep(10); waited += 10
                        if update_task.status == 'completed':
                            _set(add={'completed_nodes': node_name}, node=(node_name, {'updated': True}),
                                 log=f"✓ {node_name} updated")
                            if include_reboot:
                                _set(current_step='rebooting', add={'rebooting_nodes': node_name},
                                     node=(node_name, {'phase': 'rebooting', 'rebooted': True}))
                                if wait_for_reboot:
                                    rolling_log(mgr, f"Waiting for {node_name} to reboot...")
                                    ow = 0
                                    while ow < 120:
                                        try:
                                            ns = mgr.get_node_status()
                                            if node_name not in ns or ns[node_name].get('status') != 'online': break
                                        except: break
                                        time.sleep(5); ow += 5
                                    rw = 0
                                    came_back = False
                                    # #630 - the schedule's own reboot timeout, it was a fixed 600 s here
                                    while rw < reboot_timeout and _status() != 'cancelled':
                                        try:
                                            ns = mgr.get_node_status()
                                            if node_name in ns and ns[node_name].get('status') == 'online':
                                                _set(drop={'rebooting_nodes': node_name},
                                                     log=f"✓ {node_name} back online")
                                                came_back = True
                                                # NS May 2026 — give HA services time to start
                                                # before trying to disable maintenance. 10s was
                                                # too short → ha-manager rejected the disable
                                                # call and node stayed in maintenance.
                                                time.sleep(30)
                                                break
                                        except: pass
                                        time.sleep(10); rw += 10
                                    if not came_back:
                                        rolling_log(mgr, f"⚠ {node_name} did not come back online within {reboot_timeout}s")
                                else:
                                    rolling_log(mgr, f"{node_name} rebooting (wait_for_reboot=False)")
                        else:
                            _set(add={'failed_nodes': {'node': node_name, 'error': 'Update failed'}},
                                 node=(node_name, {'result': 'failed'}), log=f"✗ {node_name} update failed")
                    # NS May 2026 — exit_maintenance_mode now retries internally;
                    # if it still returns False the node is stuck and we log it
                    # for the post-loop sweep below. One the update took out itself is no failed exit.
                    _set(current_step='finishing', node=(node_name, {'phase': 'finishing'}))
                    if node_name not in mgr.nodes_in_maintenance or mgr.exit_maintenance_mode(node_name):
                        _set(node=(node_name, {'in_maintenance': False}))
                    else:
                        rolling_log(mgr, f"⚠ {node_name} maintenance exit failed - will retry at end")
                    if node_name in ((rolling_runs.current(mgr) or {}).get('completed_nodes') or []):
                        _set(node=(node_name, {'phase': 'done', 'result': 'done', 'moved': []}))
                
                # NS May 2026 - final sweep: every node this run put into maintenance that is
                # still in it gets one more shot, after a longer settle time. Catches the case
                # where the node took long to reboot or HA services were still starting when we
                # tried to exit. And the negative affinity rules come back on (#954).
                cancelled = _status() == 'cancelled'
                if not cancelled:
                    _set(current_step=rolling_runs.CLEANUP)
                undone = rolling_wind_down(mgr, 'scheduler', settle=15, sleep=time.sleep)

                # Finished
                done = rolling_runs.current(mgr) or {}
                counts = (f"{len(done.get('completed_nodes') or [])} updated, "
                          f"{len(done.get('skipped_nodes') or [])} skipped, "
                          f"{len(done.get('failed_nodes') or [])} failed")
                if cancelled:
                    _set(cancel_report=undone + rolling_guests_left_moved(mgr), rebooting_nodes=[],
                         log="Scheduled rolling update cancelled")
                else:
                    _set(status='completed', rebooting_nodes=[], log="Scheduled rolling update completed")
                
                # Log audit
                log_audit('scheduler', 'scheduled.rolling_update', 
                          f"Scheduled rolling update {'cancelled' if cancelled else 'completed'}: {counts}")
                
            except Exception as e:
                logging.error(f"[SCHEDULER] Rolling update error: {e}")
                # MK Oct 2026 - the nodes this run put into maintenance come out again, as after a
                # cancel; the manual run does the same in its own error path
                try:
                    rolling_wind_down(mgr, 'scheduler', settle=15, sleep=time.sleep)
                except Exception as wd:
                    logging.error(f"[SCHEDULER] Rolling update cleanup after the error failed: {wd}")
                rolling_rules_back_on(mgr, 'scheduler')   # #954, before the status says the run is over
                _set(status='failed', error=str(e), rebooting_nodes=[], log=f"ERROR: {e}")

        run_id = state.get('run_id')

        def work():
            try:
                run_scheduled_update()
            finally:
                rolling_runs.detach(cluster_id, run_id)
        
        # the steps between the confirms (apt refresh, maintenance exit) ask at their exit (#625)
        update_thread = threading.Thread(target=ha.as_job(work, f'rolling update of {cluster_id}'),
                                         daemon=True)
        rolling_runs.attach(mgr, cluster_id, update_thread)
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
    from pegaprox.utils.auth import build_authz_user
    # sec (audit): the raw stored record skips API-token effective_role flooring, so an
    # admin-owned viewer token hit the all-clusters early return below and read every
    # scheduled action in the install.
    user_data = build_authz_user(user, request.session)
    from pegaprox.utils.rbac import acts_as_admin
    is_admin = acts_as_admin(user_data)

    # NS Jul 2026 (CodeAnt IDOR) — use the real access model. The old filter read the raw
    # user_data['clusters'] field and FELL OPEN (`if not user_clusters` -> returned every tenant's
    # schedules) when it was empty. get_user_clusters returns None only for a genuine admin/
    # default-tenant all-cluster user; otherwise it's the caller's reachable cluster set.
    from pegaprox.utils.rbac import get_user_clusters, user_can_access_vm
    _ud = dict(user_data)
    _ud['username'] = user
    allowed = get_user_clusters(_ud)
    if is_admin or allowed is None:
        return jsonify(schedules.get('actions', []))

    # sec (private disclosure Sep 2026 — audit M6): the cluster filter alone let a pool-/ACL-scoped
    # caller read per-VM schedule rows (incl. other users' created_by) for every VM on a reachable
    # cluster. The create/update paths already gate per-VM via user_can_access_vm; gate the LIST too.
    # Plain operators keep every action on their clusters (user_can_access_vm returns True for them).
    authz = _ud
    out = []
    for a in schedules.get('actions', []):
        if a.get('cluster_id') not in allowed:
            continue
        try:
            if user_can_access_vm(authz, a['cluster_id'], int(a.get('vmid')), 'vm.view', a.get('vm_type')):
                out.append(a)
        except (TypeError, ValueError):
            continue   # malformed / non-VM action → drop from a scoped listing (fail closed)
    return jsonify(out)


@bp.route('/api/schedules', methods=['POST'])
@require_auth()  # per-action permission checked below
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

    perm_err = _require_action_perm(data['action'])
    if perm_err:
        return perm_err

    # NS Aug 2026 (Aikido pentest) — clear the SAME per-VM ACL the live action enforces (vms.py),
    # not just cluster reachability, else a pool-restricted user could schedule actions on any VMID.
    _sv = _schedule_vmid(data['vmid'])
    _vm_type = data.get('vm_type', 'qemu')
    _bad = _schedule_target_error({'action': data['action'], 'vm_type': _vm_type, 'vmid': _sv})
    if _bad:
        return jsonify({'error': _bad}), 400
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    if not user_can_access_vm(build_authz_user(request.session.get('user', ''), request.session),
                              data['cluster_id'], _sv, _perm_for_action(data['action']),
                              _vm_type):
        return jsonify({'error': 'Permission denied for this VM'}), 403

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
    if getattr(schedules, 'unavailable', False):
        # an empty snapshot here is not "you have no schedules" - it is "the table did
        # not answer". Saying 404/creating on top of it is how the whole table got
        # rewritten from one row.
        return jsonify({'error': 'Schedules are temporarily unavailable - check the '
                                 'server logs', 'code': 'SCHEDULE_STORE_UNAVAILABLE'}), 503

    # Generate new ID
    new_id = schedules.get('last_id', 0) + 1
    schedules['last_id'] = new_id
    
    # Create the schedule
    new_schedule = {
        'id': new_id,
        'cluster_id': data['cluster_id'],
        'vmid': _sv,
        'vm_type': _vm_type,
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
    if not save_schedules(schedules):
        # the write was refused or rolled back; do not audit it as done or tell the
        # caller it happened.
        return jsonify({'error': 'Could not save the schedule - check the server logs',
                        'code': 'SCHEDULE_WRITE_FAILED'}), 500

    log_audit(request.session.get('user', 'system'), 'schedule.created', 
             f"Created schedule '{new_schedule['name']}' for VM {data['vmid']}")
    
    return jsonify({'success': True, 'schedule': new_schedule})


@bp.route('/api/schedules/<int:schedule_id>', methods=['PUT'])
@require_auth()  # per-action permission checked below
def update_schedule(schedule_id):
    """Update a scheduled action"""
    data = request.json or {}
    schedules = load_schedules()
    if getattr(schedules, 'unavailable', False):
        # see create_schedule: an empty snapshot is not "you have none"
        return jsonify({'error': 'Schedules are temporarily unavailable - check the '
                                 'server logs', 'code': 'SCHEDULE_STORE_UNAVAILABLE'}), 503

    # Find the schedule
    schedule = next((s for s in schedules.get('actions', []) if s.get('id') == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404

    # NS: Feb 2026 - verify tenant has access to this schedule's cluster
    ok, err = check_cluster_access(schedule.get('cluster_id', ''))
    if not ok: return err

    # Validate action if being updated
    if 'action' in data:
        valid_actions = ['start', 'stop', 'shutdown', 'reboot', 'snapshot']
        if data['action'] not in valid_actions:
            return jsonify({'error': f'Action must be one of: {valid_actions}'}), 400

    # need the perm for the effective action — the new one if it's changing, else the
    # one already stored (so a no-action edit still can't be made without the right perm)
    perm_err = _require_action_perm(data.get('action', schedule.get('action', 'start')))
    if perm_err:
        return perm_err

    # NS Aug 2026 (Aikido pentest) — re-check the per-VM ACL for the effective target/action (same
    # as create) so an edit cannot retarget a schedule onto an unauthorized VMID.
    # The target as it will be stored, the request's fields over the row's (#1023).
    _uv = _schedule_vmid(data.get('vmid', schedule.get('vmid')))
    _ut = data.get('vm_type', schedule.get('vm_type', 'qemu'))
    _bad = _schedule_target_error({'action': data.get('action', schedule.get('action')),
                                   'vm_type': _ut, 'vmid': _uv})
    if _bad:
        return jsonify({'error': _bad}), 400
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    _authz = build_authz_user(request.session.get('user', ''), request.session)
    _cid = schedule.get('cluster_id', '')
    # sec (audit): only the NEW target was authorized, so a caller who owns ANY VM on the cluster
    # could point someone else's schedule at their own VM — silently destroying the stored action
    # while the row kept the victim's created_by. Authorize the STORED target first.
    try:
        _stored_vmid = int(schedule.get('vmid'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Schedule has no valid target'}), 403
    if not user_can_access_vm(_authz, _cid, _stored_vmid,
                              _perm_for_action(schedule.get('action', 'start')),
                              schedule.get('vm_type', 'qemu')):
        return jsonify({'error': 'Permission denied for this VM'}), 403
    if not user_can_access_vm(_authz, _cid, _uv,
                              _perm_for_action(data.get('action', schedule.get('action', 'start'))),
                              _ut):
        return jsonify({'error': 'Permission denied for this VM'}), 403

    # Validate time format if being updated
    if 'time' in data:
        try:
            datetime.strptime(data['time'], '%H:%M')
        except ValueError:
            return jsonify({'error': 'Time must be in HH:MM format'}), 400
    
    # Validate schedule type if being updated
    if 'schedule_type' in data:
        valid_types = ['once', 'daily', 'weekly', 'weekdays', 'weekends']
        if data['schedule_type'] not in valid_types:
            return jsonify({'error': f'Schedule type must be one of: {valid_types}'}), 400
    
    # For 'once' type, require date
    schedule_type = data.get('schedule_type', schedule.get('schedule_type'))
    if schedule_type == 'once' and 'date' in data and not data.get('date'):
        return jsonify({'error': 'Date is required for one-time schedules'}), 400
    
    # For 'weekly' type, require days
    if schedule_type == 'weekly' and 'days' in data and not data.get('days'):
        return jsonify({'error': 'Days are required for weekly schedules'}), 400

    # Update fields (vmid/vm_type added Mar 2026 - #133)
    _before = (schedule.get('vmid'), schedule.get('vm_type', 'qemu'), schedule.get('action'))
    updatable = ['name', 'vmid', 'vm_type', 'action', 'schedule_type', 'time', 'date', 'days', 'enabled']
    for field in updatable:
        if field in data:
            schedule[field] = data[field]
    schedule['vmid'] = _uv
    # NS Oct 2026 - a run asks its creator again (#1093); who picked the guest and the action
    # is the one to ask, so a retarget makes the editor the creator
    if (schedule.get('vmid'), schedule.get('vm_type', 'qemu'), schedule.get('action')) != _before:
        schedule['created_by'] = request.session.get('user', 'unknown')

    if not save_schedules(schedules):
        return jsonify({'error': 'Could not save the schedule - check the server logs',
                        'code': 'SCHEDULE_WRITE_FAILED'}), 500

    log_audit(request.session.get('user', 'system'), 'schedule.updated', 
             f"Updated schedule ID {schedule_id}")
    
    return jsonify({'success': True, 'schedule': schedule})


@bp.route('/api/schedules/<int:schedule_id>', methods=['DELETE'])
@require_auth()  # per-action permission checked below
def delete_schedule(schedule_id):
    """Delete a scheduled action"""
    schedules = load_schedules()
    if getattr(schedules, 'unavailable', False):
        # see create_schedule: an empty snapshot is not "you have none"
        return jsonify({'error': 'Schedules are temporarily unavailable - check the '
                                 'server logs', 'code': 'SCHEDULE_STORE_UNAVAILABLE'}), 503

    # verify tenant access before deleting
    schedule = next((s for s in schedules.get('actions', []) if s.get('id') == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404
    ok, err = check_cluster_access(schedule.get('cluster_id', ''))
    if not ok:
        # NS Sep 2026 (audit) — a schedule on a cluster this caller cannot reach must
        # read as absent, not as forbidden; the pair of answers is what turns an id
        # into an enumerable oracle.
        return jsonify({'error': 'Schedule not found'}), 404

    perm_err = _require_action_perm(schedule.get('action', 'start'))
    if perm_err:
        return perm_err

    # sec (private disclosure Sep 2026 — audit): create/update gate the target VM per-object; delete
    # did not, so a co-tenant could delete another tenant's scheduled action by its enumerable id.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        if not user_can_access_vm(build_authz_user(request.session.get('user', ''), request.session),
                                  schedule.get('cluster_id', ''), int(schedule.get('vmid')),
                                  _perm_for_action(schedule.get('action', 'start')), schedule.get('vm_type')):
            return jsonify({'error': 'Access denied to this VM'}), 403
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid schedule target'}), 400

    schedules['actions'] = [s for s in schedules.get('actions', []) if s.get('id') != schedule_id]

    if not save_schedules(schedules):
        return jsonify({'error': 'Could not save the schedule - check the server logs',
                        'code': 'SCHEDULE_WRITE_FAILED'}), 500

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
        'migrate_templates': False,
        'relax_anti_affinity': False,
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
                reboot_timeout INTEGER DEFAULT 600,
                last_run TEXT,
                next_run TEXT,
                created_by TEXT,
                created_at TEXT,
                updated_at TEXT,
                migrate_templates INTEGER DEFAULT 0,
                relax_anti_affinity INTEGER DEFAULT 0
            )
        ''')
        # MK #630 — older schedule tables predate the reboot_timeout column; add it in place
        # so a scheduled run can carry a per-cluster reboot timeout instead of a fixed 600s.
        try:
            cursor.execute("PRAGMA table_info(update_schedules)")
            _cols = {r[1] for r in cursor.fetchall()}
            if 'reboot_timeout' not in _cols:
                cursor.execute("ALTER TABLE update_schedules ADD COLUMN reboot_timeout INTEGER DEFAULT 600")
            for _col in ('migrate_templates', 'relax_anti_affinity'):   # #763, #954
                if _col not in _cols:
                    cursor.execute(f"ALTER TABLE update_schedules ADD COLUMN {_col} INTEGER DEFAULT 0")
        except Exception as _mig_e:
            logging.warning(f"update_schedules reboot_timeout migration skipped: {_mig_e}")

        cursor.execute('SELECT * FROM update_schedules WHERE cluster_id = ?', (cluster_id,))
        row = cursor.fetchone()
        if row:
            return _update_schedule_row(row)
    except Exception as e:
        logging.error(f"Error loading update schedule: {e}")
    return default


def _update_schedule_row(row):
    """A row of update_schedules as the routes and the scheduler read it."""
    keys = row.keys()
    return {
        'enabled': bool(row['enabled']),
        'schedule_type': row['schedule_type'] or 'recurring',
        'day': row['day'] or 'sunday',
        'time': row['time'] or '03:00',
        'include_reboot': bool(row['include_reboot']),
        'skip_evacuation': bool(row['skip_evacuation']),
        'skip_up_to_date': bool(row['skip_up_to_date']),
        'evacuation_timeout': row['evacuation_timeout'] or 1800,
        'reboot_timeout': (row['reboot_timeout'] if 'reboot_timeout' in keys else 600) or 600,
        # #763, #954 - off on a schedule saved before they existed
        'migrate_templates': bool(row['migrate_templates']) if 'migrate_templates' in keys else False,
        'relax_anti_affinity': bool(row['relax_anti_affinity']) if 'relax_anti_affinity' in keys else False,
        'last_run': row['last_run'],
        'next_run': row['next_run']
    }


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
             skip_up_to_date, evacuation_timeout, reboot_timeout, migrate_templates, relax_anti_affinity,
             last_run, next_run, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            schedule.get('reboot_timeout', 600),
            1 if schedule.get('migrate_templates') else 0,   # #763
            1 if schedule.get('relax_anti_affinity') else 0,   # #954
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
            # the scheduler asks the creator again before a run (#1093); the GET route
            # reads load_update_schedule and keeps not naming them
            schedules[row['cluster_id']] = dict(_update_schedule_row(row), created_by=row['created_by'])
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
# sec (audit): was backup.schedule — but this schedules a ROLLING NODE UPDATE (evacuate every VM,
# apt upgrade, reboot each node), not a backup. node.update is the perm the manual rolling-update
# routes already use (settings.py). A role delegated "may schedule backups" must not also be able
# to schedule a cluster-wide reboot.
@require_auth(perms=['node.update'])
def set_update_schedule(cluster_id):
    """Set the scheduled update configuration for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # sec (audit): the DELETE twin below got this gate in the sweep and the POST — the one that
    # ARMS a cluster-wide evacuate-and-reboot — did not.
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.json or {}
    usr = getattr(request, 'session', {}).get('user', 'system')

    # MK Sep 2026 - arming this with include_reboot set schedules a node reboot, and
    # node.reboot is the permission for that (see the manual route in settings.py). It
    # was enforced nowhere, so withholding it from a role changed nothing.
    if data.get('enabled', False) and data.get('include_reboot', True):
        from pegaprox.utils.rbac import has_permission as _hasp
        from pegaprox.utils.auth import build_authz_user as _bau
        if not _hasp(_bau(usr, getattr(request, 'session', {}) or {}), 'node.reboot'):
            return jsonify({'error': 'Scheduling a node reboot needs the node.reboot '
                                     'permission'}), 403

    mgr = cluster_managers[cluster_id]
    # MK Oct 2026 (#763, #954) - the two evacuation options go with the schedule, both off
    # unless asked for, and off on XCP-ng as for a run started by hand
    migrate_templates, relax_anti_affinity = evacuation_options(mgr, data)
    schedule = {
        'enabled': data.get('enabled', False),
        'schedule_type': data.get('schedule_type', 'recurring'),
        'day': data.get('day', 'sunday'),
        'time': data.get('time', '03:00'),
        'include_reboot': data.get('include_reboot', True),
        'skip_evacuation': data.get('skip_evacuation', False),
        'skip_up_to_date': data.get('skip_up_to_date', True),
        'evacuation_timeout': data.get('evacuation_timeout', 1800),
        'reboot_timeout': data.get('reboot_timeout', 600),
        'wait_for_reboot': data.get('wait_for_reboot', True),
        'migrate_templates': migrate_templates,
        'relax_anti_affinity': relax_anti_affinity,
        'last_run': None,
        'next_run': None
    }

    # Calculate next run time
    if schedule['enabled']:
        schedule['next_run'] = calculate_next_update_run(schedule['day'], schedule['time'])

    save_update_schedule(cluster_id, schedule, usr)

    # Log audit
    log_audit(usr, 'update.schedule', f"Update schedule {'enabled' if schedule['enabled'] else 'disabled'} for {mgr.config.name}"
              + (evacuation_options_said(migrate_templates, relax_anti_affinity) if schedule['enabled'] else ''),
              cluster=mgr.config.name)
    
    return jsonify({'success': True, 'schedule': schedule})


@bp.route('/api/clusters/<cluster_id>/updates/schedule', methods=['DELETE'])
@require_auth(perms=['node.update'])
def delete_update_schedule(cluster_id):
    """Delete/disable the scheduled update for a cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

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
        return jsonify({'error': safe_error(e, 'Schedule operation failed')}), 500


def calculate_next_update_run(day: str, time_str: str) -> str:
    """Calculate the next scheduled run time"""
    try:
        now = ha.schedule_now()
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
        now = ha.schedule_now()
        
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
                
                # Check if rolling update already running, or paused (one a restart interrupted
                # waits for an admin, across restarts)
                why = rolling_runs.busy(mgr, cluster_id)
                if why:
                    logging.info(f"[SCHEDULER] Scheduled update of {cluster_id} not started: {why}")
                    continue

                if not _creator_may_update(cluster_id, schedule):
                    logging.warning(f"[SCHEDULER] Not starting the scheduled update of {cluster_id}: "
                                    f"{schedule.get('created_by')!r} may no longer schedule it")
                    log_audit('scheduler', 'update.schedule_refused',
                              f"Scheduled rolling update not started: its creator "
                              f"{schedule.get('created_by')!r} may no longer schedule it",
                              cluster=getattr(mgr.config, 'name', cluster_id))
                    continue

                logging.info(f"[SCHEDULER] Starting scheduled update for cluster {cluster_id} (type: {schedule_type})")
                
                if ha.schedule_fire_first():
                    # automatic failover, at most once (5.7): written and on its way to the
                    # members before the update starts; a one-time one switches itself off
                    update_schedule_last_run(cluster_id, now.isoformat(), calculate_next_update_run(
                        day, time_str) if schedule_type == 'recurring' else None)
                    if schedule_type == 'once':
                        save_update_schedule(cluster_id, dict(schedule, enabled=False, last_run=now.isoformat()))
                    ha.schedule_fired()

                # Execute the scheduled rolling update
                action = {
                    'cluster_id': cluster_id,
                    'action': 'rolling_update',
                    'config': {
                        'include_reboot': schedule.get('include_reboot', True),
                        'skip_evacuation': schedule.get('skip_evacuation', False),
                        'skip_up_to_date': schedule.get('skip_up_to_date', True),
                        'evacuation_timeout': schedule.get('evacuation_timeout', 1800),
                        # MK #630 — forward the per-schedule reboot timeout to the runner; without this
                        # the runner falls back to 600s and the saved value never takes effect.
                        'reboot_timeout': schedule.get('reboot_timeout', 600),
                        'migrate_templates': schedule.get('migrate_templates') is True,   # #763
                        'relax_anti_affinity': schedule.get('relax_anti_affinity') is True,   # #954
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



