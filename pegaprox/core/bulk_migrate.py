# -*- coding: utf-8 -*-
"""Bulk migrations that run on the server, one guest after another or a few at a time.

MK Oct 2026 (#952) - the bulk migrate route started every migration it was handed at
once and answered when Proxmox had taken them all, so twenty guests were twenty
migrations sharing one migration network and the same storage. A run here keeps at most
`width` of its migrations in flight and starts the next guest once Proxmox reports that
the task of one before it has ended. Mode 'all' is the old way: every migration starts
right away and nobody waits for them.

A run lives in this process. A restart or a switch to another instance ends it: what was
migrating finishes in Proxmox, the guests it had not started yet stay where they are.
"""

import logging
import re
import threading
import time
import uuid

from pegaprox.constants import HA_MIGRATE_SETTLE_SECONDS

MODES = ('sequential', 'parallel', 'all')
PARALLEL_MAX = 5
# one status read per guest in flight and round, so a run costs at most PARALLEL_MAX
# reads every POLL_SECONDS whatever its size
POLL_SECONDS = 5.0
RUNNING_PER_CLUSTER = 10
KEEP_SECONDS = 3600
KEEP_FINISHED = 50
# a task whose status cannot be read for this long is given up on
BLIND_SECONDS = 600
# an HA guest: how long the CRM may take to pick up the request before it counts as refused
LAND_SECONDS = HA_MIGRATE_SETTLE_SECONDS
AUTHZ_SECONDS = 60

WAITING, MOVING = 'wait', 'migrating'
OVER = ('done', 'started', 'failed', 'skipped', 'cancelled', 'unknown')

# UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:
_UPID_RE = re.compile(r'UPID:(?P<node>[A-Za-z0-9][A-Za-z0-9.-]{0,62}):[0-9A-Fa-f]{1,16}:[0-9A-Fa-f]{1,16}:'
                      r'[0-9A-Fa-f]{1,16}:(?P<type>[A-Za-z0-9_-]{1,32}):[^:/\s]{0,64}:[^:/\s]{1,128}:')
_HA_MOVING = ('migrate', 'relocate')
_HA_BROKEN = ('error', 'fence')

_runs = {}
_lock = threading.Lock()


class BulkRun:
    def __init__(self, cluster_id, cluster_name, user, session, ip, target, mode, parallel,
                 online, with_local_disks, rows):
        self.id = uuid.uuid4().hex[:16]
        self.cluster_id, self.cluster_name = cluster_id, cluster_name
        self.user, self.ip = user, ip
        # what build_authz_user needs to judge the caller again later: an API token keeps
        # its own role, not the one of its owner
        self._session = {'api_token': session.get('api_token'), 'role': session.get('role')}
        self.target, self.mode, self.parallel = target, mode, parallel
        self.online, self.with_local_disks = online, with_local_disks
        self.rows = rows
        self.state = 'running'          # running, done, cancelled, stopped
        self.reason = ''
        self.cancelled_by = ''
        self.created = time.time()
        self.finished = None
        self._authz, self._authz_at = None, 0.0

    @property
    def width(self):
        if self.mode == 'sequential':
            return 1
        return self.parallel if self.mode == 'parallel' else max(1, len(self.rows))

    def rows_copy(self):
        with _lock:
            return [{k: v for k, v in r.items() if not k.startswith('_')} for r in self.rows]

    def view(self, rows, with_rows=True, me=''):
        """What a caller sees of the run: `rows` are the guests they may see"""
        counts = {}
        for r in rows:
            counts[r['state']] = counts.get(r['state'], 0) + 1
        with _lock:
            out = {'id': self.id, 'cluster_id': self.cluster_id, 'cluster': self.cluster_name,
                   'user': self.user, 'mine': bool(me) and me == self.user, 'target': self.target,
                   'mode': self.mode, 'parallel': self.parallel if self.mode == 'parallel' else None,
                   'online': self.online, 'with_local_disks': self.with_local_disks,
                   'state': self.state, 'reason': self.reason, 'cancelled_by': self.cancelled_by,
                   'created': int(self.created), 'finished': int(self.finished) if self.finished else None,
                   'total': len(rows), 'counts': counts,
                   'current': [r['vmid'] for r in rows if r['state'] == MOVING]}
        if with_rows:
            out['rows'] = rows
        return out


def _row_set(row, state, note=None, **kw):
    with _lock:
        row['state'] = state
        if note is not None:
            row['note'] = str(note)[:500]
        row.update(kw)
        if state in OVER and not row.get('ended'):
            row['ended'] = int(time.time())


def new_row(guest, state=WAITING, note=''):
    return {'vmid': int(guest.get('vmid')), 'name': guest.get('name') or '', 'node': guest.get('node') or '',
            'type': guest.get('type') or 'qemu', 'state': state, 'note': note, 'task': None,
            'to': None, 'began': None, 'ended': None}


# --- the registry ------------------------------------------------------------------------

def _prune_locked(now):
    done = sorted((r for r in _runs.values() if r.state != 'running'), key=lambda r: r.finished or r.created)
    for r in done[:max(0, len(done) - KEEP_FINISHED)]:
        _runs.pop(r.id, None)
    for r in done:
        if now - (r.finished or r.created) > KEEP_SECONDS:
            _runs.pop(r.id, None)


def runs():
    """Every run this process knows, newest first"""
    with _lock:
        _prune_locked(time.time())
        return sorted(_runs.values(), key=lambda r: r.created, reverse=True)


def get(run_id):
    with _lock:
        return _runs.get(run_id) if isinstance(run_id, str) else None


def busy_vmids(cluster_id):
    """The guests a running run on this cluster still has to move or is moving"""
    with _lock:
        return {r['vmid'] for run in _runs.values() if run.cluster_id == cluster_id and run.state == 'running'
                for r in run.rows if r['state'] in (WAITING, MOVING)}


class TooMany(Exception):
    pass


def register(run):
    """Take the run in. TooMany when the cluster has enough of them going."""
    with _lock:
        _prune_locked(time.time())
        going = sum(1 for r in _runs.values() if r.cluster_id == run.cluster_id and r.state == 'running')
        if going >= RUNNING_PER_CLUSTER:
            raise TooMany(f'{going} bulk migrations are running on this cluster already - '
                          f'wait for one of them to finish')
        _runs[run.id] = run
    return run


def launch(run):
    # a user job: in an automatic group every call it sends asks for the lease (#625)
    from pegaprox.core import ha
    threading.Thread(target=ha.as_job(work, f'bulk migration {run.id}'), args=(run,),
                     daemon=True, name=f'bulk-migrate-{run.id}').start()


def cancel(run, by):
    """No guest of the run starts any more; what is migrating finishes. False when it is over."""
    with _lock:
        if run.state != 'running' or run.cancelled_by:
            return False
        run.cancelled_by = by or '?'
        return True


# --- the worker ----------------------------------------------------------------------------

def task_state(mgr, upid):
    """('running'|'ok'|'failed', detail) of a migration task, None when it cannot be read"""
    if getattr(mgr, 'cluster_type', 'proxmox') == 'xcpng':
        # PegaProx follows its XAPI tasks itself (core/xcpng.py _active_tasks)
        for t in mgr.get_tasks(limit=500) or []:
            if t.get('upid') == upid:
                st = t.get('status')
                if st == 'running':
                    return 'running', ''
                return ('ok', '') if st == 'completed' else ('failed', str(st or 'failed'))
        return None
    m = _UPID_RE.fullmatch(upid or '')
    if not m:
        return None
    data = mgr.get_task_status(m.group('node'), upid)
    if not isinstance(data, dict) or not data.get('status'):
        return None
    if data.get('status') == 'running':
        return 'running', ''
    # "OK", "WARNINGS: 2" (done, with something worth a look in the log) or the error itself
    ex = str(data.get('exitstatus') or '')
    if ex == 'OK' or ex.startswith('WARNINGS'):
        return 'ok', ex
    return 'failed', ex or 'failed'


class _Guests:
    """Where the guests of the cluster are, read once per round and only when asked: the
    cached /cluster/resources the live view refreshes anyway"""

    def __init__(self, mgr):
        self.mgr, self._by = mgr, None

    def _load(self):
        if self._by is None:
            self._by = {}
            try:
                for g in self.mgr.get_vm_resources(max_age=POLL_SECONDS) or []:
                    if g.get('type') in ('qemu', 'lxc'):
                        try:
                            self._by[int(g.get('vmid'))] = g
                        except (TypeError, ValueError):
                            continue
            except Exception as e:
                logging.debug(f"[BULK-MIGRATE] guest list unreadable: {e}")
        return self._by

    def get(self, vmid):
        return self._load().get(vmid)

    def known(self):
        return bool(self._load())


def _may(run, row):
    """Whoever started the run may still move this guest: a run of hours outlives a role
    change. Asked again at most once a minute."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    now = time.time()
    if run._authz is None or now - run._authz_at > AUTHZ_SECONDS:
        u = build_authz_user(run.user, run._session)
        # an account that is gone or switched off moves nothing any more
        run._authz = u if u.get('role') and u.get('enabled', True) is not False else {}
        run._authz_at = now
    return bool(run._authz) and user_can_access_vm(run._authz, run.cluster_id, row['vmid'],
                                                   'vm.migrate', row['type'])


def _begin(run, mgr, row, where):
    """Start the migration of one guest. True when it is in flight and to be followed."""
    from pegaprox.api.helpers import register_task_user, parse_pve_error
    now = where.get(row['vmid'])
    if now is None and where.known():
        _row_set(row, 'failed', 'No longer on this cluster')
        return False
    if now is not None:
        if now.get('node') == run.target:
            _row_set(row, 'done', f'Already on {run.target}', to=run.target)
            return False
        # moved since the run began (HA, the balancer, someone else): from where it is now
        with _lock:
            row['node'] = now.get('node') or row['node']
            row['type'] = now.get('type') or row['type']
    if not _may(run, row):
        _row_set(row, 'skipped', 'Permission denied: vm.migrate')
        return False
    options = {'with_local_disks': True} if run.with_local_disks and row['type'] == 'qemu' else {}
    _row_set(row, MOVING, '', began=int(time.time()))
    try:
        result = mgr.migrate_vm_manual(row['node'], row['vmid'], row['type'], run.target, run.online, options)
    except Exception as e:
        logging.error(f"[BULK-MIGRATE] {run.id}: starting {row['vmid']} failed: {e}")
        result = {'success': False, 'error': 'Migration could not be started'}
    if not isinstance(result, dict) or not result.get('success'):
        err = result.get('error') if isinstance(result, dict) else None
        _row_set(row, 'failed', parse_pve_error(err, 'Migration could not be started') if err else
                 'Migration could not be started')
        return False
    task = result.get('task') or result.get('upid')
    task = task if isinstance(task, str) else None
    if task:
        register_task_user(task, run.user, run.cluster_id)
    if run.mode == 'all':
        _row_set(row, 'started', task=task)
        return False
    if not task:
        # nothing to follow: the next one would start at once, so say how it went
        _row_set(row, 'unknown', 'Proxmox gave no task to follow', task=None)
        return False
    with _lock:
        row.update(task=task, _seen=time.time(), _ok_at=None)
    return True


def _follow(run, mgr, row, where):
    """Look at one migration in flight. True when it is over."""
    upid = row.get('task') or ''
    m = _UPID_RE.fullmatch(upid)
    ha_request = bool(m and m.group('type') == 'hamigrate')
    if row.get('_ok_at') is None:
        try:
            st = task_state(mgr, upid)
        except Exception as e:
            logging.debug(f"[BULK-MIGRATE] task status of {row['vmid']} unreadable: {e}")
            st = None
        now = time.time()
        if st is None:
            if now - row.get('_seen', now) < BLIND_SECONDS:
                return False
            # the status went away (a node down, a purged XAPI task): where is the guest?
            g = where.get(row['vmid'])
            if g is not None and g.get('node') not in (None, row['node']):
                _row_set(row, 'done', '', to=g.get('node'))
            else:
                _row_set(row, 'unknown', 'The task status could not be read for 10 minutes - see the task list')
            return True
        with _lock:
            row['_seen'] = now
        state, detail = st
        if state == 'running':
            return False
        if not ha_request:
            if state == 'ok':
                _row_set(row, 'done', detail if detail != 'OK' else '', to=run.target)
            else:
                _row_set(row, 'failed', detail)
            return True
        # a guest under Proxmox HA: the task only handed the request to the CRM, which
        # moves the guest afterwards. It may even fail and the guest moves anyway (#647)
        with _lock:
            row['_ok_at'], row['_ha_detail'] = now, ('' if state == 'ok' else detail)
    g = where.get(row['vmid'])
    if g is not None and g.get('node') not in (None, row['node']):
        _row_set(row, 'done', '' if g.get('node') == run.target else f"Proxmox HA placed it on {g.get('node')}",
                 to=g.get('node'))
        return True
    hastate = str((g or {}).get('hastate') or '')
    if hastate in _HA_BROKEN:
        _row_set(row, 'failed', f'Proxmox HA reports {hastate}')
        return True
    if hastate in _HA_MOVING or 'migrate' in str((g or {}).get('lock') or ''):
        with _lock:
            row['_ok_at'] = time.time()
        return False
    if time.time() - row['_ok_at'] > LAND_SECONDS:
        _row_set(row, 'failed', row.get('_ha_detail') or 'Proxmox HA did not move it')
        return True
    return False


def _next_waiting(run):
    with _lock:
        return next((r for r in run.rows if r['state'] == WAITING), None)


def _claim(run):
    """The next guest to start, taken out of the waiting ones under the lock cancel() takes:
    once a cancel has answered, no guest is claimed any more"""
    with _lock:
        if run.cancelled_by:
            return None
        row = next((r for r in run.rows if r['state'] == WAITING), None)
        if row is not None:
            row['state'] = MOVING
        return row


def _end_waiting(run, state, note):
    with _lock:
        rows = [r for r in run.rows if r['state'] == WAITING]
    for r in rows:
        _row_set(r, state, note)


def _let_go(run):
    # what is in flight, or was claimed and not yet started, is no longer followed
    with _lock:
        rows = [r for r in run.rows if r['state'] == MOVING]
    for r in rows:
        _row_set(r, 'unknown', 'No longer followed - see the task list')


def work(run):
    from pegaprox.core import ha
    from pegaprox.globals import cluster_managers
    flying = []
    try:
        while True:
            stop = ''
            if not ha.is_active():
                stop = 'This instance no longer acts on the clusters (it is a standby now)'
            elif cluster_managers.get(run.cluster_id) is None:
                stop = 'The cluster is gone from PegaProx'
            if stop:
                with _lock:
                    run.state, run.reason = 'stopped', stop
                _end_waiting(run, 'cancelled', 'Not started: the run was stopped')
                _let_go(run)
                return
            mgr = cluster_managers.get(run.cluster_id)
            with _lock:
                cancelled_by = run.cancelled_by
            if cancelled_by:
                _end_waiting(run, 'cancelled', f'Not started: cancelled by {cancelled_by}')
            else:
                where, began = _Guests(mgr), False
                while len(flying) < run.width:
                    row = _claim(run)
                    if row is None:
                        break
                    began = True
                    if _begin(run, mgr, row, where):
                        flying.append(row)
                    if not ha.is_active():
                        break
                if began:
                    from pegaprox.utils.realtime import push_immediate_update
                    push_immediate_update(run.cluster_id, delay=1.0)
            if not flying and _next_waiting(run) is None:
                return
            time.sleep(POLL_SECONDS)
            if not flying:
                continue
            mgr = cluster_managers.get(run.cluster_id)
            if mgr is None:
                continue
            where = _Guests(mgr)
            ended = [r for r in flying if _follow(run, mgr, r, where)]
            if ended:
                flying = [r for r in flying if r not in ended]
                from pegaprox.utils.realtime import push_immediate_update
                push_immediate_update(run.cluster_id, delay=0.5)
    except Exception as e:
        logging.error(f"[BULK-MIGRATE] run {run.id} broke off: {e}", exc_info=True)
        with _lock:
            run.state, run.reason = 'stopped', 'The run broke off - see the PegaProx log'
        _end_waiting(run, 'cancelled', 'Not started: the run broke off')
        _let_go(run)
    finally:
        _finish(run)


def _finish(run):
    from pegaprox.utils.audit import log_audit
    with _lock:
        if run.state == 'running':
            run.state = 'cancelled' if run.cancelled_by else 'done'
        run.finished = time.time()
        for r in run.rows:
            for k in ('_seen', '_ok_at', '_ha_detail'):
                r.pop(k, None)
        rows = [dict(r) for r in run.rows]
    by = {}
    for r in rows:
        by.setdefault(r['state'], []).append(str(r['vmid']))
    parts = []
    for state in ('done', 'started', 'failed', 'skipped', 'cancelled', 'unknown'):
        ids = by.get(state)
        if ids:
            parts.append(f"{state} {len(ids)}" + (f" ({', '.join(ids[:20])}{' ...' if len(ids) > 20 else ''})"
                                                 if state in ('failed', 'unknown') else ''))
    try:
        log_audit(run.user, 'vm.bulk_migrate_finished',
                  f"Bulk migration {run.id} to {run.target} {run.state}: " + (', '.join(parts) or 'nothing')
                  + (f" - {run.reason}" if run.reason else ''), ip_address=run.ip, cluster=run.cluster_name)
    except Exception as e:
        logging.error(f"[BULK-MIGRATE] audit of run {run.id} failed: {e}")


def reset_for_tests():
    with _lock:
        _runs.clear()
