# -*- coding: utf-8 -*-
"""Restores of several backups in one go, run on the server one after another or a few at a time.

MK Oct 2026 - the restore dialog takes one backup. A batch takes one backup per guest from
one backup storage, the same options for all of them (into new VMIDs or over the guests
they came from, the target node and storage), and runs each through the restore that
POST /backup-restore runs: the same checks before anything starts, the same call to
Proxmox. At most `width` restores are in flight; the next starts once Proxmox reports the
task of one before it has ended.

Like a bulk migration (core/bulk_migrate.py) a batch lives in this process. A restart or a
switch to another instance ends it: what was restoring finishes in Proxmox, what had not
started stays unstarted.
"""

import logging
import threading
import time
import uuid

HOW = ('sequential', 'parallel')
MODES = ('new', 'overwrite')
PARALLEL_MAX = 4
POLL_SECONDS = 5.0
MAX_ITEMS = 100
RUNNING_PER_CLUSTER = 5
KEEP_SECONDS = 3600
KEEP_FINISHED = 50
# a task whose status cannot be read for this long is given up on
BLIND_SECONDS = 600
AUTHZ_SECONDS = 60

WAITING, RESTORING = 'wait', 'restoring'
OVER = ('done', 'failed', 'skipped', 'cancelled', 'unknown')

_runs = {}
_lock = threading.Lock()


def start_restore(mgr, volid, node, vmid, storage, overwrite):
    """Hand one restore to Proxmox (qmrestore or pct restore, by the backup): {'upid'} or
    {'error', 'status'} with what Proxmox said. Raises when Proxmox is not reached."""
    is_lxc = '/ct/' in volid or volid.endswith('.lxc.tar') or 'vzdump-lxc' in volid or 'vzdump-openvz' in volid
    # a container restore is a create from the archive: pct takes it as ostemplate with
    # restore set, it has no archive parameter (qmrestore does)
    params = {'vmid': vmid, 'ostemplate': volid, 'restore': 1} if is_lxc else {'vmid': vmid, 'archive': volid}
    if storage:
        params['storage'] = storage
    if overwrite:
        params['force'] = 1
    r = mgr._api_post(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{'lxc' if is_lxc else 'qemu'}",
                      data=params, timeout=30)
    if r.status_code == 200:
        return {'upid': r.json().get('data'), 'kind': 'lxc' if is_lxc else 'qemu'}
    try:
        err = r.json().get('errors') or r.json().get('message') or r.text
        if isinstance(err, dict):
            err = ', '.join(f'{k}: {v}' for k, v in err.items())
    except Exception:
        err = r.text or f'HTTP {r.status_code}'
    return {'error': err, 'status': r.status_code}


class BatchRun:
    def __init__(self, cluster_id, cluster_name, user, session, ip, storage, mode, node,
                 target_storage, how, parallel, rows):
        self.id = uuid.uuid4().hex[:16]
        self.cluster_id, self.cluster_name = cluster_id, cluster_name
        self.user, self.ip = user, ip
        # what build_authz_user needs to judge the caller again later (an API token keeps its role)
        self._session = {'api_token': session.get('api_token'), 'role': session.get('role')}
        self.storage, self.mode = storage, mode
        self.node, self.target_storage = node, target_storage
        self.how, self.parallel = how, parallel
        self.rows = rows
        self.state = 'running'          # running, done, cancelled, stopped
        self.reason = ''
        self.cancelled_by = ''
        self.created = time.time()
        self.finished = None
        self._authz, self._authz_at = None, 0.0

    @property
    def width(self):
        return 1 if self.how == 'sequential' else self.parallel

    def rows_copy(self):
        with _lock:
            return [{k: v for k, v in r.items() if not k.startswith('_')} for r in self.rows]

    def view(self, rows, with_rows=True, me=''):
        counts = {}
        for r in rows:
            counts[r['state']] = counts.get(r['state'], 0) + 1
        with _lock:
            out = {'id': self.id, 'cluster_id': self.cluster_id, 'cluster': self.cluster_name,
                   'user': self.user, 'mine': bool(me) and me == self.user, 'storage': self.storage,
                   'mode': self.mode, 'node': self.node, 'target_storage': self.target_storage,
                   'run': self.how, 'parallel': self.parallel if self.how == 'parallel' else None,
                   'state': self.state, 'reason': self.reason, 'cancelled_by': self.cancelled_by,
                   'created': int(self.created), 'finished': int(self.finished) if self.finished else None,
                   'total': len(rows), 'counts': counts,
                   'current': [r['vmid'] for r in rows if r['state'] == RESTORING]}
        if with_rows:
            out['rows'] = rows
        return out


def new_row(vmid, kind, volid, target_vmid, node):
    return {'vmid': int(vmid), 'type': kind, 'volid': volid, 'target_vmid': int(target_vmid), 'node': node,
            'state': WAITING, 'note': '', 'task': None, 'began': None, 'ended': None}


def _row_set(row, state, note=None, **kw):
    with _lock:
        row['state'] = state
        if note is not None:
            row['note'] = str(note)[:500]
        row.update(kw)
        if state in OVER and not row.get('ended'):
            row['ended'] = int(time.time())


# --- the registry ------------------------------------------------------------------------

def _prune_locked(now):
    done = sorted((r for r in _runs.values() if r.state != 'running'), key=lambda r: r.finished or r.created)
    for r in done[:max(0, len(done) - KEEP_FINISHED)]:
        _runs.pop(r.id, None)
    for r in done:
        if now - (r.finished or r.created) > KEEP_SECONDS:
            _runs.pop(r.id, None)


def runs():
    """Every batch this process knows, newest first"""
    with _lock:
        _prune_locked(time.time())
        return sorted(_runs.values(), key=lambda r: r.created, reverse=True)


def get(run_id):
    with _lock:
        return _runs.get(run_id) if isinstance(run_id, str) else None


def busy_targets(cluster_id):
    """The VMIDs a running batch on this cluster still restores into"""
    with _lock:
        return {r['target_vmid'] for run in _runs.values() if run.cluster_id == cluster_id
                and run.state == 'running' for r in run.rows if r['state'] in (WAITING, RESTORING)}


class TooMany(Exception):
    pass


def register(run):
    with _lock:
        _prune_locked(time.time())
        going = sum(1 for r in _runs.values() if r.cluster_id == run.cluster_id and r.state == 'running')
        if going >= RUNNING_PER_CLUSTER:
            raise TooMany(f'{going} batch restores are running on this cluster already - '
                          f'wait for one of them to finish')
        _runs[run.id] = run
    return run


def launch(run):
    # a user job: in an automatic group every call it sends asks for the lease (#625)
    from pegaprox.core import ha
    threading.Thread(target=ha.as_job(work, f'batch restore {run.id}'), args=(run,),
                     daemon=True, name=f'batch-restore-{run.id}').start()


def cancel(run, by):
    """No restore of the batch starts any more; what is restoring finishes. False when it is over."""
    with _lock:
        if run.state != 'running' or run.cancelled_by:
            return False
        run.cancelled_by = by or '?'
        return True


# --- the worker ----------------------------------------------------------------------------

def _may(run, row):
    """Whoever started the batch may still restore this one: the source backup, and the guest
    it overwrites or the VMID range it creates in. Asked again at most once a minute."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm, acts_as_admin, check_tenant_vmid, DEFAULT_TENANT_ID
    now = time.time()
    if run._authz is None or now - run._authz_at > AUTHZ_SECONDS:
        u = build_authz_user(run.user, run._session)
        run._authz = u if u.get('role') and u.get('enabled', True) is not False else {}
        run._authz_at = now
    u = run._authz
    if not u:
        return 'Permission denied: the account that started it is gone or disabled'
    if not acts_as_admin(u) and not user_can_access_vm(u, run.cluster_id, row['vmid'], 'vm.backup', row['type']):
        return 'Permission denied for source backup'
    if run.mode == 'overwrite':
        if not user_can_access_vm(u, run.cluster_id, row['target_vmid'], 'vm.backup', row['type']):
            return 'Permission denied for target VM'
    elif not acts_as_admin(u):
        ok, msg = check_tenant_vmid(u.get('tenant_id') or DEFAULT_TENANT_ID, row['target_vmid'])
        if not ok:
            return msg
    return ''


def _begin(run, mgr, row):
    """Start one restore. True when it is in flight and to be followed."""
    from pegaprox.api.helpers import register_task_user
    from pegaprox.utils.audit import log_audit
    denied = _may(run, row)
    if denied:
        _row_set(row, 'skipped', denied)
        return False
    _row_set(row, RESTORING, '', began=int(time.time()))
    try:
        got = start_restore(mgr, row['volid'], row['node'], row['target_vmid'], run.target_storage,
                            run.mode == 'overwrite')
    except Exception as e:
        logging.error(f"[BATCH-RESTORE] {run.id}: starting {row['volid']} failed: {e}")
        got = {'error': 'The restore could not be started'}
    if 'upid' not in got:
        _row_set(row, 'failed', got.get('error') or 'The restore could not be started')
        return False
    upid = got['upid'] if isinstance(got['upid'], str) and got['upid'].startswith('UPID:') else None
    try:
        log_audit(run.user, 'backup.restored',
                  f"Restoring {row['volid']} -> {got.get('kind')}/{row['target_vmid']} on {row['node']} "
                  f"(mode={run.mode}, batch {run.id})", ip_address=run.ip, cluster=run.cluster_name)
    except Exception as e:
        logging.error(f"[BATCH-RESTORE] audit of {row['volid']} failed: {e}")
    if not upid:
        _row_set(row, 'unknown', 'Proxmox gave no task to follow')
        return False
    register_task_user(upid, run.user, run.cluster_id)
    with _lock:
        row.update(task=upid, _seen=time.time())
    return True


def _follow(run, mgr, row):
    """Look at one restore in flight. True when it is over."""
    from pegaprox.core.bulk_migrate import task_state
    try:
        st = task_state(mgr, row.get('task') or '')
    except Exception as e:
        logging.debug(f"[BATCH-RESTORE] task status of {row['target_vmid']} unreadable: {e}")
        st = None
    now = time.time()
    if st is None:
        if now - row.get('_seen', now) < BLIND_SECONDS:
            return False
        _row_set(row, 'unknown', 'The task status could not be read for 10 minutes - see the task list')
        return True
    with _lock:
        row['_seen'] = now
    state, detail = st
    if state == 'running':
        return False
    if state == 'ok':
        _row_set(row, 'done', detail if detail != 'OK' else '')
    else:
        _row_set(row, 'failed', detail)
    return True


def _claim(run):
    """The next restore to start, taken under the lock cancel() takes: once a cancel has
    answered, none is claimed any more"""
    with _lock:
        if run.cancelled_by:
            return None
        row = next((r for r in run.rows if r['state'] == WAITING), None)
        if row is not None:
            row['state'] = RESTORING
        return row


def _end_waiting(run, state, note):
    with _lock:
        rows = [r for r in run.rows if r['state'] == WAITING]
    for r in rows:
        _row_set(r, state, note)


def _let_go(run):
    with _lock:
        rows = [r for r in run.rows if r['state'] == RESTORING]
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
                _end_waiting(run, 'cancelled', 'Not started: the batch was stopped')
                _let_go(run)
                return
            mgr = cluster_managers.get(run.cluster_id)
            with _lock:
                cancelled_by = run.cancelled_by
            if cancelled_by:
                _end_waiting(run, 'cancelled', f'Not started: cancelled by {cancelled_by}')
            else:
                while len(flying) < run.width:
                    row = _claim(run)
                    if row is None:
                        break
                    if _begin(run, mgr, row):
                        flying.append(row)
                    if not ha.is_active():
                        break
            with _lock:
                waiting = any(r['state'] == WAITING for r in run.rows)
            if not flying and not waiting:
                return
            time.sleep(POLL_SECONDS)
            mgr = cluster_managers.get(run.cluster_id)
            if not flying or mgr is None:
                continue
            ended = [r for r in flying if _follow(run, mgr, r)]
            if ended:
                flying = [r for r in flying if r not in ended]
    except Exception as e:
        logging.error(f"[BATCH-RESTORE] batch {run.id} broke off: {e}", exc_info=True)
        with _lock:
            run.state, run.reason = 'stopped', 'The batch broke off - see the PegaProx log'
        _end_waiting(run, 'cancelled', 'Not started: the batch broke off')
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
            r.pop('_seen', None)
        rows = [dict(r) for r in run.rows]
    by = {}
    for r in rows:
        by.setdefault(r['state'], []).append(str(r['vmid']))
    parts = []
    for state in OVER:
        ids = by.get(state)
        if ids:
            parts.append(f"{state} {len(ids)}" + (f" ({', '.join(ids[:20])}{' ...' if len(ids) > 20 else ''})"
                                                 if state in ('failed', 'skipped', 'unknown') else ''))
    try:
        log_audit(run.user, 'backup.batch_restore_finished',
                  f"Batch restore {run.id} from {run.storage} {run.state}: " + (', '.join(parts) or 'nothing')
                  + (f" - {run.reason}" if run.reason else ''), ip_address=run.ip, cluster=run.cluster_name)
    except Exception as e:
        logging.error(f"[BATCH-RESTORE] audit of batch {run.id} failed: {e}")


def reset_for_tests():
    with _lock:
        _runs.clear()
