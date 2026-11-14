# -*- coding: utf-8 -*-
"""ESXi bulk migrations: guests of one ESXi server moved to Proxmox, a few at a time.

MK Oct 2026 - the wizard moves one guest per run. A bulk run takes up to ITEMS_MAX guests
of one ESXi server with one set of target settings (plus NIC and disk choices per guest),
every guest checked like a dry run of the single migrate route before anything starts,
and starts at most `width` of them at a time on the server. Each started guest is a
normal ESXi migration (GET /api/vmware/migrations); the run only says which guest became
which migration and how it ended.

Before each guest starts, the run asks again whether whoever started it may still migrate
it (an account removed or switched off, an API token revoked, a VM ACL taken away), whether
the guest is being migrated already, and whether its plan still fits the target node.

Two migrations of a run never plan at once: the next one starts when the one before it
has its VM on the target (Proxmox hands out a VMID with /cluster/nextid, and two jobs
asking at the same moment get the same one), or after SETTLE_SECONDS.

A run lives in this process, like core/bulk_migrate.py. A restart or a switch to another
instance ends it: the migrations it started belong to this process as any migration does,
the guests it had not started stay on ESXi.

The ESXi password of a run is kept on the run object only, never in its view, a log line
or the audit log. Each started migration takes its own copy (the task drops that at its
end), and the run drops its own as soon as no guest is left to start: the last one
started, a cancel, the run stopped or over.

Cancel starts no further guest. A migration that already started runs on to its end (or
to its switchover gate, where it can be cancelled): stopping a copy half way leaves more
to clean up than it saves.

One guest is migrated by one job at a time. A guest is held from the moment a start of it
is decided until that job is over: by its run from the submit until its turn
('bulk:<run id>'), then by its migration until that returns ('task:<migration id>'). The
single migrate route (pegaprox/api/vmware.py) holds a guest the same way. Asking and taking happen
under one lock, so two submits, or a submit and the single route, never both get it.
"""

import logging
import threading
import time
import uuid

WIDTH_MAX = 5
ITEMS_MAX = 200
RUNNING_PER_SERVER = 3
RUNNING_PER_USER = 3
POLL_SECONDS = 5.0
SETTLE_SECONDS = 900
# a migration takes hours: what ended over night is still there in the morning
KEEP_SECONDS = 12 * 3600
KEEP_FINISHED = 50

WAITING, STARTING, MIGRATING = 'wait', 'starting', 'migrating'
OVER = ('done', 'failed', 'skipped', 'cancelled', 'unknown')
# what a view shows of the common settings
SHOWN_SETTINGS = ('target_cluster', 'target_node', 'target_storage', 'network_bridge', 'net_vlan_tag',
                  'transfer_mode', 'verify', 'start_after', 'remove_source', 'wait_for_confirmation',
                  'preserve_mac', 'esxi_user')

_runs = {}
_lock = threading.Lock()
# (vmware_id, vm_id) -> who has the guest now: 'bulk:<run id>' or 'task:<migration id>'
_held = {}


class EsxiBulkRun:
    def __init__(self, vmware_id, vmware_name, user, session, ip, settings, width, items, password):
        self.id = uuid.uuid4().hex[:16]
        self.vmware_id, self.vmware_name = vmware_id, vmware_name
        self.user, self.ip = user, ip
        # what build_authz_user needs to judge the caller again before each guest: an API
        # token acts with its own role, and is asked whether it still stands
        session = session or {}
        self._session = {'api_token': bool(session.get('api_token')), 'role': session.get('role'),
                         'token_id': session.get('token_id')}
        self.settings = {k: v for k, v in (settings or {}).items() if k != 'esxi_password'}
        self.width = width
        self.items = items
        self._password = password or None
        self.state = 'running'          # running, done, cancelled, stopped
        self.reason = ''
        self.cancelled_by = ''
        self.created = time.time()
        self.finished = None

    def __repr__(self):
        return f'<EsxiBulkRun {self.id} {self.state}>'

    @property
    def holder(self):
        return f'bulk:{self.id}'

    def password(self):
        """The ESXi password for the start of one guest, None once the run dropped it."""
        with _lock:
            return self._password

    def items_copy(self):
        with _lock:
            return [{k: v for k, v in it.items() if not k.startswith('_')} for it in self.items]

    def view(self, items, with_items=True, me=''):
        """What a caller sees of the run: `items` are the guests they may see"""
        counts = {}
        for it in items:
            counts[it['state']] = counts.get(it['state'], 0) + 1
        with _lock:
            out = {'id': self.id, 'vmware_id': self.vmware_id, 'vmware_name': self.vmware_name,
                   'user': self.user, 'mine': bool(me) and me == self.user,
                   'settings': {k: self.settings[k] for k in SHOWN_SETTINGS if k in self.settings},
                   'width': self.width, 'state': self.state, 'reason': self.reason,
                   'cancelled_by': self.cancelled_by, 'holds_password': bool(self._password),
                   'created': int(self.created), 'finished': int(self.finished) if self.finished else None,
                   'total': len(items), 'counts': counts,
                   'current': [it['vm_id'] for it in items if it['state'] in (STARTING, MIGRATING)]}
        if with_items:
            out['items'] = items
        return out


def new_item(vm_id, name='', maps=None):
    """A guest of a run. maps: its own nic_map / disk_map, as the submit checked them."""
    maps = {k: v for k, v in (maps or {}).items() if k in ('nic_map', 'disk_map') and v is not None}
    return {'vm_id': str(vm_id), 'name': str(name or '')[:200], 'state': WAITING, 'note': '',
            'migration_id': None, 'proxmox_vmid': None, 'phase': None, 'progress': 0,
            'began': None, 'ended': None,
            'custom_network': 'nic_map' in maps, 'custom_storage': 'disk_map' in maps,
            '_maps': maps}


def _item_set(item, state, note=None, **kw):
    with _lock:
        item['state'] = state
        if note is not None:
            item['note'] = str(note)[:500]
        item.update(kw)
        if state in OVER and not item.get('ended'):
            item['ended'] = int(time.time())


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


def busy_vm_ids(vmware_id):
    """The guests of this ESXi server a running run still has to start or is migrating"""
    with _lock:
        return {it['vm_id'] for run in _runs.values() if run.vmware_id == vmware_id and run.state == 'running'
                for it in run.items if it['state'] in (WAITING, STARTING, MIGRATING)}


# --- guests in flight ----------------------------------------------------------------------

def task_holder(migration_id):
    return f'task:{migration_id}'


def holder(vmware_id, vm_id):
    """Who has this guest now ('bulk:<run id>', 'task:<migration id>'), None when nobody"""
    with _lock:
        return _held.get((str(vmware_id), str(vm_id)))


def hold(vmware_id, vm_id, by):
    """Take the guest for `by`. None when it is `by`'s now, else who has it."""
    key = (str(vmware_id), str(vm_id))
    with _lock:
        have = _held.get(key)
        if have is not None and have != by:
            return have
        _held[key] = by
        return None


def pass_on(vmware_id, vm_id, old, new):
    """Hand a guest `old` has (or nobody has) to `new`. False when somebody else has it."""
    key = (str(vmware_id), str(vm_id))
    with _lock:
        if _held.get(key) not in (None, old):
            return False
        _held[key] = new
        return True


def let_go(vmware_id, vm_id, by):
    """The guest is free again, if `by` is who has it"""
    key = (str(vmware_id), str(vm_id))
    with _lock:
        if _held.get(key) == by:
            del _held[key]


def _let_go_all(run):
    with _lock:
        for key in [k for k, v in _held.items() if v == run.holder]:
            del _held[key]


class TooMany(Exception):
    pass


class Taken(Exception):
    """A guest of a run being registered is with another run or migration already"""

    def __init__(self, vm_ids):
        self.vm_ids = list(vm_ids)
        names = ', '.join(self.vm_ids[:10]) + (' ...' if len(self.vm_ids) > 10 else '')
        super().__init__(f'Another migration has {names} already - leave it out or wait for it to finish')


def _room_locked(vmware_id, user):
    going = [r for r in _runs.values() if r.state == 'running']
    if sum(1 for r in going if r.vmware_id == vmware_id) >= RUNNING_PER_SERVER:
        return (f'{RUNNING_PER_SERVER} bulk migrations are running from this ESXi server already - '
                f'wait for one of them to finish')
    if sum(1 for r in going if r.user == user) >= RUNNING_PER_USER:
        return f'You have {RUNNING_PER_USER} bulk migrations running already - wait for one of them to finish'
    return None


def room(vmware_id, user):
    """Why another run of `user` from this server cannot start now, None when it can"""
    with _lock:
        _prune_locked(time.time())
        return _room_locked(vmware_id, user)


def register(run):
    """Take the run in, and its guests with it. TooMany when the server or the user has
    enough of them going, Taken when a guest of it is with another run or migration: then
    nothing of it was taken."""
    with _lock:
        _prune_locked(time.time())
        why = _room_locked(run.vmware_id, run.user)
        if why:
            raise TooMany(why)
        keys = [(str(run.vmware_id), str(it['vm_id'])) for it in run.items]
        taken = [vm for (_s, vm) in keys if _held.get((_s, vm)) not in (None, run.holder)]
        if taken:
            raise Taken(taken)
        for key in keys:
            _held[key] = run.holder
        _runs[run.id] = run
    return run


def launch(run, starter, lookup):
    """starter(run, item) starts one guest: {'migration_id', 'name'}, or {'state', 'note'}
    when it did not start. lookup(migration_id) is the migration task or None."""
    # a user job: in an automatic group every call it sends asks for the lease
    from pegaprox.core import ha
    threading.Thread(target=ha.as_job(work, f'ESXi bulk migration {run.id}'), args=(run, starter, lookup),
                     daemon=True, name=f'esxi-bulk-{run.id}').start()


def abandon(run, reason):
    """A registered run whose worker never started: it is over before it began. Without
    this it stayed 'running' with the password on it, held a slot of its user and its
    server and kept its guests busy until a restart."""
    with _lock:
        if run.state == 'running':
            run.state, run.reason = 'stopped', reason
    _end_waiting(run, 'cancelled', 'Not started: the run could not be started')
    _finish(run)


def caller(run):
    """Whoever started the run as the account stands now, None when it may no longer act:
    removed, switched off, or an API token revoked or expired (None from the token table
    is no answer, so no start either)."""
    from pegaprox.utils.auth import build_authz_user, api_token_alive
    if run._session.get('api_token') and api_token_alive(run._session.get('token_id')) is not True:
        return None
    u = build_authz_user(run.user, run._session)
    if not u.get('role') or u.get('enabled', True) is False:
        return None
    return u


def _drop_password_when_done(run):
    # nothing is left to start: the password is not needed any more
    with _lock:
        if run.cancelled_by or run.state != 'running' or \
                not any(it['state'] in (WAITING, STARTING) for it in run.items):
            run._password = None


def cancel(run, by):
    """No guest of the run starts any more; what is migrating goes on. False when it is over."""
    with _lock:
        if run.state != 'running' or run.cancelled_by:
            return False
        run.cancelled_by = by or '?'
        # nothing claims a waiting guest after this, so it is free for another job right away
        for it in run.items:
            key = (str(run.vmware_id), str(it['vm_id']))
            if it['state'] == WAITING and _held.get(key) == run.holder:
                del _held[key]
    _drop_password_when_done(run)
    return True


# --- the worker ----------------------------------------------------------------------------

def _claim(run):
    """The next guest to start, taken out of the waiting ones under the lock cancel() takes:
    once a cancel has answered, no guest is claimed any more"""
    with _lock:
        if run.cancelled_by:
            return None
        item = next((it for it in run.items if it['state'] == WAITING), None)
        if item is not None:
            item['state'] = STARTING
            item['began'] = int(time.time())
        return item


def _next_waiting(run):
    with _lock:
        return next((it for it in run.items if it['state'] == WAITING), None)


def _end_waiting(run, state, note):
    with _lock:
        items = [it for it in run.items if it['state'] == WAITING]
    for it in items:
        _item_set(it, state, note)
        let_go(run.vmware_id, it['vm_id'], run.holder)


def _let_go(run):
    # what is in flight is a migration of its own and goes on; the run no longer follows it
    with _lock:
        items = [it for it in run.items if it['state'] in (STARTING, MIGRATING)]
    for it in items:
        _item_set(it, 'unknown', 'No longer followed - see the ESXi migrations')
        # a migration it started has the guest itself; a start that never got that far
        let_go(run.vmware_id, it['vm_id'], run.holder)


def _settling(flying, lookup):
    """True while a migration this run started has no VM on the target yet"""
    now = time.time()
    for it in flying:
        try:
            t = lookup(it.get('migration_id'))
        except Exception:
            t = None
        if t is None or str(getattr(t, 'status', '')) != 'running':
            continue
        if str(getattr(t, 'phase', '')) == 'planning' and now - (it.get('began') or now) < SETTLE_SECONDS:
            return True
    return False


def _begin(run, item, starter):
    """Start one guest. True when its migration runs and is to be followed."""
    try:
        res = starter(run, item) or {}
    except Exception as e:
        logging.error(f"[ESXI-BULK] {run.id}: starting {item['vm_id']} failed: {e}", exc_info=True)
        res = {'state': 'failed', 'note': 'The migration could not be started - see the PegaProx log'}
    mid = res.get('migration_id')
    if not mid:
        state = res.get('state') if res.get('state') in ('failed', 'skipped', 'cancelled') else 'failed'
        _item_set(item, state, res.get('note') or 'The migration could not be started')
        let_go(run.vmware_id, item['vm_id'], run.holder)
        return False
    _item_set(item, MIGRATING, '', migration_id=str(mid), name=str(res.get('name') or item['name'])[:200],
              phase='planning')
    return True


def _follow(run, item, lookup):
    """Look at one migration in flight. True when it is over."""
    try:
        t = lookup(item.get('migration_id'))
    except Exception as e:
        logging.debug(f"[ESXI-BULK] {run.id}: migration {item.get('migration_id')} unreadable: {e}")
        return False
    if t is None:
        _item_set(item, 'unknown', 'The migration is no longer known to PegaProx - see the ESXi migrations')
        let_go(run.vmware_id, item['vm_id'], run.holder)
        return True
    status = str(getattr(t, 'status', '') or '')
    try:
        progress = int(getattr(t, 'progress', 0) or 0)
    except (TypeError, ValueError):
        progress = 0
    now = {'phase': str(getattr(t, 'phase', '') or ''), 'progress': progress,
           'proxmox_vmid': getattr(t, 'proxmox_vmid', None)}
    if status == 'running':
        with _lock:
            item.update(now)
        return False
    if status == 'completed':
        _item_set(item, 'done', '', **now)
    elif status == 'cancelled':
        _item_set(item, 'cancelled', 'Cancelled at the switchover - the source was left running', **now)
    else:
        _item_set(item, 'failed', str(getattr(t, 'error', '') or 'The migration failed'), **now)
    # a starter that did not hand the guest to its migration leaves it with the run till here
    let_go(run.vmware_id, item['vm_id'], run.holder)
    return True


def work(run, starter, lookup):
    from pegaprox.core import ha
    from pegaprox.globals import cluster_managers, vmware_managers
    flying = []
    try:
        while True:
            stop = ''
            if not ha.is_active():
                stop = 'This instance no longer acts on the clusters (it is a standby now)'
            elif vmware_managers.get(run.vmware_id) is None:
                stop = 'The ESXi server is gone from PegaProx'
            elif cluster_managers.get(run.settings.get('target_cluster')) is None:
                stop = 'The target cluster is gone from PegaProx'
            if stop:
                with _lock:
                    run.state, run.reason = 'stopped', stop
                _end_waiting(run, 'cancelled', 'Not started: the run was stopped')
                _let_go(run)
                return
            with _lock:
                cancelled_by = run.cancelled_by
            if cancelled_by:
                _end_waiting(run, 'cancelled', f'Not started: cancelled by {cancelled_by}')
            else:
                while len(flying) < run.width and not _settling(flying, lookup):
                    item = _claim(run)
                    if item is None:
                        break
                    if _begin(run, item, starter):
                        flying.append(item)
                    if not ha.is_active():
                        break
            _drop_password_when_done(run)
            if not flying and _next_waiting(run) is None:
                return
            time.sleep(POLL_SECONDS)
            flying = [it for it in flying if not _follow(run, it, lookup)]
    except Exception as e:
        logging.error(f"[ESXI-BULK] run {run.id} broke off: {e}", exc_info=True)
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
        run._password = None
        items = [dict(it) for it in run.items]
    _let_go_all(run)
    by = {}
    for it in items:
        by.setdefault(it['state'], []).append(it.get('name') or it['vm_id'])
    parts = []
    for state in OVER:
        names = by.get(state)
        if names:
            parts.append(f"{state} {len(names)}" + (f" ({', '.join(names[:20])}{' ...' if len(names) > 20 else ''})"
                                                    if state in ('failed', 'skipped', 'unknown') else ''))
    s = run.settings
    try:
        log_audit(run.user, 'vmware.bulk_migration.finished',
                  f"ESXi bulk migration {run.id} from {run.vmware_name} to {s.get('target_cluster')}/"
                  f"{s.get('target_node')} {run.state}: " + (', '.join(parts) or 'nothing')
                  + (f" - {run.reason}" if run.reason else ''), ip_address=run.ip)
    except Exception as e:
        logging.error(f"[ESXI-BULK] audit of run {run.id} failed: {e}")


def reset_for_tests():
    with _lock:
        _runs.clear()
        _held.clear()
