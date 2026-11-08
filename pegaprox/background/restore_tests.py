# -*- coding: utf-8 -*-
"""The weekly restore test run: the auto-verify policy of the PBS view, carried out.

MK Oct 2026 - the policy (day, hour, how many backups, latest per guest or any, how old a
backup may be) was stored by PUT /api/pbs/verify-schedule and read by nothing, so no test
ever ran. This loop runs it on the active instance only: once a minute it asks whether the
latest slot of the policy is owed (core/recovery.py due_slot, on the group's clock), and
if so writes that it takes it before anything runs, so a restart or a new leader never
runs the same slot again. Only the latest slot is owed: a run missed while this process
was down or a standby is made up once.

The run itself is one thread, one test after another through backup_verify.run_verification,
never two runs at once; each test confirms the lease first (#625). Where it stands goes to
the pegaprox_kv row 'pbs_verify_schedule_state' after every test, the picks and results
with it, for the UI and for the next leader.

A backup larger than the policy's max_backup_gb, or one of unknown size, is left out at
the pick, and before each restore the storage it writes to has to have the backup's size
free (backup_verify.room_for). Either is a result with status 'skipped' and its reason
('too_large', 'size_unknown', 'no_space', 'space_unknown').
"""

import logging
import threading
import time
from datetime import datetime, timedelta

from pegaprox.globals import cluster_managers
from pegaprox.core import ha, recovery
from pegaprox.utils.audit import log_audit

TICK = 60
WHAT = 'restore tests'

_lock = threading.Lock()
_current = {'thread': None}
_loop_thread = None
_running = False


def busy():
    """Whether a run is going on in this process."""
    with _lock:
        t = _current['thread']
        return t is not None and t.is_alive()


def _write(report):
    try:
        state = recovery.load_state()
        state['last_run'] = report
        recovery.save_state(state)
    except Exception as e:
        logging.error(f"[RESTORE-TESTS] could not write where the run stands: {e}")


def tick(now=None, wall=None, start=True):
    """One look at the policy. Returns the slot a run was started for, else None. The
    caller checks ha.is_active() first."""
    policy = recovery.load_schedule()
    if not policy['enabled'] or busy():
        return None
    state = recovery.load_state()
    wall = time.time() if wall is None else wall
    if not isinstance(state.get('fired_wall'), (int, float)) and not isinstance(state.get('armed_wall'), (int, float)):
        # a policy switched on before anything ran it: the first run is the next slot, not
        # one that fell before this release was there to see it
        state['armed_wall'] = wall
        recovery.save_state(state)
        return None
    now = ha.schedule_now() if now is None else now
    slot = recovery.due_slot(policy, state, now, ha.schedule_at)
    if slot is None:
        return None
    minute = now.replace(second=0, microsecond=0)
    held = ha.schedule_held(slot) if slot < minute else ha.schedule_held()
    if held:
        # a leader that just took over: the one before may have started this slot, and what
        # it wrote did not reach us. Reported, not run (design 5.7)
        state['fired_wall'] = wall
        state['last_run'] = {'slot': slot.isoformat(), 'state': 'missed', 'started_at': wall,
                             'finished_at': wall, 'reason': 'the group changed its leader at the time',
                             'picked': [], 'results': []}
        recovery.save_state(state)
        ha.missed_schedules(WHAT, ['weekly restore test'], (slot, slot + timedelta(seconds=59)))
        return None
    first = ha.schedule_fire_first()
    if first and not ha.is_active():
        return None
    # at most once: the slot is written before anything runs, and in an automatic group it
    # is on its way to the members first
    state['fired_wall'] = wall
    state['last_run'] = {'slot': slot.isoformat(), 'state': 'starting', 'started_at': wall,
                         'finished_at': None, 'reason': '', 'picked': [], 'results': []}
    recovery.save_state(state)
    if first:
        ha.schedule_fired()
    if not start:
        return slot
    with _lock:
        t = threading.Thread(target=ha.as_job(_run_slot, 'the weekly restore tests'), args=(slot, policy),
                             daemon=True, name='restore-tests')
        _current['thread'] = t
        t.start()
    return slot


def _left_out(p, cap_gb):
    """The result row of a backup pick() left out for its size."""
    if p['reason'] == 'too_large':
        cause = f"the backup is {p['size'] / recovery.GIB:.1f} GB, the schedule restores up to {cap_gb} GB"
    else:
        cause = 'the backup storage does not list the size of the backup'
    return {'cluster_id': p['cluster_id'], 'vmid': p['vmid'], 'name': p['name'], 'volid': p['volid'],
            'task_id': None, 'status': 'skipped', 'reason': p['reason'], 'cause': cause, 'size': p['size'],
            'limit_gb': cap_gb, 'measured_seconds': None, 'rto_met': None}


def _run_slot(slot, policy):
    """The tests of one slot, one after another."""
    from pegaprox.core import backup_verify
    report = {'slot': slot.isoformat(), 'state': 'running', 'started_at': time.time(), 'finished_at': None,
              'reason': '', 'picked': [], 'results': []}
    rules = {}
    try:
        # MK Oct 2026 - a backup over the size cap, or of unknown size, is not restored: the
        # first run put a 300 GB copy on a production node. The run says which it left out
        skipped = []
        picks = recovery.pick(policy, cluster_managers, busy=backup_verify.running_guests(), skipped=skipped)
        report['picked'] = [{k: p[k] for k in ('cluster_id', 'vmid', 'name', 'type', 'node', 'volid', 'backup_ts',
                                               'size')}
                            for p in picks]
        cap_gb = recovery.backup_cap(policy) // recovery.GIB
        report['results'] = [_left_out(s, cap_gb) for s in skipped]
        if not picks:
            report['reason'] = ('no backup in the window to test' if not skipped
                                else 'every backup due was over the size cap or of unknown size')
        _write(report)
        for p in picks:
            cid, vmid = p['cluster_id'], p['vmid']
            entry = {'cluster_id': cid, 'vmid': vmid, 'name': p['name'], 'volid': p['volid'],
                     'task_id': None, 'status': 'skipped', 'reason': '', 'cause': '', 'measured_seconds': None,
                     'rto_met': None}
            if not ha.is_active():
                report['state'], report['reason'] = 'stopped', 'this instance is no longer the active one'
                break
            mgr = cluster_managers.get(cid)
            if mgr is None or not getattr(mgr, 'is_connected', False):
                entry['cause'] = 'the cluster is not connected'
                report['results'].append(entry)
                _write(report)
                continue
            try:
                if cid not in rules:
                    rules[cid] = recovery.load_rules(cid)
                plan = recovery.plan_for(cid, vmid, tags=set(p.get('tags') or ()), rules=rules[cid])
            except Exception as e:
                entry['cause'] = f'the rules of the cluster could not be read: {e}'
                report['results'].append(entry)
                _write(report)
                continue
            # the storage the copy's disks go to has the backup's size free, read right before
            # the restore; what cannot be read counts as no room
            short = backup_verify.room_for(mgr, p['node'], p['volid'], recovery.backup_kind(p['volid']) or p['type'],
                                           plan, p.get('size'))
            if short:
                entry.update(short)
                report['results'].append(entry)
                _write(report)
                continue
            params = {'cluster_id': cid, 'node': p['node'], 'vmid': vmid, 'vm_name': p['name'],
                      'vm_type': p['type'], 'backup_volid': p['volid'], 'backup_ts': p['backup_ts'],
                      'backup_time': datetime.fromtimestamp(p['backup_ts']).isoformat(timespec='seconds'),
                      'source': 'schedule', 'plan': plan, 'auto_cleanup': True}
            if not ha.confirm_step(f'the restore test of {vmid}'):
                report['state'], report['reason'] = 'stopped', 'the lease of this instance could not be confirmed'
                break
            try:
                st = backup_verify.run_verification(mgr, params)
            except Exception as e:
                # a test of the same guest started by hand is running
                entry['cause'] = str(e)[:200]
                report['results'].append(entry)
                _write(report)
                continue
            entry.update(task_id=st.get('id'), status=st.get('status'),
                         cause=(st.get('cause') or '') if st.get('status') != 'passed' else '',
                         measured_seconds=st.get('measured_seconds'), rto_met=st.get('rto_met'))
            report['results'].append(entry)
            _write(report)
        if report['state'] == 'running':
            report['state'] = 'done'
    except Exception as e:
        logging.error(f"[RESTORE-TESTS] the run of {slot} failed: {e}")
        report['state'], report['reason'] = 'error', str(e)[:200]
    finally:
        report['finished_at'] = time.time()
        _write(report)
        done = report['results']
        passed = sum(1 for r in done if r['status'] == 'passed')
        failed = sum(1 for r in done if r['status'] in ('failed', 'error'))
        try:
            log_audit('system', 'backup.verify_scheduled',
                      f"Weekly restore tests ({report['state']}): {len(report['picked'])} picked, "
                      f"{passed} passed, {failed} failed, {len(done) - passed - failed} skipped"
                      + (f" - {report['reason']}" if report['reason'] else ''))
        except Exception:
            pass


def status_view():
    """The policy, the next and the last run, for GET /api/pbs/verify-schedule/status."""
    policy = recovery.load_schedule()
    state = recovery.load_state()
    nxt = None
    try:
        nxt = recovery.next_slot(policy, state, ha.schedule_now(), ha.schedule_at)
    except Exception as e:
        logging.debug(f"[RESTORE-TESTS] next slot unknown: {e}")
    last = state.get('last_run') if isinstance(state.get('last_run'), dict) else None
    return {'policy': policy, 'next_run': nxt.isoformat() if nxt else None, 'running': busy(),
            'timezone': ha.group_timezone() or ha.local_timezone() or '', 'last_run': last}


def _loop():
    while _running:
        try:
            # a standby runs nothing: the tests are the active's (#625)
            if ha.is_active():
                tick()
        except Exception as e:
            logging.error(f"[RESTORE-TESTS] {e}")
        # MK Oct 2026 - test guests a run left behind: cut off by a restart, or their
        # removal refused
        try:
            if ha.is_active():
                from pegaprox.core import backup_verify
                backup_verify.sweep(cluster_managers)
        except Exception as e:
            logging.error(f"[RESTORE-TESTS] leftovers: {e}")
        time.sleep(TICK)


def start_restore_test_thread():
    global _loop_thread, _running
    if _loop_thread is None or not _loop_thread.is_alive():
        _running = True
        _loop_thread = threading.Thread(target=_loop, daemon=True, name='restore-tests-schedule')
        _loop_thread.start()
        logging.info("Restore test schedule thread started")
