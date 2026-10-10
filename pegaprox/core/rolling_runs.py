# -*- coding: utf-8 -*-
"""The state of a rolling update, kept where a restart and another instance find it.

MK Oct 2026 - a run lived in mgr._rolling_update and nowhere else. A restart of PegaProx, or
another instance taking over (#625), lost it while a node could sit in maintenance with its
guests moved away and the negative affinity rules of Proxmox HA switched off. Every change
of a run now goes through change(): the working copy on the manager and its row in
rolling_update_runs, a shared table, so the instance that acts next holds the run too.

A run that was running when its process ended is paused with the reason 'interrupted' once
an instance that may act finds it, and waits for an admin. Nothing resumes by itself:
Continue looks at the node again and goes on from the phase it was in, Cancel takes the
node out of maintenance and the rules back on. A start is refused while a run of the
cluster is running or paused, here or in the table. Finished runs stay as history, the
last HISTORY_KEEP of each cluster.
"""

import contextlib
import copy
import json
import logging
import threading
import time
import uuid

from pegaprox.core import ha
from pegaprox.core.db import get_db

ACTIVE = ('running', 'paused')
OVER = ('completed', 'failed', 'cancelled')
INTERRUPTED = 'interrupted'
# the phases of one node, in the order a run takes them
PHASES = ('checking', 'maintenance', 'evacuating', 'updating', 'rebooting', 'finishing', 'ceph', 'done')
# the sweep after the last node
CLEANUP = 'cleanup'
HISTORY_KEEP = 20
LOG_KEEP = 1000
# a finished run is history: its row keeps the end of the log
HISTORY_LOG_KEEP = 100
# guests named per node; the count is kept for all of them
MOVED_KEEP = 50
# a log line alone waits this long for the next write of the row
LOG_FLUSH = 5
# what a caller confined to part of the cluster does not get: these name guests, or who acted
CONFINED_HIDDEN = ('logs', 'paused_details', 'node_state', 'cancel_report', 'started_by', 'cancelled_by',
                   'notify_channels')

_lock = threading.RLock()
# cluster id -> {'run_id', 'state', 'thread'}: the worker of that run is in this process
_live = {}
_flushed = {}
# the clusters a Continue or a Cancel is acting on right now
_claimed = set()


def _now():
    return time.strftime('%Y-%m-%d %H:%M:%S')


def current(mgr):
    """The working copy of the run on mgr, None when there is none."""
    state = getattr(mgr, '_rolling_update', None)
    return state if isinstance(state, dict) else None


def view(mgr):
    """A copy of the working copy to hand out: the worker goes on changing its own."""
    with _lock:
        state = current(mgr)
        return copy.deepcopy(state) if state is not None else None


def _row_text(state):
    body = {k: v for k, v in state.items() if k != 'logs'}
    logs = list(state.get('logs') or [])
    if state.get('status') in OVER:
        logs = logs[-HISTORY_LOG_KEEP:]
    return json.dumps(body, default=str), json.dumps(logs, default=str)


def _persist(state, logs_only=False):
    run_id = state.get('run_id')
    if not run_id:
        return
    try:
        body, logs = _row_text(state)
        if logs_only:
            get_db().update_rolling_run_logs(run_id, logs, _now())
        else:
            get_db().update_rolling_run(run_id, state.get('status'), body, logs, _now(),
                                        state.get('completed_at'))
        if state.get('status') in OVER:
            _flushed.pop(run_id, None)
        else:
            _flushed[run_id] = time.time()
    except Exception as e:
        logging.warning(f"[RollingUpdate] could not save the state of run {run_id}: {e}")


def change(mgr, log=None, node=None, add=None, drop=None, **fields):
    """The one way a rolling update changes. fields replace keys of the working copy; log is a
    line (or a list of them) for its log; node is (name, {fields}) for the state of one node;
    add and drop are {list key: item} for completed_nodes, failed_nodes and the like.

    Anything but a log line is written to the run's row at once, and in an automatic group
    sent on before the step it announces goes out. A log line alone is written with the next
    change or after LOG_FLUSH seconds. Returns the working copy, None when mgr has no run."""
    with _lock:
        state = current(mgr)
        if state is None:
            return None
        before = (state.get('status'), state.get('current_step'), state.get('current_index'))
        structural = bool(fields or node or add or drop)
        state.update(fields)
        for key, item in (add or {}).items():
            items = state.setdefault(key, [])
            if isinstance(item, dict) or item not in items:
                items.append(item)
        for key, item in (drop or {}).items():
            items = state.get(key) or []
            while item in items:
                items.remove(item)
        if node:
            name, values = node
            entry = state.setdefault('node_state', {}).setdefault(name, {})
            if values.get('phase') and values['phase'] != entry.get('phase'):
                entry['phase_at'] = time.time()
            entry.update(values)
        if log is not None:
            lines = state.setdefault('logs', [])
            stamp = time.strftime('%H:%M:%S')
            lines.extend(f"[{stamp}] {line}" for line in (log if isinstance(log, (list, tuple)) else [log]))
            if len(lines) > LOG_KEEP:
                del lines[:len(lines) - LOG_KEEP]
        if state.get('status') in OVER and not state.get('completed_at'):
            state['completed_at'] = _now()
        if structural or time.time() - _flushed.get(state.get('run_id'), 0) >= LOG_FLUSH:
            _persist(state, logs_only=not structural)
        moved = structural and (state.get('status'), state.get('current_step'),
                                state.get('current_index')) != before
    if moved:
        ha.send_on('the phase of a rolling update')
    return state


def adopt(mgr, state):
    """state, read from the table, as the working copy of mgr, unless mgr holds that run already."""
    with _lock:
        mine = current(mgr)
        if mine is not None and mine.get('run_id') == state.get('run_id'):
            return mine
        mgr._rolling_update = state
        return state


def dismiss(mgr):
    """Drop a finished run from the working copy (its row stays as history). Not while its
    worker still winds down here."""
    with _lock:
        state = current(mgr)
        if state is None or state.get('status') not in OVER or worker_here(state.get('cluster_id'), mgr):
            return False
        mgr._rolling_update = None
        return True


def _decode(row):
    try:
        state = json.loads(row.get('state') or '{}')
    except (TypeError, ValueError):
        state = {}
    try:
        logs = json.loads(row.get('logs') or '[]')
    except (TypeError, ValueError):
        logs = []
    if not isinstance(state, dict):
        state = {}
    state.update(run_id=row.get('id'), cluster_id=row.get('cluster_id'), status=row.get('status'),
                 logs=logs if isinstance(logs, list) else [])
    state.setdefault('started_by', row.get('started_by'))
    state.setdefault('started_at', row.get('started_at'))
    if row.get('completed_at'):
        state['completed_at'] = row['completed_at']
    return state


def stored(cluster_id, statuses=None, limit=None):
    """Runs of a cluster from the table, newest first, as working copies."""
    return [_decode(r) for r in get_db().get_rolling_runs(cluster_id, statuses=statuses, limit=limit)]


def open_run(mgr, cluster_id):
    """The run of the cluster that is running or paused: the working copy, else the table's."""
    state = current(mgr)
    if state is not None and state.get('status') in ACTIVE:
        return state
    try:
        rows = stored(cluster_id, statuses=ACTIVE, limit=1)
    except Exception as e:
        logging.warning(f"[RollingUpdate] could not read the runs of {cluster_id}: {e}")
        rows = []
    return rows[0] if rows else None


def busy(mgr, cluster_id):
    """Why a new run may not start now, '' when it may."""
    with _lock:
        state = open_run(mgr, cluster_id)
        if state is not None:
            if state.get('status') == 'paused':
                return ('A rolling update of this cluster is paused - continue or cancel it first'
                        + (' (it was interrupted)' if state.get('paused_reason') == INTERRUPTED else ''))
            return 'Rolling update already in progress'
        if cluster_id in _claimed:
            return 'A rolling update of this cluster is being continued or cancelled right now'
        if worker_here(cluster_id, mgr):
            return 'The last rolling update of this cluster is still winding down'
    return ''


def begin(mgr, cluster_id, state, who):
    """A new run as the working copy of mgr, its row in the table before the first step.
    None while the cluster has a run running, paused or winding down."""
    with _lock:
        if busy(mgr, cluster_id):
            return None
        run = dict(state, run_id=uuid.uuid4().hex[:16], cluster_id=cluster_id, started_by=who,
                   node_state={}, logs=list(state.get('logs') or []))
        run.setdefault('started_at', _now())
        body, logs = _row_text(run)
        get_db().insert_rolling_run(run['run_id'], cluster_id, run.get('status') or 'running', body, logs,
                                    who, run['started_at'])
        _flushed[run['run_id']] = time.time()
        mgr._rolling_update = run
        try:
            get_db().prune_rolling_runs(cluster_id, HISTORY_KEEP, OVER)
        except Exception as e:
            logging.debug(f"[RollingUpdate] history of {cluster_id} not pruned: {e}")
    ha.send_on('a rolling update that starts')
    return run


@contextlib.contextmanager
def claim(cluster_id):
    """One Continue or Cancel of a cluster's run at a time: yields False to the second."""
    with _lock:
        got = cluster_id not in _claimed
        if got:
            _claimed.add(cluster_id)
    try:
        yield got
    finally:
        if got:
            with _lock:
                _claimed.discard(cluster_id)


def attach(mgr, cluster_id, thread=None):
    """The worker of the run on mgr runs in this process from now on."""
    with _lock:
        state = current(mgr)
        if state is not None:
            _live[cluster_id] = {'run_id': state.get('run_id'), 'state': state, 'thread': thread}


def detach(cluster_id, run_id):
    with _lock:
        if (_live.get(cluster_id) or {}).get('run_id') == run_id:
            _live.pop(cluster_id, None)


def worker_here(cluster_id, mgr):
    """Whether the worker of mgr's run is alive in this process."""
    with _lock:
        entry = _live.get(cluster_id)
        state = current(mgr)
        if entry is None or state is None or entry['state'] is not state:
            return False
        thread = entry.get('thread')
        return thread is None or thread.is_alive()


def resume_phase(state):
    """The phase a run that was running goes on from: the step it was in."""
    step = state.get('current_step') or ''
    if step in PHASES or step == CLEANUP:
        return step
    return PHASES[0]


def restore(mgr):
    """At the start of a manager: the run of its cluster that is still open, as its working
    copy. A worker of it that lives in this process (the manager was built again) keeps its
    own, shared. One that was running is paused by recover() where this instance acts; a
    standby only shows it."""
    cluster_id = getattr(mgr, 'id', None)
    if not isinstance(cluster_id, str):
        return
    with _lock:
        entry = _live.get(cluster_id)
        thread = (entry or {}).get('thread')
        alive = entry is not None and (thread is None or thread.is_alive())
    try:
        rows = stored(cluster_id, statuses=ACTIVE, limit=1)
        # a worker still winding a cancelled run down here has no open row any more
        newest = (rows or stored(cluster_id, limit=1)) if alive else rows
    except Exception as e:
        logging.warning(f"[RollingUpdate] could not read the open run of {cluster_id}: {e}")
        return
    if alive and newest and newest[0].get('run_id') == entry.get('run_id'):
        # the same run, its worker goes on with the manager this one replaces
        with _lock:
            mgr._rolling_update = entry['state']
        return
    if not rows:
        return
    adopt(mgr, rows[0])
    if rows[0].get('status') != 'running':
        return
    if ha.is_active():
        recover(mgr)
    elif ha.acting_process():
        # automatic failover: this process leads and may not act yet (the takeover wait)
        ha.when_active(lambda: recover(mgr), 'rolling-update-recovery')


def recover(mgr):
    """A run that was running when its process ended: paused, reason 'interrupted', with a log
    line that says which node was in which phase. Only where this instance may act; returns
    whether it paused one."""
    if not ha.is_active():
        return False
    with _lock:
        state = current(mgr)
        if state is None or state.get('status') != 'running' or worker_here(state.get('cluster_id'), mgr):
            return False
        nodes = list(state.get('nodes') or [])
        idx = int(state.get('current_index') or 0)
        node = state.get('current_node') or (nodes[idx] if idx < len(nodes) else '')
        step = state.get('current_step') or 'starting'
        phase = resume_phase(state)
        where = (f"{node} ({idx + 1}/{len(nodes)}) was in phase '{step}'" if phase != CLEANUP
                 else 'the run was taking the last nodes out of maintenance')
        # paused under the lock: a Continue that comes in now finds it paused
        change(mgr, status='paused', current_step='paused_interrupted', paused_reason=INTERRUPTED,
               paused_details={
                   'node': node, 'phase': step,
                   'message': (f"PegaProx stopped while {where} (a restart, or another instance took "
                               f"over). Nothing goes on by itself: Continue looks at {node or 'the cluster'} "
                               f"again and goes on from there, Cancel ends the run and takes the node out "
                               f"of maintenance."),
               },
               resume_at={'index': len(nodes) if phase == CLEANUP else idx, 'phase': phase},
               log=f"⏸ INTERRUPTED - PegaProx stopped while {where}. The run waits: Continue or Cancel.")
    cluster_id = state.get('cluster_id')
    name = getattr(getattr(mgr, 'config', None), 'name', None) or cluster_id
    logging.warning(f"[RollingUpdate] run {state.get('run_id')} of {cluster_id} was interrupted while {where} "
                    f"- paused, waiting for Continue or Cancel")
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'node.rolling_update_interrupted',
                  f"Rolling update paused after an interruption while {where}", cluster=name)
    except Exception as e:
        logging.debug(f"[RollingUpdate] audit of the interruption failed: {e}")
    try:
        from pegaprox.utils.webhooks import notify_lifecycle
        notify_lifecycle('rolling_update.interrupted', f"Rolling update interrupted on {name}",
                         f"PegaProx stopped while {where}. The run is paused until someone continues "
                         f"or cancels it.", cluster_id=cluster_id, severity='warning',
                         channel_ids=state.get('notify_channels') or [])
    except Exception:
        pass
    return True


def follow(mgr, cluster_id):
    """#625 - on a standby after a sync: the working copy as the active's row has it, so the
    progress can be shown from here when the active does not answer. Returns 1 when it
    changed."""
    if ha.is_active():
        return 0
    try:
        rows = stored(cluster_id, limit=1)
    except Exception:
        return 0
    with _lock:
        mine = current(mgr)
        if not rows:
            if mine is None:
                return 0
            mgr._rolling_update = None
            return 1
        row = rows[0]
        if row.get('status') not in ACTIVE and (mine is None or mine.get('run_id') != row.get('run_id')):
            return 0
        if mine == row:
            return 0
        mgr._rolling_update = row
        return 1


# MK Oct 2026 - the quorum gate. Before a node goes into maintenance and before its update the
# cluster has to keep its quorum with that node down, or the run waits: paused, reason 'quorum'.
# A node that comes back from its reboot can take a moment to rejoin corosync, so a verdict
# against it is looked at again for QUORUM_SETTLE seconds before the run holds.
QUORUM = 'quorum'
QUORUM_SETTLE = 60
QUORUM_LOOK_EVERY = 10


def _config_votes(mgr):
    """{node: votes} as corosync.conf has them (/cluster/config/nodes), {} when unread."""
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/config/nodes", timeout=10)
        if r.status_code != 200:
            return {}
        rows = r.json().get('data') or []
    except Exception:
        return {}
    out = {}
    for row in rows if isinstance(rows, list) else ():
        if not isinstance(row, dict) or not row.get('node'):
            continue
        try:
            out[str(row['node'])] = max(0, int(row.get('quorum_votes', 1)))
        except (TypeError, ValueError):
            out[str(row['node'])] = 1
    return out


def _qdevice_of(mgr, node_count):
    """{'present', 'connected', 'votes'} of the cluster's QDevice (core/qdevice.py, kept 30 s).
    pvecm sets one up with the ffsplit algorithm, one vote; lms gives it one less than nodes."""
    from pegaprox.core import qdevice
    try:
        v = qdevice.view(getattr(mgr, 'id', None), mgr)
    except Exception:
        v = None
    if not isinstance(v, dict) or not v.get('present'):
        return {'present': False, 'connected': False, 'votes': 0}
    algo = str(v.get('algorithm') or '').lower()
    votes = max(1, node_count - 1) if 'lms' in algo else 1
    return {'present': True, 'connected': v.get('state') == 'Connected', 'votes': votes}


def quorum_facts(mgr):
    """What decides the quorum of a Proxmox VE cluster: one read of /cluster/status, the votes
    of corosync.conf and the QDevice its nodes report. None where there is no quorum to look
    at (XCP-ng, a manager without /cluster/status); {'error': ...} when the status was not
    read."""
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None
    read = getattr(mgr, '_ha_cluster_status', None)
    if not callable(read):
        return None
    try:
        entries = read()
    except Exception:
        entries = None
    if not isinstance(entries, list):
        return {'error': 'status_unreadable'}
    cluster = next((e for e in entries if isinstance(e, dict) and e.get('type') == 'cluster'), None)
    nodes = {str(e['name']): {'online': bool(e.get('online')), 'votes': 1}
             for e in entries if isinstance(e, dict) and e.get('type') == 'node' and e.get('name')}
    if cluster is None:
        return {'standalone': True, 'quorate': True, 'nodes': nodes, 'qdevice': {'present': False},
                'two_node': False}
    for name, votes in _config_votes(mgr).items():
        if name in nodes:
            nodes[name]['votes'] = votes
    seen = getattr(mgr, 'ha_config', None)
    seen = seen.get('fence_strategy') if isinstance(seen, dict) else None
    return {'standalone': False, 'quorate': bool(cluster.get('quorate')), 'nodes': nodes,
            'qdevice': _qdevice_of(mgr, len(nodes)),
            # corosync's two_node, as the last look at pvecm status found it (#625)
            'two_node': isinstance(seen, dict) and seen.get('two_node_flag') is True}


def quorum_without(facts, node):
    """Whether the cluster stays quorate with `node` down. ok, reason ('not_quorate',
    'would_lose', 'status_unreadable' or None) and the votes behind it."""
    if facts is None:
        return {'ok': True, 'reason': None, 'skipped': True}
    if facts.get('error'):
        return {'ok': False, 'reason': facts['error'], 'node': node}
    nodes = facts.get('nodes') or {}
    offline = sorted(n for n, v in nodes.items() if not v['online'] and n != node)
    if facts.get('standalone'):
        return {'ok': True, 'reason': None, 'node': node, 'standalone': True, 'offline': offline}
    q = facts.get('qdevice') or {}
    q_votes = int(q.get('votes') or 0) if q.get('present') else 0
    expected = sum(v['votes'] for v in nodes.values()) + q_votes
    needed = 1 if facts.get('two_node') and len(nodes) == 2 and not q_votes else expected // 2 + 1
    have = sum(v['votes'] for v in nodes.values() if v['online']) + (q_votes if q.get('connected') else 0)
    mine = nodes.get(node) or {}
    after = have - (mine.get('votes', 0) if mine.get('online') else 0)
    reason = None
    if not facts.get('quorate'):
        reason = 'not_quorate'
    elif after < needed:
        reason = 'would_lose'
    return {'ok': reason is None, 'reason': reason, 'node': node, 'expected': expected, 'needed': needed,
            'have': have, 'after': after, 'offline': offline,
            'qdevice': {'present': bool(q.get('present')), 'connected': bool(q.get('connected'))}}


def quorum_gate(mgr, node, sleep=time.sleep, stop=None, settle=QUORUM_SETTLE):
    """quorum_without for node now; a verdict against it is looked at again every
    QUORUM_LOOK_EVERY seconds for `settle` seconds, or until stop() says the run ended."""
    verdict = quorum_without(quorum_facts(mgr), node)
    waited = 0
    while not verdict['ok'] and waited < settle and not (stop and stop()):
        sleep(QUORUM_LOOK_EVERY)
        waited += QUORUM_LOOK_EVERY
        verdict = quorum_without(quorum_facts(mgr), node)
    return verdict


def quorum_said(verdict):
    """The log line of a verdict."""
    if verdict.get('skipped'):
        return 'Quorum: not looked at (no corosync cluster to ask)'
    if verdict.get('standalone'):
        return 'Quorum: a single node in no cluster, nothing to lose'
    if verdict.get('reason') == 'status_unreadable':
        return 'Quorum: /cluster/status did not answer'
    head = (f"Quorum with {verdict['node']} down: {verdict['after']} of {verdict['expected']} votes, "
            f"{verdict['needed']} needed")
    if verdict['offline']:
        head += f" ({', '.join(verdict['offline'])} offline)"
    q = verdict.get('qdevice') or {}
    if q.get('present'):
        head += ', QDevice ' + ('connected' if q.get('connected') else 'NOT connected')
    return head


def quorum_hold(verdict, phase):
    """(paused_details, log line) of a run that waits for its quorum."""
    node = verdict.get('node') or ''
    step = 'goes into maintenance' if phase == 'maintenance' else 'is updated'
    if verdict.get('reason') == 'status_unreadable':
        why = "the quorum of the cluster could not be read (/cluster/status did not answer)"
    elif verdict.get('reason') == 'not_quorate':
        why = 'the cluster is not quorate right now'
    else:
        why = (f"taking {node} down would leave {verdict['after']} of {verdict['expected']} votes, "
               f"and the cluster needs {verdict['needed']}")
        if verdict.get('offline'):
            why += f" ({', '.join(verdict['offline'])} offline)"
    details = {k: verdict.get(k) for k in ('node', 'reason', 'expected', 'needed', 'have', 'after',
                                           'offline', 'qdevice')}
    details.update(phase=phase, message=(
        f"Not going on before {node} {step}: {why}. Bring the missing nodes (or the QDevice) "
        f"back, then Continue - it looks at the quorum again. Continue anyway takes the node down "
        f"all the same, Cancel ends the run."))
    return details, f"⏸ QUORUM - {node} is not taken down: {why}. Waiting for Continue or Cancel."


def history(cluster_id, limit=HISTORY_KEEP):
    """The runs of a cluster for the history list, newest first."""
    out = []
    for state in stored(cluster_id, limit=limit):
        failed = state.get('failed_nodes') or []
        out.append({
            'run_id': state.get('run_id'), 'status': state.get('status'),
            'started_at': state.get('started_at'), 'completed_at': state.get('completed_at'),
            'started_by': state.get('started_by'), 'scheduled': bool(state.get('scheduled')),
            'cancelled_by': state.get('cancelled_by'),
            'nodes': len(state.get('nodes') or []),
            'completed': len(state.get('completed_nodes') or []),
            'skipped': len(state.get('skipped_nodes') or []),
            'failed': len(failed), 'failed_nodes': failed,
            'paused_reason': state.get('paused_reason'), 'error': state.get('error'),
            'cancel_report': state.get('cancel_report') or [],
            'include_reboot': bool(state.get('include_reboot')),
            'logs': (state.get('logs') or [])[-HISTORY_LOG_KEEP:],
        })
    return out


def reset_for_tests():
    with _lock:
        _live.clear()
        _flushed.clear()
        _claimed.clear()
