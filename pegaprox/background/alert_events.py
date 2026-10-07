# -*- coding: utf-8 -*-
"""
PegaProx Event Alerts - Layer 7
Failed Proxmox tasks, Ceph health, replication, stale snapshots, guests without a
backup job, ZFS pools in trouble, node clocks that drift and guests in a restart loop.

The metric rules in alerts.py compare a number on every tick and send again after each
cooldown for as long as it stays over the line. The rules here watch a condition: one
message when it starts, one when it clears, nothing on the polls in between. The open
active_alerts row of a condition is what remembers that it was said, so a restart does
not say it again, and a mute holds a condition back until the mute runs out.

What it reads, per cluster that has such a rule:
  - one /cluster/tasks per tick, compared from a cursor on
  - one /cluster/ceph/status per tick where Ceph answers (a cluster without it is asked
    again after CEPH_RETRY), shared with the Ceph overview of all clusters (api/ceph.py)
    for CEPH_FRESH seconds, whichever asked last
  - /cluster/replication plus one status read per source node every REPLICATION_EVERY
  - the snapshot list of each guest once after a start, SNAPSHOT_READS_PER_TICK per tick,
    then only for a guest whose snapshot task shows up in the task list
  - /cluster/backup-info/not-backed-up every BACKUP_EVERY, shared with the overview of
    guests without a backup job (api/clusters.py), whichever asked last
  - the ZFS pool list of every online node every ZFS_EVERY, and `zpool status` of a pool
    (/nodes/<n>/disks/zfs/<pool>) while it is not ONLINE or shows errors, else every
    ZFS_DETAIL_EVERY, at most ZFS_DETAILS_PER_PASS per cluster and pass
  - /nodes/<n>/time of every online node every CLOCK_EVERY, shared with the Prometheus
    exporter (api/metrics_exporter.py), whichever asked last
  - restart loops need no read of their own: the start and reboot tasks of the task list
    above, kept per guest for RESTART_WINDOW_MAX minutes
Nothing here asks a cluster per guest on every tick. Only the active instance runs any
of it (alerts.alert_check_loop, #625); active_alerts is a table of its own, so after a
takeover a condition that still holds is said once more by the new active.
MK Oct 2026
"""

import html as html_lib
import logging
import re
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import quote

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.utils.concurrent import run_concurrent, run_per_node
from pegaprox.utils import zpool

try:
    import re._parser as _re_parser
except ImportError:  # python < 3.11
    import sre_parse as _re_parser


EVENT_METRICS = ('task_failed', 'ceph_health', 'replication', 'snapshot_age', 'backup_coverage',
                 'zfs_health', 'clock_drift', 'restart_loop')

# the fields a matching decision rests on; a rule whose one of these changed starts over
MATCH_FIELDS = ('metric', 'target_type', 'target_id', 'threshold', 'task_type', 'task_status',
                'task_warnings', 'snapshot_ignore_policy', 'backup_exclude_tags',
                'restart_window_minutes')

TASK_LOOKBACK = 24 * 3600     # how far back a rule looks the first time it reads a cluster
TASK_OVERLAP = 300            # pmxcfs hands on the tasks of other nodes late: read behind the cursor
CEPH_RETRY = 1800
CEPH_PROBE_NODES = 10
CEPH_FRESH = 30               # a status read this recent serves the tick and the Ceph overview alike
REPLICATION_EVERY = 300
REPLICATION_BUDGET = 40       # seconds for the per-node status reads of one cluster
SNAPSHOT_EVAL_EVERY = 600
SNAPSHOT_READS_PER_TICK = 300
SNAPSHOT_PARALLEL = 8
SNAPSHOT_RETRY = 1800
NOTICES_PER_RULE = 20         # per rule and tick; the rest go out as one summary
MUTE_MAX_MINUTES = 30 * 24 * 60
PATTERN_MAX = 120
PATTERN_REPEATS = 2
SUBJECT_MAX = 200
POLICY_PREFIX = 'pegaprox-'   # snapshot policies name their snapshots like this (api/snapshots.py)
BACKUP_EVERY = 300            # which jobs cover which guest changes seldom
BACKUP_FRESH = 60             # a read the overview made this recently serves the tick too
BACKUP_TIMEOUT = 20           # pveproxy opens the config of every guest it lists
EXCLUDE_TAGS_DEFAULT = ('no-backup',)
EXCLUDE_TAGS_MAX = 20
_TAG_RE = re.compile(r'^[\w.+-]{1,64}$')
ZFS_EVERY = 300               # the pool list of each node; a pool changes state seldom
ZFS_DETAIL_EVERY = 1800       # zpool status of a pool that looks fine, for its error counts
ZFS_DETAILS_PER_PASS = 40     # per cluster and pass, the pools in trouble first
ZFS_PARALLEL = 8              # reads at a time against one cluster
ZFS_BUDGET = 30               # seconds for the lists of one cluster, the same again for the pools
CLOCK_EVERY = 300             # a clock drifts slowly
CLOCK_PARALLEL = 8
CLOCK_BUDGET = 30
CLOCK_ROUND_TRIP_MAX = 5      # an answer that took longer says too little about the offset
CLOCK_CRITICAL = 60           # where the connection check fails a clock as well (core/conncheck.py)
RESTART_TASKS = frozenset(('qmstart', 'vzstart', 'qmreboot', 'vzreboot'))
RESTART_WINDOW_DEFAULT = 15   # minutes
RESTART_WINDOW_MAX = 1440     # minutes; the starts of a guest are kept this long
RESTART_KEEP = 200            # starts kept per guest

_THRESHOLDS = {
    # metric: (default, lowest, highest)
    'task_failed': (1, 1, 1),
    'ceph_health': (0, 0, 1),           # 0: HEALTH_WARN or worse, 1: HEALTH_ERR only
    'replication': (60, 1, 10080),      # minutes since the last sync
    'snapshot_age': (14, 1, 3650),      # days
    'backup_coverage': (1, 0, 720),     # hours a guest may be in no backup job before it counts
    'zfs_health': (0, 0, 1),            # 0: not ONLINE or with errors, 1: not ONLINE only
    'clock_drift': (2, 1, 3600),        # seconds a node's clock may be off ours
    'restart_loop': (3, 2, 100),        # starts within restart_window_minutes
}
_SNAPSHOT_TASKS = frozenset(('qmsnapshot', 'qmdelsnapshot', 'qmrollback',
                             'vzsnapshot', 'vzdelsnapshot', 'vzrollback'))
_TASK_LABELS = {
    'vzdump': 'Backup', 'qmigrate': 'Migration', 'vzmigrate': 'Migration',
    'qmrestore': 'Restore', 'vzrestore': 'Restore', 'qmclone': 'Clone', 'vzclone': 'Clone',
    'qmsnapshot': 'Snapshot', 'vzsnapshot': 'Snapshot', 'qmstart': 'Start', 'vzstart': 'Start',
}
_CEPH_LEVELS = {'HEALTH_OK': 0, 'HEALTH_WARN': 1, 'HEALTH_ERR': 2}

# per cluster, in this process. The cursors start over after a restart; the open
# incidents in the database keep that from saying anything twice.
_tasks = {}       # cid -> {'cursor': epoch, 'seen': {upid: endtime}}
_ceph = {}        # cid -> {'absent_until': epoch, 'node': str|None, 'last': (epoch, status)}
_ceph_locks = {}
_ceph_guard = threading.Lock()
_repl = {}        # cid -> {'next_at': epoch}
_snaps = {}       # cid -> {'guests': {vmid: [(name, ts)]}, 'tried': {vmid: epoch}, 'dirty': set(), 'next_eval': epoch}
_backup = {}      # cid -> {'next_at': epoch, 'since': {vmid: epoch first seen in no job}}
_zfs = {}         # cid -> {'next_at': epoch, 'pools': {node: {pool: health}}, 'detail': {(node, pool): (epoch, detail)}}
_coverage = {}    # cid -> (epoch, status, rows or None): the last not-backed-up read, any caller
_coverage_locks = {}
_coverage_guard = threading.Lock()
_status = {}      # cid -> {source: {'at': epoch, 'ok': bool, 'note': str}} for the diagnostics
_clock = {}       # cid -> the last read_node_clocks() of a cluster, any caller
_starts = {}      # cid -> {vmid: [epoch of each start or reboot task]}
_wall = time.time  # our clock against the nodes'; the tests set it


# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------

def check_pattern(pattern):
    """The compiled pattern, or ValueError saying what is wrong with it.

    A rule's patterns run in the alert loop against text from the cluster, and that loop
    is one thread for every tenant. Python's re has no time limit, so a pattern that
    backtracks for long would hold up every alert of the install. Refused are a repeat
    inside a repeat, alternatives inside a repeat, back-references and more than
    PATTERN_REPEATS open repeats; the text it runs on is cut to SUBJECT_MAX.
    """
    if not isinstance(pattern, str):
        raise ValueError('the pattern must be text')
    if len(pattern) > PATTERN_MAX:
        raise ValueError(f'the pattern is longer than {PATTERN_MAX} characters')
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
        tree = _re_parser.parse(pattern)
    except (re.error, OverflowError, RecursionError) as e:
        raise ValueError(f'invalid pattern: {e}')
    repeats = [0]

    def walk(items, in_repeat):
        for op, av in items:
            name = str(op)
            if name in ('MAX_REPEAT', 'MIN_REPEAT', 'POSSESSIVE_REPEAT'):
                lo, hi, sub = av
                if hi == 1:          # x? - at most once, nothing to backtrack over
                    walk(sub, in_repeat)
                    continue
                if in_repeat:
                    raise ValueError('a repeat inside a repeat can take very long to fail')
                repeats[0] += 1
                walk(sub, True)
            elif name == 'BRANCH':
                if in_repeat:
                    raise ValueError('alternatives inside a repeat can take very long to fail')
                for branch in av[1]:
                    walk(branch, in_repeat)
            elif name == 'SUBPATTERN':
                walk(av[-1], in_repeat)
            elif name == 'ATOMIC_GROUP':
                walk(av, in_repeat)
            elif name in ('ASSERT', 'ASSERT_NOT'):
                walk(av[1], in_repeat)
            elif name.startswith('GROUPREF'):
                raise ValueError('back-references are not supported')
    walk(tree, False)
    if repeats[0] > PATTERN_REPEATS:
        raise ValueError(f'at most {PATTERN_REPEATS} open repeats (*, + or {{n,m}}) per pattern')
    return compiled


# ---------------------------------------------------------------------------
# rule fields (api/alerts.py)
# ---------------------------------------------------------------------------

def _int_in(value, lo, hi):
    if isinstance(value, bool):
        return None
    # a float only when it is whole: 59.9 is no whole number, and inf or nan never are
    if isinstance(value, float) and not value.is_integer():
        return None
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return n if lo <= n <= hi else None


def tag_list(value):
    """(tags, None) from a list or a comma/space separated text, or (None, error text).
    Duplicates go regardless of case; the order stays as written."""
    if value is None:
        return [], None
    if isinstance(value, str):
        parts = re.split(r'[\s,;]+', value)
    elif isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
        parts = list(value)
    else:
        return None, 'the tags are a list of words'
    out, seen = [], set()
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if not _TAG_RE.match(p):
            return None, f"'{p[:70]}' is no tag (letters, digits, - _ . + and at most 64 of them)"
        if p.lower() not in seen:
            seen.add(p.lower())
            out.append(p)
    if len(out) > EXCLUDE_TAGS_MAX:
        return None, f'at most {EXCLUDE_TAGS_MAX} tags'
    return out, None


def normalize_rule(rule, data, prev_metric=None):
    """Bring the event fields of `rule` in shape, from the request body `data`.

    Returns an error text for the caller to answer 400 with, or None. A rule on any
    other metric only takes notify_resolved from here.
    """
    metric = rule.get('metric')
    if 'notify_resolved' in data:
        rule['notify_resolved'] = bool(data.get('notify_resolved'))
    if metric != 'backup_coverage':
        rule.pop('backup_exclude_tags', None)
    if metric != 'restart_loop':
        rule.pop('restart_window_minutes', None)
    if metric not in EVENT_METRICS:
        for k in ('task_type', 'task_status', 'task_warnings', 'snapshot_ignore_policy'):
            rule.pop(k, None)
        return None

    rule['operator'] = 'event'
    rule.setdefault('notify_resolved', True)
    default, lo, hi = _THRESHOLDS[metric]
    if 'threshold' in data and metric != 'task_failed':
        n = _int_in(data.get('threshold'), lo, hi)
        if n is None:
            return f'threshold must be a whole number from {lo} to {hi} for {metric}'
        rule['threshold'] = n
    else:
        kept = _int_in(rule.get('threshold'), lo, hi) if prev_metric == metric else None
        rule['threshold'] = default if kept is None else kept

    if metric == 'task_failed':
        ttype = data.get('task_type', rule.get('task_type')) or 'vzdump'
        tstatus = data.get('task_status', rule.get('task_status')) or ''
        for label, pat in (('task type', ttype), ('exit status', tstatus)):
            if pat:
                try:
                    check_pattern(pat)
                except ValueError as e:
                    return f'{label}: {e}'
        rule['task_type'] = ttype
        rule['task_status'] = tstatus
        rule['task_warnings'] = bool(data.get('task_warnings', rule.get('task_warnings', False)))
    if metric == 'snapshot_age':
        rule['snapshot_ignore_policy'] = bool(
            data.get('snapshot_ignore_policy', rule.get('snapshot_ignore_policy', True)))
    if metric == 'backup_coverage':
        # a guest tagged like this is left out on purpose: no alert, and an open one closes
        raw = data['backup_exclude_tags'] if 'backup_exclude_tags' in data \
            else rule.get('backup_exclude_tags', list(EXCLUDE_TAGS_DEFAULT))
        tags, bad = tag_list(raw)
        if bad:
            return f'excluded tags: {bad}'
        rule['backup_exclude_tags'] = tags
    if metric == 'restart_loop':
        if 'restart_window_minutes' in data:
            minutes = _int_in(data.get('restart_window_minutes'), 1, RESTART_WINDOW_MAX)
            if minutes is None:
                return f'restart_window_minutes must be a whole number from 1 to {RESTART_WINDOW_MAX}'
        else:
            minutes = _int_in(rule.get('restart_window_minutes'), 1, RESTART_WINDOW_MAX)
        rule['restart_window_minutes'] = minutes or RESTART_WINDOW_DEFAULT

    if metric == 'ceph_health':
        rule['target_type'], rule['target_id'] = 'cluster', None
    ttype = rule.get('target_type') or 'cluster'
    tid = rule.get('target_id')
    if ttype not in ('cluster', 'node', 'vm'):
        return 'target_type must be cluster, node or vm'
    if ttype == 'vm' and metric == 'zfs_health':
        return 'a ZFS rule watches the pools of the cluster or of one node'
    if ttype == 'vm' and metric == 'clock_drift':
        return 'a clock rule watches the nodes of the cluster or one node'
    if ttype == 'vm' and not str(tid or '').isdigit():
        return 'a VM target needs its numeric ID'
    if ttype == 'node' and not (isinstance(tid, str) and tid.strip()):
        return 'a node target needs the node name'
    if ttype == 'cluster':
        tid = None
    rule['target_type'], rule['target_id'] = ttype, (str(tid).strip() if tid is not None else None)
    return None


# ---------------------------------------------------------------------------
# mutes
# ---------------------------------------------------------------------------

def _row(row):
    return {k: row[k] for k in row.keys()}


def active_mutes(cluster_id=None, now=None):
    """Every mute that has not run out yet, as dicts. Never raises: no mutes on error."""
    try:
        now_dt = datetime.fromtimestamp(now) if now else datetime.now()
        cur = get_db().conn.cursor()
        if cluster_id is None:
            rows = cur.execute('SELECT * FROM alert_mutes').fetchall()
        else:
            rows = cur.execute('SELECT * FROM alert_mutes WHERE cluster_id = ?', (cluster_id,)).fetchall()
    except Exception as e:
        logging.debug(f"[AlertEvents] mutes unreadable: {e}")
        return []
    out = []
    for r in rows:
        m = _row(r)
        try:
            if datetime.fromisoformat(m['until']) <= now_dt:
                continue
        except (TypeError, ValueError):
            continue
        out.append(m)
    return out


def mute_for(mutes, cluster_id, rule_id, object_key='', target_key=''):
    """The mute that holds this back - the one that runs longest - or None.

    A mute names a rule, an object or both. An object mute matches the incident's own
    object (a task, a job) and the guest or node it is about, so muting `vm:101` silences
    every rule on that guest.
    """
    best = None
    for m in mutes or ():
        if m.get('cluster_id') != cluster_id:
            continue
        mrule, mobj = m.get('rule_id') or '', m.get('object_key') or ''
        if not mrule and not mobj:
            continue
        if mrule and mrule != rule_id:
            continue
        if mobj and mobj not in (object_key, target_key):
            continue
        if best is None or m['until'] > best['until']:
            best = m
    return best


_last_prune = [0.0]


def prune_mutes(now=None):
    """Drop mutes that ran out more than a day ago, once an hour. The table is synced to
    the standbys, so only the active does this (it runs from check_event_alerts)."""
    now = now or time.time()
    if now - _last_prune[0] < 3600:
        return
    _last_prune[0] = now
    try:
        cutoff = datetime.fromtimestamp(now - 86400).isoformat(timespec='seconds')
        db = get_db()
        db.conn.execute('DELETE FROM alert_mutes WHERE until < ?', (cutoff,))
        # committed even when nothing matched: the DELETE opened a write transaction
        # either way, and left open it holds the write lock for the next writer
        db.conn.commit()
    except Exception as e:
        logging.debug(f"[AlertEvents] mute cleanup failed: {e}")


def object_vmid(object_key):
    """The guest an object key is about, or None: vm:101, replication:101-0, task:pve1:vzdump:101."""
    key = str(object_key or '')
    if key.startswith('vm:'):
        tail = key[3:]
    elif key.startswith('replication:'):
        tail = key.split(':', 1)[1].split('-', 1)[0]
    elif key.startswith('task:'):
        tail = key.rsplit(':', 1)[-1]
    else:
        return None
    return int(tail) if tail.isdigit() else None


# ---------------------------------------------------------------------------
# reading the cluster
# ---------------------------------------------------------------------------

def _get(mgr, path, timeout=10):
    """(status, data) of a GET on the cluster API; (0, None) when nothing came back."""
    try:
        resp = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json{path}", timeout=timeout)
    except Exception as e:
        logging.debug(f"[AlertEvents] GET {path} failed: {e}")
        return 0, None
    if resp.status_code != 200:
        return resp.status_code, None
    try:
        return 200, resp.json().get('data')
    except Exception:
        return 0, None


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _note(cid, source, ok, note=''):
    _status.setdefault(cid, {})[source] = {'at': time.time(), 'ok': bool(ok), 'note': note}


def _task_window(cid, tasks, now):
    """The finished tasks behind the cursor (plus the overlap), and the ones never seen."""
    st = _tasks.setdefault(cid, {'cursor': now - TASK_LOOKBACK, 'seen': {}})
    since = st['cursor'] - TASK_OVERLAP
    window, fresh = [], []
    newest = st['cursor']
    for t in tasks:
        end = _num(t.get('endtime'))
        if not end or not t.get('status'):
            continue                      # still running
        newest = max(newest, end)
        if end <= since:
            continue
        window.append(t)
        upid = t.get('upid') or ''
        if upid and upid not in st['seen']:
            fresh.append(t)
            st['seen'][upid] = end
    st['cursor'] = min(newest, now)
    keep_after = st['cursor'] - TASK_OVERLAP
    st['seen'] = {u: e for u, e in st['seen'].items() if e > keep_after}
    return window, fresh


def _read_ceph(cid, mgr, now):
    """The Ceph status dict, or None. Absent Ceph is asked again after CEPH_RETRY."""
    return ceph_status(cid, mgr, max_age=CEPH_FRESH, now=now)[1]


def ceph_status(cid, mgr, max_age=0, now=None):
    """(state, status dict, read at) of the Ceph of a cluster: 'ok' with what
    /cluster/ceph/status or a node with Ceph answered, 'none' while no node has Ceph (asked
    again after CEPH_RETRY), 'unreadable' when it did not answer this time; dict and time
    None then. A read younger than max_age is handed out again, so the alert tick and the
    Ceph overview of all clusters (api/ceph.py) ask a cluster once between them. MK Oct 2026
    """
    clock = now is None
    now = time.time() if clock else now

    def fresh(st, at):
        last = st.get('last')
        if last and max_age and 0 <= at - last[0] < max_age:
            return 'ok', last[1], last[0]
        return None

    hit = fresh(_ceph.setdefault(cid, {'absent_until': 0, 'node': None, 'seen': False}), now)
    if hit:
        return hit
    with _ceph_guard:
        lock = _ceph_locks.setdefault(cid, threading.Lock())
    # one read per cluster at a time: an overview opened by many at once, or next to the
    # tick, waits for the read under way and takes its answer
    with lock:
        now = time.time() if clock else now
        st = _ceph.setdefault(cid, {'absent_until': 0, 'node': None, 'seen': False})
        hit = fresh(st, now)
        if hit:
            return hit
        state, data = _ceph_read(cid, mgr, st, now)
        if data is None:
            return state, None, None
        st['last'] = (now, data)
        return 'ok', data, now


def ceph_seen(cid):
    """Whether the Ceph of a cluster has answered since this process started."""
    return bool((_ceph.get(cid) or {}).get('seen'))


def _ceph_read(cid, mgr, st, now):
    if now < st['absent_until']:
        return 'none', None
    status, data = _get(mgr, '/cluster/ceph/status')
    if status == 200 and isinstance(data, dict):
        st['seen'] = True
        return 'ok', data
    if status == 0:
        return 'unreadable', None         # no answer this time - not the same as no Ceph
    if st['node']:
        s2, d2 = _get(mgr, f"/nodes/{quote(st['node'], safe='')}/ceph/status")
        if s2 == 200 and isinstance(d2, dict):
            return 'ok', d2
    if st['seen']:
        # it answered before: a Ceph in trouble can fail the status call itself, and that
        # is the moment not to stop asking. Next tick again; the condition stays as it is
        _note(cid, 'ceph', False, f'status unreadable (HTTP {status})')
        return 'unreadable', None
    # the API host may run without Ceph in a cluster that has it (#191): look for a node
    # that answers, a few of them, and not again before CEPH_RETRY if none does
    try:
        nodes = [n for n, info in (mgr.get_node_status() or {}).items()
                 if (info or {}).get('status') == 'online']
    except Exception:
        nodes = []
    for node in sorted(nodes)[:CEPH_PROBE_NODES]:
        s3, d3 = _get(mgr, f"/nodes/{quote(node, safe='')}/ceph/status")
        if s3 == 200 and isinstance(d3, dict):
            st['node'], st['seen'] = node, True
            return 'ok', d3
    st['absent_until'] = now + CEPH_RETRY
    _note(cid, 'ceph', False, f'no Ceph answered (HTTP {status}); asking again in {CEPH_RETRY // 60} minutes')
    return 'none', None


def _read_replication(cid, mgr, now):
    """{'jobs': [...], 'status': {job_id: entry}, 'failed': {node}} or None when not due/unread."""
    st = _repl.setdefault(cid, {'next_at': 0})
    if now < st['next_at']:
        return None
    st['next_at'] = now + REPLICATION_EVERY
    status, data = read_replication(mgr)
    if data is None:
        st['next_at'] = now + 60
        _note(cid, 'replication', False, f'job list unreadable (HTTP {status})')
        return None
    failed = data['failed']
    _note(cid, 'replication', not failed,
          f"{len(data['jobs'])} job(s), {len(data['sources'])} source node(s)"
          + (f", unread: {sorted(failed)}" if failed else ''))
    return data


def read_replication(mgr):
    """(HTTP status of the job list, {'jobs', 'status': {job_id: entry}, 'failed': {node},
    'sources': {node}}), the dict None when the job list could not be read. A job's state
    comes from its source node; the jobs of a node that did not answer have no entry, which
    is unknown, not fine. The alert tick reads it at its pace, the Prometheus exporter at
    its own (api/metrics_exporter.py). MK Oct 2026"""
    status, jobs = _get(mgr, '/cluster/replication')
    if status != 200 or not isinstance(jobs, list):
        return status, None
    sources = {str(j.get('source')) for j in jobs if j.get('source')}
    if any(not j.get('source') for j in jobs):
        # PVE fills `source` once a job has run; until then ask every online node
        try:
            sources |= {n for n, info in (mgr.get_node_status() or {}).items()
                        if (info or {}).get('status') == 'online'}
        except Exception:
            pass
    by_id, failed = {}, set()
    # one node after the other, inside a time budget: the cluster's other reads share
    # this greenlet, and a node that does not answer costs its whole timeout. What the
    # budget leaves unread is unknown this round, not fine.
    deadline = time.monotonic() + REPLICATION_BUDGET
    for node in sorted(sources):
        if time.monotonic() > deadline:
            failed.add(node)
            continue
        s, entries = _get(mgr, f"/nodes/{quote(node, safe='')}/replication", timeout=8)
        if s != 200 or not isinstance(entries, list):
            failed.add(node)
            continue
        for e in entries:
            jid = e.get('id')
            if not jid:
                continue
            prev = by_id.get(jid)
            if prev is None or _num(e.get('last_sync')) >= _num(prev.get('last_sync')):
                by_id[jid] = e
    return status, {'jobs': jobs, 'status': by_id, 'failed': failed, 'sources': sources}


def not_backed_up(cid, mgr, max_age=0, now=None):
    """(status, rows, read at) of /cluster/backup-info/not-backed-up: the guests no backup
    job of the cluster covers, as [{'vmid', 'type', 'name'}]; rows is None when it was not
    read.

    Proxmox counts every vzdump job, a disabled one too, and lists templates as well. A
    read younger than max_age is handed out again, so the alert tick and the overview of
    every cluster ask once between them. MK Oct 2026
    """
    clock = now is None

    def fresh(at):
        hit = _coverage.get(cid)
        if hit and max_age and 0 <= at - hit[0] < max_age:
            return hit
        return None

    hit = fresh(now or time.time())
    if hit:
        return hit[1], hit[2], hit[0]
    with _coverage_guard:
        lock = _coverage_locks.setdefault(cid, threading.Lock())
    # one read per cluster at a time: an overview opened by many at once, or next to the
    # tick, waits for the read under way and takes its answer instead of asking again
    with lock:
        now = time.time() if clock else now
        hit = fresh(now)
        if hit:
            return hit[1], hit[2], hit[0]
        status, data = _get(mgr, '/cluster/backup-info/not-backed-up', timeout=BACKUP_TIMEOUT)
        rows = None
        if status == 200 and isinstance(data, list):
            rows = []
            for g in data:
                vmid = (g or {}).get('vmid')
                if isinstance(vmid, bool) or not str(vmid).isdigit():
                    continue
                rows.append({'vmid': int(vmid), 'type': str(g.get('type') or ''),
                             'name': str(g.get('name') or '')})
        elif status == 200:
            status = 0
        _coverage[cid] = (now, status, rows)
    return status, rows, now


def guest_tags(cid, resources):
    """{vmid: {tag, ...}} in lower case: the Proxmox tags of each guest and the ones set in
    PegaProx (vm_tags), as the tag views merge them (api/search.py)."""
    out = {}
    for r in resources or ():
        raw = r.get('tags')
        if not raw or not str(r.get('vmid', '')).isdigit():
            continue
        parts = raw if isinstance(raw, list) else re.split(r'[;,\s]+', str(raw))
        out.setdefault(int(r['vmid']), set()).update(str(p).strip().lower() for p in parts if str(p).strip())
    try:
        rows = get_db().conn.execute('SELECT vmid, tag_name FROM vm_tags WHERE cluster_id = ?', (cid,)).fetchall()
    except Exception as e:
        logging.debug(f"[AlertEvents] stored tags of {cid} unreadable: {e}")
        rows = []
    for vmid, name in rows:
        if str(vmid).isdigit() and name:
            out.setdefault(int(vmid), set()).add(str(name).strip().lower())
    return out


def _read_coverage(cid, mgr, now):
    """{vmid: row} of the guests in no backup job, or None when not due or not read."""
    st = _backup.setdefault(cid, {'since': {}})
    if now < st.get('next_at', 0):
        return None
    status, rows, _at = not_backed_up(cid, mgr, max_age=BACKUP_FRESH, now=now)
    if rows is None:
        st['next_at'] = now + 60
        why = 'the API user needs Sys.Audit on /' if status == 403 else f'HTTP {status}'
        _note(cid, 'backup', False, f'not-backed-up list unreadable ({why})')
        return None
    st['next_at'] = now + BACKUP_EVERY
    uncovered = {r['vmid']: r for r in rows}
    since = st['since']
    for vmid in [v for v in since if v not in uncovered]:
        since.pop(vmid)
    for vmid in uncovered:
        since.setdefault(vmid, now)
    _note(cid, 'backup', True, f'{len(uncovered)} guest(s) in no backup job')
    return uncovered


def _plan_zfs(cid, mgr, now):
    """The online nodes whose pool list to read this tick, or None when it is not due.
    A node that left the cluster takes its pools along; an offline one keeps them, so
    what was wrong there stays open until the node answers again."""
    st = _zfs.setdefault(cid, {'pools': {}, 'detail': {}})
    if now < st.get('next_at', 0):
        return None
    try:
        nodes = mgr.get_node_status() or {}
    except Exception:
        nodes = {}
    if not nodes:
        st['next_at'] = now + 60
        _note(cid, 'zfs', False, 'node list unreadable')
        return None
    st['next_at'] = now + ZFS_EVERY
    for gone in [n for n in st['pools'] if n not in nodes]:
        st['pools'].pop(gone)
    st['detail'] = {k: v for k, v in st['detail'].items() if k[0] in nodes}
    return sorted(n for n, info in nodes.items() if (info or {}).get('status') == 'online')


def _zfs_wants_errors(rules):
    return any(r.get('metric') == 'zfs_health' and _int_in(r.get('threshold'), 0, 1) != 1
               for r in rules if r.get('enabled', True))


def _read_zfs(cid, mgr, nodes, want_errors, now):
    """The pool list of each node in `nodes`, then `zpool status` of the pools that need
    it: one not ONLINE on every pass (what is wrong with it), one that showed errors on
    every pass (whether they were cleared), any other every ZFS_DETAIL_EVERY when a rule
    asks about errors. Returns {'read': the nodes whose list came back}; a node that did
    not answer keeps what was known of it."""
    st = _zfs.setdefault(cid, {'pools': {}, 'detail': {}})
    lists = run_per_node(
        {n: (lambda node: _get(mgr, f"/nodes/{quote(node, safe='')}/disks/zfs", timeout=8)) for n in nodes},
        max_concurrent=ZFS_PARALLEL, timeout=ZFS_BUDGET) or {}
    read, unread = set(), []
    for node in nodes:
        status, rows = lists.get(node) or (0, None)
        if status != 200 or not isinstance(rows, list):
            unread.append(node)
            continue
        read.add(node)
        st['pools'][node] = {str(r['name']): str(r.get('health') or '').upper()
                             for r in rows if isinstance(r, dict) and r.get('name')}
    listed = {(n, name) for n in read for name in st['pools'][n]}
    st['detail'] = {k: v for k, v in st['detail'].items() if k[0] not in read or k in listed}

    due = []
    for node, name in listed:
        if not zpool.valid_pool_name(name):
            continue                      # Proxmox takes no other name for the detail call
        at, detail = st['detail'].get((node, name), (0, None))
        if st['pools'][node][name] != zpool.HEALTHY:
            due.append((0, at, node, name))
        elif want_errors and detail is not None and detail['has_errors']:
            due.append((1, at, node, name))
        elif want_errors and now - at >= ZFS_DETAIL_EVERY:
            due.append((2, at, node, name))
    due = sorted(due)[:ZFS_DETAILS_PER_PASS]
    done = 0
    if due:
        got = run_per_node(
            {f"{node}/{name}": (lambda _key, n=node, p=name: _get(
                mgr, f"/nodes/{quote(n, safe='')}/disks/zfs/{quote(p, safe='')}", timeout=10))
             for _, _, node, name in due},
            max_concurrent=ZFS_PARALLEL, timeout=ZFS_BUDGET) or {}
        for _, _, node, name in due:
            status, data = got.get(f"{node}/{name}") or (0, None)
            if status == 200 and isinstance(data, dict):
                d = zpool.pool_detail(data)
                # what the alert says, not the whole tree
                st['detail'][(node, name)] = (now, {k: d[k] for k in ('state', 'devices', 'data_errors',
                                                                      'has_errors', 'scan')})
                done += 1
    _note(cid, 'zfs', not unread,
          f"{len(listed)} pool(s) on {len(read)} of {len(nodes)} online node(s), {done} of {len(due)} "
          f"pool status read(s)" + (f", unread: {sorted(unread)[:10]}" if unread else ''))
    return {'read': read}


def _run_zfs_reads(order, results, now):
    """The pool reads of every cluster that is due: all clusters at once, ZFS_PARALLEL at a
    time against any one of them. After the cluster reads, like the snapshot lists, so
    their time does not count against those."""
    due = [(cid, mgr, crules, seen) for (cid, mgr, crules), seen in zip(order, results)
           if seen is not None and seen.get('zfs_nodes') is not None]
    if not due:
        return
    got = run_concurrent(
        [lambda c=cid, m=mgr, rs=crules, s=seen: _read_zfs(c, m, s['zfs_nodes'], _zfs_wants_errors(rs), now)
         for cid, mgr, crules, seen in due],
        timeout=2 * ZFS_BUDGET + 10)
    for (_cid, _mgr, _rules, seen), z in zip(due, got):
        seen['zfs'] = z


def _node_clock(mgr, node):
    """(offset, error) of one node's clock against ours in seconds, or None.

    Proxmox answers whole seconds (Perl's time()). The node took its reading T somewhere
    between our t0 and t1, while its clock stood between T and T + 1, so the offset lies
    in [T - t1, T + 1 - t0]: the middle of that, and half its width as the error.
    """
    t0 = _wall()
    status, data = _get(mgr, f"/nodes/{quote(node, safe='')}/time", timeout=8)
    t1 = _wall()
    if status != 200 or not isinstance(data, dict) or t1 - t0 > CLOCK_ROUND_TRIP_MAX:
        return None
    t = data.get('time')
    if isinstance(t, bool) or not isinstance(t, (int, float)):
        return None
    lo, hi = t - t1, t + 1 - t0
    return round((lo + hi) / 2, 2), round((hi - lo) / 2, 2)


def read_node_clocks(cid, mgr, now=None):
    """Read the clock of every online node of a cluster, keep it for clock_reading() and
    return it: {'at', 'nodes': {node: (offset, error)}, 'online': [...], 'known': {every
    node}}. None when the node list could not be read. A node that did not answer has no
    entry, which is unknown, not fine. The alert tick reads at CLOCK_EVERY, the Prometheus
    exporter at its own pace; each takes what the other read when it is recent enough."""
    try:
        nodes = mgr.get_node_status() or {}
    except Exception:
        nodes = {}
    if not nodes:
        _note(cid, 'clock', False, 'node list unreadable')
        return None
    online = sorted(n for n, info in nodes.items() if (info or {}).get('status') == 'online')
    got = run_per_node({n: (lambda node: _node_clock(mgr, node)) for n in online},
                       max_concurrent=CLOCK_PARALLEL, timeout=CLOCK_BUDGET) or {}
    readings = {n: got[n] for n in online if got.get(n)}
    entry = {'at': now or time.time(), 'nodes': readings, 'online': online, 'known': set(nodes)}
    _clock[cid] = entry
    worst = max((abs(o) for o, _e in readings.values()), default=0.0)
    unread = [n for n in online if n not in readings]
    _note(cid, 'clock', not unread,
          f"{len(readings)} of {len(online)} online node(s) read, largest offset {worst:.1f} s"
          + (f", unread: {unread[:10]}" if unread else ''))
    return entry


def clock_reading(cid):
    """The last clock read of a cluster (read_node_clocks), or None."""
    return _clock.get(cid)


def _run_clock_reads(order, results, now):
    """The clock reads of every cluster whose last one is older than CLOCK_EVERY, all
    clusters at once; then each tick evaluates the newest read it has."""
    due = [(cid, mgr) for (cid, mgr, _r), seen in zip(order, results)
           if seen is not None and seen.get('clock_due')]
    if due:
        run_concurrent([lambda c=cid, m=mgr: read_node_clocks(c, m, now) for cid, mgr in due],
                       timeout=CLOCK_BUDGET + 10)
    for (cid, _mgr, _r), seen in zip(order, results):
        if seen is None or 'clock_due' not in seen:
            continue
        hit = _clock.get(cid)
        # a read from before a long outage says nothing about now
        seen['clock'] = hit if hit is not None and now - hit['at'] < 2 * CLOCK_EVERY else None


def _record_starts(cid, fresh, now):
    """Keep the start and reboot tasks just seen in the task list, per guest. Only those
    that went through: a start that failed is a failed task (task_failed), not a start."""
    st = _starts.setdefault(cid, {})
    for t in fresh or ():
        if t.get('type') not in RESTART_TASKS:
            continue
        status = str(t.get('status') or '')
        tid = str(t.get('id') or '')
        if not tid.isdigit() or not (status == 'OK' or status.upper().startswith('WARNINGS')):
            continue
        st.setdefault(int(tid), []).append(_num(t.get('starttime')) or _num(t.get('endtime')))
    keep_after = now - RESTART_WINDOW_MAX * 60
    for vmid in list(st):
        kept = sorted(s for s in st[vmid] if s > keep_after)[-RESTART_KEEP:]
        if kept:
            st[vmid] = kept
        else:
            del st[vmid]


def _guests(resources):
    out = {}
    for r in resources or ():
        if r.get('type') not in ('qemu', 'lxc') or r.get('template'):
            continue
        try:
            out[int(r.get('vmid'))] = r
        except (TypeError, ValueError):
            continue
    return out


def _plan_snapshot_reads(cid, guests, fresh, now):
    """The guests whose snapshot list to read this tick: those a snapshot task touched
    first, then the ones never read, up to SNAPSHOT_READS_PER_TICK."""
    st = _snaps.setdefault(cid, {'guests': {}, 'tried': {}, 'dirty': set(), 'next_eval': 0})
    for t in fresh:
        if t.get('type') in _SNAPSHOT_TASKS and str(t.get('id') or '').isdigit():
            st['dirty'].add(int(t['id']))
    if guests:
        # a guest that is gone takes its entry along; an empty list may be a failed read
        for vmid in [v for v in st['guests'] if v not in guests]:
            st['guests'].pop(vmid, None)
        st['dirty'] &= set(guests)
    plan = []
    for vmid in sorted(st['dirty']):
        if vmid in guests:
            plan.append(vmid)
    for vmid in sorted(guests):
        if len(plan) >= SNAPSHOT_READS_PER_TICK:
            break
        if vmid in st['guests'] or vmid in st['dirty']:
            continue
        if now - st['tried'].get(vmid, 0) < SNAPSHOT_RETRY:
            continue
        plan.append(vmid)
    plan = plan[:SNAPSHOT_READS_PER_TICK]
    return [(vmid, guests[vmid].get('type'), guests[vmid].get('node')) for vmid in plan]


def _read_snapshots(mgr, node, vtype, vmid):
    """[(name, snaptime)] of one guest, or None when it could not be read."""
    if vtype not in ('qemu', 'lxc') or not node:
        return None
    status, data = _get(mgr, f"/nodes/{quote(str(node), safe='')}/{vtype}/{int(vmid)}/snapshot")
    if status != 200 or not isinstance(data, list):
        return None
    return [(str(s.get('name') or ''), _num(s.get('snaptime')))
            for s in data if s.get('name') and s.get('name') != 'current']


def _seed_complete(cid, guests, now):
    st = _snaps.get(cid)
    if not st or not guests:
        return False
    return all(v in st['guests'] or now - st['tried'].get(v, 0) < SNAPSHOT_RETRY for v in guests)


def _read_cluster(cid, mgr, kinds, now):
    """Everything the rules of one cluster need from it this tick. Runs in a greenlet of
    its own per cluster; touches only that cluster's state."""
    seen = {}
    if kinds & {'task_failed', 'snapshot_age', 'restart_loop'}:
        status, tasks = _get(mgr, '/cluster/tasks')
        if status == 200 and isinstance(tasks, list):
            seen['tasks'], seen['fresh'] = _task_window(cid, tasks, now)
            # whichever rule asked for the list: a restart rule added later finds the history
            _record_starts(cid, seen['fresh'], now)
            _note(cid, 'tasks', True, f"{len(tasks)} listed, {len(seen['tasks'])} in the window")
        else:
            _note(cid, 'tasks', False, f'task list unreadable (HTTP {status})')
    if kinds & {'task_failed', 'snapshot_age', 'replication', 'backup_coverage', 'restart_loop'}:
        try:
            seen['resources'] = mgr.get_vm_resources(max_age=60) or []
        except Exception:
            seen['resources'] = []
        seen['guests'] = _guests(seen['resources'])
    # before the slower reads below: the snapshot tasks just seen are marked here, and a
    # greenlet that runs out of time later must not take those marks with it
    if 'snapshot_age' in kinds:
        seen['snapshot_plan'] = _plan_snapshot_reads(cid, seen.get('guests') or {},
                                                     seen.get('fresh') or [], now)
    if 'ceph_health' in kinds:
        seen['ceph'] = _read_ceph(cid, mgr, now)
        if seen['ceph'] is not None:
            _note(cid, 'ceph', True, str((seen['ceph'].get('health') or {}).get('status', '')))
    if 'replication' in kinds:
        seen['replication'] = _read_replication(cid, mgr, now)
    if 'backup_coverage' in kinds:
        seen['backup'] = _read_coverage(cid, mgr, now)
    if 'zfs_health' in kinds:
        seen['zfs_nodes'] = _plan_zfs(cid, mgr, now)
    if 'clock_drift' in kinds:
        hit = _clock.get(cid)
        seen['clock_due'] = hit is None or not 0 <= now - hit['at'] < CLOCK_EVERY
    return seen


def _run_snapshot_reads(plans, now):
    """Read the planned snapshot lists: every cluster at once, SNAPSHOT_PARALLEL at a time
    against any one of them (pveproxy runs few workers)."""
    queues = [(cid, mgr, list(items)) for cid, mgr, items in plans if items]
    done = set()
    while any(q[2] for q in queues):
        chunk = []
        for cid, mgr, items in queues:
            chunk += [(cid, mgr, item) for item in items[:SNAPSHOT_PARALLEL]]
            del items[:SNAPSHOT_PARALLEL]
        results = run_concurrent(
            [lambda m=mgr, it=item: _read_snapshots(m, it[2], it[1], it[0]) for _, mgr, item in chunk],
            timeout=30)
        for (cid, _, item), snaps in zip(chunk, results):
            st = _snaps[cid]
            vmid = item[0]
            st['tried'][vmid] = now
            if snaps is None:
                continue
            st['guests'][vmid] = snaps
            st['dirty'].discard(vmid)
            done.add(cid)
    return done


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------

class _Pass:
    """What one look at a rule found: the conditions that hold, the objects seen fine
    (with what their resolved note says), and what tells an object that is gone - the
    jobs the cluster still lists, the guests it still has. None where it was not read."""

    def __init__(self, guests=None):
        self.firing = {}
        self.fine = {}
        self.known = None
        # an empty guest list may be a read that failed: then nothing counts as gone
        self.vmids = set(guests) if guests else None


def _guest_label(guests, vmid):
    r = (guests or {}).get(int(vmid)) if str(vmid).isdigit() else None
    name = (r or {}).get('name')
    return f"{name} ({vmid})" if name else f"VM {vmid}"


def _target_ok(rule, node, vmid):
    ttype, tid = rule.get('target_type') or 'cluster', str(rule.get('target_id') or '')
    if ttype == 'node':
        return node == tid
    if ttype == 'vm':
        return str(vmid) == tid
    return True


def _eval_tasks(rule, seen, cname):
    window = seen.get('tasks')
    if window is None:
        return None
    type_re = check_pattern(rule.get('task_type') or 'vzdump')
    status_re = check_pattern(rule['task_status']) if rule.get('task_status') else None
    newest = {}
    for t in window:
        ttype = str(t.get('type') or '')
        if not type_re.fullmatch(ttype[:SUBJECT_MAX]):
            continue
        node, tid = str(t.get('node') or ''), str(t.get('id') or '')
        if not _target_ok(rule, node, tid):
            continue
        obj = f"task:{node}:{ttype}:{tid}"
        key = (_num(t.get('endtime')), _num(t.get('starttime')))
        if obj not in newest or key > newest[obj][0]:
            newest[obj] = (key, t)
    guests = seen.get('guests')
    p = _Pass(guests)
    for obj, (_, t) in newest.items():
        ttype, node, tid = str(t.get('type') or ''), str(t.get('node') or ''), str(t.get('id') or '')
        status = str(t.get('status') or '')
        label = _TASK_LABELS.get(ttype, ttype)
        if tid.isdigit():
            who = _guest_label(guests, tid)
            subject, where = f"{label} of {who}", f" on node {node}"
            target = ('vm', tid, who, f"vm:{tid}")
        else:
            subject = f"{label} on {node}" + (f" ({tid})" if tid else '')
            where = ''
            target = ('node', node, node, f"node:{node}")
        ok = status == 'OK' or (status.upper().startswith('WARNINGS') and not rule.get('task_warnings'))
        if ok:
            p.fine[obj] = (f"Resolved: {subject}", f"{subject}{where} succeeded again.")
            continue
        if status_re is not None and not status_re.search(status[:SUBJECT_MAX]):
            continue                      # a failure this rule does not ask about
        ended = datetime.fromtimestamp(_num(t.get('endtime'))).strftime('%Y-%m-%d %H:%M')
        p.firing[obj] = {
            'object': obj, 'target_type': target[0], 'target_id': target[1],
            'target_name': target[2], 'target_key': target[3],
            'name': f"{subject} failed",
            'message': f"{subject}{where} failed: {status[:SUBJECT_MAX]}",
            'value': _num(t.get('endtime')), 'display': status[:SUBJECT_MAX],
            'severity': 'warning',
            'details': [('Task', str(t.get('upid') or '')), ('Ended', ended)],
        }
    return p


def _eval_ceph(rule, seen, cname):
    data = seen.get('ceph')
    if not data:
        return None
    health = data.get('health') or {}
    state = str(health.get('status') or health.get('overall_status') or '')
    level = _CEPH_LEVELS.get(state)
    if level is None:
        return None
    p = _Pass()
    if level <= int(rule.get('threshold') or 0):
        p.fine['ceph'] = (f"Resolved: Ceph on {cname}", f"Ceph on {cname} is back to {state}.")
        return p
    checks = health.get('checks') or {}
    ordered = sorted(checks.items(), key=lambda kv: (-_CEPH_LEVELS.get((kv[1] or {}).get('severity'), 0), kv[0]))
    parts = []
    for name, chk in ordered[:5]:
        msg = (((chk or {}).get('summary') or {}).get('message') or '').strip()
        parts.append(f"{name}: {msg}" if msg else name)
    if len(ordered) > 5:
        parts.append(f"{len(ordered) - 5} more")
    p.firing['ceph'] = {
        'object': 'ceph', 'target_type': 'cluster', 'target_id': '', 'target_name': cname,
        'target_key': '', 'name': f"Ceph {state} on {cname}",
        'message': f"Ceph on {cname} reports {state}" + (f": {'; '.join(parts)}" if parts else ''),
        'value': float(level), 'display': state,
        'severity': 'critical' if level >= 2 else 'warning',
        'changed_name': f"Ceph on {cname} is now {state}",
    }
    return p


def _eval_replication(rule, seen, cname, now):
    data = seen.get('replication')
    if not data:
        return None
    limit = int(rule.get('threshold') or _THRESHOLDS['replication'][0])
    guests = seen.get('guests')
    p = _Pass(guests)
    p.known = set()
    for job in data['jobs']:
        jid = str(job.get('id') or '')
        if not jid:
            continue
        p.known.add(f"replication:{jid}")
        guest = str(job.get('guest') or jid.split('-', 1)[0])
        if not _target_ok(rule, str(job.get('source') or ''), guest):
            continue
        obj = f"replication:{jid}"
        who = _guest_label(guests, guest)
        dest = job.get('target') or '?'
        if job.get('disable'):
            p.fine[obj] = (f"Resolved: replication {jid}", f"Replication job {jid} of {who} was disabled.")
            continue
        st = data['status'].get(jid)
        if st is None:
            continue                      # its source node did not answer: unknown, not fine
        fails = int(_num(st.get('fail_count')))
        err = str(st.get('error') or '').strip()
        last = _num(st.get('last_sync'))
        lag = (now - last) / 60.0 if last else 0.0
        base = {'object': obj, 'target_type': 'vm', 'target_id': guest, 'target_name': who,
                'target_key': f"vm:{guest}"}
        if fails > 0 or err:
            p.firing[obj] = dict(base, name=f"Replication {jid} of {who} is failing",
                                 message=(f"Replication job {jid} ({who} to {dest}) failed "
                                          f"{max(fails, 1)} time(s)" + (f": {err[:SUBJECT_MAX]}" if err else '')),
                                 value=-1.0, display='failed', severity='critical')
        elif last and lag > limit:
            p.firing[obj] = dict(base, name=f"Replication {jid} of {who} is behind",
                                 message=(f"Replication job {jid} ({who} to {dest}) last synced "
                                          f"{int(lag)} minutes ago, the limit is {limit}"),
                                 value=round(lag), display=f"{int(lag)} min", severity='warning')
        else:
            p.fine[obj] = (f"Resolved: replication {jid}",
                           f"Replication job {jid} ({who} to {dest}) is in sync again.")
    return p


def _eval_snapshots(rule, seen, cname, cid, now):
    st = _snaps.get(cid)
    guests = seen.get('guests') or {}
    if not st or not _seed_complete(cid, guests, now):
        return None
    days = int(rule.get('threshold') or _THRESHOLDS['snapshot_age'][0])
    cutoff = now - days * 86400
    skip_policy = rule.get('snapshot_ignore_policy', True)
    p = _Pass(guests)
    for vmid, snaps in st['guests'].items():
        r = guests.get(vmid) or {}
        if not _target_ok(rule, r.get('node') or '', vmid):
            continue
        obj = f"vm:{vmid}"
        who = _guest_label(guests, vmid)
        old = sorted((ts, name) for name, ts in snaps
                     if ts and ts < cutoff and not (skip_policy and name.startswith(POLICY_PREFIX)))
        if not old:
            p.fine[obj] = (f"Resolved: old snapshots on {who}",
                           f"{who} has no snapshot older than {days} days any more.")
            continue
        oldest_ts, oldest = old[0]
        age = int((now - oldest_ts) // 86400)
        p.firing[obj] = {
            'object': obj, 'target_type': 'vm', 'target_id': str(vmid), 'target_name': who,
            'target_key': obj, 'name': f"Old snapshots on {who}",
            'message': (f"{who} has {len(old)} snapshot(s) older than {days} days; the oldest, "
                        f"'{oldest}', is {age} days old"),
            'value': float(age), 'display': f"{age} days", 'severity': 'warning',
        }
    return p


def _eval_backup(rule, seen, cname, cid, now):
    uncovered = seen.get('backup')
    guests = seen.get('guests')
    if uncovered is None or not guests:
        return None                       # an empty guest list may be a read that failed
    grace = int(rule.get('threshold') or 0) * 3600
    skip = {t.lower() for t in (rule.get('backup_exclude_tags') or ())}
    tags = seen.get('tags') or {}
    since = (_backup.get(cid) or {}).get('since') or {}
    p = _Pass(guests)
    # what the rule watches; an open incident of a guest outside it (a template now, tagged
    # to be left out, on another node) closes without a word
    p.known = set()
    for vmid, r in guests.items():
        if not _target_ok(rule, r.get('node') or '', vmid) or (skip & tags.get(vmid, set())):
            continue
        obj = f"vm:{vmid}"
        p.known.add(obj)
        who = _guest_label(guests, vmid)
        if vmid not in uncovered:
            p.fine[obj] = (f"Resolved: {who} has a backup job", f"A backup job of {cname} covers {who} now.")
            continue
        if now - since.get(vmid, now) < grace:
            continue                      # new to the list: a job may still be on its way
        node, state = r.get('node') or '?', r.get('status') or 'unknown'
        p.firing[obj] = {
            'object': obj, 'target_type': 'vm', 'target_id': str(vmid), 'target_name': who,
            'target_key': obj, 'name': f"No backup job covers {who}",
            'message': f"{who} on node {node} ({state}) is in no backup job of {cname}",
            'value': 1.0, 'display': 'no backup job', 'severity': 'warning',
            'details': [('Node', node), ('Status', state)],
        }
    return p


def _eval_zfs(rule, seen, cname, cid):
    z = seen.get('zfs')
    st = _zfs.get(cid)
    if not z or st is None:
        return None
    errors_too = _int_in(rule.get('threshold'), 0, 1) != 1
    p = _Pass()
    # what the cluster still has: an incident of a pool its node no longer lists, or of
    # a node that left, closes without a word
    p.known = {f"zfs:{node}:{name}" for node, pools in st['pools'].items() for name in pools}
    for node in sorted(z['read']):
        if not _target_ok(rule, node, None):
            continue
        for name, health in sorted(st['pools'].get(node, {}).items()):
            obj = f"zfs:{node}:{name}"
            _at, detail = st['detail'].get((node, name), (0, None))
            has_errors = bool(detail and detail['has_errors'])
            if health == zpool.HEALTHY and not (errors_too and has_errors):
                if errors_too and detail is None:
                    continue              # its error counts not read yet: unknown, not fine
                p.fine[obj] = (f"Resolved: ZFS pool {name} on {node}",
                               f"ZFS pool {name} on node {node} is ONLINE"
                               + (" with no errors" if errors_too else '') + " again.")
                continue
            lvl = zpool.level(health, has_errors)
            devices = (detail or {}).get('devices') or []
            notes = [zpool.device_note(d)[:SUBJECT_MAX] for d in devices[:5]]
            if len(devices) > 5:
                notes.append(f"{len(devices) - 5} more")
            if detail and detail['data_errors']:
                notes.append(detail['data_errors'][:SUBJECT_MAX])
            if health == zpool.HEALTHY:
                name_of, display = f"ZFS pool {name} on {node} has errors", 'errors'
                changed = f"ZFS pool {name} on {node} is ONLINE again, with errors"
            else:
                display = health or 'UNKNOWN'
                name_of = f"ZFS pool {name} on {node} is {display}"
                changed = f"ZFS pool {name} on {node} is now {display}"
            rows = [('Node', node), ('Pool', name), ('State', display)]
            scan = (detail or {}).get('scan') or {}
            if scan.get('text'):
                rows.append(('Last scan', scan['text']))
            p.firing[obj] = {
                'object': obj, 'target_type': 'node', 'target_id': node, 'target_name': node,
                'target_key': f"node:{node}", 'name': name_of,
                'message': f"ZFS pool {name} on node {node} is {health or 'UNKNOWN'}"
                           + (' with errors' if health == zpool.HEALTHY else '')
                           + (f": {'; '.join(notes)}" if notes else ''),
                'value': float(lvl), 'display': display,
                'severity': 'critical' if lvl >= 3 or (detail and detail['data_errors']) else 'warning',
                'changed_name': changed, 'details': rows,
            }
    return p


def _eval_clock(rule, seen, cname):
    """One incident per node whose clock is surely off ours by more than the limit, closed
    once it is surely within it. With whole seconds from Proxmox the band between the two
    is too close to call, and an open incident stays as it is there."""
    entry = seen.get('clock')
    if not entry:
        return None
    limit = int(rule.get('threshold') or _THRESHOLDS['clock_drift'][0])
    readings = entry['nodes']
    p = _Pass()
    # a node that left takes its incident along; an offline one keeps it until it answers
    p.known = {f"clock:{n}" for n in entry['known']}
    # every node off the same way by about as much: likelier this host's clock than theirs
    ours = len(readings) >= 2 and (all(o - e > limit for o, e in readings.values())
                                   or all(o + e < -limit for o, e in readings.values()))
    if ours:
        offs = [o for o, _e in readings.values()]
        ours = max(offs) - min(offs) <= 2 * max(e for _o, e in readings.values()) + 1
    for node in sorted(readings):
        if not _target_ok(rule, node, None):
            continue
        off, err = readings[node]
        obj = f"clock:{node}"
        if abs(off) + err <= limit:
            p.fine[obj] = (f"Resolved: clock of {node}",
                           f"The clock of node {node} is within {limit} s of PegaProx again.")
            continue
        if abs(off) - err <= limit:
            continue
        way = 'ahead of' if off > 0 else 'behind'
        note = (f" Every node of {cname} is about as far off: the clock of the PegaProx host may "
                f"be the one that is wrong." if ours else '')
        p.firing[obj] = {
            'object': obj, 'target_type': 'node', 'target_id': node, 'target_name': node,
            'target_key': f"node:{node}", 'name': f"Clock of {node} is off by {abs(off):.0f} s",
            'message': f"The clock of node {node} is {abs(off):.1f} s {way} PegaProx, the limit is {limit} s."
                       + note,
            'value': round(off, 1), 'display': f"{off:+.1f} s",
            'severity': 'critical' if abs(off) - err >= CLOCK_CRITICAL else 'warning',
            'details': [('Node', node), ('Offset', f"{off:+.1f} s (± {err:.1f} s)"), ('Limit', f"{limit} s")],
        }
    return p


def _eval_restarts(rule, seen, cname, cid, now):
    """One incident per guest that started `threshold` times within the window; it closes
    once the guest stayed quiet for a whole window, so a loop is said once, not on every
    start in it."""
    guests = seen.get('guests')
    if seen.get('tasks') is None or not guests:
        return None                       # without this tick's tasks a quiet guest may not be quiet
    need = int(rule.get('threshold') or _THRESHOLDS['restart_loop'][0])
    minutes = _int_in(rule.get('restart_window_minutes'), 1, RESTART_WINDOW_MAX) or RESTART_WINDOW_DEFAULT
    since = now - minutes * 60
    starts = _starts.get(cid) or {}
    p = _Pass(guests)
    for vmid, r in guests.items():
        node = r.get('node') or ''
        if not _target_ok(rule, node, vmid):
            continue
        obj = f"vm:{vmid}"
        who = _guest_label(guests, vmid)
        recent = [s for s in starts.get(vmid, ()) if s > since]
        if not recent:
            p.fine[obj] = (f"Resolved: {who} stopped restarting",
                           f"{who} has not started again for {minutes} minutes.")
            continue
        if len(recent) < need:
            continue
        last = datetime.fromtimestamp(recent[-1]).strftime('%Y-%m-%d %H:%M:%S')
        p.firing[obj] = {
            'object': obj, 'target_type': 'vm', 'target_id': str(vmid), 'target_name': who,
            'target_key': obj, 'name': f"{who} is in a restart loop",
            'message': f"{who} on node {node or '?'} started {len(recent)} times in the last {minutes} minutes",
            'value': float(len(recent)), 'display': f"{len(recent)} starts", 'severity': 'warning',
            'details': [('Node', node or '?'), ('Starts', f"{len(recent)} in {minutes} minutes"),
                        ('Last start', last)],
        }
    return p


# ---------------------------------------------------------------------------
# incidents and notices
# ---------------------------------------------------------------------------

def _severity(rule, auto):
    sev = rule.get('severity')
    return sev if sev and sev != 'auto' else auto


def _cluster_name(cid):
    name = getattr(getattr(cluster_managers.get(cid), 'config', None), 'name', None)
    return name if isinstance(name, str) and name else cid


def _apply(rule, cid, p, mutes, now):
    """Compare what the rule found with its open incidents; write and return the notices."""
    rid, metric = rule.get('id', ''), rule.get('metric')
    db = get_db()
    cur = db.conn.cursor()
    rows = cur.execute(
        "SELECT id, object_key, current_value, message, severity, target_type, target_name "
        "FROM active_alerts WHERE cluster_id = ? AND alert_id = ? AND metric = ? AND resolved_at IS NULL",
        (cid, rid, metric)).fetchall()
    open_rows = {(r['object_key'] or ''): _row(r) for r in rows}
    stamp = datetime.now().isoformat()
    notices, muted = [], 0
    for obj, c in p.firing.items():
        sev = _severity(rule, c['severity'])
        row = open_rows.get(obj)
        if row is not None:
            if c.get('changed_name') and row['current_value'] is not None \
                    and float(row['current_value']) != float(c['value']):
                if mute_for(mutes, cid, rid, obj, c.get('target_key', '')):
                    muted += 1
                else:
                    notices.append(('changed', c))
            if row['message'] != c['message'] or row['severity'] != sev or \
                    (row['current_value'] is None or float(row['current_value']) != float(c['value'])):
                cur.execute("UPDATE active_alerts SET message=?, severity=?, current_value=?, last_fired_at=? "
                            "WHERE id=?", (c['message'], sev, c['value'], stamp, row['id']))
            continue
        if mute_for(mutes, cid, rid, obj, c.get('target_key', '')):
            muted += 1
            continue
        cur.execute(
            """INSERT INTO active_alerts
               (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, target_name,
                severity, message, current_value, threshold, operator, triggered_at, last_fired_at,
                escalation_step, object_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)""",
            (uuid.uuid4().hex[:12], f"{rid}:{cid}:{obj}", rid, cid, metric, c['target_type'],
             str(c.get('target_id') or ''), c['target_name'], sev, c['message'], c['value'],
             rule.get('threshold'), 'event', stamp, stamp, obj))
        notices.append(('firing', c))

    for obj, row in open_rows.items():
        if obj in p.firing:
            continue
        if obj in p.fine:
            cur.execute("UPDATE active_alerts SET resolved_at=?, resolved_by='clear' WHERE id=?",
                        (stamp, row['id']))
            if rule.get('notify_resolved', True) and not mute_for(
                    mutes, cid, rid, obj, _target_key_of(obj)):
                name, message = p.fine[obj]
                notices.append(('resolved', {'object': obj, 'name': name, 'message': message,
                                             'target_type': row['target_type'],
                                             'target_name': row['target_name'], 'value': 0,
                                             'display': 'resolved', 'severity': 'info'}))
            continue
        # the job left the cluster's list, the guest left the cluster: nothing to clear
        # any more, so the incident closes without a word
        vmid = object_vmid(obj)
        if (p.known is not None and obj not in p.known) or \
                (p.vmids is not None and vmid is not None and vmid not in p.vmids):
            cur.execute("UPDATE active_alerts SET resolved_at=?, resolved_by='gone' WHERE id=?",
                        (stamp, row['id']))
    db.conn.commit()
    return notices, muted


def _target_key_of(obj):
    vmid = object_vmid(obj)
    if vmid is not None:
        return f"vm:{vmid}"
    if obj.startswith(('task:', 'zfs:', 'clock:')):
        return f"node:{obj.split(':')[1]}"
    return ''


def _send(rule, cid, notices, settings):
    """Hand the notices to the one dispatch every alert uses. Past NOTICES_PER_RULE in a
    tick the rest of a kind goes out as one summary, so a rule switched on over a cluster
    with hundreds of matches does not send hundreds of mails."""
    from pegaprox.background import alerts as A
    if not notices:
        return 0
    cname = _cluster_name(cid)
    recipients = settings.get('alert_email_recipients') or []
    sent = 0
    by_kind = {}
    for kind, c in notices:
        by_kind.setdefault(kind, []).append(c)
    budget = NOTICES_PER_RULE
    for kind, items in by_kind.items():
        single, rest = items[:max(budget, 0)], items[max(budget, 0):]
        budget -= len(single)
        for c in single:
            _deliver(A, rule, cid, cname, kind, c, recipients)
            sent += 1
        if rest:
            names = ', '.join(c['name'] for c in rest[:10]) + (', ...' if len(rest) > 10 else '')
            word = {'firing': 'more alerts', 'resolved': 'more resolved', 'changed': 'more changes'}[kind]
            _deliver(A, rule, cid, cname, kind, {
                'object': '', 'target_type': 'cluster', 'target_name': cname,
                'name': f"{rule.get('name') or rule.get('metric')}: {len(rest)} {word}",
                'message': f"{len(rest)} {word} for this rule on {cname}: {names}",
                'value': len(rest), 'display': len(rest),
                'severity': 'info' if kind == 'resolved' else rest[0].get('severity', 'warning'),
            }, recipients)
            sent += 1
    return sent


def _deliver(A, rule, cid, cname, kind, c, recipients):
    if kind == 'changed':
        name = c.get('changed_name') or c['name']
    else:
        name = c['name']
    sev = 'info' if kind == 'resolved' else _severity(rule, c.get('severity', 'warning'))
    alert_data = {
        'alert_name': name, 'metric': rule.get('metric'), 'operator': 'event',
        'threshold': rule.get('threshold'), 'current_value': c.get('display', c.get('value')),
        'target_type': c.get('target_type') or 'cluster', 'target_name': c.get('target_name') or cname,
        'cluster_id': cid, 'severity': sev, 'timestamp': datetime.now().isoformat(),
        'message': c['message'], 'event': kind, 'object': c.get('object', ''),
    }
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    rows = [('Rule', rule.get('name') or rule.get('metric')), ('Cluster', cname), ('Time', stamp)]
    rows += list(c.get('details') or [])
    body = f"{c['message']}\n\n" + '\n'.join(f"{k}: {v}" for k, v in rows) + \
        "\n\nThis is an automated alert from PegaProx.\n"
    _e = html_lib.escape
    color = '#16a34a' if kind == 'resolved' else '#e74c3c'
    html_body = (
        f"<h2 style=\"color: {color};\">{_e(str(name))}</h2><p>{_e(str(c['message']))}</p>"
        "<table style=\"border-collapse: collapse; width: 100%; max-width: 500px;\">"
        + ''.join(f"<tr><td style=\"padding: 6px; border: 1px solid #ddd;\"><strong>{_e(str(k))}</strong></td>"
                  f"<td style=\"padding: 6px; border: 1px solid #ddd;\">{_e(str(v))}</td></tr>" for k, v in rows)
        + "</table><p style=\"color: #666; font-size: 12px; margin-top: 20px;\">"
          "This is an automated alert from PegaProx.</p>")
    prefix = '[PegaProx]' if kind == 'resolved' else '[PegaProx Alert]'
    A.dispatch_alert(rule, alert_data, f"{prefix} {name}", body, html_body, recipients)


def _close_orphans(rules):
    """Open incidents of an event rule that is gone, off, or on another metric now are
    closed without a word - nothing watches their condition any more."""
    live = {(r.get('id'), r.get('cluster_id'), r.get('metric'))
            for r in rules if r.get('enabled', True)}
    try:
        db = get_db()
        cur = db.conn.cursor()
        marks = ','.join('?' for _ in EVENT_METRICS)
        rows = cur.execute(
            f"SELECT id, alert_id, cluster_id, metric FROM active_alerts "
            f"WHERE resolved_at IS NULL AND metric IN ({marks})", EVENT_METRICS).fetchall()
        stale = [r['id'] for r in rows if (r['alert_id'], r['cluster_id'], r['metric']) not in live]
        if stale:
            stamp = datetime.now().isoformat()
            cur.executemany("UPDATE active_alerts SET resolved_at=?, resolved_by='rule' WHERE id=?",
                            [(stamp, i) for i in stale])
            db.conn.commit()
    except Exception as e:
        logging.debug(f"[AlertEvents] orphan sweep failed: {e}")


def rule_changed(cluster_id, rule_id):
    """A rule's matching changed (api/alerts.py): its open incidents are closed, and what
    still holds is raised again under the new terms on the next tick."""
    try:
        db = get_db()
        cur = db.conn.cursor()
        marks = ','.join('?' for _ in EVENT_METRICS)
        cur.execute(
            f"UPDATE active_alerts SET resolved_at=?, resolved_by='rule' "
            f"WHERE cluster_id=? AND alert_id=? AND resolved_at IS NULL AND metric IN ({marks})",
            (datetime.now().isoformat(), cluster_id, rule_id) + EVENT_METRICS)
        db.conn.commit()
    except Exception as e:
        logging.debug(f"[AlertEvents] reset of {rule_id} failed: {e}")
    _snaps.get(cluster_id, {}).pop('next_eval', None)
    _backup.get(cluster_id, {}).pop('next_at', None)
    _zfs.get(cluster_id, {}).pop('next_at', None)


def _evaluate(A, rule, cid, seen, mutes, settings, now):
    metric = rule.get('metric')
    cname = _cluster_name(cid)
    try:
        if metric == 'task_failed':
            p = _eval_tasks(rule, seen, cname)
        elif metric == 'ceph_health':
            p = _eval_ceph(rule, seen, cname)
        elif metric == 'replication':
            p = _eval_replication(rule, seen, cname, now)
        elif metric == 'backup_coverage':
            p = _eval_backup(rule, seen, cname, cid, now)
        elif metric == 'zfs_health':
            p = _eval_zfs(rule, seen, cname, cid)
        elif metric == 'clock_drift':
            p = _eval_clock(rule, seen, cname)
        elif metric == 'restart_loop':
            p = _eval_restarts(rule, seen, cname, cid, now)
        else:
            p = _eval_snapshots(rule, seen, cname, cid, now)
    except ValueError as e:
        A._record_eval(rule.get('id'), reason=f'pattern refused: {e}', cluster_id=cid, metric=metric)
        return
    if p is None:
        return                            # nothing read for it this tick: no change either way
    notices, muted = _apply(rule, cid, p, mutes, now)
    sent = _send(rule, cid, notices, settings)
    A._record_eval(rule.get('id'), cluster_id=cid, metric=metric, firing=len(p.firing),
                   fine=len(p.fine), notices=len(notices), sent=sent, muted=muted,
                   triggered=bool(p.firing),
                   reason=f"{len(p.firing)} firing, {len(notices)} new notice(s)"
                          + (f", {muted} muted" if muted else ''))


def check_event_alerts(now=None):
    """One tick of every event rule. alerts.alert_check_loop calls it on the active only."""
    from pegaprox.background import alerts as A
    from pegaprox.api.helpers import load_server_settings
    now = now or time.time()
    try:
        rules = [r for r in (A.load_alerts_config().get('alerts') or [])
                 if r.get('metric') in EVENT_METRICS]
    except Exception as e:
        logging.warning(f"[AlertEvents] rules unreadable: {e}")
        return
    _close_orphans(rules)
    prune_mutes(now)
    by_cluster = {}
    for r in rules:
        if r.get('enabled', True):
            by_cluster.setdefault(r.get('cluster_id') or '', []).append(r)
    if not by_cluster:
        return
    settings = load_server_settings() or {}
    mutes = active_mutes(now=now)

    order, jobs = [], []
    for cid, crules in by_cluster.items():
        mgr = cluster_managers.get(cid)
        if mgr is None or not getattr(mgr, 'is_connected', False) \
                or getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
            for r in crules:
                A._record_eval(r.get('id'), reason=f"cluster '{cid}' not connected (or not Proxmox VE)",
                               cluster_id=cid, metric=r.get('metric'))
            continue
        kinds = {r.get('metric') for r in crules}
        order.append((cid, mgr, crules))
        jobs.append(lambda c=cid, m=mgr, k=kinds: _read_cluster(c, m, k, now))
    if not jobs:
        return
    # every cluster at once, so one that does not answer holds up none of the others
    results = run_concurrent(jobs, timeout=90)

    plans = [(cid, mgr, (seen or {}).get('snapshot_plan') or [])
             for (cid, mgr, _), seen in zip(order, results)]
    read_now = _run_snapshot_reads([p for p in plans if p[2]], now)
    _run_zfs_reads(order, results, now)
    _run_clock_reads(order, results, now)

    for (cid, mgr, crules), seen in zip(order, results):
        if seen is None:
            for r in crules:
                A._record_eval(r.get('id'), reason='cluster did not answer in time',
                               cluster_id=cid, metric=r.get('metric'))
            continue
        snap_due = False
        if any(r.get('metric') == 'snapshot_age' for r in crules):
            st = _snaps.get(cid) or {}
            snap_due = cid in read_now or now >= st.get('next_eval', 0)
            guests = seen.get('guests') or {}
            done = sum(1 for v in guests if v in st.get('guests', {}))
            _note(cid, 'snapshots', True, f"snapshot lists read for {done} of {len(guests)} guests")
        if seen.get('tasks') is not None and any(r.get('metric') == 'restart_loop' for r in crules):
            _note(cid, 'restarts', True, f"start tasks of the last {RESTART_WINDOW_MAX // 60} hours kept "
                                         f"for {len(_starts.get(cid) or {})} guest(s)")
        if seen.get('backup') is not None and any(r.get('metric') == 'backup_coverage'
                                                  and r.get('backup_exclude_tags') for r in crules):
            seen['tags'] = guest_tags(cid, seen.get('resources'))
        for rule in crules:
            if rule.get('metric') == 'snapshot_age' and not snap_due:
                continue
            try:
                _evaluate(A, rule, cid, seen, mutes, settings, now)
            except Exception as e:
                logging.warning(f"[AlertEvents] rule {rule.get('id')} on {cid}: {e}")
                A._record_eval(rule.get('id'), reason=f'evaluation error: {e}', cluster_id=cid,
                               metric=rule.get('metric'))
        if snap_due and _seed_complete(cid, seen.get('guests') or {}, now):
            _snaps[cid]['next_eval'] = now + SNAPSHOT_EVAL_EVERY


def source_status(cluster_ids=None):
    """What each source last saw, per cluster, for /api/alerts/diagnostics."""
    out = {}
    for cid, sources in list(_status.items()):
        if cluster_ids is not None and cid not in cluster_ids:
            continue
        out[cid] = {k: dict(v) for k, v in sources.items()}
    return out
