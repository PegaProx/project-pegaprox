# -*- coding: utf-8 -*-
"""The runs of a backup job, read from the task lists of the nodes.

MK Oct 2026 - Proxmox keeps no history per backup job. /cluster/backup lists the jobs and
when each runs next, and the vzdump task a job starts carries no job id: the scheduler
passes job-id, but vzdump leaves it out of the command line it logs. That command line is
the first thing the task logs, with the guests it selects and the storage it writes to.
A task belongs to a job when it selects what the job selects and writes where the job
writes, so a run started by hand with the job's settings counts as well. A job without a
node runs on every node in the same minute; those tasks are one run.

The first lines of a task never change, so what they say is kept per task: reading two
weeks of a large cluster costs those reads once. The guests of a run come from its logs
and are read only when somebody opens the run.
"""

import logging
import re
import shlex
import threading
import time
from collections import OrderedDict

# UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:
UPID_RE = re.compile(r'UPID:(?P<node>[A-Za-z0-9][A-Za-z0-9.-]{0,62}):[0-9A-Fa-f]{1,16}:[0-9A-Fa-f]{1,16}:'
                     r'(?P<start>[0-9A-Fa-f]{1,16}):(?P<type>[A-Za-z0-9_-]{1,32}):[^:/\s]{0,64}:[^:/\s]{1,128}:')

# the tasks of one run start within this of the first one, one per node
GROUP_SECONDS = 120
DAYS_DEFAULT, DAYS_MAX = 14, 60
RUNS_DEFAULT, RUNS_MAX = 20, 100
TASKS_PER_NODE = 500
HEADER_LINES = 12
# first lines one call reads at most; the next call goes on where it stopped
HEADER_BUDGET = 400
READ_WIDTH = 16
LIST_SECONDS = 20
LOG_PAGE = 5000
LOG_MAX_LINES = 100000

_HEADERS_KEPT = 20000
_GUESTS_KEPT = 256
_LISTS_KEPT = 2000

_START = 'starting new backup job: '
_STARTING = re.compile(r'Starting Backup of VM (\d+) \((qemu|lxc|openvz)\)')
_FINISHED = re.compile(r'Finished Backup of VM (\d+) \(([^)]*)\)')
_FAILED = re.compile(r'Backup of VM (\d+) failed - (.*)$')
_SIZE = re.compile(r'archive file size: (\S+)')
_ARCHIVE = re.compile(r"creating (?:vzdump|Proxmox Backup Server) archive '([^']+)'")
# a task that fails before vzdump logs its command line says why, mostly a backup storage
# it cannot activate: "could not activate storage 'pbs1', ..."
_EARLY_STORAGE = re.compile(r"storage '([^'\s]{1,128})'")

_lock = threading.Lock()
_headers = OrderedDict()   # (cluster, upid) -> {'opts': {...}} or {} for a task that is no backup job
_guests = OrderedDict()    # (cluster, upid) -> (guests, status) of a finished task
_lists = {}                # (cluster, node, days) -> (read at, tasks)


def _remember(store, key, value, cap):
    with _lock:
        store[key] = value
        store.move_to_end(key)
        while len(store) > cap:
            store.popitem(last=False)


def _recall(store, key):
    with _lock:
        return store.get(key)


def reset_for_tests():
    with _lock:
        _headers.clear()
        _guests.clear()
        _lists.clear()


# --- what a job selects ----------------------------------------------------------------------

def parse_command(line):
    """The options of the command line a vzdump task logs first, None when `line` is not it.
    The guests named on it are under 'vmid'."""
    i = str(line or '').find(_START)
    if i < 0:
        return None
    try:
        words = shlex.split(line[i + len(_START):])
    except ValueError:
        return None
    if not words or words[0] != 'vzdump':
        return None
    opts, vmids, key = {}, [], None
    for w in words[1:]:
        if w.startswith('--') and len(w) > 2:
            if key is not None:
                opts[key] = ''
            key = w[2:]
        elif key is not None:
            opts[key] = w
            key = None
        elif w.isdigit():
            vmids.append(w)
    if key is not None:
        opts[key] = ''
    opts['vmid'] = ','.join(vmids)
    return opts


def _ids(value):
    return frozenset(int(x) for x in re.split(r'[\s,;]+', str(value or '')) if x.isdigit())


def selection(cfg):
    """What a job, or a command line, backs up: ('all', excluded), ('pool', name) or ('vmid', ids)"""
    if str(cfg.get('all', '')).strip().lower() in ('1', 'true', 'yes'):
        return ('all', _ids(cfg.get('exclude')))
    pool = str(cfg.get('pool') or '').strip()
    if pool:
        return ('pool', pool)
    return ('vmid', _ids(cfg.get('vmid')))


def belongs(job, opts):
    """Whether a task that logged `opts` is a run of `job`: same guests, same storage"""
    if not opts:
        return False
    sel = selection(job)
    if sel == ('vmid', frozenset()):
        return False
    return (selection(opts) == sel
            and str(job.get('storage') or '').strip() == str(opts.get('storage') or '').strip())


def may_be(job, task):
    """False when the task list alone shows a task is none of `job`'s: a task that backs up
    one guest names it, and that guest is outside what the job selects"""
    tid = str(task.get('id') or '')
    if not tid.isdigit():
        return True
    kind, what = selection(job)
    if kind == 'vmid':
        return int(tid) in what
    if kind == 'all':
        return int(tid) not in what
    return True


# --- reads -------------------------------------------------------------------------------------

def _base(mgr):
    return f'https://{mgr.host}:{mgr.api_port}/api2/json'


def node_tasks(mgr, cluster_id, node, days):
    """The vzdump tasks of a node in the last `days`, newest first; None when unreadable.
    Kept for LIST_SECONDS, a refresh does not ask every node again."""
    key = (cluster_id, node, days)
    with _lock:
        hit = _lists.get(key)
    if hit and time.time() - hit[0] < LIST_SECONDS:
        return hit[1]
    try:
        r = mgr._api_get(f'{_base(mgr)}/nodes/{node}/tasks', timeout=15,
                         params={'typefilter': 'vzdump', 'source': 'all', 'limit': TASKS_PER_NODE,
                                 'since': int(time.time()) - days * 86400})
        if r.status_code != 200:
            return None
        data = r.json().get('data') or []
    except Exception as e:
        logging.debug(f"[BACKUP-RUNS] task list of {node} unreadable: {e}")
        return None
    out = []
    for t in data:
        if not isinstance(t, dict):
            continue
        m = UPID_RE.fullmatch(str(t.get('upid') or ''))
        if not m or m.group('type') != 'vzdump' or m.group('node') != node:
            continue
        try:
            start = int(t.get('starttime') or int(m.group('start'), 16))
        except (TypeError, ValueError):
            continue
        end = t.get('endtime')
        out.append({'upid': t['upid'], 'node': node, 'start': start,
                    'end': int(end) if isinstance(end, (int, float)) and end else None,
                    'status': str(t.get('status') or '') if end else '',
                    'user': str(t.get('user') or ''), 'id': str(t.get('id') or '')})
    out.sort(key=lambda t: t['start'], reverse=True)
    with _lock:
        _lists[key] = (time.time(), out)
        if len(_lists) > _LISTS_KEPT:
            for k in sorted(_lists, key=lambda k: _lists[k][0])[:len(_lists) - _LISTS_KEPT]:
                _lists.pop(k, None)
    return out


def _log_page(mgr, node, upid, start, limit):
    r = mgr._api_get(f'{_base(mgr)}/nodes/{node}/tasks/{upid}/log', timeout=30,
                     params={'start': start, 'limit': limit})
    if r.status_code != 200:
        return None
    out = []
    for entry in r.json().get('data') or []:
        if isinstance(entry, dict):
            try:
                n = int(entry.get('n') or 0)
            except (TypeError, ValueError):
                n = 0
            out.append((n, str(entry.get('t') or '')))
    return out


def header(mgr, cluster_id, task):
    """What the task logged first: {'opts': ...}, {'early_storage': name} or {} when it ended
    without a command line (with or without naming the storage it failed on), {'waiting':
    True} while it runs and has not logged one yet (the global lock), None when the log
    cannot be read. All but the last two are kept."""
    key = (cluster_id, task['upid'])
    hit = _recall(_headers, key)
    if hit is not None:
        return hit
    try:
        lines = _log_page(mgr, task['node'], task['upid'], 0, HEADER_LINES)
    except Exception as e:
        logging.debug(f"[BACKUP-RUNS] first lines of {task['upid']} unreadable: {e}")
        return None
    if lines is None:
        return None
    for _n, text in lines:
        opts = parse_command(text)
        if opts is not None:
            got = {'opts': opts}
            _remember(_headers, key, got, _HEADERS_KEPT)
            return got
    if task.get('end') is None:
        return {'waiting': True}
    early = {}
    for _n, text in lines:
        m = _EARLY_STORAGE.search(text)
        if m:
            early = {'early_storage': m.group(1)}
            break
    _remember(_headers, key, early, _HEADERS_KEPT)
    return early


def failed_early(job, head, task):
    """Whether a task that ended before it logged a command line is a run of `job`: its error
    names the storage the job writes to, and a guest it names is one the job selects.

    MK Oct 2026 - a scheduled run whose storage could not be activated (the commonest real
    failure) logs only the error, so it was nobody's run and the job looked fine."""
    storage = (head or {}).get('early_storage')
    if not storage or storage != str(job.get('storage') or '').strip():
        return False
    return may_be(job, task)


# --- runs --------------------------------------------------------------------------------------

def group(tasks):
    """The tasks of a job as runs, newest first"""
    runs = []
    for t in sorted(tasks, key=lambda t: (t['start'], t['node'])):
        cur = runs[-1] if runs else None
        if cur is None or t['start'] - cur['start'] > GROUP_SECONDS or t['node'] in cur['nodes']:
            cur = {'start': t['start'], 'nodes': set(), 'tasks': []}
            runs.append(cur)
        cur['nodes'].add(t['node'])
        cur['tasks'].append(t)
    out = [_summary(r) for r in runs]
    out.reverse()
    return out


def _over_ok(status):
    return status == 'OK' or status.startswith('WARNINGS')


def _summary(run):
    tasks = run['tasks']
    running = any(t['end'] is None for t in tasks)
    failed = sum(1 for t in tasks if t['end'] is not None and not _over_ok(t['status']))
    warned = any(t['status'].startswith('WARNINGS') for t in tasks)
    state = 'running' if running else 'failed' if failed else 'warning' if warned else 'ok'
    end = None if running else max(t['end'] for t in tasks)
    return {'id': tasks[0]['upid'], 'start': run['start'], 'end': end,
            'duration': (end - run['start']) if end else None, 'state': state,
            'failed_tasks': failed, 'scheduled': all(t.get('scheduled') for t in tasks),
            'tasks': [{k: t[k] for k in ('node', 'upid', 'start', 'end', 'status', 'user')} for t in tasks]}


def _online_nodes(mgr, only):
    try:
        status = mgr.get_node_status() or {}
    except Exception:
        status = {}
    if only:
        names = [only]
    else:
        names = sorted(n for n in status if isinstance(n, str))
    up, down = [], []
    for n in names:
        info = status.get(n) if isinstance(status.get(n), dict) else {}
        if info.get('offline') or (info and str(info.get('status', 'online')) != 'online'):
            down.append(n)
        else:
            up.append(n)
    return up, down


def job_runs(mgr, cluster_id, job, days=DAYS_DEFAULT, limit=RUNS_DEFAULT):
    """The newest `limit` runs of `job` in the last `days`.

    {'runs', 'partial', 'unread_nodes'}: partial when some first lines were not read in
    this call (the budget, or a node that did not answer), unread_nodes the nodes that
    were offline or whose task list could not be read."""
    from pegaprox.utils.concurrent import run_per_node
    only = str(job.get('node') or '').strip()
    up, down = _online_nodes(mgr, only)
    lists = run_per_node({n: (lambda nn: node_tasks(mgr, cluster_id, nn, days)) for n in up},
                         max_concurrent=READ_WIDTH, timeout=40) if up else {}
    unread = sorted(down + [n for n in up if lists.get(n) is None])
    cands = sorted((t for n in up for t in (lists.get(n) or []) if may_be(job, t)),
                   key=lambda t: t['start'], reverse=True)

    budget, partial, matched, runs = HEADER_BUDGET, False, [], []
    for i in range(0, len(cands), 64):
        chunk = cands[i:i + 64]
        need = [t for t in chunk if _recall(_headers, (cluster_id, t['upid'])) is None]
        if len(need) > budget:
            need, partial = need[:budget], True
        budget -= len(need)
        read = {}
        if need:
            by_upid = {t['upid']: t for t in need}
            read = run_per_node({u: (lambda uu: header(mgr, cluster_id, by_upid[uu])) for u in by_upid},
                                max_concurrent=READ_WIDTH, timeout=60)
        for t in chunk:
            h = read.get(t['upid']) or _recall(_headers, (cluster_id, t['upid']))
            if h is None:
                partial = True
                continue
            if belongs(job, h.get('opts')) or failed_early(job, h, t):
                matched.append(dict(t, scheduled=str((h.get('opts') or {}).get('quiet', '')) == '1'))
        runs = group(matched)
        # what is left is older than the oldest run asked for: it cannot change those
        if len(runs) > limit and runs[limit - 1]['start'] - GROUP_SECONDS > chunk[-1]['start']:
            break
    return {'runs': runs[:limit], 'partial': partial, 'unread_nodes': unread}


# --- the guests of a task --------------------------------------------------------------------

def _new_guest(vmid, kind, n, task):
    return {'vmid': vmid, 'type': 'lxc' if kind in ('lxc', 'openvz') else 'qemu', 'node': task['node'],
            'upid': task['upid'], 'state': 'running', 'started': '', 'ended': '', 'took': '',
            'error': '', 'size': '', 'archive': '', 'first': n, 'last': n}


def guests_of(mgr, cluster_id, task):
    """(guests, status) of one vzdump task, from its log; status is '' while it runs.
    None when the log cannot be read. Kept once the task is over."""
    key = (cluster_id, task['upid'])
    hit = _recall(_guests, key)
    if hit is not None:
        return hit
    guests, cur, status, start = {}, None, '', 0
    while start < LOG_MAX_LINES:
        try:
            page = _log_page(mgr, task['node'], task['upid'], start, LOG_PAGE)
        except Exception as e:
            logging.debug(f"[BACKUP-RUNS] log of {task['upid']} unreadable: {e}")
            return None
        if page is None:
            return None
        for n, text in page:
            if text.startswith('TASK '):
                status = text[5:].strip()
                if status.startswith('ERROR:'):
                    status = status[6:].strip() or 'failed'
                cur = None
                continue
            m = _STARTING.search(text)
            if m:
                cur = _new_guest(int(m.group(1)), m.group(2), n, task)
                guests[cur['vmid']] = cur
                continue
            m = _FAILED.search(text)
            if m:
                vmid = int(m.group(1))
                g = guests.get(vmid)
                if g is None:
                    g = guests[vmid] = _new_guest(vmid, 'qemu', n, task)
                g['state'], g['error'], g['last'] = 'failed', m.group(2).strip()[:500], n
                cur = g
                continue
            if cur is None:
                continue
            cur['last'] = n
            m = _FINISHED.search(text)
            if m and int(m.group(1)) == cur['vmid']:
                cur['state'], cur['took'] = 'ok', m.group(2)
            elif 'Backup started at ' in text:
                cur['started'] = text.split('Backup started at ', 1)[1].strip()
            elif 'Backup finished at ' in text or 'Failed at ' in text:
                cur['ended'] = text.split(' at ', 1)[1].strip()
                cur = None
            elif _SIZE.search(text):
                cur['size'] = _SIZE.search(text).group(1)
            elif _ARCHIVE.search(text):
                cur['archive'] = _ARCHIVE.search(text).group(1).rsplit('/', 1)[-1]
        if len(page) < LOG_PAGE:
            break
        start += len(page)
    out = sorted(guests.values(), key=lambda g: g['vmid'])
    if status:
        for g in out:
            if g['state'] == 'running':
                g['state'] = 'unknown'
        _remember(_guests, key, (out, status), _GUESTS_KEPT)
    return out, status


def guest_lines(mgr, node, upid, first, last):
    """The log lines first..last (numbered from 1) of a task, at most LOG_PAGE of them"""
    first = max(1, int(first))
    count = max(1, min(int(last) - first + 1, LOG_PAGE))
    page = _log_page(mgr, node, upid, first - 1, count)
    if page is None:
        return None
    return [text for _n, text in page][:count]
