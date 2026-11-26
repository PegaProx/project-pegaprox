# -*- coding: utf-8 -*-
"""The whole log and the outcome of every ESXi migration, kept past the process that ran it.

MK Nov 2026 (#1278) - a run lived in api/vmware.py's _vmware_migrations and nowhere else. The UI
got the last 20 lines of its log, a restart lost the run and its log together, and the registry
grew by every run until then, each one handed out again on every poll of the list. Now:

* the log of a run keeps every line up to LOG_MAX_LINES. Past that the first LOG_HEAD_LINES and
  the newest lines stay, with one line in between that says how many were left out. Lines are
  counted from the start of the run, so a reader that asks from line n gets the same lines from
  memory and from the table.
* each run has a row in v2p_migration_runs, written when its job starts, every FLUSH_SECONDS or
  FLUSH_LINES lines while it runs and once more when the job returns. Its log sits beside it in
  v2p_migration_log in chunks of LOG_CHUNK lines: a write sends the chunks that changed, never
  the whole log again.
* a finished run leaves the registry EVICT_AFTER seconds after its last write; the routes read
  it from the table from then on.
* a row that still says running while no task of this process holds it was cut off by a stop of
  PegaProx: it is marked interrupted the first time this process looks.
* the newest KEEP_RUNS runs of the last KEEP_DAYS days are kept, pruned when a run ends.

Both tables are per instance (core/ha.py LOCAL_TABLES): a run lives in the process of the
instance that started it, and a standby hands the reads of the migrations to the active.
Nothing here ever raises into a migration: a database that cannot be written costs the history,
not the run.
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta

from pegaprox.core.db import get_db

LOG_MAX_LINES = 20000
LOG_HEAD_LINES = 2000
LOG_CHUNK = 500
# one line of tool output can be a whole page; the rest of it is dropped
LINE_MAX_CHARS = 2000
FLUSH_LINES = 200
FLUSH_SECONDS = 10
# a write that failed while the run goes on is tried again after this, not on the next line:
# against a locked database each try waits out the busy timeout inside log()
RETRY_SECONDS = 60
EVICT_AFTER = 600
KEEP_RUNS = 500
KEEP_DAYS = 90
PAGE_DEFAULT = 50
PAGE_MAX = KEEP_RUNS
# lines one read of the log route hands out
READ_MAX_LINES = 5000
INTERRUPTED = 'interrupted'

_lock = threading.RLock()


def _now_iso():
    return datetime.now().isoformat()


def left_out_line(count):
    return (f"... {count} lines left out here - a migration log keeps its first {LOG_HEAD_LINES} "
            f"and its newest lines, {LOG_MAX_LINES} in all ...")


def _cut(line):
    if len(line) <= LINE_MAX_CHARS:
        return line
    return f"{line[:LINE_MAX_CHARS]} ... ({len(line) - LINE_MAX_CHARS} more characters)"


def _dropped(task):
    try:
        return max(0, int(getattr(task, 'log_dropped', 0) or 0))
    except (TypeError, ValueError):
        return 0


def _lines(task):
    lines = getattr(task, 'log_lines', None)
    return lines if isinstance(lines, list) else []


def total_lines(task):
    """How many lines the run has logged, the left out ones included."""
    dropped = _dropped(task)
    return len(_lines(task)) - (1 if dropped else 0) + dropped


def cap(task):
    """Keeps task.log_lines within LOG_MAX_LINES: the head, one line for what is left out, the
    newest lines. Drops whole chunks, so the kept tail always starts on a chunk of the table."""
    lines = task.log_lines
    dropped = _dropped(task)
    kept = len(lines) - (1 if dropped else 0)
    if kept <= LOG_MAX_LINES:
        return
    tail_at = LOG_HEAD_LINES + (1 if dropped else 0)
    n = -(-(kept - LOG_MAX_LINES) // LOG_CHUNK) * LOG_CHUNK
    del lines[tail_at:tail_at + n]
    dropped += n
    if tail_at == LOG_HEAD_LINES:
        lines.insert(LOG_HEAD_LINES, left_out_line(dropped))
    else:
        lines[LOG_HEAD_LINES] = left_out_line(dropped)
    task.log_dropped = dropped


def note_line(task):
    """After V2PMigrationTask.log() appended a line: cut it, cap the log, and write the run
    when a batch is due."""
    try:
        with _lock:
            lines = task.log_lines
            if lines and len(lines[-1]) > LINE_MAX_CHARS:
                lines[-1] = _cut(lines[-1])
            cap(task)
        h = getattr(task, '_hist', None)
        now = time.time()
        if isinstance(h, dict) and now >= h.get('retry', 0) and (
                total_lines(task) - h['saved'] >= FLUSH_LINES or now - h['at'] >= FLUSH_SECONDS):
            try:
                _flush(task, wait=False)
            except Exception as e:
                h['retry'] = time.time() + RETRY_SECONDS
                logging.warning(f"[V2P-HISTORY] could not save migration {getattr(task, 'id', '?')}, "
                                f"tried again in {RETRY_SECONDS} s: {e}")
    except Exception as e:
        logging.debug(f"[V2P-HISTORY] note_line: {e}")


# -- reading a log ----------------------------------------------------------------------------

def _read(segments, offset, limit):
    """(lines, next offset) from `segments`, [(first line, count, get(i, j))] in order. Where
    two segments do not meet, the gap reads as one left_out_line."""
    out, pos = [], offset
    for start, count, get in segments:
        if start + count <= pos:
            continue
        if start > pos:
            out.append(left_out_line(start - pos))
            pos = start
        room = limit - len(out)
        if room <= 0:
            break
        a = pos - start
        part = get(a, min(count, a + room))
        out.extend(part)
        pos += len(part)
        if len(out) >= limit:
            break
    return out, pos


def _live_segments(task):
    lines = _lines(task)
    dropped = _dropped(task)
    if not dropped:
        return [(0, len(lines), lambda a, b: lines[a:b])]
    head = min(LOG_HEAD_LINES, len(lines))
    tail = LOG_HEAD_LINES + 1
    return [(0, head, lambda a, b: lines[a:b]),
            (LOG_HEAD_LINES + dropped, max(0, len(lines) - tail),
             lambda a, b: lines[tail + a:tail + b])]


def _stored_segments(rows):
    segs = []
    for r in rows:
        try:
            part = json.loads(r['lines'] or '[]')
        except (TypeError, ValueError):
            part = []
        if not isinstance(part, list):
            part = []
        part = [str(x) for x in part]
        segs.append((int(r['chunk']) * LOG_CHUNK, len(part), lambda a, b, p=part: p[a:b]))
    return segs


def job_running(task):
    """Whether the job of a task in the registry still goes on. A failed run logs its clean up
    after its status turned, so a tracked one counts until its job returned."""
    if str(getattr(task, 'status', '') or '') == 'running':
        return True
    h = getattr(task, '_hist', None)
    return isinstance(h, dict) and not h.get('ended')


def read_live(task, offset=0, limit=READ_MAX_LINES):
    with _lock:
        total = total_lines(task)
        lines, nxt = _read(_live_segments(task), min(offset, total), limit)
    return {'lines': lines, 'next': max(nxt, offset), 'total': total, 'dropped': _dropped(task),
            'status': str(getattr(task, 'status', '') or ''), 'running': job_running(task)}


def read_stored(row, offset=0, limit=READ_MAX_LINES):
    total = int(row.get('log_total') or 0)
    start = min(offset, total)
    rows = get_db().conn.cursor().execute(
        'SELECT chunk, lines FROM v2p_migration_log WHERE run_id = ? AND chunk >= ? '
        'ORDER BY chunk LIMIT ?', (row['id'], start // LOG_CHUNK, limit // LOG_CHUNK + 2)).fetchall()
    lines, nxt = _read(_stored_segments(rows), start, limit)
    return {'lines': lines, 'next': max(nxt, offset), 'total': total,
            'dropped': int(row.get('log_dropped') or 0), 'status': row.get('status') or '',
            'running': False}


def whole_live(task):
    with _lock:
        return _read(_live_segments(task), 0, total_lines(task) + 2)[0]


def whole_stored(row):
    rows = get_db().conn.cursor().execute(
        'SELECT chunk, lines FROM v2p_migration_log WHERE run_id = ? ORDER BY chunk',
        (row['id'],)).fetchall()
    return _read(_stored_segments(rows), 0, int(row.get('log_total') or 0) + 2)[0]


# -- writing a run ----------------------------------------------------------------------------

def _slice(task, a, b):
    """Lines a..b of the run as counted from its start, None when they were left out."""
    lines = task.log_lines
    dropped = _dropped(task)
    if not dropped or b <= LOG_HEAD_LINES:
        return lines[a:b]
    if a >= LOG_HEAD_LINES + dropped:
        off = LOG_HEAD_LINES + 1 - (LOG_HEAD_LINES + dropped)
        return lines[a + off:b + off]
    return None


def _summary(task):
    try:
        d = task.to_dict()
    except Exception as e:
        logging.debug(f"[V2P-HISTORY] to_dict of {getattr(task, 'id', '?')}: {e}")
        d = {}
    return d if isinstance(d, dict) else {}


def _save(task):
    """The run's row, and the chunks of its log written since the last time."""
    h = task._hist
    with _lock:
        total = total_lines(task)
        dropped = _dropped(task)
        summary = _summary(task)
        chunks = []
        if total:
            for k in range(min(h['saved'], total) // LOG_CHUNK, (total - 1) // LOG_CHUNK + 1):
                part = _slice(task, k * LOG_CHUNK, min((k + 1) * LOG_CHUNK, total))
                if part is not None:
                    chunks.append((k, json.dumps(part, default=str)))
    started = getattr(task, 'started_at', None)
    started = started.isoformat() if hasattr(started, 'isoformat') else _now_iso()
    completed = getattr(task, 'completed_at', None)
    completed = completed.isoformat() if hasattr(completed, 'isoformat') else None
    conn = get_db().conn
    cur = conn.cursor()
    for k, text in chunks:
        cur.execute('INSERT OR REPLACE INTO v2p_migration_log (run_id, chunk, lines) VALUES (?, ?, ?)',
                    (task.id, k, text))
    if dropped != h['dropped']:
        cur.execute('DELETE FROM v2p_migration_log WHERE run_id = ? AND chunk >= ? AND chunk < ?',
                    (task.id, LOG_HEAD_LINES // LOG_CHUNK, (LOG_HEAD_LINES + dropped) // LOG_CHUNK))
    cur.execute(
        'INSERT OR REPLACE INTO v2p_migration_runs (id, vmware_id, vm_id, vm_name, target_cluster, '
        'status, phase, summary, log_total, log_dropped, started_at, updated_at, completed_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (task.id, str(getattr(task, 'vmware_id', '') or ''), str(getattr(task, 'vm_id', '') or ''),
         str(getattr(task, 'vm_name', '') or ''), str(getattr(task, 'target_cluster', '') or ''),
         str(getattr(task, 'status', '') or ''), str(getattr(task, 'phase', '') or ''),
         json.dumps(summary, default=str), total, dropped, started, _now_iso(), completed))
    conn.commit()
    h.update(saved=total, at=time.time(), dropped=dropped)


def _flush(task, wait=True):
    """_save, one at a time per run: the disk monitor of a copy logs from a thread of its own.
    A line that comes while its run is being written leaves the write to that one."""
    lk = task._hist.get('lock')
    if lk is not None and not lk.acquire(blocking=wait):
        return
    try:
        _save(task)
    finally:
        if lk is not None:
            lk.release()


def track(task):
    """When the job of a run starts: its row is written, and its log from here on in batches."""
    if isinstance(getattr(task, '_hist', None), dict):
        return
    task._hist = {'saved': 0, 'at': time.time(), 'dropped': 0, 'ended': None, 'done': None,
                  'retry': 0, 'lock': threading.Lock()}
    try:
        _flush(task)
    except Exception as e:
        task._hist['retry'] = time.time() + RETRY_SECONDS
        logging.warning(f"[V2P-HISTORY] could not save migration {getattr(task, 'id', '?')}: {e}")


def finish(task):
    """When the job of a run returned: the last write. The run may leave the registry
    EVICT_AFTER seconds after it, once it says it is over."""
    h = getattr(task, '_hist', None)
    if not isinstance(h, dict):
        return
    h['ended'] = time.time()
    try:
        _flush(task)
        h['done'] = time.time()
    except Exception as e:
        logging.warning(f"[V2P-HISTORY] could not save migration {getattr(task, 'id', '?')}: {e}")
        return
    try:
        prune()
    except Exception as e:
        logging.warning(f"[V2P-HISTORY] could not prune the migration history: {e}")


def evict(registry, lock, now=None):
    """Takes finished runs out of `registry` EVICT_AFTER seconds after their last write. A run
    whose last write failed stays: its log is nowhere else. Returns the ids taken out."""
    now = time.time() if now is None else now
    with lock:
        gone = []
        for mid, t in list(registry.items()):
            h = getattr(t, '_hist', None)
            if (isinstance(h, dict) and h.get('done') and now - h['done'] >= EVICT_AFTER
                    and str(getattr(t, 'status', '') or '') != 'running'):
                gone.append(mid)
        for mid in gone:
            registry.pop(mid, None)
    return gone


def prune():
    """The newest KEEP_RUNS runs of the last KEEP_DAYS days stay, and every running one."""
    conn = get_db().conn
    cur = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=KEEP_DAYS)).isoformat()
    ids = [r[0] for r in cur.execute(
        "SELECT id FROM v2p_migration_runs WHERE status != 'running' AND (started_at < ? OR id NOT IN "
        "(SELECT id FROM v2p_migration_runs ORDER BY started_at DESC, rowid DESC LIMIT ?))",
        (cutoff, KEEP_RUNS)).fetchall()]
    for i in range(0, len(ids), 200):
        part = ids[i:i + 200]
        marks = ','.join('?' * len(part))
        cur.execute(f'DELETE FROM v2p_migration_log WHERE run_id IN ({marks})', part)
        cur.execute(f'DELETE FROM v2p_migration_runs WHERE id IN ({marks})', part)
    if ids:
        conn.commit()
    return len(ids)


def mark_interrupted(live_ids):
    """Rows that say running while this process holds no task for them: PegaProx stopped
    while they ran. They read as interrupted from now on, with a line at the end of the log."""
    conn = get_db().conn
    cur = conn.cursor()
    rows = cur.execute("SELECT id, phase, summary, log_total FROM v2p_migration_runs "
                       "WHERE status = 'running'").fetchall()
    marked = 0
    for r in rows:
        if r['id'] in live_ids:
            continue
        phase = r['phase'] or '?'
        line = (f"[{datetime.now().strftime('%H:%M:%S')}] INTERRUPTED: PegaProx stopped while this "
                f"migration was in phase {phase} and it did not finish. Check the source guest on "
                f"ESXi and what was created on Proxmox before you start it again.")
        try:
            summary = json.loads(r['summary'] or '{}')
        except (TypeError, ValueError):
            summary = {}
        if not isinstance(summary, dict):
            summary = {}
        summary['status'] = INTERRUPTED
        summary['error'] = summary.get('error') or 'PegaProx stopped while this migration ran'
        summary['log'] = (list(summary.get('log') or []) + [line])[-20:]
        total = int(r['log_total'] or 0)
        k = total // LOG_CHUNK
        last = cur.execute('SELECT lines FROM v2p_migration_log WHERE run_id = ? AND chunk = ?',
                           (r['id'], k)).fetchone()
        try:
            part = json.loads(last['lines']) if last else []
        except (TypeError, ValueError):
            part = []
        part = (part if isinstance(part, list) else [])[:total - k * LOG_CHUNK] + [line]
        cur.execute('INSERT OR REPLACE INTO v2p_migration_log (run_id, chunk, lines) VALUES (?, ?, ?)',
                    (r['id'], k, json.dumps(part)))
        cur.execute("UPDATE v2p_migration_runs SET status = ?, summary = ?, log_total = ?, updated_at = ? "
                    "WHERE id = ? AND status = 'running'",
                    (INTERRUPTED, json.dumps(summary, default=str), total + 1, _now_iso(), r['id']))
        marked += 1
    if marked:
        conn.commit()
        logging.info(f"[V2P-HISTORY] {marked} ESXi migration(s) cut off by a stop of PegaProx "
                     f"marked interrupted")
    return marked


def sweep_once(live_ids):
    """mark_interrupted, once for the database of this process."""
    db = get_db()
    if getattr(db, '_v2p_swept', False):
        return
    try:
        mark_interrupted(set(live_ids))
        db._v2p_swept = True
    except Exception as e:
        logging.warning(f"[V2P-HISTORY] could not check for interrupted migrations: {e}")


# -- reading runs -----------------------------------------------------------------------------

def _row(r):
    d = dict(r)
    try:
        summary = json.loads(d.get('summary') or '{}')
    except (TypeError, ValueError):
        summary = {}
    d['summary'] = summary if isinstance(summary, dict) else {}
    return d


def load(mid):
    """The stored row of one run, its summary decoded, or None."""
    if not isinstance(mid, str) or not mid or len(mid) > 64:
        return None
    r = get_db().conn.cursor().execute('SELECT * FROM v2p_migration_runs WHERE id = ?', (mid,)).fetchone()
    return _row(r) if r is not None else None


def as_dict(row, with_log=True):
    """What the routes hand out for a stored run: what to_dict() said at its last write, with
    the status of the row (interrupted is only there)."""
    d = dict(row['summary'])
    d['id'] = row['id']
    d['status'] = row.get('status') or d.get('status')
    for k in ('vmware_id', 'vm_id', 'vm_name', 'target_cluster'):
        if not d.get(k) and row.get(k):
            d[k] = row[k]
    d['log'] = list(d.get('log') or []) if with_log else []
    d['log_total'] = int(row.get('log_total') or 0)
    return d


def page(exclude, visible, offset=0, limit=PAGE_DEFAULT):
    """(rows, more): a page of the stored runs the caller may see, newest first, without the
    ids in `exclude`. visible(target_cluster, vmware_id, vm_id) is asked per run; offset counts
    the runs the caller sees. Retention keeps the walk to about KEEP_RUNS rows."""
    cur = get_db().conn.cursor()
    keys = cur.execute('SELECT id, target_cluster, vmware_id, vm_id FROM v2p_migration_runs '
                       'ORDER BY started_at DESC, rowid DESC LIMIT ?', (KEEP_RUNS * 2,)).fetchall()
    picked, seen, more = [], 0, False
    for k in keys:
        if k['id'] in exclude or not visible(k['target_cluster'], k['vmware_id'], k['vm_id']):
            continue
        seen += 1
        if seen <= offset:
            continue
        if len(picked) >= limit:
            more = True
            break
        picked.append(k['id'])
    if not picked:
        return [], more
    marks = ','.join('?' * len(picked))
    rows = {r['id']: _row(r) for r in cur.execute(
        f'SELECT * FROM v2p_migration_runs WHERE id IN ({marks})', picked).fetchall()}
    return [rows[i] for i in picked if i in rows], more
