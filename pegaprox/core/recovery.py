# -*- coding: utf-8 -*-
"""Restore tests: what they check, which backups the weekly run takes, and how recoverable
each guest looks from what they found.

core/backup_verify.py restores a backup to a test guest, isolates it, boots it, checks it
and removes it again. This module holds what that engine is told and what comes of it:

  recovery_targets    per cluster the defaults (RTO, isolation, test bridge and storage,
                      boot timeout) and the checks; per guest and per tag what differs from
                      them. Each field is taken from the guest, else from the first of its
                      tags that sets it (by tag name), else from the cluster.
  restore_test_marks  per guest the last test, the last one that passed (which backup, how
                      long restore, boot and checks took, what was checked) and the last
                      failure with its cause.

Both tables are shared with the standbys (core/ha.py SYNC_TABLES): the run history in
backup_verifications stays with the instance that ran the test, the marks go to whichever
instance leads next, so it does not see every guest as never tested.

The newest backups of each guest come from the backup storages of the cluster: a shared
storage is listed once, through one online node, a local one on every node it is on. A
read is kept for BACKUPS_FRESH seconds and shared by the report, the weekly run and
anything else that asks.

The weekly run (background/restore_tests.py) reads its policy from the pegaprox_kv row
'pbs_verify_schedule' that the auto-verify dialog writes, and keeps where it stands in
'pbs_verify_schedule_state'.

MK Oct 2026
"""

import heapq
import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from pegaprox.core.db import get_db
from pegaprox.utils.concurrent import run_concurrent

TEST_TAG = 'pegaprox-verify'
SKIP_TAGS = (TEST_TAG,)

ISOLATIONS = ('link_down', 'bridge')
AGENT_MODES = ('auto', 'require', 'off')
DEFAULTS = {'rto_minutes': None, 'agent': 'auto', 'ports': [], 'command': '',
            'isolation': 'link_down', 'test_bridge': '', 'test_storage': '', 'boot_timeout': 180}
# what a guest or a tag may set; the rest is the cluster's alone
GUEST_FIELDS = ('rto_minutes', 'agent', 'ports', 'command')
CLUSTER_FIELDS = GUEST_FIELDS + ('isolation', 'test_bridge', 'test_storage', 'boot_timeout')

RTO_MAX = 10080              # minutes
PORTS_MAX = 20
COMMAND_MAX = 500
BOOT_MIN, BOOT_MAX = 30, 1800
RULES_MAX = 2000             # guest and tag rules per cluster
STALE_DAYS = 30

_BRIDGE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,31}$')
_STORAGE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,63}$')
_TAG_RE = re.compile(r'^[\w.+-]{1,64}$')
_CTRL_RE = re.compile(r'[\x00-\x1f\x7f]')

BACKUPS_FRESH = 600
BACKUPS_PER_GUEST = 20
BACKUP_READS_MAX = 300       # storage listings of one cluster per read
BACKUP_READS_PARALLEL = 8
BACKUP_READ_TIMEOUT = 30
_SHARED_TYPES = ('pbs', 'nfs', 'cifs', 'cephfs', 'glusterfs')

SCHEDULE_KEY = 'pbs_verify_schedule'
STATE_KEY = 'pbs_verify_schedule_state'
DAYS = ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun')
SCHEDULE_DEFAULT = {'enabled': False, 'weekly_count': 5, 'day': 'sun', 'hour': 4,
                    'scope': 'latest_per_vm', 'max_age_days': 30}
SCOPES = ('latest_per_vm', 'all')

_backups = {}                # cid -> {'at', 'guests': {vmid: [backup]}, 'nodes', 'partial'}
_backup_locks = {}
_backup_guard = threading.Lock()
_marks_lock = threading.Lock()


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _whole(value, lo, hi):
    """value as a whole number within lo..hi, None for anything else (a bool is no number)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if not isinstance(value, int) or not lo <= value <= hi:
        return None
    return value


def guest_tags(raw):
    """The tags of a resource row ('a;b' as Proxmox lists them), lower case."""
    return {t.strip().lower() for t in re.split(r'[;, ]', str(raw or '')) if t.strip()}


def backup_kind(volid):
    """'qemu' or 'lxc' by the backup's name, None when it does not say."""
    v = str(volid or '')
    if '/ct/' in v or 'vzdump-lxc-' in v or 'vzdump-openvz-' in v or v.endswith('.lxc.tar'):
        return 'lxc'
    if '/vm/' in v or 'vzdump-qemu-' in v:
        return 'qemu'
    return None


def backup_time(volid, fallback=None):
    """When a backup was taken, as an epoch, from its name: a PBS snapshot names it in UTC,
    a vzdump file in the node's local time (read here as ours). `fallback` when neither."""
    v = str(volid or '')
    m = re.search(r'/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z', v)
    try:
        if m:
            return int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')
                       .replace(tzinfo=timezone.utc).timestamp())
        m = re.search(r'-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})\.', v)
        if m:
            return int(datetime.strptime(m.group(1), '%Y_%m_%d-%H_%M_%S').timestamp())
    except (ValueError, OverflowError):
        pass
    return fallback


# ---------------------------------------------------------------------------
# what is checked: recovery_targets
# ---------------------------------------------------------------------------

def _decode(row):
    out = {k: row[k] for k in row.keys()}
    try:
        out['ports'] = json.loads(out['ports']) if out.get('ports') is not None else None
    except (TypeError, ValueError):
        out['ports'] = None
    return out


def load_rules(cluster_id):
    """{'cluster': row or None, 'guest': {vmid: row}, 'tag': {tag: row}} of one cluster.
    Raises when the table cannot be read: a caller that decides on it has to know."""
    rows = get_db().conn.execute(
        'SELECT * FROM recovery_targets WHERE cluster_id = ? LIMIT ?',
        (cluster_id, RULES_MAX + 1)).fetchall()
    out = {'cluster': None, 'guest': {}, 'tag': {}}
    for r in rows:
        d = _decode(r)
        if d['scope'] == 'cluster':
            out['cluster'] = d
        elif d['scope'] == 'guest' and str(d['scope_key']).isdigit():
            out['guest'][int(d['scope_key'])] = d
        elif d['scope'] == 'tag':
            out['tag'][str(d['scope_key'])] = d
    return out


def cluster_settings(rules):
    """The cluster's own settings with the defaults filled in."""
    row = rules.get('cluster') or {}
    out = {}
    for k in CLUSTER_FIELDS:
        v = row.get(k)
        out[k] = DEFAULTS[k] if v is None else v
    if out['isolation'] not in ISOLATIONS or (out['isolation'] == 'bridge' and not out['test_bridge']):
        out['isolation'] = 'link_down'
    return out


def plan_for(cluster_id, vmid, tags=None, rules=None, mgr=None):
    """What a restore test of guest `vmid` does: isolation, storage, boot timeout, checks
    and the RTO it is held to, with where each came from ('guest', 'tag:<name>', 'cluster'
    or 'default'). `tags` of the guest; read from the manager's resource cache when None."""
    if rules is None:
        rules = load_rules(cluster_id)
    if tags is None:
        tags = set()
        try:
            for r in (mgr.get_vm_resources(max_age=60) or []) if mgr is not None else []:
                if str(r.get('vmid')) == str(vmid):
                    tags = guest_tags(r.get('tags'))
                    break
        except Exception:
            pass
    base = cluster_settings(rules)
    plan = {k: base[k] for k in ('isolation', 'test_bridge', 'test_storage', 'boot_timeout')}
    source = {}
    try:
        guest = rules['guest'].get(int(vmid))
    except (TypeError, ValueError):
        guest = None
    tag_rows = [(t, rules['tag'][t]) for t in sorted(tags or ()) if t in rules['tag']]
    cluster = rules.get('cluster') or {}
    for k in GUEST_FIELDS:
        value, where = None, 'default'
        if guest is not None and guest.get(k) is not None:
            value, where = guest[k], 'guest'
        else:
            for t, row in tag_rows:
                if row.get(k) is not None:
                    value, where = row[k], f'tag:{t}'
                    break
            else:
                if cluster.get(k) is not None:
                    value, where = cluster[k], 'cluster'
        plan[k] = DEFAULTS[k] if value is None else value
        source[k] = where
    plan['ports'] = [p for p in (plan['ports'] or []) if _whole(p, 1, 65535)][:PORTS_MAX]
    plan['command'] = str(plan['command'] or '')
    if plan['agent'] not in AGENT_MODES:
        plan['agent'] = 'auto'
    plan['rto_seconds'] = int(plan.pop('rto_minutes') or 0) * 60
    plan['source'] = source
    return plan


def clean_rule(body, scope):
    """The fields of a rule from a request body: (fields, None) or (None, why it is refused).
    A field sent as null goes back to what the next level up says; a field left out is not
    changed (the caller merges)."""
    if not isinstance(body, dict):
        return None, 'the request body must be a JSON object'
    allowed = CLUSTER_FIELDS if scope == 'cluster' else GUEST_FIELDS
    unknown = sorted(k for k in body if k not in allowed and k not in ('scope', 'key'))
    if unknown:
        return None, f"not a setting here: {', '.join(unknown)}"
    out = {}
    for k in allowed:
        if k not in body:
            continue
        v = body[k]
        if v is None or (k in ('command', 'test_bridge', 'test_storage') and v == ''):
            out[k] = None
            continue
        if k == 'rto_minutes':
            v = _whole(v, 1, RTO_MAX)
            if v is None:
                return None, f'rto_minutes is a whole number from 1 to {RTO_MAX}'
        elif k == 'boot_timeout':
            v = _whole(v, BOOT_MIN, BOOT_MAX)
            if v is None:
                return None, f'boot_timeout is a whole number of seconds from {BOOT_MIN} to {BOOT_MAX}'
        elif k == 'agent':
            if v not in AGENT_MODES:
                return None, f"agent is one of {', '.join(AGENT_MODES)}"
        elif k == 'isolation':
            if v not in ISOLATIONS:
                return None, "isolation is 'link_down' or 'bridge'"
        elif k == 'ports':
            if not isinstance(v, list) or len(v) > PORTS_MAX:
                return None, f'ports is a list of at most {PORTS_MAX} port numbers'
            ports = []
            for p in v:
                n = _whole(p, 1, 65535)
                if n is None:
                    return None, 'a port is a whole number from 1 to 65535'
                if n not in ports:
                    ports.append(n)
            v = sorted(ports)
        elif k == 'command':
            if not isinstance(v, str) or len(v) > COMMAND_MAX or _CTRL_RE.search(v) or not v.strip():
                return None, f'command is one line of at most {COMMAND_MAX} characters'
            v = v.strip()
        elif k == 'test_bridge':
            if not isinstance(v, str) or not _BRIDGE_RE.match(v):
                return None, 'test_bridge is the name of a bridge or VNet (vmbr9, testnet)'
        elif k == 'test_storage':
            if not isinstance(v, str) or not _STORAGE_RE.match(v):
                return None, 'test_storage is the ID of a storage'
        out[k] = v
    return out, None


def scope_key(scope, key):
    """The key of a guest or tag rule in its stored form, None when it is none."""
    if scope == 'guest':
        n = _whole(key, 100, 999999999)
        return str(n) if n is not None else None
    if scope == 'tag':
        k = str(key or '').strip().lower()
        return k if _TAG_RE.match(k) and k != TEST_TAG else None
    if scope == 'cluster':
        return ''
    return None


def save_rule(cluster_id, scope, key, fields, user):
    """Merge `fields` into the rule (cluster defaults when scope is 'cluster') and store it.
    A guest or tag rule with nothing left in it is removed. Returns the stored rule, None
    when it was removed. Raises ValueError when the cluster has RULES_MAX rules already."""
    db = get_db()
    conn = db.conn
    cur = conn.cursor()
    row = cur.execute('SELECT * FROM recovery_targets WHERE cluster_id = ? AND scope = ? AND scope_key = ?',
                      (cluster_id, scope, key)).fetchone()
    merged = _decode(row) if row else {}
    if scope != 'cluster' and not row:
        n = cur.execute("SELECT COUNT(*) FROM recovery_targets WHERE cluster_id = ? AND scope != 'cluster'",
                        (cluster_id,)).fetchone()[0]
        if n >= RULES_MAX:
            raise ValueError(f'a cluster has at most {RULES_MAX} guest and tag rules')
    merged.update(fields)
    if merged.get('isolation') == 'bridge' and not merged.get('test_bridge'):
        raise ValueError('an isolated test bridge needs its name (test_bridge)')
    own = CLUSTER_FIELDS if scope == 'cluster' else GUEST_FIELDS
    if scope != 'cluster' and all(merged.get(k) is None for k in own):
        cur.execute('DELETE FROM recovery_targets WHERE cluster_id = ? AND scope = ? AND scope_key = ?',
                    (cluster_id, scope, key))
        conn.commit()
        return None
    values = {k: merged.get(k) for k in CLUSTER_FIELDS}
    if scope != 'cluster':
        for k in CLUSTER_FIELDS:
            if k not in GUEST_FIELDS:
                values[k] = None
    cur.execute(
        'INSERT OR REPLACE INTO recovery_targets (cluster_id, scope, scope_key, rto_minutes, agent, '
        'ports, command, isolation, test_bridge, test_storage, boot_timeout, updated_at, updated_by) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (cluster_id, scope, key, values['rto_minutes'], values['agent'],
         None if values['ports'] is None else json.dumps(values['ports']), values['command'],
         values['isolation'], values['test_bridge'], values['test_storage'], values['boot_timeout'],
         datetime.now().isoformat(timespec='seconds'), str(user or '')[:64]))
    conn.commit()
    out = dict(values, scope=scope, scope_key=key)
    return out


def delete_rule(cluster_id, scope, key):
    """True when there was such a rule."""
    conn = get_db().conn
    cur = conn.execute('DELETE FROM recovery_targets WHERE cluster_id = ? AND scope = ? AND scope_key = ?',
                       (cluster_id, scope, key))
    conn.commit()
    return cur.rowcount > 0


def rule_view(row):
    keep = ('scope', 'scope_key', 'updated_at', 'updated_by') + (
        CLUSTER_FIELDS if row.get('scope') == 'cluster' else GUEST_FIELDS)
    return {k: row.get(k) for k in keep}


# ---------------------------------------------------------------------------
# what came of it: restore_test_marks
# ---------------------------------------------------------------------------

def load_marks(cluster_id):
    """{vmid: mark} of one cluster. Raises when the table cannot be read."""
    rows = get_db().conn.execute('SELECT * FROM restore_test_marks WHERE cluster_id = ?',
                                 (cluster_id,)).fetchall()
    out = {}
    for r in rows:
        d = {k: r[k] for k in r.keys()}
        try:
            d['ok_checks'] = json.loads(d['ok_checks']) if d.get('ok_checks') else []
        except (TypeError, ValueError):
            d['ok_checks'] = []
        out[int(d['vmid'])] = d
    return out


def failure_cause(status):
    """One line on why a test did not pass."""
    if status.get('error'):
        return str(status['error'])[:300]
    if not status.get('restore_ok'):
        return 'the restore did not complete'
    if not status.get('boot_ok'):
        return 'the test guest did not come up in time'
    bad = [c for c in status.get('checks') or [] if c.get('ok') is False]
    if bad:
        c = bad[0]
        what = {'agent': 'guest agent', 'port': f"port {c.get('target')}",
                'command': 'check command'}.get(c.get('check'), c.get('check'))
        return f"{what}: {c.get('detail') or 'failed'}"[:300] + (f' (+{len(bad) - 1} more)' if len(bad) > 1 else '')
    return 'failed'


def note_result(status, at=None):
    """A test is over: the guest's mark takes it. Never raises."""
    try:
        result = status.get('status')
        if result not in ('passed', 'failed', 'error'):
            return
        cid, vmid = status.get('cluster_id'), int(status.get('vmid'))
        at = at or time.time()
        conn = get_db().conn
        with _marks_lock:
            row = conn.execute('SELECT * FROM restore_test_marks WHERE cluster_id = ? AND vmid = ?',
                               (cid, vmid)).fetchone()
            mark = {k: row[k] for k in row.keys()} if row else {}
            mark.update(last_at=at, last_result=result, last_task=str(status.get('id') or '')[:40])
            if result == 'passed':
                mark.update(ok_at=at, ok_backup_ts=status.get('backup_ts'),
                            ok_seconds=status.get('measured_seconds'),
                            ok_rto_seconds=int(status.get('rto_seconds') or 0),
                            ok_checks=json.dumps(status.get('checks') or [])[:8000])
            else:
                mark.update(fail_at=at, fail_cause=failure_cause(status))
            conn.execute(
                'INSERT OR REPLACE INTO restore_test_marks (cluster_id, vmid, last_at, last_result, '
                'last_task, ok_at, ok_backup_ts, ok_seconds, ok_rto_seconds, ok_checks, fail_at, '
                'fail_cause) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                (cid, vmid, mark.get('last_at'), mark.get('last_result'), mark.get('last_task'),
                 mark.get('ok_at'), mark.get('ok_backup_ts'), mark.get('ok_seconds'),
                 mark.get('ok_rto_seconds'), mark.get('ok_checks'), mark.get('fail_at'),
                 mark.get('fail_cause')))
            conn.commit()
    except Exception as e:
        logging.error(f"[RECOVERY] could not note the restore test of {status.get('vmid')}: {e}")


# ---------------------------------------------------------------------------
# the backups of each guest
# ---------------------------------------------------------------------------

def _get(mgr, path, timeout=10, params=None):
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json{path}", timeout=timeout, params=params)
    except Exception as e:
        logging.debug(f"[RECOVERY] GET {path} failed: {e}")
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json().get('data')
    except Exception:
        return None


def _read_backups(mgr):
    nodes = _get(mgr, '/nodes')
    storages = _get(mgr, '/storage')
    if not isinstance(nodes, list) or not isinstance(storages, list):
        return None
    online = sorted(str(n.get('node')) for n in nodes if n.get('node') and n.get('status') == 'online')
    if not online:
        return None
    reads = []
    for st in storages:
        content = {c.strip() for c in str(st.get('content') or '').split(',')}
        name = st.get('storage')
        if 'backup' not in content or not name or st.get('disable'):
            continue
        allowed = {n.strip() for n in str(st.get('nodes') or '').split(',') if n.strip()}
        here = [n for n in online if not allowed or n in allowed]
        if not here:
            continue
        if st.get('shared') or st.get('type') in _SHARED_TYPES:
            reads.append((here[0], name, True))
        else:
            reads.extend((n, name, False) for n in here)
    reads = reads[:BACKUP_READS_MAX]

    def one(node, storage):
        return _get(mgr, f'/nodes/{node}/storage/{storage}/content', timeout=BACKUP_READ_TIMEOUT,
                    params={'content': 'backup'})
    guests, failed = {}, 0
    for i in range(0, len(reads), BACKUP_READS_PARALLEL):
        chunk = reads[i:i + BACKUP_READS_PARALLEL]
        results = run_concurrent([lambda n=n, s=s: one(n, s) for n, s, _sh in chunk],
                                 timeout=BACKUP_READ_TIMEOUT + 5)
        for (node, storage, shared), items in zip(chunk, results):
            if not isinstance(items, list):
                failed += 1
                continue
            for it in items:
                vmid, volid = str(it.get('vmid') or ''), str(it.get('volid') or '')
                ctime = it.get('ctime')
                if not vmid.isdigit() or not volid or not isinstance(ctime, (int, float)) or not ctime:
                    continue
                kind = it.get('subtype') if it.get('subtype') in ('qemu', 'lxc') else backup_kind(volid)
                if not kind:
                    continue
                guests.setdefault(int(vmid), []).append({
                    'volid': volid, 'ctime': int(ctime), 'kind': kind, 'storage': storage,
                    'node': None if shared else node,
                    'verified': ((it.get('verification') or {}).get('state') if isinstance(it.get('verification'), dict) else None),
                })
    for vmid, items in guests.items():
        items.sort(key=lambda b: -b['ctime'])
        # one copy of a shared listing, newest first
        seen, kept = set(), []
        for b in items:
            if b['volid'] in seen:
                continue
            seen.add(b['volid'])
            kept.append(b)
            if len(kept) >= BACKUPS_PER_GUEST:
                break
        guests[vmid] = kept
    if reads and failed == len(reads):
        return None
    return {'guests': guests, 'nodes': online, 'partial': failed > 0,
            'storages': len({s for _n, s, _sh in reads})}


def guest_backups(cluster_id, mgr, max_age=BACKUPS_FRESH, now=None):
    """The backups of each guest of a cluster, newest first, as one read of its backup
    storages no older than max_age: {'at', 'guests': {vmid: [{volid, ctime, kind, storage,
    node}]}, 'nodes': [online], 'partial'}. node is None for a backup on shared storage.
    None when nothing could be read and no earlier read is kept."""
    now = time.time() if now is None else now

    def fresh():
        hit = _backups.get(cluster_id)
        if hit and 0 <= now - hit['at'] < max_age:
            return hit
        return None
    hit = fresh()
    if hit:
        return hit
    with _backup_guard:
        lock = _backup_locks.setdefault(cluster_id, threading.Lock())
    with lock:
        hit = fresh()
        if hit:
            return hit
        got = _read_backups(mgr)
        if got is None:
            return _backups.get(cluster_id)
        got['at'] = now
        _backups[cluster_id] = got
        return got


def forget_backups(cluster_id=None):
    if cluster_id is None:
        _backups.clear()
    else:
        _backups.pop(cluster_id, None)


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------

def report_guests(resources):
    """{vmid: resource row} of the guests a report or a run looks at: no templates and no
    test guest of a restore test."""
    out = {}
    for r in resources or []:
        if r.get('type') not in ('qemu', 'lxc') or r.get('template'):
            continue
        if not str(r.get('vmid', '')).isdigit():
            continue
        if guest_tags(r.get('tags')) & set(SKIP_TAGS):
            continue
        out[int(r['vmid'])] = r
    return out


def _iso(ts):
    return datetime.fromtimestamp(ts).isoformat(timespec='seconds') if ts else None


def guest_row(vmid, r, mark, backups, plan, sla_hours, now, stale_days=STALE_DAYS):
    """One guest of the report."""
    mark = mark or {}
    newest = (backups or [None])[0] if backups is not None else None
    ok_at, fail_at, last_at = mark.get('ok_at'), mark.get('fail_at'), mark.get('last_at')
    measured = mark.get('ok_seconds')
    rto = int(plan.get('rto_seconds') or 0)
    if not ok_at or measured is None or not rto:
        rto_state = 'none'
    else:
        rto_state = 'met' if float(measured) <= rto else 'missed'
    if backups is None:
        rpo_state, newest_age = 'unknown', None
    elif newest is None:
        rpo_state, newest_age = 'no_backup', None
    else:
        newest_age = max(0.0, now - newest['ctime'])
        if not sla_hours:
            rpo_state = 'disabled'
        elif newest_age >= sla_hours * 3600:
            rpo_state = 'breached'
        elif newest_age >= sla_hours * 3600 * 0.8:
            rpo_state = 'warning'
        else:
            rpo_state = 'ok'
    if not last_at and not ok_at:
        state = 'never'
    elif mark.get('last_result') in ('failed', 'error') and (not ok_at or (fail_at or 0) >= ok_at):
        state = 'failing'
    elif ok_at and now - ok_at > stale_days * 86400:
        state = 'stale'
    elif rto_state == 'missed':
        state = 'rto_missed'
    else:
        state = 'ok'
    ok_backup = mark.get('ok_backup_ts')
    return {
        'vmid': vmid, 'name': r.get('name') or '', 'type': r.get('type'), 'node': r.get('node') or '',
        'tags': sorted(guest_tags(r.get('tags'))),
        'state': state,
        'last_test_at': _iso(last_at), 'last_result': mark.get('last_result'),
        'last_success_at': _iso(ok_at),
        'last_success_age_days': round((now - ok_at) / 86400, 1) if ok_at else None,
        'tested_backup_at': _iso(ok_backup),
        'tested_backup_age_hours': round((now - ok_backup) / 3600, 1) if ok_backup else None,
        'measured_seconds': round(float(measured), 1) if ok_at and measured is not None else None,
        'rto_seconds': rto or None, 'rto_state': rto_state,
        'last_checks': (mark.get('ok_checks') or []) if ok_at else [],
        'newest_backup_at': _iso(newest['ctime']) if newest else None,
        'newest_backup_age_hours': round(newest_age / 3600, 1) if newest_age is not None else None,
        'backup_count': len(backups) if backups is not None else None,
        'sla_hours': sla_hours or None, 'rpo_state': rpo_state,
        'last_failure_at': _iso(fail_at), 'last_failure_cause': mark.get('fail_cause') if fail_at else None,
    }


STATES = ('ok', 'stale', 'failing', 'never', 'rto_missed')


def cluster_report(cluster_id, mgr, now=None, stale_days=STALE_DAYS, refresh=False):
    """(rows, meta) for every guest of one cluster, by state and VMID. The caller scopes the
    rows. One read of the guest list (the manager's cache), one of the backups (shared, see
    guest_backups) and two queries."""
    now = time.time() if now is None else now
    resources = mgr.get_vm_resources(max_age=60) or []
    guests = report_guests(resources)
    marks = load_marks(cluster_id)
    rules = load_rules(cluster_id)
    idx = guest_backups(cluster_id, mgr, max_age=60 if refresh else BACKUPS_FRESH, now=now)
    sla = int(getattr(getattr(mgr, 'config', None), 'backup_sla_max_age_hours', 0) or 0)
    rows = []
    for vmid, r in guests.items():
        plan = plan_for(cluster_id, vmid, tags=guest_tags(r.get('tags')), rules=rules)
        backups = None if idx is None else (idx['guests'].get(vmid) or [])
        rows.append(guest_row(vmid, r, marks.get(vmid), backups, plan, sla, now, stale_days))
    order = {s: i for i, s in enumerate(('failing', 'never', 'stale', 'rto_missed', 'ok'))}
    rows.sort(key=lambda x: (order.get(x['state'], 9), x['vmid']))
    meta = {'backups_read_at': _iso(idx['at']) if idx else None,
            'backups_state': 'unreadable' if idx is None else ('partial' if idx.get('partial') else 'ok'),
            'sla_hours': sla or None, 'stale_days': stale_days,
            'settings': cluster_settings(rules)}
    return rows, meta


def summary(rows):
    out = {s: 0 for s in STATES}
    out.update(total=len(rows), rpo_breached=0, no_backup=0)
    for r in rows:
        out[r['state']] = out.get(r['state'], 0) + 1
        if r['rpo_state'] == 'breached':
            out['rpo_breached'] += 1
        elif r['rpo_state'] == 'no_backup':
            out['no_backup'] += 1
    return out


CSV_COLUMNS = ('cluster', 'vmid', 'name', 'type', 'node', 'state', 'last_success_at', 'tested_backup_at',
               'measured_seconds', 'rto_seconds', 'rto_state', 'newest_backup_at', 'newest_backup_age_hours',
               'sla_hours', 'rpo_state', 'last_failure_at', 'last_failure_cause')


def csv_text(rows):
    import csv
    import io
    from pegaprox.utils.sanitization import sanitize_csv_field
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([sanitize_csv_field(r.get('cluster_name') or r.get('cluster_id') or ''), r['vmid'],
                    sanitize_csv_field(r['name']), r['type'], sanitize_csv_field(r['node']), r['state'],
                    r['last_success_at'] or '', r['tested_backup_at'] or '',
                    '' if r['measured_seconds'] is None else r['measured_seconds'],
                    r['rto_seconds'] or '', r['rto_state'], r['newest_backup_at'] or '',
                    '' if r['newest_backup_age_hours'] is None else r['newest_backup_age_hours'],
                    r['sla_hours'] or '', r['rpo_state'], r['last_failure_at'] or '',
                    sanitize_csv_field(r['last_failure_cause'] or '')])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# the weekly run: its policy and where it stands
# ---------------------------------------------------------------------------

def _kv(cur):
    cur.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')


def _kv_read(key):
    conn = get_db().conn
    cur = conn.cursor()
    _kv(cur)
    conn.commit()
    row = cur.execute('SELECT v FROM pegaprox_kv WHERE k = ?', (key,)).fetchone()
    if not row or not row[0]:
        return None
    try:
        v = json.loads(row[0])
    except (TypeError, ValueError):
        return None
    return v if isinstance(v, dict) else None


def _kv_write(key, value):
    conn = get_db().conn
    cur = conn.cursor()
    _kv(cur)
    cur.execute('INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)', (key, json.dumps(value)))
    conn.commit()


def _sane_schedule(raw):
    out = dict(SCHEDULE_DEFAULT)
    raw = raw if isinstance(raw, dict) else {}
    out['enabled'] = raw.get('enabled') is True
    for k, lo, hi in (('weekly_count', 1, 50), ('hour', 0, 23), ('max_age_days', 1, 365)):
        n = _whole(raw.get(k), lo, hi)
        if n is not None:
            out[k] = n
    if raw.get('day') in DAYS:
        out['day'] = raw['day']
    if raw.get('scope') in SCOPES:
        out['scope'] = raw['scope']
    return out


def load_schedule():
    """The policy of the weekly run as stored, every field in range."""
    return _sane_schedule(_kv_read(SCHEDULE_KEY))


def clean_schedule(body, current):
    """(policy, None) from a PUT body on top of `current`, or (None, why it is refused)."""
    if not isinstance(body, dict):
        return None, 'the request body must be a JSON object'
    out = dict(current)
    if 'enabled' in body:
        if not isinstance(body['enabled'], bool):
            return None, 'enabled is true or false'
        out['enabled'] = body['enabled']
    for k, lo, hi in (('weekly_count', 1, 50), ('hour', 0, 23), ('max_age_days', 1, 365)):
        if k in body:
            n = _whole(body[k], lo, hi)
            if n is None:
                return None, f'{k} is a whole number from {lo} to {hi}'
            out[k] = n
    if 'day' in body:
        if body['day'] not in DAYS:
            return None, f"day is one of {', '.join(DAYS)}"
        out['day'] = body['day']
    if 'scope' in body:
        if body['scope'] not in SCOPES:
            return None, "scope is 'latest_per_vm' or 'all'"
        out['scope'] = body['scope']
    return out, None


def save_schedule(policy, before=None, now=None):
    """Store the policy. Switched on, or moved to another day or hour: the run waits for the
    next slot from now on, a slot before the change is not caught up."""
    _kv_write(SCHEDULE_KEY, policy)
    before = before or {}
    moved = (policy['enabled'] and (not before.get('enabled') or before.get('day') != policy['day']
                                    or before.get('hour') != policy['hour']))
    if moved:
        state = load_state()
        state['armed_wall'] = time.time() if now is None else now
        save_state(state)


def load_state():
    return _kv_read(STATE_KEY) or {}


def save_state(state):
    _kv_write(STATE_KEY, state)


def latest_slot(policy, now):
    """The latest start of the run at or before `now` (both on the schedule_now() clock)."""
    at = now.replace(hour=policy['hour'], minute=0, second=0, microsecond=0)
    at -= timedelta(days=(at.weekday() - DAYS.index(policy['day'])) % 7)
    if at > now:
        at -= timedelta(days=7)
    return at


def due_slot(policy, state, now, at_wall):
    """The slot the run owes now, or None. at_wall turns a wall time into the schedule_now()
    clock (ha.schedule_at). Only the latest slot is owed: a run that was missed (the
    process was down, the instance was a standby) is made up once, never once per week it
    missed. A slot before the policy was switched on or moved is not owed."""
    if not policy.get('enabled'):
        return None
    slot = latest_slot(policy, now)
    fired, armed = state.get('fired_wall'), state.get('armed_wall')
    if isinstance(fired, (int, float)) and at_wall(fired) >= slot:
        return None
    if isinstance(armed, (int, float)) and at_wall(armed) > slot:
        return None
    return slot


def next_slot(policy, state, now, at_wall):
    if not policy.get('enabled'):
        return None
    owed = due_slot(policy, state, now, at_wall)
    return owed if owed is not None else latest_slot(policy, now) + timedelta(days=7)


def pick(policy, managers, now=None, busy=()):
    """The backups the run tests: up to weekly_count of them over every connected Proxmox
    cluster, those of the guests whose last test is oldest first (never tested before
    all), no backup older than max_age_days. scope 'latest_per_vm' takes the newest backup
    of a guest, 'all' any backup in the window other than the one last tested, newest
    first. `busy`: (cluster_id, vmid) with a test running. A guest whose node is not
    online is left out. One read of the guests and one of the backups per cluster."""
    now = time.time() if now is None else now
    cutoff = now - policy['max_age_days'] * 86400
    heap = []
    for cid, mgr in list(managers.items()):
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox' or not getattr(mgr, 'is_connected', False):
            continue
        try:
            guests = report_guests(mgr.get_vm_resources(max_age=60) or [])
            idx = guest_backups(cid, mgr, now=now)
            marks = load_marks(cid)
        except Exception as e:
            logging.warning(f"[RECOVERY] {cid} left out of the restore test run: {e}")
            continue
        if not idx:
            continue
        online = set(idx.get('nodes') or ())
        for vmid, r in guests.items():
            if (cid, vmid) in busy:
                continue
            items = [b for b in idx['guests'].get(vmid) or [] if b['ctime'] >= cutoff and b['kind'] == r.get('type')]
            if not items:
                continue
            mark = marks.get(vmid) or {}
            if policy['scope'] == 'latest_per_vm':
                items = items[:1]
            else:
                items = [b for b in items if b['ctime'] != mark.get('ok_backup_ts')] or items[:1]
            last = float(mark.get('last_at') or 0)
            for b in items:
                node = b['node'] or r.get('node')
                if node not in online:
                    continue
                entry = (last, -b['ctime'], cid, vmid, b['volid'])
                item = {'cluster_id': cid, 'vmid': vmid, 'name': r.get('name') or '', 'type': r.get('type'),
                        'node': node, 'volid': b['volid'], 'backup_ts': b['ctime'], 'storage': b['storage'],
                        'tags': sorted(guest_tags(r.get('tags')))}
                if len(heap) < policy['weekly_count']:
                    heapq.heappush(heap, (_Neg(entry), item))
                elif _Neg(entry) > heap[0][0]:
                    heapq.heapreplace(heap, (_Neg(entry), item))
    picked = sorted(heap, key=lambda h: h[0].v)
    return [item for _k, item in picked]


class _Neg:
    """Orders the reverse way, so the heap of the n best keeps its worst on top."""
    __slots__ = ('v',)

    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return self.v > other.v

    def __gt__(self, other):
        return self.v < other.v

    def __eq__(self, other):
        return self.v == other.v
