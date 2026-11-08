# -*- coding: utf-8 -*-
"""Change plans: what the Change Guardian knows without a request around it.

NS Oct 2026 - a plan names a cluster, a scope (guests, or one of the cluster-wide kinds),
a window and the person who asked. A second admin approves it. Nothing here runs a change
and nothing blocks a direct action; the one consumer so far is config drift, which asks
for the approved plans of a cluster once per scan and marks the deviations that fall inside
one as planned (api/drift.py).

The table is shared with the standbys (core/ha.py SYNC_TABLES). All times are UTC and stored
as YYYY-MM-DDTHH:MM:SSZ, so comparing the strings compares the moments.
"""
import json
import logging
import re
from datetime import datetime, timedelta, timezone

from pegaprox.core.db import get_db

KINDS = ('guests', 'nodes', 'storage', 'network', 'firewall', 'ha', 'backup', 'access', 'cluster')
# everything but guests changes something all tenants of the cluster share
CLUSTER_WIDE = frozenset(KINDS) - {'guests'}
STATUSES = ('draft', 'submitted', 'approved', 'rejected', 'cancelled', 'done')

# status -> {action: status after}
TRANSITIONS = {
    'draft': {'submit': 'submitted', 'cancel': 'cancelled'},
    'submitted': {'approve': 'approved', 'reject': 'rejected', 'cancel': 'cancelled'},
    'approved': {'done': 'done', 'cancel': 'cancelled'},
}

WINDOW_MAX = timedelta(days=30)
# a form filled in slowly still starts "now"
START_SLACK = timedelta(minutes=5)
MAX_TARGETS = 200
TITLE_MAX = 200
TEXT_MAX = 4000
REASON_MAX = 500

# drift kind -> the plan kind that covers it (a plan of kind cluster covers all of them)
DRIFT_KIND_TO_PLAN = {
    'vm_config': 'guests',
    'storage': 'storage',
    'network': 'network',
    'cluster_options': 'cluster',
    'firewall': 'firewall',
    'ha_rules': 'ha',
    'backup_jobs': 'backup',
    'access': 'access',
}

_CTRL = re.compile(r'[\x00-\x1f\x7f]')
_VMID_MAX = 999999999


def parse_utc(value):
    """An aware UTC datetime from an ISO string (a missing offset reads as UTC), or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text[-1] in 'zZ':
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # an offset can push the year past 9999 or before 1: no date then, not a 500
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def iso_utc(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def now_utc():
    return datetime.now(timezone.utc)


def clean_scope(raw):
    """(scope, None) with the targets normalised, or (None, why not)."""
    if not isinstance(raw, dict):
        return None, 'scope must be an object with kind and targets'
    kind = raw.get('kind')
    if kind not in KINDS:
        return None, f"unknown scope kind, one of: {', '.join(KINDS)}"
    targets = raw.get('targets', [])
    if targets is None:
        targets = []
    if not isinstance(targets, list):
        return None, 'targets must be a list'
    if len(targets) > MAX_TARGETS:
        return None, f'at most {MAX_TARGETS} targets in one plan'
    if kind == 'cluster':
        # the whole cluster has nothing to pick from
        return {'kind': kind, 'targets': []}, None
    if kind == 'guests':
        ids = set()
        for t in targets:
            if isinstance(t, bool) or not isinstance(t, (int, str)):
                return None, 'guest targets are VMIDs'
            # isdigit() alone passes a superscript two, which int() then refuses with a 500
            if isinstance(t, str) and not (t.strip().isascii() and t.strip().isdigit()):
                return None, 'guest targets are VMIDs'
            n = int(t)
            if not 0 < n <= _VMID_MAX:
                return None, 'guest targets are VMIDs'
            ids.add(n)
        if not ids:
            return None, 'a plan for guests names at least one VMID'
        return {'kind': kind, 'targets': sorted(ids)}, None
    names = []
    for t in targets:
        if not isinstance(t, str) or not t.strip() or len(t) > 128 or _CTRL.search(t):
            return None, 'targets are names of at most 128 characters'
        if t.strip() not in names:
            names.append(t.strip())
    return {'kind': kind, 'targets': names}, None


def window_problem(start, end, now=None):
    """Why a window cannot be submitted, or ''. start and end are aware datetimes or None."""
    now = now or now_utc()
    if start is None or end is None:
        return 'a window needs a start and an end'
    if end <= start:
        return 'the window must end after it starts'
    if end - start > WINDOW_MAX:
        return 'a window is at most 30 days long'
    if start < now - START_SLACK:
        return 'the window cannot start in the past'
    return ''


def window_over(plan, now=None):
    end = parse_utc(plan.get('window_end'))
    return end is not None and end < (now or now_utc())


def derived_status(plan, now=None):
    """The stored status, with 'expired' for a plan nobody finished in its window."""
    st = plan.get('status')
    if st in ('draft', 'submitted', 'approved') and window_over(plan, now):
        return 'expired'
    return st


def covers(scope, kind, dscope):
    """Whether a plan's scope contains one drift deviation (drift kind and scope)."""
    pk = (scope or {}).get('kind')
    want = DRIFT_KIND_TO_PLAN.get(kind)
    if want is None:
        return False
    if pk == 'cluster':
        return True
    if pk != want:
        return False
    targets = scope.get('targets') or []
    dscope = str(dscope or '')
    if pk == 'guests':
        tail = dscope.rsplit('/', 1)[-1]
        return tail.isdigit() and int(tail) in targets
    if not targets:
        return True
    return any(dscope == t or dscope.startswith(t + '/') for t in targets)


def approved_in_window(cluster_id, now=None):
    """The approved plans of a cluster whose window holds `now`: one query, for a whole scan.
    Oldest approval first, so an event overlapping two plans always names the same one."""
    stamp = iso_utc(now or now_utc())
    try:
        c = get_db().conn.cursor()
        c.execute("SELECT id, title, scope FROM change_plans WHERE cluster_id=? AND status='approved' "
                  "AND window_start<=? AND window_end>=? ORDER BY approved_at, id",
                  (cluster_id, stamp, stamp))
        out = []
        for r in c.fetchall():
            try:
                scope = json.loads(r['scope'] or '{}')
            except ValueError:
                continue
            out.append({'id': r['id'], 'title': r['title'], 'scope': scope})
        return out
    except Exception as e:
        # a plan table that cannot be read links nothing; the deviation is recorded as before
        logging.warning(f"[changes] approved plans of {cluster_id} not read: {e}")
        return []


def link_for(plans, kind, dscope):
    """The id of the first plan in `plans` that covers this deviation, or None."""
    for p in plans or ():
        if covers(p['scope'], kind, dscope):
            return p['id']
    return None


def titles(ids):
    """{plan id: title} for the plans an event list points at."""
    ids = sorted({i for i in ids if i})
    if not ids:
        return {}
    try:
        c = get_db().conn.cursor()
        c.execute(f"SELECT id, title FROM change_plans WHERE id IN ({','.join('?' * len(ids))})", ids)
        return {r['id']: r['title'] for r in c.fetchall()}
    except Exception as e:
        logging.debug(f"[changes] titles not read: {e}")
        return {}
