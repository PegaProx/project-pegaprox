# -*- coding: utf-8 -*-
"""One time-ordered list of what happened on a cluster: the event shape, times, the page and
the links between events.

MK Oct 2026 - the readers live with the route (api/timeline.py), since each source is read
under its own access rules for the caller. What needs no request is here.

Every time leaves as UTC with its offset. The sources store theirs in three ways: server-local
without an offset (most of them), UTC without one (the site recovery events), or with an
offset; the Proxmox tasks count epoch seconds.

The links are correlation and nothing more: an event on the same guest or node a short while
before an alert, a failed task, a node going offline or a failed backup is listed under it as
having happened shortly before. Nothing here says one caused the other.
"""

import bisect
import re
from datetime import datetime, timedelta, timezone

KINDS = ('audit', 'alert', 'migration', 'balancer', 'drift', 'task', 'backup', 'backup_verify',
         'node', 'site_recovery', 'rolling_update', 'syslog', 'incident')
SEVERITIES = ('info', 'warning', 'critical')
WINDOW_DEFAULT = timedelta(hours=24)
WINDOW_MAX = timedelta(days=30)
LIMIT_DEFAULT, LIMIT_MAX = 100, 500
# minutes before an anchor that count as shortly before it
CORRELATE_DEFAULT, CORRELATE_MAX = 10, 120
LINKS_MAX = 5
# a number past this is no epoch second of ours (the year 2100)
_EPOCH_MAX = 4102444800
_EPOCH = re.compile(r'\d{1,12}(?:\.\d{1,6})?')


def parse_when(value):
    """A time of the query as aware UTC: ISO 8601 (without an offset it is UTC) or epoch
    seconds. ValueError when it is neither."""
    text = str(value if value is not None else '').strip()
    if not text or len(text) > 40:
        raise ValueError('not a time')
    try:
        if _EPOCH.fullmatch(text):
            seconds = float(text)
            if seconds > _EPOCH_MAX:
                raise ValueError('not a time')
            return datetime.fromtimestamp(seconds, timezone.utc)
        dt = datetime.fromisoformat(text)
    except (OverflowError, OSError) as e:
        raise ValueError('not a time') from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def stored_time(value, naive='local'):
    """A time as a source stored it, as aware UTC, or None. naive: how a time without an
    offset is meant, 'local' (the server's zone) or 'utc'."""
    if value in (None, ''):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc)
        dt = datetime.fromisoformat(str(value).strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc) if naive == 'utc' else dt.astimezone()
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def bound(dt, naive='local'):
    """dt as the text a source's stored times compare with, to the second and without an
    offset: server-local, or UTC for a source that stores UTC."""
    at = dt.astimezone(timezone.utc) if naive == 'utc' else dt.astimezone()
    return at.strftime('%Y-%m-%dT%H:%M:%S')


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')


def severity_of(value, default='info'):
    s = str(value or '').lower()
    if s in ('critical', 'crit', 'error', 'err', 'emergency', 'alert', 'major', 'high'):
        return 'critical'
    if s in ('warning', 'warn', 'minor', 'medium'):
        return 'warning'
    return default if s not in SEVERITIES else s


def event(kind, ref, at, *, cluster, severity='info', title='', node=None, nodes=(), guest=None,
          guest_name='', details='', what='', params=None, route='', anchor=False):
    """One event. ref is its id in its source; the event id is unique across sources."""
    # to the second, as it is handed out: the cursor of the next page is that time
    at = at.replace(microsecond=0)
    ev = {
        'id': f'{kind}:{ref}', 'time': iso(at), 'kind': kind,
        'severity': severity if severity in SEVERITIES else 'info',
        'cluster': cluster, 'node': node or None, 'guest': guest, 'guest_name': guest_name or '',
        'title': str(title or '')[:300], 'details': str(details or '')[:500],
        'what': what or kind, 'params': params or {},
        'source': {'route': route, 'id': str(ref)},
    }
    ev['_at'] = at
    ev['_nodes'] = {n for n in (node, *nodes) if n}
    ev['_anchor'] = bool(anchor)
    return ev


def order(ev):
    return (ev['_at'], ev['id'])


def parse_cursor(text):
    """'<time>|<event id>' of the last event of a page, as (aware UTC, id). ValueError else."""
    text = str(text or '')
    when, sep, eid = text.partition('|')
    if not sep or not eid or len(eid) > 300 or ':' not in eid:
        raise ValueError('not a cursor')
    return parse_when(when), eid


def cursor_of(ev):
    return f"{ev['time']}|{ev['id']}"


def page(events, since, until, *, before=None, kinds=None, severities=None, limit=LIMIT_DEFAULT):
    """The events of [since, until], older than `before` when given, of the kinds and
    severities asked, newest first: (the first `limit`, whether more were left over)."""
    inside, seen = [], set()
    for ev in sorted(events, key=order, reverse=True):
        if ev['id'] in seen:
            continue
        seen.add(ev['id'])
        if not since <= ev['_at'] <= until:
            continue
        if before is not None and order(ev) >= before:
            continue
        if kinds and ev['kind'] not in kinds:
            continue
        if severities and ev['severity'] not in severities:
            continue
        inside.append(ev)
    return inside[:limit], len(inside) > limit


def link(anchors, candidates, window):
    """Hang on every anchor among `anchors` what happened on its guest or node within
    `window` (a timedelta) before it, nearest first. An anchor that names neither (the
    cluster losing quorum) gets the node events before it. Correlation only."""
    if window <= timedelta(0):
        return
    by_guest, by_node, node_events = {}, {}, []
    for ev in candidates:
        if ev['guest'] is not None:
            by_guest.setdefault(ev['guest'], []).append(ev)
        for n in ev['_nodes']:
            by_node.setdefault(n, []).append(ev)
        if ev['kind'] == 'node':
            node_events.append(ev)
    keyed = {}

    def times(lst):
        k = id(lst)
        if k not in keyed:
            lst.sort(key=order)
            keyed[k] = [e['_at'] for e in lst]
        return keyed[k]

    for a in anchors:
        if not a.get('_anchor'):
            continue
        pools = []
        if a['guest'] is not None:
            pools.append(by_guest.get(a['guest']))
        pools.extend(by_node.get(n) for n in a['_nodes'])
        if a['guest'] is None and not a['_nodes']:
            pools.append(node_events)
        pools = [p for p in pools if p]
        lo, found = a['_at'] - window, {}
        for lst in pools:
            ts = times(lst)
            for ev in lst[bisect.bisect_left(ts, lo):bisect.bisect_right(ts, a['_at'])]:
                if ev['id'] != a['id']:
                    found[ev['id']] = ev
        near = sorted(found.values(), key=order, reverse=True)[:LINKS_MAX]
        a['shortly_before'] = [{
            'id': ev['id'], 'kind': ev['kind'], 'time': ev['time'], 'severity': ev['severity'],
            'title': ev['title'], 'what': ev['what'], 'params': ev['params'],
            'node': ev['node'], 'guest': ev['guest'], 'guest_name': ev['guest_name'],
            'seconds_before': int((a['_at'] - ev['_at']).total_seconds()),
        } for ev in near]


def public(ev):
    """The event as the route hands it out."""
    out = {k: v for k, v in ev.items() if not k.startswith('_')}
    out['anchor'] = ev.get('_anchor', False)
    out.setdefault('shortly_before', [])
    return out
