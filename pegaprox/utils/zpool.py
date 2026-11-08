# -*- coding: utf-8 -*-
"""
PegaProx ZFS Pool Status - Layer 2
One ZFS pool as Proxmox answers GET /nodes/{node}/disks/zfs/{name}: pve-storage runs
`zpool status -P <name>` and hands back the header fields (state, status, action, scan,
errors) and the config section as a tree of vdevs, each with its state and its read,
write and checksum error counts. The pool view (api/datacenter.py) and the zfs_health
alert (background/alert_events.py) read it in the shape built here.
MK Oct 2026
"""

import math
import re

HEALTHY = 'ONLINE'
# a spare waiting (AVAIL) or standing in (INUSE) is no problem of its own
_FINE_STATES = frozenset(('ONLINE', 'AVAIL', 'INUSE'))
# how bad a pool state is; an ONLINE pool with errors is 1
_LEVELS = {'ONLINE': 0, 'DEGRADED': 2, 'OFFLINE': 3, 'REMOVED': 3, 'UNAVAIL': 4, 'FAULTED': 4,
           'SUSPENDED': 4}
NO_DATA_ERRORS = 'No known data errors'

# the name parameter of the detail call is a pve-storage-id
_POOL_NAME = re.compile(r'[A-Za-z][A-Za-z0-9._-]*[A-Za-z0-9]', re.ASCII)
_NODE_NAME = re.compile(r'[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?', re.ASCII)

MAX_ROWS = 2000       # a pool of some hundred disks fits, the rest of a bigger one is cut
MAX_DEPTH = 8
TEXT_MAX = 1000

# the scan line, as print_scan_status of OpenZFS writes it (ctime dates, a duration in
# [N days ]HH:MM:SS); the lines after the first come joined with a space
_SCAN_DONE = re.compile(r'^(scrub repaired|resilvered)\s+(?:\([^)]*\)\s+)?(\S+)\s+in\s+(.+?)\s+'
                        r'with\s+(\d+)\s+errors?\s+on\s+(.+)$')
_SCAN_CANCELED = re.compile(r'^(scrub|resilver)\s+canceled\s+on\s+(.+)$')
_SCAN_RUNNING = re.compile(r'^(scrub|resilver)\s+(?:\([^)]*\)\s+)?in progress since\s+'
                           r'(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})')
_SCAN_PAUSED = re.compile(r'^scrub paused since\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})')
_SCAN_PERCENT = re.compile(r'([\d.]+)%\s+done')


def valid_pool_name(name):
    return isinstance(name, str) and len(name) <= 255 and bool(_POOL_NAME.fullmatch(name))


def valid_node_name(node):
    return isinstance(node, str) and len(node) <= 63 and bool(_NODE_NAME.fullmatch(node))


def _text(value, limit=TEXT_MAX):
    return ' '.join(str(value).split())[:limit] if value is not None else ''


def _count(value):
    """An error count, or None where zpool shows none (a section, a spare). zpool prints
    large counts as 1.2K and Perl keeps the number in front, so it may have a fraction."""
    if value is None or isinstance(value, bool):
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(n) or n < 0:
        return None
    return int(n) if n.is_integer() else round(n, 2)


def _rows(children, depth, budget):
    """budget: [rows left, whether any was left out]"""
    out = []
    for c in children if isinstance(children, list) else ():
        if not isinstance(c, dict):
            continue
        if budget[0] <= 0 or depth > MAX_DEPTH:
            budget[1] = True
            break
        budget[0] -= 1
        row = {'name': _text(c.get('name'), 255), 'state': _text(c.get('state'), 32),
               'read': _count(c.get('read')), 'write': _count(c.get('write')),
               'cksum': _count(c.get('cksum')), 'msg': _text(c.get('msg'), 300),
               'children': _rows(c.get('children'), depth + 1, budget)}
        out.append(row)
    return out


def _walk(rows):
    for r in rows:
        yield r
        yield from _walk(r['children'])


def _errors_of(row):
    return sum(row[k] or 0 for k in ('read', 'write', 'cksum'))


def parse_scan(text):
    """The scan line as {kind, state, when, repaired, duration, errors, progress, text}.
    state: finished, running, paused, canceled, none or unknown. `when` is the node's
    local time as zpool prints it."""
    raw = _text(text, 500)
    out = {'kind': '', 'state': 'unknown', 'when': '', 'repaired': '', 'duration': '',
           'errors': None, 'progress': None, 'text': raw}
    if not raw:
        out['state'] = 'none'
        return out
    if raw.startswith('none requested'):
        out['state'] = 'none'
        return out
    m = _SCAN_DONE.match(raw)
    if m:
        out.update(kind='scrub' if m.group(1).startswith('scrub') else 'resilver', state='finished',
                   repaired=m.group(2), duration=m.group(3), errors=int(m.group(4)), when=m.group(5))
        return out
    m = _SCAN_CANCELED.match(raw)
    if m:
        out.update(kind=m.group(1), state='canceled', when=m.group(2))
        return out
    m = _SCAN_RUNNING.match(raw) or _SCAN_PAUSED.match(raw)
    if m:
        paused = raw.startswith('scrub paused')
        out.update(kind='scrub' if paused else m.group(1), state='paused' if paused else 'running',
                   when=m.group(m.lastindex))
        pct = _SCAN_PERCENT.search(raw)
        if pct:
            try:
                out['progress'] = min(100.0, float(pct.group(1)))
            except ValueError:
                pass
        return out
    return out


def pool_detail(data):
    """The answer of the detail call as the pool view shows it. The first row of the tree
    is the pool itself, the sections after it (logs, cache, spares, special) have no
    state and no counts."""
    data = data if isinstance(data, dict) else {}
    budget = [MAX_ROWS, False]
    vdevs = _rows(data.get('children'), 0, budget)
    name = _text(data.get('name'), 255)
    state = _text(data.get('state'), 32)
    errors_text = _text(data.get('errors'))
    data_errors = '' if not errors_text or errors_text.startswith(NO_DATA_ERRORS) else errors_text
    devices = []
    top = {id(v) for v in vdevs}
    for r in _walk(vdevs):
        # the pool's own row repeats the pool state; its counts still count
        is_pool_row = id(r) in top and r['name'] == name
        bad_state = bool(r['state']) and r['state'] not in _FINE_STATES
        if _errors_of(r) > 0 or (bad_state and not is_pool_row):
            devices.append({k: r[k] for k in ('name', 'state', 'read', 'write', 'cksum', 'msg')})
    has_errors = bool(data_errors) or any(_errors_of(d) > 0 for d in devices)
    return {
        'name': name, 'state': state,
        'status': _text(data.get('status')), 'action': _text(data.get('action')),
        'see': _text(data.get('see'), 300), 'errors': errors_text, 'data_errors': data_errors,
        'scan': parse_scan(data.get('scan')), 'vdevs': vdevs, 'devices': devices,
        'has_errors': has_errors, 'truncated': budget[1],
    }


def level(state, has_errors=False):
    """0 a healthy pool, 1 ONLINE with errors, 2 DEGRADED, 3 OFFLINE or REMOVED (and any
    state zpool may add), 4 FAULTED, UNAVAIL or SUSPENDED."""
    state = str(state or '').upper()
    if state == HEALTHY:
        return 1 if has_errors else 0
    return _LEVELS.get(state, 3)


def device_note(dev):
    """'/dev/sdb FAULTED (too many errors), 0 read, 0 write, 12 checksum errors'"""
    parts = [dev.get('name') or '?']
    if dev.get('state') and dev['state'] not in _FINE_STATES:
        parts.append(dev['state'])
    note = ' '.join(parts)
    msg = dev.get('msg') or ''
    if msg:
        # zpool writes some of them in brackets already: (resilvering), (repairing)
        note += f" {msg}" if msg.startswith('(') else f" ({msg})"
    counts = [(dev.get(k) or 0, word) for k, word in (('read', 'read'), ('write', 'write'),
                                                       ('cksum', 'checksum'))]
    if any(n for n, _ in counts):
        note += ', ' + ', '.join(f"{n} {word}" for n, word in counts) + ' errors'
    return note
