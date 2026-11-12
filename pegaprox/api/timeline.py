# -*- coding: utf-8 -*-
"""The flight recorder of a cluster: GET /api/timeline merges what the other views keep apart.

MK Oct 2026 - the audit trail, the alerts that fired and cleared, migrations and balancer
moves, config drift, the Proxmox tasks, backups and their verification, node state changes,
site recovery events, rolling updates, syslog errors and status page incidents, newest
first and in one list, so "what happened before the alert" is one look instead of eleven.

Each source is read under the rules of the route that already serves it, for the caller
asking: a caller confined to some guests of the cluster gets the events of those guests,
and nothing about the nodes or the cluster as a whole (like the node task log). A source
the caller may not read is left out and named in `sources`, so the page can say why.

Reads are bounded: a window of at most WINDOW_MAX, at most `limit` rows per source on the
indexes added for this (core/db.py), a fixed scan where rows have to be filtered by guest,
and the Proxmox tasks only from the manager's short cache. Only the instance whose loops
fill the alert, drift, migration and node tables answers (core/ha.py LEADER_ONLY_READS).
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.core import timeline as tl
from pegaprox.core import node_history
from pegaprox.core.db import get_db
from pegaprox.utils.audit import masked_details
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import bounded_limit, caller_is_scoped, check_cluster_access

bp = Blueprint('timeline', __name__)

_NODE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.\-]{0,62}')
_DIGITS = re.compile(r'[0-9]{1,9}')
_GUEST_IN_TEXT = re.compile(r'\b(?:VM|CT|QEMU|LXC)\s+(\d{1,9})(?!\d)|\b(?:qemu|lxc)/(\d{1,9})(?!\d)')
_NODE_IN_TEXT = re.compile(r'\bnode\s+[\'"]?([A-Za-z0-9][A-Za-z0-9.\-]{0,62})', re.I)
# rows read where they have to be filtered by guest or node before the cap applies
SCAN = 2000
# rows read of a source the severity asked for thins out: the newest page of audit rows is
# mostly info, and a page of critical events would else be empty on a busy cluster
SIFT = SCAN
# the Proxmox tasks: what the broadcast loop reads every second (core/manager.py get_tasks)
TASKS_READ = 50
PLANS_READ = 200
VMID_MAX = 999999999


class _Ask:
    """One request: the cluster, the filters, the window to read and who asks."""

    def __init__(self, cid, mgr, user, node, vmid, lo, hi, cap, *, edge=None, before=None, kinds=None,
                 severities=None):
        from pegaprox.utils.rbac import acts_as_admin
        self.cid, self.mgr, self.user = cid, mgr, user
        self.node, self.vmid = node, vmid
        self.lo, self.hi, self.cap = lo, hi, cap
        # the cursor's second, read whole (the page before showed part of it), and the cursor
        self.edge, self.before = edge, before
        self.kinds, self.severities = kinds, severities
        self.scoped = caller_is_scoped(user, cid)
        self.admin = acts_as_admin(user)
        self._guests = {}
        self._map = None
        self.name = getattr(getattr(mgr, 'config', None), 'name', '') or ''
        if not isinstance(self.name, str):
            self.name = ''

    def holds(self, perm):
        from pegaprox.utils.rbac import has_permission
        return has_permission(self.user, perm)

    def sees(self, vmid, perm='vm.view'):
        """Whether the caller may see this guest, asked once per guest and request."""
        try:
            vmid = int(vmid)
        except (TypeError, ValueError):
            return False
        key = (vmid, perm)
        if key not in self._guests:
            from pegaprox.utils.rbac import user_can_access_vm
            self._guests[key] = bool(user_can_access_vm(self.user, self.cid, vmid, perm))
        return self._guests[key]

    def bounds(self, naive='local'):
        """The window to read as text for a source's stored times, the upper end exclusive."""
        return tl.bound(self.lo, naive), tl.bound(self.hi + timedelta(seconds=1), naive)

    def reads(self, kind, filtered=False):
        """Rows to read of a source: SCAN where rows are dropped after the read by guest or
        node, SIFT where the severity asked for drops them, the page size else."""
        if filtered:
            return SCAN
        if self.severities and (not self.kinds or kind in self.kinds):
            return max(SIFT, self.cap)
        return self.cap

    def counts(self, ev):
        """Whether an event takes a place on the page: one the filters keep, or any event of
        a kind that is only read for the links."""
        if self.kinds and ev['kind'] not in self.kinds:
            return True
        return not self.severities or ev['severity'] in self.severities

    def guest_map(self):
        """{vmid: (node, name)} from the guest list the manager already holds, never a fresh
        read of /cluster/resources: names for the tasks, the host of a guest."""
        if self._map is None:
            self._map = {}
            cached = getattr(self.mgr, '_vm_resources_cache', None)
            rows = cached[1] if isinstance(cached, tuple) and len(cached) == 2 else None
            if isinstance(rows, list):
                for r in rows:
                    if isinstance(r, dict) and r.get('type') in ('qemu', 'lxc'):
                        try:
                            self._map[int(r.get('vmid'))] = (r.get('node') or '', r.get('name') or '')
                        except (TypeError, ValueError):
                            continue
        return self._map

    def node_names(self):
        """The cluster's nodes as the manager last read them, no read of its own."""
        cached = getattr(self.mgr, '_node_status_cache', None)
        if isinstance(cached, tuple) and len(cached) == 2 and isinstance(cached[1], dict):
            return [n for n in cached[1] if isinstance(n, str)]
        nodes = getattr(self.mgr, 'ha_node_status', None)
        return [n for n in nodes if isinstance(n, str)] if isinstance(nodes, dict) else []

    def guest_name(self, vmid):
        return (self.guest_map().get(vmid) or ('', ''))[1]

    def keeps(self, guest=None, nodes=()):
        """Whether an event of this guest or these nodes belongs on the page asked for."""
        if self.vmid is not None and guest != self.vmid:
            return False
        if self.node is not None and self.node not in nodes:
            return False
        return True


def _note(shown=True, why='', capped=False, count=0, depth=None):
    note = {'shown': shown, 'why': why, 'capped': capped, 'count': count}
    if depth is not None:
        note['_floor'] = depth
    return note


def _select(sql, params, col, order=', id DESC', query=None):
    """A read for _window: `sql` ends in its WHERE filters, the window and the order follow."""
    full = f'{sql} AND {col} >= ? AND {col} < ? ORDER BY {col} DESC{order} LIMIT ?'
    query = query or get_db().query
    return lambda since, until, n: query(full, (*params, since, until, n))


def _window(ask, fetch, col, limit, naive='local'):
    """A source's rows of the window newest first, no second of them read in part.

    MK Oct 2026 - a read of the newest `limit` rows up to the cursor's second counted the rows
    the page before had shown, and with that many in one second the next page read the same
    rows again and the list ended there. Now the cursor's second is read whole (what was shown
    is dropped by the event, not counted), then at most `limit` older rows, then the rest of
    the second the oldest of them fell in. (rows, that second when `limit` was reached)"""
    one = timedelta(seconds=1)
    rows = []
    since, until = ask.bounds(naive)
    if ask.edge is not None:
        rows += fetch(tl.bound(ask.edge, naive), tl.bound(ask.edge + one, naive), SCAN)
        until = tl.bound(ask.edge, naive)
    older = list(fetch(since, until, limit))
    rows += older
    if len(older) < limit:
        return rows, None
    last = next((at for at in (tl.stored_time(r[col], naive) for r in reversed(older)) if at), None)
    if last is None:
        return rows, None
    last = last.replace(microsecond=0)
    seen = {r['id'] for r in older}
    rows += [r for r in fetch(tl.bound(last, naive), tl.bound(last + one, naive), SCAN) if r['id'] not in seen]
    return rows, last


class _Kept:
    """What a source hands out of its rows, which come newest first in whole seconds: its
    events until `cap` of them take a place on the page and that second is over. One a page
    before showed takes no place (it is still there for the links). How deep it went is the
    floor of the page."""

    def __init__(self, ask, depth=None):
        self.ask, self.out, self.depth = ask, [], depth
        self._placed, self._last = 0, None

    def done(self, at):
        """Whether a row at `at` is past the cut: call it for every row before anything else."""
        if self._last is None or at is None or at.replace(microsecond=0) >= self._last:
            return False
        self.depth = self._last
        return True

    def add(self, ev):
        self.out.append(ev)
        if not tl.earlier(ev, self.ask.before) and self.ask.counts(ev):
            self._placed += 1
            if self._placed == self.ask.cap:
                self._last = ev['_at']

    def result(self):
        return self.out, _note(capped=self.depth is not None, depth=self.depth)


def _guests_in(text):
    out = []
    for m in _GUEST_IN_TEXT.finditer(text or ''):
        v = int(m.group(1) or m.group(2))
        if v not in out:
            out.append(v)
    return out


# --- the sources -----------------------------------------------------------------------------

def _audit(ask):
    """The cluster's audit rows (settings.py /api/clusters/<id>/audit). A confined caller
    gets the rows that name one of their guests, as there."""
    filtered = ask.scoped or ask.vmid is not None or ask.node is not None
    rows, depth = _window(ask, _select('SELECT id, timestamp, user, action, details, severity, cluster FROM audit_log '
                                       'WHERE cluster_id = ?', (ask.cid,), 'timestamp'),
                          'timestamp', ask.reads('audit', filtered))
    known = set(ask.node_names())
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['timestamp'])
        if at is None:
            continue
        if kept.done(at):
            break
        details = r['details'] or ''
        guests = _guests_in(details)
        if ask.scoped:
            guests = [g for g in guests if ask.sees(g)]
            if not guests:
                continue
        guest = guests[0] if guests else None
        if ask.vmid is not None and ask.vmid in guests:
            guest = ask.vmid
        # a node named in the text, when it is one of the cluster's
        m = _NODE_IN_TEXT.search(details)
        node = m.group(1) if m and not ask.scoped and m.group(1) in known else None
        if not ask.keeps(guest, {node} if node else ()):
            continue
        kept.add(tl.event('audit', r['id'], at, cluster=ask.cid, severity=tl.severity_of(r['severity']),
                          title=r['action'], details=masked_details(details, r['cluster'] or ''),
                          node=node, guest=guest,
                          guest_name=ask.guest_name(guest) if guest is not None else '',
                          what='audit', params={'action': r['action'], 'user': r['user'] or ''},
                          route=f'/api/clusters/{ask.cid}/audit'))
    return kept.result()


def _alerts(ask):
    """Alerts as they fired and cleared (alerts.py active-alerts keeps the open ones). A
    confined caller gets the ones on their guests and none about a node."""
    filtered = ask.scoped or ask.node is not None
    cols = ('id, alert_id, severity, message, metric, target_type, target_id, target_name, '
            'triggered_at, resolved_at, resolved_by')
    out, depths = [], []
    for column, resolved in (('triggered_at', False), ('resolved_at', True)):
        sql = f'SELECT {cols} FROM active_alerts WHERE cluster_id = ?'
        params = [ask.cid]
        if ask.vmid is not None:
            sql += " AND target_type = 'vm' AND target_id = ?"
            params.append(str(ask.vmid))
        rows, depth = _window(ask, _select(sql, params, column, order=''), column, ask.reads('alert', filtered))
        kept = _Kept(ask, depth)
        for r in rows:
            at = tl.stored_time(r[column])
            if at is None:
                continue
            if kept.done(at):
                break
            guest, node = None, None
            if r['target_type'] == 'vm':
                try:
                    guest = int(r['target_id'])
                except (TypeError, ValueError):
                    guest = None
            elif r['target_type'] == 'node':
                node = r['target_id'] or None
            if ask.scoped and (guest is None or not ask.sees(guest)):
                continue
            host = (ask.guest_map().get(guest) or ('', ''))[0] if guest is not None else ''
            if not ask.keeps(guest, {n for n in (node, host) if n}):
                continue
            sev = 'info' if resolved else tl.severity_of(r['severity'], 'warning')
            ev = tl.event('alert', f"{r['id']}:resolved" if resolved else r['id'], at, cluster=ask.cid,
                          severity=sev, title=r['message'] or r['metric'] or '', node=node,
                          nodes=(host,) if host and not ask.scoped else (), guest=guest,
                          guest_name=r['target_name'] if guest is not None else '',
                          what='alert.resolved' if resolved else 'alert.fired',
                          params={'metric': r['metric'] or '', 'target': r['target_name'] or r['target_id'] or '',
                                  'by': (r['resolved_by'] or '') if resolved else ''},
                          route=f'/api/clusters/{ask.cid}/active-alerts',
                          anchor=not resolved and sev in ('warning', 'critical'))
            kept.add(ev)
        got, note = kept.result()
        out += got
        if note['capped']:
            depths.append(note['_floor'])
    # MK Oct 2026 - two reads, each as deep as it went: the oldest clear of the cleared ones
    # is no floor for the fired ones the capped read of those left out
    depth = max(depths, default=None)
    return out, _note(capped=depth is not None, depth=depth)


def _moves(ask, balancer):
    """Migrations (history.py), the balancer's moves apart. A confined caller gets their
    guests' moves, the balancer's without why, as in the balance history."""
    from pegaprox.core.db import PegaProxDB
    kind = 'balancer' if balancer else 'migration'
    # MK Oct 2026 - the migration routes ask vm.view of every guest (history.py); a caller who
    # is not confined to some guests holds it for all of them or for none. The balance history
    # asks cluster.view only, so its moves stay as they were.
    if not balancer and not ask.scoped and not ask.holds('vm.view'):
        return [], _note(False, 'permission')
    triggers = PegaProxDB.BALANCER_TRIGGERS
    sql = ('SELECT id, vmid, vm_name, source_node, target_node, reason, status, duration_seconds, '
           'timestamp, trigger_kind FROM migration_history WHERE cluster_id = ?')
    params = [ask.cid]
    marks = ','.join('?' * len(triggers))
    if balancer:
        sql += f' AND trigger_kind IN ({marks})'
    else:
        sql += f' AND (trigger_kind IS NULL OR trigger_kind NOT IN ({marks}))'
    params += list(triggers)
    if ask.vmid is not None:
        sql += ' AND vmid = ?'
        params.append(ask.vmid)
    if ask.node is not None:
        sql += ' AND (source_node = ? OR target_node = ?)'
        params += [ask.node, ask.node]
    rows, depth = _window(ask, _select(sql, params, 'timestamp'), 'timestamp', ask.reads(kind, ask.scoped))
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['timestamp'])
        if at is None:
            continue
        if kept.done(at):
            break
        if ask.scoped and not ask.sees(r['vmid']):
            continue
        reason = '' if (ask.scoped and balancer) else (r['reason'] or '')
        kept.add(tl.event(
            kind, r['id'], at, cluster=ask.cid, severity='warning' if r['status'] == 'failed' else 'info',
            title=f"{r['vm_name'] or r['vmid']}: {r['source_node']} -> {r['target_node']} ({r['status']})",
            details=reason, node=r['target_node'], nodes=(r['source_node'],), guest=r['vmid'],
            guest_name=r['vm_name'] or '', what='migration',
            params={'status': r['status'] or '', 'source': r['source_node'], 'target': r['target_node'],
                    'trigger': r['trigger_kind'] or '', 'duration': r['duration_seconds'] or 0},
            route=(f'/api/clusters/{ask.cid}/balance-history' if balancer
                   else f'/api/clusters/{ask.cid}/vms/{r["vmid"]}/migration-history')))
    return kept.result()


def _drift(ask):
    """Config drift (drift.py): admin.audit, and the whole cluster's, so no confined caller."""
    if ask.scoped:
        return [], _note(False, 'confined')
    if not ask.holds('admin.audit'):
        return [], _note(False, 'permission')
    sql = 'SELECT id, kind, scope, severity, summary, detected_at, status FROM drift_events WHERE cluster_id = ?'
    params = [ask.cid]
    if ask.vmid is not None:
        sql += " AND kind = 'vm_config' AND scope IN (?, ?)"
        params += [f'qemu/{ask.vmid}', f'lxc/{ask.vmid}']
    rows, depth = _window(ask, _select(sql, params, 'detected_at'), 'detected_at',
                          ask.reads('drift', ask.node is not None))
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['detected_at'])
        if at is None:
            continue
        if kept.done(at):
            break
        guest, node = None, None
        scope = r['scope'] or ''
        if r['kind'] == 'vm_config' and scope.partition('/')[2].isdigit():
            guest = int(scope.partition('/')[2])
        elif r['kind'] == 'network':
            node = scope.partition('/')[0] or None
        if not ask.keeps(guest, {node} if node else ()):
            continue
        kept.add(tl.event('drift', r['id'], at, cluster=ask.cid, severity=tl.severity_of(r['severity']),
                          title=r['summary'] or f"{r['kind']} {scope}", node=node, guest=guest,
                          guest_name=ask.guest_name(guest) if guest is not None else '', what='drift',
                          params={'drift_kind': r['kind'], 'scope': scope, 'status': r['status']},
                          route=f'/api/clusters/{ask.cid}/drift/events'))
    return kept.result()


def _tasks(ask):
    """The Proxmox tasks of the cluster as the manager's short cache has them
    (clusters.py /tasks); a vzdump task is a backup. A confined caller gets the tasks of
    their guests, no node task."""
    mgr = ask.mgr
    if not getattr(mgr, 'is_connected', False):
        return [], _note(True, 'offline')
    try:
        tasks = mgr.get_tasks(limit=TASKS_READ)
    except Exception as e:
        logging.debug(f"[Timeline] {ask.cid}: tasks not read: {e}")
        tasks = None
    if not isinstance(tasks, list):
        return [], _note(True, 'unread')
    out = {'task': [], 'backup': []}
    for t in tasks:
        if not isinstance(t, dict):
            continue
        at = tl.stored_time(t.get('starttime')) if isinstance(t.get('starttime'), (int, float)) else None
        if at is None or not ask.lo <= at <= ask.hi + timedelta(seconds=1):
            continue
        ident = str(t.get('id') or '')
        guest = int(ident) if ident.isdigit() and int(ident) <= VMID_MAX else None
        node = t.get('node') or None
        if ask.scoped and (guest is None or not ask.sees(guest)):
            continue
        if not ask.keeps(guest, {node} if node else ()):
            continue
        # get_tasks turns a failed task into 'failed'; what Proxmox said is in exitstatus
        status = str(t.get('exitstatus') or t.get('status') or '')
        running = not t.get('endtime') or status.lower() == 'running'
        failed = not running and status != 'OK' and not status.startswith('WARNINGS')
        backup = t.get('type') == 'vzdump'
        sev = 'info'
        if failed:
            sev = 'critical' if backup else 'warning'
        elif status.startswith('WARNINGS'):
            sev = 'warning'
        kind = 'backup' if backup else 'task'
        upid = str(t.get('upid') or '')
        out[kind].append(tl.event(
            kind, upid or f"{node}:{t.get('starttime')}", at, cluster=ask.cid, severity=sev,
            title=f"{t.get('type') or 'task'}{' ' + ident if ident else ''}", details='' if running else status,
            node=node, guest=guest, guest_name=ask.guest_name(guest) if guest is not None else '',
            what=kind, params={'type': t.get('type') or '', 'status': 'running' if running else status,
                               'user': t.get('pegaprox_user') or t.get('user') or '',
                               'ended': tl.iso(tl.stored_time(t['endtime'])) if not running
                               and isinstance(t.get('endtime'), (int, float)) else ''},
            route=f'/api/clusters/{ask.cid}/nodes/{node}/tasks/{upid}/log' if node and upid else '',
            anchor=failed))
    # the newest tasks only: older ones are not in this read, and no next page brings them
    why = 'recent' if len(tasks) >= TASKS_READ else ''
    return out, {k: _note(why=why) for k in out}


def _node_states(ask):
    """Node state changes (core/node_history.py): node-level, so not for a confined caller,
    and node.view like the node views. A guest's page gets its host's."""
    if ask.scoped:
        return [], _note(False, 'confined')
    if not ask.holds('node.view'):
        return [], _note(False, 'permission')
    node = ask.node
    if ask.vmid is not None:
        node = (ask.guest_map().get(ask.vmid) or ('', ''))[0]
        if not node:
            return [], _note()
    db = get_db()
    rows, depth = _window(ask, lambda since, until, n: db.list_node_states(ask.cid, since, until, node=node, limit=n),
                          'at', ask.reads('node'), 'utc')
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['at'], 'utc')
        if at is None:
            continue
        if kept.done(at):
            break
        state, maint = r['state'], r['detail'] == 'in maintenance'
        down = state in (node_history.OFFLINE, node_history.UNKNOWN)
        sev = 'info'
        if (down and not maint) or state == node_history.NO_QUORUM:
            sev = 'critical'
        name = r['node'] or None
        kept.add(tl.event(
            'node', r['id'], at, cluster=ask.cid, severity=sev,
            title=f"{name or ask.name or ask.cid}: {state}", details=r['detail'], node=name,
            what=f'node.{state}', params={'node': name or '', 'previous': r['previous'], 'detail': r['detail']},
            route='/api/timeline', anchor=sev == 'critical'))
    return kept.result()


def _backup_verify(ask):
    """Backup verification runs (pbs.py backup-verify/history): vm.backup, a confined
    caller's own guests only."""
    if not ask.holds('vm.backup'):
        return [], _note(False, 'permission')
    sql = ('SELECT id, vmid, vm_name, node, status, phase, error, started_at, completed_at '
           'FROM backup_verifications WHERE cluster_id = ?')
    params = [ask.cid]
    if ask.vmid is not None:
        sql += ' AND vmid = ?'
        params.append(ask.vmid)
    if ask.node is not None:
        sql += ' AND node = ?'
        params.append(ask.node)
    rows, depth = _window(ask, _select(sql, params, 'started_at', order=''), 'started_at',
                          ask.reads('backup_verify', ask.scoped))
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['started_at'])
        if at is None:
            continue
        if kept.done(at):
            break
        if ask.scoped and not ask.sees(r['vmid'], 'vm.backup'):
            continue
        failed = r['status'] in ('failed', 'error')
        kept.add(tl.event(
            'backup_verify', r['id'], at, cluster=ask.cid, severity='critical' if failed else 'info',
            title=f"{r['vm_name'] or r['vmid']}: {r['status']}", details=r['error'] or '',
            node=None if ask.scoped else (r['node'] or None), guest=r['vmid'], guest_name=r['vm_name'] or '',
            what='backup_verify', params={'status': r['status'], 'phase': r['phase'] or ''},
            route=f'/api/clusters/{ask.cid}/backup-verify/{r["id"]}', anchor=failed))
    return kept.result()


def _site_recovery(ask):
    """Site recovery events of the plans to or from this cluster (site_recovery.py):
    site_recovery.view and both clusters, whole plans, so no confined caller."""
    if ask.scoped:
        return [], _note(False, 'confined')
    if not ask.holds('site_recovery.view'):
        return [], _note(False, 'permission')
    if ask.node is not None:
        return [], _note()
    db = get_db()
    plans = {}
    for p in db.query('SELECT id, name, source_cluster, target_cluster FROM site_recovery_plans '
                      'WHERE source_cluster = ? OR target_cluster = ? LIMIT ?', (ask.cid, ask.cid, PLANS_READ)):
        other = p['target_cluster'] if p['source_cluster'] == ask.cid else p['source_cluster']
        if other and other != ask.cid:
            ok, _err = check_cluster_access(other)
            if not ok or caller_is_scoped(ask.user, other):
                continue
        plans[p['id']] = p
    if plans and ask.vmid is not None:
        marks = ','.join('?' * len(plans))
        holding = {r['plan_id'] for r in db.query(
            f'SELECT DISTINCT plan_id FROM site_recovery_vms WHERE vmid = ? AND plan_id IN ({marks})',
            (ask.vmid, *plans))}
        plans = {k: v for k, v in plans.items() if k in holding}
    if not plans:
        return [], _note()
    marks = ','.join('?' * len(plans))
    sql = (f'SELECT id, plan_id, event_type, status, started_at, completed_at, triggered_by '
           f'FROM site_recovery_events WHERE plan_id IN ({marks})')
    rows, depth = _window(ask, _select(sql, list(plans), 'started_at', order=''), 'started_at',
                          ask.reads('site_recovery'), 'utc')
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['started_at'], 'utc')
        if at is None:
            continue
        if kept.done(at):
            break
        plan = plans[r['plan_id']]
        kept.add(tl.event(
            'site_recovery', r['id'], at, cluster=ask.cid,
            severity='critical' if r['status'] == 'failed' else 'info',
            title=f"{plan['name']}: {r['event_type']} ({r['status']})", guest=ask.vmid,
            what='site_recovery', params={'plan': plan['name'], 'event_type': r['event_type'],
                                          'status': r['status'], 'by': r['triggered_by'] or ''},
            route=f"/api/site-recovery/plans/{r['plan_id']}/events"))
    return kept.result()


def _rolling(ask):
    """Rolling updates (settings.py updates/rolling/history): node.view and the whole
    cluster's, so no confined caller."""
    if ask.scoped:
        return [], _note(False, 'confined')
    if not ask.holds('node.view'):
        return [], _note(False, 'permission')
    if ask.vmid is not None:
        return [], _note()
    from pegaprox.core import rolling_runs
    out = []
    for state in rolling_runs.stored(ask.cid, limit=rolling_runs.HISTORY_KEEP):
        nodes = [n for n in (state.get('nodes') or []) if isinstance(n, str)]
        if ask.node is not None and ask.node not in nodes:
            continue
        # a failed node is {'node', 'error'} in the run's state
        failed = [f.get('node') if isinstance(f, dict) else f for f in (state.get('failed_nodes') or [])]
        failed = [n for n in failed if isinstance(n, str)]
        status = str(state.get('status') or '')
        params = {'status': status, 'nodes': len(nodes), 'failed': failed[:20],
                  'by': state.get('started_by') or ''}
        for edge, value in (('started', state.get('started_at')), ('ended', state.get('completed_at'))):
            at = tl.stored_time(value)
            if at is None or not ask.lo <= at <= ask.hi + timedelta(seconds=1):
                continue
            sev = 'info'
            if edge == 'ended' and (status in ('failed', 'paused') or failed):
                sev = 'warning'
            out.append(tl.event('rolling_update', f"{state.get('run_id')}:{edge}", at, cluster=ask.cid,
                                severity=sev, title=f'rolling update {edge} ({status})',
                                node=ask.node, what=f'rolling.{edge}', params=params,
                                route=f'/api/clusters/{ask.cid}/updates/rolling/history'))
    # MK Oct 2026 - the runs come as stored, each start before its end: newest first before
    # the cut, else the end of an older run fell between two pages
    kept = _Kept(ask)
    for ev in sorted(out, key=tl.order, reverse=True):
        if kept.done(ev['_at']):
            break
        kept.add(ev)
    return kept.result()


def _syslog(ask):
    """Errors and worse the integrated syslog server took from the cluster's nodes
    (reports.py /api/syslog/events): admin.audit, a cluster the caller's tenant owns,
    and node-level, so no confined caller."""
    if ask.scoped:
        return [], _note(False, 'confined')
    if not ask.holds('admin.audit'):
        return [], _note(False, 'permission')
    from pegaprox.utils.rbac import get_user_clusters
    theirs = get_user_clusters(ask.user, include_pools=False)
    if theirs is not None and ask.cid not in theirs:
        return [], _note(False, 'confined')
    if ask.vmid is not None:
        return [], _note()
    from pegaprox.background.syslog_server import DB_FILE
    if not os.path.exists(os.path.abspath(DB_FILE)):
        return [], _note()
    from pegaprox.api import reports
    names = ask.node_names()
    # MK Oct 2026 - the logs are kept by host name, not by cluster: a node page names one of
    # the cluster's nodes, or any name became the host names of another tenant's node (or of
    # a sender no cluster claims), which /api/syslog/events does not hand this caller
    if ask.node is not None:
        if ask.node not in names:
            return [], _note()
        names = [ask.node]
    tokens = set()
    for value in names:
        tokens |= reports._syslog_hostname_tokens(value)
    if not tokens:
        return [], _note()
    params = []
    hosts = reports._syslog_host_clause(tokens, params, cached_only=True)
    from pegaprox.core import dbcrypto
    conn = dbcrypto.connect(os.path.abspath(DB_FILE))
    conn.row_factory = dbcrypto.Row
    try:
        rows, depth = _window(ask, _select(f'SELECT id, timestamp, hostname, severity, severity_text, message '
                                           f'FROM logs WHERE severity IN (0, 1, 2, 3) AND {hosts}', params,
                                           'timestamp', query=lambda sql, p: conn.execute(sql, p).fetchall()),
                              'timestamp', ask.reads('syslog'))
    finally:
        conn.close()
    lowered = {n.lower(): n for n in names}
    kept = _Kept(ask, depth)
    for r in rows:
        at = tl.stored_time(r['timestamp'])
        if at is None:
            continue
        if kept.done(at):
            break
        host = str(r['hostname'] or '').lower()
        node = lowered.get(host) or lowered.get(host.split('.', 1)[0])
        kept.add(tl.event('syslog', r['id'], at, cluster=ask.cid,
                          severity='critical' if (r['severity'] or 0) <= 2 else 'warning',
                          title=str(r['message'] or '')[:200], node=node, what='syslog',
                          params={'host': r['hostname'] or '', 'level': r['severity_text'] or ''},
                          route='/api/syslog/events'))
    return kept.result()


def _incidents(ask):
    """Status page incidents (plugins/status_page): admins only, as there. One that names
    no component is about everything."""
    if not ask.admin:
        return [], _note(False, 'permission')
    if ask.vmid is not None or ask.node is not None:
        return [], _note()
    rows, depth = _window(ask, _select('SELECT id, title, status, severity, message, components, started_at, '
                                       'resolved_at FROM status_incidents WHERE started_at IS NOT NULL', (),
                                       'started_at', order=''),
                          'started_at', SCAN)
    names = {ask.cid.lower(), ask.name.lower()} - {''}
    kept = _Kept(ask, depth)
    for r in rows:
        if kept.done(tl.stored_time(r['started_at'])):
            break
        try:
            parts = json.loads(r['components'] or '[]')
        except (TypeError, ValueError):
            parts = []
        if isinstance(parts, list) and parts:
            said = set()
            for p in parts:
                if isinstance(p, dict):
                    said |= {str(p.get(k) or '').lower() for k in ('id', 'cluster_id', 'name')}
                else:
                    said.add(str(p).lower())
            if not said & names:
                continue
        at = tl.stored_time(r['started_at'])
        if at is None:
            continue
        kept.add(tl.event('incident', r['id'], at, cluster=ask.cid, severity=tl.severity_of(r['severity']),
                          title=r['title'] or '', details=r['message'] or '', what='incident',
                          params={'status': r['status'] or '', 'resolved_at': r['resolved_at'] or ''},
                          route='/api/plugins/status_page/api/incidents'))
    return kept.result()


def _read(ask):
    """Every source, under its own rules: (events, {kind: note})."""
    events, notes = [], {}

    def take(kind, fn, *a):
        try:
            got, note = fn(*a)
        except Exception as e:
            logging.warning(f"[Timeline] {ask.cid}: the {kind} events could not be read: {e}")
            got, note = [], _note(True, 'unread')
        note['count'] = len(got)
        _floor(note, got)
        notes[kind] = note
        events.extend(got)

    take('audit', _audit, ask)
    take('alert', _alerts, ask)
    take('migration', _moves, ask, False)
    take('balancer', _moves, ask, True)
    take('drift', _drift, ask)
    try:
        by_kind, task_notes = _tasks(ask)
    except Exception as e:
        logging.warning(f"[Timeline] {ask.cid}: the tasks could not be read: {e}")
        by_kind, task_notes = {}, {k: _note(True, 'unread') for k in ('task', 'backup')}
    if isinstance(by_kind, dict):
        for kind in ('task', 'backup'):
            got = by_kind.get(kind, [])
            note = task_notes.get(kind) if isinstance(task_notes, dict) else None
            notes[kind] = dict(note or _note(), count=len(got))
            _floor(notes[kind], got)
            events.extend(got)
    else:
        for kind in ('task', 'backup'):
            notes[kind] = dict(task_notes, count=0)
    take('backup_verify', _backup_verify, ask)
    take('node', _node_states, ask)
    take('site_recovery', _site_recovery, ask)
    take('rolling_update', _rolling, ask)
    take('syslog', _syslog, ask)
    take('incident', _incidents, ask)
    return events, notes


def _floor(note, got):
    """A source that hit its cap may hold older rows it did not hand over: how deep it read
    (the floor it set) or else the oldest row it handed over is as deep as a page can go
    before those would be missed"""
    if note.get('capped') and got and note.get('_floor') is None:
        note['_floor'] = min(ev['_at'] for ev in got)


def _bad(msg):
    return jsonify({'error': msg}), 400


def _listed(raw, allowed, what):
    """A comma list of known words, None for none given; ValueError names the first unknown."""
    if raw is None or raw == '':
        return None
    items = [p.strip() for p in str(raw).split(',') if p.strip()]
    if not items or len(items) > len(allowed):
        raise ValueError(f"{what} must be one or more of {', '.join(allowed)}")
    bad = [p for p in items if p not in allowed]
    if bad:
        raise ValueError(f"{what} must be one or more of {', '.join(allowed)}")
    return set(items)


def _window_args(args):
    """The window and the filters of a query: (since, until, clipped, kinds, severities).
    ValueError carries the message of the 400."""
    try:
        until = tl.parse_when(args['to']) if args.get('to') else datetime.now(timezone.utc)
        since = tl.parse_when(args['from']) if args.get('from') else until - tl.WINDOW_DEFAULT
    except (ValueError, OverflowError):
        raise ValueError('from and to must be ISO 8601 times or epoch seconds') from None
    if since >= until:
        raise ValueError('from must be before to')
    # MK Oct 2026 - a longer window is cut to the newest 30 days (the 30 days the UI asks for
    # reach a few milliseconds further by the time they arrive); 'from' in the answer says where
    clipped = until - since > tl.WINDOW_MAX
    if clipped:
        since = until - tl.WINDOW_MAX
    kinds = _listed(args.get('kinds'), tl.KINDS, 'kinds')
    severities = _listed(args.get('severity'), tl.SEVERITIES, 'severity')
    return since, until, clipped, kinds, severities


def _one_page(ask, since, until, window):
    """Read every source for `ask` and cut the page: (events shown, cursor of the next page
    or None, {kind: note}). The links to what happened shortly before are hung on the page."""
    kinds, severities, before, limit = ask.kinds, ask.severities, ask.before, ask.cap
    events, notes = _read(ask)
    # MK Oct 2026 - a page goes no deeper than the oldest row of a source that hit its cap,
    # else the rows that source left out fell between this page and the next
    floor = max((n['_floor'] for k, n in notes.items()
                 if n.get('_floor') is not None and (not kinds or k in kinds)), default=None)
    for n in notes.values():
        n.pop('_floor', None)
    shown, more = tl.page(events, since, until, before=before, kinds=kinds, severities=severities,
                          limit=limit, floor=floor)
    tl.link(shown, events, window)
    capped = any(n.get('capped') for k, n in notes.items() if not kinds or k in kinds)
    if len(shown) >= limit and (more or capped):
        nxt = tl.cursor_of(shown[-1])
    elif floor is not None and floor >= since:
        # MK Oct 2026 - what the filters keep down to the floor is all on this page, even when
        # that is nothing: the next one starts below the floor's second, not at the end
        nxt = tl.cursor_below(floor)
    else:
        nxt = None
    return shown, nxt, notes


@bp.route('/api/timeline', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_timeline():
    """Events of one cluster, newest first.
    ?cluster=<id> (required) ?node= ?vmid= ?from= ?to= (ISO 8601 or epoch seconds; the last
    24 h by default, 30 days at most) ?kinds=audit,alert,... ?severity=info,warning,critical
    ?limit=1..500 ?before=<next_before of the page before> ?correlate=<minutes, 0..120>"""
    args = request.args
    cid = (args.get('cluster') or '').strip()
    if not cid:
        return _bad('cluster is required')
    if len(cid) > 128:
        return _bad('cluster is not a cluster id')
    ok, err = check_cluster_access(cid)
    if not ok:
        return err
    mgr = cluster_managers.get(cid)
    if mgr is None:
        return jsonify({'error': 'Cluster not found'}), 404

    node = args.get('node')
    if node is not None and node != '':
        if not _NODE.fullmatch(node):
            return _bad('node is not a node name')
    else:
        node = None
    vmid = args.get('vmid')
    if vmid is not None and vmid != '':
        # str.isdigit() takes a superscript two, int() does not
        if not _DIGITS.fullmatch(vmid) or len(vmid) > 9 or int(vmid) < 1:
            return _bad('vmid must be a guest id')
        vmid = int(vmid)
    else:
        vmid = None
    try:
        since, until, clipped, kinds, severities = _window_args(args)
    except ValueError as e:
        return _bad(str(e))
    before = None
    if args.get('before'):
        try:
            before = tl.parse_cursor(args['before'])
        except ValueError:
            return _bad('before must be the next_before of a page')
    raw = args.get('correlate')
    if raw is None or raw == '':
        correlate = tl.CORRELATE_DEFAULT
    elif _DIGITS.fullmatch(raw) and int(raw) <= tl.CORRELATE_MAX:
        correlate = int(raw)
    else:
        return _bad(f'correlate is minutes from 0 to {tl.CORRELATE_MAX}')
    limit = bounded_limit(args.get('limit'), tl.LIMIT_DEFAULT, tl.LIMIT_MAX)

    from pegaprox.utils.auth import build_authz_user
    user = build_authz_user(request.session.get('user', ''), request.session)
    window = timedelta(minutes=correlate)
    # the page before ended within the cursor's second: that second is read whole again
    hi, edge = until, None
    if before and before[0] <= until:
        hi = edge = before[0].replace(microsecond=0)
    ask = _Ask(cid, mgr, user, node, vmid, since - window, hi, limit, edge=edge, before=before,
               kinds=kinds, severities=severities)
    if vmid is not None and not ask.sees(vmid):
        return jsonify({'error': 'Permission denied'}), 403

    shown, nxt, notes = _one_page(ask, since, until, window)
    return jsonify({
        'cluster': cid, 'node': node, 'vmid': vmid,
        'from': tl.iso(since), 'to': tl.iso(until), 'clipped': clipped,
        'events': [tl.public(e) for e in shown],
        'next_before': nxt,
        'sources': notes,
        'correlation': {'window_minutes': correlate,
                        'note': 'Events on the same guest or node shortly before; correlation, not cause.'},
    })


# --- the evidence bundle ----------------------------------------------------------------------

# pages read per cluster for one bundle: 500 events each, so a bit more than the cap holds
_EVIDENCE_PAGES = 60


def _evidence_clusters(args):
    """(cluster ids, None) or (None, error response): the ones named in ?clusters= (or
    ?cluster=), each under the access rule of GET /api/timeline, else every cluster the
    caller may reach."""
    from pegaprox.core import flight_recorder as fr
    raw = (args.get('clusters') or args.get('cluster') or '').strip()
    if raw:
        ids = []
        for part in raw.split(','):
            part = part.strip()
            if part and part not in ids:
                ids.append(part)
        if not ids or len(ids) > fr.CLUSTERS_MAX or any(len(c) > 128 for c in ids):
            return None, _bad(f'clusters is a list of up to {fr.CLUSTERS_MAX} cluster ids')
        for cid in ids:
            ok, err = check_cluster_access(cid)
            if not ok:
                return None, err
            if cluster_managers.get(cid) is None:
                return None, (jsonify({'error': 'Cluster not found'}), 404)
        return ids, None
    ids = []
    for cid in sorted(cluster_managers):
        if check_cluster_access(cid)[0]:
            ids.append(cid)
    return ids[:fr.CLUSTERS_MAX], None


def _walk_cluster(cid, mgr, user, since, until, kinds, severities, cap, floor=None):
    """Every event of one cluster in the window the caller may see, page by page:
    (events, {kind: note} of the first page, whether more were left over). floor: the order
    of the oldest event a full bundle keeps; a page that reaches below it is the last one."""
    out, seen, notes, before = [], set(), None, None
    for _ in range(_EVIDENCE_PAGES):
        hi, edge = until, None
        if before and before[0] <= until:
            hi = edge = before[0].replace(microsecond=0)
        ask = _Ask(cid, mgr, user, None, None, since, hi, tl.LIMIT_MAX, edge=edge, before=before,
                   kinds=kinds, severities=severities)
        shown, nxt, page_notes = _one_page(ask, since, until, timedelta(0))
        if notes is None:
            notes = {k: {a: b for a, b in n.items() if a != 'count'} for k, n in page_notes.items()}
        for ev in shown:
            if ev['id'] not in seen:
                seen.add(ev['id'])
                out.append(ev)
        if not nxt:
            return out, notes, False
        if len(out) >= cap or (floor is not None and shown and tl.order(shown[-1]) < floor):
            return out, notes, True
        cursor = tl.parse_cursor(nxt)
        if cursor == before:
            return out, notes, False
        before = cursor
    return out, notes, True


@bp.route('/api/timeline/evidence', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_timeline_evidence():
    """The timeline of a window as a signed JSON attachment: the events the caller may see
    (every page of them, up to EVENTS_MAX), the audit rows of the window when the caller
    holds admin.audit, and where the audit chain stood. Same query as GET /api/timeline:
    ?clusters=<id,id> (all the caller reaches by default) ?from= ?to= ?kinds= ?severity="""
    import socket
    from flask import Response
    from pegaprox.constants import PEGAPROX_VERSION
    from pegaprox.core import flight_recorder as fr
    from pegaprox.utils.audit import log_audit
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission

    args = request.args
    ids, err = _evidence_clusters(args)
    if err:
        return err
    try:
        since, until, clipped, kinds, severities = _window_args(args)
    except ValueError as e:
        return _bad(str(e))

    username = request.session.get('user', '')
    user = build_authz_user(username, request.session)
    # NS Oct 2026 - the cap is the bundle's: what is kept is cut to it after each cluster, and
    # once it is full the next cluster is read no deeper than the oldest event kept. Each
    # walked to a cap of its own, 50 busy clusters held a million events for 20000.
    events, sources, truncated = [], {}, False
    from pegaprox.utils.concurrent import HubTurns
    turns = HubTurns()
    for cid in ids:
        # up to 50 clusters, each read and sorted here: the others get the hub in between
        turns.take()
        floor = tl.order(events[-1]) if len(events) >= fr.EVENTS_MAX else None
        got, notes, more = _walk_cluster(cid, cluster_managers[cid], user, since, until, kinds, severities,
                                         fr.EVENTS_MAX, floor=floor)
        sources[cid] = notes or {}
        events = sorted(events + got, key=tl.order, reverse=True)
        truncated = truncated or more or len(events) > fr.EVENTS_MAX
        del events[fr.EVENTS_MAX:]

    clusters = []
    for cid in ids:
        name = getattr(getattr(cluster_managers[cid], 'config', None), 'name', '')
        clusters.append({'id': cid, 'name': name if isinstance(name, str) else ''})
    doc = {
        'format': fr.FORMAT, 'version': fr.VERSION,
        'generated_at': tl.iso(datetime.now(timezone.utc)), 'generated_by': username,
        'instance': {'name': socket.gethostname(), 'version': PEGAPROX_VERSION},
        'window': {'since': tl.iso(since), 'until': tl.iso(until), 'clipped': clipped},
        'filters': {'clusters': ids, 'kinds': sorted(kinds) if kinds else None,
                    'severities': sorted(severities) if severities else None},
        'clusters': clusters,
        'sources': sources,
        'events': [tl.public(e) for e in events],
        'event_count': len(events), 'event_cap': fr.EVENTS_MAX, 'truncated': truncated,
    }
    audit_count = None
    if has_permission(user, 'admin.audit'):
        # NS Oct 2026 - scoped as GET /api/audit scopes a caller confined to some clusters: the
        # rows of the clusters they see whole. A cluster they only reach through some guests
        # adds none, and neither does the caller's own trail outside these clusters.
        whole = [c for c in ids if not caller_is_scoped(user, c)]
        rows, audit_cut = fr.audit_rows(whole, since, until)
        doc['audit'] = {'included': True, 'clusters': whole, 'rows': fr.public_rows(rows),
                        'row_count': len(rows), 'row_cap': fr.AUDIT_MAX, 'truncated': audit_cut}
        doc['audit_chain'] = dict(fr.chain_report(rows), included=True)
        audit_count = len(rows)
    else:
        why = 'the audit rows need the admin.audit permission'
        doc['audit'] = {'included': False, 'why': why}
        doc['audit_chain'] = {'included': False, 'why': why}
    fr.sign(doc)

    # the clusters by id, and the export of a single one is that cluster's row (as the
    # recovery evidence does it), so its own trail and timeline show who took it
    one = clusters[0] if len(clusters) == 1 else None
    log_audit(username or 'system', 'timeline.evidence_export',
              f"Exported flight recorder evidence {doc['window']['since']} to {doc['window']['until']}: "
              f"{len(events)} events" + (f", {audit_count} audit rows" if audit_count is not None else '')
              + f", {len(ids)} clusters ({', '.join(ids)})" + (' (events cut at the cap)' if truncated else ''),
              cluster=(one['name'] or one['id']) if one else None, cluster_id=one['id'] if one else None)

    def stamp(dt):
        return dt.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name = f'flight-recorder-{stamp(since)}-{stamp(until)}.json'
    return Response(json.dumps(doc, ensure_ascii=False, indent=1), mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename="{name}"'})


@bp.route('/api/timeline/evidence/verify', methods=['POST'])
@require_auth(perms=['cluster.view'])
def verify_timeline_evidence():
    """Check a bundle against this instance: signed by it, and unchanged since. Answers
    {valid, reason}."""
    from pegaprox.core import flight_recorder as fr
    res = fr.verify_body(request.get_data()) if request.is_json else None
    if res is None:
        return _bad('The body must be a flight recorder bundle')
    return jsonify(res)
