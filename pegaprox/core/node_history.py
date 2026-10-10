# -*- coding: utf-8 -*-
"""When the nodes of a cluster went offline and came back, entered and left maintenance,
and when the cluster lost and regained quorum.

MK Oct 2026 - nothing kept this. The node list shows how a node is now, and the alert
watcher compares two reads in memory and forgets them. observe() takes what one read of the
nodes found (PegaProxManager.get_node_status, which every poller goes through) and writes a
row for each node whose state changed since the read before. It makes no call to Proxmox of
its own. Quorum comes from the reads of /cluster/status the HA monitor makes anyway
(observe_quorum); a cluster that had lost it has it back once every node reads online, since
a partition that holds every node is quorate.

A node seen for the first time is only written when it is not online: a fresh start of
PegaProx is no event. Where each node stood is read back from the newest rows once per
cluster, so a restart reports what changed while it was down and nothing else.

Only an instance that may act records (ha.is_active). The table is per host
(core/ha.py LOCAL_TABLES), and a standby reads the timeline from its active.
"""

import logging
import threading
from datetime import datetime, timezone

from pegaprox.core import ha

ONLINE, OFFLINE, UNKNOWN = 'online', 'offline', 'unknown'
MAINTENANCE, MAINTENANCE_END = 'maintenance', 'maintenance_end'
QUORATE, NO_QUORUM = 'quorate', 'no_quorum'
STATUS_STATES = (ONLINE, OFFLINE, UNKNOWN)
MAINTENANCE_STATES = (MAINTENANCE, MAINTENANCE_END)
QUORUM_STATES = (QUORATE, NO_QUORUM)
STATES = STATUS_STATES + MAINTENANCE_STATES + QUORUM_STATES
# the row of the cluster itself
CLUSTER_ROW = ''

_lock = threading.Lock()
# cluster id -> {'status': {node: state}, 'maintenance': {node: state}, 'quorum': state or None}
_known = {}


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def status_of(info):
    """online, offline or unknown for one node of a get_node_status answer. A node PVE lists
    in maintenance (older versions) is up; the maintenance is its own row."""
    status = str((info or {}).get('status') or '').lower()
    if status in (ONLINE, MAINTENANCE):
        return ONLINE
    if status == OFFLINE or (info or {}).get('offline') is True:
        return OFFLINE
    return UNKNOWN


def _recording():
    """An instance that may act, with its database open: a CLI run or a test that never
    opened one records nothing (and creates no database for it)."""
    from pegaprox.core import db as dbmod
    return dbmod._db is not None and ha.is_active()


def _seeded(cluster_id):
    """Where each node of the cluster stood at its newest rows."""
    known = _known.get(cluster_id)
    if known is not None:
        return known
    from pegaprox.core.db import get_db
    db = get_db()
    status = db.last_node_states(cluster_id, STATUS_STATES)
    maintenance = db.last_node_states(cluster_id, MAINTENANCE_STATES)
    quorum = db.last_node_states(cluster_id, QUORUM_STATES).get(CLUSTER_ROW)
    status.pop(CLUSTER_ROW, None)
    maintenance.pop(CLUSTER_ROW, None)
    with _lock:
        return _known.setdefault(cluster_id, {'status': status, 'maintenance': maintenance,
                                              'quorum': quorum})


def changes(cluster_id, node_status, at=None):
    """The rows one read of the nodes adds, (node, state, previous, at, detail), and what is
    known moves on to it."""
    known = _seeded(cluster_id)
    at = at or now_utc()
    rows = []
    with _lock:
        seen = set()
        for node, info in node_status.items():
            if not node or not isinstance(info, dict):
                continue
            seen.add(node)
            state = status_of(info)
            was = known['status'].get(node)
            in_maintenance = bool(info.get('maintenance_mode'))
            if was != state and not (was is None and state == ONLINE):
                rows.append((node, state, was or '', at,
                             'in maintenance' if in_maintenance and state != ONLINE else ''))
            known['status'][node] = state
            mark = MAINTENANCE if in_maintenance else MAINTENANCE_END
            was = known['maintenance'].get(node)
            if was != mark and not (was is None and mark == MAINTENANCE_END):
                rows.append((node, mark, was or '', at, ''))
            known['maintenance'][node] = mark
        # a node that left the list is forgotten, not reported: it was removed or renamed
        for states in (known['status'], known['maintenance']):
            for gone in [n for n in states if n not in seen]:
                states.pop(gone, None)
        if (known.get('quorum') == NO_QUORUM and seen
                and all(known['status'].get(n) == ONLINE for n in seen)):
            rows.append((CLUSTER_ROW, QUORATE, NO_QUORUM, at, 'every node is online'))
            known['quorum'] = QUORATE
    return rows


def observe(cluster_id, node_status):
    """Note one read of the nodes of a cluster. Never raises, never asks Proxmox."""
    if not cluster_id or not isinstance(node_status, dict) or not node_status:
        return
    try:
        if not _recording():
            return
        rows = changes(cluster_id, node_status)
        if rows:
            from pegaprox.core.db import get_db
            get_db().add_node_states(cluster_id, rows)
    except Exception as e:
        logging.debug(f"[NodeHistory] {cluster_id}: could not note the node states: {e}")


def observe_quorum(cluster_id, quorate, outside=None):
    """Note whether the API host reports the cluster quorate (None: it did not answer,
    which says nothing). outside: the nodes it does not see."""
    if not cluster_id or quorate is None:
        return
    try:
        if not _recording():
            return
        known = _seeded(cluster_id)
        state = QUORATE if quorate else NO_QUORUM
        with _lock:
            was = known.get('quorum')
            known['quorum'] = state
        if was == state or (was is None and state == QUORATE):
            return
        detail = ''
        if outside:
            detail = 'not seen: ' + ', '.join(sorted(str(n) for n in outside if n))
        from pegaprox.core.db import get_db
        get_db().add_node_states(cluster_id, [(CLUSTER_ROW, state, was or '', now_utc(), detail)])
    except Exception as e:
        logging.debug(f"[NodeHistory] {cluster_id}: could not note the quorum: {e}")


def forget(cluster_id=None):
    """Drop what is known in memory (a cluster removed, or the tests); the rows stay."""
    with _lock:
        if cluster_id is None:
            _known.clear()
        else:
            _known.pop(cluster_id, None)
