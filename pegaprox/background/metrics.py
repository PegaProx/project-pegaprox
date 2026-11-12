# -*- coding: utf-8 -*-
"""
PegaProx Metrics Collection - Layer 7
Background metrics snapshot collection.
"""

import os
import math
import time
import json
import logging
import threading
from datetime import datetime

from pegaprox.constants import CONFIG_DIR
METRICS_HISTORY_FILE = os.path.join(CONFIG_DIR, 'metrics_history.json')

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.core import ha
from pegaprox.utils.concurrent import run_per_node  # #601: SSH-aware bounded fan-out for per-node temp reads
from pegaprox.background import metrics_store


def _node_hottest_temp(mgr, node):
    """#601 - SSH lm-sensors (or the kernel's hwmon) → hottest temperature (°C) for one node, or None.

    Honours a per-node backoff so installs WITHOUT lm-sensors/SSH (or non-PVE hosts)
    aren't re-probed every 5-min cycle — an error parks the node for ~1h. Nodes that
    do report temps clear their backoff, so a freshly-installed lm-sensors is picked
    up on the next successful probe.
    """
    import time as _t
    # MK Oct 2026 - SSH off for this cluster (switched off, or only an API token): nothing
    # to read, so no address lookup for it either. No backoff, so switching SSH back on
    # shows temperatures from the next cycle.
    _blocked = getattr(mgr, 'ssh_blocked_reason', None)
    if callable(_blocked) and isinstance(_blocked(), str):
        return None
    backoff = getattr(mgr, '_node_temp_probe_backoff', None)
    if backoff is None:
        backoff = mgr._node_temp_probe_backoff = {}
    until = backoff.get(node, 0)
    if until and _t.time() < until:
        return None
    try:
        res = mgr.get_node_sensors(node)
    except Exception:
        res = {'error': 'exception'}
    if not isinstance(res, dict) or res.get('error'):
        backoff[node] = _t.time() + 3600  # no sensors/SSH here → don't storm SSH
        return None
    temps = [s.get('value') for s in (res.get('sensors') or [])
             if s.get('kind') == 'temp' and isinstance(s.get('value'), (int, float))]
    backoff.pop(node, None)  # works here — clear any prior backoff
    if not temps:
        return None
    return round(max(temps), 1)


def _node_hw_summary(mgr, node):
    """#609 phase 2 — in-band ipmitool → compact hardware-health summary for one node,
    or None. Mirrors _node_hottest_temp's backoff: a node without ipmitool/BMC (or an
    SSH failure) is parked ~1h so we never storm SSH; an available node clears its
    backoff. Returns {'available', 'health', 'reason'?, 'power_w'?, 'bad':[...]}.
    """
    import time as _t
    from pegaprox.core import bmc
    backoff = getattr(mgr, '_node_hw_probe_backoff', None)
    if backoff is None:
        backoff = mgr._node_hw_probe_backoff = {}
    until = backoff.get(node, 0)
    if until and _t.time() < until:
        return None
    try:
        res = bmc.read_node_bmc_inband(mgr, node)
    except Exception:
        res = None
    if not isinstance(res, dict):
        backoff[node] = _t.time() + 3600
        return None
    if not res.get('available'):
        backoff[node] = _t.time() + 3600  # ipmitool/BMC absent or unreachable → don't re-probe every cycle
        return {'available': False, 'reason': res.get('reason', 'unavailable')}
    backoff.pop(node, None)
    return _compact_hw(res)


def _compact_hw(res):
    """Full normalized hardware dict (bmc/redfish) → the compact cache summary
    {available, health, power_w, bad[], source} used by the rollup + alert loop."""
    bad = [s['name'] for s in (res.get('sensors') or [])
           if s.get('status') in ('warning', 'critical') and s.get('name')]
    bad += [(f"SEL: {e.get('sensor') or e.get('description') or 'event'}")
            for e in (res.get('events') or []) if e.get('severity') in ('warning', 'critical')][:5]
    chas = res.get('chassis') or {}
    if (chas.get('intrusion') or '').lower() not in ('', 'inactive', 'not present', 'disabled'):
        bad.append('chassis intrusion')
    return {
        'available': True,
        'health': res.get('health', 'ok'),
        'power_w': res.get('power_w'),
        'bad': bad[:12],
        'source': res.get('source', 'inband'),
    }


def _node_hw_summary_redfish(mgr, cluster_id, node):
    """#609 phase 3 — out-of-band Redfish → compact hardware summary for a node that
    has a configured BMC endpoint, or None. Own backoff: a node without an endpoint,
    or an unreachable BMC, is parked ~1h so we don't hammer the management network."""
    import time as _t
    from pegaprox.core import redfish
    from pegaprox.core.db import get_db
    backoff = getattr(mgr, '_node_rf_probe_backoff', None)
    if backoff is None:
        backoff = mgr._node_rf_probe_backoff = {}
    until = backoff.get(node, 0)
    if until and _t.time() < until:
        return None
    try:
        ep = get_db().get_bmc_endpoint(cluster_id, node)
    except Exception:
        ep = None
    if not (ep and ep.get('enabled') and ep.get('host')):
        backoff[node] = _t.time() + 3600  # no endpoint configured → don't recheck every cycle
        return None
    try:
        res = redfish.read_node_bmc_redfish(ep['host'], ep.get('user'), ep.get('password'),
                                            ep.get('verify_ssl', False), timeout=8)
    except Exception:
        res = None
    if not isinstance(res, dict) or not res.get('available'):
        backoff[node] = _t.time() + 3600  # BMC unreachable/auth-fail → back off
        return {'available': False, 'reason': (res or {}).get('reason', 'unavailable')} if isinstance(res, dict) else None
    backoff.pop(node, None)
    return _compact_hw(res)


# Upper bound on a windowed history read. A week at the 5-min cadence and
# stride 3 is ~670 rows, so this only bites where snapshots land far more often
# than they should, and there it stops one report from dragging tens of
# thousands of encrypted blobs through the parser.
_WINDOW_ROW_CAP = 4000


# MK Oct 2026 - a windowed read is cached per window and stays in memory until the
# next read of that window replaces it. At 10k guests one parsed snapshot is ~5 MB,
# nearly all of it the per-guest map, so a cached week held a few GB for figures the
# reports never look at. Trimmed row by row, so the parse never holds them all either.
def _cluster_totals_only(snap):
    """Keep each cluster's name and totals, drop the guest, node and storage maps."""
    clusters = snap.get('clusters')
    if isinstance(clusters, dict):
        # only keys that are there, so a reader's .get(key, default) still sees a gap as one
        snap['clusters'] = {cid: {k: c[k] for k in ('name', 'totals') if k in c}
                            for cid, c in clusters.items() if isinstance(c, dict)}
    return snap


def load_metrics_history(days=None, totals_only=False):
    """Load historical metrics from SQLite database.

    NS 2026-06-05 (#528 scaling): this SELECTed up to 1000 snapshot rows and
    json.loads'd each — multi-MB blobs at fleet scale — ON THE HUB, a multi-second
    freeze per report (reports.py calls this up to 3× per report). Now the fetch
    + parse run off-hub via run_heavy_read, with a short TTL cache so the repeated
    calls within a report (and back-to-back reports) coalesce onto one query.

    `days` bounds the read by TIME. The flat LIMIT 1000 covers ~3.5 days at the
    5-min cadence and a good deal less when snapshots land more often, so a
    caller asking for a week got "the newest 1000 rows" and no way to tell the
    difference. That is why the reports page showed the same window for
    "Last 24h" and "Last Week". Callers that know their window pass it, and the
    windowed read comes back oldest-first, which is the order a timeline wants.
    days=None keeps the old row-capped (newest-first) behaviour.

    totals_only=True hands back each cluster's name and totals and nothing else,
    which is all the report endpoints read (see _cluster_totals_only).

    MK Oct 2026 - the rows are the same as before (the same SQL picks them); what a
    converted row holds is read from its parts (background/metrics_store.py) in the
    same transaction: the heads only for totals_only, which leaves the guest maps unread.
    """
    try:
        from datetime import timedelta
        from pegaprox.core.dbcrypto import run_heavy_read
        parts = (metrics_store.P_HEAD, metrics_store.P_WHOLE) if totals_only else \
            (metrics_store.P_HEAD, metrics_store.P_NODES, metrics_store.P_STORAGE,
             metrics_store.P_GUESTS, metrics_store.P_WHOLE)

        def _parse(results):
            rows, got = results[0], metrics_store.SnapParts(*results[1:])
            out = []
            for row in rows:
                try:
                    data = metrics_store.snapshot_data(row, got)
                    data['timestamp'] = row['timestamp']
                    out.append(_cluster_totals_only(data) if totals_only else data)
                except Exception:
                    pass
            return out

        key_tail = '_totals' if totals_only else ''
        if days:
            # One decimation policy for every history consumer rather than a
            # second copy of it here. A week of 5-min rows is ~2000 blobs to
            # decrypt + parse, and every consumer either averages or feeds a
            # chart that decimates to 200 points anyway, so the skipped rows are
            # never decrypted: the modulo is answered from the timestamp index.
            from pegaprox.api.helpers import _history_stride
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            stride = _history_stride(days)
            if stride > 1:
                # Anchored on the newest row instead of a bare `id % stride = 0`.
                # A plain modulo keeps the last snapshot only when its id happens
                # to divide, so two times out of three the newest sample is
                # dropped and a report's `current` is silently a stride older
                # than the data it was read from.
                where = ('WHERE timestamp >= ? AND '
                         '((SELECT MAX(id) FROM metrics_history) - id) % ? = 0')
                params = (cutoff, stride)
            else:
                where = 'WHERE timestamp >= ?'
                params = (cutoff,)
            # The old flat LIMIT was also the only thing bounding the work. A
            # window is a time span, so on an install writing far more often than
            # the 5-min cadence a week is unbounded decrypt + parse. Keep a
            # backstop, and trim it from the OLD end so the recent resolution the
            # charts are about survives.
            newest = (f'SELECT id, timestamp, data, fmt FROM metrics_history '
                      f'{where} ORDER BY timestamp DESC LIMIT {_WINDOW_ROW_CAP}')
            sql = f'SELECT id, timestamp, data, fmt FROM ({newest}) ORDER BY timestamp ASC'
            ids = f'SELECT id FROM metrics_history {where} ORDER BY timestamp DESC LIMIT {_WINDOW_ROW_CAP}'
            snapshots = run_heavy_read(
                [(sql, params)] + metrics_store.part_statements(ids, params, parts),
                cache_key=f'mh_reports_d{days}{key_tail}', transform=_parse)
        else:
            sql = 'SELECT id, timestamp, data, fmt FROM metrics_history ORDER BY timestamp DESC LIMIT 1000'
            ids = 'SELECT id FROM metrics_history ORDER BY timestamp DESC LIMIT 1000'
            snapshots = run_heavy_read(
                [(sql, ())] + metrics_store.part_statements(ids, (), parts),
                cache_key=f'mh_reports_1000{key_tail}', transform=_parse)
        return {'snapshots': snapshots, 'last_cleanup': None}
    except Exception as e:
        logging.error(f"Error loading metrics history from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(METRICS_HISTORY_FILE):
                with open(METRICS_HISTORY_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
    return {'snapshots': [], 'last_cleanup': None}


# MK Oct 2026 - a time range picked on a chart: any from/to the stored snapshots reach,
# for one node, one guest or one cluster's totals. Not cached: the keys would be as many
# as the ranges anybody ever picks, and run_heavy_read keeps a key until it is read again.
# Bounded instead. The stride keeps the rows at what a chart draws (LineChart decimates to
# 200 points anyway), and pick() keeps the few figures asked for out of each blob inside
# the worker thread, so the multi-MB snapshots never pile up.
_RANGE_ROWS = 200
_RANGE_MAX_SECONDS = 366 * 86400
# MK Oct 2026 - one range parse at a time. A range is up to 200 whole snapshots, seconds of
# parsing at 10k guests, and each took one of the slots the cached report reads share: a
# few chart drags at once held all of them, and the power, cost and insight pages waited
_range_slot = []


def history_range(args, now=None):
    """from/to of a request, unix seconds, as a range of the stored history.

    (start, end, None), or (None, None, why) for a 400. A range older than the
    retention or reaching into the future is cut to what is stored, so it can come
    back empty; nonsense (no numbers, to not after from, more than a year) is refused.
    """
    raw_from, raw_to = args.get('from'), args.get('to')
    if raw_from is None or raw_to is None:
        return None, None, 'from and to are both needed, in unix seconds'
    try:
        start, end = float(raw_from), float(raw_to)
    except (TypeError, ValueError):
        return None, None, 'from and to are unix seconds'
    if not (math.isfinite(start) and math.isfinite(end)) or start < 0:
        return None, None, 'from and to are unix seconds'
    if end - start < 60:
        return None, None, 'to has to be at least a minute after from'
    if end - start > _RANGE_MAX_SECONDS:
        return None, None, 'A range spans a year at most'
    now = time.time() if now is None else now
    return max(start, now - _retention_days() * 86400), min(end, now), None


def _range_sem():
    if not _range_slot:
        try:
            from gevent.lock import BoundedSemaphore
            _range_slot.append(BoundedSemaphore(1))
        except Exception:
            _range_slot.append(None)
    return _range_slot[0]


# what a pick of load_metrics_range reads of its cluster -> the parts that holds
_RANGE_PARTS = {'nodes': (metrics_store.P_NODES, metrics_store.P_WHOLE),
                'vms': (metrics_store.P_GUESTS, metrics_store.P_WHOLE),
                'head': (metrics_store.P_HEAD, metrics_store.P_WHOLE)}


def load_metrics_range(start, end, pick, cluster_id=None, parts=None):
    """[(timestamp, pick(clusters))] of the snapshots from start to end (unix seconds),
    oldest first, at most about _RANGE_ROWS of them. pick gets the clusters map of one
    snapshot and returns what to keep of it, None where it has nothing.

    MK Oct 2026 - cluster_id and parts ('nodes', 'vms' or 'head') say what pick reads:
    of a converted row only that part of that cluster is read then, and pick gets a map of
    just that ({cluster_id: {'nodes': ...}}; the guests come one at a time, as a chart of
    one guest asks for them). Rows an older PegaProx wrote are parsed whole, as before."""
    from pegaprox.core.dbcrypto import run_heavy_read, _heavy_sem
    if end <= start:
        return []
    lo = datetime.fromtimestamp(start).isoformat()
    hi = datetime.fromtimestamp(end).isoformat()
    if parts and cluster_id is not None:
        wanted = sorted({p for name in parts for p in _RANGE_PARTS[name]})
    else:
        cluster_id = None
        wanted = (metrics_store.P_HEAD, metrics_store.P_NODES, metrics_store.P_STORAGE,
                  metrics_store.P_GUESTS, metrics_store.P_WHOLE)

    def _parse(results):
        rows, got = results[0], metrics_store.SnapParts(*results[1:])
        out = []
        for row in rows:
            try:
                clusters = metrics_store.snapshot_clusters(row, got, lazy_guests=cluster_id is not None)
                out.append((row['timestamp'], pick(clusters)))
            except Exception:
                continue
        return out

    # every n-th row, n from the count of the range (answered from the timestamp index),
    # anchored on the newest row of the range so its right edge is always there
    in_range = 'FROM metrics_history WHERE timestamp >= ? AND timestamp <= ?'
    picked = (f'{in_range} '
              f'AND ((SELECT MAX(id) {in_range}) - id) % '
              f'MAX(1, ((SELECT COUNT(*) {in_range}) + ? - 1) / ?) = 0 '
              'ORDER BY timestamp ASC LIMIT ?')
    params = (lo, hi, lo, hi, lo, hi, _RANGE_ROWS, _RANGE_ROWS, _RANGE_ROWS * 2)
    statements = [(f'SELECT id, timestamp, data, fmt {picked}', params)] + \
        metrics_store.part_statements(f'SELECT id {picked}', params, wanted, cluster_id)
    try:
        # the same cap the cached heavy reads take, and never more than one of its slots
        from contextlib import nullcontext
        sem = _heavy_sem()
        with (_range_sem() or nullcontext()), (sem or nullcontext()):
            return run_heavy_read(statements, (), transform=_parse)
    except Exception as e:
        logging.error(f"Error loading a metrics range: {e}")
        return []


def _node_maps(results, cluster_id):
    """(timestamp, nodes) of each row of a node history read, one at a time; a row that
    does not read is left out, as the route skipped it."""
    rows, got = results[0], metrics_store.SnapParts(*results[1:])
    for row in rows:
        try:
            if row['fmt'] == metrics_store.FMT_PARTS:
                clusters = got.clusters(row['id'])
            else:
                # the steps of the old read: the row parsed, its timestamp set, the cluster
                snap = metrics_store.snapshot_data(row, got)
                snap['timestamp'] = row['timestamp']
                clusters = snap.get('clusters')
            nodes = ((clusters or {}).get(cluster_id) or {}).get('nodes') or {}
        except Exception:
            continue
        yield row['timestamp'], nodes


def load_node_history(cluster_id):
    """[(timestamp, nodes)] of one cluster in the newest 1000 snapshots, newest first, for
    the temperature chart of a node. nodes is what the route read before of each snapshot,
    ((clusters.get(cluster_id) or {}).get('nodes') or {}); a snapshot that does not read is
    left out, as the route skipped it.

    MK Oct 2026 - the route read the newest 1000 whole fleet snapshots (load_metrics_history()
    without a window) for one number per row, and kept them for a minute: gigabytes at a few
    thousand guests. The same rows, but of a converted one only this cluster's nodes are
    read, and nothing is kept."""
    from pegaprox.core.dbcrypto import run_heavy_read, _heavy_sem
    sql = 'SELECT id, timestamp, data, fmt FROM metrics_history ORDER BY timestamp DESC LIMIT 1000'
    ids = 'SELECT id FROM metrics_history ORDER BY timestamp DESC LIMIT 1000'

    def _parse(results):
        return list(_node_maps(results, cluster_id))

    try:
        from contextlib import nullcontext
        with (_heavy_sem() or nullcontext()):
            return run_heavy_read(
                [(sql, ())] + metrics_store.part_statements(
                    ids, (), (metrics_store.P_NODES, metrics_store.P_WHOLE), cluster_id),
                (), transform=_parse)
    except Exception as e:
        logging.error(f"Error loading the node history of {cluster_id}: {e}")
        return []


def load_node_temps(cluster_id, node):
    """[(timestamp, temp)] of one node in the newest 1000 snapshots, newest first: the
    points the temperature chart draws, where (nodes.get(node) or {}).get('temp') of a
    snapshot (load_node_history) is a value and the row has a timestamp.

    MK Oct 2026 - at 200 nodes that was 1000 maps of all nodes (16 MB) read, parsed and
    held at once per request, for one number a row. Each map is let go as soon as its point
    is out, and the points are kept a minute under the heavy-read cache, as the whole
    history was kept before (a chart of one node is asked for again and again)."""
    from pegaprox.core.dbcrypto import run_heavy_read
    sql = 'SELECT id, timestamp, data, fmt FROM metrics_history ORDER BY timestamp DESC LIMIT 1000'
    ids = 'SELECT id FROM metrics_history ORDER BY timestamp DESC LIMIT 1000'

    def _points(results):
        out = []
        for ts, nodes in _node_maps(results, cluster_id):
            try:
                temp = (nodes.get(node) or {}).get('temp')
            except Exception:
                continue
            if temp is not None and ts:
                out.append((ts, temp))
        return out

    try:
        return run_heavy_read(
            [(sql, ())] + metrics_store.part_statements(
                ids, (), (metrics_store.P_NODES, metrics_store.P_WHOLE), cluster_id),
            (), cache_key=f'mh_node_temps:{cluster_id}:{node}', transform=_points)
    except Exception as e:
        logging.error(f"Error loading the temperatures of {cluster_id}/{node}: {e}")
        return []


def history_series(rows, fields):
    """Rows of load_metrics_range, where pick kept one node or guest entry, in the shape
    of the RRD charts: {timestamps, metrics: {name: [...]}}. fields maps a chart name to
    the key in the entry. A snapshot without the entry, or without a number for a field,
    is a gap (None), as in the RRD series."""
    out = {'timestamps': [], 'metrics': {name: [] for name in fields}, 'source': 'history'}
    for ts, entry in rows:
        try:
            out['timestamps'].append(int(datetime.fromisoformat(ts).timestamp()))
        except (TypeError, ValueError):
            continue
        for name, key in fields.items():
            v = entry.get(key) if isinstance(entry, dict) else None
            ok = isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
            out['metrics'][name].append(v if ok else None)
    return out


def save_metrics_history(history):
    """Save metrics history - now saves individual snapshots
    
    SQLite migration
    This function is kept for backwards compatibility
    """
    # In SQLite version, snapshots are saved individually
    pass


# MK 2026-06-03 (#456 — long-term metric history beyond RRD): retention is
# now env-driven. Default stays at 30 days (8640 snapshots × 5min cadence)
# so existing installs see no behaviour change. Operators who want longer
# history for compliance / capacity-planning set
# PEGAPROX_METRICS_RETENTION_DAYS — clamped to [7, 365] so a typo can't
# accidentally wipe the table or balloon the DB. 365d on a 50-VM cluster
# is roughly 200 MB in the data column, well within reason.
def _retention_snapshots():
    raw = os.environ.get('PEGAPROX_METRICS_RETENTION_DAYS', '30').strip()
    try:
        days = int(raw)
    except (TypeError, ValueError):
        days = 30
    days = max(7, min(days, 365))
    return days * 288  # 24h × (60/5min)


def _retention_days():
    raw = os.environ.get('PEGAPROX_METRICS_RETENTION_DAYS', '30').strip()
    try:
        days = int(raw)
    except (TypeError, ValueError):
        days = 30
    return max(7, min(days, 365))


def save_metrics_snapshot(snapshot):
    """Save a single metrics snapshot to SQLite.

    Cadence: every 5 min. Retention defaults to 30 days; override via
    PEGAPROX_METRICS_RETENTION_DAYS (7..365). The data column is a JSON
    blob of the per-cluster snapshot — see collect_metrics_snapshot for
    the shape. Insights / Cost / Power / Prometheus exporter / the new
    `/insights/history` endpoint all read from this table so it's a
    single source of truth.

    NS 2026-06-05 (#528 scaling): at 30 clusters / 100+ nodes the data blob is
    multi-MB, and json.dumps + SQLCipher-encrypt + INSERT + prune all ran on the
    gevent hub every 5 min — a periodic freeze. Now the whole thing (incl. the
    json.dumps) runs off-hub on a fresh connection via run_heavy_write, and the
    prune is an indexed timestamp DELETE instead of a full-table anti-join.

    MK Oct 2026 - the snapshot goes into its per-cluster parts (metrics_store.save), the
    row and its parts and the prune in one transaction, still off the hub.
    """
    try:
        from datetime import timedelta
        timestamp = snapshot.get('timestamp', datetime.now().isoformat())
        cutoff = (datetime.now() - timedelta(days=_retention_days())).isoformat()
        metrics_store.save(snapshot, timestamp, cutoff)
    except Exception as e:
        logging.error(f"Error saving metrics snapshot: {e}")


def collect_metrics_snapshot():
    """Collect current metrics from all clusters
    
    Called periodically to build historical data
    """
    snapshot = {
        'timestamp': datetime.now().isoformat(),
        'clusters': {}
    }
    
    # snapshot the dict first: the body below fans out over SSH (run_per_node) and
    # hits the API, so one cycle can sit on the wire for minutes. Every one of those
    # is a gevent yield point, and a cluster added or deleted meanwhile would raise
    # "dictionary changed size during iteration" — metrics_collector_loop swallows
    # that and we silently lose the whole 5-minute cycle. MK
    for cluster_id, mgr in list(cluster_managers.items()):
        if not mgr.is_connected:
            continue
        # an ESXi host registered for XHM is in cluster_managers too: no nodes, no storage
        # of its own to sample, and every cycle it only left a failure line here
        if getattr(mgr, 'cluster_type', 'proxmox') == 'esxi':
            continue
        
        try:
            cluster_data = {
                'name': mgr.config.name,
                'nodes': {},
                'totals': {
                    'vms_running': 0,
                    'vms_stopped': 0,
                    'cts_running': 0,
                    'cts_stopped': 0,
                    'cpu_used': 0,
                    'cpu_total': 0,
                    'mem_used': 0,
                    'mem_total': 0
                }
            }
            
            # Collect node metrics
            for node_name, node_data in (mgr.nodes or {}).items():
                if node_data.get('status') != 'online':
                    continue
                
                cluster_data['nodes'][node_name] = {
                    'cpu': round(node_data.get('cpu', 0) * 100, 1),
                    'mem_percent': round(node_data.get('mem', 0) / max(node_data.get('maxmem', 1), 1) * 100, 1),
                    'maxcpu': node_data.get('maxcpu', 0),
                    'maxmem': node_data.get('maxmem', 0)
                }
                
                cluster_data['totals']['cpu_total'] += node_data.get('maxcpu', 0)
                cluster_data['totals']['cpu_used'] += node_data.get('cpu', 0) * node_data.get('maxcpu', 0)
                cluster_data['totals']['mem_total'] += node_data.get('maxmem', 0)
                cluster_data['totals']['mem_used'] += node_data.get('mem', 0)

            # #601 — per-node hottest temperature (°C) for the history chart + the
            # temperature alert metric. lm-sensors is SSH-side, so fan out over ALL
            # online nodes with the SSH-AWARE primitive: run_per_node caps concurrency
            # at 8/cluster so we never open 30+ simultaneous SSH sessions (which trips
            # AccountLockFailures on hardened nodes). Real PVE (corosync) clusters are
            # <=~32 nodes, so 90s comfortably covers a whole cluster each cycle. Runs on
            # the 5-min collector greenlet, off the broadcast hot-path. Writes both the
            # snapshot (→ persisted history) and the manager temp-cache (→ read by the
            # 60s alert loop, which must not SSH).
            # MK Sep 2026 (#625) - not from a PegaProx standby, and neither is the BMC and
            # Redfish fan-out below: the active reads the same nodes already, and a TOFU pin
            # made here would land in the known_hosts file the sync replaces. The API figures
            # above and below are what a standby's live view shows.
            try:
                online_node_names = list(cluster_data['nodes'].keys())
                if online_node_names and ha.is_active():
                    node_calls = {name: (lambda nm: _node_hottest_temp(mgr, nm))
                                  for name in online_node_names}
                    temp_by_node = run_per_node(node_calls, max_concurrent=8, timeout=90)
                    now_ts = time.time()
                    tcache = getattr(mgr, '_node_temp_cache', None)
                    tlock = getattr(mgr, '_node_temp_lock', None)
                    got = 0
                    for nm, temp_c in (temp_by_node or {}).items():
                        if temp_c is None:
                            continue
                        cluster_data['nodes'][nm]['temp'] = temp_c
                        got += 1
                        if tcache is not None and tlock is not None:
                            with tlock:
                                tcache[nm] = {'temp': temp_c, 'ts': now_ts}
                    # keep the per-manager caches bounded: drop keys for decommissioned/
                    # renamed nodes so they don't accrete over the process lifetime.
                    known = set(mgr.nodes or {})
                    if known:
                        if tcache is not None and tlock is not None:
                            with tlock:
                                for k in [k for k in tcache if k not in known]:
                                    tcache.pop(k, None)
                        bo = getattr(mgr, '_node_temp_probe_backoff', None)
                        if isinstance(bo, dict):
                            for k in [k for k in bo if k not in known]:
                                bo.pop(k, None)
                    if got:
                        logging.debug(f"[metrics] {cluster_id}: temp for {got}/{len(online_node_names)} node(s)")
            except Exception as _te:
                logging.debug(f"[metrics] {cluster_id}: temp collection skipped: {_te}")

            # #609 phase 2 — per-node in-band BMC health for the cluster degraded-
            # hardware badge + the hardware_health alert metric. Same bounded SSH
            # fan-out as temperature, but GATED on the compliance consent (never poll
            # hardware the admin hasn't opted into) + proxmox-only. Off the hot-path;
            # writes the manager hw-cache read by the 60s alert loop (which must not SSH).
            try:
                from pegaprox.api.nodes import _hw_consent_state, _redfish_consent_state
                _hw_enabled = _hw_consent_state()[0]
                _rf_enabled = _redfish_consent_state()[0]
            except Exception:
                _hw_enabled = _rf_enabled = False
            if ((_hw_enabled or _rf_enabled) and getattr(mgr, 'cluster_type', 'proxmox') == 'proxmox'
                    and ha.is_active()):
                try:
                    online_node_names = list(cluster_data['nodes'].keys())
                    if online_node_names:
                        # #609 phase 3 — prefer in-band; fall back to a configured
                        # out-of-band Redfish endpoint. Defaults bind mgr/cluster_id at
                        # definition time (safe against the outer loop rebinding them).
                        def _hw_one(nm, _m=mgr, _cid=cluster_id, _ib=_hw_enabled, _rf=_rf_enabled):
                            s = _node_hw_summary(_m, nm) if _ib else None
                            if (s is None or not s.get('available')) and _rf:
                                r = _node_hw_summary_redfish(_m, _cid, nm)
                                if r is not None:
                                    s = r
                            return s
                        hw_calls = {name: _hw_one for name in online_node_names}
                        hw_by_node = run_per_node(hw_calls, max_concurrent=8, timeout=90)
                        now_ts = time.time()
                        hcache = getattr(mgr, '_node_hw_cache', None)
                        hlock = getattr(mgr, '_node_hw_lock', None)
                        got = 0
                        for nm, summ in (hw_by_node or {}).items():
                            if summ is None:
                                continue
                            cluster_data['nodes'][nm]['hw_health'] = summ.get('health') if summ.get('available') else None
                            got += 1
                            if hcache is not None and hlock is not None:
                                with hlock:
                                    hcache[nm] = {'summary': summ, 'ts': now_ts}
                        known = set(mgr.nodes or {})
                        if known and hcache is not None and hlock is not None:
                            with hlock:
                                for k in [k for k in hcache if k not in known]:
                                    hcache.pop(k, None)
                            for _bname in ('_node_hw_probe_backoff', '_node_rf_probe_backoff'):
                                bo = getattr(mgr, _bname, None)
                                if isinstance(bo, dict):
                                    for k in [k for k in bo if k not in known]:
                                        bo.pop(k, None)
                        if got:
                            logging.debug(f"[metrics] {cluster_id}: hw-health for {got}/{len(online_node_names)} node(s)")
                except Exception as _he:
                    logging.debug(f"[metrics] {cluster_id}: hw-health collection skipped: {_he}")

            # Count VMs + per-VM samples for right-sizing (MK May 2026)
            cluster_data['vms'] = {}  # vmid -> {cpu_pct, mem_pct, maxmem, maxcpu, status}
            unread = False
            try:
                resources = mgr.get_vm_resources()
                unread = getattr(resources, 'unavailable', False) is True
                for r in resources:
                    rtype = r.get('type')
                    if rtype not in ('qemu', 'lxc'):
                        continue
                    running = r.get('status') == 'running'
                    if rtype == 'qemu':
                        if running: cluster_data['totals']['vms_running'] += 1
                        else: cluster_data['totals']['vms_stopped'] += 1
                    else:
                        if running: cluster_data['totals']['cts_running'] += 1
                        else: cluster_data['totals']['cts_stopped'] += 1
                    vmid = str(r.get('vmid', ''))
                    if not vmid:
                        continue
                    maxmem = int(r.get('maxmem', 0) or 0)
                    maxcpu = int(r.get('maxcpu', 0) or 0)
                    cpu_pct = round((r.get('cpu', 0) or 0) * 100, 1) if running else None
                    mem_pct = round((r.get('mem', 0) or 0) / maxmem * 100, 1) if (running and maxmem > 0) else None
                    cluster_data['vms'][vmid] = {
                        't': rtype, 'r': running, 'cpu': cpu_pct, 'mem': mem_pct,
                        'maxmem': maxmem, 'maxcpu': maxcpu,
                        # #965 - the host it ran on, so power history follows a migration
                        'n': r.get('node') or '',
                    }
            except Exception:
                unread = True
            if unread:
                # NS Nov 2026 - the guest list did not answer (UnreadList) or broke off: this
                # snapshot has no guest counts rather than "0 running", which every chart of
                # the history read as all guests down. The readers skip the missing keys.
                for k in ('vms_running', 'vms_stopped', 'cts_running', 'cts_stopped'):
                    cluster_data['totals'].pop(k, None)
                cluster_data['vms'] = {}

            # Storage totals for capacity forecasting (MK May 2026)
            cluster_data['storage'] = {}
            try:
                host, port = mgr.host, mgr.api_port
                ss = mgr._create_session()
                sresp = ss.get(f"https://{host}:{port}/api2/json/cluster/resources?type=storage", timeout=8)
                if sresp.status_code == 200:
                    seen = set()
                    for s in sresp.json().get('data') or []:
                        sid = s.get('storage') or s.get('id', '')
                        if not sid or sid in seen: continue
                        seen.add(sid)
                        total = int(s.get('maxdisk', 0) or 0)
                        used = int(s.get('disk', 0) or 0)
                        if total > 0:
                            cluster_data['storage'][sid] = {
                                'used': used, 'total': total,
                                'pct': round(used / total * 100, 1),
                            }
            except Exception:
                pass

            snapshot['clusters'][cluster_id] = cluster_data
            
        except Exception as e:
            logging.debug(f"Failed to collect metrics for {cluster_id}: {e}")
    
    return snapshot


def metrics_collector_loop():
    """Background thread that collects metrics every 5 minutes
    
    updated for SQLite
    """
    global _metrics_collector_running
    
    while _metrics_collector_running:
        try:
            snapshot = collect_metrics_snapshot()
            
            # Save directly to SQLite
            save_metrics_snapshot(snapshot)
            
        except Exception as e:
            logging.error(f"Metrics collector error: {e}")
        
        # Sleep 5 minutes
        for _ in range(300):
            if not _metrics_collector_running:
                break
            time.sleep(1)


def start_metrics_collector():
    """Start the metrics collector"""
    global _metrics_collector_running
    
    _metrics_collector_running = True
    thread = threading.Thread(target=metrics_collector_loop, daemon=True)
    thread.start()
    # MK Oct 2026 - the snapshots an older PegaProx stored are converted to parts in the
    # background, a minute after the start so it never holds that up
    metrics_store.start_backfill(delay=60)
    logging.info("Metrics collector started")



