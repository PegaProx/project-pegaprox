# -*- coding: utf-8 -*-
"""
PegaProx Metrics Collection - Layer 7
Background metrics snapshot collection.
"""

import os
import time
import json
import logging
import threading
from datetime import datetime

from pegaprox.constants import CONFIG_DIR
METRICS_HISTORY_FILE = os.path.join(CONFIG_DIR, 'metrics_history.json')

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.utils.concurrent import run_per_node  # #601: SSH-aware bounded fan-out for per-node temp reads


def _node_hottest_temp(mgr, node):
    """#601 — SSH lm-sensors → hottest temperature reading (°C) for one node, or None.

    Honours a per-node backoff so installs WITHOUT lm-sensors/SSH (or non-PVE hosts)
    aren't re-probed every 5-min cycle — an error parks the node for ~1h. Nodes that
    do report temps clear their backoff, so a freshly-installed lm-sensors is picked
    up on the next successful probe.
    """
    import time as _t
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
    }


def load_metrics_history():
    """Load historical metrics from SQLite database.

    NS 2026-06-05 (#528 scaling): this SELECTed up to 1000 snapshot rows and
    json.loads'd each — multi-MB blobs at fleet scale — ON THE HUB, a multi-second
    freeze per report (reports.py calls this up to 3× per report). Now the fetch
    + parse run off-hub via run_heavy_read, with a short TTL cache so the repeated
    calls within a report (and back-to-back reports) coalesce onto one query.
    """
    try:
        from pegaprox.core.dbcrypto import run_heavy_read

        def _parse(rows):
            out = []
            for row in rows:
                try:
                    data = json.loads(row['data'])
                    data['timestamp'] = row['timestamp']
                    out.append(data)
                except Exception:
                    pass
            return out

        snapshots = run_heavy_read(
            'SELECT timestamp, data FROM metrics_history ORDER BY timestamp DESC LIMIT 1000',
            cache_key='mh_reports_1000', transform=_parse)
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
    """
    try:
        from pegaprox.core.dbcrypto import run_heavy_write
        from datetime import timedelta
        timestamp = snapshot.get('timestamp', datetime.now().isoformat())
        cutoff = (datetime.now() - timedelta(days=_retention_days())).isoformat()

        def _build():
            # json.dumps of the multi-MB blob happens HERE, in the worker thread
            data = json.dumps({k: v for k, v in snapshot.items() if k != 'timestamp'})
            return [
                ("INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)", (timestamp, data)),
                # indexed prune (idx_metrics_timestamp) — keep last N days
                ("DELETE FROM metrics_history WHERE timestamp < ?", (cutoff,)),
            ]
        run_heavy_write(build=_build)
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
    
    for cluster_id, mgr in cluster_managers.items():
        if not mgr.is_connected:
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
            try:
                online_node_names = list(cluster_data['nodes'].keys())
                if online_node_names:
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
                from pegaprox.api.nodes import _hw_consent_state
                _hw_enabled = _hw_consent_state()[0]
            except Exception:
                _hw_enabled = False
            if _hw_enabled and getattr(mgr, 'cluster_type', 'proxmox') == 'proxmox':
                try:
                    online_node_names = list(cluster_data['nodes'].keys())
                    if online_node_names:
                        hw_calls = {name: (lambda nm: _node_hw_summary(mgr, nm))
                                    for name in online_node_names}
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
                            bo = getattr(mgr, '_node_hw_probe_backoff', None)
                            if isinstance(bo, dict):
                                for k in [k for k in bo if k not in known]:
                                    bo.pop(k, None)
                        if got:
                            logging.debug(f"[metrics] {cluster_id}: hw-health for {got}/{len(online_node_names)} node(s)")
                except Exception as _he:
                    logging.debug(f"[metrics] {cluster_id}: hw-health collection skipped: {_he}")

            # Count VMs + per-VM samples for right-sizing (MK May 2026)
            cluster_data['vms'] = {}  # vmid -> {cpu_pct, mem_pct, maxmem, maxcpu, status}
            try:
                resources = mgr.get_vm_resources()
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
                    }
            except Exception:
                pass

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
    logging.info("Metrics collector started")



