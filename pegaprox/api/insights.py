# -*- coding: utf-8 -*-
"""
Right-sizing + Capacity Forecasting endpoints — MK May 2026.

Reads from the metrics_history snapshot table (5-min cadence, 30d retention)
and produces:
  - per-VM right-sizing recommendations (oversized / undersized CPU/RAM)
  - per-cluster + per-storage capacity forecasts (linear regression →
    estimated date when 90% threshold gets crossed)

No fancy ML — just simple stats. Linear regression with least squares is
plenty for "trending up by X%/day" predictions on monitoring data.
"""
import json
import logging
import math
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access
from pegaprox.core.db import get_db

bp = Blueprint('insights', __name__)


def _load_history(cluster_id, days=30):
    """Pull all snapshots for a cluster from metrics_history within the window.
    Returns list of (ts_unix, cluster_data_dict) sorted oldest→newest."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    out = []
    try:
        c = get_db().conn.cursor()
        c.execute(
            "SELECT timestamp, data FROM metrics_history "
            "WHERE timestamp >= ? ORDER BY timestamp ASC",
            (cutoff,))
        for row in c.fetchall():
            try:
                d = json.loads(row['data'])
                cd = (d.get('clusters') or {}).get(cluster_id)
                if not cd: continue
                ts = row['timestamp']
                # ISO → unix
                try:
                    ts_unix = int(datetime.fromisoformat(ts).timestamp())
                except Exception:
                    continue
                out.append((ts_unix, cd))
            except Exception:
                continue
    except Exception as e:
        logging.warning(f"[insights] history load failed for {cluster_id}: {e}")
    return out


def _percentile(values, p):
    if not values: return None
    sv = sorted(values)
    k = (len(sv) - 1) * p / 100
    f = math.floor(k); c = math.ceil(k)
    if f == c: return sv[int(k)]
    return sv[f] * (c - k) + sv[c] * (k - f)


def _linear_regression(xs, ys):
    """Returns (slope, intercept) or (None, None) if insufficient data.
    xs: list of unix timestamps, ys: list of values."""
    n = len(xs)
    if n < 2: return None, None
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0: return None, my
    slope = num / den
    intercept = my - slope * mx
    return slope, intercept


@bp.route('/api/clusters/<cluster_id>/insights/right-sizing', methods=['GET'])
@require_auth(perms=['cluster.view'])
def right_sizing(cluster_id):
    """Per-VM CPU/RAM utilization analysis. For each VM samples the last
    `days` of metrics history and computes mean + p95 CPU%, mean + max
    RAM%. Returns categorized recommendations."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    try:
        days = max(1, min(90, int(request.args.get('days', 30))))
    except (TypeError, ValueError):
        days = 30
    # how many running samples needed before we trust the recommendation
    min_samples = 24  # 24 × 5min = 2h of data minimum

    history = _load_history(cluster_id, days=days)
    sample_count = len(history)

    # Aggregate per-vmid
    by_vm = {}  # vmid -> {cpu: [], mem: [], running_count, latest_meta}
    for _ts, cd in history:
        vms = cd.get('vms') or {}
        for vmid, m in vms.items():
            entry = by_vm.setdefault(vmid, {'cpu': [], 'mem': [], 'running': 0,
                                             'meta': {}, 'type': m.get('t', 'qemu')})
            if m.get('r'):
                entry['running'] += 1
            if m.get('cpu') is not None:
                entry['cpu'].append(m['cpu'])
            if m.get('mem') is not None:
                entry['mem'].append(m['mem'])
            entry['meta'] = m  # last seen wins (current allocation)

    # Resolve names from current resources
    mgr = cluster_managers[cluster_id]
    name_lookup = {}
    node_lookup = {}
    try:
        for r in (mgr.get_vm_resources() or []):
            vmid = str(r.get('vmid', ''))
            if vmid:
                name_lookup[vmid] = r.get('name', '')
                node_lookup[vmid] = r.get('node', '')
    except Exception:
        pass

    recommendations = []
    counts = {'oversized_cpu': 0, 'oversized_mem': 0, 'undersized_cpu': 0,
              'undersized_mem': 0, 'idle': 0, 'no_data': 0, 'ok': 0}
    for vmid, e in by_vm.items():
        cpus = e['cpu']; mems = e['mem']
        if e['running'] < min_samples or len(cpus) < min_samples:
            counts['no_data'] += 1
            continue
        cpu_avg = round(sum(cpus) / len(cpus), 1)
        cpu_p95 = round(_percentile(cpus, 95) or 0, 1)
        mem_avg = round(sum(mems) / max(len(mems), 1), 1) if mems else 0
        mem_max = round(max(mems) if mems else 0, 1)
        meta = e['meta'] or {}
        maxcpu = int(meta.get('maxcpu', 0) or 0)
        maxmem = int(meta.get('maxmem', 0) or 0)

        flags = []
        # CPU heuristics
        if cpu_avg < 5 and cpu_p95 < 25 and maxcpu >= 2:
            new_cores = max(1, maxcpu // 2)
            flags.append({
                'kind': 'oversized_cpu', 'severity': 'info',
                'detail': f'avg {cpu_avg}% / p95 {cpu_p95}% on {maxcpu} cores',
                'current': maxcpu, 'recommended': new_cores,
                'rationale': 'low CPU utilisation across window — halve cores',
            })
            counts['oversized_cpu'] += 1
        elif cpu_avg > 50 and cpu_p95 > 85:
            flags.append({
                'kind': 'undersized_cpu', 'severity': 'warning',
                'detail': f'avg {cpu_avg}% / p95 {cpu_p95}% on {maxcpu} cores',
                'current': maxcpu, 'recommended': maxcpu + max(1, maxcpu // 4),
                'rationale': 'sustained high CPU — add cores',
            })
            counts['undersized_cpu'] += 1
        elif cpu_avg < 1 and cpu_p95 < 3:
            flags.append({
                'kind': 'idle', 'severity': 'info',
                'detail': f'avg {cpu_avg}% / p95 {cpu_p95}%',
                'rationale': 'effectively idle — candidate for shutdown',
            })
            counts['idle'] += 1

        # RAM heuristics
        if mems and maxmem > 0:
            if mem_max > 90:
                gb_now = round(maxmem / (1024**3), 1)
                flags.append({
                    'kind': 'undersized_mem', 'severity': 'warning',
                    'detail': f'avg {mem_avg}% / max {mem_max}% of {gb_now} GB',
                    'current_gb': gb_now,
                    'recommended_gb': round(gb_now * 1.5, 1),
                    'rationale': 'RAM pressure — increase by ~50%',
                })
                counts['undersized_mem'] += 1
            elif mem_avg < 25 and mem_max < 40 and maxmem >= 2 * 1024**3:
                gb_now = round(maxmem / (1024**3), 1)
                flags.append({
                    'kind': 'oversized_mem', 'severity': 'info',
                    'detail': f'avg {mem_avg}% / max {mem_max}% of {gb_now} GB',
                    'current_gb': gb_now,
                    'recommended_gb': round(max(1, gb_now / 2), 1),
                    'rationale': 'RAM heavily underutilised — halve allocation',
                })
                counts['oversized_mem'] += 1

        if flags:
            recommendations.append({
                'vmid': vmid, 'type': e['type'],
                'name': name_lookup.get(vmid, ''),
                'node': node_lookup.get(vmid, ''),
                'cpu_avg': cpu_avg, 'cpu_p95': cpu_p95,
                'mem_avg': mem_avg, 'mem_max': mem_max,
                'maxcpu': maxcpu, 'maxmem_gb': round(maxmem / (1024**3), 1) if maxmem else 0,
                'samples': len(cpus),
                'flags': flags,
            })
        else:
            counts['ok'] += 1

    # sort: warnings first, then oversize, by VMID
    sev_rank = {'warning': 0, 'info': 1}
    def _key(r):
        worst = min(sev_rank.get(f['severity'], 2) for f in r['flags'])
        return (worst, r.get('name', '') or r['vmid'])
    recommendations.sort(key=_key)

    return jsonify({
        'cluster_id': cluster_id,
        'window_days': days,
        'snapshots_in_window': sample_count,
        'min_samples_required': min_samples,
        'summary': counts,
        'total_vms': len(by_vm),
        'recommendations': recommendations,
    })


@bp.route('/api/clusters/<cluster_id>/insights/forecast', methods=['GET'])
@require_auth(perms=['cluster.view'])
def capacity_forecast(cluster_id):
    """Linear regression on cluster CPU/RAM totals + per-storage usage.
    Returns slope, current value, and forecast date when each metric crosses
    `threshold_pct` (default 90)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    try:
        days = max(1, min(90, int(request.args.get('days', 30))))
    except (TypeError, ValueError):
        days = 30
    try:
        threshold = float(request.args.get('threshold_pct', 90))
        threshold = max(50, min(99.9, threshold))
    except (TypeError, ValueError):
        threshold = 90.0

    history = _load_history(cluster_id, days=days)
    if len(history) < 6:  # need at least 30min of data
        return jsonify({
            'cluster_id': cluster_id,
            'window_days': days,
            'snapshots_in_window': len(history),
            'enough_data': False,
            'message': 'not enough history yet — collector needs ~30 min',
            'forecasts': [],
        })

    now_ts = int(datetime.now().timestamp())

    # cluster totals series
    series = {  # name -> [(ts, pct), ...]
        'cpu': [], 'memory': [],
    }
    storage_series = {}  # sid -> [(ts, pct), ...]
    for ts, cd in history:
        totals = cd.get('totals') or {}
        cpu_total = totals.get('cpu_total') or 0
        cpu_used = totals.get('cpu_used') or 0
        if cpu_total > 0:
            series['cpu'].append((ts, cpu_used / cpu_total * 100))
        mem_total = totals.get('mem_total') or 0
        mem_used = totals.get('mem_used') or 0
        if mem_total > 0:
            series['memory'].append((ts, mem_used / mem_total * 100))
        for sid, sd in (cd.get('storage') or {}).items():
            storage_series.setdefault(sid, []).append((ts, sd.get('pct') or 0))

    forecasts = []

    def _forecast_one(label, samples, kind='cluster', extra=None):
        if len(samples) < 6:
            return
        xs = [s[0] for s in samples]
        ys = [s[1] for s in samples]
        slope, intercept = _linear_regression(xs, ys)
        current = round(ys[-1], 1)
        # slope is units-per-second; convert to per-day for display
        slope_per_day = round(slope * 86400, 3) if slope is not None else None
        eta_days = None
        eta_iso = None
        status = 'stable'
        if slope is not None and slope_per_day is not None:
            if slope_per_day >= 0.05 and current < threshold:
                # extrapolate
                seconds_to_threshold = (threshold - current) / slope if slope > 0 else None
                if seconds_to_threshold and seconds_to_threshold > 0:
                    eta_days = round(seconds_to_threshold / 86400, 1)
                    eta_iso = (datetime.now() + timedelta(seconds=seconds_to_threshold)).isoformat()
                    if eta_days < 7: status = 'critical'
                    elif eta_days < 30: status = 'warning'
                    else: status = 'trending_up'
            elif current >= threshold:
                status = 'over_threshold'
            elif slope_per_day < -0.05:
                status = 'decreasing'
        item = {
            'metric': label, 'kind': kind,
            'current_pct': current,
            'slope_per_day_pct': slope_per_day,
            'threshold_pct': threshold,
            'eta_days': eta_days, 'eta_iso': eta_iso,
            'status': status, 'samples': len(samples),
        }
        if extra: item.update(extra)
        forecasts.append(item)

    _forecast_one('cluster_cpu', series['cpu'], kind='cluster')
    _forecast_one('cluster_memory', series['memory'], kind='cluster')
    for sid, samples in storage_series.items():
        _forecast_one(sid, samples, kind='storage', extra={'storage': sid})

    return jsonify({
        'cluster_id': cluster_id,
        'window_days': days,
        'threshold_pct': threshold,
        'snapshots_in_window': len(history),
        'enough_data': True,
        'forecasts': forecasts,
    })


@bp.route('/api/insights/force-snapshot', methods=['POST'])
@require_auth(perms=['admin.api'])
def force_snapshot():
    """Admin-only — kick the metrics collector right now instead of waiting
    for the next 5-min tick. Useful right after first install / SLA setup
    so the user sees data immediately rather than 'not enough history'."""
    try:
        from pegaprox.background.metrics import collect_metrics_snapshot, save_metrics_snapshot
        snap = collect_metrics_snapshot()
        save_metrics_snapshot(snap)
        # mini-summary
        out = {'ok': True, 'clusters': {}}
        for cid, cd in (snap.get('clusters') or {}).items():
            out['clusters'][cid] = {
                'name': cd.get('name'),
                'vms_sampled': len(cd.get('vms') or {}),
                'storage_devices': len(cd.get('storage') or {}),
                'nodes': len(cd.get('nodes') or {}),
            }
        return jsonify(out)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
