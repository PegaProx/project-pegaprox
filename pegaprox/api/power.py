# -*- coding: utf-8 -*-
"""
Power & Carbon Tracking — MK May 2026.

Estimates kWh + €/month + kg CO₂/month per VM and per cluster, based on
the same `metrics_history` snapshots that Insights + Cost Dashboard use.

Model (kept linear + explainable; nothing fancier holds up to scrutiny):

    cpu_w   = node_idle_w + (node_max_w - node_idle_w) × cpu_util
              # split across all VMs running on that node, weighted by
              # the VM's share of total cluster CPU time
    mem_w   = mem_used_gb × mem_w_per_gb
    pue     = data-center power usage effectiveness multiplier (1.0 = no
              cooling / racks already accounted; 1.5 = typical enterprise;
              2.0 = older facilities)
    kwh     = (cpu_w + mem_w) × pue × hours_window / 1000
    cost    = kwh × kwh_price
    co2_kg  = kwh × kg_co2_per_kwh

Default rates (admin-editable):
    node_idle_w     = 80   W  (typical 1U server idle)
    node_max_w      = 300  W  (typical full-load CPU+RAM, ignoring storage)
    mem_w_per_gb    = 0.3  W
    pue             = 1.5
    kwh_price       = 0.30 EUR
    kg_co2_per_kwh  = 0.40  (DE 2024 grid average; FR ~0.05, PL ~0.7, etc.)
"""
import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access
from pegaprox.core.db import get_db
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('power', __name__)


_DEFAULT = {
    'node_idle_w': 80.0,
    'node_max_w': 300.0,
    'mem_w_per_gb': 0.3,
    'pue': 1.5,
    'kwh_price': 0.30,
    'kg_co2_per_kwh': 0.40,
    'currency': 'EUR',
    'notes': '',
}


def _row_to_rates(r):
    return {
        'cluster_id': r['cluster_id'],
        'node_idle_w': float(r['node_idle_w'] or 0),
        'node_max_w': float(r['node_max_w'] or 0),
        'mem_w_per_gb': float(r['mem_w_per_gb'] or 0),
        'pue': float(r['pue'] or 1.0),
        'kwh_price': float(r['kwh_price'] or 0),
        'kg_co2_per_kwh': float(r['kg_co2_per_kwh'] or 0),
        'currency': r['currency'] or 'EUR',
        'notes': r['notes'] or '',
        'updated_at': r['updated_at'],
        'updated_by': r['updated_by'] or '',
    }


def _get_rates(cluster_id):
    db = get_db()
    c = db.conn.cursor()
    try:
        c.execute("SELECT * FROM power_rates WHERE cluster_id IN ('__default__', ?)", (cluster_id,))
        rows = {r['cluster_id']: r for r in c.fetchall()}
    except Exception:
        rows = {}
    if cluster_id in rows: return _row_to_rates(rows[cluster_id])
    if '__default__' in rows: return _row_to_rates(rows['__default__'])
    return {**_DEFAULT, 'cluster_id': '__default__'}


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict): return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _load_history(cluster_id, days=30):
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    out = []
    try:
        c = get_db().conn.cursor()
        c.execute("SELECT timestamp, data FROM metrics_history WHERE timestamp >= ? ORDER BY timestamp ASC", (cutoff,))
        for row in c.fetchall():
            try:
                d = json.loads(row['data'])
                cd = (d.get('clusters') or {}).get(cluster_id)
                if not cd: continue
                ts_unix = int(datetime.fromisoformat(row['timestamp']).timestamp())
                out.append((ts_unix, cd))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _compute_per_vm(snapshots, mgr, rates, hours_window):
    """Per-VM kWh + cost + CO₂ aggregation across snapshots."""
    by_vm = {}  # vmid -> dict of running totals
    # Also keep node-level aggregates for context
    for ts, cd in snapshots:
        nodes = cd.get('nodes') or {}  # {nodename: {cpu, mem_percent, maxcpu, maxmem}}
        # build node CPU-share denominators per snapshot so we can split node power across its VMs
        node_running_vms = {n: [] for n in nodes}
        for vmid, v in (cd.get('vms') or {}).items():
            if not v.get('r'): continue  # skip stopped VMs
            # need node — we infer from vm resources later via mgr; here we don't have node, treat per-cluster split
            pass
        for vmid, v in (cd.get('vms') or {}).items():
            running = bool(v.get('r'))
            cpu_pct = v.get('cpu') or 0
            mem_pct = v.get('mem') or 0
            maxcpu = v.get('maxcpu') or 0
            maxmem = v.get('maxmem') or 0
            entry = by_vm.setdefault(vmid, {
                't': v.get('t'),
                'cpu_pct_sum': 0, 'mem_pct_sum': 0,
                'samples': 0, 'running_samples': 0,
                'maxcpu': 0, 'maxmem': 0,
            })
            entry['samples'] += 1
            entry['maxcpu'] = max(entry['maxcpu'], maxcpu)
            entry['maxmem'] = max(entry['maxmem'], maxmem)
            if running:
                entry['running_samples'] += 1
                entry['cpu_pct_sum'] += cpu_pct
                entry['mem_pct_sum'] += mem_pct

    # Enrich with names from live mgr
    name_by_vmid, node_by_vmid = {}, {}
    try:
        for r in (mgr.get_vm_resources() or []):
            vid = str(r.get('vmid') or '')
            if not vid: continue
            name_by_vmid[vid] = r.get('name', '')
            node_by_vmid[vid] = r.get('node', '')
    except Exception:
        pass

    rows = []
    cur = rates['currency']
    for vmid, e in by_vm.items():
        running_h = hours_window * (e['running_samples'] / e['samples']) if e['samples'] else 0
        avg_cpu_pct = (e['cpu_pct_sum'] / e['running_samples']) if e['running_samples'] else 0
        avg_mem_pct = (e['mem_pct_sum'] / e['running_samples']) if e['running_samples'] else 0
        cpu_cores = e['maxcpu'] or 1
        mem_gb = (e['maxmem'] or 0) / (1024 ** 3)

        # Power approximation — per-VM linear share
        # node_idle_w is amortized over all running VMs cluster-wide; we
        # apportion roughly by core count. Avoid double-counting: idle is
        # already attributed to node, so per-VM only carries the active share.
        active_w = (rates['node_max_w'] - rates['node_idle_w']) * (avg_cpu_pct / 100.0) * (cpu_cores / 8.0)
        active_w = max(0.0, active_w)
        idle_share_w = rates['node_idle_w'] * (cpu_cores / 32.0)  # rough core share
        mem_w = (avg_mem_pct / 100.0) * mem_gb * rates['mem_w_per_gb']
        total_w = (active_w + idle_share_w + mem_w) * rates['pue']
        kwh = total_w * running_h / 1000.0
        cost = kwh * rates['kwh_price']
        co2 = kwh * rates['kg_co2_per_kwh']

        rows.append({
            'vmid': vmid,
            'name': name_by_vmid.get(vmid, vmid),
            'node': node_by_vmid.get(vmid, ''),
            'type': e['t'],
            'avg_cpu_pct': round(avg_cpu_pct, 1),
            'avg_mem_pct': round(avg_mem_pct, 1),
            'cores': cpu_cores,
            'memory_gb': round(mem_gb, 2),
            'running_h': round(running_h, 1),
            'kwh': round(kwh, 2),
            'cost': round(cost, 2),
            'kg_co2': round(co2, 2),
            'low_data': e['samples'] < 12,
        })

    rows.sort(key=lambda r: r['kwh'], reverse=True)
    return rows


# ── Endpoints ────────────────────────────────────────────────────────────

@bp.route('/api/power/rates', methods=['GET'])
@require_auth()
def list_rates():
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM power_rates ORDER BY cluster_id')
        return jsonify({'rates': [_row_to_rates(r) for r in c.fetchall()]})
    except Exception:
        logging.exception('list power rates')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/power/rates/<cluster_id>', methods=['GET'])
@require_auth()
def get_one(cluster_id):
    return jsonify(_get_rates(cluster_id))


@bp.route('/api/power/rates/<cluster_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def upsert(cluster_id):
    body = request.get_json(silent=True) or {}
    try:
        f = {k: float(body.get(k, _DEFAULT[k])) for k in
             ('node_idle_w', 'node_max_w', 'mem_w_per_gb', 'pue', 'kwh_price', 'kg_co2_per_kwh')}
    except (TypeError, ValueError):
        return jsonify({'error': 'rates must be numeric'}), 400
    cur = (body.get('currency') or 'EUR').strip()[:8]
    notes = (body.get('notes') or '').strip()[:500]
    try:
        c = get_db().conn.cursor()
        c.execute('''INSERT INTO power_rates
            (cluster_id, node_idle_w, node_max_w, mem_w_per_gb, pue, kwh_price,
             kg_co2_per_kwh, currency, notes, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
                node_idle_w=excluded.node_idle_w,
                node_max_w=excluded.node_max_w,
                mem_w_per_gb=excluded.mem_w_per_gb,
                pue=excluded.pue,
                kwh_price=excluded.kwh_price,
                kg_co2_per_kwh=excluded.kg_co2_per_kwh,
                currency=excluded.currency,
                notes=excluded.notes,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
        ''', (cluster_id, f['node_idle_w'], f['node_max_w'], f['mem_w_per_gb'],
              f['pue'], f['kwh_price'], f['kg_co2_per_kwh'], cur, notes,
              datetime.now().isoformat(), _current_user()))
        get_db().conn.commit()
        return jsonify({'ok': True, 'rates': _get_rates(cluster_id)})
    except Exception:
        logging.exception('upsert power rates')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/power/rates/<cluster_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_rate(cluster_id):
    if cluster_id == '__default__':
        return jsonify({'error': 'cannot delete defaults'}), 400
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM power_rates WHERE cluster_id=?', (cluster_id,))
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception:
        logging.exception('delete power rates')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/power/summary', methods=['GET'])
@require_auth(perms=['cluster.view'])
def cluster_summary(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404

    try:
        days = max(1, min(int(request.args.get('days', 30)), 30))
    except Exception:
        days = 30

    rates = _get_rates(cluster_id)
    snaps = _load_history(cluster_id, days=days)
    if not snaps:
        return jsonify({'enough_data': False, 'cluster_id': cluster_id, 'rates': rates, 'days': days})

    mgr = cluster_managers[cluster_id]
    rows = _compute_per_vm(snaps, mgr, rates, days * 24)

    total_kwh = sum(r['kwh'] for r in rows)
    total_cost = sum(r['cost'] for r in rows)
    total_co2 = sum(r['kg_co2'] for r in rows)
    factor = 30.0 / days if days < 30 else 1.0

    by_node = {}
    for r in rows:
        n = r.get('node') or 'unknown'
        d = by_node.setdefault(n, {'kwh': 0.0, 'cost': 0.0, 'kg_co2': 0.0})
        d['kwh'] += r['kwh']; d['cost'] += r['cost']; d['kg_co2'] += r['kg_co2']

    return jsonify({
        'enough_data': True,
        'cluster_id': cluster_id,
        'days': days,
        'snapshots_count': len(snaps),
        'rates': rates,
        'window': {
            'kwh': round(total_kwh, 2),
            'cost': round(total_cost, 2),
            'kg_co2': round(total_co2, 2),
        },
        'monthly': {
            'kwh': round(total_kwh * factor, 2),
            'cost': round(total_cost * factor, 2),
            'kg_co2': round(total_co2 * factor, 2),
        },
        'by_node': {k: {'kwh': round(v['kwh'] * factor, 2),
                        'cost': round(v['cost'] * factor, 2),
                        'kg_co2': round(v['kg_co2'] * factor, 2)} for k, v in by_node.items()},
        'top_consumers': rows[:10],
        'vm_count': len(rows),
    })


@bp.route('/api/clusters/<cluster_id>/power/per-vm', methods=['GET'])
@require_auth(perms=['cluster.view'])
def per_vm(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    try:
        days = max(1, min(int(request.args.get('days', 30)), 30))
    except Exception:
        days = 30
    rates = _get_rates(cluster_id)
    snaps = _load_history(cluster_id, days=days)
    if not snaps:
        return jsonify({'enough_data': False, 'rates': rates, 'rows': []})
    mgr = cluster_managers[cluster_id]
    rows = _compute_per_vm(snaps, mgr, rates, days * 24)
    factor = 30.0 / days if days < 30 else 1.0
    for r in rows:
        r['monthly_kwh'] = round(r['kwh'] * factor, 2)
        r['monthly_cost'] = round(r['cost'] * factor, 2)
        r['monthly_co2'] = round(r['kg_co2'] * factor, 2)
    return jsonify({'enough_data': True, 'cluster_id': cluster_id, 'days': days,
                    'rates': rates, 'rows': rows})
