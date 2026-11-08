# -*- coding: utf-8 -*-
"""
Cost Dashboard / Chargeback — MK May 2026.

Computes monthly cost per VM/CT and per-cluster aggregates from the existing
metrics_history snapshots. Rates are admin-configurable: global default plus
per-cluster overrides (different hardware tiers, different price plans, etc.).

Cost model — keep it explainable. Marketing won't beat us up if the numbers
are slightly off, but they will if we can't explain how we got them:

    cost_cpu     = avg_cpu_pct/100 × hours_window × maxcpu × cpu_per_core_h
    cost_memory  = avg_mem_pct/100 × hours_window × (maxmem_gb) × mem_per_gb_h
    cost_storage = sum(disk_size_gb)              × storage_per_gb_month × (days/30)
    cost_total   = cost_cpu + cost_memory + cost_storage

Defaults (~AWS m6i.large utilization-equivalent prices, in EUR — adjust per
deployment):
    cpu_per_core_h        = 0.012
    mem_per_gb_h          = 0.0035
    storage_per_gb_month  = 0.10

If a VM has only a couple of samples we still cost it (avg_cpu/mem of those
samples), with a "low_data" flag in the response so the UI can show a warning
icon. Better than refusing to display anything.
"""
import json
import logging
from datetime import datetime, timedelta
from itertools import chain, compress
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.utils.sanitization import sanitize_csv_field
from pegaprox.api.helpers import (check_cluster_access, load_metrics_window, scope_vm_rows, run_off_hub,
                                  history_report, history_version)
from pegaprox.background.metrics_store import need, guest_columns, FT, HERE, RUN, CPU_SET, MEM_SET
from pegaprox.core.db import get_db
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('costs', __name__)


_DEFAULT_RATES = {
    'cpu_per_core_h': 0.012,
    'mem_per_gb_h': 0.0035,
    'storage_per_gb_month': 0.10,
    'currency': 'EUR',
    'notes': '',
}


def _row_to_rates(row):
    return {
        'cluster_id': row['cluster_id'],
        'cpu_per_core_h': float(row['cpu_per_core_h'] or 0),
        'mem_per_gb_h': float(row['mem_per_gb_h'] or 0),
        'storage_per_gb_month': float(row['storage_per_gb_month'] or 0),
        'currency': row['currency'] or 'EUR',
        'notes': row['notes'] or '',
        'updated_at': row['updated_at'],
        'updated_by': row['updated_by'] or '',
    }


def _get_rates(cluster_id):
    """Return effective rates: cluster override → fallback to __default__ row → fallback to constants."""
    db = get_db()
    c = db.conn.cursor()
    try:
        c.execute("SELECT * FROM cost_rates WHERE cluster_id IN ('__default__', ?)", (cluster_id,))
        rows = {r['cluster_id']: r for r in c.fetchall()}
    except Exception as e:
        logging.warning(f"[costs] rates fetch failed: {e}")
        rows = {}

    if cluster_id in rows:
        return _row_to_rates(rows[cluster_id])
    if '__default__' in rows:
        return _row_to_rates(rows['__default__'])
    return {**_DEFAULT_RATES, 'cluster_id': '__default__'}


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict):
            return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _load_history(cluster_id, days=30):
    """Pull all snapshots for a cluster. Fetch+parse run off-hub + cached in
    load_metrics_window (shared with insights/power); we just filter.
    MK Oct 2026 - load_metrics_window reads the one cluster itself now."""
    try:
        return load_metrics_window(days, cluster_id)
    except Exception as e:
        logging.warning(f"[costs] history load failed for {cluster_id}: {e}")
    return []


def _compute_per_vm(snapshots, mgr, rates, hours_window, stats=None):
    """Aggregate per-VM utilization across snapshots → cost rows. NS Oct 2026 - the history
    part (_cost_stats) runs off the hub, or comes in kept as `stats`; the names, hosts and
    disk sizes are read live here, on the hub, and the rates applied, for every request."""
    if stats is None:
        stats = run_off_hub(_cost_stats, snapshots)
    live = []
    try:
        for r in (mgr.get_vm_resources() or []):
            live.append({'vmid': r.get('vmid', ''), 'name': r.get('name', ''), 'node': r.get('node', ''),
                         'maxdisk': r.get('maxdisk', 0)})
    except Exception as e:
        logging.debug(f"[costs] enrich failed: {e}")
    return _cost_rows(stats, live, rates, hours_window)


def _cost_stats(snapshots):
    """{vmid: what the cost of a guest reads of the history}: plain arithmetic, off the hub.
    MK Oct 2026 - a window whose guests are all stored in columns goes to _cost_stats_cols,
    which reads the same figures without a dict per guest and sample."""
    cols = guest_columns(snapshots)
    if cols is not None:
        return _cost_stats_cols(cols)
    snapshots = need(snapshots, 'vms')
    # NOTE: _cost_stats_cols below is this loop on the column store, and has to give the very
    # same result (tests/test_metrics_column_engines.py). A change here goes there as well.
    # vmid -> {cpu_samples, mem_samples, name, node, type, maxmem, maxcpu, running_samples, total_samples}
    by_vm = {}

    for ts, cd in snapshots:
        for vmid, v in (cd.get('vms') or {}).items():
            entry = by_vm.setdefault(vmid, {
                'cpu_samples': [], 'mem_samples': [],
                'maxmem': 0, 'maxcpu': 0,
                't': v.get('t'), 'r_count': 0, 'total': 0,
            })
            entry['total'] += 1
            if v.get('r'):
                entry['r_count'] += 1
            if v.get('cpu') is not None:
                entry['cpu_samples'].append(v['cpu'])
            if v.get('mem') is not None:
                entry['mem_samples'].append(v['mem'])
            if v.get('maxmem'):
                entry['maxmem'] = max(entry['maxmem'], v['maxmem'])
            if v.get('maxcpu'):
                entry['maxcpu'] = max(entry['maxcpu'], v['maxcpu'])

    out = {}
    for vmid, e in by_vm.items():
        cpu_samples = e['cpu_samples'] or [0]
        mem_samples = e['mem_samples'] or [0]
        out[vmid] = {'t': e['t'], 'r_count': e['r_count'], 'total': e['total'],
                     'maxcpu': e['maxcpu'], 'maxmem': e['maxmem'],
                     'avg_cpu_pct': sum(cpu_samples) / len(cpu_samples),
                     'avg_mem_pct': sum(mem_samples) / len(mem_samples)}
    return out


def _cost_stats_cols(cols):
    """_cost_stats on a metrics_store.GuestColumns. Per guest the same lists in the same
    snapshot order reach the same sum(), so the averages are the same floats; the guests
    come in the order they first show up, as the dict filled in. No list is made of them:
    sum() takes them one by one in that order all the same, and an empty one is the [0]
    of the dict way, 0 / 1."""
    out = {}
    S, get = cols.S, FT.__getitem__
    for vmid, g in cols.order:
        fl = cols.flags_of(g)
        here = fl.translate(HERE)
        cpu_set, mem_set = fl.translate(CPU_SET), fl.translate(MEM_SET)
        nc, nm = cpu_set.count(1), mem_set.count(1)
        cpu, mem = cols.cpu_of(g), cols.mem_of(g)
        # the largest of what each snapshot said, 0 where none said more (all ints, >= 0)
        out[vmid] = {'t': cols.kind(g, here.find(1)), 'r_count': fl.translate(RUN).count(1),
                     'total': here.count(1),
                     'maxcpu': max(chain((0,), cols.values(cols.maxcpu, g))),
                     'maxmem': max(chain((0,), cols.values(cols.maxmem, g))),
                     'avg_cpu_pct': sum(map(get, cpu if nc == S else compress(cpu, cpu_set))) / nc if nc else 0 / 1,
                     'avg_mem_pct': sum(map(get, mem if nm == S else compress(mem, mem_set))) / nm if nm else 0 / 1}
    return out


def _cost_rows(stats, live, rates, hours_window):
    """The cost rows of `stats`, named from `live` (the guest list as read on the hub)."""
    # Enrich with current name / node / disk size from live mgr
    name_by_vmid = {}
    node_by_vmid = {}
    disk_by_vmid = {}
    try:
        for r in live:
            vid = str(r.get('vmid', ''))
            if not vid: continue
            name_by_vmid[vid] = r.get('name', '')
            node_by_vmid[vid] = r.get('node', '')
            disk = int(r.get('maxdisk', 0) or 0)
            disk_by_vmid[vid] = disk
    except Exception as e:
        logging.debug(f"[costs] enrich failed: {e}")

    rows = []
    for vmid, e in stats.items():
        avg_cpu_pct = e['avg_cpu_pct']
        avg_mem_pct = e['avg_mem_pct']
        running_ratio = (e['r_count'] / e['total']) if e['total'] else 0
        # only count utilization for the time the VM was running
        active_h = hours_window * running_ratio

        maxcpu = e['maxcpu'] or 0
        # snapshot's maxmem is bytes — convert to GB
        maxmem_gb = (e['maxmem'] or 0) / (1024 ** 3)
        disk_gb = (disk_by_vmid.get(vmid, 0) or 0) / (1024 ** 3)

        cost_cpu = (avg_cpu_pct / 100.0) * active_h * maxcpu * rates['cpu_per_core_h']
        cost_mem = (avg_mem_pct / 100.0) * active_h * maxmem_gb * rates['mem_per_gb_h']
        # storage billed regardless of running state
        days = hours_window / 24.0
        cost_storage = disk_gb * rates['storage_per_gb_month'] * (days / 30.0)
        total = cost_cpu + cost_mem + cost_storage

        rows.append({
            'vmid': vmid,
            'name': name_by_vmid.get(vmid, vmid),
            'node': node_by_vmid.get(vmid, ''),
            'type': e['t'],
            'avg_cpu_pct': round(avg_cpu_pct, 1),
            'avg_mem_pct': round(avg_mem_pct, 1),
            'running_ratio': round(running_ratio, 3),
            'cores': maxcpu,
            'memory_gb': round(maxmem_gb, 2),
            'disk_gb': round(disk_gb, 2),
            'cost_cpu': round(cost_cpu, 2),
            'cost_memory': round(cost_mem, 2),
            'cost_storage': round(cost_storage, 2),
            'cost_total': round(total, 2),
            'low_data': e['total'] < 12,  # MK: <12 samples = <1h history, surface in UI
        })

    rows.sort(key=lambda r: r['cost_total'], reverse=True)
    return rows


def _cached_cost_rows(cluster_id, days, snapshots, rates):
    """(rows, stamp): the cluster's cost rows. The history part is worked out once for the
    summary, the per-VM table and the chargeback together, and kept (helpers.history_report);
    names, hosts, disk sizes and the rates are applied per request, so a change to any of
    them shows at once."""
    stats, stamp = history_report(('costs', cluster_id, days), history_version(snapshots),
                                  lambda: run_off_hub(_cost_stats, snapshots), rows=len)
    return _compute_per_vm(snapshots, cluster_managers[cluster_id], rates, days * 24, stats=stats), stamp


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/cost/rates', methods=['GET'])
@require_auth()
def list_rates():
    """All cost rate configs (global default + per-cluster overrides)."""
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM cost_rates ORDER BY cluster_id')
        rows = [_row_to_rates(r) for r in c.fetchall()]
        # NS Aug 2026 (Aikido IDOR) — scope rows to the caller's reachable clusters; was
        # leaking every cluster's cost rates to any authed user. Always keep the shared
        # '__default__' fallback row (every cluster reads it when it has no own row).
        from pegaprox.utils.rbac import get_user_clusters
        from pegaprox.api.helpers import acting_user
        # NS Aug 2026 — honour a token's floored effective_role (not the owner's account role),
        # so an admin-owned but scoped token can't enumerate every cluster's cost rates.
        # NS Oct 2026 - acting_user keeps the owner's role next to the token's, which
        # get_user_clusters needs to hold the token inside its owner's clusters
        allowed = get_user_clusters(acting_user())
        if allowed is not None:
            rows = [r for r in rows if r['cluster_id'] == '__default__' or r['cluster_id'] in allowed]
        return jsonify({'rates': rows})
    except Exception as e:
        logging.exception('handler error in costs.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/cost/rates/<cluster_id>', methods=['GET'])
@require_auth()
def get_one_rate(cluster_id):
    # NS Aug 2026 (Aikido IDOR) — tenant gate; the __default__ pseudo-cluster is shared (no owner).
    if cluster_id != '__default__':
        from pegaprox.api.helpers import check_cluster_access
        ok, err = check_cluster_access(cluster_id)
        if not ok:
            return err
    return jsonify(_get_rates(cluster_id))


@bp.route('/api/cost/rates/<cluster_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def upsert_rate(cluster_id):
    """Admin-only — update rates for a cluster (or '__default__' for global)."""
    body = request.get_json(silent=True) or {}
    try:
        cpu = float(body.get('cpu_per_core_h', _DEFAULT_RATES['cpu_per_core_h']))
        mem = float(body.get('mem_per_gb_h', _DEFAULT_RATES['mem_per_gb_h']))
        sto = float(body.get('storage_per_gb_month', _DEFAULT_RATES['storage_per_gb_month']))
    except (TypeError, ValueError):
        return jsonify({'error': 'rates must be numeric'}), 400
    currency = (body.get('currency') or 'EUR').strip()[:8]
    notes = (body.get('notes') or '').strip()[:500]

    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO cost_rates (cluster_id, cpu_per_core_h, mem_per_gb_h,
                                    storage_per_gb_month, currency, notes,
                                    updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
                cpu_per_core_h=excluded.cpu_per_core_h,
                mem_per_gb_h=excluded.mem_per_gb_h,
                storage_per_gb_month=excluded.storage_per_gb_month,
                currency=excluded.currency,
                notes=excluded.notes,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
        ''', (cluster_id, cpu, mem, sto, currency, notes,
              datetime.now().isoformat(), _current_user()))
        get_db().conn.commit()
        return jsonify({'ok': True, 'rates': _get_rates(cluster_id)})
    except Exception as e:
        logging.exception('handler error in costs.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/cost/rates/<cluster_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_rate(cluster_id):
    """Drop a per-cluster override (defaults take over). __default__ stays."""
    if cluster_id == '__default__':
        return jsonify({'error': 'cannot delete default rates'}), 400
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM cost_rates WHERE cluster_id = ?', (cluster_id,))
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        logging.exception('handler error in costs.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/costs/summary', methods=['GET'])
@require_auth(perms=['cluster.view'])
def cluster_summary(cluster_id):
    """Summary tiles + per-VM cost breakdown for a cluster.
    Query: ?days=30 (default 30, max 30 because that's our retention)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404

    try:
        days = int(request.args.get('days', '30'))
        days = max(1, min(days, 30))
    except Exception:
        days = 30

    rates = _get_rates(cluster_id)
    snapshots = _load_history(cluster_id, days=days)
    if not snapshots:
        return jsonify({
            'enough_data': False,
            'cluster_id': cluster_id,
            'rates': rates,
            'days': days,
        })

    rows, stamp = _cached_cost_rows(cluster_id, days, snapshots, rates)
    # #773 audit — confine per-VM cost rows (top_spenders/by_node/vm_count all derive from these)
    # to VMs the caller may see, so a pool-scoped user doesn't get the whole cluster's spend.
    rows = scope_vm_rows(cluster_id, rows)

    total = sum(r['cost_total'] for r in rows)
    cpu = sum(r['cost_cpu'] for r in rows)
    mem = sum(r['cost_memory'] for r in rows)
    sto = sum(r['cost_storage'] for r in rows)

    # extrapolate to monthly if window < 30 days
    factor = 30.0 / days if days < 30 else 1.0
    monthly_total = total * factor
    monthly_cpu = cpu * factor
    monthly_mem = mem * factor
    monthly_sto = sto * factor

    by_node = {}
    for r in rows:
        n = r.get('node') or 'unknown'
        by_node[n] = by_node.get(n, 0.0) + r['cost_total']

    return jsonify({
        'enough_data': True,
        'cluster_id': cluster_id,
        'days': days,
        'snapshots_count': len(snapshots),
        'rates': rates,
        'total_window': round(total, 2),
        'monthly_total': round(monthly_total, 2),
        'monthly_breakdown': {
            'cpu': round(monthly_cpu, 2),
            'memory': round(monthly_mem, 2),
            'storage': round(monthly_sto, 2),
        },
        'by_node': {k: round(v * factor, 2) for k, v in by_node.items()},
        'top_spenders': rows[:10],
        'vm_count': len(rows),
        **stamp,
    })


@bp.route('/api/clusters/<cluster_id>/costs/per-vm', methods=['GET'])
@require_auth(perms=['cluster.view'])
def per_vm(cluster_id):
    """Full per-VM cost table — paginate-friendly enough for now (sorted by total desc)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    try:
        days = max(1, min(int(request.args.get('days', '30')), 30))
    except Exception:
        days = 30

    rates = _get_rates(cluster_id)
    snapshots = _load_history(cluster_id, days=days)
    if not snapshots:
        return jsonify({'enough_data': False, 'rates': rates, 'rows': []})
    rows, stamp = _cached_cost_rows(cluster_id, days, snapshots, rates)
    rows = scope_vm_rows(cluster_id, rows)  # #773 audit — per-VM rows scoped to the caller
    factor = 30.0 / days if days < 30 else 1.0
    for r in rows:
        # also expose monthly extrapolation per row for direct UI display
        r['monthly_total'] = round(r['cost_total'] * factor, 2)
    return jsonify({
        'enough_data': True,
        'cluster_id': cluster_id,
        'days': days,
        'rates': rates,
        'rows': rows,
        **stamp,
    })


@bp.route('/api/tenants/<tenant_id>/chargeback', methods=['GET'])
@require_auth(perms=['admin.tenants'])
def tenant_chargeback(tenant_id):
    """#502 — per-tenant cost rollup (chargeback/showback). Aggregates per-VM
    costs across the tenant's clusters into a statement: per-cluster subtotals +
    a per-VM breakdown + a monthly extrapolation. On-demand (no persistence).
    Query: ?days=1..30 (default 30), ?format=csv for a CSV download."""
    try:
        import pegaprox.utils.rbac as _rbac
        try:
            days = max(1, min(int(request.args.get('days', '30')), 30))
        except Exception:
            days = 30
        fmt = (request.args.get('format') or 'json').lower()

        # NS #502 — refresh the cached tenants global so get_user_clusters() below
        # sees the tenant's current cluster assignment (it goes stale after an edit).
        _rbac.tenants_db = _rbac.load_tenants()
        tenant = (_rbac.tenants_db or {}).get(tenant_id)
        if not tenant:
            return jsonify({'error': 'tenant not found'}), 404

        # MK Jun 2026 (sec-review) — admin.tenants can be a tenant-scoped custom role;
        # scope to the caller's own tenant unless a real admin, else one tenant could
        # read another tenant's full VM inventory + per-VM cost breakdown (BOLA).
        from pegaprox.api.helpers import caller_acts_as_admin
        _global = caller_acts_as_admin()
        if not _global:
            _caller = get_db().get_user(request.session.get('user', '')) or {}
            if tenant_id != _caller.get('tenant_id', _rbac.DEFAULT_TENANT_ID):
                return jsonify({'error': 'Access denied to this tenant'}), 403
        allowed = _rbac.get_user_clusters({'role': _rbac.ROLE_VIEWER, 'tenant_id': tenant_id})  # None = all clusters

        factor = 30.0 / days if days < 30 else 1.0
        by_cluster = []
        all_rows = []
        grand_total = 0.0
        currency = 'EUR'
        computed_at = None  # the oldest of the clusters' figures
        for cid, mgr in list(cluster_managers.items()):
            if allowed is not None and cid not in allowed:
                continue
            cname = getattr(getattr(mgr, 'config', None), 'name', cid) or cid
            try:
                rates = _get_rates(cid)
                currency = rates.get('currency', currency) or currency
                snaps = _load_history(cid, days=days)
                if not snaps:
                    by_cluster.append({'cluster_id': cid, 'cluster_name': cname, 'subtotal': 0.0,
                                       'monthly_subtotal': 0.0, 'vm_count': 0, 'enough_data': False})
                    continue
                rows, stamp = _cached_cost_rows(cid, days, snaps, rates)
                if not computed_at or stamp['computed_at'] < computed_at:
                    computed_at = stamp['computed_at']
                if not _global:
                    # NS Oct 2026 - the statement is the tenant's clusters, its rows only the
                    # guests this caller may see, as on the per-cluster cost routes. A pool- or
                    # ACL-confined delegate read every guest's name, size and cost here.
                    rows = scope_vm_rows(cid, rows)
                for r in rows:
                    r['cluster_id'] = cid
                    r['cluster_name'] = cname
                    r['monthly_total'] = round(r['cost_total'] * factor, 2)
                sub = round(sum(r['cost_total'] for r in rows), 2)
                grand_total += sub
                all_rows.extend(rows)
                by_cluster.append({'cluster_id': cid, 'cluster_name': cname, 'subtotal': sub,
                                   'monthly_subtotal': round(sub * factor, 2), 'vm_count': len(rows),
                                   'enough_data': True})
            except Exception as ce:
                logging.warning(f"[chargeback] cluster {cid} failed: {ce}")
        grand_total = round(grand_total, 2)
        all_rows.sort(key=lambda r: r.get('cost_total', 0), reverse=True)

        if fmt == 'csv':
            import io, csv
            from flask import Response
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(['cluster', 'vmid', 'name', 'type', 'cores', 'memory_gb', 'disk_gb',
                        'cost_cpu', 'cost_memory', 'cost_storage', f'cost_total_{days}d', 'monthly_total', 'currency'])
            for r in all_rows:
                # NS #502 — neutralise CSV formula injection (CWE-1236) on the
                # user-controlled string cells (VM/cluster names); numbers stay raw
                w.writerow([sanitize_csv_field(r.get('cluster_name')), r.get('vmid'),
                            sanitize_csv_field(r.get('name')), sanitize_csv_field(r.get('type')),
                            r.get('cores'), r.get('memory_gb'), r.get('disk_gb'), r.get('cost_cpu'),
                            r.get('cost_memory'), r.get('cost_storage'), r.get('cost_total'),
                            r.get('monthly_total'), currency])
            return Response(buf.getvalue(), mimetype='text/csv',
                            headers={'Content-Disposition': f'attachment; filename="chargeback-{tenant_id}-{days}d.csv"'})

        return jsonify({
            'tenant_id': tenant_id,
            'tenant_name': tenant.get('name', tenant_id),
            'days': days,
            'currency': currency,
            'total': grand_total,
            'monthly_total': round(grand_total * factor, 2),
            'by_cluster': by_cluster,
            'rows': all_rows,
            'computed_at': computed_at,
        })
    except Exception:
        logging.exception('handler error in costs.py (chargeback)')
        return jsonify({'error': 'internal error'}), 500
