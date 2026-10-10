# -*- coding: utf-8 -*-
"""What-if simulator routes - MK Oct 2026

GET  /api/clusters/<id>/whatif/options   what the scenario picker offers
POST /api/clusters/<id>/whatif           the report of one scenario (pegaprox/core/whatif.py)

Both only read. The POST takes its scenario in the body, so a standby with the live view
answers it from its own managers like any read (app.py _STANDBY_LOCAL_WRITES) and the
active tells its members about nothing. A caller confined to some guests of the cluster
gets the rows of those guests only: the counts stay, the names of the others do not.
"""

import logging

from flask import Blueprint, jsonify, request

from pegaprox.api.helpers import check_cluster_access, safe_error, scope_vm_rows
from pegaprox.core import whatif
from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth

bp = Blueprint('whatif', __name__)

GUEST_ROWS = 2000   # guest rows a report carries; the summary counts them all


def _manager(cluster_id):
    """(manager, None) or (None, error response)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return None, err
    mgr = cluster_managers.get(cluster_id)
    if mgr is None:
        return None, (jsonify({'error': 'Cluster not found'}), 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        # an XCP-ng pool: the maintenance plan answers the same way
        return None, jsonify({'supported': False})
    if not getattr(mgr, 'is_connected', False):
        return None, (jsonify({'error': 'Cluster not connected', 'offline': True}), 503)
    return mgr, None


def thresholds_for(cluster_id, override=None):
    """CPU and memory thresholds of a cluster: the lowest of its enabled alert rules on
    node or cluster CPU / memory, else the defaults; `override` (the request's) wins.
    {'cpu', 'memory', 'cpu_source', 'memory_source', 'nodes': {node: {metric: value}}}"""
    out = {'cpu': whatif.DEFAULT_CPU, 'memory': whatif.DEFAULT_MEMORY,
           'cpu_source': 'default', 'memory_source': 'default', 'nodes': {}}
    try:
        from pegaprox.api.alerts import load_cluster_alerts
        rules = load_cluster_alerts().get(cluster_id, []) or []
    except Exception as e:
        logging.debug(f"[WHATIF] alert rules of {cluster_id} unreadable: {e}")
        rules = []
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get('enabled', True):
            continue
        metric = rule.get('metric')
        if metric not in ('cpu', 'memory') or rule.get('operator', '>') not in ('>', '>='):
            continue
        try:
            value = float(rule.get('threshold'))
        except (TypeError, ValueError):
            continue
        if not 1 <= value <= 100:
            continue
        target = rule.get('target_type', 'cluster')
        if target == 'cluster':
            if out[f'{metric}_source'] == 'default' or value < out[metric]:
                out[metric] = value
            out[f'{metric}_source'] = 'alert_rule'
        elif target == 'node' and rule.get('target_id'):
            per = out['nodes'].setdefault(str(rule['target_id']), {})
            per[metric] = min(value, per.get(metric, value))
    for metric, value in (override or {}).items():
        out[metric] = value
        out[f'{metric}_source'] = 'request'
        for per in out['nodes'].values():
            per.pop(metric, None)
    # a node's own rule replaces the default, and is not looser than a cluster rule
    for per in out['nodes'].values():
        for metric in list(per):
            if out[f'{metric}_source'] != 'default':
                per[metric] = min(per[metric], out[metric])
    return out


def _visible(cluster_id, report):
    """The report as this caller may see it: guest rows and the guests of each limit
    scoped like the guest list, the counts kept."""
    rows = report.get('guests') or []
    seen = scope_vm_rows(cluster_id, rows)
    ids = {r['vmid'] for r in seen}
    for item in report.get('limits') or []:
        if item.get('guests'):
            item['guests'] = [v for v in item['guests'] if v in ids]
    report['guests_hidden'] = len(rows) - len(seen)
    report['guests_truncated'] = max(0, len(seen) - GUEST_ROWS)
    report['guests'] = seen[:GUEST_ROWS]
    return report


@bp.route('/api/clusters/<cluster_id>/whatif/options', methods=['GET'])
@require_auth(perms=['cluster.view'])
def whatif_options(cluster_id):
    """What the scenario picker offers: nodes, guest storages, bridges, SDN VNets and the
    thresholds a run would use."""
    mgr, err = _manager(cluster_id)
    if err:
        return err
    try:
        out = whatif.options(mgr)
    except whatif.Unreadable as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logging.error(f"[WHATIF] options of {cluster_id} failed: {e}")
        return jsonify({'error': safe_error(e, 'Failed to read the cluster for the what-if simulator')}), 500
    thr = thresholds_for(cluster_id)
    out['thresholds'] = {k: v for k, v in thr.items() if k != 'nodes'}
    return jsonify(out)


@bp.route('/api/clusters/<cluster_id>/whatif', methods=['POST'])
@require_auth(perms=['cluster.view'])
def whatif_run(cluster_id):
    """One scenario's report. Body: {type, ...} as core/whatif.py parse_scenario reads it."""
    mgr, err = _manager(cluster_id)
    if err:
        return err
    body = request.get_json(silent=True)
    try:
        scenario = whatif.parse_scenario(body)
        report = whatif.run(mgr, scenario, thresholds_for(cluster_id, scenario.get('thresholds')))
    except whatif.Invalid as e:
        return jsonify({'error': str(e), 'code': e.code}), 400
    except whatif.Unreadable as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logging.error(f"[WHATIF] {cluster_id} run failed: {e}")
        return jsonify({'error': safe_error(e, 'The what-if simulation failed')}), 500
    return jsonify(_visible(cluster_id, report))
