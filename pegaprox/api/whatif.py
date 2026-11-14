# -*- coding: utf-8 -*-
"""What-if simulator routes - MK Oct 2026

GET  /api/clusters/<id>/whatif/options   what the scenario picker offers
POST /api/clusters/<id>/whatif           the report of one scenario (pegaprox/core/whatif.py)
POST /api/clusters/<id>/whatif/ranking   the single points of failure of the cluster, ranked

All only read. The POST takes its scenario in the body, so a standby with the live view
answers it from its own managers like any read (app.py _STANDBY_LOCAL_WRITES) and the
active tells its members about nothing. A caller confined to some guests of the cluster
gets the rows of those guests only, and of the nodes they run on: the counts stay, the names
of the other guests and the load of the other nodes do not, and of the backup jobs of a PBS
report the ones naming their own guests only. Their picker offers those nodes
and what is on them. The tenants of a report are the
caller's own tenant to anyone but an administrator, and none to a confined caller; the
ranking is a whole-cluster view and is refused to a confined caller.
"""

import logging

from flask import Blueprint, jsonify, request

from pegaprox.api.helpers import (caller_guest_nodes, caller_is_scoped, check_cluster_access,
                                  require_unconfined, safe_error, scope_vm_rows)
from pegaprox.core import whatif
from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import build_authz_user, require_auth
from pegaprox.utils.rbac import acting_tenant

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


def _visible(cluster_id, report, nodes=None, mgr=None):
    """The report as this caller may see it: guest rows and the guests of each limit
    scoped like the guest list, the counts kept. nodes: the nodes a confined caller's guests
    run on (caller_guest_nodes), None for the whole cluster."""
    if nodes is not None:
        whatif.for_nodes(report, nodes)
    rows = report.get('guests') or []
    seen = scope_vm_rows(cluster_id, rows)
    ids = {r['vmid'] for r in seen}
    for item in report.get('limits') or []:
        if item.get('guests'):
            item['guests'] = [v for v in item['guests'] if v in ids]
    # MK Oct 2026 - the tenants a caller may see by name
    user = build_authz_user(request.session.get('user', ''), request.session)
    if nodes is not None and isinstance(report.get('pbs'), dict):
        _pbs_jobs_visible(cluster_id, report['pbs'], user, mgr)
    mine = None if caller_is_scoped(user, cluster_id) else (acting_tenant(user) or True)
    risk = report.get('risk')
    if risk:
        items = (risk.get('tenants') or {}).get('items') or []
        risk['tenants']['items'] = [t for t in items if mine is True or t['id'] == mine] if mine else []
    for r in seen:
        if 'tenants' in r:
            r['tenants'] = [t for t in r['tenants'] if mine is True or t == mine] if mine else []
    # NS Oct 2026 - the verdict names critical guests and tenants: say it again from what this
    # caller may see, so it names no guest or tenant the rows above leave out
    report['guests'] = seen
    report['verdict'] = whatif.verdict(report)
    report['guests_hidden'] = len(rows) - len(seen)
    report['guests_truncated'] = max(0, len(seen) - GUEST_ROWS)
    report['guests'] = seen[:GUEST_ROWS]
    return report


def _pbs_jobs_visible(cluster_id, pbs, user, mgr):
    """The backup jobs of a PBS report that a confined caller sees on the Backup page
    (storage._job_visible): those naming their own guests only. An all, pool or exclude job
    spans guests of others, its id and schedule stay out. The counts stay whole."""
    from pegaprox.api.storage import _job_visible
    if not pbs.get('jobs'):
        return
    raw = whatif.backup_jobs(mgr) if mgr is not None else None
    if raw is None:
        # not readable again: say so rather than show the storage without jobs
        pbs['jobs'], pbs['jobs_read'] = [], False
        return
    by_id = {str(j.get('id') or ''): j for j in raw}
    pbs['jobs'] = [j for j in pbs['jobs'] if j['id'] in by_id and _job_visible(user, cluster_id, by_id[j['id']])]


@bp.route('/api/clusters/<cluster_id>/whatif/options', methods=['GET'])
@require_auth(perms=['cluster.view'])
def whatif_options(cluster_id):
    """What the scenario picker offers: nodes, guest storages, bridges, SDN VNets and the
    thresholds a run would use."""
    mgr, err = _manager(cluster_id)
    if err:
        return err
    try:
        nodes = caller_guest_nodes(cluster_id)
    except Exception as e:
        logging.error(f"[WHATIF] cannot read the caller's guests on {cluster_id}: {e}")
        return jsonify({'error': 'Cannot read your guests on this cluster - check the server logs'}), 503
    try:
        out = whatif.options(mgr)
    except whatif.Unreadable as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logging.error(f"[WHATIF] options of {cluster_id} failed: {e}")
        return jsonify({'error': safe_error(e, 'Failed to read the cluster for the what-if simulator')}), 500
    if nodes is not None:
        out = _options_on_nodes(out, nodes)
    thr = thresholds_for(cluster_id)
    out['thresholds'] = {k: v for k, v in thr.items() if k != 'nodes'}
    return jsonify(out)


def _options_on_nodes(out, nodes):
    """The picker of a caller confined to some guests: the nodes in `nodes` (where those run),
    the storages, PBS storages and bridges there with those nodes only, and the SDN VNets that
    the bridge list of such a node offers them, none without a node."""
    def there(rows):
        kept = []
        for r in rows or []:
            on = [n for n in r.get('nodes') or [] if n in nodes]
            if on:
                kept.append(dict(r, nodes=on))
        return kept
    return dict(out, nodes=[n for n in out.get('nodes') or [] if n.get('name') in nodes],
                storages=there(out.get('storages')), pbs=there(out.get('pbs')),
                bridges=there(out.get('bridges')), vnets=list(out.get('vnets') or []) if nodes else [])


@bp.route('/api/clusters/<cluster_id>/whatif', methods=['POST'])
@require_auth(perms=['cluster.view'])
def whatif_run(cluster_id):
    """One scenario's report. Body: {type, ...} as core/whatif.py parse_scenario reads it."""
    mgr, err = _manager(cluster_id)
    if err:
        return err
    # MK Nov 2026 - asked before the run: the report carries a row with the load of each node,
    # which a confined caller gets for the nodes of their own guests only
    try:
        nodes = caller_guest_nodes(cluster_id)
    except Exception as e:
        logging.error(f"[WHATIF] cannot read the caller's guests on {cluster_id}: {e}")
        return jsonify({'error': 'Cannot read your guests on this cluster - check the server logs'}), 503
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
    return jsonify(_visible(cluster_id, report, nodes, mgr))


@bp.route('/api/clusters/<cluster_id>/whatif/ranking', methods=['POST'])
@require_auth(perms=['cluster.view'])
def whatif_ranking(cluster_id):
    """Every node, shared storage, PBS storage and bridge failing alone, ranked by the guests
    it affects with critical ones weighted up. Body (optional): {critical_tags, thresholds}."""
    mgr, err = _manager(cluster_id)
    if err:
        return err
    denied = require_unconfined(cluster_id)
    if denied:
        return denied
    body = request.get_json(silent=True)
    try:
        if body is None and request.get_data():
            raise whatif.Invalid('The request body must be a JSON object', 'bad_body')
        asked = whatif.parse_ranking(body)
        out = whatif.ranking(mgr, thresholds_for(cluster_id, asked.get('thresholds')),
                             asked.get('critical_tags'))
    except whatif.Invalid as e:
        return jsonify({'error': str(e), 'code': e.code}), 400
    except whatif.Unreadable as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logging.error(f"[WHATIF] {cluster_id} ranking failed: {e}")
        return jsonify({'error': safe_error(e, 'The what-if ranking failed')}), 500
    return jsonify(out)
