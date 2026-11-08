# -*- coding: utf-8 -*-
"""
Audit log search + facets — MK May 2026.

Adds richer querying on top of the existing /api/audit endpoint, which only
takes user + action + limit. Compliance / security people want date-range,
cluster, severity, IP filter and pagination — that's what this is.

Endpoints:
  GET  /api/audit/search   — paginated, filterable
  GET  /api/audit/facets   — top users/actions/clusters from last N days
"""
import logging
from flask import Blueprint, jsonify, request

from pegaprox.utils.auth import require_auth
from pegaprox.core.db import get_db
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('audit_search', __name__)


def _safe_int(v, default, lo=None, hi=None):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    if lo is not None: n = max(lo, n)
    if hi is not None: n = min(hi, n)
    return n


@bp.route('/api/audit/search', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def search():
    args = request.args
    q = (args.get('q') or '').strip()[:200]
    user = (args.get('user') or '').strip()[:80]
    action = (args.get('action') or '').strip()[:120]
    cluster = (args.get('cluster') or '').strip()[:80]
    severity = (args.get('severity') or '').strip()
    ip = (args.get('ip') or '').strip()[:80]
    date_from = (args.get('date_from') or '').strip()
    date_to = (args.get('date_to') or '').strip()
    offset = _safe_int(args.get('offset', 0), 0, 0, 100000)
    limit = _safe_int(args.get('limit', 100), 100, 1, 500)

    if severity not in ('', 'info', 'warning', 'critical'):
        severity = ''

    try:
        rows, total = get_db().search_audit_log(
            q=q, user=user, action=action, cluster=cluster, severity=severity,
            ip=ip, date_from=date_from, date_to=date_to,
            offset=offset, limit=limit,
        )
        return jsonify({
            'entries': rows,
            'total': total,
            'offset': offset,
            'limit': limit,
            'has_more': (offset + len(rows)) < total,
        })
    except Exception as e:
        logging.warning(f"[audit_search] failed: {e}")
        logging.exception('handler error in audit_search.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/audit/facets', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def facets():
    days = _safe_int(request.args.get('days', 7), 7, 1, 365)
    try:
        return jsonify(get_db().audit_facets(days=days))
    except Exception as e:
        logging.exception('handler error in audit_search.py'); return jsonify({'error': 'internal error'}), 500
