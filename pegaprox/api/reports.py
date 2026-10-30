# -*- coding: utf-8 -*-
"""reports + legacy tags routes - split from monolith dec 2025, NS"""

import time
import os
import json
import logging
import re
import secrets
import unicodedata
import sqlite3  # kept for Row + type re-exports
import threading
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request

# MK May 2026 — direct DB connections must go through dbcrypto so SQLCipher
# unlocks the encrypted DB with the master key.
from pegaprox.core import dbcrypto

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *

from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.rbac import get_user_clusters
from pegaprox.api.helpers import check_cluster_access, load_server_settings, scope_vm_rows, require_unconfined
from pegaprox.background.metrics import (load_metrics_history, start_metrics_collector,
                                         history_range, load_metrics_range)
from pegaprox.background.syslog_server import DB_FILE, SEVERITY_MAP
from pegaprox.api.schedules import start_scheduler

bp = Blueprint('reports', __name__)


# The three report endpoints below take period=hour|day|week and used to cut the
# window out of "the newest 1000 snapshot rows". At the 5-min cadence that cap is
# ~3.5 days, and less whenever rows land more often, so "Last Week" quietly ended
# wherever those rows ended and looked identical to "Last 24h". Load the window
# the caller actually asked for instead.
# All three read a cluster's name and totals and nothing else, so they ask the
# loader for just that (totals_only): the cached window stays small at 10k guests.
def _period_cutoff(period):
    """(window_days, cutoff_datetime) for a period param. hour shares the 1-day
    window with day so the two views hit the same cached read."""
    now = datetime.now()
    if period == 'hour':
        return 1, now - timedelta(hours=1)
    if period == 'week':
        return 7, now - timedelta(days=7)
    return 1, now - timedelta(days=1)


def _with_offset(ts):
    """A stored timestamp as ISO with the server's UTC offset.

    MK Oct 2026 - snapshots, scans and syslog rows store datetime.now().isoformat():
    server-local and naive. A browser reads a naive ISO string as ITS local time, so
    with server and browser in different zones every chart label was off by the
    difference. The stored format stays, the answer carries the offset.
    """
    if not ts or not isinstance(ts, str):
        return ts
    try:
        return datetime.fromisoformat(ts).astimezone().isoformat()
    except ValueError:
        return ts


def _syslog_search_terms(search_text):
    return [term for term in re.split(r'\s+', search_text.strip()) if term]


def _syslog_escape_fts_term(term):
    sanitized = ''.join(ch for ch in term if ch.isprintable() and ch not in '\x00\r\n\t')
    sanitized = sanitized.replace('"', '""').strip()
    return f'"{sanitized}"*' if sanitized else ''


def _syslog_fts_query(search_text):
    terms = _syslog_search_terms(search_text)
    if not terms:
        return ''
    escaped_terms = [_syslog_escape_fts_term(term) for term in terms]
    escaped_terms = [term for term in escaped_terms if term]
    return ' AND '.join(escaped_terms)


def _syslog_like_clause(search_text):
    like = f'%{search_text}%'
    return (
        """(
            timestamp LIKE ? COLLATE NOCASE OR
            source_ip LIKE ? COLLATE NOCASE OR
            hostname LIKE ? COLLATE NOCASE OR
            severity_text LIKE ? COLLATE NOCASE OR
            message LIKE ? COLLATE NOCASE OR
            protocol LIKE ? COLLATE NOCASE
        )""",
        [like, like, like, like, like, like],
    )


def _syslog_hostname_tokens(value):
    value = str(value or '').strip().lower()
    if not value:
        return set()
    if '://' in value:
        parsed = urlparse(value)
        value = parsed.hostname or value
    value = value.split('/')[0].split('@')[-1]
    if value.startswith('[') and ']' in value:
        value = value[1:value.index(']')]
    elif ':' in value and value.count(':') == 1:
        value = value.rsplit(':', 1)[0]
    value = value.strip('.')
    if not value:
        return set()
    tokens = {value}
    # the short form of an address is its first octet, and LIKE '10.%' is every sender in 10/8 (#1119)
    if '.' in value and not re.fullmatch(r'[0-9.]+', value):
        tokens.add(value.split('.', 1)[0])
    return tokens


def _syslog_cached_node_names(manager):
    """The node names a manager last read (its short node status cache, else what the HA
    monitor keeps), None when it holds none."""
    cached = getattr(manager, '_node_status_cache', None)
    if isinstance(cached, tuple) and len(cached) == 2 and isinstance(cached[1], dict) and cached[1]:
        return list(cached[1])
    nodes = getattr(manager, 'ha_node_status', None)
    return list(nodes) if isinstance(nodes, dict) and nodes else None


def _syslog_cluster_hostnames(cluster_id, cached_only=False):
    """cached_only: the node names the manager already holds where it holds any, a read of
    its nodes only where it holds none."""
    manager = cluster_managers.get(cluster_id)
    if not manager:
        return set()

    hostnames = set()
    config = getattr(manager, 'config', None)
    for value in (
        getattr(manager, 'host', ''),
        getattr(config, 'host', '') if config else '',
        getattr(config, 'name', '') if config else '',
    ):
        hostnames.update(_syslog_hostname_tokens(value))

    names = _syslog_cached_node_names(manager) if cached_only else None
    if names is not None:
        for node_name in names:
            hostnames.update(_syslog_hostname_tokens(node_name))
        return hostnames
    try:
        node_status = manager.get_node_status() or {}
        for node_name in node_status.keys():
            hostnames.update(_syslog_hostname_tokens(node_name))
    except Exception as exc:
        logging.debug(f"[Syslog] Could not load nodes for cluster filter {cluster_id}: {exc}")
        for node_name in getattr(manager, 'ha_node_status', {}).keys():
            hostnames.update(_syslog_hostname_tokens(node_name))

    return hostnames


_AMBIGUOUS_HOSTS = {'at': 0.0, 'tokens': frozenset()}
_AMBIGUOUS_HOSTS_TTL = 60.0
_AMBIGUOUS_HOSTS_LOCK = threading.Lock()


def _syslog_ambiguous_hostnames(cached_only=False):
    """Host tokens that more than one cluster claims.

    MK Sep 2026 - _syslog_hostname_tokens derives a short form from every node name, so
    two clusters with a node called pve1 both claim the token "pve1". The gate below
    turns each token into `= token` OR `LIKE 'token.%'`, and that second half is the
    leak: tenant A's "pve1" matches tenant B's "pve1.b.example" and hands over its
    syslog. A token two clusters claim also cannot attribute a bare "pve1" line to
    either of them, so it is dropped rather than guessed - the same answer every other
    ambiguous authorization question in this tree gets.

    Memoised for a minute: node names change on the timescale of a reinstall, and
    working them out walks every cluster's node list.

    MK Oct 2026 - cached_only (the timeline, which promises no read of its own): each
    cluster's node names as its manager last read them, a read only for one that holds none.
    """
    now = time.time()
    cached = _AMBIGUOUS_HOSTS
    if cached['tokens'] is not None and (now - cached['at']) < _AMBIGUOUS_HOSTS_TTL:
        return cached['tokens']
    with _AMBIGUOUS_HOSTS_LOCK:
        if (time.time() - _AMBIGUOUS_HOSTS['at']) < _AMBIGUOUS_HOSTS_TTL:
            return _AMBIGUOUS_HOSTS['tokens']
        claims = {}
        for _cid in list(cluster_managers.keys()):
            _toks = _syslog_cluster_hostnames(_cid, cached_only=True) if cached_only else _syslog_cluster_hostnames(_cid)
            for _tok in _toks:
                claims.setdefault(_tok, set()).add(_cid)
        tokens = frozenset(t for t, cids in claims.items() if len(cids) > 1)
        if tokens:
            logging.info(f"[Syslog] {len(tokens)} host name(s) claimed by more than one "
                         f"cluster - excluded from syslog scoping: {sorted(tokens)[:5]}")
        _AMBIGUOUS_HOSTS['tokens'] = tokens
        _AMBIGUOUS_HOSTS['at'] = time.time()
        return tokens


def _syslog_like_literal(value):
    """`value` with LIKE's wildcards escaped, for `LIKE ? ESCAPE '\\'`."""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def _syslog_host_clause(values, params, cached_only=False):
    """`(host = x OR host LIKE 'x.%' OR ...)` over the tokens that identify one cluster.

    NS Oct 2026 - the tokens come from the cluster name and host, which a cluster.config
    holder sets on their own cluster. A name of '%' made the LIKE half match every host
    with a dot in it, so the caller read every tenant's syslog (#1119). Only the '.%' we
    add is a wildcard now."""
    _ambiguous = _syslog_ambiguous_hostnames(cached_only=cached_only)
    parts = []
    for value in sorted(set(values) - _ambiguous):
        parts.append("LOWER(logs.hostname) = ?")
        params.append(value)
        parts.append("LOWER(logs.hostname) LIKE ? ESCAPE '\\'")
        params.append(f"{_syslog_like_literal(value)}.%")
    return f"({' OR '.join(parts)})" if parts else "1 = 0"


def _running_in_scope(cluster_id):
    """Running guests of a cluster that the caller may see, from the manager's list (a
    poll's fresh copy where there is one). 0 when the list cannot be read."""
    mgr = cluster_managers.get(cluster_id)
    if not mgr:
        return 0
    try:
        rows = scope_vm_rows(cluster_id, mgr.get_vm_resources(max_age=15) or [])
    except Exception as e:
        logging.error(f"Error getting VM resources for reports: {e}")
        return 0
    return sum(1 for r in rows if r and r.get('status') == 'running')


@bp.route('/api/reports/summary', methods=['GET'])
@require_auth()
def get_reports_summary():
    """Get summary report across all clusters

    Query params:
    - period: 'hour', 'day', 'week' (default: day)
    """
    period = request.args.get('period', 'day')

    # NS: Feb 2026 - tenant filtering for multi-tenant security
    # sec (audit): was the raw stored record, so an admin-owned viewer-scoped token inherited the
    # owner's admin reach and get_user_clusters returned None = every cluster. (top-vms in this
    # same file already builds its identity correctly — these three were the stragglers.)
    from pegaprox.utils.auth import build_authz_user
    usr = getattr(request, 'session', {}).get('user', 'system')
    user_data = build_authz_user(usr, getattr(request, 'session', {}) or {})
    accessible_clusters = get_user_clusters(user_data)  # None = admin (all clusters)

    window_days, cutoff = _period_cutoff(period)
    history = load_metrics_history(days=window_days, totals_only=True)
    snapshots = history.get('snapshots', [])

    if not snapshots:
        return jsonify({'error': 'No historical data available yet'}), 404

    cutoff_str = cutoff.isoformat()
    filtered = [s for s in snapshots if s.get('timestamp', '') >= cutoff_str]

    if not filtered:
        return jsonify({'error': f'No data for the last {period}'}), 404

    # Calculate averages and trends
    report = {
        'period': period,
        'data_points': len(filtered),
        'start_time': _with_offset(filtered[0].get('timestamp')),
        'end_time': _with_offset(filtered[-1].get('timestamp')),
        'clusters': {}
    }

    # Aggregate per cluster
    from pegaprox.api.helpers import caller_is_scoped
    scoped = {}
    for snapshot in filtered:
        for cluster_id, cluster_data in snapshot.get('clusters', {}).items():
            # Skip clusters the user cannot access
            if accessible_clusters is not None and cluster_id not in accessible_clusters:
                continue
            if cluster_id not in report['clusters']:
                scoped[cluster_id] = caller_is_scoped(user_data, cluster_id)
                report['clusters'][cluster_id] = {
                    'name': cluster_data.get('name', cluster_id),
                    'cpu_samples': [],
                    'mem_samples': [],
                    'vm_samples': []
                }
            
            totals = cluster_data.get('totals', {})
            if totals.get('cpu_total', 0) > 0:
                cpu_percent = totals['cpu_used'] / totals['cpu_total'] * 100
                report['clusters'][cluster_id]['cpu_samples'].append(cpu_percent)
            
            if totals.get('mem_total', 0) > 0:
                mem_percent = totals['mem_used'] / totals['mem_total'] * 100
                report['clusters'][cluster_id]['mem_samples'].append(mem_percent)
            
            # the history has the cluster's totals only, not a confined caller's share
            if not scoped[cluster_id]:
                vm_count = totals.get('vms_running', 0) + totals.get('cts_running', 0)
                report['clusters'][cluster_id]['vm_samples'].append(vm_count)
    
    # Calculate stats
    for cluster_id, data in report['clusters'].items():
        cpu = data.pop('cpu_samples', [])
        mem = data.pop('mem_samples', [])
        vms = data.pop('vm_samples', [])
        if scoped.get(cluster_id):
            # MK Oct 2026 - as the cluster summary does: the running guests it may see, now
            vms = [_running_in_scope(cluster_id)]
            data['scoped'] = True
        
        data['cpu'] = {
            'avg': round(sum(cpu) / len(cpu), 1) if cpu else 0,
            'min': round(min(cpu), 1) if cpu else 0,
            'max': round(max(cpu), 1) if cpu else 0,
            'current': round(cpu[-1], 1) if cpu else 0
        }
        
        data['memory'] = {
            'avg': round(sum(mem) / len(mem), 1) if mem else 0,
            'min': round(min(mem), 1) if mem else 0,
            'max': round(max(mem), 1) if mem else 0,
            'current': round(mem[-1], 1) if mem else 0
        }
        
        data['vms_running'] = {
            'avg': round(sum(vms) / len(vms), 1) if vms else 0,
            'min': min(vms) if vms else 0,
            'max': max(vms) if vms else 0,
            'current': vms[-1] if vms else 0
        }
    
    return jsonify(report)


@bp.route('/api/syslog/events', methods=['GET'])
@require_auth(perms=['admin.audit'])
def get_integrated_syslog_events():
    """Paginated overview of events stored by the integrated syslog server."""
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except (TypeError, ValueError):
        page = 1

    try:
        per_page = int(request.args.get('per_page', 50))
    except (TypeError, ValueError):
        per_page = 50
    per_page = min(max(per_page, 1), 50)

    search = (request.args.get('search') or '').strip()
    severity = (request.args.get('severity') or '').strip()
    protocol = (request.args.get('protocol') or '').strip().upper()
    hostname = (request.args.get('hostname') or '').strip()
    source_ip = (request.args.get('source_ip') or '').strip()
    facility = (request.args.get('facility') or '').strip()
    cluster_id = (request.args.get('cluster_id') or '').strip()

    sort_map = {
        'id': 'logs.id',
        'timestamp': 'logs.timestamp',
        'source_ip': 'logs.source_ip',
        'hostname': 'logs.hostname',
        'facility': 'logs.facility',
        'severity': 'logs.severity',
        'severity_text': 'logs.severity_text',
        'message': 'logs.message',
        'protocol': 'logs.protocol',
    }

    sort_by = sort_map.get(request.args.get('sort_by', 'timestamp'), 'timestamp')
    sort_dir = 'asc' if request.args.get('sort_dir', 'desc').lower() == 'asc' else 'desc'
    # NS: belt-and-braces gegen die SQLi-finding bei semgrep am 2026-05-06.
    # sort_by ist eh aus dem map.get() mit hardcoded fallback 'timestamp', und
    # sort_dir aus dem ternary nur asc/desc -- aber semgrep sieht das nicht
    # weil der validate-step 80 zeilen frueher steht. hier nochmal explizit
    # damit's am sink offensichtlich ist und ich nicht in einem halben jahr
    # an dieser stelle nochmal grübeln muss.
    if sort_by not in sort_map.values():
        sort_by = 'logs.timestamp'
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'desc'

    db_path = os.path.abspath(DB_FILE)
    if not os.path.exists(db_path):
        return jsonify({
            'items': [],
            'pagination': {'page': page, 'per_page': per_page, 'total': 0, 'total_pages': 0},
            'filters': {
                'protocols': [],
                'severities': [{'value': level, 'label': text} for level, text in sorted(SEVERITY_MAP.items())]
            }
        })

    where = []
    params = []
    joins = []

    # MK May 2026: route via dbcrypto so SQLCipher handshake runs first.
    conn = dbcrypto.connect(db_path)
    conn.row_factory = dbcrypto.Row
    conn.execute("PRAGMA temp_store=MEMORY")
    fts_available = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'logs_fts'"
    ).fetchone() is not None

    if search:
        fts_query = _syslog_fts_query(search)
        if fts_available and fts_query:
            joins.append("JOIN logs_fts ON logs_fts.rowid = logs.id")
            where.append("logs_fts MATCH ?")
            params.append(fts_query)
        else:
            like_clause, like_params = _syslog_like_clause(search)
            where.append(like_clause)
            params.extend(like_params)

    if severity != '':
        try:
            severity_value = int(severity)
            where.append('logs.severity = ?')
            params.append(severity_value)
        except ValueError:
            pass

    if protocol:
        where.append("logs.protocol = ?")
        params.append(protocol)

    if hostname:
        where.append("logs.hostname LIKE ? COLLATE NOCASE")
        params.append(f'{hostname}%')

    if source_ip:
        where.append("logs.source_ip LIKE ? COLLATE NOCASE")
        params.append(f'{source_ip}%')

    if facility != '':
        try:
            facility_value = int(facility)
            where.append('logs.facility = ?')
            params.append(facility_value)
        except ValueError:
            pass

    if cluster_id and load_server_settings().get('syslog_filter_by_selected_cluster', False):
        ok, err = check_cluster_access(cluster_id)
        if not ok:
            return err
        where.append(_syslog_host_clause(_syslog_cluster_hostnames(cluster_id), params))

    # NS Aug 2026 (AI-pentest) — always confine a non-all-cluster caller to the hostnames of the
    # clusters they can actually reach, independent of the syslog_filter_by_selected_cluster flag and
    # of whether a cluster_id filter was supplied. Omitting cluster_id previously returned EVERY
    # cluster's syslog to a tenant-scoped admin.audit holder.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import get_user_clusters
    # NS Oct 2026 - a node's syslog is the whole node's, so only clusters the caller's tenant
    # owns count. A pool grant on a foreign cluster reaches that pool's guests, not its hosts (#1010).
    _acc = get_user_clusters(build_authz_user(request.session.get('user', ''), request.session),
                             include_pools=False)
    if _acc is not None:  # None = global-admin / all-cluster; a list = confine to it
        _allowed_hosts = set()
        for _cid in _acc:
            _allowed_hosts.update(_syslog_cluster_hostnames(_cid))
        where.append(_syslog_host_clause(_allowed_hosts, params))

    where_sql = f"WHERE {' AND '.join(where)}" if where else ''
    joins_sql = f"{' '.join(joins)}" if joins else ''
    offset = (page - 1) * per_page

    try:
        total = conn.execute(
            f"SELECT COUNT(*) AS count FROM logs {joins_sql} {where_sql}",
            params
        ).fetchone()['count']

        rows = conn.execute(
            f"""
            SELECT
                logs.id,
                logs.timestamp,
                logs.source_ip,
                logs.hostname,
                logs.facility,
                logs.severity,
                logs.severity_text,
                logs.message,
                logs.protocol
            FROM logs
            {joins_sql}
            {where_sql}
            ORDER BY {sort_by} {sort_dir}, logs.id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, per_page, offset]
        ).fetchall()

        protocol_rows = conn.execute(
            """
            SELECT DISTINCT protocol
            FROM logs
            WHERE protocol IS NOT NULL AND TRIM(protocol) != ''
            ORDER BY protocol ASC
            """
        ).fetchall()
    finally:
        conn.close()

    total_pages = (total + per_page - 1) // per_page if total else 0

    return jsonify({
        'items': [dict(dict(row), timestamp=_with_offset(row['timestamp'])) for row in rows],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
        },
        'filters': {
            'protocols': [row['protocol'] for row in protocol_rows],
            'severities': [{'value': level, 'label': text} for level, text in sorted(SEVERITY_MAP.items())]
        }
    })


@bp.route('/api/reports/timeline', methods=['GET'])
@require_auth()
def get_reports_timeline():
    """Get timeline data for charts

    Query params:
    - period: 'hour', 'day', 'week'
    - cluster_id: Optional - filter to specific cluster
    - metric: 'cpu', 'memory', 'vms' (default: all)
    """
    period = request.args.get('period', 'day')
    filter_cluster = request.args.get('cluster_id')
    metric = request.args.get('metric', 'all')

    # NS: Feb 2026 - tenant filtering for multi-tenant security
    # sec (audit): was the raw stored record, so an admin-owned viewer-scoped token inherited the
    # owner's admin reach and get_user_clusters returned None = every cluster. (top-vms in this
    # same file already builds its identity correctly — these three were the stragglers.)
    from pegaprox.utils.auth import build_authz_user
    usr = getattr(request, 'session', {}).get('user', 'system')
    user_data = build_authz_user(usr, getattr(request, 'session', {}) or {})
    accessible_clusters = get_user_clusters(user_data)  # None = admin (all clusters)

    window_days, cutoff = _period_cutoff(period)
    history = load_metrics_history(days=window_days, totals_only=True)
    snapshots = history.get('snapshots', [])

    if not snapshots:
        return jsonify({'error': 'No historical data available'}), 404

    cutoff_str = cutoff.isoformat()
    filtered = [s for s in snapshots if s.get('timestamp', '') >= cutoff_str]

    # Build timeline
    timeline = {
        'period': period,
        'timestamps': [],
        'data': {}
    }

    from pegaprox.api.helpers import caller_is_scoped
    scoped = {}
    for snapshot in filtered:
        timestamp = snapshot.get('timestamp', '')
        timeline['timestamps'].append(_with_offset(timestamp))

        for cluster_id, cluster_data in snapshot.get('clusters', {}).items():
            if filter_cluster and cluster_id != filter_cluster:
                continue
            # Skip clusters the user cannot access
            if accessible_clusters is not None and cluster_id not in accessible_clusters:
                continue
            
            if cluster_id not in timeline['data']:
                scoped[cluster_id] = caller_is_scoped(user_data, cluster_id)
                timeline['data'][cluster_id] = {
                    'name': cluster_data.get('name', cluster_id),
                    'cpu': [],
                    'memory': [],
                    'vms': []
                }
                if scoped[cluster_id]:
                    timeline['data'][cluster_id]['scoped'] = True
            
            totals = cluster_data.get('totals', {})
            
            # CPU
            if metric in ['all', 'cpu']:
                cpu = 0
                if totals.get('cpu_total', 0) > 0:
                    cpu = round(totals['cpu_used'] / totals['cpu_total'] * 100, 1)
                timeline['data'][cluster_id]['cpu'].append(cpu)
            
            # Memory
            if metric in ['all', 'memory']:
                mem = 0
                if totals.get('mem_total', 0) > 0:
                    mem = round(totals['mem_used'] / totals['mem_total'] * 100, 1)
                timeline['data'][cluster_id]['memory'].append(mem)
            
            # VMs - MK Oct 2026: the history has the cluster's totals only, so a confined
            # caller gets no guest count series, as in the summaries
            if metric in ['all', 'vms'] and not scoped[cluster_id]:
                vms = totals.get('vms_running', 0) + totals.get('cts_running', 0)
                timeline['data'][cluster_id]['vms'].append(vms)
    
    return jsonify(timeline)


@bp.route('/api/reports/top-vms', methods=['GET'])
@require_auth()
def get_top_vms():
    """Get top VMs by resource usage

    Query params:
    - metric: 'cpu' or 'memory' (default: cpu)
    - limit: Number of results (default: 10)
    """
    metric = request.args.get('metric', 'cpu')
    limit = int(request.args.get('limit', 10))

    # NS: Feb 2026 - tenant filtering for multi-tenant security
    # sec (audit): was the raw stored record, so an admin-owned viewer-scoped token inherited the
    # owner's admin reach and get_user_clusters returned None = every cluster. (top-vms in this
    # same file already builds its identity correctly — these three were the stragglers.)
    from pegaprox.utils.auth import build_authz_user
    usr = getattr(request, 'session', {}).get('user', 'system')
    user_data = build_authz_user(usr, getattr(request, 'session', {}) or {})
    accessible_clusters = get_user_clusters(user_data)  # None = admin (all clusters)

    vms = []

    for cluster_id, mgr in list(cluster_managers.items()):
        # Skip clusters the user cannot access
        if accessible_clusters is not None and cluster_id not in accessible_clusters:
            continue
        if not mgr.is_connected:
            continue
        
        try:
            # #773 audit — tenant filtering (accessible_clusters) gates the CLUSTER; still scope
            # the per-VM rows so a pool-/ACL-scoped user doesn't see every VM on a cluster they own.
            resources = scope_vm_rows(cluster_id, mgr.get_vm_resources())
            for r in resources:
                if r.get('status') != 'running':
                    continue

                vm_data = {
                    'cluster_id': cluster_id,
                    'cluster_name': mgr.config.name,
                    'vmid': r.get('vmid'),
                    'name': r.get('name'),
                    'node': r.get('node'),
                    'type': r.get('type'),
                    'cpu': r.get('cpu', 0),
                    'mem': r.get('mem', 0),
                    'maxmem': r.get('maxmem', 0),
                    'mem_percent': round(r.get('mem', 0) / max(r.get('maxmem', 1), 1) * 100, 1)
                }
                vms.append(vm_data)
        except:
            pass
    
    # Sort by metric
    if metric == 'memory':
        vms.sort(key=lambda x: x.get('mem_percent', 0), reverse=True)
    else:
        vms.sort(key=lambda x: x.get('cpu', 0), reverse=True)
    
    return jsonify(vms[:limit])


# Start background threads when server starts
# MK: Move this to main() later, for now it's fine here
threading.Thread(target=lambda: (time.sleep(5), start_scheduler()), daemon=True).start()
threading.Thread(target=lambda: (time.sleep(10), start_metrics_collector()), daemon=True).start()


# ============================================
# CVE / Package Vulnerability Scanner
# MK: Mar 2026 - per-node security scanning
# ============================================

@bp.route('/api/clusters/<cluster_id>/reports/cve-scan', methods=['POST'])
@require_auth(perms=['node.view'])
def scan_all_nodes_cves(cluster_id):
    """Scan all nodes in a cluster for package vulnerabilities"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # sec (audit): node.view is a default viewer perm and check_cluster_access admits a
    # pool-/ACL-scoped caller by design — but this returns every node's kernel, pveversion,
    # pending-reboot state and full CVE list (an unpatched-target map), and fans out one SSH
    # session per node. There is no per-object notion for a node, so deny a confined caller.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.api.helpers import caller_is_scoped
    if caller_is_scoped(build_authz_user(request.session.get('user', ''), request.session), cluster_id):
        return jsonify({'error': 'Access denied to this cluster'}), 403


    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    try:
        node_status = mgr.get_node_status()
    except:
        return jsonify({'error': 'Failed to get node list'}), 500

    results = []
    for node_name in node_status:
        # #199: skip offline nodes — no point trying SSH on dead nodes
        ns = node_status.get(node_name, {})
        if ns.get('offline') or ns.get('status') == 'offline':
            results.append({'node': node_name, 'error': 'Node offline'})
            continue
        try:
            scan = mgr.scan_node_packages(node_name)
            if isinstance(scan, dict) and scan.get('timestamp'):
                scan['timestamp'] = _with_offset(scan['timestamp'])
            results.append(scan)
        except Exception as e:
            logging.warning(f"[cve-scan] node {node_name} scan failed: {e}")  # detail to logs, not the response
            results.append({'node': node_name, 'error': 'package scan failed'})   # sec (audit): no raw str(e) to the client

    total_sec = sum(r.get('security_count', 0) for r in results)
    total_upd = sum(r.get('total_count', 0) for r in results)
    total_cves = sum(r.get('cve_count', 0) for r in results)
    has_debsecan = any(r.get('debsecan_available') for r in results)

    return jsonify({
        'cluster_id': cluster_id,
        'cluster_name': getattr(mgr.config, 'name', cluster_id),
        'scanned_at': datetime.now().astimezone().isoformat(),
        'nodes': results,
        'summary': {
            'nodes_scanned': len(results),
            'nodes_ok': sum(1 for r in results if not r.get('error') and r.get('cve_count', 0) == 0 and r.get('security_count', 0) == 0),
            'total_cves': total_cves,
            'total_security': total_sec,
            'total_updates': total_upd,
            'debsecan_available': has_debsecan,
        }
    })


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/cve-scan', methods=['POST'])
@require_auth(perms=['node.view'])
def scan_single_node_cves(cluster_id, node):
    """Scan a single node for package vulnerabilities"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # sec (audit): node.view is a default viewer perm and check_cluster_access admits a
    # pool-/ACL-scoped caller by design — but this returns every node's kernel, pveversion,
    # pending-reboot state and full CVE list (an unpatched-target map), and fans out one SSH
    # session per node. There is no per-object notion for a node, so deny a confined caller.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.api.helpers import caller_is_scoped
    if caller_is_scoped(build_authz_user(request.session.get('user', ''), request.session), cluster_id):
        return jsonify({'error': 'Access denied to this cluster'}), 403


    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    result = mgr.scan_node_packages(node)
    if isinstance(result, dict) and result.get('timestamp'):
        result['timestamp'] = _with_offset(result['timestamp'])
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/reports/install-debsecan', methods=['POST'])
@require_auth(perms=['node.maintenance'])
def install_debsecan(cluster_id):
    """Install debsecan on all nodes in the cluster via SSH"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    try:
        node_status = mgr.get_node_status()
    except:
        return jsonify({'error': 'Failed to get node list'}), 500

    results = []
    for node_name in node_status:
        out = mgr._ssh_node_output(node_name, 'DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y debsecan 2>&1 | tail -3', timeout=120)
        if out is not None:
            results.append({'node': node_name, 'success': True, 'output': out.strip()[-200:]})
        else:
            results.append({'node': node_name, 'success': False, 'error': 'SSH failed'})

    ok_count = sum(1 for r in results if r['success'])
    return jsonify({
        'installed': ok_count,
        'total': len(results),
        'nodes': results
    })


# ============================================
# CIS Hardening Endpoints - MK Mar 2026
# ============================================

# NS Sep 2026 (#717) — every SSH-backed node check answered a bare 502 "SSH to <node>
# failed", which the compliance dashboard rendered as the string "err 502" next to the
# node and nothing else. On a token-only cluster that is EVERY node, so the dashboard
# looked broken rather than unconfigured. Same shape for all of them: a code the UI can
# branch on, a sentence saying what happened, and one saying what to do about it.
_SSH_ERRORS = {
    'SSH_NO_CREDENTIALS': (412, 'Add an SSH key or a password to this cluster under '
                                'Settings > Clusters. An API token alone cannot open a '
                                'shell, which these checks need.'),
    'SSH_DISABLED':       (412, 'SSH to this cluster is switched off in its settings. '
                                'These checks read the node over SSH, so they cannot '
                                'run until it is switched back on.'),
    'NODE_BACKOFF':       (503, 'The node stopped answering and is being retried with a '
                                'backoff. Check that it is up and reachable from PegaProx.'),
    'SSH_FAILED':         (502, 'Credentials are configured but the connection did not '
                                'succeed — check reachability on port 22, the stored '
                                'username, and whether the host key changed.'),
}


def _ssh_unavailable(mgr, node):
    """One JSON shape for 'this node check needs SSH and SSH did not happen'."""
    # every manager class that reaches this route should have ssh_diagnose, but this is
    # the error path — it must not be the thing that raises. Anything unexpected back
    # from it falls through to the generic reason.
    reason = None
    try:
        probe = getattr(mgr, 'ssh_diagnose', None)
        if callable(probe):
            reason = probe(node)
    except Exception:
        logging.debug('[hardening] ssh_diagnose failed on %s', node, exc_info=True)
    if not (isinstance(reason, (tuple, list)) and len(reason) == 2):
        reason = ('SSH_FAILED', None)
    code, detail = reason
    status, hint = _SSH_ERRORS.get(code, _SSH_ERRORS['SSH_FAILED'])
    return jsonify({
        'error': f'Cannot read {node} over SSH' + (f': {detail}' if detail else ''),
        'code': code,
        'hint': hint,
        'node': node,
        # cluster-wide causes let the caller stop asking about the other 99 nodes
        'cluster_wide': code == 'SSH_NO_CREDENTIALS',
    }), status


# MK Oct 2026 - custom hardening profiles. A profile is a named pick of the built-in
# controls (CIS_CHECKS and the VS-NfD extras) plus values for the parameters of the
# templated ones, never a command of its own: what runs on a node is still the shipped
# check and apply text, and a value passes the rule apply uses (hardening_param_value).
# One list for the whole installation, shared with the standbys (ha.SYNC_TABLES). Using
# one takes node.maintenance like the check; writing one also takes admin.settings and an
# account no tenant or cluster list limits, the bar of the banners (api/banners.py).
HARDENING_PROFILE_FORMAT = 'pegaprox-hardening-profile'
HARDENING_PROFILE_VERSION = 1
HP_MAX = 100
HP_NAME_MAX = 64
HP_DESCRIPTION_MAX = 500
HP_VALUE_MAX = 256
_HP_CONTROLS_MAX = 500          # entries in a request, duplicates included
_HP_ID_RE = re.compile(r'[0-9a-f]{16}')
# C0 and C1 controls, and the bidi embeddings, overrides and isolates that make a name
# read other than it is stored
_HP_CONTROL_CHARS = re.compile('[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]')
# letters that draw nothing; a name made of them reads as blank in the profile selects
_HP_BLANK = frozenset('\u115f\u1160\u3164\uffa0\u2800')
_HP_FIELDS = ('name', 'description', 'controls', 'params')
_hp_write_lock = threading.Lock()


class _ProfileRefused(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _hardening_catalog():
    """{control id: control} of every built-in control, in the order the check runs them."""
    from pegaprox.core.manager import PegaProxManager
    return PegaProxManager._all_hardening_controls()


def _hp_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _hp_user():
    return (getattr(request, 'session', None) or {}).get('user', 'system')


def _hp_rows(profile_id=None):
    """The stored rows, or the one of `profile_id`. Raises when the table cannot be read:
    a write must not take that for an empty list."""
    from pegaprox.core.db import get_db
    c = get_db().conn.cursor()
    if profile_id is None:
        c.execute('SELECT * FROM hardening_profiles ORDER BY name COLLATE NOCASE, id')
    else:
        c.execute('SELECT * FROM hardening_profiles WHERE id = ?', (profile_id,))
    return [dict(r) for r in c.fetchall()]


def _hp_public(row, catalog):
    """A stored profile as the routes hand it out, or None when the row does not read as
    one (rows come in with the sync too, from whatever version the active runs). Controls
    this version does not know go to dropped_controls, their values are left out."""
    if not isinstance(row.get('id'), str) or not _HP_ID_RE.fullmatch(row['id']):
        return None
    try:
        controls = json.loads(row.get('controls') or '[]')
        params = json.loads(row.get('params') or '{}')
    except (TypeError, ValueError):
        return None
    if (not isinstance(controls, list) or not all(isinstance(c, str) for c in controls)
            or not isinstance(params, dict) or not isinstance(row.get('name'), str)):
        return None
    known = [c for c in controls if c in catalog]
    return {
        'id': row['id'],
        'name': row['name'],
        'description': row['description'] if isinstance(row.get('description'), str) else '',
        'controls': known,
        'params': {cid: {k: v for k, v in vals.items() if isinstance(v, str)}
                   for cid, vals in params.items() if cid in known and isinstance(vals, dict)},
        'dropped_controls': [c for c in controls if c not in catalog],
        'created_by': row.get('created_by') or '',
        'created_at': row.get('created_at') or '',
        'updated_by': row.get('updated_by') or '',
        'updated_at': row.get('updated_at') or '',
    }


def custom_hardening_profile(profile_id):
    """The custom profile of that id as _hp_public has it, None for none (or a malformed
    id). Raises when the table cannot be read."""
    if not isinstance(profile_id, str) or not _HP_ID_RE.fullmatch(profile_id):
        return None
    rows = _hp_rows(profile_id)
    return _hp_public(rows[0], _hardening_catalog()) if rows else None


def _hp_text(value, what, limit, newlines=False):
    if value is None:
        value = ''
    if not isinstance(value, str):
        raise _ProfileRefused(f'{what} is text')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        # a lone surrogate from a JSON escape; the database would refuse it at the INSERT
        raise _ProfileRefused(f'The {what} is not valid text')
    if newlines:
        value = value.replace('\r\n', '\n')
    value = value.strip()
    if len(value) > limit:
        raise _ProfileRefused(f'The {what} is longer than {limit} characters')
    if _HP_CONTROL_CHARS.search(value.replace('\n', '') if newlines else value):
        raise _ProfileRefused(f'The {what} holds a control character')
    return value


def _hp_validated(data, catalog):
    """name, description, controls and params from a request body, checked. Raises
    _ProfileRefused; nothing is written before this passed."""
    if 'format' in data or 'version' in data:
        version = data.get('version')
        if (data.get('format') != HARDENING_PROFILE_FORMAT or isinstance(version, bool)
                or version != HARDENING_PROFILE_VERSION):
            raise _ProfileRefused(f'This is not a hardening profile exported by PegaProx '
                                  f'({HARDENING_PROFILE_FORMAT}, version {HARDENING_PROFILE_VERSION})')
    name = _hp_text(data.get('name'), 'name', HP_NAME_MAX)
    if not name:
        raise _ProfileRefused('Enter a name for the profile')
    # format characters (zero width, direction marks, joiners) do not show and let two
    # names look alike; and a name needs one character that draws something
    if any(unicodedata.category(ch) == 'Cf' for ch in name):
        raise _ProfileRefused('The name holds a character that does not show')
    if not any(unicodedata.category(ch)[0] in 'LNPS' and ch not in _HP_BLANK for ch in name):
        raise _ProfileRefused('The name has no visible character')
    description = _hp_text(data.get('description'), 'description', HP_DESCRIPTION_MAX, newlines=True)

    raw = data.get('controls')
    if not isinstance(raw, list) or not raw:
        raise _ProfileRefused('Pick at least one control')
    if len(raw) > _HP_CONTROLS_MAX or not all(isinstance(c, str) for c in raw):
        raise _ProfileRefused('controls is a list of control ids')
    unknown = [c for c in dict.fromkeys(raw) if c not in catalog]
    if unknown:
        raise _ProfileRefused('Unknown control: ' + ', '.join(c[:64] for c in unknown[:5]))
    picked = set(raw)
    controls = [c for c in catalog if c in picked]

    raw_params = data.get('params')
    if raw_params is None:
        raw_params = {}
    if not isinstance(raw_params, dict):
        raise _ProfileRefused('params is an object of control id to its values')
    from pegaprox.core.manager import hardening_param_value
    params = {}
    for cid, values in raw_params.items():
        if cid not in picked:
            raise _ProfileRefused(f'{cid[:64]} has values but is not a control of this profile')
        defaults = catalog[cid].get('defaults') or {}
        if not catalog[cid].get('apply_template') or not defaults:
            raise _ProfileRefused(f'{cid} takes no parameters')
        if not isinstance(values, dict):
            raise _ProfileRefused(f'The values of {cid} are an object of parameter to value')
        for key, value in values.items():
            if key not in defaults:
                raise _ProfileRefused(f'{cid} has no parameter {key[:64]}')
            if not isinstance(value, str) or len(value) > HP_VALUE_MAX:
                raise _ProfileRefused(f'{cid} {key}: a value is text of at most {HP_VALUE_MAX} characters')
            clean = hardening_param_value(key, value)
            if clean is None:
                takes = 'an IP address' if key in ('dns1', 'dns2') else 'user names separated by commas'
                raise _ProfileRefused(f'{cid} {key}: not a value this control takes - {takes}')
            if clean:
                params.setdefault(cid, {})[key] = clean
    return {'name': name, 'description': description, 'controls': controls, 'params': params}


def _hp_name_taken(rows, name, but=None):
    folded = name.casefold()
    return any(r['id'] != but and isinstance(r.get('name'), str) and r['name'].casefold() == folded
               for r in rows)


def backup_hardening_profiles():
    """The custom profiles for a config backup (api/settings.py): id, name, description,
    controls and params of each. Raises when the table cannot be read."""
    catalog = _hardening_catalog()
    out = []
    for row in _hp_rows():
        p = _hp_public(row, catalog)
        if p is not None and p['controls']:
            out.append({k: p[k] for k in ('id',) + _HP_FIELDS})
    return out


def restore_hardening_profiles(entries, username, dry_run=False):
    """Put the custom profiles of a config backup back (api/settings.py restore_config).

    Each is checked like a new one and keeps its id: it replaces the profile of that id, or
    joins the list while there is room. One whose name another profile has here is left
    out. All of them are checked before the first is written, and a write that fails takes
    the others back with it. Returns (restored, [why one was left out])."""
    if not isinstance(entries, list):
        return 0, ['Hardening profiles: not a list']
    from pegaprox.core.db import get_db
    catalog = _hardening_catalog()
    db = get_db()
    errors, todo = [], []
    with _hp_write_lock:
        rows = _hp_rows()
        for entry in entries:
            pid = entry.get('id') if isinstance(entry, dict) else None
            if not isinstance(pid, str) or not _HP_ID_RE.fullmatch(pid):
                errors.append('Hardening profile without a valid id left out')
                continue
            try:
                fields = _hp_validated({k: entry.get(k) for k in _HP_FIELDS}, catalog)
            except _ProfileRefused as e:
                errors.append(f'Hardening profile {pid}: {e}')
                continue
            if _hp_name_taken(rows, fields['name'], but=pid):
                errors.append(f"Hardening profile {pid}: another profile is named '{fields['name']}'")
                continue
            have = next((r for r in rows if r['id'] == pid), None)
            if have is None and len(rows) >= HP_MAX:
                errors.append(f'Hardening profile {pid}: there are already {HP_MAX} profiles')
                continue
            now = _hp_now()
            row = {'id': pid, 'name': fields['name'], 'description': fields['description'],
                   'controls': json.dumps(fields['controls']), 'params': json.dumps(fields['params']),
                   'created_by': (have or {}).get('created_by') or username,
                   'created_at': (have or {}).get('created_at') or now,
                   'updated_by': username, 'updated_at': now}
            rows = [r for r in rows if r['id'] != pid] + [row]
            todo.append(row)
        if todo and not dry_run:
            try:
                for row in todo:
                    db.conn.execute('INSERT OR REPLACE INTO hardening_profiles (id, name, description, '
                                    'controls, params, created_by, created_at, updated_by, updated_at) '
                                    'VALUES (:id, :name, :description, :controls, :params, '
                                    ':created_by, :created_at, :updated_by, :updated_at)', row)
                db.conn.commit()
            except Exception:
                # the INSERTs before the failed one would go out with the next commit on
                # this connection while the restore reports none
                db.conn.rollback()
                raise
    return len(todo), errors


def _hp_may_manage():
    """Whether the caller may write the custom profiles: node.maintenance, admin.settings
    and no tenant or cluster list limiting them. Fails closed."""
    try:
        from pegaprox.api.ha import _unconfined
        from pegaprox.utils.auth import build_authz_user
        from pegaprox.utils.rbac import has_permission
        session = getattr(request, 'session', None) or {}
        user = build_authz_user(session.get('user', ''), session)
        return (has_permission(user, 'node.maintenance') and has_permission(user, 'admin.settings')
                and _unconfined(user))
    except Exception as e:
        logging.warning(f"[hardening] could not resolve the caller's scope: {e}")
        return False


def _hp_refuse_confined():
    if _hp_may_manage():
        return None
    return jsonify({'error': 'Custom hardening profiles are managed by administrators who are '
                             'not limited to a tenant or to specific clusters'}), 403


def _hp_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _hp_unreadable(e):
    logging.warning(f"[hardening] could not read the custom profiles: {e}")
    return jsonify({'error': 'The custom hardening profiles cannot be read right now'}), 503


@bp.route('/api/hardening/profiles', methods=['GET'])
@require_auth(perms=['node.maintenance'])
def list_hardening_profiles():
    """The custom hardening profiles, the built-in ones and the controls both pick from.

    custom: id, name, description, controls, params ({control: {parameter: value}}),
    dropped_controls (stored ids this version has no control for), created_at, updated_at,
    and for those who may manage them created_by and updated_by. builtin: id and the
    controls it runs. catalog: per control whether it takes parameters (templated,
    param_keys, defaults) and whether it can be rolled back. can_manage: whether the
    caller may create, change and delete custom profiles."""
    catalog = _hardening_catalog()
    try:
        rows = _hp_rows()
    except Exception as e:
        return _hp_unreadable(e)
    can_manage = _hp_may_manage()
    custom = []
    for row in rows:
        p = _hp_public(row, catalog)
        if p is None:
            continue
        if not can_manage:
            p.pop('created_by')
            p.pop('updated_by')
        custom.append(p)

    from pegaprox.core.manager import PegaProxManager
    builtin = [{'id': pid, 'controls': list(PegaProxManager.CIS_CHECKS) if members is None
                else [c for c in catalog if c in members]}
               for pid, members in PegaProxManager._HARDENING_PROFILES.items()]
    entries = []
    for cid, ctrl in catalog.items():
        templated = bool(ctrl.get('apply_template'))
        defaults = dict(ctrl.get('defaults') or {}) if templated else {}
        entries.append({'id': cid, 'templated': templated, 'param_keys': list(defaults),
                        'defaults': defaults, 'rollback': bool(ctrl.get('backup_files'))})
    return jsonify({
        'custom': custom, 'builtin': builtin, 'catalog': entries, 'can_manage': can_manage,
        'format': HARDENING_PROFILE_FORMAT, 'format_version': HARDENING_PROFILE_VERSION,
        'limits': {'profiles': HP_MAX, 'name': HP_NAME_MAX, 'description': HP_DESCRIPTION_MAX,
                   'value': HP_VALUE_MAX},
    })


@bp.route('/api/hardening/profiles', methods=['POST'])
@require_auth(perms=['node.maintenance', 'admin.settings'])
def create_hardening_profile():
    """Save a custom hardening profile.

    Body: name (1-64 characters), description (up to 500, may hold line breaks), controls
    (ids from the catalog), params ({control: {parameter: value}}, only for templated
    controls of the profile). A file exported from PegaProx (format
    pegaprox-hardening-profile, version 1) is taken as it is. 201 with the profile; 400
    for a body that does not pass, 409 for a name in use (in any case) or a full list."""
    refusal = _hp_refuse_confined()
    if refusal:
        return refusal
    catalog = _hardening_catalog()
    try:
        fields = _hp_validated(_hp_body(), catalog)
    except _ProfileRefused as e:
        return jsonify({'error': str(e)}), e.status
    user, now = _hp_user(), _hp_now()
    with _hp_write_lock:
        try:
            rows = _hp_rows()
        except Exception as e:
            return _hp_unreadable(e)
        if len(rows) >= HP_MAX:
            return jsonify({'error': f'There are already {HP_MAX} custom profiles - delete one first'}), 409
        if _hp_name_taken(rows, fields['name']):
            return jsonify({'error': f"A profile named '{fields['name']}' exists already"}), 409
        row = {'id': secrets.token_hex(8), 'name': fields['name'], 'description': fields['description'],
               'controls': json.dumps(fields['controls']), 'params': json.dumps(fields['params']),
               'created_by': user, 'created_at': now, 'updated_by': user, 'updated_at': now}
        try:
            from pegaprox.core.db import get_db
            db = get_db()
            db.conn.execute('INSERT INTO hardening_profiles (id, name, description, controls, params, '
                            'created_by, created_at, updated_by, updated_at) '
                            'VALUES (:id, :name, :description, :controls, :params, '
                            ':created_by, :created_at, :updated_by, :updated_at)', row)
            db.conn.commit()
        except Exception as e:
            logging.error(f"[hardening] could not save a custom profile: {e}")
            return jsonify({'error': 'The profile could not be saved'}), 500
    from pegaprox.utils.audit import log_audit
    log_audit(user, 'hardening.profile_created',
              f"Hardening profile '{fields['name']}' ({row['id']}) created with "
              f"{len(fields['controls'])} controls")
    return jsonify({'success': True, 'profile': _hp_public(row, catalog)}), 201


@bp.route('/api/hardening/profiles/<profile_id>', methods=['PUT'])
@require_auth(perms=['node.maintenance', 'admin.settings'])
def update_hardening_profile(profile_id):
    """Change a custom hardening profile.

    The fields the body leaves out stay as they are; left out, params keeps the values of
    the controls that stay in the profile. Checked like a new one; 404 for an unknown id,
    409 for a name another profile has. changed names the fields that changed."""
    refusal = _hp_refuse_confined()
    if refusal:
        return refusal
    if not _HP_ID_RE.fullmatch(profile_id or ''):
        return jsonify({'error': 'Profile not found'}), 404
    catalog = _hardening_catalog()
    data = _hp_body()
    user = _hp_user()
    with _hp_write_lock:
        try:
            rows = _hp_rows()
        except Exception as e:
            return _hp_unreadable(e)
        row = next((r for r in rows if r['id'] == profile_id), None)
        if row is None:
            return jsonify({'error': 'Profile not found'}), 404
        # a row that does not read (synced from another version) can still be written over
        current = _hp_public(row, catalog) or {'name': row.get('name') or '', 'description': '',
                                                 'controls': [], 'params': {}}
        merged = {k: current[k] for k in _HP_FIELDS}
        merged.update({k: data[k] for k in _HP_FIELDS if k in data})
        if 'params' not in data and isinstance(merged['controls'], list):
            merged['params'] = {c: v for c, v in current['params'].items() if c in merged['controls']}
        for k in ('format', 'version'):
            if k in data:
                merged[k] = data[k]
        try:
            fields = _hp_validated(merged, catalog)
        except _ProfileRefused as e:
            return jsonify({'error': str(e)}), e.status
        if _hp_name_taken(rows, fields['name'], but=profile_id):
            return jsonify({'error': f"A profile named '{fields['name']}' exists already"}), 409
        changed = [k for k in _HP_FIELDS if fields[k] != current[k]]
        if not changed and not current.get('dropped_controls'):
            return jsonify({'success': True, 'profile': current, 'changed': []})
        row = dict(row, name=fields['name'], description=fields['description'],
                   controls=json.dumps(fields['controls']), params=json.dumps(fields['params']),
                   updated_by=user, updated_at=_hp_now())
        try:
            from pegaprox.core.db import get_db
            db = get_db()
            db.conn.execute('UPDATE hardening_profiles SET name = ?, description = ?, controls = ?, '
                            'params = ?, updated_by = ?, updated_at = ? WHERE id = ?',
                            (row['name'], row['description'], row['controls'], row['params'],
                             row['updated_by'], row['updated_at'], profile_id))
            db.conn.commit()
        except Exception as e:
            logging.error(f"[hardening] could not save custom profile {profile_id}: {e}")
            return jsonify({'error': 'The profile could not be saved'}), 500
    from pegaprox.utils.audit import log_audit
    log_audit(user, 'hardening.profile_updated',
              f"Hardening profile '{fields['name']}' ({profile_id}) changed: "
              + (', '.join(changed) or 'controls this version does not know dropped'))
    return jsonify({'success': True, 'profile': _hp_public(row, catalog), 'changed': changed})


@bp.route('/api/hardening/profiles/<profile_id>', methods=['DELETE'])
@require_auth(perms=['node.maintenance', 'admin.settings'])
def delete_hardening_profile(profile_id):
    """Delete a custom hardening profile. 404 for an unknown id."""
    refusal = _hp_refuse_confined()
    if refusal:
        return refusal
    if not _HP_ID_RE.fullmatch(profile_id or ''):
        return jsonify({'error': 'Profile not found'}), 404
    user = _hp_user()
    with _hp_write_lock:
        try:
            rows = _hp_rows(profile_id)
        except Exception as e:
            return _hp_unreadable(e)
        if not rows:
            return jsonify({'error': 'Profile not found'}), 404
        try:
            from pegaprox.core.db import get_db
            db = get_db()
            db.conn.execute('DELETE FROM hardening_profiles WHERE id = ?', (profile_id,))
            db.conn.commit()
        except Exception as e:
            logging.error(f"[hardening] could not delete custom profile {profile_id}: {e}")
            return jsonify({'error': 'The profile could not be deleted'}), 500
    from pegaprox.utils.audit import log_audit
    log_audit(user, 'hardening.profile_deleted',
              f"Hardening profile '{rows[0].get('name')}' ({profile_id}) deleted")
    return jsonify({'success': True, 'id': profile_id})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hardening', methods=['GET'])
@require_auth(perms=['node.maintenance'])
def check_hardening(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # NS Oct 2026 - runs root checks over SSH and reads back the node's own security
    # evidence, nothing a pool or VM grant reaches; same gate as the apply route below
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster offline'}), 503

    # NS Apr 2026 (#322): verbose mode — returns per-control evidence for audit reports
    verbose = str(request.args.get('verbose', '')).lower() in ('1', 'true', 'yes')
    # NS Apr 2026 — profile filter; Harden PVE Node UI + Compliance Dashboard share these.
    profile = (request.args.get('profile', '') or '').strip().lower() or None
    custom = None
    if profile and profile.startswith('custom:'):
        # MK Oct 2026 - a custom profile runs exactly its own controls
        try:
            custom = custom_hardening_profile(profile[len('custom:'):])
        except Exception as e:
            return _hp_unreadable(e)
        if custom is None:
            return jsonify({'error': f'unknown profile: {profile[:80]}'}), 400
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
            return jsonify({'error': 'Custom hardening profiles pick Proxmox VE controls, '
                                     'this cluster has its own'}), 400
        if not custom['controls']:
            return jsonify({'error': 'None of the controls of this profile exist in this version',
                            'dropped_controls': custom['dropped_controls']}), 400
        result = mgr.check_node_hardening(node, verbose=verbose, controls=custom['controls'])
    elif profile and profile not in {'cis-l1', 'cis-l2', 'vs-nfd', 'bsi', 'iso', 'nis2',
                                     'cmmc1', 'cmmc2', 'nist53', 'stig', 'dr', 'rgs'}:
        return jsonify({'error': f'unknown profile: {profile}'}), 400
    else:
        result = mgr.check_node_hardening(node, verbose=verbose, profile=profile)
    if result is None:
        return _ssh_unavailable(mgr, node)

    # Report the profile that actually ran, not the one that was asked for - cis-l2 has no
    # control set of its own and a PDF naming it would be claiming a level nobody checked.
    _eff = mgr._effective_profile(profile) if hasattr(mgr, '_effective_profile') else None
    _eff = _eff or (profile or 'cis-l1')   # always a string - consumers indexed on it before
    # MK Oct 2026 - a control whose output could not be read is null (verbose: status
    # null), not a failure; the counts keep it apart so no score divides by it
    _st = [(v.get('status') if isinstance(v, dict) else v)
           for v in (result.values() if isinstance(result, dict) else [])]
    summary = {'total': len(_st), 'passed': sum(1 for s in _st if s is True),
               'failed': sum(1 for s in _st if s is False),
               'not_checked': sum(1 for s in _st if s is None)}
    summary['checked'] = summary['passed'] + summary['failed']
    out = {'node': node, 'controls': result, 'verbose': verbose,
           'profile': _eff, 'requested_profile': profile or 'cis-l1',
           'summary': summary}
    if custom is not None:
        out.update(profile=f"custom:{custom['id']}", requested_profile=f"custom:{custom['id']}",
                   profile_name=custom['name'], dropped_controls=custom['dropped_controls'])
    return jsonify(out)


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hardening', methods=['POST'])
@require_auth(perms=['node.maintenance'])
def apply_hardening(cluster_id, node):
    """Apply selected CIS controls"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster offline'}), 503

    data = request.get_json() or {}
    controls = data.get('controls', [])
    if not controls:
        return jsonify({'error': 'No controls specified'}), 400
    force = bool(data.get('force', False))
    requested_count = len(controls)

    # #16745 — self-lockout guard (belt-and-suspenders behind the UI ack). sshd_hardening sets
    # PermitRootLogin=prohibit-password; on a cluster we reach as root by password with no SSH
    # key, that severs PegaProx's own access to the node — and rollback needs SSH too. Refuse it
    # unless the caller explicitly forces (the UI does, after a checked acknowledgement).
    mgr_has_key = bool(getattr(mgr.config, 'ssh_key', ''))
    blocked = {}
    if 'sshd_hardening' in controls and not mgr_has_key and not force:
        controls = [c for c in controls if c != 'sshd_hardening']
        blocked['sshd_hardening'] = {
            'success': False, 'blocked': True,
            'error': 'Blocked: SSH Access Hardening disables root password login and would cut off '
                     'PegaProx access to this cluster (no SSH key is configured). Add an SSH key to '
                     'the cluster first, or re-apply with force to override.'
        }

    ctrl_params = data.get('params', {})
    results = mgr.apply_node_hardening(node, controls, params=ctrl_params) if controls else {}
    results.update(blocked)
    ok_count = sum(1 for v in results.values() if v.get('success'))

    from pegaprox.utils.audit import log_audit
    log_audit('node.hardening_applied', {
        'node': node, 'controls': list(results.keys()), 'forced': force,
        'success': ok_count, 'total': requested_count
    })

    return jsonify({
        'node': node, 'results': results,
        'applied': ok_count, 'total': requested_count
    })


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/hardening/rollback', methods=['POST'])
@require_auth(perms=['node.maintenance'])
def rollback_hardening(cluster_id, node):
    """Restore selected CIS controls to their pre-apply state (#386)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster offline'}), 503

    data = request.get_json() or {}
    controls = data.get('controls', [])
    if not controls:
        return jsonify({'error': 'No controls specified'}), 400

    results = mgr.rollback_node_hardening(node, controls)
    ok_count = sum(1 for v in results.values() if v.get('success'))

    from pegaprox.utils.audit import log_audit
    log_audit('node.hardening_rolled_back', {
        'node': node, 'controls': controls,
        'restored': ok_count, 'total': len(controls)
    })

    return jsonify({
        'node': node, 'results': results,
        'restored': ok_count, 'total': len(controls)
    })


# ============================================
# Compliance framework mapping  -  MK Apr 2026
# Frontend pulls these to render the compliance PDFs with real
# CMMC / NIST / STIG / ISO / BSI control IDs instead of our internal
# names like "pam_faillock". See pegaprox/core/compliance_mapping.py
# ============================================

@bp.route('/api/compliance/mapping', methods=['GET'])
@require_auth()
def compliance_mapping_api():
    framework = (request.args.get('framework', '') or '').strip().lower()
    from pegaprox.core import compliance_mapping as cm
    payload_full = {
        'family_labels':       cm.FAMILY_LABELS,
        'mappings':            cm.FRAMEWORK_MAPPING,
        'remediation':         cm.REMEDIATION,
        'severity':            cm.SEVERITY,
        'recommended_timeline': cm.RECOMMENDED_TIMELINE,
        'priority_level':      cm.PRIORITY_LEVEL,
        'framework_meta':      cm.FRAMEWORK_META,
        'posture_levels':      cm.POSTURE_LEVELS,
        'glossary':            cm.GLOSSARY,
        'methodology':         cm.METHODOLOGY,
    }
    if not framework:
        return jsonify(payload_full)
    if framework not in cm.FRAMEWORK_MAPPING:
        return jsonify({'error': f'unknown framework: {framework}'}), 400
    return jsonify({
        'framework':    framework,
        'family_labels': cm.FAMILY_LABELS,
        'mapping':      cm.FRAMEWORK_MAPPING[framework],
        'remediation':  cm.REMEDIATION,
        'severity':     cm.SEVERITY,
        'recommended_timeline': cm.RECOMMENDED_TIMELINE,
        'priority_level': cm.PRIORITY_LEVEL,
        'framework_meta': cm.FRAMEWORK_META.get(framework, {}),
        'posture_levels': cm.POSTURE_LEVELS,
        'glossary':     cm.GLOSSARY,
        'methodology':  cm.METHODOLOGY,
    })


# ============================================
# Legacy Fallback Endpoints
# old tags endpoints, kept for compat, these prevent 404s
# ============================================

@bp.route('/api/tags', methods=['GET'])
@require_auth()
def get_tags_legacy():
    """Legacy: Returns empty for old Settings UI"""
    return jsonify({'tags': {}, 'available_tags': []})

@bp.route('/api/tags/available', methods=['GET'])
@require_auth()
def get_available_tags_legacy():
    """Legacy: Returns empty list"""
    return jsonify([])

@bp.route('/api/tags/available', methods=['POST'])
@require_auth()
def create_tag_legacy():
    """Legacy: Redirect to cluster-based tags"""
    return jsonify({'error': 'Please use VM-based tags (click tag icon on VMs)'}), 400

@bp.route('/api/tags/available/<tag_name>', methods=['DELETE'])
@require_auth()
def delete_tag_legacy(tag_name):
    """Legacy: No-op"""
    return jsonify({'success': True})


# ============================================
# Cluster-Based Reports Endpoint
# reports are now per-cluster, not global
# ============================================

@bp.route('/api/clusters/<cluster_id>/reports/summary', methods=['GET'])
@require_auth()
def get_cluster_report_summary(cluster_id):
    """Get report summary for a specific cluster

    Returns both historical data (if available) and current live data

    Query params:
    - period: 'hour', 'day', 'week' (default: day)
    - from, to: unix seconds, instead of period: a range picked on the charts, at full
      resolution as far as the stored history reaches (a year apart at most)
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # MK Oct 2026 - a caller confined to some guests counts the running ones it may see,
    # as power and costs give it its own share. The history keeps the cluster's totals
    # only, so it gets no samples of those. CPU and memory stay, /metrics has them too.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.api.helpers import caller_is_scoped
    scoped = caller_is_scoped(build_authz_user(request.session.get('user', ''), request.session), cluster_id)

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    period = request.args.get('period', 'day')
    picked = None
    if 'from' in request.args or 'to' in request.args:
        start, end, why = history_range(request.args)
        if why:
            return jsonify({'error': why}), 400
        picked, period = (start, end), 'range'

    # Get LIVE current data from cluster using get_node_status()
    live_cpu = 0
    live_vms = 0
    live_cts = 0
    cpu_total = 0
    mem_total = 0
    mem_used = 0
    nodes_online = 0

    if mgr.is_connected:
        try:
            # Use get_node_status which actually fetches live data from Proxmox
            node_status = mgr.get_node_status()

            for node_name, node_data in node_status.items():
                if not node_data:
                    continue
                # Check status
                status = node_data.get('status', '')
                if status in ['online', 'running']:
                    nodes_online += 1
                    # CPU and memory from get_node_status are already percentages
                    cpu_pct = node_data.get('cpu_percent', 0) or 0
                    mem_pct = node_data.get('mem_percent', 0) or 0
                    mem_t = node_data.get('mem_total', 0) or 0
                    mem_u = node_data.get('mem_used', 0) or 0

                    # Accumulate (we'll average later)
                    live_cpu += cpu_pct
                    mem_total += mem_t
                    mem_used += mem_u

            # Average CPU across nodes
            if nodes_online > 0:
                live_cpu = live_cpu / nodes_online
        except Exception as e:
            logging.error(f"Error getting node status for reports: {e}")

        # Count running VMs
        try:
            resources = mgr.get_vm_resources() or []
            if scoped:
                resources = scope_vm_rows(cluster_id, resources)
            for r in resources:
                if r and r.get('status') == 'running':
                    if r.get('type') == 'qemu':
                        live_vms += 1
                    else:
                        live_cts += 1
        except Exception as e:
            logging.error(f"Error getting VM resources: {e}")

    # Calculate live percentages
    live_cpu_pct = round(live_cpu, 1)
    live_mem_pct = round(mem_used / max(mem_total, 1) * 100, 1) if mem_total > 0 else 0

    # Load historical metrics for the requested window (oldest first, so the
    # chart below runs left-to-right and 'current' really is the newest sample)
    if picked:
        # MK Oct 2026 - only this cluster's totals are kept of each snapshot
        def _totals(clusters):
            c = clusters.get(cluster_id)
            return {cluster_id: {'totals': c.get('totals') or {}}} if isinstance(c, dict) else {}
        filtered = [{'timestamp': ts, 'clusters': kept}
                    for ts, kept in load_metrics_range(picked[0], picked[1], _totals,
                                                       cluster_id=cluster_id, parts=('head',))]
    else:
        window_days, cutoff = _period_cutoff(period)
        history = load_metrics_history(days=window_days, totals_only=True)
        snapshots = history.get('snapshots', [])

        cutoff_str = cutoff.isoformat()
        filtered = [s for s in snapshots if s.get('timestamp', '') >= cutoff_str]

    # Extract data for this cluster only
    report = {
        'period': period,
        'cluster_id': cluster_id,
        'cluster_name': getattr(mgr.config, 'name', None) or cluster_id,
        'data_points': 0,
        'cpu': {'avg': live_cpu_pct, 'min': live_cpu_pct, 'max': live_cpu_pct, 'current': live_cpu_pct, 'samples': []},
        'memory': {'avg': live_mem_pct, 'min': live_mem_pct, 'max': live_mem_pct, 'current': live_mem_pct, 'samples': []},
        'vms_running': {'avg': live_vms + live_cts, 'min': live_vms + live_cts, 'max': live_vms + live_cts, 'current': live_vms + live_cts, 'samples': []},
        'timestamps': [],
        # Add live data section
        'live': {
            'cpu_percent': live_cpu_pct,
            'mem_percent': live_mem_pct,
            'vms_running': live_vms,
            'cts_running': live_cts,
            'cpu_total': cpu_total,
            'mem_total': mem_total,
            'mem_used': mem_used
        }
    }
    if picked:
        report['from'], report['to'] = int(picked[0]), int(picked[1])

    for snapshot in filtered:
        cluster_data = snapshot.get('clusters', {}).get(cluster_id)
        if not cluster_data:
            continue

        report['timestamps'].append(_with_offset(snapshot.get('timestamp', '')))
        report['data_points'] += 1

        totals = cluster_data.get('totals', {})

        # CPU
        if totals.get('cpu_total', 0) > 0:
            cpu = round(totals['cpu_used'] / totals['cpu_total'] * 100, 1)
            report['cpu']['samples'].append(cpu)

        # Memory
        if totals.get('mem_total', 0) > 0:
            mem = round(totals['mem_used'] / totals['mem_total'] * 100, 1)
            report['memory']['samples'].append(mem)

        # VMs
        if not scoped:
            vms = totals.get('vms_running', 0) + totals.get('cts_running', 0)
            report['vms_running']['samples'].append(vms)

    if scoped:
        report['scoped'] = True

    # Calculate stats from historical data (keep samples for charts)
    for metric in ['cpu', 'memory', 'vms_running']:
        samples = report[metric].get('samples', [])
        if samples:
            report[metric]['avg'] = round(sum(samples) / len(samples), 1)
            report[metric]['min'] = round(min(samples), 1)
            report[metric]['max'] = round(max(samples), 1)
            report[metric]['current'] = round(samples[-1], 1) if samples else report[metric]['current']

    return jsonify(report)


# predictive-analysis endpoint moved to api/clusters.py (was duplicate registration —
# clusters_bp wins URL match anyway). LW May 2026.
