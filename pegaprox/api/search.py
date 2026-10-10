# -*- coding: utf-8 -*-
"""search, favorites & tags routes - split from monolith dec 2025, NS/LW"""

import os
import re
import json
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users, build_authz_user
from pegaprox.utils.audit import log_audit

from pegaprox.utils.rbac import (
    has_permission, filter_clusters_for_user, user_can_access_vm,
    get_user_clusters,
)
from pegaprox.api.helpers import get_connected_manager, safe_error, check_cluster_access, scope_vm_rows
from pegaprox.background import guest_index
from pegaprox.utils import search_query

bp = Blueprint('search', __name__)

# ============================================
# User favorites: the star next to a global search result.
#
# MK Oct 2026 - this never stored anything. The loader handed back a flat list of VM
# rows per user, the route worked on three lists (vms/nodes/clusters), and the saver
# walked that dict's keys as if they were rows: AttributeError, logged, nothing
# written - after a DELETE of every user's rows that the next commit on the
# connection made stick. Now one row per favorite in user_favorites with its kind
# (db.py), written and read per user, and the three lists the dashboard reads.

FAVORITE_BUCKETS = {'vm': 'vms', 'node': 'nodes', 'cluster': 'clusters'}
# Per user and kind. The star shows in the global search dropdown only: 20 rows of
# the at most 100 results one search returns. 500 VMs are five such answers, 200
# nodes twice the 100 a large installation runs, 100 clusters more than anyone
# runs from one instance. A script stops there, the table stays small, and it goes
# to every member of an instance group with each sync.
FAVORITES_MAX = {'vm': 500, 'node': 200, 'cluster': 100}
# ids as the rest of the API hands them out: cluster ids are uuid4()[:8] (an ESXi
# host's too), node names are host names, vmids are PVE's range (XCP-ng counts from 100)
_FAV_CLUSTER_RE = re.compile(r'[A-Za-z0-9_.\-]{1,64}')
_FAV_NODE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._\-]{0,62}')
_FAV_VMID_RE = re.compile(r'[0-9]{1,9}')
_FAV_NAME_MAX = 128
# the key the unique index idx_favorites_unique holds. IFNULL: on a member that got the
# two columns from a sync (ha._add_column) they carry their default but no NOT NULL
_FAV_KEY =("username = ? AND IFNULL(kind, 'vm') = ? AND cluster_id = ? "
            "AND IFNULL(vmid, -1) = ? AND IFNULL(node, '') = ?")


def load_favorites(username):
    """One user's favorites, oldest first: {'vms': [{cluster_id, vmid, type, name}],
    'nodes': [{cluster_id, node}], 'clusters': [cluster_id, ...]}. Unfiltered; the
    routes hand out only what the caller may see (_favorite_filter)."""
    out = {bucket: [] for bucket in FAVORITE_BUCKETS.values()}
    rows = get_db().conn.execute(
        'SELECT kind, cluster_id, vmid, vm_type, vm_name, node FROM user_favorites '
        'WHERE username = ? ORDER BY id', (username,)).fetchall()
    for r in rows:
        kind = r['kind'] or 'vm'
        if kind == 'vm' and r['vmid'] is not None:
            out['vms'].append({'cluster_id': r['cluster_id'], 'vmid': r['vmid'],
                               'type': r['vm_type'] or 'qemu', 'name': r['vm_name'] or ''})
        elif kind == 'node' and r['node']:
            out['nodes'].append({'cluster_id': r['cluster_id'], 'node': r['node']})
        elif kind == 'cluster':
            out['clusters'].append(r['cluster_id'])
    return out


def _favorite_filter():
    """Whether the caller may see a favorite: what global_search checks on its results,
    with the same token-scoped identity. The cluster by tenant, group and pool grant,
    a VM by its own grant as well. A favorite outside of that is neither listed nor
    taken; the row stays, and shows again when the access comes back."""
    user_data = build_authz_user(request.session.get('user', ''), request.session)
    accessible = get_user_clusters(user_data)  # None = all

    def visible(kind, cluster_id, vmid=None):
        if accessible is not None and cluster_id not in accessible:
            return False
        if kind == 'vm':
            # no type: PVE numbers guests per cluster, and a stored type could be stale
            return user_can_access_vm(user_data, cluster_id, vmid, 'vm.view')
        return True
    return visible


def _visible_favorites(username, visible):
    favs = load_favorites(username)
    return {
        'vms': [f for f in favs['vms'] if visible('vm', f['cluster_id'], f['vmid'])],
        'nodes': [f for f in favs['nodes'] if visible('node', f['cluster_id'])],
        'clusters': [c for c in favs['clusters'] if visible('cluster', c)],
    }


def _favorite_from_body(data):
    """(kind, cluster_id, vmid, node, vm_type) from a POST body, or an error text."""
    fav_type = data.get('type')
    cluster_id = data.get('cluster_id')
    if not fav_type or not cluster_id:
        return 'type and cluster_id required'
    if not isinstance(cluster_id, str) or not _FAV_CLUSTER_RE.fullmatch(cluster_id):
        return 'Invalid cluster_id'
    if fav_type in ('vm', 'ct'):
        vmid = data.get('vmid')
        if not vmid:
            return 'vmid required for vm favorites'
        if isinstance(vmid, bool) or not isinstance(vmid, (int, str)) or not _FAV_VMID_RE.fullmatch(str(vmid)):
            return 'Invalid vmid'
        vmid = int(vmid)
        # a standalone ESXi host lists its VMs by their small moId numbers, PVE from 100
        if vmid < 1:
            return 'Invalid vmid'
        # a container row of the search sends 'ct'
        vm_type = data.get('vm_type') or ('lxc' if fav_type == 'ct' else 'qemu')
        if vm_type not in ('qemu', 'lxc'):
            return 'vm_type is qemu or lxc'
        return 'vm', cluster_id, vmid, '', vm_type
    if fav_type == 'node':
        node = data.get('node')
        if not node:
            return 'node required for node favorites'
        if not isinstance(node, str) or not _FAV_NODE_RE.fullmatch(node):
            return 'Invalid node name'
        return 'node', cluster_id, None, node, None
    if fav_type == 'cluster':
        return 'cluster', cluster_id, None, '', None
    return 'Invalid type. Use vm, node, or cluster'


def _live_vm(cluster_id, vmid):
    """(name, type) of a VM as its cluster lists it now, (None, None) when it does not."""
    mgr = cluster_managers.get(cluster_id)
    try:
        if mgr is not None and mgr.is_connected:
            for r in mgr.get_vm_resources() or []:
                if str(r.get('vmid')) == str(vmid):
                    name, vtype = r.get('name'), r.get('type')
                    return (name[:_FAV_NAME_MAX] if isinstance(name, str) else None,
                            vtype if vtype in ('qemu', 'lxc') else None)
    except Exception as e:
        logging.debug(f"[favorites] no live name for {cluster_id}/{vmid}: {e}")
    return None, None


@bp.route('/api/global/search', methods=['GET'])
@require_auth()
def global_search():
    """Search across all clusters for VMs, containers, and nodes
    
    Query params:
    - q: search query (name, vmid, ip, node name, tags, MAC address, notes), at most 256 characters
    - type: filter by type (vm, ct, node, all) - default: all
    
    Also supports prefix filters like tag:web, node:pve1, ip:192.168, status:running,
    mac:bc:24:11, notes:backup, name:web, id:100 or id:100-199, type:vm|ct|node,
    cluster:lab, pool:dev
    You can combine tags with comma: tag:web,production (AND logic)

    Terms combine with AND, OR and NOT (or a '-' in front), terms side by side are ANDed,
    parentheses group and quotes keep a value with spaces together:
    (tag:db OR tag:cache) -node:pve3 name:"web 01". A query without operators, parentheses
    or quotes is first read as before: one prefix at the start and the rest its value; its
    words count as terms of their own only when that finds nothing. At most 20 terms and 8
    levels of nesting. A query that cannot be read answers 400 with code SEARCH_SYNTAX, a
    reason and the position (from 0) where reading stopped.

    The answer says how the query was read (syntax: plain or expression), which values
    the tags of a hit are marked for (highlight), and with tag_suggestions where a picked
    tag goes (tag_complete: start, end and the prefix to put in front).
    
    A MAC address matches without regard to separators and case (bc2411aabbcc finds
    BC:24:11:AA:BB:CC). ip: looks at every address the guest agent reports and the static
    ones in the guest config. MAC addresses, notes and configured IPs come from the guest
    search index, which reads guest configs in the background: a new guest is found by
    them once its config was read. A hit on one of these carries match_value (the
    address, or the part of the notes around the hit) and match_net (the NIC) where known.
    
    LW: This is one of the most used features - people love being able
    to find a VM without knowing which cluster its on.
    NS: added tag search in Feb 2026, users kept asking for it
    MK: Claude + ChatGPT helped optimize the search logic and prefix filters
    """
    raw_query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all').lower()
    
    if not raw_query or len(raw_query) < 2:
        return jsonify({'error': 'Search query must be at least 2 characters'}), 400
    
    # MK Oct 2026 - the query language lives in utils/search_query. A query without
    # operators, parentheses or quotes is read the old way first (one prefix, the rest
    # its value, tag:web,production ANDed); its words are terms of their own only when
    # that finds nothing, so whatever found something before finds the same
    try:
        if search_query.explicit(raw_query):
            reading, plain = search_query.parse(raw_query), False
        else:
            reading, plain = search_query.read_plain(raw_query), True
    except search_query.SearchSyntaxError as e:
        return jsonify(e.to_json()), 400
    
    user = request.session.get('user', '')
    # #491 — token-scoped identity so an admin-owned viewer/user token doesn't get all-cluster search results
    user_data = build_authz_user(user, request.session)
    # #285: cluster access is tenant/group-based — resolve via the RBAC helper,
    # not a non-existent user['clusters'] field. The old read was always [] so
    # the filter below never fired and non-admins saw every cluster. MK
    accessible_clusters = get_user_clusters(user_data)  # None = admin / all

    # MK: collect tags for the autocomplete dropdown in the frontend
    all_tags = set()
    # what each cluster has to search, read once for both readings of a query
    guests, nodes = [], []
    
    for cluster_id, mgr in list(cluster_managers.items()):
        # Check cluster access - NS: important for multi-tenant setups
        if accessible_clusters is not None and cluster_id not in accessible_clusters:
            continue
        
        if not mgr.is_connected:
            continue
        
        cluster_name = mgr.config.name or cluster_id
        
        # Search VMs and Containers
        if search_type in ['all', 'vm', 'ct']:
            try:
                # sec (private disclosure Sep 2026) — the #285 filter above only gates cluster
                # REACHABILITY; check_cluster_access' #555 pool fallback admits a pool-scoped user to
                # the whole cluster, so global search enumerated every VM (name/vmid/node/ip/tags) and
                # every tag for autocomplete regardless of grant. Confine to the caller's VMs, same
                # per-VM check as get_cluster_tags / scope_vm_rows. Admins/plain operators keep all.
                # MK Oct 2026 - max_age: the command palette asks while the user types, a
                # few seconds old is plenty for a search and spares PVE the walk per keystroke
                resources = scope_vm_rows(cluster_id, mgr.get_vm_resources(max_age=6))
                indexed = guest_index.snapshot(cluster_id)
                found = [_search_facts(r, cluster_id, cluster_name, indexed) for r in resources]
                # collect tags for autocomplete
                for g in found:
                    all_tags.update(g['tags'])
                guests.extend(found)
            except Exception as e:
                logging.debug(f"Error searching cluster {cluster_id}: {e}")
        
        # Search Nodes
        if search_type in ['all', 'node']:
            try:
                for node_name, node_data in (mgr.nodes or {}).items():
                    node_data = node_data or {}
                    nodes.append({'node_name': node_name, 'data': node_data, 'cluster_id': cluster_id,
                                  'cluster_name': cluster_name, 'name': node_name.lower(),
                                  'status': str(node_data.get('status') or '').lower(),
                                  'cluster': str(cluster_name).lower()})
            except Exception as e:
                logging.debug(f"Error searching nodes in {cluster_id}: {e}")
    
    results = _search_results(reading, guests, nodes, search_type)
    if plain and not results:
        # nothing the old way: the words as terms of their own
        try:
            expression = search_query.parse(raw_query)
        except search_query.SearchSyntaxError as e:
            return jsonify(e.to_json()), 400
        if not expression.same_as(reading):
            reading = expression
            results = _search_results(reading, guests, nodes, search_type)

    # Sort by relevance (exact matches first, then partial)
    rank = reading.rank_text()
    def sort_key(r):
        name = (r.get('name') or str(r.get('vmid', ''))).lower()
        mf = r.get('match_field', '')
        # Exact name matches first, then name prefix, then tag matches, then rest
        if rank is not None and name == rank:
            return (0, name)
        elif rank is not None and name.startswith(rank):
            return (1, name)
        elif mf == 'tag':
            return (2, name)
        elif mf == 'vmid':
            return (3, name)
        else:
            return (4, name)
    
    results.sort(key=sort_key)
    
    # NS: show matching tags as clickable suggestions in the UI
    # for the term at the end of the query, so they go on after AND/OR too
    complete = reading.tag_completion()
    tag_suggestions = sorted([t for t in all_tags if complete[0] in t])[:10] if complete else []
    
    out = {
        'query': raw_query,
        'count': len(results),
        'results': results[:100],  # Limit to 100 results
        'tag_suggestions': tag_suggestions,
        'syntax': 'plain' if reading.plain else 'expression',
        'highlight': reading.highlight(),
    }
    if complete:
        out['tag_complete'] = {'start': complete[1], 'end': complete[2], 'prefix': complete[3]}
    return jsonify(out)


def _search_facts(r, cluster_id, cluster_name, indexed):
    """What the search compares of one guest row (search_query.guest_hit)."""
    vmid = str(r.get('vmid', ''))
    tags = r.get('tags') or ''
    if isinstance(tags, (list, tuple)):
        tags = ';'.join(str(t) for t in tags)
    tags_str = str(tags).lower()
    return {
        'row': r,
        'name': (r.get('name') or '').lower(),
        'vmid': vmid,
        'node': (r.get('node') or '').lower(),
        'ip': (r.get('ip') or '').lower(),
        'ip_raw': r.get('ip'),
        'tags': [t.strip() for t in tags_str.split(';') if t.strip()] if tags_str else [],
        'status': (r.get('status') or '').lower(),
        'type': r.get('type', 'qemu'),
        'cluster_id': cluster_id,
        'cluster_name': cluster_name,
        'cluster': str(cluster_name).lower(),
        'pool': str(r.get('pool') or '').lower(),
        # what the guest search index knows of this guest: MACs, notes, the
        # static IPs of its config. A hit there says which value it was
        'entry': indexed.get((r.get('type'), int(vmid))) if vmid.isdigit() else None,
        'live_ips': r.get('ip_addresses') or ([r['ip']] if r.get('ip') else []),
    }


def _search_results(reading, guests, nodes, search_type):
    """The rows global_search answers with for one reading of the query."""
    results = []
    for g in guests:
        hits = reading.match(search_query.guest_hit, g)
        if hits is None:
            continue
        # Type filter
        vm_type = g['type']
        if search_type == 'vm' and vm_type != 'qemu':
            continue
        if search_type == 'ct' and vm_type != 'lxc':
            continue
        hit = search_query.best_hit(hits)
        r = g['row']
        row = {
            'type': 'vm' if vm_type == 'qemu' else 'ct',
            'cluster_id': g['cluster_id'],
            'cluster_name': g['cluster_name'],
            'vmid': r.get('vmid'),
            'name': r.get('name'),
            'node': r.get('node'),
            'status': r.get('status'),
            'ip': r.get('ip'),
            'tags': r.get('tags', ''),
            'cpu': r.get('cpu'),
            'mem': r.get('mem'),
            'maxmem': r.get('maxmem'),
            'match_field': hit[0] if hit else None,
        }
        if hit and hit[1] is not None:
            row['match_value'] = hit[1]
            if hit[2]:
                row['match_net'] = hit[2]
        results.append(row)
    # nodes only for a query that can be about one (free text, node:, name:, type:,
    # cluster:); tag:, ip:, status:, mac: and notes: never listed any
    if reading.about_nodes():
        for n in nodes:
            hits = reading.match(search_query.node_hit, n)
            if hits is None:
                continue
            hit = search_query.best_hit(hits)
            node_data = n['data']
            results.append({
                'type': 'node',
                'cluster_id': n['cluster_id'],
                'cluster_name': n['cluster_name'],
                'name': n['node_name'],
                'status': node_data.get('status', 'unknown'),
                'cpu': node_data.get('cpu'),
                'mem': node_data.get('mem'),
                'maxmem': node_data.get('maxmem'),
                'match_field': hit[0] if hit else 'name',
            })
    return results


@bp.route('/api/global/summary', methods=['GET'])
@require_auth()
def global_summary():
    """Get summary statistics across all accessible clusters
    
    Returns aggregate stats for a datacenter-level overview
    """
    try:
        user = request.session.get('user', '')
        # #491 — token-scoped identity (build_authz_user applies the token's effective_role)
        user_data = build_authz_user(user, request.session)
        # #285: tenant/group-based access via the RBAC helper (was reading a
        # missing user['clusters'] → empty → no filtering). MK
        accessible_clusters = get_user_clusters(user_data)  # None = admin / all

        summary = {
            'clusters': {
                'total': 0,
                'online': 0,
                'offline': 0
            },
            'nodes': {
                'total': 0,
                'online': 0,
                'offline': 0
            },
            'vms': {
                'total': 0,
                'running': 0,
                'stopped': 0,
                'paused': 0
            },
            'containers': {
                'total': 0,
                'running': 0,
                'stopped': 0
            },
            'resources': {
                'cpu_total': 0,
                'cpu_used': 0,
                'mem_total': 0,
                'mem_used': 0,
                'storage_total': 0,
                'storage_used': 0
            },
            'by_cluster': []
        }
        
        for cluster_id, mgr in list(cluster_managers.items()):
            # Check cluster access
            if accessible_clusters is not None and cluster_id not in accessible_clusters:
                continue
            
            summary['clusters']['total'] += 1
            
            cluster_stats = {
                'id': cluster_id,
                'name': getattr(mgr.config, 'name', None) or cluster_id,
                'online': mgr.is_connected if mgr else False,
                'nodes': 0,
                'vms': 0,
                'containers': 0
            }
            
            if mgr and mgr.is_connected:
                summary['clusters']['online'] += 1
                
                # Count nodes - safely handle None
                nodes = getattr(mgr, 'nodes', None) or {}
                for node_name, node_data in nodes.items():
                    if not node_data:
                        continue
                    summary['nodes']['total'] += 1
                    cluster_stats['nodes'] += 1
                    
                    if node_data.get('status') == 'online':
                        summary['nodes']['online'] += 1
                        # Aggregate resources from online nodes
                        summary['resources']['cpu_total'] += node_data.get('maxcpu', 0) or 0
                        cpu_val = node_data.get('cpu', 0) or 0
                        maxcpu_val = node_data.get('maxcpu', 0) or 0
                        summary['resources']['cpu_used'] += cpu_val * maxcpu_val
                        summary['resources']['mem_total'] += node_data.get('maxmem', 0) or 0
                        summary['resources']['mem_used'] += node_data.get('mem', 0) or 0
                    else:
                        summary['nodes']['offline'] += 1
                
                # Count VMs
                try:
                    # sec (private disclosure Sep 2026) — scope the per-VM enumeration so a
                    # pool-/ACL-scoped caller's VM/CT totals reflect only their grant, not the whole
                    # cluster (node + resource aggregates below stay cluster-level infra, as elsewhere).
                    resources = scope_vm_rows(cluster_id, mgr.get_vm_resources() or [])
                    for r in resources:
                        if not r:
                            continue
                        if r.get('type') == 'qemu':
                            summary['vms']['total'] += 1
                            cluster_stats['vms'] += 1
                            status = (r.get('status') or '').lower()
                            if status == 'running':
                                summary['vms']['running'] += 1
                            elif status == 'paused':
                                summary['vms']['paused'] += 1
                            else:
                                summary['vms']['stopped'] += 1
                        else:
                            summary['containers']['total'] += 1
                            cluster_stats['containers'] += 1
                            status = (r.get('status') or '').lower()
                            if status == 'running':
                                summary['containers']['running'] += 1
                            else:
                                summary['containers']['stopped'] += 1
                except Exception as e:
                    logging.warning(f"Error getting VM resources for {cluster_id}: {e}")
            else:
                summary['clusters']['offline'] += 1
            
            summary['by_cluster'].append(cluster_stats)
        
        return jsonify(summary)
    except Exception as e:
        logging.error(f"global_summary error: {e}")
        return jsonify({'error': safe_error(e, 'Search failed')}), 500


@bp.route('/api/user/favorites', methods=['GET'])
@require_auth()
def get_favorites():
    """The caller's favorites

    vms [{cluster_id, vmid, type, name}], nodes [{cluster_id, node}], clusters
    [cluster_id], each only while the caller may still see it.
    """
    user = request.session.get('user', '')
    try:
        return jsonify(_visible_favorites(user, _favorite_filter()))
    except Exception as e:
        logging.error(f"Error loading favorites: {e}")
        return jsonify({'error': safe_error(e, 'Could not load favorites')}), 500


@bp.route('/api/user/favorites', methods=['POST'])
@require_auth()
def update_favorites():
    """Add or remove a favorite of the caller

    Body:
    - action: 'add' (default) or 'remove'
    - type: 'vm' ('ct' for a container), 'node', or 'cluster'
    - cluster_id: Cluster ID
    - vmid: (for vm) VM ID
    - vm_type: (for vm) 'qemu' or 'lxc'
    - node: (for node) Node name

    Answers with the favorites as GET does. Only what the caller may see is taken,
    and at most 500 VMs, 200 nodes and 100 clusters (409 FAVORITES_LIMIT beyond).
    """
    user = request.session.get('user', '')
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'JSON object required'}), 400
    action = data.get('action', 'add')
    if action not in ('add', 'remove'):
        return jsonify({'error': "action is 'add' or 'remove'"}), 400
    parsed = _favorite_from_body(data)
    if isinstance(parsed, str):
        return jsonify({'error': parsed}), 400
    kind, cluster_id, vmid, node, vm_type = parsed
    visible = _favorite_filter()
    key = (user, kind, cluster_id, -1 if vmid is None else vmid, node)

    # the same answer for a cluster that is not there as for one out of reach
    if action == 'add' and (cluster_id not in cluster_managers or not visible(kind, cluster_id, vmid)):
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db().conn
    full = False
    try:
        if action == 'add':
            if not conn.execute(f'SELECT 1 FROM user_favorites WHERE {_FAV_KEY}', key).fetchone():
                name = None
                if kind == 'vm':
                    name, live_type = _live_vm(cluster_id, vmid)
                    vm_type = live_type or vm_type
                # count and insert in one statement: two adds at once cannot pass the cap together
                cur = conn.execute(
                    'INSERT OR IGNORE INTO user_favorites (username, kind, cluster_id, vmid, vm_type, '
                    'vm_name, node, added_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) '
                    'FROM user_favorites WHERE username = ? AND kind = ?) < ?',
                    (user, kind, cluster_id, vmid, vm_type, name, node, datetime.now().isoformat(),
                     user, kind, FAVORITES_MAX[kind]))
                full = cur.rowcount == 0 and not conn.execute(
                    f'SELECT 1 FROM user_favorites WHERE {_FAV_KEY}', key).fetchone()
        else:
            # one's own row goes whether it is still in reach or not
            conn.execute(f'DELETE FROM user_favorites WHERE {_FAV_KEY}', key)
        # also when nothing went in: the INSERT took the write lock all the same
        conn.commit()
        if full:
            what = {'vm': 'VMs', 'node': 'nodes', 'cluster': 'clusters'}[kind]
            return jsonify({'error': f'At most {FAVORITES_MAX[kind]} {what} can be favorites - '
                                     'remove one first', 'code': 'FAVORITES_LIMIT'}), 409
        return jsonify({'success': True, 'favorites': _visible_favorites(user, visible)})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logging.error(f"Error saving favorite: {e}")
        return jsonify({'error': safe_error(e, 'Could not save favorite')}), 500


# ============================================
# VM Tags / Labels
# should have added this sooner tbh
# Tags are stored per-cluster, per-VM in a simple JSON file
# ============================================

TAGS_FILE = os.path.join(CONFIG_DIR, 'vm_tags.json')  # Legacy

def load_vm_tags():
    """Load VM tags from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM vm_tags')
        
        tags = {}
        for row in cursor.fetchall():
            cluster_id = row['cluster_id']
            vmid = str(row['vmid'])
            
            if cluster_id not in tags:
                tags[cluster_id] = {}
            if vmid not in tags[cluster_id]:
                tags[cluster_id][vmid] = []
            
            tags[cluster_id][vmid].append({
                'name': row['tag_name'],
                'color': row['tag_color'] or TAG_COLORS[hash(row['tag_name']) % len(TAG_COLORS)]
            })
        
        return tags
    except Exception as e:
        logging.error(f"Error loading VM tags from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(TAGS_FILE):
                with open(TAGS_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
    return {}


def save_vm_tags(tags):
    """Save VM tags to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # Clear existing tags
        cursor.execute('DELETE FROM vm_tags')
        
        # Insert all tags
        for cluster_id, vms in tags.items():
            for vmid, vm_tags in vms.items():
                for tag in vm_tags:
                    tag_name = tag.get('name', tag) if isinstance(tag, dict) else tag
                    tag_color = tag.get('color', '') if isinstance(tag, dict) else ''
                    
                    cursor.execute('''
                        INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color)
                        VALUES (?, ?, ?, ?)
                    ''', (cluster_id, int(vmid), tag_name, tag_color))
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving VM tags: {e}")
        # NS Aug 2026 (Aikido pentest) — defence in depth: the global DELETE above runs before
        # the re-inserts, so a mid-loop failure must NOT be left pending on the shared
        # thread-local connection (a later log_audit commit would persist the partial wipe).
        try:
            db.conn.rollback()
        except Exception:
            pass

# LW: Global tag colors - keeps things consistent
TAG_COLORS = [
    '#ef4444', '#f97316', '#eab308', '#22c55e', '#14b8a6', 
    '#3b82f6', '#8b5cf6', '#ec4899', '#6b7280', '#78716c'
]

@bp.route('/api/clusters/<cluster_id>/tags', methods=['GET'])
@require_auth()
def get_cluster_tags(cluster_id):
    """Get all tags used in this cluster
    
    Returns unique tags with their colors and usage count
    """
    # MK Jun 2026 (sec-review) — was unscoped; leaked tags cross-tenant (CWE-285)
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    tags_db = load_vm_tags()
    cluster_tags = tags_db.get(cluster_id, {})

    # MK Jun 2026 (#585 cybrwerk): this only ever knew tags assigned through our own UI
    # (the load_vm_tags store). PVE-native tags set in the VM config never showed up here.
    # Build a per-VM union of stored + live PVE tags so each VM counts once per tag.
    per_vm = {}      # vmid -> set(tag names)
    colors = {}      # tag name -> explicit colour (stored tags may carry one)
    for vm_key, vm_tags in cluster_tags.items():
        bucket = per_vm.setdefault(str(vm_key), set())
        for tag in (vm_tags or []):
            name = ((tag.get('name') if isinstance(tag, dict) else tag) or '').strip()
            if not name:
                continue
            bucket.add(name)
            if isinstance(tag, dict) and tag.get('color'):
                colors[name] = tag['color']

    # merge the live PVE tags (semicolon-separated on each guest)
    try:
        mgr = cluster_managers.get(cluster_id)
        if mgr:
            for r in (mgr.get_vm_resources() or []):
                raw = r.get('tags')
                if not raw:
                    continue
                parts = raw if isinstance(raw, list) else str(raw).split(';')
                bucket = per_vm.setdefault(str(r.get('vmid')), set())
                for p in parts:
                    p = (p or '').strip()
                    if p:
                        bucket.add(p)
    except Exception as e:
        logging.debug(f"[tags] could not merge live PVE tags for {cluster_id}: {e}")

    # NS Aug 2026 (Aikido #469089237) — only count tags of VMs the caller may access, so a
    # pool-scoped user (who reaches the cluster via the pool fallback) can't enumerate tag
    # names/usage of VMs outside their scope. Admins pass user_can_access_vm unchanged.
    from pegaprox.utils.auth import build_authz_user
    _tag_user = build_authz_user(request.session.get('user', ''), request.session)

    def _tag_vm_visible(vmid_str):
        try:
            return user_can_access_vm(_tag_user, cluster_id, int(str(vmid_str).split(':')[0]), 'vm.view')
        except (ValueError, TypeError):
            return False

    tag_counts = {}
    for _vmid_str, bucket in per_vm.items():
        if not _tag_vm_visible(_vmid_str):
            continue
        for name in bucket:
            entry = tag_counts.setdefault(name, {
                'name': name,
                'color': colors.get(name, TAG_COLORS[hash(name) % len(TAG_COLORS)]),
                'count': 0,
            })
            entry['count'] += 1

    return jsonify(list(tag_counts.values()))


@bp.route('/api/clusters/<cluster_id>/vms/<vmid>/tags', methods=['GET'])
@require_auth()
def get_vm_tags(cluster_id, vmid):
    """Get tags for a specific VM"""
    ok, err = check_cluster_access(cluster_id)  # sec-review: was unscoped (CWE-285)
    if not ok:
        return err
    # sec (private disclosure Sep 2026) — cluster access alone let a pool-scoped caller read the
    # tags of any vmid they named. Gate on per-VM access like get_cluster_tags does for the counts.
    _tag_user = build_authz_user(request.session.get('user', ''), request.session)
    try:
        if not user_can_access_vm(_tag_user, cluster_id, int(str(vmid).split(':')[0]), 'vm.view'):
            return jsonify({'error': 'Access denied to this VM'}), 403
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid VM id'}), 400
    tags_db = load_vm_tags()
    cluster_tags = tags_db.get(cluster_id, {})
    vm_tags = cluster_tags.get(str(vmid), [])

    return jsonify(vm_tags)


@bp.route('/api/clusters/<cluster_id>/vms/<vmid>/tags', methods=['POST'])
@require_auth(perms=['vm.config'])
def update_vm_tags(cluster_id, vmid):
    """Add or update tags for a VM
    
    Body:
    - tags: Array of tag objects [{name: 'prod', color: '#ef4444'}, ...]
    
    Or simple add:
    - tag: Single tag name to add
    - color: Optional color for the tag
    """
    # MK Jun 2026 (sec-review) — vm.config is global; gate per-cluster so a tenant
    # user can't write tags onto another tenant's VMs (the DELETE sibling already does)
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # NS Aug 2026 (Aikido pentest) — vmid is a bare <string> route converter. save_vm_tags
    # does a global `DELETE FROM vm_tags` + full rewrite that int()s every stored key; a
    # non-numeric vmid would ValueError mid-rewrite and (via the next log_audit commit on the
    # shared connection) persist a partial cross-tenant tag wipe. Reject non-numeric here.
    try:
        vmid = int(vmid)
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid VM ID'}), 400
    # sec (private disclosure Sep 2026 — audit): the GET sibling gates per-VM but these tag WRITES did
    # not — a pool-/ACL-scoped vm.config holder (admitted to the cluster via the #248/#555 fallback)
    # could rewrite/erase a FOREIGN VM's tags, which drive backup/snapshot/affinity selection. Gate the
    # target VM per-object like get_vm_tags does. Own-scope VM passes; a VM outside the grant is denied.
    from pegaprox.utils.auth import build_authz_user
    if not user_can_access_vm(build_authz_user(request.session.get('user', ''), request.session),
                              cluster_id, vmid, 'vm.config'):
        return jsonify({'error': 'Access denied to this VM'}), 403
    data = request.json or {}
    tags_db = load_vm_tags()
    
    if cluster_id not in tags_db:
        tags_db[cluster_id] = {}
    
    vm_key = str(vmid)
    
    # Full replacement
    if 'tags' in data:
        tags_db[cluster_id][vm_key] = data['tags']
    # Single tag add
    elif 'tag' in data:
        tag_name = data['tag'].strip()
        if not tag_name:
            return jsonify({'error': 'Tag name required'}), 400
        
        current_tags = tags_db[cluster_id].get(vm_key, [])
        
        # Check if tag already exists
        existing = next((t for t in current_tags if (t.get('name') if isinstance(t, dict) else t) == tag_name), None)
        if not existing:
            new_tag = {
                'name': tag_name,
                'color': data.get('color', TAG_COLORS[hash(tag_name) % len(TAG_COLORS)])
            }
            current_tags.append(new_tag)
            tags_db[cluster_id][vm_key] = current_tags
    
    save_vm_tags(tags_db)
    
    user = request.session.get('user', 'system')
    cluster_name = cluster_managers[cluster_id].config.name if cluster_id in cluster_managers else cluster_id
    log_audit(user, 'vm.tags_updated', f"Updated tags for VM {vmid}", cluster=cluster_name)
    
    return jsonify({
        'success': True,
        'tags': tags_db[cluster_id].get(vm_key, [])
    })


@bp.route('/api/clusters/<cluster_id>/vms/<vmid>/tags/<tag_name>', methods=['DELETE'])
@require_auth(perms=['vm.config'])
def remove_vm_tag(cluster_id, vmid, tag_name):
    """Remove a tag from a VM"""
    # NS May 2026: tenant ACL — vm.config alone wasn't enough; without this,
    # any vm.config holder could yank tags off a VM in a cluster they don't own.
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # sec (private disclosure Sep 2026 — audit): per-VM gate on the tag WRITE, matching the GET sibling
    from pegaprox.utils.auth import build_authz_user
    try:
        _v = int(str(vmid).split(':')[0])
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid VM ID'}), 400
    if not user_can_access_vm(build_authz_user(request.session.get('user', ''), request.session),
                              cluster_id, _v, 'vm.config'):
        return jsonify({'error': 'Access denied to this VM'}), 403
    tags_db = load_vm_tags()

    if cluster_id not in tags_db:
        return jsonify({'error': 'No tags for this cluster'}), 404
    
    vm_key = str(vmid)
    if vm_key not in tags_db[cluster_id]:
        return jsonify({'error': 'No tags for this VM'}), 404
    
    # Remove the tag
    current_tags = tags_db[cluster_id][vm_key]
    tags_db[cluster_id][vm_key] = [
        t for t in current_tags 
        if (t.get('name') if isinstance(t, dict) else t) != tag_name
    ]
    
    # Cleanup empty entries
    if not tags_db[cluster_id][vm_key]:
        del tags_db[cluster_id][vm_key]
    
    save_vm_tags(tags_db)
    
    return jsonify({'success': True})


@bp.route('/api/tags/search', methods=['GET'])
@require_auth()
def search_vms_by_tag():
    """Search VMs across all clusters by tag
    
    Query params:
    - tag: Tag name to search for
    - cluster_id: Optional - limit to specific cluster
    """
    tag_name = request.args.get('tag', '').strip()
    filter_cluster = request.args.get('cluster_id')
    
    if not tag_name:
        return jsonify({'error': 'Tag parameter required'}), 400
    
    tags_db = load_vm_tags()
    results = []
    
    user = request.session.get('user', '')
    # #491 — token-scoped identity (build_authz_user applies the token's effective_role)
    user_data = build_authz_user(user, request.session)
    # #285: tenant/group-based access via the RBAC helper (was reading a missing
    # user['clusters'] → empty → tags leaked across every cluster). MK
    accessible_clusters = get_user_clusters(user_data)  # None = admin / all

    for cluster_id, cluster_tags in tags_db.items():
        # Check access
        if accessible_clusters is not None and cluster_id not in accessible_clusters:
            continue
        if filter_cluster and cluster_id != filter_cluster:
            continue
        
        mgr = cluster_managers.get(cluster_id)
        cluster_name = mgr.config.name if mgr else cluster_id
        
        for vm_key, vm_tags in cluster_tags.items():
            # sec (private disclosure Sep 2026) — don't reveal tagged VMs outside the caller's
            # grant. Same per-VM gate as get_cluster_tags; a pool-/ACL-scoped user is confined,
            # admins/plain operators pass. vm_key is 'vmid' (occasionally 'vmid:type').
            try:
                if not user_can_access_vm(user_data, cluster_id, int(str(vm_key).split(':')[0]), 'vm.view'):
                    continue
            except (ValueError, TypeError):
                continue

            # Check if this VM has the tag
            has_tag = any(
                (t.get('name') if isinstance(t, dict) else t) == tag_name
                for t in vm_tags
            )

            if has_tag:
                # Try to get VM details
                vm_info = {'vmid': vm_key, 'cluster_id': cluster_id, 'cluster_name': cluster_name}
                
                if mgr and mgr.is_connected:
                    try:
                        resources = mgr.get_vm_resources()
                        vm_data = next((r for r in resources if str(r.get('vmid')) == vm_key), None)
                        if vm_data:
                            vm_info.update({
                                'name': vm_data.get('name'),
                                'node': vm_data.get('node'),
                                'status': vm_data.get('status'),
                                'type': vm_data.get('type')
                            })
                    except:
                        pass
                
                vm_info['tags'] = vm_tags
                results.append(vm_info)
    
    return jsonify(results)


# ============================================

