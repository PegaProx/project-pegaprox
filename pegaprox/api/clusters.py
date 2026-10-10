# -*- coding: utf-8 -*-
"""cluster CRUD, HA & maintenance routes - split from monolith dec 2025, NS"""

import json
import logging
import re
import threading
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.models.tasks import (PegaProxConfig, balancer_cooldown, BALANCER_COOLDOWN_MIN,
                                   BALANCER_COOLDOWN_MAX)
from pegaprox.core.db import get_db
from pegaprox.core import ha
from pegaprox.core.cache import StorageDataCache

from pegaprox.utils.auth import require_auth, load_users, build_authz_user
from pegaprox.utils.audit import log_audit
from pegaprox.utils.sanitization import sanitize_log_message as _sl  # CWE-117
from pegaprox.utils.rbac import (
    invalidate_tenants_cache,
    has_permission, get_user_clusters, filter_clusters_for_user,
    user_can_access_vm, invalidate_pool_cache, get_vm_acls,
)
from pegaprox.utils.realtime import broadcast_sse, broadcast_update, push_immediate_update
from pegaprox.core.config import load_config, save_config
from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager, XENAPI_AVAILABLE
from pegaprox.utils.sanitization import bounded_list, validate_ssh_user, validate_host_address
from pegaprox.api.helpers import (load_server_settings, get_connected_manager, check_cluster_access,
                                  safe_error, scope_vm_rows, require_unconfined, parse_pve_error,
                                  bounded_limit, node_maintenance_for_caller, upstream_failure)

# MK: this used to be 200 lines down in the monolith, good luck finding anything there
bp = Blueprint('clusters', __name__)

@bp.route('/api/clusters', methods=['GET'])
@require_auth()
def get_clusters():
    """Get all configured clusters (filtered by tenant + VM ACLs)

    NS: Clusters are now sorted by sort_order, then by name for consistent ordering
    LW: Apr 2026 - users with VM ACLs can see their clusters without cluster.view (#248)
    """
    # get user's allowed clusters
    user = build_authz_user(request.session.get('user', ''), request.session)
    allowed = get_user_clusters(user)
    has_cluster_view = has_permission(user, 'cluster.view')

    # #248: users without cluster.view can still see clusters where they have VM ACLs
    acl_cluster_ids = set()
    if not has_cluster_view:
        from pegaprox.utils.rbac import load_vm_acls, acl_grants_user
        all_acls = load_vm_acls()
        for cid, vm_acls in all_acls.items():
            for vmid, acl in vm_acls.items():
                if acl_grants_user(acl, user['username']):
                    acl_cluster_ids.add(cid)
                    break
        # #555: also surface clusters where the user holds pool perms
        try:
            for cid in get_db().get_user_pool_clusters(user['username'], user.get('groups', [])):
                acl_cluster_ids.add(cid)
        except Exception:
            pass
        if not acl_cluster_ids:
            return jsonify([])

    # Get cluster metadata from database (display_name, group_id, sort_order)
    db = get_db()
    cluster_meta = {}
    try:
        meta_rows = db.query('SELECT id, display_name, group_id, sort_order FROM clusters')
        for row in meta_rows:
            cluster_meta[row['id']] = {
                'display_name': row['display_name'],
                'group_id': row['group_id'],
                'sort_order': row['sort_order'] if row['sort_order'] is not None else 0
            }
    except:
        pass

    clusters = []
    for cluster_id, mgr in cluster_managers.items():
        # filter by tenant
        if allowed is not None and cluster_id not in allowed:
            # fallback: allow if user has VM ACLs in this cluster
            if cluster_id not in acl_cluster_ids:
                continue
        # without cluster.view, only show clusters with VM ACLs
        if not has_cluster_view and cluster_id not in acl_cluster_ids:
            continue

        meta = cluster_meta.get(cluster_id, {})
        display_name = meta.get('display_name') or ''

        # ACL-only users get minimal info (no admin settings)
        if not has_cluster_view:
            clusters.append({
                'id': cluster_id,
                'name': mgr.config.name,
                'display_name': display_name,
                'group_id': meta.get('group_id'),
                'sort_order': meta.get('sort_order', 0),
                'status': 'running' if mgr.running else 'stopped',
                'connected': mgr.is_connected,
                'cluster_type': getattr(mgr, 'cluster_type', 'proxmox'),
            })
        else:
            clusters.append({
                'id': cluster_id,
                'name': mgr.config.name,
                'display_name': display_name,
                'group_id': meta.get('group_id'),
                'sort_order': meta.get('sort_order', 0),
                'host': mgr.config.host,
                'status': 'running' if mgr.running else 'stopped',
                'connected': mgr.is_connected,
                'connection_error': mgr.connection_error,
                # #16745 — presence only (never the key). Lets the Harden PVE Node UI warn before
                # the sshd_hardening control (PermitRootLogin prohibit-password) cuts off PegaProx's
                # own access on a cluster we reach by root password with no key deployed.
                'has_ssh_key': bool(getattr(mgr.config, 'ssh_key', '')),
                # MK Sep 2026 (#941) — the listing is what the cluster dialog reads back, so
                # a field missing here is a toggle that reverts on refresh. Same trap as
                # proxlb_tags_enabled below (#628); the round-trip test I wrote went through
                # save_cluster/get_cluster and never touched this serializer, so only the
                # live E2E caught it.
                'ssh_disabled': bool(getattr(mgr.config, 'ssh_disabled', False)),
                'migration_threshold': mgr.config.migration_threshold,
                'migration_tolerance': getattr(mgr.config, 'migration_tolerance', 10),
                'migration_cooldown': balancer_cooldown(getattr(mgr.config, 'migration_cooldown', None)),
                'check_interval': mgr.config.check_interval,
                'auto_migrate': mgr.config.auto_migrate,
                'balance_containers': getattr(mgr.config, 'balance_containers', False),
                'balance_local_disks': getattr(mgr.config, 'balance_local_disks', False),
                'proxlb_tags_enabled': getattr(mgr.config, 'proxlb_tags_enabled', False),  # #628 — was missing from GET, made the UI toggle revert on refresh
                'proxlb_pins_auto_migrate': bool(getattr(mgr.config, 'proxlb_pins_auto_migrate', False)),
                'proxlb_pins_strict': bool(getattr(mgr.config, 'proxlb_pins_strict', False)),
                'dry_run': mgr.config.dry_run,
                'predictive_balancing': getattr(mgr.config, 'predictive_balancing', False),
                'predictive_threshold': getattr(mgr.config, 'predictive_threshold', 75),
                'balance_cpu_weight': getattr(mgr.config, 'balance_cpu_weight', 1.0),
                'balance_mem_weight': getattr(mgr.config, 'balance_mem_weight', 1.0),
                'balance_io_weight': getattr(mgr.config, 'balance_io_weight', 0.0),
                'cpu_baseline': getattr(mgr.config, 'cpu_baseline', None),
                'enabled': mgr.config.enabled,
                'ha_enabled': mgr.config.ha_enabled,
                'fallback_hosts': mgr.config.fallback_hosts,
                'excluded_nodes': getattr(mgr.config, 'excluded_nodes', []),
                'current_host': getattr(mgr, '_original_host', None) or getattr(mgr, 'current_host', None),
                'last_run': mgr.last_run.isoformat() if mgr.last_run else None,
                'api_token_active': bool(getattr(mgr, '_using_api_token', False)),
                'cluster_type': getattr(mgr, 'cluster_type', 'proxmox'),
                # MK May 2026 — worldmap location (per-cluster). None when not set.
                'latitude': getattr(mgr.config, 'latitude', None),
                'longitude': getattr(mgr.config, 'longitude', None),
                'location_label': getattr(mgr.config, 'location_label', '') or '',
                'node_ui_suffix': getattr(mgr.config, 'node_ui_suffix', '') or '',
                'transfer_network': getattr(mgr.config, 'transfer_network', '') or '',
            })

    # MK: Sort clusters by sort_order first, then by name for consistent ordering
    # MK Sep 2026 - coerce in the key: rows written before the validation above exist,
    # and one of them must not be able to 500 the cluster list for everyone.
    def _order_key(c):
        v = c.get('sort_order', 0)
        return (v if isinstance(v, int) and not isinstance(v, bool) else 0,
                str(c.get('name', '')).lower())
    clusters.sort(key=_order_key)

    return jsonify(clusters)


@bp.route('/api/clusters', methods=['POST'])
@require_auth(perms=['cluster.add'])
def add_cluster():
    """Add a new cluster"""
    data = request.json

    # Validate required fields
    required = ['name', 'host', 'user']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400

    # password or ssh key - need at least one
    if not data.get('pass') and not data.get('ssh_key'):
        return jsonify({'error': 'Password or SSH key is required'}), 400
    if 'pass' not in data:
        data['pass'] = ''
    _uerr = _ssh_user_error(data)
    if _uerr:
        return _uerr
    _cd_err = _cooldown_error(data)
    if _cd_err:
        return _cd_err
    _xn_err = _transfer_network_error(data)
    if _xn_err:
        return _xn_err

    # Generate unique ID
    cluster_id = str(uuid.uuid4())[:8]
    cluster_type = data.get('cluster_type', 'proxmox')

    # the manager below is built from this body and started: no HA settings from it (#625)
    data['ha_settings'] = _ha_settings_for_new_cluster()

    # Create config
    config = PegaProxConfig(data)

    # MK Mar 2026: dispatch to correct manager based on cluster type
    if cluster_type == 'xcpng':
        if not XENAPI_AVAILABLE:
            return jsonify({'error': 'XenAPI library not installed. Run: pip install XenAPI'}), 400
        manager = XcpngManager(cluster_id, config)
        if not manager.connect():
            error_detail = manager.connection_error or 'Failed to connect to XCP-ng pool'
            return jsonify({'error': f'Failed to connect: {error_detail}'}), 400
    else:
        manager = PegaProxManager(cluster_id, config)
        # Test connection - MK: return actual error instead of generic message (#88)
        if not manager.connect_to_proxmox():
            error_detail = manager.connection_error or 'Failed to connect to Proxmox cluster'
            # #683 — surface a machine code so the UI can show a localized 2FA hint (API token OR
            # temporarily disable 2FA), not just the English fallback text.
            return jsonify({'error': f'Failed to connect: {error_detail}',
                            'error_code': getattr(manager, 'connection_error_code', None)}), 400

    manager.start()
    cluster_managers[cluster_id] = manager

    # Save configuration - also store cluster_type in db
    save_config()
    if cluster_type != 'proxmox':
        db = get_db()
        db.update_cluster(cluster_id, {'cluster_type': cluster_type})

    # Audit log
    type_label = 'XCP-ng' if cluster_type == 'xcpng' else 'Proxmox'
    log_audit(request.session['user'], 'cluster.added', f"Added {type_label} cluster: {data.get('name')} ({data.get('host')})")

    result = {'id': cluster_id, 'message': 'Cluster added successfully'}
    # NS: let frontend know if we auto-created an API token (#110)
    if getattr(manager, '_token_auto_created', False):
        result['api_token_created'] = True
    return jsonify(result), 201


@bp.route('/api/clusters/<cluster_id>/config/export', methods=['GET'])
@require_auth(perms=['cluster.config'])
def export_cluster_config(cluster_id):
    """Export cluster config WITHOUT secrets — for re-configure pre-fill (#256)"""
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    c = mgr.config
    return jsonify({
        'name': c.name, 'host': c.host, 'user': c.user,
        'ssl_verification': c.ssl_verification,
        'migration_threshold': c.migration_threshold,
        'migration_tolerance': getattr(c, 'migration_tolerance', 10),
        'migration_cooldown': balancer_cooldown(getattr(c, 'migration_cooldown', None)),
        'check_interval': c.check_interval,
        'auto_migrate': c.auto_migrate,
        'balance_containers': getattr(c, 'balance_containers', False),
        'balance_local_disks': getattr(c, 'balance_local_disks', False),
        'proxlb_tags_enabled': getattr(c, 'proxlb_tags_enabled', False),  # #628
        'proxlb_pins_auto_migrate': bool(getattr(c, 'proxlb_pins_auto_migrate', False)),
        'proxlb_pins_strict': bool(getattr(c, 'proxlb_pins_strict', False)),
        'dry_run': c.dry_run,
        'cluster_type': getattr(mgr, 'cluster_type', 'proxmox'),
        'vnc_tunnel': bool(getattr(c, 'vnc_tunnel', False)),  # MK Apr 2026
        'ssh_disabled': bool(getattr(c, 'ssh_disabled', False)),  # MK Sep 2026 (#941)
        'transfer_network': getattr(c, 'transfer_network', '') or '',
        # secrets intentionally omitted: pass, ssh_key, api_token_secret
    })


# MK May 2026 (PVE 9.2) — rotate the auto-created API token without dropping
# its ACL entries. The classic delete+recreate path resets all permissions;
# the new /access/users/{user}/token/{id} POST in 9.2 regenerates the secret
# in place. On pre-9.2 we fall back to delete+create + warn that ACLs reset.
@bp.route('/api/clusters/<cluster_id>/api-token/rotate', methods=['POST'])
@require_auth(perms=['cluster.config'])
def rotate_cluster_api_token(cluster_id):
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not getattr(mgr.config, 'api_token_user', ''):
        return jsonify({'error': 'No API token configured for this cluster'}), 400

    try:
        token_user = mgr.config.api_token_user
        user_part, token_id = token_user.split('!', 1)
        base = f"https://{mgr.host}:{mgr.api_port}/api2/json/access/users/{user_part}/token/{token_id}"

        pve_ver = mgr.get_pve_version_tuple()
        new_secret = None
        # NS May 2026 — only try the 9.2 in-place regenerate when we KNOW the
        # cluster is 9.2+. Pre-9.2 PVE doesn't reject POST on an existing
        # token cleanly — it hangs / times out on some 9.1 builds. Falling
        # back is cheaper than waiting for a 10s read timeout per attempt.
        if pve_ver is not None and pve_ver >= (9, 2):
            try:
                resp = mgr._api_post(base, data={}, timeout=8)
                if resp.status_code == 200:
                    data = resp.json().get('data') or {}
                    new_secret = data.get('value') or data.get('secret')
                    preserved = True
                elif resp.status_code in (404, 405, 501):
                    preserved = False  # fall through to delete+create
                else:
                    return upstream_failure(resp.status_code, parse_pve_error(resp.text))
            except Exception as probe_err:
                mgr.logger.warning(f"[token-rotate] in-place regenerate probe failed ({probe_err}); falling back")
                preserved = False
        else:
            preserved = False

        if new_secret is None:
            # Legacy path: delete + recreate. Warn caller ACLs are lost.
            mgr._create_session().delete(base, timeout=10)
            create_resp = mgr._api_post(base, data={})
            if create_resp.status_code != 200:
                return upstream_failure(create_resp.status_code, parse_pve_error(create_resp.text))
            data = create_resp.json().get('data') or {}
            new_secret = data.get('value') or data.get('secret')
            preserved = False

        if not new_secret:
            return jsonify({'error': 'Token regenerated but PVE did not return a secret'}), 502

        # Persist the new secret in our DB so subsequent connects use it
        mgr.config.api_token_secret = new_secret
        save_config()

        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'cluster.api_token_rotated',
                  f"Rotated API token {token_user} (ACLs preserved={preserved})",
                  cluster=mgr.config.name)
        return jsonify({
            'success': True,
            'acls_preserved': preserved,
            'message': 'Token rotated; ACLs preserved' if preserved
                       else 'Token rotated via delete+recreate; ACL entries on this token were lost (pre-PVE-9.2 cluster)',
        })
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Token rotation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/reconfigure', methods=['POST'])
@require_auth(perms=['cluster.config'])
def reconfigure_cluster(cluster_id):
    """Re-configure cluster credentials. Requires re-authentication. (#256)
    Keeps same cluster_id so VM ACLs, replication jobs etc. stay intact.
    """
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json or {}

    # Re-auth: user must verify their own password
    from pegaprox.utils.auth import verify_password
    current_password = data.pop('current_password', '')
    username = request.session['user']
    users = load_users()
    user = users.get(username, {})

    auth_source = user.get('auth_source', 'local')
    if auth_source == 'local':
        if not current_password or not user.get('password_hash') or not verify_password(current_password, user.get('password_salt', ''), user['password_hash']):
            return jsonify({'error': 'Invalid password'}), 401
    elif auth_source == 'ldap':
        # LDAP user: verify against LDAP server
        from pegaprox.utils.ldap import ldap_authenticate
        ldap_result = ldap_authenticate(username, current_password) if current_password else {}
        if not current_password or 'error' in ldap_result:
            return jsonify({'error': 'Invalid LDAP password'}), 401
    else:
        return jsonify({'error': 'Re-authentication not supported for this account type. Use a local admin account.'}), 400

    # Validate required fields (same as add_cluster)
    for field in ['name', 'host', 'user']:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    if not data.get('pass') and not data.get('ssh_key'):
        return jsonify({'error': 'Password or SSH key is required'}), 400
    if 'pass' not in data:
        data['pass'] = ''
    _uerr = _ssh_user_error(data)
    if _uerr:
        return _uerr

    cluster_type = data.get('cluster_type', getattr(cluster_managers[cluster_id], 'cluster_type', 'proxmox'))

    # MK Oct 2026 (#625) - the dialog sends the connection, never the HA settings, and
    # the new manager is built from this body alone: the agent token, the two-node
    # settings and the cluster claim went with the old manager. They stay the cluster's.
    old_mgr = cluster_managers[cluster_id]
    if hasattr(old_mgr, 'ha_config'):
        data['ha_settings'] = _ha_settings_of(old_mgr)
    else:
        kept = getattr(old_mgr.config, 'ha_settings', None)
        data['ha_settings'] = dict(kept) if isinstance(kept, dict) else {}
    # the balancer cooldown is no connection setting either: one the dialog leaves out stays
    _cd_err = _cooldown_error(data)
    if _cd_err:
        return _cd_err
    data.setdefault('migration_cooldown', balancer_cooldown(getattr(old_mgr.config, 'migration_cooldown', None)))
    # nor is the transfer network
    _xn_err = _transfer_network_error(data)
    if _xn_err:
        return _xn_err
    data.setdefault('transfer_network', getattr(old_mgr.config, 'transfer_network', '') or '')

    # Create new config + manager, test connection
    new_config = PegaProxConfig(data)
    if cluster_type == 'xcpng':
        if not XENAPI_AVAILABLE:
            return jsonify({'error': 'XenAPI library not installed'}), 400
        new_mgr = XcpngManager(cluster_id, new_config)
        if not new_mgr.connect():
            return jsonify({'error': f'Connection failed: {new_mgr.connection_error or "unknown"}'}), 400
    else:
        new_mgr = PegaProxManager(cluster_id, new_config)
        if not new_mgr.connect_to_proxmox():
            return jsonify({'error': f'Connection failed: {new_mgr.connection_error or "unknown"}',
                            'error_code': getattr(new_mgr, 'connection_error_code', None)}), 400

    # Stop old manager, swap in new one
    try:
        old_mgr.stop()
    except Exception:
        pass

    new_mgr.start()
    cluster_managers[cluster_id] = new_mgr
    save_config()

    log_audit(username, 'cluster.reconfigured', f"Re-configured cluster: {data.get('name')} ({data.get('host')})")

    result = {'success': True, 'message': 'Cluster re-configured successfully'}
    if getattr(new_mgr, '_token_auto_created', False):
        result['api_token_created'] = True
    return jsonify(result)


@bp.route('/api/clusters/<cluster_id>/nodes', methods=['GET'])
@require_auth(perms=['node.view'])
def get_cluster_nodes(cluster_id):
    """Get list of nodes in a cluster
    
    NS: Made more resilient - returns cached/last known nodes if connection fails
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]

    # MK: XCP-ng clusters use their own get_nodes()
    if getattr(manager, 'cluster_type', 'proxmox') == 'xcpng':
        try:
            nodes = manager.get_nodes()
            return jsonify(nodes)
        except Exception as e:
            logging.debug(f"XCP-ng get_nodes failed for {cluster_id}: {e}")
            return jsonify({'error': 'Connection temporarily unavailable', 'nodes': [], 'offline': True}), 503

    # Try to get live data
    try:
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/nodes"
        r = manager._create_session().get(url, timeout=10)

        if r.status_code == 200:
            nodes = r.json().get('data', [])
            # MK May 2026 (#415 KowMangler): the cross-cluster-migration target-
            # node dropdown wants per-node "CPU: X% RAM: Y%" strings, but raw
            # /api2/json/nodes returns `cpu` as a 0..1 fraction and `mem`/`maxmem`
            # as bytes. Frontend was reading `.cpu_percent`/`.mem_percent` which
            # didn't exist → empty text. Cheaper to compute it here once than
            # to teach every consumer the conversion.
            for n in nodes:
                if not isinstance(n, dict):
                    continue
                cpu = n.get('cpu')
                if isinstance(cpu, (int, float)):
                    n['cpu_percent'] = round(cpu * 100, 2)
                mem = n.get('mem')
                maxmem = n.get('maxmem')
                if isinstance(mem, (int, float)) and isinstance(maxmem, (int, float)) and maxmem > 0:
                    n['mem_percent'] = round((mem / maxmem) * 100, 2)
            # Cache the nodes data
            manager._cached_nodes = nodes
            return jsonify(nodes)
    except Exception as e:
        logging.debug(f"Failed to get nodes for {cluster_id}: {e}")

    # If live data failed, return cached data with offline status
    if hasattr(manager, '_cached_nodes') and manager._cached_nodes:
        cached = manager._cached_nodes
        # Mark all as potentially stale
        for node in cached:
            if 'connection_status' not in node:
                node['connection_status'] = 'stale'
        return jsonify(cached)

    # If HA is tracking nodes, return those
    if manager.ha_node_status:
        nodes = []
        for name, data in manager.ha_node_status.items():
            nodes.append({
                'node': name,
                'status': data.get('status', 'unknown'),
                'connection_status': 'from_ha_cache'
            })
        return jsonify(nodes)
    
    # Last resort - return empty but with error info
    return jsonify({
        'error': 'Connection temporarily unavailable',
        'nodes': [],
        'offline': not manager.is_connected
    }), 503


@bp.route('/api/clusters/<cluster_id>/ssh/repin-host-keys', methods=['POST'])
@require_auth(perms=['cluster.config'])
def repin_cluster_host_keys(cluster_id):
    """Drop the pinned SSH host keys for this cluster's hosts so the next connection
    re-learns them via TOFU.

    #717: after CIS hardening or a reinstall a node regenerates its SSH host key; the
    pinned key then trips reject-on-change and every SSH feature fails — and it reads
    like an auth error, not a host-key one. Deleting + re-adding the cluster already
    clears the pins on the way out; this exposes that same cleanup on its own so an
    operator doesn't have to tear the cluster down to recover. The next SSH connect
    pins the new key.
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    mgr = cluster_managers[cluster_id]
    try:
        from pegaprox.utils.ssh_security import remove_host_keys
        from pegaprox.utils.ssh import _node_ip_cache
        # same host set the delete path cleans: configured host + resolved node IPs
        hosts = set()
        v = getattr(mgr, 'host', None) or getattr(mgr.config, 'host', None)
        if v:
            hosts.add(v)
        for (cid, _node), val in list(_node_ip_cache.items()):
            if cid == cluster_id and val and val[0]:
                hosts.add(val[0])
        try:
            for n in (mgr.get_nodes() or []):
                ip = (n or {}).get('ip') or (n or {}).get('host')
                if ip:
                    hosts.add(ip)
        except Exception:
            pass
        removed = remove_host_keys(hosts)
        logging.info(f"[SSH] host-key re-pin for cluster {cluster_id}: dropped {removed} pin(s) "
                     f"across {len(hosts)} host(s) — next connect re-learns")
        return jsonify({'success': True, 'removed': removed, 'hosts': len(hosts)})
    except Exception as e:
        logging.exception(f"host-key re-pin failed for {cluster_id}")
        return jsonify({'error': safe_error(e, 'Re-pin failed')}), 500


@bp.route('/api/clusters/<cluster_id>/connection-check', methods=['POST'])
@require_auth(perms=['cluster.config'])
def check_cluster_connection(cluster_id):
    """Read-only connection check of one Proxmox VE cluster, on demand (core/conncheck.py).

    MK Oct 2026 - API addresses with timing and certificate, the credential and the
    privileges it carries, versions, clocks, quorum and SSH per node. POST because it
    logs in to the nodes over SSH (once each, only where a credential applies), which
    an admin should ask for; {"ssh": false} leaves that part out. A standby forwards it
    to the active or refuses it like any other write (app.py), so the check always
    runs where the clusters are acted on.
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    mgr = cluster_managers[cluster_id]
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return jsonify({'error': 'The connection check covers Proxmox VE clusters only',
                        'code': 'PVE_ONLY'}), 400
    data = request.get_json(silent=True)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        return jsonify({'error': 'The request body must be a JSON object'}), 400
    with_ssh = data.get('ssh', True) is not False
    from pegaprox.core import conncheck
    try:
        report = conncheck.run_check(mgr, include_ssh=with_ssh)
    except Exception as e:
        logging.exception(f"connection check failed for {_sl(cluster_id)}")
        return jsonify({'error': safe_error(e, 'The connection check failed')}), 500
    report['cluster_id'] = cluster_id
    report['ssh_checked'] = with_ssh
    s = report['summary']
    log_audit(request.session['user'], 'cluster.connection_check',
              f"Connection check of {mgr.config.name}: {s['ok']} ok, {s['warn']} warnings, "
              f"{s['fail']} failed" + ('' if with_ssh else ' (without SSH)'),
              cluster=mgr.config.name)
    return jsonify(report)


_XFER_NODE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,62}$')
_XFER_CHECK_STATUS = {'NO_NETWORK': 409, 'NOT_MEMBER': 400, 'SSH_DISABLED': 409,
                      'SSH_NO_CREDENTIALS': 409, 'NODE_BACKOFF': 409, 'SSH_FAILED': 502}


def _pve_cluster_or_error(cluster_id):
    """(manager, None) for a Proxmox VE cluster the caller may act on as a whole, else
    (None, response)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return None, err
    if cluster_id not in cluster_managers:
        return None, (jsonify({'error': 'Cluster not found'}), 404)
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return None, _cerr
    mgr = cluster_managers[cluster_id]
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None, (jsonify({'error': 'The transfer network applies to Proxmox VE clusters only',
                               'code': 'PVE_ONLY'}), 400)
    return mgr, None


@bp.route('/api/clusters/<cluster_id>/transfer-network', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_transfer_network(cluster_id):
    """The transfer network of a Proxmox VE cluster and each node's address in it.

    MK Oct 2026 - remote migrations PegaProx starts into this cluster dial the target node
    at that address instead of the management host (core/transfer_net.py). Answers from
    the cache of the nodes' network configs; nodes it lacks are read in the background and
    come back with state 'pending' until then. ?network=<cidr> shows another network
    before it is saved. migration_network is the datacenter option PVE uses for
    migrations inside the cluster, for reference: it is edited there, not here.
    """
    mgr, err = _pve_cluster_or_error(cluster_id)
    if err:
        return err
    from pegaprox.core import transfer_net
    override = request.args.get('network')
    if override is not None:
        cidr, nerr = transfer_net.normalize(override)
        if nerr:
            return jsonify({'error': nerr.replace('transfer_network', 'network')}), 400
        override = cidr
    view = transfer_net.cluster_view(mgr, override)
    view['cluster_id'] = cluster_id
    view['saved'] = getattr(mgr.config, 'transfer_network', '') or ''
    return jsonify(view)


@bp.route('/api/clusters/<cluster_id>/transfer-network/check', methods=['POST'])
@require_auth(perms=['cluster.config'])
def check_transfer_network(cluster_id):
    """From one node of a source cluster, whether the transfer addresses of this cluster's
    nodes answer on port 8006 - the path the disk data of a remote migration takes.

    MK Oct 2026 - body {"source_cluster": id, "source_node": name}. Logs in to that node
    over SSH once, through the same path as the other node checks, and opens one TCP
    connection per address from there; nothing is changed. Both clusters must be ones the
    caller may act on as a whole. A standby forwards it to the active or refuses it like
    any other write (app.py).
    """
    mgr, err = _pve_cluster_or_error(cluster_id)
    if err:
        return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'The request body must be a JSON object'}), 400
    src_id, node = data.get('source_cluster'), data.get('source_node')
    if not isinstance(src_id, str) or not src_id or len(src_id) > 64:
        return jsonify({'error': 'source_cluster must be the id of a cluster'}), 400
    if not isinstance(node, str) or not _XFER_NODE_RE.match(node):
        return jsonify({'error': 'source_node must be a node name'}), 400
    src, err = _pve_cluster_or_error(src_id)
    if err:
        return err
    from pegaprox.core import transfer_net
    try:
        report, fail = transfer_net.check_from(src, node, mgr)
    except Exception as e:
        logging.exception(f"transfer network check failed for {_sl(cluster_id)}")
        return jsonify({'error': safe_error(e, 'The check failed')}), 500
    user = request.session['user']
    if fail:
        code, detail = fail
        log_audit(user, 'cluster.transfer_network_check',
                  f"Transfer network check of {mgr.config.name} from {_sl(node)} could not run: {code}",
                  cluster=mgr.config.name)
        return jsonify({'error': detail, 'code': code}), _XFER_CHECK_STATUS.get(code, 400)
    rows = report['nodes']
    log_audit(user, 'cluster.transfer_network_check',
              f"Transfer network check of {mgr.config.name} ({report['network']}) from "
              f"{src.config.name}/{_sl(node)}: {sum(1 for r in rows if r['status'] == 'ok')} answer, "
              f"{sum(1 for r in rows if r['status'] == 'fail')} do not, "
              f"{sum(1 for r in rows if r['status'] in ('none', 'unreadable'))} without an address",
              cluster=mgr.config.name)
    report.update(cluster_id=cluster_id, source_cluster=src_id)
    return jsonify(report)


def _retire_cluster_claim(mgr, every_node=False):
    """Take our cluster claim off the cluster and switch the claim off, for HA disable,
    for deleting the cluster and for the switch itself. What the response reports
    about it; None where the claim was off, or the cluster is of a kind that has none.

    A removal that raised is reported as one that failed. It answered None before,
    which the responses show as "the claim was off": the file may still be in
    /etc/pve/pegaprox then, and nothing said so."""
    if not hasattr(mgr, '_ha_claim_retire'):
        return None
    try:
        claim = mgr._ha_claim_retire(every_node=True) if every_node else mgr._ha_claim_retire()
    except Exception as e:
        logging.warning(f"[HA] cluster claim removal failed: {e}")
        return _claim_removal_failed(mgr)
    return claim if isinstance(claim, dict) else None


def _claim_removal_failed(mgr):
    """The report of _ha_claim_retire for a removal that did not get that far. The
    switch goes off as it does there, and the command for the admin removes the file
    only while it is ours."""
    by_hand = None
    try:
        from pegaprox.core import ha
        instance, epoch = ha.lock_holder()
        by_hand = mgr._claim_by_hand(epoch, instance)
    except Exception:
        pass
    try:
        mgr.ha_config['claim_enabled'] = False
        mgr.ha_config.pop('claim_state', None)
    except Exception:
        pass
    warning = ("The cluster claim could not be removed (the removal ended with an error): "
               "/etc/pve/pegaprox/claim may still be there. "
               + (f"To remove it by hand, run on one node of the cluster, which has to be quorate for it: `{by_hand}`"
                  if by_hand else
                  "Look at the file on one node of the cluster and remove it when it names this PegaProx instance."))
    return {'state': 'failed', 'removed': False, 'path': '/etc/pve/pegaprox/claim', 'instance': None,
            'epoch': None, 'warning': warning, 'by_hand': by_hand}


def _ensure_cluster_claim(mgr, takeover=False):
    """_ha_claim_ensure for the claim route. A write that raised is the state 'failed',
    as a write the node refused is: the switch stays where the admin put it, and the
    next look at the claim tries again."""
    try:
        return mgr._ha_claim_ensure(takeover=takeover)
    except Exception as e:
        logging.warning(f"[HA] cluster claim write failed: {e}")
        from datetime import datetime as _dt
        result = {'state': 'failed', 'node': None, 'checked_at': _dt.now().isoformat(),
                  'epoch': None, 'instance': None}
        mgr.ha_config['claim_state'] = result
        return result


@bp.route('/api/clusters/<cluster_id>', methods=['DELETE'])
@require_auth(perms=['cluster.delete'])
def delete_cluster(cluster_id):
    """Delete a cluster"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # Check cluster-scoped authorization (tenant/VM-ACL access)
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    mgr = cluster_managers[cluster_id]
    cluster_name = mgr.config.name

    # NS: revoke auto-created API token on PVE before removing cluster (#110)
    if getattr(mgr.config, 'api_token_user', '') and mgr.is_connected:
        try:
            token_user = mgr.config.api_token_user  # e.g. root@pam!pegaprox
            user_part, token_id = token_user.split('!', 1)
            url = f"https://{mgr.host}:{mgr.api_port}/api2/json/access/users/{user_part}/token/{token_id}"
            resp = mgr._create_session().delete(url, timeout=10)
            if resp.status_code == 200:
                logging.info(f"Revoked API token {token_user} on PVE")
            else:
                logging.warning(f"Could not revoke API token {token_user}: HTTP {resp.status_code}")
        except Exception as e:
            logging.debug(f"Token revocation failed (non-critical): {e}")

    # Our cluster claim leaves the cluster with it (#625): once the cluster is gone
    # from PegaProx nobody could take the file out of /etc/pve/pegaprox any more.
    # Before the host-key pins go, the removal is an SSH call.
    claim = _retire_cluster_claim(mgr)

    # Clean up pinned SSH host keys for this cluster's hosts BEFORE stopping the
    # manager (so re-adding a node that was reinstalled meanwhile works via TOFU
    # rather than tripping reject-on-change on the stale key).
    try:
        from pegaprox.utils.ssh_security import remove_host_keys
        from pegaprox.utils.ssh import _node_ip_cache
        hosts_to_clean = set()
        for attr in ('host',):
            v = getattr(mgr, attr, None) or getattr(mgr.config, attr, None)
            if v:
                hosts_to_clean.add(v)
        for (cid, _node), val in list(_node_ip_cache.items()):
            if cid == cluster_id and val and val[0]:
                hosts_to_clean.add(val[0])
        try:
            for n in (mgr.get_nodes() or []):
                ip = (n or {}).get('ip') or (n or {}).get('host')
                if ip:
                    hosts_to_clean.add(ip)
        except Exception:
            pass
        # NS Sep 2026 (Aikido 469089277) — a host can be reachable through more than one
        # configured cluster (shared management IP, a node moved between clusters, two entries
        # for the same box). Dropping its pin here would silently re-TOFU it for the OTHER
        # cluster on its next SSH connection, which is exactly the window reject-on-change
        # exists to close. Keep any host another manager still points at; only local state is
        # consulted, no per-cluster network calls.
        still_pinned = set()
        for _cid, _other in list(cluster_managers.items()):
            if _cid == cluster_id:
                continue
            v = getattr(_other, 'host', None) or getattr(getattr(_other, 'config', None), 'host', None)
            if v:
                still_pinned.add(v)
        for (_cid, _node), val in list(_node_ip_cache.items()):
            if _cid != cluster_id and val and val[0]:
                still_pinned.add(val[0])
        hosts_to_clean -= still_pinned

        n_removed = remove_host_keys(hosts_to_clean)
        if n_removed:
            logging.info(f"Removed {n_removed} SSH host-key pin(s) for deleted cluster {cluster_id}")
        if still_pinned:
            logging.debug(f"Kept {len(still_pinned)} host-key pin(s) still referenced by another cluster")
    except Exception as e:
        logging.debug(f"known_hosts cleanup on cluster delete failed (non-critical): {e}")

    mgr.stop()
    del cluster_managers[cluster_id]

    # MK: Delete cluster and all related data from database
    try:
        db = get_db()
        # #779 (zobsg) — db.delete_cluster now sweeps EVERY cluster_id-keyed table (vm_acls,
        # affinity_rules, cluster_alerts, pool_permissions, node_maintenance, … ~20 of them), so the
        # per-table DELETEs that used to live here are gone — they only ever covered three of them.
        db.delete_cluster(cluster_id)

        # tenants.clusters is a JSON array, not a cluster_id column, so prune it separately: drop the
        # deleted cluster from every tenant's assigned-clusters list, else the tenant's "N clusters"
        # badge stays stale and a reused 8-char id could re-inherit that grant.
        try:
            from pegaprox.utils.rbac import load_tenants, save_tenants
            import pegaprox.utils.rbac as _rbac
            _tenants = load_tenants()
            _changed = False
            for _t in _tenants.values():
                _cl = _t.get('clusters') or []
                if cluster_id in _cl:
                    _t['clusters'] = [c for c in _cl if c != cluster_id]
                    _changed = True
            if _changed:
                save_tenants(_tenants)
                # the cluster just left this tenant — drop rbac's cached copy so
                # get_user_clusters stops handing it out
                invalidate_tenants_cache()
        except Exception as _te:
            logging.error(f"Failed to prune deleted cluster {cluster_id} from tenants: {_te}")

        logging.info(f"Deleted cluster {cluster_id} and related data from database")
    except Exception as e:
        logging.error(f"Failed to delete cluster from database: {e}")
    
    log_audit(request.session['user'], 'cluster.deleted', f"Deleted cluster: {cluster_name}"
              + (f" (our cluster claim: {claim.get('state')})" if claim else ''))

    result = {'message': 'Cluster deleted successfully'}
    if claim:
        # the cluster is gone from here either way; what is left on it has to be said
        result['claim'] = claim
        if claim.get('warning'):
            result['warning'] = claim['warning']
    return jsonify(result)


@bp.route('/api/clusters/reorder', methods=['POST'])
@require_auth(perms=['cluster.config'])
def reorder_clusters():
    """Update cluster sort order for sidebar display
    
    NS: Allows admins to reorder clusters via drag-and-drop in UI
    Request body: { "order": ["cluster_id_1", "cluster_id_2", ...] }
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'Body must be an object'}), 400
    # MK Sep 2026 - this ran one UPDATE per element of a caller-supplied array inside a
    # single transaction, with nothing bounding the array. And it reordered by id without
    # asking whose cluster that is; sidebar order is cosmetic, but it is still somebody
    # else's row.
    order, _lerr = bounded_list(data.get('order'), max_items=512, max_length=64,
                                name='order')
    if _lerr:
        return jsonify({'error': _lerr}), 400
    if not order:
        return jsonify({'error': 'No order provided'}), 400

    _own = get_user_clusters(build_authz_user(request.session.get('user', ''), request.session))
    if _own is not None:
        order = [c for c in order if c in _own]
        if not order:
            return jsonify({'error': 'No order provided'}), 400

    db = get_db()
    cursor = db.conn.cursor()
    
    try:
        for idx, cluster_id in enumerate(order):
            cursor.execute(
                'UPDATE clusters SET sort_order = ? WHERE id = ?',
                (idx, cluster_id)
            )
        db.conn.commit()
        
        log_audit(request.session['user'], 'cluster.reordered', f"Reordered {len(order)} clusters")
        
        return jsonify({'message': 'Cluster order updated', 'order': order})
    except Exception as e:
        logging.error(f"Failed to reorder clusters: {e}")
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/sort-order', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def update_cluster_sort_order(cluster_id):
    """Update a single cluster's sort order

    Request body: { "sort_order": 5 }
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'Body must be an object'}), 400
    # MK Sep 2026 - this went to the DB unchecked, and GET /api/clusters sorts on the
    # column. One string in one row and the cluster list raises TypeError comparing str
    # to int - for everybody, durably, until somebody finds the row. bool is excluded on
    # purpose: it is an int subclass and `True` is not a position.
    _raw = data.get('sort_order', 0)
    if isinstance(_raw, bool) or not isinstance(_raw, int):
        return jsonify({'error': 'sort_order must be an integer'}), 400
    if not (-100000 <= _raw <= 100000):
        return jsonify({'error': 'sort_order is out of range'}), 400
    sort_order = _raw

    db = get_db()
    cursor = db.conn.cursor()

    try:
        cursor.execute(
            'UPDATE clusters SET sort_order = ? WHERE id = ?',
            (sort_order, cluster_id)
        )
        db.conn.commit()

        return jsonify({'message': 'Sort order updated', 'sort_order': sort_order})
    except Exception as e:
        logging.error(f"Failed to update sort order: {e}")
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500


# MK May 2026 — Worldmap location (per-cluster).
# Body: { "latitude": 50.1109, "longitude": 8.6821, "location_label": "Frankfurt DC1" }
# Pass `null` for lat+lon to remove the dot from the map.
#
# MK May 2026 — light per-IP+per-cluster rate limit. Authenticated users with
# cluster.config could otherwise hammer this endpoint to flood the HMAC-signed
# audit log (each location update writes one entry). 30 updates/min is way more
# than any legitimate UI flow needs — operators set lat/lon once and move on.
from pegaprox.utils.ratelimit import SlidingWindow as _SlidingWindow

# keyed by (ip, cluster_id): the IP half is caller-chosen, so this needs a ceiling
_location_put_attempts = _SlidingWindow(limit=30, window=60, max_keys=4096, name='cluster-location')


@bp.route('/api/clusters/<cluster_id>/location', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def update_cluster_location(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    # rate-limit per (IP, cluster) — 30 updates / 60s window
    from pegaprox.utils.audit import get_client_ip
    import time as _t
    client_ip = get_client_ip()
    if not _location_put_attempts.allow((client_ip, cluster_id)):
        logging.warning(f"[CLUSTER-LOC] rate-limited update on {cluster_id} from {client_ip}")
        return jsonify({'error': 'Too many location updates — slow down'}), 429

    data = request.get_json() or {}
    lat = data.get('latitude')
    lon = data.get('longitude')

    # MK May 2026 — strict type check before float() cast. Python's bool subclasses
    # int, so `float(True)` is 1.0 — would pass range check and silently set lat=1.
    # Also reject dict / list / bytes which could slip through some serializers.
    if lat is not None and (isinstance(lat, bool) or not isinstance(lat, (int, float))):
        return jsonify({'error': 'latitude must be a number'}), 400
    if lon is not None and (isinstance(lon, bool) or not isinstance(lon, (int, float))):
        return jsonify({'error': 'longitude must be a number'}), 400

    # MK May 2026 — label sanitisation: strip control chars + collapse internal
    # whitespace + cap length. Newlines/CR in audit-log details would let an
    # operator forge multi-line audit entries that look like separate events
    # to a naive log reader. Defense-in-depth.
    raw_label = data.get('location_label') or ''
    if not isinstance(raw_label, str):
        return jsonify({'error': 'location_label must be a string'}), 400
    # remove ASCII control chars (0x00-0x1F + 0x7F) including \n \r \t \0
    label = ''.join(ch for ch in raw_label if ord(ch) >= 0x20 and ord(ch) != 0x7F)
    label = label.strip()[:120]

    # both lat+lon must be set together, OR both null to clear the dot
    if (lat is None) != (lon is None):
        return jsonify({'error': 'latitude and longitude must be set together (or both null)'}), 400
    if lat is not None:
        try:
            lat = float(lat)
            lon = float(lon)
        except (TypeError, ValueError):
            return jsonify({'error': 'latitude/longitude must be numeric'}), 400
        # also catches NaN/Inf since the comparison returns False for those
        if not (-90.0 <= lat <= 90.0):
            return jsonify({'error': 'latitude must be between -90 and 90'}), 400
        if not (-180.0 <= lon <= 180.0):
            return jsonify({'error': 'longitude must be between -180 and 180'}), 400

    db = get_db()
    cursor = db.conn.cursor()
    try:
        from datetime import datetime as _dt
        cursor.execute(
            'UPDATE clusters SET latitude = ?, longitude = ?, location_label = ?, updated_at = ? WHERE id = ?',
            (lat, lon, label, _dt.now().isoformat(), cluster_id)
        )
        db.conn.commit()
        # mirror into in-memory config so the next /api/clusters GET reflects it
        mgr = cluster_managers[cluster_id]
        mgr.config.latitude = lat
        mgr.config.longitude = lon
        mgr.config.location_label = label

        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'cluster.location_updated',
                  f"Cluster '{mgr.config.name}' location set to {lat},{lon} ({label or '—'})")
        return jsonify({'message': 'Location updated',
                        'latitude': lat, 'longitude': lon, 'location_label': label})
    except Exception as e:
        logging.error(f"Failed to update cluster location: {e}")
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/metrics', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_metrics(cluster_id):
    """Get cluster node metrics
    
    NS: Made more resilient - returns cached/HA data if connection fails
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    # Try to get live metrics
    if mgr.is_connected:
        try:
            metrics = mgr.get_node_status()
            if metrics:
                # Cache the metrics
                mgr._cached_metrics = metrics
                # MK Oct 2026 - a node in maintenance names its guests: not to a confined caller
                return jsonify(node_maintenance_for_caller(cluster_id, metrics))
        except Exception as e:
            logging.debug(f"Error getting metrics for {cluster_id}: {e}")
    
    # If live data failed, try cached data
    if hasattr(mgr, '_cached_metrics') and mgr._cached_metrics:
        return jsonify(node_maintenance_for_caller(cluster_id, mgr._cached_metrics))
    
    # If HA is tracking nodes, build metrics from HA data
    if mgr.ha_node_status:
        ha_metrics = {}
        for name, data in mgr.ha_node_status.items():
            ha_metrics[name] = {
                'status': data.get('status', 'unknown'),
                'cpu': 0,
                'memory': {'used': 0, 'total': 0},
                'disk': {'used': 0, 'total': 0},
                'from_ha_cache': True
            }
        return jsonify(ha_metrics)
    
    # Return error with empty metrics - frontend will keep old data
    return jsonify({'error': 'Connection temporarily unavailable', 'offline': True}), 503


# MK Oct 2026 (#946) - the health pill polls from every open tab, so the storage part of the
# score is shared per cluster for a short while instead of being fetched per request.
_HEALTH_STORAGE_TTL = 30
_health_storage_cache = StorageDataCache()


def cluster_storage_resources(cluster_id, mgr):
    """Every storage on every node of a Proxmox cluster as /cluster/resources?type=storage
    lists it, or None when the read failed (not cached, so the next caller tries again).
    The health check and the storage overview share one read per cluster for the TTL."""
    rows, hit = _health_storage_cache.get(cluster_id, 'resources')
    if hit:
        return rows
    # /nodes/<n>/storage builds live status for every storage one after another, a login
    # per PBS datastore, seconds per node. /cluster/resources is served from pvestatd's cache
    # and covers all nodes in one call. Storages of offline nodes come back 'unknown'.
    url = f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/resources?type=storage"
    r = mgr._api_get(url, timeout=8)
    if r is None or r.status_code != 200:
        return None
    rows = [s for s in (r.json().get('data') or []) if isinstance(s, dict)]
    _health_storage_cache.set(cluster_id, 'resources', rows, ttl_seconds=_HEALTH_STORAGE_TTL)
    return rows


def _health_storage_rows(cluster_id, mgr, ns):
    """(node, storage, used, total) for every active storage, or None when the lookup failed
    (not cached, so the next poll tries again)."""
    if getattr(mgr, 'cluster_type', 'proxmox') == 'proxmox':
        rows = cluster_storage_resources(cluster_id, mgr)
        if rows is None:
            return None
        return [(s.get('node') or '?', s.get('storage') or '?', s.get('disk') or 0, s.get('maxdisk') or 0)
                for s in rows if s.get('status') == 'available']

    # XCP-ng has no cluster-wide storage view, keep the per-node listing.
    # MK 2026-05-31 (F1a) - parallel fanout, ONLINE nodes only: a dead node's
    # storage call would otherwise park the whole batch at the gevent-pool
    # timeout. (D2) node names are checked before they go into a URL.
    from pegaprox.utils.concurrent import run_concurrent_dict
    _SAFE_NODE = re.compile(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$')
    online_node_names = [
        name for name, d in ns.items()
        if (d.get('status') in ('online', 'running') or not d.get('offline'))
        and name and _SAFE_NODE.match(name)
    ]
    if not online_node_names:
        return []
    tasks = {n: (lambda nn=n: mgr.get_storage_list(nn) or []) for n in online_node_names}
    rows = []
    for node_name, stors in run_concurrent_dict(tasks, timeout=8).items():
        for s in (stors or []):
            if s.get('active'):
                rows.append((node_name, s.get('storage', '?'), s.get('used') or 0, s.get('total') or 0))
    return rows


# NS May 2026 — single-number cluster health score (0-100). Inputs are cheap-to-compute
# stuff we already pull elsewhere: node status, per-node storages, replication, backup-SLA.
# The drill-down list lets the user see what dragged the score down.
@bp.route('/api/clusters/<cluster_id>/health', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_health(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    score = 100
    factors = []
    issues = []

    # Connectivity gate — if API isn't reachable, everything else is moot
    if not mgr.is_connected:
        return jsonify({
            'score': 0,
            'band': 'critical',
            'factors': [{'key': 'api', 'label': 'API connectivity', 'value': 'disconnected', 'delta': -100}],
            'issues': ['Cluster API not reachable'],
            'computed_at': None,
        })

    # 1) Nodes online
    try:
        ns = mgr.get_node_status() or {}
    except Exception:
        ns = {}
    total_nodes = len(ns)
    online_nodes = sum(1 for n in ns.values() if (n.get('status') in ('online', 'running') or not n.get('offline')))
    if total_nodes:
        offline = total_nodes - online_nodes
        delta = -25 * offline
        score += delta
        factors.append({
            'key': 'nodes', 'label': 'Nodes online',
            'value': f'{online_nodes}/{total_nodes}', 'delta': delta,
            'severity': 'critical' if offline else 'ok',
        })
        if offline:
            offline_names = [name for name, d in ns.items()
                             if d.get('status') == 'offline' or d.get('offline')]
            issues.append(f'{offline} node(s) offline: {", ".join(offline_names) or "?"}')

    # 2) Storage pressure — worst-offender across all nodes
    worst_pct = 0.0
    worst_label = None
    try:
        rows, hit = _health_storage_cache.get(cluster_id, 'storage')
        if not hit:
            rows = _health_storage_rows(cluster_id, mgr, ns)
            if rows is not None:
                _health_storage_cache.set(cluster_id, 'storage', rows, ttl_seconds=_HEALTH_STORAGE_TTL)
        for node_name, stor_name, used, total in (rows or []):
            if total <= 0:
                continue
            pct = (used / total) * 100.0
            if pct > worst_pct:
                worst_pct = pct
                worst_label = f"{stor_name} @ {node_name}"
    except Exception as e:
        logging.debug(f"[health] storage scan failed: {e}")
    if worst_label is not None:
        if worst_pct >= 95:
            d = -25
        elif worst_pct >= 90:
            d = -15
        elif worst_pct >= 80:
            d = -5
        else:
            d = 0
        score += d
        factors.append({
            'key': 'storage', 'label': 'Worst storage',
            'value': f'{worst_label} ({worst_pct:.0f}%)', 'delta': d,
            'severity': 'critical' if worst_pct >= 95 else 'warning' if worst_pct >= 80 else 'ok',
        })
        if worst_pct >= 90:
            issues.append(f'Storage near full: {worst_label} at {worst_pct:.0f}%')

    # 3) Replication — failed jobs hurt
    try:
        repl = mgr.get_replication_status() or []
    except Exception:
        repl = []
    if repl:
        # PVE flags failures via 'fail_count' or non-zero error
        failed = sum(1 for r in repl if (r.get('fail_count') or 0) > 0 or r.get('error'))
        d = max(-20, -5 * failed)
        score += d
        factors.append({
            'key': 'replication', 'label': 'Replication',
            'value': f'{failed} failing / {len(repl)} jobs',
            'delta': d,
            'severity': 'warning' if failed else 'ok',
        })
        if failed:
            issues.append(f'{failed} replication job(s) failing')

    # 4) Backup-SLA — only if admin set a max-age threshold on the cluster
    try:
        db = get_db()
        row = db.conn.cursor().execute(
            "SELECT backup_sla_max_age_hours FROM clusters WHERE id = ?", (cluster_id,)
        ).fetchone()
        max_age = (dict(row).get('backup_sla_max_age_hours') if row else None) or 0
    except Exception:
        max_age = 0
    if max_age and max_age > 0:
        # Pull the most-recent backup timestamp via cluster/backup-info — cheap call
        try:
            import time as _t
            now = _t.time()
            url = f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/backup-info/not-backed-up"
            r = mgr._api_get(url)
            stale = 0
            if r is not None and r.status_code == 200:
                stale = len(r.json().get('data') or [])
            d = -10 if stale else 0
            score += d
            factors.append({
                'key': 'backup_sla', 'label': 'Backup SLA',
                'value': f'{stale} VM(s) past RPO ({max_age}h)' if stale else 'within RPO',
                'delta': d,
                'severity': 'warning' if stale else 'ok',
            })
            if stale:
                issues.append(f'{stale} VMs past backup RPO of {max_age}h')
        except Exception as e:
            logging.debug(f"[health] backup-sla check failed: {e}")

    # Clamp & band
    score = max(0, min(100, score))
    if score >= 90:
        band = 'excellent'
    elif score >= 70:
        band = 'good'
    elif score >= 50:
        band = 'warning'
    elif score >= 30:
        band = 'degraded'
    else:
        band = 'critical'

    import datetime as _dt
    return jsonify({
        'score': score,
        'band': band,
        'factors': factors,
        'issues': issues,
        'computed_at': _dt.datetime.utcnow().isoformat() + 'Z',
    })


# MK May 2026 — API latency dashboard backing endpoint. Reads the deque the
# manager populates on every Proxmox API roundtrip. Cheap: in-memory only.
@bp.route('/api/clusters/<cluster_id>/api-latency', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_api_latency(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]
    samples = list(getattr(mgr, '_api_latency', []) or [])
    if not samples:
        return jsonify({
            'samples': 0,
            'p50': 0, 'p95': 0, 'p99': 0, 'avg': 0, 'max': 0,
            'error_rate': 0,
            'recent': [],
            'by_endpoint': [],
        })

    # window: only consider last 5 min for headline stats; recent for sparkline
    import time as _t
    now = _t.time()
    window = [s for s in samples if (now - s.get('ts', 0)) <= 300]
    if not window:
        window = samples[-50:]

    durations = sorted(s['duration_ms'] for s in window)
    n = len(durations)
    def pct(q):
        idx = max(0, min(n - 1, int(n * q)))
        return round(durations[idx], 1)
    avg = round(sum(durations) / n, 1)
    mx = round(durations[-1], 1)
    errs = sum(1 for s in window if (s.get('status') or 0) >= 400 or s.get('status') == 0)

    by_ep = {}
    for s in window:
        ep = s.get('endpoint') or '?'
        e = by_ep.setdefault(ep, {'endpoint': ep, 'count': 0, 'total_ms': 0.0,
                                   'max_ms': 0.0, 'errors': 0})
        d = float(s.get('duration_ms') or 0)
        e['count'] += 1
        e['total_ms'] += d
        if d > e['max_ms']:
            e['max_ms'] = d
        if (s.get('status') or 0) >= 400 or s.get('status') == 0:
            e['errors'] += 1
    by_ep_list = sorted(by_ep.values(), key=lambda x: -x['total_ms'])[:12]
    for e in by_ep_list:
        e['avg_ms'] = round(e['total_ms'] / e['count'], 1)
        e['max_ms'] = round(e['max_ms'], 1)
        e['total_ms'] = round(e['total_ms'], 1)

    # last ~30 samples for sparkline
    recent = [{'ts': s['ts'], 'duration_ms': round(s['duration_ms'], 1),
               'status': s.get('status', 0), 'method': s.get('method', '?')}
              for s in samples[-30:]]

    return jsonify({
        'samples': n,
        'window_seconds': 300,
        'p50': pct(0.5), 'p95': pct(0.95), 'p99': pct(0.99),
        'avg': avg, 'max': mx,
        'error_rate': round((errs / n) * 100.0, 1) if n else 0,
        'recent': recent,
        'by_endpoint': by_ep_list,
    })


@bp.route('/api/clusters/<cluster_id>/resources', methods=['GET'])
@require_auth()
def get_cluster_resources(cluster_id):
    """Get cluster VM resources - filtered by VM ACLs
    
    NS: Dec 2025 - Now filters based on VM-specific ACLs
    Admin sees all VMs, others see only VMs they have access to
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster not connected', 'offline': True}), 503
    
    # get all resources — NS Jul 2026 (SSE-perf): reuse the 1s broadcast loop's
    # fresh snapshot (max_age) instead of firing another /cluster/resources walk;
    # this endpoint is polled 15s (selected) + 30s (overview) + per expanded sidebar
    # cluster, so the same heavy walk was happening 2-3x per window per cluster.
    all_resources = mgr.get_vm_resources(max_age=6)

    # NS Aug 2026 — build the authz user so an admin-owned scoped API token is floored to its
    # effective_role (the stored-role fast-path let such a token see everything).
    from pegaprox.utils.rbac import user_can_access_vm as _ucav
    from pegaprox.utils.auth import build_authz_user
    user = build_authz_user(request.session['user'], request.session)
    user['username'] = request.session['user']
    from pegaprox.utils.rbac import acts_as_admin
    if acts_as_admin(user):
        return jsonify(all_resources)

    # Aikido 469089182 re-verify — the RESTRICTIVE ACL listing below (an ACL'd VM is hidden from
    # non-whitelisted TENANT operators; a no-ACL VM stays visible via role-level vm.view) is correct
    # ONLY for a caller whose tenant actually OWNS this cluster. A caller who reached it via a #555
    # pool / #248 ACL fallback (tenant does NOT own it) must NOT get that blanket vm.view fallback —
    # confine them to exactly the VMs their pool/ACL grants, via user_can_access_vm (which enforces
    # the tenant gate). None => admin/default-tenant (unscoped).
    # MK Sep 2026 (#773, mbo-nw) — a caller with an explicit POOL grant is confined to their pool's
    # (+ any ACL'd) VMs even on a cluster their tenant owns. The restrictive-ACL listing below would
    # otherwise fall a pool-scoped operator through to the blanket vm.view branch and hand back the
    # WHOLE cluster, while the portal (get_user_pool_vmids) shows only that pool's members — a
    # portal-only user querying /resources directly saw every VM + template. Route pool-scoped
    # callers, like non-owners, through the same per-VM user_can_access_vm check (which confines
    # them to exactly their ACL + pool VMs), so the list matches per-VM access. Pure operators with no
    # pool/ACL grant keep the restrictive tenant-owner listing below unchanged.
    # sec (private disclosure Sep 2026): this predicate was open-coded here as
    # `(not owner) or user_has_any_pool_access(...)`, which asks about POOL grants only. A caller
    # whose tenant OWNS the cluster and who is confined by a VM-ACL instead of a pool has neither
    # condition true, so they fell past this into the restrictive listing below — where the
    # `elif has_general_view` arm hands back every VM that has no ACL entry of its own. helpers
    # .caller_is_scoped was written for exactly this miss and the other endpoints moved onto it;
    # this one kept its copy. Use the shared predicate so the two cannot drift again.
    from pegaprox.api.helpers import caller_is_scoped as _scoped
    if _scoped(user, cluster_id):
        filtered = []
        for vm in all_resources:
            _vmid = vm.get('vmid')
            if _vmid is None:
                continue
            try:
                if _ucav(user, cluster_id, int(_vmid), 'vm.view', vm.get('type')):
                    filtered.append(vm)
            except Exception:
                continue
        return jsonify(filtered)

    # LW: Filter VMs based on ACLs - only show VMs user can access (tenant-owner, restrictive listing)
    acls = get_vm_acls()
    cluster_acls = acls.get(cluster_id, {})

    # if no ACLs defined for this cluster, check if user has general vm.view permission
    if not cluster_acls:
        if has_permission(user, 'vm.view'):
            return jsonify(all_resources)
        else:
            return jsonify([])  # no vm.view permission and no ACLs

    # filter resources - show VMs user has ACL access to OR general vm.view permission
    filtered = []
    has_general_view = has_permission(user, 'vm.view')

    for vm in all_resources:
        vmid = str(vm.get('vmid', ''))
        vm_acl = cluster_acls.get(vmid, {})

        if vm_acl:
            # VM has specific ACL - check if user is in whitelist
            allowed_users = vm_acl.get('users', [])
            if user['username'] in allowed_users or '*' in allowed_users:
                filtered.append(vm)
        elif has_general_view:
            # No specific ACL but user has general view permission
            filtered.append(vm)

    return jsonify(filtered)

# NS: Feb 2026 - SECURITY: explicit allowlist prevents mass assignment attacks
# Password/key changes must go through dedicated endpoints with their own auth
# MK: also keeps 'sort_order' out because that was causing issues with drag-and-drop
# MK Oct 2026 (#625) - 'ha_settings' is out as well. It was taken as it came and stored
# whole: cluster.config (an API token too) could switch the cluster claim and the unsafe
# two-node recovery on past their own routes, and the same request dropped the agent
# token and what the agent installs had recorded. The HA routes write those settings.
# 'user' is out too: it is half of the credential. Editing it alone turned a token cluster
# ('user@realm!tokenid' + the token secret in pass_) into an account cluster whose SSH
# password was that secret, offered to every node. /reconfigure changes both together.
ALLOWED_CONFIG_FIELDS = {
    'name', 'host', 'ssl_verification', 'migration_threshold', 'migration_tolerance',
    'migration_cooldown',  # MK Oct 2026 - seconds the balancer leaves a moved guest alone
    'check_interval', 'auto_migrate', 'balance_containers', 'balance_local_disks',
    'dry_run', 'enabled', 'ha_enabled', 'fallback_hosts', 'ssh_user', 'ssh_port',
    'excluded_nodes',
    'predictive_balancing', 'predictive_threshold',
    'balance_cpu_weight', 'balance_mem_weight', 'balance_io_weight',
    'cpu_baseline',
    'vnc_tunnel',  # MK Apr 2026 — SSH-tunnel-mode for VNC console
    'ssh_disabled',  # MK Sep 2026 (#941) — no SSH to this cluster's nodes at all
    'proxlb_tags_enabled',  # MK Jul 2026 (#426) — derive placement from ProxLB VM tags
    'proxlb_pins_auto_migrate',  # opt-in: migrate guests back onto their plb_pin_ node
    'proxlb_pins_strict',  # opt-in: a pin also vetoes a maintenance evacuation
    'node_ui_suffix',  # MK Aug 2026 (#689) — FQDN suffix for "Open in Proxmox" node links
    'transfer_network',  # MK Oct 2026 - CIDR for remote migrations into this cluster
}

# These persist as INTEGER (db.py save_cluster) and reload through bool(), so a
# truthy string like "false" would round-trip back to True and silently flip an
# opt-in on. Only a real bool is accepted for them, no bool() coercion.
BOOLEAN_CONFIG_FIELDS = {'proxlb_pins_auto_migrate', 'proxlb_pins_strict'}


def _cooldown_error(data):
    """A 400 when the body sets migration_cooldown to anything but whole seconds in
    range. Checked before any field is applied, like the booleans above."""
    if 'migration_cooldown' not in data:
        return None
    value = data['migration_cooldown']
    if isinstance(value, bool) or not isinstance(value, int) \
            or not BALANCER_COOLDOWN_MIN <= value <= BALANCER_COOLDOWN_MAX:
        return jsonify({'error': f"'migration_cooldown' must be whole seconds from "
                                 f"{BALANCER_COOLDOWN_MIN} to {BALANCER_COOLDOWN_MAX}"}), 400
    return None


def _transfer_network_error(data, mgr=None):
    """A 400 when the body sets transfer_network to anything but a network in CIDR
    notation or empty, or sets one on a cluster that is no Proxmox VE cluster. Normalises
    it in place (10.20.0.5/24 is 10.20.0.0/24)."""
    if 'transfer_network' not in data:
        return None
    from pegaprox.core.transfer_net import normalize
    cidr, err = normalize(data['transfer_network'])
    if err:
        return jsonify({'error': err}), 400
    kind = getattr(mgr, 'cluster_type', None) if mgr is not None else data.get('cluster_type', 'proxmox')
    if cidr and (kind or 'proxmox') != 'proxmox':
        return jsonify({'error': 'transfer_network applies to Proxmox VE clusters only'}), 400
    data['transfer_network'] = cidr
    return None


def _ssh_user_error(data):
    """A 400 when the body names an ssh_user that is no login name. Normalises it in
    place; empty means the default user."""
    if 'ssh_user' not in data:
        return None
    user = data.get('ssh_user')
    user = user.strip() if isinstance(user, str) else user
    if user not in (None, '') and not validate_ssh_user(user):
        return jsonify({'error': 'ssh_user must be a user name: letters, digits and ._- only, '
                                 'not starting with - or .'}), 400
    data['ssh_user'] = user or ''
    return None


def _host_key(h):
    return str(h or '').strip().strip('[]').lower()


# NS Oct 2026 - the stored password or token secret goes to the cluster's host and fallback
# hosts on every reconnect and console ticket mint, over TLS verified or not as the cluster
# says. An edit that adds an address, changes the SSH port or turns verification off moves
# that credential, so like PBS and the ESXi servers it needs the credential typed again,
# and a stored secret nobody re-entered is dropped instead of carried along.
def _config_edit_checks(mgr, data):
    """Check a cluster config edit. Returns (error, rebind): error is a response to hand
    back as it is; rebind is None when the credential stays where it was, else
    {'creds': what this request typed, 'moved': which fields moved it}.
    ssh_user, ssh_port, host and fallback_hosts are normalised in place."""
    cfg = mgr.config
    err = _ssh_user_error(data)
    if err:
        return err, None

    def bad(msg):
        return (jsonify({'error': msg}), 400), None

    known = set()
    if 'host' in data or 'fallback_hosts' in data:
        known = {_host_key(cfg.host)} | {_host_key(h) for h in (getattr(cfg, 'fallback_hosts', None) or [])}
    moved = []
    if 'host' in data:
        host = data.get('host')
        if not isinstance(host, str) or not host.strip():
            return bad('host must be a host name or an IP address')
        data['host'] = host = host.strip()
        if _host_key(host) != _host_key(cfg.host):
            if not validate_host_address(host):
                return bad('host must be a host name or an IP address')
            if _host_key(host) not in known:
                moved.append('host')
    if 'fallback_hosts' in data:
        hosts, lerr = bounded_list(data.get('fallback_hosts'), max_items=32, max_length=253,
                                   name='fallback_hosts')
        if lerr:
            return bad(lerr)
        data['fallback_hosts'] = hosts
        new = [h for h in hosts if _host_key(h) not in known]
        if any(not validate_host_address(h) for h in new):
            return bad('fallback_hosts entries must be host names or IP addresses')
        if new:
            moved.append('fallback_hosts')
    if data.get('ssh_port') in (None, ''):
        data.pop('ssh_port', None)
    if 'ssh_port' in data:
        port = data.get('ssh_port')
        if isinstance(port, bool) or not str(port).strip().isdigit() or not 1 <= int(port) <= 65535:
            return bad('ssh_port must be a port number')
        data['ssh_port'] = int(port)
        try:
            old_port = int(getattr(cfg, 'ssh_port', 22) or 22)
        except (TypeError, ValueError):
            old_port = 22
        if data['ssh_port'] != old_port:
            moved.append('ssh_port')
    if 'ssl_verification' in data and getattr(cfg, 'ssl_verification', False) \
            and not data.get('ssl_verification'):
        moved.append('ssl_verification')
    if not moved:
        return None, None

    def typed(key):
        return isinstance(data.get(key), str) and data[key] not in ('', '********')

    token_user = getattr(cfg, 'api_token_user', '') or ''
    creds = {'pass_': data['pass'] if typed('pass') else '',
             'api_token_user': '', 'api_token_secret': ''}
    if token_user and typed('api_token_secret'):
        creds.update(api_token_user=token_user, api_token_secret=data['api_token_secret'])
    if not creds['pass_'] and not creds['api_token_secret']:
        return (jsonify({'error': 'Re-enter the cluster password (pass) or the API token secret '
                                  '(api_token_secret) to change ' + ', '.join(moved) + '.',
                         'code': 'CREDENTIAL_REQUIRED'}), 400), None
    return None, {'creds': creds, 'moved': moved}


def _rebind(mgr, rebind):
    """Swap in the credential the request typed and forget the login of the old
    destination, so the next call logs in afresh where the admin pointed it."""
    for key, value in rebind['creds'].items():
        setattr(mgr.config, key, value)
    for attr in ('_ticket', '_csrf_token', '_api_token', '_original_host'):
        if hasattr(mgr, attr):
            setattr(mgr, attr, None)
    mgr.current_host = None
    mgr.is_connected = False
    reset = getattr(mgr, '_reset_auth_failures', None)
    if callable(reset):
        reset()


@bp.route('/api/clusters/<cluster_id>', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def update_cluster_config(cluster_id):
    """Update cluster configuration"""
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json
    if not isinstance(data, dict):
        return jsonify({'error': 'Expected a JSON object'}), 400
    mgr = cluster_managers[cluster_id]

    # Reject non-boolean pin flags before any assignment, so a partial apply
    # can't leave mgr.config half-mutated.
    for _bk in BOOLEAN_CONFIG_FIELDS:
        if _bk in data and type(data[_bk]) is not bool:
            return jsonify({'error': f"'{_bk}' must be a boolean"}), 400
    _cd_err = _cooldown_error(data)
    if _cd_err:
        return _cd_err
    _xn_err = _transfer_network_error(data, mgr)
    if _xn_err:
        return _xn_err
    _err, rebind = _config_edit_checks(mgr, data)
    if _err:
        return _err
    if rebind:
        _rebind(mgr, rebind)

    # update config - only allowed fields
    updated = []
    for key, value in data.items():
        if key in ALLOWED_CONFIG_FIELDS and hasattr(mgr.config, key):
            old = getattr(mgr.config, key)
            setattr(mgr.config, key, value)
            updated.append(key)

    save_config()

    usr = getattr(request, 'session', {}).get('user', 'system')
    if rebind:
        log_audit(usr, 'cluster.endpoint_changed', f"Cluster {mgr.config.name}: "
                  f"{', '.join(rebind['moved'])} changed with the credential re-entered")
    log_audit(usr, 'cluster.config_changed', f"Cluster {mgr.config.name} config updated: {', '.join(updated)}")

    return jsonify({'message': 'Configuration updated successfully', 'updated_fields': updated})

@bp.route('/api/clusters/<cluster_id>/config', methods=['PATCH'])
@require_auth(perms=['cluster.config'])
def update_cluster_config_live(cluster_id):
    """Update cluster configuration without restart"""
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json
    if not isinstance(data, dict):
        return jsonify({'error': 'Expected a JSON object'}), 400
    mgr = cluster_managers[cluster_id]

    # Reject non-boolean pin flags before any assignment, so a partial apply
    # can't leave mgr.config half-mutated.
    for _bk in BOOLEAN_CONFIG_FIELDS:
        if _bk in data and type(data[_bk]) is not bool:
            return jsonify({'error': f"'{_bk}' must be a boolean"}), 400
    _cd_err = _cooldown_error(data)
    if _cd_err:
        return _cd_err
    _xn_err = _transfer_network_error(data, mgr)
    if _xn_err:
        return _xn_err
    _err, rebind = _config_edit_checks(mgr, data)
    if _err:
        return _err
    if rebind:
        _rebind(mgr, rebind)

    updated = []
    for key, value in data.items():
        if key in ALLOWED_CONFIG_FIELDS and hasattr(mgr.config, key):
            setattr(mgr.config, key, value)
            updated.append(key)

    save_config()
    usr = getattr(request, 'session', {}).get('user', 'system')
    if rebind:
        log_audit(usr, 'cluster.endpoint_changed',
                  f"Cluster {mgr.config.name}: {', '.join(rebind['moved'])} changed with the "
                  f"credential re-entered")
    # MK Oct 2026 - the settings tab saves through here, and nothing of it reached the audit log
    if updated:
        log_audit(usr, 'cluster.config_changed', f"Cluster {mgr.config.name} config updated: "
                  f"{', '.join(updated)}")

    return jsonify({'message': 'Configuration updated successfully', 'updated_fields': updated})


@bp.route('/api/clusters/<cluster_id>/cpu-compatibility', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cpu_compatibility(cluster_id):
    """CPU compatibility matrix for EVC-like migration safety"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    try:
        matrix = mgr._get_cpu_compatibility_matrix()
        return jsonify(matrix)
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/clusters/<cluster_id>/predictive-analysis', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_predictive_analysis(cluster_id):
    """Get predictive load analysis for all nodes"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    result = mgr.get_predictive_analysis()
    return jsonify({
        'nodes': result,
        'enabled': getattr(mgr.config, 'predictive_balancing', False),
        'threshold': getattr(mgr.config, 'predictive_threshold', 75),
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_excluded_nodes(cluster_id):
    """Get list of nodes excluded from balancing
    
    NS: Feature request - allow excluding specific nodes from VM balancing
    Similar to ProxLB's exclude hosts feature
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    excluded = getattr(mgr.config, 'excluded_nodes', []) or []
    
    return jsonify({
        'excluded_nodes': excluded,
        'cluster_id': cluster_id
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def set_excluded_nodes(cluster_id):
    """Set list of nodes excluded from balancing
    
    NS: Feature request - allow excluding specific nodes from VM balancing
    Request body: { "excluded_nodes": ["node1", "node2"] }
    
    Excluded nodes will:
    - NOT be targets for automatic VM balancing
    - NOT be targets for balancing-related live migrations
    - NOT be included in balancing score calculations
    
    Note: Manual migrations TO excluded nodes are still allowed
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.get_json() or {}
    excluded_nodes = data.get('excluded_nodes', [])
    
    # same shape as fallback_hosts above: durable, reloaded at start, previously unbounded
    excluded_nodes, _lerr = bounded_list(excluded_nodes, max_items=512, max_length=253,
                                         name='excluded_nodes')
    if _lerr:
        return jsonify({'error': _lerr}), 400
    
    mgr = cluster_managers[cluster_id]
    mgr.config.excluded_nodes = excluded_nodes
    
    # Save to database
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute(
            'UPDATE clusters SET excluded_nodes = ? WHERE id = ?',
            (json.dumps(excluded_nodes), cluster_id)
        )
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to save excluded_nodes: {e}")
        return jsonify({'error': safe_error(e, 'Database operation failed')}), 500
    
    log_audit(request.session['user'], 'cluster.excluded_nodes_changed', 
              f"Cluster {mgr.config.name}: excluded nodes set to {excluded_nodes}")
    
    return jsonify({
        'success': True,
        'excluded_nodes': excluded_nodes,
        'message': f'{len(excluded_nodes)} node(s) excluded from balancing'
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes/<node>', methods=['POST'])
@require_auth(perms=['cluster.config'])
def add_excluded_node(cluster_id, node):
    """Add a single node to the exclusion list"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    excluded = getattr(mgr.config, 'excluded_nodes', []) or []
    
    if node not in excluded:
        excluded.append(node)
        mgr.config.excluded_nodes = excluded
        
        # Save to database
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute(
                'UPDATE clusters SET excluded_nodes = ? WHERE id = ?',
                (json.dumps(excluded), cluster_id)
            )
            db.conn.commit()
        except Exception as e:
            logging.error(f"Failed to save excluded_nodes: {e}")
            return jsonify({'error': safe_error(e, 'Database operation failed')}), 500
        
        log_audit(request.session['user'], 'cluster.node_excluded', 
                  f"Node {node} excluded from balancing in cluster {mgr.config.name}")
    
    return jsonify({
        'success': True,
        'excluded_nodes': excluded,
        'message': f'Node {node} excluded from balancing'
    })


@bp.route('/api/clusters/<cluster_id>/excluded-nodes/<node>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def remove_excluded_node(cluster_id, node):
    """Remove a node from the exclusion list"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    excluded = getattr(mgr.config, 'excluded_nodes', []) or []
    
    if node in excluded:
        excluded.remove(node)
        mgr.config.excluded_nodes = excluded
        
        # Save to database
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute(
                'UPDATE clusters SET excluded_nodes = ? WHERE id = ?',
                (json.dumps(excluded), cluster_id)
            )
            db.conn.commit()
        except Exception as e:
            logging.error(f"Failed to save excluded_nodes: {e}")
            return jsonify({'error': safe_error(e, 'Database operation failed')}), 500
        
        log_audit(request.session['user'], 'cluster.node_included', 
                  f"Node {node} re-included in balancing for cluster {mgr.config.name}")
    
    return jsonify({
        'success': True,
        'excluded_nodes': excluded,
        'message': f'Node {node} re-included in balancing'
    })


# ============================================
# Excluded VMs from Balancing API
# MK: VMs that should not be auto-migrated
# ============================================

@bp.route('/api/clusters/<cluster_id>/excluded-vms', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_excluded_vms(cluster_id):
    """Get list of VMs excluded from load balancing"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        # MK: Ensure table exists (migration for existing databases)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS balancing_excluded_vms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                vmid INTEGER NOT NULL,
                reason TEXT,
                created_by TEXT,
                created_at TEXT,
                UNIQUE(cluster_id, vmid)
            )
        ''')
        
        cursor.execute(
            'SELECT vmid, reason, created_by, created_at FROM balancing_excluded_vms WHERE cluster_id = ?',
            (cluster_id,)
        )
        excluded = []
        for row in cursor.fetchall():
            excluded.append({
                'vmid': row['vmid'],
                'reason': row['reason'],
                'created_by': row['created_by'],
                'created_at': row['created_at']
            })

        # sec (private disclosure Sep 2026 — audit LOW): confine the LB-excluded list to VMs the
        # caller can access (was every excluded VM cluster-wide). Admins/plain operators keep all.
        excluded = scope_vm_rows(cluster_id, excluded)

        # Get VM names for display
        vms = mgr.get_vm_resources() if mgr.is_connected else []
        vm_names = {vm['vmid']: vm.get('name', f"VM {vm['vmid']}") for vm in vms if vm.get('vmid')}
        
        for ex in excluded:
            ex['name'] = vm_names.get(ex['vmid'], f"VM {ex['vmid']}")
        
        return jsonify({
            'excluded_vms': excluded,
            'cluster_id': cluster_id
        })
    except Exception as e:
        logging.error(f"Error getting excluded VMs: {e}")
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500


def _excluded_vm_authorized(cluster_id, vmid):
    """Per-VM gate for the balancing-exclusion writes (the read side uses scope_vm_rows)."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        return user_can_access_vm(
            build_authz_user(request.session.get('user', ''), request.session),
            cluster_id, int(vmid), 'vm.config')
    except (TypeError, ValueError):
        return False


@bp.route('/api/clusters/<cluster_id>/excluded-vms/<int:vmid>', methods=['POST'])
@require_auth(perms=['cluster.config'])
def add_excluded_vm(cluster_id, vmid):
    """Add a VM to the exclusion list for load balancing"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    # sec (audit): the GET sibling was scoped; these writes took the URL vmid on trust
    if not _excluded_vm_authorized(cluster_id, vmid):
        return jsonify({'error': 'Access denied to this VM'}), 403

    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    reason = data.get('reason', 'Manually excluded')
    user = request.session.get('user', 'system')

    if mgr.set_vm_balancing_excluded(vmid, True, reason, user):
        log_audit(user, 'cluster.vm_excluded', 
                  f"VM {vmid} excluded from balancing for cluster {mgr.config.name} (reason: {reason})")
        return jsonify({
            'success': True,
            'vmid': vmid,
            'message': f'VM {vmid} excluded from balancing'
        })
    else:
        return jsonify({'error': 'Failed to exclude VM'}), 500


@bp.route('/api/clusters/<cluster_id>/excluded-vms/<int:vmid>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def remove_excluded_vm(cluster_id, vmid):
    """Remove a VM from the exclusion list"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    if not _excluded_vm_authorized(cluster_id, vmid):
        return jsonify({'error': 'Access denied to this VM'}), 403
    
    mgr = cluster_managers[cluster_id]
    user = request.session.get('user', 'system')
    
    if mgr.set_vm_balancing_excluded(vmid, False, user=user):
        log_audit(user, 'cluster.vm_included', 
                  f"VM {vmid} re-included in balancing for cluster {mgr.config.name}")
        return jsonify({
            'success': True,
            'vmid': vmid,
            'message': f'VM {vmid} re-included in balancing'
        })
    else:
        return jsonify({'error': 'Failed to include VM'}), 500


# NS: Pool exclusion from auto-balancing
@bp.route('/api/clusters/<cluster_id>/excluded-pools', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_excluded_pools(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    mgr = cluster_managers.get(cluster_id)
    if not mgr: return jsonify({'error': 'Cluster not found'}), 404
    pools = mgr.get_balancing_excluded_pools()
    # get details from DB
    db = get_db()
    rows = db.query('SELECT pool_name, reason, created_by, created_at FROM balancing_excluded_pools WHERE cluster_id = ?', (cluster_id,)) or []
    return jsonify([dict(r) for r in rows])


@bp.route('/api/clusters/<cluster_id>/excluded-pools/<pool_name>', methods=['POST'])
@require_auth(perms=['cluster.config'])
def exclude_pool(cluster_id, pool_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    mgr = cluster_managers.get(cluster_id)
    if not mgr: return jsonify({'error': 'Cluster not found'}), 404
    data = request.json or {}
    user = getattr(request, 'session', {}).get('user', 'system')
    reason = data.get('reason', 'Manually excluded')
    if mgr.set_pool_balancing_excluded(pool_name, True, reason, user):
        log_audit(user, 'cluster.pool_excluded', f"Pool '{pool_name}' excluded from balancing")
        return jsonify({'success': True, 'message': f"Pool '{pool_name}' excluded"})
    return jsonify({'error': 'Failed'}), 500


@bp.route('/api/clusters/<cluster_id>/excluded-pools/<pool_name>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def include_pool(cluster_id, pool_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    mgr = cluster_managers.get(cluster_id)
    if not mgr: return jsonify({'error': 'Cluster not found'}), 404
    user = getattr(request, 'session', {}).get('user', 'system')
    if mgr.set_pool_balancing_excluded(pool_name, False, user=user):
        log_audit(user, 'cluster.pool_included', f"Pool '{pool_name}' re-included in balancing")
        return jsonify({'success': True, 'message': f"Pool '{pool_name}' included"})
    return jsonify({'error': 'Failed'}), 500


@bp.route('/api/clusters/<cluster_id>/fallback-hosts', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_fallback_hosts(cluster_id):
    """Get list of fallback hosts for HA"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    fallback = getattr(mgr.config, 'fallback_hosts', []) or []
    
    return jsonify({
        'fallback_hosts': fallback,
        'cluster_id': cluster_id
    })


@bp.route('/api/clusters/<cluster_id>/fallback-hosts', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def set_fallback_hosts(cluster_id):
    """Set list of fallback hosts for HA
    
    Request body: { "fallback_hosts": ["192.168.1.2", "192.168.1.3"] }
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    data = request.get_json() or {}
    fallback_hosts = data.get('fallback_hosts', [])
    
    # MK Sep 2026 - the type check was the whole validation, so one request could store
    # a million entries of a megabyte each. They are durable and get loaded back into
    # mgr.config on every start.
    fallback_hosts, _lerr = bounded_list(fallback_hosts, max_items=32, max_length=253,
                                         name='fallback_hosts')
    if _lerr:
        return jsonify({'error': _lerr}), 400
    
    mgr = cluster_managers[cluster_id]
    # a new fallback host gets the stored credential on the next reconnect
    edit = {'fallback_hosts': fallback_hosts,
            **{k: data[k] for k in ('pass', 'api_token_secret') if k in data}}
    _err, rebind = _config_edit_checks(mgr, edit)
    if _err:
        return _err
    fallback_hosts = edit['fallback_hosts']
    if rebind:
        _rebind(mgr, rebind)
    mgr.config.fallback_hosts = fallback_hosts
    
    # Save to database
    try:
        if rebind:
            # the credential changed with it, so the whole row
            save_config()
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute(
            'UPDATE clusters SET fallback_hosts = ? WHERE id = ?',
            (json.dumps(fallback_hosts), cluster_id)
        )
        db.conn.commit()
    except Exception as e:
        logging.error(f"Failed to save fallback_hosts: {e}")
        return jsonify({'error': safe_error(e, 'Database operation failed')}), 500
    
    log_audit(request.session['user'], 'cluster.fallback_hosts_changed', 
              f"Cluster {mgr.config.name}: fallback hosts set to {fallback_hosts}")
    
    return jsonify({
        'success': True,
        'fallback_hosts': fallback_hosts,
        'message': f'{len(fallback_hosts)} fallback host(s) configured'
    })


@bp.route('/api/clusters/<cluster_id>/migrations', methods=['GET'])
@require_auth(perms=['vm.view'])
def get_migration_log(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    # sec (audit): rows are per-VM ({vm, vmid, from_node, to_node, success}) and vm.view is a
    # default viewer perm — the sibling /tasks route right below was scoped, this one wasn't.
    return jsonify(scope_vm_rows(cluster_id, cluster_managers[cluster_id].last_migration_log or []))


@bp.route('/api/clusters/<cluster_id>/tasks', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_tasks(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    if not mgr.is_connected:
        return jsonify([])

    limit = bounded_limit(request.args.get('limit'), 50, 1000)
    tasks = mgr.get_tasks(limit=limit) or []

    # sec (private disclosure Sep 2026 — audit M3): the task log carries per-VM UPIDs (vmid/node/type,
    # PVE user) and was returned to any cluster-reaching caller. Admins and plain cluster-wide operators
    # keep the full log; a pool-/ACL-scoped caller sees only tasks for VMs they can access (node/cluster
    # tasks are dropped for them). Mirrors the /resources confinement predicate.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm as _ucav
    from pegaprox.api.helpers import caller_is_scoped
    authz = build_authz_user(request.session.get('user', ''), request.session)
    if not caller_is_scoped(authz, cluster_id):
        return jsonify(tasks)   # admin or plain cluster-wide operator → full log

    def _task_vmid(t):
        for k in ('vmid', 'id'):
            try:
                return int(t.get(k))
            except (TypeError, ValueError):
                continue
        return None

    out = [t for t in tasks
           if (_v := _task_vmid(t)) is not None and _ucav(authz, cluster_id, _v, 'vm.view')]
    return jsonify(out)


# MK May 2026 — Backup SLA tracking. For each VM/CT in the cluster, find the
# most recent backup across all backup-capable storages (vzdump on local/NFS/etc.
# + PBS via the matching pbs_managers entry if any). Compare age vs the
# configured cluster setting `backup_sla_max_age_hours`. Status:
#   ok        — last backup within 80% of the threshold
#   warning   — between 80% and 100% (approaching breach)
#   breached  — past the threshold
#   no-backup — never backed up
#   disabled  — SLA tracking is off for this cluster
@bp.route('/api/clusters/<cluster_id>/backup-sla', methods=['GET'])
@require_auth(perms=['backup.view'])
def get_backup_sla(cluster_id):
    import time
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return jsonify({'enabled': False, 'error': 'cluster offline'}), 503

    max_age = int(getattr(mgr.config, 'backup_sla_max_age_hours', 0) or 0)
    # allow override via query for ad-hoc inspection without saving the setting
    try:
        override = int(request.args.get('max_age_hours', 0))
        if override > 0:
            max_age = override
    except (TypeError, ValueError):
        pass

    now = int(time.time())
    max_age_seconds = max_age * 3600
    warn_at = int(max_age_seconds * 0.8) if max_age else 0

    # 1) gather VMs from cluster
    try:
        # sec (private disclosure Sep 2026 — audit HIGH): this report emitted a per-VM row for
        # every guest (vmid, name, node, status, backup age) to any backup.view holder admitted by
        # the pool/ACL fallback — the most complete inventory of the report family, and it flags the
        # unbacked guests. Scope it per-VM like its costs/power/top-vms siblings.
        vms = scope_vm_rows(cluster_id, mgr.get_vm_resources() or [])
    except Exception as e:
        return jsonify({'error': f'failed to enumerate VMs: {e}'}), 502

    # 2) most-recent backup ts per (vmtype, vmid) across local backup storages
    last_backup = {}  # (type, vmid) -> {'ts': int, 'source': 'local|pbs', 'volid': str}
    try:
        host, port = mgr.host, mgr.api_port
        sess = mgr._create_session()
        # discover unique nodes
        nodes_resp = sess.get(f"https://{host}:{port}/api2/json/nodes", timeout=10)
        nodes = [n['node'] for n in (nodes_resp.json().get('data') or []) if n.get('status') == 'online'] if nodes_resp.status_code == 200 else []
        seen_storages = set()
        for node in nodes:
            try:
                stor_resp = sess.get(f"https://{host}:{port}/api2/json/nodes/{node}/storage", timeout=10)
                if stor_resp.status_code != 200:
                    continue
                for st in stor_resp.json().get('data') or []:
                    if 'backup' not in (st.get('content') or ''):
                        continue
                    sname = st.get('storage')
                    if not sname or (node, sname) in seen_storages:
                        continue
                    seen_storages.add((node, sname))
                    try:
                        c_resp = sess.get(
                            f"https://{host}:{port}/api2/json/nodes/{node}/storage/{sname}/content",
                            params={'content': 'backup'}, timeout=(5, 30))
                    except Exception:
                        continue
                    if c_resp.status_code != 200:
                        continue
                    for item in c_resp.json().get('data') or []:
                        ts = int(item.get('ctime') or 0)
                        if not ts:
                            continue
                        vmid = str(item.get('vmid') or '')
                        if not vmid:
                            continue
                        # vmtype from volid prefix: "vzdump-qemu-100..." or "vzdump-lxc-..."
                        volid = item.get('volid') or ''
                        if 'qemu' in volid:
                            vt = 'qemu'
                        elif 'lxc' in volid or 'openvz' in volid:
                            vt = 'lxc'
                        else:
                            # PBS volids: "<store>:backup/<type>/<id>/<time>"
                            after = volid.split('backup/', 1)[1] if 'backup/' in volid else ''
                            vt = 'qemu' if after.startswith('vm/') else 'lxc' if after.startswith('ct/') else ''
                        if not vt:
                            continue
                        key = (vt, vmid)
                        prev = last_backup.get(key)
                        if not prev or ts > prev['ts']:
                            last_backup[key] = {'ts': ts, 'source': 'pbs' if 'pbs' in (st.get('type') or '').lower() else 'local', 'volid': volid}
            except Exception:
                continue
    except Exception as e:
        logging.warning(f"[BACKUP_SLA] storage scan failed for {cluster_id}: {e}")

    # 3) evaluate per VM
    out_vms = []
    counts = {'ok': 0, 'warning': 0, 'breached': 0, 'no_backup': 0, 'disabled': 0}
    for r in vms:
        rtype = r.get('type')
        if rtype not in ('qemu', 'lxc'):
            continue
        vmid = str(r.get('vmid', ''))
        info = last_backup.get((rtype, vmid))
        ts = info['ts'] if info else 0
        age_h = round((now - ts) / 3600, 1) if ts else None

        if max_age == 0:
            status = 'disabled'
        elif not ts:
            status = 'no-backup'
        else:
            age_s = now - ts
            if age_s >= max_age_seconds:
                status = 'breached'
            elif age_s >= warn_at:
                status = 'warning'
            else:
                status = 'ok'
        counts[status.replace('-', '_')] = counts.get(status.replace('-', '_'), 0) + 1
        out_vms.append({
            'vmid': vmid,
            'type': 'vm' if rtype == 'qemu' else 'ct',
            'name': r.get('name', ''),
            'node': r.get('node', ''),
            'status': r.get('status', ''),
            'last_backup_ts': ts,
            'age_hours': age_h,
            'sla_status': status,
            'backup_source': info['source'] if info else None,
        })

    # sort: breached > no-backup > warning > ok > disabled, then by age desc
    rank = {'breached': 0, 'no-backup': 1, 'warning': 2, 'ok': 3, 'disabled': 4}
    out_vms.sort(key=lambda v: (rank.get(v['sla_status'], 5), -(v['age_hours'] or 0)))

    total = len(out_vms)
    measurable = total - counts.get('disabled', 0)
    pct = round(100 * counts.get('ok', 0) / measurable, 1) if measurable else None

    return jsonify({
        'enabled': max_age > 0,
        'max_age_hours': max_age,
        'now': now,
        'cluster_id': cluster_id,
        'summary': {
            'total': total,
            'ok': counts.get('ok', 0),
            'warning': counts.get('warning', 0),
            'breached': counts.get('breached', 0),
            'no_backup': counts.get('no_backup', 0),
            'disabled': counts.get('disabled', 0),
            'compliance_pct': pct,
        },
        'vms': out_vms,
    })


@bp.route('/api/clusters/<cluster_id>/backup-sla/config', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def set_backup_sla_config(cluster_id):
    """Update the cluster-level Backup SLA target. Body: {max_age_hours: int}."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    data = request.get_json(silent=True) or {}
    try:
        v = int(data.get('max_age_hours', 0) or 0)
        if v < 0 or v > 24 * 365:
            return jsonify({'error': 'max_age_hours must be 0..8760'}), 400
    except (TypeError, ValueError):
        return jsonify({'error': 'max_age_hours must be int'}), 400
    mgr = cluster_managers[cluster_id]
    mgr.config.backup_sla_max_age_hours = v
    try:
        from pegaprox.core.config import save_config
        save_config()
    except Exception as e:
        return jsonify({'error': f'persist failed: {e}'}), 500
    log_audit(request.session.get('user', 'admin'),
              'cluster.backup_sla_set',
              f'cluster={cluster_id} max_age_hours={v}')
    return jsonify({'ok': True, 'max_age_hours': v})


# MK Oct 2026 - the guests no backup job covers, on every cluster the caller reaches.
# Proxmox answers it in one call per cluster (/cluster/backup-info/not-backed-up); the
# read is shared with the backup_coverage alert (background/alert_events.py), so a page
# that stays open and the alert tick ask a cluster once between them.
COVERAGE_MAX_AGE = 120
COVERAGE_REFRESH_AGE = 10


@bp.route('/api/backup-coverage', methods=['GET'])
@require_auth(perms=['backup.view'])
def get_backup_coverage():
    import time
    from pegaprox.background import alert_events
    from pegaprox.utils.concurrent import run_concurrent
    max_age = COVERAGE_REFRESH_AGE if request.args.get('refresh') in ('1', 'true') else COVERAGE_MAX_AGE

    def _name(cid, mgr):
        name = getattr(getattr(mgr, 'config', None), 'name', None)
        return name if isinstance(name, str) and name else cid

    reach, out_clusters = [], []
    for cid, mgr in sorted(list(cluster_managers.items()), key=lambda kv: _name(*kv).lower()):
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
            continue
        ok, _err = check_cluster_access(cid)
        if not ok:
            continue
        entry = {'cluster_id': cid, 'cluster_name': _name(cid, mgr),
                 'state': 'ok', 'count': 0, 'checked_at': None}
        out_clusters.append(entry)
        if not mgr.is_connected:
            entry['state'] = 'offline'
            continue
        reach.append((cid, mgr, entry))

    def _read(cid, mgr):
        status, rows, at = alert_events.not_backed_up(cid, mgr, max_age=max_age)
        resources = []
        if rows:
            resources = mgr.get_vm_resources(max_age=60) or []
        return status, rows, at, resources

    results = run_concurrent([lambda c=cid, m=mgr: _read(c, m) for cid, mgr, _ in reach],
                             timeout=alert_events.BACKUP_TIMEOUT + 10)
    guests = []
    for (cid, mgr, entry), res in zip(reach, results):
        status, rows, at, resources = res if res else (0, None, None, [])
        if rows is None:
            entry['state'] = 'denied' if status == 403 else 'unreadable'
            continue
        entry['checked_at'] = int(at or time.time())
        by_id = {}
        for r in resources:
            if r.get('type') in ('qemu', 'lxc') and str(r.get('vmid', '')).isdigit():
                by_id[int(r['vmid'])] = r
        tags = alert_events.guest_tags(cid, resources) if rows else {}
        found = []
        for g in rows:
            r = by_id.get(g['vmid']) or {}
            found.append({
                'cluster_id': cid, 'cluster_name': entry['cluster_name'], 'vmid': g['vmid'],
                'name': r.get('name') or g['name'], 'type': r.get('type') or g['type'],
                'node': r.get('node') or '', 'status': r.get('status') or 'unknown',
                'template': bool(r.get('template')), 'tags': sorted(tags.get(g['vmid'], ())),
            })
        # per guest: a pool or ACL grant sees its own guests, another tenant none (#773)
        found = scope_vm_rows(cid, found)
        entry['count'] = len(found)
        guests += found
    guests.sort(key=lambda g: (g['cluster_name'].lower(), g['vmid']))
    return jsonify({'guests': guests, 'clusters': out_clusters})


def _overview_name(cid, mgr):
    name = getattr(getattr(mgr, 'config', None), 'name', None)
    return name if isinstance(name, str) and name else cid


def _overview_reach(only=None):
    """(cluster_id, manager, entry) of every Proxmox and XCP-ng cluster the caller reaches, by
    name, and the entries to answer with (state 'ok' until a read says otherwise)."""
    out = []
    for cid, mgr in sorted(list(cluster_managers.items()), key=lambda kv: _overview_name(*kv).lower()):
        if only is not None and cid != only:
            continue
        if getattr(mgr, 'cluster_type', 'proxmox') not in ('proxmox', 'xcpng'):
            continue
        ok, _err = check_cluster_access(cid)
        if ok:
            out.append((cid, mgr, {'cluster_id': cid, 'cluster_name': _overview_name(cid, mgr),
                                   'state': 'ok', 'count': 0}))
    return out


def _storage_overview_rows(resources):
    """Rows of the storage overview from /cluster/resources?type=storage: one per node and
    storage, and one per shared storage, which Proxmox lists once for every node. Figures
    of a storage that is not active there are pvestatd's last ones, so they are left out."""
    def _row(s, node, shared):
        return {'node': node, 'storage': s.get('storage'), 'type': s.get('plugintype') or '',
                'content': s.get('content') or '', 'shared': shared, 'used': None, 'total': None,
                'percent': None, 'active': False, 'nodes': 0, 'inactive_on': []}

    def _figures(row, s):
        used, total = int(s.get('disk') or 0), int(s.get('maxdisk') or 0)
        # a node that has not mounted it yet says 0: the largest figure counts
        if row['total'] is None or total > row['total']:
            row['used'], row['total'] = used, total
            row['percent'] = round(used * 100.0 / total, 1) if total > 0 else None

    rows, shared = [], {}
    for s in resources:
        if not s.get('storage'):
            continue
        up = s.get('status') == 'available'
        node = s.get('node') or ''
        if s.get('shared'):
            row = shared.get(s['storage'])
            if row is None:
                row = shared[s['storage']] = _row(s, '', True)
                rows.append(row)
            row['nodes'] += 1
            if not up:
                row['inactive_on'].append(node)
                continue
        else:
            row = _row(s, node, False)
            row['nodes'] = 1
            rows.append(row)
            if not up:
                continue
        row['active'] = True
        _figures(row, s)
    for row in shared.values():
        row['inactive_on'].sort()
    rows.sort(key=lambda r: (not r['shared'], r['node'], r['storage']))
    return rows


def _xcpng_storage_rows(cid, mgr):
    """The storage repositories of an XCP-ng pool as overview rows. XAPI does not say which
    host a local repository belongs to here, so node stays empty."""
    srs, hit = _health_storage_cache.get(cid, 'srs')
    if not hit:
        srs = [s for s in (mgr.get_storages() or []) if isinstance(s, dict)]
        _health_storage_cache.set(cid, 'srs', srs, ttl_seconds=_HEALTH_STORAGE_TTL)
    rows = []
    for s in srs:
        used, total = int(s.get('used') or 0), int(s.get('total') or 0)
        rows.append({'node': '', 'storage': s.get('storage') or '?', 'type': s.get('type') or '',
                     'content': s.get('content') or '', 'shared': bool(s.get('shared')),
                     'used': used, 'total': total,
                     'percent': round(used * 100.0 / total, 1) if total > 0 else None,
                     'active': s.get('status', 'available') == 'available', 'nodes': 0, 'inactive_on': [],
                     # every host's local SR is called "Local storage": the uuid tells them apart
                     'uuid': str(s.get('uuid') or '')})
    rows.sort(key=lambda r: (not r['shared'], r['storage']))
    return rows


# MK Oct 2026 - every storage of every cluster the caller reaches, in one table: Proxmox in
# one read per cluster from pvestatd's cache (the read the health check makes, shared with
# it), XCP-ng from its SR list. No node is asked on its own.
@bp.route('/api/storage-overview', methods=['GET'])
@require_auth(perms=['storage.view'])
def get_storage_overview():
    from pegaprox.api.helpers import caller_is_scoped
    from pegaprox.utils.concurrent import run_concurrent
    user = build_authz_user(request.session.get('user', ''), request.session)
    reach, out_clusters = [], []
    for cid, mgr, entry in _overview_reach():
        out_clusters.append(entry)
        # a pool or a guest grant is a claim on guests, not on the storage of the cluster
        if caller_is_scoped(user, cid):
            entry['state'] = 'confined'
        elif not mgr.is_connected:
            entry['state'] = 'offline'
        else:
            reach.append((cid, mgr, entry))

    def _read(cid, mgr):
        if getattr(mgr, 'cluster_type', 'proxmox') == 'xcpng':
            return _xcpng_storage_rows(cid, mgr)
        rows = cluster_storage_resources(cid, mgr)
        return None if rows is None else _storage_overview_rows(rows)

    results = run_concurrent([lambda c=cid, m=mgr: _read(c, m) for cid, mgr, _ in reach], timeout=20)
    storages = []
    for (cid, _mgr, entry), rows in zip(reach, results):
        if rows is None:
            entry['state'] = 'unreadable'
            continue
        for row in rows:
            row['cluster_id'], row['cluster_name'] = cid, entry['cluster_name']
        entry['count'] = len(rows)
        storages += rows
    return jsonify({'storages': storages, 'clusters': out_clusters})


def _agent_cache(mgr, name):
    """A copy of one of the guest agent caches of a Proxmox manager, {(node, vmid): ...}."""
    cache = getattr(mgr, name, None)
    if not isinstance(cache, dict):
        return {}
    lock = getattr(mgr, name + '_lock', None)
    if lock is None:
        return dict(cache)
    with lock:
        return dict(cache)


def _inventory_guests(mgr):
    """The guests of one cluster for the inventory, None when they could not be read."""
    if getattr(mgr, 'cluster_type', 'proxmox') == 'proxmox':
        # not get_vm_resources: that puts the agent's filesystem figures over maxdisk, and the
        # inventory wants the size Proxmox has allocated
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/resources?type=vm"
        r = mgr._api_get(url, timeout=15)
        if r is None or r.status_code != 200:
            return None
        rows = r.json().get('data') or []
    else:
        rows = mgr.get_vm_resources(max_age=60) or []
    return [g for g in rows if isinstance(g, dict) and g.get('type') in ('qemu', 'lxc')
            and str(g.get('vmid', '')).isdigit()]


# MK Oct 2026 - the guest inventory behind the CSV export, of one cluster (?cluster=) or of
# all the caller reaches, guest by guest as far as they may see it. One read per cluster;
# addresses and the used disk come from the guest agent sweep where it has them.
@bp.route('/api/inventory/guests', methods=['GET'])
@require_auth()
def get_guest_inventory():
    from pegaprox.background import alert_events
    from pegaprox.utils.concurrent import run_concurrent
    only = request.args.get('cluster') or None
    if only is not None:
        ok, err = check_cluster_access(only)
        if not ok:
            return err
        if only not in cluster_managers:
            return jsonify({'error': 'Cluster not found'}), 404

    reach, out_clusters = [], []
    for cid, mgr, entry in _overview_reach(only):
        out_clusters.append(entry)
        if mgr.is_connected:
            reach.append((cid, mgr, entry))
        else:
            entry['state'] = 'offline'

    results = run_concurrent([lambda m=mgr: _inventory_guests(m) for _, mgr, _ in reach], timeout=30)
    guests = []
    for (cid, mgr, entry), rows in zip(reach, results):
        if rows is None:
            entry['state'] = 'unreadable'
            continue
        # per guest: a pool or ACL grant sees its own guests, another tenant none (#773)
        rows = scope_vm_rows(cid, rows)
        ips, disks = _agent_cache(mgr, '_ip_cache'), _agent_cache(mgr, '_disk_cache')
        tags = alert_events.guest_tags(cid, rows)
        for g in rows:
            vmid, node = int(g['vmid']), g.get('node') or ''
            running = g.get('status') == 'running'
            # the agent caches keep a guest that has stopped since
            agent_ips = ips.get((node, vmid)) if running else None
            if g.get('type') == 'lxc':
                used = int(g.get('disk') or 0) or None
            else:
                used = ((disks.get((node, vmid)) if running else None) or {}).get('used') or None
            guests.append({
                'cluster_id': cid, 'cluster_name': entry['cluster_name'], 'vmid': vmid,
                'name': g.get('name') or '', 'type': g['type'], 'node': node,
                'status': g.get('status') or 'unknown', 'template': bool(g.get('template')),
                'vcpus': int(g.get('maxcpu') or 0), 'cpu': float(g.get('cpu') or 0),
                'mem': int(g.get('mem') or 0), 'memory': int(g.get('maxmem') or 0),
                'disk_allocated': int(g.get('maxdisk') or 0), 'disk_used': used,
                'ip_addresses': list(agent_ips or g.get('ip_addresses') or []),
                'ha_state': g.get('hastate') or '', 'pool': g.get('pool') or '',
                'tags': sorted(tags.get(vmid, ())),
            })
        entry['count'] = len(rows)
    guests.sort(key=lambda g: (g['cluster_name'].lower(), g['vmid']))
    return jsonify({'guests': guests, 'clusters': out_clusters})


# MK Oct 2026 - the guest table of the All Guests page asks for one page at a time: filtered,
# sorted and cut here, so 10k guests never cross the wire at once. The rows come from the
# snapshot the guest list of a cluster reads (get_vm_resources, which the live loop keeps
# fresh), not from a walk of /cluster/resources per page, so the disk figures are that list's
# as well. Each row says which of the table's actions the caller may take on its guest; the
# actions go to the per-guest routes and the bulk migration, which ask again.
_GUEST_PAGE_MAX = 500
_GUEST_PAGE_AGE = 6
_GUEST_PAGE_TAGS = 500
_GUEST_PAGE_TEXT = 200
_GUEST_STATES = ('running', 'stopped', 'other')
_GUEST_KINDS = ('qemu', 'lxc', 'template')
_GUEST_SORTS = {
    'name': lambda g: g['name'].lower(),
    'vmid': lambda g: g['vmid'],
    'cluster': lambda g: g['cluster_name'].lower(),
    'node': lambda g: g['node'].lower(),
    'status': lambda g: g['status'],
    'type': lambda g: (g['template'], g['type']),
    'cpu': lambda g: g['cpu'],
    'mem': lambda g: g['mem'],
    'disk': lambda g: (g['disk_size'], g['disk']),
    'uptime': lambda g: g['uptime'],
}
_PAGE_NUMBER_RE = re.compile(r'[0-9]{1,9}')


def _guest_page_query(args):
    """The filters, order and window of a guest page as the query string gives them, or the
    400 a malformed one earns."""
    def number(name, default, low, high):
        raw = args.get(name)
        if raw in (None, ''):
            return default
        if not _PAGE_NUMBER_RE.fullmatch(raw) or not low <= int(raw) <= high:
            raise ValueError(f'{name} is a whole number from {low} to {high}')
        return int(raw)

    def choice(name, allowed, default=''):
        raw = args.get(name) or default
        if raw != default and raw not in allowed:
            raise ValueError(f"{name} is one of {', '.join(allowed)}")
        return raw

    def text(name, longest):
        raw = (args.get(name) or '').strip()
        if len(raw) > longest:
            raise ValueError(f'{name} is at most {longest} characters')
        return raw.lower()

    try:
        return {
            'limit': number('limit', 100, 1, _GUEST_PAGE_MAX),
            'offset': number('offset', 0, 0, 10_000_000),
            'q': text('q', _GUEST_PAGE_TEXT),
            # as typed: AND, OR and NOT are capitals
            'q_text': (args.get('q') or '').strip(),
            'tag': text('tag', 64),
            'status': choice('status', _GUEST_STATES),
            'type': choice('type', _GUEST_KINDS),
            'sort': choice('sort', tuple(_GUEST_SORTS), 'name'),
            'dir': choice('dir', ('asc', 'desc'), 'asc'),
        }, None
    except ValueError as e:
        return None, (jsonify({'error': str(e)}), 400)


def _guest_page_row(cid, cluster_name, g, ips, tags):
    vmid, node = int(g['vmid']), str(g.get('node') or '')
    running = g.get('status') == 'running'
    # the agent cache keeps a guest that has stopped since
    agent_ips = ips.get((node, vmid)) if running else None
    return {
        'cluster_id': cid, 'cluster_name': cluster_name, 'vmid': vmid, 'name': str(g.get('name') or ''),
        'type': g['type'], 'node': node, 'status': str(g.get('status') or 'unknown'),
        'template': bool(g.get('template')), 'vcpus': int(g.get('maxcpu') or 0),
        'cpu': float(g.get('cpu') or 0), 'mem': int(g.get('mem') or 0), 'memory': int(g.get('maxmem') or 0),
        'disk': int(g.get('disk') or 0), 'disk_size': int(g.get('maxdisk') or 0),
        'uptime': int(g.get('uptime') or 0) if running else 0,
        'ip_addresses': [str(a) for a in (agent_ips or (g.get('ip_addresses') if running else None) or [])],
        'pool': str(g.get('pool') or ''), 'tags': sorted(tags.get(vmid, ())),
    }


def _guest_state(g):
    return g['status'] if g['status'] in ('running', 'stopped') else 'other'


def _guest_kind_fits(g, kind):
    if not kind:
        return True
    if kind == 'template':
        return g['template']
    return g['type'] == kind and not g['template']


def _guest_text(g):
    return ' '.join([g['name'], str(g['vmid']), g['node'], g['cluster_name'], g['pool']]
                    + g['ip_addresses'] + g['tags']).lower()


def _guest_text_filter(rows, text):
    """The rows the text filter of the page keeps. Plain text is looked for in the row's
    text as before; a query with AND/OR/NOT, parentheses or quotes, and plain text that
    finds nothing that way, is an expression of the global search (utils/search_query),
    its free text still the row's text. Raises SearchSyntaxError."""
    from pegaprox.background import guest_index
    from pegaprox.utils import search_query
    if not text:
        return rows
    plain = None
    if not search_query.explicit(text):
        q = text.lower()
        plain = [g for g in rows if q in _guest_text(g)]
        if plain:
            return plain
    reading = search_query.parse(text)
    if plain is not None and reading.whole_text():
        return plain
    # MK Oct 2026 - MAC, notes and configured IPs from the guest search index, one copy
    # per cluster and only when a term asks for them
    indexes = {}
    wants_index = any(t.field in ('ip', 'mac', 'notes') for t in reading.terms)
    out = []
    for g in rows:
        entry = None
        if wants_index:
            cid = g['cluster_id']
            if cid not in indexes:
                indexes[cid] = guest_index.snapshot(cid)
            entry = indexes[cid].get((g['type'], g['vmid']))
        ips = g['ip_addresses']
        facts = {
            'name': g['name'].lower(), 'vmid': str(g['vmid']), 'node': g['node'].lower(),
            'ip': (ips[0] if ips else '').lower(), 'ip_raw': ips[0] if ips else None,
            'tags': [t.lower() for t in g['tags']], 'status': g['status'].lower(), 'type': g['type'],
            'cluster_id': g['cluster_id'], 'cluster': g['cluster_name'].lower(), 'pool': g['pool'].lower(),
            'entry': entry, 'live_ips': ips, 'text': _guest_text(g),
        }
        if reading.match(search_query.guest_hit, facts) is not None:
            out.append(g)
    return out


def _guest_page_can(user, cid, xen, g, may):
    """What the per-guest routes would let this caller do to the guest: the checks of
    vm_action_api, create_snapshot_api and bulk_migrate_api, without acting."""
    vmid, kind = g['vmid'], g['type']

    def vm(perm):
        return user_can_access_vm(user, cid, vmid, perm, kind)

    if xen:
        start = stop = reboot = vm('xapi.vm.power')
    else:
        start, stop, reboot = vm('vm.start'), vm('vm.stop'), vm('vm.restart')
    return {'start': start, 'stop': stop, 'reboot': reboot,
            'snapshot': may['vm.snapshot'] and (not xen or may['xapi.vm.snapshot']) and vm('vm.snapshot'),
            'migrate': may['vm.migrate'] and (not xen or may['xapi.vm.migrate']) and vm('vm.migrate')}


@bp.route('/api/inventory/guests/page', methods=['GET'])
@require_auth()
def get_guest_page():
    """One page of the guests of every cluster the caller reaches

    The guests the caller may see, of every Proxmox cluster and XCP-ng pool or of one
    (?cluster=), filtered, sorted and cut to a page. Query:
    - limit (1-500, default 100), offset (default 0)
    - q: text in the name, VMID, node, cluster, pool, IP addresses or tags
    - status: running, stopped or other; type: qemu, lxc or template; tag: one tag
    - sort: name, vmid, cluster, node, status, type, cpu, mem, disk or uptime; dir: asc or desc

    The answer has the rows of the page (guests, each with `can`: which of start, stop,
    reboot, snapshot and migrate the caller may do to it), total (the guests the filters
    leave), count (all the caller sees), status_counts (by status, the status filter aside),
    tags (every tag among the guests) and clusters (each with its state and guest count).
    The figures are those of the cluster's guest list, a few seconds old at most.
    q also takes the expressions of the global search (tag:web OR node:pve2, -status:running);
    one that cannot be read answers 400 with code SEARCH_SYNTAX.
    """
    from pegaprox.background import alert_events
    from pegaprox.utils.concurrent import run_concurrent
    from pegaprox.utils.search_query import SearchSyntaxError
    want, err = _guest_page_query(request.args)
    if err:
        return err
    only = request.args.get('cluster') or None
    if only is not None:
        ok, err = check_cluster_access(only)
        if not ok:
            return err
        if only not in cluster_managers:
            return jsonify({'error': 'Cluster not found'}), 404

    reach, out_clusters = [], []
    for cid, mgr, entry in _overview_reach(only):
        out_clusters.append(entry)
        if mgr.is_connected:
            reach.append((cid, mgr, entry))
        else:
            entry['state'] = 'offline'

    def _read(mgr):
        xen = getattr(mgr, 'cluster_type', 'proxmox') == 'xcpng'
        rows = mgr.get_vm_resources(max_age=60 if xen else _GUEST_PAGE_AGE)
        if rows is None or getattr(rows, 'unavailable', False):
            return None
        return [g for g in rows if isinstance(g, dict) and g.get('type') in ('qemu', 'lxc')
                and str(g.get('vmid', '')).isdigit()]

    results = run_concurrent([lambda m=mgr: _read(m) for _, mgr, _ in reach], timeout=20)
    seen, managers = [], {}
    for (cid, mgr, entry), rows in zip(reach, results):
        if rows is None:
            entry['state'] = 'unreadable'
            continue
        rows = scope_vm_rows(cid, rows)
        ips, tags = _agent_cache(mgr, '_ip_cache'), alert_events.guest_tags(cid, rows)
        seen += [_guest_page_row(cid, entry['cluster_name'], g, ips, tags) for g in rows]
        entry['count'] = len(rows)
        managers[cid] = mgr

    all_tags = sorted({t for g in seen for t in g['tags']})[:_GUEST_PAGE_TAGS]
    tag, kind = want['tag'], want['type']
    left = [g for g in seen if _guest_kind_fits(g, kind) and (not tag or tag in g['tags'])]
    try:
        left = _guest_text_filter(left, want['q_text'])
    except SearchSyntaxError as e:
        return jsonify(e.to_json()), 400
    status_counts = {s: 0 for s in _GUEST_STATES}
    for g in left:
        status_counts[_guest_state(g)] += 1
    if want['status']:
        left = [g for g in left if _guest_state(g) == want['status']]
    # equal values keep cluster and VMID order either way: reverse keeps a sort stable
    left.sort(key=lambda g: (g['cluster_name'].lower(), g['vmid']))
    left.sort(key=_GUEST_SORTS[want['sort']], reverse=want['dir'] == 'desc')
    page = left[want['offset']:want['offset'] + want['limit']]

    if page:
        user = build_authz_user(request.session.get('user', ''), request.session)
        may = {p: has_permission(user, p) for p in
               ('vm.snapshot', 'vm.migrate', 'xapi.vm.snapshot', 'xapi.vm.migrate')}
        for g in page:
            xen = getattr(managers[g['cluster_id']], 'cluster_type', 'proxmox') == 'xcpng'
            g['can'] = _guest_page_can(user, g['cluster_id'], xen, g, may)
    return jsonify({'guests': page, 'total': len(left), 'count': len(seen), 'offset': want['offset'],
                    'limit': want['limit'], 'status_counts': status_counts, 'tags': all_tags,
                    'clusters': out_clusters})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/tasks/<path:upid>', methods=['DELETE'])
@require_auth(perms=['vm.stop'])  # cancelling task is like stopping
def cancel_task(cluster_id, node, upid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    # NS Aug 2026 (Aikido #469089252) — the UPID encodes the task's VM; gate per-VM so a
    # pool-scoped user can't cancel another pool/tenant's VM task on a shared cluster.
    _p = str(upid).split(':')
    _tvmid = _p[6] if len(_p) > 6 and _p[6].isdigit() else None
    if _tvmid is None:
        # NS Aug 2026 (AI-pentest) — XCP-ng UPIDs aren't the PVE colon format, so the split yields no
        # vmid and the gate was skipped, letting a pool-scoped user cancel another VM's XAPI task.
        # Resolve the VM from the manager's tracked tasks.
        try:
            _tv = (getattr(mgr, '_active_tasks', {}) or {}).get(upid, {}).get('vmid')
            if _tv is not None:
                _tvmid = str(_tv)
        except Exception:
            pass
    if _tvmid is not None and str(_tvmid).isdigit():
        from pegaprox.utils.auth import build_authz_user
        _u = build_authz_user(request.session.get('user', ''), request.session)
        if not user_can_access_vm(_u, cluster_id, int(_tvmid), 'vm.stop'):
            return jsonify({'error': 'Access denied to this VM task'}), 403

    try:
        result = mgr.stop_task(node, upid)
        if result:
            # Log the action
            log_audit(
                request.session.get('user', 'system'),
                'task.cancelled',
                f'Task {upid} on {node}',
                request.remote_addr,
                cluster=mgr.config.name
            )
            return jsonify({'success': True, 'message': 'Task cancelled'})
        else:
            return jsonify({'error': 'Failed to cancel task'}), 500
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500



# High Availability (HA) API Routes
@bp.route('/api/clusters/<cluster_id>/ha', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_ha_status(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_ha_status())


@bp.route('/api/clusters/<cluster_id>/ha/status', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_ha_status_detailed(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_ha_status())


@bp.route('/api/clusters/<cluster_id>/ha/enable', methods=['POST'])
@require_auth(perms=['ha.config'])
def enable_ha(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    mgr.start_ha_monitor()
    mgr.config.ha_enabled = True
    save_config()
    
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ha.enabled', f"HA enabled for cluster {mgr.config.name}", cluster=mgr.config.name)
    
    return jsonify({
        'message': 'High Availability aktiviert',
        'status': mgr.get_ha_status()
    })


@bp.route('/api/clusters/<cluster_id>/ha/disable', methods=['POST'])
@require_auth(perms=['ha.config'])
def disable_ha(cluster_id):
    # MK 2026-06-03 (Nico-reported HOCHGEFÄHRLICH bug): pre-fix this endpoint
    # only flipped `ha_enabled = False` and stopped the server-side monitor —
    # it never ran the SSH-side uninstaller for the agents that were deployed
    # to every cluster node during `_ha_install_*_on_all_nodes`. Both shapes
    # of agent (self-fence + node-agent/poison-pill) share `pegaprox-agent.
    # service` + `/usr/local/bin/pegaprox-agent.sh`, so an orphaned systemd
    # service kept running on the nodes silently. UI then claimed "HA off",
    # admin rebooted a node thinking it was safe, the orphan agent on that
    # node and/or its peers reached their ping-isolation threshold (15s),
    # called `stop_all_vms` locally, and the cluster lost every running VM.
    # `disable_ha` now actually tears down the systemd service + binary +
    # storage-heartbeat dir on every reachable node before flipping the flag.
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    mgr = cluster_managers[cluster_id]

    # Stop the server-side monitor first so it can't queue any
    # recovery actions while we're tearing down the on-node agents.
    mgr.stop_ha_monitor()

    # SSH-uninstall on every reachable node. MK Oct 2026 (#625) - the two agents have
    # their own names now (pegaprox-fence-agent.* and pegaprox-agent.*), so this takes
    # both off; the self-fence uninstall alone would leave the node agent running.
    uninstall_results = {}
    try:
        uninstall_results = mgr._ha_uninstall_agents_on_all_nodes() or {}
    except Exception as e:
        logging.error(f"[HA disable] agent teardown failed: {e}")

    # Best-effort cleanup of the storage-heartbeat `.pegaprox` dir so
    # stale `poison_<node>` / `heartbeat_<node>` files don't survive into
    # the next HA-enable cycle and trip the node-agent on first install.
    storage_cleanup = None
    try:
        if hasattr(mgr, '_ha_cleanup_storage_heartbeat'):
            storage_cleanup = mgr._ha_cleanup_storage_heartbeat()
    except Exception as e:
        logging.warning(f"[HA disable] storage heartbeat cleanup: {e}")

    # MK Oct 2026 (#625) - the cluster claim goes with HA: our file out of
    # /etc/pve/pegaprox, the switch off. It stayed on the cluster and in the
    # settings before.
    claim = _retire_cluster_claim(mgr)

    # Flip the flag + clear in-memory ha_config bookkeeping last so the
    # state we report back to the UI matches what's actually on disk.
    mgr.config.ha_enabled = False
    # MK Sep 2026 - this used to clear the whole map, including the nodes whose teardown had
    # just failed. The audit line below already says "manual cleanup required" for those, but
    # our own bookkeeping said the opposite, and the next HA-enable cycle reads the
    # bookkeeping. A node we believe has no agent, still running one, is a self-fence agent
    # acting on heartbeat state nobody is maintaining any more - it can reboot the node.
    # Keep the ones that did not come off; drop only what actually went.
    # MK Oct 2026 (#625) - a node leaves the books only when its own teardown answered.
    # When the cluster did not list its nodes nothing came off, and the empty result
    # read as a clean slate: the agents kept running with nothing left to stop them.
    nodes_gone = {n for n, ok in uninstall_results.items() if ok}
    nodes_failed = sorted(n for n, ok in uninstall_results.items() if not ok)
    had_node_agent = mgr.ha_config.get('node_agent_installed')
    had_node_agent = {n for n, v in had_node_agent.items() if v} if isinstance(had_node_agent, dict) else set()
    had_fence_agent = {n for n in (mgr.ha_config.get('self_fence_nodes') or []) if isinstance(n, str)}
    had_any = bool(mgr.ha_config.get('self_fence_installed') or had_fence_agent or had_node_agent)
    # on the books and not asked: the cluster did not list them, or listed nothing
    nodes_unconfirmed = sorted((had_fence_agent | had_node_agent) - set(uninstall_results))
    _still_there = {n: True for n in (had_node_agent - nodes_gone) | set(nodes_failed)}
    if _still_there:
        logging.warning(
            "[HA disable] agent still installed on %s - keeping it in node_agent_installed "
            "so the next enable does not assume a clean slate", sorted(_still_there))
    mgr.ha_config['node_agent_installed'] = _still_there
    # the self-fence agents went with it, except where the teardown failed or never ran
    mgr.ha_config['self_fence_nodes'] = sorted((had_fence_agent - nodes_gone) | set(nodes_failed))
    mgr.ha_config['self_fence_installed'] = bool(mgr.ha_config['self_fence_nodes']) or (
        not uninstall_results and bool(mgr.ha_config.get('self_fence_installed')))
    mgr.config.ha_settings = _ha_settings_of(mgr)
    save_config()

    nodes_ok = len(nodes_gone)
    nodes_total = len(uninstall_results)
    by_hand = ("`systemctl disable --now pegaprox-fence-agent.service pegaprox-agent.service; "
               "rm -f /usr/local/bin/pegaprox-fence-agent.sh /usr/local/bin/pegaprox-agent.sh "
               "/etc/systemd/system/pegaprox-fence-agent.service "
               "/etc/systemd/system/pegaprox-agent.service; systemctl daemon-reload`")

    user = getattr(request, 'session', {}).get('user', 'system')
    audit_detail = (f"HA disabled for cluster {mgr.config.name} — "
                    f"agents removed from {nodes_ok}/{nodes_total} nodes")
    warnings = []
    if nodes_failed:
        audit_detail += f" (teardown FAILED on: {', '.join(nodes_failed)} — manual cleanup required)"
        warnings.append(f"Could not tear down agents on {len(nodes_failed)} node(s): "
                        f"{', '.join(nodes_failed)}. SSH to those nodes manually and run {by_hand}")
    if not uninstall_results and had_any:
        where = ', '.join(nodes_unconfirmed) or 'every node of the cluster'
        audit_detail += (f" (the cluster did not list its nodes, NO agent was removed - "
                         f"manual cleanup required on: {where})")
        warnings.append(f"The cluster did not list its nodes, so no agent was stopped or removed. "
                        f"The agents keep running, and can still stop the guests of a node, on: {where}. "
                        f"Disable HA again once the cluster answers, or SSH to those nodes and run {by_hand}")
    elif nodes_unconfirmed:
        audit_detail += (f" (not listed by the cluster, agents may still run on: "
                         f"{', '.join(nodes_unconfirmed)} - manual cleanup required)")
        warnings.append(f"Not listed by the cluster, agents may still run on: "
                        f"{', '.join(nodes_unconfirmed)}. SSH to those nodes and run {by_hand}")
    if claim:
        audit_detail += f" (cluster claim switched off, our claim: {claim.get('state')})"
        if claim.get('warning'):
            warnings.append(claim['warning'])
    log_audit(user, 'ha.disabled', audit_detail, cluster=mgr.config.name)

    return jsonify({
        'message': 'HA disabled',
        'agents_uninstalled': nodes_ok,
        'agents_total': nodes_total,
        'agents_failed': nodes_failed,
        'agents_unconfirmed': nodes_unconfirmed,
        # what became of our claim in /etc/pve/pegaprox, null where the claim was off
        'claim': claim,
        'storage_cleanup': storage_cleanup,
        'status': mgr.get_ha_status(),
        'warning': ' '.join(warnings) or None,
    })


@bp.route('/api/clusters/<cluster_id>/ha/config', methods=['PUT'])
@require_auth(perms=['ha.config'])
def update_ha_config(cluster_id):
    """Update HA configuration including split-brain prevention settings"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}

    def _agents_decide_by():
        # what of the settings goes into the self-fence script: whether quorum gets
        # forced, and whether without a fence (the leader then decides for a node
        # that lost quorum)
        cfg = manager.ha_config
        return (bool(cfg.get('two_node_mode') or cfg.get('force_quorum_on_failure')),
                cfg.get('unsafe_two_node_recovery') is True)
    old_forces = _agents_decide_by()

    # MK Oct 2026 (#625) - forcing quorum without a fence that was read back. Setups
    # from before the safety rules have it on and may switch it off; switching it on
    # is a decision to run with the split-brain risk and has to be typed out. Asked
    # before anything of this request is applied. Stored on where nothing forces
    # quorum it is off (the status says so), and is switched on like any off switch.
    if (data.get('unsafe_two_node_recovery') is True and not all(old_forces)
            and data.get('confirm_unsafe_two_node') != UNSAFE_TWO_NODE_PHRASE):
        return jsonify({'error': f'Type {UNSAFE_TWO_NODE_PHRASE} to confirm: with this on, quorum '
                                 'is forced on the surviving node without proof that the failed '
                                 'node is off, and both can run the same VM in a network split',
                        'code': 'HA_UNSAFE_CONFIRM'}), 400
    # the fence of each node (#625): checked as a whole before anything is applied
    new_fencing = None
    if 'fencing' in data:
        if not hasattr(manager, '_fencing_from_request'):
            return jsonify({'error': 'Node fencing exists on Proxmox clusters only'}), 400
        try:
            new_fencing = manager._fencing_from_request(data['fencing'])
        except ValueError as e:
            return jsonify({'error': f'fencing: {e}', 'code': 'HA_FENCING_INVALID'}), 400
    # the two numbers the start of a recovery is worked out from (#625). They were
    # stored as sent: a JSON true or false counts as 1 or 0 where the recovery
    # waits, and took away the time a node's self-fence agent is given
    for key in ('recovery_delay', 'failure_threshold'):
        if key in data and not PegaProxManager._ha_countable(data[key]):
            return jsonify({'error': f'{key} must be a number, zero or more',
                            'code': 'HA_TIMING_INVALID'}), 400

    # Update HA config
    if 'quorum_enabled' in data:
        manager.ha_config['quorum_enabled'] = data['quorum_enabled']
    if 'quorum_hosts' in data:
        manager.ha_config['quorum_hosts'] = data['quorum_hosts']
    if 'quorum_gateway' in data:
        manager.ha_config['quorum_gateway'] = data['quorum_gateway']
    if 'quorum_required_votes' in data:
        manager.ha_config['quorum_required_votes'] = data['quorum_required_votes']
    if 'self_fence_enabled' in data:
        manager.ha_config['self_fence_enabled'] = data['self_fence_enabled']
    if 'watchdog_enabled' in data:
        manager.ha_config['watchdog_enabled'] = data['watchdog_enabled']
    if 'verify_network' in data:
        manager.ha_config['verify_network_before_recovery'] = data['verify_network']
    if 'recovery_delay' in data:
        manager.ha_config['recovery_delay'] = data['recovery_delay']
    if 'failure_threshold' in data:
        manager.ha_failure_threshold = data['failure_threshold']
    
    # 2-Node Cluster Mode - NS Jan 2026
    if 'two_node_mode' in data:
        manager.ha_config['two_node_mode'] = data['two_node_mode']
    if 'force_quorum_on_failure' in data:
        manager.ha_config['force_quorum_on_failure'] = data['force_quorum_on_failure']
    if 'unsafe_two_node_recovery' in data:
        manager.ha_config['unsafe_two_node_recovery'] = data['unsafe_two_node_recovery'] is True
    # The switch only counts where quorum gets forced, and the status reports it as off
    # everywhere else. Kept on underneath, it came back without a word with the next
    # save of 2-node mode. A cluster this request leaves without forced quorum drops it,
    # and one it starts forcing quorum on is a new setup under the safety rules: unsafe
    # only when this request switches it on, with the phrase asked for above.
    forces = _agents_decide_by()[0]
    if not forces or (not old_forces[0] and data.get('unsafe_two_node_recovery') is not True):
        manager.ha_config['unsafe_two_node_recovery'] = False
    fencing_change = None
    if new_fencing is not None:
        old_fencing = manager.ha_config.get('fencing') or {}
        fencing_change = ', '.join(
            f"{n} ({(new_fencing.get(n) or {}).get('type') or 'removed'})"
            for n in sorted(set(old_fencing) | set(new_fencing)) if old_fencing.get(n) != new_fencing.get(n))
        manager.ha_config['fencing'] = new_fencing

    # Storage-based Split-Brain Protection - NS Jan 2026
    if 'storage_heartbeat_enabled' in data:
        manager.ha_config['storage_heartbeat_enabled'] = data['storage_heartbeat_enabled']
    
    if 'storage_heartbeat_path' in data:
        # sec (audit): this string is substituted into the node-agent script as
        # STORAGE_PATH="<value>" and that script runs as root on every node, so a quote in the
        # value breaks out of the assignment. Config is not code — constrain it to a plain
        # absolute path before it can reach the splice in manager._NODE_AGENT_SCRIPT.
        _shp = str(data['storage_heartbeat_path'] or '')
        if _shp and not PegaProxManager.HEARTBEAT_PATH_RE.fullmatch(_shp):
            return jsonify({'error': 'storage_heartbeat_path must be an absolute path '
                                     '(letters, digits and . _ @ + - / only)'}), 400
        manager.ha_config['storage_heartbeat_path'] = _shp
        
        # Auto-enable storage heartbeat when path is provided
        if data['storage_heartbeat_path']:
            manager.ha_config['storage_heartbeat_enabled'] = True
            manager.ha_config['dual_network_mode'] = True
            
            # Auto-install node agents when storage path is configured
            def install_agents():
                try:
                    manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
                    manager.logger.info("[HA] AUTO-INSTALLING NODE AGENTS FOR STORAGE HEARTBEAT")
                    manager.logger.info(f"[HA] Storage path: {_sl(data['storage_heartbeat_path'])}")
                    manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
                    results = manager._ha_install_agents_on_all_nodes()
                    success_count = sum(1 for v in results.values() if v)
                    manager.logger.info(f"[HA] ✓ Agent installation complete: {success_count}/{len(results)} nodes")
                except Exception as e:
                    manager.logger.error(f"[HA] ✗ Agent installation failed: {e}")
            
            # user jobs over every node: each SSH step asks for the lease in an automatic group (#625)
            threading.Thread(target=ha.as_job(install_agents, 'node agent install'), daemon=True).start()
    
    if 'storage_heartbeat_timeout' in data:
        manager.ha_config['storage_heartbeat_timeout'] = data['storage_heartbeat_timeout']
    if 'poison_pill_enabled' in data:
        manager.ha_config['poison_pill_enabled'] = data['poison_pill_enabled']
    if 'strict_fencing' in data:
        manager.ha_config['strict_fencing'] = data['strict_fencing']

    # PegaProx VM auto-recovery - LW Mar 2026
    old_pegaprox_vmid = manager.ha_config.get('pegaprox_vmid', '')
    if 'pegaprox_vmid' in data:
        manager.ha_config['pegaprox_vmid'] = data['pegaprox_vmid']
    
    # Enable/disable HA if specified
    if 'enabled' in data:
        if data['enabled'] and not manager.ha_enabled:
            manager.start_ha_monitor()
        elif not data['enabled'] and manager.ha_enabled:
            manager.stop_ha_monitor()
    
    # Save to config
    # Store HA settings in cluster config for persistence
    manager.config.ha_settings = _ha_settings_of(manager)
    
    save_config()

    # re-deploy self-fence agents if pegaprox_vmid changed, or whether quorum gets
    # forced: the agents decide by quorum alone or ask for the leader depending on it
    new_pegaprox_vmid = manager.ha_config.get('pegaprox_vmid', '')
    vmid_changed = 'pegaprox_vmid' in data and str(old_pegaprox_vmid) != str(new_pegaprox_vmid)
    forces_changed = old_forces != _agents_decide_by()
    if (vmid_changed or forces_changed) and manager.ha_config.get('self_fence_installed'):
        def _reinstall():
            try:
                manager.logger.info(f"[HA] pegaprox_vmid ({old_pegaprox_vmid} -> {new_pegaprox_vmid}) or the "
                                    "two-node settings changed, re-deploying agents")
                # MK Oct 2026 (#625) - the v2 agents only. This installed on every node,
                # so saving a setting replaced the agent of an older PegaProx with v2.
                # That one stays as it is, with the settings it was installed with,
                # until the install from the HA settings; the status names the nodes.
                results = manager._ha_redeploy_fence_agents('the HA settings changed', wait=True)
                ok = sum(1 for v in results.values() if v)
                manager.logger.info(f"[HA] agent redeploy: {ok}/{len(results)} nodes")
                _save_ha_config_to_db(cluster_id, manager)
            except Exception as e:
                manager.logger.error(f"[HA] agent redeploy failed: {e}")
        # MK May 2026 (#371) — removed local `import threading`, the module-level
        # one at top of file is enough. Local re-import made `threading` a local
        # for the whole function and broke the earlier ref in the storage-heartbeat
        # branch with UnboundLocalError before save_config could even run.
        threading.Thread(target=ha.as_job(_reinstall, 'self-fence agents'), daemon=True).start()

    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.config_updated', f"HA configuration updated for cluster {manager.config.name}", cluster=manager.config.name)
    if fencing_change:
        # which node and which kind, never the BMC password
        log_audit(user, 'ha.fencing_updated', f"Node fencing of cluster {manager.config.name} changed: "
                                              f"{fencing_change}", cluster=manager.config.name)

    return jsonify({
        'message': 'HA-Konfiguration gespeichert',
        'status': manager.get_ha_status()
    })


UNSAFE_TWO_NODE_PHRASE = 'UNSAFE'
CLAIM_ON_PHRASE = 'WRITE CLAIM'
CLAIM_RELEASE_PHRASE = 'RELEASE CLAIM'


def _ha_settings_of(manager):
    """A cluster's HA settings as they are stored, from the running manager.

    MK Oct 2026 (#625) - the one place that lists them. The config route used to
    rebuild the stored dict from its own form fields, which dropped what the agent
    installs had recorded (self_fence_installed, self_fence_nodes,
    node_agent_installed) at the next save; the install helper wrote the database
    row only, so the next save_config put the older copy back over it. A stored key
    that no route writes (node_ips, the timings) stays as it is."""
    cfg = manager.ha_config
    stored = getattr(manager.config, 'ha_settings', None)
    return dict(stored if isinstance(stored, dict) else {}, **{
        'quorum_enabled': cfg.get('quorum_enabled', True),
        'quorum_hosts': cfg.get('quorum_hosts', []),
        'quorum_gateway': cfg.get('quorum_gateway', ''),
        'quorum_required_votes': cfg.get('quorum_required_votes', 2),
        'self_fence_enabled': cfg.get('self_fence_enabled', True),
        'watchdog_enabled': cfg.get('watchdog_enabled', False),
        'verify_network': cfg.get('verify_network_before_recovery', True),
        'recovery_delay': cfg.get('recovery_delay', 30),
        'failure_threshold': manager.ha_failure_threshold,
        # 2-Node Cluster Mode
        'two_node_mode': cfg.get('two_node_mode', False),
        'force_quorum_on_failure': cfg.get('force_quorum_on_failure', False),
        'unsafe_two_node_recovery': cfg.get('unsafe_two_node_recovery') is True,
        # Storage-based Split-Brain Protection - NS Jan 2026
        'storage_heartbeat_enabled': cfg.get('storage_heartbeat_enabled', False),
        'storage_heartbeat_path': cfg.get('storage_heartbeat_path', ''),
        'storage_heartbeat_timeout': cfg.get('storage_heartbeat_timeout', 30),
        'poison_pill_enabled': cfg.get('poison_pill_enabled', True),
        'strict_fencing': cfg.get('strict_fencing', False),
        'pegaprox_vmid': cfg.get('pegaprox_vmid', ''),
        # what the installs recorded
        'self_fence_installed': cfg.get('self_fence_installed', False),
        'self_fence_nodes': cfg.get('self_fence_nodes', []),
        'node_agent_installed': cfg.get('node_agent_installed', {}),
        'fence_agent_versions': cfg.get('fence_agent_versions', {}),
        'agent_token': cfg.get('agent_token', ''),
        'claim_enabled': cfg.get('claim_enabled') is True,
        # per node, BMC password included: the column is encrypted like the token above
        'fencing': cfg.get('fencing') or {},
    })


# What only the HA routes put into the stored HA settings, each behind its own check:
# the two switches, the agent token, what the installs recorded, the node fences. A
# backup restore over a cluster that is there leaves them as they are.
HA_SETTINGS_GUARDED = frozenset({
    'claim_enabled', 'unsafe_two_node_recovery', 'agent_token', 'self_fence_installed',
    'self_fence_nodes', 'node_agent_installed', 'fence_agent_versions', 'fencing',
})


def _ha_settings_for_new_cluster():
    """The HA settings a cluster starts with when it is added: none from the request.
    The HA config route checks what it takes (the heartbeat path goes into a script
    that runs as root on the nodes), the body of the add route went in as it came.
    unsafe_two_node_recovery is written out as off: a missing key would read as a
    setup from before the safety rules (#625)."""
    return {'unsafe_two_node_recovery': False}


def _save_ha_config_to_db(cluster_id: str, manager):
    """Helper to persist ha_config changes to database
    
    NS: Called after self-fence install/uninstall so status survives restart
    """
    try:
        # the copy on the manager too: save_config writes that one over the row
        manager.config.ha_settings = _ha_settings_of(manager)
        db = get_db()
        cluster = db.get_cluster(cluster_id)
        if cluster:
            cluster['ha_settings'] = dict(manager.config.ha_settings)
            db.save_cluster(cluster_id, cluster)
            logging.info(f"[HA] Persisted ha_config to database for {cluster_id}")
    except Exception as e:
        logging.error(f"[HA] Failed to persist ha_config: {e}")


@bp.route('/api/clusters/<cluster_id>/ha/install-self-fence', methods=['POST'])
@require_auth(perms=['ha.config'])
def install_self_fence_agent(cluster_id):
    """Install self-fence agent on all cluster nodes"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    # Run installation in background
    def do_install():
        try:
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            manager.logger.info("[HA] INSTALLING SELF-FENCE AGENTS ON ALL NODES")
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            results = manager._ha_install_self_fence_on_all_nodes()
            success_count = sum(1 for v in results.values() if v)
            manager.logger.info(f"[HA] ✓ Self-fence installation complete: {success_count}/{len(results)} nodes")
            
            # Store installation status
            manager.ha_config['self_fence_installed'] = success_count > 0
            manager.ha_config['self_fence_nodes'] = [k for k, v in results.items() if v]
            
            # NS: Persist to database so it survives restart
            _save_ha_config_to_db(cluster_id, manager)
        except Exception as e:
            manager.logger.error(f"[HA] ✗ Self-fence installation failed: {e}")
    
    threading.Thread(target=ha.as_job(do_install, 'self-fence agents'), daemon=True).start()
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.self_fence_install', f"Self-fence agent installation started for cluster {manager.config.name}", cluster=manager.config.name)
    
    return jsonify({
        'message': 'Self-fence agent installation started',
        'status': 'installing'
    })


@bp.route('/api/clusters/<cluster_id>/ha/uninstall-self-fence', methods=['POST'])
@require_auth(perms=['ha.config'])
def uninstall_self_fence_agent(cluster_id):
    """Uninstall self-fence agent from all cluster nodes"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    # Run uninstallation in background
    def do_uninstall():
        try:
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            manager.logger.info("[HA] UNINSTALLING SELF-FENCE AGENTS FROM ALL NODES")
            manager.logger.info("[HA] ═══════════════════════════════════════════════════════")
            results = manager._ha_uninstall_self_fence_on_all_nodes()
            success_count = sum(1 for v in results.values() if v)
            manager.logger.info(f"[HA] ✓ Self-fence uninstallation complete: {success_count}/{len(results)} nodes")
            
            # Update status
            manager.ha_config['self_fence_installed'] = False
            manager.ha_config['self_fence_nodes'] = []
            
            # NS: Persist to database
            _save_ha_config_to_db(cluster_id, manager)
        except Exception as e:
            manager.logger.error(f"[HA] ✗ Self-fence uninstallation failed: {e}")
    
    threading.Thread(target=ha.as_job(do_uninstall, 'self-fence agents'), daemon=True).start()
    
    user = getattr(request, 'session', {}).get('user', 'system')
    log_audit(user, 'ha.self_fence_uninstall', f"Self-fence agent uninstallation started for cluster {manager.config.name}", cluster=manager.config.name)
    
    return jsonify({
        'message': 'Self-fence agent uninstallation started',
        'status': 'uninstalling'
    })


@bp.route('/api/clusters/<cluster_id>/ha/agent-check', methods=['POST'])
@require_auth(perms=['ha.config'])
def check_ha_agents(cluster_id):
    """The install check: which agents every node of the cluster runs (#625).

    Read over SSH from each node. For every node: the self-fence agent's version
    (0 none, 1 the agent that pings one PegaProx address, 2 quorum first), its mode,
    whether it runs and whether it is the script this instance would install now;
    whether the node agent is there; and, where the agents ask the PegaProx instances
    for the leader, the instances the node cannot reach. `outdated` names the nodes
    below the current version, `unreachable` the ones that did not answer. An outdated
    agent keeps running as it is: `outdated_warning` says so and that the install
    from the HA settings replaces it."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    manager = cluster_managers[cluster_id]
    if not hasattr(manager, '_ha_check_agents'):
        return jsonify({'error': 'Node agents exist on Proxmox clusters only'}), 400
    try:
        report = manager._ha_check_agents()
    except Exception as e:
        return jsonify({'error': safe_error(e, 'The agent check failed')}), 502
    if report is None:
        return jsonify({'error': 'The cluster did not list its nodes'}), 502
    # the versions found are what the HA status reports from now on
    _save_ha_config_to_db(cluster_id, manager)

    nodes = report['nodes']
    report['unreachable'] = sorted(n for n, info in nodes.items() if info is None)
    report['outdated'] = sorted(n for n, info in nodes.items()
                                if info and 0 < info['fence_agent']['version'] < report['expected_version'])
    report['outdated_warning'] = (PegaProxManager.FENCE_AGENT_OUTDATED.format(
        nodes=', '.join(report['outdated']), version=report['expected_version'])
        if report['outdated'] else None)
    report['not_current'] = sorted(n for n, info in nodes.items()
                                   if info and info['fence_agent']['version'] == report['expected_version']
                                   and not info['fence_agent']['current'])
    return jsonify(report)


def _recovery_runs_asked():
    """The run ids of an interrupted-recoveries body, None when it is not a list of them."""
    data = request.get_json(silent=True)
    runs = data.get('runs') if isinstance(data, dict) else None
    if (not isinstance(runs, list) or not runs or len(runs) > ha.RECOVERY_KEEP
            or not all(isinstance(r, str) and 0 < len(r) <= 64 for r in runs)):
        return None
    return list(dict.fromkeys(runs))


@bp.route('/api/clusters/<cluster_id>/ha/interrupted-recoveries/start', methods=['POST'])
@require_auth(perms=['ha.config'])
def start_interrupted_recoveries(cluster_id):
    """Start the guests that node recoveries an automatic leader left half done moved and
    did not start (#625, design 5.6) - the one way on from there, nothing resumes them on
    its own. Body {runs: [run id]}, the runs of interrupted_recoveries in the HA status.

    A guest held on purpose (moved while its node was online) is not started: `held`
    names it with the reason. A run is forgotten once each of its moved guests started
    and nothing else is left in it; `unknown` are runs this cluster does not list."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    manager = cluster_managers[cluster_id]
    if not hasattr(manager, 'ha_start_moved_vms'):
        return jsonify({'error': 'Node recoveries exist on Proxmox clusters only'}), 400
    runs = _recovery_runs_asked()
    if runs is None:
        return jsonify({'error': 'runs must be a list of run ids'}), 400

    asked = [r for r in manager.ha_interrupted_recoveries() if r['run'] in runs]
    started = manager.ha_start_moved_vms(runs=[r['run'] for r in asked], listed=asked)
    held = [{'vmid': v, 'run': r['run'], 'node': r['node'], 'note': r['held_note']}
            for r in asked for v in r['held']]
    ok_ids = sorted(v for v, went in started.items() if went)
    failed = sorted(v for v, went in started.items() if not went)
    user = getattr(request, 'session', {}).get('user', 'system')
    name = manager.config.name
    log_audit(user, 'ha.interrupted_recoveries_started',
              f"Cluster {name}: moved guests of interrupted recoveries started: "
              f"{', '.join(map(str, ok_ids)) or 'none'}; not started: {', '.join(map(str, failed)) or 'none'}; "
              f"held: {', '.join(str(h['vmid']) for h in held) or 'none'}", cluster=name)
    return jsonify({'started': ok_ids, 'failed': failed, 'held': held,
                    'unknown': sorted(set(runs) - {r['run'] for r in asked})})


@bp.route('/api/clusters/<cluster_id>/ha/interrupted-recoveries/dismiss', methods=['POST'])
@require_auth(perms=['ha.config'])
def dismiss_interrupted_recoveries(cluster_id):
    """An admin dealt with what these interrupted recoveries left (#625, design 5.6): they
    are not listed or said any more. Body {runs: [run id]}; runs of this cluster only,
    nothing on the cluster changes."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    runs = _recovery_runs_asked()
    if runs is None:
        return jsonify({'error': 'runs must be a list of run ids'}), 400

    known = {r['run'] for r in ha.recovery_leftovers(cluster_id)}
    gone = [r for r in runs if r in known]
    ha.recovery_forget(gone)
    if gone:
        user = getattr(request, 'session', {}).get('user', 'system')
        name = cluster_managers[cluster_id].config.name
        log_audit(user, 'ha.interrupted_recoveries_dismissed',
                  f"Cluster {name}: interrupted recoveries dismissed: {', '.join(gone)}", cluster=name)
    return jsonify({'dismissed': gone, 'unknown': sorted(set(runs) - known)})


@bp.route('/api/clusters/<cluster_id>/ha/claim', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def set_cluster_claim(cluster_id):
    """Switch the cluster claim of one cluster on or off, or release a foreign claim (#625).

    The claim is off unless an admin switches it on. With it on, PegaProx writes
    /etc/pve/pegaprox/claim into the cluster's file system; node recovery then runs
    only while that file names this instance, and its SSH steps are refused at the
    node otherwise. The HA status of the cluster carries the full warning text.

    action "enable" wants confirm "WRITE CLAIM", "release" (write over the claim of
    another instance) wants "RELEASE CLAIM", "disable" removes our claim again. All
    three want user_password, like the instance HA routes; no API token."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    from pegaprox.api.ha import _refuse_confined_admin, _refuse_without_reauth
    denied = _refuse_confined_admin()
    if denied:
        return denied

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    manager = cluster_managers[cluster_id]
    if not hasattr(manager, '_ha_claim_ensure'):
        return jsonify({'error': 'The cluster claim exists on Proxmox clusters only'}), 400
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    action = data.get('action')
    if action not in ('enable', 'disable', 'release'):
        return jsonify({'error': 'action must be enable, disable or release'}), 400
    phrase = {'enable': CLAIM_ON_PHRASE, 'release': CLAIM_RELEASE_PHRASE}.get(action)
    if phrase and data.get('confirm') != phrase:
        return jsonify({'error': f'Type {phrase} to confirm', 'code': 'HA_CLAIM_CONFIRM',
                        'warning': manager.CLAIM_WARNING}), 400
    if action == 'release' and not manager._ha_claim_enabled():
        return jsonify({'error': 'The cluster claim is off for this cluster'}), 409
    if action != 'disable' and manager.ssh_blocked_reason():
        return jsonify({'error': 'The cluster claim is written over SSH, which is not available '
                                 'for this cluster'}), 409
    denied = _refuse_without_reauth(f'the cluster claim of {manager.config.name} ({action})')
    if denied:
        return denied

    user = getattr(request, 'session', {}).get('user', 'system')
    name = manager.config.name
    if action == 'disable':
        # what became of the file, as HA disable and the delete report it: where it
        # may still be there this said the state and nothing else, with the switch
        # already off and no word on how to remove it
        removed = _retire_cluster_claim(manager, every_node=True) or {'state': 'off'}
        manager.ha_config['claim_enabled'] = False
        _save_ha_config_to_db(cluster_id, manager)
        log_audit(user, 'ha.claim_disabled', f"Cluster claim switched off for cluster {name} "
                                             f"(our claim: {removed.get('state')})", cluster=name)
        return jsonify({'claim': manager._ha_claim_status(), 'removed': removed.get('state'),
                        'warning': removed.get('warning'), 'by_hand': removed.get('by_hand')})

    if action == 'enable':
        manager.ha_config['claim_enabled'] = True
        _save_ha_config_to_db(cluster_id, manager)
        result = _ensure_cluster_claim(manager)
        log_audit(user, 'ha.claim_enabled', f"Cluster claim switched on for cluster {name}: PegaProx "
                                            f"writes /etc/pve/pegaprox/claim there ({result.get('state')})",
                  cluster=name)
        return jsonify({'claim': manager._ha_claim_status()})

    # release: whose claim it is goes into the audit trail before it is written over
    before = _ensure_cluster_claim(manager)
    if before.get('state') == 'ours':
        return jsonify({'error': 'The claim is this instance\'s already',
                        'claim': manager._ha_claim_status()}), 409
    result = _ensure_cluster_claim(manager, takeover=True)
    log_audit(user, 'ha.claim_released',
              f"Cluster {name}: claim of instance {before.get('instance') or '?'} (epoch "
              f"{before.get('epoch')}, {before.get('state')}) written over with ours "
              f"({result.get('state')})", cluster=name)
    return jsonify({'claim': manager._ha_claim_status()})


@bp.route('/api/clusters/<cluster_id>/ha', methods=['PUT'])
@require_auth(perms=['ha.config'])
def set_ha_status(cluster_id):
    # sec (audit): the legacy HA toggle. Its modern siblings (enable_ha / disable_ha /
    # update_ha_config) all got the confinement gate in this campaign and this one was missed —
    # it flips HA for the whole cluster.
    """Enable or disable HA for a cluster (legacy endpoint)"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    data = request.json or {}
    enable = data.get('enable', True)
    
    if enable:
        manager.start_ha_monitor()
        manager.config.ha_enabled = True
        save_config()
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'ha.enabled', f"High Availability enabled for cluster {manager.config.name}", cluster=manager.config.name)
        return jsonify({
            'message': 'High Availability aktiviert',
            'status': manager.get_ha_status()
        })
    else:
        manager.stop_ha_monitor()
        manager.config.ha_enabled = False
        save_config()
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'ha.disabled', f"High Availability disabled for cluster {manager.config.name}", cluster=manager.config.name)
        return jsonify({
            'message': 'High Availability disabled',
            'status': manager.get_ha_status()
        })


def _ha_sid_authorized(cluster_id, sid, perm='vm.config'):
    """sec (audit): the HA routes take a caller-supplied guest and had cluster-level gating only.
    ha.view and ha.config are BOTH granted by the shipped tenant_admin template, so a caller
    admitted by the #248/#555 fallbacks could enumerate every guest's HA state and add/remove
    foreign guests from HA (an availability lever). The plugin twin already filters its listing;
    this is the same question for the core routes."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    _kind, _, _num = str(sid or '').partition(':')
    if _kind not in ('vm', 'ct') or not _num.isdigit():
        return False
    _u = build_authz_user(request.session.get('user', ''), request.session)
    return user_can_access_vm(_u, cluster_id, int(_num), perm,
                              'lxc' if _kind == 'ct' else 'qemu')


# Proxmox Native HA API Routes
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_proxmox_ha_resources(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    _res = cluster_managers[cluster_id].get_proxmox_ha_resources()
    if isinstance(_res, list):
        _res = [r for r in _res if _ha_sid_authorized(cluster_id, r.get('sid'), 'vm.view')]
    return jsonify(_res)


@bp.route('/api/clusters/<cluster_id>/proxmox-ha/groups', methods=['GET'])
@require_auth(perms=['ha.view'])
def get_proxmox_ha_groups(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    return jsonify(cluster_managers[cluster_id].get_proxmox_ha_groups())


# MK: Create HA Group
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/groups', methods=['POST'])
@require_auth(perms=['ha.config'])
def create_proxmox_ha_group(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    
    manager, error = get_connected_manager(cluster_id)
    if error:
        return error
    
    data = request.json or {}
    group_name = data.get('group')
    nodes = data.get('nodes')
    
    if not group_name or not nodes:
        return jsonify({'error': 'group and nodes required'}), 400
    
    try:
        host, port = manager.host, manager.api_port
        # MK May 2026 — PVE 9.1.x replaced /cluster/ha/groups with /cluster/ha/rules.
        # Try rules-shape POST first (translated from group fields). On 404/501
        # fall back to the legacy groups endpoint for PVE 8.x.
        rules_payload = {
            'rule': group_name,
            'type': 'node-affinity',
            'nodes': nodes,
            # /rules requires non-empty resources. Caller can specify them
            # via 'resources' on the request body; otherwise PegaProx passes
            # whatever the resource picker collected.  If empty PVE will
            # reject with a clear message, which we surface to the user.
            'resources': data.get('resources', '') or '',
        }
        if data.get('restricted'):
            rules_payload['strict'] = 1
        if data.get('comment'):
            rules_payload['comment'] = data['comment']

        rules_url = f"https://{host}:{port}/api2/json/cluster/ha/rules"
        resp = manager._api_post(rules_url, data=rules_payload)

        if resp.status_code in (404, 501):
            # PVE 8.x — legacy groups path
            legacy_url = f"https://{host}:{port}/api2/json/cluster/ha/groups"
            legacy_payload = {
                'group': group_name,
                'nodes': nodes,
            }
            if data.get('restricted'):
                legacy_payload['restricted'] = 1
            if data.get('nofailback'):
                legacy_payload['nofailback'] = 1
            if data.get('comment'):
                legacy_payload['comment'] = data['comment']
            resp = manager._api_post(legacy_url, data=legacy_payload)

        if resp.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ha.group_created', f"HA group '{group_name}' created", cluster=manager.config.name)
            return jsonify({'success': True})
        else:
            # Pass PVE's own error through — usually informative enough
            # ("no resources were specified", "duplicate rule name", etc.)
            return jsonify({'error': resp.text}), 400
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500


# MK: Delete HA Group
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/groups/<group_name>', methods=['DELETE'])
@require_auth(perms=['ha.config'])
def delete_proxmox_ha_group(cluster_id, group_name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr

    manager, error = get_connected_manager(cluster_id)
    if error:
        return error

    try:
        host, port = manager.host, manager.api_port
        # MK May 2026 — same rules-first/groups-fallback as the create path.
        rules_url = f"https://{host}:{port}/api2/json/cluster/ha/rules/{group_name}"
        resp = manager._api_delete(rules_url)
        if resp.status_code in (404, 501) or (resp.status_code == 500 and 'no such ha rule' in (resp.text or '').lower()):
            legacy_url = f"https://{host}:{port}/api2/json/cluster/ha/groups/{group_name}"
            resp = manager._api_delete(legacy_url)

        if resp.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ha.group_deleted', f"HA group '{group_name}' deleted", cluster=manager.config.name)
            return jsonify({'success': True})
        else:
            return jsonify({'error': resp.text}), 400
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources', methods=['POST'])
@require_auth(perms=['ha.config'])
def add_to_proxmox_ha(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.json or {}
    
    logging.debug(f"[HA] Add resource request: {data}")
    
    # MK: Support both sid format (vm:100) and separate vmid/type
    sid = data.get('sid', '').strip()
    if sid and ':' in sid:
        parts = sid.split(':')
        vm_type = parts[0]  # vm or ct
        vmid = parts[1]
    else:
        vmid = data.get('vmid')
        vm_type = data.get('type', 'vm')
    
    group = data.get('group')
    max_restart = data.get('max_restart', 1)
    max_relocate = data.get('max_relocate', 1)
    state = data.get('state', 'started')
    comment = data.get('comment', '')
    # MK May 2026 (PVE 9.2) — per-resource auto-rebalance opt-out. None means
    # caller didn't specify, leave PVE defaults alone; True/False = explicit.
    auto_rebalance = data.get('auto_rebalance')
    if auto_rebalance is not None:
        auto_rebalance = bool(auto_rebalance)

    if not vmid:
        logging.warning(f"[HA] Add resource failed: no vmid/sid in request data: {_sl(data)}")
        return jsonify({'error': 'vmid or sid required (format: vm:100 or ct:101)'}), 400
    if not _ha_sid_authorized(cluster_id, f"{vm_type}:{vmid}"):
        return jsonify({'error': 'Access denied to this VM'}), 403

    result = mgr.add_vm_to_proxmox_ha(vmid, vm_type, group, max_restart, max_relocate, state, comment,
                                       auto_rebalance=auto_rebalance)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'ha.vm_added', f"{vm_type.upper()} {vmid} added to HA" + (f" (group: {group})" if group else ""), cluster=mgr.config.name)
        return jsonify(result)
    else:
        return jsonify(result), 400


@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources/<vm_type>:<int:vmid>', methods=['DELETE'])
@require_auth(perms=['ha.config'])
def remove_from_proxmox_ha(cluster_id, vm_type, vmid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    if not _ha_sid_authorized(cluster_id, f"{vm_type}:{vmid}"):
        return jsonify({'error': 'Access denied to this VM'}), 403

    mgr = cluster_managers[cluster_id]
    result = mgr.remove_vm_from_proxmox_ha(vmid, vm_type)
    
    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'ha.vm_removed', f"{vm_type.upper()} {vmid} removed from HA", cluster=mgr.config.name)
        return jsonify(result)
    else:
        return jsonify(result), 400


# MK: Alternative DELETE endpoint that accepts full sid string like "vm:100"
@bp.route('/api/clusters/<cluster_id>/proxmox-ha/resources/<sid>', methods=['DELETE'])
@require_auth(perms=['ha.config'])
def remove_from_proxmox_ha_by_sid(cluster_id, sid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    # Parse sid (vm:100 or ct:101)
    if ':' in sid:
        vm_type, vmid = sid.split(':', 1)
        try:
            vmid = int(vmid)
        except ValueError:
            return jsonify({'error': f'Invalid VMID in sid: {sid}'}), 400
    else:
        return jsonify({'error': f'Invalid sid format: {sid}. Expected vm:VMID or ct:VMID'}), 400

    if not _ha_sid_authorized(cluster_id, f"{vm_type}:{vmid}"):
        return jsonify({'error': 'Access denied to this VM'}), 403

    result = mgr.remove_vm_from_proxmox_ha(vmid, vm_type)

    if result['success']:
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'ha.vm_removed', f"{vm_type.upper()} {vmid} removed from HA", cluster=mgr.config.name)
        return jsonify(result)
    else:
        return jsonify(result), 400


# LW: Mar 2026 - manual balance trigger (#149)
@bp.route('/api/clusters/<cluster_id>/balance-now', methods=['POST'])
@require_auth(perms=['cluster.config'])
def trigger_balance_now(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # NS Aug 2026 (Aikido 469089250) — balance-now spawns cluster-wide node-to-node VM migrations, so
    # confine it to clusters the caller's TENANT owns; a user who reached this cluster only via a
    # single VM-ACL / pool grant (the #248/#555 fallbacks in check_cluster_access) must not rebalance
    # VMs outside their scope. Admins / default-tenant (get_user_clusters None) unaffected. Mirrors
    # the cluster-group balance guard in groups.py.
    _sess = getattr(request, 'session', {})
    _usr = _sess.get('user', 'system')
    # sec (audit): the open-coded form here did NOT do what the comment above says. get_user_clusters
    # defaults to include_pools=True, so a pool-scoped caller's cluster IS in _allowed and the check
    # passed — the #555 fallback it was meant to close walked straight through it, and a VM-ACL
    # caller inside an owning tenant did too. caller_is_scoped is the predicate that asks the
    # question correctly.
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        log_audit(_usr, 'balance.manual_denied', f"Denied balance-now on {cluster_id} (caller is confined)")
        return _cerr

    mgr = cluster_managers.get(cluster_id)
    if not mgr:
        return jsonify({'error': 'Cluster not found'}), 404
    if not mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    import gevent
    gevent.spawn(mgr.run_balance_check, force=True)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'balance.manual', f"Manual balance check triggered for {mgr.config.name}", cluster=mgr.config.name)

    return jsonify({'message': 'Balance check started'})


@bp.route('/api/clusters/<cluster_id>/proxlb-pins/violations', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_proxlb_pin_violations(cluster_id):
    """Guests running somewhere their plb_pin_<node> tag does not allow.

    Read-only. A pin only vetoes moves the balancer proposes, so this is the
    only way to see a guest that ended up off its pinned node and stayed there.
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    # MK Oct 2026 - plb_ tags are PVE tags; an XCP-ng pool or ESXi host has none to report
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return jsonify({'enabled': False, 'auto_migrate': False, 'violations': [], 'unresolved': [],
                        'can_reconcile': False})
    # the "move back now" button asks what the reconcile route asks: vm.migrate AND
    # the whole cluster. The permission list in the browser only knows the first half,
    # a pool or VM-ACL scoped caller holds vm.migrate and is still turned away there.
    from pegaprox.api.helpers import caller_is_scoped
    _user = build_authz_user(request.session.get('user', ''), request.session)
    can_reconcile = has_permission(_user, 'vm.migrate') and not caller_is_scoped(_user, cluster_id)
    try:
        return jsonify({
            'enabled': bool(getattr(mgr.config, 'proxlb_tags_enabled', False)),
            'auto_migrate': bool(getattr(mgr.config, 'proxlb_pins_auto_migrate', False)),
            'can_reconcile': bool(can_reconcile),
            # Both lists are per-VM rows (vmid / name / node / pinned nodes) for
            # every guest on the cluster, and check_cluster_access only gates
            # cluster REACHABILITY - its pool/ACL fallbacks admit a caller who may
            # see one VM. Same #773 class of leak as the other per-VM reads, so
            # the same filter: admins and cluster-wide operators keep every row.
            'violations': scope_vm_rows(cluster_id, mgr.get_pin_violations()),
            # a pin naming a node this cluster does not have is the most common
            # reason a pin looks like it does nothing at all
            'unresolved': scope_vm_rows(cluster_id, mgr.get_unresolved_pins()),
        })
    except Exception as e:
        logging.error(f"proxlb pin scan failed: {_sl(str(e))}")
        return jsonify({'error': 'Failed to scan pins'}), 500


@bp.route('/api/clusters/<cluster_id>/proxlb-pins/reconcile', methods=['POST'])
@require_auth(perms=['vm.migrate'])
def reconcile_proxlb_pins_api(cluster_id):
    """Migrate guests that drifted off their pinned node back onto it.

    Honours config.proxlb_pins_auto_migrate unless the body sets force=true,
    which is the manual "do it now" button - it still refuses under dry_run.
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    # Same gate as /balance-now (Aikido 469089250): this migrates guests across the
    # whole cluster, so a caller who reached it through a single VM-ACL / pool grant
    # (the #248/#555 fallbacks in check_cluster_access) must not be able to move
    # other guests. require_unconfined is the predicate that asks that correctly -
    # the open-coded get_user_clusters form does NOT, because it defaults to
    # include_pools=True and a pool-scoped caller's cluster is in the result.
    _sess = getattr(request, 'session', {})
    _usr = _sess.get('user', 'system')
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        log_audit(_usr, 'balance.pin_reconcile_denied',
                  f"Denied pin reconcile on {cluster_id} (caller is confined)")
        return _cerr

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return jsonify({'error': 'plb_pin_ tags are read on Proxmox VE clusters only',
                        'code': 'PVE_ONLY'}), 400
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({'error': 'Request body must be a JSON object'}), 400
    force = body.get('force', False)
    if not isinstance(force, bool):
        return jsonify({'error': "'force' must be a boolean"}), 400
    try:
        result = mgr.reconcile_proxlb_pins(force=force)
    except Exception as e:
        logging.error(f"proxlb pin reconcile failed: {_sl(str(e))}")
        return jsonify({'error': 'Reconciliation failed'}), 500

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'balance.pin_reconcile',
              f"Cluster {mgr.config.name}: {len(result['migrated'])} guest(s) returned to their "
              f"pinned node, {len(result['failed'])} failed"
              + (' (forced)' if force else ''),
              cluster=mgr.config.name)
    return jsonify(result)
