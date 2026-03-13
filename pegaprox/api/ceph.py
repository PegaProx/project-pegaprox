# -*- coding: utf-8 -*-
"""
PegaProx Ceph API Routes - Layer 6
Ceph cluster management: status, OSDs, monitors, pools, CephFS.
"""

import logging
from flask import Blueprint, jsonify, request

from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import get_connected_manager, check_cluster_access, safe_error

bp = Blueprint('ceph', __name__)


def _ceph_url(manager, node, sub=''):
    host = manager.current_host or manager.config.host
    return f"https://{host}:8006/api2/json/nodes/{node}/ceph{sub}"


# MK: Mar 2026 - PVE returns OSD data as CRUSH tree, not flat list
# need to walk the tree and pull out actual osd entries (#113)
def _flatten_osd_tree(data):
    """Extract flat OSD list from Proxmox CRUSH tree response."""
    osds = []
    if isinstance(data, dict):
        root = data.get('root', data)
        _walk_osd_nodes(root, None, osds)
    elif isinstance(data, list):
        # some PVE versions return flat array already
        for item in data:
            if isinstance(item, dict) and item.get('type') == 'osd':
                osds.append(item)
            elif isinstance(item, dict) and 'children' in item:
                _walk_osd_nodes(item, None, osds)
    return osds

def _walk_osd_nodes(node, parent_host, out):
    if not isinstance(node, dict):
        return
    ntype = node.get('type', '')
    host = parent_host
    if ntype == 'host':
        host = node.get('name', parent_host)
    if ntype == 'osd':
        entry = dict(node)
        if host and not entry.get('host'):
            entry['host'] = host
        out.append(entry)
    for child in node.get('children', []):
        _walk_osd_nodes(child, host, out)


# ============================================
# Datacenter-Level Ceph Overview
# ============================================

@bp.route('/api/clusters/<cluster_id>/datacenter/ceph', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_ceph_overview(cluster_id):
    """Ceph cluster overview - aggregates status from first available node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    result = {
        'available': False,
        'status': None,
        'osd': [],
        'mon': [],
        'mds': [],
        'mgr': [],
        'pools': [],
        'fs': [],
        'rules': [],
    }

    try:
        host = manager.current_host or manager.config.host
        session = manager._create_session()

        # Find first online node to query Ceph
        nodes_url = f"https://{host}:8006/api2/json/nodes"
        nr = session.get(nodes_url, timeout=5)
        online_nodes = []
        if nr.status_code == 200:
            online_nodes = [n['node'] for n in nr.json().get('data', []) if n.get('status') == 'online']

        if not online_nodes:
            return jsonify(result)

        node = online_nodes[0]

        # Check if Ceph is available
        try:
            status_r = session.get(_ceph_url(manager, node, '/status'), timeout=10)
            if status_r.status_code == 200:
                result['available'] = True
                result['status'] = status_r.json().get('data', {})
            elif status_r.status_code in (501, 500):
                return jsonify(result)
        except:
            return jsonify(result)

        if not result['available']:
            return jsonify(result)

        # Fetch all Ceph data
        endpoints = {
            'osd': '/osd',
            'mon': '/mon',
            'mds': '/mds',
            'mgr': '/mgr',
            'pools': '/pool',
            'fs': '/fs',
            'rules': '/rules',
        }

        for key, sub in endpoints.items():
            try:
                r = session.get(_ceph_url(manager, node, sub), timeout=10)
                if r.status_code == 200:
                    raw = r.json().get('data', [])
                    # MK: OSD endpoint returns CRUSH tree, flatten it (#113)
                    if key == 'osd':
                        raw = _flatten_osd_tree(raw)
                    result[key] = raw
            except:
                pass

        return jsonify(result)

    except Exception as e:
        logging.error(f"Error getting Ceph overview: {e}")
        return jsonify(result)


# ============================================
# Per-Node Ceph Status & Config
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/status', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_ceph_status(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/status'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', {}))
        if r.status_code in (501, 500):
            return jsonify({'available': False})
        return jsonify({}), r.status_code
    except:
        return jsonify({})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/config', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_ceph_config(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/config'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', ''))
        return jsonify('')
    except:
        return jsonify('')


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/log', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_ceph_log(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        params = {}
        if request.args.get('limit'):
            params['limit'] = request.args['limit']
        if request.args.get('start'):
            params['start'] = request.args['start']
        r = manager._create_session().get(_ceph_url(manager, node, '/log'), params=params, timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


# ============================================
# OSD Management
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/osd', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_osds(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/osd'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/osd', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_ceph_osd(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_ceph_url(manager, node, '/osd'), data=data, timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.osd.create', f"Created OSD on {node}: {data.get('dev', '')}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph OSD operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/osd/<int:osdid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def destroy_ceph_osd(cluster_id, node, osdid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # NS: Feb 2026 - SECURITY: require confirmation for destructive operations
    data = request.json or {}
    if str(data.get('confirm_name', '')) != str(osdid):
        return jsonify({'error': 'Confirmation required: send confirm_name matching the OSD ID'}), 400
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        params = {}
        if request.args.get('cleanup'):
            params['cleanup'] = 1
        r = manager._create_session().delete(_ceph_url(manager, node, f'/osd/{osdid}'), params=params, timeout=60)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.osd.destroy', f"Destroyed OSD {osdid} on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph OSD operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/osd/<int:osdid>/<action>', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def ceph_osd_action(cluster_id, node, osdid, action):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if action not in ('in', 'out', 'scrub', 'deep-scrub'):
        return jsonify({'error': f'Invalid OSD action: {action}'}), 400
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().post(_ceph_url(manager, node, f'/osd/{osdid}/{action}'), timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, f'ceph.osd.{action}', f"OSD {osdid} {action} on {node}", cluster=manager.config.name)
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph OSD operation failed')}), 500


# ============================================
# Monitor Management
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mon', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_mons(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/mon'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mon/<monid>', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_ceph_mon(cluster_id, node, monid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_ceph_url(manager, node, f'/mon/{monid}'), data=data, timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.mon.create', f"Created monitor {monid} on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph monitor operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mon/<monid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def destroy_ceph_mon(cluster_id, node, monid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_ceph_url(manager, node, f'/mon/{monid}'), timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.mon.destroy', f"Destroyed monitor {monid} on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph monitor operation failed')}), 500


# ============================================
# MDS (Metadata Server) Management
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mds', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_mds(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/mds'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mds/<name>', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_ceph_mds(cluster_id, node, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().post(_ceph_url(manager, node, f'/mds/{name}'), timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.mds.create', f"Created MDS {name} on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph service operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mds/<name>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def destroy_ceph_mds(cluster_id, node, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_ceph_url(manager, node, f'/mds/{name}'), timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.mds.destroy', f"Destroyed MDS {name} on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph service operation failed')}), 500


# ============================================
# MGR (Manager) - Read Only
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/mgr', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_mgr(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/mgr'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


# ============================================
# Pool Management
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/pool', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_pools(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/pool'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/pool', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_ceph_pool(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_ceph_url(manager, node, '/pool'), data=data, timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.pool.create', f"Created pool {data.get('name', '')}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph pool operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/pool/<name>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_ceph_pool(cluster_id, node, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().put(_ceph_url(manager, node, f'/pool/{name}'), data=data, timeout=10)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.pool.update', f"Updated pool {name}", cluster=manager.config.name)
            return jsonify({'success': True})
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph pool operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/pool/<name>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def destroy_ceph_pool(cluster_id, node, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # NS: Feb 2026 - SECURITY: require confirmation for destructive operations
    data = request.json or {}
    if data.get('confirm_name') != name:
        return jsonify({'error': 'Confirmation required: send confirm_name matching the pool name'}), 400
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        params = {}
        if request.args.get('remove_storages'):
            params['remove_storages'] = 1
        if request.args.get('remove_ecprofile'):
            params['remove_ecprofile'] = 1
        r = manager._create_session().delete(_ceph_url(manager, node, f'/pool/{name}'), params=params, timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.pool.destroy', f"Destroyed pool {name}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph pool operation failed')}), 500


# ============================================
# CephFS Management
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/fs', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_fs(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/fs'), timeout=10)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/fs', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_ceph_fs(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_ceph_url(manager, node, '/fs'), data=data, timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.fs.create', f"Created CephFS {data.get('name', '')}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'CephFS operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/fs/<name>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def destroy_ceph_fs(cluster_id, node, name):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    # NS: Feb 2026 - SECURITY: require confirmation for destructive operations
    data = request.json or {}
    if data.get('confirm_name') != name:
        return jsonify({'error': 'Confirmation required: send confirm_name matching the CephFS name'}), 400
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().delete(_ceph_url(manager, node, f'/fs/{name}'), timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.fs.destroy', f"Destroyed CephFS {name}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'CephFS operation failed')}), 500


# ============================================
# CRUSH Rules
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/rules', methods=['GET'])
@require_auth(perms=['node.view'])
def get_ceph_rules(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        r = manager._create_session().get(_ceph_url(manager, node, '/rules'), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json().get('data', []))
        return jsonify([])
    except:
        return jsonify([])


# ============================================
# Service Control
# ============================================

@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/<action>', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def ceph_service_action(cluster_id, node, action):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    if action not in ('start', 'stop', 'restart'):
        return jsonify({'error': f'Invalid service action: {action}'}), 400
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_ceph_url(manager, node, f'/{action}'), data=data, timeout=30)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, f'ceph.service.{action}', f"Ceph {action} on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph service operation failed')}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/ceph/init', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def init_ceph(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error
    try:
        data = request.json or {}
        r = manager._create_session().post(_ceph_url(manager, node, '/init'), data=data, timeout=60)
        if r.status_code == 200:
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'ceph.init', f"Initialized Ceph on {node}", cluster=manager.config.name)
            return jsonify(r.json().get('data', ''))
        return jsonify({'error': r.text}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Ceph init failed')}), 500
