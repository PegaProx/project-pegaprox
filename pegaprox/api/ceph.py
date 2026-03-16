"""
PegaProx Ceph API Routes - Layer 6
Ceph cluster management: status, OSDs, monitors, pools, CephFS, RBD mirroring.
"""

import re
import json
import logging
from flask import Blueprint, jsonify, request

from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import get_connected_manager, check_cluster_access, safe_error

bp = Blueprint('ceph', __name__)


def _ceph_url(manager, node, sub=''):
    host = manager.host
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


# MK: Mar 2026 - Input validators for rbd mirror commands
# Pool/image names go into shell commands via SSH, so we MUST validate
_POOL_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,63}$')
_IMAGE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$')
_SCHED_RE = re.compile(r'^\d+[mhd]$')  # e.g. 5m, 1h, 1d

def _valid_pool(name):
    return bool(name and _POOL_RE.match(name))

def _valid_image(name):
    return bool(name and _IMAGE_RE.match(name))


def _get_any_online_node(manager):
    """NS: grab first online node - same approach as get_ceph_overview"""
    try:
        host = manager.host
        session = manager._create_session()
        nr = session.get(f"https://{host}:8006/api2/json/nodes", timeout=5)
        if nr.status_code == 200:
            for n in nr.json().get('data', []):
                if n.get('status') == 'online':
                    return n['node'], None
    except Exception as e:
        logging.warning(f"Failed to enumerate nodes: {e}")
    return None, (jsonify({'error': 'No online node found'}), 503)


def _resolve_node_ip(manager, node_name):
    """MK: resolve node name to IP via cluster/status API
    We need the actual IP for SSH, not the node name."""
    try:
        session = manager._create_session()
        resp = session.get(f"https://{manager.host}:8006/api2/json/cluster/status", timeout=8)
        if resp.status_code == 200:
            for item in resp.json().get('data', []):
                if item.get('type') == 'node' and item.get('name') == node_name:
                    return item.get('ip', manager.raw_host)
    except:
        pass
    # fallback — raw IP for SSH, not bracketed
    return manager.raw_host


def _rbd_cmd(manager, node_ip, args, timeout=30, expect_json=True):
    """MK: Mar 2026 - Execute rbd command over SSH
    Returns (data, None) on success or (None, error_response) on failure.

    Uses manager._ssh_connect which handles key/password auth,
    rate limiting, retries etc. We just need the IP.
    """
    ssh = None
    try:
        ssh = manager._ssh_connect(node_ip)
        if not ssh:
            return None, (jsonify({'error': 'SSH connection failed - check SSH credentials in cluster settings'}), 503)

        fmt = ' --format json' if expect_json else ''
        cmd = f"rbd {args}{fmt}"
        logging.debug(f"rbd cmd on {node_ip}: {cmd}")

        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='replace').strip()
        err = stderr.read().decode('utf-8', errors='replace').strip()

        # NS: exit code 22 = EINVAL, usually means mirroring not enabled on pool
        if exit_code == 22:
            if expect_json:
                return {}, None
            return '', None

        if exit_code != 0:
            # rbd not installed
            if 'command not found' in err or 'No such file' in err:
                return None, (jsonify({'error': 'rbd command not found - is ceph-common installed?'}), 501)
            msg = err or out or f'rbd exited with code {exit_code}'
            return None, (jsonify({'error': msg}), 500)

        if not expect_json or not out:
            return out, None

        try:
            return json.loads(out), None
        except json.JSONDecodeError:
            # NS: some rbd commands output partial JSON or plain text
            return {'raw': out}, None

    except Exception as e:
        logging.error(f"rbd SSH error on {node_ip}: {e}")
        return None, (jsonify({'error': f'SSH error: {str(e)}'}), 503)
    finally:
        if ssh:
            try:
                ssh.close()
            except:
                pass


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
        host = manager.host
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
            return jsonify(_flatten_osd_tree(r.json().get('data', [])))
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


# ============================================
# RBD Mirroring
# MK: Mar 2026 - Proxmox doesn't expose rbd-mirror via API,
# so we SSH into a node and run rbd CLI commands directly.
# ============================================

@bp.route('/api/clusters/<cluster_id>/ceph/mirror/overview', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_mirror_overview(cluster_id):
    """LW: overview of mirroring status across all pools"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    # get pool list from Proxmox API first
    pools = []
    try:
        session = manager._create_session()
        r = session.get(_ceph_url(manager, node, '/pool'), timeout=10)
        if r.status_code == 200:
            pools = r.json().get('data', [])
    except:
        pass

    if not pools:
        return jsonify({'pools': [], 'node': node})

    result = []
    for pool_info in pools:
        pname = pool_info.get('pool_name') or pool_info.get('name', '')
        if not pname or not _valid_pool(pname):
            continue

        entry = {'name': pname, 'mode': 'disabled', 'peers': [], 'health': None, 'image_count': 0}

        # NS: get mirror info for this pool
        info, info_err = _rbd_cmd(manager, node_ip, f'mirror pool info {pname}')
        if not info_err and isinstance(info, dict):
            mode = info.get('mode', 'disabled')
            entry['mode'] = mode if mode != 'disabled' else 'disabled'
            entry['peers'] = info.get('peers', [])
            entry['site_name'] = info.get('site_name', '')

        # only fetch status if mirroring is actually on
        if entry['mode'] != 'disabled':
            status, st_err = _rbd_cmd(manager, node_ip, f'mirror pool status {pname}')
            if not st_err and isinstance(status, dict):
                summary = status.get('summary', {})
                health = status.get('health', 'UNKNOWN')
                entry['health'] = health
                entry['image_count'] = summary.get('states', {}).get('total', 0) if isinstance(summary, dict) else 0
                entry['summary'] = summary

        result.append(entry)

    return jsonify({'pools': result, 'node': node})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_mirror_pool_status(cluster_id, pool):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror pool status {pool}')
    if cmd_err: return cmd_err
    return jsonify(data)


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/enable', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def enable_mirror_pool(cluster_id, pool):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    body = request.json or {}
    mode = body.get('mode', 'image')
    if mode not in ('pool', 'image'):
        return jsonify({'error': 'Mode must be "pool" or "image"'}), 400

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror pool enable {pool} {mode}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.pool.enable', f"Enabled mirroring on pool {pool} (mode={mode})", cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/disable', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def disable_mirror_pool(cluster_id, pool):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror pool disable {pool}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.pool.disable', f"Disabled mirroring on pool {pool}", cluster=manager.config.name)
    return jsonify({'success': True})


# -- Peer management --

@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/peer', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def add_mirror_peer(cluster_id, pool):
    """MK: add a mirroring peer to a pool"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    body = request.json or {}
    client = body.get('client', 'client.admin')
    site = body.get('site_name', '')
    mon_host = body.get('mon_host', '')

    if not site:
        return jsonify({'error': 'site_name is required'}), 400
    # MK: validate client/site to prevent injection
    if not re.match(r'^[a-zA-Z0-9._\-]+$', client):
        return jsonify({'error': 'Invalid client name'}), 400
    if not re.match(r'^[a-zA-Z0-9._\-]+$', site):
        return jsonify({'error': 'Invalid site name'}), 400

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    cmd = f'mirror pool peer add {pool} {client}@{site}'
    if mon_host:
        # LW: mon_host can have commas/colons for multiple monitors
        if not re.match(r'^[a-zA-Z0-9._:\-,/\[\]]+$', mon_host):
            return jsonify({'error': 'Invalid monitor host format'}), 400
        cmd += f' --mon-host {mon_host}'

    data, cmd_err = _rbd_cmd(manager, node_ip, cmd, expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.peer.add', f"Added mirror peer {client}@{site} to pool {pool}", cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/peer/<uuid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def remove_mirror_peer(cluster_id, pool, uuid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400
    # MK: UUID format validation
    if not re.match(r'^[a-f0-9\-]{36}$', uuid):
        return jsonify({'error': 'Invalid peer UUID'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror pool peer remove {pool} {uuid}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.peer.remove', f"Removed mirror peer {uuid} from pool {pool}", cluster=manager.config.name)
    return jsonify({'success': True})


# -- Image mirroring --

@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/images', methods=['GET'])
@require_auth(perms=['cluster.view'])
def list_mirror_images(cluster_id, pool):
    """NS: list images + their mirror status in one go
    We batch this in a single SSH session to avoid hammering the node"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    # first get the image list
    images_data, img_err = _rbd_cmd(manager, node_ip, f'ls {pool}')
    if img_err: return img_err

    # rbd ls --format json returns a list of image names
    if isinstance(images_data, list):
        image_names = images_data
    elif isinstance(images_data, dict) and 'raw' in images_data:
        image_names = [n.strip() for n in images_data['raw'].split('\n') if n.strip()]
    else:
        image_names = []

    # NS: now get mirror status for each image (batched via separate commands)
    # could use a single SSH session but _rbd_cmd handles cleanup
    result = []
    for img in image_names[:100]:  # cap at 100 to avoid timeout
        if not _valid_image(str(img)):
            continue
        entry = {'name': img, 'mirroring': None}
        status, st_err = _rbd_cmd(manager, node_ip, f'mirror image status {pool}/{img}', timeout=10)
        if not st_err and isinstance(status, dict):
            entry['mirroring'] = status
        result.append(entry)

    return jsonify({'images': result, 'pool': pool})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/image/<image>/status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_mirror_image_status(cluster_id, pool, image):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool) or not _valid_image(image):
        return jsonify({'error': 'Invalid pool or image name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror image status {pool}/{image}')
    if cmd_err: return cmd_err
    return jsonify(data)


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/image/<image>/enable', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def enable_mirror_image(cluster_id, pool, image):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool) or not _valid_image(image):
        return jsonify({'error': 'Invalid pool or image name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    body = request.json or {}
    mode = body.get('mode', 'snapshot')
    if mode not in ('snapshot', 'journal'):
        return jsonify({'error': 'Mode must be "snapshot" or "journal"'}), 400

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror image enable {pool}/{image} {mode}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.image.enable', f"Enabled mirroring for {pool}/{image} (mode={mode})", cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/image/<image>/disable', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def disable_mirror_image(cluster_id, pool, image):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool) or not _valid_image(image):
        return jsonify({'error': 'Invalid pool or image name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror image disable {pool}/{image}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.image.disable', f"Disabled mirroring for {pool}/{image}", cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/image/<image>/promote', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def promote_mirror_image(cluster_id, pool, image):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool) or not _valid_image(image):
        return jsonify({'error': 'Invalid pool or image name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    body = request.json or {}
    force = body.get('force', False)

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    cmd = f'mirror image promote {pool}/{image}'
    if force:
        cmd += ' --force'

    data, cmd_err = _rbd_cmd(manager, node_ip, cmd, expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.image.promote', f"Promoted {pool}/{image}" + (" (forced)" if force else ""), cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/image/<image>/demote', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def demote_mirror_image(cluster_id, pool, image):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool) or not _valid_image(image):
        return jsonify({'error': 'Invalid pool or image name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror image demote {pool}/{image}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.image.demote', f"Demoted {pool}/{image}", cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/image/<image>/resync', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def resync_mirror_image(cluster_id, pool, image):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool) or not _valid_image(image):
        return jsonify({'error': 'Invalid pool or image name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror image resync {pool}/{image}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.image.resync', f"Resync {pool}/{image}", cluster=manager.config.name)
    return jsonify({'success': True})


# -- Snapshot schedules --

@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/schedule', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_mirror_schedules(cluster_id, pool):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror snapshot schedule list --pool {pool}')
    if cmd_err: return cmd_err
    return jsonify(data if isinstance(data, list) else [])


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/schedule', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def add_mirror_schedule(cluster_id, pool):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    body = request.json or {}
    interval = body.get('interval', '')
    if not _SCHED_RE.match(interval):
        return jsonify({'error': 'Invalid interval format (e.g. 5m, 1h, 1d)'}), 400

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror snapshot schedule add --pool {pool} {interval}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.schedule.add', f"Added schedule {interval} on pool {pool}", cluster=manager.config.name)
    return jsonify({'success': True})


@bp.route('/api/clusters/<cluster_id>/ceph/mirror/pool/<pool>/schedule', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def remove_mirror_schedule(cluster_id, pool):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pool(pool):
        return jsonify({'error': 'Invalid pool name'}), 400

    manager, error = get_connected_manager(cluster_id)
    if error: return error

    body = request.json or {}
    interval = body.get('interval', '')
    if not _SCHED_RE.match(interval):
        return jsonify({'error': 'Invalid interval format (e.g. 5m, 1h, 1d)'}), 400

    node, node_err = _get_any_online_node(manager)
    if node_err: return node_err
    node_ip = _resolve_node_ip(manager, node)

    data, cmd_err = _rbd_cmd(manager, node_ip, f'mirror snapshot schedule remove --pool {pool} {interval}', expect_json=False)
    if cmd_err: return cmd_err

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'ceph.mirror.schedule.remove', f"Removed schedule {interval} from pool {pool}", cluster=manager.config.name)
    return jsonify({'success': True})
