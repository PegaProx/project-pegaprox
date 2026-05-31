# -*- coding: utf-8 -*-
"""PBS (proxmox backup server) routes - split from monolith dec 2025, NS"""

import logging
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import safe_error, check_pbs_access
from pegaprox.core.pbs import PBSManager, load_pbs_servers, save_pbs_server

bp = Blueprint('pbs', __name__)

@bp.route('/api/pbs', methods=['GET'])
@require_auth(perms=['pbs.view'])
def list_pbs_servers():
    """List all configured PBS servers"""
    result = []
    for pbs_id, mgr in pbs_managers.items():
        info = mgr.to_dict()
        # Include quick status if connected
        if mgr.connected and mgr.last_status:
            info['status'] = {
                'cpu': mgr.last_status.get('cpu', 0),
                'memory': mgr.last_status.get('memory', {}),
                'uptime': mgr.last_status.get('uptime', 0),
            }
        result.append(info)

    # Also include disabled servers from DB
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT id, name, host, port, enabled, linked_clusters FROM pbs_servers")
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['id'] not in pbs_managers:
                # NS: parse linked_clusters so frontend can filter by cluster
                linked = []
                try:
                    import json
                    linked = json.loads(row_dict.get('linked_clusters', '[]') or '[]')
                except Exception:
                    pass
                result.append({
                    'id': row_dict['id'],
                    'name': row_dict['name'],
                    'host': row_dict['host'],
                    'port': row_dict['port'],
                    'enabled': bool(row_dict['enabled']),
                    'connected': False,
                    'linked_clusters': linked,
                })
    except Exception:
        pass

    return jsonify(result)


@bp.route('/api/pbs', methods=['POST'])
@require_auth(perms=['pbs.config'])
def add_pbs_server():
    """Add a new PBS server"""
    data = request.json or {}
    
    if not data.get('name') or not data.get('host'):
        return jsonify({'error': 'Name and host are required'}), 400
    
    if not data.get('user'):
        return jsonify({'error': 'Username or API token is required'}), 400
    
    pbs_id = str(uuid.uuid4())[:8]
    
    # Test connection first
    try:
        mgr = PBSManager(pbs_id, data)
    except ValueError as e:
        return jsonify({'error': 'Invalid PBS host'}), 400
    
    if not mgr.connect():
        return jsonify({'error': f'Connection failed: {mgr.last_error}'}), 400
    
    # Save to DB
    save_pbs_server(pbs_id, data)
    pbs_managers[pbs_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'pbs.added', 
              f"Added PBS server: {data['name']} ({data['host']})")
    
    return jsonify({'id': pbs_id, 'message': 'PBS server added successfully', **mgr.to_dict()}), 201


@bp.route('/api/pbs/<pbs_id>', methods=['PUT'])
@require_auth(perms=['pbs.config'])
def update_pbs_server(pbs_id):
    """Update a PBS server config"""
    data = request.json or {}
    
    if pbs_id not in pbs_managers:
        # Try loading from DB
        db = get_db()
        row = db.conn.cursor().execute("SELECT * FROM pbs_servers WHERE id = ?", (pbs_id,)).fetchone()
        if not row:
            return jsonify({'error': 'PBS server not found'}), 404
    
    save_pbs_server(pbs_id, data)

    # MK May 2026 (#469 port) — track whether saved-creds are being preserved AND
    # the host moved at the same time. If yes: don't auto-connect, because the
    # operation could be a credential-exfil attempt where the user keeps the
    # password (sent as ********) but points the server at an attacker-controlled
    # host. We'd otherwise send the real password to that host on connect.
    credentials_preserved = False
    host_changed = False

    # Recreate manager with new config
    if pbs_id in pbs_managers:
        old_mgr = pbs_managers[pbs_id]
        if (data.get('host') and data.get('host') != old_mgr.host) or \
           (data.get('port') and int(data.get('port', 8007)) != old_mgr.port):
            host_changed = True
        # Preserve credentials if masked
        if data.get('password') == '********':
            data['password'] = old_mgr.password
            credentials_preserved = True
        if data.get('api_token_secret') == '********':
            data['api_token_secret'] = old_mgr.api_token_secret
            credentials_preserved = True
        if data.get('ssh_key') == '********':
            data['ssh_key'] = getattr(old_mgr, 'ssh_key', '')

    try:
        mgr = PBSManager(pbs_id, data)
    except ValueError as e:
        return jsonify({'error': 'Invalid PBS host'}), 400

    if data.get('enabled', True):
        if host_changed and credentials_preserved:
            # cred-exfil guard — operator must explicitly re-test the new host
            mgr.connected = False
            mgr.last_error = 'Host changed — auto-connect skipped for security (preserved credentials). Use Test Connection manually after verifying the new host.'
            logging.warning(f"[PBS:{mgr.name}] Skipped auto-connect after host change with preserved credentials (cred-exfil guard)")
        else:
            mgr.connect()
    pbs_managers[pbs_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'pbs.updated', f"Updated PBS server: {data.get('name', pbs_id)}")
    
    return jsonify(mgr.to_dict())


@bp.route('/api/pbs/<pbs_id>', methods=['DELETE'])
@require_auth(perms=['pbs.config'])
def delete_pbs_server(pbs_id):
    """Delete a PBS server"""
    if pbs_id in pbs_managers:
        name = pbs_managers[pbs_id].name
        del pbs_managers[pbs_id]
    else:
        name = pbs_id
    
    db = get_db()
    db.conn.cursor().execute("DELETE FROM pbs_servers WHERE id = ?", (pbs_id,))
    db.conn.commit()
    
    log_audit(request.session.get('user', 'admin'), 'pbs.deleted', f"Deleted PBS server: {name}")
    
    return jsonify({'message': f'PBS server {name} deleted'})


@bp.route('/api/pbs/test-connection', methods=['POST'])
@require_auth(perms=['pbs.config'])
def test_pbs_new_connection():
    """Test PBS connection with provided credentials (before save)"""
    data = request.json or {}
    if not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400
    
    try:
        test_mgr = PBSManager('test', data)
    except ValueError as e:
        return jsonify({'success': False, 'error': 'Invalid PBS host'}), 400
    
    success = test_mgr.connect()
    if success:
        version = test_mgr.get_version()
        datastores = test_mgr.get_datastore_usage()
        return jsonify({
            'success': True,
            'version': version.get('data', {}),
            'datastores': len(datastores.get('data', [])),
        })
    return jsonify({'success': False, 'error': test_mgr.last_error}), 400


@bp.route('/api/pbs/<pbs_id>/test', methods=['POST'])
@require_auth(perms=['pbs.config'])
def test_pbs_connection(pbs_id):
    """Test PBS connection (or test with provided credentials)"""
    data = request.json or {}
    
    if data.get('host'):
        # Test with provided credentials (before save)
        try:
            test_mgr = PBSManager('test', data)
        except ValueError as e:
            return jsonify({'success': False, 'error': 'Invalid PBS host'}), 400
        
        success = test_mgr.connect()
        if success:
            version = test_mgr.get_version()
            datastores = test_mgr.get_datastore_usage()
            return jsonify({
                'success': True,
                'version': version.get('data', {}),
                'datastores': len(datastores.get('data', [])),
            })
        return jsonify({'success': False, 'error': test_mgr.last_error}), 400
    
    # Test existing connection
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    
    mgr = pbs_managers[pbs_id]
    success = mgr.connect()
    if success:
        version = mgr.get_version()
        return jsonify({'success': True, 'version': version.get('data', {})})
    return jsonify({'success': False, 'error': mgr.last_error}), 400


@bp.route('/api/pbs/<pbs_id>/status', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_status(pbs_id):
    """Get PBS server status (CPU, RAM, disk, uptime)"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected', 'connected': False}), 503
    
    status = mgr.get_server_status()
    version = mgr.get_version()
    datastores = mgr.get_datastore_usage()

    # NS: Mar 2026 - propagate errors so frontend can show what went wrong (#107)
    errors = []
    if 'error' in status:
        errors.append(f"Status: {status['error']}")
        logging.warning(f"[PBS:{mgr.name}] get_server_status failed: {status['error']}")
    if 'error' in datastores:
        errors.append(f"Datastores: {datastores['error']}")
        logging.warning(f"[PBS:{mgr.name}] get_datastore_usage failed: {datastores['error']}")

    return jsonify({
        'server': status.get('data', {}),
        'version': version.get('data', {}),
        'datastores': datastores.get('data', []),
        'connected': mgr.connected,
        'name': mgr.name,
        'errors': errors if errors else None,
    })


@bp.route('/api/pbs/<pbs_id>/apt/updates', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_apt_updates(pbs_id):
    """List available APT updates on PBS server"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    result = mgr.get_apt_updates()
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    return jsonify({'updates': result.get('data', []), 'count': len(result.get('data', []))})


@bp.route('/api/pbs/<pbs_id>/apt/refresh', methods=['POST'])
@require_auth(perms=['pbs.view'])
def refresh_pbs_apt(pbs_id):
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    result = mgr.refresh_apt()
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    return jsonify({'success': True, 'data': result.get('data')})


# NS Apr 2026: actually execute apt dist-upgrade via SSH. PBS API has no upgrade endpoint.
@bp.route('/api/pbs/<pbs_id>/update', methods=['POST'])
@require_auth(perms=['admin.settings'])
def start_pbs_update(pbs_id):
    """Start apt-get dist-upgrade on PBS host via SSH"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json(silent=True) or {}
    reboot = bool(data.get('reboot', False))

    existing = mgr.get_update_status()
    if existing and existing.status in ('starting', 'updating', 'rebooting', 'waiting_online'):
        return jsonify({'error': 'Update already in progress', 'status': existing.status}), 409

    task = mgr.start_update(reboot=reboot)
    if not task:
        return jsonify({'error': 'Could not start update'}), 500
    log_audit(request.session.get('user', 'admin'), 'pbs.update_started',
              f"Started apt upgrade on PBS {mgr.name}" + (' (with reboot)' if reboot else ''))
    return jsonify({'success': True, 'status': task.status, 'phase': task.phase})


@bp.route('/api/pbs/<pbs_id>/update', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_update_status(pbs_id):
    """Get current PBS update status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    task = mgr.get_update_status()
    if not task:
        return jsonify({'is_updating': False})
    return jsonify({
        'is_updating': task.status in ('starting', 'updating', 'rebooting', 'waiting_online'),
        'status': task.status,
        'phase': task.phase,
        'error': task.error,
        'output_lines': task.output_lines[-50:] if hasattr(task, 'output_lines') else [],
        'packages_upgraded': getattr(task, 'packages_upgraded', 0),
        'reboot': getattr(task, 'reboot', False),
        'started_at': task.started_at.isoformat() if getattr(task, 'started_at', None) else None,
        'completed_at': task.completed_at.isoformat() if getattr(task, 'completed_at', None) else None,
    })


@bp.route('/api/pbs/<pbs_id>/update', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def clear_pbs_update_status(pbs_id):
    """Clear completed/failed update status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    ok = pbs_managers[pbs_id].clear_update_status()
    return jsonify({'cleared': ok})


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastores(pbs_id):
    """List datastores with detailed status"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    
    # Get list of datastores
    config_resp = mgr.get_datastores()
    usage_resp = mgr.get_datastore_usage()
    
    datastores = config_resp.get('data', [])
    usage_list = {u.get('store'): u for u in usage_resp.get('data', [])}
    
    # Merge config with usage
    result = []
    for ds in datastores:
        name = ds.get('name', '')
        info = {**ds, **(usage_list.get(name, {}))}
        
        # Try to get detailed status (GC info, counts)
        try:
            detail = mgr.get_datastore_status(name)
            if 'data' in detail:
                info['detail'] = detail['data']
        except Exception:
            pass
        
        result.append(info)
    
    return jsonify(result)


def _pbs_vm_name_lookup(pbs_mgr):
    """NS May 2026 — build a {(type, vmid): name} map from the PBS server's
    linked PVE clusters. Used to enrich PBS snapshot/group responses with
    `vm_name` so the frontend doesn't have to do its own lookups (which
    only work after the cluster guests have been fetched separately).
    Falls back to all connected clusters when the PBS has no explicit
    linked_clusters configured."""
    name_map = {}
    cluster_ids = list(pbs_mgr.linked_clusters or [])
    if not cluster_ids:
        # if the PBS has no explicit linked clusters, fall back to all
        # connected clusters — covers fresh setups before linking is configured
        cluster_ids = list(cluster_managers.keys())
    for cid in cluster_ids:
        cm = cluster_managers.get(cid)
        if not cm or not getattr(cm, 'is_connected', False):
            continue
        try:
            resources = cm.get_vm_resources() or []
        except Exception:
            resources = []
        for r in resources:
            t = r.get('type')
            vmid = r.get('vmid')
            name = r.get('name')
            if vmid is None:
                continue
            # PVE 'vm' resource type is 'qemu' for VMs, 'lxc' for containers.
            # PBS backup-type is 'vm' or 'ct'.
            if t == 'lxc':
                backup_t = 'ct'
            elif t in ('qemu', 'vm'):
                backup_t = 'vm'
            else:
                continue
            key = (backup_t, str(vmid))
            # Real name preferred. If a VM has no name (fresh creates, restored
            # configs without `name`), still register it so the UI knows the VM
            # is *known* to PegaProx — synthesise "VM/CT <id>" as label.
            if key not in name_map:
                name_map[key] = name or f"{'CT' if backup_t == 'ct' else 'VM'} {vmid}"
    return name_map


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshots(pbs_id, store):
    """List snapshots in a datastore"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    backup_type = request.args.get('backup-type', None)
    backup_id = request.args.get('backup-id', None)
    result = mgr.get_snapshots(store, ns=ns, backup_type=backup_type, backup_id=backup_id)
    # #143: don't mask errors as empty arrays
    if 'error' in result:
        return jsonify({'error': result['error']}), result.get('status_code', 502)
    snaps = result.get('data', []) or []
    # NS — enrich with vm_name from linked clusters
    name_map = _pbs_vm_name_lookup(mgr)
    for s in snaps:
        bt = s.get('backup-type')
        bid = s.get('backup-id')
        if bt and bid is not None:
            nm = name_map.get((bt, str(bid)))
            if nm:
                s['vm_name'] = nm
    return jsonify(snaps)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/groups', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_groups(pbs_id, store):
    """List backup groups in a datastore"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    result = mgr.get_groups(store, ns=ns)
    if 'error' in result:
        return jsonify({'error': result['error']}), result.get('status_code', 502)
    groups = result.get('data', []) or []
    # NS — enrich with vm_name
    name_map = _pbs_vm_name_lookup(mgr)
    for g in groups:
        bt = g.get('backup-type')
        bid = g.get('backup-id')
        if bt and bid is not None:
            nm = name_map.get((bt, str(bid)))
            if nm:
                g['vm_name'] = nm
    return jsonify(groups)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/gc', methods=['POST'])
@require_auth(perms=['pbs.datastore.gc'])
def pbs_start_gc(pbs_id, store):
    """Start garbage collection"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.start_gc(store)
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.gc', f"Started GC on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/verify', methods=['POST'])
@require_auth(perms=['pbs.datastore.verify'])
def pbs_start_verify(pbs_id, store):
    """Start verification"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    result = mgr.start_verify(store, ignore_verified=data.get('ignore_verified', True))
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.verify', f"Started verify on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/prune', methods=['POST'])
@require_auth(perms=['pbs.datastore.prune'])
def pbs_prune(pbs_id, store):
    """Prune old backups"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    result = mgr.prune_datastore(
        store, ns=data.get('ns'),
        keep_last=data.get('keep_last'), keep_daily=data.get('keep_daily'),
        keep_weekly=data.get('keep_weekly'), keep_monthly=data.get('keep_monthly'),
        keep_yearly=data.get('keep_yearly'),
        backup_type=data.get('backup_type'), backup_id=data.get('backup_id'),
        dry_run=data.get('dry_run', True),
    )
    action = "dry-run prune" if data.get('dry_run', True) else "PRUNE"
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.prune', f"{action} on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['DELETE'])
@require_auth(perms=['pbs.snapshot.delete'])
def pbs_delete_snapshot(pbs_id, store):
    """Delete a specific snapshot"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    required = ['backup_type', 'backup_id', 'backup_time']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing: {field}'}), 400
    
    result = mgr.delete_snapshot(store, data['backup_type'], data['backup_id'], 
                                  data['backup_time'], ns=data.get('ns'))
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.snapshot.delete',
                  f"Deleted {data['backup_type']}/{data['backup_id']} @ {data['backup_time']} from {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/tasks', methods=['GET'])
@require_auth(perms=['pbs.tasks.view'])
def get_pbs_tasks(pbs_id):
    """List PBS tasks"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    limit = int(request.args.get('limit', 50))
    typefilter = request.args.get('typefilter', None)
    running = request.args.get('running', None)
    result = mgr.get_tasks(limit=limit, typefilter=typefilter,
                            running=bool(int(running)) if running is not None else None)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/tasks/<path:upid>', methods=['GET'])
@require_auth(perms=['pbs.tasks.view'])
def get_pbs_task_detail(pbs_id, upid):
    """Get task status and log"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    status = mgr.get_task_status(upid)
    log = mgr.get_task_log(upid)
    return jsonify({
        'status': status.get('data', {}),
        'log': log.get('data', []),
    })


@bp.route('/api/pbs/<pbs_id>/jobs', methods=['GET'])
@require_auth(perms=['pbs.jobs.view'])
def get_pbs_jobs(pbs_id):
    """List all PBS jobs (sync, verify, prune)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    sync = mgr.get_sync_jobs()
    verify = mgr.get_verify_jobs()
    prune = mgr.get_prune_jobs()
    
    return jsonify({
        'sync': sync.get('data', []),
        'verify': verify.get('data', []),
        'prune': prune.get('data', []),
    })


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>/run', methods=['POST'])
@require_auth(perms=['pbs.jobs.run'])
def run_pbs_job(pbs_id, job_type, job_id):
    """Manually trigger a PBS job"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    if job_type == 'sync':
        result = mgr.run_sync_job(job_id)
    elif job_type == 'verify':
        result = mgr.run_verify_job(job_id)
    elif job_type == 'prune':
        result = mgr.run_prune_job(job_id)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}', 
                  f"Started {job_type} job '{job_id}' on {mgr.name}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/namespaces', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_namespaces(pbs_id, store):
    """List namespaces in a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_namespaces(store)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/disks', methods=['GET'])
@require_auth(perms=['pbs.disks.view'])
def get_pbs_disks(pbs_id):
    """List disks on PBS server"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_disks()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/remotes', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_remotes(pbs_id):
    """List configured remotes"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_remotes()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/subscription', methods=['GET'])
@require_auth(perms=['pbs.subscription.view'])
def get_pbs_subscription(pbs_id):
    """Get PBS subscription status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_subscription()
    return jsonify(result.get('data', {}))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/rrd', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastore_rrd(pbs_id, store):
    """Get RRD performance data for a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    timeframe = request.args.get('timeframe', 'hour')  # hour, day, week, month, year
    cf = request.args.get('cf', 'AVERAGE')  # AVERAGE, MAX
    result = mgr.get_datastore_rrd(store, timeframe=timeframe, cf=cf)
    return jsonify(result.get('data', []))


# ── PBS Snapshot & Group Notes ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/notes', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshot_notes(pbs_id, store):
    """Get notes for a specific snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    if not all([bt, bid, btime]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.get_snapshot_notes(store, bt, bid, int(btime))
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'notes': result.get('data', '')})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/notes', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.notes'])
def set_pbs_snapshot_notes(pbs_id, store):
    """Set notes for a specific snapshot"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    btime = data.get('backup-time')
    notes = data.get('notes', '')
    if not all([bt, bid, btime is not None]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.set_snapshot_notes(store, bt, bid, int(btime), notes)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/group-notes', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_group_notes(pbs_id, store):
    """Get notes for a backup group"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    if not all([bt, bid]):
        return jsonify({'error': 'Missing backup-type or backup-id'}), 400
    result = mgr.get_group_notes(store, bt, bid)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'notes': result.get('data', '')})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/group-notes', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.notes'])
def set_pbs_group_notes(pbs_id, store):
    """Set notes for a backup group"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    notes = data.get('notes', '')
    if not all([bt, bid]):
        return jsonify({'error': 'Missing backup-type or backup-id'}), 400
    result = mgr.set_group_notes(store, bt, bid, notes)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

# ── PBS Snapshot Protection ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/protected', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.protect'])
def set_pbs_snapshot_protected(pbs_id, store):
    """Set protected flag on a snapshot"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    btime = data.get('backup-time')
    protected = data.get('protected', True)
    if not all([bt, bid, btime is not None]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.set_snapshot_protected(store, bt, bid, int(btime), protected)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

# ── PBS Traffic Control ──

@bp.route('/api/pbs/<pbs_id>/traffic-control', methods=['GET'])
@require_auth(perms=['pbs.traffic.view'])
def get_pbs_traffic_control(pbs_id):
    """Get traffic control / bandwidth limit configuration"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_traffic_control()
    return jsonify(result.get('data', []))

# ── PBS Syslog ──

@bp.route('/api/pbs/<pbs_id>/syslog', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_syslog(pbs_id):
    """Get PBS server syslog entries"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    limit = request.args.get('limit', 100, type=int)
    since = request.args.get('since')
    result = mgr.get_syslog(limit=limit, since=since)
    return jsonify(result.get('data', []))

# ── PBS Node RRD ──

@bp.route('/api/pbs/<pbs_id>/rrd', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_node_rrd(pbs_id):
    """Get PBS node-level RRD performance data"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    timeframe = request.args.get('timeframe', 'hour')
    cf = request.args.get('cf', 'AVERAGE')
    result = mgr.get_node_rrd(timeframe=timeframe, cf=cf)
    return jsonify(result.get('data', []))

# ── PBS Notifications ──

@bp.route('/api/pbs/<pbs_id>/notifications', methods=['GET'])
@require_auth(perms=['pbs.notifications.view'])
def get_pbs_notifications(pbs_id):
    """Get PBS notification config (targets + matchers)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    # Try to get both targets and matchers
    targets_result = mgr.get_notification_targets()
    matchers_result = mgr.get_notification_matchers()
    # Notification endpoints may differ between PBS versions, handle gracefully
    targets = targets_result.get('data', []) if isinstance(targets_result, dict) and 'error' not in targets_result else []
    matchers = matchers_result.get('data', []) if isinstance(matchers_result, dict) and 'error' not in matchers_result else []
    return jsonify({'targets': targets, 'matchers': matchers})

# ── PBS Catalog / File-Level Restore ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/catalog', methods=['GET'])
@require_auth(perms=['pbs.snapshot.browse'])
def browse_pbs_catalog(pbs_id, store):
    """Browse file catalog of a backup snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    filepath = request.args.get('filepath', '/')
    if not all([bt, bid, btime]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.browse_catalog(store, bt, bid, int(btime), filepath)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result.get('data', []))

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/file-download', methods=['GET'])
@require_auth(perms=['pbs.snapshot.browse'])
def download_pbs_file(pbs_id, store):
    """Download a file from a backup snapshot (file-level restore)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    filepath = request.args.get('filepath')
    if not all([bt, bid, btime, filepath]):
        return jsonify({'error': 'Missing parameters'}), 400
    try:
        resp = mgr.download_file_from_snapshot(store, bt, bid, int(btime), filepath)
        if resp is None or resp.status_code != 200:
            status = resp.status_code if resp else 502
            return jsonify({'error': f'Download failed: HTTP {status}'}), status
        # Extract filename from filepath + sanitize for Content-Disposition header injection
        import re as _re
        filename = filepath.rstrip('/').split('/')[-1] or 'download'
        filename = _re.sub(r'["\r\n\x00-\x1f]', '', filename)  # NS Feb 2026 - strip control chars
        content_type = resp.headers.get('content-type', 'application/octet-stream')
        from flask import Response
        return Response(
            resp.content,
            mimetype=content_type,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(resp.content))
            }
        )
    except Exception as e:
        logging.error(f"[PBS:{pbs_id}] File download error: {e}")
        return jsonify({'error': safe_error(e, 'PBS operation failed')}), 500


# ── PBS Datastore CRUD ── NS: Feb 2026 ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/config', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastore_config(pbs_id, store):
    """Get datastore configuration (retention, GC schedule, notifications, etc.)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_datastore_config(store)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', result))


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['POST'])
@require_auth(perms=['pbs.datastore.create'])
def create_pbs_datastore(pbs_id):
    """Create a new datastore on a PBS server
    
    NS: This creates the datastore config on the PBS. The path must already exist 
    on the PBS filesystem - we can't create directories remotely.
    """
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    name = data.get('name', '').strip()
    path = data.get('path', '').strip()
    
    if not name:
        return jsonify({'error': 'Datastore name is required'}), 400
    if not path:
        return jsonify({'error': 'Path is required'}), 400
    
    # Validate name format (PBS only allows alphanumeric + dash + underscore)
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]*$', name):
        return jsonify({'error': 'Datastore name must start with a letter/number and contain only alphanumeric, dash, or underscore'}), 400
    
    # Build kwargs for PBSManager method
    kwargs = {}
    if data.get('comment'):
        kwargs['comment'] = data['comment']
    if data.get('gc_schedule') is not None:
        kwargs['gc_schedule'] = data['gc_schedule']
    for retention_key in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
        if data.get(retention_key) is not None:
            try:
                kwargs[retention_key] = int(data[retention_key])
            except (ValueError, TypeError):
                pass
    if data.get('verify_new') is not None:
        kwargs['verify_new'] = bool(data['verify_new'])
    if data.get('notify') is not None:
        kwargs['notify'] = data['notify']
    if data.get('notify_user') is not None:
        kwargs['notify_user'] = data['notify_user']
    
    result = mgr.create_datastore(name=name, path=path, **kwargs)
    
    if 'error' in result:
        return jsonify(result), 400
    
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.created',
              f"Created datastore '{name}' at '{path}' on PBS {mgr.name}")
    
    return jsonify({'message': f'Datastore {name} created successfully', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/config', methods=['PUT'])
@require_auth(perms=['pbs.datastore.modify'])
def update_pbs_datastore_config(pbs_id, store):
    """Update datastore configuration (retention, GC schedule, etc.)"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    kwargs = {}
    if 'comment' in data:
        kwargs['comment'] = data['comment']
    if 'gc_schedule' in data:
        kwargs['gc_schedule'] = data['gc_schedule']
    for retention_key in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
        if retention_key in data:
            try:
                kwargs[retention_key] = int(data[retention_key]) if data[retention_key] is not None else None
            except (ValueError, TypeError):
                pass
    if 'verify_new' in data:
        kwargs['verify_new'] = bool(data['verify_new'])
    if 'notify' in data:
        kwargs['notify'] = data['notify']
    if 'notify_user' in data:
        kwargs['notify_user'] = data['notify_user']
    if data.get('delete'):
        kwargs['delete'] = data['delete'] if isinstance(data['delete'], list) else [data['delete']]
    
    if not kwargs:
        return jsonify({'error': 'No changes provided'}), 400
    
    result = mgr.update_datastore(store=store, **kwargs)
    
    if 'error' in result:
        return jsonify(result), 400
    
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.updated',
              f"Updated datastore '{store}' config on PBS {mgr.name}: {list(kwargs.keys())}")
    
    return jsonify({'message': f'Datastore {store} updated successfully', 'data': result.get('data')})


@bp.route('/api/pbs/<pbs_id>/datastores/<store>', methods=['DELETE'])
@require_auth(perms=['pbs.datastore.delete'])
def delete_pbs_datastore(pbs_id, store):
    """Remove a datastore from PBS configuration
    
    NS: By default this only removes the config - actual backup data on disk stays.
    This is the safe default. To also destroy data, send keep_data=false (dangerous!).
    """
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    keep_data = data.get('keep_data', True)
    
    # Extra safety: require explicit confirmation for data destruction
    if not keep_data and not data.get('confirm_destroy'):
        return jsonify({
            'error': 'Data destruction requires explicit confirmation',
            'hint': 'Send confirm_destroy=true to permanently delete all backup data'
        }), 400
    
    result = mgr.delete_datastore(store=store, keep_data=keep_data)
    
    if 'error' in result:
        return jsonify(result), 400
    
    action = 'removed (data kept)' if keep_data else 'DESTROYED (data deleted!)'
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.deleted',
              f"Datastore '{store}' {action} on PBS {mgr.name}")
    
    return jsonify({'message': f'Datastore {store} {action}', 'data': result.get('data')})



# ── PBS Job CRUD ── NS: Feb 2026 ──

@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>', methods=['POST'])
@require_auth(perms=['pbs.jobs.create'])
def create_pbs_job(pbs_id, job_type):
    """Create a new sync/verify/prune job"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    job_id = data.get('id', '').strip()
    store = data.get('store', '').strip()
    if not job_id or not store:
        return jsonify({'error': 'Job ID and store are required'}), 400
    
    if job_type == 'sync':
        if not data.get('remote') or not data.get('remote_store'):
            return jsonify({'error': 'Remote and remote_store are required for sync jobs'}), 400
        result = mgr.create_sync_job(job_id, store, data['remote'], data['remote_store'],
                                     schedule=data.get('schedule'), comment=data.get('comment'),
                                     remove_vanished=data.get('remove_vanished'),
                                     ns=data.get('ns'), max_depth=data.get('max_depth'))
    elif job_type == 'verify':
        result = mgr.create_verify_job(job_id, store, schedule=data.get('schedule'),
                                       ignore_verified=data.get('ignore_verified'),
                                       outdated_after=data.get('outdated_after'),
                                       comment=data.get('comment'), ns=data.get('ns'))
    elif job_type == 'prune':
        result = mgr.create_prune_job(job_id, store, schedule=data.get('schedule'),
                                      keep_last=data.get('keep_last'), keep_daily=data.get('keep_daily'),
                                      keep_weekly=data.get('keep_weekly'), keep_monthly=data.get('keep_monthly'),
                                      keep_yearly=data.get('keep_yearly'),
                                      comment=data.get('comment'), ns=data.get('ns'))
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.created',
              f"Created {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>', methods=['PUT'])
@require_auth(perms=['pbs.jobs.modify'])
def update_pbs_job(pbs_id, job_type, job_id):
    """Update a job configuration"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    if job_type == 'sync':
        result = mgr.update_sync_job(job_id, **data)
    elif job_type == 'verify':
        result = mgr.update_verify_job(job_id, **data)
    elif job_type == 'prune':
        result = mgr.update_prune_job(job_id, **data)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.updated',
              f"Updated {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job updated', 'data': result.get('data')})


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>', methods=['DELETE'])
@require_auth(perms=['pbs.jobs.delete'])
def delete_pbs_job(pbs_id, job_type, job_id):
    """Delete a job"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    if job_type == 'sync':
        result = mgr.delete_sync_job(job_id)
    elif job_type == 'verify':
        result = mgr.delete_verify_job(job_id)
    elif job_type == 'prune':
        result = mgr.delete_prune_job(job_id)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.deleted',
              f"Deleted {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job {job_id} deleted'})


# ── PBS Task Stop ──

@bp.route('/api/pbs/<pbs_id>/tasks/<path:upid>', methods=['DELETE'])
@require_auth(perms=['pbs.tasks.stop'])
def stop_pbs_task(pbs_id, upid):
    """Stop a running PBS task"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.stop_task(upid)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.task.stopped',
              f"Stopped task on PBS {mgr.name}: {upid[-20:]}")
    return jsonify({'message': 'Task stop requested'})


# ── PBS Notification CRUD ──

@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>', methods=['POST'])
@require_auth(perms=['pbs.notifications.manage'])
def create_pbs_notification_target(pbs_id, target_type):
    """Create a notification target (sendmail, gotify, smtp, webhook)"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.pop('name', '').strip()
    if not name:
        return jsonify({'error': 'Target name is required'}), 400
    result = pbs_managers[pbs_id].create_notification_target(target_type, name, **data)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.notification.target.created',
              f"Created {target_type} notification target '{name}'")
    return jsonify({'message': f'Notification target created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>/<name>', methods=['PUT'])
@require_auth(perms=['pbs.notifications.manage'])
def update_pbs_notification_target(pbs_id, target_type, name):
    """Update a notification target"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_notification_target(target_type, name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': f'Notification target updated'})


@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.notifications.manage'])
def delete_pbs_notification_target(pbs_id, target_type, name):
    """Delete a notification target"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_notification_target(target_type, name)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.notification.target.deleted',
              f"Deleted notification target '{name}'")
    return jsonify({'message': f'Notification target deleted'})


@bp.route('/api/pbs/<pbs_id>/notifications/matchers', methods=['POST'])
@require_auth(perms=['pbs.notifications.manage'])
def create_pbs_notification_matcher(pbs_id):
    """Create a notification matcher"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.pop('name', '').strip()
    if not name:
        return jsonify({'error': 'Matcher name is required'}), 400
    result = pbs_managers[pbs_id].create_notification_matcher(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/notifications/matchers/<name>', methods=['PUT'])
@require_auth(perms=['pbs.notifications.manage'])
def update_pbs_notification_matcher(pbs_id, name):
    """Update a notification matcher"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_notification_matcher(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher updated'})


@bp.route('/api/pbs/<pbs_id>/notifications/matchers/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.notifications.manage'])
def delete_pbs_notification_matcher(pbs_id, name):
    """Delete a notification matcher"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_notification_matcher(name)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher deleted'})


# ── PBS Traffic Control CRUD ──

@bp.route('/api/pbs/<pbs_id>/traffic-control', methods=['POST'])
@require_auth(perms=['pbs.traffic.manage'])
def create_pbs_traffic_control(pbs_id):
    """Create a traffic control rule"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Rule name is required'}), 400
    result = pbs_managers[pbs_id].create_traffic_control(**data)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.traffic.created',
              f"Created traffic control rule '{name}'")
    return jsonify({'message': 'Traffic control rule created'}), 201


@bp.route('/api/pbs/<pbs_id>/traffic-control/<name>', methods=['PUT'])
@require_auth(perms=['pbs.traffic.manage'])
def update_pbs_traffic_control(pbs_id, name):
    """Update a traffic control rule"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_traffic_control(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Traffic control rule updated'})


@bp.route('/api/pbs/<pbs_id>/traffic-control/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.traffic.manage'])
def delete_pbs_traffic_control_rule(pbs_id, name):
    """Delete a traffic control rule"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_traffic_control(name)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.traffic.deleted',
              f"Deleted traffic control rule '{name}'")
    return jsonify({'message': 'Traffic control rule deleted'})


# ── PBS Disk SMART ──

@bp.route('/api/pbs/<pbs_id>/disks/<path:disk>/smart', methods=['GET'])
@require_auth(perms=['pbs.disks.smart'])
def get_pbs_disk_smart(pbs_id, disk):
    """Get SMART data for a disk"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_disk_smart(disk)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', result))


# ── PBS Subscription Set ──

@bp.route('/api/pbs/<pbs_id>/subscription', methods=['POST'])
@require_auth(perms=['pbs.subscription.set'])
def set_pbs_subscription(pbs_id):
    """Set subscription key"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    key = data.get('key', '').strip()
    if not key:
        return jsonify({'error': 'Subscription key is required'}), 400
    result = pbs_managers[pbs_id].set_subscription(key)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.subscription.set',
              f"Updated subscription on PBS {pbs_managers[pbs_id].name}")
    return jsonify({'message': 'Subscription updated'})


# ── PBS Network/DNS/Time (read-only) ──

@bp.route('/api/pbs/<pbs_id>/network', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_network(pbs_id):
    """Get PBS server network config"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_network()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/dns', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_dns(pbs_id):
    """Get PBS server DNS config"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_dns()
    return jsonify(result.get('data', {}))


@bp.route('/api/pbs/<pbs_id>/time', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_time(pbs_id):
    """Get PBS server time/timezone"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_time()
    return jsonify(result.get('data', {}))


# ============================================================================
# Backup Verification — NS Apr 2026
# ============================================================================

# ============================================================================
# PBS Reports — issue #273 (Bradley-Radomski, cberr2024)
# Exportable backup reports for audit use cases (ISO 27001, SOC2, CMMC).
# Main question the reporter wanted answered: "prove that <VM X> was backed up
# on <day Y>, and where". Covered by summary + inventory endpoints below.
# ----------------------------------------------------------------------------
# Helpers shared by the three endpoints below.

def _pbs_collect_snapshots(mgr, protected_only=False, min_backup_time=0):
    """Walk all datastores and namespaces and return a flat list of snapshots.

    Each entry carries the originating datastore + namespace. We purposely do
    not cache — the report is refreshed on demand and the numbers must be
    current for audit use.
    """
    entries = []
    ds_resp = mgr.get_datastores() or {}
    for ds in (ds_resp.get('data', []) or []):
        store = ds.get('name', '')
        if not store:
            continue
        # Figure out which namespaces live under this store. Empty '' is the
        # root namespace and always exists even if there are no sub-namespaces.
        namespaces = ['']
        try:
            ns_resp = mgr.get_namespaces(store) or {}
            ns_list = [n.get('ns', '') for n in (ns_resp.get('data', []) or [])]
            namespaces = list({'', *ns_list})
        except Exception:
            pass
        for ns in namespaces:
            try:
                snap_resp = mgr.get_snapshots(store, ns=ns or None) or {}
            except Exception:
                continue
            for s in (snap_resp.get('data', []) or []):
                if min_backup_time and s.get('backup-time', 0) < min_backup_time:
                    continue
                if protected_only and not s.get('protected'):
                    continue
                s['_datastore'] = store
                s['_namespace'] = ns or ''
                entries.append(s)
    return entries


def _pbs_resolve_vm_names(mgr):
    """Walk each linked PVE cluster and build (type, vmid_str) -> name.
    type is normalized to 'vm' / 'ct' to match PBS worker-id conventions.
    """
    names = {}
    for cid in (mgr.linked_clusters or []):
        pve_mgr = cluster_managers.get(cid)
        if not pve_mgr or not getattr(pve_mgr, 'is_connected', False):
            continue
        try:
            resources = pve_mgr.get_vm_resources() or []
        except Exception:
            continue
        for r in resources:
            t = r.get('type')
            if t == 'qemu':
                vt = 'vm'
            elif t == 'lxc':
                vt = 'ct'
            else:
                continue
            names[(vt, str(r.get('vmid', '')))] = r.get('name', '')
    return names


@bp.route('/api/pbs/<pbs_id>/reports/summary', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_summary(pbs_id):
    """Aggregated backup report over a time window.

    Covers the executive-summary + per-VM rollup reports from #273.

    Query params:
      days      time window (default 30, max 365)
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    import time
    import datetime as _dt

    try:
        days = max(1, min(365, int(request.args.get('days', 30))))
    except Exception:
        days = 30
    now_ts = int(time.time())
    since_ts = now_ts - days * 86400

    # ── Backup tasks in window ─────────────────────────────────────────────
    tasks_resp = mgr.get_tasks(limit=500, typefilter='backup', since=since_ts) or {}
    tasks = tasks_resp.get('data', []) or []

    totals = {'jobs': 0, 'success': 0, 'warning': 0, 'failed': 0}
    per_day = {}          # YYYY-MM-DD -> {date, success, warning, failed}
    per_vm_latest = {}    # (type, vmid) -> latest task dict

    for t in tasks:
        # PBS task shape: {upid, starttime, endtime, status, worker_type, worker_id}
        if t.get('worker_type') != 'backup':
            continue
        totals['jobs'] += 1

        status_raw = (t.get('status') or '').strip()
        status_upper = status_raw.upper()
        if status_upper == 'OK':
            bucket = 'success'
        elif 'WARN' in status_upper:
            bucket = 'warning'
        else:
            bucket = 'failed'
        totals[bucket] += 1

        end_ts = t.get('endtime') or t.get('starttime') or 0
        if end_ts:
            day = _dt.datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d')
            if day not in per_day:
                per_day[day] = {'date': day, 'success': 0, 'warning': 0, 'failed': 0}
            per_day[day][bucket] += 1

        worker_id = t.get('worker_id') or t.get('id') or ''
        if '/' in worker_id:
            vm_type, vmid = worker_id.split('/', 1)
            key = (vm_type, vmid)
            prev = per_vm_latest.get(key)
            if (prev is None
                    or (t.get('endtime') or 0) > (prev.get('endtime') or 0)):
                per_vm_latest[key] = t

    # ── Snapshot inventory for size/verify info ────────────────────────────
    snapshots = _pbs_collect_snapshots(mgr)
    snapshots_by_key = {}   # (type, vmid_str) -> [snap, ...]
    for s in snapshots:
        key = (s.get('backup-type', ''), str(s.get('backup-id', '')))
        snapshots_by_key.setdefault(key, []).append(s)

    # unverified older than 30 days — used as a compliance-warning gauge
    cutoff_verify = now_ts - 30 * 86400
    unverified_old = 0
    for s in snapshots:
        v = s.get('verification') or {}
        state = v.get('state') if isinstance(v, dict) else None
        if state != 'ok' and s.get('backup-time', 0) < cutoff_verify:
            unverified_old += 1

    # ── Resolve VM names from linked clusters ──────────────────────────────
    vm_names = _pbs_resolve_vm_names(mgr)

    # ── Build per-VM rollup (Veeam-style last N per job) ───────────────────
    per_vm = []
    for (vm_type, vmid), task in per_vm_latest.items():
        snaps = snapshots_by_key.get((vm_type, vmid), [])
        latest_snap = max(snaps, key=lambda x: x.get('backup-time', 0)) if snaps else None

        end_ts = task.get('endtime') or 0
        start_ts = task.get('starttime') or 0
        duration = (end_ts - start_ts) if end_ts and start_ts else 0
        status_upper = (task.get('status') or '').upper()
        if status_upper == 'OK':
            status_label = 'success'
        elif 'WARN' in status_upper:
            status_label = 'warning'
        else:
            status_label = 'failed'

        latest_verify = {}
        if latest_snap:
            latest_verify = latest_snap.get('verification') or {}
            if not isinstance(latest_verify, dict):
                latest_verify = {}
        per_vm.append({
            'type': vm_type,
            'vmid': vmid,
            'vm_name': vm_names.get((vm_type, str(vmid)), ''),
            'datastore': latest_snap.get('_datastore') if latest_snap else '',
            'namespace': latest_snap.get('_namespace') if latest_snap else '',
            'last_backup_ts': end_ts,
            'status': status_label,
            'size': latest_snap.get('size', 0) if latest_snap else 0,
            'duration_s': duration,
            'verified': latest_verify.get('state') == 'ok',
            'snapshot_count': len(snaps),
            'upid': task.get('upid', ''),
        })
    per_vm.sort(key=lambda x: x.get('last_backup_ts', 0), reverse=True)

    # ── Fill missing days so frontend chart renders gaps as zeros ──────────
    per_day_filled = []
    for i in range(days - 1, -1, -1):
        day = (_dt.datetime.fromtimestamp(now_ts) - _dt.timedelta(days=i)).strftime('%Y-%m-%d')
        per_day_filled.append(per_day.get(day, {'date': day, 'success': 0, 'warning': 0, 'failed': 0}))

    success_rate = (totals['success'] / totals['jobs'] * 100.0) if totals['jobs'] else 0.0

    return jsonify({
        'window': {'days': days, 'since_ts': since_ts, 'until_ts': now_ts},
        'totals': {**totals, 'success_rate': round(success_rate, 1)},
        'per_day': per_day_filled,
        'per_vm': per_vm,
        'inventory_snapshot_count': len(snapshots),
        'unverified_older_than_30d': unverified_old,
    })


@bp.route('/api/pbs/<pbs_id>/reports/inventory', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_inventory(pbs_id):
    """Flat list of every snapshot across all datastores/namespaces.

    Primary use-case from #273: audit question "prove X was backed up on day Y
    and where". This endpoint is the answer.

    Query params:
      days=0         filter to snapshots newer than N days (0 = no filter)
      protected=1    only protected snapshots
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    import time
    try:
        days = int(request.args.get('days', 0))
    except Exception:
        days = 0
    protected_only = str(request.args.get('protected', '')).lower() in ('1', 'true', 'yes')
    now_ts = int(time.time())
    min_bt = (now_ts - days * 86400) if days > 0 else 0

    raw = _pbs_collect_snapshots(mgr, protected_only=protected_only, min_backup_time=min_bt)

    vm_names = _pbs_resolve_vm_names(mgr)

    entries = []
    for s in raw:
        verify = s.get('verification') or {}
        if not isinstance(verify, dict):
            verify = {}
        vtype = s.get('backup-type', '')
        vmid = str(s.get('backup-id', ''))
        entries.append({
            'type': vtype,
            'vmid': vmid,
            'vm_name': vm_names.get((vtype, vmid), ''),
            'datastore': s.get('_datastore', ''),
            'namespace': s.get('_namespace', ''),
            'backup_time': s.get('backup-time', 0),
            'size': s.get('size', 0),
            'owner': s.get('owner', ''),
            'protected': bool(s.get('protected', False)),
            'comment': s.get('comment', '') or '',
            'verified': verify.get('state') == 'ok',
            'verified_state': verify.get('state') or None,
            'verified_time': verify.get('upid_time') if isinstance(verify, dict) else None,
            'files_count': len(s.get('files', []) or []),
        })
    entries.sort(key=lambda x: x['backup_time'], reverse=True)
    return jsonify({'entries': entries, 'count': len(entries)})


@bp.route('/api/pbs/<pbs_id>/reports/protected-vms', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_protected_vms(pbs_id):
    """Gap analysis — which cluster VMs/CTs are actually backed up.

    Essential for SOC2 "protected workloads" audit evidence (#273).

    Query params:
      cluster_id   (required) PVE cluster to check
      days=7       a VM counts as protected if its most recent snapshot is
                   within this window. Older ones land in 'stale'.
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    cluster_id = request.args.get('cluster_id', '')
    if not cluster_id:
        return jsonify({'error': 'cluster_id query param required'}), 400
    pve_mgr = cluster_managers.get(cluster_id)
    if not pve_mgr:
        return jsonify({'error': 'Cluster not found'}), 404

    import time
    try:
        days = max(1, min(365, int(request.args.get('days', 7))))
    except Exception:
        days = 7
    cutoff = int(time.time()) - days * 86400

    try:
        resources = pve_mgr.get_vm_resources() or []
    except Exception as e:
        return jsonify({'error': f'Could not load cluster resources: {e}'}), 502

    # Most recent backup timestamp + datastore per (type, vmid)
    most_recent = {}
    snaps = _pbs_collect_snapshots(mgr)
    for s in snaps:
        key = (s.get('backup-type', ''), str(s.get('backup-id', '')))
        bt = s.get('backup-time', 0)
        cur = most_recent.get(key)
        if cur is None or bt > cur['ts']:
            most_recent[key] = {
                'ts': bt,
                'datastore': s.get('_datastore', ''),
                'namespace': s.get('_namespace', ''),
            }

    protected, unprotected, stale = [], [], []
    for r in resources:
        rtype = r.get('type')
        if rtype not in ('qemu', 'lxc'):
            continue
        vt = 'vm' if rtype == 'qemu' else 'ct'
        vmid = str(r.get('vmid', ''))
        info = most_recent.get((vt, vmid))
        entry = {
            'type': vt,
            'vmid': vmid,
            'vm_name': r.get('name', ''),
            'node': r.get('node', ''),
            'status': r.get('status', ''),
            'last_backup_ts': info['ts'] if info else 0,
            'datastore': info['datastore'] if info else '',
            'namespace': info['namespace'] if info else '',
        }
        if not info:
            unprotected.append(entry)
        elif info['ts'] < cutoff:
            stale.append(entry)
        else:
            protected.append(entry)

    protected.sort(key=lambda x: (x['vm_name'] or x['vmid']).lower())
    unprotected.sort(key=lambda x: (x['vm_name'] or x['vmid']).lower())
    stale.sort(key=lambda x: x['last_backup_ts'])

    return jsonify({
        'window': {'days': days, 'cutoff_ts': cutoff},
        'counts': {
            'protected': len(protected),
            'unprotected': len(unprotected),
            'stale': len(stale),
            'total': len(protected) + len(unprotected) + len(stale),
        },
        'protected': protected,
        'unprotected': unprotected,
        'stale': stale,
    })


# End of PBS Reports (#273)
# ============================================================================


@bp.route('/api/clusters/<cluster_id>/backup-verify', methods=['POST'])
@require_auth(perms=['vm.backup'])
def start_backup_verification(cluster_id):
    """Start a PBS backup verification (restore → boot → check → cleanup)"""
    from pegaprox.core.backup_verify import start_verification

    # MK May 2026 (#465 port) — cluster-scoped auth on cluster-id-keyed endpoints.
    # The earlier #476 batch only covered the pbs_id-keyed `/api/pbs/<id>` routes
    # via check_pbs_access; these `/api/clusters/<id>/backup-verify*` endpoints
    # use a different auth-key and went unprotected.
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json or {}
    required = ['node', 'vmid', 'backup_volid']
    for f in required:
        if f not in data:
            return jsonify({'error': f'Missing: {f}'}), 400

    data['cluster_id'] = cluster_id
    pve_mgr = cluster_managers[cluster_id]

    if not pve_mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    try:
        task_id = start_verification(pve_mgr, data)
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 409

    user = request.session.get('user', 'system')
    log_audit(user, 'backup.verify_started',
              f"Backup verification started for VM {data.get('vmid')} on {data.get('node')}")

    return jsonify({'success': True, 'task_id': task_id})


@bp.route('/api/clusters/<cluster_id>/backup-verify/<task_id>', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_backup_verification_status(cluster_id, task_id):
    """Get status of a running or completed verification"""
    from pegaprox.core.backup_verify import get_verification, get_verification_history

    # MK May 2026 (#465 port) — cluster-scoped auth (see start_backup_verification)
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    # check active first
    status = get_verification(task_id)
    if status:
        return jsonify(status)

    # check database
    db = get_db()
    try:
        row = db.query_one('SELECT * FROM backup_verifications WHERE id = ?', (task_id,))
        if row:
            result = dict(row)
            import json
            result['details'] = json.loads(result.get('details', '{}'))
            result['logs'] = result['details'].get('logs', [])
            return jsonify(result)
    except Exception:
        pass

    return jsonify({'error': 'Verification not found'}), 404


@bp.route('/api/clusters/<cluster_id>/backup-verify/history', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_backup_verification_history(cluster_id):
    """Get verification history, optionally filtered by vmid"""
    from pegaprox.core.backup_verify import get_verification_history

    # MK May 2026 (#465 port) — cluster-scoped auth (see start_backup_verification)
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    vmid = request.args.get('vmid', type=int)
    limit = request.args.get('limit', 50, type=int)

    results = get_verification_history(cluster_id, vmid, limit)
    return jsonify(results)


@bp.route('/api/clusters/<cluster_id>/backup-verify/active', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_active_verifications(cluster_id):
    """Get all currently running verifications"""
    from pegaprox.core.backup_verify import get_active_verifications

    active = get_active_verifications()
    # filter by cluster
    cluster_active = {k: v for k, v in active.items() if v.get('cluster_id') == cluster_id}
    return jsonify(cluster_active)


# ============================================================================
# NS May 2026 — PBS UX improvements: health score, fingerprint probe,
# capacity forecast, auto-storage, vm-backup-status, run-now.
# ============================================================================

@bp.route('/api/pbs/probe-fingerprint', methods=['POST'])
@require_auth(perms=['pbs.config'])
def probe_pbs_fingerprint():
    """Open a TLS connection to host:port and return the cert SHA-256 fingerprint.
    Used by the Add-PBS wizard so the user doesn't have to run openssl by hand.

    Body: {"host": "pbs.example.com", "port": 8007}
    """
    import socket as _sock
    import ssl as _ssl
    import hashlib

    data = request.json or {}
    host = (data.get('host') or '').strip()
    try:
        port = int(data.get('port') or 8007)
    except (TypeError, ValueError):
        return jsonify({'error': 'port must be a number'}), 400
    if not host or len(host) > 255:
        return jsonify({'error': 'host required'}), 400
    if not (1 <= port <= 65535):
        return jsonify({'error': 'invalid port'}), 400
    # SSRF-ish guard: same checks our outbound-url helper applies
    try:
        from pegaprox.utils.url_security import is_safe_outbound_url
        ok, reason = is_safe_outbound_url(f'https://{host}:{port}/',
                                          allowed_schemes=('https',),
                                          allow_private=True)  # PBS is usually on the LAN
        if not ok:
            return jsonify({'error': f'unsafe target: {reason}'}), 400
    except Exception:
        pass

    ctx = _ssl._create_unverified_context()
    try:
        with _sock.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest().upper()
        # PBS expects fingerprint formatted with colons: AA:BB:CC...
        formatted = ':'.join(fp[i:i+2] for i in range(0, len(fp), 2))
        return jsonify({'fingerprint': formatted, 'host': host, 'port': port})
    except _sock.timeout:
        return jsonify({'error': f'TLS handshake timed out connecting to {host}:{port}'}), 504
    except (_sock.gaierror, ConnectionRefusedError, OSError) as e:
        return jsonify({'error': f'cannot reach {host}:{port}: {e}'}), 502
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/pbs/<pbs_id>/health', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_health(pbs_id):
    """0-100 health score for a PBS server. Aggregates multiple datastores."""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    mgr = pbs_managers[pbs_id]
    score = 100
    factors = []
    issues = []

    if not mgr.connected:
        return jsonify({
            'score': 0, 'band': 'critical',
            'factors': [{'key': 'api', 'label': 'API connectivity', 'value': 'offline', 'delta': -100}],
            'issues': ['PBS unreachable'],
        })

    # 1) Datastore capacity
    try:
        ds = mgr.get_datastores() or {}
        stores = ds.get('data', []) if isinstance(ds, dict) else (ds or [])
        # enrich with usage info (free/total/history)
        try:
            us = mgr.get_datastore_usage() or {}
            usage = us.get('data', []) if isinstance(us, dict) else (us or [])
            ux = {u.get('store'): u for u in usage if isinstance(u, dict)}
            for s in stores:
                if isinstance(s, dict):
                    s.update(ux.get(s.get('name') or s.get('store'), {}))
        except Exception:
            pass
    except Exception:
        stores = []
    worst_pct = 0.0
    worst_store = None
    for s in stores:
        total = (s.get('total') or s.get('detail', {}).get('total') or 0)
        avail = (s.get('avail') or s.get('detail', {}).get('avail') or 0)
        if total > 0:
            used_pct = ((total - avail) / total) * 100.0
            if used_pct > worst_pct:
                worst_pct = used_pct
                worst_store = s.get('store') or s.get('name') or '?'
    if worst_store is not None:
        d = -25 if worst_pct >= 95 else -15 if worst_pct >= 90 else -5 if worst_pct >= 80 else 0
        score += d
        factors.append({'key': 'capacity', 'label': 'Worst datastore',
                        'value': f'{worst_store} ({worst_pct:.0f}%)', 'delta': d,
                        'severity': 'critical' if worst_pct >= 95 else 'warning' if worst_pct >= 80 else 'ok'})
        if worst_pct >= 90:
            issues.append(f'{worst_store} {worst_pct:.0f}% full')

    # 2) GC age (last gc per store)
    import time as _t
    now = _t.time()
    oldest_gc_age_h = None
    for s in stores:
        gc = s.get('gc-status') or {}
        upid = gc.get('upid')
        # If upid present, gc has run; we can't easily get the timestamp without
        # parsing — fall back to checking the store's own timestamp if available.
        last = s.get('last-gc') or 0
        if last:
            age_h = (now - last) / 3600
            if oldest_gc_age_h is None or age_h > oldest_gc_age_h:
                oldest_gc_age_h = age_h
    if oldest_gc_age_h is not None:
        d = -10 if oldest_gc_age_h > 24 * 30 else -5 if oldest_gc_age_h > 24 * 7 else 0
        score += d
        factors.append({'key': 'gc', 'label': 'Last GC',
                        'value': f'{oldest_gc_age_h:.0f}h ago', 'delta': d,
                        'severity': 'warning' if d < 0 else 'ok'})
        if d < 0:
            issues.append(f'GC last ran {oldest_gc_age_h:.0f}h ago')

    # 3) Last backup push age (across all groups in all stores)
    youngest_age_h = None
    try:
        for s in stores:
            store_name = s.get('store') or s.get('name')
            if not store_name:
                continue
            try:
                _r = mgr.get_snapshots(store_name) or {}
                snaps = _r.get('data', []) if isinstance(_r, dict) else (_r or [])
            except Exception:
                continue
            for sn in snaps:
                bt = sn.get('backup-time') or 0
                if bt:
                    age = (now - bt) / 3600
                    if youngest_age_h is None or age < youngest_age_h:
                        youngest_age_h = age
    except Exception:
        pass
    if youngest_age_h is not None:
        d = -20 if youngest_age_h > 24 * 7 else -10 if youngest_age_h > 24 * 2 else 0
        score += d
        factors.append({'key': 'last_push', 'label': 'Newest backup',
                        'value': f'{youngest_age_h:.1f}h ago' if youngest_age_h < 48 else f'{youngest_age_h/24:.1f}d ago',
                        'delta': d,
                        'severity': 'warning' if d < 0 else 'ok'})
        if d < 0:
            issues.append(f'No fresh backups in {youngest_age_h/24:.1f}d')
    else:
        d = -5
        score += d
        factors.append({'key': 'last_push', 'label': 'Newest backup',
                        'value': '—', 'delta': d, 'severity': 'warning'})

    score = max(0, min(100, score))
    if score >= 90: band = 'excellent'
    elif score >= 70: band = 'good'
    elif score >= 50: band = 'warning'
    elif score >= 30: band = 'degraded'
    else: band = 'critical'
    import datetime as _dt
    return jsonify({
        'score': score, 'band': band,
        'factors': factors, 'issues': issues,
        'computed_at': _dt.datetime.utcnow().isoformat() + 'Z',
    })


@bp.route('/api/pbs/<pbs_id>/capacity-forecast', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_capacity_forecast(pbs_id):
    """Linear regression on historic free-space (per datastore) → ETA-to-full."""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'PBS offline'}), 503

    out = []
    try:
        ds = mgr.get_datastores() or {}
        stores = ds.get('data', []) if isinstance(ds, dict) else (ds or [])
        # enrich with usage info (free/total/history)
        try:
            us = mgr.get_datastore_usage() or {}
            usage = us.get('data', []) if isinstance(us, dict) else (us or [])
            ux = {u.get('store'): u for u in usage if isinstance(u, dict)}
            for s in stores:
                if isinstance(s, dict):
                    s.update(ux.get(s.get('name') or s.get('store'), {}))
        except Exception:
            pass
    except Exception:
        stores = []
    for s in stores:
        store = s.get('store') or s.get('name') or '?'
        # PBS exposes a 'history' array on the datastore (one sample per day,
        # newest last; values are usage ratio 0..1 or null).
        hist = s.get('history') or s.get('detail', {}).get('history') or []
        total = s.get('total') or s.get('detail', {}).get('total') or 0
        used = s.get('used') or s.get('detail', {}).get('used') or 0
        cur_pct = (used / total) * 100.0 if total > 0 else 0.0

        # cleanup history: keep only numeric samples
        samples = [(i, v) for i, v in enumerate(hist) if isinstance(v, (int, float))]
        eta_days = None
        slope_pct_per_day = 0.0
        if len(samples) >= 5:
            # linear regression y = a + b*x where y is usage ratio
            n = len(samples)
            sx = sum(i for i, _ in samples)
            sy = sum(v for _, v in samples)
            sxy = sum(i * v for i, v in samples)
            sxx = sum(i * i for i, _ in samples)
            denom = (n * sxx - sx * sx)
            if denom > 0:
                b = (n * sxy - sx * sy) / denom
                a = (sy - b * sx) / n
                # extrapolate to y = 1.0 (= 100% full)
                if b > 1e-9:
                    x_full = (1.0 - a) / b
                    last_x = samples[-1][0]
                    eta_days = max(0, x_full - last_x)
                    slope_pct_per_day = b * 100
        out.append({
            'store': store,
            'total_bytes': total, 'used_bytes': used,
            'used_pct': round(cur_pct, 1),
            'slope_pct_per_day': round(slope_pct_per_day, 3),
            'eta_days_to_full': round(eta_days, 1) if eta_days is not None else None,
            'samples': len(samples),
        })
    return jsonify(out)


@bp.route('/api/pbs/<pbs_id>/auto-storage', methods=['POST'])
@require_auth(perms=['pbs.config'])
def auto_attach_pbs_to_clusters(pbs_id):
    """Convenience: create a `pbs:` storage entry on each linked PVE cluster
    using the PBS server's stored credentials. Avoids the user having to retype
    everything in the storage form.

    Body: {"clusters": ["cluster_id1", ...], "storage_name": "pbs-wui",
           "content": "backup"}  — storage_name defaults to pbs-<pbs_name>.
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    pbs_mgr = pbs_managers[pbs_id]
    body = request.json or {}
    cluster_ids = body.get('clusters') or pbs_mgr.linked_clusters or []
    if not cluster_ids:
        return jsonify({'error': 'no clusters specified or linked'}), 400

    storage_name = (body.get('storage_name') or f"pbs-{pbs_mgr.name}").lower()
    storage_name = ''.join(c if c.isalnum() or c in ('-', '_', '.') else '-' for c in storage_name)
    if not storage_name or not storage_name[0].isalpha():
        storage_name = 'pbs-' + storage_name
    content = body.get('content') or 'backup'

    # Probe live fingerprint so we always inject a current one
    import socket as _sock, ssl as _ssl, hashlib
    try:
        ctx = _ssl._create_unverified_context()
        with _sock.create_connection((pbs_mgr.host, pbs_mgr.port or 8007), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=pbs_mgr.host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        fp_hex = hashlib.sha256(der).hexdigest().upper()
        fingerprint = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))
    except Exception as e:
        return jsonify({'error': f'fingerprint probe failed: {e}'}), 502

    pbs_user = getattr(pbs_mgr, 'user', None) or getattr(pbs_mgr, 'username', None)
    pbs_pass = getattr(pbs_mgr, 'password', None)
    if not pbs_user or not pbs_pass:
        return jsonify({'error': 'PBS server has no stored username/password (token-only? not yet supported here)'}), 400

    results = []
    for cid in cluster_ids:
        if cid not in cluster_managers:
            results.append({'cluster_id': cid, 'ok': False, 'error': 'cluster not found'})
            continue
        cm = cluster_managers[cid]
        if not cm.is_connected:
            results.append({'cluster_id': cid, 'ok': False, 'error': 'cluster offline'})
            continue
        url = f"https://{cm.host}:{cm.api_port}/api2/json/storage"
        data = {
            'storage': storage_name, 'type': 'pbs',
            'server': pbs_mgr.host, 'datastore': '',  # set below per-store iteration if multi
            'username': pbs_user, 'password': pbs_pass,
            'fingerprint': fingerprint, 'content': content,
        }
        # default datastore: first one
        try:
            _ds = pbs_mgr.get_datastores() or {}
            stores = _ds.get('data', []) if isinstance(_ds, dict) else (_ds or [])
            if stores:
                data['datastore'] = stores[0].get('store') or stores[0].get('name') or 'Backup'
        except Exception:
            data['datastore'] = body.get('datastore') or 'Backup'
        if pbs_mgr.port and pbs_mgr.port != 8007:
            data['port'] = pbs_mgr.port
        try:
            r = cm._create_session().post(url, data=data, timeout=60)
            if r.status_code == 200:
                results.append({'cluster_id': cid, 'ok': True, 'storage': storage_name,
                                'datastore': data['datastore']})
                log_audit(request.session.get('user', 'system'), 'pbs.storage_auto_attached',
                          f"Attached PBS '{pbs_mgr.name}' as storage '{storage_name}' on cluster {cm.config.name}")
            else:
                # Surface the PVE body
                err = ''
                try:
                    j = r.json()
                    err = j.get('errors') or j.get('message') or r.text
                    if isinstance(err, dict):
                        err = ', '.join(f'{k}: {v}' for k, v in err.items())
                except Exception:
                    err = r.text or f'HTTP {r.status_code}'
                results.append({'cluster_id': cid, 'ok': False, 'error': err, 'pve_status': r.status_code})
        except Exception as e:
            results.append({'cluster_id': cid, 'ok': False, 'error': str(e)})
    return jsonify({'results': results, 'storage_name': storage_name})


@bp.route('/api/clusters/<cluster_id>/storage-preflight', methods=['POST'])
@require_auth(perms=['storage.config'])
def storage_preflight(cluster_id):
    """Pre-validate a storage config before hitting PVE — gives clear errors
    instead of PVE's opaque 595. Currently focused on PBS but extensible.

    Body: same shape as /datacenter/storage POST.
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    data = request.json or {}
    if data.get('type') != 'pbs':
        return jsonify({'ok': True, 'skipped': 'preflight only for type=pbs'})

    server = (data.get('server') or '').strip()
    port = int(data.get('port') or 8007)
    datastore = (data.get('datastore') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    given_fp = (data.get('fingerprint') or '').strip().upper().replace(' ', '')

    issues = []
    info = {}

    # 1) TCP reachability
    import socket as _sock, ssl as _ssl, hashlib
    try:
        with _sock.create_connection((server, port), timeout=6):
            info['tcp'] = 'ok'
    except Exception as e:
        return jsonify({'ok': False, 'issues': [f'TCP {server}:{port} unreachable: {e}'], 'info': info}), 200

    # 2) TLS + fingerprint
    try:
        ctx = _ssl._create_unverified_context()
        with _sock.create_connection((server, port), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=server) as ssock:
                der = ssock.getpeercert(binary_form=True)
        fp_hex = hashlib.sha256(der).hexdigest().upper()
        live_fp = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))
        info['live_fingerprint'] = live_fp
        if given_fp and given_fp != live_fp:
            issues.append(f'Fingerprint mismatch — server presents {live_fp[:16]}…, you supplied {given_fp[:16]}…')
    except Exception as e:
        return jsonify({'ok': False, 'issues': [f'TLS handshake failed: {e}'], 'info': info}), 200

    # 3) Auth probe
    try:
        import requests as _r
        s = _r.Session(); s.verify = False
        ar = s.post(f'https://{server}:{port}/api2/json/access/ticket',
                    data={'username': username, 'password': password}, timeout=8)
        if ar.status_code != 200:
            issues.append(f'PBS auth failed (HTTP {ar.status_code})')
            info['auth'] = 'fail'
        else:
            info['auth'] = 'ok'
            ticket = ar.json().get('data', {}).get('ticket')
            csrf = ar.json().get('data', {}).get('CSRFPreventionToken')
            # 4) Datastore exists?
            if datastore and ticket:
                ds_r = s.get(f'https://{server}:{port}/api2/json/admin/datastore',
                             cookies={'PBSAuthCookie': ticket}, timeout=8)
                if ds_r.status_code == 200:
                    names = [d.get('store') or d.get('name') for d in ds_r.json().get('data', [])]
                    info['datastores'] = names
                    if datastore not in names:
                        issues.append(f"Datastore '{datastore}' not found. Available: {', '.join(names) or '(none)'}")
    except Exception as e:
        issues.append(f'auth probe error: {e}')

    return jsonify({'ok': not issues, 'issues': issues, 'info': info})


@bp.route('/api/clusters/<cluster_id>/vms-backup-status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_vms_backup_status(cluster_id):
    """Per-VM backup health: last backup age, encryption flag, count over last 30d.
    Used by the VM list to render a status pill column.
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503
    import time as _t
    now = _t.time()
    cutoff_30d = now - (30 * 86400)

    # Aggregate snapshots across all PBS servers linked to this cluster + the
    # cluster's local backup storages (vzdump files).
    by_vm = {}  # vmid -> {last_age_h, count_30d, encrypted, last_verify_age_h}

    def _bump(vmid, ts, encrypted=False, verified_ts=None):
        rec = by_vm.setdefault(int(vmid), {
            'vmid': int(vmid), 'last_backup_ts': 0, 'count_30d': 0,
            'encrypted': False, 'last_verify_ts': 0,
        })
        if ts and ts > rec['last_backup_ts']:
            rec['last_backup_ts'] = ts
        if ts and ts >= cutoff_30d:
            rec['count_30d'] += 1
        if encrypted:
            rec['encrypted'] = True
        if verified_ts and verified_ts > rec['last_verify_ts']:
            rec['last_verify_ts'] = verified_ts

    # MK 2026-05-31 (F1b) — parallelise both fanouts: per-PBS-server and
    # per-PVE-node. Each task collects (vmid, ts, encrypted, verified_ts)
    # tuples in isolation, then we sequentially _bump them into by_vm at
    # the end. This separates network I/O (parallel) from shared-state
    # mutation (sequential) so we don't need a lock around by_vm.
    #
    # Was sequential: ΣPBS × Σdatastores + Σnodes × Σbackup-storages PVE
    # calls back-to-back on one worker. With 2+ PBS servers + 6+ nodes this
    # easily breached 10s and that's what was wedging /vms-backup-status.
    from pegaprox.utils.concurrent import run_concurrent_dict

    def _scan_pbs(pbs):
        """Returns list of (vmid, ts, encrypted, verified_ts) tuples for one PBS server."""
        bumps = []
        try:
            _ds = pbs.get_datastores() or {}
            stores = _ds.get('data', []) if isinstance(_ds, dict) else (_ds or [])
        except Exception:
            stores = []
        for store in stores:
            if not isinstance(store, dict):
                continue
            store_name = store.get('store') or store.get('name')
            if not store_name:
                continue
            try:
                _r = pbs.get_snapshots(store_name) or {}
                snaps = _r.get('data', []) if isinstance(_r, dict) else (_r or [])
            except Exception:
                continue
            for sn in snaps:
                if sn.get('backup-type') not in ('vm', 'ct'):
                    continue
                vmid = sn.get('backup-id')
                if not vmid:
                    continue
                ts = sn.get('backup-time') or 0
                files = sn.get('files') or []
                enc = any((f.get('crypt-mode') or 'none') != 'none' for f in files)
                verified_ts = 0
                v = sn.get('verification') or {}
                if v.get('state') == 'ok':
                    verified_ts = v.get('upid_time') or ts
                try:
                    bumps.append((int(vmid), ts, enc, verified_ts))
                except (ValueError, TypeError):
                    continue
        return bumps

    # MK 2026-05-31 (D2) — defense-in-depth: PVE-returned node names get
    # interpolated into URL paths below. PVE has its own naming rules but
    # if PVE itself were ever compromised, a crafted node like `../foo`
    # would let it pivot into other PVE namespaces. Cheap belt-and-suspenders
    # check at the boundary. Mirrors api/nodes.py:_NODE_NAME_RE.
    import re as _re
    _SAFE_NODE = _re.compile(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$')

    def _scan_node(node):
        """Returns list of (vmid, ts, encrypted, 0) tuples for one PVE node's vzdump backups."""
        bumps = []
        if not node or not _SAFE_NODE.match(node):
            return bumps
        try:
            r = cm._api_get(f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{node}/storage')
            stores = r.json().get('data', []) if r.status_code == 200 else []
        except Exception:
            return bumps
        for s in stores:
            if 'backup' not in (s.get('content') or ''):
                continue
            if s.get('type') == 'pbs':
                continue  # already counted PBS-side
            store_name = s.get('storage')
            # MK (D2 cont.) — same belt-and-suspenders for storage names
            if not store_name or not _SAFE_NODE.match(store_name):
                continue
            try:
                cr = cm._api_get(f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{node}/storage/{store_name}/content?content=backup')
                items = cr.json().get('data', []) if cr.status_code == 200 else []
            except Exception:
                items = []
            for it in items:
                vmid = it.get('vmid')
                ts = it.get('ctime') or 0
                if vmid is None:
                    continue
                try:
                    bumps.append((int(vmid), ts, bool(it.get('encryption')), 0))
                except (ValueError, TypeError):
                    continue
        return bumps

    # PBS-side tasks: one per linked + connected PBS server
    tasks = {}
    for pbs_id, pbs in pbs_managers.items():
        if cluster_id not in (pbs.linked_clusters or []):
            continue
        if not pbs.connected:
            continue
        tasks[f'pbs:{pbs_id}'] = (lambda p=pbs: _scan_pbs(p))

    # PVE-side tasks: one per ONLINE node. Skip dead nodes — under parallel
    # fanout they'd park the joinall() at the full timeout, dragging total
    # wall-time. Sequential code happened to mask this because per-call
    # connect-fail was fast; parallel waits the slowest call.
    try:
        nodes_data = []
        try:
            nodes_data = cm._api_get(
                f'https://{cm.host}:{cm.api_port}/api2/json/nodes'
            ).json().get('data', []) or []
        except Exception:
            nodes_data = []
        for nd in nodes_data:
            name = nd.get('node')
            if not name:
                continue
            # PVE marks dead nodes 'offline' or status != 'online' on /nodes
            status = (nd.get('status') or '').lower()
            if status and status not in ('online', 'running'):
                continue
            tasks[f'node:{name}'] = (lambda nn=name: _scan_node(nn))
    except Exception as e:
        logging.debug(f'[vms-backup-status] node enum failed: {e}')

    if tasks:
        # Tight timeout: most PBS + healthy-node calls return in <2s. Anything
        # stuck longer contributes None and we move on with partial data.
        results = run_concurrent_dict(tasks, timeout=8)
        for bumps in results.values():
            for (vmid, ts, enc, verified_ts) in (bumps or []):
                try:
                    _bump(vmid, ts, encrypted=enc, verified_ts=verified_ts)
                except (ValueError, TypeError):
                    continue

    # Finalize ages
    out = []
    for rec in by_vm.values():
        last_age_h = ((now - rec['last_backup_ts']) / 3600) if rec['last_backup_ts'] else None
        verify_age_h = ((now - rec['last_verify_ts']) / 3600) if rec['last_verify_ts'] else None
        # status: ok / warn / stale / none
        if last_age_h is None:
            status = 'none'
        elif last_age_h < 36:
            status = 'ok'
        elif last_age_h < 7 * 24:
            status = 'warn'
        else:
            status = 'stale'
        out.append({
            'vmid': rec['vmid'],
            'last_backup_age_hours': round(last_age_h, 1) if last_age_h is not None else None,
            'count_30d': rec['count_30d'],
            'encrypted': rec['encrypted'],
            'last_verify_age_hours': round(verify_age_h, 1) if verify_age_h is not None else None,
            'status': status,
        })
    out.sort(key=lambda r: r['vmid'])
    return jsonify(out)


@bp.route('/api/clusters/<cluster_id>/datacenter/backup/<job_id>/run', methods=['POST'])
@require_auth(perms=['vm.backup'])
def run_backup_job_now(cluster_id, job_id):
    """Trigger an existing backup job immediately. Reuses job parameters.

    Note: the job_id matches the UUID in /etc/pve/jobs.cfg (vzdump: <id>).
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503
    # Read all jobs from /cluster/backup, find ours
    try:
        r = cm._api_get(f'https://{cm.host}:{cm.api_port}/api2/json/cluster/backup')
        jobs = r.json().get('data', []) if r.status_code == 200 else []
    except Exception as e:
        return jsonify({'error': f'failed to fetch jobs: {e}'}), 502
    job = next((j for j in jobs if j.get('id') == job_id), None)
    if not job:
        return jsonify({'error': f'job {job_id} not found'}), 404

    # Pick a node to run vzdump on. Prefer a node listed in the job's `node` field;
    # otherwise the first online node we know.
    pve_node = (job.get('node') or '').split(',')[0].strip()
    if not pve_node:
        try:
            ns = cm.get_node_status() or {}
            pve_node = next((n for n, d in ns.items() if d.get('status') == 'online'
                             or not d.get('offline')), None)
        except Exception:
            pve_node = None
    if not pve_node:
        return jsonify({'error': 'no online node available'}), 503

    # Build vzdump params from the job. Skip non-vzdump fields.
    params = {}
    skip = {'id', 'enabled', 'schedule', 'comment', 'next-run', 'type', 'node',
            'starttime', 'dow', 'repeat-missed', 'job_id'}
    for k, v in job.items():
        if k in skip or v is None or v == '':
            continue
        params[k] = v
    # 'all' / pool / vmid all transfer through

    url = f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{pve_node}/vzdump'
    try:
        r = cm._api_post(url, data=params, timeout=30)
        if r.status_code == 200:
            upid = r.json().get('data')
            log_audit(request.session.get('user', 'system'), 'backup.run_now',
                      f"Triggered backup job {job_id} on {pve_node}", cluster=cm.config.name)
            return jsonify({'success': True, 'upid': upid, 'node': pve_node})
        return jsonify({'error': r.text or f'HTTP {r.status_code}'}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/clusters/<cluster_id>/backup-restore', methods=['POST'])
@require_auth(perms=['vm.backup'])
def restore_backup(cluster_id):
    """Restore a backup. Three modes:
      - mode='new':    qmrestore into a new VMID (target_vmid)
      - mode='overwrite': qmrestore into an existing VMID (force)
      - mode='test':   like the verify pipeline but skip auto-cleanup; user keeps the test VM

    Body: {volid, target_node, target_vmid, mode, target_storage?}
    """
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503

    body = request.json or {}
    volid = (body.get('volid') or '').strip()
    target_node = (body.get('target_node') or '').strip()
    target_storage = (body.get('target_storage') or '').strip()
    mode = (body.get('mode') or 'new').strip()
    if not volid or ':' not in volid:
        return jsonify({'error': 'volid is required (storage:backup/...)'}), 400
    if not target_node:
        return jsonify({'error': 'target_node is required'}), 400
    try:
        target_vmid = int(body.get('target_vmid'))
    except (ValueError, TypeError):
        return jsonify({'error': 'target_vmid must be a number'}), 400
    if mode not in ('new', 'overwrite', 'test'):
        return jsonify({'error': "mode must be 'new', 'overwrite', or 'test'"}), 400

    # Test-mode = verify pipeline without cleanup
    if mode == 'test':
        from pegaprox.core.backup_verify import start_verification
        try:
            task_id = start_verification(cm, {
                'cluster_id': cluster_id,
                'node': target_node, 'vmid': target_vmid,
                'backup_volid': volid,
                # NS — pass auto_cleanup=False so the test VM survives for inspection
                'auto_cleanup': False,
            })
            return jsonify({'success': True, 'task_id': task_id, 'mode': 'test'})
        except Exception as e:
            return jsonify({'error': safe_error(e)}), 500

    # Choose vm_type from volid: pbs:backup/vm/100/... vs pbs:backup/ct/100/...
    is_lxc = '/ct/' in volid or volid.endswith('.lxc.tar') or 'vzdump-lxc' in volid
    cmd_path = 'lxc' if is_lxc else 'qemu'
    restore_url = f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{target_node}/{cmd_path}'

    params = {
        'vmid': target_vmid,
        'archive': volid,
    }
    if target_storage:
        params['storage'] = target_storage
    if mode == 'overwrite':
        params['force'] = 1

    try:
        r = cm._api_post(restore_url, data=params, timeout=30)
        if r.status_code == 200:
            upid = r.json().get('data')
            log_audit(request.session.get('user', 'system'), 'backup.restored',
                      f"Restoring {volid} → {cmd_path}/{target_vmid} on {target_node} (mode={mode})",
                      cluster=cm.config.name)
            return jsonify({'success': True, 'upid': upid, 'mode': mode, 'target_vmid': target_vmid})
        # surface PVE body
        try:
            err = r.json().get('errors') or r.json().get('message') or r.text
            if isinstance(err, dict):
                err = ', '.join(f'{k}: {v}' for k, v in err.items())
        except Exception:
            err = r.text or f'HTTP {r.status_code}'
        return jsonify({'error': err, 'pve_status': r.status_code}), r.status_code
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/pbs/<pbs_id>/backup-diff', methods=['GET'])
@require_auth(perms=['pbs.view'])
def diff_pbs_backups(pbs_id):
    """Compare two PBS backups (same backup-id, same datastore).

    Query: ?store=Backup&type=vm&id=100&a=2026-05-01T03:00:00Z&b=2026-05-08T03:00:00Z

    Returns a per-archive diff. Without proxmox-backup-client we can't
    cheaply diff actual file contents, so we compare the manifests
    (filenames + sizes + crypt-mode); good enough for "what changed in
    the .conf file" and "is the disk-image size deviating".
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    pbs = pbs_managers[pbs_id]
    if not pbs.connected:
        return jsonify({'error': 'PBS offline'}), 503

    store = request.args.get('store', '')
    btype = request.args.get('type', 'vm')
    bid = request.args.get('id', '')
    ts_a = request.args.get('a', '')
    ts_b = request.args.get('b', '')
    if not all([store, btype, bid, ts_a, ts_b]):
        return jsonify({'error': 'store, type, id, a, b query params required'}), 400

    try:
        _r = pbs.get_snapshots(store) or {}
        snaps = _r.get('data', []) if isinstance(_r, dict) else (_r or [])
    except Exception as e:
        return jsonify({'error': f'fetch failed: {e}'}), 502

    def _find(ts):
        for s in snaps:
            if s.get('backup-type') != btype:
                continue
            if str(s.get('backup-id')) != str(bid):
                continue
            # PBS exposes backup-time as epoch
            t = s.get('backup-time') or 0
            import datetime as _dt
            iso = _dt.datetime.utcfromtimestamp(t).strftime('%Y-%m-%dT%H:%M:%SZ')
            if iso == ts:
                return s
        return None

    sa, sb = _find(ts_a), _find(ts_b)
    if not sa: return jsonify({'error': f'snapshot a not found: {ts_a}'}), 404
    if not sb: return jsonify({'error': f'snapshot b not found: {ts_b}'}), 404

    files_a = {f.get('filename', '?'): f for f in (sa.get('files') or [])}
    files_b = {f.get('filename', '?'): f for f in (sb.get('files') or [])}
    keys = sorted(set(files_a) | set(files_b))
    diffs = []
    for k in keys:
        a = files_a.get(k); b = files_b.get(k)
        if a and b:
            if a.get('size') != b.get('size') or a.get('crypt-mode') != b.get('crypt-mode'):
                diffs.append({'kind': 'changed', 'filename': k, 'a': a, 'b': b})
            else:
                diffs.append({'kind': 'same', 'filename': k, 'a': a, 'b': b})
        elif a:
            diffs.append({'kind': 'removed', 'filename': k, 'a': a, 'b': None})
        else:
            diffs.append({'kind': 'added', 'filename': k, 'a': None, 'b': b})

    summary = {
        'added': sum(1 for d in diffs if d['kind'] == 'added'),
        'removed': sum(1 for d in diffs if d['kind'] == 'removed'),
        'changed': sum(1 for d in diffs if d['kind'] == 'changed'),
        'same': sum(1 for d in diffs if d['kind'] == 'same'),
    }
    return jsonify({
        'snapshot_a': {'time': ts_a, 'verification': sa.get('verification'),
                       'protected': sa.get('protected'), 'comment': sa.get('comment')},
        'snapshot_b': {'time': ts_b, 'verification': sb.get('verification'),
                       'protected': sb.get('protected'), 'comment': sb.get('comment')},
        'diffs': diffs, 'summary': summary,
    })


# ============================================================================
# Verify auto-schedule — global setting + worker hook
# ============================================================================
@bp.route('/api/pbs/verify-schedule', methods=['GET', 'PUT'])
@require_auth(perms=['pbs.config'])
def verify_schedule_config():
    """Read or write the auto-verify policy.

    Schema (in pegaprox config row 'pbs_verify_schedule'):
      {"enabled": bool, "weekly_count": int, "day": "sun", "hour": 4,
       "scope": "all"|"latest_per_vm", "max_age_days": int}
    """
    db = get_db()
    cur = db.conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)")
    db.conn.commit()
    if request.method == 'GET':
        row = cur.execute("SELECT v FROM pegaprox_kv WHERE k=?",
                          ('pbs_verify_schedule',)).fetchone()
        import json as _j
        if row and row['v']:
            return jsonify(_j.loads(row['v']))
        return jsonify({'enabled': False, 'weekly_count': 5, 'day': 'sun',
                        'hour': 4, 'scope': 'latest_per_vm', 'max_age_days': 30})
    # PUT
    body = request.json or {}
    cleaned = {
        'enabled': bool(body.get('enabled')),
        'weekly_count': max(1, min(50, int(body.get('weekly_count') or 5))),
        'day': body.get('day') if body.get('day') in ('mon','tue','wed','thu','fri','sat','sun') else 'sun',
        'hour': max(0, min(23, int(body.get('hour') or 4))),
        'scope': body.get('scope') if body.get('scope') in ('all', 'latest_per_vm') else 'latest_per_vm',
        'max_age_days': max(1, min(365, int(body.get('max_age_days') or 30))),
    }
    import json as _j
    cur.execute("INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)",
                ('pbs_verify_schedule', _j.dumps(cleaned)))
    db.conn.commit()
    log_audit(request.session.get('user', 'system'), 'pbs.verify_schedule_updated',
              f"Auto-verify schedule: {cleaned}")
    return jsonify(cleaned)


@bp.route('/api/pbs/encryption-key/generate', methods=['POST'])
@require_auth(perms=['pbs.config'])
def generate_encryption_key():
    """Generate a fresh PBS-format encryption key + a printable recovery sheet.
    The key is NOT persisted server-side — the user is expected to save it on
    the PVE side (`storage.cfg` `encryption-key`) and to keep an offline
    paper backup. We never escrow the key.
    """
    import os, base64, hashlib, datetime as _dt
    raw = os.urandom(32)
    # PBS-style fingerprint = sha256 of the key data, formatted with colons
    fp_hex = hashlib.sha256(raw).hexdigest().upper()
    fingerprint = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))
    now = _dt.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # PBS uses an unencrypted JSON envelope when no kdf is set
    pbs_key_doc = {
        'kdf': None,
        'created': now, 'modified': now,
        'data': base64.b64encode(raw).decode('ascii'),
        'fingerprint': fingerprint,
    }

    # Printable recovery sheet — split key into chunks so a human can transcribe
    hex_chunks = [fp_hex[i:i+8] for i in range(0, len(fp_hex), 8)]
    key_b64 = base64.b64encode(raw).decode('ascii')
    sheet = (
        "PBS ENCRYPTION KEY — RECOVERY SHEET\n"
        "===================================\n"
        f"Generated: {now}\n"
        f"Fingerprint:\n  {fingerprint}\n\n"
        "Key (base64):\n"
        f"  {key_b64}\n\n"
        "Key (hex, 4 lines x 8 chars):\n  "
        + '\n  '.join('  '.join(hex_chunks[i:i+4]) for i in range(0, len(hex_chunks), 4))
        + "\n\n"
        "USAGE:\n"
        "  1. Save the JSON file as /etc/pve/priv/storage/<storage-id>.enc\n"
        "     on each PVE node that backs up to this PBS storage.\n"
        "  2. Add `encryption-key /etc/pve/priv/storage/<storage-id>.enc` to\n"
        "     the corresponding pbs: section in /etc/pve/storage.cfg.\n"
        "  3. Print this sheet, store offline (safe / vault). Without this key,\n"
        "     past backups are UNRECOVERABLE.\n"
    )

    log_audit(request.session.get('user', 'system'), 'pbs.encryption_key_generated',
              f"Generated PBS encryption key, fingerprint {fingerprint[:23]}…")
    return jsonify({
        'key_json': pbs_key_doc,
        'fingerprint': fingerprint,
        'recovery_sheet': sheet,
    })


# End PBS API endpoints
# ============================================================================

