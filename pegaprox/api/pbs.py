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
        cursor.execute("SELECT id, name, host, port, enabled FROM pbs_servers")
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['id'] not in pbs_managers:
                result.append({
                    'id': row_dict['id'],
                    'name': row_dict['name'],
                    'host': row_dict['host'],
                    'port': row_dict['port'],
                    'enabled': bool(row_dict['enabled']),
                    'connected': False,
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
    mgr = PBSManager(pbs_id, data)
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
    
    # Recreate manager with new config
    if pbs_id in pbs_managers:
        old_mgr = pbs_managers[pbs_id]
        # Preserve password if masked
        if data.get('password') == '********':
            data['password'] = old_mgr.password
        if data.get('api_token_secret') == '********':
            data['api_token_secret'] = old_mgr.api_token_secret
    
    mgr = PBSManager(pbs_id, data)
    if data.get('enabled', True):
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
    test_mgr = PBSManager('test', data)
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
        test_mgr = PBSManager('test', data)
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
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected', 'connected': False}), 503
    
    status = mgr.get_server_status()
    version = mgr.get_version()
    datastores = mgr.get_datastore_usage()
    
    return jsonify({
        'server': status.get('data', {}),
        'version': version.get('data', {}),
        'datastores': datastores.get('data', []),
        'connected': mgr.connected,
        'name': mgr.name,
    })


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastores(pbs_id):
    """List datastores with detailed status"""
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


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshots(pbs_id, store):
    """List snapshots in a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    result = mgr.get_snapshots(store, ns=ns)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/groups', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_groups(pbs_id, store):
    """List backup groups in a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    result = mgr.get_groups(store, ns=ns)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/gc', methods=['POST'])
@require_auth(perms=['pbs.datastore.gc'])
def pbs_start_gc(pbs_id, store):
    """Start garbage collection"""
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
        # Extract filename from filepath
        filename = filepath.rstrip('/').split('/')[-1] or 'download'
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
        return jsonify({'error': str(e)}), 500


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


# End PBS API endpoints
# ============================================================================

