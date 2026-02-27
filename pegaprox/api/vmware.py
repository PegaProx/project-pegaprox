# -*- coding: utf-8 -*-
"""vmware + v2p migration routes - split from monolith dec 2025, NS"""

import time
import threading
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.core.vmware import VMwareManager, load_vmware_servers, save_vmware_server
from pegaprox.core.v2p import V2PMigrationTask, _run_v2p_migration
from pegaprox.background.broadcast import broadcast_resources_loop

bp = Blueprint('vmware', __name__)

# V2P migration tracking
_vmware_migrations = {}
_migration_lock_v2p = threading.Lock()

# =============================================================================

@bp.route('/api/vmware', methods=['GET'])
@require_auth(perms=['vmware.view'])
def list_vmware_servers():
    """List all configured VMware/vCenter servers"""
    result = []
    for vmware_id, mgr in vmware_managers.items():
        result.append(mgr.to_dict())
    
    # Also include disabled servers from DB
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT id, name, host, port, enabled, server_type FROM vmware_servers")
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['id'] not in vmware_managers:
                result.append({
                    'id': row_dict['id'],
                    'name': row_dict['name'],
                    'host': row_dict['host'],
                    'port': row_dict['port'],
                    'server_type': row_dict.get('server_type', 'vcenter'),
                    'enabled': bool(row_dict['enabled']),
                    'connected': False,
                })
    except Exception:
        pass
    
    return jsonify(result)


@bp.route('/api/vmware', methods=['POST'])
@require_auth(perms=['vmware.config'])
def add_vmware_server():
    """Add a new VMware/vCenter server"""
    data = request.json or {}
    
    if not data.get('name') or not data.get('host'):
        return jsonify({'error': 'Name and host are required'}), 400
    if not data.get('username'):
        return jsonify({'error': 'Username is required'}), 400
    if not data.get('password'):
        return jsonify({'error': 'Password is required'}), 400
    
    vmware_id = str(uuid.uuid4())[:8]
    
    mgr = VMwareManager(vmware_id, data)
    if not mgr.connect():
        return jsonify({'error': f'Connection failed: {mgr.last_error}'}), 400
    
    save_vmware_server(vmware_id, data)
    vmware_managers[vmware_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'vmware.added',
              f"Added VMware server: {data['name']} ({data['host']}, type={data.get('server_type', 'vcenter')})")
    
    return jsonify({'id': vmware_id, 'message': 'VMware server added successfully', **mgr.to_dict()}), 201


@bp.route('/api/vmware/<vmware_id>', methods=['PUT'])
@require_auth(perms=['vmware.config'])
def update_vmware_server(vmware_id):
    """Update a VMware server config"""
    data = request.json or {}
    
    if vmware_id not in vmware_managers:
        db = get_db()
        row = db.conn.cursor().execute("SELECT * FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
        if not row:
            return jsonify({'error': 'VMware server not found'}), 404
    
    if vmware_id in vmware_managers:
        old_mgr = vmware_managers[vmware_id]
        if data.get('password') == '********':
            data['password'] = old_mgr.password
    
    save_vmware_server(vmware_id, data)
    
    mgr = VMwareManager(vmware_id, data)
    if data.get('enabled', True):
        mgr.connect()
    vmware_managers[vmware_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'vmware.updated', f"Updated VMware server: {data.get('name', vmware_id)}")
    
    return jsonify(mgr.to_dict())


@bp.route('/api/vmware/<vmware_id>', methods=['DELETE'])
@require_auth(perms=['vmware.config'])
def delete_vmware_server(vmware_id):
    """Delete a VMware server"""
    name = vmware_managers[vmware_id].name if vmware_id in vmware_managers else vmware_id
    if vmware_id in vmware_managers:
        del vmware_managers[vmware_id]
    
    db = get_db()
    db.conn.cursor().execute("DELETE FROM vmware_servers WHERE id = ?", (vmware_id,))
    db.conn.commit()
    
    log_audit(request.session.get('user', 'admin'), 'vmware.deleted', f"Deleted VMware server: {name}")
    return jsonify({'message': f'VMware server {name} deleted'})


@bp.route('/api/vmware/test-connection', methods=['POST'])
@require_auth(perms=['vmware.config'])
def test_vmware_connection():
    """Test VMware connection with provided credentials"""
    data = request.json or {}
    if not data.get('host') or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Host, username and password required'}), 400
    
    mgr = VMwareManager('test', data)
    if mgr.connect():
        return jsonify({'success': True, 'server_info': mgr.server_info, 'api_version': mgr.api_version,
                        'connection_type': mgr._connection_type})
    return jsonify({'success': False, 'error': mgr.last_error}), 400


@bp.route('/api/vmware/<vmware_id>/diagnose', methods=['GET'])
@require_auth(perms=['vmware.config'])
def diagnose_vmware_connection(vmware_id):
    """diagnose connection issues -- compares stored vs. fresh credentials"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    
    # Get stored encrypted password from DB
    db = get_db()
    row = db.conn.cursor().execute(
        "SELECT pass_encrypted, username, host, port FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found in DB'}), 404
    
    row_d = dict(row)
    stored_enc = row_d.get('pass_encrypted', '')
    
    # Try decrypt
    decrypted = ''
    decrypt_ok = False
    try:
        decrypted = db._decrypt(stored_enc)
        decrypt_ok = True
    except Exception as e:
        decrypted = f'DECRYPT_FAILED: {e}'
    
    # NS: Feb 2026 - SECURITY: no password chars in API response, only boolean indicators
    result = {
        'vmware_id': vmware_id,
        'host': mgr.host,
        'port': mgr.port,
        'username_in_db': row_d.get('username', ''),
        'username_in_mgr': mgr.username,
        'password_encrypted_present': bool(stored_enc),
        'password_decrypted_ok': decrypt_ok,
        'password_matches_mgr': decrypted == mgr.password if decrypt_ok else False,
        'mgr_connected': mgr.connected,
        'mgr_connection_type': mgr._connection_type,
        'mgr_last_error': mgr.last_error,
    }
    
    # Try fresh SOAP connection with stored credentials
    try:
        from pyVim.connect import SmartConnect
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        si = SmartConnect(host=mgr.host, user=mgr.username, pwd=mgr.password,
                         port=mgr.port, sslContext=ctx, disableSslCertValidation=True)
        if si:
            result['fresh_soap_test'] = 'SUCCESS'
            from pyVim.connect import Disconnect
            Disconnect(si)
        else:
            result['fresh_soap_test'] = 'FAILED: SmartConnect returned None'
    except Exception as e:
        err = str(e)
        if 'InvalidLogin' in err:
            result['fresh_soap_test'] = f'FAILED: InvalidLogin (password wrong or locked)'
        else:
            result['fresh_soap_test'] = f'FAILED: {err[:150]}'
    
    return jsonify(result)


@bp.route('/api/vmware/<vmware_id>/vms', methods=['GET'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_vms(vmware_id):
    """List all VMs from vCenter/ESXi"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vms()
    if 'error' in result:
        if mgr.connect():
            result = mgr.get_vms()
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_vms()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>', methods=['GET'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_vm_detail(vmware_id, vm_id):
    """Get detailed VM info with guest and performance data"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vm(vm_id)
    if 'error' in result and mgr.connect():
        result = mgr.get_vm(vm_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    data = result.get('data', {})
    # Guest info
    guest = mgr.get_vm_guest_info(vm_id)
    if 'error' not in guest:
        data['guest_info'] = guest.get('data', {})
    # Performance
    perf = mgr.get_vm_performance(vm_id)
    if 'error' not in perf:
        data['performance'] = perf.get('data', {})
    
    return jsonify(data)


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/power/<action>', methods=['POST'])
@require_auth(perms=['vmware.vm.power'])
def vmware_vm_power(vmware_id, vm_id, action):
    """VM power actions: start, stop, suspend, reset"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    if action not in ('start', 'stop', 'suspend', 'reset'):
        return jsonify({'error': f'Invalid action: {action}'}), 400
    
    mgr = vmware_managers[vmware_id]
    result = mgr.vm_power_action(vm_id, action)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    log_audit(request.session.get('user', 'admin'), f'vmware.vm.{action}',
              f"VM power {action} on {vm_id} @ {mgr.name}")
    return jsonify({'message': f'VM {action} successful'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/snapshots', methods=['GET'])
@require_auth(perms=['vmware.vm.snapshot'])
def get_vmware_snapshots(vmware_id, vm_id):
    """List VM snapshots"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_snapshots(vm_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/snapshots', methods=['POST'])
@require_auth(perms=['vmware.vm.snapshot'])
def create_vmware_snapshot(vmware_id, vm_id):
    """Create a VM snapshot"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Snapshot name required'}), 400
    
    mgr = vmware_managers[vmware_id]
    result = mgr.create_snapshot(vm_id, data['name'], data.get('description', ''),
                                  data.get('memory', False), data.get('quiesce', True))
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.snapshot.created',
              f"Snapshot '{data['name']}' created for VM {vm_id} @ {mgr.name}")
    return jsonify({'message': f'Snapshot created', 'data': result.get('data')}), 201


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/snapshots/<snapshot_id>', methods=['DELETE'])
@require_auth(perms=['vmware.vm.snapshot'])
def delete_vmware_snapshot(vmware_id, vm_id, snapshot_id):
    """Delete a VM snapshot"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.delete_snapshot(vm_id, snapshot_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.snapshot.deleted',
              f"Snapshot {snapshot_id} deleted from VM {vm_id} @ {mgr.name}")
    return jsonify({'message': 'Snapshot deleted'})


@bp.route('/api/vmware/<vmware_id>/hosts', methods=['GET'])
@require_auth(perms=['vmware.host.view'])
def get_vmware_hosts(vmware_id):
    """List ESXi hosts"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_hosts()
    if 'error' in result:
        # Reconnect and retry
        if mgr.connect():
            result = mgr.get_hosts()
        # If still failing with 400, try SOAP fallback
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_hosts()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/datastores', methods=['GET'])
@require_auth(perms=['vmware.datastore.view'])
def get_vmware_datastores(vmware_id):
    """List VMware datastores"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_datastores()
    if 'error' in result:
        if mgr.connect():
            result = mgr.get_datastores()
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_datastores()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/datastores/<ds_id>', methods=['GET'])
@require_auth(perms=['vmware.datastore.view'])
def get_vmware_datastore_detail(vmware_id, ds_id):
    """Get detailed datastore info"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_datastore_detail(ds_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/networks', methods=['GET'])
@require_auth(perms=['vmware.network.view'])
def get_vmware_networks(vmware_id):
    """List VMware networks"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_networks()
    if 'error' in result:
        if mgr.connect():
            result = mgr.get_networks()
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_networks()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/clusters', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_vcenter_clusters(vmware_id):
    """List vCenter compute clusters with DRS/HA status"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vcenter_clusters_detailed()
    if 'error' in result:
        # Fallback to basic list
        result = mgr.get_vcenter_clusters()
    if 'error' in result and result.get('status_code') == 400:
        mgr._try_soap_fallback()
        if mgr._connection_type == 'soap':
            result = mgr.get_vcenter_clusters_detailed()
            if 'error' in result:
                result = mgr.get_vcenter_clusters()
    if 'error' in result:
        # For standalone ESXi (no clusters), return empty list instead of error
        if result.get('status_code') in (400, 404):
            return jsonify([])
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/clusters/<cluster_id>', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_cluster_detail(vmware_id, cluster_id):
    """Get cluster detail with DRS/HA config"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_cluster_detail(cluster_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/clusters/<cluster_id>/drs', methods=['POST'])
@require_auth(perms=['vmware.cluster.manage'])
def set_vmware_cluster_drs(vmware_id, cluster_id):
    """Toggle DRS on a cluster"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    enabled = data.get('enabled', False)
    automation = data.get('automation')
    mgr = vmware_managers[vmware_id]
    result = mgr.set_cluster_drs(cluster_id, enabled, automation)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.cluster.drs',
              f"DRS {'enabled' if enabled else 'disabled'} on cluster {cluster_id} @ {mgr.name}")
    return jsonify({'message': f"DRS {'enabled' if enabled else 'disabled'}"})


@bp.route('/api/vmware/<vmware_id>/clusters/<cluster_id>/ha', methods=['POST'])
@require_auth(perms=['vmware.cluster.manage'])
def set_vmware_cluster_ha(vmware_id, cluster_id):
    """Toggle HA on a cluster"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    enabled = data.get('enabled', False)
    mgr = vmware_managers[vmware_id]
    result = mgr.set_cluster_ha(cluster_id, enabled)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.cluster.ha',
              f"HA {'enabled' if enabled else 'disabled'} on cluster {cluster_id} @ {mgr.name}")
    return jsonify({'message': f"HA {'enabled' if enabled else 'disabled'}"})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/performance', methods=['GET'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_vm_performance(vmware_id, vm_id):
    """Get VM performance metrics"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_vm_performance(vm_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/watch', methods=['POST'])
@require_auth(perms=['vmware.vm.view'])
def watch_vmware_vm(vmware_id, vm_id):
    """register interest in a VM -- SSE will push detail data every 5s.
    Call again to renew the 120s watch window. POST with empty body."""
    if not hasattr(broadcast_resources_loop, '_vmw_watched'):
        broadcast_resources_loop._vmw_watched = {}
    broadcast_resources_loop._vmw_watched[(vmware_id, vm_id)] = time.time()
    return jsonify({'ok': True, 'watching': vm_id, 'ttl': 120})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/watch', methods=['DELETE'])
@require_auth(perms=['vmware.vm.view'])
def unwatch_vmware_vm(vmware_id, vm_id):
    """Stop watching a VM"""
    watched = getattr(broadcast_resources_loop, '_vmw_watched', {})
    watched.pop((vmware_id, vm_id), None)
    return jsonify({'ok': True})


@bp.route('/api/vmware/<vmware_id>/datacenters', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_datacenters(vmware_id):
    """List vCenter datacenters"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_datacenters()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))



@bp.route('/api/vmware/<vmware_id>/summary', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_summary(vmware_id):
    """Get environment summary (VM counts, host counts, health)"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_summary()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/health', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_health(vmware_id):
    """Get vCenter appliance health"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_appliance_health()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/folders', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_folders(vmware_id):
    """List folders"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    folder_type = request.args.get('type')
    result = mgr.get_folders(folder_type)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/resource-pools', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_resource_pools(vmware_id):
    """List resource pools"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_resource_pools()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/storage-policies', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_storage_policies(vmware_id):
    """List storage policies"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_storage_policies()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/content-libraries', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_content_libraries(vmware_id):
    """List content libraries"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_content_libraries()
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/console', methods=['POST'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_console(vmware_id, vm_id):
    """get console ticket -- tries WebMKS, MKS, direct URL"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vm_console_ticket(vm_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/config', methods=['PUT'])
@require_auth(perms=['vmware.vm.manage'])
def update_vmware_vm_config(vmware_id, vm_id):
    """Update VM configuration (CPU, RAM, notes, hot-add, etc)"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    data = request.json or {}
    result = mgr.update_vm_config(vm_id, data)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.config',
              f"Updated config on VM {vm_id} @ {mgr.name}: {list(data.keys())}")
    return jsonify({'message': 'VM configuration updated'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/network', methods=['PUT'])
@require_auth(perms=['vmware.vm.manage'])
def update_vmware_vm_network(vmware_id, vm_id):
    """Change VM network adapter"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    data = request.json or {}
    nic_key = int(data.get('nic_key', 0))
    network = data.get('network', '')
    if not network:
        return jsonify({'error': 'Network name required'}), 400
    result = mgr.update_vm_network(vm_id, nic_key, network)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.network',
              f"Changed network on VM {vm_id} to '{network}' @ {mgr.name}")
    return jsonify({'message': f"Network changed to '{network}'"})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/boot-order', methods=['PUT'])
@require_auth(perms=['vmware.vm.manage'])
def update_vmware_vm_boot_order(vmware_id, vm_id):
    """Change VM boot order"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    data = request.json or {}
    boot_order = data.get('boot_order', ['disk', 'cdrom', 'net'])
    result = mgr.update_vm_boot_order(vm_id, boot_order)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'message': 'Boot order updated'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/clone', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def clone_vmware_vm(vmware_id, vm_id):
    """Clone a VM"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Clone name is required'}), 400
    
    mgr = vmware_managers[vmware_id]
    result = mgr.clone_vm(vm_id, data['name'], data.get('folder'), data.get('resource_pool'), data.get('datastore'))
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.cloned',
              f"Cloned VM {vm_id} as '{data['name']}' @ {mgr.name}")
    return jsonify({'message': f"VM cloned as '{data['name']}'", 'data': result.get('data')}), 201


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>', methods=['DELETE'])
@require_auth(perms=['vmware.vm.power'])
def delete_vmware_vm(vmware_id, vm_id):
    """Delete a VM (must be powered off)"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.delete_vm(vm_id)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.deleted',
              f"Deleted VM {vm_id} @ {mgr.name}")
    return jsonify({'message': 'VM deleted'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/rename', methods=['POST'])
@require_auth(perms=['vmware.vm.power'])
def rename_vmware_vm(vmware_id, vm_id):
    """Rename a VM"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'New name is required'}), 400
    
    mgr = vmware_managers[vmware_id]
    result = mgr.rename_vm(vm_id, data['name'])
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.renamed',
              f"Renamed VM {vm_id} to '{data['name']}' @ {mgr.name}")
    return jsonify({'message': f"VM renamed to '{data['name']}'"})



# ===========================================================================

@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/migration-plan', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_migration_plan(vmware_id, vm_id):
    """Analyze source VM and return migration plan with available Proxmox targets.
    Also detects ESXi host and datastore for SSHFS access."""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_vm_disks_for_export(vm_id)
    if 'error' in result:
        return jsonify(result), 400
    vm_data = result['data']
    
    # Available Proxmox targets
    targets = []
    for cid, cmgr in cluster_managers.items():
        if cmgr.is_connected:
            nodes = list(cmgr.nodes.keys()) if cmgr.nodes else []
            node_storages = {}
            for n in nodes:
                try:
                    sr = cmgr._api_get(f"https://{cmgr.host}:8006/api2/json/nodes/{n}/storage")
                    if sr.status_code == 200:
                        node_storages[n] = [s['storage'] for s in sr.json().get('data', [])
                                            if s.get('active') and 'images' in s.get('content', '')]
                except:
                    node_storages[n] = []
            targets.append({
                'cluster_id': cid, 'cluster_name': cmgr.config.name,
                'nodes': nodes, 'storages': node_storages
            })
    
    return jsonify({
        'source': vm_data,
        'targets': targets,
        'esxi_host': mgr.host,
        'esxi_user': 'root',
        'estimated_downtime_seconds': max(10, int(vm_data.get('total_disk_gb', 10) * 0.3)),
        'requirements': [
            'SSH must be enabled on ESXi host',
            'sshfs must be installed on target Proxmox node (apt install sshfs)',
            'ESXi root password is required for SSHFS access',
            'Sufficient temp space on Proxmox node for disk conversion',
        ],
        'method': 'SSHFS + qm importdisk (works on VMFS 5, VMFS 6, vSAN, NFS)',
    })


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/migrate', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def start_vmware_migration(vmware_id, vm_id):
    """Start near-zero-downtime migration from VMware to Proxmox.
    
    Required body:
    - target_cluster, target_node, target_storage
    - esxi_password: Root password for ESXi SSH access
    
    Optional:
    - esxi_host: ESXi host IP (default: from VMware server config)
    - esxi_user: SSH username (default: root)
    - esxi_datastore: Datastore name (auto-detected if not set)
    - esxi_vm_dir: VM directory name on datastore (default: VM name)
    - network_bridge, start_after, remove_source
    """
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    
    for field in ('target_cluster', 'target_node', 'target_storage'):
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    if not data.get('esxi_password'):
        return jsonify({'error': 'esxi_password is required for SSHFS-based migration'}), 400
    if data['target_cluster'] not in cluster_managers:
        return jsonify({'error': 'Target cluster not found'}), 404
    
    mgr = vmware_managers[vmware_id]
    vm_detail = mgr.get_vm(vm_id)
    vm_name = vm_detail.get('data', {}).get('name', vm_id) if 'data' in vm_detail else vm_id
    
    mid = str(uuid.uuid4())[:8]
    task = V2PMigrationTask(mid, vmware_id, vm_id, data['target_cluster'],
                            data['target_node'], data['target_storage'], vm_name, data)
    
    with _migration_lock_v2p:
        _vmware_migrations[mid] = task
    
    thread = threading.Thread(target=_run_v2p_migration, args=(task,), daemon=True)
    thread.start()
    
    log_audit(request.session.get('user', 'admin'), 'vmware.migration.started',
              f"V2P migration: {vm_name} @ {data.get('esxi_host', mgr.host)} -> "
              f"{data['target_cluster']}/{data['target_node']}/{data['target_storage']}")
    
    return jsonify({
        'migration_id': mid,
        'message': f'Migration started for {vm_name}',
        'task': task.to_dict(),
    }), 202


@bp.route('/api/vmware/migrations', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def list_vmware_migrations():
    """List all active and recent migrations"""
    return jsonify([t.to_dict() for t in _vmware_migrations.values()])


@bp.route('/api/vmware/migrations/<mid>', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_migration_status(mid):
    """Get detailed status of a specific migration"""
    if mid not in _vmware_migrations:
        return jsonify({'error': 'Migration not found'}), 404
    return jsonify(_vmware_migrations[mid].to_dict())


# End VMware API endpoints
# ============================================================================

