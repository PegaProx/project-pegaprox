# -*- coding: utf-8 -*-
"""Cross-Hypervisor Migration API - LW Mar 2026
Endpoints for Proxmox <-> XCP-ng <-> ESXi migration.
"""

import threading
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers, _xhm_migrations
from pegaprox.utils.auth import require_auth, load_users
from pegaprox.utils.audit import log_audit
from pegaprox.utils.rbac import user_can_access_vm
from pegaprox.api.helpers import check_cluster_access
from pegaprox.core.xhm import (
    XHMigrationTask, plan_xcpng_to_pve, plan_pve_to_xcpng,
    _run_xcpng_to_pve, _run_pve_to_xcpng,
    plan_esxi_to_pve, plan_esxi_to_xcpng,
    _run_esxi_to_pve, _run_esxi_to_xcpng,
)

bp = Blueprint('xhm', __name__)

_xhm_lock = threading.Lock()


@bp.route('/api/xhm/plan', methods=['GET'])
@require_auth(perms=['vm.migrate'])
def xhm_plan():
    """Get migration plan - analyzes source VM and lists available targets."""
    source_cluster = request.args.get('source_cluster', '')
    source_vmid = request.args.get('source_vmid', '')
    target_cluster = request.args.get('target_cluster', '')
    direction = request.args.get('direction', '')

    if not source_cluster or not source_vmid or not target_cluster:
        return jsonify({'error': 'source_cluster, source_vmid, and target_cluster are required'}), 400

    # Authorization: check source cluster access
    ok, err = check_cluster_access(source_cluster)
    if not ok:
        return err

    # Authorization: check target cluster access
    ok, err = check_cluster_access(target_cluster)
    if not ok:
        return err

    # Authorization: check source VM access
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    try:
        vmid_int = int(source_vmid)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid source_vmid'}), 400
    
    if not user_can_access_vm(user, source_cluster, vmid_int, 'vm.migrate'):
        return jsonify({'error': 'Access denied to source VM'}), 403

    # auto-detect direction from cluster types
    src_mgr = cluster_managers.get(source_cluster)
    tgt_mgr = cluster_managers.get(target_cluster)
    if not src_mgr:
        return jsonify({'error': 'Source cluster not found'}), 404
    if not tgt_mgr:
        return jsonify({'error': 'Target cluster not found'}), 404

    src_type = getattr(src_mgr, 'cluster_type', 'proxmox')
    tgt_type = getattr(tgt_mgr, 'cluster_type', 'proxmox')

    if src_type == tgt_type:
        return jsonify({'error': f'Both clusters are {src_type} - use native migration instead'}), 400

    # route to correct plan function based on cluster types
    if src_type == 'esxi' and tgt_type == 'proxmox':
        result = plan_esxi_to_pve(source_cluster, source_vmid, target_cluster)
    elif src_type == 'esxi' and tgt_type == 'xcpng':
        result = plan_esxi_to_xcpng(source_cluster, source_vmid, target_cluster)
    elif src_type == 'xcpng':
        result = plan_xcpng_to_pve(source_cluster, source_vmid, target_cluster)
    elif tgt_type == 'xcpng':
        source_node = request.args.get('source_node', '')
        if not source_node:
            return jsonify({'error': 'source_node required for Proxmox source'}), 400
        result = plan_pve_to_xcpng(source_cluster, source_node, source_vmid, target_cluster)
    else:
        return jsonify({'error': f'Unsupported migration: {src_type} -> {tgt_type}'}), 400

    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


@bp.route('/api/xhm/migrate', methods=['POST'])
@require_auth(perms=['vm.migrate'])
def xhm_start():
    """Start cross-hypervisor migration."""
    data = request.json or {}
    required = ['source_cluster', 'source_vmid', 'target_cluster', 'target_storage']
    for f in required:
        if not data.get(f):
            return jsonify({'error': f'{f} is required'}), 400

    # MK May 2026 (#481 port) — target_storage is embedded in pvesm alloc cmds
    # in core/xhm.py. Validate at api boundary.
    from pegaprox.utils.sanitization import validate_storage_name
    if not validate_storage_name(data['target_storage']):
        return jsonify({'error': 'Invalid target_storage name. Must be alphanumeric with hyphens, underscores, or dots only.'}), 400

    # Authorization: check source cluster access
    ok, err = check_cluster_access(data['source_cluster'])
    if not ok:
        return err

    # Authorization: check target cluster access
    ok, err = check_cluster_access(data['target_cluster'])
    if not ok:
        return err

    # Authorization: check source VM access
    users = load_users()
    user = users.get(request.session['user'], {})
    user['username'] = request.session['user']
    try:
        vmid_int = int(data['source_vmid'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid source_vmid'}), 400
    
    if not user_can_access_vm(user, data['source_cluster'], vmid_int, 'vm.migrate'):
        return jsonify({'error': 'Access denied to source VM'}), 403

    src_mgr = cluster_managers.get(data['source_cluster'])
    tgt_mgr = cluster_managers.get(data['target_cluster'])
    if not src_mgr:
        return jsonify({'error': 'Source cluster not found'}), 404
    if not tgt_mgr:
        return jsonify({'error': 'Target cluster not found'}), 404

    src_type = getattr(src_mgr, 'cluster_type', 'proxmox')
    tgt_type = getattr(tgt_mgr, 'cluster_type', 'proxmox')

    if src_type == 'esxi' and tgt_type == 'proxmox':
        direction = 'esxi_to_pve'
    elif src_type == 'esxi' and tgt_type == 'xcpng':
        direction = 'esxi_to_xcpng'
    elif src_type == 'xcpng' and tgt_type != 'xcpng':
        direction = 'xcpng_to_pve'
    elif src_type != 'xcpng' and tgt_type == 'xcpng':
        direction = 'pve_to_xcpng'
    else:
        return jsonify({'error': 'Invalid cluster combination for cross-hypervisor migration'}), 400

    if direction in ('xcpng_to_pve', 'esxi_to_pve') and not data.get('target_node'):
        return jsonify({'error': 'target_node is required for migration to Proxmox'}), 400

    mid = str(uuid.uuid4())[:8]
    task = XHMigrationTask(
        mid=mid,
        direction=direction,
        source_cluster=data['source_cluster'],
        source_node=data.get('source_node', ''),
        source_vmid=data['source_vmid'],
        target_cluster=data['target_cluster'],
        target_node=data['target_node'],
        target_storage=data['target_storage'],
        vm_name=data.get('vm_name', ''),
        config=data,
    )

    with _xhm_lock:
        _xhm_migrations[mid] = task

    _runners = {
        'xcpng_to_pve': _run_xcpng_to_pve,
        'pve_to_xcpng': _run_pve_to_xcpng,
        'esxi_to_pve': _run_esxi_to_pve,
        'esxi_to_xcpng': _run_esxi_to_xcpng,
    }
    runner = _runners.get(direction)
    if not runner:
        return jsonify({'error': f'No runner for direction {direction}'}), 400
    t = threading.Thread(target=runner, args=(task,), daemon=True)
    t.start()

    user = request.session.get('user', 'admin') if hasattr(request, 'session') else 'admin'
    log_audit(user, 'xhm.migration.started',
              f"XHM {direction}: {data.get('vm_name', data['source_vmid'])} -> "
              f"{data['target_cluster']}/{data['target_node']}")

    return jsonify({
        'migration_id': mid,
        'message': f'Migration started ({direction})',
        'task': task.to_dict(),
    }), 202


@bp.route('/api/xhm/migrations', methods=['GET'])
@require_auth(perms=['vm.migrate'])
def xhm_list():
    return jsonify([t.to_dict() for t in _xhm_migrations.values()])


@bp.route('/api/xhm/migrations/<mid>', methods=['GET'])
@require_auth(perms=['vm.migrate'])
def xhm_detail(mid):
    if mid not in _xhm_migrations:
        return jsonify({'error': 'Migration not found'}), 404
    return jsonify(_xhm_migrations[mid].to_dict())
