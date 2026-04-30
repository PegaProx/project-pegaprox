# site recovery plans & failover orchestration - NS Mar 2026

import json
import uuid
import logging
import time
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import check_cluster_access

bp = Blueprint('site_recovery', __name__)


# #225: wrap greenlet spawns so a crash sets plan status to 'failed' instead of stuck 'running'
def _safe_spawn_failover(func, plan_id, *args):
    import gevent
    def _wrapper():
        try:
            func(plan_id, *args)
        except Exception as e:
            logging.error(f"[SR] Background task crashed for plan {plan_id}: {e}")
            try:
                db = get_db()
                db.execute("UPDATE site_recovery_plans SET status = 'failed', updated_at = ? WHERE id = ?",
                           (datetime.utcnow().isoformat(), plan_id))
            except Exception:
                pass
    gevent.spawn(_wrapper)



# ---- helpers ----

def _get_plan(plan_id):
    db = get_db()
    row = db.query_one('SELECT * FROM site_recovery_plans WHERE id = ?', (plan_id,))
    if not row:
        return None
    plan = dict(row)
    # parse json fields
    for k in ('network_mappings', 'storage_mappings'):
        try:
            plan[k] = json.loads(plan[k] or '{}')
        except (json.JSONDecodeError, TypeError):
            plan[k] = {}
    return plan


def _get_plan_vms(plan_id):
    db = get_db()
    rows = db.query('SELECT * FROM site_recovery_vms WHERE plan_id = ? ORDER BY boot_group, vmid', (plan_id,))
    return [dict(r) for r in rows] if rows else []


def _plan_with_vms(plan):
    """Enrich plan with VMs and replication status"""
    plan['vms'] = _get_plan_vms(plan['id'])
    # attach RPO info from replication jobs
    db = get_db()
    for vm in plan['vms']:
        if vm.get('replication_job_id'):
            repl = db.query_one('SELECT last_run, last_status FROM cross_cluster_replications WHERE id = ?',
                                (vm['replication_job_id'],))
            if repl:
                vm['last_replication'] = repl['last_run']
                vm['replication_status'] = repl['last_status']
    return plan


# ---- CRUD: Plans ----

@bp.route('/api/site-recovery/plans', methods=['GET'])
@require_auth(perms=['site_recovery.view'])
def list_plans():
    db = get_db()
    rows = db.query('SELECT * FROM site_recovery_plans ORDER BY created_at DESC')
    plans = []
    for row in (rows or []):
        p = dict(row)
        for k in ('network_mappings', 'storage_mappings'):
            try:
                p[k] = json.loads(p[k] or '{}')
            except Exception:
                p[k] = {}
        # include vm count
        cnt = db.query_one('SELECT COUNT(*) as c FROM site_recovery_vms WHERE plan_id = ?', (p['id'],))
        p['vm_count'] = cnt['c'] if cnt else 0
        plans.append(p)
    return jsonify(plans)


@bp.route('/api/site-recovery/plans', methods=['POST'])
@require_auth(perms=['site_recovery.manage'])
def create_plan():
    data = request.json or {}
    if not data.get('name') or not data.get('source_cluster') or not data.get('target_cluster'):
        return jsonify({'error': 'name, source_cluster and target_cluster are required'}), 400

    if data['source_cluster'] == data['target_cluster']:
        return jsonify({'error': 'Source and target cluster must be different'}), 400

    # NS: validate clusters actually exist
    if data['source_cluster'] not in cluster_managers or data['target_cluster'] not in cluster_managers:
        return jsonify({'error': 'One or both clusters not found'}), 404

    plan_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()
    db = get_db()

    db.execute('''INSERT INTO site_recovery_plans
        (id, group_id, name, source_cluster, target_cluster, network_mappings, storage_mappings,
         auto_failover, failover_timeout, pre_failover_webhook, post_failover_webhook,
         created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (plan_id, data.get('group_id', ''), data['name'],
         data['source_cluster'], data['target_cluster'],
         json.dumps(data.get('network_mappings', {})),
         json.dumps(data.get('storage_mappings', {})),
         1 if data.get('auto_failover') else 0,
         data.get('failover_timeout', 120),
         data.get('pre_failover_webhook', ''),
         data.get('post_failover_webhook', ''),
         getattr(request, 'session', {}).get('user', 'system'),
         now, now))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.plan_created', f"Created recovery plan '{data['name']}': {data['source_cluster']} → {data['target_cluster']}")

    return jsonify({'id': plan_id, 'message': 'Plan created'}), 201


@bp.route('/api/site-recovery/plans/<plan_id>', methods=['GET'])
@require_auth(perms=['site_recovery.view'])
def get_plan_detail(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    return jsonify(_plan_with_vms(plan))


@bp.route('/api/site-recovery/plans/<plan_id>', methods=['PUT'])
@require_auth(perms=['site_recovery.manage'])
def update_plan(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    data = request.json or {}
    allowed = {'name', 'network_mappings', 'storage_mappings', 'auto_failover',
               'failover_timeout', 'pre_failover_webhook', 'post_failover_webhook', 'group_id'}
    updates = []
    params = []
    for key in allowed:
        if key in data:
            val = data[key]
            if key in ('network_mappings', 'storage_mappings'):
                val = json.dumps(val) if isinstance(val, dict) else val
            elif key == 'auto_failover':
                val = 1 if val else 0
            updates.append(f"{key} = ?")
            params.append(val)

    if not updates:
        return jsonify({'error': 'No fields to update'}), 400

    updates.append("updated_at = ?")
    params.append(datetime.utcnow().isoformat())
    params.append(plan_id)

    db = get_db()
    db.execute(f"UPDATE site_recovery_plans SET {', '.join(updates)} WHERE id = ?", params)

    usr = getattr(request, 'session', {}).get('user', 'system')
    changed = [k for k in allowed if k in data]
    log_audit(usr, 'site_recovery.plan_updated', f"Updated plan '{plan['name']}': {', '.join(changed)}")

    return jsonify({'message': 'Plan updated'})


@bp.route('/api/site-recovery/plans/<plan_id>', methods=['DELETE'])
@require_auth(perms=['site_recovery.manage'])
def delete_plan(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    # #238: allow force-delete of stuck plans via ?force=1 query param
    if plan['status'] in ('running', 'testing'):
        force = request.args.get('force', '').lower() in ('1', 'true')
        if not force:
            return jsonify({'error': 'Plan is currently active. Use force=1 to delete anyway.'}), 409
        logging.warning(f"[SR] Force-deleting plan '{plan['name']}' while status={plan['status']}")

    db = get_db()
    db.execute('DELETE FROM site_recovery_vms WHERE plan_id = ?', (plan_id,))
    db.execute('DELETE FROM site_recovery_events WHERE plan_id = ?', (plan_id,))
    db.execute('DELETE FROM site_recovery_plans WHERE id = ?', (plan_id,))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.plan_deleted', f"Deleted recovery plan '{plan['name']}'")

    return jsonify({'message': 'Plan deleted'})


# ---- CRUD: Protected VMs ----

@bp.route('/api/site-recovery/plans/<plan_id>/vms', methods=['GET'])
@require_auth(perms=['site_recovery.view'])
def list_plan_vms(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    return jsonify(_get_plan_vms(plan_id))


@bp.route('/api/site-recovery/plans/<plan_id>/vms', methods=['POST'])
@require_auth(perms=['site_recovery.manage'])
def add_plan_vm(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    data = request.json or {}
    if not data.get('vmid'):
        return jsonify({'error': 'vmid is required'}), 400
    try:
        data['vmid'] = int(data['vmid'])
    except (ValueError, TypeError):
        return jsonify({'error': 'vmid must be a number'}), 400

    vm_id = str(uuid.uuid4())[:8]
    db = get_db()

    # check for duplicate
    exists = db.query_one('SELECT id FROM site_recovery_vms WHERE plan_id = ? AND vmid = ?',
                          (plan_id, data['vmid']))
    if exists:
        return jsonify({'error': f"VM {data['vmid']} already in this plan"}), 409

    db.execute('''INSERT INTO site_recovery_vms
        (id, plan_id, vmid, vm_name, vm_type, boot_group, boot_delay, replication_job_id, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (vm_id, plan_id, data['vmid'], data.get('vm_name', ''),
         data.get('vm_type', 'qemu'), data.get('boot_group', 0),
         data.get('boot_delay', 30), data.get('replication_job_id', ''),
         data.get('notes', '')))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.vm_added', f"VM {data['vmid']} added to plan '{plan['name']}'")

    return jsonify({'id': vm_id, 'message': 'VM added to plan'}), 201


@bp.route('/api/site-recovery/plans/<plan_id>/vms/<vm_id>', methods=['PUT'])
@require_auth(perms=['site_recovery.manage'])
def update_plan_vm(plan_id, vm_id):
    db = get_db()
    row = db.query_one('SELECT * FROM site_recovery_vms WHERE id = ? AND plan_id = ?', (vm_id, plan_id))
    if not row:
        return jsonify({'error': 'VM not found in plan'}), 404

    data = request.json or {}
    allowed = {'boot_group', 'boot_delay', 'replication_job_id', 'notes', 'vm_name'}
    updates = []
    params = []
    for key in allowed:
        if key in data:
            updates.append(f"{key} = ?")
            params.append(data[key])
    if updates:
        params.append(vm_id)
        db.execute(f"UPDATE site_recovery_vms SET {', '.join(updates)} WHERE id = ?", params)

        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'site_recovery.vm_updated', f"VM {row['vmid']} config changed in plan {plan_id}")

    return jsonify({'message': 'VM updated'})


@bp.route('/api/site-recovery/plans/<plan_id>/vms/<vm_id>', methods=['DELETE'])
@require_auth(perms=['site_recovery.manage'])
def remove_plan_vm(plan_id, vm_id):
    db = get_db()
    row = db.query_one('SELECT vmid FROM site_recovery_vms WHERE id = ? AND plan_id = ?', (vm_id, plan_id))
    db.execute('DELETE FROM site_recovery_vms WHERE id = ? AND plan_id = ?', (vm_id, plan_id))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.vm_removed', f"VM {row['vmid'] if row else vm_id} removed from plan {plan_id}")

    return jsonify({'message': 'VM removed from plan'})


# ---- Actions ----

@bp.route('/api/site-recovery/plans/<plan_id>/readiness', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def check_readiness(plan_id):
    """Pre-validate that failover can succeed"""
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    issues = []
    vms = _get_plan_vms(plan_id)

    # check source cluster connected
    src_mgr = cluster_managers.get(plan['source_cluster'])
    if not src_mgr:
        issues.append({'severity': 'error', 'msg': f"Source cluster '{plan['source_cluster']}' not found"})
    elif not src_mgr.is_connected:
        issues.append({'severity': 'warning', 'msg': 'Source cluster not connected (emergency failover only)'})

    # check target cluster connected
    tgt_mgr = cluster_managers.get(plan['target_cluster'])
    if not tgt_mgr:
        issues.append({'severity': 'error', 'msg': f"Target cluster '{plan['target_cluster']}' not found"})
    elif not tgt_mgr.is_connected:
        issues.append({'severity': 'error', 'msg': 'Target cluster not connected'})

    if not vms:
        issues.append({'severity': 'warning', 'msg': 'No VMs in recovery plan'})

    # check replication status per VM
    db = get_db()
    for vm in vms:
        if vm.get('replication_job_id'):
            repl = db.query_one('SELECT last_run, last_status, enabled FROM cross_cluster_replications WHERE id = ?',
                                (vm['replication_job_id'],))
            if not repl:
                issues.append({'severity': 'warning', 'msg': f"VM {vm['vmid']}: replication job not found"})
            elif repl['last_status'] == 'error':
                issues.append({'severity': 'error', 'msg': f"VM {vm['vmid']}: last replication failed"})
            elif not repl['enabled']:
                issues.append({'severity': 'warning', 'msg': f"VM {vm['vmid']}: replication job disabled"})
        else:
            issues.append({'severity': 'info', 'msg': f"VM {vm['vmid']}: no replication job linked"})

    # check target resources (basic: is there enough RAM?)
    # MK Apr 2026 (#350) — get_node_status() returns mem_total/mem_used, not the
    # /cluster/resources field names maxmem/mem. The old code subtracted two
    # always-missing keys → 0 → warning fired even on clusters with 13G+ free.
    if tgt_mgr and tgt_mgr.is_connected:
        try:
            node_status = tgt_mgr.get_node_status()
            if node_status:
                total_mem_free = sum(
                    d.get('mem_total', 0) - d.get('mem_used', 0)
                    for d in node_status.values()
                    if d.get('status') == 'online'
                )
                if total_mem_free < 2 * 1024**3:  # less than 2GB free
                    issues.append({'severity': 'warning', 'msg': 'Target cluster has less than 2GB free memory'})
        except Exception:
            pass

    # check network mappings
    net_maps = plan.get('network_mappings', {})
    stor_maps = plan.get('storage_mappings', {})
    if not net_maps:
        issues.append({'severity': 'info', 'msg': 'No network mappings configured (VMs will keep original bridge names)'})

    # NS 2026-04-24 — actually verify mapping targets exist on target cluster.
    # Root cause of most mid-flight failover crashes: admin typo'd a storage name
    # like `local_lvm` → `local-lvmm`. Proxmox doesn't check until migration starts.
    if tgt_mgr and tgt_mgr.is_connected:
        try:
            from pegaprox.background.site_recovery import validate_mappings
            issues.extend(validate_mappings(tgt_mgr, stor_maps, net_maps))
        except Exception as e:
            issues.append({'severity': 'warning', 'msg': f'Mapping validation failed to run: {e}'})

    # update last readiness check timestamp
    now = datetime.utcnow().isoformat()
    db.execute('UPDATE site_recovery_plans SET last_readiness_check = ?, updated_at = ? WHERE id = ?',
               (now, now, plan_id))

    has_errors = any(i['severity'] == 'error' for i in issues)
    status = 'failed' if has_errors else 'passed'

    return jsonify({
        'status': status,
        'issues': issues,
        'vm_count': len(vms),
        'checked_at': now
    })


@bp.route('/api/site-recovery/plans/<plan_id>/failover', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def execute_planned_failover(plan_id):
    """Graceful planned failover - source must be reachable"""
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    if plan['status'] == 'running':
        return jsonify({'error': 'Failover already in progress'}), 409

    src_mgr = cluster_managers.get(plan['source_cluster'])
    tgt_mgr = cluster_managers.get(plan['target_cluster'])
    if not src_mgr or not src_mgr.is_connected:
        return jsonify({'error': 'Source cluster not reachable. Use emergency failover instead.'}), 503
    if not tgt_mgr or not tgt_mgr.is_connected:
        return jsonify({'error': 'Target cluster not reachable'}), 503

    vms = _get_plan_vms(plan_id)
    if not vms:
        return jsonify({'error': 'No VMs in plan'}), 400

    # NS Apr 2026: atomic ready->running transition. UPDATE..WHERE status='ready' only
    # changes the row if no one else flipped it first (e.g. auto-failover heartbeat racing).
    db = get_db()
    now = datetime.utcnow().isoformat()
    cur = db.conn.cursor()
    cur.execute(
        "UPDATE site_recovery_plans SET status = 'running', updated_at = ? WHERE id = ? AND status = 'ready'",
        (now, plan_id)
    )
    db.conn.commit()
    if cur.rowcount != 1:
        return jsonify({'error': 'Plan state changed — concurrent failover may be in progress'}), 409

    from pegaprox.background.site_recovery import execute_failover
    _safe_spawn_failover(execute_failover, plan_id, 'planned')

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.failover', f"Planned failover started: {plan['name']}")

    return jsonify({'message': 'Planned failover started', 'status': 'running'})


@bp.route('/api/site-recovery/plans/<plan_id>/emergency', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def execute_emergency_failover(plan_id):
    """Emergency failover - source may be unreachable"""
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    if plan['status'] == 'running':
        return jsonify({'error': 'Failover already in progress'}), 409

    tgt_mgr = cluster_managers.get(plan['target_cluster'])
    if not tgt_mgr or not tgt_mgr.is_connected:
        return jsonify({'error': 'Target cluster not reachable'}), 503

    vms = _get_plan_vms(plan_id)
    if not vms:
        return jsonify({'error': 'No VMs in plan'}), 400

    # atomic ready->running transition (same race protection as planned failover)
    db = get_db()
    now = datetime.utcnow().isoformat()
    cur = db.conn.cursor()
    cur.execute(
        "UPDATE site_recovery_plans SET status = 'running', updated_at = ? WHERE id = ? AND status = 'ready'",
        (now, plan_id)
    )
    db.conn.commit()
    if cur.rowcount != 1:
        return jsonify({'error': 'Plan state changed — concurrent failover may be in progress'}), 409

    from pegaprox.background.site_recovery import execute_failover
    _safe_spawn_failover(execute_failover, plan_id, 'emergency')

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.emergency', f"Emergency failover started: {plan['name']}")

    return jsonify({'message': 'Emergency failover started', 'status': 'running'})


@bp.route('/api/site-recovery/plans/<plan_id>/test', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def execute_test_failover(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    if plan['status'] in ('running', 'testing'):
        return jsonify({'error': 'Action already in progress'}), 409

    tgt_mgr = cluster_managers.get(plan['target_cluster'])
    if not tgt_mgr or not tgt_mgr.is_connected:
        return jsonify({'error': 'Target cluster not reachable'}), 503

    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute("UPDATE site_recovery_plans SET status = 'testing', updated_at = ? WHERE id = ?", (now, plan_id))

    from pegaprox.background.site_recovery import execute_test_failover
    _safe_spawn_failover(execute_test_failover, plan_id)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.test', f"Test failover started: {plan['name']}")

    return jsonify({'message': 'Test failover started', 'status': 'testing'})


@bp.route('/api/site-recovery/plans/<plan_id>/test/cleanup', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def cleanup_test_failover(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    from pegaprox.background.site_recovery import cleanup_test
    _safe_spawn_failover(cleanup_test, plan_id)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.test_cleanup', f"Test cleanup started: {plan['name']}")

    return jsonify({'message': 'Test cleanup started'})


@bp.route('/api/site-recovery/plans/<plan_id>/failback', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def execute_failback(plan_id):
    """Reverse direction - migrate VMs back to original source"""
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    if plan['status'] == 'running':
        return jsonify({'error': 'Action already in progress'}), 409

    # for failback, the original target is now source and vice versa
    original_src = cluster_managers.get(plan['source_cluster'])
    original_tgt = cluster_managers.get(plan['target_cluster'])
    if not original_src or not original_src.is_connected:
        return jsonify({'error': 'Original source cluster not reachable (needed for failback)'}), 503
    if not original_tgt or not original_tgt.is_connected:
        return jsonify({'error': 'Current cluster (original target) not reachable'}), 503

    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute("UPDATE site_recovery_plans SET status = 'running', updated_at = ? WHERE id = ?", (now, plan_id))

    from pegaprox.background.site_recovery import execute_failover
    _safe_spawn_failover(execute_failover, plan_id, 'failback')

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.failback', f"Failback started: {plan['name']}")

    return jsonify({'message': 'Failback started', 'status': 'running'})


@bp.route('/api/site-recovery/plans/<plan_id>/cancel', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def cancel_action(plan_id):
    plan = _get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404
    if plan['status'] not in ('running', 'testing'):
        return jsonify({'error': 'No active action to cancel'}), 409
    prev_status = plan['status']
    db = get_db()
    db.execute("UPDATE site_recovery_plans SET status = 'ready', updated_at = ? WHERE id = ?",
               (datetime.utcnow().isoformat(), plan_id))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'site_recovery.cancelled', f"Cancelled {prev_status} action on plan '{plan['name']}'")

    return jsonify({'message': 'Action cancelled'})


# ---- Events ----

@bp.route('/api/site-recovery/plans/<plan_id>/events', methods=['GET'])
@require_auth(perms=['site_recovery.view'])
def get_plan_events(plan_id):
    db = get_db()
    rows = db.query('SELECT * FROM site_recovery_events WHERE plan_id = ? ORDER BY started_at DESC LIMIT 50',
                    (plan_id,))
    events = []
    for r in (rows or []):
        ev = dict(r)
        try:
            ev['details'] = json.loads(ev.get('details', '{}') or '{}')
        except Exception:
            ev['details'] = {}
        events.append(ev)
    return jsonify(events)
