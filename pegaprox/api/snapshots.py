# -*- coding: utf-8 -*-
"""
Snapshot Scheduling — NS May 2026.

Lightweight scheduler that fires `mgr.create_snapshot()` on a repeating
schedule against a list of VMIDs or a tag, with retention pruning. This
sits BETWEEN the existing one-shot snapshot endpoint (`/api/clusters/<id>
/vms/.../snapshots POST`) and the heavyweight PBS backup system — perfect
for "give me the last 24h of hourly snapshots on my prod DB without
copying GBs to PBS every hour."

Schedules:
  - hourly: every full hour
  - daily:  once per day at schedule_at (HH:MM)
  - weekly: once per Sunday at schedule_at
  - cron:   placeholder for future expansion

Targets:
  - vm:  comma-separated list of VMIDs
  - tag: VMs whose Proxmox tag matches target_value (substring match)

Retention:
  - retention_count > 0: keep only the last N snapshots created BY THIS POLICY
                         (named pegaprox-<policy-id>-<ts>)
  - retention_days > 0:  also prune snapshots older than N days
"""
import json
import time
import uuid
import logging
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access
from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('snapshot_schedule', __name__)


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict): return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _row_to_policy(r):
    return {
        'id': r['id'],
        'cluster_id': r['cluster_id'],
        'name': r['name'],
        'target_type': r['target_type'],
        'target_value': r['target_value'],
        'schedule': r['schedule'],
        'schedule_at': r['schedule_at'] or '03:00',
        'retention_count': r['retention_count'] or 0,
        'retention_days': r['retention_days'] or 0,
        'include_ram': bool(r['include_ram']),
        'enabled': bool(r['enabled']),
        'last_run_at': r['last_run_at'],
        'last_run_status': r['last_run_status'] or '',
        'notes': r['notes'] or '',
        'created_by': r['created_by'] or '',
        'created_at': r['created_at'],
    }


def _resolve_targets(mgr, policy):
    """Return list of (node, vmid, vm_type) tuples that match the policy."""
    targets = []
    try:
        resources = mgr.get_vm_resources() or []
    except Exception as e:
        logging.warning(f"[snap-sched] get_vm_resources failed: {e}")
        return targets

    if policy['target_type'] == 'vm':
        wanted = {x.strip() for x in (policy['target_value'] or '').split(',') if x.strip()}
        for r in resources:
            vid = str(r.get('vmid', ''))
            t = r.get('type')
            n = r.get('node')
            if t in ('qemu', 'lxc') and vid in wanted and n:
                targets.append((n, int(vid), t))
    elif policy['target_type'] == 'tag':
        wanted_tag = (policy['target_value'] or '').strip().lower()
        if not wanted_tag:
            return targets
        for r in resources:
            tags_str = (r.get('tags') or '').lower()
            tag_set = {t.strip() for t in tags_str.split(';') if t.strip()}
            if r.get('type') in ('qemu', 'lxc') and wanted_tag in tag_set and r.get('node'):
                targets.append((r['node'], int(r['vmid']), r['type']))
    return targets


def _is_due(policy, now=None):
    """Check whether the policy should fire right now. Idempotent: also reads
    last_run_at to avoid double-fires when the scheduler wakes during the
    same minute."""
    now = now or datetime.now()
    last_run = policy['last_run_at']
    last_dt = None
    if last_run:
        try:
            last_dt = datetime.fromisoformat(last_run)
        except Exception:
            last_dt = None

    sch = (policy['schedule'] or 'daily').lower()
    if sch == 'hourly':
        # fire at the top of each hour
        if now.minute > 5: return False  # only within first 5 min of the hour
        if last_dt and (now - last_dt).total_seconds() < 3000: return False  # 50 min guard
        return True

    # daily / weekly use schedule_at HH:MM
    schedule_at = (policy['schedule_at'] or '03:00').strip()
    try:
        hh, mm = [int(x) for x in schedule_at.split(':', 1)]
    except Exception:
        hh, mm = 3, 0
    if not (now.hour == hh and 0 <= now.minute - mm < 5):
        return False
    if sch == 'daily':
        if last_dt and (now - last_dt).total_seconds() < 23 * 3600: return False
        return True
    if sch == 'weekly':
        # fire on Sunday (weekday == 6)
        if now.weekday() != 6: return False
        if last_dt and (now - last_dt).total_seconds() < 6 * 24 * 3600: return False
        return True
    return False


def _snap_name(policy_id):
    """Deterministic prefix so retention can find policy-owned snapshots."""
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    safe = (policy_id or 'pol')[:12]
    return f"pegaprox-{safe}-{ts}"


def _prune(mgr, node, vmid, vm_type, policy):
    """Delete snapshots owned by this policy beyond retention. Owned =
    name starts with `pegaprox-<policy_id_prefix>-`."""
    pruned = 0
    prefix = f"pegaprox-{policy['id'][:12]}-"
    try:
        snaps = mgr.list_snapshots(node, vmid, vm_type) if hasattr(mgr, 'list_snapshots') else []
    except Exception:
        snaps = []
    if not snaps:
        # fallback: list via direct API
        try:
            url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot"
            resp = mgr._api_get(url)
            if resp and resp.status_code == 200:
                snaps = resp.json().get('data') or []
        except Exception:
            snaps = []

    owned = []
    for s in snaps:
        name = s.get('name') or ''
        if not name.startswith(prefix): continue
        snap_t = s.get('snaptime', 0)
        owned.append((snap_t, name))
    owned.sort(reverse=True)  # newest first

    keep_set = set()
    if policy['retention_count'] > 0:
        for _, name in owned[:policy['retention_count']]:
            keep_set.add(name)
    cutoff = 0
    if policy['retention_days'] > 0:
        cutoff = (datetime.now() - timedelta(days=policy['retention_days'])).timestamp()

    for snap_t, name in owned:
        if name in keep_set:
            continue
        if cutoff and snap_t >= cutoff:
            keep_set.add(name)
            continue
        # delete this snapshot
        try:
            if hasattr(mgr, 'delete_snapshot'):
                mgr.delete_snapshot(node, vmid, vm_type, name)
            else:
                url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot/{name}"
                mgr._api_delete(url)
            pruned += 1
        except Exception as e:
            logging.warning(f"[snap-sched] prune delete failed for {name}: {e}")
    return pruned


def _execute_policy(policy_id):
    """Run one policy. Persists a row in snapshot_runs."""
    db = get_db()
    c = db.conn.cursor()
    c.execute('SELECT * FROM snapshot_policies WHERE id = ?', (policy_id,))
    row = c.fetchone()
    if not row:
        return
    policy = _row_to_policy(row)
    if not policy['enabled']:
        return

    started_at = datetime.now().isoformat()
    c.execute(
        '''INSERT INTO snapshot_runs (policy_id, started_at, status)
           VALUES (?, ?, 'running')''',
        (policy_id, started_at)
    )
    run_id = c.lastrowid
    db.conn.commit()

    log_lines = []
    created = 0
    failed = 0
    pruned_total = 0

    mgr = cluster_managers.get(policy['cluster_id'])
    if not mgr:
        log_lines.append('cluster manager not found')
        c.execute('''UPDATE snapshot_runs SET status='failed', finished_at=?, log=?, summary=?
                     WHERE id=?''',
                  (datetime.now().isoformat(), '\n'.join(log_lines), 'no manager', run_id))
        db.conn.commit()
        return

    targets = _resolve_targets(mgr, policy)
    log_lines.append(f"resolved {len(targets)} target VMs")

    for node, vmid, vm_type in targets:
        snap = _snap_name(policy['id'])
        try:
            res = mgr.create_snapshot(node, vmid, vm_type, snap, f"PegaProx policy {policy['name']}", policy['include_ram'])
            if res.get('success'):
                created += 1
                log_lines.append(f"  ✓ {vm_type}/{vmid}@{node} → {snap}")
            else:
                failed += 1
                log_lines.append(f"  ✗ {vm_type}/{vmid}@{node}: {res.get('error', 'unknown')}")
        except Exception as e:
            failed += 1
            log_lines.append(f"  ✗ {vm_type}/{vmid}@{node}: exception: {e}")
            continue
        try:
            pruned = _prune(mgr, node, vmid, vm_type, policy)
            if pruned:
                pruned_total += pruned
                log_lines.append(f"    pruned {pruned} old snapshot(s)")
        except Exception as e:
            log_lines.append(f"    prune err: {e}")

    finished_at = datetime.now().isoformat()
    status = 'completed' if failed == 0 else ('partial' if created > 0 else 'failed')
    summary = f"{created} created · {failed} failed · {pruned_total} pruned · {len(targets)} targets"

    c.execute('''UPDATE snapshot_runs SET status=?, finished_at=?, log=?, summary=?,
                 snapshots_created=?, snapshots_failed=?, snapshots_pruned=?
                 WHERE id=?''',
              (status, finished_at, '\n'.join(log_lines), summary,
               created, failed, pruned_total, run_id))
    c.execute('''UPDATE snapshot_policies SET last_run_at=?, last_run_status=? WHERE id=?''',
              (finished_at, status, policy['id']))
    db.conn.commit()

    try:
        log_audit('system', 'snapshot.policy_run',
                  f"policy '{policy['name']}': {summary}",
                  cluster=mgr.config.name if hasattr(mgr, 'config') else policy['cluster_id'])
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────
# Background scheduler
# ──────────────────────────────────────────────────────────────────────────

_scheduler_running = False
_scheduler_lock = threading.Lock()


def _scheduler_loop():
    while _scheduler_running:
        try:
            db = get_db()
            c = db.conn.cursor()
            c.execute("SELECT * FROM snapshot_policies WHERE enabled = 1")
            for row in c.fetchall():
                p = _row_to_policy(row)
                if _is_due(p):
                    try:
                        _execute_policy(p['id'])
                    except Exception as e:
                        logging.warning(f"[snap-sched] policy {p['id']} run failed: {e}")
        except Exception as e:
            logging.debug(f"[snap-sched] loop iter err: {e}")
        # check every 60s
        for _ in range(60):
            if not _scheduler_running:
                return
            time.sleep(1)


def start_scheduler():
    global _scheduler_running
    with _scheduler_lock:
        if _scheduler_running:
            return
        _scheduler_running = True
    t = threading.Thread(target=_scheduler_loop, daemon=True, name='snapshot-scheduler')
    t.start()
    logging.info("[snap-sched] scheduler thread started (60s tick)")


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/clusters/<cluster_id>/snapshot-policies', methods=['GET'])
@require_auth(perms=['vm.snapshot'])
def list_policies(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM snapshot_policies WHERE cluster_id=? ORDER BY created_at DESC', (cluster_id,))
        return jsonify({'policies': [_row_to_policy(r) for r in c.fetchall()]})
    except Exception:
        logging.exception('snapshot policies list failed')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/snapshot-policies', methods=['POST'])
@require_auth(perms=['vm.snapshot'])
def create_policy(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    body = request.get_json(silent=True) or {}
    name = (body.get('name') or '').strip()[:80]
    target_type = body.get('target_type') or 'tag'
    target_value = (body.get('target_value') or '').strip()[:300]
    schedule = body.get('schedule') or 'daily'
    schedule_at = (body.get('schedule_at') or '03:00')[:5]
    retention_count = max(0, int(body.get('retention_count') or 7))
    retention_days = max(0, int(body.get('retention_days') or 0))
    include_ram = bool(body.get('include_ram'))
    enabled = bool(body.get('enabled', True))
    notes = (body.get('notes') or '')[:500]

    if not name or not target_value:
        return jsonify({'error': 'name and target_value required'}), 400
    if target_type not in ('vm', 'tag'):
        return jsonify({'error': 'target_type must be vm or tag'}), 400
    if schedule not in ('hourly', 'daily', 'weekly'):
        return jsonify({'error': 'schedule must be hourly / daily / weekly'}), 400

    pid = uuid.uuid4().hex[:12]
    try:
        c = get_db().conn.cursor()
        c.execute('''INSERT INTO snapshot_policies
            (id, cluster_id, name, target_type, target_value, schedule, schedule_at,
             retention_count, retention_days, include_ram, enabled, notes,
             created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (pid, cluster_id, name, target_type, target_value, schedule, schedule_at,
             retention_count, retention_days, 1 if include_ram else 0, 1 if enabled else 0,
             notes, _current_user(), datetime.now().isoformat()))
        get_db().conn.commit()
        c.execute('SELECT * FROM snapshot_policies WHERE id=?', (pid,))
        return jsonify({'policy': _row_to_policy(c.fetchone())})
    except Exception:
        logging.exception('create snapshot policy failed')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/snapshot-policies/<pid>', methods=['PUT'])
@require_auth(perms=['vm.snapshot'])
def update_policy(cluster_id, pid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    body = request.get_json(silent=True) or {}
    fields = []; params = []
    for k, t in (('name', str), ('target_type', str), ('target_value', str),
                 ('schedule', str), ('schedule_at', str), ('notes', str)):
        if k in body:
            fields.append(f'{k}=?')
            params.append(str(body[k])[:300])
    if 'retention_count' in body:
        fields.append('retention_count=?'); params.append(int(body['retention_count']))
    if 'retention_days' in body:
        fields.append('retention_days=?'); params.append(int(body['retention_days']))
    if 'include_ram' in body:
        fields.append('include_ram=?'); params.append(1 if body['include_ram'] else 0)
    if 'enabled' in body:
        fields.append('enabled=?'); params.append(1 if body['enabled'] else 0)
    if not fields:
        return jsonify({'error': 'nothing to update'}), 400
    params.extend([pid, cluster_id])
    try:
        c = get_db().conn.cursor()
        c.execute(f"UPDATE snapshot_policies SET {','.join(fields)} WHERE id=? AND cluster_id=?", params)
        get_db().conn.commit()
        if c.rowcount == 0:
            return jsonify({'error': 'not found'}), 404
        c.execute('SELECT * FROM snapshot_policies WHERE id=?', (pid,))
        return jsonify({'policy': _row_to_policy(c.fetchone())})
    except Exception:
        logging.exception('update snapshot policy failed')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/snapshot-policies/<pid>', methods=['DELETE'])
@require_auth(perms=['vm.snapshot'])
def delete_policy(cluster_id, pid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM snapshot_policies WHERE id=? AND cluster_id=?', (pid, cluster_id))
        get_db().conn.commit()
        if c.rowcount == 0:
            return jsonify({'error': 'not found'}), 404
        return jsonify({'ok': True})
    except Exception:
        logging.exception('delete snapshot policy failed')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/snapshot-policies/<pid>/run', methods=['POST'])
@require_auth(perms=['vm.snapshot'])
def run_policy_now(cluster_id, pid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # verify it exists + belongs to this cluster
    c = get_db().conn.cursor()
    c.execute('SELECT id FROM snapshot_policies WHERE id=? AND cluster_id=?', (pid, cluster_id))
    if not c.fetchone():
        return jsonify({'error': 'not found'}), 404
    # fire in a thread so the request returns fast
    t = threading.Thread(target=_execute_policy, args=(pid,), daemon=True,
                         name=f'snap-run-{pid}')
    t.start()
    return jsonify({'ok': True, 'message': 'policy run started'})


@bp.route('/api/clusters/<cluster_id>/snapshot-policies/<pid>/runs', methods=['GET'])
@require_auth(perms=['vm.snapshot'])
def list_runs(cluster_id, pid):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT id FROM snapshot_policies WHERE id=? AND cluster_id=?', (pid, cluster_id))
        if not c.fetchone():
            return jsonify({'error': 'not found'}), 404
        c.execute('''SELECT * FROM snapshot_runs WHERE policy_id=?
                     ORDER BY started_at DESC LIMIT 50''', (pid,))
        return jsonify({'runs': [dict(r) for r in c.fetchall()]})
    except Exception:
        logging.exception('list snapshot runs failed')
        return jsonify({'error': 'internal error'}), 500
