# -*- coding: utf-8 -*-
"""
DR Drill — NS May 2026.

Structured dry-run of a Site Recovery plan. Unlike the existing
`/readiness` endpoint (one-shot list of issues) and `/test` (creates a
clone for real-failover smoke-testing), a Drill is a CATEGORIZED set of
~10 checks, each with status (pass/warn/fail), message, duration, and
persisted evidence — designed to be exported as a compliance artifact
(SOC 2, ISO 22301, NIS2 BCM/DR requirements).

Each check belongs to a category:
  plan         — plan integrity (VMs present, valid groups, mapping configs)
  source       — source cluster reachability (warn if down — DR is exactly
                 the case where source is down, but we want to flag it)
  target       — target cluster connected, has nodes, sane state
  capacity     — target has enough RAM + storage for all VMs
  network      — every source bridge/VNet maps to a real target bridge/VNet
  storage      — every source storage maps to a real target storage with
                 'images' content
  replication  — per-VM: replication job exists, enabled, last run < RPO,
                 last status != error
  boot         — boot groups numbered ≥ 0, no gaps that suggest typos
  ha           — HA-managed source VMs will be HA-managed on target
  compliance   — drill metadata (executor, timestamp, plan checksum)

After all checks complete, drill is marked completed/failed/partial and
summary stats are written. Frontend polls `/api/dr-drills/<id>` until
finished and renders pass/warn/fail counts + per-check detail; PDF export
uses generatePegaProxPDF for the evidence document.
"""
import json
import time
import uuid
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit

bp = Blueprint('dr_drill', __name__)


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict): return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _record_check(drill_id, category, name, status, message, detail='', duration_ms=0, seq=0):
    try:
        c = get_db().conn.cursor()
        c.execute('''INSERT INTO dr_drill_checks
            (drill_id, category, name, status, message, detail, duration_ms, sequence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (drill_id, category, name, status, message[:500], detail[:2000], int(duration_ms), seq))
        get_db().conn.commit()
    except Exception as e:
        logging.warning(f"[dr-drill] _record_check failed: {e}")


class _Runner:
    """Helper to time + persist each check inline so the runner reads top-down."""
    def __init__(self, drill_id):
        self.drill_id = drill_id
        self.seq = 0
        self.passes = 0
        self.warns = 0
        self.fails = 0

    def check(self, category, name, fn):
        """Run fn() → (status, message, detail). status in {pass, warn, fail}."""
        self.seq += 1
        start = time.time()
        try:
            status, message, detail = fn()
        except Exception as e:
            status = 'fail'
            message = f'check raised: {e}'
            detail = ''
            logging.exception(f'[dr-drill] check {category}/{name} raised')
        ms = int((time.time() - start) * 1000)
        _record_check(self.drill_id, category, name, status, message, detail, ms, self.seq)
        if status == 'pass': self.passes += 1
        elif status == 'warn': self.warns += 1
        else: self.fails += 1


def _execute_drill(drill_id):
    """Background worker — runs a complete drill. Idempotent; marks status
    on dr_drills row so polling endpoint can return progress."""
    db = get_db()
    c = db.conn.cursor()
    c.execute('SELECT * FROM dr_drills WHERE id = ?', (drill_id,))
    drow = c.fetchone()
    if not drow:
        return
    drill = dict(drow)
    plan_id = drill['plan_id']

    # load plan + vms
    c.execute('SELECT * FROM site_recovery_plans WHERE id = ?', (plan_id,))
    prow = c.fetchone()
    if not prow:
        _record_check(drill_id, 'plan', 'load_plan', 'fail', 'plan no longer exists', '', 0, 1)
        c.execute("UPDATE dr_drills SET status='failed', finished_at=?, summary=? WHERE id=?",
                  (datetime.now().isoformat(), 'plan missing', drill_id))
        db.conn.commit()
        return
    plan = dict(prow)
    try:
        plan['network_mappings'] = json.loads(plan.get('network_mappings') or '{}')
    except Exception: plan['network_mappings'] = {}
    try:
        plan['storage_mappings'] = json.loads(plan.get('storage_mappings') or '{}')
    except Exception: plan['storage_mappings'] = {}

    c.execute('SELECT * FROM site_recovery_vms WHERE plan_id = ? ORDER BY boot_group, vmid', (plan_id,))
    vms = [dict(r) for r in c.fetchall()]

    runner = _Runner(drill_id)
    src_mgr = cluster_managers.get(plan['source_cluster'])
    tgt_mgr = cluster_managers.get(plan['target_cluster'])

    # ── plan integrity ──
    runner.check('plan', 'has_vms',
                 lambda: ('pass' if vms else 'fail',
                          f'{len(vms)} VM(s) in plan' if vms else 'plan has no VMs',
                          ''))
    runner.check('plan', 'has_target_cluster',
                 lambda: ('pass' if plan.get('target_cluster') else 'fail',
                          plan.get('target_cluster') or 'missing target_cluster', ''))

    # ── source cluster ──
    def _src():
        if not src_mgr:
            return ('warn', f"source cluster '{plan['source_cluster']}' not registered (emergency-failover only)", '')
        if not getattr(src_mgr, 'is_connected', False):
            return ('warn', 'source cluster not connected — DR scenario is plausible, but we cannot verify plan against live source',
                    f"host={getattr(src_mgr, 'host', '')}")
        return ('pass', f"source cluster '{plan['source_cluster']}' connected", '')
    runner.check('source', 'cluster_reachable', _src)

    # ── target cluster ──
    def _tgt():
        if not tgt_mgr:
            return ('fail', f"target cluster '{plan['target_cluster']}' not registered", '')
        if not getattr(tgt_mgr, 'is_connected', False):
            return ('fail', 'target cluster not connected', f"host={getattr(tgt_mgr, 'host', '')}")
        nodes = list((tgt_mgr.nodes or {}).keys())
        online = [n for n, d in (tgt_mgr.nodes or {}).items() if d.get('status') == 'online']
        if not online:
            return ('fail', 'target cluster has no online nodes', f"nodes={nodes}")
        return ('pass', f"{len(online)}/{len(nodes)} target nodes online", f"online={online}")
    runner.check('target', 'cluster_reachable', _tgt)

    # ── capacity: RAM ──
    def _ram():
        if not (tgt_mgr and getattr(tgt_mgr, 'is_connected', False)):
            return ('warn', 'target offline — cannot verify capacity', '')
        try:
            ns = tgt_mgr.get_node_status() or {}
            free = sum(d.get('mem_total', 0) - d.get('mem_used', 0)
                       for d in ns.values() if d.get('status') == 'online')
        except Exception as e:
            return ('warn', f'capacity probe failed: {e}', '')
        # estimate plan footprint: try to read each VM's memory from source mgr
        need = 0
        if src_mgr and getattr(src_mgr, 'is_connected', False):
            try:
                for r in (src_mgr.get_vm_resources() or []):
                    if r.get('type') in ('qemu', 'lxc') and any(int(v.get('vmid', -1)) == int(r.get('vmid', -1)) for v in vms):
                        need += int(r.get('maxmem', 0) or 0)
            except Exception: pass
        if need == 0:
            return ('warn', 'could not determine plan RAM footprint',
                    f"target_free_gb={free/(1024**3):.1f}")
        margin_gb = (free - need) / (1024 ** 3)
        if margin_gb < 0:
            return ('fail', f'target short by {-margin_gb:.1f} GB RAM',
                    f"need_gb={need/(1024**3):.1f}, free_gb={free/(1024**3):.1f}")
        if margin_gb < 4:
            return ('warn', f'tight: only {margin_gb:.1f} GB headroom after failover',
                    f"need_gb={need/(1024**3):.1f}, free_gb={free/(1024**3):.1f}")
        return ('pass', f'{margin_gb:.1f} GB RAM headroom on target',
                f"need_gb={need/(1024**3):.1f}, free_gb={free/(1024**3):.1f}")
    runner.check('capacity', 'ram_headroom', _ram)

    # ── network mappings ──
    def _net():
        net_maps = plan.get('network_mappings') or {}
        if not net_maps:
            return ('warn', 'no network mappings configured (VMs keep original bridge names — risky if names differ)', '')
        if not (tgt_mgr and getattr(tgt_mgr, 'is_connected', False)):
            return ('warn', 'target offline — cannot verify mappings', f"mappings={list(net_maps.keys())}")
        # gather target bridges across all nodes
        tgt_bridges = set()
        try:
            for node in (tgt_mgr.nodes or {}).keys():
                r = tgt_mgr._api_get(f"https://{tgt_mgr.host}:8006/api2/json/nodes/{node}/network")
                if r and r.status_code == 200:
                    for nic in (r.json().get('data') or []):
                        if nic.get('type') in ('bridge', 'OVSBridge', 'bond'):
                            tgt_bridges.add(nic.get('iface', ''))
        except Exception: pass
        # also check SDN VNets cluster-wide
        try:
            r = tgt_mgr._api_get(f"https://{tgt_mgr.host}:8006/api2/json/cluster/sdn/vnets")
            if r and r.status_code == 200:
                for v in (r.json().get('data') or []):
                    n = v.get('vnet') or v.get('name')
                    if n: tgt_bridges.add(n)
        except Exception: pass
        missing = [v for v in net_maps.values() if v not in tgt_bridges]
        if missing:
            return ('fail', f'{len(missing)} network mapping(s) point at non-existent target bridge: {", ".join(missing[:5])}',
                    f'all_targets={sorted(tgt_bridges)}')
        return ('pass', f'all {len(net_maps)} network mapping(s) resolve on target',
                f'mappings={net_maps}')
    runner.check('network', 'mappings_resolve', _net)

    # ── storage mappings ──
    def _stor():
        stor_maps = plan.get('storage_mappings') or {}
        if not stor_maps:
            return ('warn', 'no storage mappings configured', '')
        if not (tgt_mgr and getattr(tgt_mgr, 'is_connected', False)):
            return ('warn', 'target offline — cannot verify', f"mappings={list(stor_maps.keys())}")
        try:
            r = tgt_mgr._api_get(f"https://{tgt_mgr.host}:8006/api2/json/storage")
            data = r.json().get('data') if (r and r.status_code == 200) else []
        except Exception:
            data = []
        by_id = {s.get('storage'): s for s in data if s.get('storage')}
        problems = []
        for src, dst in stor_maps.items():
            if dst not in by_id:
                problems.append(f"{src}→{dst}: target storage missing")
                continue
            content = by_id[dst].get('content') or ''
            if 'images' not in content.split(','):
                problems.append(f"{src}→{dst}: target lacks 'images' content")
        if problems:
            return ('fail', f'{len(problems)} storage mapping issue(s)',
                    '\n'.join(problems[:5]))
        return ('pass', f'all {len(stor_maps)} storage mapping(s) valid',
                f'mappings={stor_maps}')
    runner.check('storage', 'mappings_valid', _stor)

    # ── replication freshness ──
    rpo_breach_seconds = 0
    def _repl():
        nonlocal rpo_breach_seconds
        if not vms:
            return ('warn', 'no VMs in plan to verify', '')
        details = []
        worst_status = 'pass'
        c2 = get_db().conn.cursor()
        for vm in vms:
            jid = vm.get('replication_job_id') or ''
            if not jid:
                details.append(f"vmid {vm['vmid']}: NO replication job linked")
                if worst_status != 'fail': worst_status = 'warn'
                continue
            c2.execute('SELECT last_run, last_status, enabled FROM cross_cluster_replications WHERE id = ?', (jid,))
            r = c2.fetchone()
            if not r:
                details.append(f"vmid {vm['vmid']}: replication {jid[:8]}… not found")
                worst_status = 'fail'; continue
            if not r['enabled']:
                details.append(f"vmid {vm['vmid']}: replication disabled")
                if worst_status != 'fail': worst_status = 'warn'; continue
            if (r['last_status'] or '') == 'error':
                details.append(f"vmid {vm['vmid']}: last replication = error")
                worst_status = 'fail'; continue
            # freshness
            try:
                last = datetime.fromisoformat(r['last_run']) if r['last_run'] else None
            except Exception: last = None
            if not last:
                details.append(f"vmid {vm['vmid']}: never replicated")
                worst_status = 'fail'; continue
            age = (datetime.now() - last).total_seconds()
            rpo = 3600  # MK: default 1h RPO; could become per-VM in the schema later
            if age > rpo * 2:
                details.append(f"vmid {vm['vmid']}: last sync {int(age/60)} min ago (>2× RPO)")
                worst_status = 'fail'
                rpo_breach_seconds = max(rpo_breach_seconds, int(age - rpo))
            elif age > rpo:
                details.append(f"vmid {vm['vmid']}: last sync {int(age/60)} min ago (>RPO)")
                if worst_status != 'fail': worst_status = 'warn'
                rpo_breach_seconds = max(rpo_breach_seconds, int(age - rpo))
            else:
                details.append(f"vmid {vm['vmid']}: last sync {int(age/60)} min ago — fresh")
        msg = 'all replication jobs fresh' if worst_status == 'pass' else \
              ('replication has warnings' if worst_status == 'warn' else 'replication has errors')
        return (worst_status, msg, '\n'.join(details[:30]))
    runner.check('replication', 'freshness_per_vm', _repl)

    # ── boot order sanity ──
    def _boot():
        if not vms:
            return ('warn', 'no VMs to check', '')
        groups = sorted({(v.get('boot_group') or 0) for v in vms})
        if not groups:
            return ('warn', 'no boot groups assigned', '')
        # warn on gaps between sequential groups (e.g. 0,1,5 → suspicious)
        gaps = [groups[i+1] - groups[i] for i in range(len(groups)-1) if groups[i+1] - groups[i] > 1]
        if gaps:
            return ('warn', f'boot groups have gaps: {groups}',
                    'might be intentional, but commonly a typo when groups are 0,1,2,...,N')
        return ('pass', f'boot groups contiguous: {groups}', '')
    runner.check('boot', 'group_ordering', _boot)

    # ── HA policy parity (best-effort) ──
    def _ha():
        if not (src_mgr and getattr(src_mgr, 'is_connected', False)):
            return ('warn', 'source offline — cannot read source HA state', '')
        if not (tgt_mgr and getattr(tgt_mgr, 'is_connected', False)):
            return ('warn', 'target offline — cannot verify target HA capability', '')
        try:
            r = src_mgr._api_get(f"https://{src_mgr.host}:8006/api2/json/cluster/ha/resources")
            data = r.json().get('data') if (r and r.status_code == 200) else []
            ha_vmids = {str(item.get('sid', '')).split(':')[-1] for item in data if item.get('type') == 'vm'}
        except Exception as e:
            return ('warn', f'source HA query failed: {e}', '')
        ha_in_plan = [str(v['vmid']) for v in vms if str(v['vmid']) in ha_vmids]
        if not ha_in_plan:
            return ('pass', 'no HA-managed VMs in plan — nothing to mirror', '')
        # we don't enforce auto-add to target HA; warn so admin notices manually
        return ('warn',
                f'{len(ha_in_plan)} HA-managed VM(s) need manual HA-add on target after failover',
                f'vmids={ha_in_plan[:10]}')
    runner.check('ha', 'parity', _ha)

    # ── compliance metadata ──
    def _meta():
        plan_blob = json.dumps({
            'id': plan['id'], 'name': plan.get('name'),
            'src': plan['source_cluster'], 'tgt': plan['target_cluster'],
            'net': plan.get('network_mappings'), 'stor': plan.get('storage_mappings'),
            'vms': [(v['vmid'], v.get('boot_group')) for v in vms],
        }, sort_keys=True)
        sha = hashlib.sha256(plan_blob.encode('utf-8')).hexdigest()[:16]
        executor = drill.get('started_by') or 'unknown'
        run_at = drill.get('started_at')
        return ('pass',
                f'plan checksum recorded · executor: {executor}',
                f'sha256_prefix={sha}\nrun_at={run_at}')
    runner.check('compliance', 'evidence_hash', _meta)

    # ── finalize drill ──
    finished_at = datetime.now().isoformat()
    if runner.fails:
        status = 'failed'
    elif runner.warns:
        status = 'warned'
    else:
        status = 'passed'
    summary = f"{runner.passes} pass · {runner.warns} warn · {runner.fails} fail"

    # rough RTO estimate: 30s per VM + replication delta — back-of-the-envelope
    estimated_rto = max(30 * len(vms), 120)

    try:
        c.execute('''UPDATE dr_drills SET finished_at=?, status=?, summary=?,
                     pass_count=?, warn_count=?, fail_count=?,
                     rpo_breach_seconds=?, estimated_rto_seconds=?
                     WHERE id=?''',
                  (finished_at, status, summary, runner.passes, runner.warns, runner.fails,
                   rpo_breach_seconds, estimated_rto, drill_id))
        # also bump plan.last_test
        c.execute("UPDATE site_recovery_plans SET last_test = ? WHERE id = ?",
                  (finished_at, plan_id))
        db.conn.commit()
    except Exception:
        logging.exception('[dr-drill] finalize failed')

    try:
        cluster_label = ''
        if tgt_mgr and hasattr(tgt_mgr, 'config'):
            cluster_label = getattr(tgt_mgr.config, 'name', plan['target_cluster'])
        log_audit(drill.get('started_by') or 'system', 'dr.drill_completed',
                  f"plan='{plan.get('name')}' result={status}: {summary}",
                  cluster=cluster_label)
    except Exception:
        pass


# ── Endpoints ────────────────────────────────────────────────────────────

@bp.route('/api/site-recovery/plans/<plan_id>/drill', methods=['POST'])
@require_auth(perms=['site_recovery.failover'])
def start_drill(plan_id):
    db = get_db()
    c = db.conn.cursor()
    c.execute('SELECT * FROM site_recovery_plans WHERE id = ?', (plan_id,))
    plan = c.fetchone()
    if not plan:
        return jsonify({'error': 'plan not found'}), 404
    drill_id = uuid.uuid4().hex[:12]
    user = _current_user()
    try:
        c.execute('''INSERT INTO dr_drills (id, plan_id, plan_name, started_at, status, started_by)
                     VALUES (?, ?, ?, ?, 'running', ?)''',
                  (drill_id, plan_id, plan['name'] or '', datetime.now().isoformat(), user))
        db.conn.commit()
    except Exception:
        logging.exception('drill start failed')
        return jsonify({'error': 'internal error'}), 500

    log_audit(user, 'dr.drill_started', f"plan_id={plan_id} drill_id={drill_id}")

    t = threading.Thread(target=_execute_drill, args=(drill_id,), daemon=True,
                         name=f'dr-drill-{drill_id}')
    t.start()
    return jsonify({'drill_id': drill_id, 'status': 'running'})


@bp.route('/api/dr-drills/<drill_id>', methods=['GET'])
@require_auth(perms=['site_recovery.view'])
def get_drill(drill_id):
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM dr_drills WHERE id = ?', (drill_id,))
        drow = c.fetchone()
        if not drow:
            return jsonify({'error': 'not found'}), 404
        c.execute('SELECT * FROM dr_drill_checks WHERE drill_id = ? ORDER BY sequence ASC', (drill_id,))
        checks = [dict(r) for r in c.fetchall()]
        d = dict(drow)
        d['checks'] = checks
        return jsonify(d)
    except Exception:
        logging.exception('drill fetch failed')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/site-recovery/plans/<plan_id>/drills', methods=['GET'])
@require_auth(perms=['site_recovery.view'])
def list_drills(plan_id):
    try:
        c = get_db().conn.cursor()
        c.execute('''SELECT id, started_at, finished_at, status, summary,
                     pass_count, warn_count, fail_count, started_by,
                     rpo_breach_seconds, estimated_rto_seconds
                     FROM dr_drills WHERE plan_id = ? ORDER BY started_at DESC LIMIT 50''',
                  (plan_id,))
        rows = [dict(r) for r in c.fetchall()]
        return jsonify({'drills': rows})
    except Exception:
        logging.exception('list drills failed')
        return jsonify({'error': 'internal error'}), 500
