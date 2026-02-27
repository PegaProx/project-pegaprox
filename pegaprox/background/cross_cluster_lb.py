# -*- coding: utf-8 -*-
"""
PegaProx Cross-Cluster Load Balancer - Layer 7
Background thread that balances VM load across clusters within a group.

NS: Feb 2026 - extends the per-cluster LB to work across cluster boundaries.
Uses the same scoring approach (CPU + RAM weighted) but at cluster level instead
of node level. When enabled on a cluster group, it periodically checks if any
cluster in the group is significantly more loaded than others, and migrates
VMs using the existing cross-cluster migration infrastructure.
"""

import time
import logging
import threading
from datetime import datetime

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit

logger = logging.getLogger('pegaprox.xclb')

_xclb_thread = None
_xclb_running = False


def compute_cluster_score(manager):
    """Average node score across active nodes. Same formula as per-node, just averaged."""
    try:
        node_status = manager.get_node_status()
        if not node_status:
            return None
        config_excluded = getattr(manager.config, 'excluded_nodes', []) or []
        scores = [
            data['score'] for node, data in node_status.items()
            if data.get('status') == 'online'
            and not data.get('maintenance_mode', False)
            and node not in config_excluded
        ]
        return sum(scores) / len(scores) if scores else None
    except Exception as e:
        logger.warning(f"Could not compute score for {manager.id}: {e}")
        return None


def _pick_node(manager, highest=True):
    """Find most or least loaded node on a cluster. NS: DRY helper."""
    try:
        node_status = manager.get_node_status()
        if not node_status:
            return None
        config_excluded = getattr(manager.config, 'excluded_nodes', []) or []
        best, best_score = None, (-1 if highest else float('inf'))
        for node, data in node_status.items():
            if (data.get('status') != 'online'
                    or data.get('maintenance_mode', False)
                    or node in config_excluded):
                continue
            s = data.get('score', 0)
            if (highest and s > best_score) or (not highest and s < best_score):
                best, best_score = node, s
        return best
    except Exception:
        return None


def _token_cleanup_thread(target_mgr, source_mgr, token_name, task_upid, vmid, vm_type):
    """Monitor migration task, then delete temp token.
    MK: Same approach as vms.py cross-cluster migration cleanup.
    """
    max_wait, poll_interval = 7200, 15
    min_wait = 120  # NS: 2 min for automated LB (shorter than manual's 5 min)
    elapsed = 0
    logger.info(f"[XCLB-CLEANUP] Monitoring {task_upid} for {vm_type}/{vmid}...")

    while elapsed < max_wait:
        try:
            tasks = source_mgr.get_tasks(limit=100)
            found = False
            for t in tasks:
                if t and t.get('upid') == task_upid:
                    found = True
                    status = t.get('status', '')
                    if status and status != 'running':
                        level = 'info' if status == 'OK' else 'warning'
                        getattr(logger, level)(f"[XCLB-CLEANUP] {vmid} ended: {status}")
                        time.sleep(30)
                        target_mgr.delete_api_token(token_name)
                        return
                    break
            # task scrolled out of list after min_wait -> assume done
            if not found and elapsed > min_wait:
                logger.info(f"[XCLB-CLEANUP] Task gone after {elapsed}s, assuming done")
                target_mgr.delete_api_token(token_name)
                return
        except Exception as e:
            logger.warning(f"[XCLB-CLEANUP] Poll error: {e}")
        time.sleep(poll_interval)
        elapsed += poll_interval

    logger.warning(f"[XCLB-CLEANUP] Timeout after {max_wait}s, deleting token anyway")
    try:
        target_mgr.delete_api_token(token_name)
    except Exception:
        pass


def run_cross_cluster_balance_check(group):
    """Core logic: compare cluster scores within a group, migrate if needed.
    NS: Intentionally conservative - one VM per cycle, dry_run default on.
    """
    group_id = group['id']
    group_name = group.get('name', group_id)
    threshold = group.get('cross_cluster_threshold', 30)
    dry_run = bool(group.get('cross_cluster_dry_run', 1))
    target_storage = group.get('cross_cluster_target_storage', '') or 'local-lvm'
    target_bridge = group.get('cross_cluster_target_bridge', 'vmbr0') or 'vmbr0'
    include_containers = bool(group.get('cross_cluster_include_containers', 0))
    db = get_db()

    # 1. get clusters belonging to this group
    rows = db.query('SELECT id FROM clusters WHERE group_id = ?', (group_id,))
    if not rows or len(rows) < 2:
        return  # need at least 2 clusters

    # 2. compute scores for each cluster
    scored = []
    for r in rows:
        mgr = cluster_managers.get(r['id'])
        if not mgr:
            continue
        score = compute_cluster_score(mgr)
        if score is not None:
            scored.append((r['id'], mgr, score))
    if len(scored) < 2:
        return

    # 3. sort and compare
    scored.sort(key=lambda x: x[2])
    lo_cid, lo_mgr, lo_score = scored[0]
    hi_cid, hi_mgr, hi_score = scored[-1]
    diff = hi_score - lo_score

    logger.info(
        f"[XCLB] Group '{group_name}': hi={hi_cid} ({hi_score:.1f}), "
        f"lo={lo_cid} ({lo_score:.1f}), diff={diff:.1f}, thr={threshold}"
    )
    if diff <= threshold:
        return

    # 4. dry run check
    if dry_run:
        logger.info(f"[XCLB] Dry run - would migrate VM from {hi_cid} to {lo_cid}")
        log_audit('system', 'xclb.dry_run',
                  f"Cross-cluster LB dry run: group '{group_name}' imbalance "
                  f"{diff:.1f} > {threshold} ({hi_cid} -> {lo_cid})")
        return

    # 5. find source/target nodes
    source_node = _pick_node(hi_mgr, highest=True)
    target_node = _pick_node(lo_mgr, highest=False)
    if not source_node or not target_node:
        logger.warning("[XCLB] Could not determine source/target nodes")
        return

    # 6. find migration candidate on source
    vm = hi_mgr.find_migration_candidate(source_node, source_node, include_containers=include_containers)
    if not vm:
        logger.info(f"[XCLB] No migration candidate on {hi_cid}/{source_node}")
        return

    vmid = vm.get('vmid')
    vm_name = vm.get('name', 'unnamed')
    vm_type = vm.get('type', 'qemu')

    # 7. create temp API token on target cluster
    token_name = f"xclb-{group_id[:8]}-{vmid}"
    token = lo_mgr.create_api_token(token_name)
    if not token.get('success'):
        logger.error(f"[XCLB] Token creation failed on {lo_cid}: {token.get('error')}")
        return

    try:
        # 8. get fingerprint + build endpoint
        fp = lo_mgr.get_cluster_fingerprint()
        if not fp.get('success'):
            logger.error(f"[XCLB] Fingerprint failed for {lo_cid}: {fp.get('error')}")
            lo_mgr.delete_api_token(token_name)
            return

        # LW: same endpoint format as manual cross-cluster migration
        endpoint = (
            f"apitoken=PVEAPIToken={token['token_id']}={token['token_value']},"
            f"host={fp['host']},fingerprint={fp['fingerprint']}"
        )

        logger.info(f"[XCLB] Migrating {vm_type}/{vmid} ({vm_name}): "
                     f"{hi_cid}/{source_node} -> {lo_cid}/{target_node}")

        # 9. kick off the migration
        result = hi_mgr.remote_migrate_vm(
            node=source_node, vmid=vmid, vm_type=vm_type,
            target_endpoint=endpoint, target_storage=target_storage,
            target_bridge=target_bridge, online=True, delete_source=True,
        )

        if result.get('success'):
            task_upid = result.get('task')
            log_audit('system', 'xclb.migrate',
                      f"Cross-cluster LB: Migrated {vm_type}/{vmid} ({vm_name}) "
                      f"from {hi_cid} to {lo_cid} (group:{group_id})")
            # spawn token cleanup thread
            threading.Thread(
                target=_token_cleanup_thread,
                args=(lo_mgr, hi_mgr, token_name, task_upid, vmid, vm_type),
                daemon=True
            ).start()
        else:
            logger.error(f"[XCLB] Migration failed: {result.get('error')}")
            lo_mgr.delete_api_token(token_name)

    except Exception as e:
        logger.error(f"[XCLB] Error during migration: {e}")
        try:
            lo_mgr.delete_api_token(token_name)
        except Exception:
            pass

    # 10. update last run timestamp
    try:
        db.execute('UPDATE cluster_groups SET cross_cluster_last_run = ? WHERE id = ?',
                   (datetime.now().isoformat(), group_id))
    except Exception as e:
        logger.warning(f"[XCLB] Could not update last_run for {group_id}: {e}")


def cross_cluster_lb_loop():
    """Background loop - checks all enabled groups on a 30s tick."""
    global _xclb_running
    _xclb_running = True
    last_run_times = {}  # per-group tracking, survives across ticks

    while _xclb_running:
        try:
            db = get_db()
            groups = db.query(
                'SELECT * FROM cluster_groups WHERE cross_cluster_lb_enabled = 1'
            )
            if groups:
                now = time.time()
                for row in groups:
                    group = dict(row)
                    gid = group['id']
                    interval = group.get('cross_cluster_interval', 600)
                    if now - last_run_times.get(gid, 0) >= interval:
                        last_run_times[gid] = now
                        try:
                            run_cross_cluster_balance_check(group)
                        except Exception as e:
                            logger.error(f"[XCLB] Error checking group {gid}: {e}")
        except Exception as e:
            logger.error(f"[XCLB] Loop error: {e}")
        time.sleep(30)


def start_cross_cluster_lb_thread():
    global _xclb_thread
    if _xclb_thread is None or not _xclb_thread.is_alive():
        _xclb_thread = threading.Thread(target=cross_cluster_lb_loop, daemon=True)
        _xclb_thread.start()
        logging.info("Cross-cluster load balancer thread started")


def stop_cross_cluster_lb_thread():
    global _xclb_running
    _xclb_running = False
