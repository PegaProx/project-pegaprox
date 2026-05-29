# site recovery failover orchestrator
# NS Mar 2026 - handles planned, emergency, test failovers and auto-heartbeat

import json
import logging
import time
import uuid
import requests
from datetime import datetime

from pegaprox.core.db import get_db
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import log_audit
from pegaprox.utils.realtime import broadcast_sse

logger = logging.getLogger('pegaprox.site_recovery')

_heartbeat_running = False


def _create_event(plan_id, event_type, triggered_by='system'):
    event_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()
    db = get_db()
    db.execute('''INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at, triggered_by)
        VALUES (?, ?, ?, 'running', ?, ?)''', (event_id, plan_id, event_type, now, triggered_by))
    return event_id


def _complete_event(event_id, status, details=None):
    now = datetime.utcnow().isoformat()
    db = get_db()
    db.execute('UPDATE site_recovery_events SET status = ?, completed_at = ?, details = ? WHERE id = ?',
               (status, now, json.dumps(details or {}), event_id))


def _fire_webhook(url):
    """Call pre/post failover webhook, don't block on failure"""
    if not url:
        return
    try:
        # NS May 2026 — SSRF guard: failover webhooks are admin-set; refuse
        # internal/metadata targets so a misconfig doesn't ping AWS metadata.
        try:
            from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError
            sanitize_outbound_url(url, allowed_schemes=('https', 'http'))
        except SsrfError as guard_err:
            logger.warning(f"[SR] webhook URL rejected: {guard_err}")
            return
        requests.post(url, json={'event': 'site_recovery', 'timestamp': datetime.utcnow().isoformat()}, timeout=30)
    except Exception as e:
        logger.warning(f"[SR] Webhook failed: {url} - {e}")


# NS 2026-04-24 — pre-flight validation. Real-world cause of most "Site Recovery failed
# at 50%" reports: storage/bridge mappings reference names that don't exist on the
# target. Proxmox returns HTTP 500 mid-migration with a useless error. We now check
# before we start.
def validate_mappings(tgt_mgr, storage_map, net_map):
    """Validate that the mapping targets actually exist on the target cluster.
    Returns a list of {severity, msg} entries. Empty list = all good."""
    issues = []
    if not tgt_mgr:
        issues.append({'severity': 'error', 'msg': 'Target cluster manager unavailable'})
        return issues
    if not getattr(tgt_mgr, 'is_connected', False):
        issues.append({'severity': 'error', 'msg': 'Target cluster not connected — cannot validate mappings'})
        return issues

    # pick any online target node to query storage + network from
    node_name = None
    try:
        ns = tgt_mgr.get_node_status() or {}
        for n, info in ns.items():
            if info.get('status') == 'online':
                node_name = n; break
    except Exception as e:
        issues.append({'severity': 'warning', 'msg': f'Could not enumerate target nodes: {e}'})
    if not node_name:
        issues.append({'severity': 'error', 'msg': 'No online node on target cluster to validate mappings against'})
        return issues

    # storage existence check
    try:
        storages = tgt_mgr.get_storage_list(node_name) or []
        stor_names = {s.get('storage') for s in storages if s.get('storage')}
        for src, tgt in (storage_map or {}).items():
            if not tgt:
                issues.append({'severity': 'error', 'msg': f"Storage mapping '{src}' → (empty) — fill in the target storage"})
            elif tgt not in stor_names:
                issues.append({'severity': 'error',
                               'msg': f"Target storage '{tgt}' (mapped from '{src}') does not exist on target cluster"})
    except Exception as e:
        issues.append({'severity': 'warning', 'msg': f'Storage validation failed: {e}'})

    # network existence check
    try:
        nets = tgt_mgr.get_network_list(node_name) or []
        net_names = set()
        for n in nets:
            name = n.get('iface') or n.get('name')
            if name:
                net_names.add(name)
        for src, tgt in (net_map or {}).items():
            if not tgt:
                issues.append({'severity': 'error', 'msg': f"Network mapping '{src}' → (empty) — fill in the target bridge/vnet"})
            elif tgt not in net_names:
                issues.append({'severity': 'error',
                               'msg': f"Target bridge '{tgt}' (mapped from '{src}') does not exist on target cluster"})
    except Exception as e:
        issues.append({'severity': 'warning', 'msg': f'Network validation failed: {e}'})

    return issues


def _broadcast_progress(plan_id, message, progress=None):
    """Push realtime update to frontend"""
    # MK May 2026 (#413) — broadcast_sse signature is (update_type, data, cluster_id=None);
    # the single-dict call was crashing the SR background task with "missing 1 required
    # positional argument: 'data'" the moment a Test/Planned failover hit progress emit.
    broadcast_sse('site_recovery', {'plan_id': plan_id, 'message': message, 'progress': progress})


def _get_plan(plan_id):
    db = get_db()
    row = db.query_one('SELECT * FROM site_recovery_plans WHERE id = ?', (plan_id,))
    if not row:
        return None
    plan = dict(row)
    for k in ('network_mappings', 'storage_mappings'):
        try:
            plan[k] = json.loads(plan[k] or '{}')
        except Exception:
            plan[k] = {}
    return plan


def _get_plan_vms(plan_id):
    db = get_db()
    rows = db.query('SELECT * FROM site_recovery_vms WHERE plan_id = ? ORDER BY boot_group, vmid', (plan_id,))
    return [dict(r) for r in rows] if rows else []


def _group_vms_by_boot(vms):
    """Group VMs by boot_group, returns sorted list of (group_num, [vms])"""
    groups = {}
    for vm in vms:
        g = vm.get('boot_group', 0)
        groups.setdefault(g, []).append(vm)
    return sorted(groups.items())


# MK: the actual migration logic delegates to the existing cross-cluster-migrate infra
def _migrate_vm_cross_cluster(src_mgr, tgt_mgr, vmid, vm_type, storage_map, net_map):
    """Migrate single VM from source to target using existing remote_migrate API.
    Returns (success: bool, error: str)"""
    try:
        # find VM's node on source
        node_status = src_mgr.get_node_status()
        vm_node = None
        if node_status:
            for node_name, ndata in node_status.items():
                vms_on_node = src_mgr.get_vms(node_name) if hasattr(src_mgr, 'get_vms') else []
                for v in vms_on_node:
                    if v.get('vmid') == vmid:
                        vm_node = node_name
                        break
                if vm_node:
                    break

        if not vm_node:
            return False, f"VM {vmid} not found on source cluster"

        # determine target storage — build PVE mapping format "source:target"
        # MK: check if VM's current storage has a mapping, else use first available
        # NS 2026-04-24: the old `except: pass` silently hid get_vm_config failures
        # and dumped VMs onto whichever storage happened to be first in the map.
        # Now we surface the reason + record it in the result so admins can see *why*
        # the fallback kicked in.
        target_storage = ''
        fallback_reason = None
        if storage_map:
            try:
                config = src_mgr.get_vm_config(vm_node, vmid, vm_type)
                if not config:
                    fallback_reason = 'source config empty (API call returned no data)'
                else:
                    # build PVE mapping format: "src_stor:tgt_stor,src_stor2:tgt_stor2"
                    mappings = []
                    for k, v in (config or {}).items():
                        if k.startswith(('scsi', 'virtio', 'ide', 'sata', 'rootfs', 'mp')) and isinstance(v, str) and ':' in v:
                            src_stor = v.split(':')[0]
                            if src_stor and src_stor != 'none' and src_stor in storage_map:
                                mappings.append(f"{src_stor}:{storage_map[src_stor]}")
                    if mappings:
                        target_storage = ','.join(dict.fromkeys(mappings))  # dedupe
                    else:
                        unmapped = sorted({v.split(':')[0] for k, v in (config or {}).items()
                                           if k.startswith(('scsi', 'virtio', 'ide', 'sata', 'rootfs', 'mp'))
                                           and isinstance(v, str) and ':' in v}
                                          - set(storage_map.keys()) - {'none'})
                        fallback_reason = (f"VM uses storage(s) {unmapped} but no mapping exists"
                                           if unmapped else 'no disk entries in VM config')
            except Exception as _e:
                fallback_reason = f'get_vm_config failed: {_e}'
                logger.warning(f"[SR] _migrate_vm_cross_cluster({vmid}): storage-map lookup failed: {_e}")
        if not target_storage:
            if storage_map:
                # deterministic fallback: sort mapping by source-storage name so repeat runs pick same target
                fallback = sorted(storage_map.items())[0][1]
            else:
                fallback = 'local-lvm'
            logger.warning(f"[SR] VM {vmid} falling back to storage '{fallback}'"
                           + (f" ({fallback_reason})" if fallback_reason else ''))
            target_storage = fallback

        target_bridge = 'vmbr0'
        if net_map:
            # PVE remote_migrate uses colon separator (same as target-storage)
            target_bridge = ','.join(f"{s}:{t}" for s, t in net_map.items())

        # create temp token on target for migration auth
        token_result = tgt_mgr.create_api_token('pegaprox-sr')
        if not token_result.get('success'):
            return False, f"Failed to create API token on target: {token_result.get('error', 'unknown')}"

        token_id = token_result['token_id']
        token_value = token_result['token_value']

        # get target fingerprint
        fp_result = tgt_mgr.get_cluster_fingerprint()
        if not fp_result.get('success'):
            tgt_mgr.delete_api_token('pegaprox-sr')
            return False, f"Failed to get target fingerprint: {fp_result.get('error', '')}"

        fingerprint = fp_result['fingerprint']
        target_host = tgt_mgr.host

        # build target endpoint string (Proxmox format)
        target_endpoint = f"apitoken=PVEAPIToken={token_id}={token_value},host={target_host},fingerprint={fingerprint}"

        # execute migration
        result = src_mgr.remote_migrate_vm(
            node=vm_node, vmid=vmid, vm_type=vm_type,
            target_endpoint=target_endpoint,
            target_storage=target_storage,
            target_bridge=target_bridge,
            online=True, delete_source=True
        )

        # cleanup token after a delay (migration is async)
        def _delayed_cleanup():
            time.sleep(3600)  # 1h grace - large disks (1TB+) need time
            try:
                tgt_mgr.delete_api_token('pegaprox-sr')
            except Exception:
                pass

        import gevent
        gevent.spawn(_delayed_cleanup)

        if not result.get('success'):
            return False, result.get('error', 'Migration failed')

        # MK May 2026 (#413 layer 4) — remote_migrate_vm returns success the
        # moment PVE accepts the task UPID, NOT when the underlying qmigrate
        # actually finishes. A failover where the target already has the VMID
        # (e.g. xcrepl pre-replicated it) submits fine then aborts mid-flight
        # with "VM N already exists" — and the old code treated that as a clean
        # planned_complete, which is how @blackshocks ended up with a Failback
        # button on a migration that never actually moved the VM. Poll the
        # UPID's PVE task status before declaring victory.
        task_upid = result.get('task')
        if not task_upid:
            # successful submit without a UPID — extremely unusual but treat as
            # opaque success (don't make this stricter than before for paths
            # we don't fully understand)
            return True, ''
        try:
            from pegaprox.api.vms import _wait_for_task
        except Exception as _imp_err:
            logger.warning(f"[SR] _wait_for_task import failed, falling back to submit-only success: {_imp_err}")
            return True, ''
        ok, detail = _wait_for_task(src_mgr, task_upid, timeout=3600, poll=5)
        if not ok:
            err = f"Migration task aborted on PVE: {detail}"
            # hint for the most common cause we can identify from the detail string
            if detail and 'already exists' in detail.lower():
                err += " (target VMID already in use — likely a replication-pre-seeded VM; consider Emergency Failover instead of Planned)"
            logger.error(f"[SR] {err} (vmid {vmid}, task {task_upid})")
            return False, err
        return True, ''

    except Exception as e:
        logger.error(f"[SR] Migration error for VM {vmid}: {e}")
        return False, str(e)


def _start_replicated_vm(tgt_mgr, vmid, vm_type='qemu'):
    """Start a replicated VM on target (emergency failover).
    The VM should already exist on target from replication.
    Returns (success, error)
    NS Apr 2026: was calling non-existent start_vm() — use vm_action('start')
    Also check cluster/resources directly instead of per-node get_vms (faster + reliable)"""
    try:
        # find target node for the VM via cluster resources (one call vs N)
        try:
            res = tgt_mgr._api_get(
                f"https://{tgt_mgr.host}:{tgt_mgr.api_port}/api2/json/cluster/resources",
                params={'type': 'vm'}
            )
            if res.status_code != 200:
                return False, f"Cannot list target VMs (HTTP {res.status_code})"
            target_node = None
            current_status = None
            for r in res.json().get('data', []):
                if int(r.get('vmid', 0)) == int(vmid):
                    target_node = r.get('node')
                    current_status = r.get('status')
                    break
            if not target_node:
                return False, f"VM {vmid} not found on target cluster (not replicated?)"
        except Exception as e:
            return False, f"Failed to locate target VM: {e}"

        # if already running (e.g. from previous failover), treat as success
        if current_status == 'running':
            return True, ''

        result = tgt_mgr.vm_action(target_node, int(vmid), vm_type, 'start')
        if result.get('success'):
            return True, ''
        return False, result.get('error', 'start failed')
    except Exception as e:
        return False, str(e)


def execute_failover(plan_id, failover_type='planned'):
    """Main failover orchestrator. Runs in greenlet.

    failover_type: 'planned', 'emergency', 'failback'
    """
    plan = _get_plan(plan_id)
    if not plan:
        logger.error(f"[SR] Plan {plan_id} not found")
        return

    event_id = _create_event(plan_id, failover_type)
    vms = _get_plan_vms(plan_id)
    boot_groups = _group_vms_by_boot(vms)
    results = {}
    failed = False

    logger.info(f"[SR] Starting {failover_type} failover for plan '{plan['name']}' ({len(vms)} VMs, {len(boot_groups)} boot groups)")
    _broadcast_progress(plan_id, f"Starting {failover_type} failover...", 0)

    # pre-webhook
    _fire_webhook(plan.get('pre_failover_webhook'))

    # determine source/target based on type
    if failover_type == 'failback':
        # reverse: target becomes source, source becomes target
        src_id = plan['target_cluster']
        tgt_id = plan['source_cluster']
    else:
        src_id = plan['source_cluster']
        tgt_id = plan['target_cluster']

    src_mgr = cluster_managers.get(src_id)
    tgt_mgr = cluster_managers.get(tgt_id)

    net_map = plan.get('network_mappings', {})
    stor_map = plan.get('storage_mappings', {})

    # NS 2026-04-24 — pre-flight: catch bad mappings BEFORE we start moving VMs.
    # A typo like `local-lvm` → `local-lvmm` used to fail silently mid-migration
    # with a Proxmox 500; now we fail fast with a clear message.
    preflight_issues = validate_mappings(tgt_mgr, stor_map, net_map) if failover_type != 'emergency' else []
    preflight_errors = [i for i in preflight_issues if i.get('severity') == 'error']
    if preflight_errors:
        msg = '; '.join(i['msg'] for i in preflight_errors[:3])
        logger.error(f"[SR] Pre-flight failed for plan '{plan['name']}': {msg}")
        _broadcast_progress(plan_id, f"Pre-flight failed: {msg}", 100)
        _complete_event(event_id, 'failed', {'preflight_issues': preflight_issues, 'aborted': 'before any VM moved'})
        db = get_db()
        db.execute("UPDATE site_recovery_plans SET status = 'failed', updated_at = ? WHERE id = ?",
                   (datetime.utcnow().isoformat(), plan_id))
        return

    total_vms = len(vms)
    completed = 0

    for group_idx, (group_num, group_vms) in enumerate(boot_groups):
        logger.info(f"[SR] Boot group {group_num} ({len(group_vms)} VMs)")
        _broadcast_progress(plan_id, f"Boot group {group_num}...", int(completed / total_vms * 100))

        for vm in group_vms:
            vmid = vm['vmid']
            vm_type = vm.get('vm_type', 'qemu')
            vm_name = vm.get('vm_name', f'VM {vmid}')

            if failover_type == 'emergency':
                # source is down - start replicated VM on target
                logger.info(f"[SR] Emergency: starting {vm_name} ({vmid}) on target")
                _broadcast_progress(plan_id, f"Starting {vm_name} on target...", int(completed / total_vms * 100))
                ok, err = _start_replicated_vm(tgt_mgr, vmid, vm_type)
            else:
                # planned or failback - live migrate
                if not src_mgr or not src_mgr.is_connected:
                    ok, err = False, "Source cluster not connected"
                else:
                    logger.info(f"[SR] Migrating {vm_name} ({vmid}): {src_id} → {tgt_id}")
                    _broadcast_progress(plan_id, f"Migrating {vm_name}...", int(completed / total_vms * 100))
                    ok, err = _migrate_vm_cross_cluster(src_mgr, tgt_mgr, vmid, vm_type, stor_map, net_map)

            results[str(vmid)] = {'success': ok, 'error': err, 'vm_name': vm_name}
            if not ok:
                logger.error(f"[SR] Failed for {vm_name}: {err}")
                failed = True
            else:
                logger.info(f"[SR] {vm_name} OK")

            completed += 1

        # wait boot_delay before next group (use first VM's delay in group)
        if group_idx < len(boot_groups) - 1:
            delay = group_vms[0].get('boot_delay', 30)
            if delay > 0:
                logger.info(f"[SR] waiting {delay}s before next boot group")
                _broadcast_progress(plan_id, f"Waiting {delay}s before next group...", int(completed / total_vms * 100))
                time.sleep(delay)

    # done
    final_status = 'failed' if failed else 'completed'
    _complete_event(event_id, final_status, results)

    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute("UPDATE site_recovery_plans SET status = ?, last_failover = ?, updated_at = ? WHERE id = ?",
               (final_status, now, now, plan_id))

    _fire_webhook(plan.get('post_failover_webhook'))
    _broadcast_progress(plan_id, f"Failover {final_status}", 100)

    log_audit('system', f'site_recovery.{failover_type}_complete',
              f"Plan '{plan['name']}' {failover_type} {final_status}: {completed}/{total_vms} VMs")

    logger.info(f"[SR] Failover {final_status} for '{plan['name']}': {sum(1 for r in results.values() if r['success'])}/{total_vms} succeeded")


def execute_test_failover(plan_id):
    """Clone replicated VMs on target, start in test mode.
    VMs stay running until user triggers cleanup."""
    plan = _get_plan(plan_id)
    if not plan:
        return

    event_id = _create_event(plan_id, 'test')
    vms = _get_plan_vms(plan_id)
    tgt_mgr = cluster_managers.get(plan['target_cluster'])
    results = {}
    test_vmids = []

    logger.info(f"[SR] Test failover for '{plan['name']}' ({len(vms)} VMs)")
    _broadcast_progress(plan_id, "Starting test failover...", 0)

    # MK May 2026 (#413) — guard against tgt_mgr=None so the loop body
    # surfaces a useful error instead of an AttributeError under `except Exception`.
    if tgt_mgr is None:
        for vm in vms:
            results[str(vm['vmid'])] = {'success': False,
                                        'error': f"Target cluster '{plan['target_cluster']}' not connected / not configured in PegaProx"}
        logger.error(f"[SR] Test failover: target cluster '{plan['target_cluster']}' unreachable; aborting plan '{plan['name']}'")

    for i, vm in enumerate(vms):
        if tgt_mgr is None:
            break
        vmid = vm['vmid']
        vm_name = vm.get('vm_name', f'VM {vmid}')
        # MK May 2026 (#413) — site_recovery_vms has a `target_vmid` column for
        # asymmetric VMID mappings (xcrepl that renumbers, manual restore to a
        # new ID, etc). Prefer it when the operator filled it in; fall back to
        # the source vmid which is the common case (PVE qmigrate preserves the
        # ID). Either way, log which one we're looking for so the next debug
        # bundle tells us exactly why a detection failed.
        target_vmid = vm.get('target_vmid') or vmid
        _broadcast_progress(plan_id, f"Cloning {vm_name}...", int(i / len(vms) * 100))

        try:
            # find the replicated VM on target and clone it
            node_status = tgt_mgr.get_node_status() or {}
            logger.info(f"[SR] Test failover: searching for VM {target_vmid} (source vmid={vmid}) on "
                        f"target cluster {plan['target_cluster']} across nodes {list(node_status.keys())}")
            found = False
            for node_name in node_status:
                try:
                    tgt_vms = tgt_mgr.get_vms(node_name) if hasattr(tgt_mgr, 'get_vms') else []
                    all_vmids = [v.get('vmid') for v in tgt_vms]
                    logger.info(f"[SR] Test failover: node {node_name} has {len(tgt_vms)} VMs: {all_vmids}")
                    for v in tgt_vms:
                        if v.get('vmid') == target_vmid:
                            # find free VMID for test clone — base off the target vmid we found
                            test_vmid = target_vmid + 90000
                            while test_vmid in all_vmids:
                                test_vmid += 1
                            vtype = vm.get('vm_type', 'qemu')
                            clone_result = tgt_mgr.clone_vm(node_name, target_vmid, vtype,
                                                            newid=test_vmid, name=f"SR-TEST-{vm_name}")
                            # clone_vm returns dict {success, error, task?} OR truthy legacy value
                            clone_ok = clone_result.get('success') if isinstance(clone_result, dict) else bool(clone_result)
                            if clone_ok:
                                test_vmids.append({'vmid': test_vmid, 'vm_type': vtype})
                                # NS Apr 2026: was start_vm() which doesn't exist — use vm_action
                                start_res = tgt_mgr.vm_action(node_name, test_vmid, vtype, 'start')
                                if start_res.get('success'):
                                    results[str(vmid)] = {'success': True, 'test_vmid': test_vmid}
                                else:
                                    results[str(vmid)] = {'success': False, 'test_vmid': test_vmid,
                                                          'error': f"cloned OK but start failed: {start_res.get('error', 'unknown')}"}
                            else:
                                err = clone_result.get('error', 'Clone failed') if isinstance(clone_result, dict) else 'Clone failed'
                                results[str(vmid)] = {'success': False, 'error': err}
                            found = True
                            break
                except Exception as e:
                    logger.warning(f"[SR] Test failover: exception probing node {node_name} for VM {target_vmid}: {e}")
                    continue
                if found:
                    break
            if not found:
                results[str(vmid)] = {'success': False,
                                      'error': f"VM not found on target (looked for vmid {target_vmid} on nodes {list(node_status.keys())})"}
                logger.warning(f"[SR] Test failover: VM {target_vmid} not found on target {plan['target_cluster']}")
        except Exception as e:
            results[str(vmid)] = {'success': False, 'error': str(e)}

    # NS 2026-04-24 — track ok/failed/total so "6 out of 10 VMs cloned" is visible
    # to admins. Old code marked the whole test as "completed" if even one VM worked.
    ok_count = sum(1 for r in results.values() if r.get('success'))
    failed_count = sum(1 for r in results.values() if not r.get('success'))
    total = len(results)
    if total == 0:
        event_status = 'failed'
    elif failed_count == 0:
        event_status = 'completed'
    elif ok_count == 0:
        event_status = 'failed'
    else:
        event_status = 'partial'

    summary = {
        'results': results,
        'test_vmids': test_vmids,
        'counts': {'ok': ok_count, 'failed': failed_count, 'total': total},
    }
    _complete_event(event_id, event_status, summary)

    db = get_db()
    now = datetime.utcnow().isoformat()
    if event_status == 'failed':
        db.execute("UPDATE site_recovery_plans SET status = 'failed', last_test = ?, updated_at = ? WHERE id = ?", (now, now, plan_id))
        _broadcast_progress(plan_id, f"Test failover failed — 0/{total} VMs cloned.", 100)
    else:
        db.execute("UPDATE site_recovery_plans SET last_test = ?, updated_at = ? WHERE id = ?", (now, now, plan_id))
        # keep status as 'testing' until cleanup
        if event_status == 'partial':
            _broadcast_progress(plan_id, f"Test partial: {ok_count}/{total} cloned, {failed_count} failed. Review events + cleanup.", 100)
        else:
            _broadcast_progress(plan_id, f"Test failover complete: {ok_count}/{total} cloned. Cleanup when ready.", 100)

    ok = sum(1 for r in results.values() if r.get('success'))
    log_audit('system', 'site_recovery.test_complete',
              f"Test failover for '{plan['name']}': {ok}/{len(vms)} VMs cloned")
    logger.info(f"[SR] Test failover complete for '{plan['name']}': {len(test_vmids)} clones created")


def cleanup_test(plan_id):
    """Stop and delete test clone VMs"""
    plan = _get_plan(plan_id)
    if not plan:
        return

    tgt_mgr = cluster_managers.get(plan['target_cluster'])
    if not tgt_mgr:
        return

    # find last test event with test_vmids
    db = get_db()
    event = db.query_one(
        "SELECT details FROM site_recovery_events WHERE plan_id = ? AND event_type = 'test' ORDER BY started_at DESC LIMIT 1",
        (plan_id,))
    if not event:
        return

    try:
        details = json.loads(event['details'] or '{}')
    except Exception:
        details = {}

    test_vmids = details.get('test_vmids', [])

    for entry in test_vmids:
        # LW: entry can be dict {vmid, vm_type} or int (legacy)
        if isinstance(entry, dict):
            test_vmid = entry.get('vmid', 0)
            vtype = entry.get('vm_type', 'qemu')
        else:
            test_vmid = entry
            vtype = 'qemu'
        try:
            # NS Apr 2026: locate test VM via cluster resources (was iterating all nodes)
            try:
                res = tgt_mgr._api_get(
                    f"https://{tgt_mgr.host}:{tgt_mgr.api_port}/api2/json/cluster/resources",
                    params={'type': 'vm'}
                )
                target_node = None
                current_status = None
                if res.status_code == 200:
                    for r in res.json().get('data', []):
                        if int(r.get('vmid', 0)) == int(test_vmid):
                            target_node = r.get('node')
                            current_status = r.get('status')
                            break
            except Exception:
                target_node = None
                current_status = None

            if target_node:
                try:
                    # NS: was stop_vm/delete_vm — use vm_action; ignore "already stopped" errors
                    if current_status == 'running':
                        tgt_mgr.vm_action(target_node, test_vmid, vtype, 'stop', force=True)
                        time.sleep(3)
                    tgt_mgr.delete_vm(target_node, test_vmid, vtype, purge=True)
                    logger.info(f"[SR] Cleaned up test VM {test_vmid}")
                    continue  # go to next test_vmid entry
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"[SR] Cleanup failed for test VM {test_vmid}: {e}")

    db.execute("UPDATE site_recovery_plans SET status = 'ready', updated_at = ? WHERE id = ?",
               (datetime.utcnow().isoformat(), plan_id))

    log_audit('system', 'site_recovery.test_cleanup_complete',
              f"Cleaned up {len(test_vmids)} test VMs for plan '{plan['name']}'")
    _broadcast_progress(plan_id, "Test cleanup complete", 100)


# ---- Auto-Failover Heartbeat ----

_last_fail_times = {}  # plan_id -> first_fail_timestamp
_cooldowns = {}  # plan_id -> cooldown_until_timestamp


def _heartbeat_check():
    """Check all plans with auto_failover enabled.
    If source cluster unreachable for failover_timeout seconds, trigger emergency failover."""
    db = get_db()
    plans = db.query("SELECT * FROM site_recovery_plans WHERE auto_failover = 1 AND status = 'ready'")
    if not plans:
        return

    now = time.time()

    for row in plans:
        plan = dict(row)
        plan_id = plan['id']

        # respect cooldown
        if plan_id in _cooldowns and now < _cooldowns[plan_id]:
            continue

        src_mgr = cluster_managers.get(plan['source_cluster'])
        src_reachable = src_mgr and src_mgr.is_connected if src_mgr else False

        if src_reachable:
            # clear failure tracking
            _last_fail_times.pop(plan_id, None)
            continue

        # source unreachable
        if plan_id not in _last_fail_times:
            _last_fail_times[plan_id] = now
            logger.warning(f"[SR] Heartbeat: source '{plan['source_cluster']}' unreachable for plan '{plan['name']}'")
            continue

        elapsed = now - _last_fail_times[plan_id]
        timeout = plan.get('failover_timeout', 120)

        if elapsed >= timeout:
            # NS Apr 2026: before auto-failover, verify every VM in plan has a healthy recent
            # replication. Otherwise we'd start VMs that were never copied, or worse, stale copies.
            vms = db.query("SELECT * FROM site_recovery_vms WHERE plan_id = ?", (plan_id,))
            blockers = []
            for vm_row in vms:
                vm = dict(vm_row)
                repl_id = (vm.get('replication_job_id') or '').strip()
                if not repl_id:
                    blockers.append(f"VM {vm['vmid']} has no replication job linked")
                    continue
                repl = db.query_one(
                    "SELECT enabled, last_status, last_run FROM cross_cluster_replications WHERE id = ?",
                    (repl_id,)
                )
                if not repl:
                    blockers.append(f"VM {vm['vmid']}: replication job {repl_id} not found")
                elif not repl['enabled']:
                    blockers.append(f"VM {vm['vmid']}: replication disabled")
                elif repl['last_status'] != 'ok':
                    blockers.append(f"VM {vm['vmid']}: last replication status={repl['last_status'] or 'never ran'}")

            if blockers:
                logger.error(f"[SR] BLOCKING auto-failover for '{plan['name']}' — replication unhealthy: {'; '.join(blockers[:5])}")
                log_audit('system', 'site_recovery.auto_failover_blocked',
                          f"Auto-failover BLOCKED for '{plan['name']}': {'; '.join(blockers[:5])}")
                _last_fail_times.pop(plan_id, None)
                _cooldowns[plan_id] = now + 600  # shorter cooldown — admin may fix replication
                continue

            logger.error(f"[SR] AUTO-FAILOVER triggered for '{plan['name']}' after {int(elapsed)}s")
            _last_fail_times.pop(plan_id, None)
            _cooldowns[plan_id] = now + 3600  # 1h cooldown

            # trigger emergency failover — atomic status transition via WHERE status='ready'
            try:
                import gevent
                now_iso = datetime.utcnow().isoformat()
                # UPDATE .. WHERE status='ready' means we only proceed if noone else flipped it first
                cur = db.conn.cursor()
                cur.execute(
                    "UPDATE site_recovery_plans SET status = 'running', updated_at = ? WHERE id = ? AND status = 'ready'",
                    (now_iso, plan_id)
                )
                db.conn.commit()
                if cur.rowcount != 1:
                    logger.info(f"[SR] Auto-failover for '{plan['name']}' skipped — status changed concurrently")
                    continue
                # NS: use crash-safe wrapper so a greenlet crash sets status to 'failed'
                from pegaprox.api.site_recovery import _safe_spawn_failover
                _safe_spawn_failover(execute_failover, plan_id, 'emergency')
                log_audit('system', 'site_recovery.auto_failover',
                          f"Auto-failover triggered for '{plan['name']}' - source unreachable for {int(elapsed)}s")
            except Exception as e:
                logger.error(f"[SR] Auto-failover spawn failed: {e}")


def heartbeat_loop():
    """Background loop for auto-failover heartbeat monitoring"""
    global _heartbeat_running
    _heartbeat_running = True
    logger.info("[SR] Heartbeat monitor started")

    while _heartbeat_running:
        try:
            _heartbeat_check()
        except Exception as e:
            logger.error(f"[SR] Heartbeat error: {e}")
        time.sleep(30)


def recover_orphan_runs():
    """One-shot cleanup of in-flight rows left over from a previous PegaProx
    process. Without this, `site_recovery_events` rows that were `status=running`
    when the service crashed/restarted stay that way forever — and the matching
    `site_recovery_plans.status` keeps showing 'running' / 'testing' in the UI,
    which is what @blackshocks hit on #413 ("tasks still visible after reboot").

    Run once at app startup, just before the heartbeat loop spawns. Best-effort
    — if the DB isn't ready yet we log and move on; the heartbeat will reconcile
    on its next pass.

    MK May 2026 (#413).
    """
    try:
        db = get_db()
    except Exception as e:
        logger.warning(f"[SR] orphan-cleanup: DB not ready ({e}); skipping")
        return

    now = datetime.utcnow().isoformat()
    aborted_events = 0
    reset_plans = 0
    try:
        # Events that were mid-run when the previous process died. completed_at
        # is the actual "did this finish?" signal — status alone is insufficient
        # because completed rows can be 'failed' too.
        ev_rows = db.query(
            "SELECT id, plan_id, event_type FROM site_recovery_events "
            "WHERE status = 'running' AND (completed_at IS NULL OR completed_at = '')"
        ) or []
        for row in ev_rows:
            details = json.dumps({
                'reason': 'pegaprox_restart',
                'note': 'event was in flight when the service restarted; auto-aborted at boot',
            })
            db.execute(
                "UPDATE site_recovery_events SET status = 'aborted', "
                "completed_at = ?, details = ? WHERE id = ?",
                (now, details, row['id']),
            )
            aborted_events += 1

        # Plans whose status is mid-state. If the heartbeat or operator wants
        # to run it again, the state machine needs them back in 'failed' (which
        # then transitions to 'ready' on a manual reset).
        plan_rows = db.query(
            "SELECT id, name, status FROM site_recovery_plans "
            "WHERE status IN ('running', 'testing')"
        ) or []
        for row in plan_rows:
            db.execute(
                "UPDATE site_recovery_plans SET status = 'failed', updated_at = ? WHERE id = ?",
                (now, row['id']),
            )
            reset_plans += 1
    except Exception as e:
        logger.error(f"[SR] orphan-cleanup query failed: {e}")
        return

    if aborted_events or reset_plans:
        logger.warning(
            f"[SR] orphan-cleanup at boot: aborted {aborted_events} stuck event(s), "
            f"reset {reset_plans} plan(s) from running/testing → failed"
        )
        # Audit-log so an admin reading the audit feed sees what got rolled back.
        try:
            log_audit(
                user='system',
                action='site_recovery.boot_cleanup',
                details=f"aborted={aborted_events} events, reset={reset_plans} plans",
                ip_address='127.0.0.1',
            )
        except Exception as e:
            logger.debug(f"[SR] orphan-cleanup audit-log failed (non-fatal): {e}")
    else:
        logger.info("[SR] orphan-cleanup at boot: nothing to do")


def start_heartbeat():
    import gevent
    # MK May 2026 (#413): clean up any in-flight rows from the previous process
    # before the heartbeat starts so the UI doesn't keep showing aborted runs
    # as active.
    try:
        recover_orphan_runs()
    except Exception as e:
        logger.error(f"[SR] orphan-cleanup wrapper crashed: {e}")
    gevent.spawn(heartbeat_loop)


def stop_heartbeat():
    global _heartbeat_running
    _heartbeat_running = False
