# -*- coding: utf-8 -*-
"""
PegaProx Broadcast Thread - Layer 7
SSE/WebSocket resource broadcast loop.
"""

import time
import json
import logging
import threading
from datetime import datetime

from pegaprox.globals import (
    cluster_managers, _broadcast_thread,
    sse_clients, sse_tokens, sse_tokens_lock,
    vmware_managers,
)
from pegaprox.utils.realtime import broadcast_sse

# NS: map portal audit actions to task-like type strings
_AUDIT_ACTION_MAP = {
    'portal.vm.start': 'portalstart',
    'portal.vm.stop': 'portalstop',
    'portal.vm.shutdown': 'portalshutdown',
    'portal.vm.reboot': 'portalreboot',
    'portal.snapshot_created': 'portalsnapshot',
    'portal.snapshot_rollback': 'portalrollback',
    'portal.snapshot_deleted': 'portalsnapshotdel',
    'portal.password_changed': 'portalpassword',
}

def _get_recent_audit_tasks(cluster_id, cluster_name):
    """Convert recent audit log entries into task-like objects for the task bar"""
    try:
        from pegaprox.core.db import get_db
        db = get_db()
        cursor = db.conn.cursor()
        # only last 2 minutes of portal + console events
        cutoff = (datetime.now() - __import__('datetime').timedelta(minutes=2)).isoformat()
        cursor.execute('''
            SELECT id, timestamp, user, action, details FROM audit_log
            WHERE action LIKE 'portal.%'
            AND timestamp > ?
            ORDER BY timestamp DESC LIMIT 10
        ''', (cutoff,))
        rows = cursor.fetchall()
        if not rows:
            return []
        results = []
        for row in rows:
            aid, ts, user, action, details = row
            task_type = _AUDIT_ACTION_MAP.get(action, action)
            # extract vmid from details if present
            vmid = ''
            import re
            m = re.search(r'VM (\d+)', details or '')
            if m:
                vmid = m.group(1)
            results.append({
                'upid': f'audit-{aid}',
                'node': '',
                'type': task_type,
                'status': 'stopped',  # completed
                'starttime': int(datetime.fromisoformat(ts).timestamp()) if ts else 0,
                'endtime': int(datetime.fromisoformat(ts).timestamp()) if ts else 0,
                'user': '',
                'pegaprox_user': user,
                'id': vmid,
                'vmid': int(vmid) if vmid else 0,
                'exitstatus': 'OK',
                'cluster_id': cluster_id,
                '_portal': True,  # marker so frontend can style differently
            })
        return results
    except Exception:
        return []

def broadcast_resources_loop():
    """Periodically broadcast resource updates to all connected SSE clients
    
    MK: Increased frequency for more responsive UI, was 5s initially (v0.3.x)
    NS: Further optimized Jan 2026 - resources now every 2s instead of 4s
    NS: Feb 2026 - Fixed: process clusters in parallel to prevent one slow
        cluster from blocking updates to all others (Oulu-Kunde hat sich beschwert)
    """
    print("=" * 50)
    print("SSE BROADCAST LOOP STARTED")
    print("=" * 50)
    logging.info("SSE broadcast loop started")
    
    loop_count = 0
    while True:
        try:
            client_count = len(sse_clients)
            if not sse_clients:
                time.sleep(2)
                continue
            
            loop_count += 1
            
            if loop_count % 10 == 1:  # Log every 10th loop
                logging.debug(f"[SSE] Broadcasting to {client_count} clients (loop {loop_count})")
            
            # NS: Feb 2026 - Periodic ticket refresh (Proxmox tickets expire after 2h)
            # Re-authenticate every 90 minutes to prevent stale tickets
            if loop_count % 5400 == 0:  # 5400 loops × 1s = 90 minutes
                for cid, mgr in list(cluster_managers.items()):
                    if mgr.is_connected and not getattr(mgr, '_using_api_token', False):
                        try:
                            logging.info(f"[SSE] Refreshing Proxmox ticket for cluster '{cid}'")
                            mgr.connect_to_proxmox()
                        except Exception as e:
                            logging.warning(f"[SSE] Ticket refresh failed for '{cid}': {e}")

            # NS Apr 2026 — VMware keepalive. Customers reported PegaProx losing
            # the ESXi connection over time; ESXi defaults to a 30-min idle session
            # timeout. Run ensure_connected() (which now includes a cheap session
            # ping) every ~4 min on a worker thread so a slow vCenter can't stall
            # the broadcast loop.
            if vmware_managers and loop_count % 240 == 0:
                def _vmware_keepalive_tick():
                    for vmw_id, vmw_mgr in list(vmware_managers.items()):
                        try:
                            ok = vmw_mgr.ensure_connected()
                            if not ok:
                                logging.debug(f"[VMware:{vmw_id}] keepalive: not connected")
                        except Exception as e:
                            logging.debug(f"[VMware:{vmw_id}] keepalive error: {e}")
                threading.Thread(target=_vmware_keepalive_tick, daemon=True).start()
            
            def broadcast_for_cluster(cid, mgr):
                """Broadcast updates for a single cluster - runs in own thread"""
                try:
                    # NS May 2026 — when a cluster's API calls have been timing out,
                    # back off so we don't spawn 1 thread per second waiting on the
                    # same dead TCP connection. Cooldown is per-mgr.
                    now = time.time()
                    cooldown_until = getattr(mgr, '_sse_cooldown_until', 0)
                    if now < cooldown_until:
                        # still in cooldown — don't poke, but tell client we're alive
                        broadcast_sse('tasks', [], cid)
                        return
                    # NS: Feb 2026 - AUTO-RECONNECT disconnected clusters
                    # Without this, a network reload (ifreload) permanently kills the connection
                    # until PegaProx is restarted. Now we retry every 10 seconds.
                    # MK 2026-05-31 — log backoff. Previously the "is disconnected,
                    # attempting reconnect..." INFO line fired every 10s while a
                    # cluster stayed down → ~360 INFO entries per hour per dead
                    # cluster filling up the log file. Now: INFO on the first
                    # attempt + once every 50 attempts (~8min) for ongoing
                    # visibility, DEBUG in between. Reconnect cadence itself is
                    # unchanged.
                    if not mgr.is_connected:
                        if now - mgr._last_reconnect_attempt >= 10:
                            mgr._last_reconnect_attempt = now
                            attempt_count = getattr(mgr, '_reconnect_attempt_count', 0) + 1
                            mgr._reconnect_attempt_count = attempt_count
                            _attempt_log = (logging.info if attempt_count == 1 or attempt_count % 50 == 0
                                            else logging.debug)
                            _attempt_log(f"[SSE] Cluster '{cid}' is disconnected, "
                                         f"attempting reconnect (try #{attempt_count})...")
                            try:
                                if mgr.connect_to_proxmox():
                                    logging.info(f"[SSE] Cluster '{cid}' reconnected successfully "
                                                 f"after {attempt_count} attempt(s)!")
                                    mgr._reconnect_attempt_count = 0
                                    mgr._sse_cooldown_until = 0  # clear any pending cooldown
                                    # only notify if last broadcast was >60s ago (avoid toast spam on WAN)
                                    last_notified = getattr(mgr, '_last_reconnect_broadcast', 0)
                                    if now - last_notified >= 60:
                                        mgr._last_reconnect_broadcast = now
                                        broadcast_sse('node_status', {
                                            'event': 'cluster_reconnected',
                                            'cluster_id': cid,
                                            'message': f'Connection to cluster restored'
                                        }, cid)
                                    # MK 2026-05-31 — push a fresh metrics
                                    # snapshot immediately so the UI flips
                                    # to "online" without waiting one full
                                    # loop tick. Worst case the next-loop
                                    # broadcast just re-confirms.
                                    try:
                                        _fresh = mgr.get_node_status()
                                        if _fresh:
                                            broadcast_sse('metrics', _fresh, cid)
                                    except Exception:
                                        pass
                                else:
                                    logging.debug(f"[SSE] Cluster '{cid}' reconnect failed, will retry in 10s")
                            except Exception as e:
                                logging.debug(f"[SSE] Cluster '{cid}' reconnect error: {e}")
                        
                        if not mgr.is_connected:
                            # Still disconnected - send empty data so UI knows
                            broadcast_sse('tasks', [], cid)
                            return
                    
                    # Get tasks every loop - but only broadcast if changed
                    # NS May 2026 — wrap in try/except so a single hung call
                    # doesn't kill the whole broadcast for this cluster.
                    try:
                        tasks = mgr.get_tasks(limit=50)
                    except Exception as e:
                        logging.debug(f"[SSE] {cid} get_tasks failed: {e}")
                        # cooldown so we don't hammer a hung host
                        mgr._sse_cooldown_until = time.time() + 10
                        broadcast_sse('tasks', [], cid)
                        return
                    task_list = tasks or []

                    # NS: Apr 2026 - Inject recent portal/audit actions as virtual tasks
                    # so admins can see what customers are doing in their task bar
                    try:
                        audit_tasks = _get_recent_audit_tasks(cid, mgr.config.name)
                        if audit_tasks:
                            task_list = task_list + audit_tasks
                    except Exception:
                        pass

                    # Deduplicate: only broadcast if tasks actually changed
                    task_hash = hash(tuple((t.get('upid',''), t.get('status','')) for t in task_list[:20]))
                    prev_hash = getattr(mgr, '_last_task_hash', None)
                    if task_hash != prev_hash or loop_count % 10 == 0:
                        mgr._last_task_hash = task_hash
                        broadcast_sse('tasks', task_list, cid)
                    
                    # Get metrics every loop
                    try:
                        metrics = mgr.get_node_status()
                        if metrics:
                            broadcast_sse('metrics', metrics, cid)
                    except Exception as e:
                        # NS May 2026 — surface this in debug; cooldown if frequent
                        logging.debug(f"[SSE] {cid} get_node_status failed: {e}")
                        mgr._sse_cooldown_until = time.time() + 10
                    
                    # NS: Resources every loop now (was every 2nd loop)
                    # This makes VM status update much faster in the UI
                    # NS: Fixed - was calling get_all_resources() which doesn't exist!
                    try:
                        resources = mgr.get_vm_resources()
                        if resources:
                            broadcast_sse('resources', resources, cid)
                            # NS: Feb 2026 - Reset stale counter on success
                            mgr._consecutive_empty_responses = 0
                        else:
                            # NS: Feb 2026 - Track empty responses while "connected"
                            # This catches stale tickets (Proxmox returns 401 but no exception)
                            mgr._consecutive_empty_responses = getattr(mgr, '_consecutive_empty_responses', 0) + 1
                            if mgr._consecutive_empty_responses >= 30:  # ~30s of empty data, WAN needs more tolerance
                                logging.warning(f"[SSE] Cluster '{cid}' returning empty data despite being 'connected' - forcing re-auth")
                                mgr._consecutive_empty_responses = 0
                                mgr.is_connected = False  # Force reconnect on next loop
                    except:
                        pass
                        
                except Exception as e:
                    logging.debug(f"Error broadcasting updates for {cid}: {e}")
            
            # NS: Run each cluster broadcast in its own thread with 8s max
            # Prevents one slow/timing-out cluster from blocking all SSE updates
            threads = []
            for cluster_id, manager in list(cluster_managers.items()):
                t = threading.Thread(target=broadcast_for_cluster, args=(cluster_id, manager), daemon=True)
                t.start()
                threads.append(t)
            
            # Wait for all threads, but max 8 seconds
            for t in threads:
                t.join(timeout=8)
            
            # ============================================================
            # VMware SSE: Push VMware data in background threads
            # to avoid blocking Proxmox metrics broadcasts
            # ============================================================
            vmware_sse_counter = getattr(broadcast_resources_loop, '_vmw_counter', 0) + 1
            broadcast_resources_loop._vmw_counter = vmware_sse_counter
            
            if vmware_sse_counter % 10 == 0 and vmware_managers:
                def _vmware_sse_push():
                    try:
                        vmw_list = []
                        for vmw_id, vmw_mgr in list(vmware_managers.items()):
                            try:
                                vmw_list.append({
                                    'id': vmw_id,
                                    'name': getattr(vmw_mgr, 'name', vmw_id),
                                    'host': getattr(vmw_mgr, 'host', ''),
                                    'connected': getattr(vmw_mgr, 'connected', False),
                                    'type': getattr(vmw_mgr, 'server_type', 'vcenter'),
                                })
                            except:
                                pass
                        if vmw_list:
                            broadcast_sse('vmware_servers', vmw_list)
                        for vmw_id, vmw_mgr in list(vmware_managers.items()):
                            try:
                                if not getattr(vmw_mgr, 'connected', False):
                                    # NS Apr 2026 — auto-reconnect mirrors Proxmox path.
                                    # Otherwise a transient ESXi blip leaves us "disconnected"
                                    # forever until the user restarts PegaProx.
                                    try:
                                        if not vmw_mgr.ensure_connected():
                                            continue
                                    except Exception:
                                        continue
                                result = vmw_mgr.get_vms()
                                if 'error' not in result:
                                    broadcast_sse('vmware_vms', {
                                        'vmware_id': vmw_id,
                                        'vms': result.get('data', [])
                                    })
                            except Exception as e:
                                logging.debug(f"[SSE] VMware VMs broadcast failed for {vmw_id}: {e}")
                    except Exception as e:
                        logging.debug(f"[SSE] VMware broadcast error: {e}")
                threading.Thread(target=_vmware_sse_push, daemon=True).start()
            
            if vmware_sse_counter % 5 == 0:
                def _vmware_detail_push():
                    try:
                        watched = getattr(broadcast_resources_loop, '_vmw_watched', {})
                        for (vmw_id, vm_id), last_time in list(watched.items()):
                            if time.time() - last_time > 120:
                                del watched[vmw_id, vm_id]
                                continue
                            if vmw_id not in vmware_managers:
                                continue
                            vmw_mgr = vmware_managers[vmw_id]
                            if not getattr(vmw_mgr, 'connected', False):
                                continue
                            try:
                                result = vmw_mgr.get_vm(vm_id)
                                if 'error' not in result:
                                    data = result.get('data', {})
                                    guest = vmw_mgr.get_vm_guest_info(vm_id)
                                    if 'error' not in guest:
                                        data['guest_info'] = guest.get('data', {})
                                    perf = vmw_mgr.get_vm_performance(vm_id)
                                    if 'error' not in perf:
                                        data['performance'] = perf.get('data', {})
                                    broadcast_sse('vmware_vm_detail', {
                                        'vmware_id': vmw_id,
                                        'vm_id': vm_id,
                                        'data': data
                                    })
                            except:
                                pass
                        broadcast_resources_loop._vmw_watched = watched
                    except Exception as e:
                        logging.debug(f"[SSE] VMware detail broadcast error: {e}")
                threading.Thread(target=_vmware_detail_push, daemon=True).start()
            
            # NS May 2026 — periodic heartbeat. Lets the frontend distinguish
            # "server still ticking, just no data" from "server dead". Frontend
            # watchdog force-reconnects if no message for >30s.
            # MK May 2026 (#484) — was `loop_count % 5 == 0`. With a dead node
            # in the cluster the per-cluster fan-out can wall on the join(8s)
            # timeout for every cycle, so heartbeat-every-5-loops drifts out
            # to ~40s between beats and the frontend's 30s wedge fires. Cost
            # of one tiny SSE message per second is negligible, just send it.
            try:
                broadcast_sse('heartbeat', {'ts': time.time(), 'loop': loop_count})
            except Exception:
                pass

            # NS: Reduced to 1 second for faster task updates
            # Proxmox API can handle this - it's just GET requests
            time.sleep(1)

        except Exception as e:
            logging.error(f"Broadcast loop error: {e}")
            time.sleep(5)

# Start broadcast thread when module loads
_broadcast_thread = None

def start_broadcast_thread():
    global _broadcast_thread
    if _broadcast_thread is None or not _broadcast_thread.is_alive():
        _broadcast_thread = threading.Thread(target=broadcast_resources_loop, daemon=True)
        _broadcast_thread.start()



