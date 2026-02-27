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
            
            def broadcast_for_cluster(cid, mgr):
                """Broadcast updates for a single cluster - runs in own thread"""
                try:
                    # NS: Feb 2026 - AUTO-RECONNECT disconnected clusters
                    # Without this, a network reload (ifreload) permanently kills the connection
                    # until PegaProx is restarted. Now we retry every 10 seconds.
                    if not mgr.is_connected:
                        now = time.time()
                        if now - mgr._last_reconnect_attempt >= 10:
                            mgr._last_reconnect_attempt = now
                            logging.info(f"[SSE] Cluster '{cid}' is disconnected, attempting reconnect...")
                            try:
                                if mgr.connect_to_proxmox():
                                    logging.info(f"[SSE] Cluster '{cid}' reconnected successfully!")
                                    # Notify all SSE clients that cluster is back online
                                    broadcast_sse('node_status', {
                                        'event': 'cluster_reconnected',
                                        'cluster_id': cid,
                                        'message': f'Connection to cluster restored'
                                    }, cid)
                                else:
                                    logging.debug(f"[SSE] Cluster '{cid}' reconnect failed, will retry in 10s")
                            except Exception as e:
                                logging.debug(f"[SSE] Cluster '{cid}' reconnect error: {e}")
                        
                        if not mgr.is_connected:
                            # Still disconnected - send empty data so UI knows
                            broadcast_sse('tasks', [], cid)
                            return
                    
                    # Get tasks every loop - but only broadcast if changed
                    tasks = mgr.get_tasks(limit=50)
                    task_list = tasks or []
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
                    except:
                        pass
                    
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
                            if mgr._consecutive_empty_responses >= 10:  # ~10s of empty data
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



