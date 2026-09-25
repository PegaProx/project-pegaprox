# -*- coding: utf-8 -*-
"""
PBS Backup Verification Engine
NS: Apr 2026 — Restore → Boot → Health Check → Cleanup

Validates that PBS backups are actually restorable and bootable.
Runs as background thread, stores results in SQLite.
"""

import logging
import time
import json
import uuid
import threading
from datetime import datetime

from pegaprox.core.db import get_db

# active verification tasks — {task_id: status_dict}
_active_verifications = {}
_verify_lock = threading.Lock()


def get_active_verifications():
    with _verify_lock:
        return dict(_active_verifications)


def get_verification(task_id):
    with _verify_lock:
        return _active_verifications.get(task_id)


def start_verification(pve_mgr, params):
    """Start a backup verification in a background thread.

    params: dict with keys:
        cluster_id, pbs_id, node, vmid, vm_name, backup_volid,
        backup_time, storage, network_bridge (optional),
        boot_timeout (default 120), check_agent (default True),
        auto_cleanup (default True)

    Returns task_id or raises Exception if duplicate.
    """
    # check for duplicate before starting
    with _verify_lock:
        for v in _active_verifications.values():
            if v.get('vmid') == params.get('vmid') and v['status'] == 'running':
                raise Exception(f"Verification already running for VM {params.get('vmid')}")

    task_id = str(uuid.uuid4())[:12]

    status = {
        'id': task_id,
        'cluster_id': params.get('cluster_id'),
        'pbs_id': params.get('pbs_id'),
        'vmid': params.get('vmid'),
        'vm_name': params.get('vm_name', ''),
        'backup_time': params.get('backup_time', ''),
        'node': params.get('node'),
        'test_vmid': None,
        'status': 'running',
        'phase': 'init',
        'started_at': datetime.now().isoformat(),
        'completed_at': None,
        'restore_ok': False,
        'boot_ok': False,
        'agent_ok': False,
        'cleanup_ok': False,
        'duration_seconds': 0,
        'error': '',
        'logs': [],
    }

    with _verify_lock:
        _active_verifications[task_id] = status

    def _log(msg):
        status['logs'].append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        logging.info(f"[VERIFY {task_id}] {msg}")

    def run():
        start_time = time.time()
        test_vmid = None
        host, port = pve_mgr.host, pve_mgr.api_port
        node = params.get('node', '')
        vm_type = params.get('vm_type', 'qemu')

        try:
            volid = params['backup_volid']
            storage = params.get('storage', 'local-lvm')
            network_bridge = params.get('network_bridge')
            boot_timeout = params.get('boot_timeout', 120)
            check_agent = params.get('check_agent', True)
            auto_cleanup = params.get('auto_cleanup', True)

            if not node:
                raise Exception("Node is required")

            # Phase 1: Get next VMID
            status['phase'] = 'allocating'
            _log(f"Getting next available VMID...")

            nextid_resp = pve_mgr._api_get(
                f"https://{host}:{port}/api2/json/cluster/nextid"
            )
            if nextid_resp.status_code != 200:
                raise Exception("Could not get next VMID")
            test_vmid = int(nextid_resp.json().get('data'))
            status['test_vmid'] = test_vmid
            _log(f"Test VMID: {test_vmid}")

            # Phase 2: Restore backup
            status['phase'] = 'restoring'
            _log(f"Restoring backup {volid} to VMID {test_vmid}...")

            restore_data = {
                'vmid': test_vmid,
                'archive': volid,
                'storage': storage,
                'force': 0,
                'start': 0,  # don't start yet
            }

            restore_resp = pve_mgr._api_post(
                f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}",
                data=restore_data
            )

            if restore_resp.status_code != 200:
                raise Exception(f"Restore failed: {restore_resp.text[:200]}")

            restore_upid = restore_resp.json().get('data')
            _log(f"Restore task started: {restore_upid}")

            # Wait for restore to complete
            if not _wait_task(pve_mgr, restore_upid, timeout=600):
                raise Exception("Restore task failed or timed out")

            status['restore_ok'] = True
            _log("Restore completed successfully")

            # Phase 3: Reconfigure network (optional isolation)
            if network_bridge:
                status['phase'] = 'configuring'
                _log(f"Setting network to isolated bridge: {network_bridge}")

                # get current config to find network interfaces
                cfg_resp = pve_mgr._api_get(
                    f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/config"
                )
                if cfg_resp.status_code == 200:
                    config = cfg_resp.json().get('data', {})
                    for key in config:
                        if key.startswith('net') and key[3:].isdigit():
                            # replace bridge in network config
                            net_val = config[key]
                            import re
                            new_net = re.sub(r'bridge=[^,]+', f'bridge={network_bridge}', net_val)
                            pve_mgr._api_put(
                                f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/config",
                                data={key: new_net}
                            )
                    _log(f"Network reconfigured to {network_bridge}")

            # Phase 4: Start VM
            status['phase'] = 'booting'
            _log("Starting test VM...")

            start_resp = pve_mgr._api_post(
                f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/status/start"
            )
            if start_resp.status_code != 200:
                raise Exception(f"Failed to start VM: {start_resp.text[:200]}")

            start_upid = start_resp.json().get('data')
            if start_upid:
                _wait_task(pve_mgr, start_upid, timeout=60)

            # Phase 5: Wait for boot
            status['phase'] = 'verifying'
            _log(f"Waiting for VM to boot (timeout: {boot_timeout}s)...")

            boot_start = time.time()
            booted = False
            while time.time() - boot_start < boot_timeout:
                try:
                    st_resp = pve_mgr._api_get(
                        f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/status/current"
                    )
                    if st_resp.status_code == 200:
                        st_data = st_resp.json().get('data', {})
                        if st_data.get('status') == 'running' and st_data.get('uptime', 0) > 5:
                            booted = True
                            _log(f"VM booted! Uptime: {st_data.get('uptime', 0)}s")
                            break
                except Exception:
                    pass
                time.sleep(5)

            if not booted:
                _log("VM did not boot within timeout")
                status['boot_ok'] = False
            else:
                status['boot_ok'] = True

                # Phase 6: Check QEMU guest agent (optional)
                if check_agent and booted and vm_type == 'qemu':
                    status['phase'] = 'agent_check'
                    _log("Checking QEMU guest agent...")

                    # wait a bit for agent to start
                    time.sleep(10)

                    try:
                        agent_resp = pve_mgr._api_get(
                            f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/agent/network-get-interfaces"
                        )
                        if agent_resp.status_code == 200:
                            interfaces = agent_resp.json().get('data', {}).get('result', [])
                            _log(f"Guest agent OK — {len(interfaces)} network interface(s)")
                            status['agent_ok'] = True
                        else:
                            _log(f"Guest agent not available (status {agent_resp.status_code})")
                            status['agent_ok'] = False
                    except Exception as e:
                        _log(f"Guest agent check failed: {e}")
                        status['agent_ok'] = False

            # Phase 7: Cleanup
            if auto_cleanup:
                status['phase'] = 'cleanup'
                _log("Cleaning up test VM...")

                # stop first
                try:
                    pve_mgr._api_post(
                        f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/status/stop",
                        data={'timeout': 30}
                    )
                    time.sleep(5)
                except Exception:
                    pass

                # delete
                try:
                    del_resp = pve_mgr._api_delete(
                        f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}",
                        params={'purge': 1, 'destroy-unreferenced-disks': 1}
                    )
                    if del_resp.status_code == 200:
                        del_upid = del_resp.json().get('data')
                        if del_upid:
                            _wait_task(pve_mgr, del_upid, timeout=120)
                        status['cleanup_ok'] = True
                        _log("Test VM deleted")
                    else:
                        _log(f"Cleanup failed: {del_resp.text[:100]}")
                except Exception as e:
                    _log(f"Cleanup error: {e}")
            else:
                _log(f"Auto-cleanup disabled — test VM {test_vmid} kept for inspection")
                status['cleanup_ok'] = True

            # Final status
            if status['restore_ok'] and status['boot_ok']:
                status['status'] = 'passed'
                _log("✓ Verification PASSED")
            else:
                status['status'] = 'failed'
                _log("✗ Verification FAILED")

        except Exception as e:
            status['status'] = 'error'
            status['error'] = str(e)
            _log(f"ERROR: {e}")

            # cleanup on error
            if test_vmid:
                try:
                    pve_mgr._api_post(
                        f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}/status/stop"
                    )
                    time.sleep(3)
                    pve_mgr._api_delete(
                        f"https://{host}:{port}/api2/json/nodes/{node}/{vm_type}/{test_vmid}",
                        params={'purge': 1, 'destroy-unreferenced-disks': 1}
                    )
                    _log(f"Emergency cleanup: deleted test VM {test_vmid}")
                except Exception:
                    _log(f"Emergency cleanup failed for VM {test_vmid}")

        finally:
            status['completed_at'] = datetime.now().isoformat()
            status['duration_seconds'] = round(time.time() - start_time, 1)
            status['phase'] = 'done'

            # save to database
            _save_result(status)

            # remove from active after 5 min
            def _cleanup():
                time.sleep(300)
                with _verify_lock:
                    _active_verifications.pop(task_id, None)
            threading.Thread(target=_cleanup, daemon=True).start()

    thread = threading.Thread(target=run, daemon=True, name=f"verify-{task_id}")
    thread.start()

    return task_id


def _wait_task(pve_mgr, upid, timeout=600):
    """Wait for a Proxmox task to complete. Returns True if OK."""
    if not upid:
        return False
    elapsed = 0
    while elapsed < timeout:
        try:
            tasks = pve_mgr.get_tasks(limit=50)
            for t in tasks:
                if t and t.get('upid') == upid:
                    st = t.get('status', '')
                    if st and st != 'running':
                        return st in ('OK', 'WARNINGS')
                    break
        except Exception:
            pass
        time.sleep(5)
        elapsed += 5
    return False


def _save_result(status):
    """Save verification result to SQLite."""
    try:
        db = get_db()
        db.execute('''
            INSERT OR REPLACE INTO backup_verifications
            (id, cluster_id, pbs_id, vmid, vm_name, backup_time, node, test_vmid,
             started_at, completed_at, status, phase, restore_ok, boot_ok, agent_ok,
             cleanup_ok, duration_seconds, error, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            status['id'], status['cluster_id'], status.get('pbs_id'),
            status['vmid'], status.get('vm_name', ''),
            status.get('backup_time', ''), status.get('node', ''),
            status.get('test_vmid'),
            status['started_at'], status.get('completed_at'),
            status['status'], status.get('phase', 'done'),
            int(status.get('restore_ok', False)), int(status.get('boot_ok', False)),
            int(status.get('agent_ok', False)), int(status.get('cleanup_ok', False)),
            status.get('duration_seconds', 0), status.get('error', ''),
            json.dumps({'logs': status.get('logs', [])})
        ))
    except Exception as e:
        logging.error(f"[VERIFY] Failed to save result: {e}")


def get_verification_history(cluster_id=None, vmid=None, limit=50):
    """Get verification history from database."""
    # NS Sep 2026 (audit) — the route clamps this too, but the cap belongs here as well:
    # the limit goes straight into a SQL LIMIT and this function has callers that never
    # pass through the HTTP boundary. A bound that only exists at one of two entrances
    # is the shape of most of what this audit turned up.
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 50
    try:
        db = get_db()
        if cluster_id and vmid:
            rows = db.query(
                'SELECT * FROM backup_verifications WHERE cluster_id = ? AND vmid = ? ORDER BY started_at DESC LIMIT ?',
                (cluster_id, vmid, limit)
            )
        elif cluster_id:
            rows = db.query(
                'SELECT * FROM backup_verifications WHERE cluster_id = ? ORDER BY started_at DESC LIMIT ?',
                (cluster_id, limit)
            )
        else:
            rows = db.query(
                'SELECT * FROM backup_verifications ORDER BY started_at DESC LIMIT ?',
                (limit,)
            )
        return [dict(r) for r in rows] if rows else []
    except Exception as e:
        logging.error(f"[VERIFY] Failed to get history: {e}")
        return []
