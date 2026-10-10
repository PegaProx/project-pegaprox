# -*- coding: utf-8 -*-
"""
PBS Backup Verification Engine
NS: Apr 2026 — Restore → Boot → Health Check → Cleanup

Validates that PBS backups are actually restorable and bootable.
Runs as background thread, stores results in SQLite.

MK Oct 2026 - a test guest comes up off the production network: it is restored with new
MAC addresses, and before it boots every NIC is set link_down (or moved to the cluster's
isolated test bridge), onboot is off, passthrough devices and bind mounts are dropped, its
disks are left out of backup jobs and it is tagged pegaprox-verify. The checks after boot
(guest agent, listening ports, a command) run through the guest agent, in a container
through pct exec on its node, and what restore, boot and checks took is held against the
RTO. core/recovery.py says what each guest is checked for and keeps the last result.
"""

import logging
import re
import shlex
import time
import json
import uuid
import threading
from datetime import datetime

from pegaprox.core.db import get_db

# active verification tasks — {task_id: status_dict}
_active_verifications = {}
_verify_lock = threading.Lock()
# a finished verification is answered from here this long, then from the database
KEEP_DONE = 300

AGENT_WAIT = 90         # seconds the guest agent gets to answer after boot
EXEC_WAIT = 60          # a check command
_NET_RE = re.compile(r'net\d+')
_QEMU_DISK_RE = re.compile(r'(?:scsi|virtio|sata|ide)\d+')
_PASSTHROUGH_RE = re.compile(r'(?:hostpci|usb|parallel)\d+')
_SERIAL_RE = re.compile(r'serial\d+')
_LXC_MP_RE = re.compile(r'mp\d+')
_LXC_DEV_RE = re.compile(r'dev\d+')
LINUX_LISTENERS = ['sh', '-c', 'ss -Hltn 2>/dev/null || netstat -ltn 2>/dev/null']
WINDOWS_LISTENERS = ['cmd.exe', '/c', 'netstat -an -p tcp']


def _prune_done(now=None):
    now = time.time() if now is None else now
    with _verify_lock:
        for tid in [k for k, v in _active_verifications.items()
                    if v.get('_done_at') and now - v['_done_at'] > KEEP_DONE]:
            _active_verifications.pop(tid, None)


def _public(status):
    return {k: v for k, v in status.items() if not k.startswith('_')}


def get_active_verifications():
    _prune_done()
    with _verify_lock:
        return {k: _public(v) for k, v in _active_verifications.items()}


def get_verification(task_id):
    with _verify_lock:
        v = _active_verifications.get(task_id)
        return _public(v) if v else None


def running_guests():
    """(cluster_id, vmid) of every verification still running."""
    with _verify_lock:
        return {(v.get('cluster_id'), v.get('vmid')) for v in _active_verifications.values()
                if v.get('status') == 'running'}


def _register(params):
    _prune_done()
    with _verify_lock:
        for v in _active_verifications.values():
            if v.get('vmid') == params.get('vmid') and v.get('cluster_id') == params.get('cluster_id') \
                    and v['status'] == 'running':
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
            'isolated': False,
            'checks': [],
            'duration_seconds': 0,
            'measured_seconds': None,
            'rto_seconds': 0,
            'rto_met': None,
            'source': params.get('source') or 'manual',
            'error': '',
            'logs': [],
        }
        _active_verifications[task_id] = status
    return status


def start_verification(pve_mgr, params):
    """Start a backup verification in a background thread.

    params: dict with keys:
        cluster_id, pbs_id, node, vmid, vm_name, backup_volid,
        backup_time, storage (optional: the backup's own storages when left out),
        boot_timeout (optional), check_agent (default True), auto_cleanup (default True),
        plan (optional: what core/recovery.plan_for says, read for the guest when left out)

    Returns task_id or raises Exception if duplicate.
    """
    status = _register(params)

    def run():
        _run(pve_mgr, params, status)

    # a user job: in an automatic group each call it sends asks for the lease (#625)
    from pegaprox.core import ha
    thread = threading.Thread(target=ha.as_job(run, f"backup verification {status['id']}"), daemon=True,
                              name=f"verify-{status['id']}")
    thread.start()

    return status['id']


def run_verification(pve_mgr, params):
    """The same as start_verification, in the thread that calls: returns the finished status.
    The weekly run tests one backup after another through here."""
    status = _register(params)
    _run(pve_mgr, params, status)
    return _public(status)


def _plan(params, pve_mgr):
    """What this test does, from params['plan'] or the guest's rules; the defaults (NICs
    down, no checks beyond the agent) when neither can be read."""
    from pegaprox.core import recovery
    plan = params.get('plan')
    if not isinstance(plan, dict):
        try:
            plan = recovery.plan_for(params.get('cluster_id'), params.get('vmid'), mgr=pve_mgr)
        except Exception as e:
            logging.warning(f"[VERIFY] rules of {params.get('vmid')} unreadable, defaults apply: {e}")
            plan = {}
    out = dict(recovery.DEFAULTS)
    out.pop('rto_minutes', None)
    out.update({k: v for k, v in plan.items() if v is not None})
    if out.get('isolation') not in recovery.ISOLATIONS or (out['isolation'] == 'bridge' and not out.get('test_bridge')):
        out['isolation'] = 'link_down'
    if params.get('check_agent') is False:
        out['agent'] = 'off'
    return out


def _run(pve_mgr, params, status):
    task_id = status['id']

    def _log(msg):
        status['logs'].append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        logging.info(f"[VERIFY {task_id}] {msg}")

    start_time = time.time()
    test_vmid = None
    restore_accepted = False
    host, port = pve_mgr.host, pve_mgr.api_port
    base = f"https://{host}:{port}/api2/json"
    node = params.get('node', '')
    volid = params.get('backup_volid') or ''
    # the archive says what it holds; a container backup restored as a VM fails
    from pegaprox.core import recovery
    vm_type = recovery.backup_kind(volid) or params.get('vm_type') or 'qemu'
    if vm_type not in ('qemu', 'lxc'):
        vm_type = 'qemu'
    status['vm_type'] = vm_type
    status['backup_ts'] = params.get('backup_ts') or recovery.backup_time(
        volid, _iso_epoch(params.get('backup_time')))

    try:
        plan = _plan(params, pve_mgr)
        status['isolation'] = plan['isolation']
        status['rto_seconds'] = int(plan.get('rto_seconds') or 0)
        storage = params.get('storage') or plan.get('test_storage') or None
        boot_timeout = params.get('boot_timeout') or plan.get('boot_timeout') or 180
        auto_cleanup = params.get('auto_cleanup', True)

        if not node:
            raise Exception("Node is required")

        # Phase 1: Get next VMID
        status['phase'] = 'allocating'
        _log(f"Getting next available VMID...")

        nextid_resp = pve_mgr._api_get(f"{base}/cluster/nextid")
        if nextid_resp.status_code != 200:
            raise Exception("Could not get next VMID")
        test_vmid = int(nextid_resp.json().get('data'))
        status['test_vmid'] = test_vmid
        _log(f"Test VMID: {test_vmid}")
        # an HA resource left on that VMID would have Proxmox start the restored guest
        # before it is isolated
        if _ha_resource(pve_mgr, base, test_vmid):
            raise Exception(f"VMID {test_vmid} has a Proxmox HA resource - not restoring there")

        # Phase 2: Restore backup
        status['phase'] = 'restoring'
        _log(f"Restoring backup {volid} to VMID {test_vmid}...")
        measured_from = time.time()

        # unique: new MAC addresses, the original's stay with the original
        if vm_type == 'lxc':
            restore_data = {'vmid': test_vmid, 'ostemplate': volid, 'restore': 1, 'force': 0, 'unique': 1}
        else:
            restore_data = {'vmid': test_vmid, 'archive': volid, 'force': 0, 'unique': 1,
                            'start': 0}  # don't start yet
        if storage:
            restore_data['storage'] = storage

        restore_resp = pve_mgr._api_post(f"{base}/nodes/{node}/{vm_type}", data=restore_data)

        if restore_resp.status_code != 200:
            raise Exception(f"Restore failed: {restore_resp.text[:200]}")
        # PVE creates and locks the guest config before it answers, so from here on
        # the VMID is ours to clean up
        restore_accepted = True

        restore_upid = restore_resp.json().get('data')
        _log(f"Restore task started: {restore_upid}")

        # Wait for restore to complete
        if not _wait_task(pve_mgr, restore_upid, timeout=600):
            raise Exception("Restore task failed or timed out")

        status['restore_ok'] = True
        _log("Restore completed successfully")

        # Phase 3: isolate it before it boots; nothing starts that is not
        status['phase'] = 'isolating'
        config = _isolate(pve_mgr, base, node, vm_type, test_vmid, plan, _log)
        status['isolated'] = True

        # Phase 4: Start VM
        status['phase'] = 'booting'
        _log("Starting test VM...")

        start_resp = pve_mgr._api_post(f"{base}/nodes/{node}/{vm_type}/{test_vmid}/status/start")
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
                st_resp = pve_mgr._api_get(f"{base}/nodes/{node}/{vm_type}/{test_vmid}/status/current")
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

            # Phase 6: the health checks
            status['phase'] = 'agent_check'
            status['checks'] = run_checks(pve_mgr, base, node, vm_type, test_vmid, plan, config, _log)
            status['agent_ok'] = any(c['check'] == 'agent' and c['ok'] for c in status['checks'])
        status['measured_seconds'] = round(time.time() - measured_from, 1)

        # Phase 7: Cleanup
        if auto_cleanup:
            status['phase'] = 'cleanup'
            _log("Cleaning up test VM...")

            # stop first
            try:
                pve_mgr._api_post(f"{base}/nodes/{node}/{vm_type}/{test_vmid}/status/stop", data={'timeout': 30})
                time.sleep(5)
            except Exception:
                pass

            # delete
            try:
                del_resp = pve_mgr._api_delete(f"{base}/nodes/{node}/{vm_type}/{test_vmid}",
                                               params={'purge': 1, 'destroy-unreferenced-disks': 1})
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
            _log(f"Auto-cleanup disabled - test VM {test_vmid} kept for inspection, isolated")
            status['cleanup_ok'] = True

        # Final status
        failed_checks = [c for c in status['checks'] if c.get('ok') is False]
        if status['restore_ok'] and status['boot_ok'] and not failed_checks:
            status['status'] = 'passed'
            rto = status['rto_seconds']
            if rto:
                status['rto_met'] = status['measured_seconds'] <= rto
                _log(f"Restore, boot and checks took {status['measured_seconds']}s, the RTO is {rto}s"
                     + ('' if status['rto_met'] else ' - missed'))
            _log("✓ Verification PASSED")
        else:
            status['status'] = 'failed'
            for c in failed_checks:
                _log(f"Check failed: {c['check']} {c.get('target') or ''} - {c.get('detail') or ''}")
            _log("✗ Verification FAILED")

    except Exception as e:
        status['status'] = 'error'
        status['error'] = str(e)
        _log(f"ERROR: {e}")

        # cleanup on error
        # NS Oct 2026 (#1018) - nextid only names a free VMID, it does not reserve it.
        # When another create took it first our restore was refused, and this purged
        # that other guest. Only what our accepted restore created goes.
        if test_vmid and not restore_accepted:
            _log(f"Restore to VMID {test_vmid} was not accepted - a guest there is not ours, left alone")
        elif test_vmid:
            try:
                pve_mgr._api_post(f"{base}/nodes/{node}/{vm_type}/{test_vmid}/status/stop")
                time.sleep(3)
                pve_mgr._api_delete(f"{base}/nodes/{node}/{vm_type}/{test_vmid}",
                                    params={'purge': 1, 'destroy-unreferenced-disks': 1})
                _log(f"Emergency cleanup: deleted test VM {test_vmid}")
            except Exception:
                _log(f"Emergency cleanup failed for VM {test_vmid}")

    finally:
        status['completed_at'] = datetime.now().isoformat()
        status['duration_seconds'] = round(time.time() - start_time, 1)
        status['phase'] = 'done'
        if status['status'] != 'passed':
            from pegaprox.core.recovery import failure_cause
            status['cause'] = failure_cause(status)

        # save to database
        _save_result(status)
        # kept in the registry for KEEP_DONE seconds, then the database answers
        status['_done_at'] = time.time()


def _iso_epoch(text):
    if not text:
        return None
    try:
        return int(datetime.fromisoformat(str(text).replace('Z', '+00:00')).timestamp())
    except (TypeError, ValueError):
        return None


def _ha_resource(pve_mgr, base, vmid):
    """Whether Proxmox HA manages a guest on `vmid`. An unreadable list says no: a cluster
    without HA answers it too, and the check is about a stale entry, not a lock."""
    try:
        r = pve_mgr._api_get(f"{base}/cluster/ha/resources", timeout=10)
        if r.status_code != 200:
            return False
        sids = {str(x.get('sid') or '') for x in (r.json().get('data') or []) if isinstance(x, dict)}
    except Exception:
        return False
    return f'vm:{vmid}' in sids or f'ct:{vmid}' in sids


# ---------------------------------------------------------------------------
# isolation
# ---------------------------------------------------------------------------

def _opts(value):
    """'virtio=AA:..,bridge=vmbr0,firewall=1' as [[key, value]] in their order; a part
    without '=' (a disk's volume) has value None."""
    out = []
    for part in str(value or '').split(','):
        if part:
            k, sep, v = part.partition('=')
            out.append([k, v if sep else None])
    return out


def _joined(opts):
    return ','.join(k if v is None else f'{k}={v}' for k, v in opts)


def _set(opts, key, value):
    for o in opts:
        if o[0] == key:
            o[1] = value
            return opts
    opts.append([key, value])
    return opts


def _volume(opts):
    """The volume of a disk or mount point: its first part, with or without 'volume='."""
    if not opts:
        return ''
    k, v = opts[0]
    return k if v is None else (v if k in ('volume', 'file') else '')


def isolation_changes(config, vm_type, plan):
    """What makes a restored guest safe to boot: (changes, deletes, disk_changes).
    changes and deletes go in one config write that has to succeed; disk_changes (leave
    the disks out of backup jobs) are best effort."""
    changes, deletes, disks = {}, [], {}
    bridge = plan.get('test_bridge') if plan.get('isolation') == 'bridge' else None
    for key, value in config.items():
        if _NET_RE.fullmatch(key):
            opts = _opts(value)
            if bridge:
                opts = [o for o in opts if o[0] not in ('tag', 'trunks')]
                _set(opts, 'bridge', bridge)
            else:
                _set(opts, 'link_down', '1')
            changes[key] = _joined(opts)
        elif vm_type == 'qemu' and (_PASSTHROUGH_RE.fullmatch(key)
                                    or (_SERIAL_RE.fullmatch(key) and str(value) != 'socket')):
            deletes.append(key)
        elif vm_type == 'lxc' and _LXC_DEV_RE.fullmatch(key):
            deletes.append(key)
        elif vm_type == 'lxc' and _LXC_MP_RE.fullmatch(key):
            opts = _opts(value)
            if _volume(opts).startswith('/'):
                # a bind mount: a directory of the node, production data
                deletes.append(key)
            elif dict((k, v) for k, v in opts).get('backup') != '0':
                disks[key] = _joined(_set(opts, 'backup', '0'))
        elif vm_type == 'qemu' and _QEMU_DISK_RE.fullmatch(key):
            opts = _opts(value)
            vol = _volume(opts)
            if vol in ('', 'none', 'cdrom') or ('media', 'cdrom') in [tuple(o) for o in opts]:
                continue
            if dict((k, v) for k, v in opts).get('backup') != '0':
                disks[key] = _joined(_set(opts, 'backup', '0'))
    changes['onboot'] = 0
    from pegaprox.core.recovery import TEST_TAG, guest_tags
    tags = guest_tags(config.get('tags'))
    if TEST_TAG not in tags:
        changes['tags'] = ';'.join(sorted(tags | {TEST_TAG}))
    return changes, sorted(deletes), disks


def unisolated_nics(config, plan):
    """The NICs of `config` that would reach a network the test is not meant for."""
    bad = []
    bridge = plan.get('test_bridge') if plan.get('isolation') == 'bridge' else None
    for key, value in config.items():
        if not _NET_RE.fullmatch(key):
            continue
        opts = dict((k, v) for k, v in _opts(value))
        if bridge:
            if opts.get('bridge') != bridge or 'tag' in opts or 'trunks' in opts:
                bad.append(key)
        elif opts.get('link_down') != '1':
            bad.append(key)
    return sorted(bad)


def _isolate(pve_mgr, base, node, vm_type, test_vmid, plan, log):
    """Write the isolation into the test guest's config and read it back. Raises when it
    did not take: the guest is then removed without ever booting."""
    url = f"{base}/nodes/{node}/{vm_type}/{test_vmid}/config"
    r = pve_mgr._api_get(url)
    if r.status_code != 200:
        raise Exception(f"could not read the test guest's config (HTTP {r.status_code})")
    config = r.json().get('data') or {}
    changes, deletes, disks = isolation_changes(config, vm_type, plan)
    body = dict(changes)
    if deletes:
        body['delete'] = ','.join(deletes)
    r = pve_mgr._api_put(url, data=body)
    if r.status_code != 200:
        raise Exception(f"could not isolate the test guest: {r.text[:200]}")
    if disks:
        try:
            r = pve_mgr._api_put(url, data=disks)
            if r.status_code != 200:
                log(f"Disks stay in the backup jobs' reach: {r.text[:120]}")
        except Exception as e:
            log(f"Disks stay in the backup jobs' reach: {e}")
    r = pve_mgr._api_get(url)
    if r.status_code != 200:
        raise Exception('could not read the test guest back after isolating it')
    after = r.json().get('data') or {}
    bad = unisolated_nics(after, plan)
    if bad:
        raise Exception(f"the test guest would boot on the network: {', '.join(bad)} not isolated")
    if str(after.get('onboot', '0')) not in ('0', ''):
        raise Exception('onboot is still set on the test guest')
    nics = len([k for k in after if _NET_RE.fullmatch(k)])
    how = f"on bridge {plan['test_bridge']}" if plan.get('isolation') == 'bridge' else 'link down'
    log(f"Isolated: {nics} NIC(s) {how}, onboot off"
        + (f", removed {', '.join(deletes)}" if deletes else ''))
    # the checks ask it whether the guest agent is on
    return after


# ---------------------------------------------------------------------------
# health checks
# ---------------------------------------------------------------------------

def parse_listening(text):
    """The TCP ports something listens on, from what ss, netstat or Windows netstat print."""
    ports = set()
    for line in str(text or '').splitlines():
        addrs = [t for t in line.split() if re.fullmatch(r'\S*:(\d+|\*)', t)]
        if len(addrs) < 2:
            continue
        local, remote = addrs[0], addrs[1]
        port = local.rsplit(':', 1)[1]
        if not port.isdigit():
            continue
        if 'LISTEN' in line.upper() or remote.endswith(':*') or remote.endswith(':0'):
            ports.add(int(port))
    return ports


def _agent_on(config):
    v = str((config or {}).get('agent') or '0')
    return v.startswith('1') or 'enabled=1' in v


def _agent_ping(pve_mgr, base, node, vmid, wait):
    deadline = time.time() + wait
    while True:
        try:
            r = pve_mgr._api_post(f"{base}/nodes/{node}/qemu/{vmid}/agent/ping", timeout=15)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        if time.time() >= deadline:
            return False
        time.sleep(5)


def _agent_exec(pve_mgr, base, node, vmid, argv, wait=EXEC_WAIT):
    """(exitcode, stdout) of a command the guest agent ran, None when it could not run it."""
    try:
        # an array parameter: one 'command' per argument
        r = pve_mgr._api_post(f"{base}/nodes/{node}/qemu/{vmid}/agent/exec", data={'command': list(argv)}, timeout=15)
        if r.status_code != 200:
            return None
        pid = (r.json().get('data') or {}).get('pid')
    except Exception:
        return None
    if pid is None:
        return None
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            r = pve_mgr._api_get(f"{base}/nodes/{node}/qemu/{vmid}/agent/exec-status",
                                 params={'pid': pid}, timeout=15)
            if r.status_code == 200:
                d = r.json().get('data') or {}
                if d.get('exited'):
                    return int(d.get('exitcode') or 0), str(d.get('out-data') or '')
        except Exception:
            pass
        time.sleep(2)
    return None


def _ct_exec(pve_mgr, node, vmid, inner, wait=EXEC_WAIT):
    """(exitcode, stdout, stderr) of a shell command in container `vmid`, through pct exec
    on its node."""
    from pegaprox.utils.ssh import _pve_node_exec
    cmd = f"pct exec {int(vmid)} -- sh -c {shlex.quote(inner)}"
    return _pve_node_exec(pve_mgr, node, cmd, timeout=wait)


def run_checks(pve_mgr, base, node, vm_type, test_vmid, plan, config, log):
    """The checks of a booted test guest: [{check, target, ok, detail}]. ok is None for a
    check that could not be made where that is no failure of the guest (a container whose
    node has no shell for us)."""
    checks = []
    ports, command = list(plan.get('ports') or []), str(plan.get('command') or '')
    if vm_type == 'qemu':
        mode = plan.get('agent', 'auto')
        wanted = mode == 'require' or (mode == 'auto' and _agent_on(config))
        up = None
        if wanted or ports or command:
            log("Checking QEMU guest agent...")
            up = _agent_ping(pve_mgr, base, node, test_vmid, AGENT_WAIT)
            log('Guest agent answers' if up else f'Guest agent did not answer within {AGENT_WAIT}s')
        if wanted:
            checks.append({'check': 'agent', 'target': '', 'ok': bool(up),
                           'detail': 'answers' if up else f'no answer within {AGENT_WAIT}s'})
        if ports:
            listening = None
            if up:
                got = _agent_exec(pve_mgr, base, node, test_vmid, LINUX_LISTENERS)
                if got is None or (got[0] != 0 and not got[1].strip()):
                    got = _agent_exec(pve_mgr, base, node, test_vmid, WINDOWS_LISTENERS) or got
                listening = parse_listening(got[1]) if got else None
            for p in ports:
                if listening is None:
                    checks.append({'check': 'port', 'target': str(p), 'ok': False,
                                   'detail': 'the listening ports could not be read through the guest agent'})
                else:
                    checks.append({'check': 'port', 'target': str(p), 'ok': p in listening,
                                   'detail': 'listening' if p in listening else 'nothing listens'})
        if command:
            got = None
            if up:
                got = _agent_exec(pve_mgr, base, node, test_vmid, ['sh', '-c', command])
                if got is None:
                    got = _agent_exec(pve_mgr, base, node, test_vmid, ['cmd.exe', '/c', command])
            if got is None:
                checks.append({'check': 'command', 'target': command, 'ok': False,
                               'detail': 'the guest agent could not run it'})
            else:
                checks.append({'check': 'command', 'target': command, 'ok': got[0] == 0,
                               'detail': f'exit code {got[0]}'})
        for c in checks:
            log(f"Check {c['check']} {c['target']}: {'ok' if c['ok'] else 'FAILED'} ({c['detail']})")
        return checks

    # a container: booted is what counts unless its node lets us in
    checks.append({'check': 'booted', 'target': '', 'ok': True, 'detail': 'running'})
    if not ports and not command:
        return checks
    rc, _out, err = _ct_exec(pve_mgr, node, test_vmid, 'true', wait=30)
    if rc != 0:
        why = f"no shell into the container: {str(err or '')[:120]}"
        log(f"Container checks skipped - {why}")
        for p in ports:
            checks.append({'check': 'port', 'target': str(p), 'ok': None, 'detail': why})
        if command:
            checks.append({'check': 'command', 'target': command, 'ok': None, 'detail': why})
        return checks
    if ports:
        rc, out, _err = _ct_exec(pve_mgr, node, test_vmid, LINUX_LISTENERS[2])
        listening = parse_listening(out) if rc == 0 or str(out or '').strip() else None
        for p in ports:
            if listening is None:
                checks.append({'check': 'port', 'target': str(p), 'ok': False,
                               'detail': 'the listening ports could not be read in the container'})
            else:
                checks.append({'check': 'port', 'target': str(p), 'ok': p in listening,
                               'detail': 'listening' if p in listening else 'nothing listens'})
    if command:
        rc, _out, _err = _ct_exec(pve_mgr, node, test_vmid, command)
        checks.append({'check': 'command', 'target': command, 'ok': rc == 0, 'detail': f'exit code {rc}'})
    for c in checks:
        log(f"Check {c['check']} {c['target']}: {'skipped' if c['ok'] is None else 'ok' if c['ok'] else 'FAILED'}"
            f" ({c['detail']})")
    return checks


def _upid_node(upid):
    parts = str(upid or '').split(':')
    return parts[1] if len(parts) > 2 and parts[0] == 'UPID' and parts[1] else None


def _wait_task(pve_mgr, upid, timeout=600):
    """Wait for a Proxmox task to complete. Returns True if OK."""
    if not upid:
        return False
    # MK Oct 2026 - the status of the task itself; the last 50 of the whole cluster's list
    # lose it on a busy cluster, and the wait then ran into its timeout as a failure
    node = _upid_node(upid)
    wait_for = getattr(type(pve_mgr), '_wait_for_task', None)
    if node and callable(wait_for):
        return bool(pve_mgr._wait_for_task(node, upid, timeout=timeout))
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
    """Save verification result to SQLite, and the guest's mark (core/recovery.py)."""
    try:
        db = get_db()
        details = {'logs': status.get('logs', [])}
        for k in ('checks', 'measured_seconds', 'rto_seconds', 'rto_met', 'backup_ts', 'isolation',
                  'isolated', 'vm_type', 'source', 'cause'):
            if status.get(k) is not None:
                details[k] = status[k]
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
            json.dumps(details)
        ))
    except Exception as e:
        logging.error(f"[VERIFY] Failed to save result: {e}")
    from pegaprox.core.recovery import note_result
    note_result(status)


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
