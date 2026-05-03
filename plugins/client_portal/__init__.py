"""
Client Portal Plugin — Self-service portal for hosting customers
NS: Apr 2026

Clients log in at /portal and see only their assigned VMs.
Uses existing VM ACLs for permission enforcement.
Hoster configures allowed actions via config.json.
"""
import os
import json
import logging
from flask import request, jsonify, send_file

from pegaprox.api.plugins import register_plugin_route
from pegaprox.globals import cluster_managers
from pegaprox.utils.rbac import load_vm_acls, user_can_access_vm, get_user_permissions
from pegaprox.utils.auth import load_users

PLUGIN_NAME = "Client Portal"
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_config():
    cfg_path = os.path.join(PLUGIN_DIR, 'config.json')
    try:
        with open(cfg_path) as f:
            return json.load(f)
    except Exception:
        return {"allowed_actions": ["vm.view", "vm.start", "vm.stop", "vm.console"]}


def _get_portal_config():
    """Return portal configuration (public, no secrets)"""
    cfg = _load_config()
    return {
        'portal_title': cfg.get('portal_title', 'Client Portal'),
        'allowed_actions': cfg.get('allowed_actions', []),
        'show_resource_usage': cfg.get('show_resource_usage', True),
        'show_ip_addresses': cfg.get('show_ip_addresses', True),
        'allow_password_change': cfg.get('allow_password_change', True),
        'allow_snapshots': cfg.get('allow_snapshots', False),
        'custom_logo_url': cfg.get('custom_logo_url', ''),
        'theme_color': cfg.get('theme_color', '#e57000'),
    }


def _get_my_vms():
    """Return all VMs the authenticated user can access across all clusters"""
    username = request.session.get('user', '')
    if not username:
        return {'error': 'Not authenticated'}, 401

    users = load_users()
    user = users.get(username, {})
    user['username'] = username

    # don't let admins use the portal — redirect them
    from pegaprox.models.permissions import ROLE_ADMIN
    if user.get('role') == ROLE_ADMIN:
        return {'redirect': '/', 'reason': 'admin'}

    cfg = _load_config()
    all_acls = load_vm_acls()
    result = []

    for cluster_id, mgr in cluster_managers.items():
        if not mgr.is_connected:
            continue

        cluster_acls = all_acls.get(cluster_id, {})
        # find VMIDs where this user has access
        user_vmids = set()
        for vmid_str, acl in cluster_acls.items():
            acl_users = acl.get('users', [])
            if username in acl_users or '*' in acl_users:
                user_vmids.add(int(vmid_str))

        if not user_vmids:
            continue

        # get VM resources from cluster
        try:
            resources = mgr.get_vm_resources()
        except Exception:
            continue

        for vm in resources:
            vmid = vm.get('vmid')
            if vmid not in user_vmids:
                continue

            vm_info = {
                'vmid': vmid,
                'name': vm.get('name', f'VM {vmid}'),
                'type': vm.get('type', 'qemu'),
                'status': vm.get('status', 'unknown'),
                'node': vm.get('node', ''),
                'cluster_id': cluster_id,
                'cluster_name': mgr.config.name,
                'uptime': vm.get('uptime', 0),
            }

            if cfg.get('show_resource_usage', True):
                vm_info['cpu_percent'] = vm.get('cpu_percent', 0)
                vm_info['mem_percent'] = vm.get('mem_percent', 0)
                vm_info['maxmem'] = vm.get('maxmem', 0)
                vm_info['mem'] = vm.get('mem', 0)
                vm_info['maxcpu'] = vm.get('maxcpu', 0)
                vm_info['maxdisk'] = vm.get('maxdisk', 0)
                vm_info['disk'] = vm.get('disk', 0)

            # get IP addresses if guest agent available
            if cfg.get('show_ip_addresses', True) and vm.get('status') == 'running':
                try:
                    host = mgr.host
                    node = vm.get('node')
                    vt = vm.get('type', 'qemu')
                    if vt == 'qemu':
                        agent_resp = mgr._api_get(
                            f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"
                        )
                        if agent_resp.status_code == 200:
                            interfaces = agent_resp.json().get('data', {}).get('result', [])
                            ips = []
                            for iface in interfaces:
                                for addr in iface.get('ip-addresses', []):
                                    ip = addr.get('ip-address', '')
                                    if ip and not ip.startswith('127.') and not ip.startswith('fe80'):
                                        ips.append(ip)
                            if ips:
                                vm_info['ips'] = ips[:3]  # max 3 IPs
                    elif vt == 'lxc':
                        # LXC: IPs from config
                        cfg_resp = mgr._api_get(
                            f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/interfaces"
                        )
                        if cfg_resp.status_code == 200:
                            interfaces = cfg_resp.json().get('data', [])
                            ips = [i.get('inet', '').split('/')[0] for i in interfaces
                                   if i.get('inet') and not i.get('inet', '').startswith('127.')]
                            if ips:
                                vm_info['ips'] = ips[:3]
                except Exception:
                    pass

            result.append(vm_info)

    return {'vms': result, 'user': username}


def _vm_power():
    """Handle VM power action (start/stop/shutdown/reboot)"""
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    user['username'] = username
    cfg = _load_config()

    data = request.get_json() or {}
    cluster_id = data.get('cluster_id')
    vmid = data.get('vmid')
    action = data.get('action')  # start, stop, shutdown, reboot

    if not cluster_id or not vmid or not action:
        return {'error': 'Missing cluster_id, vmid, or action'}

    # map action to permission
    perm_map = {'start': 'vm.start', 'stop': 'vm.stop', 'shutdown': 'vm.stop', 'reboot': 'vm.start'}
    required_perm = perm_map.get(action, 'vm.start')

    # check allowed actions
    if required_perm not in cfg.get('allowed_actions', []):
        return {'error': f'Action not allowed by hoster: {action}'}

    # check VM ACL
    if not user_can_access_vm(user, cluster_id, int(vmid), required_perm):
        return {'error': 'Permission denied'}

    if cluster_id not in cluster_managers:
        return {'error': 'Cluster not found'}

    mgr = cluster_managers[cluster_id]
    if not mgr.is_connected:
        return {'error': 'Cluster not connected'}

    # find VM node
    try:
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}

        node = vm.get('node')
        vm_type = vm.get('type', 'qemu')
        host = mgr.host

        action_map = {
            'start': f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/start",
            'stop': f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/stop",
            'shutdown': f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/shutdown",
            'reboot': f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/reboot",
        }

        url = action_map.get(action)
        if not url:
            return {'error': f'Unknown action: {action}'}

        resp = mgr._api_post(url)
        if resp.status_code == 200:
            from pegaprox.utils.audit import log_audit
            log_audit(username, f'portal.vm.{action}', f'Client portal: {action} VM {vmid}')
            return {'success': True, 'action': action, 'vmid': vmid}
        else:
            return {'error': f'Action failed: {resp.text[:100]}'}

    except Exception as e:
        return {'error': str(e)}


def _vm_console():
    """Get VNC console ticket + WS token for embedded noVNC"""
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    user['username'] = username
    cfg = _load_config()

    cluster_id = request.args.get('cluster_id')
    vmid = request.args.get('vmid')

    if not cluster_id or not vmid:
        return {'error': 'Missing cluster_id or vmid'}

    if 'vm.console' not in cfg.get('allowed_actions', []):
        return {'error': 'Console not allowed'}

    if not user_can_access_vm(user, cluster_id, int(vmid), 'vm.console'):
        return {'error': 'Permission denied'}

    if cluster_id not in cluster_managers:
        return {'error': 'Cluster not found'}

    mgr = cluster_managers[cluster_id]
    try:
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}

        result = mgr.get_vnc_ticket(vm.get('node'), int(vmid), vm.get('type', 'qemu'))
        if result.get('success'):
            from pegaprox.utils.realtime import create_ws_token
            ws_token = create_ws_token(username, user.get('role', 'viewer'))
            result['ws_token'] = ws_token
            from pegaprox.utils.audit import log_audit
            log_audit(username, 'vm.console', f'Portal: VNC console opened for VM {vmid}', cluster=mgr.config.name)
            return result
        return {'error': result.get('error', 'Console failed')}
    except Exception as e:
        return {'error': str(e)}


def _vm_snapshots():
    """List or create snapshots for a VM"""
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    user['username'] = username
    cfg = _load_config()

    if not cfg.get('allow_snapshots', False):
        return {'error': 'Snapshots not allowed'}

    cluster_id = request.args.get('cluster_id') or (request.get_json() or {}).get('cluster_id')
    vmid = request.args.get('vmid') or (request.get_json() or {}).get('vmid')

    if not cluster_id or not vmid:
        return {'error': 'Missing cluster_id or vmid'}

    if not user_can_access_vm(user, cluster_id, int(vmid), 'vm.snapshot'):
        return {'error': 'Permission denied'}

    if cluster_id not in cluster_managers:
        return {'error': 'Cluster not found'}

    mgr = cluster_managers[cluster_id]
    host = mgr.host

    # find VM
    try:
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}

        node = vm.get('node')
        vm_type = vm.get('type', 'qemu')
    except Exception as e:
        return {'error': str(e)}

    if request.method == 'GET':
        # list snapshots
        try:
            resp = mgr._api_get(f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot")
            if resp.status_code == 200:
                snaps = [s for s in resp.json().get('data', []) if s.get('name') != 'current']
                return {'snapshots': snaps, 'max': cfg.get('max_snapshots_per_vm', 5)}
            return {'error': 'Failed to list snapshots'}
        except Exception as e:
            return {'error': str(e)}

    elif request.method == 'POST':
        # create snapshot
        data = request.get_json() or {}
        snap_name = data.get('name', f'portal-{int(os.popen("date +%s").read().strip())}')
        description = data.get('description', f'Created via Client Portal by {username}')

        # check limit
        max_snaps = cfg.get('max_snapshots_per_vm', 5)
        try:
            resp = mgr._api_get(f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot")
            if resp.status_code == 200:
                existing = [s for s in resp.json().get('data', []) if s.get('name') != 'current']
                if len(existing) >= max_snaps:
                    return {'error': f'Snapshot limit reached ({max_snaps} max). Delete old snapshots first.'}
        except Exception:
            pass

        try:
            snap_resp = mgr._api_post(
                f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot",
                data={'snapname': snap_name, 'description': description}
            )
            if snap_resp.status_code == 200:
                from pegaprox.utils.audit import log_audit
                log_audit(username, 'portal.snapshot_created', f'Snapshot "{snap_name}" on VM {vmid}')
                return {'success': True, 'name': snap_name}
            return {'error': f'Snapshot failed: {snap_resp.text[:100]}'}
        except Exception as e:
            return {'error': str(e)}

    return {'error': 'Method not allowed'}


def _vm_snapshot_rollback():
    """Rollback VM to a snapshot"""
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    user['username'] = username
    cfg = _load_config()

    if not cfg.get('allow_snapshots', False):
        return {'error': 'Snapshots not allowed'}

    data = request.get_json() or {}
    cluster_id = data.get('cluster_id')
    vmid = data.get('vmid')
    snapname = data.get('snapname')

    if not cluster_id or not vmid or not snapname:
        return {'error': 'Missing cluster_id, vmid, or snapname'}

    if not user_can_access_vm(user, cluster_id, int(vmid), 'vm.snapshot'):
        return {'error': 'Permission denied'}

    if cluster_id not in cluster_managers:
        return {'error': 'Cluster not found'}

    mgr = cluster_managers[cluster_id]

    try:
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}

        node = vm.get('node')
        vm_type = vm.get('type', 'qemu')

        result = mgr.rollback_snapshot(node, int(vmid), vm_type, snapname)
        if result.get('success'):
            from pegaprox.utils.audit import log_audit
            log_audit(username, 'portal.snapshot_rollback', f'Rollback to "{snapname}" on VM {vmid}')
            return {'success': True, 'snapname': snapname}
        return {'error': result.get('error', 'Rollback failed')}
    except Exception as e:
        return {'error': str(e)}


def _vm_snapshot_delete():
    """Delete a snapshot"""
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    user['username'] = username
    cfg = _load_config()

    if not cfg.get('allow_snapshots', False):
        return {'error': 'Snapshots not allowed'}

    data = request.get_json() or {}
    cluster_id = data.get('cluster_id')
    vmid = data.get('vmid')
    snapname = data.get('snapname')

    if not cluster_id or not vmid or not snapname:
        return {'error': 'Missing cluster_id, vmid, or snapname'}

    if not user_can_access_vm(user, cluster_id, int(vmid), 'vm.snapshot'):
        return {'error': 'Permission denied'}

    if cluster_id not in cluster_managers:
        return {'error': 'Cluster not found'}

    mgr = cluster_managers[cluster_id]
    host = mgr.host

    try:
        resources = mgr.get_vm_resources()
        vm = next((r for r in resources if r.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}

        node = vm.get('node')
        vm_type = vm.get('type', 'qemu')

        resp = mgr._api_delete(
            f"https://{host}:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/snapshot/{snapname}"
        )
        if resp.status_code == 200:
            from pegaprox.utils.audit import log_audit
            log_audit(username, 'portal.snapshot_deleted', f'Deleted snapshot "{snapname}" on VM {vmid}')
            return {'success': True, 'snapname': snapname}
        return {'error': f'Delete failed: {resp.text[:100]}'}
    except Exception as e:
        return {'error': str(e)}


def _change_password():
    """Change authenticated user's password"""
    cfg = _load_config()
    if not cfg.get('allow_password_change', True):
        return {'error': 'Password change not allowed'}

    username = request.session.get('user', '')
    data = request.get_json() or {}
    current = data.get('current_password', '')
    new_pwd = data.get('new_password', '')

    if not current or not new_pwd:
        return {'error': 'Current and new password required'}

    from pegaprox.utils.auth import verify_password, hash_password, save_users
    users = load_users()
    user = users.get(username, {})

    if user.get('auth_source', 'local') != 'local':
        return {'error': 'Password managed by external provider'}

    if not verify_password(current, user.get('password_salt', ''), user.get('password_hash', '')):
        return {'error': 'Current password incorrect'}

    salt, pwd_hash = hash_password(new_pwd)
    user['password_salt'] = salt
    user['password_hash'] = pwd_hash

    from datetime import datetime
    user['password_changed_at'] = datetime.now().isoformat()
    save_users(users)

    from pegaprox.utils.audit import log_audit
    log_audit(username, 'portal.password_changed', 'Password changed via client portal')

    return {'success': True}


# LW: Apr 2026 — ISO mount for portal customers
# hoster defines allowed ISOs in config.json: "allowed_isos": ["local:iso/debian.iso", ...]
# or "iso_storage": "local" to allow all ISOs from a specific storage

def _list_allowed_isos():
    """List ISOs that portal customers are allowed to mount"""
    username = request.session.get('user', '')
    if not username:
        return {'error': 'Not authenticated'}, 401
    cfg = _load_config()

    # hoster can specify individual ISOs or an entire storage
    allowed_list = cfg.get('allowed_isos', [])
    iso_storage = cfg.get('iso_storage', '')

    isos = []
    if iso_storage:
        # list all ISOs from the configured storage across all clusters
        for cid, mgr in cluster_managers.items():
            if not mgr.is_connected:
                continue
            try:
                for iso in mgr.get_iso_list(list(mgr.get_node_status().keys())[0], iso_storage):
                    volid = iso.get('volid', '')
                    name = volid.split('/')[-1] if '/' in volid else volid
                    if volid not in [i['volid'] for i in isos]:
                        isos.append({'volid': volid, 'name': name, 'size': iso.get('size', 0), 'cluster_id': cid})
            except:
                pass
    # also add individually allowed ISOs
    for iso_id in allowed_list:
        if iso_id not in [i['volid'] for i in isos]:
            name = iso_id.split('/')[-1] if '/' in iso_id else iso_id
            isos.append({'volid': iso_id, 'name': name, 'size': 0, 'cluster_id': ''})

    return {'isos': isos}


def _mount_iso():
    """Mount an allowed ISO to a customer's VM"""
    username = request.session.get('user', '')
    if not username:
        return {'error': 'Not authenticated'}, 401
    data = request.get_json() or {}
    cluster_id = data.get('cluster_id', '')
    vmid = data.get('vmid')
    iso_volid = data.get('iso', '')
    drive = data.get('drive', 'ide2')  # ide2 is standard CD-ROM

    if not all([cluster_id, vmid, iso_volid]):
        return {'error': 'cluster_id, vmid, iso required'}, 400

    # check VM access
    if not user_can_access_vm(username, cluster_id, vmid):
        return {'error': 'Access denied'}, 403

    # MK: security audit — verify ISO is in explicit allowed list or allowed storage
    cfg = _load_config()
    allowed = cfg.get('allowed_isos', [])
    iso_storage = cfg.get('iso_storage', '')
    # prevent path traversal in volid
    if '..' in iso_volid or '/' in iso_volid.split(':')[-1].split('/')[0]:
        return {'error': 'Invalid ISO path'}, 400
    if iso_volid not in allowed and not (iso_storage and iso_volid.startswith(f'{iso_storage}:iso/')):
        return {'error': 'This ISO is not allowed'}, 403

    mgr = cluster_managers.get(cluster_id)
    if not mgr or not mgr.is_connected:
        return {'error': 'Cluster not available'}, 503

    # find node
    try:
        vms = mgr.get_vm_resources()
        vm = next((v for v in vms if v.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}, 404
        node = vm.get('node')
        vm_type = vm.get('type', 'qemu')
        if vm_type != 'qemu':
            return {'error': 'ISO mount only supported for QEMU VMs'}, 400

        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        resp = mgr._api_post(url, data={drive: f'{iso_volid},media=cdrom'})
        if resp.status_code == 200:
            from pegaprox.utils.audit import log_audit
            log_audit(username, 'portal.iso_mount', f'Mounted {iso_volid} on VM {vmid}')
            return {'success': True, 'message': f'ISO mounted on {drive}'}
        return {'error': f'Mount failed: {resp.text[:200]}'}, 500
    except Exception as e:
        return {'error': str(e)}, 500


def _unmount_iso():
    """Remove ISO from VM CD-ROM drive"""
    username = request.session.get('user', '')
    if not username:
        return {'error': 'Not authenticated'}, 401
    data = request.get_json() or {}
    cluster_id = data.get('cluster_id', '')
    vmid = data.get('vmid')
    drive = data.get('drive', 'ide2')

    if not all([cluster_id, vmid]):
        return {'error': 'cluster_id, vmid required'}, 400
    if not user_can_access_vm(username, cluster_id, vmid):
        return {'error': 'Access denied'}, 403

    mgr = cluster_managers.get(cluster_id)
    if not mgr or not mgr.is_connected:
        return {'error': 'Cluster not available'}, 503

    try:
        vms = mgr.get_vm_resources()
        vm = next((v for v in vms if v.get('vmid') == int(vmid)), None)
        if not vm:
            return {'error': 'VM not found'}, 404
        node = vm.get('node')
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
        resp = mgr._api_post(url, data={drive: 'none,media=cdrom'})
        if resp.status_code == 200:
            from pegaprox.utils.audit import log_audit
            log_audit(username, 'portal.iso_unmount', f'Unmounted ISO from VM {vmid}')
            return {'success': True}
        return {'error': f'Unmount failed: {resp.text[:200]}'}, 500
    except Exception as e:
        return {'error': str(e)}, 500


def _portal_snapshot_policies():
    """Read-only list of snapshot policies that touch the caller's VMs.
    Filters: returns only policies whose target_value matches a VM the
    caller has access to (via VM-ACL / pool / tenant). NS May 2026."""
    from pegaprox.core.db import get_db
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    user['username'] = username

    # collect (cluster_id, vmid, tags) the caller can reach via _get_my_vms logic
    # Re-use the existing helper to avoid duplicating ACL/permission code.
    try:
        my_vms_data = _get_my_vms()
    except Exception:
        my_vms_data = {'vms': []}

    by_cluster = {}
    for vm in (my_vms_data.get('vms') or []):
        cid = vm.get('cluster_id') or vm.get('clusterId')
        if not cid: continue
        d = by_cluster.setdefault(cid, {'vmids': set(), 'tags': set()})
        if vm.get('vmid') is not None:
            d['vmids'].add(str(vm['vmid']))
        for t in (vm.get('tags') or '').split(';'):
            t = t.strip()
            if t: d['tags'].add(t.lower())

    policies_out = []
    try:
        c = get_db().conn.cursor()
        for cid, ctx in by_cluster.items():
            c.execute('''SELECT id, cluster_id, name, target_type, target_value,
                         schedule, schedule_at, retention_count, retention_days,
                         enabled, last_run_at, last_run_status
                         FROM snapshot_policies WHERE cluster_id = ? AND enabled = 1''', (cid,))
            for row in c.fetchall():
                pol = dict(row)
                applies = False
                if pol['target_type'] == 'vm':
                    wanted = {x.strip() for x in (pol['target_value'] or '').split(',') if x.strip()}
                    applies = bool(wanted & ctx['vmids'])
                elif pol['target_type'] == 'tag':
                    applies = (pol['target_value'] or '').strip().lower() in ctx['tags']
                if applies:
                    policies_out.append(pol)
    except Exception:
        logging.exception('[client_portal] snapshot-policies failed')
        return {'error': 'internal error'}, 500

    return {'policies': policies_out}


def register(app):
    """Register plugin routes"""
    register_plugin_route('client_portal', 'config', _get_portal_config)
    register_plugin_route('client_portal', 'my-vms', _get_my_vms)
    register_plugin_route('client_portal', 'vm/power', _vm_power)
    register_plugin_route('client_portal', 'vm/console', _vm_console)
    register_plugin_route('client_portal', 'vm/snapshots', _vm_snapshots)
    register_plugin_route('client_portal', 'vm/snapshot-rollback', _vm_snapshot_rollback)
    register_plugin_route('client_portal', 'vm/snapshot-delete', _vm_snapshot_delete)
    register_plugin_route('client_portal', 'account/change-password', _change_password)
    # ISO mount for portal customers
    register_plugin_route('client_portal', 'vm/isos', _list_allowed_isos)
    register_plugin_route('client_portal', 'vm/iso-mount', _mount_iso)
    register_plugin_route('client_portal', 'vm/iso-unmount', _unmount_iso)
    # NS May 2026 — read-only view of snapshot policies that affect the
    # caller's VMs, plus latest run history. Lets customers see "yes my DB
    # gets snapshotted hourly" without any management surface.
    register_plugin_route('client_portal', 'snapshot-policies', _portal_snapshot_policies)

    logging.info("[PLUGINS] Client Portal plugin registered")
