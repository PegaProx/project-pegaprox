# -*- coding: utf-8 -*-
"""vmware + v2p migration routes - split from monolith dec 2025, NS"""

import logging
import re
import time
import threading
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth, load_users, build_authz_user, resolve_authz_user
from pegaprox.utils.audit import log_audit
# MK 2026-06-04 (CWE-117): mgr.name is from cluster-config (admin-controlled),
# vmware_id from URL. Sanitise both before logging for consistency.
from pegaprox.utils.sanitization import sanitize_log_message as _sl
from pegaprox.utils.rbac import user_can_access_vmware_vm, acts_as_admin
from pegaprox.utils.ratelimit import SlidingWindow
from pegaprox.api.helpers import (check_cluster_access, check_vmware_access, caller_is_scoped,
                                  acting_user, vmware_server_reach, upstream_failure,
                                  UPSTREAM_AUTH_STATUSES, caller_acts_as_admin)
from pegaprox.core.vmware import VMwareManager, load_vmware_servers, save_vmware_server, esxi_target_refusal
from pegaprox.core.v2p import V2PMigrationTask, _run_v2p_migration, DISK_CACHE_MODES, DIRECT_CACHE_MODES
from pegaprox.core import v2p as _v2p
from pegaprox.background.broadcast import broadcast_resources_loop

bp = Blueprint('vmware', __name__)

# V2P migration tracking
_vmware_migrations = {}
_migration_lock_v2p = threading.Lock()


def migrations_a_restart_would_end():
    """'name (id)' of every ESXi migration this process still runs, and of the guests a bulk
    run has yet to start. A restart (update, rollback, the restart button) ends them: their
    state lives in this process only. MK Nov 2026"""
    from pegaprox.core import esxi_bulk
    out = [f"{getattr(t, 'vm_name', '') or getattr(t, 'vm_id', '')} ({mid})"
           for mid, t in list(_vmware_migrations.items()) if getattr(t, 'status', '') == 'running']
    for run in esxi_bulk.runs():
        if run.state == 'running':
            waiting = [it for it in run.items if it.get('state') == esxi_bulk.WAITING]
            if waiting:
                out.append(f"bulk run {run.id}: {len(waiting)} guest(s) not started yet")
    return out


def _esxi_failed(result):
    """The answer for a failed call to an ESXi server.

    MK Oct 2026 (#1142) - this was jsonify(result) with the server's own status, so wrong
    stored credentials came back as a 401 and the browser signed the user off on every click
    on the server, with no way left to fix or remove it. Its 401/403 is a 502 UPSTREAM_AUTH
    now, its 5xx a 502; a 400/404 of the server keeps its status.
    """
    status = result.get('status_code')
    if status in UPSTREAM_AUTH_STATUSES:
        return upstream_failure(status, system='The ESXi server', detail=result.get('error'))
    if isinstance(status, int) and status >= 500:
        return jsonify(result), 502
    return jsonify(result), status or 500


def _target_refusal(host):
    """esxi_target_refusal for the caller of this request: loopback for a global admin only."""
    return esxi_target_refusal(host, allow_loopback=caller_acts_as_admin())


def _port_refusal(data):
    """Reads the port of a request body in place: an int afterwards, or gone when it came as
    null or '' (the stored port, or 443, is used then). The answer when it is no port at all.

    int(data.get('port', 443)) ran on whatever the client sent, so 'abc' or null was a 500."""
    port = data.get('port')
    if port is None or port == '':
        data.pop('port', None)
        return None
    # int() takes true as 1 and 443.9 as 443
    if isinstance(port, bool) or (isinstance(port, float) and not port.is_integer()):
        return jsonify({'error': 'Invalid port'}), 400
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    if not 0 < port < 65536:
        return jsonify({'error': 'Invalid port'}), 400
    data['port'] = port
    return None


def _stored_config(vmware_id):
    """The config an update of this server starts from: its row with the password decrypted,
    or what the live manager holds when there is no row. linked_clusters is left out when the
    stored ones do not parse. None when there is neither."""
    import json as _json
    db = get_db()
    row = db.conn.cursor().execute("SELECT * FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
    if row is None:
        mgr = vmware_managers.get(vmware_id)
        if mgr is None:
            return None
        return {k: getattr(mgr, k) for k in ('name', 'host', 'port', 'username', 'password', 'server_type',
                                              'ssl_verify', 'enabled', 'linked_clusters', 'notes')
                if getattr(mgr, k, None) is not None}
    row = dict(row)
    # a column that is NULL is left to the defaults of VMwareManager and save_vmware_server
    config = {k: row[k] for k in ('name', 'host', 'port', 'username', 'server_type', 'notes')
              if row.get(k) is not None}
    config['ssl_verify'] = bool(row.get('ssl_verify') or 0)
    config['enabled'] = bool(row['enabled']) if row.get('enabled') is not None else True
    config['password'] = ''
    if row.get('pass_encrypted'):
        try:
            config['password'] = db._decrypt(row['pass_encrypted'])
        except Exception:
            pass
    try:
        linked = _json.loads(row.get('linked_clusters') or '[]')
    except (TypeError, ValueError):
        linked = False
    if isinstance(linked, (list, type(None))):
        config['linked_clusters'] = list(linked or [])
    return config


def _stored_server_access(vmware_id):
    """check_vmware_access for a server that is only a row, for update and delete.

    load_vmware_servers loads enabled servers only, so after the next start a disabled one
    was a 404 at the gate and could be neither switched back on nor removed. Same rule as
    the gate, against the row's linked_clusters; a linkage that does not parse leaves the
    row to a global admin, as in the list. No row is a 404."""
    import json as _json
    row = get_db().conn.cursor().execute(
        "SELECT linked_clusters FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
    if row is None:
        return False, (jsonify({'error': 'ESXi server not found'}), 404)
    user = acting_user()
    if not user:
        return False, (jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401)
    try:
        linked = _json.loads(row['linked_clusters'] or '[]')
    except (TypeError, ValueError):
        linked = False
    if isinstance(linked, (list, type(None))):
        allowed = vmware_server_reach(user)(linked)
    else:
        allowed = acts_as_admin(user)
    if allowed:
        return True, None
    return False, (jsonify({'error': 'Access denied to this ESXi server'}), 403)

# =============================================================================

@bp.route('/api/vmware', methods=['GET'])
@require_auth(perms=['vmware.view'])
def list_vmware_servers():
    """List the ESXi servers the caller may reach"""
    # NS Oct 2026 - this handed every tenant's servers to any vmware.view holder; each row
    # now has to pass the rule check_vmware_access applies to the server it names
    user = acting_user()
    if not user:
        return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
    reaches = vmware_server_reach(user)
    result = []
    for vmware_id, mgr in list(vmware_managers.items()):
        if reaches(getattr(mgr, 'linked_clusters', None)):
            result.append(mgr.to_dict())
    
    # Also include disabled servers from DB
    try:
        import json as _json
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT id, name, host, port, username, ssl_verify, enabled, server_type, "
                       "linked_clusters, notes FROM vmware_servers")
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['id'] not in vmware_managers:
                try:
                    _linked = _json.loads(row_dict.get('linked_clusters') or '[]')
                except (TypeError, ValueError):
                    _linked = False
                # a linkage we cannot read shows the row to an admin and nobody else
                if not isinstance(_linked, (list, type(None))):
                    if not acts_as_admin(user):
                        continue
                    _linked = []
                if not reaches(_linked):
                    continue
                # the edit dialog is filled from this entry and saves all of it, so it
                # carries what to_dict gives of a loaded server, the secret aside
                result.append({
                    'id': row_dict['id'],
                    'name': row_dict['name'],
                    'host': row_dict['host'],
                    'port': row_dict['port'],
                    'username': row_dict.get('username') or '',
                    'server_type': row_dict.get('server_type', 'vcenter'),
                    'ssl_verify': bool(row_dict.get('ssl_verify') or 0),
                    'enabled': bool(row_dict['enabled']),
                    'connected': False,
                    'notes': row_dict.get('notes') or '',
                })
    except Exception:
        pass
    
    return jsonify(result)


@bp.route('/api/vmware', methods=['POST'])
@require_auth(perms=['vmware.config'])
def add_vmware_server():
    """Add a new VMware/vCenter server"""
    data = request.json or {}
    
    if not data.get('name') or not data.get('host'):
        return jsonify({'error': 'Name and host are required'}), 400
    if not data.get('username'):
        return jsonify({'error': 'Username is required'}), 400
    if not data.get('password'):
        return jsonify({'error': 'Password is required'}), 400
    _bad_port = _port_refusal(data)
    if _bad_port:
        return _bad_port
    _why = _target_refusal(data.get('host'))
    if _why:
        return jsonify({'error': _why}), 400
    
    vmware_id = str(uuid.uuid4())[:8]
    
    mgr = VMwareManager(vmware_id, data)
    if not mgr.connect():
        return jsonify({'error': f'Connection failed: {mgr.last_error}'}), 400
    
    save_vmware_server(vmware_id, data)
    vmware_managers[vmware_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'vmware.added',
              f"Added VMware server: {data['name']} ({data['host']}, type={data.get('server_type', 'vcenter')})")
    
    return jsonify({'id': vmware_id, 'message': 'VMware server added successfully', **mgr.to_dict()}), 201


@bp.route('/api/vmware/<vmware_id>', methods=['PUT'])
@require_auth(perms=['vmware.config'])
def update_vmware_server(vmware_id):
    """Update a VMware server config"""
    ok, err = check_vmware_access(vmware_id)  # NS Aug 2026 (Aikido) — object-level authz on write
    # a disabled server is not loaded after a start, only its row says who may change it
    if not ok and vmware_id not in vmware_managers:
        ok, err = _stored_server_access(vmware_id)
    if not ok:
        return err
    data = request.json or {}

    # NS Oct 2026 (#981) - linked_clusters is the list check_vmware_access reads, and an
    # empty one opens the server to everybody. Same rule as the PBS twin: a non-admin may
    # only narrow it, to clusters they reach themselves.
    if 'linked_clusters' in data:
        _lc = data.get('linked_clusters')
        # a string was stored as its characters and kept raw on the live manager
        if _lc is not None and not (isinstance(_lc, list) and all(isinstance(c, str) for c in _lc)):
            return jsonify({'error': 'linked_clusters must be a list of cluster ids'}), 400
        from pegaprox.utils.rbac import get_user_clusters, acts_as_admin
        _caller = build_authz_user(request.session.get('user', ''), request.session)
        if not acts_as_admin(_caller):
            _new_links = list(data.get('linked_clusters') or [])
            if not _new_links:
                return jsonify({'error': 'Access denied: only a global admin may unlink an ESXi '
                                         'server from every cluster'}), 403
            _reachable = get_user_clusters(_caller, include_pools=False)
            if _reachable is not None:
                _beyond = [c for c in _new_links if c not in set(_reachable)]
                if _beyond:
                    return jsonify({'error': 'Access denied: cannot link this ESXi server to '
                                             + ', '.join(_beyond)}), 403

    _bad_port = _port_refusal(data)
    if _bad_port:
        return _bad_port

    if vmware_id not in vmware_managers:
        db = get_db()
        row = db.conn.cursor().execute("SELECT * FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
        if not row:
            return jsonify({'error': 'VMware server not found'}), 404
    
    # MK May 2026 (#469 port) — cred-exfil guard. If host changes WHILE the
    # password is preserved (came in as ********), don't auto-connect — that
    # would ship the saved credential to a potentially attacker-controlled host.
    #
    # NS Aug 2026 (Aikido pentest) — never persist the preserved password against a CHANGED
    # host: the saved row is reused verbatim by diagnose / Test Connection / the boot-time
    # auto-connect, any of which would ship the secret to the new (possibly attacker-chosen)
    # host. Require a full password whenever the host changes.
    credentials_preserved = False
    host_changed = False

    # MK Sep 2026 (Aikido 700489023) — two ways past that guard, both closed here.
    #
    # First, it hung off vmware_managers, and load_vmware_servers only loads `enabled = 1`.
    # A DISABLED server is therefore absent from that dict and the whole block was skipped:
    # disable, repoint the host, re-enable, and the boot-time auto-connect hands the saved
    # credential to the new destination. The stored ROW is the authority for what gets
    # reused, so compare against it.
    _row = get_db().conn.cursor().execute(
        "SELECT host, port FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
    if _row is None:
        # MK Sep 2026 — no stored row means we cannot tell what the destination is today,
        # so we cannot tell whether this request moves it. The guard below only refuses a
        # preserved credential when host_changed is True, so leaving it False on a failed
        # read would wave an UNKNOWN destination through with the stored secret attached.
        # "Cannot tell" has to mean "changed" here; the cost is re-typing the password.
        # The 404 above only runs when the id is absent from vmware_managers, so a manager
        # without a row reaches this line.
        host_changed = True
    elif (data.get('host') and data.get('host') != _row['host']) or \
         ('port' in data and data['port'] != int(_row['port'] or 443)):
        host_changed = True
    if host_changed:
        # a new port on the old host is a new target as well
        _host = data.get('host')
        if not _host:
            _host = _row['host'] if _row is not None else getattr(vmware_managers.get(vmware_id), 'host', '')
        _why = _target_refusal(_host)
        if _why:
            return jsonify({'error': _why}), 400

    # Second, "keep the password" has three spellings and the guard knew one.
    # save_vmware_server writes `pass_encrypted or <the stored one>`, so an OMITTED or an
    # EMPTY password preserves the credential exactly as the UI's ******** sentinel does —
    # and only the sentinel was checked. Leaving the field out walked straight past it and
    # the row ended up holding the real credential against the caller's new host.
    _pw = data.get('password')
    if _pw is None or _pw == '' or _pw == '********':
        if host_changed:
            return jsonify({
                'error': 'Re-enter the password when changing the VMware host or port.'}), 400
        credentials_preserved = True

    # MK Nov 2026 - the stored server is what this update starts from, as on the PBS twin. It
    # was rebuilt from the body alone: the edit dialog sends no server_type or enabled, so a
    # save gave an ESXi host the default type and switched a disabled one back on, and a body
    # without host or username stored them empty. What the body leaves out or sends as null
    # keeps its stored value, and so does an empty one, the notes aside.
    config = _stored_config(vmware_id) or {}
    for k, v in data.items():
        if k in ('password', 'linked_clusters') or v is None or (v == '' and k != 'notes'):
            continue
        config[k] = v
    if credentials_preserved:
        # the live manager's credential first, else the stored one. Host changes returned
        # 400 above, so this only ever re-supplies a credential to the destination it had
        if getattr(vmware_managers.get(vmware_id), 'password', ''):
            config['password'] = vmware_managers[vmware_id].password
    else:
        config['password'] = _pw

    # an update that leaves linked_clusters out keeps them; a manager built without them
    # comes up unlinked, open to everybody (#981)
    if 'linked_clusters' in data:
        config['linked_clusters'] = list(data.get('linked_clusters') or [])
    elif vmware_id in vmware_managers:
        config['linked_clusters'] = list(getattr(vmware_managers[vmware_id], 'linked_clusters', None) or [])
    elif 'linked_clusters' not in config:
        return jsonify({'error': 'The stored linked_clusters of this server cannot be read, '
                                 'send linked_clusters with the update'}), 400

    save_vmware_server(vmware_id, config)

    mgr = VMwareManager(vmware_id, config)
    if config.get('enabled', True):
        if host_changed and credentials_preserved:
            try:
                mgr.connected = False
                mgr.last_error = 'Host changed — auto-connect skipped for security (preserved credentials). Use Test Connection manually after verifying the new host.'
            except Exception:
                pass
            logging.warning(f"[VMware:{_sl(getattr(mgr, 'name', vmware_id))}] Skipped auto-connect after host change with preserved credentials (cred-exfil guard)")
        else:
            mgr.connect()
    # a server that is only a row and stays disabled stays out of the registry, as at a
    # start: the keepalive of the broadcast loop would connect it with the stored password
    if config.get('enabled', True) or vmware_id in vmware_managers:
        vmware_managers[vmware_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'vmware.updated', f"Updated VMware server: {data.get('name', vmware_id)}")
    
    return jsonify(mgr.to_dict())


@bp.route('/api/vmware/<vmware_id>', methods=['DELETE'])
@require_auth(perms=['vmware.config'])
def delete_vmware_server(vmware_id):
    """Delete a VMware server"""
    ok, err = check_vmware_access(vmware_id)  # NS Aug 2026 (Aikido) — object-level authz on delete
    if not ok and vmware_id not in vmware_managers:
        ok, err = _stored_server_access(vmware_id)
    if not ok:
        return err
    name = vmware_managers[vmware_id].name if vmware_id in vmware_managers else vmware_id
    if vmware_id in vmware_managers:
        del vmware_managers[vmware_id]
    
    db = get_db()
    db.conn.cursor().execute("DELETE FROM vmware_servers WHERE id = ?", (vmware_id,))
    db.conn.commit()
    
    log_audit(request.session.get('user', 'admin'), 'vmware.deleted', f"Deleted VMware server: {name}")
    return jsonify({'message': f'VMware server {name} deleted'})


@bp.route('/api/vmware/test-connection', methods=['POST'])
@require_auth(perms=['vmware.config'])
def test_vmware_connection():
    """Test VMware connection with provided credentials"""
    data = request.json or {}
    if not data.get('host') or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Host, username and password required'}), 400
    _bad_port = _port_refusal(data)
    if _bad_port:
        return _bad_port
    _why = _target_refusal(data.get('host'))
    if _why:
        return jsonify({'error': _why}), 400
    
    mgr = VMwareManager('test', data)
    if mgr.connect():
        return jsonify({'success': True, 'server_info': mgr.server_info, 'api_version': mgr.api_version,
                        'connection_type': mgr._connection_type})
    return jsonify({'success': False, 'error': mgr.last_error}), 400


@bp.route('/api/vmware/<vmware_id>/diagnose', methods=['GET'])
@require_auth(perms=['vmware.config'])
def diagnose_vmware_connection(vmware_id):
    """diagnose connection issues -- compares stored vs. fresh credentials"""
    ok, err = check_vmware_access(vmware_id)  # NS Aug 2026 (Aikido) — object-level authz on diagnose
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    
    # Get stored encrypted password from DB
    db = get_db()
    row = db.conn.cursor().execute(
        "SELECT pass_encrypted, username, host, port FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found in DB'}), 404
    
    row_d = dict(row)
    stored_enc = row_d.get('pass_encrypted', '')
    
    # Try decrypt
    decrypted = ''
    decrypt_ok = False
    try:
        decrypted = db._decrypt(stored_enc)
        decrypt_ok = True
    except Exception as e:
        decrypted = f'DECRYPT_FAILED: {e}'
    
    # NS: Feb 2026 - SECURITY: no password chars in API response, only boolean indicators
    result = {
        'vmware_id': vmware_id,
        'host': mgr.host,
        'port': mgr.port,
        'username_in_db': row_d.get('username', ''),
        'username_in_mgr': mgr.username,
        'password_encrypted_present': bool(stored_enc),
        'password_decrypted_ok': decrypt_ok,
        'password_matches_mgr': decrypted == mgr.password if decrypt_ok else False,
        'mgr_connected': mgr.connected,
        'mgr_connection_type': mgr._connection_type,
        'mgr_last_error': mgr.last_error,
    }
    
    # Try fresh SOAP connection with stored credentials.
    # MK 2026-06-04: honour the per-cluster `ssl_verify` flag instead of
    # hard-disabling. Default is False because ESXi/vCenter ship with
    # self-signed certs in most labs; admins flip it on via cluster settings
    # once they've installed a real CA-signed cert + uploaded the CA. When
    # opt-out is in effect we log it so the cert posture is observable in
    # the audit/SIEM forward.
    try:
        from pyVim.connect import SmartConnect
        import ssl
        verify_tls = bool(getattr(mgr, 'ssl_verify', False))
        if verify_tls:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            logging.warning(
                f"[VMware:{getattr(mgr, 'name', vmware_id)}] fresh-SOAP-test TLS verify DISABLED "
                f"(cluster ssl_verify=false). Set ssl_verify=true once a CA-signed cert is in place."
            )
        si = SmartConnect(host=mgr.host, user=mgr.username, pwd=mgr.password,
                         port=mgr.port, sslContext=ctx,
                         disableSslCertValidation=not verify_tls)
        if si:
            result['fresh_soap_test'] = 'SUCCESS'
            from pyVim.connect import Disconnect
            Disconnect(si)
        else:
            result['fresh_soap_test'] = 'FAILED: SmartConnect returned None'
    except Exception as e:
        err = str(e)
        if 'InvalidLogin' in err:
            result['fresh_soap_test'] = f'FAILED: InvalidLogin (password wrong or locked)'
        else:
            result['fresh_soap_test'] = f'FAILED: {err[:150]}'
    
    return jsonify(result)


@bp.route('/api/vmware/<vmware_id>/vms', methods=['GET'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_vms(vmware_id):
    """List all VMs from vCenter/ESXi"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vms()
    if 'error' in result:
        if mgr.connect():
            result = mgr.get_vms()
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_vms()
    if 'error' in result:
        return _esxi_failed(result)
    # sec (private disclosure Sep 2026 — audit H2): the list returned the FULL ESXi inventory gated
    # only by server reach (check_vmware_access admits a tenant caller, and returns True when the
    # server has no linked_clusters — the common single-ESXi case). Every sibling per-VM route calls
    # user_can_access_vmware_vm; the list didn't → the ESXi analog of the #773 /resources leak. Filter
    # per-VM so an ACL-scoped caller sees only their VMs; admins/plain operators pass the helper.
    _vmw_user = build_authz_user(request.session.get('user', ''), request.session)
    _vms = result.get('data', []) or []
    _scoped = [v for v in _vms
               if user_can_access_vmware_vm(_vmw_user, vmware_id, str(v.get('vm', '')), 'vmware.vm.view')]
    return jsonify(_scoped)


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>', methods=['GET'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_vm_detail(vmware_id, vm_id):
    """Get detailed VM info with guest and performance data"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    # NS Aug 2026 (BOLA audit 2026-08-17) — per-VM ACL scope, not just server reach
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.view'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vm(vm_id)
    if 'error' in result and mgr.connect():
        result = mgr.get_vm(vm_id)
    if 'error' in result:
        return _esxi_failed(result)
    
    data = result.get('data', {})
    # Guest info
    guest = mgr.get_vm_guest_info(vm_id)
    if 'error' not in guest:
        data['guest_info'] = guest.get('data', {})
    # Performance
    perf = mgr.get_vm_performance(vm_id)
    if 'error' not in perf:
        data['performance'] = perf.get('data', {})
    
    return jsonify(data)


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/power/<action>', methods=['POST'])
@require_auth(perms=['vmware.vm.power'])
def vmware_vm_power(vmware_id, vm_id, action):
    """VM power actions: start, stop, suspend, reset"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    if action not in ('start', 'stop', 'suspend', 'reset'):
        return jsonify({'error': f'Invalid action: {action}'}), 400
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.power'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    result = mgr.vm_power_action(vm_id, action)
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), f'vmware.vm.{action}',
              f"VM power {action} on {vm_id} @ {mgr.name}")
    return jsonify({'message': f'VM {action} successful'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/snapshots', methods=['GET'])
@require_auth(perms=['vmware.vm.snapshot'])
def get_vmware_snapshots(vmware_id, vm_id):
    """List VM snapshots"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    # NS Aug 2026 (BOLA audit 2026-08-17) — per-VM ACL scope, not just server reach
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.snapshot'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_snapshots(vm_id)
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/snapshots', methods=['POST'])
@require_auth(perms=['vmware.vm.snapshot'])
def create_vmware_snapshot(vmware_id, vm_id):
    """Create a VM snapshot"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Snapshot name required'}), 400
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.snapshot'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    result = mgr.create_snapshot(vm_id, data['name'], data.get('description', ''),
                                  data.get('memory', False), data.get('quiesce', True))
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.snapshot.created',
              f"Snapshot '{data['name']}' created for VM {vm_id} @ {mgr.name}")
    return jsonify({'message': f'Snapshot created', 'data': result.get('data')}), 201


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/snapshots/<snapshot_id>', methods=['DELETE'])
@require_auth(perms=['vmware.vm.snapshot'])
def delete_vmware_snapshot(vmware_id, vm_id, snapshot_id):
    """Delete a VM snapshot"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.snapshot'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    result = mgr.delete_snapshot(vm_id, snapshot_id)
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.snapshot.deleted',
              f"Snapshot {snapshot_id} deleted from VM {vm_id} @ {mgr.name}")
    return jsonify({'message': 'Snapshot deleted'})


@bp.route('/api/vmware/<vmware_id>/hosts', methods=['GET'])
@require_auth(perms=['vmware.host.view'])
def get_vmware_hosts(vmware_id):
    """List ESXi hosts"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_hosts()
    if 'error' in result:
        # Reconnect and retry
        if mgr.connect():
            result = mgr.get_hosts()
        # If still failing with 400, try SOAP fallback
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_hosts()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/datastores', methods=['GET'])
@require_auth(perms=['vmware.datastore.view'])
def get_vmware_datastores(vmware_id):
    """List VMware datastores"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_datastores()
    if 'error' in result:
        if mgr.connect():
            result = mgr.get_datastores()
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_datastores()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/datastores/<ds_id>', methods=['GET'])
@require_auth(perms=['vmware.datastore.view'])
def get_vmware_datastore_detail(vmware_id, ds_id):
    """Get detailed datastore info"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_datastore_detail(ds_id)
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/networks', methods=['GET'])
@require_auth(perms=['vmware.network.view'])
def get_vmware_networks(vmware_id):
    """List VMware networks"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_networks()
    if 'error' in result:
        if mgr.connect():
            result = mgr.get_networks()
        if 'error' in result and result.get('status_code') == 400:
            mgr._try_soap_fallback()
            if mgr._connection_type == 'soap':
                result = mgr.get_networks()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/clusters', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_vcenter_clusters(vmware_id):
    """List vCenter compute clusters with DRS/HA status"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_vcenter_clusters_detailed()
    if 'error' in result:
        # Fallback to basic list
        result = mgr.get_vcenter_clusters()
    if 'error' in result and result.get('status_code') == 400:
        mgr._try_soap_fallback()
        if mgr._connection_type == 'soap':
            result = mgr.get_vcenter_clusters_detailed()
            if 'error' in result:
                result = mgr.get_vcenter_clusters()
    if 'error' in result:
        # For standalone ESXi (no clusters), return empty list instead of error
        if result.get('status_code') in (400, 404):
            return jsonify([])
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/clusters/<cluster_id>', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_cluster_detail(vmware_id, cluster_id):
    """Get cluster detail with DRS/HA config"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_cluster_detail(cluster_id)
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/clusters/<cluster_id>/drs', methods=['POST'])
@require_auth(perms=['vmware.cluster.manage'])
def set_vmware_cluster_drs(vmware_id, cluster_id):
    """Toggle DRS on a cluster"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    enabled = data.get('enabled', False)
    automation = data.get('automation')
    mgr = vmware_managers[vmware_id]
    result = mgr.set_cluster_drs(cluster_id, enabled, automation)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.cluster.drs',
              f"DRS {'enabled' if enabled else 'disabled'} on cluster {cluster_id} @ {mgr.name}")
    return jsonify({'message': f"DRS {'enabled' if enabled else 'disabled'}"})


@bp.route('/api/vmware/<vmware_id>/clusters/<cluster_id>/ha', methods=['POST'])
@require_auth(perms=['vmware.cluster.manage'])
def set_vmware_cluster_ha(vmware_id, cluster_id):
    """Toggle HA on a cluster"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    enabled = data.get('enabled', False)
    mgr = vmware_managers[vmware_id]
    result = mgr.set_cluster_ha(cluster_id, enabled)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.cluster.ha',
              f"HA {'enabled' if enabled else 'disabled'} on cluster {cluster_id} @ {mgr.name}")
    return jsonify({'message': f"HA {'enabled' if enabled else 'disabled'}"})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/performance', methods=['GET'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_vm_performance(vmware_id, vm_id):
    """Get VM performance metrics"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    # NS Aug 2026 (BOLA audit 2026-08-17) — per-VM ACL scope, not just server reach
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.view'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_vm_performance(vm_id)
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/watch', methods=['POST'])
@require_auth(perms=['vmware.vm.view'])
def watch_vmware_vm(vmware_id, vm_id):
    """register interest in a VM -- SSE will push detail data every 5s.
    Call again to renew the 120s watch window. POST with empty body."""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if not hasattr(broadcast_resources_loop, '_vmw_watched'):
        broadcast_resources_loop._vmw_watched = {}
    _w = broadcast_resources_loop._vmw_watched
    # sec (audit): this dict is keyed on a caller-supplied vm_id and had no bound, while the
    # detail push walks EVERY entry every 5s and issues three ESXi calls per entry. A caller
    # holding vmware.vm.view — a builtin viewer permission — could enqueue unlimited ids and
    # keep a worker thread busy indefinitely. Expire stale entries and cap the registry.
    _now = time.time()
    for _k in [k for k, t in list(_w.items()) if _now - t > 120]:
        _w.pop(_k, None)
    _MAX_WATCHED = 200
    if (vmware_id, vm_id) not in _w and len(_w) >= _MAX_WATCHED:
        for _k, _ in sorted(_w.items(), key=lambda kv: kv[1])[:max(1, len(_w) - _MAX_WATCHED + 1)]:
            _w.pop(_k, None)
    _w[(vmware_id, vm_id)] = _now
    return jsonify({'ok': True, 'watching': vm_id, 'ttl': 120})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/watch', methods=['DELETE'])
@require_auth(perms=['vmware.vm.view'])
def unwatch_vmware_vm(vmware_id, vm_id):
    """Stop watching a VM"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    watched = getattr(broadcast_resources_loop, '_vmw_watched', {})
    watched.pop((vmware_id, vm_id), None)
    return jsonify({'ok': True})


@bp.route('/api/vmware/<vmware_id>/datacenters', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_datacenters(vmware_id):
    """List vCenter datacenters"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    result = mgr.get_datacenters()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))



@bp.route('/api/vmware/<vmware_id>/summary', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_summary(vmware_id):
    """Get environment summary (VM counts, host counts, health)"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_summary()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/health', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_health(vmware_id):
    """Get vCenter appliance health"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_appliance_health()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/folders', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_folders(vmware_id):
    """List folders"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    folder_type = request.args.get('type')
    result = mgr.get_folders(folder_type)
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/resource-pools', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_resource_pools(vmware_id):
    """List resource pools"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_resource_pools()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/storage-policies', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_storage_policies(vmware_id):
    """List storage policies"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_storage_policies()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/content-libraries', methods=['GET'])
@require_auth(perms=['vmware.view'])
def get_vmware_content_libraries(vmware_id):
    """List content libraries"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-server tenant gate (was role-perm only)
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    mgr = vmware_managers[vmware_id]
    result = mgr.get_content_libraries()
    if 'error' in result:
        return _esxi_failed(result)
    return jsonify(result.get('data', []))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/console', methods=['POST'])
@require_auth(perms=['vmware.vm.view'])
def get_vmware_console(vmware_id, vm_id):
    """get console ticket -- tries WebMKS, MKS, direct URL"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404

    # Security fix: Check VM-level authorization
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    # NS Oct 2026 (#1101) - read by the account's own row. This route has no cluster gate of
    # its own, so the {} a failed whole-table read answers (default tenant, every cluster)
    # passed the tenant check in user_can_access_vmware_vm for any ESXi server.
    user = resolve_authz_user(request.session)
    if not user:
        return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401

    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.view'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403

    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()

    # Security: Verify VM exists on this VMware server before issuing console ticket
    # This prevents users from requesting console tickets for arbitrary VM IDs
    vm_check = mgr.get_vm(vm_id)
    if 'error' in vm_check:
        log_audit(request.session.get('user', 'admin'), 'vmware.console.denied',
                  f"Console access denied for VM {vm_id} @ {mgr.name}: VM not found")
        return jsonify({'error': 'VM not found or access denied'}), 404
    
    result = mgr.get_vm_console_ticket(vm_id)
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.console.accessed',
              f"Console ticket issued for VM {vm_id} @ {mgr.name}")
    return jsonify(result.get('data', {}))


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/config', methods=['PUT'])
@require_auth(perms=['vmware.vm.manage'])
def update_vmware_vm_config(vmware_id, vm_id):
    """Update VM configuration (CPU, RAM, notes, hot-add, etc)"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    data = request.json or {}
    result = mgr.update_vm_config(vm_id, data)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.config',
              f"Updated config on VM {vm_id} @ {mgr.name}: {list(data.keys())}")
    return jsonify({'message': 'VM configuration updated'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/network', methods=['PUT'])
@require_auth(perms=['vmware.vm.manage'])
def update_vmware_vm_network(vmware_id, vm_id):
    """Change VM network adapter"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    data = request.json or {}
    nic_key = int(data.get('nic_key', 0))
    network = data.get('network', '')
    if not network:
        return jsonify({'error': 'Network name required'}), 400
    result = mgr.update_vm_network(vm_id, nic_key, network)
    if 'error' in result:
        return jsonify(result), 500
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.network',
              f"Changed network on VM {vm_id} to '{network}' @ {mgr.name}")
    return jsonify({'message': f"Network changed to '{network}'"})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/boot-order', methods=['PUT'])
@require_auth(perms=['vmware.vm.manage'])
def update_vmware_vm_boot_order(vmware_id, vm_id):
    """Change VM boot order"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    data = request.json or {}
    boot_order = data.get('boot_order', ['disk', 'cdrom', 'net'])
    result = mgr.update_vm_boot_order(vm_id, boot_order)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'message': 'Boot order updated'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/clone', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def clone_vmware_vm(vmware_id, vm_id):
    """Clone a VM"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Clone name is required'}), 400
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.migrate'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    result = mgr.clone_vm(vm_id, data['name'], data.get('folder'), data.get('resource_pool'), data.get('datastore'))
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.cloned',
              f"Cloned VM {vm_id} as '{data['name']}' @ {mgr.name}")
    return jsonify({'message': f"VM cloned as '{data['name']}'", 'data': result.get('data')}), 201


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>', methods=['DELETE'])
# MK Sep 2026 - was vmware.vm.power on both the route and the per-VM check, so anyone
# allowed to switch a guest on and off could DELETE it. Power and destruction are not the
# same authority; vmware.vm.manage is the one that already means "may change this guest".
@require_auth(perms=['vmware.vm.manage'])
def delete_vmware_vm(vmware_id, vm_id):
    """Delete a VM (must be powered off)"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    result = mgr.delete_vm(vm_id)
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.deleted',
              f"Deleted VM {vm_id} @ {mgr.name}")
    return jsonify({'message': 'VM deleted'})


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/rename', methods=['POST'])
@require_auth(perms=['vmware.vm.manage'])   # renaming is a config change, not a power one
def rename_vmware_vm(vmware_id, vm_id):
    """Rename a VM"""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'New name is required'}), 400
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    result = mgr.rename_vm(vm_id, data['name'])
    if 'error' in result:
        return _esxi_failed(result)
    
    log_audit(request.session.get('user', 'admin'), 'vmware.vm.renamed',
              f"Renamed VM {vm_id} to '{data['name']}' @ {mgr.name}")
    return jsonify({'message': f"VM renamed to '{data['name']}'"})



# ===========================================================================

# what the migration plan lists of a NIC for a caller who may migrate the guest but not view it:
# the NIC rows of the wizard, nothing a dry run of the migration does not show anyway
_V2P_PLAN_NIC_KEYS = ('label', 'network', 'mac_address', 'pve_model')


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/migration-plan', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_migration_plan(vmware_id, vm_id):
    """Analyze source VM and return migration plan with available Proxmox targets.
    Also detects ESXi host and datastore for SSHFS access."""
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.migrate'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    mgr = vmware_managers[vmware_id]
    # NS Aug 2026 — refresh a stale ESXi REST/CIS session before the read, exactly like the
    # VM-list/detail routes do (get_vmware_vms:270, single-VM GET:295). Without it, a server
    # that's been up long enough for the ESXi session to expire returns "VM not found" here and
    # the migration wizard dies at the planning step even though the VM plainly exists.
    mgr.ensure_connected()
    result = mgr.get_vm_disks_for_export(vm_id)
    if 'error' in result:
        return jsonify(result), 400
    vm_data = result['data']
    # the NICs in the order nic_map counts them: the same list the migrate
    # route hands the task, plus what the wizard shows as detected hardware
    try:
        _vm_full = (mgr.get_vm(vm_id) or {}).get('data') or {}
    except Exception:
        _vm_full = {}
    _nics = list(_vm_full.get('nics') or [])
    # hardware, sizing, guest OS and notes are what the VM view shows (vmware.vm.view). A
    # caller who may only migrate the guest gets the rows the wizard needs for its NIC choices;
    # the migration reads the rest from ESXi itself when it starts
    _may_view = user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.view')
    if _may_view:
        vm_data['nics'] = _nics
        for _k in ('hardware', 'cpu', 'memory', 'guest_OS', 'notes'):
            if _k in _vm_full and _k not in vm_data:
                vm_data[_k] = _vm_full[_k]
    else:
        vm_data['nics'] = [{k: n[k] for k in _V2P_PLAN_NIC_KEYS if k in n} if isinstance(n, dict) else {}
                           for n in _nics]
    vm_data['details'] = bool(_may_view)
    
    # Available Proxmox targets — only clusters the caller may reach (don't leak others' topology)
    targets = []
    for cid, cmgr in list(cluster_managers.items()):
        # MK Nov 2026 - an ESXi host registered for XHM (or an XCP-ng pool) sits in the same
        # dict, has no PVE nodes and failed the whole plan with an AttributeError
        if getattr(cmgr, 'cluster_type', 'proxmox') != 'proxmox':
            continue
        if cmgr.is_connected:
            allowed, _ = check_cluster_access(cid)
            if not allowed:
                continue
            nodes = list(cmgr.nodes.keys()) if cmgr.nodes else []
            node_storages = {}
            for n in nodes:
                try:
                    sr = cmgr._api_get(f"https://{cmgr.host}:{cmgr.api_port}/api2/json/nodes/{n}/storage")
                    if sr.status_code == 200:
                        node_storages[n] = [s['storage'] for s in sr.json().get('data', [])
                                            if s.get('active') and 'images' in s.get('content', '')]
                except:
                    node_storages[n] = []
            targets.append({
                'cluster_id': cid, 'cluster_name': cmgr.config.name,
                'nodes': nodes, 'storages': node_storages
            })
    
    return jsonify({
        'source': vm_data,
        'targets': targets,
        'esxi_host': mgr.host,
        'esxi_user': 'root',
        'estimated_downtime_seconds': max(10, int(vm_data.get('total_disk_gb', 10) * 0.3)),
        'requirements': [
            'SSH must be enabled on ESXi host',
            'sshfs on the target Proxmox node; the review step lists every package the chosen options need there',
            'ESXi root password is required for SSHFS access',
            'Sufficient temp space on Proxmox node for disk conversion',
        ],
        'method': 'SSHFS + qm importdisk (works on VMFS 5, VMFS 6, vSAN, NFS)',
    })


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/migrate', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def start_vmware_migration(vmware_id, vm_id):
    """Start near-zero-downtime migration from VMware to Proxmox.
    
    Required body:
    - target_cluster, target_node, target_storage
    - esxi_password: Root password for ESXi SSH access
    
    Optional:
    - esxi_host: ESXi host IP (default: from the ESXi server config)
    - esxi_user: SSH username (default: root)
    - esxi_datastore: Datastore name (auto-detected if not set)
    - esxi_vm_dir: VM directory name on datastore (default: VM name)
    - network_bridge, start_after, remove_source
    - wait_for_confirmation (#562): hold before the final switchover and wait for an
      explicit POST .../confirm-cutover (or .../cancel-cutover). Default false.
    - confirmation_timeout: seconds to wait at that gate before auto-aborting (default 86400).
    - nic_map: [{index, bridge, vlan, skip}] per source NIC, in the order of the migration
      plan's source.nics. The bridge must exist on the target node (bridge, OVS bridge or an
      SDN VNet of a zone on that node).
    - disk_map: [{index, storage, skip}] per source disk, in the order of source.disks. The
      storage must be active on the target node and take images; disk 0 cannot be skipped.
      EFI and TPM state stay on target_storage.
    - verify: 'sample' (default), 'full' (every copied disk compared with its source before
      the target starts; Live Clone, Auto and Offline Copy only) or 'off'.
    - target_vmid (#1339): the VMID of the new guest, 100 to 999999999. It has to be free on
      the target cluster, inside the caller's tenant range and allowed by the cluster's next-id
      setting. It is asked again right before the guest is created, and the migration fails
      when it got taken meanwhile. Empty: the next free VMID, inside the caller's tenant range.
    - allow_package_install (#1252): default true. False installs nothing on the target node;
      a run that misses a package it needs stops before it changes anything and names them.
    - Windows guests are prepared fully automatically (MK Nov 2026), no login needed: the VirtIO
      drivers and the guest agent are staged offline after the copy (virtio-win.iso from the
      node, downloaded into its ISO storage when missing and package installs are allowed), the
      static IPv4 of every adapter is carried over to the new VirtIO NIC at the first boot, the
      old adapter's address is cleared, the old adapters are removed where Windows can, the ESXi
      guest tools are uninstalled, and the two-stage boot (SATA first, then VirtIO SCSI) runs.
      The source VM on ESXi is not changed by it.
      install_virtio_drivers: absent = on for Windows guests, false turns the preparation off.
      two_stage_boot: absent/null = on for Windows guests whose drivers will be there, false off,
      true refused where it cannot run (Live Mirror, disk_bus sata/ide, another scsihw, agent
      false, no drivers). Its failure is a warning, never a failed migration.
      guest_prep: true prepares the guest in the running source VM first, over the ESXi guest
      operations (SOAP connection, guest tools running), with guest_user and guest_password (a
      Windows administrator; with UAC only the built-in Administrator gets a full token). They
      are used for that and nothing else: never stored, logged or returned. Any problem before
      the guest is released falls back to the offline preparation; a failure after it powers
      the source on again with its guest tools installer mounted.
    - dry_run: true checks all of it against the target node and answers 200 with the
      resolved plan ({ok, errors, warnings, nics, disks, storages, available, node_packages});
      nothing is started and no ESXi password is needed. node_packages lists what the options
      may install on the target node and which of it is missing (one SSH call to that node;
      checked false when it could not be asked). check_packages: false leaves that call out
      (node_packages null), for a dry run that only wants the node's bridges and storages.
    """
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'VMware server not found'}), 404
    
    # Security fix: Check VM-level authorization
    from pegaprox.utils.auth import load_users
    # #491 — token-scoped identity so an admin-owned viewer/user API token can't reach a VM
    # outside its token scope (user_can_access_vmware_vm honors effective_role).
    user = build_authz_user(request.session.get('user', ''), request.session)
    
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.migrate'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    
    data = request.json or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'A JSON object is expected'}), 400
    dry_run = data.get('dry_run', False)
    if not isinstance(dry_run, bool):
        return jsonify({'error': 'dry_run must be true or false'}), 400

    for field in ('target_cluster', 'target_node', 'target_storage'):
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    # MK Sep 2026 - same rule as the XHM path: remove_source destroys the source guest
    # when the copy lands, and destruction is vmware.vm.manage, not vmware.vm.migrate.
    if data.get('remove_source'):
        if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
            return jsonify({'error': 'Permission denied: removing the source guest needs '
                                     'vmware.vm.manage on it'}), 403

    # the shape of the body: names that reach a node shell or a config line, the ESXi host
    # pinned to the server's, the per NIC / per disk choices and the verify mode
    _body_err, _opts = _migrate_body_refusal(vmware_id, data, dry_run)
    if _body_err:
        return jsonify({'error': _body_err}), 400

    if not dry_run and not data.get('esxi_password'):
        return jsonify({'error': 'esxi_password is required for SSHFS-based migration'}), 400
    if data.get('guest_prep') is True and not dry_run and not (data.get('guest_user') and data.get('guest_password')):
        return jsonify({'error': 'guest_user and guest_password are required for the Windows preparation in '
                                 'the running guest (guest_prep)'}), 400
    if data['target_cluster'] not in cluster_managers:
        return jsonify({'error': 'Target cluster not found'}), 404

    # gate the migration target on cluster access
    # sec (audit): reachability only — but this CREATES a guest on the target, and a new vmid
    # matches no per-object grant, so a pool-scoped caller admitted by the #555 fallback could
    # land a VM on a cluster they do not own. The XHM twin (api/xhm.py) already asks the
    # confinement question about its target; ask it here too.
    _v2p_u = build_authz_user(request.session.get('user', ''), request.session)
    if caller_is_scoped(_v2p_u, data['target_cluster']):
        return jsonify({'error': 'Access denied to the target cluster'}), 403
    allowed, err_response = check_cluster_access(data['target_cluster'])
    if not allowed:
        return err_response
    # MK Nov 2026 - the guest lands on the target cluster over many steps: none of them
    # starts where this instance holds no federation lease on it
    if not dry_run:
        from pegaprox.api.federation import refuse_unleased
        refused = refuse_unleased(data['target_cluster'], f"cluster {data['target_cluster']}")
        if refused:
            return refused
    # MK Nov 2026 (#1224) - the planning step runs commands on target_node over SSH with the
    # target cluster's key or password: one of its nodes, nothing else
    try:
        _tn = data['target_node']
        _member = isinstance(_tn, str) and _tn in (cluster_managers[data['target_cluster']].nodes or {})
    except Exception:
        _member = False
    if not _member:
        return jsonify({'error': 'target_node is not a node of the target cluster'}), 400

    mgr = vmware_managers[vmware_id]
    # NS Aug 2026 — same stale-session guard as the migration-plan + VM-list routes: a long-lived
    # server whose ESXi session has expired would otherwise read "VM not found" here and the
    # migration would abort before it even started.
    mgr.ensure_connected()
    vm_detail = mgr.get_vm(vm_id)
    vm_name = vm_detail.get('data', {}).get('name', vm_id) if 'data' in vm_detail else vm_id

    # the plan against the target node: what a dry run answers with, and the allowlist the
    # bridges and storages of nic_map / disk_map have to be on before anything starts
    _plan = None
    if dry_run or _opts['nic_map'] is not None or _opts['disk_map'] is not None:
        _plan, _plan_err = _v2p_plan(mgr, vm_id, data, _opts, vm_detail)
        if _plan_err:
            return _plan_err
    _skipped = {i for i, e in (_opts['disk_map'] or {}).items() if e['skip']}

    # MK Nov 2026 - the VMID it lands under: a chosen one asked of the target now (the
    # task asks once more before it creates the guest), else the tenant range the task keeps to
    _pick, _vmid_err = _vmid_pick(_v2p_u, data['target_cluster'], data.get('target_vmid'))
    if dry_run:
        _plan.update(_vmid_view(_pick))
        if _vmid_err:
            _plan['errors'].append(_vmid_err[1])
            _plan['ok'] = False
    elif _vmid_err:
        return jsonify({'error': _vmid_err[1]}), _vmid_err[0]

    # MK Oct 2026 - the guest lands on the target as a new one, sized as core/v2p.py builds
    # it (the wizard's sockets, cores and memory over what ESXi reports): the tenant quota
    # counts it like a create
    def _v2p_adds():
        from pegaprox.utils.rbac import landing_adds, quota_tenant
        return landing_adds(quota_tenant(_v2p_u), data['target_cluster'], _v2p_footprint(vm_detail, data, _skipped),
                            source_cluster=vmware_id, source_removed=bool(data.get('remove_source')))
    from pegaprox.api.helpers import tenant_quota_gate, quota_hold_alive
    from pegaprox.core import esxi_bulk as _ebulk
    if dry_run:
        _busy = _guest_busy(vmware_id, vm_id, tasks=False)
        if _busy:
            _plan['errors'].append(_busy)
            _plan['ok'] = False
        # the same quota question, without holding a slot for a run that does not start
        _qerr, _qwarn = tenant_quota_gate(_v2p_u, f'ESXi migration of {vm_name} (dry run)', _v2p_adds,
                                          cluster=data['target_cluster'])
        if _qerr:
            try:
                _plan['errors'].append(str((_qerr[0].get_json() or {}).get('error') or 'Tenant quota exceeded'))
            except Exception:
                _plan['errors'].append('Tenant quota exceeded')
            _plan['ok'] = False
        if _qwarn:
            _plan['warnings'].append(str(_qwarn.get('message') or 'Tenant quota exceeded (warning only)'))
        # MK Nov 2026 (#1252) - what the options may install on the target node, and what of it is missing.
        # The wizard's inventory read (bridges and storages on a target change) has no use for it.
        _plan['node_packages'], _perr, _pwarn = _v2p_node_packages(data, _plan) \
            if data.get('check_packages') is not False else (None, None, None)
        if _perr:
            _plan['errors'].append(_perr)
            _plan['ok'] = False
        if _pwarn:
            _plan['warnings'].append(_pwarn)
        # MK Nov 2026 - the in-guest preparation uploads from the node to ESXi's port 443
        if data.get('guest_prep') is True and data.get('check_packages') is not False and _plan.get('guest_prep'):
            _gp_reach = _v2p._node_cannot_reach(cluster_managers.get(data['target_cluster']), data['target_node'],
                                                mgr.host, int(getattr(mgr, 'port', 443) or 443))
            _plan['guest_prep']['reaches_esxi_443'] = None if _gp_reach is None else not _gp_reach
            if _gp_reach:
                _plan['warnings'].append(f"Prepare Windows in the running guest will fall back to the offline "
                                         f"preparation: node {data['target_node']} cannot reach {mgr.host} on port "
                                         f"443 ({_gp_reach})")
        return jsonify({'dry_run': True, 'vm_name': vm_name, **_plan})
    if _plan is not None and not _plan['ok']:
        return jsonify({'error': 'The migration plan does not fit the target node: '
                                 + '; '.join(_plan['errors']),
                        'errors': _plan['errors'], 'warnings': _plan['warnings']}), 400

    # MK Oct 2026 - one job per guest. Taken here under the lock the bulk runs take theirs
    # with, given back when the job returns or on any way out below before it started
    mid = str(uuid.uuid4())[:8]
    _holder = _ebulk.task_holder(mid)
    _other = _ebulk.hold(vmware_id, vm_id, _holder)
    if _other:
        return jsonify({'error': _guest_busy(vmware_id, vm_id, _other, tasks=False)}), 409
    _started = False
    try:
        _qerr, _qwarn = tenant_quota_gate(_v2p_u, f'ESXi migration of {vm_name}', _v2p_adds,
                                          cluster=data['target_cluster'],
                                          hold={'cluster_id': data['target_cluster']})
        if _qerr:
            return _qerr
        # the chosen VMID is this migration's until it ends, no other one here gets it
        from pegaprox.core import target_vmid as _tvmid
        if _pick['vmid'] and _tvmid.claim(data['target_cluster'], _pick['vmid'], _holder,
                                          _tvmid.until_over(_v2p_task, mid)):
            return jsonify({'error': f"VMID {_pick['vmid']} is promised to another ESXi migration "
                                     f"under way - choose another one"}), 409

        # NS: pass all NICs from ESXi to migration task so multi-NIC + MAC works
        if 'selected_nics' not in data and 'data' in vm_detail:
            nics = vm_detail['data'].get('nics', [])
            if nics:
                data['selected_nics'] = nics

        task = V2PMigrationTask(mid, vmware_id, vm_id, data['target_cluster'],
                                data['target_node'], data['target_storage'], vm_name, data)
        _tvmid.bind(task, _pick['vmid'], _pick['start'], _pick['end'], _pick['strict'], _holder)

        with _migration_lock_v2p:
            _vmware_migrations[mid] = task
        # the quota holds the new guest while the task runs (MK Oct 2026)
        quota_hold_alive(alive=lambda: task.status == 'running')

        # a user job: in an automatic group each call it sends asks for the lease (#625)
        from pegaprox.core import ha
        thread = threading.Thread(target=ha.as_job(_run_held, 'ESXi migration'), args=(task, _holder),
                                  daemon=True)
        thread.start()
        _started = True
    finally:
        if not _started:
            _never_ran(mid)
            _ebulk.let_go(vmware_id, vm_id, _holder)
            # a VMID claimed above is free again now, not only once the unstarted grace ends
            from pegaprox.core.target_vmid import release as _vmid_release
            _vmid_release(_holder)

    _extra = ''
    if _opts['nic_map'] is not None or _opts['disk_map'] is not None or _opts['verify'] != 'sample':
        _extra = (f" (verify {_opts['verify']}, {len(_skipped)} disk(s) skipped, "
                  f"per-disk storage {'yes' if _opts['disk_map'] else 'no'}, "
                  f"per-NIC network {'yes' if _opts['nic_map'] else 'no'})")
    if _pick['vmid']:
        _extra += f" as VMID {_pick['vmid']}"
    _extra += _winprep_audit(vm_detail, data)
    log_audit(request.session.get('user', 'admin'), 'vmware.migration.started',
              f"V2P migration: {vm_name} @ {data.get('esxi_host', mgr.host)} -> "
              f"{data['target_cluster']}/{data['target_node']}/{data['target_storage']}{_extra}")
    
    return jsonify({
        'migration_id': mid,
        'message': f'Migration started for {vm_name}',
        'task': task.to_dict(),
        **({'quota_warning': _qwarn} if _qwarn else {}),
    }), 202


@bp.route('/api/vmware/guest-prep-script', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_guest_prep_script():
    """The PowerShell script of the Windows preparation, for a run by hand

    MK Nov 2026 - the same bytes the in-guest preparation (guest_prep) runs in the guest. Mount
    virtio-win.iso in the Windows guest on ESXi, run it as administrator
    (powershell -ExecutionPolicy Bypass -File Prepare-KvmMigration.ps1): it puts the VirtIO
    drivers into the Driver Store, saves and releases the static IPv4, uninstalls the ESXi guest
    tools and shuts the guest down (-NoShutdown leaves that to you). Then migrate it, and do not
    power it on again on ESXi. Without it PegaProx prepares a Windows guest on its own after the
    copy, no login needed."""
    from flask import Response
    from pegaprox.core.v2p_guestprep import script_bytes, SCRIPT_NAME
    resp = Response(script_bytes(), status=200)
    resp.headers['Content-Type'] = 'text/plain; charset=us-ascii'
    resp.headers['Content-Disposition'] = f'attachment; filename="{SCRIPT_NAME}"'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp


# MK Nov 2026 - the login check's own windows, never the shared auth-action ones: its keys
# hold a VM id from the URL, and 4096 made-up ones would push the password change and 2FA
# windows of the same window size out. Per caller across all guests first (a domain account
# is not sprayed over every guest), per caller and guest once ESXi knows the guest.
_guest_login_callers = SlidingWindow(limit=15, window=300, max_keys=4096, name='esxi-guest-login-caller')
_guest_login_guests = SlidingWindow(limit=5, window=300, max_keys=4096, name='esxi-guest-login-guest')


@bp.route('/api/vmware/<vmware_id>/vms/<vm_id>/guest-login', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def check_vmware_guest_login(vmware_id, vm_id):
    """Check a Windows login for the preparation in the running guest

    MK Nov 2026 - body {guest_user, guest_password}. One login attempt in the guest over the ESXi
    guest operations per call (never retried: a wrong password tried in a loop locks the
    account), at most 15 per caller in 5 minutes over all guests and 5 per caller and guest
    (429). Answers {ok, tools_running, windows, error}. Nothing of the body is stored, logged
    or audited."""
    from pegaprox.core import v2p_guestprep
    from pegaprox.core.esxi_guestops import GuestSession, GuestOpsError
    if vmware_id not in vmware_managers:
        return jsonify({'error': 'ESXi server not found'}), 404
    user = build_authz_user(request.session.get('user', ''), request.session)
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.migrate'):
        return jsonify({'error': 'Permission denied: You do not have access to this VM'}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'A JSON object is expected'}), 400
    if not (data.get('guest_user') and data.get('guest_password')):
        return jsonify({'error': 'guest_user and guest_password are required'}), 400
    err = _winprep_refusal({'guest_user': data.get('guest_user'), 'guest_password': data.get('guest_password')})
    if err:
        return jsonify({'error': err}), 400
    who = request.session.get('user', '') or '?'
    if not _guest_login_callers.allow(who):
        return jsonify({'error': 'Too many login checks, wait a few minutes'}), 429
    mgr = vmware_managers[vmware_id]
    mgr.ensure_connected()
    gs = v2p_guestprep.guest_state(mgr, vm_id)
    out = {'ok': False, 'tools_running': bool(gs.get('tools_running')),
           'windows': (gs.get('family') == 'windowsGuest') if gs.get('family') else None, 'error': None}
    why = v2p_guestprep.state_refusal(gs)
    if why:
        out['error'] = why
        return jsonify(out)
    # a guest ESXi answered for: the key space is the caller's real guests
    if not _guest_login_guests.allow(f'{who}:{vmware_id}:{vm_id}'):
        return jsonify({'error': 'Too many login checks for this guest, wait a few minutes'}), 429
    sess = GuestSession(mgr, vm_id, data['guest_user'], data['guest_password'])
    try:
        sess.validate()
        out['ok'] = True
    except GuestOpsError as e:
        out['error'] = e.msg
    finally:
        sess.close()
    return jsonify(out)


def _migrate_body_refusal(vmware_id, data, dry_run):
    """(error, None) for the first thing wrong with the shape of a migrate body, else
    (None, parse_migration_options of it). Sets data['esxi_host'] to the registered host.
    The single migrate route and each guest of a bulk run (at the submit and again right
    before it starts) go through this."""
    # MK May 2026 (#481 port) - target_storage flows into `pvesm` calls on the
    # PVE node. Validate at the api boundary before the shell touches it.
    from pegaprox.utils.sanitization import validate_storage_name, validate_esxi_path_component
    if not validate_storage_name(data['target_storage']):
        return 'Invalid target_storage name. Must be alphanumeric with hyphens, underscores, or dots only.', None

    # NS 2026-06-05: esxi_datastore / esxi_vm_dir are user-supplied
    # and get interpolated into root shell commands on the PVE node. Empty = let
    # the task auto-detect from the VM config; non-empty must be a safe single
    # component name (no slashes, no shell metacharacters). Reject at the door.
    for _f in ('esxi_datastore', 'esxi_vm_dir'):
        _v = (data.get(_f) or '').strip()
        if _v and not validate_esxi_path_component(_v):
            return f'Invalid {_f}: only letters, digits, space and ._()+- are allowed (single name, no path).', None

    # #598 - aio_mode is interpolated into the root `qm set` / conf line that
    # attaches the migrated disk. V2PMigrationTask.__init__ already whitelists it,
    # but reject a bad value at the door too (matches the boundary-validation
    # style above); empty = unset = PVE default.
    _aio = (data.get('aio_mode') or '').strip().lower()
    if _aio and _aio not in ('threads', 'native', 'io_uring'):
        return 'Invalid aio_mode: must be threads, native or io_uring.', None
    # JB Nov 2026 (#1270) - the cache mode reaches the same line. A guest whose disk has native
    # AIO without O_DIRECT does not start, so that pair is refused here and not found out later
    _cache = str(data.get('disk_cache') or '').strip().lower()
    if _cache and _cache not in DISK_CACHE_MODES:
        return f"Invalid disk_cache: must be one of {', '.join(DISK_CACHE_MODES)}.", None
    if _aio == 'native' and _cache not in ('',) + DIRECT_CACHE_MODES:
        return 'aio_mode native needs the cache mode none or directsync.', None

    # the tenant quota sizes the new guest from these. A value that is no number made that
    # count raise, the quota gate takes a failed count as "could not check" and lets the
    # migration through, and the create still got the value ([64] goes out as 64)
    for _f, _hi in (('sockets', 4096), ('cores_per_socket', 4096), ('memory', 16 * 1024 * 1024)):
        if data.get(_f) in (None, ''):
            continue
        try:
            _v2p._whole_number(data[_f], 0, _hi, _f)
        except ValueError as e:
            return str(e), None
    # the VMID the guest lands under; whether it is free is asked later
    from pegaprox.core import target_vmid as _tvmid
    try:
        _tvmid.parse(data.get('target_vmid'))
    except ValueError as e:
        return str(e), None

    # NS Oct 2026 (#1090) - root loop-mounts this on the node; empty = the default places.
    # MK Nov 2026 - a Windows guest takes it without install_virtio_drivers too (the preset)
    from pegaprox.utils.sanitization import validate_node_iso_path
    _iso = data.get('virtio_iso_path')
    if _iso not in (None, '') and not validate_node_iso_path(_iso):
        return 'Invalid virtio_iso_path: an absolute path to an .iso file on the node', None
    _wp_err = _winprep_refusal(data)
    if _wp_err:
        return _wp_err, None

    # NS Oct 2026 (#1106) - esxi_host decides which host the PVE node SSHes/sshfs-mounts and
    # reads disks from as root. Left to the caller it could aim the node at any SSH server,
    # one serving a crafted descriptor. It is the configured server's host; pin it there.
    # The wizard never sends it (it defaults to the server host); an explicit mismatch is refused.
    _reg_host = vmware_managers[vmware_id].host
    _req_host = data.get('esxi_host')
    if _req_host not in (None, '') and str(_req_host).strip().lower() != str(_reg_host or '').lower():
        return 'esxi_host must match the registered ESXi server', None
    # the task reads data['esxi_host'] as is, so hand it the registered value, not the
    # spelling that passed the compare
    data['esxi_host'] = _reg_host
    # NS Oct 2026 - user and host go onto the local sshpass/ssh argv and into the ssh, scp,
    # sshfs and ssh_config text the node runs as root. A user starting with '-' is an
    # OpenSSH option there, a newline in the host a new ssh_config line.
    from pegaprox.utils.sanitization import validate_ssh_user, validate_host_address
    _esxi_user = data.get('esxi_user')
    if _esxi_user not in (None, '') and not validate_ssh_user(_esxi_user):
        return 'Invalid esxi_user: letters, digits and ._- only, not starting with - or .', None
    if not validate_host_address(data['esxi_host']):
        return 'Invalid esxi_host: a host name or an IP address', None

    # MK Oct 2026 - the per NIC / per disk choices and the verify mode, parsed at the door. The
    # names in them are checked against the target node in _v2p_plan; a bridge also has to look
    # like one, since it lands on the guest's net line
    try:
        _opts = _v2p.parse_migration_options(data)
    except ValueError as e:
        return f'Invalid migration options: {e}', None
    # the list nic_map counts and the plan makes a row of each: a guest has net0 to net31,
    # a longer list is only a way to make this process build millions of rows
    _sel = data.get('selected_nics')
    if isinstance(_sel, list) and len(_sel) > _v2p.NIC_MAP_MAX:
        return f'selected_nics has more than {_v2p.NIC_MAP_MAX} entries', None
    # its model and MAC go onto the guest's net line as they are: 'virtio,trunks=1-4094' would
    # open options there that no check of this route ever saw
    _sel_err = _v2p.selected_nics_refusal(_sel)
    if _sel_err:
        return _sel_err, None
    _bridge = data.get('network_bridge')
    if _bridge not in (None, '') and not _v2p.valid_bridge_name(_bridge):
        return 'Invalid network_bridge: a bridge or VNet name, letters, digits and ._- only', None
    # MK Nov 2026 - a mode name this code does not know ran the pre-sync flow of Auto, which
    # falls back to Live Mirror; say so instead of running something else than was asked for
    if data.get('transfer_mode') not in (None, '') and data.get('transfer_mode') not in _BULK_MODES:
        return f"transfer_mode is one of {', '.join(_BULK_MODES)}", None
    _full_refusal = _v2p.full_verify_refusal(data.get('transfer_mode', 'auto')) \
        if _opts['verify'] == 'full' else None
    if _full_refusal and not dry_run:
        return _full_refusal, None
    # MK Nov 2026 (#1252) - false: nothing is installed on the target node, and a run that
    # misses a package it needs stops before it changes anything
    if 'allow_package_install' in data and not isinstance(data['allow_package_install'], bool):
        return 'allow_package_install must be true or false', None
    return None, _opts


_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f]')


def _winprep_refusal(data):
    """MK Nov 2026 - the shape of the Windows preparation fields, None when it is fine"""
    if 'guest_prep' in data and data['guest_prep'] is not None and not isinstance(data['guest_prep'], bool):
        return 'guest_prep must be true or false'
    if data.get('two_stage_boot') is not None and not isinstance(data['two_stage_boot'], bool):
        return 'two_stage_boot must be true, false or null'
    u = data.get('guest_user')
    if u not in (None, '') and (not isinstance(u, str) or len(u) > 256 or _CONTROL_CHARS.search(u)):
        return 'guest_user is a Windows account name of at most 256 characters, without control characters'
    pw = data.get('guest_password')
    if pw not in (None, '') and (not isinstance(pw, str) or len(pw) > 1024 or '\x00' in pw):
        return 'guest_password is a text of at most 1024 characters'
    from pegaprox.core import v2p_twostage
    return v2p_twostage.refusal(data)


def _winprep_views(mgr, vm_id, vm_detail, data, plan):
    """plan['windows_prep'], plan['two_stage'] and, with guest_prep, plan['guest_prep'] of a
    dry run or bulk check; their errors and warnings go into the plan's lists"""
    from pegaprox.core import v2p_twostage, v2p_winprep
    vd = (vm_detail.get('data') or {}) if isinstance(vm_detail, dict) else {}
    win = v2p_winprep.is_windows(data.get('ostype') or '', vd.get('guest_id'), vd.get('guest_OS'))
    mode = data.get('transfer_mode') or 'auto'
    offline = win and data.get('install_virtio_drivers') is not False and mode != 'sshfs_boot'
    gp = data.get('guest_prep') is True
    ts = v2p_twostage.plan_view(vm_detail, data, kept_disks=sum(1 for d in plan.get('disks') or [] if not d.get('skip')),
                                drivers=offline or gp)
    virtio_hw = bool(ts['on']) or gp
    wp = {'windows': win, 'on': bool(offline or gp), 'offline': bool(offline), 'guest_prep': gp,
          'scsihw': ts['scsihw'] if win else None,
          'net_driver': ('virtio' if virtio_hw and data.get('net_driver') in (None, '', 'auto') else
                         (data.get('net_driver') or 'auto')) if win else None,
          'iso': None, 'errors': [], 'warnings': []}
    if win and not wp['on']:
        wp['warnings'].append('Windows guest without the automatic preparation: '
                              + ('Live Mirror boots it before anything can be staged' if mode == 'sshfs_boot'
                                 else 'install_virtio_drivers is off')
                              + '; it keeps the disk controller and NICs of the source')
    if not win and (gp or data.get('two_stage_boot') is True):
        wp['warnings'].append('The guest does not look like Windows: the Windows preparation does not run')
    # MK Nov 2026 - stage 1 runs after the clone: Live Clone copies what it writes (drivers and
    # guest tools, several GB) at the switchover, in the downtime (34 min against 9 with
    # Snapshot-Iterative in the lab), Auto takes Snapshot-Iterative for it
    if win and gp and mode == 'vmkfstools_clone':
        wp['warnings'].append('Live Clone copies what the preparation in the guest writes (drivers and guest tools, '
                              'several GB) at the switchover, in the downtime: Snapshot-Iterative or Auto copy it '
                              'while the source VM still runs')
    plan['windows_prep'], plan['two_stage'] = wp, ts
    # MK Nov 2026 - not for a guest that is no Windows: its check warned that it falls back to the
    # offline preparation, which does not run for it either, and the bulk list tagged its tools
    if gp and win:
        from pegaprox.core import v2p_guestprep
        plan['guest_prep'] = v2p_guestprep.plan_view(mgr, vm_id, vm_detail, data)
    for part in (ts, plan.get('guest_prep') or {}):
        for e in part.get('errors') or []:
            plan['errors'].append(e)
            plan['ok'] = False
        plan['warnings'] += [w for w in part.get('warnings') or [] if w not in plan['warnings']]
    plan['warnings'] += [w for w in wp['warnings'] if w not in plan['warnings']]


def _winprep_audit(vm_detail, data):
    """The words the audit line of a migration start gets for the Windows preparation, never
    the account"""
    from pegaprox.core import v2p_twostage, v2p_winprep
    vd = (vm_detail.get('data') or {}) if isinstance(vm_detail, dict) else {}
    if not v2p_winprep.is_windows(data.get('ostype') or '', vd.get('guest_id'), vd.get('guest_OS')):
        return ''
    mode = data.get('transfer_mode') or 'auto'
    offline = data.get('install_virtio_drivers') is not False and mode != 'sshfs_boot'
    gp = data.get('guest_prep') is True
    out = ''
    if offline:
        out += ', Windows prepared automatically'
    if gp:
        out += ', guest preparation'
    d = v2p_twostage.decide(data, windows=True, transfer_mode=mode, disk_bus_req=data.get('disk_bus'),
                            scsihw_req=data.get('scsihw'), agent=data.get('agent', True) is not False,
                            drivers=offline or gp)
    if d['on']:
        out += ', two-stage boot'
    return out


def _v2p_node_packages(data, plan=None):
    """(report, error, warning): what the options of a migrate request may install on its
    target node and which of it the node has, with one SSH call to that one node
    (v2p_packages.package_report); the error when the run would stop on it, the warning
    when the node could not be asked. The plan, when there is one, tells the storage type
    of the boot disk; a bulk check hands in the disks of all its guests, and one boot disk
    on rbd among them is enough for the rbd CLI."""
    from pegaprox.core import v2p_packages as pk
    # MK Nov 2026 - a Windows guest gets the injection unless it was turned off (the preset),
    # and a virtio-win.iso the node may not have yet
    wp = (plan or {}).get('windows_prep') or {}
    windows = bool(wp.get('windows'))
    mirror = (data.get('transfer_mode') or 'auto') == 'sshfs_boot'
    virtio = bool(data.get('install_virtio_drivers')) or (windows and data.get('install_virtio_drivers') is None
                                                          and not mirror)
    guest_prep = data.get('guest_prep') is True
    boot_type = ''
    if virtio and plan:
        types_of = {s.get('storage'): str(s.get('type') or '').lower()
                    for s in (plan.get('available') or {}).get('storages') or []}
        boots = [types_of.get(d.get('storage') or data.get('target_storage'), '')
                 for d in plan.get('disks') or [] if d.get('boot')] \
            or [types_of.get(data.get('target_storage'), '')]
        boot_type = 'rbd' if 'rbd' in boots else boots[0]
    pkplan = pk.package_plan(data.get('transfer_mode') or 'auto', virtio, boot_type, guest_prep=guest_prep,
                             virtio_iso=(virtio or guest_prep) and not data.get('virtio_iso_path'))
    report = pk.package_report(_v2p._pve_node_exec, cluster_managers.get(data['target_cluster']),
                               str(data['target_node']), pkplan,
                               allow_install=data.get('allow_package_install', True) is not False)
    err, warn = pk.report_problem(report)
    iso = next((it for it in report['items'] if it['package'] == 'virtio-win.iso'), None)
    if iso is not None and wp:
        wp.setdefault('warnings', [])
        wp['iso'] = 'present' if iso['installed'] else ('missing' if iso['installed'] is False else None)
        if iso['installed'] is False:
            if report['allow_install']:
                wp['warnings'].append(f"virtio-win.iso is not on node {data['target_node']}: the migration downloads "
                                      f"it from fedorapeople.org into {pk.VIRTIO_ISO_DIR} first")
            else:
                wp['warnings'].append(f"virtio-win.iso is not on node {data['target_node']} and this migration may not "
                                      f"download it: the Windows guest keeps the disk controller and NICs of the "
                                      f"source, without the automatic preparation")
        if plan is not None and isinstance(plan.get('warnings'), list):
            plan['warnings'] += [w for w in wp['warnings'] if w not in plan['warnings']]
    return report, err, warn


def _v2p_footprint(vm_detail, data, skipped):
    """{cores, memory_gb, disk_gb} of the guest a migration lands on the target, sized as
    core/v2p.py builds it: the request's sockets, cores and memory over what ESXi reports,
    without the disks left behind."""
    vd = (vm_detail.get('data') or {}) if isinstance(vm_detail, dict) else {}
    cpu = vd.get('cpu') or {}
    sockets = int(data.get('sockets') or cpu.get('sockets') or 0)
    per = int(data.get('cores_per_socket') or cpu.get('cores_per_socket') or 0)
    cores = sockets * per if sockets and per else int(cpu.get('count') or 1)
    mem_mb = float(data.get('memory') or (vd.get('memory') or {}).get('size_MiB') or 0)
    disks = vd.get('disks') or {}
    # a disk left behind does not land on the target
    disk_b = sum(float((d or {}).get('capacity') or 0) for i, d in
                 enumerate(disks.values() if isinstance(disks, dict) else disks) if i not in skipped)
    return {'cores': cores, 'memory_gb': mem_mb / 1024.0, 'disk_gb': disk_b / 1024.0 ** 3}


def _v2p_plan(mgr, vm_id, data, opts, vm_detail, inv=None, exp=None):
    """(plan, None) or (None, error response) for a migrate request: its disks, NICs and
    choices checked against what the target node offers right now. A bulk run hands in the
    node's inventory it read once for all its guests, and the disk list it read already."""
    pve = cluster_managers.get(data['target_cluster'])
    node = str(data.get('target_node') or '')
    if node not in (getattr(pve, 'nodes', None) or {}):
        return None, (jsonify({'error': f'{node[:64]!r} is not a node of the target cluster'}), 400)
    if exp is None:
        exp = mgr.get_vm_disks_for_export(vm_id)
    if not isinstance(exp, dict) or 'error' in exp:
        return None, (jsonify({'error': f"The VM's disks could not be read: "
                                        f"{(exp or {}).get('error') if isinstance(exp, dict) else exp}"}), 502)
    disks = (exp.get('data') or {}).get('disks') or []
    vd = (vm_detail.get('data') or {}) if isinstance(vm_detail, dict) else {}
    if opts.get('nic_map') is not None and data.get('selected_nics') not in (None, []) \
            and not isinstance(data.get('selected_nics'), list):
        # nic_map counts the entries of this list; anything else has no order to count
        return None, (jsonify({'error': 'selected_nics must be a list when nic_map is given'}), 400)
    nics = data.get('selected_nics') if isinstance(data.get('selected_nics'), list) else (vd.get('nics') or [])
    if inv is None:
        try:
            inv = _v2p.read_target_inventory(pve, node)
        except RuntimeError as e:
            return None, (jsonify({'error': f'The target node could not be checked: {e}'}), 502)
    hw = vd.get('hardware') or {}
    bios = str(data.get('bios') or 'auto')
    needs_efi = bios == 'ovmf' or (bios == 'auto' and hw.get('firmware') == 'efi')
    tpm = data.get('tpm_enabled')
    needs_tpm = bool(hw.get('has_tpm')) if tpm is None else bool(tpm)
    plan = _v2p.resolve_migration_plan(
        inv, disks, nics, opts, data['target_storage'], data.get('network_bridge', 'vmbr0'),
        net_vlan_tag=data.get('net_vlan_tag'), transfer_mode=data.get('transfer_mode', 'auto'),
        needs_efi=needs_efi, needs_tpm=needs_tpm)
    # MK Nov 2026 - what keeps Snapshot-Iterative from running (change tracking the VM does not
    # support, a raw or independent disk, snapshots), said in the review and not at the start.
    # The wizard picks it for the in-guest Windows preparation
    if data.get('transfer_mode') == 'snapshot_zero' and plan['ok']:
        keys = {str((disks[r['index']] or {}).get('key')) for r in plan.get('disks') or []
                if not r.get('skip') and r['index'] < len(disks) and isinstance(disks[r['index']], dict)}
        why = _v2p._snapshot_iterative_refusal(mgr, vm_id, disks, keys)
        if why:
            plan['errors'].append(why.replace(' Nothing was copied, the source VM was not touched.', ''))
            plan['ok'] = False
    # MK Nov 2026 (#1253) - the wizard's review and each guest of a bulk check list these
    fw_warn = _v2p.firmware_mismatch(vd, bios)
    if fw_warn:
        plan['warnings'].append(fw_warn)
    # MK Nov 2026 - the Windows preset, the two-stage boot and the in-guest preparation
    _winprep_views(mgr, vm_id, vm_detail, data, plan)
    plan['target'] = {'cluster': data['target_cluster'], 'node': node, 'storage': data['target_storage']}
    plan['available'] = {
        'bridges': [{'name': n, 'kind': k} for n, k in sorted(inv['bridges'].items())],
        'storages': [{'storage': n, 'type': st['type'], 'avail_bytes': st['avail']}
                     for n, st in sorted(inv['storages'].items())
                     if st['active'] and 'images' in st['content']],
    }
    return plan, None


def _vmid_pick(user, cluster_id, raw, mine=()):
    """(pick, refusal) of the VMID a migration of `user` lands under on the cluster. pick:
    {vmid, start, end, strict}, the chosen id (None: the next free one) and the caller's
    tenant range the task keeps to. refusal: (status, message) or None. A chosen id is
    asked of the target cluster here; mine are holders of it that are this request's own.
    MK Nov 2026 (#1339)"""
    from pegaprox.core import target_vmid as tvmid
    from pegaprox.utils.rbac import TenantRangeUnknown
    vmid = tvmid.parse(raw)
    try:
        start, end, strict = tvmid.caller_range(user)
    except TenantRangeUnknown:
        # not "no range": nothing the task could keep to is known, so nothing starts
        return ({'vmid': vmid, 'start': 0, 'end': 0, 'strict': True},
                (403, 'Cannot verify the tenant VMID range right now - check the server logs'))
    pick = {'vmid': vmid, 'start': start, 'end': end, 'strict': strict}
    if vmid is None:
        return pick, None
    return pick, tvmid.refusal(user, cluster_id, cluster_managers[cluster_id], vmid, mine)


def _vmid_view(pick):
    """What a dry run shows of it: the chosen id, or the range the next free one comes from"""
    return {'target_vmid': pick['vmid'],
            'vmid_range': [pick['start'], pick['end']] if pick['start'] else None}


def _bulk_vmid_check(res, user, vmware_id, settings, vms):
    """The chosen VMID of each guest of a bulk check asked of the target cluster, a few at a
    time, into the guest's errors; res gets the tenant range the others are picked from."""
    from pegaprox.core import target_vmid as tvmid
    from pegaprox.utils.concurrent import run_per_node
    cid = settings['target_cluster']
    chosen = {vm_id: maps['target_vmid'] for vm_id, maps in vms if maps.get('target_vmid')}
    pick, err = _vmid_pick(user, cid, None)
    res.update(_vmid_view(pick))
    if err:
        res['errors'].append(err[1])
    pve = cluster_managers[cid]

    def _ask(vm_id):
        return ('asked', tvmid.refusal(user, cid, pve, chosen[vm_id]))
    # a guest the caller may not migrate gets no question asked about it
    asks = {vm_id: _ask for vm_id in chosen
            if not err and not _bulk_vm_refusal(user, vmware_id, vm_id, settings)}
    got = run_per_node(asks, max_concurrent=_BULK_READERS, timeout=60) if asks else {}
    for it in res['items']:
        it['target_vmid'] = chosen.get(it['vm_id'])
        if it['vm_id'] in asks:
            answer = got.get(it['vm_id'])
            # a question that broke off or timed out cleared nothing
            why = answer[1] if isinstance(answer, tuple) else \
                (502, f"The target cluster could not say whether VMID {chosen[it['vm_id']]} is free")
            if why:
                it['errors'].append(why[1])
        it['ok'] = not it['errors']
    res['ok'] = not res['errors'] and all(it['ok'] for it in res['items'])


def _bulk_vmid_alive(run, item):
    """alive() of a run's hold on the chosen VMID of one of its guests: while the run still has
    that guest to start, and a short while before the run is registered at all"""
    from pegaprox.core import esxi_bulk as ebulk
    since = time.time()

    def alive():
        if ebulk.get(run.id) is not run:
            return time.time() - since < 5
        return run.state == 'running' and item['state'] in (ebulk.WAITING, ebulk.STARTING)
    return alive


def _migration_reachable(t):
    # NS Jul 2026 (CodeAnt IDOR) — a caller may see a migration only if they can reach one of the
    # clusters it touches (source or target). Tasks with no determinable cluster are shown.
    cids = [c for c in (getattr(t, 'target_cluster', None), getattr(t, 'source_cluster', None)) if c]
    if cids and not any(check_cluster_access(c)[0] for c in cids):
        return False
    # sec (audit): reaching the TARGET cluster was the whole gate, so anyone who could migrate
    # into a shared target could read another tenant's V2P run — and drive its cutover. The XHM
    # twin (_xhm_reachable) already checks the source VM; mirror it on the ESXi source here.
    vmw, vid = getattr(t, 'vmware_id', None), getattr(t, 'vm_id', None)
    if vmw and vid:
        try:
            _u = build_authz_user(request.session.get('user', ''), request.session)
            return user_can_access_vmware_vm(_u, vmw, str(vid), 'vmware.vm.migrate')
        except Exception:
            return False
    return True


def _reach_checker():
    """_migration_reachable for the stored runs of one request (#1278): the same two questions,
    the cluster asked once per cluster and the guest once per guest, the caller built once. A
    stored run without its cluster or its guest is left to an admin.
    MK Nov 2026"""
    clusters, guests, me = {}, {}, []

    def visible(target_cluster, vmware_id, vm_id):
        if not (target_cluster and vmware_id and vm_id):
            return caller_acts_as_admin()
        if target_cluster not in clusters:
            clusters[target_cluster] = bool(check_cluster_access(target_cluster)[0])
        if not clusters[target_cluster]:
            return False
        key = (vmware_id, str(vm_id))
        if key not in guests:
            try:
                if not me:
                    me.append(build_authz_user(request.session.get('user', ''), request.session))
                guests[key] = bool(user_can_access_vmware_vm(me[0], vmware_id, str(vm_id),
                                                             'vmware.vm.migrate'))
            except Exception:
                guests[key] = False
        return guests[key]
    return visible


def _v2p_history_ready():
    """Before the migrations are read, and when a job starts (#1278): rows a stop of PegaProx cut
    off read as interrupted (once per process), and runs that ended a while ago leave the
    registry for the table."""
    from pegaprox.core import v2p_history
    try:
        with _migration_lock_v2p:
            live = set(_vmware_migrations)
        v2p_history.sweep_once(live)
        v2p_history.evict(_vmware_migrations, _migration_lock_v2p)
    except Exception as e:
        logging.warning(f"[V2P] migration history housekeeping failed: {e}")


def _stored_migration(mid):
    """The stored row of a run this process does not hold, when the caller may see it, else None"""
    from pegaprox.core import v2p_history
    _v2p_history_ready()
    try:
        row = v2p_history.load(mid)
    except Exception as e:
        logging.warning(f"[V2P] stored migration {_sl(str(mid)[:64])} could not be read: {e}")
        return None
    if row is None or not _reach_checker()(row.get('target_cluster'), row.get('vmware_id'), row.get('vm_id')):
        return None
    return row


# NS Aug 2026 (#654) — the route + auth decorators were stuck on the _migration_reachable helper
# above (a copy-paste slip when the IDOR helper was inserted between them and this handler), so
# GET /api/vmware/migrations called the helper with no args -> TypeError 500 and ESXi migration
# blew up immediately, while the real handler below was never routed. Put the decorators back here.
@bp.route('/api/vmware/migrations', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def list_vmware_migrations():
    """List all active and recent migrations

    The runs this instance holds (running, or ended a few minutes ago), newest first, then a
    page of the stored ones the caller may see, newest first. Query: limit (stored runs, default
    50, at most 500, 0 for none) and offset (stored runs to skip). The header X-History-More: 1
    says older ones follow. A stored run carries its fields as of its last write, an empty log
    and log_total; its whole log is at /api/vmware/migrations/{mid}/log.
    """
    # MK Nov 2026 (#1278) - stored runs and the page; the answer stays a list for old callers
    from pegaprox.core import v2p_history
    try:
        limit = int(request.args.get('limit', v2p_history.PAGE_DEFAULT))
        offset = int(request.args.get('offset', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'limit and offset are whole numbers'}), 400
    if not 0 <= limit <= v2p_history.PAGE_MAX or offset < 0:
        return jsonify({'error': f'limit is 0 to {v2p_history.PAGE_MAX}, offset 0 or more'}), 400
    _v2p_history_ready()
    with _migration_lock_v2p:
        live = list(_vmware_migrations.items())
    out = [t.to_dict() for _, t in reversed(live) if _migration_reachable(t)]
    more = False
    if limit:
        try:
            rows, more = v2p_history.page({mid for mid, _ in live}, _reach_checker(), offset, limit)
            out += [v2p_history.as_dict(r, with_log=False) for r in rows]
        except Exception as e:
            logging.warning(f"[V2P] the stored migrations could not be read: {e}")
    resp = jsonify(out)
    resp.headers['X-History-More'] = '1' if more else '0'
    return resp


@bp.route('/api/vmware/migrations/<mid>', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_migration_status(mid):
    """Get detailed status of a specific migration, a stored one too"""
    task = _vmware_migrations.get(mid)
    if task is None:
        row = _stored_migration(mid)
        if row is None:
            return jsonify({'error': 'Migration not found'}), 404
        from pegaprox.core import v2p_history
        return jsonify(v2p_history.as_dict(row))
    if not _migration_reachable(task):
        return jsonify({'error': 'Migration not found'}), 404
    return jsonify(task.to_dict())


@bp.route('/api/vmware/migrations/<mid>/log', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_migration_log(mid):
    """The whole log of a migration, running or ended

    Query: offset (the first line wanted, counted from the start of the run; the answer's next
    is where the next read starts) and limit (lines, at most 5000). download=1 answers the whole
    log as a plain-text file instead.

    JSON: {id, offset, lines, next, total, dropped, status, running}. A log over 20000 lines
    keeps its first 2000 and its newest lines; where lines were left out, one line says how
    many. running stays true until the job has written its last line.
    """
    # MK Nov 2026 (#1278)
    from pegaprox.core import v2p_history
    try:
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', v2p_history.READ_MAX_LINES))
    except (TypeError, ValueError):
        return jsonify({'error': 'offset and limit are whole numbers'}), 400
    if offset < 0 or not 1 <= limit <= v2p_history.READ_MAX_LINES:
        return jsonify({'error': f'offset is 0 or more, limit 1 to {v2p_history.READ_MAX_LINES}'}), 400
    task, row = _vmware_migrations.get(mid), None
    if task is not None:
        if not _migration_reachable(task):
            return jsonify({'error': 'Migration not found'}), 404
    else:
        row = _stored_migration(mid)
        if row is None:
            return jsonify({'error': 'Migration not found'}), 404
    try:
        if request.args.get('download') in ('1', 'true'):
            info = task.to_dict() if task is not None else v2p_history.as_dict(row)
            lines = v2p_history.whole_live(task) if task is not None else v2p_history.whole_stored(row)
            return _log_download(mid, info if isinstance(info, dict) else {}, lines)
        got = v2p_history.read_live(task, offset, limit) if task is not None else \
            v2p_history.read_stored(row, offset, limit)
    except Exception as e:
        logging.warning(f"[V2P] log of migration {_sl(str(mid)[:64])} could not be read: {e}")
        return jsonify({'error': 'The log could not be read'}), 500
    return jsonify({'id': mid, 'offset': offset, **got})


def _log_download(mid, info, lines):
    from flask import Response
    safe = lambda v: re.sub(r'[^A-Za-z0-9._-]+', '_', str(v or ''))[:60].strip('._') or 'run'
    # a name from ESXi with a line break in it stays on its header line
    one = lambda k, dflt='?': ' '.join(str(info.get(k) or '').split()) or dflt
    head = [f"# ESXi migration {safe(mid)}: {one('vm_name', one('vm_id'))} "
            f"({one('vmware_id')}/{one('vm_id')}) -> {one('target_cluster')}/{one('target_node')}/"
            f"{one('target_storage')}",
            f"# status {one('status')}, phase {one('phase')}, started {one('started_at')}, "
            f"ended {one('completed_at', '-')}"]
    name = f"esxi-migration-{safe(info.get('vm_name') or info.get('vm_id'))}-{safe(mid)}.log"
    return Response('\n'.join(head + [str(x) for x in lines]) + '\n', mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename="{name}"',
                             'Cache-Control': 'no-store'})


@bp.route('/api/vmware/migrations/<mid>/confirm-cutover', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def confirm_vmware_cutover(mid):
    """#562 — commit the final switchover for a migration that is holding at the
    optional pre-cutover confirmation gate. Only valid while the task is parked in
    'awaiting_confirmation'; the migration thread picks the flag up within ~2s."""
    if mid not in _vmware_migrations:
        return jsonify({'error': 'Migration not found'}), 404
    task = _vmware_migrations[mid]
    if not _migration_reachable(task):
        return jsonify({'error': 'Migration not found'}), 404
    if getattr(task, 'phase', None) != 'awaiting_confirmation':
        return jsonify({'error': 'Migration is not waiting for cutover confirmation',
                        'phase': getattr(task, 'phase', None)}), 409
    # NS Oct 2026 (#984) - on a run started with remove_source this click is what sets the
    # source deletion off, so it asks the same right the start asked for that
    if getattr(task, 'remove_source', False):
        _cu = build_authz_user(request.session.get('user', ''), request.session)
        if not user_can_access_vmware_vm(_cu, task.vmware_id, str(task.vm_id), 'vmware.vm.manage'):
            return jsonify({'error': 'Permission denied: this cutover removes the source guest, '
                                     'which needs vmware.vm.manage on it'}), 403
    task._cutover_confirmed = True
    log_audit(request.session.get('user', 'admin'), 'vmware.migration.cutover_confirmed',
              f"V2P cutover confirmed for {getattr(task, 'vm_name', mid)} (migration {mid})")
    return jsonify({'message': 'Cutover confirmed — switchover proceeding', 'task': task.to_dict()})


@bp.route('/api/vmware/migrations/<mid>/cancel-cutover', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def cancel_vmware_cutover(mid):
    """#562 — abort a migration that is holding at the confirmation gate. The source
    VM is left running (it was never suspended); the migration thread tears down the
    staging mount + migration snapshot and marks the run 'cancelled'. Only valid while
    the task is parked in 'awaiting_confirmation'."""
    if mid not in _vmware_migrations:
        return jsonify({'error': 'Migration not found'}), 404
    task = _vmware_migrations[mid]
    if not _migration_reachable(task):
        return jsonify({'error': 'Migration not found'}), 404
    if getattr(task, 'phase', None) != 'awaiting_confirmation':
        return jsonify({'error': 'Migration is not waiting for cutover confirmation',
                        'phase': getattr(task, 'phase', None)}), 409
    task._cutover_cancelled = True
    log_audit(request.session.get('user', 'admin'), 'vmware.migration.cutover_cancelled',
              f"V2P cutover cancelled for {getattr(task, 'vm_name', mid)} (migration {mid}) — source left running")
    return jsonify({'message': 'Cutover cancelled — source VM left running', 'task': task.to_dict()})


# =============================================================================
# ESXi bulk migration (core/esxi_bulk.py)
#
# MK Oct 2026 - several guests of one ESXi server with one set of target settings and their
# own NIC / disk choices. The submit checks every guest the way a dry run of the single
# migrate route does, against one read of the target node, and refuses the whole request
# with a line per guest when one of them does not fit. The run starts `width` of them at a
# time and asks the same questions again right before each one.

# what a bulk run takes besides the guests. The rest of what the single route reads
# (datastore, VM folder, sizing, NICs) belongs to each guest and comes from ESXi. A key that
# is not here refuses the request instead of being dropped without a word
_BULK_COMMON = ('target_cluster', 'target_node', 'target_storage', 'network_bridge', 'net_vlan_tag',
                'transfer_mode', 'verify', 'start_after', 'remove_source', 'wait_for_confirmation',
                'confirmation_timeout', 'esxi_user', 'preserve_mac', 'bios', 'disk_format',
                'allow_package_install',
                # MK Nov 2026 - the Windows preparation (two_stage_boot may be null: the rule)
                'guest_prep', 'two_stage_boot', 'install_virtio_drivers', 'virtio_iso_path', 'guest_user')
_BULK_KEYS = frozenset(_BULK_COMMON + ('vms', 'width', 'dry_run', 'esxi_password', 'guest_password'))
_BULK_FLAGS = ('start_after', 'remove_source', 'wait_for_confirmation', 'preserve_mac', 'allow_package_install',
               'guest_prep', 'install_virtio_drivers')
_BULK_MODES = ('vmkfstools_clone', 'auto', 'sshfs_boot', 'snapshot_zero', 'offline')
# what ESXi calls a guest: vm-42 over REST, a plain number on a lone host over SOAP
_ESXI_VM_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
# the submit reads two things per guest from ESXi, a few guests at a time
_BULK_READERS = 5
_BULK_READ_SECONDS = 300


def _v2p_task(mid):
    return _vmware_migrations.get(mid) if isinstance(mid, str) else None


def _v2p_running(vmware_id, vm_id):
    """Whether a migration of this guest runs in this process"""
    with _migration_lock_v2p:
        tasks = list(_vmware_migrations.values())
    return any(getattr(t, 'vmware_id', None) == vmware_id and str(getattr(t, 'vm_id', '')) == str(vm_id)
               and getattr(t, 'status', '') == 'running' for t in tasks)


def _guest_busy(vmware_id, vm_id, have=None, tasks=True):
    """Why this guest cannot start another migration now, None when it can. `have` is who
    holds it, when the caller asked already; `tasks` also counts a migration of it in this
    process that says it runs (what a bulk run always asked)."""
    from pegaprox.core import esxi_bulk as ebulk
    have = have if have is not None else ebulk.holder(vmware_id, vm_id)
    if have and have.startswith('bulk:'):
        return 'Another bulk migration has this guest already'
    if have or (tasks and _v2p_running(vmware_id, vm_id)):
        return 'A migration of this guest is running'
    return None


def _run_held(task, holder):
    """The migration job of one guest. However it ends, the guest is free for another job
    once it returns."""
    from pegaprox.core import esxi_bulk as ebulk
    from pegaprox.core import v2p_history
    try:
        # MK Nov 2026 (#1278) - its row is written as the job starts and once more when it returns
        _v2p_history_ready()
        v2p_history.track(task)
        _run_v2p_migration(task)
    finally:
        ebulk.let_go(task.vmware_id, task.vm_id, holder)
        v2p_history.finish(task)


def _never_ran(mid):
    # a task registered for a job that never started must not count as running: the quota
    # hold and the start checks of the guest ask its status
    with _migration_lock_v2p:
        t = _vmware_migrations.get(mid)
    if t is not None and getattr(t, 'status', '') == 'running':
        t.status, t.phase = 'failed', 'failed'
        t.error = 'The migration could not be started'
        # MK Nov 2026 - no job writes its row or lets it leave the registry, so both happen here.
        # Runs in a finally before the guest is let go: it must not raise
        try:
            from datetime import datetime
            from pegaprox.core import v2p_history
            if not getattr(t, 'completed_at', None):
                t.completed_at = datetime.now()
            v2p_history.track(t)
            v2p_history.finish(t)
        except Exception as e:
            logging.warning(f"[V2P] migration {_sl(str(mid)[:64])} that never started was not saved: {e}")


def _answer_error(resp, default='The check failed'):
    """The error text of a (response, status) a helper answered with"""
    try:
        return str((resp[0].get_json() or {}).get('error') or default)
    except Exception:
        return default


def _bulk_vm_refusal(user, vmware_id, vm_id, settings):
    """Why `user` may not migrate this guest as the run's settings say, None when they may"""
    if not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.migrate'):
        return 'Permission denied: vmware.vm.migrate'
    if settings.get('remove_source') and not user_can_access_vmware_vm(user, vmware_id, vm_id, 'vmware.vm.manage'):
        return 'Permission denied: removing the source guest needs vmware.vm.manage on it'
    return None


def _bulk_vms(raw):
    """[(vm_id, {nic_map, disk_map, target_vmid})] of a bulk request. Raises ValueError."""
    from pegaprox.core import esxi_bulk as ebulk
    from pegaprox.core import target_vmid as tvmid
    if not isinstance(raw, list) or not 1 <= len(raw) <= ebulk.ITEMS_MAX:
        raise ValueError(f'vms is a list of 1 to {ebulk.ITEMS_MAX} guests')
    out, seen = [], set()
    vmids = {}
    for row in raw:
        if isinstance(row, str):
            row = {'vm_id': row}
        if not isinstance(row, dict):
            raise ValueError('every vms entry is a VM id or {vm_id, nic_map, disk_map}')
        # a guest's own VMID; one run never gives the same one twice
        vmid = tvmid.parse(row.get('target_vmid'), 'vms: target_vmid')
        if vmid is not None and vmid in vmids:
            raise ValueError(f"vms gives VMID {vmid} to {vmids[vmid]} and {str(row.get('vm_id'))[:64]}")
        if vmid is not None:
            vmids[vmid] = str(row.get('vm_id'))[:64]
        row = {k: v for k, v in row.items() if k not in ('target_vmid', 'guest_user', 'guest_password')}
        extra = sorted(str(k)[:40] for k in row if k not in ('vm_id', 'nic_map', 'disk_map'))
        if extra:
            raise ValueError(f'vms: unknown field {extra[0]!r}')
        vm_id = row.get('vm_id')
        if not isinstance(vm_id, str) or not _ESXI_VM_ID.fullmatch(vm_id):
            raise ValueError('vms holds something that is no ESXi VM id')
        if vm_id in seen:
            raise ValueError(f'vms names {vm_id} twice')
        seen.add(vm_id)
        out.append((vm_id, {k: row[k] for k in ('nic_map', 'disk_map') if row.get(k) not in (None, [])}))
        if vmid is not None:
            out[-1][1]['target_vmid'] = vmid
    return out


def _bulk_guest_logins(raw):
    """{vm_id: {'guest_user', 'guest_password'}} of the guests of a bulk request that bring their
    own Windows login for the in-guest preparation (both or neither). Raises ValueError."""
    out = {}
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict) or ('guest_user' not in row and 'guest_password' not in row):
            continue
        vm_id = str(row.get('vm_id'))[:64]
        user, pw = row.get('guest_user'), row.get('guest_password')
        if user in (None, '') and pw in (None, ''):
            continue
        if not (user and pw):
            raise ValueError(f'vms: {vm_id} needs guest_user and guest_password together')
        err = _winprep_refusal({'guest_user': user, 'guest_password': pw})
        if err:
            raise ValueError(f'vms: {vm_id}: {err}')
        out[vm_id] = {'guest_user': user, 'guest_password': pw}
    return out


def _bulk_settings(vmware_id, data, dry_run):
    """(settings, None) of the part every guest of a bulk request shares, (None, error) when
    its shape is wrong. The checks of the single route, and a few of its own: a transfer
    mode or VLAN the task would quietly ignore is refused here."""
    s = {k: data[k] for k in _BULK_COMMON if k in data}
    for f in ('target_cluster', 'target_node', 'target_storage'):
        if not isinstance(s.get(f), str) or not s[f]:
            return None, f'{f} is required'
    from pegaprox.utils.sanitization import validate_hostname
    if not validate_hostname(s['target_node']):
        return None, 'target_node is a node name'
    if s.setdefault('transfer_mode', 'auto') not in _BULK_MODES:
        return None, f"transfer_mode is one of {', '.join(_BULK_MODES)}"
    for f in _BULK_FLAGS:
        if f in s and not isinstance(s[f], bool):
            return None, f'{f} must be true or false'
    if s.get('bios', 'auto') not in ('auto', 'seabios', 'ovmf'):
        return None, 'bios is auto, seabios or ovmf'
    if s.get('disk_format', 'raw') not in ('raw', 'qcow2'):
        return None, 'disk_format is raw or qcow2'
    try:
        if s.get('net_vlan_tag') in (None, ''):
            s.pop('net_vlan_tag', None)
        else:
            s['net_vlan_tag'] = _v2p._whole_number(s['net_vlan_tag'], 1, 4094, 'net_vlan_tag')
        if 'confirmation_timeout' in s:
            s['confirmation_timeout'] = _v2p._whole_number(s['confirmation_timeout'], 0, 30 * 86400,
                                                           'confirmation_timeout')
    except ValueError as e:
        return None, str(e)
    err, _opts = _migrate_body_refusal(vmware_id, s, dry_run)
    if err:
        return None, err
    return s, None


def _bulk_check(vmware_id, settings, vms, user):
    """Every guest of a bulk request checked like a dry run of the single migrate route,
    against one read of the target node: ({ok, errors, warnings, items, storages, available,
    target}, None), or (None, error response) when nothing can be checked."""
    from pegaprox.core import esxi_bulk as ebulk
    from pegaprox.api.helpers import tenant_quota_gate
    from pegaprox.utils.concurrent import run_per_node
    mgr = vmware_managers[vmware_id]
    pve = cluster_managers.get(settings['target_cluster'])
    node = settings['target_node']
    if node not in (getattr(pve, 'nodes', None) or {}):
        return None, (jsonify({'error': f'{node[:64]!r} is not a node of the target cluster'}), 400)

    items, todo, permitted = [], {}, 0
    busy = ebulk.busy_vm_ids(vmware_id)
    for vm_id, maps in vms:
        it = {'vm_id': vm_id, 'name': '', 'ok': False, 'errors': [], 'warnings': [], 'nics': [], 'disks': [],
              'storages': [], 'custom_network': 'nic_map' in maps, 'custom_storage': 'disk_map' in maps}
        items.append(it)
        why = _bulk_vm_refusal(user, vmware_id, vm_id, settings)
        if why:
            it['errors'].append(why)
            continue
        permitted += 1
        why = 'Another bulk migration has this guest already' if vm_id in busy else _guest_busy(vmware_id, vm_id)
        if why:
            it['errors'].append(why)
            continue
        body = dict(settings, **maps)
        try:
            opts = _v2p.parse_migration_options(body)
        except ValueError as e:
            it['errors'].append(f'Invalid migration options: {e}')
            continue
        todo[vm_id] = (it, body, opts)
    if not permitted:
        # nothing is read for a caller who may migrate none of them, not even the target node
        return None, (jsonify({'error': 'Permission denied: You do not have access to these VMs',
                               'items': items}), 403)

    inv = {'bridges': {}, 'storages': {}, 'notes': []}
    if todo:
        try:
            inv = _v2p.read_target_inventory(pve, node)
        except RuntimeError as e:
            return None, (jsonify({'error': f'The target node could not be checked: {e}'}), 502)

    def _read(vm_id):
        return mgr.get_vm(vm_id), mgr.get_vm_disks_for_export(vm_id)
    got = {}
    if todo:
        mgr.ensure_connected()
        got = run_per_node({vm_id: _read for vm_id in todo}, max_concurrent=_BULK_READERS,
                           timeout=_BULK_READ_SECONDS)

    needed, guests_on = {}, {}
    for vm_id, (it, body, opts) in todo.items():
        pair = got.get(vm_id)
        detail, exp = pair if isinstance(pair, tuple) and len(pair) == 2 else (None, None)
        if not isinstance(detail, dict) or not isinstance(detail.get('data'), dict):
            why = detail.get('error') if isinstance(detail, dict) else None
            it['errors'].append('The guest could not be read on ESXi' + (f': {str(why)[:200]}' if why else ''))
            continue
        vd = detail['data']
        it['name'] = str(vd.get('name') or vm_id)[:200]
        it['power_state'] = str(vd.get('power_state') or '')
        plan, perr = _v2p_plan(mgr, vm_id, body, opts, detail, inv=inv, exp=exp)
        if perr:
            it['errors'].append(_answer_error(perr))
            continue
        it.update(nics=plan['nics'], disks=plan['disks'], storages=plan['storages'],
                  verify=plan['verify'], transfer_mode=plan['transfer_mode'],
                  windows_prep=plan.get('windows_prep'), two_stage=plan.get('two_stage'),
                  guest_prep=plan.get('guest_prep'))
        it['errors'] += plan['errors']
        it['warnings'] += plan['warnings']
        skipped = {i for i, e in (opts['disk_map'] or {}).items() if e['skip']}
        it['_footprint'] = _v2p_footprint(detail, body, skipped)
        for row in plan['storages']:
            name = row['storage']
            needed[name] = needed.get(name, 0) + int(row.get('needed_bytes') or 0)
            guests_on[name] = guests_on.get(name, 0) + 1

    # each guest fits on its own above; together they may not
    errors, warnings, storages = [], [], []
    for name in sorted(needed):
        st = inv['storages'].get(name) or {}
        row = {'storage': name, 'type': st.get('type', ''), 'needed_bytes': needed[name],
               'avail_bytes': st.get('avail'), 'guests': guests_on[name], 'ok': True}
        storages.append(row)
        if not st or st.get('avail') is None or needed[name] <= st['avail'] or guests_on[name] < 2:
            continue
        msg = (f"storage {name!r} has {st['avail'] / 1024 ** 3:.1f} GiB free, the {guests_on[name]} guests "
               f"placed on it need {needed[name] / 1024 ** 3:.1f} GiB together")
        if st.get('type') in _v2p._SPACE_SOFT_TYPES:
            warnings.append(msg + ' (it may still fit if the pool compresses)')
        else:
            row['ok'] = False
            errors.append(msg + ' - the copy writes every block of a disk')

    def _adds():
        from pegaprox.utils.rbac import landing_adds, quota_tenant
        total = {}
        for it in items:
            if it.get('_footprint') is None:
                continue
            a = landing_adds(quota_tenant(user), settings['target_cluster'], it['_footprint'],
                             source_cluster=vmware_id, source_removed=bool(settings.get('remove_source')))
            for k, v in (a or {}).items():
                total[k] = total.get(k, 0) + v
        return total or None
    qerr, qwarn = tenant_quota_gate(user, f'ESXi bulk migration of {len(items)} guest(s) (check)', _adds,
                                    cluster=settings['target_cluster'])
    if qerr:
        errors.append(_answer_error(qerr, 'Tenant quota exceeded'))
    if qwarn:
        warnings.append(str(qwarn.get('message') or 'Tenant quota exceeded (warning only)'))
    # MK Nov 2026 (#1252) - every guest shares the transfer mode and the node: the packages are
    # asked once for the run, not once per guest. The boot disks of all guests decide rbd.
    packages, perr, pwarn = _v2p_node_packages(settings, {
        'disks': [d for it in items for d in it['disks']],
        'available': {'storages': [{'storage': n, 'type': st.get('type')} for n, st in inv['storages'].items()]},
        # MK Nov 2026 - one Windows guest among them is enough for the injection and the ISO
        'windows_prep': {'windows': any((it.get('windows_prep') or {}).get('windows') for it in items),
                         'warnings': []},
    }) if todo else (None, None, None)
    if perr:
        errors.append(perr)
    if pwarn:
        warnings.append(pwarn)

    for it in items:
        it.pop('_footprint', None)
        it['ok'] = not it['errors']
    return {'ok': not errors and all(it['ok'] for it in items), 'errors': errors, 'warnings': warnings,
            'items': items, 'storages': storages, 'node_packages': packages,
            'target': {'cluster': settings['target_cluster'], 'node': node, 'storage': settings['target_storage']},
            'available': {
                'bridges': [{'name': n, 'kind': k} for n, k in sorted(inv['bridges'].items())],
                'storages': [{'storage': n, 'type': st['type'], 'avail_bytes': st['avail']}
                             for n, st in sorted(inv['storages'].items())
                             if st['active'] and 'images' in st['content']]}}, None


def _bulk_start_item(app, run, item):
    """Start one guest of an ESXi bulk run as a normal migration. core/esxi_bulk.py calls
    this from the run's thread, right before the guest's turn: the account is asked again
    whether it may migrate it, the guest must not be migrating already, and its plan has to
    fit the target node as it is now."""
    from pegaprox.core import esxi_bulk as ebulk
    from pegaprox.core import ha
    from pegaprox.api.helpers import tenant_quota_gate
    s, vm_id = run.settings, item['vm_id']
    with app.app_context():
        user = ebulk.caller(run)
        if not user:
            return {'state': 'skipped', 'note': 'The account that started the run may no longer act '
                                                '(removed, switched off, or its API token revoked)'}
        why = _bulk_vm_refusal(user, run.vmware_id, vm_id, s)
        if why:
            return {'state': 'skipped', 'note': why}
        if caller_is_scoped(user, s['target_cluster']):
            return {'state': 'skipped', 'note': 'Access denied to the target cluster'}
        if _v2p_running(run.vmware_id, vm_id):
            return {'state': 'skipped', 'note': 'Another migration of this guest is running'}
        mgr = vmware_managers.get(run.vmware_id)
        if mgr is None or s['target_cluster'] not in cluster_managers:
            return {'state': 'failed', 'note': 'The ESXi server or the target cluster is gone from PegaProx'}
        pw = run.password()
        if not pw:
            return {'state': 'cancelled', 'note': 'Not started: the run was cancelled'}
        body = dict(s, **(item.get('_maps') or {}))
        err, opts = _migrate_body_refusal(run.vmware_id, body, False)
        if err:
            return {'state': 'failed', 'note': err}
        mgr.ensure_connected()
        vm_detail = mgr.get_vm(vm_id)
        if not isinstance(vm_detail, dict) or not isinstance(vm_detail.get('data'), dict):
            return {'state': 'failed', 'note': 'The guest could not be read on ESXi'}
        vm_name = str(vm_detail['data'].get('name') or vm_id)
        plan, perr = _v2p_plan(mgr, vm_id, body, opts, vm_detail)
        if perr:
            return {'state': 'failed', 'note': _answer_error(perr)}
        if not plan['ok']:
            return {'state': 'failed', 'note': 'The plan no longer fits the target node: ' + '; '.join(plan['errors'])}
        skipped = {i for i, e in (opts['disk_map'] or {}).items() if e['skip']}
        # MK Nov 2026 - its chosen VMID asked again (the run holds it since the submit),
        # or the caller's tenant range as it stands now for the automatic one
        pick, verr = _vmid_pick(user, s['target_cluster'], body.get('target_vmid'), mine=(run.holder,))
        if verr:
            return {'state': 'failed', 'note': verr[1]}

        # the run had the guest since the submit; its migration has it from here on, under the
        # same lock the single route takes a guest with
        mid = str(uuid.uuid4())[:8]
        holder = ebulk.task_holder(mid)
        if not ebulk.pass_on(run.vmware_id, vm_id, run.holder, holder):
            return {'state': 'skipped', 'note': 'Another migration of this guest is running'}
        started = False
        # the quota holds the new guest while its migration runs; nothing to hold once it failed
        box = {'task': None, 'dead': False}

        def _alive():
            return (box['task'].status == 'running') if box['task'] is not None else not box['dead']

        def _adds():
            from pegaprox.utils.rbac import landing_adds, quota_tenant
            return landing_adds(quota_tenant(user), s['target_cluster'], _v2p_footprint(vm_detail, body, skipped),
                                source_cluster=run.vmware_id, source_removed=bool(s.get('remove_source')))
        try:
            qerr, _qwarn = tenant_quota_gate(user, f'ESXi migration of {vm_name} (bulk run {run.id})', _adds,
                                             cluster=s['target_cluster'],
                                             hold={'cluster_id': s['target_cluster'], 'alive': _alive})
            if qerr:
                return {'state': 'failed', 'note': _answer_error(qerr, 'Tenant quota exceeded')}
            nics = vm_detail['data'].get('nics') or []
            if nics:
                body['selected_nics'] = nics
            body['esxi_password'] = pw
            if s.get('guest_prep') is True:
                login = run.guest_login(item)
                if not login:
                    return {'state': 'failed', 'note': 'No Windows login for the preparation in the guest: '
                                                       'the run dropped it'}
                body.update(login)
            from pegaprox.core import target_vmid as tvmid
            if pick['vmid'] and tvmid.claim(s['target_cluster'], pick['vmid'], holder,
                                            tvmid.until_over(_v2p_task, mid), replaces=run.holder):
                return {'state': 'failed', 'note': f"VMID {pick['vmid']} went to another ESXi migration"}
            task = V2PMigrationTask(mid, run.vmware_id, vm_id, s['target_cluster'], s['target_node'],
                                    s['target_storage'], vm_name, body)
            tvmid.bind(task, pick['vmid'], pick['start'], pick['end'], pick['strict'], holder)
            with _migration_lock_v2p:
                _vmware_migrations[mid] = task
            box['task'] = task
            # a user job: in an automatic group each call it sends asks for the lease
            threading.Thread(target=ha.as_job(_run_held, 'ESXi migration'), args=(task, holder),
                             daemon=True).start()
            started = True
        finally:
            if not started:
                box['dead'] = True
                _never_ran(mid)
                ebulk.let_go(run.vmware_id, vm_id, holder)
                from pegaprox.core.target_vmid import release as _vmid_release
                _vmid_release(holder)
        maps = item.get('_maps') or {}
        log_audit(run.user, 'vmware.migration.started',
                  f"V2P migration: {vm_name} @ {body.get('esxi_host')} -> {s['target_cluster']}/"
                  f"{s['target_node']}/{s['target_storage']} (bulk run {run.id}, verify {opts['verify']}"
                  f"{', own network' if 'nic_map' in maps else ''}{', own storage' if 'disk_map' in maps else ''}"
                  f"{_winprep_audit(vm_detail, body)})",
                  ip_address=run.ip)
        return {'migration_id': mid, 'name': vm_name}


def _bulk_view(run, with_items=True):
    """The run as the caller may see it, None when it is not theirs to see: who started it
    and an admin see it, nobody else. Who is no admin sees the guests they may still migrate."""
    if run is None:
        return None
    me = request.session.get('user', '')
    user = build_authz_user(me, request.session)
    admin = acts_as_admin(user)
    if not admin and (not me or me != run.user):
        return None
    items = run.items_copy()
    if not admin:
        items = [it for it in items if user_can_access_vmware_vm(user, run.vmware_id, it['vm_id'],
                                                                 'vmware.vm.migrate')]
    view = run.view(items, with_items=with_items, me=me)
    view['may_cancel'] = view['state'] == 'running' and not view['cancelled_by']
    return view


@bp.route('/api/vmware/<vmware_id>/bulk-migrate', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def start_vmware_bulk_migration(vmware_id):
    """Migrate several guests of an ESXi server to Proxmox, a few at a time

    Body: vms (1 to 200 guests: a VM id, or {vm_id, nic_map, disk_map} with the guest's own
    NIC and disk choices as the single migrate route takes them), width (how many migrate at
    once, 1 to 5, default 1), esxi_password (one for the run), dry_run, and what every guest
    shares: target_cluster, target_node, target_storage (required), network_bridge,
    net_vlan_tag, transfer_mode, verify, start_after, remove_source (needs vmware.vm.manage
    on each guest), wait_for_confirmation, confirmation_timeout, esxi_user, preserve_mac,
    bios, disk_format, allow_package_install (#1252, default true), and the Windows
    preparation as the single route takes it: install_virtio_drivers, virtio_iso_path,
    two_stage_boot, guest_prep with guest_user / guest_password for the run (a guest's vms
    row may bring its own guest_user and guest_password, only for the real start; never
    stored, logged or shown). Any other key is refused.

    Each guest is checked like a dry run of POST .../vms/<vm_id>/migrate: the caller may
    migrate it, no other migration has it, its NICs and disks fit the target node, and the
    guests together fit the storages and the tenant quota. dry_run: true answers 200 with
    that check ({ok, errors, warnings, items: one per guest, storages, available,
    node_packages: what the run may install on the target node, asked once}), needs no
    password and starts nothing. Without it, one guest that does not fit refuses the whole
    request (400, with the same items); otherwise the answer is the run (202, {run}), to
    follow with GET /api/vmware/bulk-migrate/<run_id>.

    A guest's target_vmid in vms is its own VMID, checked as the single route checks it; no
    two guests of a run get the same one. The others get the next free VMID each,
    inside the caller's tenant range.

    Before each guest starts, the run asks all of it again. Each started guest is a normal
    migration in /api/vmware/migrations. The run lives in this process (a restart ends it),
    and the ESXi password with it: in memory only, dropped once no guest is left to start.
    """
    from flask import current_app
    from functools import partial
    from pegaprox.core import esxi_bulk as ebulk
    from pegaprox.utils.audit import get_client_ip
    ok, err = check_vmware_access(vmware_id)
    if not ok:
        return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'A JSON object is expected'}), 400
    unknown = sorted(str(k)[:40] for k in data if k not in _BULK_KEYS)
    if unknown:
        return jsonify({'error': f'{unknown[0]!r} is not a setting of a bulk migration'}), 400
    dry_run = data.get('dry_run', False)
    if not isinstance(dry_run, bool):
        return jsonify({'error': 'dry_run must be true or false'}), 400
    width = data.get('width', 1)
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= ebulk.WIDTH_MAX:
        return jsonify({'error': f'width is a number from 1 to {ebulk.WIDTH_MAX}'}), 400
    try:
        vms = _bulk_vms(data.get('vms'))
        logins = _bulk_guest_logins(data.get('vms'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    settings, serr = _bulk_settings(vmware_id, data, dry_run)
    if serr:
        return jsonify({'error': serr}), 400
    pw = data.get('esxi_password')
    if pw not in (None, '') and (not isinstance(pw, str) or len(pw) > 1024):
        return jsonify({'error': 'esxi_password is a text of at most 1024 characters'}), 400
    if not dry_run and not pw:
        return jsonify({'error': 'esxi_password is required for SSHFS-based migration'}), 400
    gpw_err = _winprep_refusal({'guest_password': data.get('guest_password')})
    if gpw_err:
        return jsonify({'error': gpw_err}), 400
    run_login = {'guest_user': data['guest_user'], 'guest_password': data['guest_password']} \
        if data.get('guest_user') and data.get('guest_password') else None
    if settings.get('guest_prep') is True and not dry_run:
        without = [vm_id for vm_id, _m in vms if vm_id not in logins and not run_login]
        if without:
            return jsonify({'error': f"guest_user and guest_password are required for the Windows preparation in "
                                     f"the running guest: none for {', '.join(without[:20])}"}), 400
    target = settings['target_cluster']
    if target not in cluster_managers:
        return jsonify({'error': 'Target cluster not found'}), 404
    # the guests land on the target as new ones: a caller confined to some guests of that
    # cluster may not put any there (the single route asks the same)
    user = build_authz_user(request.session.get('user', ''), request.session)
    if caller_is_scoped(user, target):
        return jsonify({'error': 'Access denied to the target cluster'}), 403
    allowed, err_response = check_cluster_access(target)
    if not allowed:
        return err_response
    me = request.session.get('user', '')
    if not dry_run:
        # the guests land on the target over many steps: none starts without the
        # federation lease on it
        from pegaprox.api.federation import refuse_unleased
        refused = refuse_unleased(target, f'cluster {target}')
        if refused:
            return refused
        busy = ebulk.room(vmware_id, me)
        if busy:
            return jsonify({'error': busy}), 409

    res, rerr = _bulk_check(vmware_id, settings, vms, user)
    if rerr:
        return rerr
    _bulk_vmid_check(res, user, vmware_id, settings, vms)
    res['width'] = width
    if dry_run:
        return jsonify({'dry_run': True, **res})
    if not res['ok']:
        bad = sum(1 for it in res['items'] if not it['ok'])
        why = (f'{bad} of {len(res["items"])} guests cannot be migrated as asked' if bad
               else 'The guests do not fit the target together: ' + '; '.join(res['errors']))
        return jsonify({'error': why, **res}), 400

    mgr = vmware_managers[vmware_id]
    items = [ebulk.new_item(vm_id, it['name'], maps, logins.get(vm_id) if settings.get('guest_prep') else None)
             for (vm_id, maps), it in zip(vms, res['items'])]
    run = ebulk.EsxiBulkRun(vmware_id, str(getattr(mgr, 'name', '') or vmware_id), me, request.session,
                            get_client_ip(), settings, width, items, pw,
                            guest_login=run_login if settings.get('guest_prep') else None)
    # the chosen VMIDs are the run's till each guest's migration takes its own over
    from pegaprox.core import target_vmid as tvmid
    for it in items:
        vmid = (it.get('_maps') or {}).get('target_vmid')
        if vmid and tvmid.claim(target, vmid, run.holder, _bulk_vmid_alive(run, it)):
            tvmid.release(run.holder)
            return jsonify({'error': f'VMID {vmid} went to another ESXi migration since the check - '
                                     f'choose another one'}), 409
    try:
        ebulk.register(run)
    except (ebulk.TooMany, ebulk.Taken) as e:
        # Taken: a guest went to another run or the single route since the check above
        tvmid.release(run.holder)
        return jsonify({'error': str(e)}), 409
    names = [it['name'] or it['vm_id'] for it in items]
    try:
        log_audit(me, 'vmware.bulk_migration.started',
                  f"ESXi bulk migration {run.id} of {len(items)} guest(s) from {run.vmware_name} to "
                  f"{target}/{settings['target_node']}/{settings['target_storage']}, {width} at a time, "
                  f"{settings['transfer_mode']}, verify {settings.get('verify') or 'sample'}"
                  f"{', source removed after' if settings.get('remove_source') else ''}"
                  f"{', guest preparation' if settings.get('guest_prep') else ''}"
                  f"{', no Windows preparation' if settings.get('install_virtio_drivers') is False else ''}"
                  f"{', no two-stage boot' if settings.get('two_stage_boot') is False else ''}: "
                  f"{', '.join(names[:50])}{' ...' if len(names) > 50 else ''}", ip_address=run.ip)
        ebulk.launch(run, partial(_bulk_start_item, current_app._get_current_object()), _v2p_task)
    except Exception as e:
        # registered but nobody works on it: it must not keep the password or the slots
        logging.error(f"[ESXI-BULK] run {run.id} could not be started: {e}", exc_info=True)
        ebulk.abandon(run, 'The run could not be started - see the PegaProx log')
        return jsonify({'error': 'The bulk migration could not be started - see the PegaProx log'}), 500
    return jsonify({'run': _bulk_view(run)}), 202


@bp.route('/api/vmware/bulk-migrate', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def list_vmware_bulk_migrations():
    """ESXi bulk migrations of the last hours

    The runs the caller started (an admin: every run), newest first, with their counts and
    without the guests; ?vmware_id= narrows it to one ESXi server. A run lives in the
    process of the instance that started it: a restart ends it."""
    from pegaprox.core import esxi_bulk as ebulk
    only = request.args.get('vmware_id') or None
    out = []
    for run in ebulk.runs():
        if only is not None and run.vmware_id != only:
            continue
        view = _bulk_view(run, with_items=False)
        if view:
            out.append(view)
    return jsonify({'runs': out})


@bp.route('/api/vmware/bulk-migrate/<run_id>', methods=['GET'])
@require_auth(perms=['vmware.vm.migrate'])
def get_vmware_bulk_migration(run_id):
    """One ESXi bulk migration, a line per guest

    Each guest with its state (wait, starting, migrating, done, failed, skipped, cancelled,
    unknown), a note, the migration it became (migration_id, see /api/vmware/migrations),
    its phase and progress; may_cancel says whether the rest can still be cancelled."""
    from pegaprox.core import esxi_bulk as ebulk
    view = _bulk_view(ebulk.get(run_id))
    if not view:
        return jsonify({'error': 'Bulk migration not found'}), 404
    return jsonify({'run': view})


@bp.route('/api/vmware/bulk-migrate/<run_id>/cancel', methods=['POST'])
@require_auth(perms=['vmware.vm.migrate'])
def cancel_vmware_bulk_migration(run_id):
    """Cancel the rest of an ESXi bulk migration

    Who started it or an admin. No further guest starts and the run drops the ESXi
    password. Migrations that already started go on to their end: each can still be
    cancelled at its switchover gate (wait_for_confirmation)."""
    from pegaprox.core import esxi_bulk as ebulk
    run = ebulk.get(run_id)
    if not _bulk_view(run, with_items=False):
        return jsonify({'error': 'Bulk migration not found'}), 404
    me = request.session.get('user', 'system')
    if not ebulk.cancel(run, me):
        return jsonify({'error': 'This bulk migration is over'}), 409
    waiting = sum(1 for it in run.items_copy() if it['state'] == ebulk.WAITING)
    log_audit(me, 'vmware.bulk_migration.cancelled',
              f"ESXi bulk migration {run.id} from {run.vmware_name} (started by {run.user}): "
              f"{waiting} guest(s) not started")
    view = _bulk_view(run) or {}
    view['may_cancel'] = False
    return jsonify({'run': view})


# End VMware API endpoints
# ============================================================================

