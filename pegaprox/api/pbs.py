# -*- coding: utf-8 -*-
"""PBS (proxmox backup server) routes - split from monolith dec 2025, NS"""

import logging
import re
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.utils.sanitization import bounded_list
from pegaprox.api.helpers import safe_error, check_pbs_access, check_cluster_access, scope_vm_rows, require_unconfined, bounded_limit, acts_as_admin, caller_acts_as_admin
from pegaprox.api.helpers import upstream_failure, tenant_quota_gate
from pegaprox.core.pbs import PBSManager, load_pbs_servers, save_pbs_server, pbs_config_from_row, pbs_target_refusal

bp = Blueprint('pbs', __name__)

# the three secrets a PBS server holds, by the column they are encrypted into
_PBS_SECRETS = {'password': 'pass_encrypted', 'api_token_secret': 'api_token_secret_encrypted',
                'ssh_key': 'ssh_key_encrypted'}


# MK Sep 2026 (#802) — PBSManager.api_get does not raise; on a refusal it returns
# {'error': 'HTTP 403', 'status_code': 403}. Routes that then reach for result.get('data', [])
# hand the browser an empty 200, so a refusal and an empty log look identical to the UI. The
# syslog panel re-rendered its own "click to load" prompt on both, which is why the reporter
# could click it forever with nothing in the browser console and nothing on screen.
def pbs_upstream_error(result):
    """Return (status, payload) if result is a failed api_* call, else None.

    The description stays bounded on purpose — api_get puts the requests exception
    (which carries the PBS host, port and full URL) in the server log already, and the
    browser picks its own sentence from the code, so there is nothing to gain from
    reflecting that string back out of the API.
    """
    if not isinstance(result, dict) or 'error' not in result:
        return None
    upstream = result.get('status_code')
    if upstream == 403:
        # PBS guards the node log with Sys.Audit on /system/log. A token minted for
        # backup work alone (Datastore.*) does not carry it, and that is the common case.
        return 403, {'error': 'PBS denied the request', 'code': 'PBS_FORBIDDEN'}
    if upstream is None:
        # never got an answer: DNS, refused, timed out, TLS
        return 502, {'error': 'PBS is unreachable', 'code': 'PBS_UNREACHABLE', 'upstream_status': None}
    return 502, {'error': f'PBS returned HTTP {upstream}', 'code': 'PBS_UPSTREAM',
                 'upstream_status': upstream}


def _link_refusal(links, empty_error):
    """The 403 for a non-admin caller who links a PBS server to `links`, or None.

    linked_clusters is the list check_pbs_access reads, and an empty one opens the server to
    every tenant. So only a global admin leaves it empty, and anybody else links it only to
    clusters they reach themselves. NS Oct 2026 (#995) - shared by the add and the update.
    """
    from pegaprox.utils.auth import build_authz_user as _bau
    from pegaprox.utils.rbac import get_user_clusters as _guc
    _caller = _bau(request.session.get('user', ''), request.session)
    if acts_as_admin(_caller):
        return None
    _new_links = list(links or [])
    if not _new_links:
        return jsonify({'error': empty_error}), 403
    _reachable = _guc(_caller)
    if _reachable is not None:
        _beyond = [c for c in _new_links if c not in set(_reachable)]
        if _beyond:
            return jsonify({'error': 'Access denied: cannot link this PBS server to '
                                     + ', '.join(_beyond)}), 403
    return None


def _target_refusal(host):
    """pbs_target_refusal for the caller of this request: loopback for a global admin only."""
    return pbs_target_refusal(host, allow_loopback=caller_acts_as_admin())


@bp.route('/api/pbs', methods=['GET'])
@require_auth(perms=['pbs.view'])
def list_pbs_servers():
    """List all configured PBS servers"""
    # NS Jul 2026 (CodeAnt IDOR) — scope the listing to PBS servers the caller can reach.
    # Unfiltered enumeration here is what made the per-route PBS BOLA trivial to exploit.
    # Mirrors check_pbs_access semantics but also covers disabled (DB-only) servers.
    # NS Aug 2026 (Aikido 469089255) — build_authz_user (not raw load_users) so an admin-owned but
    # role-scoped API token is floored to its effective_role here too, matching the fixed siblings
    # check_pbs_access / check_vmware_access. The raw path let a viewer-scoped admin token read every
    # PBS server (role==ADMIN short-circuit + _guc None) despite the token's reduced scope.
    from pegaprox.utils.auth import build_authz_user as _bau
    from pegaprox.utils.rbac import get_user_clusters as _guc
    _lu = _bau(request.session.get('user', ''), request.session)
    _uc = _guc(_lu)  # None => all clusters (admin / default tenant)
    _all = acts_as_admin(_lu)
    def _pbs_visible(linked):
        if _all or _uc is None:
            return True
        linked = linked or []
        return (not linked) or any(c in _uc for c in linked)
    result = []
    for pbs_id, mgr in pbs_managers.items():
        if not _pbs_visible(getattr(mgr, 'linked_clusters', None)):
            continue
        info = mgr.to_dict()
        # Include quick status if connected
        if mgr.connected and mgr.last_status:
            info['status'] = {
                'cpu': mgr.last_status.get('cpu', 0),
                'memory': mgr.last_status.get('memory', {}),
                'uptime': mgr.last_status.get('uptime', 0),
            }
        result.append(info)

    # Also include disabled servers from DB
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT id, name, host, port, enabled, linked_clusters FROM pbs_servers")
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['id'] not in pbs_managers:
                # NS: parse linked_clusters so frontend can filter by cluster
                linked = []
                try:
                    import json
                    linked = json.loads(row_dict.get('linked_clusters', '[]') or '[]')
                except Exception:
                    pass
                if not _pbs_visible(linked):
                    continue
                result.append({
                    'id': row_dict['id'],
                    'name': row_dict['name'],
                    'host': row_dict['host'],
                    'port': row_dict['port'],
                    'enabled': bool(row_dict['enabled']),
                    'connected': False,
                    'linked_clusters': linked,
                })
    except Exception:
        pass

    return jsonify(result)


@bp.route('/api/pbs', methods=['POST'])
@require_auth(perms=['pbs.config'])
def add_pbs_server():
    """Add a new PBS server"""
    data = request.json or {}
    
    if not data.get('name') or not data.get('host'):
        return jsonify({'error': 'Name and host are required'}), 400
    
    if not data.get('user') and not data.get('api_token_id'):
        return jsonify({'error': 'Username or API token is required'}), 400

    # NS Oct 2026 (#995) - the update has refused an empty or foreign link list since September,
    # the add never did: a new server without links was open to every tenant from the start
    _lerr = _link_refusal(data.get('linked_clusters'),
                          'Access denied: only a global admin may add a PBS server linked to no cluster')
    if _lerr:
        return _lerr
    _why = _target_refusal(data.get('host'))
    if _why:
        return jsonify({'error': _why}), 400

    pbs_id = str(uuid.uuid4())[:8]
    
    # Test connection first
    try:
        mgr = PBSManager(pbs_id, data)
    except ValueError as e:
        return jsonify({'error': 'Invalid PBS host'}), 400
    
    if not mgr.connect():
        return jsonify({'error': f'Connection failed: {mgr.last_error}'}), 400
    
    # Save to DB
    save_pbs_server(pbs_id, data)
    pbs_managers[pbs_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'pbs.added', 
              f"Added PBS server: {data['name']} ({data['host']})")
    
    return jsonify({'id': pbs_id, 'message': 'PBS server added successfully', **mgr.to_dict()}), 201


@bp.route('/api/pbs/<pbs_id>', methods=['PUT'])
@require_auth(perms=['pbs.config'])
def update_pbs_server(pbs_id):
    """Update a PBS server config"""
    ok, err = check_pbs_access(pbs_id)  # NS Aug 2026 (Aikido) — object-level authz on write
    if not ok:
        return err
    data = request.json or {}

    # MK Sep 2026 (audit) — linked_clusters is the authorization list check_pbs_access reads,
    # and an EMPTY one means "reachable by everybody" (the backward-compatibility arm). Omitting
    # the field was already made safe at the storage layer, but sending it EXPLICITLY empty was
    # not: any user who reached this server through one of its links could hand the whole backup
    # server — every tenant's snapshots on it — to every tenant, in one PUT. Widening the list is
    # the same move at half speed, so a non-admin may only ever narrow it, and only to clusters
    # they can reach themselves.
    if 'linked_clusters' in data:
        _lerr = _link_refusal(data.get('linked_clusters'),
                              'Access denied: only a global admin may unlink a PBS server from every cluster')
        if _lerr:
            return _lerr

    # NS Oct 2026 (#999, #1033) - the stored row is what this update starts from, for the guards
    # below and for the manager it rebuilds. The manager used to be rebuilt from the body alone:
    # a PUT without linked_clusters left the running server unlinked (open to every tenant until
    # a restart), and one without the secrets emptied them in memory only - which is where the
    # host-change guard looked, so the next PUT could move the host while the row kept the real
    # credentials for the next start. What the body leaves out now keeps its stored value.
    old_mgr = pbs_managers.get(pbs_id)
    db = get_db()
    row = db.conn.cursor().execute("SELECT * FROM pbs_servers WHERE id = ?", (pbs_id,)).fetchone()
    row = dict(row) if row else {}
    if row:
        stored = {k: v for k, v in pbs_config_from_row(db, row).items() if v is not None}
    elif old_mgr is not None:
        # a registry entry without a row: what the manager holds is all there is
        stored = {k: getattr(old_mgr, k, '') for k in ('host', 'port', 'linked_clusters', *_PBS_SECRETS)}
    else:
        return jsonify({'error': 'PBS server not found'}), 404
    old_host, old_port = stored.get('host'), stored.get('port')

    # NS Aug 2026 (CodeAnt) — a non-numeric submitted port must not blow up change-detection with an
    # unhandled ValueError (500). Reject it up front; everything below assumes a parseable port.
    _new_port = data.get('port')
    if _new_port not in (None, ''):
        try:
            _new_port = int(_new_port)
        except (TypeError, ValueError):
            return jsonify({'error': 'Invalid port'}), 400
    else:
        _new_port = None
    # NS Aug 2026 (CodeAnt) — treat an unstored port as the PBS default (8007) so a port change from
    # "none stored" to a new value still counts as an endpoint change and trips the cred-exfil guard.
    try:
        _old_port_i = int(old_port) if old_port not in (None, '') else 8007
    except (TypeError, ValueError):
        _old_port_i = 8007
    host_changed = (data.get('host') and data.get('host') != old_host) or \
                   (_new_port is not None and _new_port != _old_port_i)
    if host_changed:
        _why = _target_refusal(data.get('host') or old_host)
        if _why:
            return jsonify({'error': _why}), 400

    # NS Aug 2026 (Aikido 469089267 + AI-pentest re-check) — FAIL CLOSED on a host/port change: every
    # credential the STORED config holds must be freshly re-entered, otherwise it would be shipped to
    # the caller-chosen new host (on save+auto-connect, the next daemon reload, or a follow-up /test).
    # The first guard only checked the '********' sentinel and gated each clause on the key being
    # PRESENT — so simply OMITTING password/api_token_secret/ssh_key bypassed it and the stored secret
    # was still preserved against the attacker host. An omitted OR blank OR masked value is NOT a
    # re-entry.
    def _fresh(key):
        return data.get(key) not in (None, '', '********')
    if host_changed:
        # a secret is held when its encrypted column is set, decryptable or not
        _stored = {k: bool(stored.get(k)) or bool(row.get(col)) for k, col in _PBS_SECRETS.items()}
        _stale = [k for k, present in _stored.items() if present and not _fresh(k)]
        if _stale:
            logging.warning(f"[PBS:{pbs_id}] Rejected host/port change without re-entering {_stale} (cred-exfil guard)")
            return jsonify({'error': 'Re-enter the PBS credentials when changing the host or port.'}), 400

    # NS Aug 2026 — normalise the port so an empty/invalid value can't hit int('') in save_pbs_server
    # (500). We already parsed/validated it above; drop an empty one so the stored default is used.
    if data.get('port') in ('', None):
        data.pop('port', None)
    elif _new_port is not None:
        data['port'] = _new_port

    # Host unchanged (or full creds supplied): a blank or masked secret keeps the stored one,
    # in the rebuilt manager as in the row.
    config = dict(stored)
    for k, v in data.items():
        if k in _PBS_SECRETS and not _fresh(k):
            continue
        config[k] = v

    # built before the save, so a host it refuses leaves the row as it was
    try:
        mgr = PBSManager(pbs_id, config)
    except ValueError as e:
        return jsonify({'error': 'Invalid PBS host'}), 400

    save_pbs_server(pbs_id, config)

    if config.get('enabled', True):
        mgr.connect()
    pbs_managers[pbs_id] = mgr

    log_audit(request.session.get('user', 'admin'), 'pbs.updated', f"Updated PBS server: {config.get('name', pbs_id)}")
    
    return jsonify(mgr.to_dict())


@bp.route('/api/pbs/<pbs_id>', methods=['DELETE'])
@require_auth(perms=['pbs.config'])
def delete_pbs_server(pbs_id):
    """Delete a PBS server"""
    ok, err = check_pbs_access(pbs_id)  # NS Aug 2026 (Aikido) — object-level authz on delete
    if not ok:
        return err
    if pbs_id in pbs_managers:
        name = pbs_managers[pbs_id].name
        del pbs_managers[pbs_id]
    else:
        name = pbs_id
    
    db = get_db()
    db.conn.cursor().execute("DELETE FROM pbs_servers WHERE id = ?", (pbs_id,))
    db.conn.commit()
    
    log_audit(request.session.get('user', 'admin'), 'pbs.deleted', f"Deleted PBS server: {name}")
    
    return jsonify({'message': f'PBS server {name} deleted'})


@bp.route('/api/pbs/test-connection', methods=['POST'])
@require_auth(perms=['pbs.config'])
def test_pbs_new_connection():
    """Test PBS connection with provided credentials (before save)"""
    data = request.json or {}
    if not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400
    _why = _target_refusal(data.get('host'))
    if _why:
        return jsonify({'success': False, 'error': _why}), 400

    try:
        test_mgr = PBSManager('test', data)
    except ValueError as e:
        return jsonify({'success': False, 'error': 'Invalid PBS host'}), 400
    
    success = test_mgr.connect()
    if success:
        version = test_mgr.get_version()
        datastores = test_mgr.get_datastore_usage()
        return jsonify({
            'success': True,
            'version': version.get('data', {}),
            'datastores': len(datastores.get('data', [])),
        })
    return jsonify({'success': False, 'error': test_mgr.last_error}), 400


@bp.route('/api/pbs/<pbs_id>/test', methods=['POST'])
@require_auth(perms=['pbs.config'])
def test_pbs_connection(pbs_id):
    """Test PBS connection (or test with provided credentials)"""
    data = request.json or {}
    
    if data.get('host'):
        _why = _target_refusal(data.get('host'))
        if _why:
            return jsonify({'success': False, 'error': _why}), 400
        # MK Oct 2026 (#805) - the edit dialog shows stored secrets as '********', and its Test
        # button sent that mask to PBS as the password or token secret, so testing a saved
        # server always failed with HTTP 401. Fill the mask from the stored server like the PUT
        # does, but only for the same host and port: a new endpoint gets nothing not retyped.
        masked = [k for k in ('password', 'api_token_secret') if data.get(k) == '********']
        if masked:
            ok, err = check_pbs_access(pbs_id)
            if not ok:
                return err
            stored = pbs_managers.get(pbs_id)
            try:
                same_port = stored is not None and int(data.get('port') or 8007) == int(stored.port or 8007)
            except (TypeError, ValueError):
                return jsonify({'success': False, 'error': 'Invalid port'}), 400
            if not same_port or data.get('host') != stored.host:
                return jsonify({'success': False, 'error': 'Re-enter the PBS credentials when '
                                                           'changing the host or port.'}), 400
            data = dict(data)
            for k in masked:
                data[k] = getattr(stored, k, '') or ''
        # Test with provided credentials (before save)
        try:
            test_mgr = PBSManager('test', data)
        except ValueError as e:
            return jsonify({'success': False, 'error': 'Invalid PBS host'}), 400
        
        success = test_mgr.connect()
        if success:
            version = test_mgr.get_version()
            datastores = test_mgr.get_datastore_usage()
            return jsonify({
                'success': True,
                'version': version.get('data', {}),
                'datastores': len(datastores.get('data', [])),
            })
        return jsonify({'success': False, 'error': test_mgr.last_error}), 400
    
    # Test existing connection
    # NS Aug 2026 (audit) — object-level gate for the existing-connection branch (siblings
    # update/delete/status all carry it); without it a pbs.config holder could probe any tenant's
    # PBS by id and read its reachability/version.
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404

    mgr = pbs_managers[pbs_id]
    success = mgr.connect()
    if success:
        version = mgr.get_version()
        return jsonify({'success': True, 'version': version.get('data', {})})
    return jsonify({'success': False, 'error': mgr.last_error}), 400


@bp.route('/api/pbs/<pbs_id>/status', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_status(pbs_id):
    """Get PBS server status (CPU, RAM, disk, uptime)"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected', 'connected': False}), 503
    
    status = mgr.get_server_status()
    version = mgr.get_version()
    datastores = mgr.get_datastore_usage()

    # NS: Mar 2026 - propagate errors so frontend can show what went wrong (#107)
    errors = []
    if 'error' in status:
        errors.append(f"Status: {status['error']}")
        logging.warning(f"[PBS:{mgr.name}] get_server_status failed: {status['error']}")
    if 'error' in datastores:
        errors.append(f"Datastores: {datastores['error']}")
        logging.warning(f"[PBS:{mgr.name}] get_datastore_usage failed: {datastores['error']}")

    return jsonify({
        'server': status.get('data', {}),
        'version': version.get('data', {}),
        'datastores': datastores.get('data', []),
        'connected': mgr.connected,
        'name': mgr.name,
        'errors': errors if errors else None,
    })


@bp.route('/api/pbs/<pbs_id>/apt/updates', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_apt_updates(pbs_id):
    """List available APT updates on PBS server"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    result = mgr.get_apt_updates()
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    return jsonify({'updates': result.get('data', []), 'count': len(result.get('data', []))})


@bp.route('/api/pbs/<pbs_id>/apt/refresh', methods=['POST'])
@require_auth(perms=['pbs.view'])
def refresh_pbs_apt(pbs_id):
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'an apt refresh')
    if _wide:
        return _wide
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    result = mgr.refresh_apt()
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    return jsonify({'success': True, 'data': result.get('data')})


# NS Apr 2026: actually execute apt dist-upgrade via SSH. PBS API has no upgrade endpoint.
@bp.route('/api/pbs/<pbs_id>/update', methods=['POST'])
@require_auth(perms=['admin.settings'])
def start_pbs_update(pbs_id):
    """Start apt-get dist-upgrade on PBS host via SSH"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'a host upgrade')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json(silent=True) or {}
    reboot = bool(data.get('reboot', False))

    existing = mgr.get_update_status()
    if existing and existing.status in ('starting', 'updating', 'rebooting', 'waiting_online'):
        return jsonify({'error': 'Update already in progress', 'status': existing.status}), 409

    task = mgr.start_update(reboot=reboot)
    if not task:
        return jsonify({'error': 'Could not start update'}), 500
    log_audit(request.session.get('user', 'admin'), 'pbs.update_started',
              f"Started apt upgrade on PBS {mgr.name}" + (' (with reboot)' if reboot else ''))
    return jsonify({'success': True, 'status': task.status, 'phase': task.phase})


@bp.route('/api/pbs/<pbs_id>/update', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_update_status(pbs_id):
    """Get current PBS update status"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    task = mgr.get_update_status()
    if not task:
        return jsonify({'is_updating': False})
    return jsonify({
        'is_updating': task.status in ('starting', 'updating', 'rebooting', 'waiting_online'),
        'status': task.status,
        'phase': task.phase,
        'error': task.error,
        'output_lines': task.output_lines[-50:] if hasattr(task, 'output_lines') else [],
        'packages_upgraded': getattr(task, 'packages_upgraded', 0),
        'reboot': getattr(task, 'reboot', False),
        'started_at': task.started_at.isoformat() if getattr(task, 'started_at', None) else None,
        'completed_at': task.completed_at.isoformat() if getattr(task, 'completed_at', None) else None,
    })


@bp.route('/api/pbs/<pbs_id>/update', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def clear_pbs_update_status(pbs_id):
    """Clear completed/failed update status"""
    # the same two gates as starting the upgrade beside it (#1012)
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'clearing the upgrade status')
    if _wide:
        return _wide
    ok = pbs_managers[pbs_id].clear_update_status()
    return jsonify({'cleared': ok})


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastores(pbs_id):
    """List datastores with detailed status"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    
    # Get list of datastores
    config_resp = mgr.get_datastores()
    usage_resp = mgr.get_datastore_usage()
    
    datastores = config_resp.get('data', [])
    usage_list = {u.get('store'): u for u in usage_resp.get('data', [])}
    
    # Merge config with usage
    result = []
    for ds in datastores:
        name = ds.get('name', '')
        info = {**ds, **(usage_list.get(name, {}))}
        
        # Try to get detailed status (GC info, counts)
        try:
            detail = mgr.get_datastore_status(name)
            if 'data' in detail:
                info['detail'] = detail['data']
        except Exception:
            pass
        
        result.append(info)
    
    return jsonify(result)


def _pbs_vm_name_lookup(pbs_mgr, cluster_ids=None):
    """NS May 2026 — build a {(type, vmid): name} map from the PBS server's
    linked PVE clusters. Used to enrich PBS snapshot/group responses with
    `vm_name` so the frontend doesn't have to do its own lookups (which
    only work after the cluster guests have been fetched separately).
    Falls back to all connected clusters when the PBS has no explicit
    linked_clusters configured. cluster_ids narrows it to the owners of
    the place being listed, so a vm/100 is not named after another
    cluster's VM 100 (#1083)."""
    name_map = {}
    if cluster_ids is None:
        cluster_ids = list(pbs_mgr.linked_clusters or [])
    if not cluster_ids:
        # if the PBS has no explicit linked clusters, fall back to all
        # connected clusters — covers fresh setups before linking is configured
        cluster_ids = list(cluster_managers.keys())
    for cid in cluster_ids:
        cm = cluster_managers.get(cid)
        if not cm or not getattr(cm, 'is_connected', False):
            continue
        try:
            resources = cm.get_vm_resources() or []
        except Exception:
            resources = []
        for r in resources:
            t = r.get('type')
            vmid = r.get('vmid')
            name = r.get('name')
            if vmid is None:
                continue
            # PVE 'vm' resource type is 'qemu' for VMs, 'lxc' for containers.
            # PBS backup-type is 'vm' or 'ct'.
            if t == 'lxc':
                backup_t = 'ct'
            elif t in ('qemu', 'vm'):
                backup_t = 'vm'
            else:
                continue
            key = (backup_t, str(vmid))
            # Real name preferred. If a VM has no name (fresh creates, restored
            # configs without `name`), still register it so the UI knows the VM
            # is *known* to PegaProx — synthesise "VM/CT <id>" as label.
            if key not in name_map:
                name_map[key] = name or f"{'CT' if backup_t == 'ct' else 'VM'} {vmid}"
    return name_map


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshots(pbs_id, store):
    """List snapshots in a datastore"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    backup_type = request.args.get('backup-type', None)
    backup_id = request.args.get('backup-id', None)
    result = mgr.get_snapshots(store, ns=ns, backup_type=backup_type, backup_id=backup_id)
    # #143: don't mask errors as empty arrays
    if 'error' in result:
        return upstream_failure(result.get('status_code'), result['error'], system='The PBS server', default=502)
    snaps = result.get('data', []) or []
    # NS — enrich with vm_name from linked clusters
    owners = _BackupOwners(mgr)
    name_map = _pbs_vm_name_lookup(mgr, owners.of(store, ns))
    for s in snaps:
        bt = s.get('backup-type')
        bid = s.get('backup-id')
        if bt and bid is not None:
            nm = name_map.get((bt, str(bid)))
            if nm:
                s['vm_name'] = nm
    return jsonify(_scope_pbs_rows(mgr, snaps, store=store, ns=ns, owners=owners))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/groups', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_groups(pbs_id, store):
    """List backup groups in a datastore"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    result = mgr.get_groups(store, ns=ns)
    if 'error' in result:
        return upstream_failure(result.get('status_code'), result['error'], system='The PBS server', default=502)
    groups = result.get('data', []) or []
    # NS — enrich with vm_name
    owners = _BackupOwners(mgr)
    name_map = _pbs_vm_name_lookup(mgr, owners.of(store, ns))
    for g in groups:
        bt = g.get('backup-type')
        bid = g.get('backup-id')
        if bt and bid is not None:
            nm = name_map.get((bt, str(bid)))
            if nm:
                g['vm_name'] = nm
    return jsonify(_scope_pbs_rows(mgr, groups, store=store, ns=ns, owners=owners))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/gc', methods=['POST'])
@require_auth(perms=['pbs.datastore.gc'])
def pbs_start_gc(pbs_id, store):
    """Start garbage collection"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'garbage collection')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.start_gc(store)
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.gc', f"Started GC on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/verify', methods=['POST'])
@require_auth(perms=['pbs.datastore.verify'])
def pbs_start_verify(pbs_id, store):
    """Start verification"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'verification')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    result = mgr.start_verify(store, ignore_verified=data.get('ignore_verified', True))
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.verify', f"Started verify on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/prune', methods=['POST'])
@require_auth(perms=['pbs.datastore.prune'])
def pbs_prune(pbs_id, store):
    """Prune old backups"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'prune')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    # NS Aug 2026 (audit re-verify) — a TARGETED prune (a specific backup group) deletes that group's
    # snapshots, so re-check the per-backup owner like the other write ops. A store-wide prune (no
    # backup-id) stays a datastore-level op gated by pbs.datastore.prune.
    if data.get('backup_id'):
        ok, err = _authz_pbs_backup(mgr, data.get('backup_type'), data.get('backup_id'),
                                    store=store, ns=data.get('ns'))
        if not ok:
            return err
    result = mgr.prune_datastore(
        store, ns=data.get('ns'),
        keep_last=data.get('keep_last'), keep_daily=data.get('keep_daily'),
        keep_weekly=data.get('keep_weekly'), keep_monthly=data.get('keep_monthly'),
        keep_yearly=data.get('keep_yearly'),
        backup_type=data.get('backup_type'), backup_id=data.get('backup_id'),
        dry_run=data.get('dry_run', True),
    )
    action = "dry-run prune" if data.get('dry_run', True) else "PRUNE"
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.prune', f"{action} on {mgr.name}/{store}")
    return jsonify(result)


def _scope_pbs_rows(mgr, rows, type_key='backup-type', id_key='backup-id',
                    permission='vm.view', key_fn=None, store=None, ns=None, where_fn=None,
                    owners=None):
    """sec (audit): a datastore is shared across every VM on every linked cluster, and
    pbs.datastore.view is a BUILTIN ROLE_USER and ROLE_VIEWER permission — so the snapshot and
    group listings handed every user the whole install's backup inventory (enriched with VM
    names), while the per-object routes beside them were gated. Same predicate, applied per row.

    An admin or a caller who is not confined keeps everything; a scoped caller keeps only the
    rows whose guest they may see. Rows with no resolvable guest (host-type backups) are
    dropped for a scoped caller, matching _authz_pbs_backup.

    key_fn overrides the two dict lookups for rows that carry the guest somewhere else — task
    rows name it in worker_id, not in backup-type/backup-id.

    Where a row lives - its datastore and namespace, which decide whose it is (#1083) - is
    store/ns for a listing of one place, the _datastore/_namespace a row from
    _pbs_collect_snapshots carries, or where_fn(row)."""
    from pegaprox.utils.auth import build_authz_user
    user = build_authz_user(request.session.get('user', ''), request.session)
    if acts_as_admin(user):
        return rows
    scoped = _caller_is_scoped_here(mgr, user)
    if not scoped:
        return rows                      # plain cluster-wide operator — unchanged
    owners = owners or _BackupOwners(mgr)
    out = []
    for r in rows or []:
        bt, bid = key_fn(r) if key_fn else (r.get(type_key), r.get(id_key))
        r_store, r_ns = where_fn(r) if where_fn else (r.get('_datastore', store),
                                                       r.get('_namespace', ns))
        # hand down both the identity and the confinement answer — a datastore listing is the
        # whole install's inventory, and each of those costs a users-table read or a pool and
        # ACL enumeration per row otherwise
        ok, _ = _authz_pbs_backup(mgr, bt, bid, permission, user=user, scoped=scoped,
                                  store=r_store, ns=r_ns, owners=owners)
        if ok:
            out.append(r)
    return out


def _pbs_task_guest(worker_id):
    """('vm'|'ct', '100') out of a PBS backup task's worker_id.

    PBS spells it '<datastore>:<type>/<id>/<hex-backup-time>'. Returns (None, None) for
    host-type backups and anything we can't read."""
    parts = [p for p in str(worker_id or '').split(':')[-1].split('/') if p]
    if len(parts) < 2 or parts[0] not in ('vm', 'ct'):
        return None, None
    return parts[0], parts[1]


def _pbs_upid_guest(upid):
    """('vm'|'ct', '100') out of a PBS UPID.

    A UPID is 'UPID:node:pid:pstart:taskid:starttime:worker_type:worker_id:user:' and the
    worker_id is itself colon-separated, so pick the guest out of the whole string instead
    of counting fields."""
    import re
    m = re.search(r'(?:^|[:/])(vm|ct)/(\d+)(?:[:/]|$)', str(upid or ''))
    return (m.group(1), m.group(2)) if m else (None, None)


def _pbs_task_store(text):
    """The datastore of a backup task, out of its worker_id or its UPID - the field in front of
    '<type>/<id>' - or None. A task in a namespace does not match and gets None."""
    import re
    m = re.search(r'(?:^|:)([^:/]+):(?:vm|ct)/\d+(?:[:/]|$)', str(text or ''))
    return m.group(1) if m else None


# NS Oct 2026 (#1083) - a VMID names a guest inside one cluster, and clusters that share a PBS
# number their guests from 100 as well. "The caller may use VM 100 on one of the linked
# clusters" said nothing about whose vm/100 a backup was: a tenant with VM 100 on cluster A
# listed, browsed, downloaded and deleted cluster B's vm/100 backups on a shared datastore.
# PBS does not record the cluster, but each cluster's storage.cfg names the datastore and
# namespace its pbs storage writes to, and that is what decides the owner here.
_PBS_STORAGE_TTL = 60.0
_pbs_storages_seen = {}          # cluster id -> (monotonic read time, [pbs storage entries])


def _pbs_storages_of(cluster_id):
    """The pbs-type entries of a cluster's storage.cfg, or None when they cannot be told.

    Kept for a minute. A read that fails falls back to the last one that worked, so a cluster
    that drops offline keeps its claims instead of locking its tenants out."""
    import time
    cm = cluster_managers.get(cluster_id)
    if cm is None:
        return None
    if getattr(cm, 'cluster_type', 'proxmox') != 'proxmox':
        return []                        # only PVE writes to a PBS
    now = time.monotonic()
    hit = _pbs_storages_seen.get(cluster_id)
    if hit and now - hit[0] < _PBS_STORAGE_TTL:
        return hit[1]
    entries = None
    if getattr(cm, 'is_connected', False):
        try:
            r = cm._api_get(f"https://{cm.host}:{cm.api_port}/api2/json/storage")
            if r is not None and r.status_code == 200:
                entries = [s for s in (r.json().get('data') or [])
                           if isinstance(s, dict) and s.get('type') == 'pbs']
        except Exception as e:
            logging.debug(f"[PBS] cannot read the storages of {cluster_id}: {e}")
    if entries is None:
        return hit[1] if hit else None
    _pbs_storages_seen[cluster_id] = (now, entries)
    return entries


def _pbs_ns(ns):
    return str(ns or '').strip().strip('/')


def _storage_is_this_pbs(entry, mgr):
    """Whether a pbs storage entry points at this PBS: same host and port, or the same
    certificate where one side names the server by address and the other by name."""
    def _host(h):
        return str(h or '').strip().strip('[]').lower()

    def _port(p):
        try:
            return int(p or 8007)
        except (TypeError, ValueError):
            return None

    def _fp(f):
        f = ''.join(c for c in str(f or '').upper() if c in '0123456789ABCDEF')
        return f if len(f) == 64 else ''

    server = _host(entry.get('server'))
    if server and server == _host(mgr.host) and _port(entry.get('port')) == _port(mgr.port):
        return True
    fp = _fp(entry.get('fingerprint'))
    return bool(fp) and fp == _fp(getattr(mgr, 'fingerprint', ''))


class _BackupOwners:
    """The clusters a backup in one datastore and namespace of this PBS may belong to.

    The candidates are the clusters the PBS backs up for (linked, else every connected one,
    as everywhere in this module). One candidate owns everything. With more, the owners of a
    place are the candidates whose storage.cfg writes there, plus any whose storage.cfg cannot
    be read. A place no candidate claims answers with all of them - nobody can tell whose it is,
    so a confined caller needs the guest on each. Several claims on one place answer with all
    the claimants for the same reason: their backup groups are one and the same.

    One per listing. The storage reads happen on first use and only with two candidates or
    more; _pbs_storages_of keeps them for a minute."""

    def __init__(self, mgr):
        self.mgr = mgr
        self.candidates = list(mgr.linked_clusters or []) or list(cluster_managers.keys())
        self._claims = None

    def of(self, store, ns=None):
        if len(self.candidates) < 2 or store is None:
            return self.candidates
        if self._claims is None:
            self._claims = {}
            for cid in self.candidates:
                entries = _pbs_storages_of(cid)
                self._claims[cid] = None if entries is None else {
                    (str(e.get('datastore') or ''), _pbs_ns(e.get('namespace')))
                    for e in entries if _storage_is_this_pbs(e, self.mgr)}
        where = (str(store), _pbs_ns(ns))
        claimed = [c for c in self.candidates if self._claims[c] and where in self._claims[c]]
        if not claimed:
            return self.candidates
        return claimed + [c for c in self.candidates if self._claims[c] is None]


def _caller_is_scoped_here(mgr, user):
    """True when this caller is confined on any cluster this PBS backs up for.

    Linked clusters own the backups; a PBS with no linking falls back to every connected
    cluster, matching _pbs_vm_name_lookup. Conservative on purpose: confined anywhere means
    confined here."""
    from pegaprox.api.helpers import caller_is_scoped
    _cids = list(mgr.linked_clusters or []) or list(cluster_managers.keys())
    return any(caller_is_scoped(user, c) for c in _cids)


def _authz_restore_node(cluster_id, node, user):
    """A confined caller may not pick an arbitrary node to restore onto.

    Placing a guest on a node is a cluster-level decision - it consumes that node's CPU,
    memory and local storage. An ACL/pool-scoped caller has no cluster-level standing, so
    they restore where their existing guests already live and nowhere else. Returns an
    error response, or None. MK Sep 2026
    """
    from pegaprox.api.helpers import caller_is_scoped
    if not caller_is_scoped(user, cluster_id):
        return None
    from pegaprox.utils.rbac import user_can_access_vm
    mgr = cluster_managers.get(cluster_id)
    try:
        # NS Oct 2026 - asked guest by guest. get_user_vms knows the VM-ACLs only, so a caller
        # confined by a pool came back as unrestricted and restored onto any node (#1081)
        _nodes = {r.get('node') for r in (mgr.get_vm_resources() or [])
                  if r.get('node') and str(r.get('vmid', '')).isdigit()
                  and user_can_access_vm(user, cluster_id, int(r['vmid']), 'vm.view', r.get('type'))}
    except Exception as e:
        logging.error(f"[PBS] cannot resolve the caller's nodes on {cluster_id}: {e}")
        return jsonify({'error': 'Cannot verify the restore destination - check the server logs'}), 503
    if node not in _nodes:
        logging.warning(f"[PBS] {request.session.get('user','?')} refused a restore onto "
                        f"'{node}' on {cluster_id}: none of their guests live there")
        return jsonify({'error': 'Access denied: you cannot restore onto this node'}), 403
    return None


def require_pbs_wide(pbs_id, action='this action'):
    """Gate for an operation that hits the WHOLE PBS resource, not one backup.

    check_pbs_access proves the caller reaches ONE of the PBS's linked clusters. That is
    the right question for reading, and the wrong one for garbage collection, prune,
    verify, datastore creation/removal, job management and host upgrades: a PBS backing
    up three tenants' clusters is shared infrastructure, and those actions hit all of it.
    A tenant operator was reaching them with one linked cluster to their name - GC and
    prune destroy data other tenants own, and an upgrade with reboot takes the backup
    target away from everyone.

    So: a global admin passes, and so does a caller who holds EVERY linked cluster (the
    single-tenant install, which is most of them). Anyone else is refused. Deliberately
    coarse - the datastore-to-tenant ownership mapping Aikido asks for is a data-model
    change, and this is the honest guard until that exists.

    Returns an error response to `return`, or None when the caller may proceed. MK Sep 2026
    """
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import get_user_clusters
    from pegaprox.api.helpers import caller_is_scoped

    mgr = pbs_managers.get(pbs_id)
    if mgr is None:
        return jsonify({'error': 'PBS server not found'}), 404

    user = build_authz_user(request.session.get('user', ''), request.session)
    if acts_as_admin(user):
        return None

    linked = list(mgr.linked_clusters or [])
    if not linked:
        # unlinked PBS: no tenant boundary is expressed at all, so fall back to the
        # confinement question on the clusters we do know about
        linked = list(cluster_managers.keys())

    mine = get_user_clusters(user)
    if mine is not None:
        missing = [c for c in linked if c not in mine]
        if missing:
            logging.warning(
                f"[PBS] {request.session.get('user','?')} refused {action} on {pbs_id}: "
                f"it also serves {len(missing)} cluster(s) outside their scope")
            return jsonify({
                'error': 'Access denied: this PBS server also serves clusters outside '
                         'your scope, and this action affects all of them',
            }), 403

    # reaching every linked cluster is not the same as being unconfined on them
    if any(caller_is_scoped(user, c) for c in linked):
        return jsonify({
            'error': 'Access denied: this action affects the whole backup server',
        }), 403
    return None


def _authz_pbs_backup(mgr, backup_type, backup_id, permission='vm.backup', user=None, scoped=None,
                      store=None, ns=None, owners=None):
    """NS Aug 2026 (sec-report, BOLA/CWE-639) — object-level scope for PBS backup ops.

    check_pbs_access only proves the caller reaches ONE of the PBS's linked clusters; it
    does NOT prove they own the VM/CT whose backup they're about to touch. A datastore is
    shared across every VM on every linked cluster, so a VM-ACL/pool-scoped user could
    delete/browse/download another tenant's backup by substituting its backup-id.

    Resolve the backup's owning VMID and require user_can_access_vm on it against one of the
    linked clusters (ACL/pool-scope-wins via the fixed chokepoint in rbac.py). Admins pass;
    a scoped user whose vmid can't be resolved (host-type or non-numeric id) is denied.
    Returns (ok, err_response).

    A caller who is not confined ANYWHERE on the linked clusters passes too — the same
    carve-out _scope_pbs_rows has had from the start. Without it, extending this gate to the
    read routes denied every plain operator and viewer on anything that is not a per-guest
    backup: garbage-collection, prune, verify and sync tasks, and host-type backups. Those are
    most of a PBS task list, and the listing route beside these hands them to the same caller,
    so the page listed a GC task and 403'd the moment anyone clicked it.

    `user` and `scoped` let a caller in a loop hand down what it already worked out.
    build_authz_user reads the whole users table and decrypts two TOTP columns per account, and
    caller_is_scoped enumerates pool grants and VM ACLs per linked cluster — _scope_pbs_rows
    runs this once per snapshot, so at 10k guests both are the difference between one lookup
    and hundreds of thousands, on a greenlet that yields to nobody while it runs.

    store/ns say where the backup lives, and the guest has to be the caller's on every cluster
    that may own that place (_BackupOwners) - not on any linked cluster that happens to use the
    same VMID (#1083). Leaving store out asks about all of them. `owners` is shared the same way
    as `user`."""
    from pegaprox.utils.rbac import user_can_access_vm
    if user is None:
        from pegaprox.utils.auth import build_authz_user
        user = build_authz_user(request.session.get('user', ''), request.session)
    if acts_as_admin(user):
        return True, None

    if scoped is None:
        scoped = _caller_is_scoped_here(mgr, user)
    if not scoped:
        return True, None                # plain cluster-wide operator — unchanged

    def _deny():
        # built on demand: constructing a Response for every row was the other half of the cost
        return False, (jsonify({'error': 'Access denied: you do not have permission for this backup'}), 403)

    bt = (backup_type or '').strip().lower()
    # only vm/ct backups carry a VMID we can scope; host/other → deny scoped users
    if bt not in ('vm', 'ct') or backup_id is None or not str(backup_id).strip().isdigit():
        return _deny()
    vmid = int(str(backup_id).strip())
    vm_type = 'lxc' if bt == 'ct' else 'qemu'
    # user_can_access_vm still enforces per-cluster ACL/pool scope, so an empty-scope user gets
    # no free pass here
    cluster_ids = (owners or _BackupOwners(mgr)).of(store, ns)
    if cluster_ids and all(user_can_access_vm(user, cid, vmid, permission, vm_type)
                           for cid in cluster_ids):
        return True, None
    return _deny()


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['DELETE'])
@require_auth(perms=['pbs.snapshot.delete'])
def pbs_delete_snapshot(pbs_id, store):
    """Delete a specific snapshot"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err

    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}

    required = ['backup_type', 'backup_id', 'backup_time']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing: {field}'}), 400

    # NS Aug 2026 (sec-report, BOLA) — per-backup scope: the owning VMID must be one the
    # caller can access; check_pbs_access above only proves server/tenant reach.
    _ok, _err = _authz_pbs_backup(mgr, data['backup_type'], data['backup_id'], 'vm.backup',
                                  store=store, ns=data.get('ns'))
    if not _ok:
        return _err

    result = mgr.delete_snapshot(store, data['backup_type'], data['backup_id'],
                                  data['backup_time'], ns=data.get('ns'))
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.snapshot.delete',
                  f"Deleted {data['backup_type']}/{data['backup_id']} @ {data['backup_time']} from {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/tasks', methods=['GET'])
@require_auth(perms=['pbs.tasks.view'])
def get_pbs_tasks(pbs_id):
    """List PBS tasks"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    limit = bounded_limit(request.args.get('limit'), 50, 1000)
    typefilter = request.args.get('typefilter', None)
    running = request.args.get('running', None)
    result = mgr.get_tasks(limit=limit, typefilter=typefilter,
                            running=bool(int(running)) if running is not None else None)
    # sec (audit) — the report path scopes these very rows; the raw list didn't, so a scoped
    # caller read every guest's backup history off the same server. Rows with no guest (gc,
    # prune, sync) carry no per-object question, so they go the same way as everywhere else:
    # kept for an unconfined caller, dropped for a confined one.
    return jsonify(_scope_pbs_rows(mgr, result.get('data', []) or [],
                                   key_fn=lambda t: _pbs_task_guest(t.get('worker_id') or t.get('id')),
                                   where_fn=lambda t: (_pbs_task_store(t.get('worker_id') or t.get('id')), '')))


@bp.route('/api/pbs/<pbs_id>/tasks/<path:upid>', methods=['GET'])
@require_auth(perms=['pbs.tasks.view'])
def get_pbs_task_detail(pbs_id, upid):
    """Get task status and log"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    # sec (audit) — the log names the archives and the guest it backed up
    _bt, _bid = _pbs_upid_guest(upid)
    ok, err = _authz_pbs_backup(mgr, _bt, _bid, 'vm.view', store=_pbs_task_store(upid), ns='')
    if not ok:
        return err
    status = mgr.get_task_status(upid)
    log = mgr.get_task_log(upid)
    return jsonify({
        'status': status.get('data', {}),
        'log': log.get('data', []),
    })


@bp.route('/api/pbs/<pbs_id>/jobs', methods=['GET'])
@require_auth(perms=['pbs.jobs.view'])
def get_pbs_jobs(pbs_id):
    """List all PBS jobs (sync, verify, prune)"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    sync = mgr.get_sync_jobs()
    verify = mgr.get_verify_jobs()
    prune = mgr.get_prune_jobs()
    
    return jsonify({
        'sync': sync.get('data', []),
        'verify': verify.get('data', []),
        'prune': prune.get('data', []),
    })


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>/run', methods=['POST'])
@require_auth(perms=['pbs.jobs.run'])
def run_pbs_job(pbs_id, job_type, job_id):
    """Manually trigger a PBS job"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'running a job')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    if job_type == 'sync':
        result = mgr.run_sync_job(job_id)
    elif job_type == 'verify':
        result = mgr.run_verify_job(job_id)
    elif job_type == 'prune':
        result = mgr.run_prune_job(job_id)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}', 
                  f"Started {job_type} job '{job_id}' on {mgr.name}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/namespaces', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_namespaces(pbs_id, store):
    """List namespaces in a datastore"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_namespaces(store)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/disks', methods=['GET'])
@require_auth(perms=['pbs.disks.view'])
def get_pbs_disks(pbs_id):
    """List disks on PBS server"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_disks()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/remotes', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_remotes(pbs_id):
    """List configured remotes"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_remotes()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/subscription', methods=['GET'])
@require_auth(perms=['pbs.subscription.view'])
def get_pbs_subscription(pbs_id):
    """Get PBS subscription status"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_subscription()
    return jsonify(result.get('data', {}))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/rrd', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastore_rrd(pbs_id, store):
    """Get RRD performance data for a datastore"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    timeframe = request.args.get('timeframe', 'hour')  # hour, day, week, month, year
    cf = request.args.get('cf', 'AVERAGE')  # AVERAGE, MAX
    result = mgr.get_datastore_rrd(store, timeframe=timeframe, cf=cf)
    return jsonify(result.get('data', []))


# ── PBS Snapshot & Group Notes ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/notes', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshot_notes(pbs_id, store):
    """Get notes for a specific snapshot"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    if not all([bt, bid, btime]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    # sec (audit) — same per-backup owner check the PUT twin below carries. A datastore spans
    # every guest on every linked cluster, so reading is as much a boundary as writing.
    ok, err = _authz_pbs_backup(mgr, bt, bid, 'vm.view', store=store, ns='')
    if not ok:
        return err
    result = mgr.get_snapshot_notes(store, bt, bid, int(btime))
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'notes': result.get('data', '')})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/notes', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.notes'])
def set_pbs_snapshot_notes(pbs_id, store):
    """Set notes for a specific snapshot"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    btime = data.get('backup-time')
    notes = data.get('notes', '')
    if not all([bt, bid, btime is not None]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    # NS Aug 2026 (audit) — per-backup owner check (delete/browse/download all carry it); a shared
    # datastore spans tenants, so without this a scoped user could rewrite another tenant's backup.
    ok, err = _authz_pbs_backup(mgr, bt, bid, store=store, ns='')
    if not ok:
        return err
    result = mgr.set_snapshot_notes(store, bt, bid, int(btime), notes)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/group-notes', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_group_notes(pbs_id, store):
    """Get notes for a backup group"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    if not all([bt, bid]):
        return jsonify({'error': 'Missing backup-type or backup-id'}), 400
    ok, err = _authz_pbs_backup(mgr, bt, bid, 'vm.view', store=store, ns='')   # sec (audit), as above
    if not ok:
        return err
    result = mgr.get_group_notes(store, bt, bid)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'notes': result.get('data', '')})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/group-notes', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.notes'])
def set_pbs_group_notes(pbs_id, store):
    """Set notes for a backup group"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    notes = data.get('notes', '')
    if not all([bt, bid]):
        return jsonify({'error': 'Missing backup-type or backup-id'}), 400
    # NS Aug 2026 (audit) — per-backup owner check; a shared datastore spans tenants.
    ok, err = _authz_pbs_backup(mgr, bt, bid, store=store, ns='')
    if not ok:
        return err
    result = mgr.set_group_notes(store, bt, bid, notes)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

# ── PBS Snapshot Protection ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/protected', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.protect'])
def set_pbs_snapshot_protected(pbs_id, store):
    """Set protected flag on a snapshot"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    btime = data.get('backup-time')
    protected = data.get('protected', True)
    if not all([bt, bid, btime is not None]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    # NS Aug 2026 (audit) — per-backup owner check; protect-flag tamper on a shared datastore
    # (clear→enables a later prune to delete a co-tenant's backup; set→blocks their pruning).
    ok, err = _authz_pbs_backup(mgr, bt, bid, store=store, ns='')
    if not ok:
        return err
    result = mgr.set_snapshot_protected(store, bt, bid, int(btime), protected)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

# ── PBS Traffic Control ──

@bp.route('/api/pbs/<pbs_id>/traffic-control', methods=['GET'])
@require_auth(perms=['pbs.traffic.view'])
def get_pbs_traffic_control(pbs_id):
    """Get traffic control / bandwidth limit configuration"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_traffic_control()
    return jsonify(result.get('data', []))

# ── PBS Syslog ──

@bp.route('/api/pbs/<pbs_id>/syslog', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_syslog(pbs_id):
    """Get PBS server syslog entries"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    limit = bounded_limit(request.args.get('limit'), 100, 1000)
    since = request.args.get('since')
    result = mgr.get_syslog(limit=limit, since=since)
    failed = pbs_upstream_error(result)
    if failed:
        status, payload = failed
        return jsonify(payload), status
    return jsonify(result.get('data', []))

# ── PBS Node RRD ──

@bp.route('/api/pbs/<pbs_id>/rrd', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_node_rrd(pbs_id):
    """Get PBS node-level RRD performance data"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    timeframe = request.args.get('timeframe', 'hour')
    cf = request.args.get('cf', 'AVERAGE')
    result = mgr.get_node_rrd(timeframe=timeframe, cf=cf)
    return jsonify(result.get('data', []))

# ── PBS Notifications ──

@bp.route('/api/pbs/<pbs_id>/notifications', methods=['GET'])
@require_auth(perms=['pbs.notifications.view'])
def get_pbs_notifications(pbs_id):
    """Get PBS notification config (targets + matchers)"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    # NS Oct 2026 (#1012) - targets and matchers belong to the whole PBS, not to a tenant: they
    # carry webhook URLs and mail settings, and every tenant's backup alerts go through them
    _wide = require_pbs_wide(pbs_id, 'the notification settings')
    if _wide:
        return _wide
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    # Try to get both targets and matchers
    targets_result = mgr.get_notification_targets()
    matchers_result = mgr.get_notification_matchers()
    # Notification endpoints may differ between PBS versions, handle gracefully
    targets = targets_result.get('data', []) if isinstance(targets_result, dict) and 'error' not in targets_result else []
    matchers = matchers_result.get('data', []) if isinstance(matchers_result, dict) and 'error' not in matchers_result else []
    # MK Sep 2026 (#803) — the two lists stay independent (one PBS version dropping matchers
    # shouldn't blank the targets), but say WHICH one we failed to read. Empty-because-none
    # and empty-because-refused rendered identically before, i.e. as nothing at all.
    errors = {}
    for key, res in (('targets', targets_result), ('matchers', matchers_result)):
        failed = pbs_upstream_error(res)
        if failed:
            errors[key] = failed[1]
    payload = {'targets': targets, 'matchers': matchers}
    if errors:
        payload['errors'] = errors
    return jsonify(payload)

# ── PBS Catalog / File-Level Restore ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/catalog', methods=['GET'])
@require_auth(perms=['pbs.snapshot.browse'])
def browse_pbs_catalog(pbs_id, store):
    """Browse file catalog of a backup snapshot"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    filepath = request.args.get('filepath', '/')
    if not all([bt, bid, btime]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    # NS Aug 2026 (sec-report, BOLA) — per-backup scope on top of the server/tenant gate
    _ok, _err = _authz_pbs_backup(mgr, bt, bid, 'vm.backup', store=store, ns='')
    if not _ok:
        return _err
    result = mgr.browse_catalog(store, bt, bid, int(btime), filepath)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result.get('data', []))

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/file-download', methods=['GET'])
@require_auth(perms=['pbs.snapshot.browse'])
def download_pbs_file(pbs_id, store):
    """Download a file from a backup snapshot (file-level restore)"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    filepath = request.args.get('filepath')
    if not all([bt, bid, btime, filepath]):
        return jsonify({'error': 'Missing parameters'}), 400
    # NS Aug 2026 (sec-report, BOLA) — per-backup scope: only stream files from a backup
    # whose owning VMID the caller can access, not any backup on a reachable datastore.
    _ok, _err = _authz_pbs_backup(mgr, bt, bid, 'vm.backup', store=store, ns='')
    if not _ok:
        return _err
    try:
        resp = mgr.download_file_from_snapshot(store, bt, bid, int(btime), filepath)
        if resp is None or resp.status_code != 200:
            status = resp.status_code if resp else 502
            return upstream_failure(status, f'Download failed: HTTP {status}', system='The PBS server')
        # Extract filename from filepath + sanitize for Content-Disposition header injection
        import re as _re
        filename = filepath.rstrip('/').split('/')[-1] or 'download'
        filename = _re.sub(r'["\r\n\x00-\x1f]', '', filename)  # NS Feb 2026 - strip control chars
        content_type = resp.headers.get('content-type', 'application/octet-stream')
        from flask import Response
        # MK Sep 2026 - api_get_raw already asks PBS for a streamed response, and its
        # docstring says the point is to stream it on to the client. `resp.content`
        # threw that away: it pulls the WHOLE file into the hub's memory first, so a
        # file-level restore of anything large is a self-inflicted outage. Hand the
        # iterator to Flask instead and keep the length only when PBS told us one.
        _len = resp.headers.get('content-length')
        _headers = {'Content-Disposition': f'attachment; filename="{filename}"'}
        if _len:
            _headers['Content-Length'] = _len
        return Response(
            resp.iter_content(chunk_size=64 * 1024),
            mimetype=content_type,
            headers=_headers,
        )
    except Exception as e:
        logging.error(f"[PBS:{pbs_id}] File download error: {e}")
        return jsonify({'error': safe_error(e, 'PBS operation failed')}), 500


# ── PBS Datastore CRUD ── NS: Feb 2026 ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/config', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastore_config(pbs_id, store):
    """Get datastore configuration (retention, GC schedule, notifications, etc.)"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_datastore_config(store)
    if 'error' in result:
        return upstream_failure(result.get('status_code'), result['error'], system='The PBS server')
    return jsonify(result.get('data', result))


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['POST'])
@require_auth(perms=['pbs.datastore.create'])
def create_pbs_datastore(pbs_id):
    """Create a new datastore on a PBS server
    
    NS: This creates the datastore config on the PBS. The path must already exist 
    on the PBS filesystem - we can't create directories remotely.
    """
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'creating a datastore')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    name = data.get('name', '').strip()
    path = data.get('path', '').strip()
    
    if not name:
        return jsonify({'error': 'Datastore name is required'}), 400
    if not path:
        return jsonify({'error': 'Path is required'}), 400
    
    # Validate name format (PBS only allows alphanumeric + dash + underscore)
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]*$', name):
        return jsonify({'error': 'Datastore name must start with a letter/number and contain only alphanumeric, dash, or underscore'}), 400
    
    # Build kwargs for PBSManager method
    kwargs = {}
    if data.get('comment'):
        kwargs['comment'] = data['comment']
    if data.get('gc_schedule') is not None:
        kwargs['gc_schedule'] = data['gc_schedule']
    for retention_key in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
        if data.get(retention_key) is not None:
            try:
                kwargs[retention_key] = int(data[retention_key])
            except (ValueError, TypeError):
                pass
    if data.get('verify_new') is not None:
        kwargs['verify_new'] = bool(data['verify_new'])
    if data.get('notify') is not None:
        kwargs['notify'] = data['notify']
    if data.get('notify_user') is not None:
        kwargs['notify_user'] = data['notify_user']
    
    result = mgr.create_datastore(name=name, path=path, **kwargs)
    
    if 'error' in result:
        return jsonify(result), 400
    
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.created',
              f"Created datastore '{name}' at '{path}' on PBS {mgr.name}")
    
    return jsonify({'message': f'Datastore {name} created successfully', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/config', methods=['PUT'])
@require_auth(perms=['pbs.datastore.modify'])
def update_pbs_datastore_config(pbs_id, store):
    """Update datastore configuration (retention, GC schedule, etc.)"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing a datastore')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    kwargs = {}
    if 'comment' in data:
        kwargs['comment'] = data['comment']
    if 'gc_schedule' in data:
        kwargs['gc_schedule'] = data['gc_schedule']
    for retention_key in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
        if retention_key in data:
            try:
                kwargs[retention_key] = int(data[retention_key]) if data[retention_key] is not None else None
            except (ValueError, TypeError):
                pass
    if 'verify_new' in data:
        kwargs['verify_new'] = bool(data['verify_new'])
    if 'notify' in data:
        kwargs['notify'] = data['notify']
    if 'notify_user' in data:
        kwargs['notify_user'] = data['notify_user']
    if data.get('delete'):
        kwargs['delete'] = data['delete'] if isinstance(data['delete'], list) else [data['delete']]
    
    if not kwargs:
        return jsonify({'error': 'No changes provided'}), 400
    
    result = mgr.update_datastore(store=store, **kwargs)
    
    if 'error' in result:
        return jsonify(result), 400
    
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.updated',
              f"Updated datastore '{store}' config on PBS {mgr.name}: {list(kwargs.keys())}")
    
    return jsonify({'message': f'Datastore {store} updated successfully', 'data': result.get('data')})


@bp.route('/api/pbs/<pbs_id>/datastores/<store>', methods=['DELETE'])
@require_auth(perms=['pbs.datastore.delete'])
def delete_pbs_datastore(pbs_id, store):
    """Remove a datastore from PBS configuration
    
    NS: By default this only removes the config - actual backup data on disk stays.
    This is the safe default. To also destroy data, send keep_data=false (dangerous!).
    """
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'removing a datastore')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    keep_data = data.get('keep_data', True)
    
    # Extra safety: require explicit confirmation for data destruction
    if not keep_data and not data.get('confirm_destroy'):
        return jsonify({
            'error': 'Data destruction requires explicit confirmation',
            'hint': 'Send confirm_destroy=true to permanently delete all backup data'
        }), 400
    
    result = mgr.delete_datastore(store=store, keep_data=keep_data)
    
    if 'error' in result:
        return jsonify(result), 400
    
    action = 'removed (data kept)' if keep_data else 'DESTROYED (data deleted!)'
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.deleted',
              f"Datastore '{store}' {action} on PBS {mgr.name}")
    
    return jsonify({'message': f'Datastore {store} {action}', 'data': result.get('data')})



# ── PBS Job CRUD ── NS: Feb 2026 ──

@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>', methods=['POST'])
@require_auth(perms=['pbs.jobs.create'])
def create_pbs_job(pbs_id, job_type):
    """Create a new sync/verify/prune job"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'creating a job')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    job_id = data.get('id', '').strip()
    store = data.get('store', '').strip()
    if not job_id or not store:
        return jsonify({'error': 'Job ID and store are required'}), 400
    
    if job_type == 'sync':
        if not data.get('remote') or not data.get('remote_store'):
            return jsonify({'error': 'Remote and remote_store are required for sync jobs'}), 400
        result = mgr.create_sync_job(job_id, store, data['remote'], data['remote_store'],
                                     schedule=data.get('schedule'), comment=data.get('comment'),
                                     remove_vanished=data.get('remove_vanished'),
                                     ns=data.get('ns'), max_depth=data.get('max_depth'))
    elif job_type == 'verify':
        result = mgr.create_verify_job(job_id, store, schedule=data.get('schedule'),
                                       ignore_verified=data.get('ignore_verified'),
                                       outdated_after=data.get('outdated_after'),
                                       comment=data.get('comment'), ns=data.get('ns'))
    elif job_type == 'prune':
        result = mgr.create_prune_job(job_id, store, schedule=data.get('schedule'),
                                      keep_last=data.get('keep_last'), keep_daily=data.get('keep_daily'),
                                      keep_weekly=data.get('keep_weekly'), keep_monthly=data.get('keep_monthly'),
                                      keep_yearly=data.get('keep_yearly'),
                                      comment=data.get('comment'), ns=data.get('ns'))
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.created',
              f"Created {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>', methods=['PUT'])
@require_auth(perms=['pbs.jobs.modify'])
def update_pbs_job(pbs_id, job_type, job_id):
    """Update a job configuration"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing a job')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    if job_type == 'sync':
        result = mgr.update_sync_job(job_id, **data)
    elif job_type == 'verify':
        result = mgr.update_verify_job(job_id, **data)
    elif job_type == 'prune':
        result = mgr.update_prune_job(job_id, **data)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.updated',
              f"Updated {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job updated', 'data': result.get('data')})


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>', methods=['DELETE'])
@require_auth(perms=['pbs.jobs.delete'])
def delete_pbs_job(pbs_id, job_type, job_id):
    """Delete a job"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'removing a job')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    if job_type == 'sync':
        result = mgr.delete_sync_job(job_id)
    elif job_type == 'verify':
        result = mgr.delete_verify_job(job_id)
    elif job_type == 'prune':
        result = mgr.delete_prune_job(job_id)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.deleted',
              f"Deleted {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job {job_id} deleted'})


# ── PBS Task Stop ──

@bp.route('/api/pbs/<pbs_id>/tasks/<path:upid>', methods=['DELETE'])
@require_auth(perms=['pbs.tasks.stop'])
def stop_pbs_task(pbs_id, upid):
    """Stop a running PBS task"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'stopping a task')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.stop_task(upid)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.task.stopped',
              f"Stopped task on PBS {mgr.name}: {upid[-20:]}")
    return jsonify({'message': 'Task stop requested'})


# ── PBS Notification CRUD ──

@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>', methods=['POST'])
@require_auth(perms=['pbs.notifications.manage'])
def create_pbs_notification_target(pbs_id, target_type):
    """Create a notification target (sendmail, gotify, smtp, webhook)"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing the notification settings')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.pop('name', '').strip()
    if not name:
        return jsonify({'error': 'Target name is required'}), 400
    result = pbs_managers[pbs_id].create_notification_target(target_type, name, **data)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.notification.target.created',
              f"Created {target_type} notification target '{name}'")
    return jsonify({'message': f'Notification target created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>/<name>', methods=['PUT'])
@require_auth(perms=['pbs.notifications.manage'])
def update_pbs_notification_target(pbs_id, target_type, name):
    """Update a notification target"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing the notification settings')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_notification_target(target_type, name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': f'Notification target updated'})


@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.notifications.manage'])
def delete_pbs_notification_target(pbs_id, target_type, name):
    """Delete a notification target"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing the notification settings')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_notification_target(target_type, name)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.notification.target.deleted',
              f"Deleted notification target '{name}'")
    return jsonify({'message': f'Notification target deleted'})


@bp.route('/api/pbs/<pbs_id>/notifications/matchers', methods=['POST'])
@require_auth(perms=['pbs.notifications.manage'])
def create_pbs_notification_matcher(pbs_id):
    """Create a notification matcher"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing the notification settings')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.pop('name', '').strip()
    if not name:
        return jsonify({'error': 'Matcher name is required'}), 400
    result = pbs_managers[pbs_id].create_notification_matcher(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/notifications/matchers/<name>', methods=['PUT'])
@require_auth(perms=['pbs.notifications.manage'])
def update_pbs_notification_matcher(pbs_id, name):
    """Update a notification matcher"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing the notification settings')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_notification_matcher(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher updated'})


@bp.route('/api/pbs/<pbs_id>/notifications/matchers/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.notifications.manage'])
def delete_pbs_notification_matcher(pbs_id, name):
    """Delete a notification matcher"""
    # Check PBS access authorization
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing the notification settings')
    if _wide:
        return _wide
    
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_notification_matcher(name)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher deleted'})


# ── PBS Traffic Control CRUD ──

@bp.route('/api/pbs/<pbs_id>/traffic-control', methods=['POST'])
@require_auth(perms=['pbs.traffic.manage'])
def create_pbs_traffic_control(pbs_id):
    """Create a traffic control rule"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing traffic control')
    if _wide:
        return _wide
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Rule name is required'}), 400
    result = pbs_managers[pbs_id].create_traffic_control(**data)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.traffic.created',
              f"Created traffic control rule '{name}'")
    return jsonify({'message': 'Traffic control rule created'}), 201


@bp.route('/api/pbs/<pbs_id>/traffic-control/<name>', methods=['PUT'])
@require_auth(perms=['pbs.traffic.manage'])
def update_pbs_traffic_control(pbs_id, name):
    """Update a traffic control rule"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing traffic control')
    if _wide:
        return _wide
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_traffic_control(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Traffic control rule updated'})


@bp.route('/api/pbs/<pbs_id>/traffic-control/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.traffic.manage'])
def delete_pbs_traffic_control_rule(pbs_id, name):
    """Delete a traffic control rule"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'changing traffic control')
    if _wide:
        return _wide
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_traffic_control(name)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.traffic.deleted',
              f"Deleted traffic control rule '{name}'")
    return jsonify({'message': 'Traffic control rule deleted'})


# ── PBS Disk SMART ──

@bp.route('/api/pbs/<pbs_id>/disks/<path:disk>/smart', methods=['GET'])
@require_auth(perms=['pbs.disks.smart'])
def get_pbs_disk_smart(pbs_id, disk):
    """Get SMART data for a disk"""
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_disk_smart(disk)
    if 'error' in result:
        return upstream_failure(result.get('status_code'), result['error'], system='The PBS server')
    return jsonify(result.get('data', result))


# ── PBS Subscription Set ──

@bp.route('/api/pbs/<pbs_id>/subscription', methods=['POST'])
@require_auth(perms=['pbs.subscription.set'])
def set_pbs_subscription(pbs_id):
    """Set subscription key"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    _wide = require_pbs_wide(pbs_id, 'setting the subscription')
    if _wide:
        return _wide
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    key = data.get('key', '').strip()
    if not key:
        return jsonify({'error': 'Subscription key is required'}), 400
    result = pbs_managers[pbs_id].set_subscription(key)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.subscription.set',
              f"Updated subscription on PBS {pbs_managers[pbs_id].name}")
    return jsonify({'message': 'Subscription updated'})


# ── PBS Network/DNS/Time (read-only) ──

@bp.route('/api/pbs/<pbs_id>/network', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_network(pbs_id):
    """Get PBS server network config"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_network()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/dns', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_dns(pbs_id):
    """Get PBS server DNS config"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_dns()
    return jsonify(result.get('data', {}))


@bp.route('/api/pbs/<pbs_id>/time', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_time(pbs_id):
    """Get PBS server time/timezone"""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_time()
    return jsonify(result.get('data', {}))


# ============================================================================
# Backup Verification — NS Apr 2026
# ============================================================================

# ============================================================================
# PBS Reports — issue #273 (Bradley-Radomski, cberr2024)
# Exportable backup reports for audit use cases (ISO 27001, SOC2, CMMC).
# Main question the reporter wanted answered: "prove that <VM X> was backed up
# on <day Y>, and where". Covered by summary + inventory endpoints below.
# ----------------------------------------------------------------------------
# Helpers shared by the three endpoints below.

def _pbs_collect_snapshots(mgr, protected_only=False, min_backup_time=0):
    """Walk all datastores and namespaces and return a flat list of snapshots.

    Each entry carries the originating datastore + namespace. We purposely do
    not cache — the report is refreshed on demand and the numbers must be
    current for audit use.
    """
    entries = []
    ds_resp = mgr.get_datastores() or {}
    for ds in (ds_resp.get('data', []) or []):
        store = ds.get('name', '')
        if not store:
            continue
        # Figure out which namespaces live under this store. Empty '' is the
        # root namespace and always exists even if there are no sub-namespaces.
        namespaces = ['']
        try:
            ns_resp = mgr.get_namespaces(store) or {}
            ns_list = [n.get('ns', '') for n in (ns_resp.get('data', []) or [])]
            namespaces = list({'', *ns_list})
        except Exception:
            pass
        for ns in namespaces:
            try:
                snap_resp = mgr.get_snapshots(store, ns=ns or None) or {}
            except Exception:
                continue
            for s in (snap_resp.get('data', []) or []):
                if min_backup_time and s.get('backup-time', 0) < min_backup_time:
                    continue
                if protected_only and not s.get('protected'):
                    continue
                s['_datastore'] = store
                s['_namespace'] = ns or ''
                entries.append(s)
    return entries


def _pbs_resolve_vm_names(mgr, cluster_ids=None):
    """Walk each linked PVE cluster and build (type, vmid_str) -> name.
    type is normalized to 'vm' / 'ct' to match PBS worker-id conventions.
    cluster_ids keeps only those of the linked clusters.
    """
    names = {}
    linked = list(mgr.linked_clusters or [])
    for cid in (linked if cluster_ids is None else [c for c in linked if c in cluster_ids]):
        pve_mgr = cluster_managers.get(cid)
        if not pve_mgr or not getattr(pve_mgr, 'is_connected', False):
            continue
        try:
            resources = pve_mgr.get_vm_resources() or []
        except Exception:
            continue
        for r in resources:
            t = r.get('type')
            if t == 'qemu':
                vt = 'vm'
            elif t == 'lxc':
                vt = 'ct'
            else:
                continue
            names[(vt, str(r.get('vmid', '')))] = r.get('name', '')
    return names


def _pbs_names_by_place(mgr, owners):
    """name(store, ns, (type, vmid)) for report rows: the guest's name on the clusters that may
    own that place, so a vm/100 is not named after another cluster's VM 100 (#1083). A report
    has thousands of rows and a handful of owner sets, hence the memo."""
    memo = {}

    def name(store, ns, key):
        cids = tuple(owners.of(store, ns))
        if cids not in memo:
            memo[cids] = _pbs_resolve_vm_names(mgr, cids)
        return memo[cids].get(key, '')
    return name


@bp.route('/api/pbs/<pbs_id>/reports/summary', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_summary(pbs_id):
    """Aggregated backup report over a time window.

    Covers the executive-summary + per-VM rollup reports from #273.

    Query params:
      days      time window (default 30, max 365)
    """
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    import time
    import datetime as _dt

    try:
        days = max(1, min(365, int(request.args.get('days', 30))))
    except Exception:
        days = 30
    now_ts = int(time.time())
    since_ts = now_ts - days * 86400

    # ── Backup tasks in window ─────────────────────────────────────────────
    tasks_resp = mgr.get_tasks(limit=500, typefilter='backup', since=since_ts) or {}
    # sec (audit): check_pbs_access above only proves the caller reaches ONE of this PBS's linked
    # clusters, and pbs.view is a builtin ROLE_USER/ROLE_VIEWER permission — so the report described
    # every guest on the install. Drop the tasks whose guest the caller may not see BEFORE the
    # aggregation, so the totals and the per-day chart can't count them either.
    owners = _BackupOwners(mgr)
    tasks = _scope_pbs_rows(mgr, tasks_resp.get('data', []) or [],
                            key_fn=lambda t: _pbs_task_guest(t.get('worker_id') or t.get('id')),
                            where_fn=lambda t: (_pbs_task_store(t.get('worker_id') or t.get('id')), ''),
                            owners=owners)

    totals = {'jobs': 0, 'success': 0, 'warning': 0, 'failed': 0}
    per_day = {}          # YYYY-MM-DD -> {date, success, warning, failed}
    per_vm_latest = {}    # (type, vmid) -> latest task dict

    for t in tasks:
        # PBS task shape: {upid, starttime, endtime, status, worker_type, worker_id}
        if t.get('worker_type') != 'backup':
            continue
        totals['jobs'] += 1

        status_raw = (t.get('status') or '').strip()
        status_upper = status_raw.upper()
        if status_upper == 'OK':
            bucket = 'success'
        elif 'WARN' in status_upper:
            bucket = 'warning'
        else:
            bucket = 'failed'
        totals[bucket] += 1

        end_ts = t.get('endtime') or t.get('starttime') or 0
        if end_ts:
            day = _dt.datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d')
            if day not in per_day:
                per_day[day] = {'date': day, 'success': 0, 'warning': 0, 'failed': 0}
            per_day[day][bucket] += 1

        vm_type, vmid = _pbs_task_guest(t.get('worker_id') or t.get('id'))
        if vm_type:
            key = (vm_type, vmid)
            prev = per_vm_latest.get(key)
            if (prev is None
                    or (t.get('endtime') or 0) > (prev.get('endtime') or 0)):
                per_vm_latest[key] = t

    # ── Snapshot inventory for size/verify info ────────────────────────────
    snapshots = _scope_pbs_rows(mgr, _pbs_collect_snapshots(mgr), owners=owners)
    snapshots_by_key = {}   # (type, vmid_str) -> [snap, ...]
    for s in snapshots:
        key = (s.get('backup-type', ''), str(s.get('backup-id', '')))
        snapshots_by_key.setdefault(key, []).append(s)

    # unverified older than 30 days — used as a compliance-warning gauge
    cutoff_verify = now_ts - 30 * 86400
    unverified_old = 0
    for s in snapshots:
        v = s.get('verification') or {}
        state = v.get('state') if isinstance(v, dict) else None
        if state != 'ok' and s.get('backup-time', 0) < cutoff_verify:
            unverified_old += 1

    # ── Resolve VM names from linked clusters ──────────────────────────────
    vm_name = _pbs_names_by_place(mgr, owners)

    # ── Build per-VM rollup (Veeam-style last N per job) ───────────────────
    per_vm = []
    for (vm_type, vmid), task in per_vm_latest.items():
        snaps = snapshots_by_key.get((vm_type, vmid), [])
        latest_snap = max(snaps, key=lambda x: x.get('backup-time', 0)) if snaps else None

        end_ts = task.get('endtime') or 0
        start_ts = task.get('starttime') or 0
        duration = (end_ts - start_ts) if end_ts and start_ts else 0
        status_upper = (task.get('status') or '').upper()
        if status_upper == 'OK':
            status_label = 'success'
        elif 'WARN' in status_upper:
            status_label = 'warning'
        else:
            status_label = 'failed'

        latest_verify = {}
        if latest_snap:
            latest_verify = latest_snap.get('verification') or {}
            if not isinstance(latest_verify, dict):
                latest_verify = {}
        where = ((latest_snap.get('_datastore'), latest_snap.get('_namespace')) if latest_snap
                 else (_pbs_task_store(task.get('worker_id') or task.get('id')), ''))
        per_vm.append({
            'type': vm_type,
            'vmid': vmid,
            'vm_name': vm_name(*where, (vm_type, str(vmid))),
            'datastore': latest_snap.get('_datastore') if latest_snap else '',
            'namespace': latest_snap.get('_namespace') if latest_snap else '',
            'last_backup_ts': end_ts,
            'status': status_label,
            'size': latest_snap.get('size', 0) if latest_snap else 0,
            'duration_s': duration,
            'verified': latest_verify.get('state') == 'ok',
            'snapshot_count': len(snaps),
            'upid': task.get('upid', ''),
        })
    per_vm.sort(key=lambda x: x.get('last_backup_ts', 0), reverse=True)

    # ── Fill missing days so frontend chart renders gaps as zeros ──────────
    per_day_filled = []
    for i in range(days - 1, -1, -1):
        day = (_dt.datetime.fromtimestamp(now_ts) - _dt.timedelta(days=i)).strftime('%Y-%m-%d')
        per_day_filled.append(per_day.get(day, {'date': day, 'success': 0, 'warning': 0, 'failed': 0}))

    success_rate = (totals['success'] / totals['jobs'] * 100.0) if totals['jobs'] else 0.0

    return jsonify({
        'window': {'days': days, 'since_ts': since_ts, 'until_ts': now_ts},
        'totals': {**totals, 'success_rate': round(success_rate, 1)},
        'per_day': per_day_filled,
        'per_vm': per_vm,
        'inventory_snapshot_count': len(snapshots),
        'unverified_older_than_30d': unverified_old,
    })


@bp.route('/api/pbs/<pbs_id>/reports/inventory', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_inventory(pbs_id):
    """Flat list of every snapshot across all datastores/namespaces.

    Primary use-case from #273: audit question "prove X was backed up on day Y
    and where". This endpoint is the answer.

    Query params:
      days=0         filter to snapshots newer than N days (0 = no filter)
      protected=1    only protected snapshots
    """
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    import time
    try:
        days = int(request.args.get('days', 0))
    except Exception:
        days = 0
    protected_only = str(request.args.get('protected', '')).lower() in ('1', 'true', 'yes')
    now_ts = int(time.time())
    min_bt = (now_ts - days * 86400) if days > 0 else 0

    # "every snapshot across all datastores/namespaces" means every snapshot the CALLER may
    # read — see the note in the summary route above; this one also carries the owner. (audit)
    owners = _BackupOwners(mgr)
    raw = _scope_pbs_rows(mgr, _pbs_collect_snapshots(
        mgr, protected_only=protected_only, min_backup_time=min_bt), owners=owners)

    vm_name = _pbs_names_by_place(mgr, owners)

    entries = []
    for s in raw:
        verify = s.get('verification') or {}
        if not isinstance(verify, dict):
            verify = {}
        vtype = s.get('backup-type', '')
        vmid = str(s.get('backup-id', ''))
        entries.append({
            'type': vtype,
            'vmid': vmid,
            'vm_name': vm_name(s.get('_datastore'), s.get('_namespace'), (vtype, vmid)),
            'datastore': s.get('_datastore', ''),
            'namespace': s.get('_namespace', ''),
            'backup_time': s.get('backup-time', 0),
            'size': s.get('size', 0),
            'owner': s.get('owner', ''),
            'protected': bool(s.get('protected', False)),
            'comment': s.get('comment', '') or '',
            'verified': verify.get('state') == 'ok',
            'verified_state': verify.get('state') or None,
            'verified_time': verify.get('upid_time') if isinstance(verify, dict) else None,
            'files_count': len(s.get('files', []) or []),
        })
    entries.sort(key=lambda x: x['backup_time'], reverse=True)
    return jsonify({'entries': entries, 'count': len(entries)})


@bp.route('/api/pbs/<pbs_id>/reports/protected-vms', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_protected_vms(pbs_id):
    """Gap analysis — which cluster VMs/CTs are actually backed up.

    Essential for SOC2 "protected workloads" audit evidence (#273).

    Query params:
      cluster_id   (required) PVE cluster to check
      days=7       a VM counts as protected if its most recent snapshot is
                   within this window. Older ones land in 'stale'.
    """
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    cluster_id = request.args.get('cluster_id', '')
    if not cluster_id:
        return jsonify({'error': 'cluster_id query param required'}), 400
    # sec (private disclosure Sep 2026 — audit HIGH): cluster_id comes straight from the query
    # string and was never authorized — check_pbs_access only vets the PBS server (and passes
    # unconditionally for a PBS with no linked_clusters). A pbs.view holder could therefore name ANY
    # cluster and read its complete guest inventory plus which guests are unprotected. Gate the named
    # cluster, then scope the rows per-VM exactly like /vms-backup-status does.
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    pve_mgr = cluster_managers.get(cluster_id)
    if not pve_mgr:
        return jsonify({'error': 'Cluster not found'}), 404

    import time
    try:
        days = max(1, min(365, int(request.args.get('days', 7))))
    except Exception:
        days = 7
    cutoff = int(time.time()) - days * 86400

    try:
        resources = scope_vm_rows(cluster_id, pve_mgr.get_vm_resources() or [])
    except Exception as e:
        return jsonify({'error': f'Could not load cluster resources: {e}'}), 502

    # Most recent backup timestamp + datastore per (type, vmid)
    most_recent = {}
    snaps = _pbs_collect_snapshots(mgr)
    # NS Oct 2026 (#1083) - the rows above are this cluster's guests, but a vm/100 on the PBS can
    # be another linked cluster's VM 100. A confined caller only gets the backups that may be
    # this cluster's and that they may read; everyone else keeps the report as it was.
    from pegaprox.utils.auth import build_authz_user
    _caller = build_authz_user(request.session.get('user', ''), request.session)
    if (not acts_as_admin(_caller)
            and _caller_is_scoped_here(mgr, _caller)):
        owners = _BackupOwners(mgr)
        snaps = [s for s in _scope_pbs_rows(mgr, snaps, owners=owners)
                 if cluster_id in owners.of(s.get('_datastore'), s.get('_namespace'))]
    for s in snaps:
        key = (s.get('backup-type', ''), str(s.get('backup-id', '')))
        bt = s.get('backup-time', 0)
        cur = most_recent.get(key)
        if cur is None or bt > cur['ts']:
            most_recent[key] = {
                'ts': bt,
                'datastore': s.get('_datastore', ''),
                'namespace': s.get('_namespace', ''),
            }

    protected, unprotected, stale = [], [], []
    for r in resources:
        rtype = r.get('type')
        if rtype not in ('qemu', 'lxc'):
            continue
        vt = 'vm' if rtype == 'qemu' else 'ct'
        vmid = str(r.get('vmid', ''))
        info = most_recent.get((vt, vmid))
        entry = {
            'type': vt,
            'vmid': vmid,
            'vm_name': r.get('name', ''),
            'node': r.get('node', ''),
            'status': r.get('status', ''),
            'last_backup_ts': info['ts'] if info else 0,
            'datastore': info['datastore'] if info else '',
            'namespace': info['namespace'] if info else '',
        }
        if not info:
            unprotected.append(entry)
        elif info['ts'] < cutoff:
            stale.append(entry)
        else:
            protected.append(entry)

    protected.sort(key=lambda x: (x['vm_name'] or x['vmid']).lower())
    unprotected.sort(key=lambda x: (x['vm_name'] or x['vmid']).lower())
    stale.sort(key=lambda x: x['last_backup_ts'])

    return jsonify({
        'window': {'days': days, 'cutoff_ts': cutoff},
        'counts': {
            'protected': len(protected),
            'unprotected': len(unprotected),
            'stale': len(stale),
            'total': len(protected) + len(unprotected) + len(stale),
        },
        'protected': protected,
        'unprotected': unprotected,
        'stale': stale,
    })


# End of PBS Reports (#273)
# ============================================================================


@bp.route('/api/clusters/<cluster_id>/backup-verify', methods=['POST'])
@require_auth(perms=['vm.backup'])
def start_backup_verification(cluster_id):
    """Start a PBS backup verification (restore → boot → check → cleanup)"""
    from pegaprox.core.backup_verify import start_verification

    # MK May 2026 (#465 port) — cluster-scoped auth on cluster-id-keyed endpoints.
    # The earlier #476 batch only covered the pbs_id-keyed `/api/pbs/<id>` routes
    # via check_pbs_access; these `/api/clusters/<id>/backup-verify*` endpoints
    # use a different auth-key and went unprotected.
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json or {}
    required = ['node', 'vmid', 'backup_volid']
    for f in required:
        if f not in data:
            return jsonify({'error': f'Missing: {f}'}), 400

    # NS Aug 2026 (sec-report, BOLA) — verification restores + boots the backup, so it needs
    # the same per-VM ACL as a direct VM op; cluster reach alone let a vm.backup holder restore
    # ANY VM's backup on a reachable cluster. Also bind backup_volid's id to vmid so a scoped
    # user can't pass their own vmid but a foreign VM's archive.
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        _vmid = int(data['vmid'])
    except (ValueError, TypeError):
        return jsonify({'error': 'vmid must be a number'}), 400
    _volid = str(data.get('backup_volid') or '')
    _is_lxc = '/ct/' in _volid or _volid.endswith('.lxc.tar') or 'vzdump-lxc' in _volid
    if not user_can_access_vm(build_authz_user(request.session.get('user', ''), request.session),
                              cluster_id, _vmid, 'vm.backup', 'lxc' if _is_lxc else 'qemu'):
        return jsonify({'error': 'Access denied: you do not have permission for this VM'}), 403
    import re as _re
    _m = _re.search(r'/(?:vm|ct)/(\d+)/', _volid) or _re.search(r'-(?:qemu|lxc)-(\d+)-', _volid)
    # fail closed: a non-empty volid whose owning id we can't parse (unrecognised format) must
    # be rejected, not silently trusted — otherwise a scoped user passes their own vmid but a
    # foreign archive in an odd format and the bind is skipped.
    if _volid and (not _m or int(_m.group(1)) != _vmid):
        return jsonify({'error': 'Access denied: backup_volid does not belong to the given VM'}), 403

    data['cluster_id'] = cluster_id
    pve_mgr = cluster_managers[cluster_id]

    if not pve_mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    try:
        task_id = start_verification(pve_mgr, data)
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 409

    user = request.session.get('user', 'system')
    log_audit(user, 'backup.verify_started',
              f"Backup verification started for VM {data.get('vmid')} on {data.get('node')}")

    return jsonify({'success': True, 'task_id': task_id})


def _verification_rows_visible(cluster_id, rows):
    """sec (audit): start_backup_verification gates the target per VM (and binds the volid to
    the vmid), but the status, history and active reads beside it had only check_cluster_access
    — so a scoped caller could read back which of a co-tenant's guests were verified, when, and
    the archive names. The rows carry vmid, so apply the same question here."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    from pegaprox.api.helpers import caller_is_scoped
    _u = build_authz_user(request.session.get('user', ''), request.session)
    if not caller_is_scoped(_u, cluster_id):
        return rows
    out = []
    for r in rows or []:
        try:
            if user_can_access_vm(_u, cluster_id, int(dict(r).get('vmid')), 'vm.backup'):
                out.append(r)
        except (TypeError, ValueError):
            continue
    return out


@bp.route('/api/clusters/<cluster_id>/backup-verify/<task_id>', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_backup_verification_status(cluster_id, task_id):
    """Get status of a running or completed verification"""
    from pegaprox.core.backup_verify import get_verification, get_verification_history

    # MK May 2026 (#465 port) — cluster-scoped auth (see start_backup_verification)
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    # check active first
    status = get_verification(task_id)
    if status:
        # sec (audit): the registry is keyed on task_id alone, so a task belonging to ANOTHER
        # cluster answered here — and _verification_rows_visible passes an unconfined caller
        # through unchanged, which is exactly the caller whose tenant may not own that cluster.
        if status.get('cluster_id') != cluster_id:
            return jsonify({'error': 'Verification not found'}), 404
        if not _verification_rows_visible(cluster_id, [status]):
            return jsonify({'error': 'Verification not found'}), 404
        return jsonify(status)

    # check database
    db = get_db()
    try:
        row = db.query_one('SELECT * FROM backup_verifications WHERE id = ? AND cluster_id = ?',
                           (task_id, cluster_id))
        if row:
            result = dict(row)
            import json
            result['details'] = json.loads(result.get('details', '{}'))
            result['logs'] = result['details'].get('logs', [])
            if not _verification_rows_visible(cluster_id, [result]):
                return jsonify({'error': 'Verification not found'}), 404
            return jsonify(result)
    except Exception:
        pass

    return jsonify({'error': 'Verification not found'}), 404


@bp.route('/api/clusters/<cluster_id>/backup-verify/history', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_backup_verification_history(cluster_id):
    """Get verification history, optionally filtered by vmid"""
    from pegaprox.core.backup_verify import get_verification_history

    # MK May 2026 (#465 port) — cluster-scoped auth (see start_backup_verification)
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err

    vmid = request.args.get('vmid', type=int)
    limit = bounded_limit(request.args.get('limit'), 50, 1000)

    results = get_verification_history(cluster_id, vmid, limit)
    return jsonify(_verification_rows_visible(cluster_id, results))


@bp.route('/api/clusters/<cluster_id>/backup-verify/active', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_active_verifications(cluster_id):
    """Get all currently running verifications"""
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    from pegaprox.core.backup_verify import get_active_verifications

    active = get_active_verifications()
    # filter by cluster
    cluster_active = {k: v for k, v in active.items() if v.get('cluster_id') == cluster_id}
    # a scoped caller sees only their own guests' runs (see _verification_rows_visible)
    _keys = [k for k, v in cluster_active.items()
             if _verification_rows_visible(cluster_id, [v])]
    return jsonify({k: cluster_active[k] for k in _keys})


# ============================================================================
# NS May 2026 — PBS UX improvements: health score, fingerprint probe,
# capacity forecast, auto-storage, vm-backup-status, run-now.
# ============================================================================

@bp.route('/api/pbs/probe-fingerprint', methods=['POST'])
@require_auth(perms=['pbs.config'])
def probe_pbs_fingerprint():
    """Open a TLS connection to host:port and return the cert SHA-256 fingerprint.
    Used by the Add-PBS wizard so the user doesn't have to run openssl by hand.

    Body: {"host": "pbs.example.com", "port": 8007}
    """
    import socket as _sock
    import ssl as _ssl
    import hashlib

    data = request.json or {}
    host = (data.get('host') or '').strip()
    try:
        port = int(data.get('port') or 8007)
    except (TypeError, ValueError):
        return jsonify({'error': 'port must be a number'}), 400
    if not host or len(host) > 255:
        return jsonify({'error': 'host required'}), 400
    if not (1 <= port <= 65535):
        return jsonify({'error': 'invalid port'}), 400
    # SSRF-ish guard: same checks our outbound-url helper applies
    try:
        from pegaprox.utils.url_security import is_safe_outbound_url
        ok, reason = is_safe_outbound_url(f'https://{host}:{port}/',
                                          allowed_schemes=('https',),
                                          allow_private=True)  # PBS is usually on the LAN
        if not ok:
            return jsonify({'error': f'unsafe target: {reason}'}), 400
    except Exception:
        pass
    _why = _target_refusal(host)
    if _why:
        return jsonify({'error': _why}), 400

    ctx = _ssl._create_unverified_context()
    try:
        with _sock.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest().upper()
        # PBS expects fingerprint formatted with colons: AA:BB:CC...
        formatted = ':'.join(fp[i:i+2] for i in range(0, len(fp), 2))
        return jsonify({'fingerprint': formatted, 'host': host, 'port': port})
    except _sock.timeout:
        return jsonify({'error': f'TLS handshake timed out connecting to {host}:{port}'}), 504
    except (_sock.gaierror, ConnectionRefusedError, OSError) as e:
        return jsonify({'error': f'cannot reach {host}:{port}: {e}'}), 502
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/pbs/<pbs_id>/health', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_health(pbs_id):
    """0-100 health score for a PBS server. Aggregates multiple datastores."""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    mgr = pbs_managers[pbs_id]
    score = 100
    factors = []
    issues = []

    if not mgr.connected:
        return jsonify({
            'score': 0, 'band': 'critical',
            'factors': [{'key': 'api', 'label': 'API connectivity', 'value': 'offline', 'delta': -100}],
            'issues': ['PBS unreachable'],
        })

    # 1) Datastore capacity
    try:
        ds = mgr.get_datastores() or {}
        stores = ds.get('data', []) if isinstance(ds, dict) else (ds or [])
        # enrich with usage info (free/total/history)
        try:
            us = mgr.get_datastore_usage() or {}
            usage = us.get('data', []) if isinstance(us, dict) else (us or [])
            ux = {u.get('store'): u for u in usage if isinstance(u, dict)}
            for s in stores:
                if isinstance(s, dict):
                    s.update(ux.get(s.get('name') or s.get('store'), {}))
        except Exception:
            pass
    except Exception:
        stores = []
    worst_pct = 0.0
    worst_store = None
    for s in stores:
        total = (s.get('total') or s.get('detail', {}).get('total') or 0)
        avail = (s.get('avail') or s.get('detail', {}).get('avail') or 0)
        if total > 0:
            used_pct = ((total - avail) / total) * 100.0
            if used_pct > worst_pct:
                worst_pct = used_pct
                worst_store = s.get('store') or s.get('name') or '?'
    if worst_store is not None:
        d = -25 if worst_pct >= 95 else -15 if worst_pct >= 90 else -5 if worst_pct >= 80 else 0
        score += d
        factors.append({'key': 'capacity', 'label': 'Worst datastore',
                        'value': f'{worst_store} ({worst_pct:.0f}%)', 'delta': d,
                        'severity': 'critical' if worst_pct >= 95 else 'warning' if worst_pct >= 80 else 'ok'})
        if worst_pct >= 90:
            issues.append(f'{worst_store} {worst_pct:.0f}% full')

    # 2) GC age (last gc per store)
    import time as _t
    now = _t.time()
    oldest_gc_age_h = None
    for s in stores:
        gc = s.get('gc-status') or {}
        upid = gc.get('upid')
        # If upid present, gc has run; we can't easily get the timestamp without
        # parsing — fall back to checking the store's own timestamp if available.
        last = s.get('last-gc') or 0
        if last:
            age_h = (now - last) / 3600
            if oldest_gc_age_h is None or age_h > oldest_gc_age_h:
                oldest_gc_age_h = age_h
    if oldest_gc_age_h is not None:
        d = -10 if oldest_gc_age_h > 24 * 30 else -5 if oldest_gc_age_h > 24 * 7 else 0
        score += d
        factors.append({'key': 'gc', 'label': 'Last GC',
                        'value': f'{oldest_gc_age_h:.0f}h ago', 'delta': d,
                        'severity': 'warning' if d < 0 else 'ok'})
        if d < 0:
            issues.append(f'GC last ran {oldest_gc_age_h:.0f}h ago')

    # 3) Last backup push age (across all groups in all stores)
    youngest_age_h = None
    try:
        for s in stores:
            store_name = s.get('store') or s.get('name')
            if not store_name:
                continue
            try:
                _r = mgr.get_snapshots(store_name) or {}
                snaps = _r.get('data', []) if isinstance(_r, dict) else (_r or [])
            except Exception:
                continue
            for sn in snaps:
                bt = sn.get('backup-time') or 0
                if bt:
                    age = (now - bt) / 3600
                    if youngest_age_h is None or age < youngest_age_h:
                        youngest_age_h = age
    except Exception:
        pass
    if youngest_age_h is not None:
        d = -20 if youngest_age_h > 24 * 7 else -10 if youngest_age_h > 24 * 2 else 0
        score += d
        factors.append({'key': 'last_push', 'label': 'Newest backup',
                        'value': f'{youngest_age_h:.1f}h ago' if youngest_age_h < 48 else f'{youngest_age_h/24:.1f}d ago',
                        'delta': d,
                        'severity': 'warning' if d < 0 else 'ok'})
        if d < 0:
            issues.append(f'No fresh backups in {youngest_age_h/24:.1f}d')
    else:
        d = -5
        score += d
        factors.append({'key': 'last_push', 'label': 'Newest backup',
                        'value': '—', 'delta': d, 'severity': 'warning'})

    score = max(0, min(100, score))
    if score >= 90: band = 'excellent'
    elif score >= 70: band = 'good'
    elif score >= 50: band = 'warning'
    elif score >= 30: band = 'degraded'
    else: band = 'critical'
    import datetime as _dt
    return jsonify({
        'score': score, 'band': band,
        'factors': factors, 'issues': issues,
        'computed_at': _dt.datetime.utcnow().isoformat() + 'Z',
    })


@bp.route('/api/pbs/<pbs_id>/capacity-forecast', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_capacity_forecast(pbs_id):
    """Linear regression on historic free-space (per datastore) → ETA-to-full."""
    # NS Jul 2026 (CodeAnt re-scan IDOR) — per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'PBS offline'}), 503

    out = []
    try:
        ds = mgr.get_datastores() or {}
        stores = ds.get('data', []) if isinstance(ds, dict) else (ds or [])
        # enrich with usage info (free/total/history)
        try:
            us = mgr.get_datastore_usage() or {}
            usage = us.get('data', []) if isinstance(us, dict) else (us or [])
            ux = {u.get('store'): u for u in usage if isinstance(u, dict)}
            for s in stores:
                if isinstance(s, dict):
                    s.update(ux.get(s.get('name') or s.get('store'), {}))
        except Exception:
            pass
    except Exception:
        stores = []
    for s in stores:
        store = s.get('store') or s.get('name') or '?'
        # PBS exposes a 'history' array on the datastore (one sample per day,
        # newest last; values are usage ratio 0..1 or null).
        hist = s.get('history') or s.get('detail', {}).get('history') or []
        total = s.get('total') or s.get('detail', {}).get('total') or 0
        used = s.get('used') or s.get('detail', {}).get('used') or 0
        cur_pct = (used / total) * 100.0 if total > 0 else 0.0

        # cleanup history: keep only numeric samples
        samples = [(i, v) for i, v in enumerate(hist) if isinstance(v, (int, float))]
        eta_days = None
        slope_pct_per_day = 0.0
        if len(samples) >= 5:
            # linear regression y = a + b*x where y is usage ratio
            n = len(samples)
            sx = sum(i for i, _ in samples)
            sy = sum(v for _, v in samples)
            sxy = sum(i * v for i, v in samples)
            sxx = sum(i * i for i, _ in samples)
            denom = (n * sxx - sx * sx)
            if denom > 0:
                b = (n * sxy - sx * sy) / denom
                a = (sy - b * sx) / n
                # extrapolate to y = 1.0 (= 100% full)
                if b > 1e-9:
                    x_full = (1.0 - a) / b
                    last_x = samples[-1][0]
                    eta_days = max(0, x_full - last_x)
                    slope_pct_per_day = b * 100
        out.append({
            'store': store,
            'total_bytes': total, 'used_bytes': used,
            'used_pct': round(cur_pct, 1),
            'slope_pct_per_day': round(slope_pct_per_day, 3),
            'eta_days_to_full': round(eta_days, 1) if eta_days is not None else None,
            'samples': len(samples),
        })
    return jsonify(out)


@bp.route('/api/pbs/<pbs_id>/auto-storage', methods=['POST'])
@require_auth(perms=['pbs.config'])
def auto_attach_pbs_to_clusters(pbs_id):
    """Convenience: create a `pbs:` storage entry on each linked PVE cluster
    using the PBS server's stored credentials. Avoids the user having to retype
    everything in the storage form.

    Body: {"clusters": ["cluster_id1", ...], "storage_name": "pbs-wui",
           "content": "backup"}  — storage_name defaults to pbs-<pbs_name>.
    """
    # NS Aug 2026 (Aikido) — this pushes the PBS's stored credentials into a PVE storage
    # config, so authz the PBS object AND every target cluster before touching anything.
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    pbs_mgr = pbs_managers[pbs_id]
    body = request.json or {}
    # MK Sep 2026 - the authz loop below runs once per entry and then does real work per
    # entry. Unbounded and un-deduped, so the body sized the fan-out.
    cluster_ids, _lerr = bounded_list(body.get('clusters'), max_items=256, max_length=64,
                                      name='clusters')
    if _lerr:
        return jsonify({'error': _lerr}), 400
    cluster_ids = cluster_ids or list(pbs_mgr.linked_clusters or [])
    if not cluster_ids:
        return jsonify({'error': 'no clusters specified or linked'}), 400
    # NS Oct 2026 (#980) - the credentials go only where the server is linked. The tenant check
    # below takes any cluster the caller's tenant owns, so reaching the server through one
    # linked cluster was enough to plant its credentials on another. A global admin may still
    # attach it anywhere, and a server linked to nothing is open to everybody anyway.
    _linked = list(pbs_mgr.linked_clusters or [])
    if _linked and not caller_acts_as_admin():
        _off = [c for c in cluster_ids if c not in _linked]
        if _off:
            return jsonify({'error': 'Access denied: this PBS server is not linked to '
                                     + ', '.join(_off)}), 403
    # NS Aug 2026 (Aikido 469089213) — this injects the PBS's stored (often root@pam) credentials
    # into a PVE storage config, so check_cluster_access (which passes on the #555 pool / #248 ACL
    # fallback) is not enough: confine to clusters the caller's TENANT owns, like the storage
    # auto-balance arming guard (469089261). Admin / default-tenant (_owned None) unaffected.
    from pegaprox.utils.rbac import get_user_clusters as _guc_pbs
    from pegaprox.utils.auth import build_authz_user as _bau_pbs
    _owned = _guc_pbs(_bau_pbs(request.session.get('user', ''), request.session), include_pools=False)
    for _cid in cluster_ids:
        _ok, _err = check_cluster_access(_cid)
        if not _ok:
            return _err
        if _owned is not None and _cid not in _owned:
            return jsonify({'error': 'Access denied — target cluster not owned by your tenant'}), 403

    storage_name = (body.get('storage_name') or f"pbs-{pbs_mgr.name}").lower()
    storage_name = ''.join(c if c.isalnum() or c in ('-', '_', '.') else '-' for c in storage_name)
    if not storage_name or not storage_name[0].isalpha():
        storage_name = 'pbs-' + storage_name
    content = body.get('content') or 'backup'

    # Probe live fingerprint so we always inject a current one
    import socket as _sock, ssl as _ssl, hashlib
    from urllib3.util.ssl_ import assert_fingerprint as _assert_fp
    from urllib3.exceptions import SSLError as _FpMismatch
    try:
        ctx = _ssl._create_unverified_context()
        with _sock.create_connection((pbs_mgr.host, pbs_mgr.port or 8007), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=pbs_mgr.host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as e:
        return jsonify({'error': f'fingerprint probe failed: {e}'}), 502
    # NS Oct 2026 (#1074) - PVE is told to trust this certificate, next to the stored credentials,
    # and it was read unverified past the fingerprint the server is pinned to. A pinned server has
    # to present its pinned certificate now; one without a pin takes what the probe sees, as before.
    _pin = getattr(pbs_mgr, 'fingerprint', '')
    _pin = _pin.strip() if isinstance(_pin, str) else ''
    if _pin:
        try:
            _assert_fp(der, _pin)
        except _FpMismatch:
            logging.warning(f"[PBS:{pbs_id}] auto-storage refused: the certificate does not match the stored fingerprint")
            return jsonify({'error': 'The PBS server presents a certificate that does not match its '
                                     'stored fingerprint'}), 502
    fp_hex = hashlib.sha256(der).hexdigest().upper()
    fingerprint = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))

    pbs_user = getattr(pbs_mgr, 'user', None) or getattr(pbs_mgr, 'username', None)
    pbs_pass = getattr(pbs_mgr, 'password', None)
    if not pbs_user or not pbs_pass:
        return jsonify({'error': 'PBS server has no stored username/password (token-only? not yet supported here)'}), 400

    results = []
    for cid in cluster_ids:
        if cid not in cluster_managers:
            results.append({'cluster_id': cid, 'ok': False, 'error': 'cluster not found'})
            continue
        cm = cluster_managers[cid]
        if not cm.is_connected:
            results.append({'cluster_id': cid, 'ok': False, 'error': 'cluster offline'})
            continue
        url = f"https://{cm.host}:{cm.api_port}/api2/json/storage"
        data = {
            'storage': storage_name, 'type': 'pbs',
            'server': pbs_mgr.host, 'datastore': '',  # set below per-store iteration if multi
            'username': pbs_user, 'password': pbs_pass,
            'fingerprint': fingerprint, 'content': content,
        }
        # default datastore: first one
        try:
            _ds = pbs_mgr.get_datastores() or {}
            stores = _ds.get('data', []) if isinstance(_ds, dict) else (_ds or [])
            if stores:
                data['datastore'] = stores[0].get('store') or stores[0].get('name') or 'Backup'
        except Exception:
            data['datastore'] = body.get('datastore') or 'Backup'
        if pbs_mgr.port and pbs_mgr.port != 8007:
            data['port'] = pbs_mgr.port
        try:
            r = cm._create_session().post(url, data=data, timeout=60)
            if r.status_code == 200:
                results.append({'cluster_id': cid, 'ok': True, 'storage': storage_name,
                                'datastore': data['datastore']})
                log_audit(request.session.get('user', 'system'), 'pbs.storage_auto_attached',
                          f"Attached PBS '{pbs_mgr.name}' as storage '{storage_name}' on cluster {cm.config.name}")
            else:
                # Surface the PVE body
                err = ''
                try:
                    j = r.json()
                    err = j.get('errors') or j.get('message') or r.text
                    if isinstance(err, dict):
                        err = ', '.join(f'{k}: {v}' for k, v in err.items())
                except Exception:
                    err = r.text or f'HTTP {r.status_code}'
                results.append({'cluster_id': cid, 'ok': False, 'error': err, 'pve_status': r.status_code})
        except Exception as e:
            results.append({'cluster_id': cid, 'ok': False, 'error': str(e)})
    return jsonify({'results': results, 'storage_name': storage_name})


@bp.route('/api/clusters/<cluster_id>/storage-preflight', methods=['POST'])
@require_auth(perms=['storage.config'])
def storage_preflight(cluster_id):
    """Pre-validate a storage config before hitting PVE — gives clear errors
    instead of PVE's opaque 595. Currently focused on PBS but extensible.

    Body: same shape as /datacenter/storage POST.
    """
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    data = request.json or {}
    if data.get('type') != 'pbs':
        return jsonify({'ok': True, 'skipped': 'preflight only for type=pbs'})

    server = (data.get('server') or '').strip()
    port = int(data.get('port') or 8007)
    datastore = (data.get('datastore') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    given_fp = (data.get('fingerprint') or '').strip().upper().replace(' ', '')

    # SSRF guard (MK 2026-06-09, static-audit): the auth probe below POSTs the supplied
    # username/password to server:port — same outbound check probe_pbs_fingerprint uses,
    # so a tricked admin can't aim the credential POST at an arbitrary/metadata host.
    if not server:
        return jsonify({'ok': False, 'issues': ['server required'], 'info': {}}), 200
    try:
        from pegaprox.utils.url_security import is_safe_outbound_url
        _ok, _reason = is_safe_outbound_url(f'https://{server}:{port}/',
                                            allowed_schemes=('https',),
                                            allow_private=True)  # PBS is usually on the LAN
        if not _ok:
            return jsonify({'ok': False, 'issues': [f'unsafe target: {_reason}'], 'info': {}}), 200
    except Exception:
        pass
    _why = _target_refusal(server)
    if _why:
        return jsonify({'ok': False, 'issues': [_why], 'info': {}}), 200

    issues = []
    info = {}

    # 1) TCP reachability
    import socket as _sock, ssl as _ssl, hashlib
    from urllib3.util.ssl_ import assert_fingerprint as _assert_fp
    from urllib3.exceptions import SSLError as _FpMismatch
    try:
        with _sock.create_connection((server, port), timeout=6):
            info['tcp'] = 'ok'
    except Exception as e:
        return jsonify({'ok': False, 'issues': [f'TCP {server}:{port} unreachable: {e}'], 'info': info}), 200

    # 2) TLS + fingerprint
    try:
        ctx = _ssl._create_unverified_context()
        with _sock.create_connection((server, port), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=server) as ssock:
                der = ssock.getpeercert(binary_form=True)
        fp_hex = hashlib.sha256(der).hexdigest().upper()
        live_fp = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))
        info['live_fingerprint'] = live_fp
    except Exception as e:
        return jsonify({'ok': False, 'issues': [f'TLS handshake failed: {e}'], 'info': info}), 200
    # NS Oct 2026 (#1074) - a mismatch was only a line in the list, and the typed password went to
    # that server right after. It stays here now, and with a fingerprint given the login below
    # only talks to the certificate it names (colons and case no longer count as a mismatch).
    if given_fp:
        try:
            _assert_fp(der, given_fp)
        except _FpMismatch:
            issues.append(f'Fingerprint mismatch - server presents {live_fp[:16]}…, you supplied {given_fp[:16]}…')
            return jsonify({'ok': False, 'issues': issues, 'info': info}), 200

    # 3) Auth probe
    try:
        import requests as _r
        s = _r.Session(); s.verify = False
        if given_fp:
            from pegaprox.core.pbs import _PinnedFingerprintAdapter
            s.mount('https://', _PinnedFingerprintAdapter(given_fp))
        ar = s.post(f'https://{server}:{port}/api2/json/access/ticket',
                    data={'username': username, 'password': password}, timeout=8)
        if ar.status_code != 200:
            issues.append(f'PBS auth failed (HTTP {ar.status_code})')
            info['auth'] = 'fail'
        else:
            info['auth'] = 'ok'
            ticket = ar.json().get('data', {}).get('ticket')
            csrf = ar.json().get('data', {}).get('CSRFPreventionToken')
            # 4) Datastore exists?
            if datastore and ticket:
                ds_r = s.get(f'https://{server}:{port}/api2/json/admin/datastore',
                             cookies={'PBSAuthCookie': ticket}, timeout=8)
                if ds_r.status_code == 200:
                    names = [d.get('store') or d.get('name') for d in ds_r.json().get('data', [])]
                    info['datastores'] = names
                    if datastore not in names:
                        issues.append(f"Datastore '{datastore}' not found. Available: {', '.join(names) or '(none)'}")
    except Exception as e:
        issues.append(f'auth probe error: {e}')

    return jsonify({'ok': not issues, 'issues': issues, 'info': info})


# NS Jul 2026 (SSE-perf): the per-VM backup pill rode fetchClusterResources at 15s,
# re-scanning the FULL PBS snapshot catalog (O(PBS×datastores×snapshots)) + every
# online node's backup storages each time — backup age changes hourly, not per-15s.
# Cache the derived per-VM list per cluster. Only cache a COMPLETE scan for the full
# window; a partial scan (the 8s fan-out cap tripped → incomplete data) gets a short
# TTL so a transient PBS slowdown can't pin wrong 'stale/none' pills for 90s.
_backup_status_cache = {}
_BACKUP_STATUS_TTL = 90.0
_BACKUP_STATUS_TTL_PARTIAL = 15.0


@bp.route('/api/clusters/<cluster_id>/vms-backup-status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_vms_backup_status(cluster_id):
    """Per-VM backup health: last backup age, encryption flag, count over last 30d.
    Used by the VM list to render a status pill column.
    """
    # SECURITY (MK Jul 2026): this route was gated only by cluster.view (held by every
    # non-admin role) and never scoped to the caller — a scoped tenant could read
    # ANOTHER cluster's backup posture, and see backup pills for VMs they can't access.
    # Add the cluster gate + per-VM ACL scoping (mirrors get_cluster_resources,
    # clusters.py:1010-1044). The ACL filter runs AFTER the cache read so the cached
    # list stays cluster-global + reusable across users. Pre-existing gap, hardened here.
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503
    import time as _t
    now = _t.time()

    def _scope_backup_out(rows):
        # sec (private disclosure Sep 2026 — audit M2): the old inline filter honoured VM-ACLs +
        # global vm.view but NOT pool grants, so a pool-scoped caller with global vm.view saw the
        # whole cluster's backup posture. scope_vm_rows is the canonical per-VM gate (ACL + pool +
        # tenant, admins/plain operators keep all) used by /resources and search — reuse it.
        return scope_vm_rows(cluster_id, rows)

    _bc = _backup_status_cache.get(cluster_id)
    if _bc and (now - _bc[0]) < _bc[2]:
        return jsonify(_scope_backup_out(_bc[1]))
    return jsonify(_scope_backup_out(scan_backup_status(cluster_id, cm)))


def backup_status_entry(cluster_id):
    """(read at, rows, complete) of the last scan of a cluster, or None. A partial scan is
    the one cached with the short TTL. MK Oct 2026"""
    hit = _backup_status_cache.get(cluster_id)
    if not hit:
        return None
    return hit[0], hit[1], hit[2] >= _BACKUP_STATUS_TTL


def scan_backup_status(cluster_id, cm):
    """Read the newest backup of every guest of a cluster from the snapshot lists of the
    PBS servers linked to it and the vzdump files on its backup storages, cache the
    cluster-global list and return it. Unscoped: callers filter. The VM list pill and the
    Prometheus exporter share it."""
    import time as _t
    now = _t.time()
    cutoff_30d = now - (30 * 86400)

    # Aggregate snapshots across all PBS servers linked to this cluster + the
    # cluster's local backup storages (vzdump files).
    by_vm = {}  # vmid -> {last_age_h, count_30d, encrypted, last_verify_age_h}

    def _bump(vmid, ts, encrypted=False, verified_ts=None):
        rec = by_vm.setdefault(int(vmid), {
            'vmid': int(vmid), 'last_backup_ts': 0, 'count_30d': 0,
            'encrypted': False, 'last_verify_ts': 0,
        })
        if ts and ts > rec['last_backup_ts']:
            rec['last_backup_ts'] = ts
        if ts and ts >= cutoff_30d:
            rec['count_30d'] += 1
        if encrypted:
            rec['encrypted'] = True
        if verified_ts and verified_ts > rec['last_verify_ts']:
            rec['last_verify_ts'] = verified_ts

    # MK 2026-05-31 (F1b) — parallelise both fanouts: per-PBS-server and
    # per-PVE-node. Each task collects (vmid, ts, encrypted, verified_ts)
    # tuples in isolation, then we sequentially _bump them into by_vm at
    # the end. This separates network I/O (parallel) from shared-state
    # mutation (sequential) so we don't need a lock around by_vm.
    #
    # Was sequential: ΣPBS × Σdatastores + Σnodes × Σbackup-storages PVE
    # calls back-to-back on one worker. With 2+ PBS servers + 6+ nodes this
    # easily breached 10s and that's what was wedging /vms-backup-status.
    from pegaprox.utils.concurrent import run_concurrent_dict

    def _scan_pbs(pbs):
        """Returns list of (vmid, ts, encrypted, verified_ts) tuples for one PBS server."""
        bumps = []
        owners = _BackupOwners(pbs)
        try:
            _ds = pbs.get_datastores() or {}
            stores = _ds.get('data', []) if isinstance(_ds, dict) else (_ds or [])
        except Exception:
            stores = []
        for store in stores:
            if not isinstance(store, dict):
                continue
            store_name = store.get('store') or store.get('name')
            if not store_name:
                continue
            # another linked cluster's root namespace holds its own VM 100, not ours (#1083)
            if cluster_id not in owners.of(store_name, ''):
                continue
            try:
                _r = pbs.get_snapshots(store_name) or {}
                snaps = _r.get('data', []) if isinstance(_r, dict) else (_r or [])
            except Exception:
                continue
            for sn in snaps:
                if sn.get('backup-type') not in ('vm', 'ct'):
                    continue
                vmid = sn.get('backup-id')
                if not vmid:
                    continue
                ts = sn.get('backup-time') or 0
                files = sn.get('files') or []
                enc = any((f.get('crypt-mode') or 'none') != 'none' for f in files)
                verified_ts = 0
                v = sn.get('verification') or {}
                if v.get('state') == 'ok':
                    verified_ts = v.get('upid_time') or ts
                try:
                    bumps.append((int(vmid), ts, enc, verified_ts))
                except (ValueError, TypeError):
                    continue
        return bumps

    # MK 2026-05-31 (D2) — defense-in-depth: PVE-returned node names get
    # interpolated into URL paths below. PVE has its own naming rules but
    # if PVE itself were ever compromised, a crafted node like `../foo`
    # would let it pivot into other PVE namespaces. Cheap belt-and-suspenders
    # check at the boundary. Mirrors api/nodes.py:_NODE_NAME_RE.
    import re as _re
    _SAFE_NODE = _re.compile(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$')

    def _scan_node(node):
        """Returns list of (vmid, ts, encrypted, 0) tuples for one PVE node's vzdump backups."""
        bumps = []
        if not node or not _SAFE_NODE.match(node):
            return bumps
        try:
            r = cm._api_get(f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{node}/storage')
            stores = r.json().get('data', []) if r.status_code == 200 else []
        except Exception:
            return bumps
        for s in stores:
            if 'backup' not in (s.get('content') or ''):
                continue
            if s.get('type') == 'pbs':
                continue  # already counted PBS-side
            store_name = s.get('storage')
            # MK (D2 cont.) — same belt-and-suspenders for storage names
            if not store_name or not _SAFE_NODE.match(store_name):
                continue
            try:
                cr = cm._api_get(f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{node}/storage/{store_name}/content?content=backup')
                items = cr.json().get('data', []) if cr.status_code == 200 else []
            except Exception:
                items = []
            for it in items:
                vmid = it.get('vmid')
                ts = it.get('ctime') or 0
                if vmid is None:
                    continue
                try:
                    bumps.append((int(vmid), ts, bool(it.get('encryption')), 0))
                except (ValueError, TypeError):
                    continue
        return bumps

    # PBS-side tasks: one per linked + connected PBS server
    tasks = {}
    for pbs_id, pbs in list(pbs_managers.items()):
        if cluster_id not in (pbs.linked_clusters or []):
            continue
        if not pbs.connected:
            continue
        tasks[f'pbs:{pbs_id}'] = (lambda p=pbs: _scan_pbs(p))

    # PVE-side tasks: one per ONLINE node. Skip dead nodes — under parallel
    # fanout they'd park the joinall() at the full timeout, dragging total
    # wall-time. Sequential code happened to mask this because per-call
    # connect-fail was fast; parallel waits the slowest call.
    try:
        nodes_data = []
        try:
            nodes_data = cm._api_get(
                f'https://{cm.host}:{cm.api_port}/api2/json/nodes'
            ).json().get('data', []) or []
        except Exception:
            nodes_data = []
        for nd in nodes_data:
            name = nd.get('node')
            if not name:
                continue
            # PVE marks dead nodes 'offline' or status != 'online' on /nodes
            status = (nd.get('status') or '').lower()
            if status and status not in ('online', 'running'):
                continue
            tasks[f'node:{name}'] = (lambda nn=name: _scan_node(nn))
    except Exception as e:
        logging.debug(f'[vms-backup-status] node enum failed: {e}')

    _scan_complete = True
    if tasks:
        # Tight timeout: most PBS + healthy-node calls return in <2s. Anything
        # stuck longer contributes None and we move on with partial data.
        results = run_concurrent_dict(tasks, timeout=8)
        # a None result = a fan-out task that timed out → the aggregate is partial;
        # don't pin it for the full TTL (see cache note at the top of this route)
        _scan_complete = all(v is not None for v in results.values())
        for bumps in results.values():
            for (vmid, ts, enc, verified_ts) in (bumps or []):
                try:
                    _bump(vmid, ts, encrypted=enc, verified_ts=verified_ts)
                except (ValueError, TypeError):
                    continue

    # Finalize ages
    out = []
    for rec in by_vm.values():
        last_age_h = ((now - rec['last_backup_ts']) / 3600) if rec['last_backup_ts'] else None
        verify_age_h = ((now - rec['last_verify_ts']) / 3600) if rec['last_verify_ts'] else None
        # status: ok / warn / stale / none
        if last_age_h is None:
            status = 'none'
        elif last_age_h < 36:
            status = 'ok'
        elif last_age_h < 7 * 24:
            status = 'warn'
        else:
            status = 'stale'
        out.append({
            'vmid': rec['vmid'],
            'last_backup_ts': int(rec['last_backup_ts'] or 0),
            'last_backup_age_hours': round(last_age_h, 1) if last_age_h is not None else None,
            'count_30d': rec['count_30d'],
            'encrypted': rec['encrypted'],
            'last_verify_age_hours': round(verify_age_h, 1) if verify_age_h is not None else None,
            'status': status,
        })
    out.sort(key=lambda r: r['vmid'])
    # cache the UNFILTERED cluster-global list; scope per-request at return time
    _backup_status_cache[cluster_id] = (
        now, out, _BACKUP_STATUS_TTL if _scan_complete else _BACKUP_STATUS_TTL_PARTIAL)
    return out


@bp.route('/api/clusters/<cluster_id>/datacenter/backup/<job_id>/run', methods=['POST'])
@require_auth(perms=['vm.backup'])
def run_backup_job_now(cluster_id, job_id):
    """Trigger an existing backup job immediately. Reuses job parameters.

    Note: the job_id matches the UUID in /etc/pve/jobs.cfg (vzdump: <id>).
    """
    # NS Jul 2026 (CodeAnt re-scan auth-bypass/IDOR) — cluster-scoped route was missing the tenant gate
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503
    # Read all jobs from /cluster/backup, find ours
    try:
        r = cm._api_get(f'https://{cm.host}:{cm.api_port}/api2/json/cluster/backup')
        jobs = r.json().get('data', []) if r.status_code == 200 else []
    except Exception as e:
        return jsonify({'error': f'failed to fetch jobs: {e}'}), 502
    job = next((j for j in jobs if j.get('id') == job_id), None)
    if not job:
        return jsonify({'error': f'job {job_id} not found'}), 404

    # NS Aug 2026 (sec-report, BOLA) — a scoped vm.backup holder must not trigger a job that
    # targets VMs outside their scope. Re-use the create/update selection gate: all=1/pool/
    # exclude/empty selection is admin-only, explicit vmids are re-checked per-VM. The job's
    # own selection fields (all/pool/exclude/vmid) map straight onto that helper's expectations.
    from pegaprox.api.storage import _authz_backup_targets
    _aerr = _authz_backup_targets(cluster_id, job)
    if _aerr:
        return _aerr

    # Pick a node to run vzdump on. Prefer a node listed in the job's `node` field;
    # otherwise the first online node we know.
    pve_node = (job.get('node') or '').split(',')[0].strip()
    if not pve_node:
        try:
            ns = cm.get_node_status() or {}
            pve_node = next((n for n, d in ns.items() if d.get('status') == 'online'
                             or not d.get('offline')), None)
        except Exception:
            pve_node = None
    if not pve_node:
        return jsonify({'error': 'no online node available'}), 503

    # Build vzdump params from the job. Skip non-vzdump fields.
    params = {}
    skip = {'id', 'enabled', 'schedule', 'comment', 'next-run', 'type', 'node',
            'starttime', 'dow', 'repeat-missed', 'job_id'}
    for k, v in job.items():
        if k in skip or v is None or v == '':
            continue
        params[k] = v
    # 'all' / pool / vmid all transfer through

    url = f'https://{cm.host}:{cm.api_port}/api2/json/nodes/{pve_node}/vzdump'
    try:
        r = cm._api_post(url, data=params, timeout=30)
        if r.status_code == 200:
            upid = r.json().get('data')
            log_audit(request.session.get('user', 'system'), 'backup.run_now',
                      f"Triggered backup job {job_id} on {pve_node}", cluster=cm.config.name)
            return jsonify({'success': True, 'upid': upid, 'node': pve_node})
        return upstream_failure(r.status_code, r.text or f'HTTP {r.status_code}')
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


@bp.route('/api/clusters/<cluster_id>/backup-restore', methods=['POST'])
@require_auth(perms=['vm.backup'])
def restore_backup(cluster_id):
    """Restore a backup. Three modes:
      - mode='new':    qmrestore into a new VMID (target_vmid)
      - mode='overwrite': qmrestore into an existing VMID (force)
      - mode='test':   like the verify pipeline but skip auto-cleanup; user keeps the test VM

    Body: {volid, target_node, target_vmid, mode, target_storage?}
    """
    # MK: restore is destructive (qmrestore into a VMID) — gate on cluster access, not just vm.backup
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503

    body = request.json or {}
    volid = (body.get('volid') or '').strip()
    target_node = (body.get('target_node') or '').strip()
    target_storage = (body.get('target_storage') or '').strip()
    mode = (body.get('mode') or 'new').strip()
    if not volid or ':' not in volid:
        return jsonify({'error': 'volid is required (storage:backup/...)'}), 400
    if not target_node:
        return jsonify({'error': 'target_node is required'}), 400
    try:
        target_vmid = int(body.get('target_vmid'))
    except (ValueError, TypeError):
        return jsonify({'error': 'target_vmid must be a number'}), 400
    if mode not in ('new', 'overwrite', 'test'):
        return jsonify({'error': "mode must be 'new', 'overwrite', or 'test'"}), 400

    from pegaprox.utils.auth import build_authz_user
    _caller = build_authz_user(request.session.get('user', ''), request.session)
    _refused = _restore_refusal(cluster_id, _caller, volid, target_node, target_vmid, mode)
    if _refused:
        return _refused

    # MK Oct 2026 - 'new' and 'test' leave a guest of their own behind, 'overwrite' grows the
    # guest by what the backup has more of: the tenant quota counts it as a create would
    from pegaprox.core.batch_restore import restore_adds
    _src = next((r.search(volid) for r in _SOURCE_RES if r.search(volid)), None)
    _qerr, _qwarn = tenant_quota_gate(
        _caller, f'restore of {volid}',
        lambda: restore_adds(cm, target_node, volid, int(_src.group(1)) if _src else 0, target_vmid,
                             mode == 'overwrite'),
        cluster=cm.config.name,
        hold={'cluster_id': cluster_id, 'vmid': target_vmid, 'grow': mode == 'overwrite'})
    if _qerr:
        return _qerr

    # Test-mode = verify pipeline without cleanup
    if mode == 'test':
        from pegaprox.core.backup_verify import start_verification
        try:
            task_id = start_verification(cm, {
                'cluster_id': cluster_id,
                'node': target_node, 'vmid': target_vmid,
                'backup_volid': volid,
                # NS - pass auto_cleanup=False so the test VM survives for inspection
                'auto_cleanup': False,
            })
            return jsonify({'success': True, 'task_id': task_id, 'mode': 'test',
                            **({'quota_warning': _qwarn} if _qwarn else {})})
        except Exception as e:
            return jsonify({'error': safe_error(e)}), 500

    # qmrestore or pct restore by the backup (pbs:backup/vm/100/... vs pbs:backup/ct/100/...);
    # a batch restore hands each of its backups through here too
    from pegaprox.core.batch_restore import start_restore
    try:
        got = start_restore(cm, volid, target_node, target_vmid, target_storage, mode == 'overwrite')
        if 'upid' in got:
            log_audit(request.session.get('user', 'system'), 'backup.restored',
                      f"Restoring {volid} → {got['kind']}/{target_vmid} on {target_node} (mode={mode})",
                      cluster=cm.config.name)
            return jsonify({'success': True, 'upid': got['upid'], 'mode': mode, 'target_vmid': target_vmid,
                            **({'quota_warning': _qwarn} if _qwarn else {})})
        return upstream_failure(got['status'], got['error'], pve_status=got['status'])
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


def _restore_refusal(cluster_id, user, volid, target_node, target_vmid, mode, node_checked=False):
    """The checks of a restore: an error response when `user` may not restore `volid` into
    `target_vmid` on `target_node` this way, else None. node_checked: the caller asked
    _authz_restore_node already (a batch does once, for all of its backups)."""
    import re as _re
    from pegaprox.utils.rbac import user_can_access_vm

    # NS Aug 2026 (audit) — authorize the SOURCE backup, not only the target. Every mode reads the
    # backup's disk image (overwrite→qmrestore --force, test→boot, new→into a fresh VMID), so a
    # vm.backup holder scoped to their own VM could otherwise restore/boot ANOTHER VM's backup and
    # read its contents. Resolve the backup's owning VMID from the volid and require access to it.
    if not acts_as_admin(user):
        _sm = _re.search(r'/(?:vm|ct)/(\d+)/', volid) or _re.search(r'vzdump-(?:qemu|lxc|openvz)-(\d+)-', volid)
        _src_vmid = int(_sm.group(1)) if _sm else None
        _src_is_lxc = '/ct/' in volid or 'vzdump-lxc' in volid or 'vzdump-openvz' in volid or volid.endswith('.lxc.tar')
        if _src_vmid is None or not user_can_access_vm(user, cluster_id, _src_vmid,
                                                       'vm.backup', 'lxc' if _src_is_lxc else 'qemu'):
            return jsonify({'error': 'Permission denied for source backup'}), 403

    # MK Sep 2026 - mode='new' creates a guest, so it has to respect the same boundaries the
    # create routes do. Only the SOURCE backup and (below) an existing target were authorized,
    # which left the destination free: a scoped caller could restore into any VMID on any node,
    # including one inside another tenant's configured VMID range, and onto storage they have
    # no claim to. vms.py has enforced the range on create since the tenant-limits work; the
    # restore path never learned about it.
    if mode == 'new' and not acts_as_admin(user):
        from pegaprox.utils.rbac import check_tenant_vmid, DEFAULT_TENANT_ID as _DT
        _rok, _rmsg = check_tenant_vmid(user.get('tenant_id') or _DT, target_vmid)
        if not _rok:
            return jsonify({'error': _rmsg}), 403
        # and the node has to be one this caller may actually place a guest on
        if not node_checked:
            _nerr = _authz_restore_node(cluster_id, target_node, user)
            if _nerr:
                return _nerr

    # NS Aug 2026 (Aikido pentest) — overwrite (destructive qmrestore --force) and test (boots into
    # the VMID) both act on an EXISTING target VM, so require the same per-VM ACL as a direct VM op;
    # cluster reachability alone let a vm.backup holder clobber/boot any VM in a reachable cluster.
    if mode in ('overwrite', 'test'):
        _is_lxc = '/ct/' in volid or volid.endswith('.lxc.tar') or 'vzdump-lxc' in volid
        if not user_can_access_vm(user, cluster_id, target_vmid, 'vm.backup', 'lxc' if _is_lxc else 'qemu'):
            return jsonify({'error': 'Permission denied for target VM'}), 403
    return None


# MK Oct 2026 - several backups restored in one go (core/batch_restore.py). Each backup is
# checked as the single restore above checks it before any of them starts; the batch asks
# again before each one whether its starter may still restore it.
_STORAGE_ID_RE = re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,63}')
_VOLID_RE = re.compile(r'(?P<storage>[A-Za-z][A-Za-z0-9_.-]{0,63}):[^\s\x00]{1,400}')
_SOURCE_RES = (re.compile(r'/(?:vm|ct)/(\d+)/'), re.compile(r'vzdump-(?:qemu|lxc|openvz)-(\d+)-'))


def _vmid_arg(value):
    """A VMID from a request body, None when it is none"""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    return v if 100 <= v <= 999999999 else None


def _batch_items(cluster_id, cm, body):
    """(rows, storage, None, clash) for the backups of a batch, or (None, None, error response,
    None). clash is the answer for a VMID another batch or guest has already, or None: the
    caller gives it only once the backups are checked, so it says nothing about guests
    beyond them."""
    from pegaprox.core import batch_restore as batch

    def bad(msg, status=400):
        return None, None, (jsonify({'error': msg}), status), None

    items = body.get('items')
    if not isinstance(items, list) or not 1 <= len(items) <= batch.MAX_ITEMS:
        return bad(f'items lists 1 to {batch.MAX_ITEMS} backups')
    mode = body['mode']
    nxt = 100
    if mode == 'new' and body.get('first_vmid') is not None:
        nxt = _vmid_arg(body.get('first_vmid'))
        if nxt is None:
            return bad('first_vmid is a number from 100 on')
    picked, storage = [], None
    for item in items:
        volid = item.get('volid') if isinstance(item, dict) else None
        m = _VOLID_RE.fullmatch(volid) if isinstance(volid, str) else None
        if not m:
            return bad('Every item names a backup volume (storage:backup/...)')
        if storage not in (None, m.group('storage')):
            return bad('The backups of a batch come from one storage')
        storage = m.group('storage')
        src = next((r.search(volid) for r in _SOURCE_RES if r.search(volid)), None)
        if src is None:
            return bad(f'Cannot tell which guest {volid} belongs to')
        is_lxc = '/ct/' in volid or volid.endswith('.lxc.tar') or 'vzdump-lxc' in volid or 'vzdump-openvz' in volid
        want = None
        if mode == 'new' and item.get('target_vmid') is not None:
            want = _vmid_arg(item.get('target_vmid'))
            if want is None:
                return bad('target_vmid is a number from 100 on')
        picked.append((volid, int(src.group(1)), 'lxc' if is_lxc else 'qemu', want))
    if len({p[1] for p in picked}) != len(picked):
        return bad('One backup per guest: two items restore the same guest')
    wanted = [p[3] for p in picked if p[3] is not None]
    if len(set(wanted)) != len(wanted):
        return bad('Two items name the same target_vmid')

    # the guests as the live view has them: which VMIDs are taken, and where a guest that is
    # overwritten lives (Proxmox restores over a guest only on its own node). An empty
    # cluster is fine - a restore after a loss starts from one
    try:
        where = {int(g.get('vmid')): g.get('node') for g in (cm.get_vm_resources(max_age=5) or [])
                 if str(g.get('vmid', '')).isdigit()}
    except Exception as e:
        logging.error(f"[PBS] guest list of {cluster_id} unreadable for a batch restore: {e}")
        return bad('Cannot read the guests of this cluster right now', 503)
    busy = batch.busy_targets(cluster_id)
    rows, clash = [], None
    if mode == 'overwrite':
        if busy & {p[1] for p in picked}:
            clash = (jsonify({'error': 'Another batch restore is restoring one of these guests'}), 409)
        for volid, src, kind, _want in picked:
            rows.append(batch.new_row(src, kind, volid, src, where.get(src) or body['target_node']))
        return rows, storage, None, clash
    taken = set(where) | busy
    if taken & set(wanted):
        clash = (jsonify({'error': 'A target VMID is taken already'}), 409)
    taken |= set(wanted)
    for volid, src, kind, want in picked:
        if want is None:
            while nxt in taken:
                nxt += 1
            want, nxt = nxt, nxt + 1
            taken.add(want)
        rows.append(batch.new_row(src, kind, volid, want, body['target_node']))
    return rows, storage, None, clash


@bp.route('/api/clusters/<cluster_id>/backup-restore/batch', methods=['POST'])
@require_auth(perms=['vm.backup'])
def restore_backup_batch(cluster_id):
    """Restore several backups in one go

    Body: {items: [{volid, target_vmid?}], mode: 'new'|'overwrite', target_node,
    target_storage?, first_vmid?, run: 'sequential'|'parallel', parallel? (2-4), confirm?}.
    One backup per guest, all from one storage, 1 to 100 of them. 'new' restores each on
    target_node into a VMID of its own (its target_vmid, else the next free one from
    first_vmid on). 'overwrite' restores each over the guest it came from, on the node that
    guest is on (target_node for one that is gone), and only with confirm: true. Every backup
    is checked as POST /backup-restore checks it before anything starts: one refused and
    none starts (403, refused names each). Answers 202 {run}, to follow with GET
    /api/batch-restores/<run_id>.
    """
    from pegaprox.core import batch_restore as batch
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.sanitization import validate_hostname
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    cm = cluster_managers[cluster_id]
    if getattr(cm, 'cluster_type', 'proxmox') != 'proxmox':
        return jsonify({'error': 'Batch restore is for Proxmox VE clusters'}), 400
    if not cm.is_connected:
        return jsonify({'error': 'cluster offline'}), 503

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'error': 'A JSON object is expected'}), 400
    if body.get('mode') not in batch.MODES:
        return jsonify({'error': "mode is 'new' or 'overwrite'"}), 400
    how = body.get('run', 'sequential')
    if how not in batch.HOW:
        return jsonify({'error': "run is 'sequential' or 'parallel'"}), 400
    parallel = 1
    if how == 'parallel':
        parallel = body.get('parallel', 2)
        if isinstance(parallel, bool) or not isinstance(parallel, int) or not 2 <= parallel <= batch.PARALLEL_MAX:
            return jsonify({'error': f'parallel is a number from 2 to {batch.PARALLEL_MAX}'}), 400
    if body['mode'] == 'overwrite' and body.get('confirm') is not True:
        return jsonify({'error': 'Overwriting guests needs confirm: true', 'code': 'CONFIRM_REQUIRED'}), 400
    target_node = body.get('target_node')
    if not isinstance(target_node, str) or not validate_hostname(target_node):
        return jsonify({'error': 'target_node is required'}), 400
    nodes = cm.get_node_status() or {}
    tinfo = nodes.get(target_node)
    if not isinstance(tinfo, dict):
        return jsonify({'error': f'{target_node} is no node of this cluster'}), 400
    if tinfo.get('offline') or tinfo.get('status', 'online') != 'online':
        return jsonify({'error': f'{target_node} is not online'}), 400
    target_storage = body.get('target_storage') or ''
    if not isinstance(target_storage, str) or (target_storage and not _STORAGE_ID_RE.fullmatch(target_storage)):
        return jsonify({'error': 'target_storage is a storage ID'}), 400

    rows, storage, rerr, clash = _batch_items(cluster_id, cm, body)
    if rerr:
        return rerr

    user = build_authz_user(request.session.get('user', ''), request.session)
    refused = []
    if body['mode'] == 'new' and not acts_as_admin(user):
        # one node for the whole batch: asked once, it walks the guests of the cluster
        _nerr = _authz_restore_node(cluster_id, target_node, user)
        if _nerr:
            return _nerr
    for row in rows:
        r = _restore_refusal(cluster_id, user, row['volid'], row['node'], row['target_vmid'],
                             body['mode'], node_checked=True)
        if r:
            refused.append({'volid': row['volid'], 'vmid': row['vmid'],
                            'error': (r[0].get_json(silent=True) or {}).get('error') or 'Refused'})
    if refused:
        return jsonify({'error': f'{len(refused)} of these backups cannot be restored by you - nothing was started',
                        'refused': refused}), 403
    if clash:
        return clash

    # MK Oct 2026 - the whole batch against the tenant quota before any of it starts, each
    # item by what its backup brings back: the backup's own config, read 8 at a time, never
    # the guest it came from as it is now (shrunk since, an old big backup of it went
    # through). Only where that config cannot be read does the guest stand in for it. Only
    # for a tenant that has a quota at all
    def _batch_adds():
        from pegaprox.core.batch_restore import restore_adds, backup_footprint
        from pegaprox.utils.concurrent import run_per_node
        live = {int(g['vmid']): g for g in (cm.get_vm_resources(max_age=30) or [])
                if str(g.get('vmid', '')).isdigit()}
        fps = run_per_node({str(i): (lambda _k, r=row: backup_footprint(cm, r['node'], r['volid']))
                            for i, row in enumerate(rows)}, max_concurrent=8, timeout=120)
        total = {'vms': 0, 'cores': 0, 'memory_gb': 0.0, 'disk_gb': 0.0}
        for i, row in enumerate(rows):
            got = restore_adds(cm, row['node'], row['volid'], row['vmid'], row['target_vmid'],
                               body['mode'] == 'overwrite', rows=live, footprint=fps.get(str(i)),
                               read_backup=False)
            for k in total:
                total[k] += (got or {}).get(k, 0) or 0
        return total
    _qerr, _qwarn = tenant_quota_gate(
        user, f'batch restore of {len(rows)} backup(s)', _batch_adds, cluster=cm.config.name,
        hold={'cluster_id': cluster_id, 'vmids': [r['target_vmid'] for r in rows] if body['mode'] == 'new' else []})
    if _qerr:
        return _qerr

    usr = request.session.get('user', 'system')
    from pegaprox.utils.audit import get_client_ip
    run = batch.BatchRun(cluster_id, cm.config.name, usr, request.session, get_client_ip(), storage,
                         body['mode'], target_node, target_storage, how, parallel, rows)
    try:
        batch.register(run)
    except batch.TooMany as e:
        return jsonify({'error': str(e)}), 409
    listed = ', '.join(f"{r['vmid']}->{r['target_vmid']}" for r in rows[:50]) + (' ...' if len(rows) > 50 else '')
    log_audit(usr, 'backup.batch_restore',
              f"Batch restore {run.id} of {len(rows)} backup(s) from {storage} onto {target_node} "
              f"(mode={body['mode']}, {how}{f' {parallel}' if how == 'parallel' else ''}): {listed}",
              cluster=cm.config.name)
    # the quota's hold on the batch lasts while it runs; what it restored is counted by then
    from pegaprox.api.helpers import quota_hold_alive
    quota_hold_alive(alive=lambda: run.state == 'running')
    batch.launch(run)
    return jsonify({'run': run.view(run.rows_copy(), me=usr),
                    **({'quota_warning': _qwarn} if _qwarn else {})}), 202


def _batch_view(run, with_rows=True):
    """The batch as the caller may see it, None when they may see none of it: the cluster
    out of their reach, or not one of its guests theirs to see"""
    if run is None:
        return None
    ok, _err = check_cluster_access(run.cluster_id)
    if not ok:
        return None
    rows = scope_vm_rows(run.cluster_id, run.rows_copy())
    if not rows:
        return None
    return run.view(rows, with_rows=with_rows, me=request.session.get('user', ''))


def _may_cancel_batch(run):
    """Who started it, or a caller with vm.backup on the whole cluster"""
    if request.session.get('user') == run.user:
        return True
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission
    from pegaprox.api.helpers import caller_is_scoped
    user = build_authz_user(request.session.get('user', ''), request.session)
    return has_permission(user, 'vm.backup') and not caller_is_scoped(user, run.cluster_id)


@bp.route('/api/batch-restores', methods=['GET'])
@require_auth(perms=['backup.view'])
def list_batch_restores():
    """Batch restores of the last hour

    The batches on the clusters the caller reaches, newest first, with their counts and
    without the backups. A batch counts only the guests the caller may see. They run in
    the process of the active instance: a restart ends them."""
    from pegaprox.core import batch_restore as batch
    out = []
    for run in batch.runs():
        view = _batch_view(run, with_rows=False)
        if view:
            out.append(view)
    return jsonify({'runs': out})


@bp.route('/api/batch-restores/<run_id>', methods=['GET'])
@require_auth(perms=['backup.view'])
def get_batch_restore(run_id):
    """One batch restore, a line per backup

    Each with its state (wait, restoring, done, failed, skipped, cancelled, unknown), a
    note, its task and the VMID it restores into; may_cancel says whether the caller may
    cancel the rest."""
    from pegaprox.core import batch_restore as batch
    run = batch.get(run_id)
    view = _batch_view(run)
    if not view:
        return jsonify({'error': 'Batch restore not found'}), 404
    view['may_cancel'] = view['state'] == 'running' and not view['cancelled_by'] and _may_cancel_batch(run)
    return jsonify({'run': view})


@bp.route('/api/batch-restores/<run_id>/cancel', methods=['POST'])
@require_auth(perms=['vm.backup'])
def cancel_batch_restore(run_id):
    """Cancel the rest of a batch restore

    No further backup is restored. What is restoring finishes in Proxmox."""
    from pegaprox.core import batch_restore as batch
    run = batch.get(run_id)
    if not _batch_view(run, with_rows=False):
        return jsonify({'error': 'Batch restore not found'}), 404
    if not _may_cancel_batch(run):
        return jsonify({'error': 'Only who started it, or someone who restores on the whole '
                                 'cluster, cancels a batch restore'}), 403
    usr = request.session.get('user', 'system')
    if not batch.cancel(run, usr):
        return jsonify({'error': 'This batch restore is over'}), 409
    waiting = sum(1 for r in run.rows_copy() if r['state'] == batch.WAITING)
    log_audit(usr, 'backup.batch_restore_cancelled',
              f"Batch restore {run.id} (started by {run.user}): {waiting} backup(s) not started",
              cluster=run.cluster_name)
    view = _batch_view(run) or {}
    view['may_cancel'] = False
    return jsonify({'run': view})


@bp.route('/api/pbs/<pbs_id>/backup-diff', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])  # NS Aug 2026 (Aikido pentest): snapshot metadata is datastore-view, not plain pbs.view
def diff_pbs_backups(pbs_id):
    """Compare two PBS backups (same backup-id, same datastore).

    Query: ?store=Backup&type=vm&id=100&a=2026-05-01T03:00:00Z&b=2026-05-08T03:00:00Z

    Returns a per-archive diff. Without proxmox-backup-client we can't
    cheaply diff actual file contents, so we compare the manifests
    (filenames + sizes + crypt-mode); good enough for "what changed in
    the .conf file" and "is the disk-image size deviating".
    """
    # NS Jul 2026 (CodeAnt IDOR) — enforce the per-PBS linked-clusters tenant gate
    ok, err = check_pbs_access(pbs_id)
    if not ok:
        return err
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS not found'}), 404
    pbs = pbs_managers[pbs_id]
    if not pbs.connected:
        return jsonify({'error': 'PBS offline'}), 503

    store = request.args.get('store', '')
    btype = request.args.get('type', 'vm')
    bid = request.args.get('id', '')
    ts_a = request.args.get('a', '')
    ts_b = request.args.get('b', '')
    if not all([store, btype, bid, ts_a, ts_b]):
        return jsonify({'error': 'store, type, id, a, b query params required'}), 400
    # sec (audit) — type+id name a guest, and the diff hands back its manifests; the seven
    # sibling routes that take the same pair all gate on it.
    ok, err = _authz_pbs_backup(pbs, btype, bid, 'vm.view', store=store, ns='')
    if not ok:
        return err

    try:
        _r = pbs.get_snapshots(store) or {}
        snaps = _r.get('data', []) if isinstance(_r, dict) else (_r or [])
    except Exception as e:
        return jsonify({'error': f'fetch failed: {e}'}), 502

    def _find(ts):
        for s in snaps:
            if s.get('backup-type') != btype:
                continue
            if str(s.get('backup-id')) != str(bid):
                continue
            # PBS exposes backup-time as epoch
            t = s.get('backup-time') or 0
            import datetime as _dt
            iso = _dt.datetime.utcfromtimestamp(t).strftime('%Y-%m-%dT%H:%M:%SZ')
            if iso == ts:
                return s
        return None

    sa, sb = _find(ts_a), _find(ts_b)
    if not sa: return jsonify({'error': f'snapshot a not found: {ts_a}'}), 404
    if not sb: return jsonify({'error': f'snapshot b not found: {ts_b}'}), 404

    files_a = {f.get('filename', '?'): f for f in (sa.get('files') or [])}
    files_b = {f.get('filename', '?'): f for f in (sb.get('files') or [])}
    keys = sorted(set(files_a) | set(files_b))
    diffs = []
    for k in keys:
        a = files_a.get(k); b = files_b.get(k)
        if a and b:
            if a.get('size') != b.get('size') or a.get('crypt-mode') != b.get('crypt-mode'):
                diffs.append({'kind': 'changed', 'filename': k, 'a': a, 'b': b})
            else:
                diffs.append({'kind': 'same', 'filename': k, 'a': a, 'b': b})
        elif a:
            diffs.append({'kind': 'removed', 'filename': k, 'a': a, 'b': None})
        else:
            diffs.append({'kind': 'added', 'filename': k, 'a': None, 'b': b})

    summary = {
        'added': sum(1 for d in diffs if d['kind'] == 'added'),
        'removed': sum(1 for d in diffs if d['kind'] == 'removed'),
        'changed': sum(1 for d in diffs if d['kind'] == 'changed'),
        'same': sum(1 for d in diffs if d['kind'] == 'same'),
    }
    return jsonify({
        'snapshot_a': {'time': ts_a, 'verification': sa.get('verification'),
                       'protected': sa.get('protected'), 'comment': sa.get('comment')},
        'snapshot_b': {'time': ts_b, 'verification': sb.get('verification'),
                       'protected': sb.get('protected'), 'comment': sb.get('comment')},
        'diffs': diffs, 'summary': summary,
    })


# ============================================================================
# Verify auto-schedule — global setting + worker hook
# ============================================================================
@bp.route('/api/pbs/verify-schedule', methods=['GET', 'PUT'])
@require_auth(perms=['pbs.config'])
def verify_schedule_config():
    """Read or write the auto-verify policy.

    Schema (in pegaprox config row 'pbs_verify_schedule'):
      {"enabled": bool, "weekly_count": int, "day": "sun", "hour": 4,
       "scope": "all"|"latest_per_vm", "max_age_days": int}
    """
    db = get_db()
    cur = db.conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)")
    db.conn.commit()
    if request.method == 'GET':
        row = cur.execute("SELECT v FROM pegaprox_kv WHERE k=?",
                          ('pbs_verify_schedule',)).fetchone()
        import json as _j
        if row and row['v']:
            return jsonify(_j.loads(row['v']))
        return jsonify({'enabled': False, 'weekly_count': 5, 'day': 'sun',
                        'hour': 4, 'scope': 'latest_per_vm', 'max_age_days': 30})
    # PUT
    body = request.json or {}
    cleaned = {
        'enabled': bool(body.get('enabled')),
        'weekly_count': max(1, min(50, int(body.get('weekly_count') or 5))),
        'day': body.get('day') if body.get('day') in ('mon','tue','wed','thu','fri','sat','sun') else 'sun',
        'hour': max(0, min(23, int(body.get('hour') or 4))),
        'scope': body.get('scope') if body.get('scope') in ('all', 'latest_per_vm') else 'latest_per_vm',
        'max_age_days': max(1, min(365, int(body.get('max_age_days') or 30))),
    }
    import json as _j
    cur.execute("INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)",
                ('pbs_verify_schedule', _j.dumps(cleaned)))
    db.conn.commit()
    log_audit(request.session.get('user', 'system'), 'pbs.verify_schedule_updated',
              f"Auto-verify schedule: {cleaned}")
    return jsonify(cleaned)


@bp.route('/api/pbs/encryption-key/generate', methods=['POST'])
@require_auth(perms=['pbs.config'])
def generate_encryption_key():
    """Generate a fresh PBS-format encryption key + a printable recovery sheet.
    The key is NOT persisted server-side — the user is expected to save it on
    the PVE side (`storage.cfg` `encryption-key`) and to keep an offline
    paper backup. We never escrow the key.
    """
    import os, base64, hashlib, datetime as _dt
    raw = os.urandom(32)
    # PBS-style fingerprint = sha256 of the key data, formatted with colons
    fp_hex = hashlib.sha256(raw).hexdigest().upper()
    fingerprint = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))
    now = _dt.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # PBS uses an unencrypted JSON envelope when no kdf is set
    pbs_key_doc = {
        'kdf': None,
        'created': now, 'modified': now,
        'data': base64.b64encode(raw).decode('ascii'),
        'fingerprint': fingerprint,
    }

    # Printable recovery sheet — split key into chunks so a human can transcribe
    hex_chunks = [fp_hex[i:i+8] for i in range(0, len(fp_hex), 8)]
    key_b64 = base64.b64encode(raw).decode('ascii')
    sheet = (
        "PBS ENCRYPTION KEY — RECOVERY SHEET\n"
        "===================================\n"
        f"Generated: {now}\n"
        f"Fingerprint:\n  {fingerprint}\n\n"
        "Key (base64):\n"
        f"  {key_b64}\n\n"
        "Key (hex, 4 lines x 8 chars):\n  "
        + '\n  '.join('  '.join(hex_chunks[i:i+4]) for i in range(0, len(hex_chunks), 4))
        + "\n\n"
        "USAGE:\n"
        "  1. Save the JSON file as /etc/pve/priv/storage/<storage-id>.enc\n"
        "     on each PVE node that backs up to this PBS storage.\n"
        "  2. Add `encryption-key /etc/pve/priv/storage/<storage-id>.enc` to\n"
        "     the corresponding pbs: section in /etc/pve/storage.cfg.\n"
        "  3. Print this sheet, store offline (safe / vault). Without this key,\n"
        "     past backups are UNRECOVERABLE.\n"
    )

    log_audit(request.session.get('user', 'system'), 'pbs.encryption_key_generated',
              f"Generated PBS encryption key, fingerprint {fingerprint[:23]}…")
    return jsonify({
        'key_json': pbs_key_doc,
        'fingerprint': fingerprint,
        'recovery_sheet': sheet,
    })


# End PBS API endpoints
# ============================================================================

