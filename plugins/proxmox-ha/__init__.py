# -*- coding: utf-8 -*-
"""
proxmox-ha — PegaProx Plugin
Exposes Proxmox native HA resource management (add / update / remove VMs from HA)
through the PegaProx plugin API.

Proxmox does not expose HA management in its own public API surface that PegaProx
currently wraps, so this plugin bridges the gap by calling the Proxmox HA endpoints
via the existing authenticated cluster manager session.

API (all require Bearer token auth, handled by PegaProx catch-all route):

  GET    /api/plugins/proxmox-ha/api/ha?cluster_id=<id>
         List all HA resources in the cluster.

  GET    /api/plugins/proxmox-ha/api/ha?cluster_id=<id>&sid=vm:<vmid>
         Get a specific HA resource entry.

  POST   /api/plugins/proxmox-ha/api/ha
         Body: { "cluster_id": "...", "sid": "vm:<vmid>",
                 "state": "started|stopped|enabled|disabled",
                 "max_restart": <int>, "max_relocate": <int> }
         Register a VM as an HA resource.

  PUT    /api/plugins/proxmox-ha/api/ha
         Body: { "cluster_id": "...", "sid": "vm:<vmid>",
                 "state": "...", "max_restart": <int>, "max_relocate": <int> }
         Update an existing HA resource entry.

  DELETE /api/plugins/proxmox-ha/api/ha?cluster_id=<id>&sid=vm:<vmid>
         Remove a VM from HA resources.
"""

import logging
from flask import request, jsonify

from pegaprox.api.plugins import register_plugin_route
from pegaprox.api.helpers import get_connected_manager, check_cluster_access, safe_error
from pegaprox.utils.auth import load_users
from pegaprox.utils.rbac import has_permission
from pegaprox.utils.audit import log_audit

PLUGIN_ID = 'proxmox-ha'
log = logging.getLogger(f'plugin.{PLUGIN_ID}')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_manager_or_error(cluster_id):
    """Return (manager, None) or (None, error_response_tuple)."""
    if not cluster_id:
        return None, (jsonify({'error': 'cluster_id is required'}), 400)

    allowed, err = check_cluster_access(cluster_id)
    if not allowed:
        return None, err

    manager, err = get_connected_manager(cluster_id)
    if err:
        return None, err

    return manager, None


def _validate_sid(sid):
    """
    Require sid to be in the form 'vm:<integer>' or 'ct:<integer>'.
    Returns (sid, None) if valid, (None, error_response_tuple) if not.
    """
    if not sid:
        return None, (jsonify({'error': "'sid' is required (format: vm:<vmid> or ct:<vmid>)"}), 400)
    parts = sid.split(':', 1)
    if len(parts) != 2 or parts[0] not in ('vm', 'ct') or not parts[1].isdigit():
        return None, (jsonify({'error': f"Invalid sid '{sid}'. Expected 'vm:<vmid>' or 'ct:<vmid>'"}), 400)
    return sid, None


def _authz_sid_or_error(cluster_id, validated_sid, permission):
    """NS Aug 2026 (audit) — object-level gate: the caller must be allowed to touch the specific
    VM/CT behind the sid, not merely hold ha.view/ha.config on a reachable cluster. Cluster access
    passes for any VM-ACL/pool-scoped tenant user, so without this a portal user could add/remove/
    reconfigure another customer's VM in HA. Mirrors the built-in set_vm_ha_priority_api gate.
    Returns None if allowed, else an (error_response, status) tuple."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    kind, _, num = validated_sid.partition(':')
    if kind not in ('vm', 'ct') or not num.isdigit():
        return jsonify({'error': 'Permission denied for this HA resource'}), 403
    user = build_authz_user(request.session.get('user', ''), request.session)
    if not user_can_access_vm(user, cluster_id, int(num), permission, 'lxc' if kind == 'ct' else 'qemu'):
        return jsonify({'error': 'Permission denied for this HA resource'}), 403
    return None


def _px_url(manager, path):
    """Build a full Proxmox API URL from a path."""
    return f"https://{manager.host}:8006/api2/json{path}"


def _require_string(body, field):
    """
    Extract a string field from a dict, rejecting non-strings (including None).
    Returns (stripped_value, None) on success, (None, error_response_tuple) on failure.
    """
    value = body.get(field)
    if value is None:
        return None, (jsonify({'error': f"'{field}' is required"}), 400)
    if not isinstance(value, str):
        return None, (jsonify({'error': f"'{field}' must be a string"}), 400)
    return value.strip(), None


def _get_optional_string(body, field):
    """
    Extract an optional string field from a dict.
    Returns (stripped_value, None) if present and a string, (None, None) if absent,
    or (None, error_response_tuple) if present but not a string.
    """
    if field not in body:
        return None, None
    value = body[field]
    if not isinstance(value, str):
        return None, (jsonify({'error': f"'{field}' must be a string"}), 400)
    return value.strip(), None


def _parse_optional_int(body, field):
    """
    Parse an optional integer field from a dict.
    Returns (int_value_or_None, None) on success, (None, error_response_tuple) on bad input.
    """
    if field not in body:
        return None, None
    try:
        val = int(body[field])
        if val < 0:
            return None, (jsonify({'error': f"'{field}' must be a non-negative integer"}), 400)
        return val, None
    except (TypeError, ValueError):
        return None, (jsonify({'error': f"'{field}' must be an integer"}), 400)


def _parse_proxmox_error(r):
    """Safely extract an error detail from a Proxmox response."""
    detail = None
    try:
        j = r.json()
        detail = j.get('errors') or j.get('message')
    except ValueError:
        pass
    if not detail:
        detail = r.text or f'HTTP {r.status_code}'
    return detail


# ---------------------------------------------------------------------------
# Route handler
# ---------------------------------------------------------------------------

def ha_handler():
    """
    Single handler dispatched for all HA resource operations.
    Method determines the action; cluster_id / sid come from query string or
    JSON body depending on the operation.

    Uses manager._api_* directly (instead of api_request) so we can inspect
    the real HTTP status code. api_request returns None both on error AND on
    legitimate Proxmox responses where data=null (e.g. POST /cluster/ha/resources).
    """
    method = request.method

    # ---- RBAC --------------------------------------------------------------
    # sec (audit): the raw stored record carries no effective_role, so an admin-owned but
    # viewer-scoped API token reached has_permission with its owner's admin role. The per-SID
    # gate below already builds the identity correctly; this one drives the ha.view/ha.config
    # decision and was missed.
    from pegaprox.utils.auth import build_authz_user as _bau
    _username = request.session.get('user', 'system')
    _current_user = _bau(request.session.get('user', ''), request.session)

    # Permission constants — aligned with the built-in HA resources API:
    #   GET  uses ha.view   (read-only, unchanged)
    #   POST/PUT/DELETE use ha.config (matches built-in HA resource creation restriction)
    _PERM_VIEW   = 'ha.view'
    _PERM_WRITE  = 'ha.config'

    # ---- GET ---------------------------------------------------------------
    if method == 'GET':
        if not has_permission(_current_user, _PERM_VIEW):
            return jsonify({'error': 'Permission denied', 'required': _PERM_VIEW}), 403
        cluster_id = request.args.get('cluster_id', '').strip()
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid = request.args.get('sid', '').strip()

        try:
            if sid:
                validated_sid, err = _validate_sid(sid)
                if err:
                    return err
                err = _authz_sid_or_error(cluster_id, validated_sid, 'vm.view')
                if err:
                    return err
                r = manager._api_get(_px_url(manager, f'/cluster/ha/resources/{validated_sid}'))
                if r.status_code == 404:
                    return jsonify({'error': f'HA resource {sid} not found'}), 404
                if r.status_code != 200:
                    detail = _parse_proxmox_error(r)
                    status = r.status_code if 400 <= r.status_code < 500 else 502
                    return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), status
                return jsonify({'data': r.json().get('data')})
            else:
                r = manager._api_get(_px_url(manager, '/cluster/ha/resources'))
                if r.status_code != 200:
                    detail = _parse_proxmox_error(r)
                    status = r.status_code if 400 <= r.status_code < 500 else 502
                    return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), status
                # NS Aug 2026 (audit) — filter the listing to HA resources the caller may see;
                # otherwise a scoped user enumerates every tenant's guests + HA state on the cluster.
                from pegaprox.utils.auth import build_authz_user
                from pegaprox.utils.rbac import user_can_access_vm
                _u = build_authz_user(request.session.get('user', ''), request.session)
                _visible = []
                for _e in r.json().get('data', []):
                    _kind, _, _num = str(_e.get('sid', '')).partition(':')
                    if _kind in ('vm', 'ct') and _num.isdigit() and user_can_access_vm(
                            _u, cluster_id, int(_num), 'vm.view', 'lxc' if _kind == 'ct' else 'qemu'):
                        _visible.append(_e)
                return jsonify({'data': _visible})
        except Exception as e:
            log.exception(f"[{cluster_id}] HA GET error")
            return jsonify({'error': safe_error(e, 'HA GET failed')}), 500

    # ---- POST (add) --------------------------------------------------------
    if method == 'POST':
        if not has_permission(_current_user, _PERM_WRITE):
            return jsonify({'error': 'Permission denied', 'required': _PERM_WRITE}), 403
        body = request.get_json(silent=True) or {}

        cluster_id, err = _require_string(body, 'cluster_id')
        if err:
            return err
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid, err = _require_string(body, 'sid')
        if err:
            return err
        validated_sid, err = _validate_sid(sid)
        if err:
            return err
        err = _authz_sid_or_error(cluster_id, validated_sid, 'vm.config')
        if err:
            return err

        state, err = _get_optional_string(body, 'state')
        if err:
            return err
        if state is None:
            state = 'started'
        elif state not in ('started', 'stopped', 'enabled', 'disabled'):
            return jsonify({'error': f"Invalid state '{state}'. Choose: started, stopped, enabled, disabled"}), 400

        max_restart, err = _parse_optional_int(body, 'max_restart')
        if err:
            return err
        max_relocate, err = _parse_optional_int(body, 'max_relocate')
        if err:
            return err

        # Proxmox HA endpoints expect form-encoded data; numeric values must be strings.
        payload = {'sid': validated_sid, 'state': state}
        if max_restart is not None:
            payload['max_restart'] = str(max_restart)
        if max_relocate is not None:
            payload['max_relocate'] = str(max_relocate)

        try:
            r = manager._api_post(_px_url(manager, '/cluster/ha/resources'), data=payload)
            if r.status_code != 200:
                detail = _parse_proxmox_error(r)
                status = r.status_code if 400 <= r.status_code < 500 else 502
                return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), status
        except Exception as e:
            log.exception(f"[{cluster_id}] HA POST error")
            return jsonify({'error': safe_error(e, 'HA add failed')}), 500

        log.info(f"[{cluster_id}] Added HA resource: {validated_sid} (state={state})")
        log_audit(
            user=_username,
            action='ha.resource_added',
            details=f"Added HA resource {validated_sid} with state={state}",
            cluster=cluster_id,
        )
        return jsonify({'message': f'Added {validated_sid} to HA resources'})

    # ---- PUT (update) ------------------------------------------------------
    if method == 'PUT':
        if not has_permission(_current_user, _PERM_WRITE):
            return jsonify({'error': 'Permission denied', 'required': _PERM_WRITE}), 403
        body = request.get_json(silent=True) or {}

        cluster_id, err = _require_string(body, 'cluster_id')
        if err:
            return err
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid, err = _require_string(body, 'sid')
        if err:
            return err
        validated_sid, err = _validate_sid(sid)
        if err:
            return err
        err = _authz_sid_or_error(cluster_id, validated_sid, 'vm.config')
        if err:
            return err

        payload = {}
        state, err = _get_optional_string(body, 'state')
        if err:
            return err
        if state is not None:
            if state not in ('started', 'stopped', 'enabled', 'disabled'):
                return jsonify({'error': f"Invalid state '{state}'"}), 400
            payload['state'] = state

        max_restart, err = _parse_optional_int(body, 'max_restart')
        if err:
            return err
        max_relocate, err = _parse_optional_int(body, 'max_relocate')
        if err:
            return err

        # Proxmox HA endpoints expect form-encoded data; numeric values must be strings.
        if max_restart is not None:
            payload['max_restart'] = str(max_restart)
        if max_relocate is not None:
            payload['max_relocate'] = str(max_relocate)

        if not payload:
            return jsonify({'error': 'No fields to update (provide state, max_restart, or max_relocate)'}), 400

        try:
            r = manager._api_put(_px_url(manager, f'/cluster/ha/resources/{validated_sid}'), data=payload)
            if r.status_code != 200:
                detail = _parse_proxmox_error(r)
                status = r.status_code if 400 <= r.status_code < 500 else 502
                return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), status
        except Exception as e:
            log.exception(f"[{cluster_id}] HA PUT error")
            return jsonify({'error': safe_error(e, 'HA update failed')}), 500

        log.info(f"[{cluster_id}] Updated HA resource: {validated_sid} -> {payload}")
        log_audit(
            user=_username,
            action='ha.resource_updated',
            details=f"Updated HA resource {validated_sid}: {payload}",
            cluster=cluster_id,
        )
        return jsonify({'message': f'Updated HA resource {validated_sid}'})

    # ---- DELETE (remove) ---------------------------------------------------
    if method == 'DELETE':
        if not has_permission(_current_user, _PERM_WRITE):
            return jsonify({'error': 'Permission denied', 'required': _PERM_WRITE}), 403
        cluster_id = request.args.get('cluster_id', '').strip()
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid = request.args.get('sid', '').strip()
        validated_sid, err = _validate_sid(sid)
        if err:
            return err
        err = _authz_sid_or_error(cluster_id, validated_sid, 'vm.config')
        if err:
            return err

        try:
            r = manager._api_delete(_px_url(manager, f'/cluster/ha/resources/{validated_sid}'))
            if r.status_code == 404:
                return jsonify({'error': f'HA resource {sid} not found'}), 404
            if r.status_code != 200:
                detail = _parse_proxmox_error(r)
                status = r.status_code if 400 <= r.status_code < 500 else 502
                return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), status
        except Exception as e:
            log.exception(f"[{cluster_id}] HA DELETE error")
            return jsonify({'error': safe_error(e, 'HA remove failed')}), 500

        log.info(f"[{cluster_id}] Removed HA resource: {validated_sid}")
        log_audit(
            user=_username,
            action='ha.resource_removed',
            details=f"Removed HA resource {validated_sid}",
            cluster=cluster_id,
        )
        return jsonify({'message': f'Removed {validated_sid} from HA resources'})

    return jsonify({'error': f'Method {method} not allowed'}), 405


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def register(app):
    register_plugin_route(PLUGIN_ID, 'ha', ha_handler)
    log.info(f"[{PLUGIN_ID}] Registered route: /api/plugins/{PLUGIN_ID}/api/ha")
