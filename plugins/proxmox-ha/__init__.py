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
from pegaprox.api.helpers import get_connected_manager, check_cluster_access
from pegaprox.utils.auth import load_users
from pegaprox.utils.rbac import has_permission

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


def _px_url(manager, path):
    """Build a full Proxmox API URL from a path."""
    return f"https://{manager.host}:8006/api2/json{path}"


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
    _users_db = load_users()
    _current_user = _users_db.get(request.session.get('user'), {})

    _PERM_VIEW      = 'ha.view'
    _PERM_RESOURCES = 'ha.resources'

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
                r = manager._api_get(_px_url(manager, f'/cluster/ha/resources/{validated_sid}'))
                if r.status_code == 404:
                    return jsonify({'error': f'HA resource {sid} not found'}), 404
                if r.status_code != 200:
                    return jsonify({'error': f'Proxmox returned {r.status_code}'}), 502
                return jsonify({'data': r.json().get('data')})
            else:
                r = manager._api_get(_px_url(manager, '/cluster/ha/resources'))
                if r.status_code != 200:
                    return jsonify({'error': f'Proxmox returned {r.status_code}'}), 502
                return jsonify({'data': r.json().get('data', [])})
        except Exception as e:
            log.error(f"[{cluster_id}] HA GET error: {e}")
            return jsonify({'error': str(e)}), 500

    # ---- POST (add) --------------------------------------------------------
    if method == 'POST':
        if not has_permission(_current_user, _PERM_RESOURCES):
            return jsonify({'error': 'Permission denied', 'required': _PERM_RESOURCES}), 403
        body = request.get_json(silent=True) or {}
        cluster_id = body.get('cluster_id', '').strip()
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid = body.get('sid', '').strip()
        validated_sid, err = _validate_sid(sid)
        if err:
            return err

        state = body.get('state', 'started')
        if state not in ('started', 'stopped', 'enabled', 'disabled'):
            return jsonify({'error': f"Invalid state '{state}'. Choose: started, stopped, enabled, disabled"}), 400

        payload = {'sid': validated_sid, 'state': state}
        if 'max_restart' in body:
            payload['max_restart'] = int(body['max_restart'])
        if 'max_relocate' in body:
            payload['max_relocate'] = int(body['max_relocate'])

        try:
            r = manager._api_post(_px_url(manager, '/cluster/ha/resources'), json=payload)
            if r.status_code != 200:
                detail = r.json().get('errors') or r.json().get('message') or r.text
                return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), 502
        except Exception as e:
            log.error(f"[{cluster_id}] HA POST error: {e}")
            return jsonify({'error': str(e)}), 500

        log.info(f"[{cluster_id}] Added HA resource: {validated_sid} (state={state})")
        return jsonify({'message': f'Added {validated_sid} to HA resources'})

    # ---- PUT (update) ------------------------------------------------------
    if method == 'PUT':
        if not has_permission(_current_user, _PERM_RESOURCES):
            return jsonify({'error': 'Permission denied', 'required': _PERM_RESOURCES}), 403
        body = request.get_json(silent=True) or {}
        cluster_id = body.get('cluster_id', '').strip()
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid = body.get('sid', '').strip()
        validated_sid, err = _validate_sid(sid)
        if err:
            return err

        payload = {}
        if 'state' in body:
            state = body['state']
            if state not in ('started', 'stopped', 'enabled', 'disabled'):
                return jsonify({'error': f"Invalid state '{state}'"}), 400
            payload['state'] = state
        if 'max_restart' in body:
            payload['max_restart'] = int(body['max_restart'])
        if 'max_relocate' in body:
            payload['max_relocate'] = int(body['max_relocate'])

        if not payload:
            return jsonify({'error': 'No fields to update (provide state, max_restart, or max_relocate)'}), 400

        try:
            r = manager._api_put(_px_url(manager, f'/cluster/ha/resources/{validated_sid}'), json=payload)
            if r.status_code != 200:
                detail = r.json().get('errors') or r.json().get('message') or r.text
                return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), 502
        except Exception as e:
            log.error(f"[{cluster_id}] HA PUT error: {e}")
            return jsonify({'error': str(e)}), 500

        log.info(f"[{cluster_id}] Updated HA resource: {validated_sid} -> {payload}")
        return jsonify({'message': f'Updated HA resource {validated_sid}'})

    # ---- DELETE (remove) ---------------------------------------------------
    if method == 'DELETE':
        if not has_permission(_current_user, _PERM_RESOURCES):
            return jsonify({'error': 'Permission denied', 'required': _PERM_RESOURCES}), 403
        cluster_id = request.args.get('cluster_id', '').strip()
        manager, err = _get_manager_or_error(cluster_id)
        if err:
            return err

        sid = request.args.get('sid', '').strip()
        validated_sid, err = _validate_sid(sid)
        if err:
            return err

        try:
            r = manager._api_delete(_px_url(manager, f'/cluster/ha/resources/{validated_sid}'))
            if r.status_code == 404:
                return jsonify({'error': f'HA resource {sid} not found'}), 404
            if r.status_code != 200:
                detail = r.json().get('errors') or r.json().get('message') or r.text
                return jsonify({'error': f'Proxmox returned {r.status_code}', 'detail': detail}), 502
        except Exception as e:
            log.error(f"[{cluster_id}] HA DELETE error: {e}")
            return jsonify({'error': str(e)}), 500

        log.info(f"[{cluster_id}] Removed HA resource: {validated_sid}")
        return jsonify({'message': f'Removed {validated_sid} from HA resources'})

    return jsonify({'error': f'Method {method} not allowed'}), 405


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def register(app):
    register_plugin_route(PLUGIN_ID, 'ha', ha_handler)
    log.info(f"[{PLUGIN_ID}] Registered route: /api/plugins/{PLUGIN_ID}/api/ha")
