# -*- coding: utf-8 -*-
"""
PegaProx Realtime API Routes - Layer 6
WebSocket, SSE, and email test endpoints.
"""

import json
import logging
import threading
import uuid
import queue as queue_module
from datetime import datetime
from flask import Blueprint, jsonify, request, Response

from flask_sock import Sock
from pegaprox.constants import *
from pegaprox.globals import (
    cluster_managers, vmware_managers,
    ws_clients, ws_clients_lock,
    sse_clients, sse_clients_lock,
)
from pegaprox.utils.auth import require_auth, validate_session, load_users
from pegaprox.utils.rbac import get_user_clusters
from pegaprox.utils.realtime import (
    broadcast_update, broadcast_sse, broadcast_action,
    create_sse_token, validate_sse_token,
    create_ws_token, validate_ws_token,
    push_immediate_update,
)
from pegaprox.utils.email import send_email
from pegaprox.api.helpers import load_server_settings, get_connected_manager
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('realtime', __name__)
sock = Sock()


@sock.route('/api/ws/updates')
def ws_live_updates(ws):
    """WebSocket endpoint for live updates"""
    client_id = str(uuid.uuid4())
    client_lock = threading.Lock()

    # Authenticate via first message
    try:
        auth_msg = ws.receive(timeout=3)
        auth_data = json.loads(auth_msg)
        session_id = auth_data.get('session_id')

        session = validate_session(session_id)
        if not session:
            ws.send(json.dumps({'type': 'error', 'message': 'Authentication required'}))
            return

        username = session['user']
        subscribed_clusters = auth_data.get('clusters', None)

        with ws_clients_lock:
            ws_clients[client_id] = {
                'ws': ws,
                'lock': client_lock,
                'user': username,
                'clusters': subscribed_clusters,
                'connected_at': datetime.now().isoformat()
            }

        logging.info(f"WebSocket client connected: {username} ({client_id})")
        ws.send(json.dumps({'type': 'connected', 'client_id': client_id}))

        # Keep connection alive
        while True:
            try:
                # Wait for incoming messages with timeout
                msg = ws.receive(timeout=30)
                if msg is None:
                    break

                data = json.loads(msg)
                msg_type = data.get('type')

                if msg_type == 'ping':
                    with client_lock:
                        ws.send(json.dumps({'type': 'pong'}))
                elif msg_type == 'pong':
                    pass
                elif msg_type == 'subscribe':
                    with ws_clients_lock:
                        if client_id in ws_clients:
                            ws_clients[client_id]['clusters'] = data.get('clusters')

            except Exception as e:
                err_str = str(e).lower()
                if 'timed out' in err_str:
                    # Send ping on timeout
                    try:
                        with client_lock:
                            ws.send(json.dumps({'type': 'ping'}))
                    except:
                        break
                else:
                    logging.debug(f"WebSocket error for {client_id}: {e}")
                    break

    except Exception as e:
        logging.error(f"WebSocket connection error: {e}")
    finally:
        with ws_clients_lock:
            if client_id in ws_clients:
                del ws_clients[client_id]
        logging.info(f"WebSocket client disconnected: {client_id}")


@bp.route('/api/sse/token', methods=['POST'])
@require_auth()
def get_sse_token():
    """Get SSE token for URL param auth"""
    user = request.session.get('user', 'unknown')
    users = load_users()
    user_data = users.get(user, {})
    allowed_clusters = get_user_clusters(user_data)

    token = create_sse_token(user, allowed_clusters)

    return jsonify({
        'token': token,
        'expires_in': SSE_TOKEN_TTL,
        'hint': 'Use this token in /api/sse/updates?token=...'
    })


# NS: Mar 2026 - WebSocket auth tokens (single-use, 60s TTL)
# VNC/SSH WebSocket servers call /api/ws/token/validate instead of trusting session in URL
@bp.route('/api/ws/token', methods=['POST'])
@require_auth()
def get_ws_token():
    """Get a single-use WebSocket auth token - avoids session_id in URLs"""
    user = request.session.get('user', 'unknown')
    role = request.session.get('role', 'viewer')
    token = create_ws_token(user, role)
    return jsonify({'token': token, 'expires_in': 60})


@bp.route('/api/ws/token/validate')
def validate_ws_token_api():
    """Validate a WS token - called by standalone VNC/SSH servers
    MK: internal endpoint, consumes the token (single-use)

    MK May 2026 (CodeAnt CWE-285) - if the caller passes ?cluster_id=<id>, also
    verify the token's user has access to that cluster. Closes the cross-cluster
    BOLA case where someone with cluster-A access could open a WS for cluster-B
    and trust the token alone to gate it. cluster_id is OPTIONAL for back-compat
    (the VNC paths in vms.py / VM-level shells call without it today).
    """
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'Token required'}), 401

    data = validate_ws_token(token)
    if not data:
        return jsonify({'error': 'Invalid or expired token'}), 401

    requested_cluster = (request.args.get('cluster_id') or '').strip()
    cluster_context = None
    if requested_cluster:
        try:
            from pegaprox.utils.auth import load_users
            from pegaprox.utils.rbac import get_user_clusters, load_vm_acls
            users = load_users()
            user = users.get(data['user'], {})
            allowed = get_user_clusters(user)
            access_ok = allowed is None or requested_cluster in allowed
            if not access_ok:
                # VM-ACL fallback (mirrors api/helpers.py check_cluster_access)
                cluster_acls = load_vm_acls().get(requested_cluster, {}) or {}
                for _vmid, acl in cluster_acls.items():
                    if data['user'] in (acl.get('users') or []) or '*' in (acl.get('users') or []):
                        access_ok = True
                        break
            if not access_ok:
                logging.warning(f"[WS-TOKEN] user '{data['user']}' has no access to cluster '{requested_cluster}'")
                return jsonify({'error': 'Access denied to this cluster'}), 403

            # MK May 2026 - lightweight cluster context for the SSH/VNC proxy.
            # We intentionally do NOT call mgr._get_node_ip() here: that has a
            # network-probing first-call path (up to ~15s) which would hang the
            # validate endpoint when this same Flask process is busy. The proxy
            # gets the cluster's primary host + any fallback_hosts already known
            # from the DB. Multi-node clusters where the frontend prefetched a
            # per-node IP that isn't in this set will need to re-resolve through
            # the normal cluster-creds endpoint with a session cookie.
            try:
                from pegaprox.globals import cluster_managers
                mgr = cluster_managers.get(requested_cluster)
                if mgr is not None:
                    cluster_host = getattr(mgr, 'host', None)
                    cfg = getattr(mgr, 'config', None)
                    node_ips = {}
                    # Include fallback_hosts from the DB — those were discovered by
                    # the manager at connect time and persist across restarts. Cheap.
                    fb = getattr(cfg, 'fallback_hosts', None) or []
                    for i, host in enumerate(fb):
                        if host:
                            node_ips[f'_fallback_{i}'] = host
                    cluster_context = {
                        'host': cluster_host,
                        'node_ips': node_ips,
                        'ssh_port': getattr(cfg, 'ssh_port', 22) or 22,
                    }
            except Exception as e:
                logging.debug(f"[WS-TOKEN] cluster-context build soft-fail: {e}")
        except Exception as e:
            logging.error(f"[WS-TOKEN] cluster-access check failed: {e}")
            # fail closed
            return jsonify({'error': 'Authorization check failed'}), 500

    resp = {'valid': True, 'user': data['user'], 'role': data['role']}
    if cluster_context is not None:
        resp['cluster_context'] = cluster_context
    return jsonify(resp)


@bp.route('/api/sse/updates')
def sse_updates():
    """SSE endpoint for live updates

    NS: accepts ?token= (preferred) or ?session= (legacy)
    MK: token is better because session IDs in URLs can leak to logs
    """
    # token auth first (preferred)
    sse_token = request.args.get('token')
    session_id = request.args.get('session')

    user = None
    allowed_clusters = None
    auth_method = None

    if sse_token:
        # Validate SSE token
        token_data = validate_sse_token(sse_token)
        if token_data:
            user = token_data['user']
            allowed_clusters = token_data['allowed_clusters']
            auth_method = 'token'

    # NS Mar 2026 - removed session_id fallback, token-only auth for SSE
    if not user:
        return jsonify({'error': 'Authentication required. Provide a valid SSE token.'}), 401

    client_id = str(uuid.uuid4())
    message_queue = queue_module.Queue(maxsize=100)

    # Get cluster subscription from query params
    clusters_param = request.args.get('clusters')
    requested_clusters = clusters_param.split(',') if clusters_param else None

    # MK: only let users subscribe to clusters they have access to
    if requested_clusters:
        if allowed_clusters is None:
            # admin - all clusters allowed
            subscribed_clusters = requested_clusters
        else:
            # filter to allowed only
            subscribed_clusters = [c for c in requested_clusters if c in allowed_clusters]
            if not subscribed_clusters:
                logging.warning(f"[SSE] User {user} tried to subscribe to unauthorized clusters")
                subscribed_clusters = allowed_clusters
    else:
        subscribed_clusters = allowed_clusters

    with sse_clients_lock:
        sse_clients[client_id] = {
            'queue': message_queue,
            'user': user,
            'clusters': subscribed_clusters,
            'connected_at': datetime.now().isoformat(),
            'auth_method': auth_method
        }

    logging.info(f"[SSE] Client connected: {client_id} (user: {user}, auth: {auth_method}) - Total: {len(sse_clients)}")

    def generate():
        try:
            # Send initial connected message
            yield f"data: {json.dumps({'type': 'connected', 'client_id': client_id})}\n\n"

            while True:
                try:
                    # Wait for message with timeout
                    message = message_queue.get(timeout=30)
                    yield f"data: {message}\n\n"
                except queue_module.Empty:
                    # Send keepalive
                    yield f": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with sse_clients_lock:
                if client_id in sse_clients:
                    del sse_clients[client_id]
            logging.info(f"[SSE] Client disconnected: {client_id} - Remaining clients: {len(sse_clients)}")

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Connection'] = 'keep-alive'
    return response


@bp.route('/api/sse/subscribe', methods=['POST'])
@require_auth()
def update_sse_subscription():
    """Update cluster subscription for an active SSE client without reconnecting.
    NS: Mar 2026 - avoids 200-500ms data gap on sidebar toggle
    """
    data = request.json or {}
    client_id = data.get('client_id')
    requested = data.get('clusters')  # list of cluster IDs or None for all

    if not client_id:
        return jsonify({'error': 'client_id required'}), 400

    username = request.session.get('user', 'unknown')

    # RBAC: what clusters is this user allowed to see?
    users = load_users()
    user_data = users.get(username, {})
    allowed = get_user_clusters(user_data)  # None = admin

    # filter requested against allowed
    if requested and len(requested) > 0:
        if allowed is not None:
            filtered = [c for c in requested if c in allowed]
            new_sub = filtered if filtered else allowed
        else:
            new_sub = requested  # admin sees all
    else:
        new_sub = allowed  # None = everything user can see

    with sse_clients_lock:
        client = sse_clients.get(client_id)
        if not client:
            # NS: return 200 not 404 — client may have reconnected with a new ID
            # (token refresh cycle), frontend treats subscribe as best-effort anyway
            return jsonify({'ok': False, 'reason': 'client_not_found'})
        if client.get('user') != username:
            return jsonify({'error': 'Unauthorized'}), 403
        client['clusters'] = new_sub

    logging.debug(f"[SSE] Subscription updated for {client_id}: {new_sub}")
    return jsonify({'ok': True, 'clusters': new_sub})


@bp.route('/api/settings/smtp/test', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def test_smtp():
    """Send a test email to verify SMTP settings

    NS: Uses the same send_email function for consistency
    """
    data = request.json or {}
    test_email = data.get('email', '')

    logging.info(f"[SMTP Test] Received data: {list(data.keys())}")

    if not test_email:
        return jsonify({'error': 'Email address required'}), 400

    # Load saved settings first (we might need the real password)
    saved_settings = load_server_settings()

    # Build SMTP settings from request or use saved
    smtp_host = data.get('smtp_host', '')

    if smtp_host:
        # Use provided settings for testing (before save)
        # But if password is masked (********), use the saved password
        provided_password = data.get('smtp_password', '')
        if provided_password == '********' or not provided_password:
            # Use saved password - NS: Feb 2026: now encrypted in DB, must decrypt
            raw_password = saved_settings.get('smtp_password', '')
            try:
                from pegaprox.core.db import get_db
                real_password = get_db()._decrypt(raw_password) if raw_password else ''
            except Exception:
                real_password = raw_password  # Fallback for unencrypted legacy values
            logging.info("[SMTP Test] Using saved password (frontend sent masked value)")
        else:
            real_password = provided_password

        smtp_settings = {
            'smtp_host': smtp_host,
            'smtp_port': data.get('smtp_port', 587),
            'smtp_user': data.get('smtp_user', ''),
            'smtp_password': real_password,
            'smtp_from_email': data.get('smtp_from_email', ''),
            'smtp_from_name': data.get('smtp_from_name', 'PegaProx'),
            'smtp_tls': data.get('smtp_tls', True),
            'smtp_ssl': data.get('smtp_ssl', False),
        }

        if not smtp_settings['smtp_from_email']:
            return jsonify({'error': 'From email address is required'}), 400

        logging.info(f"[SMTP Test] Using settings: host={smtp_host}, user={smtp_settings['smtp_user']}, has_password={bool(real_password)}")
    else:
        # Use saved settings
        smtp_settings = None  # send_email will load from database
        if not saved_settings.get('smtp_enabled'):
            return jsonify({'error': 'SMTP not enabled'}), 400

    # Send test email using the same function as alerts
    success, error = send_email(
        to_addresses=[test_email],
        subject='PegaProx Test Email',
        body='This is a test email from PegaProx to verify your SMTP settings are working correctly.',
        html_body='<h2>PegaProx Test Email</h2><p>This is a test email to verify your SMTP settings.</p><p style="color: green;">Your SMTP configuration is working!</p>',
        smtp_settings=smtp_settings
    )

    if success:
        return jsonify({'success': True, 'message': f'Test email sent to {test_email}'})
    else:
        return jsonify({'error': error or 'Failed to send test email'}), 400
