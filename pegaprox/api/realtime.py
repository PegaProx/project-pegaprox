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
        auth_msg = ws.receive(timeout=10)
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

    if not user and session_id:
        # Fallback to session auth (legacy)
        session = validate_session(session_id)
        if session:
            user = session.get('user', 'unknown')
            users = load_users()
            user_data = users.get(user, {})
            allowed_clusters = get_user_clusters(user_data)
            auth_method = 'session'

    if not user:
        return jsonify({'error': 'Authentication required. Use token or session parameter.'}), 401

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
