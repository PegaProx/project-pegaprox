# -*- coding: utf-8 -*-
"""
PegaProx Realtime Updates - Layer 4
WebSocket and SSE broadcasting utilities.
"""

import time
import json
import logging
import threading
import base64
import os
from datetime import datetime

from pegaprox.constants import SSE_TOKEN_TTL
from pegaprox.globals import (
    cluster_managers, ws_clients, ws_clients_lock,
    sse_tokens, sse_tokens_lock,
    sse_clients, sse_clients_lock,
)


def push_immediate_update(cluster_id: str, delay: float = 0.3):
    """NS: push immediate SSE update after VM actions for faster UI feedback"""
    def _push():
        time.sleep(delay)
        try:
            if cluster_id not in cluster_managers:
                return
            manager = cluster_managers[cluster_id]
            if not manager.is_connected:
                return

            # Push resources
            # NS: Fixed - was calling get_all_resources() which doesn't exist
            resources = manager.get_vm_resources()
            if resources:
                broadcast_sse('resources', resources, cluster_id)

            # Push tasks
            tasks = manager.get_tasks(limit=50)
            if tasks:
                broadcast_sse('tasks', tasks, cluster_id)

        except Exception as e:
            logging.debug(f"[SSE] Immediate push failed for {cluster_id}: {e}")

    threading.Thread(target=_push, daemon=True).start()


def broadcast_update(update_type: str, data: dict, cluster_id: str = None):
    """Broadcast update to all connected WebSocket clients"""
    try:
        message = json.dumps({
            'type': update_type,
            'data': data,
            'cluster_id': cluster_id,
            'timestamp': datetime.now().isoformat()
        })

        # Limit message size
        if len(message) > 500000:  # 500KB limit
            logging.warning(f"Broadcast message too large ({len(message)} bytes), skipping")
            return

        disconnected = []

        # Get clients list under lock, then send outside lock
        clients_to_send = []
        with ws_clients_lock:
            for client_id, client_info in list(ws_clients.items()):
                ws = client_info.get('ws')
                client_lock = client_info.get('lock')
                if ws is None or client_lock is None:
                    disconnected.append(client_id)
                    continue

                # Only send if client is subscribed to this cluster or all clusters
                subscribed = client_info.get('clusters')
                if cluster_id is None or subscribed is None or cluster_id in subscribed:
                    clients_to_send.append((client_id, ws, client_lock))

        # Send to clients outside the main lock
        for client_id, ws, client_lock in clients_to_send:
            try:
                with client_lock:
                    ws.send(message)
            except Exception as e:
                logging.debug(f"Failed to send to client {client_id}: {e}")
                disconnected.append(client_id)

        # Remove disconnected clients
        if disconnected:
            with ws_clients_lock:
                for client_id in set(disconnected):  # Use set to avoid duplicates
                    if client_id in ws_clients:
                        del ws_clients[client_id]
                        logging.info(f"Removed disconnected client: {client_id}")
    except Exception as e:
        logging.error(f"Broadcast error: {e}")


def broadcast_action(action: str, resource_type: str, resource_id: str, details: dict = None, cluster_id: str = None, user: str = None):
    """Broadcast an action event to all clients for real-time UI updates"""
    broadcast_update('action', {
        'action': action,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'details': details or {},
        'user': user
    }, cluster_id)


def create_sse_token(username: str, allowed_clusters: list) -> str:
    """Create SSE token - avoids session ID in URL"""
    token = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')
    expires = time.time() + SSE_TOKEN_TTL

    with sse_tokens_lock:
        # cleanup expired
        now = time.time()
        expired = [t for t, data in sse_tokens.items() if data['expires'] < now]
        for t in expired:
            del sse_tokens[t]

        sse_tokens[token] = {
            'user': username,
            'expires': expires,
            'allowed_clusters': allowed_clusters
        }

    return token


def validate_sse_token(token: str) -> dict:
    """Validate an SSE token and return user info or None"""
    if not token:
        return None

    with sse_tokens_lock:
        token_data = sse_tokens.get(token)
        if not token_data:
            return None

        if token_data['expires'] < time.time():
            del sse_tokens[token]
            return None

        return token_data


def broadcast_sse(update_type: str, data: dict, cluster_id: str = None):
    """Broadcast update to SSE clients

    For cluster-specific events (node_status, vm_update, etc.), only sends to clients
    subscribed to that cluster. Global events (update_type starting with 'global_')
    are sent to all clients.
    """
    try:
        message = json.dumps({
            'type': update_type,
            'data': data,
            'cluster_id': cluster_id,
            'timestamp': datetime.now().isoformat()
        })

        # Limit message size
        if len(message) > 500000:
            return

        # Determine if this is a cluster-specific event
        # NS: Added 'tasks' and 'resources' - broadcast loop sends these types
        cluster_specific_events = ['node_status', 'vm_update', 'task_update', 'tasks',
                                   'metrics', 'resources', 'migration', 'maintenance',
                                   'ha_event', 'alert', 'ha_status']
        is_cluster_specific = update_type in cluster_specific_events or cluster_id is not None

        with sse_clients_lock:
            for client_id, client_info in list(sse_clients.items()):
                try:
                    q = client_info.get('queue')
                    subscribed = client_info.get('clusters')

                    should_send = False
                    if not is_cluster_specific:
                        # Global event - send to everyone
                        should_send = True
                    elif cluster_id and subscribed is None:
                        # NS: subscribed=None means admin/all-access -> send everything
                        # Was previously blocking ALL SSE events for admin users!
                        should_send = True
                    elif cluster_id and subscribed and cluster_id in subscribed:
                        # Cluster-specific event and client is subscribed
                        should_send = True

                    if q and should_send:
                        try:
                            q.put_nowait(message)
                        except:
                            pass  # Queue full
                except:
                    pass
    except Exception as e:
        logging.error(f"SSE broadcast error: {e}")
