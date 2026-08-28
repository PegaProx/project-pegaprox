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
    ws_tokens, ws_tokens_lock,
)

# NS 2026-06-05 (#528 scaling): max SSE/WS broadcast message size. The old hard
# 500KB cap silently dropped any broadcast above it — a cluster with thousands
# of VMs has a `resources` payload well over 500KB, so its live UI just stopped
# updating with only a log warning. Raised to 5MB, env-overridable. (The real
# long-term fix is per-cluster subscription so a client only gets its own data.)
_MAX_BROADCAST_BYTES = int(os.environ.get('PEGAPROX_MAX_BROADCAST_BYTES', str(5_000_000)))


def _filter_sse_resources_for_user(resources, cluster_id, username):
    """Apply the normal per-VM authorization decision before an SSE frame leaves."""
    from pegaprox.utils.auth import load_users
    from pegaprox.utils.rbac import user_can_access_vm

    stored = load_users().get(username)
    if not stored:
        return []
    user = dict(stored)
    user['username'] = username
    return [
        resource for resource in resources
        if user_can_access_vm(
            user,
            cluster_id,
            resource.get('vmid'),
            'vm.view',
            resource.get('type'),
        )
    ]


def _serialize_sse_message(update_type, data, cluster_id, timestamp):
    """Serialize one SSE payload consistently for shared and per-user frames."""
    return json.dumps({
        'type': update_type,
        'data': data,
        'cluster_id': cluster_id,
        'timestamp': timestamp,
    }, default=str)


def watched_clusters():
    """Cluster IDs at least one live SSE/WS client is subscribed to, or None if
    any client has all-access (clusters=None → poll everything). Shared by the
    broadcast loop AND the per-cluster background refreshers so they skip work
    for clusters nobody is viewing. NS 2026-06-05 (scale audit H4 / #528)."""
    watched = set()
    with sse_clients_lock:
        for c in list(sse_clients.values()):
            sub = c.get('clusters')
            if sub is None:
                return None
            watched.update(sub)
    with ws_clients_lock:
        for c in list(ws_clients.values()):
            sub = c.get('clusters')
            if sub is None:
                return None
            watched.update(sub)
    return watched


def is_cluster_watched(cluster_id):
    """True if any live client is viewing this cluster (or has all-access)."""
    w = watched_clusters()
    return w is None or cluster_id in w


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

            # Push tasks — force=True bypasses the 3s result cache so the action's
            # just-started task shows up immediately (N-2), not on the next tick.
            tasks = manager.get_tasks(limit=50, force=True)
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
        if update_type != 'resources' and len(message) > _MAX_BROADCAST_BYTES:
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


# MK: Mar 2026 - WS tokens for VNC/SSH, avoids putting session_id in WebSocket URLs
# These are single-use and expire after 60s
WS_TOKEN_TTL = 60

def create_ws_token(username: str, role: str) -> str:
    """Create a short-lived single-use WebSocket auth token"""
    token = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')
    expires = time.time() + WS_TOKEN_TTL

    with ws_tokens_lock:
        # cleanup old ones
        now = time.time()
        expired = [t for t, d in ws_tokens.items() if d['expires'] < now]
        for t in expired:
            del ws_tokens[t]

        ws_tokens[token] = {
            'user': username,
            'role': role,
            'expires': expires,
        }

    return token


def validate_ws_token(token: str) -> dict:
    """Validate and consume a WS token (single-use). Returns user info or None."""
    if not token:
        return None

    with ws_tokens_lock:
        token_data = ws_tokens.pop(token, None)
        if not token_data:
            return None

        if token_data['expires'] < time.time():
            return None

        return token_data


def invalidate_user_ws_tokens(username: str) -> int:
    """NS Aug 2026 (audit re-verify) — drop every outstanding single-use WS token for a user, so a
    ws_token minted while the account was enabled can't still open a console/shell within its TTL
    after the account is disabled/deleted. Called alongside invalidate_all_user_sessions."""
    with ws_tokens_lock:
        gone = [t for t, d in ws_tokens.items() if d.get('user') == username]
        for t in gone:
            del ws_tokens[t]
    return len(gone)


def broadcast_sse(update_type: str, data: dict, cluster_id: str = None, target_clusters=None):
    """Broadcast update to SSE clients

    For cluster-specific events (node_status, vm_update, etc.), only sends to clients
    subscribed to that cluster. Global events (update_type starting with 'global_')
    are sent to all clients.

    NS Aug 2026 (Aikido pentest) — target_clusters scopes an event that maps to a SET of
    clusters (e.g. a VMware/ESXi server's linked_clusters) rather than a single cluster_id.
    When provided (not None) it takes precedence: deliver to all-access clients (subscribed
    is None) and to any client whose subscription intersects target_clusters. An empty list
    means "not linked to any cluster" → global, mirroring check_vmware_access's backward-compat
    rule. Without it (default None) the classic cluster_id / global logic below is unchanged.
    """
    try:
        # MK 2026-05-31 — `default=str` so a datetime / set / bytes / custom
        # object slipping into `data` doesn't TypeError and silently lose the
        # broadcast. Caller's intent was "best-effort dispatch", not "verify
        # data shape" — that's a stability/observability win for broadcasts
        # like #413 layer 1 where a wrong arg shape killed the publisher.
        timestamp = datetime.now().isoformat()
        try:
            message = _serialize_sse_message(update_type, data, cluster_id, timestamp)
        except (TypeError, ValueError) as _ser_err:
            # If even default=str can't coerce, log enough context to find
            # the bad caller, then drop. Don't take the broadcaster down.
            logging.warning(
                f"[SSE] broadcast '{update_type}' (cluster={cluster_id}) "
                f"unserialisable, skipped: {_ser_err}"
            )
            return

        # Limit message size
        if len(message) > _MAX_BROADCAST_BYTES:
            logging.warning(f"SSE message too large ({len(message)} bytes), skipping")
            return

        # Determine if this is a cluster-specific event
        # NS: Added 'tasks' and 'resources' - broadcast loop sends these types
        cluster_specific_events = ['node_status', 'vm_update', 'task_update', 'tasks',
                                   'metrics', 'resources', 'migration', 'maintenance',
                                   'ha_event', 'alert', 'ha_status']
        is_cluster_specific = update_type in cluster_specific_events or cluster_id is not None

        clients_to_send = []
        with sse_clients_lock:
            for client_id, client_info in list(sse_clients.items()):
                try:
                    q = client_info.get('queue')
                    subscribed = client_info.get('clusters')

                    should_send = False
                    if target_clusters is not None:
                        # NS Aug 2026 (Aikido pentest) — multi-cluster-scoped event (VMware
                        # linked_clusters). Empty → unlinked server → global (matches REST).
                        if not target_clusters:
                            should_send = True
                        elif subscribed is None:
                            should_send = True   # admin / all-access
                        elif subscribed and any(c in subscribed for c in target_clusters):
                            should_send = True
                    elif not is_cluster_specific:
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
                        clients_to_send.append((client_id, client_info, q))
                except:
                    pass

        for client_id, client_info, q in clients_to_send:
            try:
                client_message = message
                if update_type == 'resources' and cluster_id is not None:
                    filtered = _filter_sse_resources_for_user(
                        data, cluster_id, client_info.get('user'))
                    client_message = _serialize_sse_message(
                        update_type, filtered, cluster_id, timestamp)
                if len(client_message) > _MAX_BROADCAST_BYTES:
                    logging.warning(
                        f"SSE message too large ({len(client_message)} bytes), skipping")
                    continue
                q.put_nowait(client_message)
            except Exception:
                # R3 (regression scan): a slow client's queue is full, so
                # this frame is dropped — make it OBSERVABLE instead of
                # silent (its VM grid goes stale otherwise with no signal).
                n = client_info['dropped'] = client_info.get('dropped', 0) + 1
                if n == 1 or n % 100 == 0:
                    logging.warning(
                        f"[SSE] client {client_id} queue full — dropped {n} frames (slow consumer)")
    except Exception as e:
        logging.error(f"SSE broadcast error: {e}")
