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
import itertools
import os
import socket
from datetime import datetime

from pegaprox.constants import SSE_TOKEN_TTL
from pegaprox.utils.sanitization import sanitize_log_message as _sl
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
        if len(message) > _MAX_BROADCAST_BYTES:
            logging.warning(f"Broadcast message too large ({len(message)} bytes), skipping")
            return

        disconnected = []

        # Snapshot the registry under the lock, then filter and send outside it. The per-VM
        # check below does DB work (a user fetch plus the ACL and pool lookups inside
        # user_can_access_vm), so running it while holding the global registry lock would put
        # every WS connect and disconnect behind it — the same reason broadcast_sse snapshots.
        candidates = []
        with ws_clients_lock:
            for client_id, client_info in list(ws_clients.items()):
                if client_info.get('ws') is None or client_info.get('lock') is None:
                    disconnected.append(client_id)
                    continue
                candidates.append((client_id, client_info))

        clients_to_send = []
        _node_views = {}     # (user, role) -> how it sees THIS node action frame
        _own_message = []    # the frame for a confined client, made once
        for client_id, client_info in candidates:
            # Only send if client is subscribed to this cluster or all clusters
            subscribed = client_info.get('clusters')
            if not (cluster_id is None or subscribed is None or cluster_id in subscribed):
                continue
            client_message = message
            # sec (audit): the WS path had cluster-level scoping only, while its SSE twin
            # filters per VM. 'action' frames name the vmid, the VM's NAME and the operator
            # (create/delete/migrate/power), so a pool-/ACL-scoped client watching a cluster
            # saw every guest's activity. Same per-VM question as the SSE 'tasks' frame.
            if (update_type == 'action' and cluster_id is not None
                    and not client_info.get('is_admin', False)):
                _rid = (data or {}).get('resource_id')
                if (data or {}).get('resource_type') in ('vm', 'qemu', 'lxc', 'ct'):
                    if not _sse_user_can_view_vm(client_info.get('user'), cluster_id, _rid,
                                                 client_info.get('effective_role')):
                        continue
                else:
                    # MK Nov 2026 (#1218) - a node's maintenance, reboot, removal and the start,
                    # stop or move of all its guests: as the SSE node_status frame, node.view,
                    # and a confined client only about a node its own guests run on, without
                    # the guests of the action (others' among them) and its target
                    _key = (client_info.get('user'), client_info.get('effective_role'))
                    _view = _node_views.get(_key, _SSE_FILTER_MISSING)
                    if _view is _SSE_FILTER_MISSING:
                        _view = _ws_node_action_view(_key[0], _rid if isinstance(_rid, str) else None,
                                                     cluster_id, _key[1])
                        _node_views[_key] = _view
                    if _view is None:
                        continue
                    if _view == 'own':
                        if not _own_message:
                            _details = {k: v for k, v in ((data or {}).get('details') or {}).items()
                                        if k not in ('vms', 'target')}
                            _own_message.append(json.dumps(dict(json.loads(message),
                                                                data=dict(data, details=_details))))
                        client_message = _own_message[0]
            clients_to_send.append((client_id, client_info['ws'], client_info['lock'], client_message))

        # Send to clients outside the main lock.
        # A client already mid-send holds its own lock, and blocking on it here let one slow or
        # wedged consumer delay the frame for everyone after it in the list. Skip it for this
        # frame instead; the next broadcast reaches it once it has caught up.
        for client_id, ws, client_lock, client_message in clients_to_send:
            if not client_lock.acquire(blocking=False):
                logging.debug(f"[WS] client {client_id} still sending — skipped this frame")
                continue
            try:
                ws.send(client_message)
            except Exception as e:
                logging.debug(f"Failed to send to client {client_id}: {e}")
                disconnected.append(client_id)
            finally:
                client_lock.release()

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


def create_sse_token(username: str, allowed_clusters: list, effective_role: str = None,
                     sid: str = None, token_id=None) -> str:
    """Create SSE token - avoids session ID in URL

    sec (audit): effective_role is captured at mint time because /api/sse/updates authenticates
    on the token alone — it has no session to floor an API token's role from, and reading the
    stored role there flagged an admin-owned viewer-scoped token as admin, which switched off
    every per-VM filter in the broadcast loop.

    sid / token_id: the session or API token it was minted under, see end_session_channels."""
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
            'allowed_clusters': allowed_clusters,
            'effective_role': effective_role,
            'sid': sid,
            'token_id': token_id,
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

    # sec (audit): the ws-token twin rechecks the account on every consume; this one checked
    # nothing, so a token minted before a disable kept opening streams for its full TTL.
    # Outside the lock — this touches the DB. Tolerant of a transient miss (revocation covers
    # deletion), strict about an explicitly disabled account.
    try:
        from pegaprox.core.db import get_db
        _acct = get_db().get_user(token_data.get('user'))
    except Exception:
        _acct = None
    if _acct is not None and not _acct.get('enabled', True):
        with sse_tokens_lock:
            sse_tokens.pop(token, None)
        return None
    return token_data


# MK: Mar 2026 - WS tokens for VNC/SSH, avoids putting session_id in WebSocket URLs
# These are single-use and expire after 60s
WS_TOKEN_TTL = 60

def create_ws_token(username: str, role: str, api_token: bool = False, sid: str = None) -> str:
    """Create a short-lived single-use WebSocket auth token. api_token: minted by an API
    token, whose role then bounds every console the ws token opens (#1116). sid: the
    session it was minted under, see end_session_channels."""
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
            'api_token': bool(api_token),
            'expires': expires,
            'sid': sid,
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


def invalidate_user_sse_tokens(username: str) -> int:
    """sec (audit): SSE tokens had NO revocation path at all — logout, password change, account
    disable and account delete each dropped sessions (and ws tokens, and API tokens) but left a
    working 10-minute SSE token behind. Twin of invalidate_user_ws_tokens; called from the same
    sites."""
    with sse_tokens_lock:
        gone = [t for t, d in sse_tokens.items() if d.get('user') == username]
        for t in gone:
            del sse_tokens[t]
    return len(gone)


def end_session_channels(username: str, sids=None, keep: str = None) -> int:
    """End what a session opened next to itself: its pending ws and SSE tokens, its open
    SSE streams and its WebSockets on this port.

    NS Oct 2026 (#1038) - signing out, a revoked session or a password change dropped the
    session and its SSE token, and left a console token minted under it working for its
    60 s and every stream and socket it had open running. sids: those sessions only.
    Without: every one of the user's but `keep`'s, the API token ones among them.
    Consoles on the VNC and SSH ports of their own are not reached from here.
    """
    sids = set(sids) if sids is not None else None

    def _ends(d):
        if d.get('user') != username:
            return False
        if sids is not None:
            return d.get('sid') in sids
        return keep is None or d.get('sid') != keep

    n = 0
    for store, lock in ((ws_tokens, ws_tokens_lock), (sse_tokens, sse_tokens_lock),
                        (sse_clients, sse_clients_lock)):
        with lock:
            gone = [k for k, d in store.items() if isinstance(d, dict) and _ends(d)]
            for k in gone:
                store.pop(k, None)
        n += len(gone)
    with _held_ws_lock:
        gone = [k for k, (user, _ws) in _held_ws.items()
                if _ends({'user': user, 'sid': _held_ws_sid.get(k)})]
        socks = [_held_ws.pop(k)[1] for k in gone]
        for k in gone:
            _held_ws_sid.pop(k, None)
    for ws in socks:
        logging.info(f"[WS] hung up a WebSocket of '{_sl(username)}' - its session ended")
        _hang_up(ws)
    return n + len(socks)


# NS Oct 2026 (#988) - a WebSocket on the main port holds a request-pool slot for as long
# as it is open, like an SSE stream, and nothing bounded how many one account kept open:
# any signed-in viewer could fill the pool with them. Counted per account across the
# live-update socket and the consoles. Over the cap the oldest is hung up rather than the
# new one refused, so a console that reconnects never locks its owner out. Next to the
# SSE cap (20) one account holds at most 31 slots (slow bodies below), and the smallest
# pool is 32.
MAX_WS_PER_USER = 10
_held_ws = {}
_held_ws_sid = {}      # key -> the session a socket was opened under, when one was
_held_ws_lock = threading.Lock()
_held_ws_seq = itertools.count()
# NS Oct 2026 (#1052) - request bodies taken off their clock, key -> account. A body that
# never arrives holds its slot like a socket does, so these share the cap: one more
# WebSocket hangs up the oldest socket, one more body keeps its clock. Bodies are never
# hung up, so an account holds at most MAX_WS_PER_USER + 1 of the two.
_held_bodies = {}


def _bodies_of(username):
    return sum(1 for user in _held_bodies.values() if user == username)


def hold_websocket(username, ws, sid=None):
    """Count this request's open WebSocket against its account until the route returns.
    Past MAX_WS_PER_USER the account's oldest socket is hung up. sid: the session it was
    opened under, hung up with it (end_session_channels)."""
    from flask import after_this_request
    key = next(_held_ws_seq)
    with _held_ws_lock:
        mine = sorted(k for k, (user, _) in _held_ws.items() if user == username)
        over = len(mine) + _bodies_of(username) - MAX_WS_PER_USER + 1
        gone = [_held_ws.pop(k)[1] for k in mine[:max(0, over)]]
        _held_ws[key] = (username, ws)
        if sid:
            _held_ws_sid[key] = sid

    # per request, not an app-wide hook: the lease fast path in app.py stands in for the
    # app-wide ones and turns itself off for any it does not know
    @after_this_request
    def _let_go(response):
        release_websocket(key)
        return response

    for old in gone:
        logging.info(f"[WS] hung up the oldest WebSocket of '{_sl(username)}' - over the per-user cap")
        _hang_up(old)


def release_websocket(key):
    with _held_ws_lock:
        _held_ws.pop(key, None)
        _held_ws_sid.pop(key, None)


def hold_body(username):
    """Count a request body that may take as long as the link needs against its account.
    The key to release it with, or None when the account's WebSockets and slow bodies
    already fill MAX_WS_PER_USER: that body keeps its clock."""
    with _held_ws_lock:
        mine = sum(1 for user, _ in _held_ws.values() if user == username) + _bodies_of(username)
        if mine >= MAX_WS_PER_USER:
            return None
        key = next(_held_ws_seq)
        _held_bodies[key] = username
    return key


def release_body(key):
    with _held_ws_lock:
        _held_bodies.pop(key, None)


def _hang_up(ws):
    """End a WebSocket's connection from outside the greenlet that serves it. A close frame
    waits on a client that may never answer; a shutdown wakes every read on the connection
    with EOF, TLS or not, and the handler unwinds as it does when a browser goes away."""
    sock = getattr(ws, 'sock', None)                                    # simple-websocket
    if sock is None:
        sock = getattr(getattr(ws, 'handler', None), 'socket', None)    # geventwebsocket
    try:
        # on a dup of the descriptor, so a TLS socket object is left in one piece
        raw = socket.fromfd(sock.fileno(), sock.family, sock.type)
    except (AttributeError, OSError, ValueError):
        return
    try:
        raw.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        raw.close()


_SSE_FILTER_MISSING = object()

# MK Nov 2026 - the nodes of a cluster a non-admin stream may see, as the resources pass last
# found them: (cluster_id, user, role) -> (monotonic, scope). None is the whole cluster, a
# frozenset the nodes its own guests run on, False no cluster.view, _SCOPE_UNSEEN confined
# with no resources pass yet. The frames that carry nodes are cut from it, so the per-guest
# work stays in the resources pass. That one goes out at least every 10th loop and a loop
# takes up to 9 s, hence the TTL; an entry older than it is not trusted.
_SSE_SCOPE_TTL = 120.0
_SCOPE_UNSEEN = object()
_sse_node_scope = {}
_sse_node_scope_lock = threading.Lock()
_sse_scope_pruned_at = 0.0

# what a non-admin needs for these frames, as their REST twins ask it
_NODE_EVENT_PERMS = {'node_status': 'node.view', 'ha_status': 'ha.view'}
# HA events whose message lists guests of the node by vmid, others' included
_HA_EVENTS_NAMING_GUESTS = ('ha.recovery_left_guests', 'ha.recovery_node_back',
                            'ha.recovery_unclassified', 'ha.recovery_interrupted')


def _node_scope_of(user, cluster_id, guests=None):
    """The node scope of `user` in `cluster_id` (see _sse_node_scope). guests: the rows of
    the resources frame this user gets; without them a confined user's nodes are unseen.
    Fails closed: a check that fails reads as no cluster.view, or as confined."""
    from pegaprox.utils.rbac import has_permission
    from pegaprox.api.helpers import caller_is_scoped
    try:
        if not has_permission(user, 'cluster.view'):
            return False
    except Exception:
        return False
    try:
        if not caller_is_scoped(user, cluster_id):
            return None
    except Exception:
        pass
    if guests is None:
        return _SCOPE_UNSEEN
    return frozenset(r.get('node') for r in guests if r.get('node'))


def _note_node_scope(cluster_id, username, effective_role, scope, keep_fresh=False):
    """Store a node scope and hand back the one that holds. keep_fresh: leave an entry that
    is still fresh, so a guess from a metrics frame never covers a resources pass."""
    global _sse_scope_pruned_at
    key = (cluster_id, username, effective_role)
    now = time.monotonic()
    with _sse_node_scope_lock:
        had = _sse_node_scope.get(key)
        if keep_fresh and had is not None and now - had[0] < _SSE_SCOPE_TTL:
            return had[1]
        _sse_node_scope[key] = (now, scope)
        if now - _sse_scope_pruned_at > _SSE_SCOPE_TTL:
            _sse_scope_pruned_at = now
            for k in [k for k, (t, _s) in _sse_node_scope.items() if now - t >= _SSE_SCOPE_TTL]:
                del _sse_node_scope[k]
    return scope


def _sse_node_scope_for(cluster_id, username, effective_role=None, user=None):
    """The node scope of a non-admin stream. Without a fresh entry the account is read once
    (or `user` taken) and what it tells is kept for the TTL: no cluster.view, the whole
    cluster, or confined. A confined stream's nodes only come from the resources pass."""
    had = _sse_node_scope.get((cluster_id, username, effective_role))
    if had is not None and time.monotonic() - had[0] < _SSE_SCOPE_TTL:
        return had[1]
    if user is None:
        user = _sse_stored_user(username, effective_role)
    if not user:
        return False
    return _note_node_scope(cluster_id, username, effective_role,
                            _node_scope_of(user, cluster_id), keep_fresh=True)


def _metrics_for_nodes(nodes, scope, cluster_id, timestamp):
    """The 'metrics' frame with the nodes in `scope` only, a maintenance on them less its
    guests. Serialized; None for a frame that is no node map."""
    if not isinstance(nodes, dict):
        return None
    from pegaprox.api.helpers import nodes_in_maintenance_view, nodes_without_maintenance_guests
    cut = {name: n for name, n in nodes.items() if name in scope}
    if nodes_in_maintenance_view(cut):
        cut = nodes_without_maintenance_guests(cut)
    return _serialize_sse_message('metrics', cut, cluster_id, timestamp)


def _sse_may_see_node_event(username, update_type, data, cluster_ids, effective_role=None):
    """Whether a non-admin stream gets this 'node_status' / 'ha_status' frame. It needs the
    permission (node.view / ha.view); unconfined in one of `cluster_ids` it gets the frame
    whole, confined only one about a node its own guests run on, and none that lists guests.
    Fails closed."""
    user = _sse_stored_user(username, effective_role)
    if not user or not cluster_ids:
        return False
    data = data if isinstance(data, dict) else {}
    view = _node_event_view(user, username, _NODE_EVENT_PERMS[update_type], data.get('node'),
                            cluster_ids, effective_role)
    return view == 'whole' or (view == 'own' and data.get('event') not in _HA_EVENTS_NAMING_GUESTS)


def _ws_node_action_view(username, node, cluster_id, effective_role=None):
    """_node_event_view of a WebSocket client for an 'action' frame about a node (node.view).
    One account read; the node scope comes from the SSE resources pass, so a confined client
    that has no stream gets none of these frames."""
    user = _sse_stored_user(username, effective_role)
    if not user:
        return None
    return _node_event_view(user, username, 'node.view', node, (cluster_id,), effective_role)


def _node_event_view(user, username, perm, node, cluster_ids, effective_role=None):
    """How a non-admin stream sees an event about `node`: 'whole' when `user` holds `perm`
    and is unconfined in one of `cluster_ids`, 'own' when confined and one of its own guests
    runs on `node` (the scope of the resources pass), else None. Fails closed."""
    from pegaprox.utils.rbac import has_permission
    from pegaprox.api.helpers import caller_is_scoped
    try:
        if not has_permission(user, perm):
            return None
    except Exception:
        return None
    for cid in cluster_ids:
        try:
            if not caller_is_scoped(user, cid):
                return 'whole'
        except Exception:
            pass
    if not node:
        return None
    for cid in cluster_ids:
        scope = _sse_node_scope_for(cid, username, effective_role, user)
        if isinstance(scope, frozenset) and node in scope:
            return 'own'
    return None


def _serialize_sse_message(update_type, data, cluster_id, timestamp):
    """One consistent SSE frame — used for the shared broadcast and per-user filtered frames."""
    return json.dumps({
        'type': update_type, 'data': data,
        'cluster_id': cluster_id, 'timestamp': timestamp,
    }, default=str)


def _filtered_resources_frame(resources, cluster_id, username, timestamp, effective_role=None):
    """A per-VM-authorized 'resources' frame for a NON-admin client. Returns the serialized JSON,
    or None to send nothing (unknown user -> fail closed).

    #736 SSE-ACL rebuild — the 'resources' frame carries the whole cluster VM list, so a client
    with cluster access but pool-/VM-scoped rights must not receive VMs it can't see (REST already
    filters per-VM; the SSE stream previously did not). Scale: the caller filters ONLY scoped
    clients and caches this per DISTINCT username within one broadcast, so it's
    O(distinct-scoped-users), not O(clients); we fetch a SINGLE user (get_db().get_user), never
    load_users() — that call is the documented hot-path landmine. user_can_access_vm admin-fast-
    returns and reads the cached ACL map, so the per-VM pass is a dict lookup per VM.
    """
    if not isinstance(resources, list):
        return None
    from pegaprox.utils.rbac import user_can_access_vm
    user = _sse_stored_user(username, effective_role)
    if not user:
        return None
    allowed = [
        r for r in resources
        if user_can_access_vm(user, cluster_id, r.get('vmid'), 'vm.view', r.get('type'))
    ]
    # MK Nov 2026 - the nodes these guests run on are what the stream shows of the cluster
    try:
        _note_node_scope(cluster_id, username, effective_role,
                         _node_scope_of(user, cluster_id, allowed))
    except Exception as e:
        logging.debug(f"[SSE] node scope of '{_sl(username)}' on {cluster_id} not kept: {e}")
    return _serialize_sse_message('resources', allowed, cluster_id, timestamp)


def _sse_user_can_view_vm(username, cluster_id, vmid, effective_role=None):
    """sec (private disclosure Sep 2026 — audit M1): SSE only per-VM-filtered the 'resources' frame;
    'vm_config' (full VM config incl. possible cloud-init secrets) and per-VM 'tasks' rows were
    broadcast cluster-wide to any subscribed non-admin. This is the per-VM gate for those frames.
    Single-user fetch (never load_users, the hot-path landmine), same pattern as the resources frame."""
    from pegaprox.utils.rbac import user_can_access_vm
    user = _sse_stored_user(username, effective_role)
    if not user:
        return False
    try:
        return user_can_access_vm(user, cluster_id, int(vmid), 'vm.view')
    except (TypeError, ValueError):
        return False


def _filtered_vmware_vms_frame(data, username, timestamp, effective_role=None):
    """A per-VM-authorized 'vmware_vms' frame for a NON-admin client. Returns the serialized
    JSON, or None to send nothing (unknown user -> fail closed).

    sec (audit): the frame carries an ESXi server's whole inventory and was gated on the bare
    vmware.vm.view permission, which is a builtin viewer default — while the REST twin has
    filtered per-VM since the Sep audit. Same leak, one transport over. The caller keeps the
    perm gate (no permission still means no frame at all); this decides which guests survive."""
    user = _sse_stored_user(username, effective_role)
    if not user:
        return None
    from pegaprox.utils.rbac import user_can_access_vmware_vm
    from pegaprox.api.helpers import vmware_server_reach
    from pegaprox.globals import vmware_managers
    data = data or {}
    vmware_id = data.get('vmware_id')
    # NS Oct 2026 - a client subscribed to a linked cluster it does not own (a pool grant there)
    # still got this frame for a server it cannot reach: its id, an empty list, and every ten
    # seconds the news that the server is up. check_vmware_access answers no, so send nothing.
    mgr = vmware_managers.get(vmware_id)
    if mgr is not None and not vmware_server_reach(user)(getattr(mgr, 'linked_clusters', None)):
        return None
    allowed = [v for v in (data.get('vms') or [])
               if user_can_access_vmware_vm(user, vmware_id, str(v.get('vm', '')), 'vmware.vm.view')]
    return _serialize_sse_message('vmware_vms', {**data, 'vms': allowed}, None, timestamp)


def _filtered_vmware_servers_frame(servers, username, timestamp, effective_role=None):
    """The 'vmware_servers' list cut to the servers a NON-admin client may reach. Returns the
    serialized JSON, or None to send nothing (unknown user -> fail closed).

    NS Oct 2026 - the frame went to every vmware.view holder, so each tenant saw the name and
    host of every other tenant's ESXi server, pool-confined users included. Same question as
    GET /api/vmware now asks per row. The linkage comes from the live manager, where
    check_vmware_access reads it; a server removed since the frame was built is dropped."""
    if not isinstance(servers, list):
        return None
    user = _sse_stored_user(username, effective_role)
    if not user:
        return None
    from pegaprox.api.helpers import vmware_server_reach
    from pegaprox.globals import vmware_managers
    try:
        reaches = vmware_server_reach(user)
        allowed = []
        for s in servers:
            mgr = vmware_managers.get(s.get('id')) if isinstance(s, dict) else None
            if mgr is not None and reaches(getattr(mgr, 'linked_clusters', None)):
                allowed.append(s)
    except Exception as e:
        logging.debug(f"[SSE] vmware_servers filter failed for '{_sl(username)}': {e}")
        return None
    return _serialize_sse_message('vmware_servers', allowed, None, timestamp)


def _sse_user_can_view_vmware_vm(username, vmware_id, vm_id, effective_role=None):
    """Per-VM gate for the 'vmware_vm_detail' push. The watch registry it is driven from is
    global, so one authorized watcher used to put a guest's detail — guest info and performance
    included — in front of every client subscribed to the server's linked clusters."""
    user = _sse_stored_user(username, effective_role)
    if not user:
        return False
    from pegaprox.utils.rbac import user_can_access_vmware_vm
    return user_can_access_vmware_vm(user, vmware_id, str(vm_id), 'vmware.vm.view')


def _sse_user_has_perm(username, permission, effective_role=None):
    """sec (audit): the SSE stream carried the ESXi inventory ('vmware_*' frames) to every client,
    while the REST twin gates on a vmware.* permission — so a custom role built to hide ESXi still
    saw it over the stream. Same single-user fetch as _sse_user_can_view_vm."""
    from pegaprox.utils.rbac import has_permission
    user = _sse_stored_user(username, effective_role)
    if not user:
        return False
    return has_permission(user, permission)


def _sse_stored_user(username, effective_role=None):
    """The acting user as a plain dict, fetched one row at a time. SSE runs in background threads
    with no request context, so there is no session to build an identity from.

    sec (audit): pass the role the STREAM was minted with. The connect path floors an
    admin-owned but viewer-scoped API token down to its token role and stores that on the
    client, which is what switches the per-VM filters on — but every filter then rebuilt the
    identity from this stored record, whose role is still the owner's `admin`. So each filter
    admin-fast-returned and passed everything through, and the floor was captured and thrown
    away one level down. Whoever reads a user for a filter decision must carry it."""
    if not username:
        return None
    from pegaprox.core.db import get_db
    try:
        stored = get_db().get_user(username)
    except Exception:
        return None
    if not stored:
        return None
    user = dict(stored)
    user['username'] = username
    if effective_role:
        user['effective_role'] = effective_role
    return user


# sec (audit): the migration and DR progress frames carry a VM name, direction, target vmid and
# free-text log lines, and every one of them was broadcast with no cluster and no target_clusters —
# i.e. globally, to every SSE client in the install. Their REST twins are gated per-object
# (_migration_reachable / _xhm_reachable / _authz_plan_vms), so the stream was a way around those
# gates. Map each frame back to its underlying object and ask the same question.
_SSE_OBJECT_FRAMES = ('xhm_migration', 'xhm_migration_log',
                      'vmware_migration', 'vmware_migration_log', 'site_recovery')


def _sse_may_see_object_frame(username, update_type, data, effective_role=None):
    """True if this client may see one of the _SSE_OBJECT_FRAMES. Fails closed: an unknown user, or
    a frame naming an object we can no longer resolve, gets nothing (an admin short-circuits)."""
    from pegaprox.utils.rbac import acts_as_admin
    user = _sse_stored_user(username, effective_role)
    if not user:
        return False
    if acts_as_admin(user):
        return True
    data = data or {}
    try:
        if update_type.startswith('xhm_'):
            from pegaprox.globals import _xhm_migrations
            from pegaprox.api.xhm import _may_migrate_source
            t = _xhm_migrations.get(data.get('id'))
            vmid, cid = getattr(t, 'source_vmid', None), getattr(t, 'source_cluster', None)
            if t is None or not vmid or not cid:
                return False
            # the same gate as the list route, ESXi sources included (#1039)
            return _may_migrate_source(user, cid, vmid)

        if update_type.startswith('vmware_migration'):
            # the live V2P registry is vmware.py's module-level dict; globals._v2p_migrations
            # is a leftover that nothing writes to
            from pegaprox.api.vmware import _vmware_migrations
            from pegaprox.utils.rbac import user_can_access_vmware_vm
            t = _vmware_migrations.get(data.get('id'))
            vmw, vid = getattr(t, 'vmware_id', None), getattr(t, 'vm_id', None)
            if t is None or not vmw or not vid:
                return False
            return user_can_access_vmware_vm(user, vmw, str(vid), 'vmware.vm.migrate')

        # site_recovery: mirror _authz_plan_vms — every VM in the plan must be visible
        from pegaprox.core.db import get_db
        from pegaprox.utils.rbac import user_can_access_vm
        db = get_db()
        plan = db.query_one('SELECT source_cluster FROM site_recovery_plans WHERE id = ?',
                            (data.get('plan_id'),))
        if not plan:
            return False
        cid = dict(plan).get('source_cluster')
        vms = db.query('SELECT vmid, vm_type FROM site_recovery_vms WHERE plan_id = ?',
                       (data.get('plan_id'),)) or []
        if not cid or not vms:
            return False
        return all(user_can_access_vm(user, cid, int(dict(v)['vmid']), 'vm.view',
                                      dict(v).get('vm_type', 'qemu')) for v in vms)
    except Exception:
        return False


def _filtered_tasks_frame(tasks, cluster_id, username, timestamp, effective_role=None):
    """Per-VM-authorized 'tasks' frame for a non-admin client: keep only rows whose vmid the caller
    may view (task rows without a resolvable vmid — node/cluster tasks — are dropped for a scoped
    client). None => unknown user, fail closed."""
    if not isinstance(tasks, list):
        return None
    from pegaprox.utils.rbac import user_can_access_vm
    user = _sse_stored_user(username, effective_role)
    if not user:
        return None

    # audit regression fix — only CONFINE a pool-/ACL-scoped client; a plain cluster-wide operator
    # (non-admin, tenant owns the cluster, no pool/ACL scope) keeps the FULL task log, matching the
    # REST /clusters/<id>/tasks confinement. Without this the live 'tasks' stream silently dropped
    # every node/cluster-level task for legitimate operators.
    from pegaprox.api.helpers import caller_is_scoped
    if not caller_is_scoped(user, cluster_id):
        return _serialize_sse_message('tasks', tasks, cluster_id, timestamp)

    def _vmid_of(t):
        for k in ('vmid', 'id'):
            v = t.get(k)
            try:
                return int(v)
            except (TypeError, ValueError):
                continue
        return None

    allowed = []
    for t in tasks:
        _vid = _vmid_of(t)
        if _vid is None:
            continue  # node/cluster task → not for a per-VM-scoped client
        if user_can_access_vm(user, cluster_id, _vid, 'vm.view'):
            allowed.append(t)
    return _serialize_sse_message('tasks', allowed, cluster_id, timestamp)


def _sse_user_sees_maintenance(username, cluster_id, effective_role=None):
    """MK Oct 2026 - the 'metrics' frame carries every node's maintenance task, guests and
    all; the REST twin cuts them for a confined caller (helpers.sees_whole_maintenance).
    Same question here, the stream's role carried. Unknown user: no."""
    from pegaprox.api.helpers import sees_whole_maintenance
    user = _sse_stored_user(username, effective_role)
    return bool(user) and sees_whole_maintenance(user, cluster_id)


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

        # Limit message size. For 'resources' the shared frame (all VMs) can be large, but scoped
        # clients get a smaller per-user frame, so don't drop the whole broadcast on the shared
        # size here — each outgoing frame is size-checked in the send loop instead (#736).
        if update_type != 'resources' and len(message) > _MAX_BROADCAST_BYTES:
            logging.warning(f"SSE message too large ({len(message)} bytes), skipping")
            return

        # Determine if this is a cluster-specific event
        # NS: Added 'tasks' and 'resources' - broadcast loop sends these types
        cluster_specific_events = ['node_status', 'vm_update', 'task_update', 'tasks',
                                   'metrics', 'resources', 'migration', 'maintenance',
                                   'ha_event', 'alert', 'ha_status']
        is_cluster_specific = update_type in cluster_specific_events or cluster_id is not None

        # #736 — cache each scoped user's filtered 'resources' frame within this broadcast, so we
        # filter O(distinct-scoped-users) times rather than once per client.
        # keyed on (user, the role the STREAM was minted with) — two streams of the same
        # account can be floored differently, and must not share a filter decision
        _res_frame_cache = {}
        _cfg_access_cache = {}    # uname -> bool: may this user view THIS vm_config frame's vmid (audit M1)
        _tasks_frame_cache = {}   # uname -> per-VM-filtered 'tasks' frame (audit M1)
        _vmw_perm_cache = {}      # uname -> bool: holds the vmware.* perm the REST twin requires
        _vmw_vms_frame_cache = {} # uname -> per-VM-filtered ESXi inventory frame (audit)
        _vmw_servers_frame_cache = {}  # uname -> the ESXi server list cut to what they reach
        _vmw_detail_cache = {}    # uname -> bool: may see THIS watched ESXi guest's detail (audit)
        _obj_frame_cache = {}     # uname -> bool: may see THIS migration/DR-plan frame (audit)
        _maint_seen_cache = {}    # uname -> bool: gets the guests of a maintenance in this cluster
        _metrics_cut = []         # the 'metrics' frame less those guests, made once
        _metrics_frame_cache = {}  # uname -> the 'metrics' frame cut to their node scope
        _metrics_by_scope = {}    # node set -> that frame, made once per distinct set
        _node_event_cache = {}    # uname -> bool: gets THIS node_status / ha_status frame
        # only while a node of the cluster is in maintenance, so a quiet cluster costs nothing
        _metrics_maint = False
        if update_type == 'metrics' and cluster_id is not None:
            from pegaprox.api.helpers import nodes_in_maintenance_view
            _metrics_maint = nodes_in_maintenance_view(data)
        # sec/scale (audit): the per-client filtering below does uncached DB work — a single
        # user fetch plus the VM-ACL and pool lookups inside user_can_access_vm — and this loop
        # runs about once a second. Holding the GLOBAL sse_clients lock across that serialises
        # every connect and disconnect behind the slowest authz lookup, and under gevent each
        # of those reads is a yield point. Snapshot the registry under the lock and do the work
        # outside it, which is what broadcast_update already does for the WebSocket path.
        with sse_clients_lock:
            _clients_snapshot = list(sse_clients.items())
        for client_id, client_info in _clients_snapshot:
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
                    client_message = message
                    # #736 — a scoped (non-admin) client must not receive VMs it can't view over
                    # the 'resources' stream. Gate on the REAL admin role, NOT `subscribed is None`:
                    # get_user_clusters() returns None for a default-tenant scoped user too
                    # (rbac.py:347), so the old `subscribed is not None` check silently leaked the
                    # full inventory to them. Every non-admin (list-scoped OR default-tenant) gets a
                    # per-VM-authorized frame (cached per distinct user above). Fail-closed: a client
                    # registered without the is_admin flag is treated as non-admin and filtered.
                    if update_type == 'resources' and cluster_id is not None and not client_info.get('is_admin', False):
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        client_message = _res_frame_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            client_message = _filtered_resources_frame(data, cluster_id, uname,
                                                                       timestamp, _eff)
                            _res_frame_cache[uname, _eff] = client_message
                    elif update_type == 'vm_config' and cluster_id is not None and not client_info.get('is_admin', False):
                        # audit M1 — vm_config carries the full VM config (disks/net/cloud-init);
                        # deliver only to a scoped client that may view this vmid.
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ok_cfg = _cfg_access_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if _ok_cfg is _SSE_FILTER_MISSING:
                            _ok_cfg = _sse_user_can_view_vm(uname, cluster_id,
                                                            (data or {}).get('vmid'), _eff)
                            _cfg_access_cache[uname, _eff] = _ok_cfg
                        if not _ok_cfg:
                            continue  # foreign VM's config → not for this scoped client
                    elif update_type == 'tasks' and cluster_id is not None and not client_info.get('is_admin', False):
                        # audit M1 — filter per-VM task rows to the ones this client may view.
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        client_message = _tasks_frame_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            client_message = _filtered_tasks_frame(data, cluster_id, uname,
                                                                   timestamp, _eff)
                            _tasks_frame_cache[uname, _eff] = client_message
                    elif (update_type == 'metrics' and cluster_id is not None
                          and not client_info.get('is_admin', False)):
                        # MK Nov 2026 (#1218) - the frame named every node to each client of the
                        # cluster, a grant on one guest or no cluster.view at all being enough.
                        # A non-admin gets the nodes its own guests run on, from the scope the
                        # resources pass keeps, and nothing while that is not known. No guest
                        # and no account is looked at here in steady state.
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        client_message = _metrics_frame_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            _scope = _sse_node_scope_for(cluster_id, uname, _eff)
                            if _scope is None:
                                client_message = message   # unconfined: maintenance guests too
                            elif isinstance(_scope, frozenset):
                                client_message = _metrics_by_scope.get(_scope, _SSE_FILTER_MISSING)
                                if client_message is _SSE_FILTER_MISSING:
                                    client_message = _metrics_for_nodes(data, _scope, cluster_id, timestamp)
                                    _metrics_by_scope[_scope] = client_message
                            else:
                                client_message = None
                            _metrics_frame_cache[uname, _eff] = client_message
                    elif update_type in _NODE_EVENT_PERMS and not client_info.get('is_admin', False):
                        # MK Nov 2026 (#1218) - node online/offline and the HA events went to every
                        # client of the cluster, without node.view / ha.view and with every node
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ids = ((cluster_id,) if cluster_id is not None else
                                tuple(c for c in (target_clusters or ())
                                      if subscribed is None or c in subscribed))
                        _ok_ev = _node_event_cache.get((uname, _eff, _ids), _SSE_FILTER_MISSING)
                        if _ok_ev is _SSE_FILTER_MISSING:
                            _ok_ev = _sse_may_see_node_event(uname, update_type, data, _ids, _eff)
                            _node_event_cache[uname, _eff, _ids] = _ok_ev
                        if not _ok_ev:
                            continue
                    elif _metrics_maint:
                        # an admin client, asked all the same: is_admin does not know the tenant
                        # override that lowers an admin where they live (sees_whole_maintenance does)
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ok_maint = _maint_seen_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if _ok_maint is _SSE_FILTER_MISSING:
                            _ok_maint = _sse_user_sees_maintenance(uname, cluster_id, _eff)
                            _maint_seen_cache[uname, _eff] = _ok_maint
                        if not _ok_maint:
                            if not _metrics_cut:
                                from pegaprox.api.helpers import nodes_without_maintenance_guests
                                _metrics_cut.append(_serialize_sse_message(
                                    'metrics', nodes_without_maintenance_guests(data), cluster_id, timestamp))
                            client_message = _metrics_cut[0]
                    elif update_type == 'vmware_vms' and not client_info.get('is_admin', False):
                        # audit — the ESXi twin of the 'resources' filter above. The perm gate
                        # below still decides whether this client hears about ESXi at all; what
                        # it never did was decide WHICH guests, so the frame carried the whole
                        # server inventory to anyone holding a builtin viewer permission.
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ok_vmw = _vmw_perm_cache.get((uname, _eff, 'vmware.vm.view'), _SSE_FILTER_MISSING)
                        if _ok_vmw is _SSE_FILTER_MISSING:
                            _ok_vmw = _sse_user_has_perm(uname, 'vmware.vm.view', _eff)
                            _vmw_perm_cache[uname, _eff, 'vmware.vm.view'] = _ok_vmw
                        if not _ok_vmw:
                            continue
                        client_message = _vmw_vms_frame_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            client_message = _filtered_vmware_vms_frame(data, uname, timestamp, _eff)
                            _vmw_vms_frame_cache[uname, _eff] = client_message
                    elif update_type == 'vmware_servers' and not client_info.get('is_admin', False):
                        # NS Oct 2026 - the perm gate decided who hears about ESXi, never which
                        # servers; the list carried every tenant's to each vmware.view holder
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ok_vmw = _vmw_perm_cache.get((uname, _eff, 'vmware.view'), _SSE_FILTER_MISSING)
                        if _ok_vmw is _SSE_FILTER_MISSING:
                            _ok_vmw = _sse_user_has_perm(uname, 'vmware.view', _eff)
                            _vmw_perm_cache[uname, _eff, 'vmware.view'] = _ok_vmw
                        if not _ok_vmw:
                            continue
                        client_message = _vmw_servers_frame_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            client_message = _filtered_vmware_servers_frame(data, uname, timestamp, _eff)
                            _vmw_servers_frame_cache[uname, _eff] = client_message
                    elif update_type == 'vmware_vm_detail' and not client_info.get('is_admin', False):
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ok_det = _vmw_detail_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if _ok_det is _SSE_FILTER_MISSING:
                            _ok_det = _sse_user_can_view_vmware_vm(
                                uname, (data or {}).get('vmware_id'), (data or {}).get('vm_id'), _eff)
                            _vmw_detail_cache[uname, _eff] = _ok_det
                        if not _ok_det:
                            continue  # someone else's watch → not for this client
                    elif (update_type.startswith('vmware_')
                          and update_type not in _SSE_OBJECT_FRAMES
                          and not client_info.get('is_admin', False)):
                        # audit — mirror the REST perm gate (vmware.vm.view / vmware.view) that
                        # the stream skipped entirely. Both are default viewer perms, so this
                        # only bites a custom role that deliberately withholds them.
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _need = 'vmware.vm.view'   # vmware_servers has its own branch above
                        _ok_vmw = _vmw_perm_cache.get((uname, _eff, _need), _SSE_FILTER_MISSING)
                        if _ok_vmw is _SSE_FILTER_MISSING:
                            _ok_vmw = _sse_user_has_perm(uname, _need, _eff)
                            _vmw_perm_cache[uname, _eff, _need] = _ok_vmw
                        if not _ok_vmw:
                            continue
                    elif update_type in _SSE_OBJECT_FRAMES and not client_info.get('is_admin', False):
                        uname, _eff = client_info.get('user'), client_info.get('effective_role')
                        _ok_obj = _obj_frame_cache.get((uname, _eff), _SSE_FILTER_MISSING)
                        if _ok_obj is _SSE_FILTER_MISSING:
                            _ok_obj = _sse_may_see_object_frame(uname, update_type, data, _eff)
                            _obj_frame_cache[uname, _eff] = _ok_obj
                        if not _ok_obj:
                            continue
                    if client_message is None:
                        continue  # unknown user -> fail closed, send nothing
                    if len(client_message) > _MAX_BROADCAST_BYTES:
                        logging.warning(f"SSE message too large ({len(client_message)} bytes), skipping")
                        continue
                    try:
                        q.put_nowait(client_message)
                    except Exception:
                        # R3 (regression scan): a slow client's queue is full, so
                        # this frame is dropped — make it OBSERVABLE instead of
                        # silent (its VM grid goes stale otherwise with no signal).
                        n = client_info['dropped'] = client_info.get('dropped', 0) + 1
                        if n == 1 or n % 100 == 0:
                            logging.warning(f"[SSE] client {client_id} queue full — dropped {n} frames (slow consumer)")
            except:
                pass
    except Exception as e:
        logging.error(f"SSE broadcast error: {e}")
