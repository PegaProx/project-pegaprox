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
        for client_id, client_info in candidates:
            # Only send if client is subscribed to this cluster or all clusters
            subscribed = client_info.get('clusters')
            if not (cluster_id is None or subscribed is None or cluster_id in subscribed):
                continue
            # sec (audit): the WS path had cluster-level scoping only, while its SSE twin
            # filters per VM. 'action' frames name the vmid, the VM's NAME and the operator
            # (create/delete/migrate/power), so a pool-/ACL-scoped client watching a cluster
            # saw every guest's activity. Same per-VM question as the SSE 'tasks' frame.
            if (update_type == 'action' and cluster_id is not None
                    and not client_info.get('is_admin', False)):
                _rid = (data or {}).get('resource_id')
                if (data or {}).get('resource_type') in ('vm', 'qemu', 'lxc', 'ct'):
                    if not _sse_user_can_view_vm(client_info.get('user'), cluster_id, _rid):
                        continue
            clients_to_send.append((client_id, client_info['ws'], client_info['lock']))

        # Send to clients outside the main lock.
        # A client already mid-send holds its own lock, and blocking on it here let one slow or
        # wedged consumer delay the frame for everyone after it in the list. Skip it for this
        # frame instead; the next broadcast reaches it once it has caught up.
        for client_id, ws, client_lock in clients_to_send:
            if not client_lock.acquire(blocking=False):
                logging.debug(f"[WS] client {client_id} still sending — skipped this frame")
                continue
            try:
                ws.send(message)
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


def create_sse_token(username: str, allowed_clusters: list, effective_role: str = None) -> str:
    """Create SSE token - avoids session ID in URL

    sec (audit): effective_role is captured at mint time because /api/sse/updates authenticates
    on the token alone — it has no session to floor an API token's role from, and reading the
    stored role there flagged an admin-owned viewer-scoped token as admin, which switched off
    every per-VM filter in the broadcast loop."""
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


_SSE_FILTER_MISSING = object()


def _serialize_sse_message(update_type, data, cluster_id, timestamp):
    """One consistent SSE frame — used for the shared broadcast and per-user filtered frames."""
    return json.dumps({
        'type': update_type, 'data': data,
        'cluster_id': cluster_id, 'timestamp': timestamp,
    }, default=str)


def _filtered_resources_frame(resources, cluster_id, username, timestamp):
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
    if not isinstance(resources, list) or not username:
        return None
    from pegaprox.core.db import get_db
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        stored = get_db().get_user(username)
    except Exception:
        stored = None
    if not stored:
        return None
    user = dict(stored)
    user['username'] = username
    allowed = [
        r for r in resources
        if user_can_access_vm(user, cluster_id, r.get('vmid'), 'vm.view', r.get('type'))
    ]
    return _serialize_sse_message('resources', allowed, cluster_id, timestamp)


def _sse_user_can_view_vm(username, cluster_id, vmid):
    """sec (private disclosure Sep 2026 — audit M1): SSE only per-VM-filtered the 'resources' frame;
    'vm_config' (full VM config incl. possible cloud-init secrets) and per-VM 'tasks' rows were
    broadcast cluster-wide to any subscribed non-admin. This is the per-VM gate for those frames.
    Single-user fetch (never load_users, the hot-path landmine), same pattern as the resources frame."""
    if not username:
        return False
    from pegaprox.core.db import get_db
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        stored = get_db().get_user(username)
    except Exception:
        stored = None
    if not stored:
        return False
    user = dict(stored)
    user['username'] = username
    try:
        return user_can_access_vm(user, cluster_id, int(vmid), 'vm.view')
    except (TypeError, ValueError):
        return False


def _sse_user_has_perm(username, permission):
    """sec (audit): the SSE stream carried the ESXi inventory ('vmware_*' frames) to every client,
    while the REST twin gates on a vmware.* permission — so a custom role built to hide ESXi still
    saw it over the stream. Same single-user fetch as _sse_user_can_view_vm."""
    if not username:
        return False
    from pegaprox.core.db import get_db
    from pegaprox.utils.rbac import has_permission
    try:
        stored = get_db().get_user(username)
    except Exception:
        stored = None
    if not stored:
        return False
    user = dict(stored)
    user['username'] = username
    return has_permission(user, permission)


def _sse_stored_user(username):
    """The acting user as a plain dict, fetched one row at a time. SSE runs in background threads
    with no request context, so there is no session to build an identity from."""
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
    return user


# sec (audit): the migration and DR progress frames carry a VM name, direction, target vmid and
# free-text log lines, and every one of them was broadcast with no cluster and no target_clusters —
# i.e. globally, to every SSE client in the install. Their REST twins are gated per-object
# (_migration_reachable / _xhm_reachable / _authz_plan_vms), so the stream was a way around those
# gates. Map each frame back to its underlying object and ask the same question.
_SSE_OBJECT_FRAMES = ('xhm_migration', 'xhm_migration_log',
                      'vmware_migration', 'vmware_migration_log', 'site_recovery')


def _sse_may_see_object_frame(username, update_type, data):
    """True if this client may see one of the _SSE_OBJECT_FRAMES. Fails closed: an unknown user, or
    a frame naming an object we can no longer resolve, gets nothing (an admin short-circuits)."""
    from pegaprox.models.permissions import ROLE_ADMIN
    user = _sse_stored_user(username)
    if not user:
        return False
    if user.get('role') == ROLE_ADMIN:
        return True
    data = data or {}
    try:
        if update_type.startswith('xhm_'):
            from pegaprox.globals import _xhm_migrations
            from pegaprox.utils.rbac import user_can_access_vm
            t = _xhm_migrations.get(data.get('id'))
            vmid, cid = getattr(t, 'source_vmid', None), getattr(t, 'source_cluster', None)
            if t is None or not vmid or not cid:
                return False
            return user_can_access_vm(user, cid, int(vmid), 'vm.migrate')

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


def _filtered_tasks_frame(tasks, cluster_id, username, timestamp):
    """Per-VM-authorized 'tasks' frame for a non-admin client: keep only rows whose vmid the caller
    may view (task rows without a resolvable vmid — node/cluster tasks — are dropped for a scoped
    client). None => unknown user, fail closed."""
    if not isinstance(tasks, list) or not username:
        return None
    from pegaprox.core.db import get_db
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        stored = get_db().get_user(username)
    except Exception:
        stored = None
    if not stored:
        return None
    user = dict(stored)
    user['username'] = username

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
        _res_frame_cache = {}
        _cfg_access_cache = {}    # uname -> bool: may this user view THIS vm_config frame's vmid (audit M1)
        _tasks_frame_cache = {}   # uname -> per-VM-filtered 'tasks' frame (audit M1)
        _vmw_perm_cache = {}      # uname -> bool: holds the vmware.* perm the REST twin requires
        _obj_frame_cache = {}     # uname -> bool: may see THIS migration/DR-plan frame (audit)
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
                        uname = client_info.get('user')
                        client_message = _res_frame_cache.get(uname, _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            client_message = _filtered_resources_frame(data, cluster_id, uname, timestamp)
                            _res_frame_cache[uname] = client_message
                    elif update_type == 'vm_config' and cluster_id is not None and not client_info.get('is_admin', False):
                        # audit M1 — vm_config carries the full VM config (disks/net/cloud-init);
                        # deliver only to a scoped client that may view this vmid.
                        uname = client_info.get('user')
                        _ok_cfg = _cfg_access_cache.get(uname, _SSE_FILTER_MISSING)
                        if _ok_cfg is _SSE_FILTER_MISSING:
                            _ok_cfg = _sse_user_can_view_vm(uname, cluster_id, (data or {}).get('vmid'))
                            _cfg_access_cache[uname] = _ok_cfg
                        if not _ok_cfg:
                            continue  # foreign VM's config → not for this scoped client
                    elif update_type == 'tasks' and cluster_id is not None and not client_info.get('is_admin', False):
                        # audit M1 — filter per-VM task rows to the ones this client may view.
                        uname = client_info.get('user')
                        client_message = _tasks_frame_cache.get(uname, _SSE_FILTER_MISSING)
                        if client_message is _SSE_FILTER_MISSING:
                            client_message = _filtered_tasks_frame(data, cluster_id, uname, timestamp)
                            _tasks_frame_cache[uname] = client_message
                    elif (update_type.startswith('vmware_')
                          and update_type not in _SSE_OBJECT_FRAMES
                          and not client_info.get('is_admin', False)):
                        # audit — mirror the REST perm gate (vmware.vm.view / vmware.view) that
                        # the stream skipped entirely. Both are default viewer perms, so this
                        # only bites a custom role that deliberately withholds them.
                        uname = client_info.get('user')
                        _need = 'vmware.view' if update_type == 'vmware_servers' else 'vmware.vm.view'
                        _ok_vmw = _vmw_perm_cache.get((uname, _need), _SSE_FILTER_MISSING)
                        if _ok_vmw is _SSE_FILTER_MISSING:
                            _ok_vmw = _sse_user_has_perm(uname, _need)
                            _vmw_perm_cache[uname, _need] = _ok_vmw
                        if not _ok_vmw:
                            continue
                    elif update_type in _SSE_OBJECT_FRAMES and not client_info.get('is_admin', False):
                        uname = client_info.get('user')
                        _ok_obj = _obj_frame_cache.get(uname, _SSE_FILTER_MISSING)
                        if _ok_obj is _SSE_FILTER_MISSING:
                            _ok_obj = _sse_may_see_object_frame(uname, update_type, data)
                            _obj_frame_cache[uname] = _ok_obj
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
