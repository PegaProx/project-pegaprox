# -*- coding: utf-8 -*-
"""Root passwords of single nodes, for clusters whose nodes do not share one (#1136).

MK Oct 2026 - PegaProx offered every node of a cluster the cluster's one password. Nodes
with a root password of their own (good practice, and common) refused every SSH step and
every API login at a fallback host. Such a node keeps its password here, in
cluster_node_credentials, sealed like clusters.pass_encrypted, and a password step to it
offers that one instead of the cluster's:

  * SSH: the key still goes first, then the node's own password where it has one, the
    cluster's otherwise. SSH switched off still means no SSH at all.
  * API: a login at a fallback host whose node has its own password sends that one, for
    a @pam account of the same name. The registered host keeps the cluster password.
  * A token cluster ('!' in the user) has no password to offer any node. A node password
    is a real account password, so that node still gets it for SSH.

Which node an address belongs to is the manager's to say, from the membership it resolved
itself (_get_node_ip, cluster status), never from a name a request brings along. An
address it cannot place on exactly one current member gets nothing extra: the cluster
password, as before. The management address of a node with a password of its own is
kept in its row too, for a start with the registered host down, when nothing has been
resolved yet.

The value never goes into a response, a log line or an audit entry.
"""

import logging
import re
import threading
import time
import unicodedata

log = logging.getLogger(__name__)

MAX_LEN = 256
# how long an opened set of passwords is used before the table is read again. A standby
# gets its rows from the sync, and a change on this instance drops the entry at once
CACHE_TTL = 10.0
# an address the manager placed a node at counts that long. Every SSH path resolves the
# node right before it connects, which places it again
ADDRESS_TTL = 1800.0
# a node missing from the cluster's own node list for that long has left it; one listing
# that misses it is no reason to forget its password
LEAVE_GRACE = 600.0
SWEEP_EVERY = 60.0
NODE_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}')

# conncheck codes of a login that went through
LOGIN_OK = ('OK', 'SUDO_REFUSED')
LOGIN_REFUSED = 'AUTH_REFUSED'

_lock = threading.Lock()
_secrets = {}       # cluster_id -> (monotonic, {node: password}, {node: kept address})
_generation = {}    # cluster_id -> count of invalidations; None counts for all of them
_addresses = {}     # cluster_id -> {address: {node: monotonic}}
_absent = {}        # (cluster_id, node) -> monotonic of the first listing without it
_swept = {}         # cluster_id -> monotonic


def _now():
    return time.monotonic()


def value_problem(value):
    """Why `value` cannot be a node's password, or None."""
    if not isinstance(value, str):
        return 'The password must be a string'
    if not value:
        return 'The password is empty - clear it with DELETE instead'
    if len(value) > MAX_LEN:
        return f'The password is longer than {MAX_LEN} characters'
    if any(unicodedata.category(c) in ('Cc', 'Zl', 'Zp') for c in value):
        return 'The password must not contain control characters or line breaks'
    return None


def node_name_ok(node):
    return isinstance(node, str) and bool(NODE_NAME_RE.fullmatch(node))


# --- the passwords ---------------------------------------------------------------------

def _loaded(cluster_id):
    """({node: password}, {node: last address}) of one cluster, from a short cache."""
    if not isinstance(cluster_id, str) or not cluster_id:
        return {}, {}
    now = _now()
    with _lock:
        hit = _secrets.get(cluster_id)
        if hit is not None and now - hit[0] < CACHE_TTL:
            return hit[1], hit[2]
        gen = (_generation.get(None, 0), _generation.get(cluster_id, 0))
    try:
        from pegaprox.core.db import get_db
        found, where = get_db().node_credential_secrets(cluster_id, with_addresses=True)
    except Exception as e:
        log.debug(f"[NodeCreds] could not read the node passwords of {cluster_id}: {type(e).__name__}")
        found, where = {}, {}
    with _lock:
        # a clear that landed while this read ran must not be undone by caching the read
        if gen == (_generation.get(None, 0), _generation.get(cluster_id, 0)):
            _secrets[cluster_id] = (now, found, where)
    return found, where


def secrets_of(cluster_id):
    """{node: password} of one cluster, opened. Server side only."""
    return _loaded(cluster_id)[0]


def invalidate(cluster_id=None):
    with _lock:
        _generation[cluster_id] = _generation.get(cluster_id, 0) + 1
        if cluster_id is None:
            _secrets.clear()
        else:
            _secrets.pop(cluster_id, None)


def store(cluster_id, node, value, by):
    from pegaprox.core.db import get_db
    get_db().save_node_credential(cluster_id, node, value, by)
    invalidate(cluster_id)


def clear(cluster_id, node, by):
    from pegaprox.core.db import get_db
    get_db().save_node_credential(cluster_id, node, '', by)
    invalidate(cluster_id)


def forget(cluster_id, node):
    """The row of a node that left the cluster, password and check alike."""
    from pegaprox.core.db import get_db
    gone = get_db().delete_node_credential(cluster_id, node)
    invalidate(cluster_id)
    with _lock:
        _absent.pop((cluster_id, node), None)
        for names in (_addresses.get(cluster_id) or {}).values():
            names.pop(node, None)
    return gone


def forget_cluster(cluster_id):
    """What this process holds of a deleted cluster (the rows go with delete_cluster)."""
    invalidate(cluster_id)
    with _lock:
        _addresses.pop(cluster_id, None)
        _swept.pop(cluster_id, None)
        for key in [k for k in _absent if k[0] == cluster_id]:
            _absent.pop(key, None)


def state(cluster_id):
    """The rows of one cluster without the values (has_password instead)."""
    from pegaprox.core.db import get_db
    return get_db().list_node_credentials(cluster_id)


# --- which node an address belongs to ---------------------------------------------------

def _norm(address):
    a = str(address or '').strip()
    if a.startswith('[') and a.endswith(']'):
        a = a[1:-1]
    return a.lower()


def note_address(cluster_id, node, address, primary=False):
    """The manager of `cluster_id` placed `node` at `address`, by its own resolution.

    `primary`: its management address (_get_node_ip). That one is kept with the node's
    password as well, for a manager that starts while the registered host is down and
    has resolved nothing yet. Written on a change only, and only where this instance acts."""
    a = _norm(address)
    if not isinstance(cluster_id, str) or not cluster_id or not a or not isinstance(node, str) or not node:
        return
    now = _now()
    with _lock:
        book = _addresses.setdefault(cluster_id, {})
        book.setdefault(a, {})[node] = now
        if len(book) > 1024:
            # bounded by the cluster's own nodes; prune what ran out
            for addr in list(book):
                names = {n: t for n, t in book[addr].items() if now - t < ADDRESS_TTL}
                if names:
                    book[addr] = names
                else:
                    del book[addr]
    if not primary:
        return
    own, where = _loaded(cluster_id)
    if node not in own or where.get(node) == a:
        return
    try:
        from pegaprox.core import ha
        if not ha.is_active():
            return
        from pegaprox.core.db import get_db
        get_db().set_node_credential_address(cluster_id, node, a)
        invalidate(cluster_id)
    except Exception as e:
        log.debug(f"[NodeCreds] could not keep the address of {node}: {type(e).__name__}")


def nodes_at(cluster_id, address):
    """The node names the manager placed at `address` lately. Where it placed nobody
    there yet (a start with the registered host down), the address a node with a
    password of its own was last seen at."""
    a = _norm(address)
    now = _now()
    with _lock:
        names = (_addresses.get(cluster_id) or {}).get(a) or {}
        fresh = {n for n, t in names.items() if now - t < ADDRESS_TTL}
    if fresh or not a:
        return fresh
    own, where = _loaded(cluster_id)
    return {n for n, addr in where.items() if addr == a and n in own}


# --- the check --------------------------------------------------------------------------

def outcome(item):
    """(code, detail, credential) of one ssh item of conncheck."""
    return (str(item.get('code') or ''), str(item.get('detail') or '')[:300],
            str(item.get('credential') or ''))


def record(cluster_id, items, members):
    """Keep what a check found per node. An item without a node (SSH off, no credential
    at all) stands for every member. Only the instance that acts writes."""
    results = {}
    for it in items or []:
        if it.get('kind') != 'ssh':
            continue
        if it.get('node'):
            results[it['node']] = outcome(it)
        else:
            for name in members:
                results.setdefault(name, outcome(it))
    if not results:
        return {}
    from pegaprox.core.db import get_db
    get_db().record_node_credential_checks(cluster_id, results)
    return results


def refused(items):
    return sorted(it['node'] for it in items or []
                  if it.get('kind') == 'ssh' and it.get('node') and it.get('code') == LOGIN_REFUSED)


def run_check(mgr, cluster_id, only=None):
    """One SSH login per online node with what that node would get (conncheck.check_ssh),
    kept per node. Returns (items, members). Raises when the cluster status is unreadable."""
    from pegaprox.core import conncheck
    _cluster, members = conncheck._cluster_status(mgr)
    if only:
        members = [n for n in members if n['name'] in only]
    items = conncheck.check_ssh(mgr, members) if members else []
    names = [n['name'] for n in members]
    record(cluster_id, items, names)
    return items, names


def check_in_background(cluster_id, delay=5.0):
    """Once after a cluster was added: who refuses the login. A look, no change: the
    login and `sudo -n true` go out as a read (ha.reading)."""
    def run():
        time.sleep(delay)
        from pegaprox.core import ha
        from pegaprox.globals import cluster_managers
        mgr = cluster_managers.get(cluster_id)
        if mgr is None or getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox' or not ha.is_active():
            return
        try:
            with ha.reading():
                items, _names = run_check(mgr, cluster_id)
        except Exception as e:
            log.info(f"[NodeCreds] login check of the new cluster {cluster_id} did not run: {e}")
            return
        bad = refused(items)
        if bad:
            log.warning(f"[NodeCreds] new cluster {cluster_id}: the login was refused by "
                        f"{', '.join(bad)} - set their own passwords under Node credentials")
    t = threading.Thread(target=run, name=f'node-creds-check-{cluster_id}', daemon=True)
    t.start()
    return t


# --- nodes that left --------------------------------------------------------------------

def note_membership(cluster_id, names):
    """The nodes the cluster lists right now. The row of a node missing from it for
    LEAVE_GRACE goes (a node removed elsewhere than in PegaProx); a node that turns up
    again keeps its row. Looks at most once a SWEEP_EVERY, and only on the active."""
    if not cluster_id or not names:
        return []
    now = _now()
    with _lock:
        if now - _swept.get(cluster_id, -SWEEP_EVERY) < SWEEP_EVERY:
            return []
        _swept[cluster_id] = now
    from pegaprox.core import ha
    if not ha.is_active():
        return []
    try:
        rows = state(cluster_id)
    except Exception:
        return []
    present = set(names)
    gone = []
    for row in rows:
        node = row['node']
        key = (cluster_id, node)
        if node in present:
            with _lock:
                _absent.pop(key, None)
            continue
        with _lock:
            first = _absent.setdefault(key, now)
        if now - first >= LEAVE_GRACE:
            forget(cluster_id, node)
            gone.append(node)
    if gone:
        try:
            from pegaprox.globals import cluster_managers
            from pegaprox.utils.audit import log_audit
            mgr = cluster_managers.get(cluster_id)
            log_audit('system', 'cluster.node_credential_removed',
                      f"Dropped the stored login of node(s) {', '.join(gone)}: no longer in the cluster",
                      cluster=getattr(getattr(mgr, 'config', None), 'name', None), cluster_id=cluster_id)
        except Exception:
            pass
    return gone
