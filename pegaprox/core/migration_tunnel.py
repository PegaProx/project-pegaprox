# -*- coding: utf-8 -*-
"""The tunnel a remote migration runs through, across Proxmox VE versions - MK Nov 2026

A remote migration opens a websocket tunnel from the source node to the node of the target
cluster its endpoint names. qemu-server 9.2.21 and pve-container 6.1.25 (the guest identity
of Proxmox VE 9.3) raised the version of that tunnel from 2 to 3: such a source aborts
against a target that reports 2 with "Remote tunnel endpoint too old, upgrade required".
It does so in the task, once the target reserved the VMID, which is after every step
PegaProx takes before a migration: a cross-cluster replication run had removed the old
replica by then. An older source still migrates into a newer target.

So the installed qemu-server (for a VM) or pve-container (for a container) of the source
node and of the node the guest lands on are compared before anything is made or removed.
They come from /nodes/<n>/apt/versions (Sys.Audit on the node, in the role PegaProx
documents), read at most every TTL seconds per node; a move that would be refused is read
again before it is refused. A version that cannot be read refuses nothing, as before,
unless the caller asks for strict, which reads every version fresh: a replication run
removes the old replica first.

The same releases take the 'allow-new-uid' parameter of a remote migrate; older ones
refuse a parameter they do not know.
"""

import logging
import re
import threading
import time
from urllib.parse import quote

from pegaprox.utils.ssh import bare_host

log = logging.getLogger(__name__)

CODE = 'PVE_TUNNEL_TOO_OLD'
# the first release with tunnel version 3, per guest type
V3 = {'qemu': ('qemu-server', (9, 2, 21)), 'lxc': ('pve-container', (6, 1, 25))}
TTL = 300
ERROR_TTL = 60

_VERSION = re.compile(r'^(\d+)\.(\d+)(?:\.(\d+))?')
_lock = threading.Lock()
_versions = {}     # (cluster_id, node) -> (at, {package: (major, minor, patch)} or None)
_local = {}        # (cluster_id, host) -> (at, node or None)


def reset_for_tests():
    with _lock:
        _versions.clear()
        _local.clear()


def _cid(mgr):
    return getattr(mgr, 'id', None) or getattr(mgr, 'cluster_id', '') or ''


def _label(mgr):
    name = getattr(getattr(mgr, 'config', None), 'name', None) or _cid(mgr)
    return name if isinstance(name, str) else ''


def _what(mgr, node):
    return f"{node} of {_label(mgr)}" if _label(mgr) else str(node)


def _fresh(entry, now):
    return entry is not None and now - entry[0] < (TTL if entry[1] is not None else ERROR_TTL)


def packages(mgr, node, refresh=False):
    """{package: (major, minor, patch)} of qemu-server and pve-container installed on node,
    None when the list cannot be read."""
    key, now = (_cid(mgr), node), time.time()
    with _lock:
        cached = _versions.get(key)
    if not refresh and _fresh(cached, now):
        return cached[1]
    got = None
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{quote(str(node), safe='')}"
                         f"/apt/versions")
        if r.status_code == 200:
            wanted = {pkg for pkg, _first in V3.values()}
            got = {}
            for p in r.json().get('data') or []:
                if not isinstance(p, dict) or p.get('Package') not in wanted:
                    continue
                # OldVersion is the installed one, Version what apt would install next
                m = _VERSION.match(str(p.get('OldVersion') or ''))
                if m:
                    got[p['Package']] = tuple(int(x or 0) for x in m.groups())
    except Exception as e:
        log.debug(f"[TUNNEL] package versions of {node} on {_cid(mgr)}: {e}")
    with _lock:
        _versions[key] = (now, got)
    return got


def _side(mgr, node, vm_type, refresh=False):
    """(tunnel version, installed version) of node for a guest of vm_type, (None, None)
    when unread."""
    pkg, first = V3['lxc' if vm_type == 'lxc' else 'qemu']
    have = (packages(mgr, node, refresh) or {}).get(pkg)
    if have is None:
        return None, None
    return (3 if have >= first else 2), have


def tunnel_version(mgr, node, vm_type):
    """The tunnel version node runs for a guest of vm_type: 2 or 3, None when unread."""
    return _side(mgr, node, vm_type)[0]


def takes_allow_new_uid(mgr, node, vm_type):
    """Whether a remote migrate on node takes 'allow-new-uid' (the release of tunnel 3)."""
    return (tunnel_version(mgr, node, vm_type) or 0) >= 3


def _bare(host):
    return bare_host(host) if isinstance(host, str) else ''


def _endpoint_node(mgr, host, refresh=False):
    """The node behind host, the one the endpoint of a remote migrate into mgr's cluster
    names. PVE's remote_migrate asks that host's /cluster/status for the node marked local:
    the host PegaProx talks to answers it for itself, another one (config.host while the
    HA fallback talks to a fallback host) is found by its node name or cluster address."""
    key, now = (_cid(mgr), host), time.time()
    with _lock:
        cached = _local.get(key)
    if not refresh and _fresh(cached, now):
        return cached[1]
    node = None
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/status")
        if r.status_code == 200:
            members = [it for it in r.json().get('data') or [] if isinstance(it, dict) and it.get('type') == 'node']
            if host in {_bare(getattr(mgr, 'host', None)), _bare(getattr(mgr, '_original_host', None))}:
                node = next((it.get('name') for it in members if it.get('local')), None)
            else:
                node = next((it.get('name') for it in members if host in (it.get('name'), it.get('ip'))), None)
    except Exception as e:
        log.debug(f"[TUNNEL] node behind {host} on {_cid(mgr)}: {e}")
    with _lock:
        _local[key] = (now, node if isinstance(node, str) and node else None)
    return _local[key][1]


def landing_nodes(mgr, node=None, host=None, refresh=False):
    """The nodes of mgr's cluster a remote migrate into it lands on: the node the transfer
    network route dials (core/transfer_net.py), else the node behind host, the one the
    endpoint names without it (config.host, as get_cluster_fingerprint() hands it out, when
    None), else, when that is not known either, every online node."""
    from pegaprox.core import transfer_net
    try:
        route = transfer_net.migration_route(mgr, node)
    except Exception as e:
        log.debug(f"[TUNNEL] transfer route of {_cid(mgr)}: {e}")
        route = None
    if route and route.get('host') and route.get('node'):
        return [route['node']]
    host = _bare(host if host is not None else getattr(getattr(mgr, 'config', None), 'host', None))
    local = _endpoint_node(mgr, host, refresh) if host else None
    if local:
        return [local]
    try:
        return sorted(n for n, d in (mgr.nodes or {}).items()
                      if not isinstance(d, dict) or d.get('status', 'online') == 'online')
    except Exception:
        return []


def _v(t):
    return '.'.join(str(x) for x in t)


def too_old(vm_type, src, src_what, tgt, tgt_what, tgt_have=None):
    """The refusal of a source with tunnel src into a target with tunnel tgt, or None."""
    if src is None or tgt is None or src <= tgt:
        return None
    pkg, first = V3['lxc' if vm_type == 'lxc' else 'qemu']
    have = f" ({pkg} {_v(tgt_have)})" if tgt_have else ''
    return (f"Proxmox VE refuses this move: {src_what} runs migration tunnel version {src}, {tgt_what}{have} "
            f"only {tgt} ('Remote tunnel endpoint too old, upgrade required'). Upgrade the target cluster "
            f"first ({pkg} {_v(first)} or newer, Proxmox VE 9.3), then migrate.")


def refusal(src_mgr, src_node, vm_type, tgt_mgr, tgt_node=None, strict=False, host=None):
    """Why Proxmox VE would refuse the remote migration of a vm_type guest from src_node into
    tgt_mgr's cluster for the tunnel version, or None. tgt_node is the node the caller names,
    host the one its endpoint names without a transfer network (None: config.host); the
    check takes the nodes the guest lands on (landing_nodes). The target is read only
    behind a source that may run the newer tunnel, and a refusal rests on a fresh read of
    both. strict reads everything fresh and also refuses when a version that could make it
    fail cannot be read."""
    src, _src_have = _side(src_mgr, src_node, vm_type, refresh=strict)
    if src is not None and src < 3:
        # every target takes the older tunnel
        return None
    if src is None and not strict:
        return None
    tgt_nodes = landing_nodes(tgt_mgr, tgt_node, host, refresh=strict)
    src_what = _what(src_mgr, src_node)
    unread = []
    for node in tgt_nodes or ():
        tgt, tgt_have = _side(tgt_mgr, node, vm_type, refresh=strict)
        tgt_what = _what(tgt_mgr, node)
        if tgt is None:
            unread.append(tgt_what)
        elif tgt >= 3:
            continue
        elif src is None:
            # an older target: it depends on the source
            unread.append(src_what)
        else:
            if not strict:
                src, _src_have = _side(src_mgr, src_node, vm_type, refresh=True)
                tgt, tgt_have = _side(tgt_mgr, node, vm_type, refresh=True)
            why = too_old(vm_type, src, src_what, tgt, tgt_what, tgt_have)
            if why:
                return why
    if strict and (unread or not tgt_nodes):
        pkg, first = V3['lxc' if vm_type == 'lxc' else 'qemu']
        if src is None:
            unread.insert(0, src_what)
        what = ', '.join(dict.fromkeys(unread)) or f"the node of {_label(tgt_mgr) or 'the target'} the migration lands on"
        return (f"The {pkg} version of {what} could not be read: whether Proxmox VE takes the move is "
                f"not known (a source with {pkg} {_v(first)} or newer refuses an older target)")
    return None


# a migration between two sites (core/federation_migrate.py): each site reads its own side,
# the other one's comes as a number

def known(value):
    """A tunnel version another site sent, or None"""
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 100 else None


def lowest(mgr, nodes, vm_type):
    """The lowest tunnel version of these nodes that could be read, or None"""
    got = [v for v in (tunnel_version(mgr, n, vm_type) for n in nodes or ()) if v is not None]
    return min(got) if got else None


def refusal_from(src, src_what, vm_type, tgt_mgr, tgt_nodes):
    """refusal() for a source whose tunnel version src the other site read"""
    for node in tgt_nodes or ():
        tgt, _have = _side(tgt_mgr, node, vm_type)
        if src is not None and tgt is not None and src > tgt:
            tgt, have = _side(tgt_mgr, node, vm_type, refresh=True)
            why = too_old(vm_type, src, src_what, tgt, _what(tgt_mgr, node), have)
            if why:
                return why
    return None


def refusal_to(src_mgr, src_node, vm_type, tgt, tgt_what):
    """refusal() for a target whose tunnel version tgt the other site read"""
    src, _have = _side(src_mgr, src_node, vm_type)
    if src is None or tgt is None or src <= tgt:
        return None
    src, _have = _side(src_mgr, src_node, vm_type, refresh=True)
    return too_old(vm_type, src, _what(src_mgr, src_node), tgt, tgt_what)
