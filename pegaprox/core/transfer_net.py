# -*- coding: utf-8 -*-
"""Transfer network of a cluster - MK Oct 2026

A cluster can name a network (transfer_network, a CIDR) for the traffic that comes in
from other clusters. The remote migrations PegaProx starts towards it (by hand, in bulk,
for a cross-cluster replication, a Site Recovery run or the cross-cluster balancer) then
dial the target node at its address in that network instead of the management host, so
the disks stop crossing the management network. Migrations inside a cluster are PVE's
own: the datacenter option 'migration' already picks their network, nothing here
touches it.

A node's address comes from its own network config (/nodes/<n>/network), read at most
every ten minutes per node and never fanned out by a request: the settings view reads
the cache and lets one background read per cluster fill the gaps. The certificate an
endpoint pins is the one the node reports for itself through the API we are signed in
to, not whatever answers on the transfer address. A node without an address in the
network keeps the management host, and the caller says so.

Where PegaProx relays replication data over SSH itself, a node's transfer address is
used only when PegaProx reaches it and the host key there is the one pinned for the
node's management address (the caller connects with pinned_as, ssh_security.pin_as).
"""

import ipaddress
import logging
import shlex
import threading
import time
from urllib.parse import quote

log = logging.getLogger(__name__)

TTL = 600              # a node's network config and certificate, per node
ERROR_TTL = 60         # a node whose config could not be read is asked again after this
SSH_AWAY_TTL = 600     # a transfer address PegaProx could not use over SSH
OPTIONS_TTL = 60       # the datacenter migration network shown next to the setting
REPORT_EVERY = 3600    # one audit entry per node and reason in this time, the log gets each
FANOUT = 8
MAX_LEN = 64
MAX_PROBES = 256
PVE_PORT = 8006
PROBE_TIMEOUT = 4

INVALID = ('transfer_network must be a network in CIDR notation, IPv4 or IPv6 '
           '(e.g. 10.20.0.0/24), or empty to switch it off')

_lock = threading.Lock()
_nets = {}         # (cluster_id, node) -> {'at', 'ifaces': [(iface, ip, active)], 'error'}
_certs = {}        # (cluster_id, node) -> (at, fingerprint or None)
_options = {}      # cluster_id -> (at, migration network or None)
_ssh_away = {}     # (cluster_id, node, address) -> until
_reported = {}     # (cluster_id, node, reason) -> at
_refreshing = set()


def _spawn(fn):
    threading.Thread(target=fn, daemon=True, name='transfer-net-read').start()


def normalize(value):
    """(cidr, None) for a usable network, ('', None) for off, (None, error) otherwise."""
    if value is None:
        return '', None
    if not isinstance(value, str):
        return None, INVALID
    v = value.strip()
    if not v:
        return '', None
    if len(v) > MAX_LEN or '/' not in v:
        return None, INVALID
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None, INVALID
    if (net.prefixlen == 0 or net.is_loopback or net.is_multicast or net.is_link_local
            or net.is_unspecified):
        return None, ('transfer_network must be a network the nodes can route, not a '
                      'loopback, link-local, multicast or catch-all one')
    return str(net), None


def network_of(mgr, override=None):
    """The ip_network of the cluster's transfer network, or None when it is off."""
    raw = override if override is not None else getattr(getattr(mgr, 'config', None), 'transfer_network', '')
    cidr, _err = normalize(raw or '')
    return ipaddress.ip_network(cidr) if cidr else None


def _cid(mgr):
    return getattr(mgr, 'id', None) or getattr(mgr, 'cluster_id', '') or ''


def _members(mgr):
    try:
        return mgr.nodes or {}
    except Exception:
        return {}


def _is_member(mgr, node):
    return isinstance(node, str) and bool(node) and node in _members(mgr)


def _base(mgr):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json"


def addresses_of(entries):
    """[(iface, ip, active)] from a /nodes/<n>/network answer, each address once."""
    out, seen = [], set()
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        iface = str(e.get('iface') or '')
        active = e.get('active') in (1, '1', True)
        for key in ('cidr', 'address', 'cidr6', 'address6'):
            val = e.get(key)
            if not isinstance(val, str) or not val:
                continue
            try:
                ip = ipaddress.ip_address(val.split('/')[0].strip())
            except ValueError:
                continue
            if (iface, str(ip)) in seen:
                continue
            seen.add((iface, str(ip)))
            out.append((iface, str(ip), active))
    return out


def pick(ifaces, net):
    """(iface, address) of the address inside net, an interface that is up first, or None."""
    hits = []
    for iface, ip, active in ifaces or []:
        try:
            if ipaddress.ip_address(ip) in net:
                hits.append((0 if active else 1, iface, ip))
        except ValueError:
            continue
    if not hits:
        return None
    hits.sort()
    return hits[0][1], hits[0][2]


def _fresh(entry, now):
    if not entry:
        return False
    return now - entry['at'] < (ERROR_TTL if entry.get('error') else TTL)


def node_addresses(mgr, node, refresh=False):
    """The addresses in one member node's network config: {'at', 'ifaces', 'error'}.
    From the cache while it is fresh, else one API read."""
    key, now = (_cid(mgr), node), time.time()
    with _lock:
        entry = _nets.get(key)
    if not refresh and _fresh(entry, now):
        return entry
    try:
        r = mgr._api_get(f"{_base(mgr)}/nodes/{quote(node, safe='')}/network")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        entry = {'at': now, 'ifaces': addresses_of(r.json().get('data') or []), 'error': None}
    except Exception as e:
        entry = {'at': now, 'ifaces': [], 'error': (str(e) or type(e).__name__)[:200]}
    with _lock:
        _nets[key] = entry
    return entry


def node_fingerprint(mgr, node):
    """SHA-256 of the certificate the node's pveproxy presents, as the node reports it
    through the API we are signed in to: pveproxy-ssl.pem when there is one, else
    pve-ssl.pem, the order pveproxy itself uses. Colon-separated uppercase as PVE compares
    it, or None."""
    key, now = (_cid(mgr), node), time.time()
    with _lock:
        cached = _certs.get(key)
    if cached and now - cached[0] < (TTL if cached[1] else ERROR_TTL):
        return cached[1]
    fp = None
    try:
        r = mgr._api_get(f"{_base(mgr)}/nodes/{quote(node, safe='')}/certificates/info")
        if r.status_code == 200:
            certs = {c.get('filename'): c.get('fingerprint') for c in (r.json().get('data') or [])
                     if isinstance(c, dict)}
            raw = certs.get('pveproxy-ssl.pem') or certs.get('pve-ssl.pem') or ''
            parts = str(raw).replace('-', ':').split(':')
            if len(parts) == 32 and all(len(p) == 2 for p in parts):
                fp = ':'.join(p.upper() for p in parts)
    except Exception as e:
        log.debug(f"[XFER] certificate of {node} unreadable: {e}")
    with _lock:
        _certs[key] = (now, fp)
    return fp


def _node_at(mgr, host):
    """The member node whose name or cluster address is host, or None (one API read)."""
    if host in _members(mgr):
        return host
    try:
        r = mgr._api_get(f"{_base(mgr)}/cluster/status")
        if r.status_code == 200:
            for it in r.json().get('data') or []:
                if isinstance(it, dict) and it.get('type') == 'node' and it.get('ip') == host:
                    return it.get('name')
    except Exception:
        pass
    return None


def _node_for(mgr, net):
    """The node a remote migrate that names none goes to: the one behind the management
    host when it has an address in net, else the first online node that has one."""
    host = str(getattr(mgr, 'raw_host', '') or getattr(getattr(mgr, 'config', None), 'host', '') or '')
    online = sorted(n for n, d in _members(mgr).items()
                    if not isinstance(d, dict) or d.get('status', 'online') == 'online')
    first = _node_at(mgr, host)
    order = ([first] if first in online else []) + [n for n in online if n != first]
    for n in order:
        if pick(node_addresses(mgr, n)['ifaces'], net):
            return n
    return order[0] if order else None


def migration_route(mgr, node=None):
    """Where a remote migrate into mgr's cluster dials, for a cluster with a transfer network.

    None when the cluster has none: the caller keeps the management host as before. Else
    a dict: network, node, and host + fingerprint when that node (or the one picked for a
    run that names none) has an address there whose certificate the API reports. Without
    them reason (no_node, not_member, unreadable, no_address, no_certificate) and note say
    why the management host is used; report_fallback() tells the log and the audit."""
    net = network_of(mgr)
    if net is None:
        return None
    out = {'network': str(net), 'node': node, 'host': None, 'iface': None, 'fingerprint': None,
           'reason': None, 'note': '', 'cluster': getattr(getattr(mgr, 'config', None), 'name', '') or _cid(mgr)}

    def fallback(reason, why):
        out.update(reason=reason, note=f"transfer network {net} of {out['cluster']} not used: {why} - "
                                       f"the migration goes to the management host")
        return out

    if node is None:
        node = _node_for(mgr, net)
        out['node'] = node
        if not node:
            return fallback('no_node', 'no online node')
    elif not _is_member(mgr, node):
        return fallback('not_member', f"{node} is not a node of the cluster")
    entry = node_addresses(mgr, node)
    if entry.get('error'):
        return fallback('unreadable', f"the network config of {node} could not be read ({entry['error']})")
    hit = pick(entry['ifaces'], net)
    if not hit:
        return fallback('no_address', f"{node} has no address in it")
    fp = node_fingerprint(mgr, node)
    if not fp:
        return fallback('no_certificate', f"the certificate of {node} could not be read")
    out.update(iface=hit[0], host=hit[1], fingerprint=fp)
    return out


def report_fallback(route, logger=None, user='system'):
    """Say that a migration into a cluster with a transfer network went to the management
    host, never silently: the cluster log each time, the audit log once an hour per node
    and reason. Nothing for a route that has an address or a cluster without the setting."""
    if not route or route.get('host'):
        return
    (logger or log).warning(f"[XFER] {route['note']}")
    key, now = (route.get('cluster'), route.get('node'), route.get('reason')), time.time()
    with _lock:
        if now - _reported.get(key, 0) < REPORT_EVERY:
            return
        _reported[key] = now
    try:
        from pegaprox.utils.audit import log_audit
        log_audit(user, 'migration.transfer_network_fallback', route['note'], cluster=route.get('cluster'))
    except Exception:
        pass


def describe(route):
    """What a response carries about the transfer network of a migration, or None."""
    if not route:
        return None
    return {'network': route['network'], 'node': route.get('node'),
            'via': 'transfer' if route.get('host') else 'management',
            'host': route.get('host'), 'reason': route.get('reason')}


def endpoint(token, host, fingerprint):
    """PVE's target-endpoint property string. An IPv6 host goes in bare, the way PVE's
    address format takes it."""
    return (f"apitoken=PVEAPIToken={token['token_id']}={token['token_value']},"
            f"host={host},fingerprint={fingerprint}")


# --- SSH relay -------------------------------------------------------------------------

def transfer_ssh_address(mgr, node, mgmt_ip):
    """A member node's address in its cluster's transfer network for an SSH relay PegaProx
    runs itself, or None: then the management address stays. Never mgmt_ip itself, and not
    an address PegaProx failed to use in the last ten minutes. The caller connects there
    with pinned_as=mgmt_ip, so it is used only where the host key matches that pin."""
    net = network_of(mgr)
    if net is None or not _is_member(mgr, node):
        return None
    entry = node_addresses(mgr, node)
    hit = pick(entry['ifaces'], net) if not entry.get('error') else None
    if not hit or hit[1] == mgmt_ip:
        return None
    with _lock:
        if _ssh_away.get((_cid(mgr), node, hit[1]), 0) > time.time():
            return None
    return hit[1]


def ssh_unusable(mgr, node, address):
    """The relay could not use this transfer address (unreachable, or another host key):
    the management address for the next ten minutes."""
    with _lock:
        _ssh_away[(_cid(mgr), node, address)] = time.time() + SSH_AWAY_TTL


# --- the settings view -----------------------------------------------------------------

def _dc_migration_network(mgr):
    """The datacenter migration network of the cluster (PVE's option 'migration'), '' when
    unset, None when it could not be read."""
    cid, now = _cid(mgr), time.time()
    with _lock:
        cached = _options.get(cid)
    if cached and now - cached[0] < OPTIONS_TTL:
        return cached[1]
    value = None
    try:
        r = mgr._api_get(f"{_base(mgr)}/cluster/options")
        if r.status_code == 200:
            mig = (r.json().get('data') or {}).get('migration')
            value = ''
            if isinstance(mig, dict):
                value = str(mig.get('network') or '')
            elif isinstance(mig, str):
                for part in mig.split(','):
                    k, _, v = part.partition('=')
                    if k.strip() == 'network':
                        value = v.strip()
    except Exception as e:
        log.debug(f"[XFER] datacenter options of {cid} unreadable: {e}")
    with _lock:
        _options[cid] = (now, value)
    return value


def _refresh_async(mgr, nodes):
    """One background read per cluster for the nodes whose config the cache lacks."""
    cid = _cid(mgr)
    with _lock:
        if cid in _refreshing:
            return
        _refreshing.add(cid)

    def run():
        try:
            from pegaprox.utils.concurrent import run_per_node
            run_per_node({n: (lambda nm: node_addresses(mgr, nm, refresh=True)) for n in nodes},
                         max_concurrent=FANOUT, timeout=max(30, len(nodes) // FANOUT * 15 + 30))
        except Exception as e:
            log.warning(f"[XFER] reading the node networks of {cid} failed: {e}")
        finally:
            with _lock:
                _refreshing.discard(cid)
    _spawn(run)


def cluster_view(mgr, override=None):
    """The settings view: per node the address in the network (the saved one, or override
    for a preview), from the cache only. Nodes the cache lacks are read in the background
    and reported pending meanwhile."""
    net = network_of(mgr, override)
    members = _members(mgr)
    now = time.time()
    rows, stale = [], []
    for name in sorted(members):
        d = members.get(name)
        online = not isinstance(d, dict) or d.get('status', 'online') == 'online'
        row = {'node': name, 'online': online, 'address': None, 'iface': None, 'state': 'off'}
        if net is not None:
            with _lock:
                entry = _nets.get((_cid(mgr), name))
            if not _fresh(entry, now) and online:
                stale.append(name)
            if not entry:
                row['state'] = 'pending' if online else 'offline'
            elif entry.get('error'):
                row.update(state='unreadable', error=entry['error'])
            else:
                hit = pick(entry['ifaces'], net)
                if hit:
                    row.update(state='ok', iface=hit[0], address=hit[1])
                else:
                    row['state'] = 'none'
        rows.append(row)
    if stale:
        _refresh_async(mgr, stale)
    return {'network': str(net) if net is not None else '', 'nodes': rows,
            'pending': any(r['state'] == 'pending' for r in rows),
            'missing': sum(1 for r in rows if r['state'] in ('none', 'unreadable')),
            'migration_network': _dc_migration_network(mgr)}


# --- the reachability check ------------------------------------------------------------

def probe_command(addresses, port=PVE_PORT, timeout=PROBE_TIMEOUT):
    """One shell line that opens a TCP connection to every address at once from the node it
    runs on and prints '<index> ok|fail <ms>' per address. Addresses are checked here, so
    nothing else reaches the shell."""
    parts = []
    for i, addr in enumerate(addresses):
        ip = str(ipaddress.ip_address(addr))
        dial = shlex.quote(f"exec 3<>/dev/tcp/{ip}/{int(port)}")
        parts.append(f"( s=$(date +%s%N); if timeout {int(timeout)} bash -c {dial} 2>/dev/null; "
                     f"then r=ok; else r=fail; fi; e=$(date +%s%N); "
                     f"echo \"{i} $r $(( (e - s) / 1000000 ))\" ) &")
    return ' '.join(parts) + ' wait'


def parse_probe(output, count):
    """{index: (ok, ms)} from probe_command's output; lines it cannot read are left out."""
    out = {}
    for line in (output or '').splitlines():
        bits = line.split()
        if len(bits) < 2 or not bits[0].isdigit():
            continue
        i = int(bits[0])
        if i >= count or bits[1] not in ('ok', 'fail'):
            continue
        ms = int(bits[2]) if len(bits) > 2 and bits[2].isdigit() else None
        out[i] = (bits[1] == 'ok', ms)
    return out


def check_from(source_mgr, source_node, target_mgr):
    """Whether the transfer addresses of target_mgr's nodes answer on 8006 from one node of
    source_mgr, through the node's SSH like the other node checks (_ssh_node_output_ex).
    Returns (report, None) or (None, (code, detail))."""
    net = network_of(target_mgr)
    if net is None:
        return None, ('NO_NETWORK', 'the cluster has no transfer network set')
    if not _is_member(source_mgr, source_node):
        return None, ('NOT_MEMBER', f"{source_node} is not a node of the source cluster")
    diag = source_mgr.ssh_diagnose(source_node)
    if diag:
        return None, diag
    names = sorted(_members(target_mgr))[:MAX_PROBES]
    from pegaprox.utils.concurrent import run_per_node
    entries = run_per_node({n: (lambda nm: node_addresses(target_mgr, nm)) for n in names},
                           max_concurrent=FANOUT, timeout=max(30, len(names) // FANOUT * 15 + 30))
    rows, targets = [], []
    for name in names:
        entry = entries.get(name) or {'ifaces': [], 'error': 'timed out'}
        row = {'node': name, 'address': None, 'status': 'none'}
        if entry.get('error'):
            row['status'] = 'unreadable'
        else:
            hit = pick(entry['ifaces'], net)
            if hit:
                row.update(address=hit[1], status='unknown', index=len(targets))
                targets.append(hit[1])
        rows.append(row)
    report = {'network': str(net), 'source_node': source_node, 'port': PVE_PORT, 'nodes': rows}
    if not targets:
        return report, None
    output, reason = source_mgr._ssh_node_output_ex(source_node, probe_command(targets),
                                                    timeout=PROBE_TIMEOUT + 30)
    if output is None:
        return None, ('SSH_FAILED', reason or 'SSH connection failed')
    got = parse_probe(output, len(targets))
    for row in rows:
        i = row.pop('index', None)
        if i is None:
            continue
        if i in got:
            row['status'] = 'ok' if got[i][0] else 'fail'
            row['ms'] = got[i][1]
    return report, None
