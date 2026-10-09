# -*- coding: utf-8 -*-
"""The QDevice of a Proxmox VE cluster, as its nodes see it - MK Oct 2026 (#1137)

GET /cluster/config/qdevice asks the corosync-qdevice daemon of the node that serves the
call (its socket, `status verbose`) and answers with what the daemon prints, as text:
Algorithm, Echo reply, Last poll call, Model, QNetd host, State and Tie-breaker. A node
without a running daemon answers {}. The call takes no node, so a node is asked at an
address of its own: the API host, and the registered and fallback hosts, with the
cluster's session (its TLS policy, its ticket or token) the way the connection check
probes those addresses (conncheck.probe_host). Which address is which node is found as
the check finds it (conncheck._host_nodes), and an address it cannot place says itself
through the `local` flag of its /cluster/status. A node at none of these addresses is
listed but not asked.

The QNetd host is no Proxmox node: nothing in the Proxmox API reads its CPU, memory or
updates. What is known of it is what the daemons on the nodes say - whether they are
connected, and when it last answered them.

Read when someone asks: the route while somebody looks at the cluster, the qdevice alert
rule on the active instance. One read per cluster every FRESH seconds whoever asks: the
node list and one GET per node that can be asked, never anything per guest. The Prometheus
exporter only takes what is kept here.
"""

import logging
import math
import threading
import time
from datetime import datetime, timezone

from pegaprox.core import conncheck
from pegaprox.utils.concurrent import run_per_node

log = logging.getLogger(__name__)

FRESH = 30            # a read this recent is handed out again
SERVE_MAX = 300       # what the exporter still hands out
HOST_TIMEOUT = 5      # per address, connect and answer each
FANOUT = 8
PLACE_EVERY = 600     # which address is which node changes seldom
TEXT_MAX = 200
CONNECTED = 'Connected'

# what the daemon prints -> our keys
FIELDS = {'Algorithm': 'algorithm', 'Echo reply': 'echo_reply', 'Last poll call': 'last_poll',
          'Model': 'model', 'QNetd host': 'qnetd_host', 'State': 'state', 'Tie-breaker': 'tie_breaker'}

_views = {}       # cid -> (epoch, view or None)
_places = {}      # cid -> (epoch, key, {host: node or None})
_seen = set()     # clusters where a QDevice answered since this process started
_locks = {}
_guard = threading.Lock()


def parse(data):
    """Our fields of one answer; {} for a node that runs no QDevice daemon."""
    if not isinstance(data, dict):
        return {}
    out = {}
    for theirs, ours in FIELDS.items():
        value = data.get(theirs)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        text = str(value).strip()
        if text:
            out[ours] = text[:TEXT_MAX]
    return out


def _err(e):
    """A short word for what went wrong; the text of the exception (addresses, pool
    internals) goes to the debug log, not to the route's answer."""
    log.debug(f"[qdevice] read failed: {type(e).__name__}: {e}")
    name = type(e).__name__
    return {'ConnectTimeout': 'connect timed out', 'ReadTimeout': 'timed out', 'Timeout': 'timed out',
            'SSLError': 'TLS error', 'ConnectionError': 'connection failed'}.get(name, name)


def _get(mgr, host, path):
    """(status, data, error) of a GET at `host`; None is the API host. That one goes
    through _api_get like every other read of the cluster. Any other address takes the
    cluster's session as it is, so one that is down counts nowhere against the
    cluster's connection, and a 401 there resets no ticket."""
    try:
        if host is None:
            r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json{path}", timeout=HOST_TIMEOUT)
        else:
            url = f"https://{mgr._bracket_ipv6(str(host).strip('[]'))}:{mgr.api_port}/api2/json{path}"
            r = mgr._create_session().get(url, timeout=HOST_TIMEOUT)
    except Exception as e:
        return 0, None, _err(e)
    if r.status_code != 200:
        return r.status_code, None, f"HTTP {r.status_code}"
    try:
        body = r.json()
    except ValueError:
        return 0, None, 'the answer is no JSON'
    return 200, (body or {}).get('data') if isinstance(body, dict) else None, None


def _status_nodes(mgr, host=None):
    """The node entries of /cluster/status as `host` (None: the API host) has them."""
    status, data, _e = _get(mgr, host, '/cluster/status')
    if status != 200 or not isinstance(data, list):
        return None
    return [e for e in data if isinstance(e, dict) and e.get('type') == 'node' and e.get('name')]


def _place(cid, mgr, nodes, now):
    """{host: node or None} for the registered and fallback hosts of the cluster."""
    hosts = [mgr.config.host] + list(getattr(mgr.config, 'fallback_hosts', None) or [])
    hosts = [h for h in dict.fromkeys(hosts) if isinstance(h, str) and h]
    key = (tuple(hosts), tuple(sorted((n['name'], str(n.get('ip') or '')) for n in nodes)))
    hit = _places.get(cid)
    if hit and hit[1] == key and 0 <= now - hit[0] < PLACE_EVERY:
        return hit[2]
    placed = dict(conncheck._host_nodes(mgr, nodes))
    names = {n['name'] for n in nodes}
    # a management address next to the corosync one: the node behind it names itself
    rest = [h for h in hosts if h not in placed]
    said = run_per_node({h: (lambda host: _status_nodes(mgr, host)) for h in rest},
                        max_concurrent=FANOUT, timeout=_budget(len(rest))) if rest else {}
    for h in rest:
        local = next((e['name'] for e in said.get(h) or () if e.get('local')), None)
        placed[h] = local if local in names else None
    _places[cid] = (now, key, placed)
    return placed


def _budget(count):
    return min(60, max(1, math.ceil(count / FANOUT)) * (2 * HOST_TIMEOUT + 2))


def read(cid, mgr, now=None):
    """Ask every node that can be asked. Returns the view, or None when the API host did
    not give its node list:

      present      some node answered with a QDevice
      answered_by  the node whose answer the fields below are (the API host's when it has one)
      state, qnetd_host, model, algorithm, tie_breaker, last_poll, echo_reply
      nodes        per node of the cluster: online, api_host, asked, answered, present,
                   connected, the daemon's fields, error
      removed      every node asked (two at least) answered and none runs a daemon
      seen         a QDevice answered in this cluster since this process started
      read_at, at
    """
    now = time.time() if now is None else now
    nodes = _status_nodes(mgr)
    if nodes is None:
        return None
    by_name = {n['name']: n for n in nodes}
    placed = _place(cid, mgr, nodes, now)
    api_node = next((n['name'] for n in nodes if n.get('local')), None)
    if api_node is None:
        api_node = placed.get(getattr(mgr, 'current_host', None) or mgr.config.host)

    ask = {}
    if api_node in by_name:
        ask[api_node] = None
    for host, name in placed.items():
        if name and name not in ask and by_name[name].get('online'):
            ask[name] = host
    got = run_per_node({name: (lambda _n, h=host: _get(mgr, h, '/cluster/config/qdevice'))
                        for name, host in ask.items()},
                       max_concurrent=FANOUT, timeout=_budget(len(ask))) if ask else {}

    rows = []
    for name in sorted(by_name):
        row = {'node': name, 'online': bool(by_name[name].get('online')), 'api_host': name == api_node,
               'asked': name in ask, 'answered': False, 'present': None, 'connected': None,
               'state': None, 'last_poll': None, 'echo_reply': None, 'error': None}
        if name in ask:
            res = got.get(name)
            if res is None:
                row['error'] = 'no answer in time'
            elif res[2]:
                row['error'] = res[2]
            else:
                fields = parse(res[1])
                row.update(fields)
                row.update(answered=True, present=bool(fields),
                           connected=fields.get('state') == CONNECTED)
        rows.append(row)

    with_q = [r for r in rows if r['present']]
    asked = [r for r in rows if r['asked']]
    removed = not with_q and len(asked) >= 2 and all(r['answered'] for r in asked)
    if with_q:
        _seen.add(cid)
    elif removed:
        _seen.discard(cid)
    src = next((r for r in with_q if r['api_host']), with_q[0] if with_q else None)
    view = {'present': bool(with_q), 'answered_by': src['node'] if src else None, 'api_node': api_node,
            'nodes': rows, 'removed': removed, 'seen': cid in _seen, 'at': now,
            'read_at': datetime.fromtimestamp(now, timezone.utc).isoformat(timespec='seconds')}
    for ours in FIELDS.values():
        view[ours] = src.get(ours) if src else None
    return view


def _lock(cid):
    with _guard:
        lk = _locks.get(cid)
        if lk is None:
            lk = _locks[cid] = threading.Lock()
        return lk


def view(cid, mgr, max_age=FRESH, now=None):
    """The view of a cluster no older than max_age, read now when there is none. Callers
    that ask at the same time wait for the one read. A read that failed is kept as long,
    so a cluster that does not answer is not asked on every request."""
    with _lock(cid):
        at = time.time() if now is None else now
        hit = _views.get(cid)
        if hit is not None and 0 <= at - hit[0] < max_age:
            return hit[1]
        try:
            v = read(cid, mgr, now=at)
        except Exception as e:
            log.debug(f"[qdevice] {cid}: read failed: {e}")
            v = None
        _views[cid] = (at, v)
        return v


def cached(cid, now=None):
    """The last view of a cluster while it is younger than SERVE_MAX, else None. Never reads."""
    hit = _views.get(cid)
    now = time.time() if now is None else now
    if hit is None or hit[1] is None or not 0 <= now - hit[0] < SERVE_MAX:
        return None
    return hit[1]


def public(v):
    """What the route hands out: present false and nothing else without a QDevice."""
    if not v or not v.get('present'):
        return {'present': False}
    out = {k: v.get(k) for k in ('present', 'answered_by', *FIELDS.values(), 'read_at')}
    out['nodes'] = [dict(r) for r in v.get('nodes') or ()]
    return out
