# -*- coding: utf-8 -*-
"""Connection check for one Proxmox VE cluster - MK Oct 2026

Runs when an admin asks for it and never on a timer. Everything here reads: the API
addresses (reachability, timing, the certificate on the wire), which credential the
cluster uses and what it may do, the PVE version and clock of every node, quorum, and
SSH. SSH goes through ssh_diagnose first, and only a node it has no objection to gets
one login attempt (#941: no credential, no attempt - a refused login counts against
fail2ban on hardened nodes).

The answer is a list of items {id, kind, status, hint, ...}; status is ok, warn, fail
or skip, hint a code the UI turns into the fix text in the user's language. Free text
(error messages, versions) travels in detail and is shown as it is.
"""

import logging
import math
import ssl
import time
from datetime import datetime, timezone

import requests

from pegaprox.utils.concurrent import run_per_node

log = logging.getLogger(__name__)

HOST_TIMEOUT = 5          # per API address, TLS handshake and the HTTP call each
SSH_TIMEOUT = 10          # connect + banner of the one SSH probe per node
FANOUT = 8                # parallel probes, per check
SLOW_MS = 2000
CLOCK_WARN_S = 3          # /nodes/<n>/time answers whole seconds
CLOCK_FAIL_S = 60

# What PegaProx asks PVE for and which features stop working without it. One entry
# per privilege set: any of `privs` on `path` (or propagated from above) is enough.
# VM.Monitor is the PVE 8 name of the guest agent read, VM.GuestAgent.Audit the PVE 9 one.
PRIVILEGE_NEEDS = (
    (('Sys.Audit',), '/', ('monitoring',)),
    (('VM.Audit',), '/vms', ('guests',)),
    (('VM.PowerMgmt',), '/vms', ('power',)),
    (('VM.Migrate',), '/vms', ('migration',)),
    (('VM.Console',), '/vms', ('consoles',)),
    (('VM.Snapshot',), '/vms', ('snapshots',)),
    (('VM.Backup',), '/vms', ('backups',)),
    (('VM.Allocate',), '/vms', ('create',)),
    (('VM.Clone',), '/vms', ('clone',)),
    (('VM.Config.CPU',), '/vms', ('hardware',)),
    (('VM.Config.Memory',), '/vms', ('hardware',)),
    (('VM.Config.Disk',), '/vms', ('hardware',)),
    (('VM.Config.Network',), '/vms', ('hardware',)),
    (('VM.Config.Options',), '/vms', ('hardware',)),
    (('VM.GuestAgent.Audit', 'VM.Monitor'), '/vms', ('agent',)),
    (('Datastore.Audit',), '/storage', ('storage',)),
    (('Datastore.AllocateSpace',), '/storage', ('disks',)),
    (('Datastore.AllocateTemplate',), '/storage', ('uploads',)),
    (('Sys.PowerMgmt',), '/nodes', ('nodePower',)),
    (('Sys.Modify',), '/', ('nodeConfig',)),
    (('Sys.Syslog',), '/', ('syslog',)),
    (('SDN.Audit',), '/sdn', ('sdn',)),
)


def _budget(count, per_probe):
    # run_per_node's timeout covers the whole fan-out, not one probe
    return min(300, max(1, math.ceil(count / FANOUT)) * per_probe)


def _item(kind, status, item_id=None, hint=None, **extra):
    out = {'id': item_id or kind, 'kind': kind, 'status': status, 'hint': hint}
    out.update(extra)
    return out


def _err_text(e):
    text = str(e) or type(e).__name__
    return text[:300]


def holds_privilege(perms, path, privs):
    """'yes', 'partial' or 'no' for any of `privs` on `path` in an /access/permissions answer.

    PVE lists the effective privileges for the standard paths ('/', '/vms', '/storage',
    '/nodes', '/sdn' ...) and every path with an ACL. 1 means the grant propagates, 0
    that it sits on that path only. A path missing from the answer inherits from the
    nearest listed parent, if that one propagates. 'partial': not on the path itself
    but on something below it, a pool or a single guest."""
    perms = perms if isinstance(perms, dict) else {}
    entry = perms.get(path)
    if isinstance(entry, dict):
        if any(p in entry for p in privs):
            return 'yes'
    else:
        parent = path
        while parent != '/':
            parent = parent.rsplit('/', 1)[0] or '/'
            up = perms.get(parent)
            if isinstance(up, dict):
                if any(up.get(p) == 1 for p in privs):
                    return 'yes'
                break
    below = path.rstrip('/') + '/'
    for other, granted in perms.items():
        if other.startswith(below) and isinstance(granted, dict) and any(p in granted for p in privs):
            return 'partial'
    return 'no'


def missing_privileges(perms):
    """[{privs, path, features, partial}] of PRIVILEGE_NEEDS the answer does not cover."""
    out = []
    for privs, path, features in PRIVILEGE_NEEDS:
        held = holds_privilege(perms, path, privs)
        if held != 'yes':
            out.append({'privs': list(privs), 'path': path, 'features': list(features),
                        'partial': held == 'partial'})
    return out


def credential_info(mgr):
    """Which credential the cluster is set up with and which one is in use now.

    api_token: the operator entered a token id (user@realm!id) and its secret.
    minted_token: username and password, and PegaProx created its own token on the first
    login (#110); the password stays for SSH and the console tickets.
    password: username and password, PVE tickets."""
    cfg = mgr.config
    user = getattr(cfg, 'user', '') or ''
    if '!' in user:
        kind, token_id = 'api_token', user
    elif getattr(cfg, 'api_token_user', '') and getattr(cfg, 'api_token_secret', ''):
        kind, token_id = 'minted_token', cfg.api_token_user
    else:
        kind, token_id = 'password', ''
    if getattr(mgr, '_api_token', None) and getattr(mgr, '_using_api_token', False):
        active = 'token'
    elif getattr(mgr, '_ticket', None):
        active = 'ticket'
    else:
        active = None
    return {'type': kind, 'user': user.split('!')[0], 'token_id': token_id, 'active': active,
            'has_password': kind != 'api_token' and bool(getattr(cfg, 'pass_', ''))}


def check_credentials(mgr):
    info = credential_info(mgr)
    if not mgr.is_connected:
        blocked, remaining = mgr._is_auth_blocked()
        if getattr(mgr, 'connection_error_code', None) == 'NEEDS_2FA':
            return _item('credentials', 'fail', hint='cred_needs_2fa', **info)
        if blocked:
            return _item('credentials', 'fail', hint='cred_auth_backoff', retry_in=remaining, **info)
        return _item('credentials', 'fail', hint='cred_not_connected',
                     detail=(mgr.connection_error or '')[:300], **info)
    if info['type'] == 'minted_token' and info['active'] == 'ticket':
        # the stored token answered 401/403 and connect() fell back to the password
        return _item('credentials', 'warn', hint='cred_token_rejected', **info)
    note = {'api_token': 'cred_token_note', 'password': 'cred_password_note'}.get(info['type'])
    return _item('credentials', 'ok', hint=note, **info)


def _get(mgr, endpoint, timeout=None):
    url = f"https://{mgr.host}:{mgr.api_port}/api2/json{endpoint}"
    kw = {'timeout': timeout} if timeout else {}
    return mgr._api_get(url, **kw)


def check_privileges(mgr):
    try:
        r = _get(mgr, '/access/permissions')
    except Exception as e:
        return _item('privileges', 'fail', hint='priv_unreadable', detail=_err_text(e))
    if r.status_code != 200:
        return _item('privileges', 'fail', hint='priv_unreadable', detail=f"HTTP {r.status_code}")
    try:
        perms = r.json().get('data') or {}
    except ValueError:
        perms = {}
    missing = missing_privileges(perms)
    status = 'warn' if missing else 'ok'
    return _item('privileges', status, hint='priv_missing' if missing else None,
                 missing=missing, checked=len(PRIVILEGE_NEEDS))


def _cluster_status(mgr):
    """(cluster entry or None, [node entries]) from /cluster/status, or raises."""
    r = _get(mgr, '/cluster/status')
    if r.status_code != 200:
        raise RuntimeError(f"/cluster/status answered HTTP {r.status_code}")
    rows = r.json().get('data') or []
    cluster = next((x for x in rows if x.get('type') == 'cluster'), None)
    nodes = [x for x in rows if x.get('type') == 'node' and x.get('name')]
    return cluster, nodes


def check_quorum(cluster, nodes):
    offline = sorted(n['name'] for n in nodes if not n.get('online'))
    data = {'nodes_total': len(nodes), 'nodes_online': len(nodes) - len(offline), 'offline': offline}
    if cluster is None:
        # a single node without a cluster: nothing to vote
        return _item('quorum', 'ok', hint='quorum_standalone', quorate=True, standalone=True, **data)
    quorate = bool(cluster.get('quorate'))
    if not quorate:
        return _item('quorum', 'fail', hint='quorum_lost', quorate=False, standalone=False, **data)
    if offline:
        return _item('quorum', 'warn', hint='quorum_offline', quorate=True, standalone=False, **data)
    return _item('quorum', 'ok', quorate=True, standalone=False, **data)


def _node_facts(mgr, node):
    """version, clock skew and the node's own certificate fingerprints, one node."""
    out = {'version': None, 'release': None, 'skew': None, 'fingerprints': [], 'error': None}
    try:
        r = _get(mgr, f'/nodes/{node}/version', timeout=mgr.per_node_timeout)
        if r.status_code == 200:
            d = r.json().get('data') or {}
            out['version'] = d.get('version')
            out['release'] = d.get('release')
        else:
            out['error'] = f"version: HTTP {r.status_code}"
    except Exception as e:
        out['error'] = f"version: {_err_text(e)}"
    try:
        t0 = time.time()
        r = _get(mgr, f'/nodes/{node}/time', timeout=mgr.per_node_timeout)
        t1 = time.time()
        if r.status_code == 200:
            node_time = (r.json().get('data') or {}).get('time')
            if isinstance(node_time, (int, float)):
                out['skew'] = round(float(node_time) - (t0 + t1) / 2, 1)
    except Exception as e:
        out['error'] = out['error'] or f"time: {_err_text(e)}"
    try:
        r = _get(mgr, f'/nodes/{node}/certificates/info', timeout=mgr.per_node_timeout)
        if r.status_code == 200:
            # pveproxy serves pveproxy-ssl.pem when there is one, pve-ssl.pem else
            out['fingerprints'] = [str(c.get('fingerprint') or '').upper()
                                   for c in (r.json().get('data') or [])
                                   if c.get('filename') in ('pve-ssl.pem', 'pveproxy-ssl.pem')
                                   and c.get('fingerprint')]
    except Exception:
        pass
    return out


def check_versions(facts):
    versions = {n: f['version'] for n, f in facts.items() if f and f.get('version')}
    unknown = sorted(n for n, f in facts.items() if not f or not f.get('version'))
    if not versions:
        return _item('versions', 'skip', hint='ver_unknown', nodes={}, unknown=unknown)
    releases = set()
    old = []
    for n, v in versions.items():
        parts = str(v).split('.')
        releases.add('.'.join(parts[:2]))
        try:
            if int(parts[0]) < 8:
                old.append(n)
        except ValueError:
            pass
    if old:
        return _item('versions', 'warn', hint='ver_old', nodes=versions, unknown=unknown, old=sorted(old))
    if len(releases) > 1:
        return _item('versions', 'warn', hint='ver_mixed', nodes=versions, unknown=unknown)
    return _item('versions', 'ok', nodes=versions, unknown=unknown)


def check_clock(facts):
    skews = {n: f['skew'] for n, f in facts.items() if f and f.get('skew') is not None}
    if not skews:
        return _item('clock', 'skip', hint='clock_unknown', nodes={})
    worst = max(abs(v) for v in skews.values())
    status = 'fail' if worst > CLOCK_FAIL_S else 'warn' if worst > CLOCK_WARN_S else 'ok'
    return _item('clock', status, hint='clock_skew' if status != 'ok' else None,
                 nodes=skews, max_skew=worst)


def _host_nodes(mgr, nodes):
    """{host string -> node name} for the API addresses we can place on a node."""
    by_ip = {str(n.get('ip') or ''): n['name'] for n in nodes if n.get('ip')}
    names = {n['name'] for n in nodes}
    hosts = [mgr.config.host] + list(mgr.config.fallback_hosts or [])
    out = {}
    for h in hosts:
        bare = (h or '').strip('[]')
        if bare in by_ip:
            out[h] = by_ip[bare]
            continue
        short = bare.split('.')[0]
        if bare in names or (short in names and not bare.replace('.', '').isdigit()):
            out[h] = bare if bare in names else short
            continue
        resolved = mgr._resolve_host(bare)
        if resolved in by_ip:
            out[h] = by_ip[resolved]
    return out


def probe_host(mgr, host, authed, node_fps=None):
    """One API address: TLS handshake (time, fingerprint), then GET /version.

    `authed`: send the cluster's session along. Only while the cluster is connected -
    the credentials are known good then, so this cannot add a failed login anywhere.
    Not connected, the call goes without credentials and a 401 still proves pveproxy
    answers."""
    port = mgr.api_port
    res = {'host': host, 'role': 'primary' if host == mgr.config.host else 'fallback',
           'ms': None, 'fingerprint': None, 'tls': 'unknown', 'http': None}
    t0 = time.monotonic()
    try:
        res['fingerprint'] = mgr.tls_fingerprint(host, port, timeout=HOST_TIMEOUT)
    except Exception as e:
        res['ms'] = int((time.monotonic() - t0) * 1000)
        return _item('api_host', 'fail', item_id=f'api:{host}', hint='api_unreachable',
                     detail=_err_text(e), **res)
    if node_fps:
        res['tls'] = 'match' if res['fingerprint'] in node_fps else 'mismatch'

    sess = mgr._create_session() if authed else requests.Session()
    url = f"https://{mgr._bracket_ipv6(host.strip('[]'))}:{port}/api2/json/version"
    try:
        if authed:
            r = sess.get(url, timeout=HOST_TIMEOUT)
        else:
            # what connect() would verify against, without its credentials
            sess.trust_env = False
            verify = False
            if mgr.config.ssl_verification:
                _ca = ssl.get_default_verify_paths()
                verify = _ca.cafile or _ca.openssl_cafile or True
            r = sess.get(url, timeout=HOST_TIMEOUT, verify=verify)
        res['http'] = r.status_code
    except requests.exceptions.SSLError as e:
        res['ms'] = int((time.monotonic() - t0) * 1000)
        return _item('api_host', 'fail', item_id=f'api:{host}', hint='api_tls_untrusted',
                     detail=_err_text(e), **res)
    except Exception as e:
        res['ms'] = int((time.monotonic() - t0) * 1000)
        return _item('api_host', 'fail', item_id=f'api:{host}', hint='api_unreachable',
                     detail=_err_text(e), **res)
    finally:
        if not authed:
            sess.close()
    res['ms'] = int((time.monotonic() - t0) * 1000)

    if authed and r.status_code == 401:
        return _item('api_host', 'fail', item_id=f'api:{host}', hint='api_auth', **res)
    if r.status_code not in (200, 401):
        return _item('api_host', 'warn', item_id=f'api:{host}', hint='api_http',
                     detail=f"HTTP {r.status_code}", **res)
    if res['tls'] == 'mismatch':
        return _item('api_host', 'warn', item_id=f'api:{host}', hint='api_tls_mismatch', **res)
    if res['ms'] > SLOW_MS:
        return _item('api_host', 'warn', item_id=f'api:{host}', hint='api_slow', **res)
    return _item('api_host', 'ok', item_id=f'api:{host}', **res)


def _ssh_user(mgr):
    # what _ssh_connect logs in as
    cfg = mgr.config
    return cfg.ssh_user if getattr(cfg, 'ssh_user', '') else (cfg.user or 'root').split('@')[0]


def _credential_at(mgr, ip):
    """Which login the node at `ip` gets: 'key', its own password ('node', #1136) or the
    cluster's ('cluster'). The key goes first, so with one stored the answer is the key."""
    if getattr(mgr.config, 'ssh_key', ''):
        return 'key'
    own = getattr(mgr, '_own_password_at', None)
    if callable(own):
        try:
            if own(ip):
                return 'node'
        except Exception:
            pass
    return 'cluster'


def probe_ssh(mgr, node):
    """One login attempt at most, and only where ssh_diagnose has nothing against it."""
    method = 'key' if getattr(mgr.config, 'ssh_key', '') else 'password'
    base = {'node': node, 'user': _ssh_user(mgr), 'method': method}
    iid = f'ssh:{node}'
    diag = mgr.ssh_diagnose(node)
    if diag:
        code, detail = diag
        hint = {'NODE_BACKOFF': 'ssh_backoff', 'SSH_DISABLED': 'ssh_disabled',
                'SSH_NO_CREDENTIALS': 'ssh_no_credentials'}.get(code, 'ssh_error')
        return _item('ssh', 'skip' if code == 'SSH_DISABLED' else 'warn', item_id=iid, hint=hint,
                     code=code, detail=detail, **base)
    ip = mgr._get_node_ip(node)
    if not ip:
        return _item('ssh', 'fail', item_id=iid, hint='ssh_no_ip', code='NO_IP', **base)
    base['ip'] = ip
    base['credential'] = _credential_at(mgr, ip)
    failure = {}
    client = mgr._ssh_connect(ip, retries=1, connect_timeout=SSH_TIMEOUT, failure=failure)
    if client is None:
        kind = failure.get('kind') or 'error'
        code = {'auth': 'AUTH_REFUSED', 'host_key': 'HOST_KEY', 'unreachable': 'UNREACHABLE',
                'key': 'KEY_UNUSABLE', 'blocked': failure.get('detail') or 'SSH_DISABLED'}.get(kind, 'ERROR')
        hint = {'AUTH_REFUSED': 'ssh_auth_refused', 'HOST_KEY': 'ssh_host_key',
                'UNREACHABLE': 'ssh_unreachable', 'KEY_UNUSABLE': 'ssh_key_unusable'}.get(code, 'ssh_error')
        return _item('ssh', 'fail', item_id=iid, hint=hint, code=code,
                     detail=failure.get('detail') or '', **base)
    try:
        if base['user'] != 'root':
            # the node checks run as root through sudo; a login that cannot sudo reads nothing
            try:
                _in, out, _err = client.exec_command('sudo -n true', timeout=SSH_TIMEOUT)
                if out.channel.recv_exit_status() != 0:
                    return _item('ssh', 'warn', item_id=iid, hint='ssh_sudo', code='SUDO_REFUSED', **base)
            except Exception as e:
                return _item('ssh', 'warn', item_id=iid, hint='ssh_sudo', code='SUDO_REFUSED',
                             detail=_err_text(e), **base)
        return _item('ssh', 'ok', item_id=iid, code='OK', **base)
    finally:
        try:
            client.close()
        except Exception:
            pass


def check_ssh(mgr, nodes):
    """Per online node, except when SSH is off or has no credential for the whole
    cluster: then one item says so and no node is contacted. Each node is tried with
    what it would get anywhere else, its own password where it has one (#1136)."""
    blocked = mgr.ssh_blocked_reason()
    if blocked:
        diag = mgr.ssh_diagnose(nodes[0]['name']) if nodes else None
        detail = diag[1] if diag and diag[0] == blocked else ''
        hint = 'ssh_disabled' if blocked == 'SSH_DISABLED' else 'ssh_no_credentials'
        return [_item('ssh', 'skip' if blocked == 'SSH_DISABLED' else 'warn', item_id='ssh',
                      hint=hint, code=blocked, detail=detail)]
    items = []
    online = []
    for n in nodes:
        if n.get('online'):
            online.append(n['name'])
        else:
            items.append(_item('ssh', 'skip', item_id=f"ssh:{n['name']}", hint='ssh_node_offline',
                               code='NODE_OFFLINE', node=n['name']))
    results = run_per_node({name: (lambda nm: probe_ssh(mgr, nm)) for name in online},
                           max_concurrent=FANOUT, timeout=_budget(len(online), SSH_TIMEOUT * 3))
    for name in online:
        items.append(results.get(name) or _item('ssh', 'fail', item_id=f'ssh:{name}', hint='ssh_error',
                                                 code='TIMEOUT', node=name))
    return items


def run_check(mgr, include_ssh=True):
    """The whole check for one PegaProxManager. Returns the report dict."""
    started = time.monotonic()
    items = [check_credentials(mgr)]
    connected = bool(mgr.is_connected)

    cluster, nodes, status_error = None, [], None
    if connected:
        try:
            cluster, nodes = _cluster_status(mgr)
        except Exception as e:
            status_error = _err_text(e)

    online = [n['name'] for n in nodes if n.get('online')]
    facts = run_per_node({name: (lambda nm: _node_facts(mgr, nm)) for name in online},
                         max_concurrent=FANOUT,
                         timeout=_budget(len(online), mgr.per_node_timeout * 3 + 2)) if online else {}

    host_node = _host_nodes(mgr, nodes) if nodes else {}
    hosts = []
    for h in [mgr.config.host] + list(mgr.config.fallback_hosts or []):
        if h and h not in hosts:
            hosts.append(h)

    def _host(h):
        fps = (facts.get(host_node.get(h)) or {}).get('fingerprints') if h in host_node else None
        item = probe_host(mgr, h, connected, fps)
        if h in host_node:
            item['node'] = host_node[h]
        return item
    host_results = run_per_node({h: _host for h in hosts}, max_concurrent=FANOUT,
                                timeout=_budget(len(hosts), HOST_TIMEOUT * 2 + 2))
    for h in hosts:
        items.append(host_results.get(h) or _item('api_host', 'fail', item_id=f'api:{h}',
                                                   hint='api_unreachable', host=h, detail='timed out'))
    if len(hosts) == 1 and len(nodes) > 1:
        items.append(_item('api_fallbacks', 'warn', hint='api_no_fallback', nodes_total=len(nodes)))

    if not connected or status_error:
        reason = 'needs_connection' if not connected else 'status_unreadable'
        for kind in ('privileges', 'versions', 'clock', 'quorum', 'ssh'):
            items.append(_item(kind, 'skip', hint=reason, detail=status_error or ''))
    else:
        items.append(check_privileges(mgr))
        items.append(check_versions({n: facts.get(n) for n in online}))
        items.append(check_clock({n: facts.get(n) for n in online}))
        items.append(check_quorum(cluster, nodes))
        if include_ssh:
            items.extend(check_ssh(mgr, nodes))

    summary = {'ok': 0, 'warn': 0, 'fail': 0, 'skip': 0}
    for it in items:
        summary[it['status']] = summary.get(it['status'], 0) + 1
    return {
        'cluster_type': 'proxmox',
        'connected': connected,
        'checked_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'duration_ms': int((time.monotonic() - started) * 1000),
        'summary': summary,
        'items': items,
    }
