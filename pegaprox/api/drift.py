# -*- coding: utf-8 -*-
"""
Config Drift Detection — NS May 2026.

Snapshots core cluster configuration on a schedule, compares against an
admin-set baseline, emits drift events when something changed.

Categories tracked:
  - vm_config       per-VM `qm config` (qemu) / `pct config` (lxc)
  - storage         /etc/pve/storage.cfg (via /api2/json/storage)
  - network         per-node /etc/network/interfaces (via /api2/json/nodes/<n>/network)
  - cluster_options /etc/pve/datacenter.cfg (via /api2/json/cluster/options)
  - firewall        cluster options/rules/aliases/ipsets/groups, node and guest rules
  - ha_rules        HA rules (PVE 9) or groups (PVE 8), and the HA resources
  - backup_jobs     /cluster/backup
  - access          users, groups, roles and ACL entries (never a secret, tokens by id)

Workflow:
  1. Admin clicks "Set baseline" — current state stored in drift_baselines.
  2. Background scanner (every 6h) and manual trigger compute current state,
     diff against baseline, write drift_events.
  3. UI shows open events with diff. Admin "Acknowledge" or "Promote diff
     to new baseline" (latter rebases so the change is no longer flagged).

Diff is a list of {path, op, before, after} entries. Keeps it explainable.

Drift events also fan out via the alerts notification handlers, so the same
Slack/Discord/ntfy/web-push channels users have configured for alerts also
get drift notifications without extra plumbing.
"""
import json
import os
import re
import time
import hashlib
import uuid
import logging
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access, require_unconfined
from pegaprox.core.db import get_db
from pegaprox.core import dbcrypto, ha, changes
from pegaprox.background import guest_index
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('drift', __name__)


# ──────────────────────────────────────────────────────────────────────────
# Snapshot fetchers — return (kind, scope, dict) tuples
# scope is a sub-identifier (e.g. vmid for vm_config, node name for network)
# ──────────────────────────────────────────────────────────────────────────

# Keys whose change should NOT count as drift (volatile bookkeeping)
_VM_VOLATILE_KEYS = {'meta', 'lock', 'parent', 'snapshot', 'snapstate',
                     'lastsnapshot', 'pending', 'running-machine', 'running-qemu',
                     'digest'}
_NETWORK_VOLATILE = {'active'}

# NS: PVE returns these comma-separated lists in non-deterministic order (e.g.
# `content` on storages, `tags` on VMs). Without sorting them we'd flood the
# admin with bogus drift events. Sort once at fetch time, the diff becomes
# stable.
_CSV_NORMALIZE_KEYS = {'content', 'tags', 'nodes'}

# NS Sep 2026 (Aikido 469089254) — raising the read gate to admin.audit stopped a plain cluster
# viewer reading these, but the value was still being written to the baseline and the event diff
# in the clear, where it outlives the VM and lands in every DB backup. Nothing about drift needs
# the value itself — only whether it CHANGED — so store a digest instead. Diffs stay accurate
# (a new password produces a new digest) and there is no secret left to leak. Storage state runs
# through the same helper, which also covers a CIFS password and a Ceph keyring.
_SECRET_KEYS = {'cipassword', 'password', 'smbpassword', 'keyring', 'encryption-key'}


def _redact_secret(value):
    """Stable stand-in for a secret: same value in, same marker out, so a change is still a
    change. Existing baselines hold the old cleartext, so the first scan after an upgrade
    reports one drift event per affected VM — acknowledge and it settles."""
    if value in (None, ''):
        return value
    digest = hashlib.sha256(str(value).encode('utf-8', 'replace')).hexdigest()
    return f"<redacted:{digest[:16]}>"


# MK Oct 2026 - comma lists of the new kinds that come back in no fixed order
_CSV_NORMALIZE_NEW = _CSV_NORMALIZE_KEYS | {'groups', 'users', 'privs', 'resources', 'vmid'}


def _strip_volatile(d, volatile_keys, csv_keys=_CSV_NORMALIZE_KEYS):
    if not isinstance(d, dict): return d
    out = {}
    for k, v in d.items():
        if k in volatile_keys: continue
        if k in _SECRET_KEYS:
            out[k] = _redact_secret(v)
            continue
        if k in csv_keys and isinstance(v, str) and ',' in v:
            parts = [p.strip() for p in v.split(',') if p.strip()]
            v = ','.join(sorted(parts))
        out[k] = v
    return out


class _State(list):
    """The (kind, scope, snapshot) tuples _fetch_state read, and what it could not read.

    A read that failed is not an empty answer. Both came back as "nothing there", so a
    guest list that timed out at 10k guests turned every guest baseline into a removal,
    and a storage read answering 500 did the same to every storage. MK Oct 2026
    """
    def __init__(self):
        super().__init__()
        self.unread_kinds = set()    # the read of the whole kind failed
        self.unread_scopes = set()   # (kind, scope): listed, but its own read failed
        self.unread_nodes = set()    # nodes whose network read failed
        self.unread_prefixes = set() # (kind, prefix): a list that names the scopes did not answer
        self.read_kinds = set()      # kinds whose main read answered, even with nothing in it


def _not_read(state, kind, scope):
    """True when this fetch never saw the scope, so its absence says nothing.
    A plain list (no record of failures) reads as everything answered."""
    if kind in getattr(state, 'unread_kinds', ()):
        return True
    if (kind, scope) in getattr(state, 'unread_scopes', ()):
        return True
    if any(kind == k and scope.startswith(p) for k, p in getattr(state, 'unread_prefixes', ())):
        return True
    return kind == 'network' and scope.split('/', 1)[0] in getattr(state, 'unread_nodes', ())


def _fetch_state(mgr, cluster_id):
    """Return list of (kind, scope, snapshot_dict). Robust to per-call fails;
    a single dead node shouldn't poison the whole snapshot. The list also
    records what did not answer (see _State)."""
    out = _State()
    host, port = mgr.host, mgr.api_port

    # cluster options
    try:
        r = mgr._api_get(f"https://{host}:{port}/api2/json/cluster/options")
        if r is not None and getattr(r, 'status_code', 0) == 200:
            data = r.json().get('data') or {}
            out.append(('cluster_options', 'global', data))
            out.read_kinds.add('cluster_options')
        else:
            out.unread_kinds.add('cluster_options')
    except Exception as e:
        out.unread_kinds.add('cluster_options')
        logging.debug(f"[drift] cluster/options fetch failed: {e}")

    # storage configs (cluster-wide)
    try:
        r = mgr._api_get(f"https://{host}:{port}/api2/json/storage")
        if r is not None and getattr(r, 'status_code', 0) == 200:
            for s in (r.json().get('data') or []):
                sid = s.get('storage')
                if not sid: continue
                # _strip_volatile sorts comma-list fields like `content`, `nodes`
                # which Proxmox returns in non-deterministic order
                out.append(('storage', sid, _strip_volatile(s, set())))
            out.read_kinds.add('storage')
        else:
            out.unread_kinds.add('storage')
    except Exception as e:
        out.unread_kinds.add('storage')
        logging.debug(f"[drift] storage fetch failed: {e}")

    # per-node network state
    try:
        nodes = list((mgr.nodes or {}).keys())
    except Exception:
        nodes = []
    if not nodes:
        # a cluster has at least one node: no node list is a failed read
        out.unread_kinds.add('network')
    else:
        out.read_kinds.add('network')
    for node in nodes:
        try:
            r = mgr._api_get(f"https://{host}:{port}/api2/json/nodes/{node}/network")
            if r is None or getattr(r, 'status_code', 0) != 200:
                out.unread_nodes.add(node)
                continue
            for nic in (r.json().get('data') or []):
                iface = nic.get('iface')
                if not iface: continue
                clean = _strip_volatile(nic, _NETWORK_VOLATILE)
                out.append(('network', f"{node}/{iface}", clean))
        except Exception as e:
            out.unread_nodes.add(node)
            logging.debug(f"[drift] network/{node} fetch failed: {e}")

    # per-VM/CT configs
    fw_guests = []   # guests with the firewall on a NIC: their rules are read below
    try:
        guests = mgr.get_vm_resources()
        if getattr(guests, 'unavailable', False):
            # the guest list itself did not answer (UnreadList), not an empty cluster
            out.unread_kinds.add('vm_config')
            out.unread_prefixes.add(('firewall', 'guest/'))
            guests = []
        else:
            out.read_kinds.add('vm_config')
        for r in (guests or []):
            t = r.get('type')
            vmid = r.get('vmid')
            node = r.get('node')
            if t not in ('qemu', 'lxc') or not vmid or not node:
                continue
            url = f"https://{host}:{port}/api2/json/nodes/{node}/{t}/{vmid}/config"
            try:
                resp = mgr._api_get(url)
                if resp is None or getattr(resp, 'status_code', 0) != 200:
                    out.unread_scopes.add(('vm_config', f"{t}/{vmid}"))
                    out.unread_scopes.add(('firewall', f"guest/{t}/{vmid}"))
                    continue
                cfg = resp.json().get('data') or {}
                # the search index takes the same read (MAC, notes, configured IPs)
                guest_index.ingest(cluster_id, t, vmid, cfg)
                clean = _strip_volatile(cfg, _VM_VOLATILE_KEYS)
                out.append(('vm_config', f"{t}/{vmid}", clean))
                if _guest_firewall_on(cfg):
                    fw_guests.append((t, vmid, node))
            except Exception:
                out.unread_scopes.add(('vm_config', f"{t}/{vmid}"))
                out.unread_scopes.add(('firewall', f"guest/{t}/{vmid}"))
                continue
    except Exception as e:
        out.unread_kinds.add('vm_config')
        out.unread_prefixes.add(('firewall', 'guest/'))
        logging.debug(f"[drift] vm enumeration failed: {e}")

    # MK Oct 2026 - the kinds added later; each marks what it could not read the same way
    for fetch, kind in ((lambda: _fetch_firewall(mgr, out, nodes, fw_guests, cluster_id), 'firewall'),
                        (lambda: _fetch_ha(mgr, out), 'ha_rules'),
                        (lambda: _fetch_backup_jobs(mgr, out), 'backup_jobs'),
                        (lambda: _fetch_access(mgr, out), 'access')):
        try:
            fetch()
        except Exception as e:
            out.unread_kinds.add(kind)
            out.read_kinds.discard(kind)
            logging.debug(f"[drift] {kind} fetch failed: {e}")

    return out


# ──────────────────────────────────────────────────────────────────────────
# Firewall, HA rules, backup jobs, access - MK Oct 2026
# ──────────────────────────────────────────────────────────────────────────

# a snapshot of these is one dict per object (keyed by its id), so the diff names the
# object that was added, removed or changed
_FW_VOLATILE = {'digest'}
_BACKUP_VOLATILE = {'digest', 'next-run'}
_HA_VOLATILE = {'digest'}

# guest rules are read for guests with the firewall on a NIC only, and not all at once:
# at 10k guests that would be thousands of calls in one scan. A read is kept for a while
# and the oldest ones are refreshed first, so every scan moves the whole set along.
_FW_GUEST_TTL = 5 * 3600
_FW_GUEST_BUDGET = 300
_FW_GUEST_PAUSE = 0.02
_fw_guest_cache = {}   # (cluster_id, 'qemu/101') -> (read at, snapshot)
_fw_cache_lock = threading.Lock()

_NIC_FW_ON = re.compile(r'(^|,)firewall=1(,|$)')


def _guest_firewall_on(cfg):
    for k, v in (cfg or {}).items():
        if k.startswith('net') and k[3:].isdigit() and isinstance(v, str) and _NIC_FW_ON.search(v):
            return True
    return False


def _api_data(mgr, path):
    """(status, data) of one read under /api2/json; (0, None) when it raised."""
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json{path}")
        code = getattr(r, 'status_code', 0) if r is not None else 0
        if code == 200:
            return 200, r.json().get('data')
        return code, None
    except Exception as e:
        logging.debug(f"[drift] read {path} failed: {e}")
        return 0, None


def _keyed(rows, key_field, volatile, csv_keys=_CSV_NORMALIZE_NEW):
    """{id: cleaned row} for a PVE list; a row without its id field is skipped."""
    out = {}
    for row in rows or []:
        if isinstance(row, dict) and row.get(key_field) not in (None, ''):
            out[str(row[key_field])] = _strip_volatile(
                {k: v for k, v in row.items() if k != key_field}, volatile, csv_keys)
    return out


def _rules_snapshot(rows):
    """Firewall rules by position. A rule inserted in the middle moves those below it,
    which is a change of the list and reads as one."""
    out = {}
    for row in rows or []:
        if isinstance(row, dict):
            pos = row.get('pos', len(out))
            out[f"rule {int(pos):04d}" if str(pos).isdigit() else f"rule {pos}"] = _strip_volatile(
                {k: v for k, v in row.items() if k != 'pos'}, _FW_VOLATILE)
    return out


def _read_list(mgr, out, kind, scope, path):
    """The list at path, or None after noting the scope as unread."""
    code, data = _api_data(mgr, path)
    if code == 200 and isinstance(data, list):
        return data
    out.unread_scopes.add((kind, scope))
    return None


def _fetch_firewall(mgr, out, nodes, fw_guests, cluster_id):
    code, opts = _api_data(mgr, '/cluster/firewall/options')
    if code == 200 and isinstance(opts, dict):
        out.append(('firewall', 'cluster/options', _strip_volatile(opts, _FW_VOLATILE)))
        out.read_kinds.add('firewall')
    else:
        out.unread_scopes.add(('firewall', 'cluster/options'))
    rows = _read_list(mgr, out, 'firewall', 'cluster/rules', '/cluster/firewall/rules')
    if rows is not None:
        out.append(('firewall', 'cluster/rules', _rules_snapshot(rows)))
        out.read_kinds.add('firewall')
    rows = _read_list(mgr, out, 'firewall', 'cluster/aliases', '/cluster/firewall/aliases')
    if rows is not None:
        out.append(('firewall', 'cluster/aliases', _keyed(rows, 'name', _FW_VOLATILE)))
        out.read_kinds.add('firewall')

    sets = _read_list(mgr, out, 'firewall', 'cluster/ipset', '/cluster/firewall/ipset')
    if sets is None:
        out.unread_prefixes.add(('firewall', 'cluster/ipset/'))
    for row in sets or []:
        name = row.get('name') if isinstance(row, dict) else None
        if not name:
            continue
        scope = f"cluster/ipset/{name}"
        items = _read_list(mgr, out, 'firewall', scope, f"/cluster/firewall/ipset/{name}")
        if items is not None:
            snap = _keyed(items, 'cidr', _FW_VOLATILE)
            snap['@comment'] = row.get('comment', '')
            out.append(('firewall', scope, snap))
    groups = _read_list(mgr, out, 'firewall', 'cluster/group', '/cluster/firewall/groups')
    if groups is None:
        out.unread_prefixes.add(('firewall', 'cluster/group/'))
    for row in groups or []:
        name = row.get('group') if isinstance(row, dict) else None
        if not name:
            continue
        scope = f"cluster/group/{name}"
        items = _read_list(mgr, out, 'firewall', scope, f"/cluster/firewall/groups/{name}")
        if items is not None:
            out.append(('firewall', scope, _rules_snapshot(items)))

    for node in nodes:
        scope = f"node/{node}"
        rows = _read_list(mgr, out, 'firewall', scope, f"/nodes/{node}/firewall/rules")
        if rows is not None:
            out.append(('firewall', scope, _rules_snapshot(rows)))
    _fetch_guest_firewall(mgr, out, fw_guests, cluster_id)


def _fetch_guest_firewall(mgr, out, fw_guests, cluster_id):
    now = time.time()
    with _fw_cache_lock:
        have = {(t, vmid): _fw_guest_cache.get((cluster_id, f"{t}/{vmid}")) for t, vmid, _ in fw_guests}
    # never read first, then the oldest read
    order = sorted(fw_guests, key=lambda g: (have[(g[0], g[1])] or (0,))[0])
    budget = _FW_GUEST_BUDGET
    for t, vmid, node in order:
        scope = f"guest/{t}/{vmid}"
        hit = have[(t, vmid)]
        if hit and now - hit[0] < _FW_GUEST_TTL:
            out.append(('firewall', scope, hit[1]))
            continue
        if budget > 0:
            budget -= 1
            time.sleep(_FW_GUEST_PAUSE)
            code, rows = _api_data(mgr, f"/nodes/{node}/{t}/{vmid}/firewall/rules")
            if code == 200 and isinstance(rows, list):
                snap = _rules_snapshot(rows)
                with _fw_cache_lock:
                    _fw_guest_cache[(cluster_id, f"{t}/{vmid}")] = (now, snap)
                out.append(('firewall', scope, snap))
                continue
        # past the budget, or the read failed: an older read is still the better answer
        # than none, and with none the scope is unread (its baseline stays)
        if hit:
            out.append(('firewall', scope, hit[1]))
        else:
            out.unread_scopes.add(('firewall', scope))
    # forget guests that no longer have the firewall on
    live = {f"{t}/{vmid}" for t, vmid, _ in fw_guests}
    with _fw_cache_lock:
        for key in [k for k in _fw_guest_cache if k[0] == cluster_id and k[1] not in live]:
            _fw_guest_cache.pop(key, None)


def _fetch_ha(mgr, out):
    # PVE 9 has HA rules; PVE 8 has groups. The path that is not there answers 404 or 501,
    # which is "this version has no such thing", not a failed read.
    got = False
    code, rows = _api_data(mgr, '/cluster/ha/rules')
    if code == 200 and isinstance(rows, list):
        out.append(('ha_rules', 'rules', _keyed(rows, 'rule', _HA_VOLATILE)))
        got = True
    elif code in (404, 501):
        code, rows = _api_data(mgr, '/cluster/ha/groups')
        if code == 200 and isinstance(rows, list):
            out.append(('ha_rules', 'groups', _keyed(rows, 'group', _HA_VOLATILE)))
            got = True
        elif code not in (404, 501):
            out.unread_scopes.add(('ha_rules', 'groups'))
    else:
        out.unread_scopes.add(('ha_rules', 'rules'))
    code, rows = _api_data(mgr, '/cluster/ha/resources')
    if code == 200 and isinstance(rows, list):
        out.append(('ha_rules', 'resources', _keyed(rows, 'sid', _HA_VOLATILE)))
        got = True
    else:
        out.unread_scopes.add(('ha_rules', 'resources'))
    if got:
        out.read_kinds.add('ha_rules')
    else:
        out.unread_kinds.add('ha_rules')


def _fetch_backup_jobs(mgr, out):
    code, rows = _api_data(mgr, '/cluster/backup')
    if code != 200 or not isinstance(rows, list):
        out.unread_kinds.add('backup_jobs')
        return
    for job_id, snap in _keyed(rows, 'id', _BACKUP_VOLATILE).items():
        out.append(('backup_jobs', job_id, snap))
    out.read_kinds.add('backup_jobs')


def _fetch_access(mgr, out):
    """Users, groups, roles and ACL entries. Only fields that name who may do what are
    kept (no e-mail, name, comment, password or second-factor key), a token only as its
    id and expiry: a snapshot never holds a secret."""
    code, rows = _api_data(mgr, '/access/users?full=1')
    if code == 200 and isinstance(rows, list):
        users = {}
        for u in rows:
            if not isinstance(u, dict) or not u.get('userid'):
                continue
            snap = _strip_volatile({k: u.get(k) for k in ('enable', 'expire', 'groups') if k in u},
                                   set(), _CSV_NORMALIZE_NEW)
            for tok in (u.get('tokens') or []):
                if isinstance(tok, dict) and tok.get('tokenid'):
                    snap[f"token:{tok['tokenid']}"] = tok.get('expire', 0)
            users[u['userid']] = snap
        out.append(('access', 'users', users))
        out.read_kinds.add('access')
    else:
        out.unread_scopes.add(('access', 'users'))
    rows = _read_list(mgr, out, 'access', 'groups', '/access/groups')
    if rows is not None:
        grp = _keyed(rows, 'groupid', set(), _CSV_NORMALIZE_NEW)
        out.append(('access', 'groups', {g: {'users': v.get('users', '')} for g, v in grp.items()}))
        out.read_kinds.add('access')
    rows = _read_list(mgr, out, 'access', 'roles', '/access/roles')
    if rows is not None:
        rl = _keyed(rows, 'roleid', set(), _CSV_NORMALIZE_NEW)
        out.append(('access', 'roles', {r: {'privs': v.get('privs', ''), 'special': v.get('special', 0)}
                                        for r, v in rl.items()}))
        out.read_kinds.add('access')
    rows = _read_list(mgr, out, 'access', 'acl', '/access/acl')
    if rows is not None:
        acl = {}
        for a in rows:
            if isinstance(a, dict) and a.get('path') is not None and a.get('roleid'):
                acl[f"{a['path']} | {a.get('type', 'user')}:{a.get('ugid', '')} | {a['roleid']}"] = {
                    'propagate': a.get('propagate', 1)}
        out.append(('access', 'acl', acl))
        out.read_kinds.add('access')


# ──────────────────────────────────────────────────────────────────────────
# Diff
# ──────────────────────────────────────────────────────────────────────────

def _flat_diff(baseline, current):
    """Compare two dicts, return list of {path, op, before, after}.
    Top-level keys only — Proxmox configs are flat enough that this is fine
    and produces much more readable output than recursive deep-diffs."""
    if not isinstance(baseline, dict): baseline = {}
    if not isinstance(current, dict): current = {}
    keys = set(baseline.keys()) | set(current.keys())
    diffs = []
    for k in sorted(keys):
        b, c = baseline.get(k), current.get(k)
        if b == c: continue
        if k in baseline and k not in current:
            diffs.append({'path': k, 'op': 'removed', 'before': b, 'after': None})
        elif k not in baseline and k in current:
            diffs.append({'path': k, 'op': 'added', 'before': None, 'after': c})
        else:
            diffs.append({'path': k, 'op': 'changed', 'before': b, 'after': c})
    return diffs


def _severity_for(kind, diffs, scope=''):
    """Heuristic — VM disks/network changes are louder than e.g. description edits."""
    paths = {d['path'] for d in diffs}
    sensitive_vm = {'scsi0', 'sata0', 'virtio0', 'ide0', 'net0', 'net1', 'net2',
                    'memory', 'cores', 'cpu', 'ostype', 'boot', 'bootdisk',
                    'cipassword', 'sshkeys'}
    sensitive_storage = {'shared', 'export', 'server', 'username', 'content', 'pool'}
    sensitive_network = {'address', 'netmask', 'gateway', 'bridge_ports', 'type',
                         'bond_slaves', 'vlan-raw-device'}
    if kind == 'cluster_options':
        return 'warning'
    # MK Oct 2026 - who may do what is the loudest of the new kinds; the rest changes how
    # traffic, backups and failover behave, which is worth a warning
    if kind == 'access':
        return 'critical' if scope in ('acl', 'roles') else 'warning'
    if kind in ('firewall', 'ha_rules'):
        return 'warning'
    if kind == 'backup_jobs':
        return 'warning' if paths & {'enabled', 'schedule', 'storage', 'vmid', 'all', 'pool'} else 'info'
    if kind == 'vm_config' and (paths & sensitive_vm):
        return 'warning'
    if kind == 'storage' and (paths & sensitive_storage):
        return 'warning'
    if kind == 'network' and (paths & sensitive_network):
        return 'critical'
    return 'info'


def _short_summary(kind, scope, diffs):
    keys = ', '.join(d['path'] for d in diffs[:4])
    if len(diffs) > 4:
        keys += f", +{len(diffs) - 4} more"
    return f"{kind} {scope}: {keys}"


# ──────────────────────────────────────────────────────────────────────────
# Persistence helpers
# ──────────────────────────────────────────────────────────────────────────

def _baseline_key(cluster_id, kind, scope):
    return f"{cluster_id}:{kind}:{scope}"


def _load_baselines(cluster_id):
    try:
        c = get_db().conn.cursor()
        c.execute(
            "SELECT id, kind, scope, snapshot, created_at, created_by "
            "FROM drift_baselines WHERE cluster_id = ?",
            (cluster_id,)
        )
        out = {}
        for r in c.fetchall():
            try:
                snap = json.loads(r['snapshot'])
            except Exception:
                snap = {}
            out[(r['kind'], r['scope'])] = {
                'id': r['id'],
                'snapshot': snap,
                'created_at': r['created_at'],
                'created_by': r['created_by'] or '',
            }
        return out
    except Exception as e:
        logging.warning(f"[drift] baseline load failed: {e}")
        return {}


def _set_baseline(cluster_id, kind, scope, snapshot, user):
    try:
        c = get_db().conn.cursor()
        # one baseline per (cluster,kind,scope) — replace
        c.execute(
            "DELETE FROM drift_baselines WHERE cluster_id=? AND kind=? AND scope=?",
            (cluster_id, kind, scope)
        )
        c.execute('''
            INSERT INTO drift_baselines (id, cluster_id, kind, scope, snapshot, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (uuid.uuid4().hex[:12], cluster_id, kind, scope,
              json.dumps(snapshot), datetime.now().isoformat(), user))
        get_db().conn.commit()
    except Exception as e:
        logging.warning(f"[drift] set_baseline failed: {e}")


CATEGORY_DEVIATION = 'deviation'
CATEGORY_POLICY = 'policy_violation'
CATEGORY_INCIDENT = 'incident'
CATEGORIES = (CATEGORY_DEVIATION, CATEGORY_POLICY, CATEGORY_INCIDENT)
KINDS = ('vm_config', 'storage', 'network', 'cluster_options',
         'firewall', 'ha_rules', 'backup_jobs', 'access')


def _record_event(cluster_id, kind, scope, diffs, severity, summary, category=CATEGORY_DEVIATION,
                  change_id=None):
    # NS Oct 2026 - only a deviation can be planned; a violation of a rule or an incident is
    # never linked to a change, whatever the caller found
    if category != CATEGORY_DEVIATION:
        change_id = None
    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO drift_events (cluster_id, kind, scope, severity,
                                      summary, diff, detected_at, status, category, change_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
        ''', (cluster_id, kind, scope, severity, summary,
              json.dumps(diffs), datetime.now().isoformat(), category, change_id))
        eid = c.lastrowid
        get_db().conn.commit()
        return eid
    except Exception as e:
        logging.warning(f"[drift] record_event failed: {e}")
        return None


def _refuse_baseline_write(what='changing a drift baseline'):
    """403 unless the caller may also change the cluster's configuration, else None.

    NS Oct 2026 - admin.audit reads drift. Rewriting a baseline accepts whatever changed
    as the new normal, so a read-only auditor could make drift disappear. Plain
    acknowledging stays with the reader: it keeps the row and who acknowledged it."""
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission
    if not has_permission(build_authz_user(_current_user(), request.session), 'cluster.config'):
        return jsonify({'error': f'Permission denied: {what} needs cluster.config',
                        'code': 'MISSING_PERMISSION', 'required': 'cluster.config'}), 403
    return None


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict):
            return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _owning_node(kind, scope, guest_nodes=None):
    """Node a drift scope belongs to, when a single one owns it. network scopes
    are '<node>/<iface>'. A guest config carries no node of its own, so a
    vm_config scope ('qemu/<vmid>', 'lxc/<vmid>') is looked up in guest_nodes,
    the live guest list. Cluster-wide kinds (storage, cluster_options) have no
    single owning node -> None -> the removal guard never masks them."""
    if kind == 'network':
        node = scope.split('/', 1)[0]
        return node or None
    if kind == 'vm_config' and guest_nodes:
        return guest_nodes.get(scope) or None
    if kind == 'firewall':
        if scope.startswith('node/'):
            return scope.split('/', 1)[1] or None
        if scope.startswith('guest/') and guest_nodes:
            return guest_nodes.get(scope.split('/', 1)[1]) or None
    return None


# the guest list _fetch_state read moments ago is still in the manager's cache
_GUEST_LIST_MAX_AGE = 600


def _guest_nodes(mgr):
    """'qemu/101' -> node. PVE keeps listing an offline node's guests in
    cluster/resources (status unknown), only their config read fails."""
    out = {}
    try:
        for r in (mgr.get_vm_resources(max_age=_GUEST_LIST_MAX_AGE) or []):
            t, vmid, node = r.get('type'), r.get('vmid'), r.get('node')
            if t in ('qemu', 'lxc') and vmid and node:
                out[f"{t}/{vmid}"] = node
    except Exception as e:
        logging.debug(f"[drift] guest list for node ownership failed: {e}")
    return out


def _offline_nodes(mgr):
    """Set of node names the manager currently reports NOT online. Uses the
    node status PegaProx already tracks (get_node_status), so a node reboot or
    power outage is visible to the drift scanner without any new collector.
    Best effort: any error means NO node is considered offline, i.e. removal
    detection behaves exactly as before - never mask a removal because the
    liveness read hiccupped."""
    try:
        st = mgr.get_node_status() or {}
        return {name for name, data in st.items()
                if isinstance(data, dict) and data.get('status') != 'online'}
    except Exception as e:
        logging.debug(f"[drift] node liveness read failed (removals unmasked): {e}")
        return set()


def _is_presence_unknown(diffs):
    return (isinstance(diffs, list) and len(diffs) == 1 and isinstance(diffs[0], dict)
            and diffs[0].get('op') == 'unknown')


def _open_unknown_events(cluster_id):
    """(kind, scope) -> ids of the open 'presence unknown' rows of a cluster."""
    out = {}
    try:
        c = get_db().conn.cursor()
        c.execute("SELECT id, kind, scope, diff FROM drift_events "
                  "WHERE cluster_id=? AND status='open' AND diff LIKE ?",
                  (cluster_id, '%"op": "unknown"%'))
        for r in c.fetchall():
            try:
                if _is_presence_unknown(json.loads(r['diff'])):
                    out.setdefault((r['kind'], r['scope']), []).append(r['id'])
            except Exception:
                continue
    except Exception as e:
        logging.debug(f"[drift] open unknown events read failed: {e}")
    return out


def _supersede_events(ids):
    if not ids:
        return
    try:
        c = get_db().conn.cursor()
        c.executemany("UPDATE drift_events SET status='superseded' WHERE id=? AND status='open'",
                      [(i,) for i in ids])
        get_db().conn.commit()
    except Exception as e:
        logging.warning(f"[drift] superseding events failed: {e}")


def _diff_digest(text):
    return hashlib.sha256(str(text).encode('utf-8', 'replace')).digest()


def _open_deviation_diffs(cluster_id):
    """{(kind, scope, digest of the diff text)} of the deviations still open. A scan that finds
    the same unchanged diff again records nothing new; a changed diff does. An incident is a
    deviation an admin confirmed, so it counts as the same row. Failing to read them means
    every deviation is recorded as before. MK Oct 2026"""
    out = set()
    try:
        c = get_db().conn.cursor()
        c.execute("SELECT kind, scope, diff FROM drift_events WHERE cluster_id=? AND status='open' "
                  "AND category IN (?, ?)", (cluster_id, CATEGORY_DEVIATION, CATEGORY_INCIDENT))
        for r in c.fetchall():
            out.add((r['kind'], r['scope'], _diff_digest(r['diff'])))
    except Exception as e:
        logging.debug(f"[drift] open deviations read failed: {e}")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Policy checks and what the last scan could read - MK Oct 2026
# ──────────────────────────────────────────────────────────────────────────
#
# A policy check is a forbidden state for one kind, judged on the snapshot the scan just
# took. It is evaluated whether or not a baseline exists. What the scan could not read is
# "not checked", never a pass: a check passes only on data that was read.

POLICY_CHECKS = {
    'access_admin_role': {'kind': 'access', 'severity': 'critical', 'allow': ['root@pam']},
    'access_token_expiry': {'kind': 'access', 'severity': 'warning'},
    'firewall_cluster_enabled': {'kind': 'firewall', 'severity': 'warning'},
    'backup_none_disabled': {'kind': 'backup_jobs', 'severity': 'warning'},
}
_POLICY_ALLOW_MAX = 100

# cluster_id -> {'at', 'kinds': {kind: checked|partial|not_checked}, 'policy': [result]}
_last_scan = {}


def _policy_key(cluster_id):
    return f"drift_policy:{cluster_id}"


def _policy_settings(cluster_id):
    """The admin's choices per check: {check_id: {'enabled': bool, 'allow': [...]}}.
    A check nobody switched on is off, so an upgrade raises nothing by itself."""
    try:
        from pegaprox.core.recovery import _kv_read
        stored = _kv_read(_policy_key(cluster_id)) or {}
    except Exception as e:
        logging.debug(f"[drift] policy settings read failed: {e}")
        stored = {}
    out = {}
    for cid, spec in POLICY_CHECKS.items():
        mine = stored.get(cid) if isinstance(stored.get(cid), dict) else {}
        allow = mine.get('allow', spec.get('allow', []))
        out[cid] = {'enabled': bool(mine.get('enabled', False)),
                    'allow': [a for a in allow if isinstance(a, str)] if isinstance(allow, list) else []}
    return out


def _kinds_state(state, baselines=None):
    """Per kind: 'checked', 'partial' (some scopes did not answer), 'no_baseline' (read, but
    none of its scopes has a baseline, so there is nothing to compare with) or 'not_checked'.

    baselines is anything that answers `(kind, scope) in baselines`; None means the caller
    has no record of them and no kind is judged on that."""
    read = getattr(state, 'read_kinds', None)
    if read is None:
        # a plain list (no record of what was read): a kind is checked when it has rows
        read = {k for k, _, _ in state}
    bad_kinds = getattr(state, 'unread_kinds', set())
    unread = {k for k, _ in getattr(state, 'unread_scopes', set())} | \
             {k for k, _ in getattr(state, 'unread_prefixes', set())}
    cover = _baseline_coverage(state, baselines) if baselines is not None else {}
    out = {}
    for kind in KINDS:
        if kind in bad_kinds or kind not in read:
            out[kind] = 'not_checked'
        elif kind in cover and cover[kind]['baselined'] == 0:
            out[kind] = 'no_baseline'
        elif kind in unread or (kind == 'network' and getattr(state, 'unread_nodes', None)):
            out[kind] = 'partial'
        else:
            out[kind] = 'checked'
    return out


def _baseline_coverage(state, baselines):
    """{kind: {'scopes': n, 'baselined': m}} for the kinds that have a scope in this read.
    A kind with no scope at all has nothing to compare and nothing missing, so it is left out."""
    out = {}
    for kind, scope, _ in state:
        c = out.setdefault(kind, {'scopes': 0, 'baselined': 0})
        c['scopes'] += 1
        if (kind, scope) in baselines:
            c['baselined'] += 1
    return out


def _refresh_last_scan(cluster_id, state, baselined):
    """A reset gave the kinds their baselines: what the last scan said about them is no longer
    'no baseline'. Nothing else of that scan is touched."""
    last = _last_scan.get(cluster_id)
    if not last:
        return
    now = _kinds_state(state, baselined)
    for kind, was in list(last.get('kinds', {}).items()):
        if was == 'no_baseline':
            last['kinds'][kind] = now.get(kind, was)
    last['coverage'] = _baseline_coverage(state, baselined)


def _check_access_admin_role(idx, state, params):
    acl = idx.get(('access', 'acl'))
    if acl is None:
        return None
    allow = set(params.get('allow') or [])
    bad = []
    for key in sorted(acl):
        path, _, rest = key.partition(' | ')
        who, _, role = rest.rpartition(' | ')
        if role == 'Administrator' and who.partition(':')[2] not in allow:
            bad.append((who, f"Administrator on {path}"))
    return bad


def _check_access_token_expiry(idx, state, params):
    users = idx.get(('access', 'users'))
    if users is None:
        return None
    bad = []
    for uid in sorted(users):
        for k, v in sorted((users[uid] or {}).items()):
            if k.startswith('token:') and str(v or 0) == '0':
                bad.append((f"{uid}!{k[6:]}", 'token never expires'))
    return bad


def _check_firewall_cluster_enabled(idx, state, params):
    opts = idx.get(('firewall', 'cluster/options'))
    if opts is None:
        return None
    if str(opts.get('enable', 0)).lower() in ('1', 'true'):
        return []
    return [('cluster firewall', 'the cluster firewall is off')]


def _check_backup_none_disabled(idx, state, params):
    if 'backup_jobs' not in getattr(state, 'read_kinds', set()) or 'backup_jobs' in state.unread_kinds:
        return None
    return [(scope, 'backup job is disabled') for (kind, scope), snap in sorted(idx.items())
            if kind == 'backup_jobs' and str((snap or {}).get('enabled', 1)).lower() in ('0', 'false')]


_POLICY_FUNCS = {
    'access_admin_role': _check_access_admin_role,
    'access_token_expiry': _check_access_token_expiry,
    'firewall_cluster_enabled': _check_firewall_cluster_enabled,
    'backup_none_disabled': _check_backup_none_disabled,
}


def _evaluate_policy(state, settings):
    """One result per check: status is 'pass', 'fail', 'not_checked' (the data it needs
    was not read) or 'disabled'; violations are [{'path', 'detail'}]."""
    idx = {(k, s): snap for k, s, snap in state}
    results = []
    for cid, spec in POLICY_CHECKS.items():
        mine = settings.get(cid) or {'enabled': False, 'allow': spec.get('allow', [])}
        res = {'id': cid, 'kind': spec['kind'], 'severity': spec['severity'],
               'enabled': mine['enabled'], 'violations': []}
        if 'allow' in spec:
            res['allow'] = mine['allow']
        if not mine['enabled']:
            res['status'] = 'disabled'
        else:
            try:
                bad = _POLICY_FUNCS[cid](idx, state, mine)
            except Exception as e:
                logging.debug(f"[drift] policy check {cid} failed: {e}")
                bad = None
            if bad is None:
                res['status'] = 'not_checked'
            else:
                res['violations'] = [{'path': p, 'detail': d} for p, d in bad]
                res['status'] = 'fail' if bad else 'pass'
        results.append(res)
    return results


def _violation_fingerprint(diffs):
    try:
        return sorted(d.get('path', '') for d in diffs)
    except Exception:
        return []


def _apply_policy(cluster_id, results):
    """Turn the results into events: one open event per failing check while the offenders
    stay the same, a new one when they change, and a pass closes the check's events. A
    check that was not checked leaves everything as it is. Incidents are never touched."""
    new_events = []
    c = get_db().conn.cursor()
    for res in results:
        scope = f"policy:{res['id']}"
        if res['status'] not in ('pass', 'fail'):
            continue
        c.execute("SELECT id, diff, category FROM drift_events WHERE cluster_id=? AND kind=? "
                  "AND scope=? AND status IN ('open','acknowledged') AND category=?",
                  (cluster_id, res['kind'], scope, CATEGORY_POLICY))
        live = c.fetchall()
        if res['status'] == 'pass':
            c.executemany("UPDATE drift_events SET status='resolved' WHERE id=?",
                          [(r['id'],) for r in live])
            continue
        diffs = [{'path': v['path'], 'op': 'violation', 'before': None, 'after': v['detail']}
                 for v in res['violations']]
        same = _violation_fingerprint(diffs)
        if any(_violation_fingerprint(json.loads(r['diff'] or '[]')) == same for r in live):
            continue
        # the offenders changed: the old row is replaced, not left beside the new one
        c.executemany("UPDATE drift_events SET status='superseded' WHERE id=?", [(r['id'],) for r in live])
        get_db().conn.commit()
        names = ', '.join(v['path'] for v in res['violations'][:3])
        more = len(res['violations']) - 3
        summary = f"policy {res['id']}: {names}" + (f", +{more} more" if more > 0 else '')
        eid = _record_event(cluster_id, res['kind'], scope, diffs, res['severity'], summary,
                            category=CATEGORY_POLICY)
        new_events.append({'id': eid, 'kind': res['kind'], 'scope': scope, 'severity': res['severity'],
                           'summary': summary, 'category': CATEGORY_POLICY})
    get_db().conn.commit()
    return new_events


# ──────────────────────────────────────────────────────────────────────────
# Scan
# ──────────────────────────────────────────────────────────────────────────

SCAN_ALREADY_RUNNING = 'a scan of this cluster is already running'
# NS Nov 2026 - clusters with a scan in progress. "Scan now" pressed twice, or while the
# scheduled pass was on the same cluster, ran two scans side by side: both read the same open
# deviations and both wrote the same event. The second one is skipped and says why.
_scans_running = set()
_scans_running_lock = threading.Lock()


def _scan_cluster(cluster_id, autobaseline=False):
    """Snapshot + diff for one cluster. Returns dict with counts/events.
    If autobaseline=True and no baseline exists yet, set one without firing
    drift events (initial seeding behavior). One scan per cluster at a time, the
    manual route and the scheduled scanner alike."""
    with _scans_running_lock:
        if cluster_id in _scans_running:
            return {'error': SCAN_ALREADY_RUNNING, 'status': 'skipped'}
        _scans_running.add(cluster_id)
    try:
        return _scan_cluster_once(cluster_id, autobaseline)
    finally:
        with _scans_running_lock:
            _scans_running.discard(cluster_id)


def _scan_cluster_once(cluster_id, autobaseline):
    if cluster_id not in cluster_managers:
        return {'error': 'cluster not found'}
    mgr = cluster_managers[cluster_id]
    if not getattr(mgr, 'is_connected', False):
        return {'error': 'cluster offline', 'status': 'skipped'}

    state = _fetch_state(mgr, cluster_id)
    baselines = _load_baselines(cluster_id)
    # what the baseline holds, the seeding of this scan included, says which kinds could be
    # compared at all
    have_baseline = set(baselines)
    # the same diff against the same baseline is one event, not one per scan
    open_diffs = _open_deviation_diffs(cluster_id)
    already_open = 0
    # NS Oct 2026 - the approved plans whose window is open right now, read once for the scan
    plans = changes.approved_in_window(cluster_id)

    new_events = []
    seeded = 0
    seen_keys = set()
    for kind, scope, snap in state:
        seen_keys.add((kind, scope))
        bk = baselines.get((kind, scope))
        if not bk:
            if autobaseline:
                _set_baseline(cluster_id, kind, scope, snap, 'system')
                have_baseline.add((kind, scope))
                seeded += 1
            continue
        diffs = _flat_diff(bk['snapshot'], snap)
        if not diffs: continue
        if (kind, scope, _diff_digest(json.dumps(diffs))) in open_diffs:
            already_open += 1
            continue
        sev = _severity_for(kind, diffs, scope)
        summary = _short_summary(kind, scope, diffs)
        planned = changes.link_for(plans, kind, scope)
        eid = _record_event(cluster_id, kind, scope, diffs, sev, summary, change_id=planned)
        new_events.append({'id': eid, 'kind': kind, 'scope': scope,
                           'severity': sev, 'summary': summary, 'change_id': planned})

    # detect deletions: baseline keys that are no longer in current state
    missing = [(key, bk) for key, bk in baselines.items() if key not in seen_keys]
    if missing and not state:
        # MK Oct 2026 - nothing answered at all (API down while the manager still
        # counts as connected). An empty read says nothing about what exists.
        return {'error': 'cluster did not answer', 'status': 'skipped'}

    # An offline node does not answer its per-node reads, so its NICs and guest
    # configs never reach `state` and their absence would read as a removal on
    # every node reboot (#968). Such a scope is recorded once per outage as
    # 'presence unknown' (info, no alert) and keeps its baseline: if it is really
    # gone, the first scan after the node is back reports the removal. Liveness
    # and the guest list are only read when something is missing.
    removed = []
    masked = set()
    # MK Oct 2026 - a scope whose read failed (the guest list timed out, storage answered
    # an error, one node's network did not) was not seen, which is not the same as gone.
    # Like an offline node's scopes it keeps its baseline; unlike them it records no row,
    # a failed read is no news about the cluster. The scan result and the log say so.
    not_read = set()
    unread_kinds = getattr(state, 'unread_kinds', set())
    open_unknown = _open_unknown_events(cluster_id)
    guest_nodes = offline_nodes = None
    for (kind, scope), bk in missing:
        if kind in unread_kinds:
            # before the guest list below, which is the read that just failed
            not_read.add((kind, scope))
            continue
        if (kind == 'vm_config' or (kind == 'firewall' and scope.startswith('guest/'))) \
                and guest_nodes is None:
            guest_nodes = _guest_nodes(mgr)
        owning_node = _owning_node(kind, scope, guest_nodes)
        if owning_node and offline_nodes is None:
            offline_nodes = _offline_nodes(mgr)
        if owning_node and owning_node in offline_nodes:
            masked.add((kind, scope))
            if (kind, scope) in open_unknown:
                continue
            summary = f"{kind} {scope}: on offline node {owning_node}, presence unknown"
            diffs = [{'path': '*', 'op': 'unknown', 'before': bk['snapshot'], 'after': None,
                      'node-offline': owning_node}]
            eid = _record_event(cluster_id, kind, scope, diffs, 'info', summary)
            new_events.append({'id': eid, 'kind': kind, 'scope': scope, 'severity': 'info',
                               'summary': summary, 'node_offline': owning_node})
            continue
        if _not_read(state, kind, scope):
            not_read.add((kind, scope))
            continue
        diffs = [{'path': '*', 'op': 'removed', 'before': bk['snapshot'], 'after': None}]
        removed.append(scope)
        if (kind, scope, _diff_digest(json.dumps(diffs))) in open_diffs:
            already_open += 1
            continue
        summary = f"{kind} {scope}: object removed"
        sev = 'warning' if kind in ('vm_config', 'storage', 'firewall', 'access', 'backup_jobs') else 'info'
        planned = changes.link_for(plans, kind, scope)
        eid = _record_event(cluster_id, kind, scope, diffs, sev, summary, change_id=planned)
        new_events.append({'id': eid, 'kind': kind, 'scope': scope,
                           'severity': sev, 'summary': summary, 'change_id': planned})

    # MK Oct 2026 - policy checks judge this scan's snapshot, and the result of the scan
    # says per kind what was read: a kind that was not is "not checked", not "no drift"
    kinds = _kinds_state(state, have_baseline)
    coverage = _baseline_coverage(state, have_baseline)
    results = _evaluate_policy(state, _policy_settings(cluster_id))
    try:
        new_events.extend(_apply_policy(cluster_id, results))
    except Exception as e:
        logging.warning(f"[drift] policy events failed: {e}")
    _last_scan[cluster_id] = {'at': datetime.now().isoformat(), 'kinds': kinds,
                              'coverage': coverage, 'policy': results}

    unread = sorted({kind for kind, _ in not_read})
    if not_read:
        logging.warning(f"[drift] {cluster_id}: {len(not_read)} object(s) not read this scan "
                        f"({', '.join(unread)}), their baselines are kept")

    # rows of an earlier outage are done with once the node answers again; one that
    # was not read this time is not known to be back
    _supersede_events([i for key, ids in open_unknown.items()
                       if key not in masked and key not in not_read for i in ids])

    # fire alert handler so configured Slack/Discord/etc. + push pick it up. A
    # presence-unknown row is no drift; the node being down has its own alert.
    if any(not e.get('node_offline') for e in new_events):
        try:
            from pegaprox.background import alerts as alerts_mod
            alertable = [e for e in new_events if not e.get('node_offline')]
            count = len(alertable)
            npol = sum(1 for e in alertable if e.get('category') == CATEGORY_POLICY)
            top_sev = 'critical' if any(e['severity'] == 'critical' for e in alertable) \
                else 'warning' if any(e['severity'] == 'warning' for e in alertable) \
                else 'info'
            payload = {
                'alert_name': 'Config Drift',
                'severity': top_sev,
                'cluster_id': cluster_id,
                'message': f"{count} config drift event(s) detected" + (
                    f" ({npol} policy violation(s))" if npol else ''),
                'metric': 'drift',
                'target_type': 'cluster',
                'target_name': cluster_id,
                'timestamp': datetime.now().isoformat(),
            }
            for h in alerts_mod._notification_handlers:
                try: h(payload)
                except Exception: pass
            # MK Sep 2026 (#815) — that list is the PLUGIN hook (web-push and whatever
            # else registered itself); it is not the webhook channels. alerts.py fires
            # both, this path only ever fired the first, so a drift event reached push
            # and nothing else no matter how many webhooks were configured — and the
            # Test button still worked, because it dispatches directly.
            # Drift has no per-event channel picker the way a metric alert does, so
            # every enabled channel gets it, which is send_to_channels' own default.
            try:
                from pegaprox.utils.webhooks import send_to_channels
                send_to_channels(payload)
            except Exception as _we:
                logging.warning(f"[DRIFT] webhook dispatch failed: {_we}")
        except Exception:
            pass

    return {
        'ok': True,
        'cluster_id': cluster_id,
        'events_count': len(new_events),
        'seeded_baselines': seeded,
        'removed': removed,
        'suppressed_offline': len(masked),
        'suppressed_unread': len(not_read),
        'unread': unread,
        'already_open': already_open,
        'kinds': kinds,
        'coverage': coverage,
        'not_checked': sorted(k for k, v in kinds.items() if v != 'checked'),
        'policy_failed': [r['id'] for r in results if r['status'] == 'fail'],
        'events': new_events,
    }


# ──────────────────────────────────────────────────────────────────────────
# Background scanner — every 6h. Also runs on first call after import.
# ──────────────────────────────────────────────────────────────────────────

_scanner_running = False
_scanner_lock = threading.Lock()
SCAN_INTERVAL = 6 * 3600

# MK Oct 2026 - until _open_deviation_diffs, every scan wrote an unchanged deviation again,
# removals included, so one drifted object could hold thousands of identical open rows.
# The scanner thread collapses them when it starts: the oldest of each (the start of the
# drift) stays open, the rest is superseded the way a baseline reset does it. drift_events
# is per instance (core/ha.py LOCAL_TABLES), so this runs on every start, standby or not,
# rather than once behind a marker the sync would carry to a standby with piles of its own.
# Off the hub and in chunks: a big pile takes minutes to write (500k rows about two), the
# start does not wait for it and another writer waits one chunk at most, some 0.2 s.
# With nothing left it reads the open deviations, no more.
_REPEAT_CHUNK = 1000
_REPEAT_PAUSE = 0.05


def _find_repeats(conn):
    """Ids of the open deviations that repeat an older open one of the same cluster, kind
    and scope with the very same diff text."""
    oldest, repeats = {}, []
    for r in conn.execute("SELECT id, cluster_id, kind, scope, diff FROM drift_events "
                          "WHERE status='open' AND category=?", (CATEGORY_DEVIATION,)):
        key = (r[1], r[2], r[3], _diff_digest(r[4]))
        first = oldest.get(key)
        if first is None:
            oldest[key] = r[0]
        elif r[0] < first:
            oldest[key] = r[0]
            repeats.append(first)
        else:
            repeats.append(r[0])
    return sorted(repeats)


def _supersede_repeats(conn, ids):
    # still open and still a deviation: what an admin acknowledged or confirmed since stays
    c = conn.cursor()
    c.executemany("UPDATE drift_events SET status='superseded' WHERE id=? AND status='open' "
                  "AND category=?", [(i, CATEGORY_DEVIATION) for i in ids])
    return max(c.rowcount, 0)


def _collapse_repeats():
    """Supersede the repeated open deviations, logged as one line. A failure is logged and
    leaves the rest for the next start. No alert and no audit entry: nothing new was found.
    Returns how many rows it superseded."""
    done = 0
    try:
        path = get_db().db_path
        ids = dbcrypto.run_off_hub(_find_repeats, path)
        for at in range(0, len(ids), _REPEAT_CHUNK):
            if at:
                time.sleep(_REPEAT_PAUSE)    # the other writers get the database in between
            chunk = ids[at:at + _REPEAT_CHUNK]
            done += dbcrypto.run_off_hub(lambda conn, chunk=chunk: _supersede_repeats(conn, chunk),
                                         path, commit=True)
    except Exception as e:
        logging.warning(f"[drift] superseding repeated open deviations stopped after {done}: {e}")
        return done
    if done:
        logging.info(f"[drift] {done} repeated open deviation(s) superseded, the oldest of each stays open")
    return done


# MK Oct 2026 - drift_events kept every row it ever got. A fleet-wide change at a few
# thousand guests writes thousands per scan, and every resolved or superseded one stayed for
# good. The rows nobody acts on any more are pruned now, by age and, per cluster, by count:
# only 'resolved' and 'superseded' ones, never an open or acknowledged row, an incident an
# admin confirmed or a deviation an approved change plan names (the evidence of that plan).
# Once at the start of the scanner thread and then once a day, on every instance (the table
# is LOCAL, a standby has a pile of its own), off the hub and in chunks like the collapse
# above. A cluster that is no longer configured keeps its rows under the same rules, so a
# cluster added back finds its history.
#   PEGAPROX_DRIFT_EVENT_RETENTION_DAYS  default 365, held to 90..3650; 0 prunes nothing
#   PEGAPROX_DRIFT_EVENT_CAP             prunable rows kept per cluster, default 200000
#                                        (0 or less: no cap); past it the oldest go first,
#                                        superseded ones before resolved ones
_PRUNE_EVERY = 86400
_PRUNE_CHUNK = 200          # a few ms of writing each, the hub writes on its own connection
_PRUNE_PAUSE = 0.05
_PRUNE_BATCH = 50000        # ids looked up per round, deleted in chunks
_PRUNABLE = "status IN ('resolved', 'superseded') AND category != 'incident' AND change_id IS NULL"
# the same for a chunk of ids: the + keeps the status indexes out of it, so SQLite finds the
# rows by their ids (the primary key) and checks the rest on them; past about 20 ids it took
# idx_drift_events_status and went through every resolved row for each chunk
_PRUNABLE_IDS = '+' + _PRUNABLE


def _event_retention_days():
    raw = os.environ.get('PEGAPROX_DRIFT_EVENT_RETENTION_DAYS', '').strip()
    try:
        days = int(raw) if raw else 365
    except ValueError:
        days = 365
    return 0 if days == 0 else max(90, min(days, 3650))


def _event_cap():
    raw = os.environ.get('PEGAPROX_DRIFT_EVENT_CAP', '').strip()
    try:
        cap = int(raw) if raw else 200000
    except ValueError:
        cap = 200000
    return max(cap, 0)


def _delete_events(path, ids):
    """Delete the prunable rows among ids, a chunk per transaction with a pause in
    between; how many went. A row acknowledged or linked meanwhile stays."""
    done = 0
    for at in range(0, len(ids), _PRUNE_CHUNK):
        if at:
            time.sleep(_PRUNE_PAUSE)    # the other writers get the database in between
        chunk = ids[at:at + _PRUNE_CHUNK]

        def work(conn, chunk=chunk):
            c = conn.cursor()
            c.execute(f"DELETE FROM drift_events WHERE id IN ({','.join('?' * len(chunk))}) AND {_PRUNABLE_IDS}",
                      chunk)
            return max(c.rowcount, 0)
        done += dbcrypto.run_off_hub(work, path, commit=True)
    return done


def _prune_events():
    """Prune resolved and superseded drift events past the retention, then per cluster past
    the cap; logged as one line. A failure is logged and leaves the rest for the next run.
    Returns how many rows went."""
    days = _event_retention_days()
    if not days:
        return 0
    cap = _event_cap()
    aged = capped = 0
    try:
        path = get_db().db_path
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        def old_ones(conn):
            # by idx_drift_events_age, which the schema pass makes (core/db.py)
            return [r[0] for r in conn.execute(
                f'SELECT id FROM drift_events WHERE {_PRUNABLE} AND detected_at < ? ORDER BY id LIMIT ?',
                (cutoff, _PRUNE_BATCH))]
        while True:
            ids = dbcrypto.run_off_hub(old_ones, path)
            gone = _delete_events(path, ids)
            aged += gone
            if len(ids) < _PRUNE_BATCH or not gone:
                break
        if cap:
            def over_cap(conn):
                out = []
                for (cid,) in conn.execute('SELECT DISTINCT cluster_id FROM drift_events').fetchall():
                    n = conn.execute(f'SELECT COUNT(*) FROM drift_events WHERE cluster_id = ? AND {_PRUNABLE}',
                                     (cid,)).fetchone()[0]
                    if n > cap:
                        # kept: resolved before superseded, the newest of each first
                        out += [r[0] for r in conn.execute(
                            f"SELECT id FROM drift_events WHERE cluster_id = ? AND {_PRUNABLE} "
                            f"ORDER BY status = 'superseded', detected_at DESC, id DESC LIMIT -1 OFFSET ?",
                            (cid, cap))]
                return out
            capped = _delete_events(path, dbcrypto.run_off_hub(over_cap, path))
    except Exception as e:
        logging.warning(f"[drift] pruning old drift events stopped after {aged + capped}: {e}")
        return aged + capped
    if aged or capped:
        why = f"{aged} older than {days} days" + (f", {capped} over the {cap} kept per cluster" if capped else '')
        logging.info(f"[drift] {aged + capped} resolved or superseded drift event(s) pruned: {why}")
    return aged + capped


def _scanner_loop():
    _collapse_repeats()
    pruned_at = None
    while _scanner_running:
        # the old events go at the start and then once a day; the scans every SCAN_INTERVAL
        if pruned_at is None or time.time() - pruned_at >= _PRUNE_EVERY:
            pruned_at = time.time()
            _prune_events()
        try:
            for cid in list(cluster_managers.keys()):
                # standby: baselines and events are the active instance's business
                if not ha.is_active():
                    break
                try:
                    # a manual scan of this cluster may be running: then this pass leaves it be
                    res = _scan_cluster(cid, autobaseline=True)
                    if isinstance(res, dict) and res.get('error') == SCAN_ALREADY_RUNNING:
                        logging.debug(f"[drift] scheduled scan of {cid} skipped, one is running")
                except Exception as e:
                    logging.debug(f"[drift] scan {cid} failed: {e}")
        except Exception as e:
            logging.warning(f"[drift] scanner iteration failed: {e}")
        # break sleep into 1-sec chunks so shutdown is responsive
        for _ in range(SCAN_INTERVAL):
            if not _scanner_running:
                return
            time.sleep(1)


def start_scanner():
    global _scanner_running
    with _scanner_lock:
        if _scanner_running:
            return
        _scanner_running = True
    t = threading.Thread(target=_scanner_loop, daemon=True, name='drift-scanner')
    t.start()
    logging.info("[drift] scanner thread started (6h cadence)")


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────

def _no_such_cluster(cluster_id):
    """404 for an id no manager serves, else None. Asked after the access gates, so a caller who
    may not reach the cluster still gets the refusal and learns nothing about which ids exist.
    MK Oct 2026"""
    if cluster_id in cluster_managers:
        return None
    return jsonify({'error': 'cluster not found'}), 404


@bp.route('/api/clusters/<cluster_id>/drift/status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def drift_status(cluster_id):
    """Counts of open events grouped by kind + severity."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # MK Sep 2026 - the four siblings in this file (events, scan, baseline, acknowledge)
    # all settled on "drift is a whole-cluster notion" and refuse a confined caller. This
    # one was left on cluster.view alone, so an ACL- or pool-scoped user still read the
    # per-kind and per-severity counts for the entire cluster - how much storage, network
    # and node config has drifted, and when it last did. The dashboard fetches this
    # side by side with /drift/events, which already refuses them, so the panel was
    # never usable for these callers anyway.
    _cerr = require_unconfined(cluster_id)
    if _cerr: return _cerr
    _gone = _no_such_cluster(cluster_id)
    if _gone: return _gone
    try:
        c = get_db().conn.cursor()
        c.execute('''
            SELECT kind, severity, category, COUNT(*) AS n
            FROM drift_events
            WHERE cluster_id = ? AND status = 'open'
            GROUP BY kind, severity, category
        ''', (cluster_id,))
        by_kind = {}
        total = 0
        sev_total = {'critical': 0, 'warning': 0, 'info': 0}
        by_category = {cat: 0 for cat in CATEGORIES}
        for r in c.fetchall():
            d = by_kind.setdefault(r['kind'], {'critical': 0, 'warning': 0, 'info': 0})
            d[r['severity']] = d.get(r['severity'], 0) + r['n']
            sev_total[r['severity']] = sev_total.get(r['severity'], 0) + r['n']
            by_category[r['category']] = by_category.get(r['category'], 0) + r['n']
            total += r['n']

        # baseline count
        c.execute("SELECT COUNT(*) AS n FROM drift_baselines WHERE cluster_id=?", (cluster_id,))
        baseline_count = c.fetchone()['n']
        # open deviations that sit inside an approved change; they stay deviations
        c.execute("SELECT COUNT(*) AS n FROM drift_events WHERE cluster_id=? AND status='open' "
                  "AND category=? AND change_id IS NOT NULL", (cluster_id, CATEGORY_DEVIATION))
        planned_total = c.fetchone()['n']

        # last scan: pick max(detected_at) from events, fallback to baseline created_at
        c.execute("SELECT MAX(detected_at) AS t FROM drift_events WHERE cluster_id=?", (cluster_id,))
        last_event_t = c.fetchone()['t']

        return jsonify({
            'cluster_id': cluster_id,
            'open_total': total,
            'by_kind': by_kind,
            'by_severity': sev_total,
            'by_category': by_category,
            'planned': planned_total,
            'baselines': baseline_count,
            'last_event_at': last_event_t,
            # what the last scan could read per kind; empty until this instance has scanned
            'kinds': (_last_scan.get(cluster_id) or {}).get('kinds', {}),
            # scopes read and scopes holding a baseline, per kind: 'no_baseline' in numbers
            'coverage': (_last_scan.get(cluster_id) or {}).get('coverage', {}),
            'last_scan_at': (_last_scan.get(cluster_id) or {}).get('at'),
        })
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/drift/events', methods=['GET'])
# NS Aug 2026 (AI-pentest) — drift events carry the full before/after VM config diff (cloud-init
# cipassword/sshkeys, disk/net layout). Gate reads at admin.audit like the scan/baseline/acknowledge
# siblings, not cluster.view — a plain cluster viewer (or per-VM-ACL user) must not read other VMs'
# secrets out of the drift log.
@require_auth(perms=['admin.audit'])
def list_events(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # MK Sep 2026 - a drift event carries the cluster's configuration diff: node config,
    # storage definitions, network. There is no per-VM notion to filter on, so an
    # ACL/pool-scoped caller reading this gets the whole cluster's configuration history
    # - including every other tenant's. The scan and baseline routes below already treat
    # drift as whole-cluster; reading it is the same scope.
    _cerr = require_unconfined(cluster_id)
    if _cerr: return _cerr
    _gone = _no_such_cluster(cluster_id)
    if _gone: return _gone
    status = request.args.get('status', 'open')
    try:
        limit = int(request.args.get('limit', '100'))
    except ValueError:
        limit = 0
    if limit < 1:
        return jsonify({'error': 'limit must be a whole number from 1 to 500'}), 400
    # above the cap it is the cap, as before: API clients asked for more and got 500
    limit = min(limit, 500)
    # MK Oct 2026 - optional filters; a value that is no kind or category is a 400, not an
    # empty list that reads as "nothing drifted"
    kind = request.args.get('kind', '')
    category = request.args.get('category', '')
    if kind and kind not in KINDS:
        return jsonify({'error': 'unknown kind', 'kinds': list(KINDS)}), 400
    if category and category not in CATEGORIES:
        return jsonify({'error': 'unknown category', 'categories': list(CATEGORIES)}), 400
    try:
        c = get_db().conn.cursor()
        sql = 'SELECT * FROM drift_events WHERE cluster_id=?'
        args = [cluster_id]
        if status != 'all':
            sql += ' AND status=?'
            args.append(status)
        if kind:
            sql += ' AND kind=?'
            args.append(kind)
        if category:
            sql += ' AND category=?'
            args.append(category)
        c.execute(sql + ' ORDER BY detected_at DESC LIMIT ?', args + [limit])
        out = []
        for r in c.fetchall():
            d = dict(r)
            try:
                d['diff'] = json.loads(d['diff'])
            except Exception:
                pass
            out.append(d)
        # NS Oct 2026 - a deviation planned under an approved change names it
        named = changes.titles(e.get('change_id') for e in out)
        for e in out:
            if e.get('change_id'):
                e['change_title'] = named.get(e['change_id'], '')
        return jsonify({'events': out})
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/drift/events/<int:eid>/acknowledge', methods=['POST'])
@require_auth(perms=['admin.audit'])
def acknowledge_event(eid):
    """Mark event acknowledged. If body has promote=true, also rebase the
    baseline so the same change won't trigger again next scan."""
    body = request.get_json(silent=True) or {}
    promote = bool(body.get('promote', False))
    user = _current_user()
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM drift_events WHERE id=?', (eid,))
        ev = c.fetchone()
        if not ev:
            return jsonify({'error': 'not found'}), 404
        # NS Jul 2026 (CodeAnt IDOR) — tenant gate on the event's cluster before ack/promote
        # (was ack-ing / rebaselining another tenant's drift events).
        from pegaprox.api.helpers import check_cluster_access
        ok, err = check_cluster_access(ev['cluster_id'])
        if not ok:
            # NS Sep 2026 (audit) — returning the cluster-access refusal here answers a
            # question the caller was not allowed to ask: it says the event id exists.
            # A drift event they may not touch is, to them, an event that is not there.
            return jsonify({'error': 'not found'}), 404
        # acknowledging - and especially promoting, which rewrites the baseline the next
        # scan compares against - is a whole-cluster act for the same reason
        _cerr = require_unconfined(ev['cluster_id'])
        if _cerr:
            return _cerr
        # MK Oct 2026 - a policy violation is not raised again while its offenders stay the
        # same, and an acknowledged one no longer counts as open: acknowledging it silences
        # the rule, which is the configuration's business, not a reader's (a deviation comes
        # back with the next scan and stays the auditor's to acknowledge)
        if (ev['category'] if 'category' in ev.keys() else '') == CATEGORY_POLICY:
            _werr = _refuse_baseline_write('acknowledging a policy violation')
            if _werr:
                return _werr
        if promote:
            if (ev['category'] if 'category' in ev.keys() else '') == CATEGORY_POLICY:
                # a violation of a rule has no baseline to rebase onto
                return jsonify({'error': 'a policy violation has no baseline to promote'}), 400
            _werr = _refuse_baseline_write()
            if _werr:
                return _werr
        c.execute('''UPDATE drift_events SET status='acknowledged',
                     acknowledged_at=?, acknowledged_by=? WHERE id=?''',
                  (datetime.now().isoformat(), user, eid))

        if promote:
            # re-fetch the live state for that scope and store as new baseline.
            # A presence-unknown row (#968) has no change to accept: rebaselining
            # it once the node is back would swallow whatever changed meanwhile.
            # The row keeps its real kind, the diff says what it is.
            try:
                unknown = _is_presence_unknown(json.loads(ev['diff'] or '[]'))
            except Exception:
                unknown = False
            cid = ev['cluster_id']
            mgr = cluster_managers.get(cid)
            if mgr and not unknown:
                if ev['kind'] == 'firewall' and ev['scope'].startswith('guest/'):
                    # the baseline must be what the guest has now, not a read from earlier
                    with _fw_cache_lock:
                        _fw_guest_cache.pop((cid, ev['scope'].split('/', 1)[1]), None)
                state = _fetch_state(mgr, cid)
                for kind, scope, snap in state:
                    if kind == ev['kind'] and scope == ev['scope']:
                        _set_baseline(cid, kind, scope, snap, user)
                        break
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/drift/scan', methods=['POST'])
@require_auth(perms=['admin.audit'])
def manual_scan(cluster_id):
    """Trigger immediate scan. Body: {seed: bool} — if true and no baseline
    exists, write current state as baseline silently (initial setup)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    body = request.get_json(silent=True) or {}
    seed = bool(body.get('seed', False))
    if seed:
        _werr = _refuse_baseline_write()
        if _werr:
            return _werr
    _gone = _no_such_cluster(cluster_id)
    if _gone:
        return _gone
    return jsonify(_scan_cluster(cluster_id, autobaseline=seed))


@bp.route('/api/clusters/<cluster_id>/drift/baseline', methods=['POST'])
@require_auth(perms=['admin.audit'])
def reset_baseline(cluster_id):
    """Reset all baselines for the cluster from current state. Drops outstanding
    open events implicitly (they reference old baselines)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    _werr = _refuse_baseline_write()
    if _werr:
        return _werr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    user = _current_user()
    state = _fetch_state(mgr, cluster_id)
    # what this fetch could not read keeps its baseline: a guest list that timed out
    # would otherwise drop every guest baseline without a word
    fresh = {(kind, scope) for kind, scope, _ in state}
    baselines = _load_baselines(cluster_id)
    keep = {key for key in baselines if key not in fresh and _not_read(state, *key)}
    try:
        c = get_db().conn.cursor()
        if keep:
            c.executemany('DELETE FROM drift_baselines WHERE id=?',
                          [(bk['id'],) for key, bk in baselines.items() if key not in keep])
        else:
            c.execute('DELETE FROM drift_baselines WHERE cluster_id=?', (cluster_id,))
        # policy violations and incidents do not depend on a baseline
        c.execute("UPDATE drift_events SET status='superseded' WHERE cluster_id=? AND status='open' "
                  "AND category=?", (cluster_id, CATEGORY_DEVIATION))
        for kind, scope, snap in state:
            c.execute('''
                INSERT INTO drift_baselines (id, cluster_id, kind, scope, snapshot, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (uuid.uuid4().hex[:12], cluster_id, kind, scope,
                  json.dumps(snap), datetime.now().isoformat(), user))
        get_db().conn.commit()
        _refresh_last_scan(cluster_id, state, {(k, sc) for k, sc, _ in state} | keep)
        return jsonify({'ok': True, 'baselines': len(state), 'kept_unread': len(keep),
                        'unread': sorted({kind for kind, _ in keep})})
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/drift/events/<int:eid>/incident', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def confirm_incident(eid):
    """An admin confirms an event as an incident (body {incident: false} takes it back).
    Nothing sets this on its own: a deviation or a violation is an incident only because a
    person looked and said so."""
    body = request.get_json(silent=True) or {}
    flag = body.get('incident', True)
    if not isinstance(flag, bool):
        return jsonify({'error': 'incident must be true or false'}), 400
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM drift_events WHERE id=?', (eid,))
        ev = c.fetchone()
        if not ev:
            return jsonify({'error': 'not found'}), 404
        ok, err = check_cluster_access(ev['cluster_id'])
        if not ok:
            return jsonify({'error': 'not found'}), 404
        _cerr = require_unconfined(ev['cluster_id'])
        if _cerr:
            return _cerr
        if flag:
            # an incident is never planned, whatever the deviation was linked to before
            c.execute("UPDATE drift_events SET category=?, confirmed_by=?, confirmed_at=?, change_id=NULL "
                      "WHERE id=?",
                      (CATEGORY_INCIDENT, _current_user(), datetime.now().isoformat(), eid))
        else:
            if ev['category'] != CATEGORY_INCIDENT:
                return jsonify({'error': 'not an incident'}), 400
            back = CATEGORY_POLICY if str(ev['scope']).startswith('policy:') else CATEGORY_DEVIATION
            c.execute("UPDATE drift_events SET category=?, confirmed_by='', confirmed_at=NULL WHERE id=?",
                      (back, eid))
        get_db().conn.commit()
        try:
            from pegaprox.utils.audit import log_audit
            log_audit(_current_user(), 'drift.incident' if flag else 'drift.incident_withdrawn',
                      f"event {eid} ({ev['kind']} {ev['scope']})", cluster_id=ev['cluster_id'])
        except Exception as e:
            logging.debug(f"[drift] incident audit entry failed: {e}")
        return jsonify({'ok': True, 'category': CATEGORY_INCIDENT if flag else back})
    except Exception:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


def _policy_view(cluster_id):
    """The checks with the admin's choices and the result of the last scan. A check no scan
    has judged yet is 'not_checked'."""
    settings = _policy_settings(cluster_id)
    last = _last_scan.get(cluster_id)
    by_id = {r['id']: r for r in (last or {}).get('policy', [])}
    out = []
    for cid, spec in POLICY_CHECKS.items():
        res = dict(by_id.get(cid) or {'id': cid, 'kind': spec['kind'], 'severity': spec['severity'],
                                      'violations': []})
        res['enabled'] = settings[cid]['enabled']
        if 'allow' in spec:
            res['allow'] = settings[cid]['allow']
        # a result from before the admin switched the check on or off is not its result
        if not res['enabled']:
            res['status'] = 'disabled'
        elif by_id.get(cid, {}).get('status') in (None, 'disabled'):
            res['status'] = 'not_checked'
        out.append(res)
    return out, (last or {}).get('at')


@bp.route('/api/clusters/<cluster_id>/drift/policy', methods=['GET'])
@require_auth(perms=['admin.audit'])
def get_policy(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr: return _cerr
    _gone = _no_such_cluster(cluster_id)
    if _gone: return _gone
    checks, at = _policy_view(cluster_id)
    return jsonify({'checks': checks, 'last_scan_at': at})


@bp.route('/api/clusters/<cluster_id>/drift/policy', methods=['PUT'])
@require_auth(perms=['admin.audit'])
def set_policy(cluster_id):
    """Body {checks: {<id>: {enabled: bool, allow: [str]}}}. Switching a check on or
    changing what it allows is a change to the cluster's rules, so it needs cluster.config
    like rewriting a baseline."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    _cerr = require_unconfined(cluster_id)
    if _cerr: return _cerr
    _werr = _refuse_baseline_write()
    if _werr: return _werr
    _gone = _no_such_cluster(cluster_id)
    if _gone: return _gone
    body = request.get_json(silent=True)
    checks = body.get('checks') if isinstance(body, dict) else None
    if not isinstance(checks, dict) or not checks:
        return jsonify({'error': 'checks must be an object of check ids'}), 400
    current = _policy_settings(cluster_id)
    for cid, spec in checks.items():
        if cid not in POLICY_CHECKS:
            return jsonify({'error': f'unknown check: {cid}', 'checks': list(POLICY_CHECKS)}), 400
        if not isinstance(spec, dict):
            return jsonify({'error': f'{cid}: expected an object'}), 400
        if 'enabled' in spec:
            if not isinstance(spec['enabled'], bool):
                return jsonify({'error': f'{cid}: enabled must be true or false'}), 400
            current[cid]['enabled'] = spec['enabled']
        if 'allow' in spec:
            allow = spec['allow']
            if 'allow' not in POLICY_CHECKS[cid]:
                return jsonify({'error': f'{cid}: this check has no allow list'}), 400
            if (not isinstance(allow, list) or len(allow) > _POLICY_ALLOW_MAX
                    or not all(isinstance(a, str) and 0 < len(a.strip()) <= 128 for a in allow)):
                return jsonify({'error': f'{cid}: allow must be a list of up to {_POLICY_ALLOW_MAX} names'}), 400
            current[cid]['allow'] = sorted({a.strip() for a in allow})
    try:
        from pegaprox.core.recovery import _kv_write
        _kv_write(_policy_key(cluster_id), current)
    except Exception:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500
    checks_out, at = _policy_view(cluster_id)
    return jsonify({'ok': True, 'checks': checks_out, 'last_scan_at': at})
