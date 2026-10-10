# -*- coding: utf-8 -*-
"""What a migration would run into, guest by guest, before anything moves.

MK Oct 2026 - one preflight for a set of guests and a target: inside a cluster to a node
(or to the node each guest fits best), or to another cluster with its storage and bridge
maps. Every guest comes back ready, warning or blocked with its reasons; the set with its
totals, what the target nodes hold afterwards and the steps a run takes, in order, and
what an abort leaves behind. Warnings proceed. A block is something Proxmox refuses or a
rule of PegaProx forbids: the second kind (and a few that only might fail) the caller may
override, with confirmation and an audit entry, the first kind not.

The set is placed as a whole: the RAM, CPU and disk space each guest takes on its target
count for the guests after it, and the affinity rules are judged on where every guest
ends up, not on where the others are now.

It reads only, and little: per cluster the guest list and node status the live view
keeps, one storage list (/cluster/resources?type=storage, shared with the health score),
the HA resources and rules and the replication jobs once each; per target node its
network config (shared with the transfer network, core/transfer_net.py). Per guest only
its config, a few at a time. A read that fails makes a warning, never a block.

The single guest's migrate check (api/vms.py migrate-check) and the DR drill's mapping
checks (api/dr_drill.py) take their volume, bridge and storage rules from here.
"""

import logging
import re
import threading
import time

log = logging.getLogger(__name__)

READY, WARNING, BLOCKED, INFO = 'ready', 'warning', 'blocked', 'info'
GUESTS_MAX = 1000
CROSS_GUESTS_MAX = 100
MAP_MAX = 256
CONFIG_FANOUT = 8
READ_TTL = 30
# a node's network config: the transfer network keeps it ten minutes, a block wants it fresher
BRIDGE_MAX_AGE = 60
MEM_WARN_PCT = 90.0
CPU_WARN_PCT = 90.0
# cross-cluster: a live migration of more disk than this goes offline unless forced
LARGE_DISK_GB = 100

NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$')

# --- a guest's config --------------------------------------------------------------------

VOLUME_KEYS = {'qemu': re.compile(r'^(?:(?:ide|sata|scsi|virtio)\d+|efidisk0|tpmstate0|unused\d+)$'),
               'lxc': re.compile(r'^(?:rootfs|mp\d+|unused\d+)$')}
PATH_STORAGES = ('dir', 'nfs', 'cifs', 'glusterfs', 'cephfs', 'btrfs')
_SIZE_RE = re.compile(r'^(\d+(?:\.\d+)?)([KMGT]?)$', re.I)
_UNITS = {'': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4}


def snapshot_family(stype, fmt, vm_type):
    """How an offline migration carries the snapshots of a volume: 'zfs', 'btrfs' or 'qcow2',
    None where Proxmox cannot take them along (LVM-thin, a raw file, ...)."""
    if vm_type == 'qemu' and fmt in ('qcow2', 'vmdk') and stype in PATH_STORAGES:
        return 'qcow2'
    return {'zfspool': 'zfs', 'btrfs': 'btrfs'}.get(stype)


def size_bytes(text):
    """Bytes of a size= value ('32G', '512M', '1T'), 0 when it says none."""
    m = _SIZE_RE.match(str(text or '').strip())
    if not m:
        return 0
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()])


def _opts(val):
    parts = str(val).split(',')
    return parts, dict(p.split('=', 1) for p in parts[1:] if '=' in p)


def guest_volumes(cfg, vm_type):
    """The storage volumes of a guest config: [{key, storage, format, flagged_shared, size}]."""
    out = []
    keys = VOLUME_KEYS.get(vm_type) or VOLUME_KEYS['qemu']
    for key in sorted(cfg):
        val = cfg.get(key)
        if not keys.match(key) or not isinstance(val, str):
            continue
        parts, opts = _opts(val)
        vol = parts[0]
        if '=' in vol:
            name, _, rest = vol.partition('=')
            vol = rest if name in ('volume', 'file') else opts.get('volume', '')
        if opts.get('media') == 'cdrom' or vol.startswith('/') or ':' not in vol:
            continue
        storage, volname = vol.split(':', 1)
        base = volname.rsplit('/', 1)[-1]
        fmt = opts.get('format') or (base.rsplit('.', 1)[1] if '.' in base else 'raw')
        out.append({'key': key, 'storage': storage, 'format': fmt.lower(),
                    'flagged_shared': opts.get('shared') in ('1', 'on', 'yes', 'true'),
                    'size': size_bytes(opts.get('size'))})
    return out


def guest_nics(cfg):
    """[(net0, bridge)] of a guest config, in key order."""
    out = []
    for key in sorted(k for k in cfg if re.fullmatch(r'net\d+', k)):
        _parts, opts = _opts(cfg.get(key) or '')
        if opts.get('bridge'):
            out.append((key, opts['bridge']))
    return out


def cdrom_images(cfg):
    """[(ide2, storage, volid)] of the CD/DVD drives holding an image from a storage."""
    out = []
    for key in sorted(k for k in cfg if re.fullmatch(r'(?:ide|sata|scsi)\d+', k)):
        val = cfg.get(key)
        if not isinstance(val, str) or 'media=cdrom' not in val:
            continue
        vol = val.split(',')[0]
        if vol.startswith('file='):
            vol = vol[5:]
        if ':' in vol and 'cloudinit' not in vol and not vol.startswith('/'):
            out.append((key, vol.split(':', 1)[0], vol))
    return out


def local_devices(cfg, vm_type):
    """[(key, kind, mapped)] of what ties a guest to its node: passed-through PCI and USB
    devices (a mapping can exist on the target, a host address cannot), virtiofs shares and
    a container's bind mounts."""
    out = []
    for key in sorted(cfg):
        val = cfg.get(key)
        if not isinstance(val, str):
            continue
        if vm_type == 'qemu' and re.fullmatch(r'hostpci\d+', key):
            out.append((key, 'pci', 'mapping=' in val))
        elif vm_type == 'qemu' and re.fullmatch(r'usb\d+', key) and not val.startswith('spice'):
            out.append((key, 'usb', 'mapping=' in val))
        elif vm_type == 'qemu' and re.fullmatch(r'virtiofs\d+', key):
            out.append((key, 'virtiofs', True))
        elif vm_type == 'lxc' and re.fullmatch(r'mp\d+', key):
            parts, opts = _opts(val)
            if parts[0].startswith('/') and opts.get('shared') not in ('1', 'on', 'yes', 'true'):
                out.append((key, 'bind', False))
    return out


# --- Proxmox HA --------------------------------------------------------------------------

def _on(v):
    return str(v).strip().lower() in ('1', 'true', 'yes', 'on')


def node_names(spec):
    """'pve1:2,pve2' -> {'pve1', 'pve2'}, priorities dropped"""
    return {p.split(':')[0].strip() for p in str(spec or '').split(',') if p.strip()}


def _top_nodes(spec):
    """The nodes of the highest priority in 'pve1:2,pve2:2,pve3'"""
    prio = {}
    for p in str(spec or '').split(','):
        name, _, n = p.strip().partition(':')
        if name:
            try:
                prio[name.strip()] = int(n) if n else 0
            except ValueError:
                prio[name.strip()] = 0
    if not prio:
        return set()
    best = max(prio.values())
    return {k for k, v in prio.items() if v == best}


def _sid_vmid(sid):
    try:
        return int(str(sid).strip().split(':')[-1])
    except ValueError:
        return None


def restricted_groups(groups):
    """{group: nodes} of the restricted PVE 8 HA groups"""
    return {g.get('group'): node_names(g.get('nodes')) for g in groups or []
            if isinstance(g, dict) and _on(g.get('restricted'))}


def ha_node_limits(rules, groups, resources):
    """{vmid: nodes} Proxmox HA lets a guest run on: strict PVE 9 node-affinity rules (the
    others are preferences) and the restricted PVE 8 groups of `groups` ({group: nodes}).
    A guest missing from it is not limited. ha-manager refuses a target outside (#647)."""
    out = {}

    def _restrict(sid, nodes):
        vmid = _sid_vmid(sid)
        if vmid is not None:
            out[vmid] = out[vmid] & nodes if vmid in out else set(nodes)

    for rule in rules or []:
        if (isinstance(rule, dict) and str(rule.get('type') or '').lower() == 'node-affinity'
                and _on(rule.get('strict')) and not _on(rule.get('disable'))):
            for sid in str(rule.get('resources') or '').split(','):
                if sid.strip():
                    _restrict(sid, node_names(rule.get('nodes')))
    if groups:
        for res in resources or []:
            if isinstance(res, dict) and res.get('group') in groups:
                _restrict(res.get('sid'), groups[res['group']])
    return out


def _ha_preferences(rules, groups, resources):
    """{vmid: (nodes, name)} of the nodes HA prefers for a guest and moves it back to while
    failback is on: a non-strict node-affinity rule, or an unrestricted PVE 8 group."""
    out = {}
    for rule in rules or []:
        if (isinstance(rule, dict) and str(rule.get('type') or '').lower() == 'node-affinity'
                and not _on(rule.get('strict')) and not _on(rule.get('disable'))):
            for sid in str(rule.get('resources') or '').split(','):
                vmid = _sid_vmid(sid) if sid.strip() else None
                if vmid is not None:
                    out[vmid] = (_top_nodes(rule.get('nodes')), str(rule.get('rule') or ''))
    for res in resources or []:
        if not isinstance(res, dict) or not res.get('group'):
            continue
        g = (groups or {}).get(res['group'])
        vmid = _sid_vmid(res.get('sid'))
        if g and vmid is not None and not _on(g.get('restricted')) and not _on(g.get('nofailback')):
            out.setdefault(vmid, (_top_nodes(g.get('nodes')), str(res['group'])))
    return out


def _resource_affinity(rules):
    """[{'rule', 'positive', 'sids'}] of the enabled resource-affinity rules"""
    out = []
    for rule in rules or []:
        if (isinstance(rule, dict) and str(rule.get('type') or '').lower() == 'resource-affinity'
                and not _on(rule.get('disable'))):
            sids = [s.strip() for s in str(rule.get('resources') or '').split(',') if s.strip()]
            out.append({'rule': str(rule.get('rule') or ''), 'sids': sids,
                        'positive': str(rule.get('affinity') or '').lower() == 'positive'})
    return out


def sid_of(vmid, vm_type):
    return f"{'ct' if vm_type == 'lxc' else 'vm'}:{vmid}"


# --- shared with the DR drill ------------------------------------------------------------

def storage_mapping_problems(mapping, by_id, content='images'):
    """[(source, target, 'missing'|'content')] of a storage map against the storages of the
    target ({storage: row with 'content'})"""
    out = []
    for src, dst in (mapping or {}).items():
        row = by_id.get(dst)
        if row is None:
            out.append((src, dst, 'missing'))
        elif content not in str(row.get('content') or '').split(','):
            out.append((src, dst, 'content'))
    return out


def node_bridges(mgr, node):
    """The bridges of one node, None when its network config cannot be read"""
    from pegaprox.core import transfer_net
    entry = transfer_net.node_addresses(mgr, node, max_age=BRIDGE_MAX_AGE)
    if entry.get('error'):
        return None
    return set(entry.get('bridges') or ())


def sdn_vnets(mgr, cluster_id=None):
    """The SDN VNets of a cluster, set() where it has no SDN, None when they cannot be read"""
    def read():
        from pegaprox.background.alert_events import _get
        status, data = _get(mgr, '/cluster/sdn/vnets')
        if status in (404, 501):
            return set()
        if status != 200 or not isinstance(data, list):
            return None
        return {str(v.get('vnet') or v.get('name')) for v in data
                if isinstance(v, dict) and (v.get('vnet') or v.get('name'))}
    return _cached(mgr, cluster_id, 'vnets', read)


def cluster_bridges(mgr, cluster_id=None):
    """Every bridge of every node of a cluster and its VNets, what a network map may point at"""
    from pegaprox.utils.concurrent import run_per_node
    try:
        names = sorted((mgr.nodes or {}).keys())
    except Exception:
        names = []
    found = set()
    reads = run_per_node({n: (lambda nm: node_bridges(mgr, nm)) for n in names},
                         max_concurrent=CONFIG_FANOUT, timeout=max(30, len(names) // CONFIG_FANOUT * 10 + 30))
    for got in reads.values():
        found |= got or set()
    return found | (sdn_vnets(mgr, cluster_id) or set())


# --- reads, each at most once ------------------------------------------------------------

_cache = {}
_cache_lock = threading.Lock()


def _cached(mgr, cluster_id, key, read, ttl=READ_TTL):
    """A cluster-wide read shared for ttl seconds; one that failed is not kept"""
    k = (cluster_id or getattr(mgr, 'id', None) or '', id(mgr), key)
    now = time.time()
    with _cache_lock:
        hit = _cache.get(k)
    if hit and now - hit[0] < ttl:
        return hit[1]
    data = read()
    if data is not None:
        with _cache_lock:
            _cache[k] = (now, data)
            if len(_cache) > 512:
                for old in sorted(_cache, key=lambda x: _cache[x][0])[:128]:
                    _cache.pop(old, None)
    return data


def reset_for_tests():
    with _cache_lock:
        _cache.clear()


def _name(mgr, cluster_id):
    name = getattr(getattr(mgr, 'config', None), 'name', None)
    return name if isinstance(name, str) and name else cluster_id


def _setting(mgr, name):
    v = getattr(getattr(mgr, 'config', None), name, None)
    return v if isinstance(v, (int, float, str)) and not isinstance(v, bool) else None


def _int(v):
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        return 0
    try:
        return int(float(v))
    except ValueError:
        return 0


class _Side:
    """One cluster as the checks see it"""

    def __init__(self, cluster_id, mgr):
        self.id, self.mgr = cluster_id, mgr
        self.name = _name(mgr, cluster_id)
        self.unread = set()
        self._memo = {}

    def _once(self, key, fn, what=None):
        if key not in self._memo:
            try:
                self._memo[key] = fn()
            except Exception as e:
                log.debug(f"[PREFLIGHT] {self.id} {key}: {e}")
                self._memo[key] = None
            if self._memo[key] is None and what:
                self.unread.add(what)
        return self._memo[key]

    def guests(self):
        def read():
            rows = self.mgr.get_vm_resources(max_age=5)
            if not isinstance(rows, list):
                return None
            out = {}
            for g in rows:
                if isinstance(g, dict) and g.get('type') in ('qemu', 'lxc'):
                    try:
                        out[int(g.get('vmid'))] = g
                    except (TypeError, ValueError):
                        continue
            return out
        return self._once('guests', read, f'the guest list of {self.name}')

    def nodes(self):
        def read():
            ns = self.mgr.get_node_status()
            return ns if isinstance(ns, dict) and ns else None
        return self._once('nodes', read, f'the node status of {self.name}')

    def storages(self, node):
        def read():
            from pegaprox.api.clusters import cluster_storage_resources
            rows = cluster_storage_resources(self.id, self.mgr)
            if not isinstance(rows, list):
                return None
            out = {}
            for s in rows:
                if isinstance(s, dict) and s.get('storage') and s.get('node'):
                    out.setdefault(s['node'], {})[s['storage']] = s
            return out
        every = self._once('storages', read, f'the storages of {self.name}')
        return None if every is None else every.get(node, {})

    def bridges(self, node):
        own = self._once(('bridges', node), lambda: node_bridges(self.mgr, node),
                         f'the network of {node}')
        if own is None:
            return None, False
        vnets = self._once('vnets', lambda: sdn_vnets(self.mgr, self.id),
                           f'the SDN VNets of {self.name}')
        return own | (vnets or set()), vnets is not None

    def ha(self):
        def read():
            from pegaprox.background.alert_events import _get
            st, resources = _get(self.mgr, '/cluster/ha/resources')
            if st != 200 or not isinstance(resources, list):
                return None
            st, rules = _get(self.mgr, '/cluster/ha/rules')
            if st in (404, 501):
                rules = []
            elif st != 200 or not isinstance(rules, list):
                return None
            groups = []
            if any(isinstance(r, dict) and r.get('group') for r in resources):
                st, groups = _get(self.mgr, '/cluster/ha/groups')
                groups = groups if st == 200 and isinstance(groups, list) else []
            by_group = {g.get('group'): g for g in groups if isinstance(g, dict)}
            return {'managed': {_sid_vmid(r.get('sid')): r for r in resources if isinstance(r, dict)},
                    'limits': ha_node_limits(rules, restricted_groups(groups), resources),
                    'prefer': _ha_preferences(rules, by_group, resources),
                    'affinity': _resource_affinity(rules)}
        return self._once('ha', lambda: _cached(self.mgr, self.id, 'ha', read),
                          f'the HA resources and rules of {self.name}')

    def replication(self):
        def read():
            from pegaprox.background.alert_events import _get
            st, jobs = _get(self.mgr, '/cluster/replication')
            return [j for j in jobs if isinstance(j, dict)] if st == 200 and isinstance(jobs, list) else None
        return self._once('replication', lambda: _cached(self.mgr, self.id, 'replication', read),
                          f'the replication jobs of {self.name}')

    def jobs_of(self, vmid):
        return [j for j in (self.replication() or []) if str(j.get('guest')) == str(vmid) and not _on(j.get('disable'))]

    def configs(self, guests):
        """{vmid: config or None} of these guest rows, CONFIG_FANOUT at a time"""
        from pegaprox.utils.concurrent import run_per_node
        if not guests:
            return {}

        def one(g):
            cfg = self.mgr._guest_config(g.get('node'), int(g['vmid']), 'lxc' if g.get('type') == 'lxc' else 'qemu')
            return cfg if isinstance(cfg, dict) else None
        reads = {int(g['vmid']): (lambda _k, g=g: one(g)) for g in guests}
        got = run_per_node(reads, max_concurrent=CONFIG_FANOUT,
                           timeout=max(30, len(reads) // CONFIG_FANOUT * 2 + 30))
        if any(v is None for v in got.values()):
            self.unread.add(f'guest configurations on {self.name}')
        return got

    def backups(self):
        # None: the scan has not run yet; asking started it
        return self._once('backups', lambda: backup_times(self.id, self.mgr),
                          f'backup ages on {self.name} (being read now)')


def backup_times(cluster_id, mgr):
    """{vmid: epoch of its newest backup, 0 for none} of the scan the VM list and the
    Prometheus exporter share; None while there is none, and asking starts one."""
    from pegaprox.api.metrics_exporter import _last_backups
    return _last_backups(cluster_id, mgr, time.time())


# --- the verdict of one guest ------------------------------------------------------------

class _Guest:
    def __init__(self, vmid, g, kind=None):
        g = g or {}
        self.vmid, self.g = vmid, g
        self.kind = g.get('type') or kind or 'qemu'
        self.node = g.get('node') or ''
        self.running = g.get('status') == 'running'
        self.cfg = None
        self.row = {'vmid': vmid, 'name': g.get('name') or '', 'type': self.kind, 'node': self.node,
                    'status': g.get('status') or 'unknown', 'to': None, 'verdict': READY,
                    'overridable': False, 'overridden': False, 'reasons': [], 'abort': ''}

    def add(self, level, code, text, overridable=False):
        reason = {'level': level, 'code': code, 'text': text}
        if level == BLOCKED:
            reason['overridable'] = bool(overridable)
        self.row['reasons'].append(reason)

    def block(self, code, text, overridable=False):
        self.add(BLOCKED, code, text, overridable)

    def warn(self, code, text):
        self.add(WARNING, code, text)

    def info(self, code, text):
        self.add(INFO, code, text)

    @property
    def blocked(self):
        return any(r['level'] == BLOCKED for r in self.row['reasons'])

    @property
    def hard_blocked(self):
        return any(r['level'] == BLOCKED and not r['overridable'] for r in self.row['reasons'])

    def label(self):
        return f"{self.vmid} ({self.row['name']})" if self.row['name'] else str(self.vmid)

    def finish(self, override=()):
        levels = {r['level'] for r in self.row['reasons']}
        blocked = BLOCKED in levels
        self.row['verdict'] = BLOCKED if blocked else WARNING if WARNING in levels else READY
        self.row['overridable'] = blocked and not self.hard_blocked
        self.row['overridden'] = self.row['overridable'] and self.vmid in override
        return self.row


def block_note(row):
    """What a run says of a guest the preflight blocks"""
    return '; '.join(r['text'] for r in row['reasons'] if r['level'] == BLOCKED)[:500]


def moving(row):
    return row['verdict'] != BLOCKED or row.get('overridden')


def _gb(n):
    return f"{n / 1024 ** 3:.1f} GB"


# --- the checks ----------------------------------------------------------------------------

class _Sim:
    """What the target nodes hold while the set is placed on them, guest after guest. A fork
    tries a guest on a node without touching what it was forked from."""

    def __init__(self, side, parent=None, scoped=False):
        self.side, self.parent, self.mem, self.disk = side, parent, {}, {}
        # a caller confined to some guests reads no figures of a node
        self.scoped = parent.scoped if parent is not None else scoped

    def fork(self):
        return _Sim(self.side, self)

    def node(self, name):
        if name not in self.mem:
            if self.parent is not None:
                base = self.parent.node(name)
                self.mem[name] = dict(base) if base else None
                return self.mem[name]
            d = (self.side.nodes() or {}).get(name) or {}
            total = _int(d.get('mem_total'))
            cpus = _int((d.get('cpuinfo') or {}).get('cpus')) if isinstance(d.get('cpuinfo'), dict) else 0
            pct = d.get('cpu_percent') if isinstance(d.get('cpu_percent'), (int, float)) else 0
            self.mem[name] = {'node': name, 'mem_total': total, 'mem_now': _int(d.get('mem_used')),
                              'mem_used': _int(d.get('mem_used')), 'cpus': cpus,
                              'cpu_now': cpus * pct / 100.0, 'cpu_used': cpus * pct / 100.0,
                              'guests': 0} if total > 0 else None
        return self.mem[name]

    def take(self, gv, t):
        """Count a running guest on t; a block when it does not fit"""
        if not gv.running:
            return
        n = self.node(t)
        if n is None:
            gv.warn('memory_unknown', f"The memory of {t} is not known: whether it fits is not checked")
            return
        need = _int(gv.g.get('maxmem'))
        after = n['mem_used'] + need
        if after > n['mem_total']:
            figures = '' if self.scoped else f"{_gb(after)} of {_gb(n['mem_total'])}, "
            gv.block('memory_short', f"{t} runs out of memory with it ({figures}counting the guests before it "
                                     f"in this set)", overridable=True)
            return
        n['mem_used'] = after
        n['guests'] += 1
        pct = after * 100.0 / n['mem_total']
        if pct > MEM_WARN_PCT:
            gv.warn('memory_tight', f"{t} is nearly out of memory with it" if self.scoped
                    else f"{t} is at {pct:.0f}% memory with it")
        vcpus = _int(gv.g.get('maxcpu'))
        if n['cpus'] and vcpus:
            n['cpu_used'] += vcpus * float(gv.g.get('cpu') or 0) if isinstance(gv.g.get('cpu'), (int, float)) else 0
            cpu_pct = n['cpu_used'] * 100.0 / n['cpus']
            if cpu_pct > CPU_WARN_PCT:
                gv.warn('cpu_busy', f"{t} is nearly out of CPU with it" if self.scoped
                        else f"{t} is at {cpu_pct:.0f}% CPU with it")

    def space(self, gv, t, storage, need, free):
        """Count need bytes on storage of t; False when they do not fit"""
        if free is None or not need:
            return True
        key = (t, storage)
        if key not in self.disk:
            self.disk[key] = self.parent.disk.get(key, free) if self.parent is not None else free
        left = self.disk[key]
        if need > left:
            return False
        self.disk[key] = left - need
        return True

    def view(self):
        out = []
        for n in sorted(k for k, v in self.mem.items() if v):
            v = self.mem[n]
            out.append({'node': n, 'guests': v['guests'], 'mem_total': v['mem_total'],
                        'mem_pct_now': round(v['mem_now'] * 100.0 / v['mem_total'], 1),
                        'mem_pct_after': round(v['mem_used'] * 100.0 / v['mem_total'], 1),
                        'cpus': v['cpus'],
                        'cpu_pct_after': round(v['cpu_used'] * 100.0 / v['cpus'], 1) if v['cpus'] else None})
        return out


def _free(row):
    if not isinstance(row, dict):
        return None
    total, used = _int(row.get('maxdisk')), _int(row.get('disk'))
    return max(0, total - used) if total else None


def _cpu_checks(gv, src_info, tgt_info, t, baseline, live, tgt_cpus):
    from pegaprox.core.manager import PegaProxManager
    if gv.kind != 'qemu':
        return
    vcpus = _int(gv.g.get('maxcpu'))
    if gv.running and vcpus and tgt_cpus and vcpus > tgt_cpus:
        gv.block('vcpus', f"It has {vcpus} vCPUs and {t} has {tgt_cpus}: it cannot run there")
    if gv.cfg is None:
        return
    vm_cpu = PegaProxManager.cpu_type_of(gv.cfg)
    verdict = PegaProxManager.cpu_verdict(vm_cpu, src_info, tgt_info, None)
    if live and gv.running:
        if not verdict.get('compatible', True):
            gv.block('cpu_vendor', f"CPU type {vm_cpu}: {verdict.get('reason')} - it cannot move live to {t}")
        elif verdict.get('warning'):
            gv.warn('cpu_model', verdict['warning'])
    if baseline:
        policy = PegaProxManager.cpu_verdict(vm_cpu, {}, {}, baseline)
        if not policy.get('compatible', True):
            gv.warn('cpu_baseline', f"{policy.get('reason')}: the balancer will not move it")


def _device_checks(gv, live):
    for key, kind, mapped in local_devices(gv.cfg, gv.kind):
        if kind == 'bind':
            gv.block('bind_mount', f"{key} is a bind mount of a host directory: Proxmox does not migrate it "
                                   f"(mark it shared if the path exists on every node)")
        elif kind == 'virtiofs':
            if live and gv.running:
                gv.block('virtiofs_live', f"{key} is a virtiofs share: it does not migrate live - shut the VM down first")
            else:
                gv.warn('virtiofs', f"{key} is a virtiofs share: its directory mapping has to cover the target node")
        elif not mapped:
            gv.block('local_device', f"{key} passes a {kind.upper()} device of {gv.node} through: Proxmox does not "
                                     f"migrate it - use a resource mapping or remove it")
        else:
            gv.warn('mapped_device', f"{key} uses a resource mapping: it has to cover the target node")


def _backup_check(gv, side):
    if gv.g.get('template'):
        return
    times = side.backups()
    if times is None:
        return
    ts = _int(times.get(gv.vmid))
    sla = _int(_setting(side.mgr, 'backup_sla_max_age_hours'))
    if not ts:
        gv.warn('no_backup', 'No backup of it was found')
        return
    age_h = max(0.0, (time.time() - ts) / 3600.0)
    if sla and age_h > sla:
        gv.warn('backup_old', f"Its newest backup is {age_h:.0f} h old, older than the {sla} h of the "
                              f"cluster's backup SLA")
    else:
        gv.info('backup_recent', f"Newest backup {age_h:.0f} h old")


def _frame(kind, side, scoped):
    return {'kind': kind, 'supported': True, 'cluster_id': side.id, 'cluster': side.name,
            'checked_at': int(time.time()), 'scoped': bool(scoped), 'guests': [], 'totals': {},
            'capacity': [], 'steps': [], 'abort': [], 'unread': []}


def _close(out, rows, sides, sim=None, scoped=False):
    out['guests'] = rows
    t = {'guests': len(rows), READY: 0, WARNING: 0, BLOCKED: 0, 'overridable': 0, 'overridden': 0}
    for r in rows:
        t[r['verdict']] += 1
        t['overridable'] += 1 if r['overridable'] else 0
        t['overridden'] += 1 if r['overridden'] else 0
    t['moving'] = sum(1 for r in rows if moving(r))
    out['totals'] = t
    out['unread'] = sorted(set().union(*(s.unread for s in sides)))
    if sim is not None and not scoped:
        out['capacity'] = sim.view()
    return out


# --- inside a cluster ----------------------------------------------------------------------

_HOW = {'sequential': 'One at a time: the next starts once the migration before it has ended',
        'parallel': '{n} at a time: the next starts once one of them has ended',
        'all': 'All at once: every migration starts right away and PegaProx does not wait for them',
        None: 'All at once: every migration starts right away'}


def intra(cluster_id, mgr, vmids, target=None, online=True, with_local_disks=False, mode=None,
          parallel=2, busy=(), scoped=False, override=(), backups=True):
    """The preflight of a migration of `vmids` inside one cluster, to `target` or (None) each
    to the node it fits best. busy: the guests another bulk run moves; scoped: the caller is
    confined to some guests (the answer names no others and no node figures)."""
    side = _Side(cluster_id, mgr)
    out = _frame('intra', side, scoped)
    out.update(target=target, online=bool(online), with_local_disks=bool(with_local_disks), mode=mode,
               parallel=parallel if mode == 'parallel' else None)
    override = set(override or ())
    guests = side.guests()
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        out['supported'] = False
        rows = []
        for vmid in vmids:
            gv = _Guest(vmid, (guests or {}).get(vmid))
            gv.info('unsupported', 'PegaProx checks migrations on Proxmox clusters only')
            gv.row['to'] = target
            rows.append(gv.finish())
        out['steps'] = _intra_steps(rows, target, online, mode, parallel)
        return _close(out, rows, [side])

    nodes = side.nodes() or {}
    sim = _Sim(side, scoped=scoped)
    todo, all_gv = [], []
    for vmid in vmids:
        g = (guests or {}).get(vmid)
        gv = _Guest(vmid, g)
        all_gv.append(gv)
        if g is None:
            if guests is None:
                gv.warn('guests_unread', 'The guest list of the cluster could not be read: nothing is checked')
            else:
                gv.block('not_found', 'Not on this cluster')
            continue
        if target and gv.node == target:
            gv.block('already_there', f'Already on {target}')
        elif vmid in busy:
            gv.block('busy', 'Another bulk migration moves it already')
        else:
            todo.append(gv)
    configs = side.configs([gv.g for gv in todo])
    for gv in todo:
        gv.cfg = configs.get(gv.vmid)

    pool = None
    if not target:
        try:
            pool = mgr.placement_pool(nodes)
        except Exception:
            pool = None
        if not isinstance(pool, dict):
            pool = {n: d for n, d in nodes.items() if isinstance(d, dict) and d.get('status') == 'online'}
        if todo:
            # every node of the pool is a candidate: their network configs in one go
            from pegaprox.utils.concurrent import run_per_node
            run_per_node({n: (lambda nm: side.bridges(nm)) for n in pool}, max_concurrent=CONFIG_FANOUT,
                         timeout=max(30, len(pool) // CONFIG_FANOUT * 10 + 30))

    for gv in todo:
        t = target or _pick(side, sim, gv, pool, online, with_local_disks)
        gv.row['to'] = t
        if not t:
            gv.block('no_node', 'No node can take it: on every node that could, one of the checks blocks it')
            continue
        _intra_checks(side, sim, gv, t, online, with_local_disks)

    # where everyone is once the set moved, for the affinity rules of PegaProx and of HA
    planned = {str(v): (g.get('node')) for v, g in (guests or {}).items()}
    for gv in todo:
        if gv.row['to'] and not gv.blocked:
            planned[str(gv.vmid)] = gv.row['to']
    _affinity_checks(side, todo, planned, scoped)
    for gv in todo:
        if gv.row['to']:
            _intra_after(side, gv, gv.row['to'], backups)

    rows = [gv.finish(override) for gv in all_gv]
    out['steps'] = _intra_steps(rows, target, online, mode, parallel)
    out['abort'] = ['Cancelling the run starts no further guest: migrations already running finish, '
                    'the guests not started yet stay where they are.']
    return _close(out, rows, [side], sim, scoped)


def _pick(side, sim, gv, pool, online, with_local_disks):
    """The node of the pool a guest fits best on: none of the checks blocks it there, least
    memory in use after it. A scratch verdict per node, the real one is made afterwards."""
    best = None
    for t in sorted(n for n in (pool or {}) if n != gv.node):
        trial = _Guest(gv.vmid, gv.g)
        trial.cfg = gv.cfg
        scratch = sim.fork()
        _intra_checks(side, scratch, trial, t, online, with_local_disks)
        if trial.blocked:
            continue
        n = scratch.node(t)
        load = n['mem_used'] * 1.0 / n['mem_total'] if n else 1.0
        if best is None or load < best[0]:
            best = (load, t)
    return best[1] if best else None


def _intra_checks(side, sim, gv, t, online, with_local_disks):
    nodes = side.nodes() or {}
    if nodes and t not in nodes:
        gv.block('target_unknown', f'{t} is no node of this cluster')
        return
    tinfo = nodes.get(t) or {}
    if nodes and (tinfo.get('offline') or tinfo.get('status', 'online') != 'online'):
        gv.block('target_offline', f'{t} is not online')
        return
    if tinfo.get('maintenance_mode'):
        gv.warn('target_maintenance', f'{t} is in maintenance: its evacuation may move it away again')
    _busy_checks(gv)
    live = bool(online)
    if gv.running and not live:
        if gv.kind == 'qemu':
            gv.block('running_offline', 'It runs: Proxmox moves a running VM only live - pick live '
                                        'migration or shut it down first')
        else:
            gv.block('running_offline', 'It runs: a container moves in restart mode only - pick live '
                                        'migration or shut it down first')
    elif gv.running and gv.kind == 'lxc':
        gv.warn('ct_restart', f"It is a container: it stops on {gv.node} and starts again on {t}")
    _cpu_checks(gv, (nodes.get(gv.node) or {}).get('cpuinfo') or {}, tinfo.get('cpuinfo') or {}, t,
                _setting(side.mgr, 'cpu_baseline'), live,
                _int((tinfo.get('cpuinfo') or {}).get('cpus')) if isinstance(tinfo.get('cpuinfo'), dict) else 0)
    ha = side.ha()
    if ha:
        allowed = ha['limits'].get(gv.vmid)
        if allowed is not None and t not in allowed:
            gv.block('ha_node_rule', f"Proxmox HA keeps it on {', '.join(sorted(allowed)) or 'no node'} "
                                     f"(strict node affinity or a restricted group)")
    if gv.cfg is None:
        gv.warn('config_unread', 'Its configuration could not be read: disks, networks and devices are not checked')
        if not gv.blocked:
            sim.take(gv, t)
        return

    src_st, tgt_st = side.storages(gv.node), side.storages(t)
    local = []
    for vol in guest_volumes(gv.cfg, gv.kind):
        if tgt_st is not None:
            row = tgt_st.get(vol['storage'])
            if row is None or row.get('status') != 'available':
                gv.block('storage_missing', f"{vol['key']} is on storage {vol['storage']}, which {t} does not have")
                continue
        src = (src_st or {}).get(vol['storage'])
        # a storage this node does not list cannot be told apart, so it is not counted as local
        if src is None or vol['flagged_shared'] or src.get('shared'):
            continue
        local.append(dict(vol, type=str(src.get('plugintype') or '')))
    if tgt_st is None:
        gv.warn('storage_unread', f'The storages of {t} could not be read: not checked')
    if local:
        names = ', '.join(f"{v['key']} on {v['storage']}" for v in local[:4])
        if gv.running and live and gv.kind == 'qemu' and not with_local_disks:
            gv.block('local_disks', f"It has local disks ({names}): a live migration needs 'migrate local disks'")
        else:
            gv.info('local_disks', f"Its local disks are copied to {t}: {names}")
        for storage in sorted({v['storage'] for v in local}):
            need = sum(v['size'] for v in local if v['storage'] == storage)
            if tgt_st is not None and not sim.space(gv, t, storage, need, _free(tgt_st.get(storage))):
                gv.block('storage_full', f"Storage {storage} on {t} has less room than its {_gb(need)} "
                                         f"(counting the guests before it in this set)", overridable=True)
        if 'parent' in gv.cfg:
            repl = {str(j.get('target')) for j in side.jobs_of(gv.vmid)}
            if gv.running and live and gv.kind == 'qemu':
                if not (all(v['type'] == 'zfspool' for v in local) and t in repl):
                    gv.block('snapshots_live', f"It has snapshots and local disks ({names}): Proxmox does not move "
                                               f"those while it runs - shut it down or remove the snapshots")
            else:
                stuck = [v for v in local if not snapshot_family(v['type'], v['format'], gv.kind)]
                if stuck:
                    gv.block('snapshots_storage', f"It has snapshots on local storage that cannot carry them along "
                                                  f"({', '.join(v['key'] + ' on ' + v['storage'] for v in stuck[:4])})"
                                                  f": remove the snapshots first")
    for key, storage, _vol in cdrom_images(gv.cfg):
        src = (src_st or {}).get(storage)
        if src is not None and not src.get('shared'):
            gv.block('local_cdrom', f"{key} holds an image on local storage {storage} - eject it first")
    bridges, vnets_known = side.bridges(t)
    nics = guest_nics(gv.cfg)
    if nics and bridges is None:
        gv.warn('network_unread', f'The network of {t} could not be read: bridges not checked')
    elif nics:
        missing = [(k, b) for k, b in nics if b not in bridges]
        for key, bridge in missing:
            if not vnets_known:
                gv.warn('bridge_unknown', f"{key} uses {bridge}: {t} has no such bridge, and the SDN VNets "
                                          f"could not be read")
            elif gv.running:
                gv.block('bridge_missing', f"{key} uses bridge {bridge}, which {t} does not have: it cannot run there")
            else:
                gv.warn('bridge_missing', f"{key} uses bridge {bridge}, which {t} does not have: it will not start there")
    _device_checks(gv, live)
    if not gv.blocked:
        sim.take(gv, t)


def _busy_checks(gv):
    lock = gv.g.get('lock') or (gv.cfg or {}).get('lock')
    if lock:
        gv.block('locked', f"It is locked ({lock}): Proxmox migrates no locked guest")
    if str(gv.g.get('hastate') or '') in ('migrate', 'relocate'):
        gv.block('ha_moving', 'Proxmox HA moves it right now')


def _affinity_checks(side, todo, planned, scoped):
    """The affinity rules of PegaProx and the resource affinity of Proxmox HA, on where every
    guest ends up"""
    moving_gv = [gv for gv in todo if gv.row['to'] and not gv.hard_blocked]
    if not moving_gv:
        return
    from pegaprox.api import history
    try:
        rules = history.load_affinity_rules() or {'rules': []}
    except Exception:
        rules = {'rules': []}
    ruled = set()
    for rule in rules.get('rules', []):
        if rule.get('cluster_id') == side.id and rule.get('enabled', True):
            ruled.update(str(v) for v in (rule.get('vm_ids') or rule.get('vms') or []))
    for gv in moving_gv:
        if str(gv.vmid) not in ruled:
            continue
        try:
            aff = history.check_affinity_violation(side.id, gv.vmid, gv.row['to'], vm_nodes=planned, config=rules)
        except Exception as e:
            log.debug(f"[PREFLIGHT] affinity of {gv.vmid}: {e}")
            gv.warn('affinity_unread', 'The affinity rules could not be checked')
            continue
        if not isinstance(aff, dict) or aff.get('violation') is not True:
            continue
        if aff.get('enforce'):
            gv.block('affinity', f"Affinity rule '{aff.get('rule')}' keeps it off {gv.row['to']}", overridable=True)
        else:
            gv.warn('affinity_soft', f"Affinity rule '{aff.get('rule')}' (not enforced)"
                                     + ('' if scoped else f": {aff.get('message')}"))
    ha = side.ha()
    if not ha or not ha['affinity']:
        return
    for gv in moving_gv:
        sid = sid_of(gv.vmid, gv.kind)
        for rule in ha['affinity']:
            if sid not in rule['sids']:
                continue
            others = [s for s in rule['sids'] if s != sid]
            where = {s: planned.get(str(_sid_vmid(s))) for s in others}
            who = '' if scoped else f" ({', '.join(others)})"
            if rule['positive']:
                apart = [s for s, n in where.items() if n and n != gv.row['to']]
                if apart:
                    gv.warn('ha_together', f"HA rule {rule['rule']} keeps it together with other guests{who}: "
                                           f"Proxmox HA moves them to {gv.row['to']} as well")
            elif any(n == gv.row['to'] for n in where.values()):
                gv.block('ha_apart', f"HA rule {rule['rule']} keeps it apart from other guests{who} that are "
                                     f"on {gv.row['to']} then")


def _intra_after(side, gv, t, backups):
    """What does not decide whether it moves: HA, replication, backups, and the abort"""
    ha = side.ha()
    managed = bool(ha) and gv.vmid in ha['managed']
    if managed:
        gv.info('ha_managed', 'Proxmox HA manages it: PegaProx hands the move to the HA manager')
        pref = ha['prefer'].get(gv.vmid)
        if pref and pref[0] and t not in pref[0]:
            gv.warn('ha_prefers', f"Proxmox HA prefers {', '.join(sorted(pref[0]))} for it ({pref[1]}) and "
                                  f"may move it back")
    for job in side.jobs_of(gv.vmid):
        if str(job.get('target')) == t:
            gv.info('replicated_to_target', f"Replication job {job.get('id')} has it on {t} already: only what "
                                            f"changed since its last run moves, and Proxmox turns the job round")
        else:
            gv.info('replication_follows', f"Replication job {job.get('id')} to {job.get('target')} runs from "
                                           f"{t} afterwards")
    if backups:
        _backup_check(gv, side)
    if managed:
        gv.row['abort'] = (f"An aborted move leaves it to Proxmox HA: it stays on {gv.node} or HA "
                           f"tries again")
    elif gv.running and gv.kind == 'qemu':
        gv.row['abort'] = (f"Aborted, it keeps running on {gv.node}; Proxmox removes what it copied "
                           f"to {t} so far")
    elif gv.running:
        gv.row['abort'] = (f"Aborted, it starts again on {gv.node}; volumes already copied to {t} can "
                           f"stay behind there as unused volumes")
    else:
        gv.row['abort'] = (f"Aborted, it stays on {gv.node}; volumes already copied to {t} can stay "
                           f"behind there as unused volumes")


def _how_guest(row, online):
    kind = row['type']
    if row['status'] != 'running':
        how = 'offline'
    elif kind == 'lxc':
        how = 'restart mode'
    else:
        how = 'live' if online else 'offline'
    if any(r['code'] == 'ha_managed' for r in row['reasons']):
        how += ', through Proxmox HA'
    if any(r['code'] == 'local_disks' and r['level'] == INFO for r in row['reasons']):
        how += ', with its local disks'
    return how


def _intra_steps(rows, target, online, mode, parallel):
    steps = [{'kind': 'run', 'text': _HOW.get(mode, _HOW[None]).format(n=parallel)}]
    if mode is not None:
        steps.append({'kind': 'recheck', 'text': 'Right before each guest starts: where it is now, and '
                                                 'whether whoever started the run may still move it'})
    for r in rows:
        if moving(r):
            text = f"Migrate {r['vmid']}{' (' + r['name'] + ')' if r['name'] else ''} from {r['node']} to " \
                   f"{r['to'] or target}, {_how_guest(r, online)}"
            if r['overridden']:
                text += ' - a block overridden'
            steps.append({'kind': 'migrate', 'vmid': r['vmid'], 'text': text})
    for r in rows:
        if not moving(r):
            steps.append({'kind': 'skip', 'vmid': r['vmid'],
                          'text': f"Skip {r['vmid']}{' (' + r['name'] + ')' if r['name'] else ''}: {block_note(r)}"})
    return steps


# --- to another cluster --------------------------------------------------------------------

def cross_online(config, online, force_online):
    """(online, total disk GB, warning) of a cross-cluster migration: a live one of more
    than LARGE_DISK_GB disk goes offline unless forced. MK: Proxmox WebSocket tickets have
    an internal timeout (~5 min); large disk migrations take longer than this, causing 401
    errors during RAM sync. Math: 100GB in 5 min = 333 MB/s = ~2.7 Gbit/s sustained, which
    most cross-cluster links can't sustain."""
    total_gb = 0.0
    for key, value in (config or {}).items():
        if key.startswith(('scsi', 'virtio', 'sata', 'ide', 'efidisk', 'tpmstate')) and 'size' in str(value):
            m = re.search(r'size=(\d+)([GMT])', str(value))
            if m:
                total_gb += int(m.group(1)) * {'G': 1, 'T': 1024, 'M': 1 / 1024}[m.group(2)]
    warning = None
    if total_gb > LARGE_DISK_GB and online:
        required_speed_mbps = (total_gb * 1024) / 300
        if not force_online:
            warning = (f"VM has {total_gb:.0f}GB disk. Would need {required_speed_mbps:.0f} MB/s "
                       f"({required_speed_mbps * 8 / 1000:.1f} Gbit/s) to complete in 5 min. Automatically "
                       f"using offline migration.")
            online = False
        else:
            warning = (f"VM has {total_gb:.0f}GB disk with forced online migration. Need "
                       f"{required_speed_mbps:.0f} MB/s sustained to avoid timeout. Migration may fail with "
                       f"'401 Unauthorized'.")
    return online, total_gb, warning


def map_arg(value, name):
    """A storage or bridge map of a request body: (dict or None, error)"""
    if value is None or value == {}:
        return None, None
    if not isinstance(value, dict) or len(value) > MAP_MAX:
        return None, f'{name} is an object of at most {MAP_MAX} names'
    for k, v in value.items():
        if not (isinstance(k, str) and isinstance(v, str) and NAME_RE.match(k) and NAME_RE.match(v)):
            return None, f'{name} maps names to names'
    return dict(value), None


def cross(src_id, src_mgr, tgt_id, tgt_mgr, vmids, target_node, storage_map=None, target_storage=None,
          bridge_map=None, target_bridge=None, target_vmid=None, online=True, force_online=False,
          delete_source=True, may_delete=True, user=None, vm_type=None, scoped=False, override=(),
          backups=True):
    """The preflight of a remote migration of `vmids` to `target_node` of another cluster.
    may_delete: the caller may remove the source guests; user: the authz user, for the
    tenant's VMID range and quota at the target."""
    src, tgt = _Side(src_id, src_mgr), _Side(tgt_id, tgt_mgr)
    out = _frame('cross', src, scoped)
    out.update(target_cluster_id=tgt_id, target_cluster=tgt.name, target=target_node, online=bool(online),
               delete_source=bool(delete_source), transfer_network=None)
    override = set(override or ())
    guests = src.guests()
    all_gv, todo = [], []
    for vmid in vmids:
        g = (guests or {}).get(vmid)
        gv = _Guest(vmid, g, vm_type)
        all_gv.append(gv)
        gv.row['to'] = target_node
        if g is None:
            if guests is None:
                gv.warn('guests_unread', f'The guest list of {src.name} could not be read: it is not checked there')
                todo.append(gv)
            else:
                gv.block('not_found', f'Not on {src.name}')
            continue
        todo.append(gv)

    target_ok = True
    if getattr(tgt_mgr, 'cluster_type', 'proxmox') != 'proxmox' or getattr(src_mgr, 'cluster_type', 'proxmox') != 'proxmox':
        for gv in all_gv:
            gv.block('unsupported', 'A remote migration runs between Proxmox clusters only')
        target_ok = False
    elif getattr(tgt_mgr, 'is_connected', True) is False:
        for gv in todo:
            gv.block('target_offline', f'{tgt.name} is not connected')
        target_ok = False
    tnodes = (tgt.nodes() or {}) if target_ok else {}
    tinfo = tnodes.get(target_node) or {}
    if target_ok and tnodes and target_node not in tnodes:
        for gv in todo:
            gv.block('target_unknown', f'{target_node} is no node of {tgt.name}')
        target_ok = False
    elif target_ok and tnodes and (tinfo.get('offline') or tinfo.get('status', 'online') != 'online'):
        for gv in todo:
            gv.block('target_offline', f'{target_node} is not online')
        target_ok = False

    configs = src.configs([gv.g for gv in todo if gv.g])
    for gv in todo:
        gv.cfg = configs.get(gv.vmid)

    route = None
    if target_ok:
        from pegaprox.core import transfer_net
        try:
            route = transfer_net.migration_route(tgt_mgr, target_node)
        except Exception as e:
            log.debug(f"[PREFLIGHT] transfer route to {tgt_id}/{target_node}: {e}")
        out['transfer_network'] = transfer_net.describe(route) if route else None

    sim = _Sim(tgt, scoped=scoped)
    taken = tgt.guests() if target_ok else None
    for gv in todo:
        if target_ok:
            _cross_checks(src, tgt, sim, gv, target_node, storage_map, target_storage, bridge_map, target_bridge,
                          target_vmid if len(vmids) == 1 else None, online, force_online, delete_source,
                          may_delete, user, taken, route)
    if target_ok:
        _quota_check(src, tgt, [gv for gv in todo if not gv.hard_blocked], user, delete_source)
    for gv in todo:
        if backups and gv.g:
            _backup_check(gv, src)
        tv = (target_vmid if len(vmids) == 1 else None) or gv.vmid
        gv.row['target_vmid'] = tv
        gv.row['abort'] = (f"Aborted, it stays on {src.name}; a half-copied guest {tv} on {tgt.name} has to "
                           f"be removed there, and PegaProx removes its temporary token")

    rows = [gv.finish(override) for gv in all_gv]
    out['steps'] = _cross_steps(rows, src, tgt, target_node, route, delete_source)
    out['abort'] = ['The source guest is deleted only once the migration has succeeded.' if delete_source
                    else 'The source guest stays where it is in any case.']
    return _close(out, rows, [src, tgt], sim, scoped)


def _cross_checks(src, tgt, sim, gv, t, storage_map, target_storage, bridge_map, target_bridge, target_vmid,
                  online, force_online, delete_source, may_delete, user, taken, route):
    _busy_checks(gv)
    if delete_source and not may_delete:
        gv.block('needs_delete', 'Removing the source guest needs vm.delete on it')
    live = bool(online)
    if gv.kind == 'qemu' and gv.cfg is not None:
        live, _gb_total, note = cross_online(gv.cfg, bool(online), bool(force_online))
        if note:
            gv.warn('large_disk', note)
    if gv.running and gv.kind == 'lxc':
        gv.block('ct_running', 'It runs: PegaProx moves containers to another cluster offline - shut it down '
                               'first', overridable=True)
    elif gv.running and not live:
        gv.block('running_offline', 'It runs and the move goes offline: Proxmox moves a running VM only live - '
                                    'shut it down first, or force online', overridable=True)

    tv = target_vmid or gv.vmid
    if taken is None:
        gv.warn('target_guests_unread', f'The guests of {tgt.name} could not be read: whether VMID {tv} is free '
                                        f'there is not checked')
    elif tv in taken:
        gv.block('vmid_taken', f'VMID {tv} is taken on {tgt.name}: pick another one')
    from pegaprox.utils.rbac import acts_as_admin, check_tenant_vmid, DEFAULT_TENANT_ID
    if user is not None and not acts_as_admin(user):
        ok, msg = check_tenant_vmid(user.get('tenant_id') or DEFAULT_TENANT_ID, tv)
        if not ok:
            gv.block('vmid_range', msg)

    nodes_src = src.nodes() or {}
    tnodes = tgt.nodes() or {}
    tinfo = tnodes.get(t) or {}
    _cpu_checks(gv, (nodes_src.get(gv.node) or {}).get('cpuinfo') or {}, tinfo.get('cpuinfo') or {}, t,
                _setting(tgt.mgr, 'cpu_baseline'), live,
                _int((tinfo.get('cpuinfo') or {}).get('cpus')) if isinstance(tinfo.get('cpuinfo'), dict) else 0)

    ha = src.ha()
    if ha and gv.vmid in ha['managed']:
        gv.warn('ha_source', f"Proxmox HA manages it on {src.name}: take it out of HA there first, and add it "
                             f"to HA on {tgt.name} afterwards")
    for job in src.jobs_of(gv.vmid):
        gv.warn('replication_left', f"Replication job {job.get('id')} on {src.name} stays behind and fails once "
                                    f"it left: remove the job")
    if route and not route.get('host'):
        gv.warn('transfer_fallback', route.get('note') or 'The transfer network is not used')

    if gv.cfg is None:
        if gv.g:
            gv.warn('config_unread', 'Its configuration could not be read: disks, networks and devices are not checked')
        if not gv.blocked:
            sim.take(gv, t)
        return
    tgt_st = tgt.storages(t)
    if tgt_st is None:
        gv.warn('storage_unread', f'The storages of {t} could not be read: not checked')
    need = {}
    for vol in guest_volumes(gv.cfg, gv.kind):
        dst = (storage_map or {}).get(vol['storage']) if storage_map else target_storage
        if not dst:
            gv.block('storage_unmapped', f"{vol['key']} is on {vol['storage']}, which the storage map does not cover")
            continue
        if tgt_st is None:
            continue
        row = tgt_st.get(dst)
        if row is None or row.get('status') != 'available':
            gv.block('storage_missing', f"{vol['key']} goes to storage {dst}, which {t} does not have")
            continue
        content = 'rootdir' if gv.kind == 'lxc' else 'images'
        if storage_mapping_problems({vol['storage']: dst}, {dst: row}, content):
            gv.block('storage_content', f"{vol['key']} goes to storage {dst}, which does not take {content}")
            continue
        need[dst] = need.get(dst, 0) + vol['size']
    for dst, size in sorted(need.items()):
        if not sim.space(gv, t, dst, size, _free((tgt_st or {}).get(dst))):
            gv.block('storage_full', f"Storage {dst} on {t} has less room than its {_gb(size)} (counting the "
                                     f"guests before it in this set)", overridable=True)
    for key, _storage, volid in cdrom_images(gv.cfg):
        gv.block('cdrom', f"{key} holds an image ({volid}): eject it first, a remote migration does not take it "
                          f"along", overridable=True)
    nics = guest_nics(gv.cfg)
    bridges, vnets_known = tgt.bridges(t) if nics else (set(), True)
    if nics and bridges is None:
        gv.warn('network_unread', f'The network of {t} could not be read: bridges not checked')
    for key, bridge in nics if bridges is not None else ():
        dst = (bridge_map or {}).get(bridge) if bridge_map else (target_bridge or 'vmbr0')
        if not dst:
            gv.block('bridge_unmapped', f"{key} uses {bridge}, which the network map does not cover")
        elif dst not in bridges:
            if vnets_known:
                gv.block('bridge_missing', f"{key} goes to bridge {dst}, which {t} does not have")
            else:
                gv.warn('bridge_unknown', f"{key} goes to {dst}: {t} has no such bridge, and the SDN VNets "
                                          f"could not be read")
    if 'parent' in gv.cfg:
        gv.block('snapshots_remote', 'It has snapshots: a remote migration does not take them along - remove '
                                     'them first', overridable=True)
    _device_checks(gv, live)
    if not gv.blocked:
        sim.take(gv, t)


def _quota_check(src, tgt, movers, user, delete_source):
    """The tenant's quota at the target: a move inside the clusters it counts, deleting the
    source, changes nothing; anything else adds the guests"""
    if user is None or not movers:
        return
    from pegaprox.utils.rbac import acts_as_admin, check_tenant_quota, get_user_clusters, DEFAULT_TENANT_ID
    from pegaprox.models.permissions import ROLE_VIEWER
    if acts_as_admin(user):
        return
    tid = user.get('tenant_id') or DEFAULT_TENANT_ID
    try:
        counted = get_user_clusters({'role': ROLE_VIEWER, 'tenant_id': tid})
    except Exception:
        counted = None
    if delete_source and (counted is None or src.id in counted):
        return
    gb = 1024.0 ** 3
    res = check_tenant_quota(tid, add_cores=sum(_int(gv.g.get('maxcpu')) for gv in movers),
                             add_mem_gb=sum(_int(gv.g.get('maxmem')) for gv in movers) / gb,
                             add_vms=len(movers), add_disk_gb=sum(_int(gv.g.get('maxdisk')) for gv in movers) / gb)
    if res.get('ok'):
        return
    what = ', '.join(res.get('violations') or [])
    for gv in movers:
        if res.get('enforce') == 'block':
            gv.block('quota', f"The tenant's quota would be exceeded ({what})")
        else:
            gv.warn('quota', f"The tenant's quota would be exceeded ({what}) - it only warns")


def _cross_steps(rows, src, tgt, t, route, delete_source):
    steps = [{'kind': 'token', 'text': f'Create a temporary API token on {tgt.name}'}]
    if route and route.get('host'):
        steps.append({'kind': 'endpoint', 'text': f"Dial {t} at {route['host']} over the transfer network "
                                                  f"{route['network']}"})
    else:
        steps.append({'kind': 'endpoint', 'text': f'Dial the management host of {tgt.name}'})
    for r in rows:
        if moving(r):
            how = 'live' if r['status'] == 'running' and r['type'] == 'qemu' and not any(
                x['code'] == 'large_disk' and 'offline' in x['text'] for x in r['reasons']) else 'offline'
            text = f"Migrate {r['vmid']}{' (' + r['name'] + ')' if r['name'] else ''} {how} to {t} as VMID " \
                   f"{r.get('target_vmid') or r['vmid']}"
            if r['overridden']:
                text += ' - a block overridden'
            steps.append({'kind': 'migrate', 'vmid': r['vmid'], 'text': text})
    steps.append({'kind': 'source', 'text': f'Delete it on {src.name} once the migration has succeeded'
                  if delete_source else f'Keep it on {src.name}'})
    steps.append({'kind': 'cleanup', 'text': 'Remove the temporary token once the migration task has ended'})
    for r in rows:
        if not moving(r):
            steps.append({'kind': 'skip', 'vmid': r['vmid'],
                          'text': f"Skip {r['vmid']}{' (' + r['name'] + ')' if r['name'] else ''}: {block_note(r)}"})
    return steps
