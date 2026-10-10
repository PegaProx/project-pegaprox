# -*- coding: utf-8 -*-
"""What-if simulator for one Proxmox VE cluster - MK Oct 2026

Answers "what happens if ..." for five scenarios. It reads, it never acts:

  node_failure     nodes fail unplanned. The guests Proxmox HA manages restart elsewhere as
                   its rules and groups allow (PegaProx HA, where it is on, restarts the
                   running guests it may), every other guest stays down until its node is
                   back, and one with a disk on the node's own storage restarts nowhere else.
  maintenance      nodes go into maintenance: the placement the evacuation itself uses
                   (manager._evacuation_placement, smallest guest first, lowest load score,
                   pins), which is what maintenance_capacity_preview did for RAM and one node.
  headroom         N+1 / N+2: which single or double node failure leaves the other nodes over
                   their CPU or memory threshold.
  storage_failure  a storage fails, everywhere or on one node: the guests with a disk on it.
  network_failure  a bridge (or one VLAN on it) or an SDN VNet fails on one node or on all of
                   them: the guests with an interface on it.

The report says per guest what becomes of it (down, restarted on X, moved to X, degraded;
every guest not listed is unaffected), per node CPU and memory before and after against the
thresholds, the HA limits hit and the reserve that is left. Each statement carries what it
rests on - known (configuration and what PVE reports now), calculated (capacity math on
that) or assumed - and the assumptions are listed with the report.

What it reads: the guest list (the manager's snapshot), the node status, and the HA, storage
and network configuration of the cluster, kept READ_TTL seconds per manager. Guest configs
only where a scenario needs disks or interfaces, CONFIG_READS per run at most, each kept
CONFIG_TTL seconds, so a run over more guests than that checks the rest in the next one.
Which guest provides a service another one needs is not modeled.
"""

import heapq
import itertools
import logging
import re
import time

log = logging.getLogger(__name__)

SCENARIOS = ('node_failure', 'maintenance', 'headroom', 'storage_failure', 'network_failure')
OUTCOMES = ('down', 'degraded', 'restarted', 'moved', 'unknown')   # the order of the report

CONFIG_READS = 1000     # guest configs read per run at most
CONFIG_TTL = 300        # a guest's disks and interfaces, kept this long
CONFIG_KEPT = 20000     # entries kept per cluster before the old ones go
READ_TTL = 60           # HA, storage and network configuration of the cluster
PAIRS_PLACED = 60       # N+2: the heaviest pairs are placed guest by guest, the rest summed up
MAX_NODES_PICKED = 16
DEFAULT_CPU = 80.0
DEFAULT_MEMORY = 90.0

NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_VOLUME_KEY = re.compile(r'^(?:scsi|virtio|ide|sata|unused|mp)\d+$|^(?:efidisk0|tpmstate0|rootfs)$')
_NET_KEY = re.compile(r'^net\d+$')
_DEVICE_KEY = re.compile(r'^(?:hostpci|usb|dev)\d+$')
_ON = ('1', 'true', 'yes', 'on')

# English for API callers; the UI says the same per code in its own language
REASONS = {
    'not_ha': 'not managed by HA, stays down until its node is back',
    'ha_state': 'its HA state is {state}, HA does not start it',
    'ha_unreadable': 'the HA configuration could not be read',
    'local_disks': 'a disk of it is on storage of {node} only',
    'storage_unknown': 'where its disks are is not known',
    'passthrough': 'it uses a PCI or USB device of {node}',
    'ha_restart': 'restarted by Proxmox HA',
    'pegaprox_restart': 'restarted by PegaProx HA',
    'no_node_rule': 'HA rule {rule} allows only nodes that are down',
    'no_node_storage': 'storage {storages} is on none of the nodes left',
    'no_node_apart': 'HA rule {rule} keeps it apart from a guest on every node left',
    'apart_refused': 'HA rule {rule} refuses {node}, the node the evacuation picks: a guest it stays apart from runs there',
    'no_target': 'no other node can take it',
    'quorum_lost': 'the cluster loses quorum, HA restarts nothing',
    'fence_reset': '{node} runs HA guests and resets itself without quorum',
    'overcommitted': '{node} ends up with more memory or CPU in use than it has',
    'moved_live': 'moved by live migration',
    'ct_restart': 'container moved with a restart',
    'local_disks_copied': 'moved with its local disks copied',
    'local_disks_stay': 'local disks: the evacuation does not move it',
    'pin_strict': 'pinned to {nodes} strictly, none of them can take it',
    'off_pin': 'placed off its pin to {nodes}',
    'disk_on_storage': 'its disk {disk} is on {storage}',
    'data_disk_on_storage': 'data disk {disk} is on {storage}',
    'cdrom_on_storage': 'its CD/DVD image is on {storage}',
    'volumes_on_storage': 'it has disks on {storage}',
    'copy_on_storage': 'a copy of its disks on {storage} of {node} is lost',
    'all_nics': 'every network interface is on {nets}',
    'some_nics': 'interfaces {nics} are on {nets}',
    'config_unread': 'its configuration was not read in this run',
}
LIMITS = {
    'quorum_lost': 'No quorum: {left} votes are left and {need} are needed, HA restarts nothing',
    'fence_reset': 'Nodes running HA guests reset themselves without quorum: {nodes}',
    'not_ha': 'Guests not managed by HA, staying down: {count}',
    'local_disks': 'Guests with disks on local storage, which cannot restart elsewhere: {count}',
    'passthrough': 'Guests using a PCI or USB device of their node: {count}',
    'storage_unknown': 'Guests whose disk location is not known: {count}',
    'no_node_rule': 'Guests whose HA rule allows no node that is left: {count}',
    'no_node_storage': 'Guests whose storage is on none of the nodes left: {count}',
    'no_node_apart': 'Guests an HA rule keeps apart from guests on every node left: {count}',
    'apart_refused': 'Guests HA refuses on the node the evacuation picks (letting the rules give way moves them): {count}',
    'pin_strict': 'Guests pinned strictly to nodes that cannot take them: {count}',
    'no_target': 'No other node can take the guests',
    'local_disks_stay': 'Guests with local disks the evacuation does not move: {count}',
    'over_threshold': 'Over the CPU or memory threshold afterwards: {nodes}',
    'overcommitted': 'More memory or CPU in use than the node has: {nodes}',
    'ha_unreadable': 'The HA configuration could not be read',
    'configs_unread': 'Guest configurations not read in this run: {count}',
    'no_ha_reaction': 'Proxmox HA reacts to node failures only, it does not restart these guests',
}
ASSUMPTIONS = {
    'mem_configured': 'A restarted or moved guest uses its configured memory in full',
    'mem_current': 'A restarted or moved guest uses as much memory as it does now',
    'cpu_now': 'A restarted or moved guest uses as much CPU as it does now',
    'votes': 'Each node has one vote; {votes} votes in all',
    'votes_qdevice': 'Each node has one vote and the QDevice one more; {votes} votes in all',
    'ha_choice': 'Proxmox HA picks the node as its {crs} scheduler would, ties by node name',
    'pegaprox_choice': 'PegaProx HA restarts each guest on the node with the lowest load score',
    'restart_order': 'Restarts are placed one by one in the order HA works through them',
    'fence_delay': 'Restarts begin once the failed node is fenced, about two minutes after it fails',
    'passthrough_local': 'A PCI or USB device given by its host address exists on that node only',
    'configs_unread': 'Guest configurations not read in this run, another run reads them: {count}',
    'no_service_model': 'Services that depend on other guests are not modeled',
    'headroom_all': 'Every running guest of a failed node is restarted on the nodes left',
    'headroom_ha': 'Only the guests HA manages are restarted on the nodes left',
    'headroom_no_storage': 'Local disks and storage limits are not applied in the headroom check',
    'headroom_pairs': '{placed} of {total} node pairs were placed guest by guest, the others by totals',
    'storage_disks': 'A guest whose boot disk is on the storage counts as down, one with a data disk there as degraded',
    'storage_content': 'Disks are found in the storage content list by the guest they belong to',
    'net_underlay': 'Cluster, storage and VXLAN/EVPN traffic over the failed network is not modeled',
    'net_down': 'A guest without a working network interface counts as down',
    'maint_evacuator': 'Guests are placed as the evacuation does: smallest first, on the node with the lowest load score',
    'maint_apart': 'Proxmox HA refuses to move a guest next to one it must stay apart from',
}
_KNOWN, _CALC, _ASSUMED = 'known', 'calculated', 'assumed'


class Invalid(ValueError):
    """A scenario the route answers with a 400."""

    def __init__(self, message, code='invalid'):
        super().__init__(message)
        self.code = code


class Unreadable(RuntimeError):
    """What a run needs could not be read from the cluster: a 503."""


# --- what the caller sends ---------------------------------------------------------------------

def _name(value, what):
    if not isinstance(value, str) or not NAME_RE.match(value):
        raise Invalid(f'{what} is not a valid name', 'bad_name')
    return value


def _flag(body, key):
    value = body.get(key, False)
    if not isinstance(value, bool):
        raise Invalid(f'{key} is true or false', 'bad_flag')
    return value


def _percent(value, what):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= 100:
        raise Invalid(f'{what} is a number from 1 to 100', 'bad_threshold')
    return float(value)


def parse_scenario(body):
    """The scenario of a request body, checked and normalized. Raises Invalid. Whether the
    nodes and storages it names exist is checked by run(), against the cluster."""
    if not isinstance(body, dict):
        raise Invalid('The request body must be a JSON object', 'bad_body')
    kind = body.get('type')
    if kind not in SCENARIOS:
        raise Invalid(f"type is one of {', '.join(SCENARIOS)}", 'bad_type')
    sc = {'type': kind}
    memory = body.get('memory', 'configured')
    if memory not in ('configured', 'current'):
        raise Invalid('memory is configured or current', 'bad_memory')
    sc['memory'] = memory
    thr = body.get('thresholds')
    if thr is not None:
        if not isinstance(thr, dict) or not set(thr) <= {'cpu', 'memory'}:
            raise Invalid('thresholds holds cpu and memory', 'bad_threshold')
        sc['thresholds'] = {k: _percent(v, f'thresholds.{k}') for k, v in thr.items()}

    if kind in ('node_failure', 'maintenance'):
        nodes = body.get('nodes')
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES_PICKED:
            raise Invalid(f'nodes is a list of 1 to {MAX_NODES_PICKED} node names', 'bad_nodes')
        picked = []
        for n in nodes:
            n = _name(n, 'node')
            if n not in picked:
                picked.append(n)
        sc['nodes'] = picked
        if kind == 'maintenance':
            sc['allow_local_disks'] = _flag(body, 'allow_local_disks')
            sc['relax_anti_affinity'] = _flag(body, 'relax_anti_affinity')
    elif kind == 'headroom':
        depth = body.get('depth', 1)
        if isinstance(depth, bool) or depth not in (1, 2):
            raise Invalid('depth is 1 or 2', 'bad_depth')
        guests = body.get('guests', 'all')
        if guests not in ('all', 'ha'):
            raise Invalid('guests is all or ha', 'bad_guests')
        sc.update(depth=depth, guests=guests)
    elif kind == 'storage_failure':
        sc['storage'] = _name(body.get('storage'), 'storage')
        if body.get('node') not in (None, ''):
            sc['node'] = _name(body['node'], 'node')
    else:
        bridge, vnet = body.get('bridge'), body.get('vnet')
        if bridge in (None, '') and vnet in (None, ''):
            raise Invalid('name a bridge or a vnet', 'bad_network')
        if bridge not in (None, ''):
            sc['bridge'] = _name(bridge, 'bridge')
        if vnet not in (None, ''):
            sc['vnet'] = _name(vnet, 'vnet')
        vlan = body.get('vlan')
        if vlan not in (None, ''):
            if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
                raise Invalid('vlan is a number from 1 to 4094', 'bad_vlan')
            sc['vlan'] = vlan
        if body.get('node') not in (None, ''):
            sc['node'] = _name(body['node'], 'node')
    return sc


# --- reads, kept per manager --------------------------------------------------------------------

def _cache(mgr):
    box = mgr.__dict__.get('_whatif_cache')
    if not isinstance(box, dict):
        box = mgr.__dict__['_whatif_cache'] = {}
    return box


def _cached(mgr, key, ttl, read):
    """read() kept for ttl seconds. A failed read (None) is not kept."""
    box = _cache(mgr)
    hit = box.get(key)
    now = time.monotonic()
    if hit is not None and now - hit[0] < ttl:
        return hit[1]
    value = read()
    if value is not None:
        box[key] = (now, value)
    return value


def _get(mgr, path, params=None):
    """(ok, data) of a GET on the cluster API. A path this PVE version does not have is ok
    with no data, like the HA rules on PVE 8."""
    url = f"https://{mgr.host}:{mgr.api_port}/api2/json{path}"
    try:
        r = mgr._api_get(url, params=params) if params else mgr._api_get(url)
    except Exception as e:
        log.debug(f"[WHATIF] {path} unreadable: {e}")
        return False, None
    if r is None:
        return False, None
    if r.status_code in (404, 501):
        return True, []
    if r.status_code != 200:
        return False, None
    try:
        return True, r.json().get('data')
    except Exception:
        return False, None


def _nodes_spec(spec):
    """'pve1:2,pve2' -> {'pve1': 2, 'pve2': 0}"""
    out = {}
    for part in str(spec or '').split(','):
        name, _, prio = part.strip().partition(':')
        if name:
            try:
                out[name] = int(prio) if prio else 0
            except ValueError:
                out[name] = 0
    return out


def _sids(spec):
    return [s.strip() for s in str(spec or '').split(',') if s.strip()]


def ha_config(mgr):
    """The Proxmox HA configuration as the scenarios use it, or None when its resources
    cannot be read: {resources: {sid: row}, placement: {sid: {rule, nodes, strict}},
    apart: [{rule, sids}], together: [{rule, sids}], rules_read, crs}."""
    def read():
        ok, resources = _get(mgr, '/cluster/ha/resources')
        if not ok:
            return None
        rules_ok, rules = _get(mgr, '/cluster/ha/rules')
        groups_ok, groups = _get(mgr, '/cluster/ha/groups')
        _ok, options = _get(mgr, '/cluster/options')
        out = {'resources': {}, 'placement': {}, 'apart': [], 'together': [],
               'rules_read': bool(rules_ok or groups_ok), 'crs': 'basic'}
        for row in resources or []:
            if isinstance(row, dict) and row.get('sid'):
                out['resources'][str(row['sid'])] = row
        for rule in rules or []:
            if not isinstance(rule, dict) or str(rule.get('disable') or '').lower() in _ON:
                continue
            rtype = str(rule.get('type') or '').lower()
            name = str(rule.get('rule') or '')
            if rtype == 'node-affinity':
                for sid in _sids(rule.get('resources')):
                    out['placement'][sid] = {'rule': name, 'nodes': _nodes_spec(rule.get('nodes')),
                                             'strict': str(rule.get('strict') or '').lower() in _ON}
            elif rtype == 'resource-affinity':
                which = 'apart' if str(rule.get('affinity') or '').lower() == 'negative' else 'together'
                out[which].append({'rule': name, 'sids': _sids(rule.get('resources'))})
        # PVE 8 groups, and a 9.0 cluster that has not migrated them yet
        by_group = {g.get('group'): g for g in groups or [] if isinstance(g, dict)}
        for sid, row in out['resources'].items():
            group = by_group.get(row.get('group'))
            if group and sid not in out['placement']:
                out['placement'][sid] = {'rule': str(group.get('group')), 'nodes': _nodes_spec(group.get('nodes')),
                                         'strict': str(group.get('restricted') or '').lower() in _ON}
        crs = str((options or {}).get('crs') or '') if isinstance(options, dict) else ''
        if 'ha=static' in crs:
            out['crs'] = 'static'
        return out
    return _cached(mgr, 'ha', READ_TTL, read)


def storage_config(mgr):
    """GET /storage by name, None when it cannot be read."""
    def read():
        ok, rows = _get(mgr, '/storage')
        if not ok:
            return None
        return {s['storage']: s for s in rows or [] if isinstance(s, dict) and s.get('storage')}
    return _cached(mgr, 'storage', READ_TTL, read)


def storage_presence(mgr):
    """{node: {storage: shared}} of the storages each node has active, None when unreadable."""
    def read():
        ok, rows = _get(mgr, '/cluster/resources', params={'type': 'storage'})
        if not ok:
            return None
        out = {}
        for s in rows or []:
            if isinstance(s, dict) and s.get('status') == 'available' and s.get('node') and s.get('storage'):
                out.setdefault(s['node'], {})[s['storage']] = bool(s.get('shared'))
        return out
    return _cached(mgr, 'presence', READ_TTL, read)


def node_networks(mgr, nodes):
    """{node: [bridge rows]} of the given nodes, each read once per READ_TTL."""
    def one(node):
        def read():
            ok, rows = _get(mgr, f'/nodes/{node}/network')
            if not ok:
                return None
            return [{'iface': r.get('iface'), 'type': r.get('type'),
                     'vlan_aware': str(r.get('bridge_vlan_aware') or '').lower() in _ON}
                    for r in rows or [] if isinstance(r, dict) and r.get('iface')
                    and r.get('type') in ('bridge', 'OVSBridge')]
        return _cached(mgr, ('net', node), READ_TTL, read)
    return _fan_out({n: (lambda n=n: one(n)) for n in nodes})


def sdn(mgr):
    """{'vnets': [...], 'zones': {zone: row}}, empty where the cluster has no SDN; None when
    the VNets cannot be read."""
    def read():
        ok, vnets = _get(mgr, '/cluster/sdn/vnets')
        if not ok:
            return None
        _ok, zones = _get(mgr, '/cluster/sdn/zones')
        return {'vnets': [v for v in vnets or [] if isinstance(v, dict) and v.get('vnet')],
                'zones': {z.get('zone'): z for z in zones or [] if isinstance(z, dict) and z.get('zone')}}
    return _cached(mgr, 'sdn', READ_TTL, read)


def storage_content(mgr, node, storage, kind):
    """The volumes of one content kind on a node's storage, None when unreadable."""
    def read():
        ok, rows = _get(mgr, f'/nodes/{node}/storage/{storage}/content', params={'content': kind})
        return [r for r in rows or [] if isinstance(r, dict)] if ok else None
    return _cached(mgr, ('content', node, storage, kind), READ_TTL, read)


def _fan_out(tasks, timeout=20):
    if not tasks:
        return {}
    if len(tasks) == 1:
        return {k: f() for k, f in tasks.items()}
    from pegaprox.utils.concurrent import run_concurrent_dict
    return run_concurrent_dict(tasks, timeout=timeout)


def _boot_key(config, kind):
    if kind == 'lxc':
        return 'rootfs'
    order = str(config.get('boot') or '')
    if 'order=' in order:
        for key in order.split('order=', 1)[1].split(','):
            for k in key.split(';'):
                k = k.strip()
                if _VOLUME_KEY.match(k) and 'media=cdrom' not in str(config.get(k) or ''):
                    return k
    if config.get('bootdisk'):
        return str(config['bootdisk'])
    disks = sorted(k for k, v in config.items() if re.match(r'^(?:scsi|virtio|sata|ide)\d+$', k)
                   and isinstance(v, str) and 'media=cdrom' not in v)
    return disks[0] if disks else None


def guest_facts(config, kind, storages):
    """What the scenarios need of one guest config: its volumes, its interfaces, the host
    devices it is tied to and its storage class ('local', 'shared', 'nodisk' as PegaProx HA
    tells it, see manager._ha_volume_class)."""
    from pegaprox.core.manager import PegaProxManager
    config = config or {}
    boot = _boot_key(config, kind)
    volumes, nets, devices = [], [], []
    for key, value in config.items():
        if not isinstance(value, str):
            continue
        if _VOLUME_KEY.match(key):
            head = value.split(',')[0]
            if head.startswith(('file=', 'volume=')):
                head = head.split('=', 1)[1]
            if ':' not in head or head.startswith('/'):
                continue
            role = ('unused' if key.startswith('unused') else 'cdrom' if 'media=cdrom' in value
                    else 'boot' if key == boot else 'disk')
            volumes.append({'key': key, 'storage': head.split(':', 1)[0], 'role': role})
        elif _NET_KEY.match(key):
            opts = dict(p.split('=', 1) for p in value.split(',') if '=' in p)
            if opts.get('bridge'):
                try:
                    tag = int(opts.get('tag')) if opts.get('tag') else None
                except ValueError:
                    tag = None
                nets.append({'key': key, 'bridge': opts['bridge'], 'tag': tag})
        elif _DEVICE_KEY.match(key):
            mapped = 'mapping=' in value or value.split(',')[0] == 'spice'
            devices.append({'key': key, 'mapped': mapped})
    volume_class = None
    if storages is not None:
        volume_class = PegaProxManager._ha_volume_class(config, kind, storages)
    return {'volumes': sorted(volumes, key=lambda v: v['key']), 'nets': sorted(nets, key=lambda n: n['key']),
            'devices': devices, 'class': volume_class}


# --- the cluster as it is now --------------------------------------------------------------------

def _sid(vm):
    return f"{'ct' if vm.get('type') == 'lxc' else 'vm'}:{vm.get('vmid')}"


def _pct(used, total):
    return round(used / total * 100.0, 1) if total > 0 else None


class _Load:
    """CPU (cores) and memory (bytes) of the nodes as the scenario leaves them."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.mem_used, self.mem_total, self.cores, self.cpu_used, self.disk = {}, {}, {}, {}, {}
        self.into, self.out, self.ha = {}, {}, {}
        for n, d in ctx.status.items():
            self.mem_used[n] = float(d.get('mem_used') or 0)
            self.mem_total[n] = float(d.get('mem_total') or 0)
            self.cores[n] = ctx.cores.get(n, 0)
            self.cpu_used[n] = float(d.get('cpu_percent') or 0) / 100.0 * self.cores[n]
            self.disk[n] = float(d.get('disk_percent') or 0)
            self.into[n] = self.out[n] = 0
        self.before = {n: (self.mem_used[n], self.cpu_used[n]) for n in self.mem_used}
        self.w = self.weights()

    def mem_pct(self, n, extra=0.0):
        t = self.mem_total.get(n) or 0
        return (self.mem_used[n] + extra) / t * 100.0 if t > 0 else float('inf')

    def cpu_pct(self, n, extra=0.0):
        c = self.cores.get(n) or 0
        return (self.cpu_used[n] + extra) / c * 100.0 if c > 0 else 0.0

    def weights(self):
        # the weights get_node_status scores a node with, which the evacuation and PegaProx
        # HA pick their target by
        cfg = getattr(self.ctx.mgr, 'config', None)
        out = []
        for key, default in (('balance_cpu_weight', 1.0), ('balance_mem_weight', 1.0), ('balance_io_weight', 0.0)):
            try:
                out.append(float(getattr(cfg, key, default) or 0))
            except (TypeError, ValueError):
                out.append(default)
        if not any(out):
            out = [1.0, 1.0, 0.0]
        return out

    def score(self, n):
        w_cpu, w_mem, w_io = self.w
        return self.cpu_pct(n) * w_cpu + min(self.mem_pct(n), 1e6) * w_mem + self.disk[n] * w_io

    def add(self, n, mem, cores):
        self.mem_used[n] += mem
        self.cpu_used[n] += cores
        self.into[n] += 1

    def remove(self, n, mem, cores):
        self.mem_used[n] = max(0.0, self.mem_used[n] - mem)
        self.cpu_used[n] = max(0.0, self.cpu_used[n] - cores)
        self.out[n] += 1


class _Run:
    def __init__(self, mgr, scenario, thresholds):
        self.mgr, self.sc = mgr, scenario
        self.thr = thresholds or {}
        status = mgr.get_node_status() or {}
        if not status:
            raise Unreadable('The node status of the cluster could not be read')
        self.status = status
        try:
            listed = mgr.nodes or {}
        except Exception:
            listed = {}
        self.cores = {}
        for n, d in status.items():
            cores = (listed.get(n) or {}).get('maxcpu') or (d.get('cpuinfo') or {}).get('cpus') or 0
            try:
                self.cores[n] = int(cores)
            except (TypeError, ValueError):
                self.cores[n] = 0
        vms = mgr.get_vm_resources(max_age=15)
        if getattr(vms, 'unavailable', False):
            raise Unreadable('The guest list of the cluster could not be read')
        self.vms = [v for v in vms or [] if v.get('type') in ('qemu', 'lxc') and not v.get('template')
                    and v.get('vmid') is not None]
        self.running = [v for v in self.vms if v.get('status') == 'running']
        self.online = sorted(n for n, d in status.items() if d.get('status') == 'online')
        self.in_maintenance = {n for n, d in status.items() if d.get('maintenance_mode')}
        self.load = _Load(self)
        self.state = {n: ('offline' if d.get('status') != 'online' else
                          'maintenance' if d.get('maintenance_mode') else 'up') for n, d in status.items()}
        self.rows = {}
        self.limits = {}
        self.assumptions = {}
        self.extra = {}
        self.facts = {}
        self.unread = set()
        self.reads = {'configs_read': 0, 'configs_cached': 0, 'configs_unread': 0}
        self.storages = None
        self.assume('no_service_model')

    # -- bookkeeping --
    def assume(self, code, **args):
        self.assumptions.setdefault(code, args)

    def limit(self, code, basis, guests=None, **args):
        item = self.limits.get(code)
        if item is None:
            item = self.limits[code] = {'code': code, 'basis': basis, 'args': dict(args), 'guests': []}
        else:
            item['args'].update(args)
        if guests:
            item['guests'].extend(guests)

    def mem_of(self, vm):
        if self.sc.get('memory') == 'current':
            return float(vm.get('mem') or 0)
        return float(vm.get('maxmem') or vm.get('mem') or 0)

    @staticmethod
    def cores_of(vm):
        try:
            return float(vm.get('cpu') or 0) * float(vm.get('maxcpu') or 0)
        except (TypeError, ValueError):
            return 0.0

    def guest(self, vm, outcome, code, basis, target=None, target_basis=None, **args):
        self.rows[int(vm['vmid'])] = {
            'vmid': int(vm['vmid']), 'name': vm.get('name') or '', 'type': vm.get('type'),
            'node': vm.get('node'), 'outcome': outcome, 'target': target, 'target_basis': target_basis,
            'reason': {'code': code, 'args': {k: v for k, v in args.items()}},
            'text': REASONS[code].format(**{k: _say(v) for k, v in args.items()}),
            'basis': basis,
        }

    def threshold(self, node, metric):
        per = (self.thr.get('nodes') or {}).get(node) or {}
        return float(per.get(metric) or self.thr.get(metric) or (DEFAULT_CPU if metric == 'cpu' else DEFAULT_MEMORY))

    # -- reads --
    def storage_cfg(self):
        if self.storages is None:
            self.storages = storage_config(self.mgr)
        return self.storages

    def read_facts(self, vms):
        """Facts of the given guests, CONFIG_READS reads per run at most; what is left out
        is in self.unread."""
        storages = self.storage_cfg()
        box = _cache(self.mgr).setdefault('configs', {})
        now = time.monotonic()
        todo = []
        for vm in sorted(vms, key=lambda v: int(v['vmid'])):
            vmid = int(vm['vmid'])
            if vmid in self.facts:
                continue
            key = (vmid, vm.get('type'), vm.get('node'))
            hit = box.get(key)
            if hit is not None and now - hit[0] < CONFIG_TTL:
                self.facts[vmid] = hit[1]
                self.reads['configs_cached'] += 1
            else:
                todo.append(vm)
        reading, left = todo[:CONFIG_READS], todo[CONFIG_READS:]
        got = _fan_out({int(vm['vmid']): (lambda vm=vm: _get(self.mgr, f"/nodes/{vm['node']}/{vm['type']}/{vm['vmid']}/config"))
                        for vm in reading}) if reading else {}
        for vm in reading:
            vmid = int(vm['vmid'])
            res = got.get(vmid)
            if not res or not res[0] or not isinstance(res[1], dict):
                self.unread.add(vmid)
                continue
            facts = guest_facts(res[1], vm.get('type'), storages)
            self.facts[vmid] = facts
            box[(vmid, vm.get('type'), vm.get('node'))] = (now, facts)
            self.reads['configs_read'] += 1
        for vm in left:
            self.unread.add(int(vm['vmid']))
        if len(box) > CONFIG_KEPT:
            for k in [k for k, (at, _f) in box.items() if now - at >= CONFIG_TTL]:
                box.pop(k, None)
        self.reads['configs_unread'] = len(self.unread)

    # -- report --
    def node_rows(self, after_states=None):
        rows, over, overcommitted = [], [], []
        load = self.load
        for n in sorted(self.status):
            st = self.state.get(n)
            mb, cb = load.before[n]
            up = st in ('up', 'maintenance') if after_states is None else after_states.get(n, False)
            mem_before = _pct(mb, load.mem_total[n]) if self.status[n].get('status') == 'online' else None
            cpu_before = (_pct(cb, load.cores[n]) if load.cores[n] else None) if mem_before is not None else None
            mem_after = _pct(load.mem_used[n], load.mem_total[n]) if up else None
            cpu_after = (_pct(load.cpu_used[n], load.cores[n]) if load.cores[n] else None) if up else None
            tc, tm = self.threshold(n, 'cpu'), self.threshold(n, 'memory')
            row = {'node': n, 'state': st, 'cores': load.cores[n], 'mem_total': int(load.mem_total[n]),
                   'cpu_before': cpu_before, 'cpu_after': cpu_after, 'mem_before': mem_before, 'mem_after': mem_after,
                   'mem_used_before': int(mb), 'mem_used_after': int(load.mem_used[n]) if up else None,
                   'guests_in': load.into[n], 'guests_out': load.out[n],
                   'cpu_threshold': tc, 'mem_threshold': tm,
                   'over_cpu': cpu_after is not None and cpu_after > tc,
                   'over_mem': mem_after is not None and mem_after > tm,
                   'overcommitted': bool(up) and ((mem_after or 0) > 100.0 or (cpu_after or 0) > 100.0),
                   'basis': {'before': _KNOWN, 'after': _CALC}}
            if row['over_cpu'] or row['over_mem']:
                over.append(n)
            if row['overcommitted']:
                overcommitted.append(n)
            rows.append(row)
        return rows, over, overcommitted

    def reserve(self, node_rows):
        mem_thr = mem_all = cpu_thr = cpu_all = 0.0
        for r in node_rows:
            if r['mem_after'] is None:
                continue
            used = float(r['mem_used_after'] or 0)
            total = float(r['mem_total'] or 0)
            mem_thr += max(0.0, total * r['mem_threshold'] / 100.0 - used)
            mem_all += max(0.0, total - used)
            if r['cores'] and r['cpu_after'] is not None:
                busy = r['cpu_after'] / 100.0 * r['cores']
                cpu_thr += max(0.0, r['cores'] * r['cpu_threshold'] / 100.0 - busy)
                cpu_all += max(0.0, r['cores'] - busy)
        return {'mem_to_threshold': int(mem_thr), 'mem_to_full': int(mem_all),
                'cpu_to_threshold': round(cpu_thr, 1), 'cpu_to_full': round(cpu_all, 1), 'basis': _CALC}

    def mark_overcommitted(self, overcommitted):
        """A guest that keeps running on a node the scenario overloads is degraded; one the
        scenario brings there carries the risk on its row."""
        if not overcommitted:
            return
        hot = set(overcommitted)
        for vm in self.running:
            row = self.rows.get(int(vm['vmid']))
            if row is None:
                if vm.get('node') in hot:
                    self.guest(vm, 'degraded', 'overcommitted', _CALC, node=vm['node'])
            elif row['outcome'] in ('restarted', 'moved') and row['target'] in hot:
                row['risk'] = 'overcommitted'

    def report(self, node_rows=None, over=None, overcommitted=None):
        if node_rows is None:
            node_rows, over, overcommitted = self.node_rows()
        if over:
            self.limit('over_threshold', _CALC, nodes=over)
        if overcommitted:
            self.limit('overcommitted', _CALC, nodes=overcommitted)
        if self.unread:
            self.limit('configs_unread', _KNOWN, count=len(self.unread))
            self.assume('configs_unread', count=len(self.unread))
        rank = {o: i for i, o in enumerate(OUTCOMES)}
        guests = sorted(self.rows.values(), key=lambda r: (rank.get(r['outcome'], 9), r['vmid']))
        counts = {o: 0 for o in OUTCOMES}
        for r in guests:
            counts[r['outcome']] = counts.get(r['outcome'], 0) + 1
        affected_running = sum(1 for vm in self.running if int(vm['vmid']) in self.rows)
        counts['unaffected'] = max(0, len(self.running) - affected_running)
        limits = []
        for item in self.limits.values():
            args = dict(item['args'])
            if item['guests']:
                item['guests'] = sorted(set(item['guests']))
                args.setdefault('count', len(item['guests']))
            item['args'] = args
            item['text'] = LIMITS[item['code']].format(**{k: _say(v) for k, v in args.items()})
            limits.append(item)
        assumptions = [{'code': c, 'args': a, 'text': ASSUMPTIONS[c].format(**{k: _say(v) for k, v in a.items()})}
                       for c, a in self.assumptions.items()]
        out = {
            'supported': True,
            'scenario': self.sc,
            'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'summary': dict(counts, running=len(self.running), guests=len(self.vms)),
            'guests': guests,
            'nodes': node_rows,
            'limits': limits,
            'reserve': self.reserve(node_rows),
            'thresholds': {k: v for k, v in self.thr.items() if k != 'nodes'},
            'assumptions': assumptions,
            'reads': dict(self.reads),
        }
        out.update(self.extra)
        return out


def _say(value):
    if isinstance(value, (list, tuple, set)):
        return ', '.join(str(v) for v in value)
    return str(value)


# --- placement ---------------------------------------------------------------------------------

def _vote_math(run, survivors):
    """(quorate, left, need) once only `survivors` are up, and adds the votes assumption."""
    total = len(run.status)
    qdev, two_node = 0, False
    try:
        from pegaprox.core import qdevice
        view = qdevice.cached(run.mgr.id)
    except Exception:
        view = None
    strategy = (getattr(run.mgr, 'ha_config', None) or {}).get('fence_strategy') if isinstance(
        getattr(run.mgr, 'ha_config', None), dict) else None
    if view and view.get('present'):
        qdev = 1
    elif isinstance(strategy, dict) and strategy.get('has_qdevice'):
        qdev = 1
    if isinstance(strategy, dict) and strategy.get('two_node_flag'):
        two_node = True
    votes = total + qdev
    need = votes // 2 + 1
    left = len(survivors) + qdev
    run.assume('votes_qdevice' if qdev else 'votes', votes=votes)
    quorate = left >= need or (two_node and total == 2 and len(survivors) >= 1)
    return quorate, left, need


def _ha_pick(run, ha, sid, pool, placed, crs):
    """The node Proxmox HA would recover sid to among pool, or (None, code, args)."""
    rule = ha['placement'].get(sid)
    allowed = list(pool)
    prios = {}
    if rule:
        prios = {n: p for n, p in rule['nodes'].items()}
        in_rule = [n for n in allowed if n in prios]
        if rule['strict']:
            allowed = in_rule
            if not allowed:
                return None, 'no_node_rule', {'rule': rule['rule']}
    for group in ha['apart']:
        if sid in group['sids']:
            partners = {placed.get(s) for s in group['sids'] if s != sid}
            allowed = [n for n in allowed if n not in partners]
            if not allowed:
                return None, 'no_node_apart', {'rule': group['rule']}
    for group in ha['together']:
        if sid in group['sids']:
            with_partner = [n for n in allowed if n in {placed.get(s) for s in group['sids'] if s != sid}]
            if with_partner:
                allowed = with_partner
    if not allowed:
        return None, 'no_target', {}
    top = max((prios.get(n, -1) for n in allowed), default=-1)
    allowed = [n for n in allowed if prios.get(n, -1) == top] if prios else allowed
    load = run.load
    if crs == 'static':
        key = lambda n: (load.mem_pct(n) + load.cpu_pct(n), n)   # noqa: E731
    else:
        key = lambda n: (load.ha.get(n, 0), n)   # noqa: E731
    return min(allowed, key=key), None, None


def _storage_limits(facts, storages, pool):
    """pool narrowed to the nodes every storage of the guest is limited to; the storages
    that leave none."""
    if not facts or storages is None:
        return list(pool), []
    allowed = set(pool)
    blocking = []
    for vol in facts['volumes']:
        if vol['role'] == 'unused':
            continue
        cfg = storages.get(vol['storage']) or {}
        limit = _nodes_spec(cfg.get('nodes')) if cfg.get('nodes') else None
        if limit is not None:
            narrowed = allowed & set(limit)
            if not narrowed and vol['storage'] not in blocking:
                blocking.append(vol['storage'])
            allowed = narrowed
    return [n for n in pool if n in allowed], blocking


def _raw_device(facts):
    return bool(facts) and any(not d['mapped'] for d in facts['devices'])


def _node_failure(run):
    sc, mgr = run.sc, run.mgr
    failed = list(sc['nodes'])
    for n in failed:
        if n not in run.status:
            raise Invalid(f'{n} is not a node of this cluster', 'unknown_node')
        if run.status[n].get('status') != 'online':
            raise Invalid(f'{n} is not online', 'node_offline')
    for n in failed:
        run.state[n] = 'failed'
    survivors = [n for n in run.online if n not in failed]
    targets = [n for n in survivors if n not in run.in_maintenance]
    hit = [vm for vm in run.running if vm.get('node') in failed]
    for vm in hit:
        run.load.remove(vm['node'], float(vm.get('mem') or 0), run.cores_of(vm))

    ha = ha_config(mgr)
    pegaprox_ha = bool(getattr(mgr, 'ha_enabled', False))
    quorate, left, need = _vote_math(run, survivors)
    run.assume('fence_delay')
    after = {n: n in survivors for n in run.status}

    if not quorate:
        run.limit('quorum_lost', _CALC, left=left, need=need)
        for vm in hit:
            run.guest(vm, 'down', 'quorum_lost', _CALC)
        # a node whose LRM is active (it runs an HA guest) resets on its own without quorum
        if ha is not None:
            active = {vm.get('node') for vm in run.running if vm.get('node') in survivors
                      and str((ha['resources'].get(_sid(vm)) or {}).get('state') or '') in ('started', 'enabled')}
            if active:
                run.limit('fence_reset', _CALC, nodes=sorted(active))
                for vm in run.running:
                    if vm.get('node') in active:
                        run.guest(vm, 'down', 'fence_reset', _CALC, node=vm['node'])
                for n in active:
                    run.state[n] = 'reset'
                    after[n] = False
        rows, over, oc = run.node_rows(after)
        return run.report(rows, over, oc)

    if ha is None:
        run.limit('ha_unreadable', _KNOWN)
    managed = {}
    for vm in hit:
        row = (ha or {}).get('resources', {}).get(_sid(vm)) if ha else None
        if row is not None:
            managed[int(vm['vmid'])] = row
    restart = [vm for vm in hit if int(vm['vmid']) in managed
               and str(managed[int(vm['vmid'])].get('state') or 'started') in ('started', 'enabled')]
    pg = [vm for vm in hit if int(vm['vmid']) not in managed] if pegaprox_ha else []
    run.read_facts(restart + pg)
    storages = run.storage_cfg()

    # where each HA guest is now, for the rules that keep guests together or apart
    placed = {_sid(vm): vm.get('node') for vm in run.running if vm.get('node') not in failed}
    if ha is not None:
        for vm in run.running:
            if vm.get('node') in survivors and _sid(vm) in ha['resources']:
                run.load.ha[vm['node']] = run.load.ha.get(vm['node'], 0) + 1

    def blocked(vm):
        """True when the guest itself cannot start elsewhere (its row is written then): its
        config was not read, a disk on the node's own storage, a device of the node."""
        vmid, node = int(vm['vmid']), vm['node']
        facts = run.facts.get(vmid)
        if facts is None:
            run.guest(vm, 'unknown', 'config_unread', _ASSUMED)
        elif facts['class'] is None:
            # the storages could not be read: whether a disk is local is not known
            run.limit('storage_unknown', _KNOWN, guests=[vmid])
            run.guest(vm, 'unknown', 'storage_unknown', _ASSUMED)
        elif facts['class'] == 'local':
            run.limit('local_disks', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'local_disks', _KNOWN, node=node)
        elif _raw_device(facts):
            run.limit('passthrough', _ASSUMED, guests=[vmid])
            run.assume('passthrough_local')
            run.guest(vm, 'down', 'passthrough', _ASSUMED, node=node)
        else:
            return False
        return True

    crs = (ha or {}).get('crs', 'basic')
    if restart:
        run.assume('ha_choice', crs=crs)
        run.assume('restart_order')
    # the CRM works through its services in the order of their ids
    for vm in sorted(restart, key=_sid):
        vmid = int(vm['vmid'])
        if blocked(vm):
            continue
        facts = run.facts[vmid]
        pool, blocking = _storage_limits(facts, storages, targets)
        if not pool:
            run.limit('no_node_storage', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'no_node_storage', _KNOWN, storages=blocking or ['-'])
            continue
        target, code, args = _ha_pick(run, ha, _sid(vm), pool, placed, crs)
        if target is None:
            run.limit(code if code in LIMITS else 'no_target', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', code, _KNOWN if code != 'no_node_apart' else _CALC, **args)
            continue
        run.load.add(target, run.mem_of(vm), run.cores_of(vm))
        run.load.ha[target] = run.load.ha.get(target, 0) + 1
        placed[_sid(vm)] = target
        run.guest(vm, 'restarted', 'ha_restart', _KNOWN, target=target, target_basis=_ASSUMED)

    if pg:
        run.assume('pegaprox_choice')
        run.assume('restart_order')
    for vm in sorted(pg, key=lambda v: int(v['vmid'])):
        vmid = int(vm['vmid'])
        if blocked(vm):
            continue
        if not targets:
            run.limit('no_target', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'no_target', _KNOWN)
            continue
        target = min(targets, key=lambda n: (run.load.score(n), n))
        run.load.add(target, run.mem_of(vm), run.cores_of(vm))
        run.guest(vm, 'restarted', 'pegaprox_restart', _KNOWN, target=target, target_basis=_ASSUMED)

    for vm in hit:
        vmid = int(vm['vmid'])
        if vmid in run.rows:
            continue
        row = managed.get(vmid)
        if row is not None:
            state = str(row.get('state') or '')
            run.guest(vm, 'down', 'ha_state', _KNOWN, state=state or '-')
        elif ha is None and not pegaprox_ha:
            run.guest(vm, 'unknown', 'ha_unreadable', _ASSUMED)
        else:
            run.limit('not_ha', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'not_ha', _KNOWN)

    run.assume('mem_configured' if sc.get('memory') != 'current' else 'mem_current')
    run.assume('cpu_now')
    rows, over, oc = run.node_rows(after)
    run.mark_overcommitted(oc)
    return run.report(rows, over, oc)


def _maintenance(run):
    sc, mgr = run.sc, run.mgr
    nodes = list(sc['nodes'])
    for n in nodes:
        if n not in run.status:
            raise Invalid(f'{n} is not a node of this cluster', 'unknown_node')
        if run.status[n].get('status') != 'online':
            raise Invalid(f'{n} is not online', 'node_offline')
    for n in nodes:
        run.state[n] = 'maintenance'

    # the target pool of get_best_target_node: no rolling-update node, no excluded node
    exclude = set(getattr(mgr.config, 'excluded_nodes', []) or [])
    ru = getattr(mgr, '_rolling_update', None) or {}
    if isinstance(ru, dict):
        exclude |= {n for n in (ru.get('rebooting_nodes') or []) + [ru.get('current_node') or ''] if n}
    avail = [n for n in run.online if n not in nodes and n not in run.in_maintenance and n not in exclude]

    try:
        ha_nodes, storage_nodes = mgr._evacuation_placement()
    except Exception as e:
        log.debug(f"[WHATIF] evacuation placement unreadable: {e}")
        ha_nodes, storage_nodes = {}, {}
    try:
        pins = mgr._derive_proxlb_tag_rules(vms=run.vms)['pins']
    except Exception:
        pins = {}
    pin_mode = 'strict' if getattr(mgr.config, 'proxlb_pins_strict', False) else 'prefer'
    ha = ha_config(mgr)
    presence = storage_presence(mgr) or {}
    relax = sc.get('relax_anti_affinity')
    allow_local = sc.get('allow_local_disks')

    going = [vm for n in nodes for vm in sorted((v for v in run.running if v.get('node') == n),
                                                key=lambda v: int(v.get('mem') or 0))]
    run.read_facts(going)
    run.assume('maint_evacuator')
    run.assume('mem_configured' if sc.get('memory') != 'current' else 'mem_current')
    run.assume('cpu_now')
    placed = {_sid(vm): vm.get('node') for vm in run.running}
    if not avail and going:
        run.limit('no_target', _KNOWN, guests=[int(v['vmid']) for v in going])
    for vm in going:
        vmid, node = int(vm['vmid']), vm['node']
        facts = run.facts.get(vmid)
        if not avail:
            run.guest(vm, 'down', 'no_target', _KNOWN)
            continue
        if facts is None and vmid in run.unread:
            run.guest(vm, 'unknown', 'config_unread', _ASSUMED)
            continue
        if _raw_device(facts):
            run.limit('passthrough', _ASSUMED, guests=[vmid])
            run.assume('passthrough_local')
            run.guest(vm, 'down', 'passthrough', _ASSUMED, node=node)
            continue
        local = bool(facts) and facts['class'] == 'local'
        if local and vm.get('type') == 'qemu' and not allow_local:
            run.limit('local_disks_stay', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'local_disks_stay', _KNOWN)
            continue
        # what HA and storage.cfg allow, as manager._evacuation_allowed_nodes has it
        by_rule = [n for n in avail if n in ha_nodes[vmid]] if vmid in ha_nodes else list(avail)
        if not by_rule:
            rule = ((ha or {}).get('placement', {}).get(_sid(vm)) or {}).get('rule') or '-'
            run.limit('no_node_rule', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'no_node_rule', _KNOWN, rule=rule)
            continue
        volumes = [v for v in (facts or {}).get('volumes', [])]
        pool = [n for n in by_rule if all(n in storage_nodes[v['storage']] for v in volumes
                                          if v['storage'] in storage_nodes)]
        if local:
            need = {v['storage'] for v in volumes if v['role'] != 'unused'}
            pool = [n for n in pool if need <= set(presence.get(n, {}))]
        if not pool:
            run.limit('no_node_storage', _KNOWN, guests=[vmid])
            run.guest(vm, 'down', 'no_node_storage', _KNOWN,
                      storages=sorted({v['storage'] for v in volumes if v['role'] != 'unused'}) or ['-'])
            continue
        pin = pins.get(vmid)
        off_pin = False
        if pin:
            pinned = [n for n in pool if n in pin]
            if pinned:
                pool = pinned
            elif pin_mode == 'strict':
                run.limit('pin_strict', _KNOWN, guests=[vmid])
                run.guest(vm, 'down', 'pin_strict', _KNOWN, nodes=sorted(pin))
                continue
            else:
                off_pin = True
        target = min(pool, key=lambda n: (run.load.score(n), n))
        if ha is not None and not relax and _sid(vm) in ha['resources']:
            refused = next((g for g in ha['apart'] if _sid(vm) in g['sids']
                            and target in {placed.get(s) for s in g['sids'] if s != _sid(vm)}), None)
            if refused:
                # the evacuation tries its one target and leaves the guest when that fails
                run.assume('maint_apart')
                run.limit('apart_refused', _CALC, guests=[vmid])
                run.guest(vm, 'down', 'apart_refused', _CALC, rule=refused['rule'], node=target)
                continue
        run.load.remove(node, float(vm.get('mem') or 0), run.cores_of(vm))
        run.load.add(target, run.mem_of(vm), run.cores_of(vm))
        placed[_sid(vm)] = target
        if vm.get('type') == 'lxc':
            code = 'ct_restart'
        elif local:
            code = 'local_disks_copied'
        else:
            code = 'moved_live'
        outcome = 'restarted' if vm.get('type') == 'lxc' else 'moved'
        if off_pin:
            run.guest(vm, outcome, 'off_pin', _KNOWN, target=target, target_basis=_CALC, nodes=sorted(pin))
        else:
            run.guest(vm, outcome, code, _KNOWN, target=target, target_basis=_CALC)
    after = {n: run.state.get(n) == 'up' for n in run.status}
    rows, over, oc = run.node_rows(after)
    run.mark_overcommitted(oc)
    return run.report(rows, over, oc)


def _place_all(load, survivors, guests, allowed_of):
    """Least-loaded placement by memory, the way the capacity preview of the maintenance
    dialog places guests: [(mem, cores, sid)] -> number that found no node. A heap keeps
    it O(guests log nodes) for the guests without a rule; an entry whose node took a guest
    since is stale and skipped."""
    heap = [(load.mem_pct(n), n) for n in survivors]
    heapq.heapify(heap)
    unplaced = 0
    for mem, cores, sid in guests:
        allowed = allowed_of(sid)
        if allowed is None:
            while heap:
                pct, n = heapq.heappop(heap)
                if pct == load.mem_pct(n):
                    break
            else:
                unplaced += 1
                continue
            load.add(n, mem, cores)
            heapq.heappush(heap, (load.mem_pct(n), n))
            continue
        pool = [n for n in survivors if n in allowed]
        if not pool:
            unplaced += 1
            continue
        n = min(pool, key=lambda x: (load.mem_pct(x, mem), x))
        load.add(n, mem, cores)
        heapq.heappush(heap, (load.mem_pct(n), n))
    return unplaced


def _headroom(run):
    sc, mgr = run.sc, run.mgr
    depth = sc.get('depth', 1)
    candidates = [n for n in run.online if n not in run.in_maintenance]
    ha = ha_config(mgr)
    pegaprox_ha = bool(getattr(mgr, 'ha_enabled', False))
    if sc.get('guests') == 'ha':
        run.assume('headroom_ha')
    else:
        run.assume('headroom_all')
    run.assume('headroom_no_storage')
    run.assume('mem_configured' if sc.get('memory') != 'current' else 'mem_current')
    run.assume('cpu_now')
    if ha is None:
        run.limit('ha_unreadable', _KNOWN)

    def moves(vm):
        if sc.get('guests') != 'ha' or pegaprox_ha:
            return True
        row = (ha or {}).get('resources', {}).get(_sid(vm))
        return row is not None and str(row.get('state') or 'started') in ('started', 'enabled')

    per_node = {n: [] for n in candidates}
    for vm in run.running:
        if vm.get('node') in per_node and moves(vm):
            per_node[vm['node']].append((run.mem_of(vm), run.cores_of(vm), _sid(vm)))
    for n in per_node:
        per_node[n].sort(key=lambda g: g[2])
    strict = {sid: set(p['nodes']) for sid, p in ((ha or {}).get('placement') or {}).items() if p['strict']}

    def simulate(failed):
        survivors = [n for n in candidates if n not in failed]
        load = _Load(run)
        guests = [g for f in failed for g in per_node[f]]
        quorate, left, need = _vote_math(run, [n for n in run.online if n not in failed])
        unplaced = _place_all(load, survivors, guests, strict.get) if survivors else len(guests)
        over_mem, over_cpu, worst_mem, worst_cpu = [], [], 0.0, 0.0
        mem_res = cpu_res = 0.0
        for n in survivors:
            mp, cp = load.mem_pct(n), load.cpu_pct(n)
            worst_mem, worst_cpu = max(worst_mem, mp), max(worst_cpu, cp)
            if mp > run.threshold(n, 'memory'):
                over_mem.append(n)
            if load.cores[n] and cp > run.threshold(n, 'cpu'):
                over_cpu.append(n)
            mem_res += max(0.0, load.mem_total[n] * run.threshold(n, 'memory') / 100.0 - load.mem_used[n])
            if load.cores[n]:
                cpu_res += max(0.0, load.cores[n] * run.threshold(n, 'cpu') / 100.0 - load.cpu_used[n])
        return {'failed': list(failed), 'quorate': quorate, 'votes_left': left, 'votes_needed': need,
                'guests': len(guests), 'moved_mem': int(sum(g[0] for g in guests)), 'unplaced': unplaced,
                'over_mem': over_mem, 'over_cpu': over_cpu,
                'worst_mem_pct': round(worst_mem, 1) if survivors else None,
                'worst_cpu_pct': round(worst_cpu, 1) if survivors else None,
                'mem_reserve': int(mem_res), 'cpu_reserve': round(cpu_res, 1),
                'ok': quorate and not unplaced and not over_mem and not over_cpu,
                'checked': 'placed', 'basis': _CALC}, load

    combos = []
    worst_after = {}
    if depth == 1:
        sets = [(n,) for n in candidates]
        placed_sets = sets
    else:
        sets = list(itertools.combinations(candidates, 2))
        weight = {n: sum(g[0] for g in per_node[n]) for n in candidates}
        sets.sort(key=lambda p: (-(weight[p[0]] + weight[p[1]]), p))
        placed_sets = sets[:PAIRS_PLACED]
        if len(sets) > len(placed_sets):
            run.assume('headroom_pairs', placed=len(placed_sets), total=len(sets))
    for failed in placed_sets:
        row, load = simulate(failed)
        combos.append(row)
        for n in candidates:
            if n in failed:
                continue
            mp = load.mem_pct(n)
            w = worst_after.get(n)
            if w is None or mp > w['mem_after']:
                worst_after[n] = {'mem_after': mp, 'when': list(failed), 'into': load.into[n],
                                  'mem_used_after': load.mem_used[n], 'cpu_used_after': load.cpu_used[n]}
    # the pairs not placed one by one: memory summed up against what the others have left
    if len(sets) > len(placed_sets):
        free = {n: run.load.mem_total[n] * run.threshold(n, 'memory') / 100.0 - run.load.mem_used[n]
                for n in candidates}
        total_free = sum(free.values())
        for failed in sets[len(placed_sets):]:
            moved = sum(g[0] for f in failed for g in per_node[f])
            room = total_free - sum(free[f] for f in failed)
            quorate, left, need = _vote_math(run, [n for n in run.online if n not in failed])
            combos.append({'failed': list(failed), 'quorate': quorate, 'votes_left': left, 'votes_needed': need,
                           'guests': sum(len(per_node[f]) for f in failed), 'moved_mem': int(moved), 'unplaced': None,
                           'over_mem': [], 'over_cpu': [], 'worst_mem_pct': None, 'worst_cpu_pct': None,
                           'mem_reserve': int(max(0.0, room - moved)), 'cpu_reserve': None,
                           'ok': quorate and moved <= room, 'checked': 'totals', 'basis': _CALC})
    failing = [c for c in combos if not c['ok']]
    combos.sort(key=lambda c: (c['ok'], -(c['worst_mem_pct'] or 0), c['failed']))

    # the nodes table: what each node carries in the worst of these failures
    load = run.load
    for n, w in worst_after.items():
        load.mem_used[n] = w['mem_used_after']
        load.cpu_used[n] = w['cpu_used_after']
        load.into[n] = w['into']
    after = {n: n in candidates for n in run.status}
    rows, over, oc = run.node_rows(after)
    for r in rows:
        w = worst_after.get(r['node'])
        r['worst_when'] = w['when'] if w else None
    run.extra['headroom'] = {
        'depth': depth, 'checked': len(combos), 'failing': len(failing),
        'ok': not failing and bool(combos),
        'combinations': combos[:200], 'basis': _CALC,
    }
    return run.report(rows, over, oc)


def _storage_failure(run):
    sc, mgr = run.sc, run.mgr
    name, only = sc['storage'], sc.get('node')
    storages = run.storage_cfg()
    presence = storage_presence(mgr)
    if storages is None or presence is None:
        raise Unreadable('The storage configuration of the cluster could not be read')
    cfg = storages.get(name)
    where = sorted(n for n, have in presence.items() if name in have)
    if cfg is None and not where:
        raise Invalid(f'{name} is not a storage of this cluster', 'unknown_storage')
    if only is not None and only not in run.status:
        raise Invalid(f'{only} is not a node of this cluster', 'unknown_node')
    if only is not None and only not in where:
        raise Invalid(f'{name} is not active on {only}', 'storage_not_on_node')
    from pegaprox.core.manager import PegaProxManager
    shared = bool(cfg and PegaProxManager._ha_storage_shared(cfg)) or any(presence[n].get(name) for n in where)
    scope = [only] if only else where
    run.limit('no_ha_reaction', _KNOWN)
    run.assume('storage_content')
    run.assume('storage_disks')

    content = str((cfg or {}).get('content') or 'images,rootdir')
    kinds = [k for k in ('images', 'rootdir') if k in content]
    readers = [scope[0]] if shared and scope else scope
    got = _fan_out({(n, k): (lambda n=n, k=k: storage_content(mgr, n, name, k))
                    for n in readers for k in kinds})
    owners = {}   # node (None: shared, every node) -> {vmid}
    for (n, _k), rows in got.items():
        if rows is None:
            raise Unreadable(f'The content of {name} on {n} could not be read')
        for row in rows or []:
            try:
                vmid = int(row.get('vmid'))
            except (TypeError, ValueError):
                continue
            owners.setdefault(None if shared else n, set()).add(vmid)

    if shared:
        holders = owners.get(None, set())
        hit = [vm for vm in run.vms if int(vm['vmid']) in holders and vm.get('node') in scope]
        copies = []
    else:
        hit = [vm for vm in run.vms if int(vm['vmid']) in owners.get(vm.get('node'), set())]
        copies = [(vm, n) for n in scope for vm in run.running
                  if vm.get('node') != n and int(vm['vmid']) in owners.get(n, set())]
    running = [vm for vm in hit if vm.get('status') == 'running']
    run.extra['stopped_affected'] = len(hit) - len(running)
    run.read_facts(running)
    for vm in running:
        vmid = int(vm['vmid'])
        facts = run.facts.get(vmid)
        if facts is None:
            run.guest(vm, 'down', 'volumes_on_storage', _ASSUMED, storage=name)
            continue
        on = [v for v in facts['volumes'] if v['storage'] == name and v['role'] != 'unused']
        boot = next((v for v in on if v['role'] == 'boot'), None)
        disk = next((v for v in on if v['role'] == 'disk'), None)
        cdrom = next((v for v in on if v['role'] == 'cdrom'), None)
        if boot:
            run.guest(vm, 'down', 'disk_on_storage', _KNOWN, disk=boot['key'], storage=name)
        elif disk:
            run.guest(vm, 'degraded', 'data_disk_on_storage', _KNOWN, disk=disk['key'], storage=name)
        elif cdrom:
            run.guest(vm, 'degraded', 'cdrom_on_storage', _KNOWN, storage=name)
    for vm, n in copies:
        if int(vm['vmid']) not in run.rows:
            run.guest(vm, 'degraded', 'copy_on_storage', _ASSUMED, storage=name, node=n)
    run.extra['storage'] = {'storage': name, 'shared': shared, 'nodes': scope, 'type': (cfg or {}).get('type')}
    return run.report()


def _network_failure(run):
    sc, mgr = run.sc, run.mgr
    only, bridge, vnet, vlan = sc.get('node'), sc.get('bridge'), sc.get('vnet'), sc.get('vlan')
    if only is not None and only not in run.status:
        raise Invalid(f'{only} is not a node of this cluster', 'unknown_node')
    scope = [only] if only else sorted(run.status)
    names = set()
    direct = set()
    zone_vnets = []
    net = sdn(mgr)
    if net is None:
        if vnet:
            raise Unreadable('The SDN configuration of the cluster could not be read')
        net = {'vnets': [], 'zones': {}}
    if vnet:
        if not any(v.get('vnet') == vnet for v in net['vnets']):
            raise Invalid(f'{vnet} is not an SDN VNet of this cluster', 'unknown_vnet')
        names.add(vnet)
        direct.add(vnet)
    if bridge:
        nets = node_networks(mgr, [n for n in scope if n in run.online])
        if nets and all(rows is None for rows in nets.values()):
            raise Unreadable('The networks of the nodes could not be read')
        if not any(any(r.get('iface') == bridge for r in rows or []) for rows in nets.values()):
            raise Invalid(f'{bridge} is not a bridge of {only or "this cluster"}', 'unknown_bridge')
        names.add(bridge)
        direct.add(bridge)
        # the VNets of a VLAN or QinQ zone on this bridge go down with it
        for v in net['vnets']:
            zone = net['zones'].get(v.get('zone')) or {}
            if zone.get('type') in ('vlan', 'qinq') and zone.get('bridge') == bridge:
                try:
                    tag = int(v.get('tag')) if v.get('tag') not in (None, '') else None
                except (TypeError, ValueError):
                    tag = None
                if vlan is None or tag == vlan:
                    names.add(v['vnet'])
                    zone_vnets.append(v['vnet'])
    run.limit('no_ha_reaction', _KNOWN)
    run.assume('net_down')
    run.assume('net_underlay')

    def fails(nic):
        if nic['bridge'] not in names:
            return False
        if vlan is not None and nic['bridge'] in direct:
            return nic['tag'] == vlan
        return True

    guests = [vm for vm in run.running if vm.get('node') in scope]
    run.read_facts(guests)
    for vm in guests:
        vmid = int(vm['vmid'])
        facts = run.facts.get(vmid)
        if facts is None:
            run.guest(vm, 'unknown', 'config_unread', _ASSUMED)
            continue
        nics = facts['nets']
        lost = [n for n in nics if fails(n)]
        if not lost:
            continue
        nets_hit = sorted({n['bridge'] + (f".{n['tag']}" if n['tag'] else '') for n in lost})
        if len(lost) == len(nics):
            run.guest(vm, 'down', 'all_nics', _KNOWN, nets=nets_hit)
        else:
            run.guest(vm, 'degraded', 'some_nics', _KNOWN, nics=[n['key'] for n in lost], nets=nets_hit)
    run.extra['network'] = {'names': sorted(names), 'sdn_vnets': sorted(zone_vnets), 'nodes': scope}
    return run.report()


def run(mgr, scenario, thresholds=None):
    """The report of one scenario (parse_scenario's output) on a Proxmox VE manager.
    Raises Invalid for a node or storage the cluster does not have, Unreadable when what
    the run needs cannot be read."""
    sim = _Run(mgr, scenario, thresholds)
    return {'node_failure': _node_failure, 'maintenance': _maintenance, 'headroom': _headroom,
            'storage_failure': _storage_failure, 'network_failure': _network_failure}[scenario['type']](sim)


def options(mgr):
    """What the scenario picker offers: the nodes, the storages that hold guest disks, the
    bridges of the online nodes and the SDN VNets."""
    status = mgr.get_node_status() or {}
    if not status:
        raise Unreadable('The node status of the cluster could not be read')
    online = sorted(n for n, d in status.items() if d.get('status') == 'online')
    storages = storage_config(mgr) or {}
    presence = storage_presence(mgr) or {}
    from pegaprox.core.manager import PegaProxManager
    stores = []
    for name in sorted(set(storages) | {s for have in presence.values() for s in have}):
        cfg = storages.get(name) or {}
        content = str(cfg.get('content') or '')
        if cfg and not ({'images', 'rootdir'} & set(content.split(','))):
            continue   # backups or ISO images only: no running guest has a disk there
        on = sorted(n for n, have in presence.items() if name in have)
        stores.append({'storage': name, 'type': cfg.get('type'), 'nodes': on,
                       'shared': bool(cfg and PegaProxManager._ha_storage_shared(cfg))
                       or any(presence[n].get(name) for n in on)})
    bridges = {}
    for node, rows in node_networks(mgr, online).items():
        for r in rows or []:
            b = bridges.setdefault(r['iface'], {'name': r['iface'], 'nodes': [], 'vlan_aware': False})
            b['nodes'].append(node)
            b['vlan_aware'] = b['vlan_aware'] or r['vlan_aware']
    net = sdn(mgr) or {'vnets': [], 'zones': {}}
    ha = ha_config(mgr)
    return {
        'supported': True,
        'nodes': [{'name': n, 'status': d.get('status'), 'maintenance': bool(d.get('maintenance_mode'))}
                  for n, d in sorted(status.items())],
        'storages': stores,
        'bridges': [dict(b, nodes=sorted(b['nodes'])) for _n, b in sorted(bridges.items())],
        'vnets': [{'vnet': v['vnet'], 'zone': v.get('zone'), 'tag': v.get('tag')}
                  for v in sorted(net['vnets'], key=lambda v: v['vnet'])],
        'ha': {'readable': ha is not None, 'resources': len((ha or {}).get('resources') or {}),
               'pegaprox_ha': bool(getattr(mgr, 'ha_enabled', False))},
    }
