"""A metrics history to hold the readers of metrics_history against, seeded the way the
collector writes it, at whatever size a test or a benchmark asks for.

Each cluster is modelled as live state: what a manager's `nodes` and get_vm_resources()
hold, and the storage list of /cluster/resources. A snapshot is built from that state
with the expressions collect_metrics_snapshot uses (same keys, same order, same rounding)
and written through the real save_metrics_snapshot with the timestamp the model chose.
test_metrics_golden_equivalence holds the builder against the collector itself.

On top of what today's collector writes, a history carries what older or odd writers
left in the table: guest entries without 'n' (written before #965) and, in one cluster,
entries off the usual shape (an extra key, an int cpu, two decimals, an int 'r').

Everything comes from seeded random.Random streams, so the same arguments give the same
history byte for byte. Also imported by the scale benchmark outside pytest, so no
fixtures and no pytest imports here.
MK Oct 2026
"""
import copy
import datetime as _datetime
import json
import math
import random
import sys
import time as _time
import types
from datetime import datetime, timezone

_GIB = 1024 ** 3
_TIB = 1024 ** 4

# what a guest entry of the history holds, in the collector's order
GUEST_KEYS = ('t', 'r', 'cpu', 'mem', 'maxmem', 'maxcpu', 'n')


class Guest:
    __slots__ = ('vmid', 't', 'name', 'node', 'maxcpu', 'maxmem', 'maxdisk', 'on',
                 'cpu_base', 'cpu_amp', 'cpu_noise', 'mem_base', 'mem_drift', 'mem_noise',
                 'burst', 'nodeless', 'steady')

    def __init__(self, vmid, t, name, node, maxcpu, maxmem, maxdisk, on, profile):
        self.vmid, self.t, self.name, self.node = vmid, t, name, node
        self.maxcpu, self.maxmem, self.maxdisk, self.on = maxcpu, maxmem, maxdisk, on
        (self.cpu_base, self.cpu_amp, self.cpu_noise,
         self.mem_base, self.mem_drift, self.mem_noise) = profile
        self.burst = False      # now and then a little over 100 %, as PVE reports it
        self.nodeless = False   # its resource row carries no node
        self.steady = False     # nobody switches it on or off at random


class Node:
    __slots__ = ('name', 'maxcpu', 'maxmem', 'online', 'down_for', 'base_cpu', 'base_mem',
                 'sensor', 'hw')

    def __init__(self, name, maxcpu, maxmem, sensor=None, hw=None):
        self.name, self.maxcpu, self.maxmem = name, maxcpu, maxmem
        self.online, self.down_for = True, 0
        self.base_cpu, self.base_mem = 0.03, int(maxmem * 0.06)
        self.sensor = sensor    # base temperature, None where lm-sensors is missing
        self.hw = hw            # hw(step) -> None | 'na' | health, see _hw_summary


class Storage:
    __slots__ = ('sid', 'total', 'used', 'growth', 'per_node')

    def __init__(self, sid, total, used, growth=0, per_node=False):
        self.sid, self.total, self.used = sid, total, used
        self.growth, self.per_node = growth, per_node   # growth in bytes per day


class Cluster:
    def __init__(self, cid, name, ssh=True):
        self.cid, self.name, self.ssh = cid, name, ssh
        self.nodes = {}       # name -> Node, in the order the manager lists them
        self.guests = {}      # vmid -> Guest
        self.storage = []     # Storage, in the order the REST answer lists them
        self.order = None     # cached resource order, rebuilt when a guest moves or comes
        self.blank_vmid = None  # (from, to): a resource row without a vmid in those steps

    def node(self, name, maxcpu, maxmem_gib, sensor=None, hw=None):
        self.nodes[name] = Node(name, maxcpu, maxmem_gib * _GIB, sensor, hw)

    def resource_order(self):
        if self.order is None:
            rank = {n: i for i, n in enumerate(self.nodes)}
            self.order = sorted(self.guests.values(), key=lambda g: (rank.get(g.node, 99), g.vmid))
        return self.order


# --- the builder: collect_metrics_snapshot's arithmetic over the modelled live state -----

def cluster_entry(live):
    """The dict collect_metrics_snapshot stores for one cluster, from what its manager holds
    (`live`, see Fleet.live). None where the cluster is not connected."""
    if live['fail'] == 'gone':
        return None
    cd = {'name': live['name'], 'nodes': {},
          'totals': {'vms_running': 0, 'vms_stopped': 0, 'cts_running': 0, 'cts_stopped': 0,
                     'cpu_used': 0, 'cpu_total': 0, 'mem_used': 0, 'mem_total': 0}}
    tot = cd['totals']
    for node_name, nd in live['nodes'].items():
        if nd.get('status') != 'online':
            continue
        cd['nodes'][node_name] = {
            'cpu': round(nd.get('cpu', 0) * 100, 1),
            'mem_percent': round(nd.get('mem', 0) / max(nd.get('maxmem', 1), 1) * 100, 1),
            'maxcpu': nd.get('maxcpu', 0),
            'maxmem': nd.get('maxmem', 0),
        }
        tot['cpu_total'] += nd.get('maxcpu', 0)
        tot['cpu_used'] += nd.get('cpu', 0) * nd.get('maxcpu', 0)
        tot['mem_total'] += nd.get('maxmem', 0)
        tot['mem_used'] += nd.get('mem', 0)
    if live['ssh']:
        for nm in list(cd['nodes']):
            values = live['sensors'].get(nm)
            if values:
                cd['nodes'][nm]['temp'] = round(max(values), 1)
    if live['hw_on']:
        for nm in list(cd['nodes']):
            summ = live['hw'].get(nm)
            if summ is not None:
                cd['nodes'][nm]['hw_health'] = summ.get('health') if summ.get('available') else None
    cd['vms'] = {}
    if live['fail'] != 'vms':
        vms = cd['vms']
        for r in live['resources']:
            rtype = r.get('type')
            if rtype not in ('qemu', 'lxc'):
                continue
            running = r.get('status') == 'running'
            if rtype == 'qemu':
                if running: tot['vms_running'] += 1
                else: tot['vms_stopped'] += 1
            else:
                if running: tot['cts_running'] += 1
                else: tot['cts_stopped'] += 1
            vmid = str(r.get('vmid', ''))
            if not vmid:
                continue
            maxmem = int(r.get('maxmem', 0) or 0)
            maxcpu = int(r.get('maxcpu', 0) or 0)
            vms[vmid] = {
                't': rtype, 'r': running,
                'cpu': round((r.get('cpu', 0) or 0) * 100, 1) if running else None,
                'mem': round((r.get('mem', 0) or 0) / maxmem * 100, 1) if (running and maxmem > 0) else None,
                'maxmem': maxmem, 'maxcpu': maxcpu, 'n': r.get('node') or '',
            }
    else:
        # a guest list that was not read leaves no counts (NS Nov 2026, was all zeros)
        for k in ('vms_running', 'vms_stopped', 'cts_running', 'cts_stopped'):
            del tot[k]
    cd['storage'] = {}
    if live['fail'] != 'storage':
        seen = set()
        for s in live['storage']:
            sid = s.get('storage') or s.get('id', '')
            if not sid or sid in seen:
                continue
            seen.add(sid)
            total = int(s.get('maxdisk', 0) or 0)
            used = int(s.get('disk', 0) or 0)
            if total > 0:
                cd['storage'][sid] = {'used': used, 'total': total, 'pct': round(used / total * 100, 1)}
    return cd


class Fleet:
    """Clusters, their churn and the clock of the collector, step by step.

    Step s is the collector cycle at about start + s * cadence (a few seconds late, as a
    cycle that waited on SSH is). A gap step changes the fleet but writes nothing, an
    extra row lands between two cycles (force-snapshot), a failure drops what that part
    of the collector swallowed."""

    def __init__(self, seed, end, steps, cadence=300, jitter=25):
        self.seed, self.steps, self.cadence, self.jitter = seed, steps, cadence, jitter
        self.start = end - (steps - 1) * cadence - jitter - 1
        self.end = end
        self.clusters = {}
        self.events = {}       # step -> [callable]
        self.gaps = set()
        self.extras = {}       # step -> [seconds after the cycle]
        self.fails = {}        # (cid, step) -> 'vms' | 'storage' | 'gone'
        self.no_host_until = None   # guest entries carry no 'n' before this unix time (#965)
        self.odd = {}          # cid -> fn(step, vms) that bends some entries off the shape
        self.shuffle_every = 50
        self.hw_on = False
        self._tick = random.Random(seed * 7919 + 1)
        self._val = random.Random(seed * 7919 + 2)
        self.live = {}          # cid -> what its manager holds after the last step
        self.captured = {}      # step -> (live of every cluster, the snapshot as built)
        self.capture = set()

    # scenario ---------------------------------------------------------------------------
    def cluster(self, cid, name, ssh=True):
        c = self.clusters[cid] = Cluster(cid, name, ssh)
        return c

    def at(self, step, fn):
        self.events.setdefault(step, []).append(fn)

    def migrate(self, cid, vmid, step, node):
        def go(c=self.clusters[cid]):
            g = c.guests.get(vmid)
            if g is not None:
                g.node = node
                c.order = None
        self.at(step, go)

    def resize(self, cid, vmid, step, maxcpu=None, maxmem_gib=None):
        def go(c=self.clusters[cid]):
            g = c.guests.get(vmid)
            if g is not None:
                if maxcpu is not None:
                    g.maxcpu = maxcpu
                if maxmem_gib is not None:
                    g.maxmem = maxmem_gib * _GIB
        self.at(step, go)

    def delete(self, cid, vmid, step):
        def go(c=self.clusters[cid]):
            if c.guests.pop(vmid, None) is not None:
                c.order = None
        self.at(step, go)

    def create(self, cid, step, guest):
        def go(c=self.clusters[cid]):
            c.guests[guest.vmid] = guest
            c.order = None
        self.at(step, go)

    def power(self, cid, vmid, step, on):
        def go(c=self.clusters[cid]):
            g = c.guests.get(vmid)
            if g is not None:
                g.on = on
        self.at(step, go)

    def node_down(self, cid, name, first, last):
        def down(c=self.clusters[cid]):
            c.nodes[name].online = False
        def up(c=self.clusters[cid]):
            c.nodes[name].online = True
            c.nodes[name].down_for = 0
        self.at(first, down)
        self.at(last + 1, up)

    def node_join(self, cid, step, name, maxcpu, maxmem_gib, sensor=None):
        def go(c=self.clusters[cid]):
            c.node(name, maxcpu, maxmem_gib, sensor)
            c.order = None
        self.at(step, go)

    # running it ------------------------------------------------------------------------
    def ts(self, step):
        return self.start + step * self.cadence + self._tick.uniform(1, self.jitter)

    def _live(self, c, step, ts):
        """What the manager of `c` holds at this step: nodes, resources, storage rows,
        the sensor readings and the hardware summaries."""
        rv = self._val.random
        day = (ts - self.start) / 86400.0
        daily = math.sin(2 * math.pi * ((ts % 86400) / 86400.0))
        cores = {n: nd.base_cpu * nd.maxcpu for n, nd in c.nodes.items()}
        mem = {n: nd.base_mem for n, nd in c.nodes.items()}
        resources = []
        order = c.resource_order()
        if self.shuffle_every and step % self.shuffle_every == 7:
            # PVE hands the list back in another order now and then
            order = list(order)
            random.Random(self.seed * 31 + step).shuffle(order)
        for g in order:
            nd = c.nodes.get(g.node)
            # a guest on a host that went away stays 'running' for a while (the last word
            # PVE had of it), then turns 'unknown'
            running = g.on and nd is not None and (nd.online or nd.down_for < 12)
            if running:
                cpu = g.cpu_base + g.cpu_amp * daily + g.cpu_noise * rv()
                if cpu < 0:
                    cpu = 0.0
                if g.burst and rv() < 0.05:
                    cpu = 1.053
                m = g.mem_base + g.mem_drift * day + g.mem_noise * rv()
                m = int(g.maxmem * (0.02 if m < 0.02 else 0.99 if m > 0.99 else m))
                if nd.online:
                    cores[g.node] += cpu * g.maxcpu
                    mem[g.node] += m
                status = 'running'
            else:
                cpu, m = 0, 0
                status = 'unknown' if nd is not None and not nd.online else 'stopped'
            r = {'id': f'{g.t}/{g.vmid}', 'vmid': g.vmid, 'name': g.name, 'type': g.t,
                 'status': status, 'node': g.node, 'cpu': cpu, 'mem': m,
                 'maxmem': g.maxmem, 'maxcpu': g.maxcpu, 'maxdisk': g.maxdisk}
            if g.nodeless:
                del r['node']
            resources.append(r)
        if c.blank_vmid and c.blank_vmid[0] <= step <= c.blank_vmid[1]:
            resources.append({'type': 'qemu', 'status': 'running', 'name': 'half-made', 'vmid': ''})
        nodes, sensors, hw = {}, {}, {}
        for n, nd in c.nodes.items():
            if not nd.online:
                nd.down_for += 1
                nodes[n] = {'node': n, 'status': 'offline', 'maxcpu': nd.maxcpu, 'maxmem': nd.maxmem}
                continue
            frac = min(cores[n] / nd.maxcpu + 0.01 * rv(), 1.0)
            nodes[n] = {'node': n, 'status': 'online', 'cpu': frac, 'maxcpu': nd.maxcpu,
                        'mem': min(mem[n], nd.maxmem), 'maxmem': nd.maxmem}
            if nd.sensor is not None:
                base = nd.sensor + 18 * frac
                sensors[n] = [round(base + rv(), 3), round(base - 4 + rv(), 3)]
            if nd.hw is not None:
                hw[n] = _hw_summary(nd.hw(step))
        storage = []
        online = [n for n, nd in c.nodes.items() if nd.online]
        for st in c.storage:
            used = int(st.used + st.growth * day + st.total * 0.002 * rv())
            used = max(0, min(used, st.total))
            for n in (online if st.per_node else online[:1]):
                storage.append({'id': f'storage/{n}/{st.sid}', 'storage': st.sid, 'node': n,
                                'disk': used, 'maxdisk': st.total})
                used = int(used * 0.9)  # another host's copy of a local storage
        return {'name': c.name, 'nodes': nodes, 'resources': resources, 'storage': storage,
                'sensors': sensors, 'hw': hw, 'ssh': c.ssh, 'hw_on': self.hw_on,
                'fail': self.fails.get((c.cid, step))}

    def _bend(self, step, ts, clusters):
        """What older or odd writers left: no 'n' before #965, and the off-shape cluster."""
        if self.no_host_until is not None and ts < self.no_host_until:
            for cd in clusters.values():
                for e in cd['vms'].values():
                    e.pop('n', None)
        for cid, fn in self.odd.items():
            if cid in clusters:
                fn(step, clusters[cid]['vms'])

    def snapshot(self, step, ts):
        """{'timestamp', 'clusters'} as the collector hands it to save_metrics_snapshot."""
        clusters, live = {}, {}
        for cid, c in self.clusters.items():
            live[cid] = lv = self._live(c, step, ts)
            cd = cluster_entry(lv)
            if cd is not None:
                clusters[cid] = cd
        self.live = live
        if step in self.capture:
            self.captured[step] = (copy.deepcopy(live), ts, json.dumps(clusters))
        self._bend(step, ts, clusters)
        return {'timestamp': datetime.fromtimestamp(ts).isoformat(), 'clusters': clusters}

    def run(self):
        """(unix ts, snapshot) for every row of the history, oldest first."""
        for step in range(self.steps):
            for fn in self.events.get(step, ()):
                fn()
            self._drift(step)
            ts = self.ts(step)
            if step in self.gaps:
                continue
            yield ts, self.snapshot(step, ts)
            for after in self.extras.get(step, ()):
                yield ts + after, self.snapshot(step, ts + after)

    def _drift(self, step):
        """A guest switched on or off now and then, in every cluster."""
        r = self._tick
        for c in self.clusters.values():
            if c.guests and r.random() < 0.03:
                g = c.guests[r.choice(list(c.guests))]
                if not g.steady:
                    g.on = not g.on

    def write(self, save, progress=None):
        """Every row through save(snapshot) (the real save_metrics_snapshot); the count."""
        n = 0
        for _ts, snap in self.run():
            save(snap)
            n += 1
            if progress and n % 500 == 0:
                progress(n)
        return n


def _hw_summary(state):
    """What _node_hw_summary hands the collector: None (backed off, no key), 'na' (no BMC
    this time, the key is None) or a health string."""
    if state is None:
        return None
    if state == 'na':
        return {'available': False, 'reason': 'ipmitool not found'}
    return {'available': True, 'health': state, 'power_w': None, 'bad': [], 'source': 'inband'}


# --- guests ------------------------------------------------------------------------------

_PROFILES = (
    # weight, cpu base, cpu amp, cpu noise, mem base, mem drift/day, mem noise
    (20, 0.002, 0.001, 0.004, 0.10, 0.0, 0.05),     # idle
    (30, 0.02, 0.01, 0.03, 0.15, 0.0, 0.08),       # oversized
    (35, 0.18, 0.08, 0.20, 0.55, 0.002, 0.20),     # ordinary
    (10, 0.62, 0.15, 0.30, 0.78, 0.0, 0.15),       # busy
    (5, 0.30, 0.10, 0.25, 0.93, 0.001, 0.05),      # tight on RAM
)


def make_guest(rng, vmid, node, t=None, name=None, on=None):
    t = t or ('lxc' if vmid % 6 == 0 else 'qemu')
    pick = rng.random() * 100
    for w, *profile in _PROFILES:
        pick -= w
        if pick <= 0:
            break
    maxcpu = rng.choice((1, 2, 2, 4, 4, 8, 16))
    maxmem = rng.choice((1, 2, 4, 4, 8, 16, 32)) * _GIB
    maxdisk = rng.choice((8, 32, 32, 64, 100, 250)) * _GIB
    if on is None:
        on = rng.random() > 0.15
    return Guest(vmid, t, name or f'{t}-{vmid}', node, maxcpu, maxmem, maxdisk, on, tuple(profile))


def populate(fleet, c, vmids, rng):
    nodes = list(c.nodes)
    for i, vmid in enumerate(vmids):
        g = make_guest(rng, vmid, nodes[i % len(nodes)] if i % 5 else rng.choice(nodes))
        c.guests[vmid] = g
    c.order = None


# --- the golden scenario -----------------------------------------------------------------

# The server zone of the golden run: POSIX rules, so no tzdata is needed, and the window
# holds the night the clocks go back (2026-10-25 03:00 CEST -> 02:00 CET), when the naive
# local timestamps of the table repeat an hour.
GOLDEN_TZ = 'CET-1CEST,M3.5.0,M10.5.0/3'
GOLDEN_NOW = (2026, 10, 28, 13, 47, 12)   # local, read in GOLDEN_TZ
GOLDEN_STEPS = 10 * 288


def golden_fleet(now):
    """Three clusters, 12 nodes, about 300 guests, ten days at the 5-min cadence."""
    f = Fleet(seed=965, end=now - 240, steps=GOLDEN_STEPS)
    rng = random.Random(1155)
    day = 288

    # cluster_1: six hosts (one joins on day 5, one is away for six hours), temperatures on
    # most of them, a guest name nobody's spreadsheet likes, vmids reused after a delete
    c1 = f.cluster('cluster_1', 'Rechenzentrum Süd')
    for i, (cpu, mem) in enumerate(((32, 256), (32, 256), (48, 384), (16, 128), (16, 128)), 1):
        c1.node(f'pve{i}', cpu, mem, sensor=38.0 + i if i <= 4 else None)
    populate(f, c1, list(range(100, 270)), rng)
    c1.storage = [Storage('local-lvm', 2 * _TIB, int(0.4 * _TIB), per_node=True),
                  Storage('ceph-vm', 20 * _TIB, 9 * _TIB, growth=int(0.28 * _TIB)),
                  Storage('backup-nfs', 50 * _TIB, 30 * _TIB, growth=-int(0.2 * _TIB)),
                  Storage('iso', 0, 0)]
    c1.guests[104].name = 'Datenbank-Süd'
    c1.guests[105].name = '=HYPERLINK("x")'
    c1.guests[106].burst = True
    c1.guests[107].maxmem = 0          # a guest PVE reports no memory size for
    c1.guests[108].on = True
    for vmid in (110, 111, 112, 113):
        c1.guests[vmid].on = False     # never on in the window
    f.node_join('cluster_1', 5 * day, 'pve6', 64, 512, sensor=41.0)
    f.node_down('cluster_1', 'pve3', 8 * day, 8 * day + 71)
    on_pve3 = [v for v, g in sorted(c1.guests.items()) if g.node == 'pve3' and g.on][:3]
    for vmid in on_pve3:               # HA brings them up elsewhere after the stale hour
        f.migrate('cluster_1', vmid, 8 * day + 12, 'pve1')
    for k, vmid in enumerate((120, 121, 122, 123, 124, 125, 126, 127, 128)):
        f.migrate('cluster_1', vmid, day // 2 + 301 * k, f'pve{1 + (k + 2) % 5}')
    f.migrate('cluster_1', 121, 7 * day, 'pve6')        # moved twice
    c1.guests[121].on = c1.guests[121].steady = True
    f.migrate('cluster_1', 129, 6 * day, 'pve6')
    for k, vmid in enumerate((130, 131, 132, 133, 134, 135)):
        f.resize('cluster_1', vmid, 2 * day + 333 * k, maxcpu=(2, 8, 4, 16, 1, 6)[k],
                 maxmem_gib=(4, 16, 8, 32, 2, 12)[k])
    for k, vmid in enumerate((140, 141, 142, 143, 144, 145, 146, 147)):
        f.delete('cluster_1', vmid, day + 290 * k)
    # PVE's next free id: two deleted vmids come back as other guests; 277 arrives too late
    # for any figures of its own
    for vmid, step, node, t in ((140, 700, 'pve1', 'qemu'), (143, 1300, 'pve4', 'lxc'),
                                (270, 900, 'pve2', 'qemu'), (271, 1100, 'pve3', 'qemu'),
                                (272, 1500, 'pve1', 'lxc'), (273, 1700, 'pve5', 'qemu'),
                                (274, 1900, 'pve6', 'qemu'), (275, 2100, 'pve2', 'qemu'),
                                (276, 2500, 'pve6', 'qemu'), (277, 2850, 'pve4', 'qemu')):
        f.create('cluster_1', step, make_guest(rng, vmid, node, t=t, on=True))
    f.power('cluster_1', 150, 4 * day, False)            # switched off for good
    f.power('cluster_1', 151, 8 * day, True)

    # cluster_2: four hosts without SSH (no temperatures), a vmid at the top of PVE's range,
    # a resource row without a node, one without a vmid, a cycle whose guest list failed,
    # one where the cluster was not connected, a storage that is filling up fast
    c2 = f.cluster('cluster_2', 'edge', ssh=False)
    for i in range(1, 5):
        c2.node(f'edge{i}', 24, 192)
    populate(f, c2, list(range(1000, 1098)), rng)
    big = make_guest(rng, 999999999, 'edge2', t='qemu', name='top-of-range', on=True)
    c2.guests[big.vmid] = big
    c2.guests[1001].nodeless = True
    c2.blank_vmid = (4 * day, 4 * day + 40)
    c2.storage = [Storage('local', 1 * _TIB, int(0.3 * _TIB), per_node=True),
                  Storage('zfs-data', 8 * _TIB, int(6.2 * _TIB), growth=int(0.12 * _TIB))]
    for k, vmid in enumerate((1010, 1011, 1012, 1013)):
        f.delete('cluster_2', vmid, 3 * day + 500 * k)
        f.migrate('cluster_2', vmid + 10, 2 * day + 450 * k, f'edge{1 + (k + 1) % 4}')
    for k, vmid in enumerate((1010, 1098, 1099, 1100)):
        f.create('cluster_2', 5 * day + 200 * k, make_guest(rng, vmid, f'edge{1 + k % 4}', on=True))
    for k, vmid in enumerate((1030, 1031, 1032)):
        f.resize('cluster_2', vmid, 6 * day + 100 * k, maxcpu=(4, 2, 12)[k])
    f.fails[('cluster_2', 6 * day + 100)] = 'vms'
    f.fails[('cluster_2', 6 * day + 140)] = 'storage'
    f.fails[('cluster_2', 7 * day + 3)] = 'gone'

    # cluster_3: two hosts with BMC health, temperatures on one of them, and guest entries
    # off the usual shape in some cycles (the JSON fallback of a columnar store)
    c3 = f.cluster('cluster_3', 'legacy lab')
    c3.node('lab-a', 40, 320, sensor=44.0,
            hw=lambda s: 'critical' if 1500 <= s < 1506 else 'warning' if 4 * day <= s < 5 * day else 'ok')
    c3.node('lab-b', 40, 320, hw=lambda s: 'na' if s % 12 == 0 else None)
    populate(f, c3, list(range(300, 335)), rng)
    for vmid in (300, 301, 302, 303):
        c3.guests[vmid].on = c3.guests[vmid].steady = True
    c3.storage = [Storage('local', 512 * _GIB, 200 * _GIB, growth=2 * _GIB, per_node=True)]
    f.delete('cluster_3', 333, 5 * day)
    f.create('cluster_3', 6 * day, make_guest(rng, 335, 'lab-b', t='lxc', on=True))
    f.hw_on = True

    def odd(step, vms):
        e = vms.get('300')
        if e is not None and step % 5 == 0:
            e['note'] = 'imported'                    # a key the collector never wrote
        e = vms.get('301')
        if e is not None and step % 7 == 0 and e['cpu'] is not None:
            e['cpu'] = int(e['cpu'])                  # an int where a float was
        e = vms.get('302')
        if e is not None and step % 11 == 0 and e['cpu'] is not None:
            e['cpu'] = round(e['cpu'] + 0.04, 2)      # two decimals
        e = vms.get('303')
        if e is not None and step % 13 == 0:
            e['r'] = int(e['r'])                      # 1/0 for running
    f.odd['cluster_3'] = odd

    # the collector did not run for two hours on day 6; a few force-snapshot rows
    f.gaps.update(range(6 * day + 30, 6 * day + 54))
    for k, step in enumerate((day + 17, 8 * day + 5, 5 * day + 200, 8 * day + 99, 9 * day + 250)):
        f.extras[step] = [97 + 13 * k]
    # the first two days were written before #965
    f.no_host_until = f.start + 2 * 86400
    # steps the builder is held against the collector at: stale guests on a host that went
    # away, a shuffled resource list, a failed guest list, BMC health 'na', the blank vmid
    f.capture = {8 * day + 2, 8 * day + 30, 57, 6 * day + 100, 6 * day + 140, 7 * day + 3,
                 4 * day + 12, 1503, 9 * day}
    return f


def scale_fleet(guests, nodes, days, end, seed=3000, steps=None):
    """One cluster at fleet scale for the benchmark: `guests` guests on `nodes` hosts for
    `days` days at the 5-min cadence (or just `steps` cycles), with about 1 % churn,
    migrations and resizes."""
    f = Fleet(seed=seed, end=end, steps=steps or days * 288)
    rng = random.Random(seed + 1)
    c = f.cluster('cluster_1', 'scale')
    for i in range(1, nodes + 1):
        c.node(f'pve{i:03d}', rng.choice((32, 48, 64, 96, 128)), rng.choice((256, 384, 512, 768)),
               sensor=40.0 + i % 9 if i % 4 else None)
    populate(f, c, list(range(100, 100 + guests)), rng)
    c.storage = [Storage('local-lvm', 4 * _TIB, _TIB, per_node=True),
                 Storage('ceph-vm', 400 * _TIB, 180 * _TIB, growth=int(1.5 * _TIB)),
                 Storage('backup', 800 * _TIB, 300 * _TIB, growth=int(0.5 * _TIB))]
    names = list(c.nodes)
    churn = max(1, guests // 100)
    for k in range(churn):
        step = rng.randrange(f.steps)
        f.delete('cluster_1', 100 + rng.randrange(guests), step)
        f.create('cluster_1', rng.randrange(f.steps),
                 make_guest(rng, 100 + guests + k, rng.choice(names), on=True))
        f.migrate('cluster_1', 100 + rng.randrange(guests), rng.randrange(f.steps), rng.choice(names))
        if k % 2 == 0:
            f.resize('cluster_1', 100 + rng.randrange(guests), rng.randrange(f.steps),
                     maxcpu=rng.choice((2, 4, 8)), maxmem_gib=rng.choice((4, 8, 16)))
    f.shuffle_every = 50
    return f


# --- the live side: what the routes read of a cluster now --------------------------------

class FakeManager:
    """A cluster manager as the history routes and the collector read it, holding the
    fleet's live state of one cluster. Every call hands out copies."""
    cluster_type = 'proxmox'

    def __init__(self, cid, live):
        self.cluster_id = self.name = cid
        self._live = live
        self.config = types.SimpleNamespace(name=live['name'])
        self.is_connected = live['fail'] != 'gone'
        self.online = True
        self.host, self.api_port = '192.0.2.10', 8006
        self.current_host = None

    @property
    def nodes(self):
        return copy.deepcopy(self._live['nodes'])

    def get_vm_resources(self, max_age=None):
        if self._live['fail'] == 'vms':
            raise RuntimeError('cluster/resources timed out')
        return copy.deepcopy(self._live['resources'])

    def get_node_status(self):
        out = {}
        for n, nd in self._live['nodes'].items():
            if nd.get('status') != 'online':
                out[n] = {'status': nd.get('status')}
                continue
            out[n] = {'status': 'online', 'cpu_percent': round(nd['cpu'] * 100, 1),
                      'mem_percent': round(nd['mem'] / nd['maxmem'] * 100, 1),
                      'mem_total': nd['maxmem'], 'mem_used': nd['mem'], 'maxcpu': nd['maxcpu']}
        return out

    def ssh_blocked_reason(self):
        return None if self._live['ssh'] else 'ssh_disabled'

    def get_node_sensors(self, node):
        values = self._live['sensors'].get(node)
        if not values:
            return {'error': 'no sensors'}
        return {'sensors': [{'kind': 'temp', 'name': f'temp{i}', 'value': v} for i, v in enumerate(values)]}

    def hw_summary(self, node):
        return copy.deepcopy(self._live['hw'].get(node))

    def _create_session(self):
        live = self._live

        def get(url, timeout=None):
            if live['fail'] == 'storage':
                raise OSError('storage list timed out')
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': copy.deepcopy(live['storage'])})
        return types.SimpleNamespace(get=get)


RATES_STAMP = '2026-10-01T09:00:00'


def install(db, set_manager, fleet, tenants=None):
    """The live side of `fleet`: a manager per cluster, tenants, cost and power rates and
    host power profiles, all with fixed stamps."""
    for cid in fleet.clusters:
        set_manager(cid, FakeManager(cid, fleet.live[cid]))
    for tid, data in (tenants or {}).items():
        db.save_tenant(tid, data)
    cur = db.conn.cursor()
    cost = [('__default__', 0.012, 0.0035, 0.10, 'EUR', ''),
            ('cluster_3', 0.02, 0.005, 0.08, 'EUR', 'lab tier')]
    for row in cost:
        cur.execute('INSERT INTO cost_rates (cluster_id, cpu_per_core_h, mem_per_gb_h, storage_per_gb_month, '
                    'currency, notes, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?) '
                    'ON CONFLICT(cluster_id) DO UPDATE SET cpu_per_core_h=excluded.cpu_per_core_h, '
                    'mem_per_gb_h=excluded.mem_per_gb_h, storage_per_gb_month=excluded.storage_per_gb_month, '
                    'currency=excluded.currency, notes=excluded.notes, updated_at=excluded.updated_at, '
                    'updated_by=excluded.updated_by', row + (RATES_STAMP, 'root'))
    power = [('__default__', 80.0, 300.0, 0.3, 1.5, 0.30, 0.40),
             ('cluster_1', 120.0, 450.0, 0.375, 1.35, 0.28, 0.38)]
    for row in power:
        cur.execute('INSERT OR REPLACE INTO power_rates (cluster_id, node_idle_w, node_max_w, mem_w_per_gb, pue, '
                    'kwh_price, kg_co2_per_kwh, currency, notes, updated_at, updated_by) '
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'EUR', '', ?, 'root')", row + (RATES_STAMP,))
    first = next(iter(fleet.clusters))
    nodes = list(fleet.clusters[first].nodes)
    for node, idle, mx in ((nodes[1], 140.0, 520.0), (nodes[-1], 95.0, 410.0)):
        cur.execute('INSERT OR REPLACE INTO power_host_profiles (cluster_id, node, idle_w, max_w, notes, '
                    "updated_at, updated_by) VALUES (?, ?, ?, ?, 'measured', ?, 'root')",
                    (first, node, idle, mx, RATES_STAMP))
    if 'cluster_3' in fleet.clusters:
        cur.execute('INSERT OR REPLACE INTO power_host_profiles (cluster_id, node, idle_w, max_w, notes, '
                    "updated_at, updated_by) VALUES ('cluster_3', 'lab-b', 60.0, 60.0, 'flat', ?, 'root')",
                    (RATES_STAMP,))
    db.conn.commit()


# --- the routes ----------------------------------------------------------------------------

def cluster_routes(cid, node, guests, now, tenant):
    """(label, path) of every metrics-backed read for one cluster, the list the golden test
    and the benchmark share. guests: vmids for the guest charts; the first gets three ranges."""
    now = int(now)
    two_h, three_d, nine_d = (now - 7200, now), (now - 3 * 86400, now), (now - 9 * 86400 - 600, now)
    out = []
    for p in ('hour', 'day', 'week'):
        out.append((f'reports/summary {p}', f'/api/reports/summary?period={p}'))
    for p in ('hour', 'day', 'week'):
        out.append((f'reports/timeline {p}', f'/api/reports/timeline?period={p}'))
    base = f'/api/clusters/{cid}'
    for p in ('day', 'week'):
        out.append((f'{cid} report {p}', f'{base}/reports/summary?period={p}'))
    out.append((f'{cid} report range 9d', f'{base}/reports/summary?from={nine_d[0]}&to={nine_d[1]}'))
    out.append((f'{cid} temperature {node}', f'{base}/nodes/{node}/temperature-history'))
    for label, (a, b) in (('2h', two_h), ('3d', three_d), ('9d', nine_d)):
        out.append((f'{cid} node {node} history {label}', f'{base}/nodes/{node}/metrics-history?from={a}&to={b}'))
    for k, vmid in enumerate(guests):
        for label, (a, b) in (('2h', two_h), ('3d', three_d), ('9d', nine_d)) if k == 0 else (('9d', nine_d),):
            out.append((f'{cid} guest {vmid} history {label}', f'{base}/vms/{vmid}/metrics-history?from={a}&to={b}'))
    for d in (1, 7, 30, 90):
        out.append((f'{cid} right-sizing {d}', f'{base}/insights/right-sizing?days={d}'))
    out.append((f'{cid} forecast', f'{base}/insights/forecast'))
    out.append((f'{cid} forecast 7d at 60', f'{base}/insights/forecast?days=7&threshold_pct=60'))
    for d in (1, 7, 365):
        for step in (0, 3600):
            out.append((f'{cid} insights/history {d} step {step}', f'{base}/insights/history?days={d}&step={step}'))
    for d in (1, 7, 14, 30):
        out.append((f'{cid} costs summary {d}', f'{base}/costs/summary?days={d}'))
        out.append((f'{cid} costs per-vm {d}', f'{base}/costs/per-vm?days={d}'))
    out.append((f'chargeback {tenant}', f'/api/tenants/{tenant}/chargeback?days=30'))
    out.append((f'chargeback {tenant} csv', f'/api/tenants/{tenant}/chargeback?days=30&format=csv'))
    for d in (1, 7, 30):
        out.append((f'{cid} power summary {d}', f'{base}/power/summary?days={d}'))
        out.append((f'{cid} power per-vm {d}', f'{base}/power/per-vm?days={d}'))
    return out


# --- the pinned clocks ------------------------------------------------------------------------

_REAL_CLOCKS = {'datetime': _datetime.datetime, 'date': _datetime.date, 'datetime module': _datetime,
                'time module': _time, 'time': _time.time}


class _Same(type):
    """isinstance() of a pinned class still answers for the real one."""

    def __instancecheck__(cls, obj):
        return isinstance(obj, cls.__mro__[1])


def clocks(now):
    """{kind: stand-in} reading `now` (unix seconds) for each way a module holds a clock:
    the datetime and date classes, the datetime and time modules, time.time itself."""
    real_dt, real_date = _datetime.datetime, _datetime.date

    class PinnedDateTime(real_dt, metaclass=_Same):
        _clock_kind = 'datetime'

        @classmethod
        def now(cls, tz=None):
            return real_dt.fromtimestamp(now, tz)

        @classmethod
        def utcnow(cls):
            return real_dt.fromtimestamp(now, timezone.utc).replace(tzinfo=None)

        @classmethod
        def today(cls):
            return real_dt.fromtimestamp(now)

    class PinnedDate(real_date, metaclass=_Same):
        _clock_kind = 'date'

        @classmethod
        def today(cls):
            return real_date.fromtimestamp(now)

    def pinned_time():
        return now
    pinned_time._clock_kind = 'time'

    class PinnedTimeModule(types.ModuleType):
        def time(self):
            return now

        def time_ns(self):
            return int(now * 1_000_000_000)

        def __getattr__(self, name):
            return getattr(_time, name)

    class PinnedDatetimeModule(types.ModuleType):
        def __getattr__(self, name):
            return getattr(_datetime, name)

    dt_module = PinnedDatetimeModule('datetime')
    dt_module.datetime, dt_module.date = PinnedDateTime, PinnedDate
    dt_module._clock_kind = 'datetime module'
    time_module = PinnedTimeModule('time')
    time_module._clock_kind = 'time module'
    return {'datetime': PinnedDateTime, 'date': PinnedDate, 'datetime module': dt_module,
            'time module': time_module, 'time': pinned_time}


def _clock_kind(v, pinned_too=True):
    for kind, real in _REAL_CLOCKS.items():
        if v is real:
            return kind
    if pinned_too and isinstance(v, (type, types.ModuleType, types.FunctionType)):
        kind = getattr(v, '__dict__', {}).get('_clock_kind')
        return kind if kind in _REAL_CLOCKS else None
    return None


def pegaprox_modules():
    return [(n, m) for n, m in list(sys.modules.items())
            if m is not None and (n == 'pegaprox' or n.startswith('pegaprox.'))]


def real_clocks_in(mod):
    """(name, value) of the globals of `mod` that read the real wall clock."""
    return [(k, v) for k, v in list(vars(mod).items()) if _clock_kind(v, pinned_too=False)]


def pin_clocks(now, setattr_=setattr):
    """datetime.now/today/utcnow, date.today and time.time read `now` in every loaded
    pegaprox module, however it imported them (a module imported later is not covered:
    import it first). monotonic, perf_counter and sleep stay real. Pinning again moves
    the clocks to the new `now`. Pass monkeypatch.setattr to have a test undo it."""
    pinned = clocks(now)
    for _name, mod in pegaprox_modules():
        for attr, val in list(vars(mod).items()):
            kind = _clock_kind(val)
            if kind:
                setattr_(mod, attr, pinned[kind])
