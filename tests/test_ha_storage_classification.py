"""Where the disks of a dead node's guests are, for its recovery.

The recovery read each guest's config (GET /nodes/<node>/qemu/<vmid>/config) and
skipped only what that called 'local'. PVE proxies the read to <node> itself
(proxyto => 'node'), so for a dead node it never answers: the guest came out 'unknown'
and its config was moved to another node, its disks still on the dead node's local
storage. The start failed there, and once the node was back each config had to be
moved back by hand.

Every node of the quorate part holds the configs of all nodes in /etc/pve (pmxcfs).
Once the node does not answer, the recovery reads the configs of all its guests there,
in one SSH command and as they are at that moment, and moves nothing it cannot tell.
Nothing is classified ahead of time: a class worked out while the node was up is old
by the time it is needed, missing after a restart or a takeover of PegaProx, and at
10k guests the reads behind it never catch up.

The recovery runs are the monitor loop, its passes and the worker of
tests/test_ha_recovery_midloop.py, on its clock, with a cluster that keeps the disks
of each guest, answers a config read only from a node that is up and has /etc/pve on
each node that is up.

MK Oct 2026
"""
import os
import re
import subprocess
import threading
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as manager_mod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager

import test_ha_recovery_midloop as midloop

STORAGES = [
    {'storage': 'local', 'type': 'dir', 'content': 'iso,vztmpl,backup'},
    {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir'},
    {'storage': 'ceph', 'type': 'rbd', 'content': 'images,rootdir', 'shared': 1},
    {'storage': 'nas', 'type': 'nfs', 'content': 'iso,images'},
    # a storage only one node has
    {'storage': 'pve2-ssd', 'type': 'lvmthin', 'content': 'images', 'nodes': 'pve2'},
]
ON_LOCAL = {'scsi0': 'local-lvm:vm-100-disk-0,size=32G', 'ide2': 'none,media=cdrom'}
ON_CEPH = {'scsi0': 'ceph:vm-101-disk-0,size=32G', 'efidisk0': 'ceph:vm-101-disk-1,efitype=4m',
           'ide2': 'nas:iso/debian.iso,media=cdrom'}
LOCAL_ISO = {'scsi0': 'ceph:vm-102-disk-0,size=32G', 'ide2': 'local:iso/debian.iso,media=cdrom'}
NO_DISK = {'ide2': 'none,media=cdrom', 'net0': 'virtio=BC:24:11:00:00:03,bridge=vmbr0', 'boot': 'order=net0'}
GUESTS = {100: ON_LOCAL, 101: ON_CEPH, 102: LOCAL_ISO, 103: NO_DISK}


def _by_name(rows):
    return {s['storage']: s for s in rows}


# --- the class of one config -----------------------------------------------------------

@pytest.mark.parametrize('kind,config,want', [
    ('qemu', ON_LOCAL, 'local'),
    ('qemu', ON_CEPH, 'shared'),
    ('qemu', LOCAL_ISO, 'local'),
    ('qemu', NO_DISK, 'nodisk'),
    ('qemu', {}, 'nodisk'),
    # scsihw names no volume, unusedN is not started with
    ('qemu', {'scsihw': 'virtio-scsi-pci', 'scsi0': 'ceph:vm-1-disk-0', 'unused0': 'local-lvm:vm-1-disk-9'}, 'shared'),
    ('qemu', {'virtio0': 'file=ceph:vm-1-disk-0,size=8G'}, 'shared'),
    ('qemu', {'sata0': 'local-lvm:vm-1-disk-0'}, 'local'),
    ('qemu', {'tpmstate0': 'local-lvm:vm-1-disk-1,version=v2.0', 'scsi0': 'ceph:vm-1-disk-0'}, 'local'),
    # a passthrough disk, the host's own drive and a storage nobody knows
    ('qemu', {'scsi0': 'ceph:vm-1-disk-0', 'scsi1': '/dev/disk/by-path/pci-0000:00:1f.2-ata-1'}, 'local'),
    ('qemu', {'scsi0': 'ceph:vm-1-disk-0', 'ide2': 'cdrom,media=cdrom'}, 'local'),
    ('qemu', {'scsi0': 'gone:vm-1-disk-0'}, 'local'),
    # a cloud-init drive is made afresh at the start, where its storage is on every node
    ('qemu', {'scsi0': 'ceph:vm-1-disk-0', 'ide2': 'local-lvm:vm-1-cloudinit,media=cdrom'}, 'shared'),
    ('qemu', {'scsi0': 'ceph:vm-1-disk-0', 'ide0': 'local:1/vm-1-cloudinit.qcow2,media=cdrom'}, 'shared'),
    ('qemu', {'scsi0': 'ceph:vm-1-disk-0', 'ide2': 'pve2-ssd:vm-1-cloudinit,media=cdrom'}, 'local'),
    ('qemu', {'scsi0': 'ceph:vm-1-disk-0', 'ide2': 'gone:vm-1-cloudinit,media=cdrom'}, 'local'),
    ('qemu', {'scsi0': 'local-lvm:vm-1-disk-0-cloudinit'}, 'local'),
    ('lxc', {'rootfs': 'local-lvm:vm-200-cloudinit,size=8G'}, 'local'),
    ('lxc', {'rootfs': 'ceph:vm-200-disk-0,size=8G', 'mp0': 'ceph:vm-200-disk-1,mp=/data'}, 'shared'),
    ('lxc', {'rootfs': 'ceph:vm-200-disk-0,size=8G', 'mp0': 'local-lvm:vm-200-disk-1,mp=/data'}, 'local'),
    ('lxc', {'rootfs': 'ceph:vm-200-disk-0', 'mp1': '/mnt/scratch,mp=/scratch'}, 'local'),
    ('lxc', {'rootfs': 'ceph:vm-200-disk-0', 'mp1': '/mnt/pve/nas,mp=/nas,shared=1'}, 'shared'),
    # an lxc has no scsi disks, a qemu guest no rootfs
    ('lxc', {'rootfs': 'ceph:vm-200-disk-0', 'scsi0': 'local-lvm:x'}, 'shared'),
])
def test_the_class_of_a_config(kind, config, want):
    assert PegaProxManager._ha_volume_class(config, kind, _by_name(STORAGES)) == want


def test_a_storage_is_shared_by_its_flag_or_its_type():
    shared = PegaProxManager._ha_storage_shared
    assert shared({'type': 'lvm', 'shared': 1}) and shared({'type': 'rbd'}) and shared({'type': 'starlvm'})
    assert not shared({'type': 'lvm', 'shared': 0}) and not shared({'type': 'zfspool'})
    assert not shared({'type': 'dir', 'shared': '0'})


# --- the configs in /etc/pve ---------------------------------------------------------------

def test_a_config_file_reads_as_the_api_answers_it():
    """The main part with the pending changes over it; the description, the snapshots and
    the cloud-init section say nothing about what the guest starts with."""
    vm = ('#web\n#scsi0: local-lvm:forged\nboot: order=scsi0\nscsi0: ceph:vm-101-disk-0,size=32G\n'
          'ide2: none,media=cdrom\n\n[PENDING]\nscsi0: local-lvm:vm-101-disk-3,size=32G\n\n'
          '[special:cloudinit]\nipconfig0: ip=dhcp\n\n[before-upgrade]\nscsi1: local-lvm:vm-101-disk-1\n'
          'vmstate: local-lvm:vm-101-state-before-upgrade\n')
    assert PegaProxManager._ha_parse_guest_config(vm.splitlines()) == {
        'boot': 'order=scsi0', 'scsi0': 'local-lvm:vm-101-disk-3,size=32G', 'ide2': 'none,media=cdrom'}
    ct = ('arch: amd64\r\nrootfs: ceph:vm-200-disk-0,size=8G\r\n[pve:pending]\r\nmp0: local-lvm:vm-200-disk-1,mp=/d\r\n'
          '[snap1]\r\nmp1: /mnt,mp=/mnt\r\n')
    assert PegaProxManager._ha_parse_guest_config(ct.splitlines()) == {
        'arch': 'amd64', 'rootfs': 'ceph:vm-200-disk-0,size=8G', 'mp0': 'local-lvm:vm-200-disk-1,mp=/d'}


def _text(cfg, description='a guest'):
    return f'#{description}\n' + ''.join(f'{k}: {v}\n' for k, v in cfg.items())


def _reader(answers):
    """A manager whose SSH to a node answers from `answers`: node -> output, or a
    callable of the command. What was sent is in .sent, with whether ha.reading() was on."""
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.sent = []

    def output(node, cmd, timeout=60):
        m.sent.append((node, cmd, getattr(ha._guard_tls, 'reading', 0)))
        answer = answers.get(node)
        return answer(cmd) if callable(answer) else answer
    m._ssh_node_output = output
    return m


def _shell(tree):
    """The command as a shell on a node runs it, with `tree` for /etc/pve."""
    def run(cmd):
        r = subprocess.run(['bash', '-c', cmd.replace('/etc/pve/', f'{tree}/')], capture_output=True, text=True,
                           timeout=30)
        return r.stdout if r.returncode == 0 else None
    return run


def _etc(tmp_path, files):
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def test_the_configs_are_read_in_one_command_on_the_first_other_node_that_answers(tmp_path):
    """pve1 does not answer, pve3 does: its shell gets one command for all the guests of
    pve2, in ha.reading(). 102 has no config there (moved meanwhile), and the snapshot
    in 101's file does not count."""
    tree = _etc(tmp_path, {
        'nodes/pve2/qemu-server/100.conf': _text(ON_LOCAL),
        'nodes/pve2/qemu-server/101.conf': _text(ON_CEPH) + '\n[before]\nscsi1: local-lvm:vm-101-disk-7\n',
        'nodes/pve2/lxc/200.conf': _text({'rootfs': 'ceph:vm-200-disk-0,size=8G'}),
        'nodes/pve3/qemu-server/102.conf': _text(LOCAL_ISO),
    })
    m = _reader({'pve1': None, 'pve3': _shell(tree)})
    guests = [{'vmid': 100, 'type': 'qemu'}, {'vmid': 101, 'type': 'qemu'}, {'vmid': 102, 'type': 'qemu'},
              {'vmid': 200, 'type': 'lxc'}]

    got = m._ha_read_guest_configs('pve2', guests, ['pve2', 'pve1', 'pve3', 'pve4'])

    assert [(node, reading > 0) for node, _cmd, reading in m.sent] == [('pve1', True), ('pve3', True)]
    assert got == {100: ON_LOCAL, 101: ON_CEPH, 200: {'rootfs': 'ceph:vm-200-disk-0,size=8G'}}


def test_three_nodes_are_asked_at_most_and_no_answer_is_none(tmp_path):
    m = _reader({'pve5': _shell(_etc(tmp_path, {'nodes/pve2/qemu-server/100.conf': _text(ON_LOCAL)}))})

    assert m._ha_read_guest_configs('pve2', [{'vmid': 100, 'type': 'qemu'}],
                                    [f'pve{i}' for i in range(1, 9)]) is None
    assert [node for node, _c, _r in m.sent] == ['pve1', 'pve3', 'pve4']


def test_a_node_without_the_directory_of_the_failed_node_is_no_answer(tmp_path):
    m = _reader({'pve1': _shell(_etc(tmp_path, {'nodes/pve1/qemu-server/1.conf': 'x: y\n'}))})

    assert m._ha_read_guest_configs('pve2', [{'vmid': 100, 'type': 'qemu'}], ['pve1']) is None


@pytest.mark.skipif(os.geteuid() == 0, reason='root reads a file of mode 000')
def test_a_config_that_cannot_be_read_is_no_answer_from_that_node(tmp_path):
    """Half of the read would leave out what the unreadable file has: the node that
    failed it counts as one that did not answer, the next one is asked."""
    tree = _etc(tmp_path / 'a', {'nodes/pve2/qemu-server/100.conf': _text(ON_LOCAL),
                                 'nodes/pve2/qemu-server/101.conf': _text(ON_CEPH)})
    (tree / 'nodes/pve2/qemu-server/100.conf').chmod(0)
    good = _etc(tmp_path / 'b', {'nodes/pve2/qemu-server/100.conf': _text(ON_LOCAL),
                                 'nodes/pve2/qemu-server/101.conf': _text(ON_CEPH)})
    m = _reader({'pve1': _shell(tree), 'pve3': _shell(good)})

    got = m._ha_read_guest_configs('pve2', [{'vmid': 100, 'type': 'qemu'}, {'vmid': 101, 'type': 'qemu'}],
                                   ['pve1', 'pve3'])

    assert [node for node, _c, _r in m.sent] == ['pve1', 'pve3'] and got == {100: ON_LOCAL, 101: ON_CEPH}


def test_no_line_of_a_config_starts_the_file_of_another_guest(tmp_path):
    """101's description, and a line someone wrote into the file by hand, look like the
    line between two files: the line of this read has a part nobody could guess."""
    fake = '--- ' + '0' * 32 + ' qemu-server/100.conf'
    tree = _etc(tmp_path, {'nodes/pve2/qemu-server/101.conf':
                           f'#{fake}\n{fake}\nscsi0: local-lvm:vm-100-disk-0\n'})
    m = _reader({'pve1': _shell(tree)})

    got = m._ha_read_guest_configs('pve2', [{'vmid': 100, 'type': 'qemu'}, {'vmid': 101, 'type': 'qemu'}], ['pve1'])

    assert got == {101: {'scsi0': 'local-lvm:vm-100-disk-0'}}


@pytest.mark.parametrize('node', ['pve2; reboot', 'pve2 && rm -rf /', '$(id)', '', None])
def test_a_node_name_that_is_no_host_name_goes_into_no_shell(node):
    m = _reader({'pve1': ''})

    assert m._ha_read_guest_configs(node, [{'vmid': 100, 'type': 'qemu'}], ['pve1']) is None
    assert m.sent == []


def test_one_command_reads_the_hundred_guests_of_a_node(tmp_path):
    files = {f'nodes/pve7/qemu-server/{v}.conf': _text({'scsi0': f'ceph:vm-{v}-disk-0'}) for v in range(1000, 1100)}
    m = _reader({'pve1': _shell(_etc(tmp_path, files))})

    got = m._ha_read_guest_configs('pve7', [{'vmid': v, 'type': 'qemu'} for v in range(1000, 1100)], ['pve1'])

    assert len(m.sent) == 1 and len(m.sent[0][1]) < 4000
    assert got == {v: {'scsi0': f'ceph:vm-{v}-disk-0'} for v in range(1000, 1100)}


# --- nothing ahead of time ---------------------------------------------------------------

class Api:
    """GET of the API host for `nodes` nodes with `per_node` running guests each, a
    fifth of them on their node's local-lvm. Every path asked is kept."""

    def __init__(self, nodes=100, per_node=100):
        self.nodes = [f'pve{i}' for i in range(1, nodes + 1)]
        self.guests = {}
        vmid = 100
        for n in self.nodes:
            for j in range(per_node):
                where = 'local-lvm' if j % 5 == 0 else 'ceph'
                self.guests[vmid] = (n, {'scsi0': f'{where}:vm-{vmid}-disk-0,size=32G'})
                vmid += 1
        self.paths = []
        self.down = set()

    def get(self, url, params=None, timeout=10, **kw):
        path = url.split('/api2/json', 1)[1]
        self.paths.append(path)
        if path == '/nodes':
            return midloop._answer([{'node': n, 'status': 'online'} for n in self.nodes])
        if path == '/storage':
            return midloop._answer(STORAGES)
        if path == '/cluster/resources':
            rows = [{'type': 'node', 'node': n, 'status': 'online'} for n in self.nodes]
            rows += [{'type': 'storage', 'node': n, 'storage': s['storage'], 'status': 'available'}
                     for n in self.nodes for s in STORAGES]
            rows += [{'type': 'qemu', 'vmid': v, 'node': n, 'status': 'running'} for v, (n, _c) in self.guests.items()]
            return midloop._answer(rows)
        if path.endswith('/content'):
            return midloop._answer([])
        m = re.fullmatch(r'/nodes/([\w-]+)/qemu/(\d+)/config', path)
        if m:
            if m.group(1) in self.down:
                return midloop._answer(None, 595, 'no route to host')
            return midloop._answer(dict(self.guests[int(m.group(2))][1]))
        raise AssertionError(url)


def _mgr(api):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m.logger = MagicMock()
    m.config = types.SimpleNamespace(name='lab', host='10.9.0.1', api_port=8006, fallback_hosts=[])
    m.current_host = '10.9.0.1'
    m.is_connected = True
    m.ha_lock = threading.Lock()
    m.ha_node_status = {n: {'status': 'online', 'consecutive_failures': 0} for n in api.nodes}
    m._create_session = lambda: api
    return m


def test_between_failures_the_monitor_reads_nothing_per_guest(monkeypatch):
    """100 nodes, 10k guests: a monitor pass asks for the node list and nothing else, no
    storage listing and no config in the background. The recovery reads what it needs
    once a node is gone."""
    clock = types.SimpleNamespace(now=1000.0)
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(sleep=lambda s: None, monotonic=lambda: clock.now,
                                                                    time=lambda: 1_790_000_000.0 + clock.now))
    monkeypatch.setattr(manager_mod.ha, 'is_active', lambda: True)
    api = Api()
    m = _mgr(api)
    m.ha_check_interval = 10
    m.ha_enabled = True
    m.stop_event = threading.Event()
    passes = []

    def check():
        api.get(f'https://{m.host}:8006/api2/json/nodes')
        passes.append(clock.now)
        clock.now += 10
        m.ha_enabled = len(passes) < 60
    m._ha_check_nodes = check
    m._ha_update_fallback_hosts = lambda: None
    m._ha_agent_members_changed = lambda: False

    m._ha_monitor_loop()

    assert len(passes) == 60 and set(api.paths) == {'/nodes'}


def test_the_balancer_still_reads_a_guest_without_disks_as_unknown():
    api = Api(nodes=1, per_node=1)
    api.guests[100] = ('pve1', dict(NO_DISK))
    m = _mgr(api)

    assert m._ha_check_vm_storage(100, 'qemu', 'pve1') == 'nodisk'
    assert m.check_vm_storage_type('pve1', 100, 'qemu') == 'unknown'
    api.down.add('pve1')
    assert m._ha_check_vm_storage(100, 'qemu', 'pve1') == 'unknown'


# --- the recovery of a node that is gone ---------------------------------------------------

class _Cluster(midloop.Pve):
    """The cluster of the midloop runs, with the disks of each guest (layout) and the
    storages: GET /storage, /cluster/resources with nodes and storages, the content of
    a storage on a node (with the `orphans` no config names), and the config read that
    PVE proxies to the guest's node, so answered only while that node is up (or with
    proxy_while_out, a node out of the cluster whose API still answers). Over SSH each
    node that is up has /etc/pve, but those in ssh_down do not answer, and the configs
    of not_in_etc are gone from it."""

    layout = {}
    proxy_while_out = False
    orphans = {}
    ssh_down = ()
    not_in_etc = ()

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.disks = {v: dict(cfg) for v, cfg in self.layout.items()}
        self.conf = {v: 'pve2' for v in self.disks}
        self.runs = {v: {'pve2'} for v in self.disks}
        self.home = dict(self.conf)     # where their local volumes are

    def get(self, url, params=None, timeout=10, **kw):
        path = url.split('/api2/json', 1)[1]
        answer = None
        with self.lock:
            self._catch_up()
            if path == '/storage':
                answer = midloop._answer(STORAGES)
            elif path == '/cluster/resources' and not params:
                ips = midloop.IPS
                rows = [{'type': 'node', 'node': n, 'status': 'online' if self.online(n) else 'offline'} for n in ips]
                rows += [{'type': 'storage', 'node': n, 'storage': s['storage'],
                          'status': 'available' if self.online(n) else 'unknown'} for n in ips for s in STORAGES]
                rows += [{'type': 'qemu', 'vmid': v, 'node': n, 'name': f'g{v}',
                          'status': self._status(v, n) if self.online(n) else self.frozen.get(v, 'unknown')}
                         for v, n in sorted(self.conf.items())]
                answer = midloop._answer(rows)
            elif re.fullmatch(r'/nodes/\w+/storage/[\w-]+/content', path):
                node, storage = path.split('/')[2], path.split('/')[4]
                assert self.online(node), path
                answer = midloop._answer([
                    {'volid': value.split(',')[0], 'vmid': v, 'content': 'images'}
                    for v, cfg in self.disks.items() if self.home[v] == node
                    for value in cfg.values() if value.startswith(f'{storage}:') and 'media=cdrom' not in value]
                    + list(self.orphans.get((node, storage), ())))
            elif re.fullmatch(r'/nodes/\w+/qemu/\d+/config', path):
                node, v = path.split('/')[2], int(path.split('/')[4])
                if not self.online(node) and not (self.proxy_while_out and node == 'pve2'):
                    answer = midloop._answer(None, 595, f'Errors during connection establishment: {node}: '
                                                        'No route to host')
                elif self.conf[v] != node:
                    answer = midloop._answer(None, 500, f"Configuration file 'nodes/{node}/qemu-server/{v}.conf' "
                                                        "does not exist")
                else:
                    answer = midloop._answer(dict(self.disks[v]))
            if answer is not None:
                self.calls.append((self.clock.now, 'GET', path))
        if answer is not None:
            return answer
        return super().get(url, params=params, timeout=timeout, **kw)

    def ssh_output(self, node, cmd, timeout=60):
        """A command over SSH on `node` as _ha_read_guest_configs sends it: the configs
        under /etc/pve/nodes/<x>, which every node of the quorate part has."""
        m = re.fullmatch(r"cd /etc/pve/nodes/(\w+) \|\| exit 1; for f in (.+?); do .*echo '(--- [0-9a-f]{32})' .*",
                         cmd)
        assert m and getattr(ha._guard_tls, 'reading', 0), cmd
        where, paths, mark = m.groups()
        with self.lock:
            self._catch_up()
            self.calls.append((self.clock.now, 'SSH', f'configs of {where} on {node}'))
            if not self.online(node) or node in self.ssh_down:
                return None
            out = []
            for path in paths.split():
                v = int(re.search(r'(\d+)\.conf$', path).group(1))
                if self.conf.get(v) == where and v in self.disks and v not in self.not_in_etc:
                    out += ['', f'{mark} {path}', _text(self.disks[v], f'guest {v}')]
            return '\n'.join(out)

    def reads(self, node='pve2', after=5):
        """The config reads through the API for `node`'s guests from `after` on."""
        return [p for t, kind, p in self.calls if kind == 'GET' and t >= after
                and re.fullmatch(rf'/nodes/{node}/qemu/\d+/config', p)]


def _gone(monkeypatch, layout=GUESTS, out=((5, midloop.NEVER),), setup=None, probes=(), **cluster):
    """pve2, with the guests of `layout` running on it, falls out of the cluster at 5 s
    and stays out (or as `out` says). The manager's own storage check, not the 'shared'
    of the midloop runs."""
    cluster = type('Cluster', (_Cluster,), dict({'layout': layout}, **cluster))
    monkeypatch.setattr(midloop, 'Pve', cluster)

    def ready(pve, m):
        del m._ha_check_vm_storage
        m._ssh_node_output = pve.ssh_output
        m._probe_cluster = pve
        if setup:
            setup(pve, m)
    return midloop._run(monkeypatch, [tuple(o) for o in out], setup=ready, probes=probes)


def _started(pve):
    return [e for _t, e in pve.happened('start')]


def _ssh_reads(pve):
    return [e for _t, kind, e in pve.calls if kind == 'SSH']


def test_a_dead_node_keeps_the_guests_whose_disks_are_on_its_own_storage(monkeypatch):
    """100 has its disk on pve2's local-lvm, 102 an ISO in its CD-ROM drive from pve2's
    local: both stay with pve2, their configs never move. 101 (ceph, an ISO on the NFS
    share) and 103 (no disk at all) are recovered. pve2 is asked for the first config
    only (595, as from any node that is down), then the configs of all four are read
    once, in /etc/pve on pve1."""
    run = _gone(monkeypatch)
    pve = run.pve

    assert pve.moves() == ['config 101 moved pve2 -> pve1', 'config 103 moved pve2 -> pve1']
    assert _started(pve) == ['start 101 on pve1', 'start 103 on pve1']
    assert pve.conf[100] == pve.conf[102] == 'pve2'
    assert run.log.said('SKIPPING g100 (100) - Uses LOCAL storage') and run.log.said('SKIPPING g102 (102)')
    assert run.log.said('Recovered: 2, Failed: 0, Skipped (local storage): 2, Skipped (storage not known): 0')
    assert run.log.said('HA RECOVERY COMPLETE')
    assert pve.reads() == ['/nodes/pve2/qemu/100/config']
    assert _ssh_reads(pve) == ['configs of pve2 on pve1']
    assert not run.pushed and not run.audits


ALL_CEPH = {100: ON_LOCAL, 101: ON_CEPH, 103: NO_DISK,
            104: {'scsi0': 'ceph:vm-104-disk-0,size=32G'}, 105: {'scsi0': 'ceph:vm-105-disk-0,size=8G'}}


def test_a_pegaprox_that_starts_after_the_node_died_recovers_what_it_can(monkeypatch):
    """pve2 is gone from the first pass of this PegaProx on: a restart during the
    outage, or a standby of an automatic group that takes over from a leader that went
    down with pve2. Nothing was known about pve2's guests before; the read at the
    recovery recovers all of them that can move, and 100 stays."""
    run = _gone(monkeypatch, ALL_CEPH, out=[(0, midloop.NEVER)])
    pve = run.pve

    assert pve.moves() == [f'config {v} moved pve2 -> pve1' for v in (101, 103, 104, 105)]
    assert pve.conf[100] == 'pve2' and run.log.said('SKIPPING g100 (100) - Uses LOCAL storage')


def test_a_disk_left_unused_on_local_storage_does_not_keep_a_guest_down(monkeypatch):
    """101 was moved to ceph with 'Move disk', 'Delete source' left off as the GUI has
    it: its old disk is unused0 on pve2's local-lvm, and it starts on any node."""
    run = _gone(monkeypatch, {101: {'scsi0': 'ceph:vm-101-disk-0,size=32G', 'unused0': 'local-lvm:vm-101-disk-1'},
                              103: NO_DISK})

    assert run.pve.moves() == ['config 101 moved pve2 -> pve1', 'config 103 moved pve2 -> pve1']


def test_a_volume_of_the_guest_on_another_node_does_not_keep_it_down(monkeypatch):
    """pve3's local-lvm still has vm-101-disk-0 from a migration that failed half way,
    no config names it."""
    orphans = {('pve3', 'local-lvm'): [{'volid': 'local-lvm:vm-101-disk-0', 'vmid': 101, 'content': 'images'}]}
    run = _gone(monkeypatch, {101: {'scsi0': 'ceph:vm-101-disk-7,size=32G'}, 103: NO_DISK}, orphans=orphans)

    assert run.pve.moves() == ['config 101 moved pve2 -> pve1', 'config 103 moved pve2 -> pve1']


def test_a_cloud_init_drive_on_local_storage_does_not_keep_a_guest_down(monkeypatch):
    """qemu-server makes the cloud-init drive afresh at the start where it is missing:
    101's drive is on local-lvm, which every node has, and 101 moves. 104's is on a
    storage of pve2 alone, and it stays."""
    run = _gone(monkeypatch, {
        101: {'scsi0': 'ceph:vm-101-disk-0,size=32G', 'ide2': 'local-lvm:vm-101-cloudinit,media=cdrom'},
        104: {'scsi0': 'ceph:vm-104-disk-0,size=32G', 'ide2': 'pve2-ssd:vm-104-cloudinit,media=cdrom'}})

    assert run.pve.moves() == ['config 101 moved pve2 -> pve1']
    assert run.pve.conf[104] == 'pve2' and run.log.said('SKIPPING g104 (104) - Uses LOCAL storage')


def test_the_disks_decide_as_they_are_when_the_node_is_gone(monkeypatch):
    """At 3 s, two seconds before pve2 fails: 101's disk moves from pve2's local-lvm to
    ceph ('Delete source' ticked), 102's from ceph to pve2's local-lvm. What counts is
    the config at the recovery: 101 moves, 102 stays."""
    def move_disks(m):
        m._probe_cluster.disks[101]['scsi0'] = 'ceph:vm-101-disk-0,size=32G'
        m._probe_cluster.disks[102]['scsi0'] = 'local-lvm:vm-102-disk-0,size=32G'
    run = _gone(monkeypatch, {101: {'scsi0': 'local-lvm:vm-101-disk-0,size=32G'},
                              102: {'scsi0': 'ceph:vm-102-disk-0,size=32G'}, 103: NO_DISK},
                probes=[(3, move_disks)])

    assert run.seen
    assert run.pve.moves() == ['config 101 moved pve2 -> pve1', 'config 103 moved pve2 -> pve1']
    assert run.pve.conf[102] == 'pve2' and run.log.said('SKIPPING g102 (102) - Uses LOCAL storage')


def test_guests_whose_configs_cannot_be_read_stay_and_are_reported(monkeypatch):
    """No node answers over SSH and pve2 does not answer for a config: nothing is moved,
    and the guests left down go to the audit log and out as a critical push, the
    recovery does not call itself complete. pve2 is asked for one config, not one per
    guest."""
    run = _gone(monkeypatch, out=[(0, midloop.NEVER)], ssh_down=('pve1', 'pve3'))
    pve = run.pve

    assert pve.moves() == [] and _started(pve) == []
    pushed = [d for _t, _e, d in run.pushed if d.get('event') == 'ha.recovery_unclassified']
    assert len(pushed) == 1 and pushed[0]['severity'] == 'critical' and pushed[0]['node'] == 'pve2'
    assert '100, 101, 102, 103' in pushed[0]['message']
    assert [a for _t, a, _d in run.audits] == ['ha.recovery_unclassified']
    assert run.log.said('HA RECOVERY ENDED') and not run.log.said('HA RECOVERY COMPLETE')
    for v in GUESTS:
        assert run.log.said(f'SKIPPING g{v} ({v}) - pve2 does not answer for its config, and no other node did '
                            'over SSH: its disks may be on pve2, not recovered')
    assert run.log.said('Skipped (local storage): 0, Skipped (storage not known): 4')
    assert pve.reads(after=0) == ['/nodes/pve2/qemu/100/config']
    assert _ssh_reads(pve) == ['configs of pve2 on pve1', 'configs of pve2 on pve3']


def test_the_node_itself_decides_while_it_answers_for_the_configs(monkeypatch):
    """pve2 is out of the cluster while its API still answers for the configs, and no
    node answers over SSH: pve2's answer recovers 101 and 103 and keeps 100 and 102."""
    run = _gone(monkeypatch, proxy_while_out=True, ssh_down=('pve1', 'pve3'))

    assert run.pve.moves() == ['config 101 moved pve2 -> pve1', 'config 103 moved pve2 -> pve1']
    assert run.pve.conf[100] == run.pve.conf[102] == 'pve2'
    assert _ssh_reads(run.pve) == [] and not run.pushed


def test_a_guest_whose_config_left_the_node_is_not_moved(monkeypatch):
    """101's config is no longer under /etc/pve/nodes/pve2 when the recovery reads it
    (an admin moved it by hand): there is nothing to move, and it is named."""
    run = _gone(monkeypatch, not_in_etc=(101,))

    assert run.pve.moves() == ['config 103 moved pve2 -> pve1']
    assert run.log.said('SKIPPING g101 (101) - its config is not in /etc/pve/nodes/pve2 any more')
    pushed = [d for _t, _e, d in run.pushed if d.get('event') == 'ha.recovery_unclassified']
    assert len(pushed) == 1 and ': 101 - ' in pushed[0]['message']
