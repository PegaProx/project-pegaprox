# ESXi -> Proxmox migration: two ways a run said "completed" and the guest lost data.
#
# The TPM state. A VM with a vTPM gets tpmstate0 on target_storage when it is created, and
# Proxmox names it vm-<vmid>-disk-0 there. The disk allocation used to free whatever held
# vm-<vmid>-disk-<index> before it allocated (pvesm free, lvremove, the 'unused' lines out of
# the config), so disk 0 freed the TPM state and took its name. The post-copy fixes (EFI
# fallback loader, VirtIO drivers, 512b sector emulation) then opened a vm-<vmid>-disk-0 they
# made up from the VMID, which is the TPM state again. An allocation now takes the first name
# the storage does not list for the VMID, never frees or takes over a volume it did not make,
# and the fixes work on the volume disk 0 was really copied to.
#
# The folder copies. Offline Copy, Live Mirror and Snapshot-Iterative copy the disk files of
# the boot disk's folder. A disk on another datastore or in another folder was not there and
# the guest came up without it; a VM running on its own snapshot (<disk>-000001.vmdk) got the
# state its disk had before that snapshot. Those runs now stop before anything is touched and
# point to Live Clone, which reads every disk from its own file. Auto stops only when its
# clone is not possible and it would fall back to such a copy.
#
# The migration runs against an ESXi host, its API and a Proxmox node that only exist in
# this file; every command they get is recorded.

import os
import re
import shlex
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.core.v2p as v2p

try:
    from gevent import sleep as _gevent_turn
except ImportError:  # pragma: no cover - the suite has gevent
    def _gevent_turn(_s):
        return None

GiB = 1024 ** 3
VMID = 120
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# sizes of the flat files on ESXi, by basename
FLATS = {
    'app01-flat.vmdk': 2 * GiB + 3 * 1024 ** 2,
    'app01_1-flat.vmdk': 1 * GiB,
    'app01_2-flat.vmdk': 512 * 1024 ** 2,
    'old-app01-flat.vmdk': 1 * GiB,
}

DESC = '''# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="vmfs"

# Extent description
RW {sectors} VMFS "{flat}"
'''

NICS = [
    {'type': 'VirtualVmxnet3', 'pve_model': 'vmxnet3', 'mac_address': '00:50:56:aa:00:01',
     'network': 'VM Network', 'label': 'Network adapter 1'},
]


def _disks(n=2):
    names = ['app01', 'app01_1', 'app01_2'][:n]
    return [{'key': str(2000 + i), 'label': f'Hard disk {i + 1}',
             'capacity_bytes': FLATS[f'{nm}-flat.vmdk'],
             'capacity_gb': round(FLATS[f'{nm}-flat.vmdk'] / GiB, 1), 'thin': False,
             'vmdk_file': f'[ds1] app01/{nm}.vmdk'} for i, nm in enumerate(names)]


def _stem(name):
    return re.sub(r'\.(raw|qcow2|vmdk)$', '', name.rsplit('/', 1)[-1])


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# =========================================================================== the fakes

class Clock:
    def __init__(self):
        self.now = 1000.0

    def sleep(self, s):
        self.now += s
        # the suite runs under gevent: give the other greenlets a turn on every sleep
        _gevent_turn(0)

    def monotonic(self):
        return self.now


class Esxi:
    """The ESXi API side: power state, snapshots, the VM's disks."""

    def __init__(self, log, disks, power='POWERED_ON', firmware='efi', tpm=True, clone_snap_fails=False):
        self.log = log
        self.host = 'esx1.lab'
        self.ssl_verify = False
        self.power = power
        self.disks = disks
        self.firmware = firmware
        self.tpm = tpm
        self.clone_snap_fails = clone_snap_fails
        self.snaps = []
        self.extra_files = []   # descriptors in the boot folder that are no disk of the VM
        self._n = 0

    def ensure_connected(self):
        return True

    def get_vm_disks_for_export(self, vm_id):
        return {'data': {'vm_id': vm_id, 'name': 'app01', 'power_state': self.power,
                         'cpu_count': 2, 'memory_mb': 2048, 'guest_os': 'Linux',
                         'disks': [dict(d) for d in self.disks],
                         'total_disk_gb': sum(d['capacity_gb'] for d in self.disks)}}

    def get_vm(self, vm_id):
        return {'data': {'name': 'app01', 'power_state': self.power, 'guest_OS': 'Linux',
                         'guest_id': 'debian12_64Guest',
                         'cpu': {'count': 2, 'sockets': 1, 'cores_per_socket': 2},
                         'memory': {'size_MiB': 2048},
                         'hardware': {'firmware': self.firmware, 'secure_boot': False,
                                      'has_tpm': self.tpm, 'scsi_controller': 'ParaVirtual',
                                      'scsi_controller_pve': 'pvscsi', 'disk_bus': 'scsi',
                                      'nic_type': 'VirtualVmxnet3', 'nic_type_pve': 'vmxnet3'},
                         'controllers': {}, 'nics': [dict(n) for n in NICS],
                         'disks': {d['key']: {'capacity': d['capacity_bytes']} for d in self.disks}}}

    def get_snapshots(self, vm_id):
        return {'data': [dict(s) for s in self.snaps]}

    def create_snapshot(self, vm_id, name, description='', memory=False, quiesce=True):
        self.log.append(('esxi_api', 'snapshot', name, self.power))
        if name == '_pegaprox_clone_snap' and self.clone_snap_fails:
            return {'error': 'snapshot did not appear within 60s'}
        self._n += 1
        self.snaps.append({'snapshot': f'snapshot-{self._n}', 'name': name})
        return {'data': {'name': name}}

    def create_migration_snapshot(self, vm_id):
        return self.create_snapshot(vm_id, '_pegaprox_migration_snap')

    def delete_migration_snapshot(self, vm_id):
        for s in list(self.snaps):
            if s['name'] == '_pegaprox_migration_snap':
                return self.delete_snapshot(vm_id, s['snapshot'])
        return {'data': 'no migration snapshot found'}

    def delete_snapshot(self, vm_id, snapshot_id):
        self.log.append(('esxi_api', 'remove_snapshot', snapshot_id, self.power))
        self.snaps = [s for s in self.snaps if s['snapshot'] != snapshot_id]
        return {'data': 'deleted'}

    def vm_power_action(self, vm_id, action):
        self.log.append(('esxi_api', 'power', action, self.power))
        self.power = {'stop': 'POWERED_OFF', 'start': 'POWERED_ON',
                      'suspend': 'SUSPENDED'}.get(action, self.power)
        return {'data': {'task': 'ok'}}

    def delete_vm(self, vm_id):
        self.log.append(('esxi_api', 'delete_vm'))
        return {'data': 'ok'}


class _Resp:
    def __init__(self, data, status=200):
        self.status_code = status
        self._data = data
        self.text = str(data)

    def json(self):
        return {'data': self._data}


class Pve:
    """The Proxmox API. It puts the TPM state of a new VM on the storage tpmstate0 names, as
    the first free vm-<vmid>-disk-N there, like Proxmox does."""
    host = 'pve1.lab'
    api_port = 8006

    def __init__(self, log, vols):
        self.log = log
        self.vols = vols
        self.nodes = {'pve1': {}}
        self.is_connected = True
        self.running = False

    def _api_get(self, url, **kw):
        if url.endswith('/cluster/nextid'):
            return _Resp(VMID)
        if '/tasks/' in url:
            return _Resp({'status': 'stopped', 'exitstatus': 'OK'})
        if url.endswith('/status/current'):
            return _Resp({'status': 'running' if self.running else 'stopped'})
        return _Resp({})

    def _api_post(self, url, data=None, **kw):
        self.log.append(('pve_api', url.split('/api2/json', 1)[-1], sorted((data or {}).items())))
        tpm = (data or {}).get('tpmstate0')
        if url.endswith('/nodes/pve1/qemu') and tpm:
            st = tpm.split(':', 1)[0]
            n = 0
            while f'{st}:vm-{VMID}-disk-{n}' in self.vols:
                n += 1
            self.vols[f'{st}:vm-{VMID}-disk-{n}'] = 'tpm'
        if url.endswith('/status/start'):
            self.running = True
            return _Resp(f'UPID:pve1:1:2:qmstart:{VMID}:root@pam:')
        return _Resp('UPID:pve1:1:2:create')


def _md5_lines(path, n):
    """What a block checksum loop prints: the same lines for the same disk on both sides"""
    return ''.join(f'sum-{path}-{b}\n' for b in range(n))


def _flat_size(path):
    base = path.rsplit('/', 1)[-1]
    for i, nm in enumerate(('app01', 'app01_1', 'app01_2')):
        base = base.replace(f'_pegaprox_clone_{VMID}_{i}', nm)
    return FLATS.get(base)


class Node:
    """_pve_node_exec on the target node, with the volumes Proxmox keeps on its storages:
    pvesm list shows them, alloc adds one, free takes one away. A checksum of a target
    volume is the one of the source file it was copied from, whatever name it got."""

    def __init__(self, log, vols):
        self.log = log
        self.vols = vols
        self.copied_from = {}   # target device path -> source flat basename
        self.freed = []
        self._n = 0

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        self.log.append(('node', node, cmd))
        m = re.match(r"umask 077; f=\$\(mktemp (/tmp/v2p-[a-z0-9-]+-)XXXXXXXXXX\)", cmd)
        if m:
            self._n += 1
            return 0, f"{m.group(1)}{self._n:010d}\n", ''
        if 'command -v sshfs' in cmd:
            return 0, 'PRESENT\n', ''
        if 'df --output=avail' in cmd:
            return 0, '99999999\n', ''
        if cmd.startswith('dir=$(pvesm path'):
            return 0, '/var/tmp\n', ''
        if cmd.startswith('pvesm status --storage'):
            st = shlex.split(cmd)[3]
            return 0, f'Name Type Status Total Used Available %\n{st} lvmthin active 100 1 99 1%\n', ''
        m = re.match(r'pvesm list (\S+)', cmd)
        if m:
            st = shlex.split(m.group(1))[0]
            rows = ''.join(f'{v} raw images 4194304 {VMID}\n' for v in sorted(self.vols) if v.startswith(st + ':'))
            return 0, 'Volid Format Type Size VMID\n' + rows, ''
        m = re.match(r'pvesm alloc (\S+) (\d+) (\S+) ', cmd)
        if m:
            st, name = shlex.split(m.group(1))[0], m.group(3)
            if any(v.split(':', 1)[0] == st and _stem(v.split(':', 1)[1]) == _stem(name) for v in self.vols):
                return 5, f'Logical Volume "{_stem(name)}" already exists\n', ''
            self.vols[f'{st}:{name}'] = 'disk'
            return 0, f"successfully created '{st}:{name}'\n", ''
        if cmd.startswith(('pvesm free', 'lvremove')):
            vol = shlex.split(cmd)[2]
            self.freed.append(vol)
            self.vols.pop(vol, None)
            return 0, '', ''
        m = re.match(r'pvesm path (\S+)', cmd)
        if m:
            vol = shlex.split(m.group(1))[0]
            if vol in self.vols:
                st, name = vol.split(':', 1)
                return 0, f'/dev/{st}/{name}\n', ''
            return 2, f"no such volume '{vol}'\n", ''
        if 'md5sum' in cmd and 'while' in cmd:
            n = int(re.search(r'-lt (\d+) \]', cmd).group(1))
            path = shlex.split(re.search(r'dd if=(\S+)', cmd).group(1))[0]
            return 0, _md5_lines(self.copied_from.get(path, path), n), ''
        if 'curl' in cmd and 'FSIZE' in cmd:
            return 0, 'HTTP=000 DL=0 FSIZE=0', ''
        if 'sshpass -f ' in cmd and '| dd of=' in cmd:
            # the last word before the pipe is the command ESXi runs, quoted once more
            remote = shlex.split(cmd.split(' 2>/dev/null | dd of=')[0])[-1]
            src = shlex.split(remote)[1][len('if='):]
            dst = re.search(r"\| dd of=(\S+)", cmd).group(1).strip("'\"")
            flat = src.rsplit('/', 1)[-1]
            for i, nm in enumerate(('app01', 'app01_1', 'app01_2')):
                flat = flat.replace(f'_pegaprox_clone_{VMID}_{i}', nm)
            self.copied_from[dst] = flat
            return 0, f'PIPE=0/0\n{FLATS.get(flat, GiB)} bytes (1 GB) copied, 1 s, 1 GB/s\n', ''
        if 'qemu-img info' in cmd:
            return 0, 'file format: raw\nvirtual size: 2 GiB\n', ''
        if 'lsblk -nd -o LOG-SEC' in cmd:
            return 0, '512\n', ''
        if cmd.startswith('bash /tmp/v2p-verify-'):
            return 0, 'MATCH:0123456789abcdef\n', ''
        if cmd.startswith('bash /tmp/v2p-efi-fallback'):
            return 0, 'bootmgfw.efi not present (not a Windows ESP?)\n', ''
        return 0, '', ''


class EsxiShell:
    """The shell on the ESXi host. A folder lists the descriptors of the disks whose backing
    is in it, plus the extra files; like the real grep, the -0000NN snapshot files are left
    out of the listing."""

    def __init__(self, log, esxi, kind):
        self.log = log
        self.esxi = esxi
        self.kind = kind

    def _folder(self, ds, folder):
        names = list(self.esxi.extra_files)
        for d in self.esxi.disks:
            m = re.match(r'^\[([^\]]+)\]\s+(.+)$', d['vmdk_file'])
            if m and m.group(1) == ds and os.path.dirname(m.group(2)) == folder:
                names.append(os.path.basename(m.group(2)))
        return sorted(names)

    def __call__(self, host, user, pw, cmd, timeout=30):
        self.log.append((self.kind, cmd))
        if cmd == 'hostname':
            return 0, 'esx1\n', ''
        if 'XXHASH=' in cmd:
            return 0, 'LZ4=NO\nGZIP=/bin/gzip\nPIGZ=NO\nXXHASH=/usr/bin/xxhsum\n', ''
        m = re.match(r"ls -(la|1) '?/vmfs/volumes/([^/]+)/(.+?)/'?", cmd)
        if m:
            ds, folder = m.group(2), m.group(3)
            names = self._folder(ds, folder)
            if m.group(1) == 'la':
                return 0, ''.join(f'-rw------- 1 root root 512 {n}\n' for n in names), ''
            names = [n for n in names if not re.search(r'-0000\d\d\.vmdk$', n)]
            return 0, ''.join(f'/vmfs/volumes/{ds}/{folder}/{n}\n' for n in names), ''
        if 'md5sum' in cmd:
            n = int(re.search(r'-lt (\d+) \]', cmd).group(1))
            path = shlex.split(re.search(r'dd if=(\S+)', cmd).group(1))[0]
            return 0, _md5_lines(_flat_size(path) and path.rsplit('/', 1)[-1], n), ''
        if cmd.startswith('df -k'):
            return 0, 'vmfs 900000000 1 800000000 1% /vmfs/volumes/ds\n', ''
        if cmd.startswith('cat '):
            path = shlex.split(cmd)[1]
            stem = path.rsplit('/', 1)[-1][:-len('.vmdk')]
            size = FLATS.get(f'{stem}-flat.vmdk', GiB)
            return 0, DESC.format(sectors=size // 512, flat=f'{stem}-flat.vmdk'), ''
        if 'nohup vmkfstools' in cmd:
            return 0, '4242\n', ''
        if cmd.startswith('kill -0'):
            return 0, 'DONE\n', ''
        if cmd.startswith("sed 's/"):
            return 0, 'Clone: 100% done.\n', ''
        if cmd.startswith('stat ') and '-*.vmdk' in cmd:
            return 0, '0\n', ''
        if cmd.startswith('stat '):
            path = shlex.split(cmd.split("'%s'", 1)[-1].split(' 2>')[0])[0]
            size = _flat_size(path)
            return (0, f'{size}\n', '') if size else (1, '', 'no such file')
        return 0, '', ''


class Run:
    """One migration against the fakes."""

    def __init__(self, monkeypatch, mode='offline', ndisks=2, power='POWERED_ON', ssh_key=None,
                 disk_order=None, **esxi_kw):
        self.log = []
        self.vols = {}
        self.clock = Clock()
        disks = _disks(ndisks)
        if disk_order:
            disks = [disks[k] for k in disk_order]
        self.esxi = Esxi(self.log, disks, power=power, **esxi_kw)
        self.pve = Pve(self.log, self.vols)
        self.node = Node(self.log, self.vols)
        cfg = {'esxi_password': 'pw', 'esxi_host': 'esx1.lab', 'esxi_user': 'root',
               'transfer_mode': mode, 'network_bridge': 'vmbr0', 'preserve_mac': True,
               'start_after': True, 'remove_source': False, 'selected_nics': [dict(n) for n in NICS]}
        self.task = v2p.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm',
                                         vm_name='app01', config=cfg)
        mp = monkeypatch
        mp.setattr(time, 'sleep', self.clock.sleep)
        mp.setattr(time, 'monotonic', self.clock.monotonic)
        mp.setattr(v2p, 'vmware_managers', {'vw1': self.esxi})
        mp.setattr(v2p, 'cluster_managers', {'pve-cl': self.pve})
        mp.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
        mp.setattr(v2p, 'log_audit', lambda *a, **k: None)
        mp.setattr(v2p, '_pve_node_exec', self.node)
        mp.setattr(v2p, '_ssh_exec', EsxiShell(self.log, self.esxi, 'esxi_ssh'))
        mp.setattr(v2p, '_ssh_esxi_exec', EsxiShell(self.log, self.esxi, 'esxi_cli'))
        mp.setattr(v2p, '_monitor_disk_write', lambda *a, **k: None)
        mp.setattr(v2p, '_setup_temp_ssh_key', lambda *a, **k: ssh_key)
        mp.setattr(v2p, '_node_hkc', lambda: 'accept-new')

    def go(self):
        v2p._run_v2p_migration(self.task)
        return self

    def nodecmds(self):
        return [e[2] for e in self.log if e[0] == 'node']

    def posts(self):
        return [e for e in self.log if e[0] == 'pve_api']

    def attached(self):
        """{scsiN: volume} as the run attached them"""
        out = {}
        for c in self.nodecmds():
            m = re.match(rf'qm set {VMID} --(scsi\d+) (\S+?)(?:,| |$)', c)
            if m:
                out[m.group(1)] = m.group(2).strip("'")
        return out


# =========================================================================== 1. allocation

class AllocNode:
    """pvesm on one node. `hidden` are names the storage has but does not list (an LV of
    another thin pool in the same volume group). `lists` False makes the listing fail.
    `stray_error` makes the first alloc of a name create it and still answer an error, the
    way some plugins do."""

    def __init__(self, vols, kind='lvmthin', hidden=(), lists=True, stray_error=False):
        self.vols = dict.fromkeys(vols, 'old')
        self.kind = kind
        self.hidden = set(hidden)
        self.lists = lists
        self.stray_error = stray_error
        self.cmds = []

    def _has(self, st, stem):
        return any(v.split(':', 1)[0] == st and _stem(v.split(':', 1)[1]) == stem
                   for v in list(self.vols) + list(self.hidden))

    def __call__(self, mgr, node, cmd, timeout=30, **kw):
        self.cmds.append(cmd)
        if cmd.startswith('pvesm status'):
            st = shlex.split(cmd)[3]
            return 0, f'Name Type Status Total Used Available %\n{st} {self.kind} active 9 1 8 1%\n', ''
        m = re.match(r'pvesm list (\S+)', cmd)
        if m:
            if not self.lists:
                return 2, 'storage is not online\n', ''
            st = shlex.split(m.group(1))[0]
            rows = ''.join(f'{v} raw images 4194304 117\n' for v in sorted(self.vols) if v.startswith(st + ':'))
            return 0, 'Volid Format Type Size VMID\n' + rows, ''
        m = re.match(r'pvesm alloc (\S+) (\d+) (\S+) ', cmd)
        if m:
            st, name = shlex.split(m.group(1))[0], m.group(3)
            if self._has(st, _stem(name)):
                return 5, f'lvcreate \'pve/{_stem(name)}\' error:   Logical Volume "{_stem(name)}" already exists\n', ''
            vol = f'{st}:117/{name}' if self.kind == 'dir' else f'{st}:{name}'
            self.vols[vol] = 'new'
            if self.stray_error:
                self.stray_error = False
                return 1, 'WARNING: plugin failed to report the volume\n', ''
            return 0, f"successfully created '{vol}'\n", ''
        m = re.match(r'pvesm path (\S+)', cmd)
        if m:
            vol = shlex.split(m.group(1))[0]
            if vol in self.vols:
                name = vol.split(':', 1)[1]
                return 0, (f'/var/lib/vz/images/{name}\n' if self.kind == 'dir'
                           else f'/dev/pve/{name}\n'), ''
            return 2, f"no such volume '{vol}'\n", ''
        if cmd.startswith('pvesm free'):
            self.vols.pop(shlex.split(cmd)[2], None)
            return 0, '', ''
        return 0, '', ''

    def freeing(self):
        return [c for c in self.cmds if c.startswith(('pvesm free', 'lvremove', 'sed -i'))]


def _alloc(monkeypatch, node, storage='local-lvm', index=0):
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    mgr = MagicMock(host='pve1', api_port=8006)
    mgr._api_post.return_value = MagicMock(status_code=500)
    errbuf = []
    vol, path = v2p._pvesm_alloc_disk(mgr, 'pve1', storage, 117, index, 4 * GiB, errbuf=errbuf)
    return vol, path, errbuf


def test_the_tpm_state_on_the_target_storage_is_never_freed_for_disk_0(monkeypatch):
    node = AllocNode(['local-lvm:vm-117-disk-0'])
    vol, path, errbuf = _alloc(monkeypatch, node)
    assert (vol, path) == ('local-lvm:vm-117-disk-1', '/dev/pve/vm-117-disk-1'), errbuf
    assert node.vols['local-lvm:vm-117-disk-0'] == 'old'
    assert node.freeing() == []


def test_a_file_volume_of_any_format_and_a_template_base_count_as_taken(monkeypatch):
    node = AllocNode(['local:117/vm-117-disk-0.raw', 'local:117/base-117-disk-1.qcow2'], kind='dir')
    vol, _path, errbuf = _alloc(monkeypatch, node, storage='local')
    assert vol == 'local:117/vm-117-disk-2.raw', errbuf
    assert node.freeing() == []
    # the names in use were not even asked for
    assert not any(c.startswith('pvesm alloc') and ('disk-0' in c or 'disk-1' in c) for c in node.cmds)


def test_disk_n_starts_at_its_own_index(monkeypatch):
    node = AllocNode(['local-lvm:vm-117-disk-0', 'local-lvm:vm-117-disk-3'])
    vol, _path, _ = _alloc(monkeypatch, node, index=3)
    assert vol == 'local-lvm:vm-117-disk-4'
    assert node.vols['local-lvm:vm-117-disk-3'] == 'old'
    vol, _path, _ = _alloc(monkeypatch, node, index=1)
    assert vol == 'local-lvm:vm-117-disk-1'
    assert node.freeing() == []


def test_a_storage_whose_volumes_cannot_be_listed_gets_nothing_allocated(monkeypatch):
    node = AllocNode(['local-lvm:vm-117-disk-0'], lists=False)
    vol, path, errbuf = _alloc(monkeypatch, node)
    assert (vol, path) == (None, None)
    assert errbuf and 'could not be listed' in errbuf[0]
    assert not any(c.startswith('pvesm alloc') for c in node.cmds)
    assert node.freeing() == []


def test_a_name_the_listing_missed_is_passed_over_not_reused(monkeypatch):
    # an LV of the same name in another thin pool of the volume group: alloc says it exists
    node = AllocNode([], hidden=['local-lvm:vm-117-disk-0'])
    vol, _path, errbuf = _alloc(monkeypatch, node)
    assert vol == 'local-lvm:vm-117-disk-1', errbuf
    assert not any(c.startswith('pvesm path') and 'disk-0' in c for c in node.cmds)
    assert node.freeing() == []


def test_a_volume_an_earlier_attempt_of_this_call_made_is_used(monkeypatch):
    """An attempt that created the LV and still answered with an error, the next one says
    it exists. That volume is this call's own, nothing is freed or cleaned up for it."""
    node = AllocNode([], stray_error=True)
    vol, _path, errbuf = _alloc(monkeypatch, node)
    assert vol == 'local-lvm:vm-117-disk-0', errbuf
    assert len([c for c in node.cmds if c.startswith('pvesm alloc')]) == 2
    assert node.freeing() == []


def test_an_alloc_answer_naming_another_volume_is_not_taken(monkeypatch):
    """pvesm alloc answered with a volume it was not asked for: the run would write the
    disk onto that one. The answer only counts when it names the volume asked for."""
    node = AllocNode(['local-lvm:vm-117-disk-0'])
    real = node.__call__

    def answer_other(mgr, nd, cmd, timeout=30, **kw):
        rc, out, err = real(mgr, nd, cmd, timeout, **kw)
        if cmd.startswith('pvesm alloc') and rc == 0:
            return 0, "successfully created 'local-lvm:vm-117-disk-0'\n", ''
        return rc, out, err
    vol, path, errbuf = _alloc(monkeypatch, answer_other)
    assert (vol, path) == ('local-lvm:vm-117-disk-1', '/dev/pve/vm-117-disk-1'), errbuf
    assert not any('vm-117-disk-0' in c for c in node.cmds if not c.startswith('pvesm list'))


@pytest.mark.parametrize('kw', [dict(mode='offline'), dict(mode='vmkfstools_clone'),
                                dict(mode='auto', clone_snap_fails=True),
                                dict(mode='snapshot_zero'),
                                dict(mode='sshfs_boot', ndisks=2, ssh_key='/tmp/v2p-key-fixed')],
                         ids=lambda kw: kw['mode'])
def test_a_migration_with_tpm_leaves_the_tpm_state_alone(monkeypatch, kw):
    if kw['mode'] == 'snapshot_zero':
        monkeypatch.setattr(v2p, '_snapshot_zero_v2p_delta_loop', lambda *a, **k: (True, 1, []))
    r = Run(monkeypatch, **kw).go()
    assert r.task.status == 'completed', r.task.error
    tpm = f'local-lvm:vm-{VMID}-disk-0'
    assert r.vols.get(tpm) == 'tpm', 'the TPM state was freed'
    assert tpm not in r.node.freed
    # no node command names the TPM volume: not a free, not a write, not a post-copy fix
    assert [c for c in r.nodecmds() if f'vm-{VMID}-disk-0' in c] == []
    assert r.attached()['scsi0'] == f'local-lvm:vm-{VMID}-disk-1', r.attached()
    assert r.attached()['scsi1'] == f'local-lvm:vm-{VMID}-disk-2', r.attached()
    # the post-copy fixes looked at the volume disk 0 was copied to
    assert f'pvesm path local-lvm:vm-{VMID}-disk-1 2>/dev/null' in r.nodecmds()


def test_the_post_copy_fixes_skip_when_no_copy_of_disk_0_is_known(monkeypatch):
    """Nothing recorded for disk 0: the fixes do nothing rather than open a volume whose
    name they made up from the VMID."""
    log, vols = [], {f'local-lvm:vm-{VMID}-disk-0': 'tpm'}
    node = Node(log, vols)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    t = v2p.V2PMigrationTask('t', 'vw', 'vm', 'c', 'pve1', 'local-lvm', config={})
    t.proxmox_vmid = VMID
    v2p._register_uefi_fallback_loader(MagicMock(), t)
    v2p._ensure_guest_sector_size_512(MagicMock(), t, 'scsi', 1)
    assert v2p._inject_virtio_drivers(MagicMock(), t) is False
    assert [e for e in log if 'disk-0' in e[2]] == []


def test_no_call_site_makes_up_a_volume_name_or_frees_before_it_allocates():
    src = _read('pegaprox', 'core', 'v2p.py')
    alloc = src[src.index('def _pvesm_alloc_disk('):src.index('def _setup_temp_ssh_key(')]
    head = alloc[:alloc.index('alloc_attempts')]
    assert 'pvesm free' not in head and 'lvremove' not in head and 'sed -i' not in head
    assert not re.search(r"vm-\{[^}]*\}-disk-0", src)


# =========================================================================== 2. folder copies

def _elsewhere(r):
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    return r


def _on_its_own_snapshot(r):
    """Disk 1 runs on a snapshot of the VM: ESXi names its current file app01-000001.vmdk,
    the base app01.vmdk is still in the folder."""
    r.esxi.disks[0]['vmdk_file'] = '[ds1] app01/app01-000001.vmdk'
    r.esxi.extra_files = ['app01.vmdk']
    return r


def _nothing_touched(r):
    assert r.posts() == [], 'a VM was created on Proxmox'
    assert not any(c.startswith('pvesm alloc') for c in r.nodecmds())
    assert not [e for e in r.log if e[:2] in (('esxi_api', 'power'), ('esxi_api', 'snapshot'))]


@pytest.mark.parametrize('mode', ['offline', 'sshfs_boot', 'snapshot_zero'])
def test_a_folder_copy_that_would_leave_a_disk_out_is_refused_before_anything(monkeypatch, mode):
    r = _elsewhere(Run(monkeypatch, mode=mode)).go()
    assert r.task.status == 'failed'
    assert 'disk 2 (Hard disk 2)' in r.task.error and '[ds2] other' in r.task.error, r.task.error
    assert 'Live Clone' in r.task.error
    _nothing_touched(r)


def test_a_folder_copy_of_a_vm_on_its_own_snapshot_is_refused_before_anything(monkeypatch):
    r = _on_its_own_snapshot(Run(monkeypatch, mode='offline')).go()
    assert r.task.status == 'failed'
    assert 'disk 1 (Hard disk 1)' in r.task.error and 'snapshot' in r.task.error, r.task.error
    assert 'Live Clone' in r.task.error
    _nothing_touched(r)


def test_auto_reads_a_disk_outside_the_folder_by_clone_and_never_falls_back_to_the_folder(monkeypatch):
    # the clone reads every disk from its own file, the one on ds2 included
    r = _elsewhere(Run(monkeypatch, mode='auto')).go()
    assert r.task.status == 'completed', r.task.error
    clones = [e[1] for e in r.log if e[0] == 'esxi_cli' and 'nohup vmkfstools' in e[1]]
    assert any('/vmfs/volumes/ds2/other/app01_1.vmdk' in c for c in clones), clones
    # no clone possible: Auto stops instead of copying the boot folder without that disk
    r = _elsewhere(Run(monkeypatch, mode='auto', clone_snap_fails=True)).go()
    assert r.task.status == 'failed'
    assert 'disk 2 (Hard disk 2)' in r.task.error and 'Live Clone' in r.task.error, r.task.error
    assert not any(c.startswith('pvesm alloc') for c in r.nodecmds())
    assert not [e for e in r.log if e[:2] == ('esxi_api', 'power')]
    assert r.esxi.snaps == []


def test_a_disk_label_from_esxi_stays_one_short_line_in_the_refusal(monkeypatch):
    r = _elsewhere(Run(monkeypatch, mode='offline'))
    r.esxi.disks[1]['label'] = 'Hard disk 2\n[V2P] COMPLETED: forged line' + 'x' * 500
    r.go()
    assert r.task.status == 'failed'
    assert '\n' not in r.task.error and len(r.task.error) < 700, r.task.error
    assert 'disk 2 (Hard disk 2 [V2P] COMPLETED: forged line' in r.task.error
    label = r.task.error.split('disk 2 (', 1)[1].split(') is in', 1)[0]
    assert len(label) <= 80, label


def test_each_disk_keeps_its_place_and_a_stray_vmdk_in_the_folder_is_not_copied(monkeypatch):
    """ls lists app01, app01_1, app01_2 and a leftover old-app01.vmdk; the VM has app01,
    app01_2, app01_1. scsiN is the N-th disk of the VM, and the leftover is no disk of it."""
    r = Run(monkeypatch, mode='offline', ndisks=3, disk_order=[0, 2, 1], tpm=False)
    r.esxi.extra_files = ['old-app01.vmdk']
    r.go()
    assert r.task.status == 'completed', r.task.error
    att = r.attached()
    assert sorted(att) == ['scsi0', 'scsi1', 'scsi2'], att
    src = {k: r.node.copied_from.get(f'/dev/{v.replace(":", "/", 1)}') for k, v in att.items()}
    assert src == {'scsi0': 'app01-flat.vmdk', 'scsi1': 'app01_2-flat.vmdk',
                   'scsi2': 'app01_1-flat.vmdk'}, src
    assert not any('old-app01' in c for c in r.nodecmds())
    assert r.task.disk_progress['disk1']['total'] == FLATS['app01_2-flat.vmdk']


# --- what ESXi says about a snapshot wins over the file name ---------------------------------

def _gap_disk(name, **kw):
    return dict({'label': 'Hard disk 1', 'vmdk_file': f'[ds1] app01/{name}'}, **kw)


def test_a_disk_named_like_a_delta_is_copied_when_esxi_says_it_runs_on_no_snapshot():
    order, why = v2p.folder_copy_gap([_gap_disk('db-202401.vmdk', snapshot_delta=False)],
                                     descriptor_files=['db-202401.vmdk'])
    assert (order, why) == (['db-202401.vmdk'], None)


def test_a_disk_esxi_says_runs_on_a_snapshot_is_refused_whatever_its_name():
    order, why = v2p.folder_copy_gap([_gap_disk('app01.vmdk', snapshot_delta=True)],
                                     descriptor_files=['app01.vmdk'])
    assert order is None and 'runs on a snapshot of the VM' in why


def test_without_word_from_esxi_the_delta_name_still_counts():
    order, why = v2p.folder_copy_gap([_gap_disk('app01-000001.vmdk')],
                                     descriptor_files=['app01-000001.vmdk'])
    assert order is None and 'runs on a snapshot of the VM' in why


def test_the_esxi_reader_reports_which_disk_runs_on_a_delta():
    from unittest.mock import MagicMock
    from pyVmomi import vim
    from pegaprox.core import vmware

    def disk(key, unit, name, parent=None):
        d = vim.vm.device.VirtualDisk(key=key, unitNumber=unit, capacityInKB=1024 * 1024)
        d.deviceInfo = vim.Description(label=f'Hard disk {unit + 1}', summary='')
        d.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName=f'[ds1] app01/{name}', parent=parent)
        return d

    base = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName='[ds1] app01/data.vmdk')
    vm = MagicMock()
    vm.config.hardware.device = [disk(2000, 0, 'db-202401.vmdk'), disk(2001, 1, 'data-000001.vmdk', base)]
    vm.config.hardware.numCPU, vm.config.hardware.numCoresPerSocket, vm.config.hardware.memoryMB = 2, 1, 2048
    mgr = object.__new__(vmware.VMwareManager)
    mgr._connection_type = 'soap'
    mgr._soap_get_managed_object = lambda kind, vm_id: vm
    got = mgr.get_vm_disks_for_export('vm-1')
    assert 'error' not in got, got
    flags = {d['vmdk_file'].rsplit('/', 1)[-1]: d['snapshot_delta'] for d in got['data']['disks']}
    assert flags == {'db-202401.vmdk': False, 'data-000001.vmdk': True}
    order, why = v2p.folder_copy_gap(got['data']['disks'])
    assert order is None and 'disk 2' in why and 'runs on a snapshot' in why


def test_auto_says_its_vm_stays_and_the_folder_modes_say_nothing_was_touched():
    auto = v2p.folder_copy_refusal('auto', 'x')
    assert 'Proxmox VM of this run stays' in auto and 'not touched' not in auto
    for mode in ('offline', 'sshfs_boot', 'snapshot_zero'):
        assert 'the source VM was not touched' in v2p.folder_copy_refusal(mode, 'x')
