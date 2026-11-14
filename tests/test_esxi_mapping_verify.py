# ESXi migration: network per NIC, storage per disk, skipped disks, a dry run behind the
# wizard's review step and the verify modes sample / full / off.
#
# The migration runs here against an ESXi host, an ESXi API and a Proxmox node that only
# exist in this file. Every command the node, the ESXi shell and the Proxmox API would get
# is recorded, so a test can say what ran, in which order and with which names.

import json
import os
import re
import shlex
import subprocess
import time
import types

import pytest

import pegaprox.core.v2p as v2p

try:
    from gevent import sleep as _gevent_turn
except ImportError:  # pragma: no cover - the suite has gevent
    def _gevent_turn(_s):
        return None

GiB = 1024 ** 3
VMID = 120
BLOCK = 256 * 1024 ** 2

# sizes of the flat files on ESXi, by basename
FLATS = {
    'app01-flat.vmdk': 2 * GiB + 3 * 1024 ** 2,   # a partial last block on purpose
    'app01_1-flat.vmdk': 1 * GiB,
    'app01_2-flat.vmdk': 512 * 1024 ** 2,
}

DESC = '''# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="vmfs"

# Extent description
RW {sectors} VMFS "{flat}"
'''


def _disks(n=2):
    names = ['app01', 'app01_1', 'app01_2'][:n]
    return [{'key': str(2000 + i), 'label': f'Hard disk {i + 1}',
             'capacity_bytes': FLATS[f'{nm}-flat.vmdk'],
             'capacity_gb': round(FLATS[f'{nm}-flat.vmdk'] / GiB, 1), 'thin': False,
             'vmdk_file': f'[ds1] app01/{nm}.vmdk'} for i, nm in enumerate(names)]


NICS = [
    {'type': 'VirtualVmxnet3', 'pve_model': 'vmxnet3', 'mac_address': '00:50:56:aa:00:01',
     'network': 'VM Network', 'label': 'Network adapter 1'},
    {'type': 'VirtualE1000e', 'pve_model': 'e1000e', 'mac_address': '00:50:56:aa:00:02',
     'network': 'DMZ', 'label': 'Network adapter 2'},
]


class Clock:
    def __init__(self):
        self.now = 1000.0

    def sleep(self, s):
        self.now += s
        # the suite runs under gevent: a background loop of the app (the drift scanner) that
        # wakes while this clock stands in for time.sleep would spin on it for ever and never
        # give the hub back to the test. Each sleep lets the other greenlets have a turn.
        _gevent_turn(0)

    def monotonic(self):
        return self.now


class Esxi:
    """The ESXi API side: power state, snapshots, the VM's disks and NICs."""

    def __init__(self, log, disks, power='POWERED_ON', firmware='efi', tpm=True, clone_snap_fails=False):
        self.log = log
        self.host = 'esx1.lab'
        self.ssl_verify = False
        self.power = power
        self.disks = disks
        self.firmware = firmware
        self.tpm = tpm
        self.clone_snap_fails = clone_snap_fails
        self.linked_clusters = []
        self.snaps = []
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
        if action == 'stop':
            self.power = 'POWERED_OFF'
        elif action == 'start':
            self.power = 'POWERED_ON'
        elif action == 'suspend':
            self.power = 'SUSPENDED'
        return {'data': {'task': 'ok'}}

    def delete_vm(self, vm_id):
        self.log.append(('esxi_api', 'delete_vm'))
        return {'data': 'ok'}


class _Resp:
    def __init__(self, data, status=200, text=''):
        self.status_code = status
        self._data = data
        self.text = text or json.dumps(data)

    def json(self):
        return {'data': self._data}


# what /nodes/pve1/network, /cluster/sdn/vnets, /nodes/pve1/sdn/zones and /nodes/pve1/storage answer
NETWORK = [
    {'iface': 'vmbr0', 'type': 'bridge', 'bridge_vlan_aware': 1},
    {'iface': 'vmbr1', 'type': 'bridge'},
    {'iface': 'ovsbr0', 'type': 'OVSBridge'},
    {'iface': 'eno1', 'type': 'eth'},
]
VNETS = [{'vnet': 'dmz10', 'zone': 'zlan'}, {'vnet': 'far20', 'zone': 'zother'}]
ZONES = [{'zone': 'zlan', 'status': 'available'}]
STORAGES = [
    {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'active': 1,
     'enabled': 1, 'avail': 500 * GiB, 'total': 600 * GiB},
    {'storage': 'fast-lvm', 'type': 'lvm', 'content': 'images', 'active': 1, 'enabled': 1,
     'avail': 100 * GiB, 'total': 100 * GiB},
    {'storage': 'nfs-a', 'type': 'nfs', 'content': 'images,iso', 'active': 1, 'enabled': 1,
     'avail': 512 * 1024 ** 2, 'total': 50 * GiB},
    {'storage': 'local', 'type': 'dir', 'content': 'iso,vztmpl', 'active': 1, 'enabled': 1,
     'avail': 50 * GiB, 'total': 60 * GiB},
    {'storage': 'offline-nfs', 'type': 'nfs', 'content': 'images', 'active': 0, 'enabled': 1,
     'avail': 0, 'total': 0},
]


class Pve:
    host = 'pve1.lab'
    api_port = 8006

    def __init__(self, log, network=None, vnets=None, zones=None, storages=None):
        self.log = log
        self.nodes = {'pve1': {}, 'pve2': {}}
        self.is_connected = True
        self.network = NETWORK if network is None else network
        self.vnets = VNETS if vnets is None else vnets
        self.zones = ZONES if zones is None else zones
        self.storages = STORAGES if storages is None else storages
        self.gets = []
        self.running = False
        self.config = types.SimpleNamespace(name='lab-cluster')

    def _api_get(self, url, **kw):
        self.gets.append(url)
        if url.endswith('/cluster/nextid'):
            return _Resp(VMID)
        if '/tasks/' in url:
            return _Resp({'status': 'stopped', 'exitstatus': 'OK'})
        if url.endswith('/status/current'):
            return _Resp({'status': 'running' if self.running else 'stopped'})
        if url.endswith('/nodes/pve1/network'):
            return _Resp(self.network) if self.network != 'fail' else _Resp(None, 500, 'boom')
        if url.endswith('/cluster/sdn/vnets'):
            return _Resp(self.vnets) if self.vnets != 'fail' else _Resp(None, 500, 'boom')
        if url.endswith('/nodes/pve1/sdn/zones'):
            return _Resp(self.zones) if self.zones != 'fail' else _Resp(None, 500, 'boom')
        if url.endswith('/nodes/pve1/storage'):
            return _Resp(self.storages) if self.storages != 'fail' else _Resp(None, 500, 'boom')
        return _Resp({})

    def _api_post(self, url, data=None, **kw):
        self.log.append(('pve_api', url.split('/api2/json', 1)[-1],
                         sorted((data or {}).items())))
        if url.endswith('/status/start'):
            self.running = True
            return _Resp(f'UPID:pve1:1:2:qmstart:{VMID}:root@pam:')
        return _Resp('UPID:pve1:1:2:create')


def _md5_lines(path, n, size=None, bad=None):
    """What the block checksum loops print: one line per block, the same for the same
    block of the same disk on both sides, so a copy matches its source."""
    stem = re.sub(r'.*/', '', path)
    stem = {'vm-120-disk-0': 'app01', 'vm-120-disk-1': 'app01_1', 'vm-120-disk-2': 'app01_2'}.get(
        re.sub(r'\.(raw|qcow2)$', '', stem), stem.replace('-flat.vmdk', '').replace('_pegaprox_clone_120_', 'clone'))
    stem = {'clone0': 'app01', 'clone1': 'app01_1', 'clone2': 'app01_2'}.get(stem, stem)
    return ''.join(f'{"bad" if bad and b in bad else "sum"}-{stem}-{b}\n' for b in range(n))


def _attaches(cmds):
    """The disk attaches as slot and volume. The drive options each of them carries are
    held by test_v2p_disk_options_1270.py."""
    return [c.split(' 2>')[0].split(',')[0] for c in cmds if re.match(r'qm set \d+ --scsi\d', c)]


def _ssh_pipe(cmd):
    """The SSH copy of a flat file on the node: ESXi's dd piped into the target volume."""
    return cmd.startswith('sshpass -f ') and ' ssh ' in cmd and '| dd of=' in cmd


class Node:
    """_pve_node_exec on the target node."""

    def __init__(self, log, esxi, storage_types=None, verify_bad=None, verify_fail=False):
        self.log = log
        self.esxi = esxi
        self.storage_types = storage_types or {}
        self.verify_bad = verify_bad or {}     # vol path -> blocks that read back wrong
        self.verify_fail = verify_fail
        self.scripts = {}
        self._n = 0

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        self.log.append(('node', node, cmd))
        m = re.match(r"umask 077; f=\$\(mktemp (/tmp/v2p-[a-z0-9-]+-)XXXXXXXXXX\)", cmd)
        if m:
            self._n += 1
            path = f"{m.group(1)}{self._n:010d}"
            self.scripts[path] = cmd
            return 0, path + '\n', ''
        if cmd.startswith('bash /tmp/v2p-fullcheck-'):
            body = self.scripts.get(cmd.split()[1], '')
            vol = re.search(r"^VOL=(.*)$", body, re.M).group(1)
            vol = shlex.split(vol)[0]
            n = int(re.search(r'^N=(\d+)$', body, re.M).group(1))
            if self.verify_fail:
                return 3, 'NBD_CONNECT_FAILED\n', ''
            return 0, _md5_lines(vol, n, bad=self.verify_bad.get(vol)) + 'VERIFY_DONE\n', ''
        if 'command -v sshfs' in cmd:
            return 0, 'PRESENT\n', ''
        if 'df --output=avail' in cmd:
            return 0, '99999999\n', ''
        if cmd.startswith('dir=$(pvesm path'):
            return 0, '/var/tmp\n', ''
        if cmd.startswith('pvesm status --storage'):
            st = shlex.split(cmd)[3]
            t = self.storage_types.get(st, 'lvmthin')
            return 0, f'Name Type Status Total Used Available %\n{st} {t} active 100 1 99 1%\n', ''
        m = re.match(r'pvesm alloc (\S+) (\d+) (\S+) ', cmd)
        if m:
            return 0, f"successfully created '{m.group(1)}:{m.group(3)}'\n", ''
        m = re.match(r'pvesm path (\S+) 2>&1', cmd)
        if m:
            vol = shlex.split(m.group(1))[0]
            st, name = vol.split(':', 1)
            if self.storage_types.get(st) in ('dir', 'nfs'):
                return 0, f'/mnt/pve/{st}/images/{VMID}/{name}\n', ''
            return 0, f'/dev/{st}/{name}\n', ''
        if cmd.startswith('pvesm path'):
            return 1, '', ''
        if 'md5sum' in cmd and 'while' in cmd:
            n = int(re.search(r'-lt (\d+) \]', cmd).group(1))
            path = shlex.split(re.search(r'dd if=(\S+)', cmd).group(1))[0]
            return 0, _md5_lines(path, n), ''
        if 'curl' in cmd and 'FSIZE' in cmd:
            return 0, 'HTTP=000 DL=0 FSIZE=0', ''
        if _ssh_pipe(cmd):
            # sshpass reads the password from a file; the remote dd is quoted once more
            remote = next(t for t in shlex.split(cmd.split('|', 1)[0]) if t.startswith('dd if='))
            src = shlex.split(remote)[1][len('if='):]
            size = FLATS.get(src.rsplit('/', 1)[-1].replace('_pegaprox_clone_120_0', 'app01')
                             .replace('_pegaprox_clone_120_1', 'app01_1')
                             .replace('_pegaprox_clone_120_2', 'app01_2'), GiB)
            return 0, f'PIPE=0/0\n{size} bytes (1 GB) copied, 1 s, 1 GB/s\n', ''
        if 'qemu-img info' in cmd:
            return 0, 'file format: raw\nvirtual size: 2 GiB\n', ''
        if 'lsblk -nd -o LOG-SEC' in cmd:
            return 0, '512\n', ''
        if cmd.startswith('bash /tmp/v2p-verify-'):
            return 0, 'MATCH:0123456789abcdef\n', ''
        if cmd.startswith('bash /tmp/v2p-efi-fallback'):
            return 0, 'bootmgfw.efi not present (not a Windows ESP?)\n', ''
        return 0, '', ''


def _flat_size(path):
    base = path.rsplit('/', 1)[-1]
    for i, nm in enumerate(('app01', 'app01_1', 'app01_2')):
        base = base.replace(f'_pegaprox_clone_{VMID}_{i}', nm)
    return FLATS.get(base)


class EsxiShell:
    """_ssh_exec and _ssh_esxi_exec: the shell on the ESXi host."""

    def __init__(self, log, esxi, kind, src_bad=None):
        self.log = log
        self.esxi = esxi
        self.kind = kind
        self.src_bad = src_bad or {}

    def __call__(self, host, user, pw, cmd, timeout=30):
        self.log.append((self.kind, cmd))
        if cmd == 'hostname':
            return 0, 'esx1\n', ''
        if 'XXHASH=' in cmd:
            return 0, 'LZ4=NO\nGZIP=/bin/gzip\nPIGZ=NO\nXXHASH=/usr/bin/xxhsum\n', ''
        if cmd.startswith('ls -la'):
            return 0, ''.join(f'-rw------- 1 root root 512 {d["vmdk_file"].split("/")[-1]}\n'
                              for d in self.esxi.disks), ''
        if cmd.startswith('ls -1'):
            # ls sorts by name, the API by device key: app01_10 would sort before app01_2
            return 0, ''.join(f'/vmfs/volumes/ds1/app01/{d["vmdk_file"].split("/")[-1]}\n'
                              for d in sorted(self.esxi.disks, key=lambda d: d['vmdk_file'])), ''
        if 'md5sum' in cmd:
            n = int(re.search(r'-lt (\d+) \]', cmd).group(1))
            path = shlex.split(re.search(r'dd if=(\S+)', cmd).group(1))[0]
            head = f'{_flat_size(path)}\n' if cmd.startswith("stat -c '%s'") else ''
            return 0, head + _md5_lines(path, n, bad=self.src_bad.get(path)), ''
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
    """One migration against the fakes. `mod` is the v2p module under test."""

    def __init__(self, monkeypatch, mod=v2p, mode='offline', ndisks=2, power='POWERED_ON',
                 config=None, storage_types=None, verify_bad=None, src_bad=None, verify_fail=False,
                 ssh_key=None, disk_order=None, **esxi_kw):
        self.mod = mod
        self.log = []
        self.clock = Clock()
        disks = _disks(ndisks)
        if disk_order:
            disks = [disks[k] for k in disk_order]
        self.esxi = Esxi(self.log, disks, power=power, **esxi_kw)
        self.pve = Pve(self.log)
        self.node = Node(self.log, self.esxi, storage_types=storage_types, verify_bad=verify_bad,
                         verify_fail=verify_fail)
        cfg = {'esxi_password': 'pw', 'esxi_host': 'esx1.lab', 'esxi_user': 'root',
               'transfer_mode': mode, 'network_bridge': 'vmbr0', 'net_vlan_tag': '30',
               'preserve_mac': True, 'start_after': True, 'remove_source': False,
               'selected_nics': [dict(n) for n in NICS]}
        cfg.update(config or {})
        self.task = mod.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm',
                                         vm_name='app01', config=cfg)
        mp = monkeypatch
        mp.setattr(time, 'sleep', self.clock.sleep)
        mp.setattr(time, 'monotonic', self.clock.monotonic)
        mp.setattr(mod, 'vmware_managers', {'vw1': self.esxi})
        mp.setattr(mod, 'cluster_managers', {'pve-cl': self.pve})
        mp.setattr(mod, 'broadcast_sse', lambda *a, **k: None)
        mp.setattr(mod, 'log_audit', lambda *a, **k: None)
        mp.setattr(mod, '_pve_node_exec', self.node)
        mp.setattr(mod, '_ssh_exec', EsxiShell(self.log, self.esxi, 'esxi_ssh', src_bad=src_bad))
        mp.setattr(mod, '_ssh_esxi_exec', EsxiShell(self.log, self.esxi, 'esxi_cli', src_bad=src_bad))
        mp.setattr(mod, '_monitor_disk_write', lambda *a, **k: None)
        mp.setattr(mod, '_setup_temp_ssh_key', lambda *a, **k: ssh_key)
        mp.setattr(mod, '_node_hkc', lambda: 'accept-new')

    def go(self):
        self.mod._run_v2p_migration(self.task)
        return self

    def nodecmds(self):
        return [e[2] for e in self.log if e[0] == 'node']

    def posts(self):
        return [e for e in self.log if e[0] == 'pve_api']


# The requests that predate nic_map, disk_map and verify, one per transfer mode family. The
# golden file next to this one holds what each of them sent to the node, the ESXi shell and
# the Proxmox API, recorded from the code as it was before those keys existed. Re-recorded
# when that code moved under them, each time from the code without the keys, and the run
# with them sent the same: a disk allocation lists the VMID's volumes on the storage instead
# of freeing a vm-<vmid>-disk-N that was there (the TPM state), and the post-copy fixes look
# at the volume disk 0 was copied to (tests/test_esxi_followups.py). Then the tool probes
# that say which tool is missing and the reachability probe of the ESXi host, the ESXi
# password in a file on the node instead of on a command line, the drive options of every
# attach, and the EFI disk a live pivot gives a guest left on Auto firmware.
LEGACY_SCENARIOS = {
    'offline': dict(mode='offline'),
    'vmkfstools_clone': dict(mode='vmkfstools_clone'),
    'auto_presync': dict(mode='auto', clone_snap_fails=True),
    'auto_presync_off': dict(mode='auto', clone_snap_fails=True, power='POWERED_OFF'),
    'sshfs_boot_offline_copy': dict(mode='sshfs_boot', firmware='bios', tpm=False),
    'sshfs_boot_live': dict(mode='sshfs_boot', ndisks=3, ssh_key='/tmp/v2p-key-fixed'),
    'offline_three_disks_dir': dict(mode='offline', ndisks=3, storage_types={'local-lvm': 'dir'},
                                    config={'net_vlan_tag': '', 'disk_format': 'qcow2'}),
}
GOLDEN = os.path.join(os.path.dirname(__file__), 'test_esxi_mapping_verify.golden.json')


# --------------------------------------------------------------------------- no key, no change

@pytest.mark.parametrize('name', sorted(LEGACY_SCENARIOS))
def test_a_request_without_the_new_keys_runs_byte_for_byte_as_before(monkeypatch, name):
    """Every node command, ESXi command and Proxmox API call of a request that predates
    nic_map, disk_map and verify, held against the recording made from the old code."""
    golden = json.load(open(GOLDEN))[name]
    r = Run(monkeypatch, **LEGACY_SCENARIOS[name]).go()
    assert r.task.status == golden['status'], r.task.error
    got = json.loads(json.dumps(r.log))
    for n, (want, have) in enumerate(zip(golden['log'], got)):
        assert have == want, f'step {n} differs:\n  was: {want}\n  now: {have}'
    assert len(got) == len(golden['log'])


def test_the_golden_recording_holds_the_spot_check_and_no_full_check():
    """The recording is the old behaviour: the sample check of the SSH copy is in it, the full
    check is not. If either flips, the recording was made from the wrong code."""
    golden = json.load(open(GOLDEN))
    cmds = [e[2] for e in golden['sshfs_boot_offline_copy']['log'] if e[0] == 'node']
    assert any('xxhsum' in c for c in cmds)
    every = json.dumps(golden)
    assert 'fullcheck' not in every and 'VERIFY_DONE' not in every


# --------------------------------------------------------------------------- parsing

@pytest.mark.parametrize('bridge', ['vmbr0,firewall=0', 'vmbr0 ', 'a;reboot', '$(id)', 'vmbr0\n',
                                    '-vmbr0', 'x' * 16, '', 'vm br', 'vmbr0=1', 5])
def test_a_bridge_that_is_no_interface_name_is_refused(bridge):
    if bridge == '':
        # empty means "the job's bridge"
        assert v2p.parse_nic_map([{'index': 0, 'bridge': ''}])[0]['bridge'] is None
        return
    with pytest.raises(ValueError):
        v2p.parse_nic_map([{'index': 0, 'bridge': bridge}])


@pytest.mark.parametrize('vlan', [0, 4095, -1, True, '5;rm', '5 6', 1.5, [5]])
def test_a_vlan_outside_1_to_4094_is_refused(vlan):
    with pytest.raises(ValueError):
        v2p.parse_nic_map([{'index': 0, 'bridge': 'vmbr0', 'vlan': vlan}])


@pytest.mark.parametrize('storage', ['local;reboot', 'a b', '../x', '-x', '$(id)', 'x' * 101, 7])
def test_a_storage_that_is_no_storage_name_is_refused(storage):
    with pytest.raises(ValueError):
        v2p.parse_disk_map([{'index': 1, 'storage': storage}])


@pytest.mark.parametrize('raw,why', [
    ([{'index': 0, 'skip': True}], 'boot disk'),
    ([{'index': 1}, {'index': 1}], 'twice'),
    ([{'index': 1, 'size': 5}], 'unknown field'),
    ([{'index': 1, 'skip': 'yes'}], 'true or false'),
    ({'index': 1}, 'must be a list'),
    (['x'], 'must be an object'),
    ([{'index': 64}], 'between'),
    ([{'index': '1; rm'}], 'whole number'),
])
def test_a_malformed_disk_map_is_refused(raw, why):
    with pytest.raises(ValueError, match=why):
        v2p.parse_disk_map(raw)


def test_maps_and_verify_parse_to_what_the_task_reads():
    o = v2p.parse_migration_options({
        'nic_map': [{'index': 1, 'bridge': 'vmbr1', 'vlan': '7'}, {'index': 0, 'skip': True}],
        'disk_map': [{'index': 1, 'storage': 'fast-lvm'}, {'index': 2, 'skip': True}],
        'verify': 'FULL'})
    assert o['nic_map'] == {1: {'bridge': 'vmbr1', 'vlan': 7, 'vlan_set': True, 'skip': False},
                            0: {'bridge': None, 'vlan': None, 'vlan_set': False, 'skip': True}}
    assert o['disk_map'] == {1: {'storage': 'fast-lvm', 'skip': False}, 2: {'storage': None, 'skip': True}}
    assert o['verify'] == 'full'
    assert v2p.parse_migration_options({}) == {'nic_map': None, 'disk_map': None, 'verify': 'sample'}
    with pytest.raises(ValueError):
        v2p.parse_verify('paranoid')


def test_the_task_decides_storage_and_skip_in_one_place():
    t = v2p.V2PMigrationTask('t', 'vw', 'vm', 'c', 'pve1', 'local-lvm', config={
        'disk_map': [{'index': 1, 'storage': 'fast-lvm'}, {'index': 2, 'skip': True}],
        'nic_map': [{'index': 0, 'skip': True}, {'index': 1, 'bridge': 'vmbr1', 'vlan': None}],
        'network_bridge': 'vmbr0', 'net_vlan_tag': '30'})
    assert [t.disk_target(i) for i in range(4)] == ['local-lvm', 'fast-lvm', None, 'local-lvm']
    assert t.kept_disks(4) == [0, 1, 3]
    assert t.nic_target(0) is None
    assert t.nic_target(1) == ('vmbr1', None)        # "vlan": null - no tag on this NIC
    assert t.nic_target(2) == ('vmbr0', 30)          # not in the map - the job's bridge and tag
    plain = v2p.V2PMigrationTask('t', 'vw', 'vm', 'c', 'pve1', 'local-lvm', config={})
    assert plain.disk_target(5) == 'local-lvm' and plain.kept_disks(3) == [0, 1, 2]
    plain.proxmox_vmid = 7
    # the post-copy fixes get the volume disk 0 was copied to, never a name made up from the
    # VMID (on target_storage that can be the TPM state, tests/test_esxi_followups.py)
    assert plain.boot_volume() is None
    plain.record_disk_volume(0, 'local-lvm:vm-7-disk-1')
    assert plain.boot_volume() == 'local-lvm:vm-7-disk-1'


def test_a_task_with_options_that_do_not_parse_touches_nothing(monkeypatch):
    r = Run(monkeypatch, mode='offline', config={'disk_map': [{'index': 1, 'storage': 'x;reboot'}]}).go()
    assert r.task.status == 'failed' and 'Invalid migration options' in r.task.error
    assert r.log == []


# --------------------------------------------------------------------------- the plan

def _inv(**kw):
    log = []
    return v2p.read_target_inventory(Pve(log, **kw), 'pve1')


def test_the_inventory_holds_bridges_vnets_of_the_node_and_storages():
    inv = _inv()
    assert inv['bridges'] == {'vmbr0': 'bridge', 'vmbr1': 'bridge', 'ovsbr0': 'ovs', 'dmz10': 'vnet'}
    # far20 sits in a zone this node is not part of
    assert 'far20' not in inv['bridges'] and 'eno1' not in inv['bridges']
    assert inv['storages']['offline-nfs']['active'] is False
    assert inv['storages']['local']['content'] == {'iso', 'vztmpl'}


@pytest.mark.parametrize('broken', ['network', 'storages'])
def test_an_unreadable_node_list_is_no_allowlist(broken):
    with pytest.raises(RuntimeError):
        _inv(**{broken: 'fail'})


def test_without_sdn_there_are_no_vnets_and_no_complaint():
    inv = _inv(vnets='fail')
    assert 'dmz10' not in inv['bridges'] and inv['notes']
    p = Pve([])
    real = p._api_get
    p._api_get = lambda url, **k: _Resp(None, 404) if 'sdn' in url else real(url)
    inv = v2p.read_target_inventory(p, 'pve1')
    assert 'dmz10' not in inv['bridges'] and inv['notes'] == []


def test_unreadable_zones_offer_no_vnet():
    inv = _inv(zones='fail')
    assert 'dmz10' not in inv['bridges'] and inv['notes']


def _plan(opts, **kw):
    args = dict(source_disks=_disks(3), source_nics=NICS, target_storage='local-lvm',
                network_bridge='vmbr0', net_vlan_tag='', transfer_mode='offline')
    args.update(kw)
    return v2p.resolve_migration_plan(_inv(), args.pop('source_disks'), args.pop('source_nics'),
                                      v2p.parse_migration_options(opts), **args)


def test_a_plan_that_fits_lists_every_nic_disk_and_storage():
    p = _plan({'nic_map': [{'index': 0, 'bridge': 'dmz10'}, {'index': 1, 'bridge': 'vmbr1', 'vlan': 12}],
               'disk_map': [{'index': 1, 'storage': 'fast-lvm'}, {'index': 2, 'skip': True}],
               'verify': 'full'})
    assert p['ok'], p['errors']
    assert [(n['bridge'], n['vlan'], n['skip']) for n in p['nics']] == [('dmz10', None, False),
                                                                       ('vmbr1', 12, False)]
    assert [(d['storage'], d['skip']) for d in p['disks']] == [('local-lvm', False), ('fast-lvm', False), (None, True)]
    need = {s['storage']: s['needed_bytes'] for s in p['storages']}
    assert need == {'local-lvm': FLATS['app01-flat.vmdk'], 'fast-lvm': FLATS['app01_1-flat.vmdk']}
    assert any('stays behind' in w for w in p['warnings'])


@pytest.mark.parametrize('opts,needle', [
    ({'nic_map': [{'index': 1, 'bridge': 'vmbr9'}]}, "bridge 'vmbr9' does not exist"),
    ({'nic_map': [{'index': 0, 'bridge': 'far20'}]}, "bridge 'far20' does not exist"),
    ({'nic_map': [{'index': 2, 'bridge': 'vmbr0'}]}, 'names NIC 2'),
    ({'disk_map': [{'index': 1, 'storage': 'nope'}]}, "storage 'nope' does not exist"),
    ({'disk_map': [{'index': 1, 'storage': 'offline-nfs'}]}, 'not active'),
    ({'disk_map': [{'index': 1, 'storage': 'local'}]}, 'does not take disk images'),
    ({'disk_map': [{'index': 1, 'storage': 'nfs-a'}]}, 'GiB free'),
    ({'disk_map': [{'index': 5, 'storage': 'fast-lvm'}]}, 'names disk 5'),
])
def test_a_plan_that_does_not_fit_says_why(opts, needle):
    p = _plan(opts)
    assert not p['ok']
    assert any(needle in e for e in p['errors']), p['errors']


@pytest.mark.parametrize('mode', ['sshfs_boot', 'snapshot_zero'])
def test_full_verify_is_refused_where_it_cannot_be_done(mode):
    p = _plan({'verify': 'full'}, transfer_mode=mode)
    assert not p['ok'] and any('verify=full is not possible' in e for e in p['errors'])
    assert v2p.full_verify_refusal(mode)
    for ok_mode in ('offline', 'vmkfstools_clone', 'auto'):
        assert v2p.full_verify_refusal(ok_mode) is None


def test_the_job_bridge_is_checked_as_well():
    p = _plan({'nic_map': [{'index': 1, 'bridge': 'vmbr1'}]}, network_bridge='vmbr7')
    assert any("bridge 'vmbr7' does not exist" in e for e in p['errors'])


def test_every_nic_skipped_is_a_warning():
    p = _plan({'nic_map': [{'index': 0, 'skip': True}, {'index': 1, 'skip': True}]})
    assert p['ok'] and any('no network' in w for w in p['warnings'])


# --------------------------------------------------------------------------- the maps at work

def _create(r):
    """The data the VM create call sent to Proxmox."""
    post = next(e for e in r.posts() if e[1] == '/nodes/pve1/qemu')
    return dict(post[2])


MAPS = {'disk_map': [{'index': 1, 'storage': 'fast-lvm'}, {'index': 2, 'skip': True}],
        'nic_map': [{'index': 0, 'skip': True}, {'index': 1, 'bridge': 'vmbr1', 'vlan': 5}]}


@pytest.mark.parametrize('mode', ['offline', 'vmkfstools_clone', 'auto'])
def test_each_disk_lands_where_the_map_says_and_a_skipped_one_nowhere(monkeypatch, mode):
    kw = {'clone_snap_fails': True} if mode == 'auto' else {}
    r = Run(monkeypatch, mode=mode, ndisks=3, config=dict(MAPS), **kw).go()
    assert r.task.status == 'completed', r.task.error
    cmds = r.nodecmds()
    allocs = [c.split(' 2>')[0] for c in cmds if c.startswith('pvesm alloc')]
    assert allocs == [f'pvesm alloc local-lvm {VMID} vm-{VMID}-disk-0 3G --format raw',
                      f'pvesm alloc fast-lvm {VMID} vm-{VMID}-disk-1 1G --format raw'], allocs
    attach = _attaches(cmds)
    assert attach == [f'qm set {VMID} --scsi0 local-lvm:vm-{VMID}-disk-0',
                      f'qm set {VMID} --scsi1 fast-lvm:vm-{VMID}-disk-1'], attach
    # nothing read the skipped disk on either side
    every = json.dumps(r.log)
    assert 'app01_2' not in every.replace('"label"', '')
    # EFI vars stay on target_storage, and the post-copy fixes look at the boot disk
    assert f'qm set {VMID} --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=0 2>&1' in cmds
    assert f'pvesm path local-lvm:vm-{VMID}-disk-0 2>/dev/null' in cmds
    cfg = _create(r)
    assert cfg['tpmstate0'].startswith('local-lvm:1,')
    # NIC 0 skipped: no net0, the boot order names what exists; NIC 1 on its own bridge and tag
    assert 'net0' not in cfg
    assert cfg['net1'] == 'e1000e,bridge=vmbr1,macaddr=00:50:56:aa:00:02,tag=5'
    assert cfg['boot'] == 'order=scsi0;net1'
    assert r.task.disk_progress.keys() == {'disk0', 'disk1'}


def test_the_disk_index_is_the_vms_order_not_the_folder_listing(monkeypatch):
    """ls lists app01, app01_1, app01_2; the VM has them as app01, app01_2, app01_1. Skipping
    disk 1 of the plan must leave app01_2 behind, not app01_1."""
    r = Run(monkeypatch, mode='offline', ndisks=3, disk_order=[0, 2, 1],
            config={'disk_map': [{'index': 1, 'skip': True}]}).go()
    assert r.task.status == 'completed', r.task.error
    copies = [c for c in r.nodecmds() if _ssh_pipe(c)]
    assert len(copies) == 2
    assert 'app01-flat.vmdk' in copies[0] and f'vm-{VMID}-disk-0' in copies[0]
    assert 'app01_1-flat.vmdk' in copies[1] and f'vm-{VMID}-disk-2' in copies[1]
    assert not any('app01_2' in c for c in r.nodecmds())
    attach = _attaches(r.nodecmds())
    assert attach == [f'qm set {VMID} --scsi0 local-lvm:vm-{VMID}-disk-0',
                      f'qm set {VMID} --scsi2 local-lvm:vm-{VMID}-disk-2']


def test_a_disk_outside_the_boot_folder_stops_per_disk_choices_on_the_folder_modes(monkeypatch):
    r = Run(monkeypatch, mode='offline', ndisks=2, config={'disk_map': [{'index': 1, 'storage': 'fast-lvm'}]})
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    r.go()
    assert r.task.status == 'failed' and 'Live Clone' in r.task.error
    assert not any(c.startswith('pvesm alloc') for c in r.nodecmds())
    assert ('esxi_api', 'power', 'stop', 'POWERED_ON') not in r.log


def test_snapshot_zero_pairs_deltas_with_the_disks_that_were_copied(monkeypatch):
    seen = {}

    def loop(pve_mgr, task, vmw, host, user, pw, ds, vm_dir, descs, vols, mnt):
        seen['descs'], seen['vols'] = list(descs), [v[0] for v in vols]
        return True, 1, []
    r = Run(monkeypatch, mode='snapshot_zero', ndisks=3,
            config={'disk_map': [{'index': 1, 'skip': True}, {'index': 2, 'storage': 'fast-lvm'}]})
    monkeypatch.setattr(v2p, '_snapshot_zero_v2p_delta_loop', loop)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert seen['descs'] == ['app01.vmdk', 'app01_2.vmdk']
    assert seen['vols'] == [f'local-lvm:vm-{VMID}-disk-0', f'fast-lvm:vm-{VMID}-disk-2']
    # the sector-size args name only devices the VM has
    assert r.task.kept_disks(3) == [0, 2]


def test_the_live_mirror_mode_follows_the_maps_too(monkeypatch):
    r = Run(monkeypatch, mode='sshfs_boot', ndisks=3, ssh_key='/tmp/v2p-key-fixed',
            config={'disk_map': [{'index': 1, 'skip': True}, {'index': 2, 'storage': 'fast-lvm'}]}).go()
    assert r.task.status == 'completed', r.task.error
    cmds = r.nodecmds()
    allocs = [c.split(' 2>')[0] for c in cmds if c.startswith('pvesm alloc')]
    assert allocs == [f'pvesm alloc local-lvm {VMID} vm-{VMID}-disk-0 3G --format raw',
                      f'pvesm alloc fast-lvm {VMID} vm-{VMID}-disk-2 1G --format raw']
    args = next(c for c in cmds if c.startswith("echo 'args:"))
    assert 'ssh-disk0' in args and 'ssh-disk2' in args and 'ssh-disk1' not in args
    assert 'app01_1-flat' not in args
    attach = _attaches(cmds)
    assert attach == [f'qm set {VMID} --scsi0 local-lvm:vm-{VMID}-disk-0',
                      f'qm set {VMID} --scsi2 fast-lvm:vm-{VMID}-disk-2']


def test_the_sector_size_args_name_only_the_disks_the_vm_has(monkeypatch):
    log = []
    node = Node(log, None)

    def run(mgr, n, cmd, timeout=600, **kw):
        if 'LOG-SEC' in cmd:
            return 0, '4096\n', ''
        if cmd.startswith('pvesm path'):
            return 0, '/dev/fast-lvm/vm-120-disk-0\n', ''
        return node(mgr, n, cmd, timeout)
    monkeypatch.setattr(v2p, '_pve_node_exec', run)
    t = v2p.V2PMigrationTask('t', 'vw', 'vm', 'c', 'pve1', 'local-lvm',
                             config={'disk_map': [{'index': 0, 'storage': 'fast-lvm'}, {'index': 1, 'skip': True}]})
    t.proxmox_vmid = VMID
    t.record_disk_volume(0, f'fast-lvm:vm-{VMID}-disk-0')
    v2p._ensure_guest_sector_size_512(None, t, 'scsi', 3)
    cmds = [e[2] for e in log]
    qm = next(c for c in cmds if '--args' in c)
    assert 'scsi0.' in qm and 'scsi2.' in qm and 'scsi1.' not in qm


def test_qcow2_conversion_keeps_each_disk_on_its_own_storage(monkeypatch):
    log = []
    cfg = (f'scsi0: local-lvm:vm-{VMID}-disk-0,size=3G\nscsi1: fast-lvm:vm-{VMID}-disk-1,size=1G\n'
           f'efidisk0: local-lvm:vm-{VMID}-disk-5,size=4M\nscsi3: other:vm-{VMID}-disk-3,size=1G\n')

    def run(mgr, n, cmd, timeout=600, **kw):
        log.append(cmd)
        return (0, cfg, '') if cmd.startswith('qm config') else (0, '', '')
    monkeypatch.setattr(v2p, '_pve_node_exec', run)
    t = v2p.V2PMigrationTask('t', 'vw', 'vm', 'c', 'pve1', 'local-lvm',
                             config={'disk_format': 'qcow2', 'disk_map': [{'index': 1, 'storage': 'fast-lvm'}]})
    t.proxmox_vmid = VMID
    v2p._maybe_convert_disks_to_qcow2(None, t)
    moves = [c.split(' 2>')[0] for c in log if 'move-disk' in c]
    assert moves == [f'qm move-disk {VMID} scsi0 local-lvm --format qcow2 --delete 1',
                     f'qm move-disk {VMID} scsi1 fast-lvm --format qcow2 --delete 1']


# --------------------------------------------------------------------------- verify

def _fullchecks(r):
    return [c for c in r.nodecmds() if c.startswith('bash /tmp/v2p-fullcheck-')]


def test_full_verify_on_offline_compares_every_disk_before_anything_writes_or_starts(monkeypatch):
    r = Run(monkeypatch, mode='offline', ndisks=3,
            config={'verify': 'full', 'disk_map': [{'index': 2, 'skip': True}]}).go()
    assert r.task.status == 'completed', r.task.error
    cmds = r.nodecmds()
    checks = _fullchecks(r)
    assert len(checks) == 2
    first_fix = cmds.index(f'qm set {VMID} --boot order=scsi0 2>&1')
    assert all(cmds.index(c) < first_fix for c in checks)
    assert ('pve_api', f'/nodes/pve1/qemu/{VMID}/status/start', []) in r.log
    # the ESXi side hashed each source flat in full, from the same block count
    esxi = [e[1] for e in r.log if e[0] == 'esxi_ssh' and 'md5sum' in e[1]]
    assert len(esxi) == 2
    assert '-lt 9 ]' in esxi[0] and 'app01-flat.vmdk' in esxi[0]     # 2 GiB + 3 MiB = 9 blocks
    assert '-lt 4 ]' in esxi[1] and 'app01_1-flat.vmdk' in esxi[1]
    body = r.node.scripts[checks[0].split()[1]]
    assert 'SIZE=%d\n' % FLATS['app01-flat.vmdk'] in body and 'FMT=raw\n' in body
    assert any('all 9 blocks match the source' in line for line in r.task.log_lines)


def test_a_mismatch_fails_the_run_before_the_target_starts_and_brings_the_source_back(monkeypatch):
    r = Run(monkeypatch, mode='offline', config={'verify': 'full'},
            verify_bad={f'/dev/local-lvm/vm-{VMID}-disk-1': {2}}).go()
    assert r.task.status == 'failed'
    assert 'disk 1' in r.task.error and '1 of 4 blocks differ' in r.task.error
    assert f'byte {2 * BLOCK}' in r.task.error
    starts = [e for e in r.log if e[0] == 'pve_api' and e[1].endswith('/status/start')]
    assert starts == []
    cmds = r.nodecmds()
    assert not any('--efidisk0' in c or '--boot order' in c for c in cmds)
    # it was running before: stopped for the copy, powered on again after the failed check
    power = [e[2] for e in r.log if e[:2] == ('esxi_api', 'power')]
    assert power == ['stop', 'start']
    assert 'powered back on' in r.task.error
    assert r.task.esxi_password == ''


def test_a_side_that_cannot_be_read_is_a_failure_not_a_pass(monkeypatch):
    r = Run(monkeypatch, mode='offline', config={'verify': 'full'}, verify_fail=True,
            power='POWERED_OFF').go()
    assert r.task.status == 'failed' and 'could not be read' in r.task.error
    assert not [e for e in r.log if e[0] == 'pve_api' and e[1].endswith('/status/start')]
    # it was off before, it stays off
    assert not [e for e in r.log if e[:2] == ('esxi_api', 'power')]


def test_a_changed_source_size_is_a_failure(monkeypatch):
    r = Run(monkeypatch, mode='offline', config={'verify': 'full'})
    real = r.mod._ssh_exec

    def grown(host, user, pw, cmd, timeout=30):
        rc, out, err = real(host, user, pw, cmd, timeout)
        if cmd.startswith("stat -c '%s'") and 'md5sum' in cmd:
            lines = out.splitlines()
            out = '\n'.join([str(int(lines[0]) + 4096)] + lines[1:]) + '\n'
        return rc, out, err
    monkeypatch.setattr(v2p, '_ssh_exec', grown)
    r.go()
    assert r.task.status == 'failed' and 'bytes now' in r.task.error


def test_full_verify_on_the_live_clone_checks_the_frozen_base_while_the_source_runs(monkeypatch):
    r = Run(monkeypatch, mode='vmkfstools_clone', config={'verify': 'full'}).go()
    assert r.task.status == 'completed', r.task.error
    cmds = r.nodecmds()
    checks = _fullchecks(r)
    assert len(checks) == 2
    stop = r.log.index(next(e for e in r.log if e[:3] == ('esxi_api', 'power', 'stop')))
    assert all(r.log.index(('node', 'pve1', c)) < stop for c in checks)
    # the copies were compared with the clones, the frozen base
    esxi = [e[1] for e in r.log if e[0] == 'esxi_ssh' and 'md5sum' in e[1] and "stat -c '%s'" in e[1]]
    assert [f'_pegaprox_clone_{VMID}_{i}-flat.vmdk' in esxi[i] for i in (0, 1)] == [True, True]
    # the sums of that read stand in for the switchover's pre-checksums: no second full read
    assert not [c for c in cmds if 'md5sum' in c and 'while' in c and not c.startswith('umask 077')]


def test_a_live_clone_mismatch_fails_before_the_source_is_touched(monkeypatch):
    r = Run(monkeypatch, mode='vmkfstools_clone', config={'verify': 'full'},
            src_bad={f'/vmfs/volumes/ds1/app01/_pegaprox_clone_{VMID}_0-flat.vmdk': {0}}).go()
    assert r.task.status == 'failed' and 'disk 0' in r.task.error and 'not touched' in r.task.error
    assert not [e for e in r.log if e[:2] == ('esxi_api', 'power')]
    assert not [e for e in r.log if e[0] == 'pve_api' and e[1].endswith('/status/start')]
    # failed-job cleanup: clone snapshot dropped, clones removed
    assert r.esxi.snaps == []
    rms = [e[1] for e in r.log if e[0] == 'esxi_cli' and e[1].startswith('vmkfstools -U')]
    assert len(rms) >= 2


def test_auto_without_a_snapshot_on_a_running_source_refuses_full_verify(monkeypatch):
    r = Run(monkeypatch, mode='auto', config={'verify': 'full'}, clone_snap_fails=True)
    real = r.esxi.create_snapshot

    def no_migration_snapshot(vm_id, name, *a, **k):
        if name == '_pegaprox_migration_snap':
            return {'error': 'locked'}
        return real(vm_id, name, *a, **k)
    r.esxi.create_snapshot = no_migration_snapshot
    r.go()
    assert r.task.status == 'failed' and 'snapshot' in r.task.error
    assert not any(c.startswith('pvesm alloc') for c in r.nodecmds())


def test_auto_presync_is_checked_against_the_frozen_base(monkeypatch):
    r = Run(monkeypatch, mode='auto', config={'verify': 'full'}, clone_snap_fails=True).go()
    assert r.task.status == 'completed', r.task.error
    checks = _fullchecks(r)
    stop = next(n for n, e in enumerate(r.log) if e[:3] == ('esxi_api', 'power', 'stop'))
    assert len(checks) == 2 and all(r.log.index(('node', 'pve1', c)) < stop for c in checks)


@pytest.mark.parametrize('mode', ['sshfs_boot', 'snapshot_zero'])
def test_full_verify_never_starts_on_a_mode_that_cannot_do_it(monkeypatch, mode):
    r = Run(monkeypatch, mode=mode, config={'verify': 'full'}).go()
    assert r.task.status == 'failed' and 'verify=full is not possible' in r.task.error
    assert r.log == []


def test_verify_off_drops_the_spot_check_and_sample_keeps_it(monkeypatch):
    def run(verify):
        mp = pytest.MonkeyPatch()
        try:
            r = Run(mp, mode='sshfs_boot', firmware='bios', tpm=False, config={'verify': verify}).go()
            return r, r.nodecmds()
        finally:
            mp.undo()
    r_off, off = run('off')
    r_sample, sample = run('sample')
    assert r_off.task.status == r_sample.task.status == 'completed'
    assert any('xxhsum' in c for c in sample) and any(c.startswith('bash /tmp/v2p-verify-') for c in sample)
    assert not any('xxhsum' in c for c in off) and not any(c.startswith('bash /tmp/v2p-verify-') for c in off)
    # the rest is the same run; script files are numbered as they are written
    def norm(cmds):
        return [re.sub(r'(/tmp/v2p-[a-z0-9-]+-)\d{10}', r'\1N', c) for c in cmds
                if 'xxhsum' not in c and 'v2p-verify-' not in c]
    assert norm(sample) == norm(off)


# --------------------------------------------------------------------------- the node script

def test_the_block_sum_script_reads_raw_volumes_as_they_are(tmp_path):
    vol = tmp_path / 'vm 120;disk.raw'
    data = os.urandom(3 * 1024 * 1024 + 5)
    vol.write_bytes(data + b'\xff' * 4096)          # what lies past the disk is not part of it
    monkey = v2p.DELTA_BLOCK_SIZE
    try:
        v2p.DELTA_BLOCK_SIZE = 1024 * 1024
        body = v2p._target_block_sums_script(str(vol), 'raw', len(data))
    finally:
        v2p.DELTA_BLOCK_SIZE = monkey
    out = subprocess.run(['bash', '-c', body], capture_output=True, text=True, timeout=60)
    lines = out.stdout.split()
    import hashlib
    want = [hashlib.md5(data[i:i + 1024 * 1024]).hexdigest() for i in range(0, len(data), 1024 * 1024)]
    assert out.returncode == 0, out.stdout + out.stderr
    assert lines == want + ['VERIFY_DONE']


def test_the_block_sum_script_refuses_a_volume_shorter_than_the_disk(tmp_path):
    vol = tmp_path / 'short.raw'
    vol.write_bytes(b'\0' * 1000)
    out = subprocess.run(['bash', '-c', v2p._target_block_sums_script(str(vol), 'raw', 4096)],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 4 and 'SHORT 1000' in out.stdout and 'VERIFY_DONE' not in out.stdout


def test_a_qcow2_target_is_read_through_qemu_nbd_read_only():
    body = v2p._target_block_sums_script("/mnt/pve/nfs a/images/120/vm-120-disk-1.qcow2", 'qcow2', GiB)
    assert "VOL='/mnt/pve/nfs a/images/120/vm-120-disk-1.qcow2'\n" in body
    assert 'qemu-nbd --read-only --format="$FMT"' in body and 'FMT=qcow2\n' in body
    assert 'qemu-nbd --disconnect' in body and 'trap cleanup EXIT' in body
    assert subprocess.run(['bash', '-n'], input=body, text=True).returncode == 0
    assert v2p._volume_format('nfs:120/vm-120-disk-1.qcow2') == 'qcow2'
    assert v2p._volume_format('local-lvm:vm-120-disk-1') == 'raw'
    assert v2p._volume_format('local:120/vm-120-disk-1.raw') == 'raw'
    with pytest.raises(ValueError):
        v2p._target_block_sums_script('/x', 'raw;reboot', 1)


def test_the_check_has_time_in_proportion_to_the_disk(monkeypatch):
    seen = []
    r = Run(monkeypatch, mode='offline', config={'verify': 'full'})
    node = r.node

    def timed(mgr, n, cmd, timeout=600, **kw):
        if cmd.startswith('bash /tmp/v2p-fullcheck-'):
            seen.append(timeout)
        return node(mgr, n, cmd, timeout)
    monkeypatch.setattr(v2p, '_pve_node_exec', timed)
    r.go()
    assert r.task.status == 'completed'
    assert seen == [v2p._full_check_timeout(FLATS['app01-flat.vmdk']),
                    v2p._full_check_timeout(FLATS['app01_1-flat.vmdk'])]
    assert v2p._full_check_timeout(4 * 1024 ** 4) > 4 * 1024 ** 4 // (25 * 1024 ** 2)
    assert v2p._full_check_timeout(1) == 600


# --------------------------------------------------------------------------- the route

@pytest.fixture
def route(api, seed, monkeypatch):
    import pegaprox.globals as g
    import pegaprox.api.vmware as vmwareapi
    log = []
    esxi = Esxi(log, _disks(3))
    pve = Pve(log)
    api.set_manager('pve-cl', pve)
    g.vmware_managers['vw1'] = esxi
    started = []
    monkeypatch.setattr(vmwareapi, '_run_v2p_migration', lambda task: started.append(task))
    admin = api.as_user(seed.user('root', role='admin'))

    def post(**extra):
        body = {'target_cluster': 'pve-cl', 'target_node': 'pve1', 'target_storage': 'local-lvm',
                'esxi_password': 'pw', 'transfer_mode': 'offline'}
        body.update(extra)
        body = {k: v for k, v in body.items() if v is not None}
        return admin.post('/api/vmware/vw1/vms/vm-42/migrate', json=body)

    def wait_started(n=1):
        for _ in range(100):
            if len(started) >= n:
                break
            time.sleep(0.02)
        return started
    try:
        yield types.SimpleNamespace(post=post, pve=pve, esxi=esxi, started=started, admin=admin,
                                    wait_started=wait_started, module=vmwareapi)
    finally:
        g.vmware_managers.pop('vw1', None)


def test_a_dry_run_answers_with_the_plan_needs_no_password_and_starts_nothing(route):
    r = route.post(esxi_password=None, dry_run=True, verify='full',
                   nic_map=[{'index': 1, 'bridge': 'dmz10'}],
                   disk_map=[{'index': 1, 'storage': 'fast-lvm'}, {'index': 2, 'skip': True}])
    assert r.status_code == 200, r.get_data(as_text=True)
    p = r.get_json()
    assert p['dry_run'] is True and p['ok'] is True, p
    assert [n['bridge'] for n in p['nics']] == ['vmbr0', 'dmz10']
    assert [(d['storage'], d['skip']) for d in p['disks']] == [('local-lvm', False), ('fast-lvm', False), (None, True)]
    assert {'name': 'dmz10', 'kind': 'vnet'} in p['available']['bridges']
    assert {s['storage'] for s in p['available']['storages']} == {'local-lvm', 'fast-lvm', 'nfs-a'}
    assert 'pw' not in r.get_data(as_text=True)
    time.sleep(0.1)
    assert route.started == []


def test_a_dry_run_reports_what_does_not_fit_with_200(route):
    r = route.post(dry_run=True, nic_map=[{'index': 0, 'bridge': 'vmbr9'}], verify='full',
                   transfer_mode='sshfs_boot')
    assert r.status_code == 200
    p = r.get_json()
    assert p['ok'] is False
    assert any("'vmbr9' does not exist" in e for e in p['errors'])
    assert any('verify=full is not possible' in e for e in p['errors'])


def test_a_start_with_a_bridge_the_node_does_not_have_is_refused(route):
    r = route.post(nic_map=[{'index': 1, 'bridge': 'vmbr9'}])
    assert r.status_code == 400, r.get_data(as_text=True)
    assert "'vmbr9' does not exist" in r.get_json()['error']
    time.sleep(0.1)
    assert route.started == []


def test_a_start_with_maps_that_fit_hands_them_to_the_task(route):
    r = route.post(nic_map=[{'index': 1, 'bridge': 'ovsbr0', 'vlan': 7}],
                   disk_map=[{'index': 2, 'skip': True}], verify='full')
    assert r.status_code == 202, r.get_data(as_text=True)
    task = route.wait_started()[0]
    assert task.nic_map[1]['bridge'] == 'ovsbr0' and task.disk_map[2]['skip'] is True
    assert task.verify_mode == 'full' and task.to_dict()['config']['verify'] == 'full'


@pytest.mark.parametrize('extra', [
    {'nic_map': [{'index': 0, 'bridge': 'vmbr0,firewall=0'}]},
    {'nic_map': [{'index': 0, 'bridge': 'vmbr0', 'vlan': '5;reboot'}]},
    {'disk_map': [{'index': 1, 'storage': 'local-lvm;reboot'}]},
    {'disk_map': [{'index': 1, 'storage': '$(id)'}]},
    {'network_bridge': 'vmbr0,tag=5'},
    {'network_bridge': 'vmbr0\nreboot'},
    {'verify': 'yes'},
    {'dry_run': 'yes'},
    {'disk_map': [{'index': 0, 'skip': True}]},
])
def test_names_that_could_reach_a_shell_or_a_net_line_are_refused_at_the_door(route, extra):
    r = route.post(**extra)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert not any('/network' in u for u in route.pve.gets), 'checked the node before the format'
    time.sleep(0.05)
    assert route.started == []


def test_full_verify_on_a_mode_that_cannot_do_it_is_refused_at_the_start(route):
    for mode in ('sshfs_boot', 'snapshot_zero'):
        r = route.post(verify='full', transfer_mode=mode)
        assert r.status_code == 400 and 'verify=full is not possible' in r.get_json()['error']
    time.sleep(0.05)
    assert route.started == []


def test_a_request_without_the_new_keys_does_not_ask_the_node_anything(route):
    r = route.post()
    assert r.status_code == 202, r.get_data(as_text=True)
    assert not [u for u in route.pve.gets if '/network' in u or '/storage' in u]
    task = route.wait_started()[0]
    assert task.nic_map is None and task.disk_map is None and task.verify_mode == 'sample'


def test_a_target_node_outside_the_cluster_is_refused(route):
    r = route.post(dry_run=True, target_node='pve9')
    assert r.status_code == 400 and 'not a node of the target cluster' in r.get_json()['error']


@pytest.mark.parametrize('what', ['network', 'storages'])
def test_an_unreadable_node_fails_closed(route, what):
    setattr(route.pve, what, 'fail')
    r = route.post(disk_map=[{'index': 1, 'storage': 'fast-lvm'}])
    assert r.status_code == 502, r.get_data(as_text=True)
    time.sleep(0.05)
    assert route.started == []


def test_the_dry_run_goes_through_the_target_cluster_gate(route, monkeypatch):
    monkeypatch.setattr(route.module, 'caller_is_scoped', lambda *a, **k: True)
    r = route.post(dry_run=True, esxi_password=None)
    assert r.status_code == 403
    assert not [u for u in route.pve.gets if '/network' in u]


def test_the_migration_plan_lists_the_nics_the_maps_count(route):
    r = route.admin.get('/api/vmware/vw1/vms/vm-42/migration-plan')
    assert r.status_code == 200, r.get_data(as_text=True)
    src = r.get_json()['source']
    assert [n['mac_address'] for n in src['nics']] == [n['mac_address'] for n in NICS]
    assert [d['vmdk_file'] for d in src['disks']] == [d['vmdk_file'] for d in _disks(3)]


# --------------------------------------------------------------------------- the wizard, rendered

PLAN_SOURCE = {
    'vm_id': 'vm-1', 'name': 'legacy01', 'power_state': 'POWERED_ON', 'cpu_count': 2, 'memory_mb': 4096,
    'guest_os': 'Ubuntu', 'total_disk_gb': 3.5, 'nics': [dict(n) for n in NICS], 'disks': _disks(3),
    'hardware': {'firmware': 'bios', 'disk_bus': 'scsi'},
}
WIZ_PLAN = {'source': PLAN_SOURCE, 'method': 'test', 'requirements': [],
            'targets': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'nodes': ['pve1'],
                         'storages': {'pve1': ['local-lvm', 'fast-lvm']}}]}
WIZ_DRY = {'dry_run': True, 'ok': True, 'errors': [], 'warnings': ['disk 3 (Hard disk 3, 0.5 GiB) stays behind'],
           'nics': [{'index': 0, 'net': 'net0', 'label': 'Network adapter 1', 'source_network': 'VM Network',
                     'skip': False, 'bridge': 'vmbr1', 'vlan': None},
                    {'index': 1, 'net': 'net1', 'label': 'Network adapter 2', 'source_network': 'DMZ',
                     'skip': True, 'bridge': None, 'vlan': None}],
           'disks': [{'index': 0, 'label': 'Hard disk 1', 'size_bytes': 2 * GiB, 'boot': True, 'skip': False,
                      'storage': 'local-lvm'}],
           'storages': [{'storage': 'local-lvm', 'type': 'lvmthin', 'needed_bytes': 2 * GiB,
                         'avail_bytes': 500 * GiB, 'ok': True}],
           'verify': 'full',
           'available': {'bridges': [{'name': 'vmbr0', 'kind': 'bridge'}, {'name': 'vmbr1', 'kind': 'bridge'},
                                     {'name': 'dmz10', 'kind': 'vnet'}],
                         'storages': [{'storage': 'local-lvm', 'type': 'lvmthin', 'avail_bytes': 500 * GiB},
                                      {'storage': 'fast-lvm', 'type': 'lvm', 'avail_bytes': 100 * GiB}]},
           'migration_id': 'm1'}


from test_ha_ui import browser  # noqa: E402,F401 (a fixture: headless Chromium, skips without Playwright)


@pytest.fixture
def wizard(browser):
    from test_ha_ui import _App, _FakeServer, ESXI_READS, SSE_TOKEN
    apps = []

    def _open(dry=None):
        extra = {**ESXI_READS, **SSE_TOKEN,
                 ('GET', '/api/vmware/v1/vms/vm-1/migration-plan'): (200, WIZ_PLAN),
                 ('POST', '/api/vmware/v1/vms/vm-1/migrate'): (200, dry or WIZ_DRY),
                 ('GET', '/api/vmware/migrations'): (200, [])}
        app = _App(browser, _FakeServer(role='standalone', layout='modern', extra=extra))
        apps.append(app)
        page = app.page
        page.get_by_text('esx01').first.click()
        page.get_by_text('legacy01').first.wait_for(timeout=8000)
        page.get_by_text('legacy01').first.click()
        page.locator('button:visible', has_text='Migration').first.wait_for(timeout=8000)
        page.locator('button:visible', has_text='Migration').first.click()
        page.locator('button:visible', has_text='Start Migration Wizard').first.click()
        page.locator('option', has_text='Select cluster...').first.wait_for(state='attached', timeout=5000)
        return app, page
    yield _open
    for app in apps:
        app.ctx.close()


def _pick_target(page):
    page.locator('select', has=page.locator('option', has_text='Select cluster...')).select_option('c1')
    page.locator('select', has=page.locator('option', has_text='Select node...')).select_option('pve1')
    page.locator('select', has=page.locator('option', has_text='Select storage...')).select_option('local-lvm')


def _migrate_bodies(app):
    return app.server.bodies.get('/api/vmware/v1/vms/vm-1/migrate', [])


def test_runtime_the_wizard_maps_nics_and_disks_reviews_and_starts_what_it_reviewed(wizard):
    app, page = wizard()
    _pick_target(page)
    # the dry run without maps fills the bridge lists with what the node has
    page.locator('option', has_text='dmz10 (vnet)').first.wait_for(state='attached', timeout=5000)
    assert _migrate_bodies(app)[0] == {'target_cluster': 'c1', 'target_node': 'pve1',
                                       'target_storage': 'local-lvm', 'dry_run': True}
    nic_selects = page.locator('select', has=page.locator('option', has_text='dmz10 (vnet)'))
    assert nic_selects.count() == 2
    nic_selects.nth(0).select_option('vmbr1')
    rows = page.locator('label', has_text='Skip')
    # the two disks that may be skipped (the boot disk has none), then the two NICs
    assert rows.count() == 4
    rows.nth(1).locator('input').check()          # disk 3
    rows.nth(3).locator('input').check()          # NIC 2
    disk_selects = page.locator('select', has=page.locator('option', has_text='Default (local-lvm)'))
    assert disk_selects.count() == 3
    disk_selects.nth(1).select_option('fast-lvm')
    # a running source on Live Clone: the spot check is the default, full is a pick
    verify = page.locator('select', has=page.locator('option', has_text='Full - compare every block'))
    assert verify.input_value() == 'sample'
    verify.select_option('full')
    page.get_by_text('Every copied disk is read again on both sides').first.wait_for(timeout=2000)
    page.locator('input[placeholder="ESXi password"]').fill('pw')

    # no Start outside the review step
    assert page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$')).count() == 0
    page.locator('button', has_text='Review and start').click()
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    page.get_by_text('stays behind').first.wait_for(timeout=2000)
    review = _migrate_bodies(app)[-1]
    assert review['dry_run'] is True and 'esxi_password' not in review and 'oc_acknowledge' not in review
    assert review['nic_map'] == [{'index': 0, 'skip': False, 'bridge': 'vmbr1'}, {'index': 1, 'skip': True}]
    assert review['disk_map'] == [{'index': 0, 'skip': False}, {'index': 1, 'skip': False, 'storage': 'fast-lvm'},
                                  {'index': 2, 'skip': True}]
    assert review['verify'] == 'full'

    start = page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$'))
    assert start.is_disabled()                     # the support note is not ticked yet
    page.locator('label', has_text='keep this in mind').locator('input').check()
    assert start.is_enabled()
    start.click()
    for _ in range(50):
        if len(_migrate_bodies(app)) > len([b for b in _migrate_bodies(app) if b.get('dry_run')]):
            break
        page.wait_for_timeout(100)
    sent = [b for b in _migrate_bodies(app) if not b.get('dry_run')]
    assert len(sent) == 1
    body = dict(sent[0])
    assert body.pop('esxi_password') == 'pw'
    expect = dict(review)
    expect.pop('dry_run')
    assert body == expect, 'Start sent something other than what the review checked'
    assert not app.errors, app.errors


def test_runtime_a_change_after_the_review_needs_a_new_check(wizard):
    app, page = wizard()
    _pick_target(page)
    page.locator('option', has_text='dmz10 (vnet)').first.wait_for(state='attached', timeout=5000)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    page.locator('label', has_text='keep this in mind').locator('input').check()
    page.locator('button', has_text='Review and start').click()
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    start = page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$'))
    assert start.is_enabled()
    # back to the target step, skip a disk, back to the review tab: checked again on the way
    page.locator('button', has_text='Target').first.click()
    page.locator('label', has_text='Skip').nth(0).locator('input').check()
    n = len(_migrate_bodies(app))
    page.locator('button', has_text=re.compile(r'^\W*Review\s*$')).first.click()
    for _ in range(50):
        if len(_migrate_bodies(app)) > n:
            break
        page.wait_for_timeout(100)
    assert _migrate_bodies(app)[-1]['disk_map'][1]['skip'] is True, 'the review tab did not check again'
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    assert page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$')).is_enabled()
    assert not app.errors, app.errors


def test_runtime_server_errors_show_on_the_review_and_keep_start_off(wizard):
    bad = dict(WIZ_DRY, ok=False, errors=["NIC 1: bridge 'vmbr9' does not exist on the target node",
                                          'verify=full is not possible with the sshfs_boot transfer mode'])
    app, page = wizard(dry=bad)
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    page.locator('label', has_text='keep this in mind').locator('input').check()
    page.locator('button', has_text='Review and start').click()
    page.get_by_text('The plan does not fit the target node:').first.wait_for(timeout=5000)
    page.get_by_text("bridge 'vmbr9' does not exist").first.wait_for(timeout=2000)
    assert page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$')).is_disabled()
    assert not app.errors, app.errors
