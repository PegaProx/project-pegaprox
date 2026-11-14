# #1124 - the live clone mode lost data. It snapshotted the running VM, cloned and copied the
# frozen base, then suspended the source and started the target. Whatever the guest wrote after
# the snapshot, during the copy and during the confirmation hold, never reached Proxmox. The
# switchover now stops the source, folds the snapshot back, checks that it really is gone and
# copies the blocks that differ before anything writes to the target disks.
#
# These tests drive _run_v2p_migration against an ESXi and a Proxmox that only exist here and
# look at the order of what happens around the switchover. Nothing reaches a host.

import re
import shlex
import time

import pytest

import pegaprox.core.v2p as v2p

GiB = 1024 ** 3
VMID = 120

BASE_DESC = '''# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="vmfs"

# Extent description
RW {sectors} VMFS "{flat}"
'''

CHAIN_DESC = '''# Disk DescriptorFile
version=1
CID=2a1b3c4d
parentCID=fffffffe
createType="seSparse"
parentFileNameHint="app01.vmdk"

# Extent description
RW {sectors} SESPARSE "app01-000001-sesparse.vmdk"
'''

TWO_DISKS = [
    {'key': '2000', 'file': '[ds1] app01/app01.vmdk', 'capacity': 2 * GiB},
    {'key': '2001', 'file': '[ds2] app01-data/app01_1.vmdk', 'capacity': 1 * GiB},
]


class FakeEsxi:
    """The vSphere side: power state, the snapshot tree and the file each disk runs on.

    `consolidation` is what removing a snapshot does: 'now', 'later' (the remove call times
    out and ESXi finishes a few polls afterwards), 'never' (times out and stays), or
    'snapshot_only' (the snapshot goes, the disks stay on their delta). 'slow' and 'stuck'
    keep a merge task running on the VM for `merge_secs` of clock time, or forever; like
    ESXi, the VM then takes no other task, PowerOn included."""

    def __init__(self, events, disks, clock=None, power='POWERED_ON', consolidation='now', polls=3,
                 merge_secs=0, clone_snap_fails=False, ignores_stop=False):
        self.events = events
        self.clock = clock
        self.host = 'esx1.lab'
        self.power = power
        self.disks = disks
        self.files = {d['key']: d['file'] for d in disks}
        self.snaps = []
        self.consolidation = consolidation
        self.polls = polls
        self.merge_secs = merge_secs
        self.clone_snap_fails = clone_snap_fails
        self.ignores_stop = ignores_stop
        self._pending = None
        self._merging = None  # (snapshot id, clock time the merge ends)
        self._n = 0

    def _tick(self):
        if self._merging and self.clock.now >= self._merging[1]:
            self._fold(self._merging[0])
            self._merging = None

    def consolidated(self):
        return not self.snaps and self.files == {d['key']: d['file'] for d in self.disks}

    def _fold(self, sid):
        self.snaps = [s for s in self.snaps if s['snapshot'] != sid]
        self.files = {d['key']: d['file'] for d in self.disks}

    def get_vm_disks_for_export(self, vm_id):
        self._tick()
        return {'data': {
            'vm_id': vm_id, 'name': 'app01', 'power_state': self.power,
            'cpu_count': 2, 'memory_mb': 2048, 'guest_os': 'Linux',
            'disks': [{'key': d['key'], 'label': d['key'], 'capacity_bytes': d['capacity'],
                       'capacity_gb': d['capacity'] / GiB, 'thin': False,
                       'vmdk_file': self.files[d['key']]} for d in self.disks],
            'total_disk_gb': sum(d['capacity'] for d in self.disks) / GiB}}

    def get_vm(self, vm_id):
        self._tick()
        return {'data': {'name': 'app01', 'power_state': self.power, 'guest_OS': 'Linux',
                         'hardware': {'firmware': 'bios', 'scsi_controller_pve': 'pvscsi',
                                      'disk_bus': 'scsi', 'nic_type_pve': 'vmxnet3'},
                         'controllers': {}, 'nics': []}}

    def get_snapshots(self, vm_id):
        self._tick()
        if self._pending:
            sid, left = self._pending
            if left <= 0:
                self._fold(sid)
                self._pending = None
            else:
                self._pending = (sid, left - 1)
        return {'data': [dict(s) for s in self.snaps]}

    def create_snapshot(self, vm_id, name, description='', memory=False, quiesce=True):
        if name == '_pegaprox_clone_snap' and self.clone_snap_fails:
            return {'error': 'snapshot did not appear within 60s'}
        self._n += 1
        self.snaps.append({'snapshot': f'snapshot-{self._n}', 'name': name})
        # from here on the running VM writes to a delta of every disk
        self.files = {k: f.replace('.vmdk', '-000001.vmdk') for k, f in self.files.items()}
        self.events.append(('snapshot', name, self.power))
        return {'data': {'name': name}}

    def create_migration_snapshot(self, vm_id):
        return self.create_snapshot(vm_id, '_pegaprox_migration_snap')

    def delete_migration_snapshot(self, vm_id):
        for s in self.snaps:
            if s['name'] == '_pegaprox_migration_snap':
                self._fold(s['snapshot'])
                return {'data': 'deleted'}
        return {'data': 'no migration snapshot found'}

    def delete_snapshot(self, vm_id, snapshot_id):
        self._tick()
        self.events.append(('remove_snapshot', snapshot_id, self.power))
        if self._merging:
            return {'error': 'Another task is already in progress.'}
        if not any(s['snapshot'] == snapshot_id for s in self.snaps):
            return {'error': f'snapshot {snapshot_id} not found'}
        if self.consolidation in ('slow', 'stuck'):
            ends = self.clock.now + self.merge_secs if self.consolidation == 'slow' else float('inf')
            self._merging = (snapshot_id, ends)
            return {'error': 'remove timed out'}
        if self.consolidation == 'now':
            self._fold(snapshot_id)
            return {'data': 'deleted'}
        if self.consolidation == 'later':
            self._pending = (snapshot_id, self.polls)
            return {'error': 'remove timed out'}
        if self.consolidation == 'snapshot_only':
            self.snaps = [s for s in self.snaps if s['snapshot'] != snapshot_id]
            return {'data': 'deleted'}
        return {'error': 'remove timed out'}

    def vm_power_action(self, vm_id, action):
        self._tick()
        self.events.append(('power', action))
        if self._merging:
            return {'error': 'Another task is already in progress.'}
        if action == 'stop' and self.power != 'POWERED_OFF':
            if not self.ignores_stop:
                self.power = 'POWERED_OFF'
        elif action == 'start' and self.power == 'POWERED_OFF':
            self.power = 'POWERED_ON'
        elif action == 'suspend' and self.power == 'POWERED_ON':
            self.power = 'SUSPENDED'
        else:
            return {'error': f'cannot {action} a VM that is {self.power}'}
        return {'data': {'task': 'ok'}}

    def delete_vm(self, vm_id):
        self.events.append(('delete_vm',))
        return {'data': 'ok'}


class _Resp:
    def __init__(self, data, status=200, text=''):
        self.status_code = status
        self._data = data
        self.text = text

    def json(self):
        return {'data': self._data}


class FakePve:
    """`start` is how Proxmox takes the target start: 'ok', 'http500' (refused, no task),
    'task_error' (the start task fails), 'no_answer' (the request times out, nothing runs)
    or 'dies' (the task ends OK, the VM is gone right after)."""
    host = 'pve1.lab'
    api_port = 8006

    def __init__(self, events, start='ok'):
        self.events = events
        self.start = start
        self.running = False

    def _api_get(self, url, **kw):
        if url.endswith('/cluster/nextid'):
            return _Resp(VMID)
        if '/tasks/' in url:
            if 'qmstart' in url and self.start == 'task_error':
                return _Resp({'status': 'stopped', 'exitstatus': 'start failed: QEMU exited with code 1'})
            return _Resp({'status': 'stopped', 'exitstatus': 'OK'})
        if url.endswith('/status/current'):
            return _Resp({'status': 'running' if self.running else 'stopped'})
        return _Resp({})

    def _api_post(self, url, data=None, **kw):
        if url.endswith('/status/start'):
            self.events.append(('start_target',))
            if self.start == 'http500':
                return _Resp(None, 500, "can't lock file '/var/lock/qemu-server/lock-120.conf'")
            if self.start == 'no_answer':
                import requests
                raise requests.exceptions.ReadTimeout('read timed out')
            self.running = self.start == 'ok'
            return _Resp(f'UPID:pve1:00005678:0000ABCD:qmstart:{VMID}:root@pam:')
        return _Resp('UPID:pve1:00001234:create')


class FakeNode:
    """_pve_node_exec. Checksum loops answer one line per block that names the volume, so a
    test can tell which volume a checksum list came from."""

    def __init__(self, events):
        self.events = events
        self.checksum_timeouts = []

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'md5sum' in cmd:
            n = int(re.search(r'-lt (\d+) \]', cmd).group(1))
            path = re.search(r'dd if=(\S+)', cmd).group(1)
            self.events.append(('checksums', path))
            self.checksum_timeouts.append((path, timeout))
            return 0, ''.join(f'{path}#{b}\n' for b in range(n)), ''
        if 'command -v sshfs' in cmd:
            return 0, 'PRESENT\n', ''
        if cmd.startswith('qm set'):
            self.events.append(('qm', cmd.split(' 2>')[0]))
        elif cmd.startswith('pvesm free'):
            self.events.append(('free', cmd.split(' 2>')[0]))
        elif 'df --output' in cmd:
            return 0, '99999999\n', ''
        return 0, '', ''


def _esxi_shell(host, user, pw, cmd, timeout=30):
    """_ssh_exec for the planning steps: the boot disk folder holds app01.vmdk."""
    if cmd == 'hostname':
        return 0, 'esx1\n', ''
    if cmd.startswith('ls -la'):
        return 0, '-rw------- 1 root root 512 app01.vmdk\n', ''
    if cmd.startswith('ls -1'):
        return 0, '/vmfs/volumes/ds1/app01/app01.vmdk\n', ''
    return 0, '', ''


class EsxiSsh:
    """_ssh_esxi_exec: datastore space, descriptor contents and file sizes. `delta` is the
    size of each disk's clone snapshot delta file, None when it cannot be found."""

    def __init__(self, descriptors, delta=256 * 1024 ** 2):
        self.descriptors = descriptors
        self.delta = delta
        self.cmds = []

    def __call__(self, host, user, pw, cmd, timeout=30):
        self.cmds.append(cmd)
        if cmd.startswith('df -k'):
            return 0, 'vmfs 900000000 1 800000000 1% /vmfs/volumes/ds\n', ''
        if cmd.startswith('cat '):
            text = self.descriptors.get(shlex.split(cmd)[1])
            return (0, text, '') if text else (1, '', 'No such file or directory')
        if cmd.startswith('stat ') and '-*.vmdk' in cmd:
            return (0, f'{self.delta}\n4096\n', '') if self.delta is not None else (1, '', '')
        if cmd.startswith('stat '):
            return 0, f'{64 * GiB}\n', ''
        return 0, '', ''


class Clock:
    """time.sleep and time.monotonic: sleeping moves the clock, and `on_sleep` plays the
    operator at the confirmation gate."""

    def __init__(self):
        self.now = 1000.0
        self.on_sleep = None

    def sleep(self, s):
        self.now += s
        if self.on_sleep:
            self.on_sleep()

    def monotonic(self):
        return self.now


def _descriptors(disks):
    out = {}
    for d in disks:
        ds, rest = re.match(r'^\[([^\]]+)\]\s+(.+)$', d['file']).groups()
        stem = rest.rsplit('/', 1)[-1][:-len('.vmdk')]
        out[f'/vmfs/volumes/{ds}/{rest}'] = BASE_DESC.format(
            sectors=d['capacity'] // 512, flat=f'{stem}-flat.vmdk')
    return out


class Run:
    def __init__(self, monkeypatch, disks=TWO_DISKS, descriptors=None, replay_ok=None,
                 confirm=True, cancel=False, mode='vmkfstools_clone', start='ok', start_after=True,
                 remove_source=False, delta=256 * 1024 ** 2, **esxi_kw):
        self.events = []
        self.clock = Clock()
        self.esxi = FakeEsxi(self.events, disks, clock=self.clock, **esxi_kw)
        self.pve = FakePve(self.events, start=start)
        self.node = FakeNode(self.events)
        self.ssh = EsxiSsh(descriptors if descriptors is not None else _descriptors(disks), delta=delta)
        self.replay_ok = replay_ok or {}
        self.copied = set()
        config = {'esxi_password': 'pw', 'esxi_host': 'esx1.lab', 'transfer_mode': mode,
                  'wait_for_confirmation': confirm or cancel, 'start_after': start_after,
                  'remove_source': remove_source}
        self.task = v2p.V2PMigrationTask('m1124', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm',
                                         vm_name='app01', config=config)

        def at_gate():
            if self.task.phase == 'awaiting_confirmation':
                self.events.append(('hold', self.esxi.power))
                if cancel:
                    self.task._cutover_cancelled = True
                else:
                    self.task._cutover_confirmed = True
        self.clock.on_sleep = at_gate

        mp = monkeypatch
        mp.setattr(time, 'sleep', self.clock.sleep)
        mp.setattr(time, 'monotonic', self.clock.monotonic)
        mp.setattr(v2p, 'vmware_managers', {'vw1': self.esxi})
        mp.setattr(v2p, 'cluster_managers', {'pve-cl': self.pve})
        mp.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
        mp.setattr(v2p, 'log_audit', lambda *a, **k: None)
        mp.setattr(v2p, '_pve_node_exec', self.node)
        mp.setattr(v2p, '_ssh_exec', _esxi_shell)
        mp.setattr(v2p, '_ssh_esxi_exec', self.ssh)
        mp.setattr(v2p, '_esxi_vmkfstools_clone', self._clone)
        mp.setattr(v2p, '_esxi_rm_clone', self._rm_clone)
        mp.setattr(v2p, '_ssh_pipe_transfer', self._transfer)
        mp.setattr(v2p, '_delta_sync_blocks', self._replay)
        for name in ('_ensure_guest_sector_size_512', '_register_uefi_fallback_loader',
                     '_inject_virtio_drivers', '_maybe_convert_disks_to_qcow2'):
            mp.setattr(v2p, name, lambda *a, _n=name, **k: self.events.append(('postcopy', _n)))

    def _clone(self, host, user, pw, ds, vm_dir, desc, cb, task=None, timeout=86400):
        self.events.append(('clone', ds, vm_dir, desc, cb, self.esxi.power, self.esxi.consolidated()))
        base = f'/vmfs/volumes/{ds}/{vm_dir}'
        return f'{base}/{cb}.vmdk', f'{base}/{cb}-flat.vmdk'

    def _rm_clone(self, host, user, pw, ds, vm_dir, cb):
        self.events.append(('rm_clone', cb))

    def _transfer(self, pve_mgr, task, host, user, pw, ds, vm_dir, desc, i):
        # a second copy of the same disk lands in a new volume, disk-1 -> disk-11
        n = i + 10 if i in self.copied else i
        self.copied.add(i)
        self.events.append(('transfer', ds, vm_dir, desc, i, self.esxi.power))
        return f'local-lvm:vm-{VMID}-disk-{n}', f'/dev/pve/vm-{VMID}-disk-{n}'

    def _replay(self, pve_mgr, task, host, user, pw, flat, vol_path, size, i, pve_checksums=None):
        self.events.append(('replay', i, flat, vol_path, size, pve_checksums,
                            self.esxi.power, self.esxi.consolidated()))
        return self.replay_ok.get(i, True)

    def go(self):
        v2p._run_v2p_migration(self.task)
        return self

    def idx(self, pred):
        hits = [n for n, e in enumerate(self.events) if pred(e)]
        assert hits, f'not in {self.events}'
        return hits

    def kinds(self, kind):
        return [e for e in self.events if e[0] == kind]


# --------------------------------------------------------------------------- the switchover

def test_a_running_source_is_stopped_folded_back_and_replayed_before_the_target_starts(monkeypatch):
    r = Run(monkeypatch).go()
    assert r.task.status == 'completed', r.task.error

    hold = r.idx(lambda e: e[0] == 'hold')[0]
    stop = r.idx(lambda e: e == ('power', 'stop'))[0]
    removes = r.idx(lambda e: e[0] == 'remove_snapshot')
    replays = r.idx(lambda e: e[0] == 'replay')
    post = r.idx(lambda e: e[0] == 'postcopy')
    start = r.idx(lambda e: e == ('start_target',))

    # the hold sits where the source still runs, and nothing was stopped or suspended before it
    assert r.events[hold] == ('hold', 'POWERED_ON')
    assert ('power', 'suspend') not in r.events
    assert hold < stop < removes[0] < replays[0]
    assert r.events[removes[0]][2] == 'POWERED_OFF'
    # one replay per disk, after the snapshot is gone and both disks are back on their own files
    rep = r.kinds('replay')
    assert [e[1] for e in rep] == [0, 1]
    assert all(e[6] == 'POWERED_OFF' and e[7] for e in rep), rep
    # each disk is read from its own datastore and folder (#561)
    assert rep[0][2] == '/vmfs/volumes/ds1/app01/app01-flat.vmdk'
    assert rep[1][2] == '/vmfs/volumes/ds2/app01-data/app01_1-flat.vmdk'
    assert [e[3] for e in rep] == [f'/dev/pve/vm-{VMID}-disk-0', f'/dev/pve/vm-{VMID}-disk-1']
    # with the checksums of the untouched copies, taken before the hold
    for e in rep:
        assert e[5] == [f'{e[3]}#{b}' for b in range((e[4] + 256 * 1024 ** 2 - 1) // (256 * 1024 ** 2))]
    sums = r.idx(lambda e: e[0] == 'checksums')
    assert len(sums) == 2 and max(sums) < hold
    # the post-copy chain writes to the disks, so it runs after the replay, the start comes last
    assert max(replays) < min(post) and max(post) < start[0]
    assert {r.events[n][1] for n in post} == {'_ensure_guest_sector_size_512', '_register_uefi_fallback_loader',
                                              '_inject_virtio_drivers', '_maybe_convert_disks_to_qcow2'}
    assert len(start) == 1
    # the clones go, the source stays off, nothing is left to remove afterwards
    assert {e[1] for e in r.kinds('rm_clone')} == {f'_pegaprox_clone_{VMID}_0', f'_pegaprox_clone_{VMID}_1'}
    assert r.esxi.power == 'POWERED_OFF' and r.esxi.consolidated()
    assert r.task.total_downtime_seconds is not None
    assert any('carry over what changed' in line for line in r.task.log_lines)


def test_a_remove_that_times_out_is_waited_for_until_esxi_is_done(monkeypatch):
    """The SOAP remove gives up after 120s and says 'remove timed out' while ESXi keeps
    consolidating a large delta. Reading the flat before that would read a half-merged disk."""
    r = Run(monkeypatch, consolidation='later', polls=4).go()
    assert r.task.status == 'completed', r.task.error
    rep = r.kinds('replay')
    assert len(rep) == 2 and all(e[7] for e in rep), 'read before the consolidation finished'
    assert r.idx(lambda e: e[0] == 'remove_snapshot')[0] < r.idx(lambda e: e[0] == 'replay')[0]


def test_a_source_that_was_off_throughout_is_still_folded_back_and_compared(monkeypatch):
    """Off at the snapshot and off at the switchover does not mean nothing was written in
    between. The compare costs the ESXi read only, the source serves nothing anyway."""
    r = Run(monkeypatch, power='POWERED_OFF', confirm=True).go()
    assert r.task.status == 'completed', r.task.error
    assert r.kinds('power') == [], 'a source that was off is never powered on or off'
    # an off source serves nothing, so the confirmation hold does not open
    assert r.kinds('hold') == []
    assert any('already stopped' in line for line in r.task.log_lines)
    remove = r.idx(lambda e: e[0] == 'remove_snapshot')[0]
    rep = r.kinds('replay')
    assert [e[1] for e in rep] == [0, 1]
    assert remove < r.idx(lambda e: e[0] == 'replay')[0] < r.idx(lambda e: e == ('start_target',))[0]
    assert all(e[6] == 'POWERED_OFF' and e[7] for e in rep), rep
    # the target checksums were taken ahead, the replay only reads ESXi
    assert all(e[5] == [f'{e[3]}#{b}' for b in range(e[4] // (256 * 1024 ** 2))] for e in rep)
    assert r.esxi.consolidated()


def test_an_off_source_powered_on_and_off_during_the_copy_is_replayed(monkeypatch):
    """What it wrote while it ran sits in the clone snapshot's delta. Deciding from two power
    readings dropped it."""
    r = Run(monkeypatch, power='POWERED_OFF', confirm=False)
    real_clone = r._clone

    def clone_with_a_power_cycle(*a, **k):
        out = real_clone(*a, **k)
        r.esxi.power = 'POWERED_ON'     # someone booted it mid-copy ...
        r.esxi.power = 'POWERED_OFF'    # ... and shut it down again
        return out
    monkeypatch.setattr(v2p, '_esxi_vmkfstools_clone', clone_with_a_power_cycle)
    r.go()
    assert r.task.status == 'completed', r.task.error
    rep = r.kinds('replay')
    assert [e[1] for e in rep] == [0, 1]
    assert all(e[7] for e in rep), 'read before the snapshot was folded back'


def test_a_source_started_during_the_copy_is_replayed_anyway(monkeypatch):
    r = Run(monkeypatch, power='POWERED_OFF', confirm=False)
    real_clone = r._clone

    def clone_then_boot(*a, **k):
        out = real_clone(*a, **k)
        r.esxi.power = 'POWERED_ON'     # someone powered the source on mid-copy
        return out
    monkeypatch.setattr(v2p, '_esxi_vmkfstools_clone', clone_then_boot)
    r.go()
    assert r.task.status == 'completed', r.task.error
    rep = r.kinds('replay')
    assert len(rep) == 2 and all(e[5] for e in rep), 'the checksums taken ahead reach the replay'
    assert r.idx(lambda e: e == ('power', 'stop'))[0] < r.idx(lambda e: e[0] == 'replay')[0]


def test_a_source_booted_during_the_copy_gets_the_hold(monkeypatch):
    """The hold follows what the source does at the gate, not what it did at the snapshot."""
    r = Run(monkeypatch, power='POWERED_OFF', confirm=True)
    real_clone = r._clone

    def clone_then_boot(*a, **k):
        out = real_clone(*a, **k)
        r.esxi.power = 'POWERED_ON'
        return out
    monkeypatch.setattr(v2p, '_esxi_vmkfstools_clone', clone_then_boot)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert r.kinds('hold') == [('hold', 'POWERED_ON')]
    assert r.idx(lambda e: e[0] == 'hold')[0] < r.idx(lambda e: e == ('power', 'stop'))[0]


# --------------------------------------------------------------------------- rollback

def test_a_snapshot_that_never_consolidates_brings_the_source_back(monkeypatch):
    r = Run(monkeypatch, consolidation='never')
    r.go()
    assert r.task.status == 'failed'
    assert 'not consolidated' in r.task.error and 'powered back on' in r.task.error
    assert ('start_target',) not in r.events
    assert r.kinds('replay') == [] and r.kinds('postcopy') == []
    stop = r.idx(lambda e: e == ('power', 'stop'))[0]
    back = r.idx(lambda e: e == ('power', 'start'))[0]
    assert stop < back and r.esxi.power == 'POWERED_ON'
    # it waited the scaled deadline (10 min floor), not just the 120s the remove call waits,
    # and not forever either. The rest of the run sleeps well under a minute.
    assert 600 <= r.clock.now - 1000.0 < 700


def test_disks_still_on_their_delta_count_as_not_consolidated(monkeypatch):
    """The snapshot left the list but a disk still runs on the delta ('consolidation needed').
    Its base flat does not hold the last writes, so nothing may be read from it."""
    r = Run(monkeypatch, consolidation='snapshot_only').go()
    assert r.task.status == 'failed'
    assert ('start_target',) not in r.events and r.kinds('replay') == []
    assert r.esxi.power == 'POWERED_ON'


def test_a_source_that_does_not_power_off_is_not_read(monkeypatch):
    r = Run(monkeypatch, ignores_stop=True).go()
    assert r.task.status == 'failed' and 'did not power off' in r.task.error
    assert r.kinds('replay') == [] and ('start_target',) not in r.events
    switchover_removes = [e for e in r.kinds('remove_snapshot') if e[2] == 'POWERED_OFF']
    assert switchover_removes == []


def test_a_cancel_at_the_hold_leaves_the_source_untouched(monkeypatch):
    r = Run(monkeypatch, cancel=True).go()
    assert r.task.status == 'cancelled', r.task.error
    assert r.kinds('power') == [] and ('start_target',) not in r.events
    assert r.kinds('replay') == []
    # the clones and the clone snapshot go, the running source is left as it was
    assert {e[1] for e in r.kinds('rm_clone')} == {f'_pegaprox_clone_{VMID}_0', f'_pegaprox_clone_{VMID}_1'}
    assert r.esxi.consolidated() and r.esxi.power == 'POWERED_ON'


# --------------------------------------------------------------------------- a merge that takes long

def test_a_merge_that_outlasts_its_deadline_still_gets_the_source_back(monkeypatch):
    """The merge ran out of time but ESXi is still at it and takes no PowerOn until it is
    done. One start right after gave up and left the source off for good."""
    r = Run(monkeypatch, consolidation='slow', merge_secs=2400).go()
    assert r.task.status == 'failed'
    assert 'not consolidated within 600s' in r.task.error, r.task.error
    assert 'powered back on' in r.task.error
    assert r.esxi.power == 'POWERED_ON'
    assert ('start_target',) not in r.events and r.kinds('replay') == []
    assert len([e for e in r.kinds('power') if e[1] == 'start']) > 1, 'asked ESXi only once'
    # it got the source back once the merge was over, not before
    assert r.clock.now - 1000.0 >= 2400


def test_the_merge_deadline_follows_the_measured_delta(monkeypatch):
    """40 GiB of changes on slow storage take longer than the 10 minutes the old formula
    gave a 3 GiB VM from its capacity."""
    r = Run(monkeypatch, consolidation='slow', merge_secs=3000, delta=20 * GiB).go()
    assert r.task.status == 'completed', r.task.error
    assert len(r.kinds('replay')) == 2
    assert any('40.0 GiB of changes' in line for line in r.task.log_lines), r.task.log_lines
    # measured on the files the disks ran on, the clone snapshot's deltas
    assert [c for c in r.ssh.cmds if '-*.vmdk' in c] == [
        "stat -c '%s' /vmfs/volumes/ds1/app01/app01-000001-*.vmdk 2>/dev/null",
        "stat -c '%s' /vmfs/volumes/ds2/app01-data/app01_1-000001-*.vmdk 2>/dev/null"]


def test_an_unmeasured_delta_falls_back_to_the_disk_size(monkeypatch):
    r = Run(monkeypatch, delta=None).go()
    assert r.task.status == 'completed', r.task.error
    assert any('could not be measured' in line for line in r.task.log_lines)


def test_a_merge_that_never_ends_gives_up_in_bounded_time(monkeypatch):
    r = Run(monkeypatch, consolidation='stuck').go()
    assert r.task.status == 'failed'
    assert 'did not come back up' in r.task.error, r.task.error
    assert r.esxi.power == 'POWERED_OFF' and ('start_target',) not in r.events
    # the 600s merge deadline, then up to an hour of asking ESXi, not forever
    assert 3600 < r.clock.now - 1000.0 < 600 + 3600 + 300


def test_an_idle_esxi_that_keeps_refusing_is_given_up_on_soon(monkeypatch):
    """No merge running and the snapshot is gone: three refusals are an answer."""
    r = Run(monkeypatch, replay_ok={0: False})
    real_transfer, real_power = r._transfer, r.esxi.vm_power_action

    def no_second_copy(pve_mgr, task, host, user, pw, ds, vm_dir, desc, i):
        if r.esxi.power == 'POWERED_OFF':
            return None, None
        return real_transfer(pve_mgr, task, host, user, pw, ds, vm_dir, desc, i)

    def no_memory(vm_id, action):
        if action == 'start':
            r.events.append(('power', action))
            return {'error': 'Insufficient memory resources on the host'}
        return real_power(vm_id, action)
    monkeypatch.setattr(v2p, '_ssh_pipe_transfer', no_second_copy)
    r.esxi.vm_power_action = no_memory
    t0 = r.clock.now
    r.go()
    assert r.task.status == 'failed' and 'did not come back up' in r.task.error
    assert len([e for e in r.kinds('power') if e[1] == 'start']) == 3
    assert r.clock.now - t0 < 600


# --------------------------------------------------------------------------- starting the target

def test_a_target_proxmox_refuses_to_start_brings_the_source_back(monkeypatch):
    """_api_post hands back the 500 instead of raising. It used to count as started: the run
    said completed with both VMs off, and remove_source deleted the source."""
    r = Run(monkeypatch, start='http500', remove_source=True).go()
    assert r.task.status == 'failed'
    assert 'did not start' in r.task.error and 'HTTP 500' in r.task.error, r.task.error
    assert 'powered back on' in r.task.error
    assert r.esxi.power == 'POWERED_ON'
    assert ('delete_vm',) not in r.events
    assert r.idx(lambda e: e == ('start_target',))[0] < r.idx(lambda e: e == ('power', 'start'))[0]


def test_a_start_task_that_fails_brings_the_source_back(monkeypatch):
    r = Run(monkeypatch, start='task_error', remove_source=True).go()
    assert r.task.status == 'failed'
    assert 'QEMU exited with code 1' in r.task.error and 'powered back on' in r.task.error
    assert r.esxi.power == 'POWERED_ON' and ('delete_vm',) not in r.events


def test_a_target_that_stops_right_after_its_start_brings_the_source_back(monkeypatch):
    r = Run(monkeypatch, start='dies', remove_source=True).go()
    assert r.task.status == 'failed'
    assert 'not running' in r.task.error and 'powered back on' in r.task.error
    assert r.esxi.power == 'POWERED_ON' and ('delete_vm',) not in r.events


def test_a_start_without_an_answer_leaves_both_alone(monkeypatch):
    """The start may still go through. Powering the source on could leave the VM running
    twice, once on each side, so both stay as they are and the run says so."""
    r = Run(monkeypatch, start='no_answer', remove_source=True).go()
    assert r.task.status == 'failed'
    assert 'may be running' in r.task.error, r.task.error
    assert r.esxi.power == 'POWERED_OFF'
    assert ('power', 'start') not in r.events and ('delete_vm',) not in r.events


def test_the_source_is_deleted_only_once_the_target_runs(monkeypatch):
    r = Run(monkeypatch, remove_source=True).go()
    assert r.task.status == 'completed', r.task.error
    assert r.pve.running
    assert r.idx(lambda e: e == ('start_target',))[0] < r.idx(lambda e: e == ('delete_vm',))[0]
    assert any('Target VM is running' in line for line in r.task.log_lines)


def test_remove_source_keeps_the_source_when_the_target_is_not_started(monkeypatch):
    r = Run(monkeypatch, start_after=False, remove_source=True).go()
    assert r.task.status == 'completed', r.task.error
    assert ('start_target',) not in r.events and ('delete_vm',) not in r.events
    assert any('stays on ESXi' in line for line in r.task.log_lines)


# --------------------------------------------------------------------------- replay sources

def test_a_failed_replay_copies_that_disk_again(monkeypatch):
    r = Run(monkeypatch, replay_ok={1: False}).go()
    assert r.task.status == 'completed', r.task.error
    rep1 = r.idx(lambda e: e[0] == 'replay' and e[1] == 1)[0]
    again = [n for n, e in enumerate(r.events) if e[0] == 'transfer' and n > rep1]
    assert len(again) == 1
    # from that disk's own datastore, with the source off, into a fresh volume
    assert r.events[again[0]] == ('transfer', 'ds2', 'app01-data', 'app01_1.vmdk', 1, 'POWERED_OFF')
    assert ('qm', f'qm set {VMID} --delete scsi1') in r.events[rep1:again[0]]
    assert ('free', f'pvesm free local-lvm:vm-{VMID}-disk-1') in r.events[rep1:again[0]]
    attach = r.idx(lambda e: e[0] == 'qm' and e[1].startswith(f'qm set {VMID} --scsi1 local-lvm:vm-{VMID}-disk-11'))
    assert attach[0] > again[0]
    # disk 0 was replayed fine and is not copied again
    assert [e for e in r.kinds('transfer') if e[4] == 0 and e[5] == 'POWERED_OFF'] == []
    assert attach[0] < r.idx(lambda e: e == ('start_target',))[0]


def test_a_failed_full_copy_rolls_back(monkeypatch):
    r = Run(monkeypatch, replay_ok={0: False})
    real = r._transfer

    def no_second_copy(pve_mgr, task, host, user, pw, ds, vm_dir, desc, i):
        if r.esxi.power == 'POWERED_OFF':
            r.events.append(('transfer', ds, vm_dir, desc, i, r.esxi.power))
            return None, None
        return real(pve_mgr, task, host, user, pw, ds, vm_dir, desc, i)
    monkeypatch.setattr(v2p, '_ssh_pipe_transfer', no_second_copy)
    r.go()
    assert r.task.status == 'failed' and 'both failed' in r.task.error
    assert ('start_target',) not in r.events and r.kinds('postcopy') == []
    assert r.esxi.power == 'POWERED_ON'


def test_a_disk_on_the_vms_own_snapshot_chain_is_read_through_a_fresh_clone(monkeypatch):
    """The VM had a snapshot of its own, so the disk runs on app01-000001.vmdk, a delta whose
    flat holds only the changed grains. The replay reads a clone of the chain head instead."""
    disks = [{'key': '2000', 'file': '[ds1] app01/app01-000001.vmdk', 'capacity': 2 * GiB}]
    desc = {'/vmfs/volumes/ds1/app01/app01-000001.vmdk': CHAIN_DESC.format(sectors=2 * GiB // 512)}
    r = Run(monkeypatch, disks=disks, descriptors=desc).go()
    assert r.task.status == 'completed', r.task.error
    cb = f'_pegaprox_replay_{VMID}_0'
    fresh = r.idx(lambda e: e[0] == 'clone' and e[4] == cb)
    assert len(fresh) == 1
    # cloned with the source off and the snapshot folded back
    assert r.events[fresh[0]][1:4] == ('ds1', 'app01', 'app01-000001.vmdk')
    assert r.events[fresh[0]][5:] == ('POWERED_OFF', True)
    (rep,) = r.kinds('replay')
    assert rep[2] == f'/vmfs/volumes/ds1/app01/{cb}-flat.vmdk'
    assert r.idx(lambda e: e == ('rm_clone', cb))[0] > fresh[0]


def test_a_descriptor_that_cannot_be_read_is_not_guessed(monkeypatch):
    """No descriptor means no way to tell a base disk from a delta: clone it instead of
    reading a -flat.vmdk that may not hold the whole disk."""
    r = Run(monkeypatch, descriptors={}).go()
    assert r.task.status == 'completed', r.task.error
    rep = r.kinds('replay')
    assert [e[2] for e in rep] == [f'/vmfs/volumes/ds1/app01/_pegaprox_replay_{VMID}_0-flat.vmdk',
                                   f'/vmfs/volumes/ds2/app01-data/_pegaprox_replay_{VMID}_1-flat.vmdk']


def test_a_listing_that_fails_reads_as_not_consolidated():
    class Broken:
        def get_snapshots(self, vm_id):
            return {'error': 'session expired'}

        def get_vm_disks_for_export(self, vm_id):
            raise AssertionError('no disk check without a snapshot listing')
    assert not v2p._clone_snap_consolidated(Broken(), 'vm-42', {'2000': '[ds1] app01/app01.vmdk'})


# --------------------------------------------------------------------------- timeouts

def test_the_replay_checksums_scale_with_the_disk(monkeypatch):
    """600s was enough for ~100 GB. A 500 GiB disk always timed out and fell back to a full
    download during the downtime."""
    seen = {}
    big = 500 * GiB
    blocks = big // (256 * 1024 ** 2)

    def esxi(host, user, pw, cmd, timeout=30):
        seen['esxi'] = timeout
        return 0, 'same\n' * blocks, ''

    def node(mgr, node_name, cmd, timeout=600, **kw):
        seen['node'] = timeout
        return 0, 'same\n' * blocks, ''
    monkeypatch.setattr(v2p, '_ssh_exec', esxi)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
    t = object.__new__(v2p.V2PMigrationTask)
    t.id, t.log_lines, t.esxi_password, t.phase, t.progress = 'm1124', [], 'pw', 'delta_sync', 0
    t.target_node, t.target_storage, t.proxmox_vmid, t.config = 'pve1', 'local-lvm', VMID, {}

    assert v2p._delta_sync_blocks(None, t, 'esx1', 'root', 'pw', '/vmfs/volumes/ds1/a/a-flat.vmdk',
                                  '/dev/pve/vm-120-disk-0', big, 0)
    floor = big // (50 * 1024 ** 2)
    assert seen['esxi'] >= floor and seen['node'] >= floor, seen

    # small disks keep the old 600s
    assert v2p._checksum_timeout(1 * GiB) == 600


def test_the_pre_sync_flow_checksums_scale_with_the_disk(monkeypatch):
    """The legacy pre-sync + delta flow (here reached as the auto fallback) took its
    checksums ahead of the downtime with the same fixed 600s."""
    disks = [{'key': '2000', 'file': '[ds1] app01/app01.vmdk', 'capacity': 200 * GiB}]
    r = Run(monkeypatch, disks=disks, mode='auto', confirm=False, clone_snap_fails=True).go()
    assert r.task.status == 'completed', r.task.error
    (path, timeout), = r.node.checksum_timeouts
    assert path == f'/dev/pve/vm-{VMID}-disk-0'
    assert timeout >= 200 * GiB // (50 * 1024 ** 2)
    # and the pre-computed list still reaches the replay
    (rep,) = r.kinds('replay')
    assert rep[5] == [f'{path}#{b}' for b in range(800)]


# --------------------------------------------------------------------------- the block copy itself
#
# The tests above stub _delta_sync_blocks. These run the real one: the checksum loops and the
# transfer script go through bash on this machine, ssh and sshpass are stand-ins that run the
# "remote" dd here, so the bytes travel through a real pipe like they do on the node.

MiB = 1024 ** 2

SSHPASS_STANDIN = '#!/bin/sh\n[ "$1" = "-f" ] && shift 2\nexec "$@"\n'
# drop the -o options and the login, run the remote command here
SSH_STANDIN = '#!/bin/sh\nwhile [ "$1" = "-o" ]; do shift 2; done\nshift\nexec sh -c "$*"\n'


class BlockCopy:
    def __init__(self, monkeypatch, tmp_path, ssh=SSH_STANDIN, flat_size=4 * MiB + 512 * 1024,
                 vol_size=5 * MiB):
        import random
        self.tmp = tmp_path
        rnd = random.Random(1124)
        self.flat = tmp_path / 'app01-flat.vmdk'
        self.vol = tmp_path / 'vm-120-disk-0'
        self.flat_size = flat_size
        old = rnd.randbytes(flat_size)
        # the copy made from the snapshot; the volume is a little larger than the disk, like
        # an LVM volume rounded up to its extent size
        self.vol.write_bytes(old + b'\0' * (vol_size - flat_size))
        new = bytearray(old)
        # written after the snapshot: well past the first 64 KiB of block 2, and the tail of
        # the last, partial block
        new[2 * MiB + 300 * 1024: 2 * MiB + 400 * 1024] = rnd.randbytes(100 * 1024)
        new[flat_size - 1000:] = rnd.randbytes(1000)
        self.new = bytes(new)
        self.flat.write_bytes(self.new)

        bin_dir = tmp_path / 'bin'
        bin_dir.mkdir()
        for name, body in (('sshpass', SSHPASS_STANDIN), ('ssh', ssh)):
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        import os
        self.env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
        self.node_cmds = []

        monkeypatch.setattr(v2p, 'DELTA_BLOCK_SIZE', MiB)
        monkeypatch.setattr(v2p, '_ssh_exec', self._esxi)
        monkeypatch.setattr(v2p, '_pve_node_exec', self._node)
        monkeypatch.setattr(v2p, '_node_hkc', lambda: 'accept-new')
        monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
        t = object.__new__(v2p.V2PMigrationTask)
        t.id, t.log_lines, t.esxi_password, t.phase, t.progress = 'm1124', [], 'pw', 'delta_sync', 0
        t.target_node, t.target_storage, t.proxmox_vmid, t.config = 'pve1', 'local-lvm', VMID, {}
        self.task = t

    def _sh(self, shell, cmd, stdin=''):
        import subprocess
        p = subprocess.run([shell, '-c', cmd], capture_output=True, text=True, env=self.env, timeout=60,
                           input=stdin)
        return p.returncode, p.stdout, p.stderr

    def _esxi(self, host, user, pw, cmd, timeout=30):
        return self._sh('sh', cmd)

    def _node(self, mgr, node, cmd, timeout=600, **kw):
        # the password file goes to /run on the node, here it stays in the test folder; what
        # the call hands on stdin (the password) reaches the command, as on the node
        cmd = cmd.replace('/run/pegaprox-', f'{self.tmp}/run-pegaprox-')
        self.node_cmds.append(cmd)
        return self._sh('bash', cmd, kw.get('stdin_data') or '')

    def go(self):
        return v2p._delta_sync_blocks(None, self.task, 'esx1.lab', 'root', 'pw', str(self.flat),
                                      str(self.vol), self.flat_size, 0)


def test_the_changed_blocks_really_arrive(monkeypatch, tmp_path):
    """A pipe hands dd at most 64 KiB per read. Without iflag=fullblock, count=1 took that
    first read as the whole block, wrote it and exited 0: the rest of every changed block
    never arrived and the run said it did."""
    bc = BlockCopy(monkeypatch, tmp_path)
    assert bc.go(), bc.task.log_lines
    got = bc.vol.read_bytes()
    assert got[:bc.flat_size] == bc.new, 'the target does not hold what the source holds'
    # nothing past the end of the disk was touched
    assert got[bc.flat_size:] == b'\0' * (len(got) - bc.flat_size)
    assert not list(tmp_path.glob('run-pegaprox-*')), 'the password file was left behind'


def test_a_transfer_whose_ssh_fails_is_not_reported_as_done(monkeypatch, tmp_path):
    """The receiving dd gets an empty pipe, writes nothing and exits 0. Without pipefail
    that read as 'DELTA_DONE errors=0'."""
    bc = BlockCopy(monkeypatch, tmp_path, ssh='#!/bin/sh\necho "Permission denied" >&2\nexit 255\n')
    before = bc.vol.read_bytes()
    assert not bc.go()
    assert bc.vol.read_bytes() == before
    # the transfer itself counts every failed block, the read-back is not what caught it
    result = [line for line in bc.task.log_lines if 'Delta result' in line]
    assert result and 'DELTA_DONE errors=2' in result[0], bc.task.log_lines
    assert not any('Read-back' in line for line in bc.task.log_lines)


def test_a_short_block_that_exits_0_fails_the_read_back(monkeypatch, tmp_path):
    """Every command in the pipe exits 0, but a block arrives short. Only reading the target
    back and comparing it with the ESXi checksums notices, and the caller then copies the
    whole disk again."""
    short = '#!/bin/sh\nwhile [ "$1" = "-o" ]; do shift 2; done\nshift\nsh -c "$*" | head -c 1000\n'
    bc = BlockCopy(monkeypatch, tmp_path, ssh=short)
    assert not bc.go()
    assert any('do not match' in line for line in bc.task.log_lines), bc.task.log_lines
