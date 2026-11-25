# Snapshot-Iterative (transfer_mode 'snapshot_zero') said completed with missing or wrong data.
# It read the delta files of the running chain, which ESXi does not open while the VM runs,
# looked for -delta.vmdk only (VMFS6 writes -sesparse.vmdk) and wrote the bytes of the sparse
# delta file at guest offsets. It now runs on the live clone: the first copy is the clone of
# the frozen disks, ESXi's change tracking names what was written since, catch-up rounds copy
# that while the source runs (each from a fresh clone of the round's snapshot), and the
# switchover copies the rest from the folded-back disk.
#
# The runs use the ESXi host and Proxmox node of tests/test_v2p_clone_delta_1124.py with
# change tracking added. The area copy itself runs in a real shell here.

import os
import random
import shlex
import subprocess
import types

import pytest

import pegaprox.core.v2p as v2p
from test_v2p_clone_delta_1124 import (FakeEsxi, Run as CloneRun, TWO_DISKS, VMID, GiB,
                                       SSHPASS_STANDIN, SSH_STANDIN)
from test_sec_migrations_paths import V2P, _v2p_body, v2p_route  # noqa: F401

MiB = 1024 ** 2
KiB = 1024


# --------------------------------------------------------------------------- the runs

def test_areas_are_widened_joined_cut_and_clipped():
    size = 100 * MiB + 512
    runs = v2p._change_runs([(70 * MiB, 10), (4096, 512), (0, 4096), (200 * KiB, 1), (5 * MiB, 0),
                             (100 * MiB, 512), (60 * MiB, 40 * MiB)], size)
    # 0-64K and 4096+512 widen to the first 64 KiB, 200K is within 256 KiB of it: one run
    assert runs[0] == (0, 256 * KiB)
    # 60 MiB..100 MiB+512 is one span, cut at 32 MiB, the last run ends on the disk's end
    assert runs[1:] == [(60 * MiB, 32 * MiB), (92 * MiB, 8 * MiB + 512)]
    assert all(s % (64 * KiB) == 0 for s, _ in runs)
    assert sum(ln for _, ln in runs) <= size


def test_far_apart_areas_stay_apart():
    runs = v2p._change_runs([(0, 4096), (10 * MiB, 4096)], 20 * MiB)
    assert runs == [(0, 64 * KiB), (10 * MiB, 64 * KiB)]


def test_nothing_written_is_nothing_to_copy():
    assert v2p._change_runs([], GiB) == []
    assert v2p._change_runs(None, GiB) == []
    assert v2p._change_runs([(GiB, 4096)], GiB) == []   # past the end of the disk


@pytest.mark.parametrize('start,length,want', [
    (0, 64 * KiB, (64 * KiB, 0, 1)),
    (128 * KiB, 32 * MiB, (64 * KiB, 2, 512)),
    (64 * KiB, 1536, (512, 128, 3)),
    (64 * KiB, 1000, (1, 64 * KiB, 1000)),
])
def test_a_run_becomes_one_dd_call(start, length, want):
    assert v2p._dd_run(start, length) == want
    bs, skip, count = want
    assert (bs * skip, bs * count) == (start, length)


# --------------------------------------------------------------------------- the copy, in a shell

class AreaCopy:
    """_copy_changed_areas against two files of this machine, ssh and sshpass replaced by
    stand-ins that run the 'remote' command here, so the bytes go through a real pipe."""

    def __init__(self, monkeypatch, tmp_path, size=6 * MiB + 1024, ssh=SSH_STANDIN):
        rnd = random.Random(1387)
        self.tmp = tmp_path
        self.size = size
        self.src = tmp_path / 'app01-clone-flat.vmdk'
        self.vol = tmp_path / 'vm-120-disk-0'
        old = rnd.randbytes(size)
        self.vol.write_bytes(old + b'\0' * MiB)   # an LV rounded up past the disk
        new = bytearray(old)
        for start, ln in ((100 * KiB, 4 * KiB), (3 * MiB, 700 * KiB), (size - 1024, 1024)):
            new[start:start + ln] = rnd.randbytes(ln)
        self.new = bytes(new)
        self.src.write_bytes(self.new)
        self.written = [(100 * KiB, 4 * KiB), (3 * MiB, 700 * KiB), (size - 1024, 1024)]

        bin_dir = tmp_path / 'bin'
        bin_dir.mkdir()
        for name, body in (('sshpass', SSHPASS_STANDIN), ('ssh', ssh)):
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
        self.cmds = []
        monkeypatch.setattr(v2p, '_pve_node_exec', self._node)
        monkeypatch.setattr(v2p, '_node_hkc', lambda: 'accept-new')
        self.task = types.SimpleNamespace(id='m1387', target_node='pve1', log=lambda m: None,
                                          _node_secrets=[])

    def _node(self, mgr, node, cmd, timeout=600, **kw):
        # mktemp in /tmp and the secret in /run stay in the test folder here
        cmd = cmd.replace('/run/pegaprox-', f'{self.tmp}/run-pegaprox-')
        cmd = cmd.replace('mktemp /tmp/v2p-', f'mktemp {self.tmp}/v2p-')
        self.cmds.append(cmd)
        p = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, env=self.env,
                           timeout=60, input=kw.get('stdin_data') or '')
        out = p.stdout.replace(f'{self.tmp}/v2p-', '/tmp/v2p-')
        return p.returncode, out, p.stderr

    def go(self, runs=None):
        runs = v2p._change_runs(self.written, self.size) if runs is None else runs
        # the node scripts were made under /tmp: point the run at the test folder again
        real_exec = v2p._pve_node_exec

        def node(mgr, n, cmd, timeout=600, **kw):
            return real_exec(mgr, n, cmd.replace('/tmp/v2p-', f'{self.tmp}/v2p-'), timeout, **kw)
        v2p._pve_node_exec = node
        try:
            return v2p._copy_changed_areas(None, self.task, 'esx1.lab', 'root', 'pw', str(self.src),
                                           str(self.vol), runs, 0)
        finally:
            v2p._pve_node_exec = real_exec


def test_the_written_areas_really_arrive_and_nothing_else_changes(monkeypatch, tmp_path):
    ac = AreaCopy(monkeypatch, tmp_path)
    ok, why = ac.go()
    assert ok, why
    got = ac.vol.read_bytes()
    assert got[:ac.size] == ac.new
    assert got[ac.size:] == b'\0' * MiB, 'written past the end of the disk'
    # the run list, the script and the password file are all gone
    assert not list(tmp_path.glob('v2p-*')), list(tmp_path.glob('v2p-*'))
    assert not list(tmp_path.glob('run-pegaprox-*'))


def test_the_password_reaches_sshpass_through_a_file_only(monkeypatch, tmp_path):
    ac = AreaCopy(monkeypatch, tmp_path)
    ac.task.esxi_password = 'Secr3t-pw'
    ok, _why = v2p._copy_changed_areas(None, ac.task, 'esx1.lab', 'root', 'Secr3t-pw', str(ac.src),
                                       str(ac.vol), [(0, 64 * KiB)], 0)
    assert not any('Secr3t-pw' in c for c in ac.cmds)


def test_a_copy_whose_ssh_fails_is_not_reported_as_done(monkeypatch, tmp_path):
    ac = AreaCopy(monkeypatch, tmp_path, ssh='#!/bin/sh\necho "Permission denied" >&2\nexit 255\n')
    before = ac.vol.read_bytes()
    ok, why = ac.go()
    assert not ok and 'COPY_FAILED' in why, why
    assert ac.vol.read_bytes() == before


def test_a_short_stream_that_exits_0_is_caught_by_the_compare(monkeypatch, tmp_path):
    short = '#!/bin/sh\nwhile [ "$1" = "-o" ]; do shift 2; done\nshift\nsh -c "$*" | head -c 70000\n'
    ac = AreaCopy(monkeypatch, tmp_path, ssh=short)
    ok, why = ac.go()
    assert not ok and ('RUNS_DIFFER' in why or 'ESXI_SUMS_SHORT' in why), why


def test_a_source_that_changes_under_the_copy_is_caught(monkeypatch, tmp_path):
    """The ESXi sums are read after the copy: a source that differs from what arrived (a
    clone that was not frozen) fails instead of passing silently."""
    ac = AreaCopy(monkeypatch, tmp_path)
    flip = ('#!/bin/sh\nwhile [ "$1" = "-o" ]; do shift 2; done\nshift\n'
            f'case "$*" in *md5sum*) printf x | dd of={ac.src} bs=1 seek=3145728 conv=notrunc 2>/dev/null;; esac\n'
            'exec sh -c "$*"\n')
    (tmp_path / 'bin' / 'ssh').write_text(flip)
    ok, why = ac.go()
    assert not ok and 'RUNS_DIFFER' in why, why


def test_a_node_without_sshpass_copies_with_a_key_on_esxi(monkeypatch, tmp_path):
    """An air-gapped node has no sshpass and no repository to fetch it from; the copy logs in
    with a key put on ESXi for it, and takes the key away again."""
    ssh_any = ('#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o|-i) shift 2;; *@*) shift; break;; '
               '*) shift;; esac; done\nexec sh -c "$*"\n')
    ac = AreaCopy(monkeypatch, tmp_path, ssh=ssh_any)
    keys = []
    monkeypatch.setattr(v2p, '_setup_temp_ssh_key',
                        lambda mgr, node, host, user, pw: keys.append('made') or '/tmp/v2p-key-abc')
    monkeypatch.setattr(v2p, '_cleanup_temp_ssh_key',
                        lambda mgr, node, key, host, user: keys.append(('gone', key)))
    real = v2p._pve_node_exec

    def node(mgr, n, cmd, timeout=600, **kw):
        if 'command -v sshpass' in cmd:
            return 1, '', ''
        return real(mgr, n, cmd, timeout, **kw)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    ok, why = ac.go()
    assert ok, why
    assert ac.vol.read_bytes()[:ac.size] == ac.new
    # one key for the whole run, not one per disk and round: a second copy reuses it
    ok, why = ac.go()
    assert ok, why
    assert keys == ['made']
    # the end of the run takes it away
    v2p._drop_area_copy_key(None, ac.task, 'esx1.lab', 'root')
    assert keys == ['made', ('gone', '/tmp/v2p-key-abc')]
    script = [c for c in ac.cmds if 'V2P_NODE_SCRIPT' in c][0]
    # (the test folder stands in for /tmp in what was recorded)
    assert 'ssh -i ' in script and 'v2p-key-abc' in script and 'sshpass -f' not in script
    assert not list(tmp_path.glob('run-pegaprox-*')), 'a password file was written all the same'


def test_no_runs_copy_nothing(monkeypatch, tmp_path):
    ac = AreaCopy(monkeypatch, tmp_path)
    assert ac.go(runs=[]) == (True, '')
    assert ac.cmds == []


# --------------------------------------------------------------------------- whole runs

class CbtEsxi(FakeEsxi):
    """FakeEsxi with change tracking. `areas(key, change_id, snapshot_name)` answers a query:
    a list of (start, length) or {'error': ...}. A snapshot holds the files its disks ran
    on when it was taken."""

    def __init__(self, events, disks, tracking=False, supported=True, tools=False, areas=None,
                 disk_modes=None, **kw):
        super().__init__(events, disks, **kw)
        self.tracking = tracking
        self.supported = supported
        self.tools = tools
        self.areas = areas or (lambda key, cid, snap: [(0, 64 * KiB)])
        self.disk_modes = disk_modes or {}
        self.held = {}      # snapshot name -> {disk key: (file, change id)}
        self.seq = 0
        self.queries = []

    def create_snapshot(self, vm_id, name, description='', memory=False, quiesce=True):
        before = dict(self.files)
        res = super().create_snapshot(vm_id, name, description, memory, quiesce)
        if 'error' not in res:
            self.seq += 1
            self.held[name] = {k: (f, f'cid-{self.seq}' if self.tracking else '') for k, f in before.items()}
        return res

    def change_tracking_state(self, vm_id):
        return {'data': {'supported': self.supported, 'enabled': self.tracking,
                         'disks': {d['key']: {'file': d['file'], 'mode': self.disk_modes.get(d['key'], 'persistent'),
                                              'raw': self.disk_modes.get(d['key']) == 'raw'}
                                   for d in self.disks}}}

    def set_change_tracking(self, vm_id, enabled):
        self.events.append(('tracking', enabled))
        self.tracking = enabled
        return {'data': 'ok'}

    def snapshot_disk_state(self, vm_id, name):
        if name not in self.held:
            return {'error': f'snapshot {name} not found'}
        return {'data': {k: {'file': f, 'change_id': cid} for k, (f, cid) in self.held[name].items()}}

    def changed_disk_areas(self, vm_id, key, change_id, capacity, snapshot_name=None):
        self.queries.append((key, change_id, snapshot_name, self.power, self.consolidated()))
        got = self.areas(key, change_id, snapshot_name)
        return got if isinstance(got, dict) else {'data': got}

    def shutdown_guest(self, vm_id):
        self.events.append(('shutdown_guest',))
        if not self.tools:
            return {'error': 'the guest tools are not running'}
        self.power = 'POWERED_OFF'
        return {'data': 'ok'}


class Run(CloneRun):
    """A Snapshot-Iterative run. `copy_ok` answers the area copies per call (True by
    default), `xfer_secs` is how long each first copy of a disk takes on the clock."""

    def __init__(self, monkeypatch, copy_ok=None, xfer_secs=0, esxi_kw=None, **kw):
        kw.setdefault('mode', 'snapshot_zero')
        super().__init__(monkeypatch, **kw)
        self.esxi = CbtEsxi(self.events, kw.get('disks', TWO_DISKS), clock=self.clock,
                            power=kw.get('power', 'POWERED_ON'), **(esxi_kw or {}))
        monkeypatch.setattr(v2p, 'vmware_managers', {'vw1': self.esxi})
        self.copy_ok = copy_ok or (lambda n, src, vol, runs: (True, ''))
        self.xfer_secs = xfer_secs
        self.copies = []
        monkeypatch.setattr(v2p, '_copy_changed_areas', self._copy_areas)

    def _transfer(self, pve_mgr, task, host, user, pw, ds, vm_dir, desc, i):
        self.clock.now += self.xfer_secs
        return super()._transfer(pve_mgr, task, host, user, pw, ds, vm_dir, desc, i)

    def _copy_areas(self, pve_mgr, task, host, user, pw, src, vol, runs, i):
        self.copies.append((i, src, vol, list(runs), self.esxi.power, self.esxi.consolidated()))
        self.events.append(('copy_areas', i, src))
        return self.copy_ok(len(self.copies), src, vol, runs)


def test_a_run_copies_the_clone_then_only_what_was_written_and_switches_over(monkeypatch):
    r = Run(monkeypatch).go()
    assert r.task.status == 'completed', r.task.error
    # change tracking went on before the clone snapshot and is off again at the end
    on = r.idx(lambda e: e == ('tracking', True))[0]
    snap = r.idx(lambda e: e[:2] == ('snapshot', '_pegaprox_clone_snap'))[0]
    assert on < snap
    assert r.events[-1] == ('tracking', False) or ('tracking', False) in r.events
    assert r.esxi.tracking is False
    # the first copy is the live clone's, of the files the disks ran on
    clones = r.kinds('clone')
    assert [(c[1], c[2], c[3]) for c in clones[:2]] == [('ds1', 'app01', 'app01.vmdk'),
                                                         ('ds2', 'app01-data', 'app01_1.vmdk')]
    # the switchover: the source off and folded back, then each disk's written areas from
    # its own flat, asked for since the clone snapshot's change ids, no snapshot named
    sw = [c for c in r.copies if c[4] == 'POWERED_OFF']
    assert [c[0] for c in sw] == [0, 1] and all(c[5] for c in sw), sw
    assert sw[0][1] == '/vmfs/volumes/ds1/app01/app01-flat.vmdk'
    assert sw[1][1] == '/vmfs/volumes/ds2/app01-data/app01_1-flat.vmdk'
    off_queries = [q for q in r.esxi.queries if q[3] == 'POWERED_OFF']
    assert [(q[0], q[1], q[2]) for q in off_queries] == [('2000', 'cid-1', None), ('2001', 'cid-1', None)]
    # no block compare: change tracking answered
    assert r.kinds('replay') == []
    # the post-copy chain after the copies, the start last
    last_copy = r.idx(lambda e: e[0] == 'copy_areas')[-1]
    assert last_copy < min(r.idx(lambda e: e[0] == 'postcopy')) < r.idx(lambda e: e == ('start_target',))[0]
    assert r.esxi.consolidated()
    assert any('COMPLETED (snapshot_zero' in line for line in r.task.log_lines)


def test_tracking_that_was_on_already_stays_on(monkeypatch):
    r = Run(monkeypatch, esxi_kw={'tracking': True}).go()
    assert r.task.status == 'completed', r.task.error
    assert r.kinds('tracking') == []
    assert r.esxi.tracking is True


def test_a_small_carry_over_runs_no_round(monkeypatch):
    """64 KiB written since the copy: the switchover copies that in no time, a round of
    clones would only cost time and datastore space."""
    r = Run(monkeypatch, xfer_secs=600).go()
    assert r.task.status == 'completed', r.task.error
    # the round's snapshot was taken to measure and removed again, no clone for a round
    assert ('snapshot', v2p._CATCHUP_SNAP, 'POWERED_ON') in r.events
    assert not [c for c in r.kinds('clone') if c[4].startswith('_pegaprox_round_')]
    assert any('small enough for the switchover' in line for line in r.task.log_lines)
    assert r.esxi.consolidated()


def _written(per_query):
    """areas() answering each query in turn with the bytes listed, spread over the disk"""
    seen = []

    def areas(key, cid, snap):
        seen.append((key, cid, snap))
        n = min(len(seen) - 1, len(per_query) - 1)
        return [(s, 64 * KiB) for s in range(0, per_query[n], 64 * KiB)]
    return areas


def test_a_large_carry_over_gets_a_round_from_a_fresh_clone(monkeypatch):
    # 1 hour of copying, 640 MiB written since: about 13s at 50 MiB/s -> a round pays off only
    # above SI_SWITCH_SECONDS, so the first answer is larger: 4 GiB, ~82s
    big, small = 4 * GiB, 64 * KiB
    r = Run(monkeypatch, xfer_secs=1800,
            esxi_kw={'areas': _written([big, big, small, small, small, small])}).go()
    assert r.task.status == 'completed', r.task.error
    rounds = [c for c in r.kinds('clone') if c[4].startswith('_pegaprox_round_')]
    # one clone per disk, of the file the round's snapshot holds (the clone snapshot's delta)
    assert [(c[1], c[3]) for c in rounds] == [('ds1', 'app01-000001.vmdk'), ('ds2', 'app01_1-000001.vmdk')]
    assert {e[1] for e in r.kinds('rm_clone')} >= {f'_pegaprox_round_{VMID}_0', f'_pegaprox_round_{VMID}_1'}
    # the areas copied while the source ran came out of those clones
    live = [c for c in r.copies if c[4] == 'POWERED_ON']
    assert [c[1] for c in live] == [f'/vmfs/volumes/ds1/app01/_pegaprox_round_{VMID}_0-flat.vmdk',
                                     f'/vmfs/volumes/ds2/app01-data/_pegaprox_round_{VMID}_1-flat.vmdk']
    # the round's snapshot became the state the switchover copies on from
    off_queries = [q for q in r.esxi.queries if q[3] == 'POWERED_OFF']
    assert {q[1] for q in off_queries} == {'cid-2'}, off_queries
    # the clone snapshot went while the source ran, after the round's copy
    rm_clone_snap = [n for n, e in enumerate(r.events) if e[0] == 'remove_snapshot' and e[1] == 'snapshot-1']
    assert rm_clone_snap and r.events[rm_clone_snap[0]][2] == 'POWERED_ON'
    assert rm_clone_snap[0] > r.idx(lambda e: e[0] == 'copy_areas')[1]
    assert r.esxi.consolidated()


def test_a_round_never_fills_the_source_datastore(monkeypatch):
    """The clone of a round lands next to the deltas of the running VM; a full datastore
    would stop the VM. Too little room skips the round, the switchover copies the rest."""
    r = Run(monkeypatch, xfer_secs=1800, esxi_kw={'areas': _written([4 * GiB] * 6)})
    real = v2p._ssh_esxi_exec

    def esxi(host, user, pw, cmd, timeout=30):
        if cmd.startswith('df -k') and r.kinds('copy_areas') == [] and r.esxi.snaps and \
                any(s['name'] == v2p._CATCHUP_SNAP for s in r.esxi.snaps):
            return 0, 'vmfs 900000000 1 3000000 1% /vmfs/volumes/ds1\n', ''   # ~2.9 GiB free
        return real(host, user, pw, cmd, timeout)
    monkeypatch.setattr(v2p, '_ssh_esxi_exec', esxi)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert not [c for c in r.kinds('clone') if c[4].startswith('_pegaprox_round_')]
    assert any('a clone needs about' in line and 'no round' in line for line in r.task.log_lines)
    assert r.esxi.consolidated()


def test_a_guest_that_writes_faster_than_a_round_gets_no_round(monkeypatch):
    # a clone takes 30 min, the copy 10 min: 1 GiB written in those 70 min means about as
    # much again while a round of clones runs, the rounds stop at once
    r = Run(monkeypatch, xfer_secs=300, esxi_kw={'areas': _written([GiB])})
    real = r._clone

    def slow_clone(*a, **k):
        r.clock.now += 1800
        return real(*a, **k)
    monkeypatch.setattr(v2p, '_esxi_vmkfstools_clone', slow_clone)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert not [c for c in r.kinds('clone') if c[4].startswith('_pegaprox_round_')]
    assert any('no shorter switchover' in line for line in r.task.log_lines)


def test_a_round_that_fails_keeps_the_state_before_it(monkeypatch):
    """A round whose copy breaks off may have written part of the newer state; the
    switchover copies everything written since the old state, which covers it."""
    big = 4 * GiB
    fails = lambda n, src, vol, runs: (False, 'RUNS_DIFFER 3') if n == 1 else (True, '')
    r = Run(monkeypatch, xfer_secs=1800, copy_ok=fails, esxi_kw={'areas': _written([big] * 6)}).go()
    assert r.task.status == 'completed', r.task.error
    off_queries = [q for q in r.esxi.queries if q[3] == 'POWERED_OFF']
    assert {q[1] for q in off_queries} == {'cid-1'}, off_queries
    # the round's clone and snapshot are gone, the clone snapshot stayed until the switchover
    assert f'_pegaprox_round_{VMID}_0' in {e[1] for e in r.kinds('rm_clone')}
    assert r.esxi.consolidated()


def test_the_rounds_end_after_the_copies_allowed(monkeypatch):
    monkeypatch.setattr(v2p, 'SI_MAX_ROUNDS', 2)
    monkeypatch.setattr(v2p, 'SI_SHRINK', float('inf'))   # every round looks worth it
    r = Run(monkeypatch, xfer_secs=1800, esxi_kw={'areas': _written([4 * GiB] * 20)}).go()
    assert r.task.status == 'completed', r.task.error
    rounds = [c for c in r.kinds('clone') if c[4].startswith('_pegaprox_round_')]
    assert len(rounds) == 4   # two rounds of two disks
    assert any('The rounds end after 2 copies' in line for line in r.task.log_lines)
    # the snapshots took turns as the copied state; the last one is what the switchover reads on from
    off_queries = [q for q in r.esxi.queries if q[3] == 'POWERED_OFF']
    assert {q[1] for q in off_queries} == {'cid-3'}, off_queries
    assert r.esxi.consolidated()


def test_change_tracking_that_fails_at_the_switchover_compares_every_block(monkeypatch):
    def areas(key, cid, snap):
        return {'error': 'Error caused by file /vmfs/volumes/ds1/app01/app01-ctk.vmdk'} if snap is None \
            else [(0, 64 * KiB)]
    r = Run(monkeypatch, esxi_kw={'areas': areas}).go()
    assert r.task.status == 'completed', r.task.error
    rep = r.kinds('replay')
    assert [e[1] for e in rep] == [0, 1]
    # no checksums were taken ahead: the rounds write to the copies, both sides are read now
    assert all(e[5] is None for e in rep), rep
    assert any('change tracking did not answer at the switchover' in w for w in r.task.warnings)


def test_an_area_copy_that_fails_at_the_switchover_compares_every_block(monkeypatch):
    r = Run(monkeypatch, copy_ok=lambda n, src, vol, runs: (False, 'COPY_FAILED 255/0')).go()
    assert r.task.status == 'completed', r.task.error
    assert [e[1] for e in r.kinds('replay')] == [0, 1]
    assert any('COPY_FAILED' in w for w in r.task.warnings)


def _full_checks(monkeypatch, answers):
    """_full_check stand-in: records what it compared, answers from `answers` in turn"""
    seen = []

    def check(pve_mgr, task, host, user, pw, vols, what):
        seen.append((dict(vols), what, dict(getattr(task, '_copy_sources', {}) or {})))
        ok = answers[min(len(seen), len(answers)) - 1]
        return (True, '', {}) if ok else (False, 'Full check failed on disk 0: block 3 differs', {})
    monkeypatch.setattr(v2p, '_full_check', check)
    return seen


def test_full_verify_compares_the_first_copy_and_every_block_at_the_switchover(monkeypatch):
    seen = _full_checks(monkeypatch, [True])
    r = Run(monkeypatch)
    r.task.verify_mode = 'full'
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert [s[1] for s in seen] == ['the frozen base copies', 'disk 0 at the switchover',
                                    'disk 1 at the switchover']
    # at the switchover each disk is held against its folded-back flat, not the gone clone
    assert seen[1][2][0][0] == '/vmfs/volumes/ds1/app01/app01-flat.vmdk'
    assert seen[2][2][1][0] == '/vmfs/volumes/ds2/app01-data/app01_1-flat.vmdk'
    assert r.kinds('replay') == []


def test_a_full_check_that_fails_at_the_switchover_compares_and_copies_every_block(monkeypatch):
    seen = _full_checks(monkeypatch, [True, False, True])
    r = Run(monkeypatch)
    r.task.verify_mode = 'full'
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert [e[1] for e in r.kinds('replay')] == [0]
    assert any('the full check after copying the written areas failed' in w for w in r.task.warnings)


def test_a_guest_with_tools_shuts_down_instead_of_being_powered_off(monkeypatch):
    r = Run(monkeypatch, esxi_kw={'tools': True}).go()
    assert r.task.status == 'completed', r.task.error
    assert ('shutdown_guest',) in r.events
    assert ('power', 'stop') not in r.events


def test_a_guest_without_tools_is_powered_off(monkeypatch):
    r = Run(monkeypatch).go()
    assert r.task.status == 'completed', r.task.error
    assert r.idx(lambda e: e == ('shutdown_guest',))[0] < r.idx(lambda e: e == ('power', 'stop'))[0]


def test_a_failed_switchover_brings_the_source_back_and_switches_tracking_off(monkeypatch):
    r = Run(monkeypatch, start='http500').go()
    assert r.task.status == 'failed'
    assert 'powered back on' in r.task.error
    assert r.esxi.power == 'POWERED_ON'
    assert r.esxi.tracking is False and r.esxi.snaps == []


def test_a_merge_esxi_does_not_finish_ends_the_run_before_the_source_is_touched(monkeypatch):
    """ESXi takes no other task on the VM while it merges: going on to the switchover, the
    power off would be refused with the downtime already started."""
    r = Run(monkeypatch, xfer_secs=1800, esxi_kw={'areas': _written([4 * GiB] * 6)})
    real_delete = r.esxi.delete_snapshot

    def delete(vm_id, sid):
        if r.kinds('copy_areas'):          # the old state's snapshot after a copied round
            r.events.append(('remove_snapshot', sid, r.esxi.power))
            return {'error': 'remove timed out'}   # and it stays listed
        return real_delete(vm_id, sid)
    r.esxi.delete_snapshot = delete
    r.go()
    assert r.task.status == 'failed'
    assert 'did not finish removing snapshot' in r.task.error and 'the source runs on' in r.task.error
    assert ('power', 'stop') not in r.events and ('shutdown_guest',) not in r.events
    assert r.esxi.power == 'POWERED_ON'


def test_tracking_is_switched_back_once_esxi_is_done_with_the_snapshot(monkeypatch):
    r = Run(monkeypatch, start='http500')
    answers = iter([{'error': 'Another task is already in progress.'}, {'error': 'TaskInProgress'}])
    real = r.esxi.set_change_tracking

    def tracking(vm_id, enabled):
        if not enabled:
            nxt = next(answers, None)
            if nxt:
                r.events.append(('tracking_refused',))
                return nxt
        return real(vm_id, enabled)
    r.esxi.set_change_tracking = tracking
    r.go()
    assert r.task.status == 'failed'
    assert r.kinds('tracking_refused') == [('tracking_refused',), ('tracking_refused',)]
    assert r.esxi.tracking is False


def test_a_hanging_area_copy_is_ended_with_its_budget(monkeypatch, tmp_path):
    ac = AreaCopy(monkeypatch, tmp_path)
    ok, why = ac.go()
    assert ok, why
    run = [c for c in ac.cmds if 'bash ' in c and 'v2p-runs-' in c and 'V2P_NODE_SCRIPT' not in c]
    assert run and run[0].startswith('timeout -k 30 '), run


# --------------------------------------------------------------------------- refused up front

def _untouched(r):
    assert r.kinds('snapshot') == [] and r.kinds('clone') == [] and r.kinds('transfer') == []
    assert r.kinds('tracking') == []
    assert r.esxi.power == 'POWERED_ON'


@pytest.mark.parametrize('esxi_kw,needle', [
    ({'supported': False}, 'does not support it'),
    ({'disk_modes': {'2001': 'independent_persistent'}}, 'is independent'),
    ({'disk_modes': {'2000': 'raw'}}, 'maps a raw device'),
], ids=['unsupported', 'independent', 'raw'])
def test_a_vm_change_tracking_cannot_follow_is_refused_before_anything(monkeypatch, esxi_kw, needle):
    r = Run(monkeypatch, esxi_kw=esxi_kw).go()
    assert r.task.status == 'failed' and needle in r.task.error, r.task.error
    _untouched(r)


def test_a_raw_disk_the_map_leaves_behind_is_no_reason_to_refuse(monkeypatch):
    r = Run(monkeypatch, esxi_kw={'disk_modes': {'2001': 'raw'}})
    real = r.task.disk_target
    r.task.disk_target = lambda i: None if i == 1 else real(i)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert {c[0] for c in r.copies} == {0}


def test_a_vm_with_snapshots_of_its_own_is_refused_before_anything(monkeypatch):
    r = Run(monkeypatch)
    r.esxi.snaps.append({'snapshot': 'snapshot-90', 'name': 'before-update'})
    r.go()
    assert r.task.status == 'failed'
    assert 'before-update' in r.task.error and 'Live Clone' in r.task.error, r.task.error
    _untouched(r)


def test_tracking_that_does_not_start_stops_the_run_before_any_copy(monkeypatch):
    r = Run(monkeypatch)
    real = r.esxi.set_change_tracking
    # ESXi says yes but the snapshot holds no change ids
    r.esxi.set_change_tracking = lambda vm, on: (real(vm, on), setattr(r.esxi, 'tracking', False))[0]
    r.go()
    assert r.task.status == 'failed' and 'change tracking did not start' in r.task.error, r.task.error
    assert r.kinds('transfer') == []
    assert r.esxi.snaps == [], 'the clone snapshot was left on the source'
    assert r.esxi.power == 'POWERED_ON'


def test_the_plan_refuses_a_vm_on_its_own_snapshots():
    disks = [{'key': '2000', 'label': 'Hard disk 1', 'capacity_bytes': GiB,
              'vmdk_file': '[ds1] app01/app01-000001.vmdk', 'snapshot_delta': True}]
    inv = {'bridges': {'vmbr0': {}}, 'storages': {'local-lvm': {'type': 'lvmthin', 'avail': 10 * GiB,
                                                                 'content': 'images', 'active': True}}}
    p = v2p.resolve_migration_plan(inv, disks, [], v2p.parse_migration_options({}), 'local-lvm', 'vmbr0',
                                   transfer_mode='snapshot_zero')
    assert not p['ok'] and any('snapshots of its own' in e for e in p['errors']), p['errors']


# --------------------------------------------------------------------------- the Live Clone exits

def test_a_live_clone_whose_transfer_fails_leaves_no_snapshot_on_the_source(monkeypatch):
    """A failed copy returned early and left _pegaprox_clone_snap on the running source,
    where its delta grew until someone removed it by hand."""
    r = CloneRun(monkeypatch, mode='vmkfstools_clone')
    monkeypatch.setattr(v2p, '_ssh_pipe_transfer', lambda *a, **k: (None, None))
    r.go()
    assert r.task.status == 'failed' and 'Transfer/import of clone for disk 0 failed' in r.task.error
    assert r.esxi.snaps == []
    assert {e[1] for e in r.kinds('rm_clone')} >= {f'_pegaprox_clone_{VMID}_0'}


def test_a_disk_copy_on_a_node_without_sshpass_logs_in_with_a_key(monkeypatch):
    """The first copy of every mode: without sshpass on the node the SSH pipe failed with
    exit code 127, and nothing went back to the HTTPS download."""
    import test_v2p_tpm_and_folder_copy as farm
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False)
    keys = []
    monkeypatch.setattr(v2p, '_setup_temp_ssh_key',
                        lambda mgr, node, host, user, pw: keys.append('made') or '/tmp/v2p-key-t1')
    monkeypatch.setattr(v2p, '_cleanup_temp_ssh_key',
                        lambda mgr, node, key, host, user: keys.append(('gone', key)))
    real = r.node

    def node(mgr, n, cmd, timeout=600, **kw):
        if cmd.startswith('which sshpass') or cmd == 'command -v sshpass >/dev/null 2>&1':
            real.log.append(('node', n, cmd))
            return 1, '', ''
        if cmd.startswith('ssh -i ') and '| dd of=' in cmd:
            # the copy works like the sshpass one in the fake
            return real(mgr, n, 'sshpass -f /x ' + cmd, timeout, **kw)
        return real(mgr, n, cmd, timeout, **kw)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    r.go()
    assert r.task.status == 'completed', r.task.error
    pipes = [c for c in r.nodecmds() if '| dd of=' in c and c.startswith('sshpass')]
    assert pipes and all('ssh -i /tmp/v2p-key-t1 -o IdentitiesOnly=yes' in c for c in pipes), pipes
    assert keys == ['made', ('gone', '/tmp/v2p-key-t1')]
    assert not [c for c in r.nodecmds() if c.startswith('umask 077; rm -f /run/pegaprox-v2p-t1-ssh-')], \
        'a password file was written for a copy that logs in with a key'


# --------------------------------------------------------------------------- the ESXi calls

class _Area:
    def __init__(self, start, length):
        self.start, self.length = start, length


class _Answer:
    def __init__(self, start, length, areas):
        self.startOffset, self.length, self.changedArea = start, length, [_Area(*a) for a in areas]


def _soap_mgr(vm):
    from pegaprox.core.vmware import VMwareManager
    mgr = object.__new__(VMwareManager)
    mgr._connection_type = 'soap'
    mgr._soap_get_managed_object = lambda kind, moid: vm
    return mgr


def test_the_area_query_asks_on_until_the_disk_is_covered():
    asked = []

    def query(snapshot, deviceKey, startOffset, changeId):
        asked.append(startOffset)
        # ESXi answers in parts of 4 GiB
        return _Answer(startOffset, 4 * GiB, [(startOffset + MiB, 64 * KiB)])
    vm = types.SimpleNamespace(QueryChangedDiskAreas=query, snapshot=None)
    got = _soap_mgr(vm).changed_disk_areas('5', '2000', '52 aa/3', 10 * GiB)
    assert asked == [0, 4 * GiB, 8 * GiB]
    assert got == {'data': [(MiB, 64 * KiB), (4 * GiB + MiB, 64 * KiB), (8 * GiB + MiB, 64 * KiB)]}


def test_an_answer_that_covers_nothing_is_an_error_not_a_loop():
    vm = types.SimpleNamespace(QueryChangedDiskAreas=lambda **k: _Answer(0, 0, []), snapshot=None)
    assert 'covered nothing' in _soap_mgr(vm).changed_disk_areas('5', '2000', '*', GiB)['error']


def test_two_snapshots_of_one_name_are_an_error():
    snap = types.SimpleNamespace(name='_pegaprox_clone_snap', snapshot=object(), childSnapshotList=[])
    vm = types.SimpleNamespace(snapshot=types.SimpleNamespace(rootSnapshotList=[snap, snap]))
    assert 'are called' in _soap_mgr(vm).snapshot_disk_state('5', '_pegaprox_clone_snap')['error']


def test_the_snapshot_says_file_and_change_id_of_each_disk():
    from pyVmomi import vim
    disk = vim.vm.device.VirtualDisk(key=2000, backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(
        fileName='[ds1] app01/app01.vmdk', changeId='52 51 e3/1'))
    nic = vim.vm.device.VirtualVmxnet3(key=4000)
    obj = types.SimpleNamespace(config=types.SimpleNamespace(hardware=types.SimpleNamespace(device=[disk, nic])))
    snap = types.SimpleNamespace(name='_pegaprox_clone_snap', snapshot=obj, childSnapshotList=[])
    vm = types.SimpleNamespace(snapshot=types.SimpleNamespace(rootSnapshotList=[snap]))
    got = _soap_mgr(vm).snapshot_disk_state('5', '_pegaprox_clone_snap')
    assert got == {'data': {'2000': {'file': '[ds1] app01/app01.vmdk', 'change_id': '52 51 e3/1'}}}


def test_change_tracking_needs_the_soap_api():
    from pegaprox.core.vmware import VMwareManager
    mgr = object.__new__(VMwareManager)
    mgr._connection_type = 'rest'
    for call in (lambda: mgr.change_tracking_state('5'), lambda: mgr.set_change_tracking('5', True),
                 lambda: mgr.snapshot_disk_state('5', 'x'), lambda: mgr.changed_disk_areas('5', '1', '*', 1),
                 lambda: mgr.shutdown_guest('5')):
        assert 'SOAP' in call()['error']


def test_shutdown_needs_running_guest_tools():
    vm = types.SimpleNamespace(guest=types.SimpleNamespace(toolsRunningStatus='guestToolsNotRunning'),
                               ShutdownGuest=lambda: pytest.fail('asked a guest without tools'))
    assert 'not running' in _soap_mgr(vm).shutdown_guest('5')['error']


def test_the_copy_script_is_valid_bash():
    script = v2p._copy_runs_script('/tmp/v2p-runs-x', ('password', '/run/pegaprox-v2p-x'), 'root', 'esx1.lab',
                                   "/vmfs/volumes/ds 1/app's/_pegaprox_round_120_0-flat.vmdk",
                                   '/dev/pve/vm-120-disk-0')
    p = subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    # the source path reaches ESXi's shell as one quoted word, inside the node's quoting
    assert shlex.quote("/vmfs/volumes/ds 1/app's/_pegaprox_round_120_0-flat.vmdk") in \
        shlex.split(script.split('esxi ', 2)[2].split(' < ')[0])[0]


def test_a_refused_snapshot_says_why(monkeypatch):
    """A question pending on the VM (or another task) makes ESXi refuse the snapshot; the
    call said only that it did not appear within 60s."""
    import time as _time
    monkeypatch.setattr(_time, 'sleep', lambda s: None)
    err = types.SimpleNamespace(msg='The operation cannot be allowed at the current time because the '
                                    'virtual machine has a question pending')
    task = types.SimpleNamespace(info=types.SimpleNamespace(state='error', error=err))
    vm = types.SimpleNamespace(CreateSnapshot_Task=lambda **k: task, snapshot=None)
    got = _soap_mgr(vm)._soap_create_snapshot('7', '_pegaprox_catchup_snap', memory=False, quiesce=False)
    assert got == {'error': 'snapshot refused: ' + err.msg}


@pytest.mark.parametrize('mode', ['Auto', 'live_mirror', 'snapshot-zero', 7], ids=repr)
def test_a_transfer_mode_this_code_does_not_know_is_refused_at_the_door(api, seed, v2p_route, mode):
    """Such a name ran Auto's pre-sync flow, which falls back to the Live Mirror."""
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(V2P, json=_v2p_body(transfer_mode=mode))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'transfer_mode is one of' in r.get_json()['error']
    assert v2p_route == []
