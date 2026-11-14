# ESXi migration follow-ups after the first review of the per NIC / per disk choices, the
# verify modes and the bulk runs:
#
# - an allocation never frees or reuses a volume this job did not create (the TPM state
#   Proxmox puts on target_storage at the VM create is vm-<vmid>-disk-0 there)
# - a copy from the boot disk's folder that would leave a disk out or read an old state of
#   it is refused before anything is touched
# - one guest is started by one job at a time, whichever route starts it
# - a caller's selected_nics cannot open options on the net line
# - the migration plan shows a caller who may only migrate what the wizard needs
# - a forwarding standby reads the ESXi bulk runs on the active
# - the wizard only uses classes the static Tailwind build has
# - verify=full stops waiting as soon as one side failed
#
# The fakes of tests/test_esxi_mapping_verify.py and tests/test_esxi_bulk.py stand in for
# ESXi, the Proxmox node and its API.

import json
import os
import re
import shlex
import threading
import time

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import esxi_bulk as ebulk

from test_esxi_mapping_verify import (  # noqa: F401 (route is a fixture)
    GiB, NICS, VMID, Node, Pve, Run, _disks, _md5_lines, route)
from test_esxi_bulk import _started, _view, _over, _wait, PW, env  # noqa: F401 (env is a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# =========================================================================== 1. volumes

def _stem(name):
    return re.sub(r'\.(raw|qcow2|vmdk)$', '', name.rsplit('/', 1)[-1])


class AllocNode:
    """pvesm on one node with the volumes of its storages. `hidden` are names the storage
    has but does not list (an LV of another thin pool in the same volume group). `lists`
    False makes the listing fail. `stray_error` makes the first alloc of a name create it
    and still answer with an error, the way some plugins do."""

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
    from unittest.mock import MagicMock
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
    # the old names were not even asked for
    assert not any(c.startswith('pvesm alloc') and ('disk-0' in c or 'disk-1' in c) for c in node.cmds)


def test_disk_n_starts_at_its_own_index(monkeypatch):
    node = AllocNode(['local-lvm:vm-117-disk-0', 'local-lvm:vm-117-disk-3'])
    vol, _path, _ = _alloc(monkeypatch, node, index=3)
    assert vol == 'local-lvm:vm-117-disk-4'
    vol, _path, _ = _alloc(monkeypatch, node, index=1)
    assert vol == 'local-lvm:vm-117-disk-1'


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
    """An attempt that created the LV and still answered with an error, the next one
    says it exists. That volume is this job's own."""
    node = AllocNode([], stray_error=True)
    vol, _path, errbuf = _alloc(monkeypatch, node)
    assert vol == 'local-lvm:vm-117-disk-0', errbuf
    assert [c for c in node.cmds if c.startswith('pvesm alloc')][1:] and node.freeing() == []


class VolNode(Node):
    """The fake node of test_esxi_mapping_verify with the volumes Proxmox keeps: pvesm list
    shows them, alloc adds one, free takes one away. A checksum of a system disk is the one
    of the source disk it was allocated for, whatever name it got."""

    def __init__(self, log, esxi, vols, **kw):
        super().__init__(log, esxi, **kw)
        self.vols = vols
        self.alias = {}
        self.freed = []

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        m = re.match(r'pvesm list (\S+)', cmd)
        if m:
            self.log.append(('node', node, cmd))
            st = shlex.split(m.group(1))[0]
            rows = ''.join(f'{v} raw images 4194304 {VMID}\n' for v in sorted(self.vols) if v.startswith(st + ':'))
            return 0, 'Volid Format Type Size VMID\n' + rows, ''
        m = re.match(r'pvesm alloc (\S+) (\d+) (\S+) ', cmd)
        if m:
            self.log.append(('node', node, cmd))
            st, name = shlex.split(m.group(1))[0], m.group(3)
            if any(v.split(':', 1)[0] == st and _stem(v.split(':', 1)[1]) == _stem(name) for v in self.vols):
                return 5, f'Logical Volume "{_stem(name)}" already exists\n', ''
            self.vols[f'{st}:{name}'] = 'disk'
            self.alias[_stem(name)] = f'vm-{VMID}-disk-{len(self.alias)}'
            return 0, f"successfully created '{st}:{name}'\n", ''
        if cmd.startswith(('pvesm free', 'lvremove')):
            self.log.append(('node', node, cmd))
            vol = shlex.split(cmd)[2]
            self.freed.append(vol)
            self.vols.pop(vol, None)
            return 0, '', ''
        m = re.match(r'pvesm path (\S+) 2>/dev/null', cmd)
        if m:
            self.log.append(('node', node, cmd))
            vol = shlex.split(m.group(1))[0]
            return (0, f'/dev/{vol.split(":", 1)[0]}/{vol.split(":", 1)[1]}\n', '') if vol in self.vols else (1, '', '')
        if 'md5sum' in cmd and 'while' in cmd and 'dd if=/dev/' in cmd:
            self.log.append(('node', node, cmd))
            n = int(re.search(r'-lt (\d+) \]', cmd).group(1))
            path = shlex.split(re.search(r'dd if=(\S+)', cmd).group(1))[0]
            return 0, _md5_lines('/dev/x/' + self.alias.get(_stem(path), _stem(path)), n), ''
        return super().__call__(mgr, node, cmd, timeout, **kw)


class VolPve(Pve):
    """The Proxmox API puts the TPM state of a new VM on the storage tpmstate0 names, as
    the first free vm-<vmid>-disk-N there."""

    def __init__(self, log, vols, **kw):
        super().__init__(log, **kw)
        self.vols = vols

    def _api_post(self, url, data=None, **kw):
        tpm = (data or {}).get('tpmstate0')
        if url.endswith('/nodes/pve1/qemu') and tpm:
            st = tpm.split(':', 1)[0]
            n = 0
            while f'{st}:vm-{VMID}-disk-{n}' in self.vols:
                n += 1
            self.vols[f'{st}:vm-{VMID}-disk-{n}'] = 'tpm'
        return super()._api_post(url, data, **kw)


class VolRun(Run):
    def __init__(self, monkeypatch, **kw):
        super().__init__(monkeypatch, **kw)
        self.vols = {}
        self.node = VolNode(self.log, self.esxi, self.vols, storage_types=kw.get('storage_types'))
        self.pve = VolPve(self.log, self.vols)
        monkeypatch.setattr(self.mod, '_pve_node_exec', self.node)
        monkeypatch.setattr(self.mod, 'cluster_managers', {'pve-cl': self.pve})


@pytest.mark.parametrize('kw', [dict(mode='offline'), dict(mode='vmkfstools_clone'),
                                dict(mode='auto', clone_snap_fails=True),
                                dict(mode='sshfs_boot', ndisks=2, ssh_key='/tmp/v2p-key-fixed')],
                         ids=lambda kw: kw['mode'])
def test_a_migration_with_tpm_leaves_the_tpm_state_alone(monkeypatch, kw):
    r = VolRun(monkeypatch, **kw).go()
    assert r.task.status == 'completed', r.task.error
    tpm = f'local-lvm:vm-{VMID}-disk-0'
    assert r.vols.get(tpm) == 'tpm', 'the TPM state was freed'
    assert r.node.freed == [] or tpm not in r.node.freed
    # no node command names the TPM volume: not a free, not a write, not a post-copy fix
    assert [c for c in r.nodecmds() if f'vm-{VMID}-disk-0' in c] == []
    attach = [c for c in r.nodecmds() if re.match(rf'qm set {VMID} --scsi0 ', c)]
    assert attach and all(f'local-lvm:vm-{VMID}-disk-1' in c for c in attach), attach
    assert r.task.boot_volume() == f'local-lvm:vm-{VMID}-disk-1'


def test_the_post_copy_fixes_never_guess_a_volume_name():
    t = v2p.V2PMigrationTask('t', 'vw', 'vm', 'c', 'pve1', 'local-lvm', config={})
    t.proxmox_vmid = VMID
    # nothing copied yet: no name made up from the VMID
    assert t.boot_volume() is None
    t.record_disk_volume(0, f'local-lvm:vm-{VMID}-disk-3')
    assert t.boot_volume() == f'local-lvm:vm-{VMID}-disk-3'


def test_no_allocation_frees_a_volume_before_it_allocates():
    """The free-before-alloc and the made-up disk names are gone from every copy path."""
    src = _read('pegaprox', 'core', 'v2p.py')
    alloc = src[src.index('def _pvesm_alloc_disk('):src.index('def _setup_temp_ssh_key(')]
    head = alloc[:alloc.index('alloc_attempts')]
    assert 'pvesm free' not in head and 'lvremove' not in head and 'sed -i' not in head
    assert not re.search(r"vm-\{[^}]*\}-disk-0", src)


# =========================================================================== 2. folder copies

def _elsewhere(r):
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    return r


def _on_its_own_snapshot(r, monkeypatch):
    """Disk 1 runs on a snapshot of the VM: ESXi names its current file app01-000001.vmdk.
    The folder listing leaves the -0000NN files out, as the real grep does."""
    r.esxi.disks[0]['vmdk_file'] = '[ds1] app01/app01-000001.vmdk'
    shell = r.mod._ssh_exec

    def listing(host, user, pw, cmd, timeout=30):
        if cmd.startswith('ls -1'):
            r.log.append(('esxi_ssh', cmd))
            return 0, '/vmfs/volumes/ds1/app01/app01.vmdk\n/vmfs/volumes/ds1/app01/app01_1.vmdk\n', ''
        return shell(host, user, pw, cmd, timeout)
    monkeypatch.setattr(r.mod, '_ssh_exec', listing)
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
    r = _on_its_own_snapshot(Run(monkeypatch, mode='offline'), monkeypatch).go()
    assert r.task.status == 'failed'
    assert 'disk 1 (Hard disk 1)' in r.task.error and 'snapshot' in r.task.error, r.task.error
    assert 'Live Clone' in r.task.error
    _nothing_touched(r)


def test_auto_refuses_the_fallback_copy_when_the_clone_is_not_possible(monkeypatch):
    r = _elsewhere(Run(monkeypatch, mode='auto', clone_snap_fails=True)).go()
    assert r.task.status == 'failed'
    assert 'disk 2 (Hard disk 2)' in r.task.error and 'Live Clone' in r.task.error, r.task.error
    assert r.posts() and not any(c.startswith('pvesm alloc') for c in r.nodecmds())
    assert not [e for e in r.log if e[:2] == ('esxi_api', 'power')]
    assert r.esxi.snaps == []


def test_auto_with_the_clone_copies_every_disk_from_its_own_file(monkeypatch):
    r = _elsewhere(Run(monkeypatch, mode='auto')).go()
    assert r.task.status == 'completed', r.task.error
    clones = [e[1] for e in r.log if e[0] == 'esxi_cli' and 'nohup vmkfstools' in e[1]]
    assert any('/vmfs/volumes/ds2/other/app01_1.vmdk' in c for c in clones), clones


def test_the_plan_says_so_before_the_start(monkeypatch):
    disks = _disks(3)
    disks[2]['vmdk_file'] = '[ds1] app01/app01_2-000001.vmdk'
    inv = {'bridges': {'vmbr0': 'bridge'}, 'notes': [],
           'storages': {'local-lvm': {'type': 'lvmthin', 'content': {'images'}, 'active': True, 'avail': 900 * GiB}}}
    opts = v2p.parse_migration_options({})

    def plan(mode):
        return v2p.resolve_migration_plan(inv, disks, NICS, opts, 'local-lvm', 'vmbr0', transfer_mode=mode)
    p = plan('offline')
    assert not p['ok'] and any('disk 3 (Hard disk 3)' in e and 'snapshot' in e for e in p['errors']), p['errors']
    p = plan('auto')
    assert p['ok'] and any('disk 3 (Hard disk 3)' in w for w in p['warnings']), p['warnings']
    p = plan('vmkfstools_clone')
    assert p['ok'] and not any('disk 3' in w for w in p['warnings'])
    disks[2]['vmdk_file'] = '[ds1] app01/app01_2.vmdk'
    assert plan('offline')['ok']


# =========================================================================== 3. one job per guest

def _single(client, vm, **kw):
    body = {'target_cluster': 'pve-cl', 'target_node': 'pve1', 'target_storage': 'local-lvm',
            'esxi_password': PW, 'transfer_mode': 'offline'}
    body.update(kw)
    return client.post(f'/api/vmware/vw1/vms/{vm}/migrate', json=body)


class Blocking:
    """Stands in for _run_v2p_migration: a migration that runs until the test lets it end"""

    def __init__(self):
        self.tasks, self.lock = [], threading.Lock()
        self.events, self.boom = {}, set()
        self.over = False

    def __call__(self, task):
        ev = threading.Event()
        with self.lock:
            self.tasks.append(task)
            self.events[task.id] = ev
            if self.over:
                ev.set()
        ev.wait(15)
        if task.vm_id in self.boom:
            task.status = task.phase = 'failed'
            raise RuntimeError('the job broke')
        task.status = task.phase = 'completed'

    def vms(self):
        with self.lock:
            return [t.vm_id for t in self.tasks]

    def finish(self, vm_id=None):
        with self.lock:
            # the end of the test: a job that comes in later ends at once as well
            self.over = self.over or vm_id is None
            evs = [self.events[t.id] for t in self.tasks if vm_id in (None, t.vm_id)]
        for ev in evs:
            ev.set()


@pytest.fixture
def blocking(env, monkeypatch):
    b = Blocking()
    monkeypatch.setattr(env.module, '_run_v2p_migration', b)
    yield b
    b.finish()
    # no run of this test may still follow a job when the next one patches the clock
    _wait(lambda: all(r.state != 'running' for r in ebulk.runs()) or not ebulk.runs(), seconds=10,
          what='the runs of the test to end')


def _second_client(env, _integration_app, name):
    import conftest
    sid = env.api.as_user(env.seed.user(name, role='admin')).session_id
    return conftest._ApiClient(_integration_app.test_client(), sid)


def test_two_bulk_submits_never_both_get_the_same_guest(env, monkeypatch, _integration_app):
    env.runner.hold_planning = True
    real = env.module._bulk_check
    both = threading.Barrier(2, timeout=3)

    def checked_together(*a, **k):
        res = real(*a, **k)
        try:
            both.wait()
        except threading.BrokenBarrierError:
            pass
        return res
    monkeypatch.setattr(env.module, '_bulk_check', checked_together)
    other = _second_client(env, _integration_app, 'ann')
    codes = []

    def submit(client):
        codes.append(env.post(client, vms=['vm-1']).status_code)
    threads = [threading.Thread(target=submit, args=(c,)) for c in (env.admin, other)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert sorted(codes) == [202, 409], codes
    _wait(lambda: env.runner.names() == ['web01'])
    time.sleep(0.2)
    assert env.runner.names() == ['web01'], 'one guest started twice'


def test_the_single_route_does_not_start_a_guest_a_bulk_run_has(env, blocking):
    run = _started(env.post(vms=['vm-1', 'vm-2'], width=1))
    _wait(lambda: blocking.vms() == ['vm-1'])
    # vm-2 waits for its turn in the run, vm-1 migrates
    for vm in ('vm-2', 'vm-1'):
        r = _single(env.admin, vm)
        assert r.status_code == 409, r.get_data(as_text=True)
        assert 'migrat' in r.get_json()['error']
    assert blocking.vms() == ['vm-1']
    # a dry run says so as well
    d = _single(env.admin, 'vm-2', dry_run=True, esxi_password=None).get_json()
    assert d['ok'] is False and any('bulk migration' in e for e in d['errors']), d
    # a guest nobody has goes
    assert _single(env.admin, 'vm-3').status_code == 202
    _wait(lambda: blocking.vms() == ['vm-1', 'vm-3'])
    assert run['id']


def test_a_bulk_submit_does_not_take_a_guest_the_single_route_started(env, blocking):
    assert _single(env.admin, 'vm-1').status_code == 202
    _wait(lambda: blocking.vms() == ['vm-1'])
    r = env.post(vms=['vm-1', 'vm-2'])
    assert r.status_code == 400
    items = {it['vm_id']: it for it in r.get_json()['items']}
    assert items['vm-1']['errors'] == ['A migration of this guest is running']
    blocking.finish('vm-1')
    _wait(lambda: ebulk.holder('vw1', 'vm-1') is None, what='the guest is free again')
    assert _started(env.post(vms=['vm-1']))


def test_a_single_start_between_the_bulk_check_and_its_start_wins_alone(env, blocking, monkeypatch,
                                                                       _integration_app):
    real = env.module._bulk_check
    other = _second_client(env, _integration_app, 'ann')
    single = []

    def check_then_single(*a, **k):
        res = real(*a, **k)
        t = threading.Thread(target=lambda: single.append(_single(other, 'vm-1').status_code))
        t.start()
        t.join(10)
        return res
    monkeypatch.setattr(env.module, '_bulk_check', check_then_single)
    r = env.post(vms=['vm-1'])
    assert single == [202]
    assert r.status_code == 409, r.get_data(as_text=True)
    time.sleep(0.2)
    assert blocking.vms() == ['vm-1'], 'one guest started twice'


def test_two_single_starts_of_one_guest_start_it_once(env, blocking, monkeypatch, _integration_app):
    import pegaprox.api.helpers as helpers
    real = helpers.tenant_quota_gate
    both = threading.Barrier(2, timeout=2)

    def gate(*a, **k):
        if k.get('hold'):
            try:
                both.wait()
            except threading.BrokenBarrierError:
                pass
        return real(*a, **k)
    monkeypatch.setattr(helpers, 'tenant_quota_gate', gate)
    other = _second_client(env, _integration_app, 'ann')
    codes = []
    threads = [threading.Thread(target=lambda c=c: codes.append(_single(c, 'vm-1').status_code))
               for c in (env.admin, other)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert sorted(codes) == [202, 409], codes
    time.sleep(0.2)
    assert blocking.vms() == ['vm-1']


def test_the_guest_is_free_again_on_every_way_out_of_the_single_route(env, blocking, monkeypatch):
    # the job ends
    assert _single(env.admin, 'vm-1').status_code == 202
    _wait(lambda: ebulk.holder('vw1', 'vm-1') is not None)
    blocking.finish('vm-1')
    _wait(lambda: ebulk.holder('vw1', 'vm-1') is None, what='free after the end')
    # the job breaks
    blocking.boom.add('vm-2')
    assert _single(env.admin, 'vm-2').status_code == 202
    _wait(lambda: blocking.vms().count('vm-2') == 1)
    blocking.finish('vm-2')
    _wait(lambda: ebulk.holder('vw1', 'vm-2') is None, what='free after the job broke')
    # the quota says no
    import pegaprox.api.helpers as helpers
    from flask import jsonify
    real_gate = helpers.tenant_quota_gate
    monkeypatch.setattr(helpers, 'tenant_quota_gate',
                        lambda *a, **k: ((jsonify({'error': 'Tenant quota exceeded'}), 403), None))
    assert _single(env.admin, 'vm-3').status_code == 403
    assert ebulk.holder('vw1', 'vm-3') is None
    monkeypatch.setattr(helpers, 'tenant_quota_gate', real_gate)
    # the job cannot be started
    from pegaprox.core import ha

    def no_job(*a, **k):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(ha, 'as_job', no_job)
    try:
        status = _single(env.admin, 'vm-4').status_code
    except RuntimeError:
        status = None
    assert status != 202
    assert ebulk.holder('vw1', 'vm-4') is None
    assert not any(t.status == 'running' for t in env.module._vmware_migrations.values() if t.vm_id == 'vm-4')


def test_a_bulk_run_lets_go_of_each_guest_on_every_way_out(env, blocking):
    run = _started(env.post(vms=['vm-1', 'vm-2', 'vm-3'], width=1))
    _wait(lambda: blocking.vms() == ['vm-1'])
    assert {vm: (ebulk.holder('vw1', vm) or '')[:5] for vm in ('vm-1', 'vm-2', 'vm-3')} == \
        {'vm-1': 'task:', 'vm-2': 'bulk:', 'vm-3': 'bulk:'}
    assert env.admin.post(f"/api/vmware/bulk-migrate/{run['id']}/cancel").status_code == 200
    # what waited is free at once, what migrates stays with its migration
    _wait(lambda: ebulk.holder('vw1', 'vm-2') is None and ebulk.holder('vw1', 'vm-3') is None)
    assert (ebulk.holder('vw1', 'vm-1') or '').startswith('task:')
    blocking.finish('vm-1')
    _wait(lambda: _over(run['id']))
    assert [ebulk.holder('vw1', vm) for vm in ('vm-1', 'vm-2', 'vm-3')] == [None, None, None]


def test_a_skipped_guest_is_free_again(env):
    bob = env.seed.user('bob', role='user')
    for vm in ('vm-1', 'vm-2'):
        env.seed.vm_acl('vmware:vw1', vm, ['bob'], inherit_role=False, permissions=['vmware.vm.migrate'])
    env.rbac.invalidate_vm_acls_cache()
    run = _started(env.post(env.api.as_user(bob), vms=['vm-1', 'vm-2'], width=1))
    _wait(lambda: env.runner.names() == ['web01'])
    env.seed.vm_acl('vmware:vw1', 'vm-2', ['bob'], inherit_role=False, permissions=['vmware.vm.view'])
    env.rbac.invalidate_vm_acls_cache()
    env.runner.end('web01')
    _wait(lambda: _over(run['id']))
    assert next(it for it in _view(env.admin, run['id'])['items'] if it['vm_id'] == 'vm-2')['state'] == 'skipped'
    assert ebulk.holder('vw1', 'vm-2') is None


def test_the_registry_takes_a_guest_once():
    ebulk.reset_for_tests()
    try:
        assert ebulk.hold('vw1', 'vm-1', 'task:a') is None
        assert ebulk.hold('vw1', 'vm-1', 'task:b') == 'task:a'
        assert ebulk.hold('vw2', 'vm-1', 'task:b') is None       # another server's guest
        ebulk.let_go('vw1', 'vm-1', 'task:b')                    # not b's to free
        assert ebulk.holder('vw1', 'vm-1') == 'task:a'
        ebulk.let_go('vw1', 'vm-1', 'task:a')
        assert ebulk.holder('vw1', 'vm-1') is None
        run = ebulk.EsxiBulkRun('vw1', 's', 'root', {}, '', {}, 1, [ebulk.new_item('vm-1'), ebulk.new_item('vm-2')], PW)
        ebulk.hold('vw1', 'vm-2', 'task:c')
        with pytest.raises(ebulk.Taken) as e:
            ebulk.register(run)
        assert 'vm-2' in str(e.value)
        assert ebulk.holder('vw1', 'vm-1') is None and ebulk.get(run.id) is None, 'half a run was taken in'
        ebulk.let_go('vw1', 'vm-2', 'task:c')
        ebulk.register(run)
        assert ebulk.holder('vw1', 'vm-1') == ebulk.holder('vw1', 'vm-2') == f'bulk:{run.id}'
        assert ebulk.pass_on('vw1', 'vm-1', f'bulk:{run.id}', 'task:d') is True
        assert ebulk.pass_on('vw1', 'vm-1', f'bulk:{run.id}', 'task:e') is False
        ebulk.abandon(run, 'test')
        assert ebulk.holder('vw1', 'vm-2') is None and ebulk.holder('vw1', 'vm-1') == 'task:d'
    finally:
        ebulk.reset_for_tests()


# =========================================================================== 4. selected_nics

@pytest.mark.parametrize('nic', [
    {'pve_model': 'virtio,trunks=1-4094', 'mac_address': '00:50:56:aa:00:01'},
    {'pve_model': 'virtio,bridge=vmbr9'},
    {'pve_model': 'VirtIO'},
    {'pve_model': ['virtio']},
    {'pve_model': 'virtio', 'mac_address': '00:50:56:aa:00:01,firewall=0'},
    {'pve_model': 'e1000', 'mac_address': '01:00:5e:00:00:01'},
    {'pve_model': 'e1000', 'mac_address': '00:50:56:aa:00'},
    {'pve_model': 'e1000', 'mac_address': '00-50-56-aa-00-01'},
    {'mac_address': 5},
    'virtio',
], ids=repr)
def test_a_nic_value_that_is_no_model_or_no_unicast_mac_is_refused(route, nic):
    for dry in (False, True):
        r = route.post(selected_nics=[dict(NICS[0]), nic], dry_run=dry)
        assert r.status_code == 400, r.get_data(as_text=True)
    assert route.started == []


def test_every_model_proxmox_knows_and_a_unicast_mac_still_go(route):
    nics = [{'pve_model': m, 'mac_address': f'02:00:00:00:00:{i:02x}'} for i, m in enumerate(v2p.PVE_NIC_MODELS)]
    nics.append({'pve_model': '', 'mac_address': ''})
    nics.append({'network': 'VM Network'})
    r = route.post(selected_nics=nics)
    assert r.status_code == 202, r.get_data(as_text=True)
    assert route.wait_started()[0].selected_nics == nics
    assert len(v2p.PVE_NIC_MODELS) == 14 and 'virtio' in v2p.PVE_NIC_MODELS


def test_the_net_line_takes_no_model_or_mac_it_does_not_know(monkeypatch):
    bad = [{'pve_model': 'virtio,trunks=1-4094', 'mac_address': '00:50:56:aa:00:01,firewall=0'},
           {'pve_model': 'e1000e', 'mac_address': '01:00:5e:00:00:01'}]
    r = Run(monkeypatch, mode='offline', config={'selected_nics': bad}).go()
    post = next(e for e in r.posts() if e[1] == '/nodes/pve1/qemu')
    cfg = dict(post[2])
    assert cfg['net0'] == 'vmxnet3,bridge=vmbr0,tag=30'
    assert cfg['net1'] == 'e1000e,bridge=vmbr0,tag=30'


# =========================================================================== 5. migration plan

HW_KEYS = ('hardware', 'cpu', 'memory', 'guest_OS', 'notes')


def _may(monkeypatch, route, perms):
    monkeypatch.setattr(route.module, 'user_can_access_vmware_vm',
                        lambda user, vmw, vm, perm='vmware.vm.view': perm in perms)


def test_a_caller_who_may_only_migrate_gets_what_the_wizard_needs(route, monkeypatch):
    _may(monkeypatch, route, {'vmware.vm.migrate'})
    r = route.admin.get('/api/vmware/vw1/vms/vm-42/migration-plan')
    assert r.status_code == 200, r.get_data(as_text=True)
    src = r.get_json()['source']
    assert not [k for k in HW_KEYS if k in src], src.keys()
    assert src['details'] is False
    assert [n['mac_address'] for n in src['nics']] == [n['mac_address'] for n in NICS]
    assert [n['network'] for n in src['nics']] == [n['network'] for n in NICS]
    assert {k for n in src['nics'] for k in n} <= {'label', 'network', 'mac_address', 'pve_model'}
    assert [d['vmdk_file'] for d in src['disks']] == [d['vmdk_file'] for d in _disks(3)]
    assert src['power_state'] and src['name']


def test_a_caller_who_may_view_the_guest_gets_its_hardware(route, monkeypatch):
    _may(monkeypatch, route, {'vmware.vm.migrate', 'vmware.vm.view'})
    src = route.admin.get('/api/vmware/vw1/vms/vm-42/migration-plan').get_json()['source']
    assert src['hardware']['firmware'] == 'efi' and src['cpu']['sockets'] == 1 and src['guest_OS'] == 'Linux'
    assert src['details'] is True
    assert src['nics'][0]['type'] == 'VirtualVmxnet3'


def test_a_caller_who_may_not_migrate_gets_nothing(route, monkeypatch):
    _may(monkeypatch, route, {'vmware.vm.view'})
    assert route.admin.get('/api/vmware/vw1/vms/vm-42/migration-plan').status_code == 403


# =========================================================================== 6. HA forwarding

BULK_READS = ('/api/vmware/bulk-migrate', '/api/vmware/bulk-migrate/<run_id>')


def test_a_forwarding_standby_reads_the_esxi_bulk_runs_on_the_active(api):
    from pegaprox.core import ha
    assert set(BULK_READS) <= ha.FORWARDED_READS
    assert not set(BULK_READS) & ha.LEADER_ONLY_READS
    served = {r.rule for r in api.app.url_map.iter_rules() if 'GET' in r.methods}
    assert set(BULK_READS) <= served


# =========================================================================== 7. classes

def _esxi_ui_parts():
    dash = _read('web', 'src', 'dashboard.js')

    def cut(head, tail):
        start = dash.index(head)
        return dash[start:dash.index(tail, start)]
    return [cut('// LW Oct 2026 - ESXi bulk migration: the settings', '// NS: Mar 2026 - Topology View redesign'),
            cut('{/* LW Oct 2026 - what is ticked goes into one bulk migration */}', '{/* VM Table'),
            cut('{/* storage per disk; empty = the target storage above */}', '{/* ESXi SSH User'),
            cut('{/* NICs of the ESXi VM: bridge, VLAN and skip per NIC */}', '{/* Transfer Mode'),
            cut('{/* verify mode: full compares every block before the start */}', '{/* Options */}'),
            cut('{/* === STEP 4: REVIEW ===', "{t('v2pReviewCheckAgain')}")]


def test_every_class_of_the_esxi_wizard_is_in_the_static_tailwind_build():
    from test_ha_ui import _classes
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _esxi_ui_parts():
        names |= _classes(part)
    assert len(names) > 60
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


# =========================================================================== 8. verify=full

class Stops:
    """The stop files the two sides of a full check watch. A side that has one runs until
    a later command names it, or for `cap` seconds; a side without one runs for `cap`."""

    def __init__(self, cap=8.0):
        self.cap = cap
        self.events = {}
        self.ended = []
        self.lock = threading.Lock()

    def watch(self, path):
        ev = threading.Event()
        if path:
            with self.lock:
                self.events[path] = ev
        return ev

    def seen(self, cmd):
        with self.lock:
            evs = [ev for p, ev in self.events.items() if p in cmd]
        for ev in evs:
            ev.set()


def _slow_full_check(monkeypatch, slow, fail):
    """An offline run with verify=full: the `fail` side answers at once with an error, the
    `slow` side hashes until it is told to stop."""
    r = Run(monkeypatch, mode='offline', ndisks=1, config={'verify': 'full'}, verify_fail=(fail == 'node'))
    stops = Stops()
    node, shell = r.mod._pve_node_exec, r.mod._ssh_exec

    def node_exec(mgr, n, cmd, timeout=600, **kw):
        if cmd.startswith('bash /tmp/v2p-fullcheck-') and slow == 'node':
            r.log.append(('node', n, cmd))
            body = r.node.scripts.get(cmd.split()[1], '')
            m = re.search(r"^STOP=(.+)$", body, re.M)
            stopped = stops.watch(shlex.split(m.group(1))[0] if m else None).wait(stops.cap)
            stops.ended.append('node')
            return (6, 'STOPPED\n', '') if stopped else (0, 'VERIFY_DONE\n', '')
        stops.seen(cmd)
        return node(mgr, n, cmd, timeout, **kw)

    def esxi_exec(host, user, pw, cmd, timeout=30):
        if cmd.startswith("stat -c '%s'") and 'md5sum' in cmd:
            if fail == 'esxi':
                r.log.append(('esxi_ssh', cmd))
                return 1, '', 'TCP connect to esx1.lab:22 timed out after 8s'
            if slow == 'esxi':
                r.log.append(('esxi_ssh', cmd))
                m = re.search(r"\[ -e ([^ \]]+) \]", cmd)
                stopped = stops.watch(shlex.split(m.group(1))[0] if m else None).wait(stops.cap)
                stops.ended.append('esxi')
                r.log.append(('esxi_side_ended',))
                return (9, '2147483648\n', '') if stopped else (0, '1\n', '')
        stops.seen(cmd)
        return shell(host, user, pw, cmd, timeout)
    monkeypatch.setattr(r.mod, '_pve_node_exec', node_exec)
    monkeypatch.setattr(r.mod, '_ssh_exec', esxi_exec)
    return r, stops


def test_a_node_side_that_fails_stops_the_esxi_side_and_the_source_comes_back(monkeypatch):
    r, stops = _slow_full_check(monkeypatch, slow='esxi', fail='node')
    t0 = time.perf_counter()
    r.go()
    took = time.perf_counter() - t0
    assert r.task.status == 'failed' and 'Proxmox side could not be read' in r.task.error, r.task.error
    assert took < 4, f'waited {took:.1f}s for the ESXi side after the node side failed'
    assert stops.ended == ['esxi']
    # the source was powered on again once ESXi no longer read its disk
    power = [n for n, e in enumerate(r.log) if e[:3] == ('esxi_api', 'power', 'start')]
    assert power and power[0] > r.log.index(('esxi_side_ended',))
    assert not [e for e in r.log if e[0] == 'pve_api' and e[1].endswith('/status/start')]


def test_an_esxi_side_that_fails_stops_the_node_side(monkeypatch):
    r, stops = _slow_full_check(monkeypatch, slow='node', fail='esxi')
    t0 = time.perf_counter()
    r.go()
    took = time.perf_counter() - t0
    assert r.task.status == 'failed' and 'ESXi side could not be read' in r.task.error, r.task.error
    assert took < 4, f'waited {took:.1f}s for the node side after the ESXi side failed'
    assert stops.ended == ['node']
    # the check script is gone from the node
    assert any(c.startswith('rm -f /tmp/v2p-fullcheck-') for c in r.nodecmds())


def test_a_check_where_both_sides_pass_sends_no_stop(monkeypatch):
    r = Run(monkeypatch, mode='offline', config={'verify': 'full'}).go()
    assert r.task.status == 'completed', r.task.error
    assert len([c for c in r.nodecmds() if c.startswith('bash /tmp/v2p-fullcheck-')]) == 2
    assert not [e for e in r.log if 'touch ' in json.dumps(e)], 'a stop went out on a check that passed'


# --------------------------------------------------------------------------- the wizard, migrate only

def test_the_hidden_details_hint_is_in_every_language():
    from test_ha_ui import _blocks
    blocks = _blocks()
    assert len(blocks) == 10
    for lang, block in blocks.items():
        lines = re.findall(r'^ +v2pSourceDetailsHidden: (.*)$', block, re.M)
        assert len(lines) == 1, lang
        assert '\u2014' not in lines[0] and '\u2013' not in lines[0], lang
    assert "{t('v2pSourceDetailsHidden')}" in _read('web', 'src', 'dashboard.js')


from test_ha_ui import browser  # noqa: E402,F401 (a fixture: headless Chromium, skips without Playwright)


def test_runtime_the_wizard_works_for_a_caller_who_may_only_migrate(browser):
    """The plan of a migrate-only caller: no hardware, no sizing, NICs with only what the
    rows show. The wizard says why the hardware is not shown, maps the NICs and starts."""
    from test_ha_ui import _App, _FakeServer, ESXI_READS, SSE_TOKEN
    from test_esxi_mapping_verify import WIZ_DRY, _migrate_bodies, _pick_target
    source = {'vm_id': 'vm-1', 'name': 'legacy01', 'power_state': 'POWERED_ON', 'cpu_count': 2,
              'memory_mb': 4096, 'guest_os': 'Ubuntu', 'total_disk_gb': 3.5, 'details': False,
              'nics': [{k: n[k] for k in ('label', 'network', 'mac_address', 'pve_model')} for n in NICS],
              'disks': _disks(3)}
    plan = {'source': source, 'method': 'test', 'requirements': [],
            'targets': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'nodes': ['pve1'],
                         'storages': {'pve1': ['local-lvm', 'fast-lvm']}}]}
    extra = {**ESXI_READS, **SSE_TOKEN,
             ('GET', '/api/vmware/v1/vms/vm-1/migration-plan'): (200, plan),
             ('POST', '/api/vmware/v1/vms/vm-1/migrate'): (200, WIZ_DRY),
             ('GET', '/api/vmware/migrations'): (200, [])}
    app = _App(browser, _FakeServer(role='standalone', layout='modern', extra=extra))
    try:
        page = app.page
        page.get_by_text('esx01').first.click()
        page.get_by_text('legacy01').first.wait_for(timeout=8000)
        page.get_by_text('legacy01').first.click()
        page.locator('button:visible', has_text='Migration').first.wait_for(timeout=8000)
        page.locator('button:visible', has_text='Migration').first.click()
        page.locator('button:visible', has_text='Start Migration Wizard').first.click()
        page.locator('option', has_text='Select cluster...').first.wait_for(state='attached', timeout=5000)
        _pick_target(page)
        page.locator('option', has_text='dmz10 (vnet)').first.wait_for(state='attached', timeout=5000)
        # a row per NIC with the network it is on
        assert page.locator('select', has=page.locator('option', has_text='dmz10 (vnet)')).count() == 2
        page.get_by_text('DMZ', exact=True).first.wait_for(timeout=2000)
        page.locator('button', has_text=re.compile('\U0001F527\\s*Hardware')).first.click()
        page.locator('[data-v2p-details-hidden]').wait_for(timeout=3000)
        assert 'not shown here' in page.locator('[data-v2p-details-hidden]').inner_text()
        # the memory the export lists, not a made-up default
        assert page.locator('input[type="number"][min="128"]').input_value() == '4096'
        page.locator('button', has_text=re.compile('\U0001F3AF\\s*Target')).first.click()
        page.locator('input[placeholder="ESXi password"]').fill('pw')
        page.locator('label', has_text='keep this in mind').locator('input').check()
        page.locator('button', has_text='Review and start').click()
        page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
        start = page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$'))
        assert start.is_enabled()
        start.click()
        for _ in range(50):
            if any(not b.get('dry_run') for b in _migrate_bodies(app)):
                break
            page.wait_for_timeout(100)
        sent = [b for b in _migrate_bodies(app) if not b.get('dry_run')]
        assert len(sent) == 1 and sent[0]['esxi_password'] == 'pw'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_a_disk_label_from_esxi_stays_one_short_line_in_the_refusal():
    disks = _disks(2)
    disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    disks[1]['label'] = 'Hard disk 2\n[V2P] COMPLETED: forged line' + 'x' * 500
    _order, why = v2p.folder_copy_gap(disks)
    assert '\n' not in why and len(why) < 300 and why.startswith('disk 2 (Hard disk 2 [V2P]')
