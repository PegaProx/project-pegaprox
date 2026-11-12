"""A cross-cluster replication run that did not go through removes its clone.

A full run snapshots the guest, makes a full clone of it on the source (xcrepl-<vmid>-tmp,
at the next free VMID) and remote-migrates that clone with delete=1. Proxmox removes the
clone only with a migration that went through. A migration that did not start, timed out
or failed left it on the source cluster, a full copy of the guest per failed run: the
cleanup took the snapshot only.

Now such a run removes the clone it made, by the VMID it recorded and only while that
guest still carries the clone's label and, for a clone from the run's snapshot, the
snapshot's description. Not while a migration task of it runs on the node: the node's
task list is read, a running task is waited for up to CLONE_TASK_WAIT, and a list that
cannot be read leaves the clone with a warning. What is removed is logged.

The run goes through a real manager object here, its API calls answered by a fake Proxmox
VE of the source cluster.
"""
import logging
import re
import time
import types

import pytest
import requests

import pegaprox.api.vms as vms
import pegaprox.core.manager as manager_mod
import pegaprox.globals as ppglobals
from pegaprox.core import transfer_net
from pegaprox.core.manager import PegaProxManager

WALL = 1794400000
CLONE = 9100
LABEL = 'xcrepl-100-tmp'
MIGRATION = 'UPID:pve1:00001234:00000001:6AF5E100:qmigrate:9100:root@pam!pegaprox:'


class _Clock:
    """sleep, time and monotonic of the run and of the manager, one clock for all"""

    def __init__(self):
        self.t = 0.0

    def sleep(self, seconds):
        self.t += seconds

    def time(self):
        return WALL + self.t

    def monotonic(self):
        return self.t


class _R:
    def __init__(self, status=200, data=None, reason='', text=''):
        self.status_code, self._data, self.reason, self.text = status, data, reason, text
        self.headers = {}

    def json(self):
        return {'data': self._data}


class _Pve:
    """The source cluster's Proxmox VE as far as a run of VM 100 reaches: one node pve1, the
    guest, the clone the run makes, the node's clock and its migration tasks."""

    def __init__(self, clock, storage_type='lvmthin'):
        self.clock, self.storage_type = clock, storage_type
        self.guests = {100: {'name': 'web', 'description': 'the shop\n', 'scsi0': 'fast:vm-100-disk-0,size=8G'}}
        self.snapshots = {}
        # how the remote_migrate POST of the clone is answered
        self.migrate = ('refuse', "500 storage 'far' does not exist on the target")
        self.tasks = []
        self.listable = True
        self.deleted, self.reads = [], []

    @staticmethod
    def _path(url):
        return url.split('/api2/json', 1)[1]

    def get(self, url, params=None, **kw):
        path = self._path(url)
        self.reads.append((path, self.clock.t))
        if path == '/cluster/resources':
            return _R(200, [{'vmid': v, 'node': 'pve1', 'type': 'qemu', 'status': 'running' if v == 100 else 'stopped'}
                            for v in self.guests])
        if path == '/cluster/nextid':
            return _R(200, str(CLONE))
        if path == '/storage':
            return _R(200, [{'storage': 'fast', 'type': self.storage_type}])
        m = re.fullmatch(r'/nodes/pve1/qemu/(\d+)/config', path)
        if m:
            cfg = self.guests.get(int(m.group(1)))
            if cfg is None:
                return _R(500, None, reason=f"Configuration file 'nodes/pve1/qemu-server/{m.group(1)}.conf' "
                                            f"does not exist")
            return _R(200, dict(cfg))
        if path == '/nodes/pve1/time':
            return _R(200, {'time': int(WALL + self.clock.t)})
        if path == '/nodes/pve1/tasks':
            if not self.listable:
                return _R(500, None)
            return _R(200, [self._listed(t) for t in self.tasks])
        return _R(404)

    def _listed(self, task):
        entry = {'upid': task['upid'], 'node': 'pve1', 'type': 'qmigrate', 'id': str(CLONE),
                 'starttime': task['start'], 'user': 'root@pam!pegaprox'}
        if self.clock.t >= task['ends']:
            entry.update(endtime=int(WALL + task['ends']), status=task['exit'])
        return entry

    def post(self, url, data=None, timeout=None, **kw):
        path = self._path(url)
        if path == '/nodes/pve1/qemu/100/snapshot':
            self.snapshots[data['snapname']] = data.get('description', '')
            return _R(200, 'UPID:pve1:00000001:00000001:6AF5E100:qmsnapshot:100:root@pam!pegaprox:')
        if path == '/nodes/pve1/qemu/100/clone':
            # as Proxmox clones: the config of the snapshot when one is named, its description too
            cfg = dict(self.guests[100], name=data['name'], scsi0=f"fast:vm-{data['newid']}-disk-0,size=8G")
            if data.get('snapname'):
                cfg['description'] = self.snapshots[data['snapname']] + '\n'
            self.guests[int(data['newid'])] = cfg
            return _R(200, 'UPID:pve1:00000002:00000001:6AF5E100:qmclone:100:root@pam!pegaprox:')
        if path == f'/nodes/pve1/qemu/{CLONE}/remote_migrate':
            how, arg = self.migrate
            if how == 'refuse':
                return _R(500, None, text=arg)
            if how == 'timeout':
                read = timeout[1] if isinstance(timeout, tuple) else (timeout or 10)
                self.clock.t += read
                raise requests.exceptions.ReadTimeout(
                    f"HTTPSConnectionPool(host='10.0.0.1', port=8006): Read timed out. (read timeout={read})")
            runs_for, exit_status, end_read = arg
            self.tasks.append({'upid': MIGRATION, 'start': int(WALL + self.clock.t), 'ends': self.clock.t + runs_for,
                               'exit': exit_status, 'end_read': end_read, 'delete': data.get('delete')})
            return _R(200, MIGRATION)
        return _R(404)

    def delete(self, url, params=None, **kw):
        path = self._path(url)
        self.deleted.append((path, dict(params or {}), self.clock.t))
        m = re.fullmatch(r'/nodes/pve1/qemu/(\d+)', path)
        if m:
            self.guests.pop(int(m.group(1)), None)
            return _R(200, f'UPID:pve1:00000003:00000001:6AF5E200:qmdestroy:{m.group(1)}:root@pam!pegaprox:')
        return _R(200, None)

    def follow(self, target_mgr, source_mgr, token, upid, what, later=False):
        """drop_token_when_done as the run uses it: how the task ended, None when that could
        not be read. A migration that went through took its source with it (delete=1)."""
        task = next(t for t in self.tasks if t['upid'] == upid)
        if not task['end_read']:
            return None
        self.clock.t = max(self.clock.t, task['ends'])
        if task['exit'] == 'OK':
            if task['delete']:
                self.guests.pop(CLONE, None)
            return 'ok', 'OK'
        return 'failed', task['exit']

    def clone_deletes(self):
        return [(p, params, t) for p, params, t in self.deleted if p == f'/nodes/pve1/qemu/{CLONE}']

    def guest_deletes(self):
        return [p for p, _params, _t in self.deleted if re.fullmatch(r'/nodes/pve1/qemu/\d+', p)]

    def task_reads(self):
        return [t for p, t in self.reads if p == '/nodes/pve1/tasks']


class _Target:
    host, api_port, is_connected = 'far.example', 8006, True

    def __init__(self):
        self.logger = logging.getLogger('test.xcrepl_clone.target')
        self.created, self.deleted = [], []

    def _api_get(self, url, params=None, **kw):
        if url.endswith('/cluster/resources'):
            return _R(200, [])
        return _R(404)

    def create_api_token(self, name, **kw):
        self.created.append(name)
        return {'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}

    def delete_api_token(self, name):
        self.deleted.append(name)
        return {'success': True}

    def get_cluster_fingerprint(self):
        return {'success': True, 'host': '10.0.0.11', 'fingerprint': 'AB:CD'}


def _source(pve):
    """A PegaProxManager without its constructor that talks to pve."""
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host='10.0.0.1', api_port=8006, user='root@pam')
    m.current_host = None
    m.is_connected = True
    m.api_timeout = 10
    m._consecutive_failures = 0
    m.logger = logging.getLogger('test.xcrepl_clone.source')
    session = types.SimpleNamespace(get=pve.get, post=pve.post, delete=pve.delete)
    m._create_session = lambda: session
    return m


@pytest.fixture
def run(db, monkeypatch, caplog):
    """A full run of VM 100 to the target cluster; returns what the job recorded."""
    caplog.set_level(logging.INFO)
    clock = _Clock()
    fake_time = types.SimpleNamespace(**{**vars(time), 'sleep': clock.sleep, 'time': clock.time,
                                         'monotonic': clock.monotonic})
    for module in (vms, manager_mod):
        monkeypatch.setattr(module, 'time', fake_time)
    pve, tgt = _Pve(clock), _Target()
    said = []
    # the snapshot, the clone and the destroy are done at once
    monkeypatch.setattr(vms, '_wait_for_task', lambda mgr, upid, **kw: (True, 'OK'))
    monkeypatch.setattr(vms, '_restore_vm_identity', lambda *a, **kw: None)
    monkeypatch.setattr(vms, '_tag_as_replica', lambda *a, **kw: (True, ''))
    monkeypatch.setattr(vms, '_enforce_retention', lambda *a, **kw: None)
    monkeypatch.setattr(vms, '_update_repl_status', lambda _db, job_id, status, error='': said.append((status, error)))
    monkeypatch.setattr(transfer_net, 'migration_route', lambda mgr, node=None: None)
    monkeypatch.setattr(transfer_net, 'drop_token_when_done', pve.follow)
    monkeypatch.setitem(ppglobals.cluster_managers, 'src', _source(pve))
    monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)

    def go():
        vms._execute_replication({'id': 'j1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src',
                                  'target_cluster': 'tgt', 'target_storage': 'far', 'target_node': 't1',
                                  'mode': 'full'})
        return said
    return types.SimpleNamespace(go=go, pve=pve, tgt=tgt, clock=clock, caplog=caplog)


def _said(caplog, level, about):
    return [r.getMessage() for r in caplog.records if r.levelno == level and about in r.getMessage()]


def _removed(run):
    """the clone is gone from the source by a delete of its VMID, and the log says so"""
    deletes = run.pve.clone_deletes()
    assert len(deletes) == 1, f'the clone was deleted {len(deletes)} times'
    assert deletes[0][1] == {'purge': 1, 'destroy-unreferenced-disks': 1}
    assert CLONE not in run.pve.guests and 100 in run.pve.guests
    assert run.pve.guest_deletes() == [f'/nodes/pve1/qemu/{CLONE}']
    assert _said(run.caplog, logging.INFO, f"removed the temporary clone qemu/{CLONE} '{LABEL}' on pve1")
    return True


# --- a run whose migration did not go through ----------------------------------------------

def test_a_migration_the_node_refused_to_start_leaves_no_clone(run):
    said = run.go()
    assert said == [('error', "Migration failed: 500 storage 'far' does not exist on the target")]
    assert _removed(run)
    # the token and the snapshot went as before
    assert run.tgt.deleted == run.tgt.created
    assert [p for p, _q, _t in run.pve.deleted if '/snapshot/' in p]


def test_a_migration_request_that_timed_out_leaves_no_clone(run):
    run.pve.migrate = ('timeout', None)
    said = run.go()
    (status, error), = said
    assert status == 'error' and error.startswith('Migration failed: ')
    assert _removed(run)
    # the node was asked whether a migration of the clone still runs before it went
    at = run.pve.clone_deletes()[0][2]
    assert [t for t in run.pve.task_reads() if t <= at]


def test_a_migration_task_that_failed_leaves_no_clone(run):
    run.pve.migrate = ('task', (120, 'migration aborted', True))
    said = run.go()
    assert said == [('error', 'Migration task failed: migration aborted')]
    assert _removed(run)


def test_a_clone_whose_migration_still_runs_goes_only_once_the_task_has_ended(run):
    """The run could not read the end of the task, the node still lists it running: the
    clone stays until the task has ended, then goes."""
    run.pve.migrate = ('task', (300, 'migration aborted', False))
    said = run.go()
    (status, error), = said
    assert status == 'error' and 'could not be read' in error
    assert _removed(run)
    at = run.pve.clone_deletes()[0][2]
    assert at >= 300
    reads = run.pve.task_reads()
    assert len(reads) > 2 and reads[0] < 300 <= reads[-1]


def test_a_clone_whose_migration_runs_past_the_wait_stays_and_says_so(run):
    wait = getattr(vms, 'CLONE_TASK_WAIT', 600)
    run.pve.migrate = ('task', (wait * 3, 'migration aborted', False))
    run.go()
    assert run.pve.clone_deletes() == [] and CLONE in run.pve.guests
    warned = _said(run.caplog, logging.WARNING, f"temporary clone qemu/{CLONE} '{LABEL}' on pve1 is left")
    assert warned and MIGRATION in warned[0], warned
    assert run.clock.t < wait * 2


def test_a_task_list_that_cannot_be_read_is_no_empty_one(run):
    """Nobody can tell whether a migration of the clone still runs: it stays, with a warning."""
    run.pve.migrate = ('task', (120, 'migration aborted', True))
    run.pve.listable = False
    run.go()
    assert run.pve.clone_deletes() == [] and CLONE in run.pve.guests
    assert _said(run.caplog, logging.WARNING, 'could not be read')


def test_a_direct_clone_goes_by_its_label(run):
    """On storage without clones from a snapshot the clone is made from the guest itself and
    carries the guest's description, not the snapshot's."""
    run.pve.storage_type = 'zfspool'
    run.go()
    assert _removed(run)


# --- never another guest -------------------------------------------------------------------

@pytest.mark.parametrize('change', [{'name': 'db01'}, {'description': 'nightly build\n'}])
def test_a_guest_at_the_clone_vmid_that_is_not_the_clone_stays(run, monkeypatch, change):
    run.pve.migrate = ('task', (120, 'migration aborted', True))
    follow = run.pve.follow

    def replaced(*a, **kw):
        # meanwhile the VMID belongs to another guest
        end = follow(*a, **kw)
        run.pve.guests[CLONE] = dict(run.pve.guests[CLONE], **change)
        return end
    monkeypatch.setattr(transfer_net, 'drop_token_when_done', replaced)
    run.go()
    assert run.pve.clone_deletes() == [] and CLONE in run.pve.guests
    assert _said(run.caplog, logging.WARNING, f'VMID {CLONE} on pve1 is not the temporary clone')


def test_the_source_guest_is_never_touched(run):
    for how in [('refuse', 'no'), ('timeout', None), ('task', (60, 'migration aborted', True))]:
        run.pve.guests = {100: run.pve.guests[100]}
        run.pve.migrate, run.pve.tasks, run.pve.deleted = how, [], []
        run.go()
        assert '/nodes/pve1/qemu/100' not in run.pve.guest_deletes()
        assert 100 in run.pve.guests


# --- a run that went through ---------------------------------------------------------------

def test_a_run_that_went_through_leaves_the_clone_to_proxmox(run):
    run.pve.migrate = ('task', (600, 'OK', True))
    said = run.go()
    assert said == [('ok', '')]
    assert run.pve.clone_deletes() == [] and CLONE not in run.pve.guests
    assert run.pve.task_reads() == []
    assert not _said(run.caplog, logging.WARNING, 'temporary clone')
