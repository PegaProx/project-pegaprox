"""A bulk snapshot delete sends the next delete of a guest only once PVE ended the one before.

PVE answers DELETE .../snapshot/{name} with a task and takes the guest's lock inside that
task (pve-guest-common AbstractConfig::snapshot_delete), so a second delete of the same
guest sent while the first still runs is accepted as well and then ends 'VM is locked
(snapshot-delete)'. POST /api/snapshots/delete handed every snapshot to PVE at once and
counted each accepted task as deleted: select three snapshots of one VM, one went, the
toast said three. Now the snapshots of one guest go one after the other, each once its
task ended, several guests at a time (bounded), and only a task that ended OK counts. A
failure says what PVE said. The policy prune uses the same wait and stops at a guest
whose delete still runs.

The fake cluster below answers like PVE: the delete with a UPID at once, the task status
'running' for a few reads and then 'stopped' with its exit status. The manager's own
_wait_for_task and get_task_status read it.

MK Nov 2026
"""
import logging
import threading
import time
import types

import gevent
import pytest

import pegaprox.core.manager as manager_mod
from pegaprox.api import snapshots as sn
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager

CID = 'cluster_1'
LOCKED = 'VM is locked (snapshot-delete)'


class _Clock:
    """The time module as the manager module sees it, with a sleep that only lets the
    other greenlets run: the 2 s poll of _wait_for_task takes a millisecond here."""

    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def sleep(_seconds):
        gevent.sleep(0.001)


class _Pve:
    """A cluster that runs snapshot deletes like PVE. A delete is answered with a task at
    once; the task takes the guest's lock, so one sent while another task of the guest
    runs ends at once with LOCKED and removes nothing. A task stays 'running' for `reads`
    status reads, then stops with 'OK' (the snapshot is gone) or with what `fail` says
    for it. The task of a (vmid, name) in `never` runs for 5000 reads, far longer than
    any wait of these tests (a read is a millisecond at least). The manager's DELETE
    binds the task to the PegaProx user of the request it runs in (_auto_capture_upid),
    and so does this one."""

    cluster_type = 'proxmox'
    is_connected = True

    def __init__(self, snaps, reads=3, fail=None, never=()):
        self.start = {vmid: set(names) for vmid, names in snaps.items()}
        self.snaps = {vmid: set(names) for vmid, names in snaps.items()}
        self.reads, self.fail, self.never = reads, dict(fail or {}), set(never)
        self.id, self.config = CID, types.SimpleNamespace(name=CID)
        self.host, self.api_port = '10.0.0.1', 8006
        self.logger = logging.getLogger('fake-pve')
        self.tasks = {}
        self.running = {}         # vmid -> the upid holding its lock
        self.collisions = []      # (vmid, name) of deletes sent while the guest was locked
        self.peak = 0             # most guests with a delete running at the same time
        self.sent = []
        self._lock = threading.Lock()

    _wait_for_task = PegaProxManager._wait_for_task
    get_task_status = PegaProxManager.get_task_status
    _auto_capture_upid = PegaProxManager._auto_capture_upid

    def delete_snapshot(self, node, vmid, vm_type, name):
        vmid = int(vmid)
        with self._lock:
            upid = f'UPID:{node}:{len(self.tasks) + 1:08X}:00000001:6730AABB:qmdelsnapshot:{vmid}:root@pam:'
            self.sent.append((vmid, name))
            if vmid in self.running:
                self.collisions.append((vmid, name))
                self.tasks[upid] = {'vmid': vmid, 'name': name, 'left': 0, 'exit': LOCKED, 'holds': False}
            else:
                left = 5000 if (vmid, name) in self.never else self.reads
                self.tasks[upid] = {'vmid': vmid, 'name': name, 'left': left,
                                    'exit': self.fail.get(name, 'OK'), 'holds': True}
                self.running[vmid] = upid
                self.peak = max(self.peak, len(self.running))
        self._auto_capture_upid(types.SimpleNamespace(status_code=200, headers={'Content-Type': 'application/json'},
                                                      json=lambda: {'data': upid}))
        return {'success': True, 'task': upid}

    def _api_get(self, url, **kw):
        upid = url.split('/tasks/', 1)[1].rsplit('/status', 1)[0]
        with self._lock:
            t = self.tasks[upid]
            if t['left'] > 0:
                t['left'] -= 1
                data = {'status': 'running', 'upid': upid}
            else:
                if t['holds']:
                    t['holds'] = False
                    self.running.pop(t['vmid'], None)
                    if t['exit'] == 'OK':
                        self.snaps[t['vmid']].discard(t['name'])
                data = {'status': 'stopped', 'exitstatus': t['exit'], 'upid': upid}
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': data})

    def gone(self):
        return sum(1 for vmid, names in self.start.items() for n in names if n not in self.snaps[vmid])


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch):
    monkeypatch.setattr(manager_mod, 'time', _Clock())


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('snap_adm', role='admin'))


def _items(*pairs):
    return [{'cluster_id': CID, 'node': 'pve1', 'vmid': vmid, 'vm_type': 'qemu', 'snapshot_name': name}
            for vmid, name in pairs]


def _bulk(admin, *pairs):
    r = admin.post('/api/snapshots/delete', json={'snapshots': _items(*pairs)})
    return r.status_code, r.get_json()


# --- the bulk route -------------------------------------------------------------------------

def test_three_snapshots_of_one_guest_are_all_gone_and_counted(api, admin):
    pve = api.set_manager(CID, _Pve({100: ['s1', 's2', 's3']}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'), (100, 's3'))
    assert pve.collisions == [], 'a delete went out while the guest was still locked by the one before'
    assert pve.snaps[100] == set()
    assert code == 200 and body['deleted'] == 3 == pve.gone(), body
    assert not body['errors']


def test_only_a_task_that_ended_ok_counts_and_a_failure_says_what_pve_said(api, admin):
    said = 'zfs error: could not find any snapshots to destroy; check snapshot names.'
    pve = api.set_manager(CID, _Pve({100: ['s1', 's2', 's3']}, fail={'s2': said}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'), (100, 's3'))
    assert pve.collisions == []
    assert pve.snaps[100] == {'s2'}
    assert code == 200 and body['deleted'] == 2 == pve.gone(), body
    assert body['errors'] == [f'Failed to delete s2 of VM 100: {said}']


def test_nothing_gone_is_a_500_with_the_reason_per_snapshot(api, admin):
    said = 'VM is locked (backup)'
    pve = api.set_manager(CID, _Pve({100: ['s1', 's2']}, fail={'s1': said, 's2': said}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'))
    assert code == 500 and body['success'] is False and pve.gone() == 0
    assert body['errors'] == [f'Failed to delete s1 of VM 100: {said}', f'Failed to delete s2 of VM 100: {said}']


def test_guests_run_side_by_side_but_no_more_than_the_bound(api, admin, monkeypatch):
    monkeypatch.setattr(sn, 'BULK_DELETE_GUESTS', 2, raising=False)
    pve = api.set_manager(CID, _Pve({100: ['a', 'b'], 101: ['a', 'b'], 102: ['a', 'b']}))
    code, body = _bulk(admin, (100, 'a'), (101, 'a'), (102, 'a'), (100, 'b'), (101, 'b'), (102, 'b'))
    assert pve.collisions == []
    assert code == 200 and body['deleted'] == 6 == pve.gone(), body
    assert pve.peak == 2, f'{pve.peak} guests had a delete running at the same time, the bound is 2'


def test_a_delete_that_still_runs_is_not_counted_and_the_next_of_that_guest_waits(api, admin, monkeypatch):
    monkeypatch.setattr(sn, 'SNAP_DELETE_WAIT', 0.3, raising=False)
    pve = api.set_manager(CID, _Pve({100: ['s1', 's2'], 101: ['s1']}, never={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'), (101, 's1'))
    assert pve.collisions == []
    assert (100, 's2') not in pve.sent, 'the next delete went out while the guest was still locked'
    assert code == 200 and body['deleted'] == 1 == pve.gone(), body
    assert pve.snaps[101] == set()
    assert len(body['errors']) == 2
    assert body['errors'][0].startswith('Failed to delete s1 of VM 100: its delete task still runs in Proxmox')
    assert body['errors'][1] == 'Failed to delete s2 of VM 100: not started, the delete of s1 still runs'


def test_nothing_new_starts_once_the_request_ran_out_of_time(api, admin, monkeypatch):
    monkeypatch.setattr(sn, 'BULK_DELETE_SECONDS', 0.3, raising=False)
    monkeypatch.setattr(sn, 'BULK_DELETE_GUESTS', 1, raising=False)
    pve = api.set_manager(CID, _Pve({100: ['s1'], 101: ['s9']}, never={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'), (101, 's9'))
    assert pve.sent == [(100, 's1')]
    assert code == 500 and pve.gone() == 0
    assert body['errors'][0].startswith('Failed to delete s1 of VM 100: its delete task still runs in Proxmox')
    assert body['errors'][1] == 'Failed to delete s9 of VM 101: not started, the request ran out of its 0.3s'


def test_each_deleted_snapshot_is_in_the_audit_log_and_a_failed_one_is_not(api, admin, db):
    api.set_manager(CID, _Pve({100: ['s1', 's2']}, fail={'s2': 'snapshot is protected'}))
    _bulk(admin, (100, 's1'), (100, 's2'))
    rows = db.conn.execute("SELECT details FROM audit_log WHERE action='snapshot.deleted'").fetchall()
    assert [r['details'] for r in rows] == ["QEMU 100 - snapshot 's1' deleted [cluster_1]"]


def test_each_delete_task_is_bound_to_the_user_who_asked(api, admin):
    """The deletes run in greenlets of their own, where the manager's DELETE does not see the
    request and so cannot name who asked."""
    from pegaprox.api.helpers import get_task_user
    pve = api.set_manager(CID, _Pve({100: ['s1', 's2']}))
    _bulk(admin, (100, 's1'), (100, 's2'))
    assert len(pve.tasks) == 2
    assert {get_task_user(upid) for upid in pve.tasks} == {'snap_adm'}


def test_the_checks_still_come_first(api, admin):
    """A row that fails a check is not deleted, the rows beside it are."""
    pve = api.set_manager(CID, _Pve({100: ['s1'], 101: ['s1']}))
    items = _items((100, 's1'), (101, 's1'))
    items[1]['snapshot_name'] = 'a/b'
    r = admin.post('/api/snapshots/delete', json={'snapshots': items + [{'cluster_id': 'nope', 'vmid': 1}]})
    body = r.get_json()
    assert pve.sent == [(100, 's1')]
    assert body['deleted'] == 1
    assert body['errors'] == ['Invalid node, guest type, VMID or snapshot name', 'Cluster nope not found']


# --- the shared pieces ------------------------------------------------------------------------

def test_a_cluster_that_deletes_within_the_call_counts_what_it_accepted():
    """An XCP-ng pool answers {'success': True} once the snapshot is gone and an error otherwise."""
    gone = []
    xcp = types.SimpleNamespace(delete_snapshot=lambda node, vmid, kind, name: (
        gone.append(name) or {'success': True}) if name != 'bad' else {'error': 'Snapshot bad not found'})
    jobs = [[{'mgr': xcp, 'node': 'h1', 'vmid': 'uuid-1', 'vm_type': 'qemu', 'name': n} for n in ('a', 'bad', 'b')]]
    out = sn.delete_per_guest(jobs)
    assert [(j['name'], j['state'], j['why']) for j in out] == [
        ('a', 'gone', ''), ('bad', 'failed', 'Snapshot bad not found'), ('b', 'gone', '')]
    assert gone == ['a', 'b']


def test_an_exception_of_one_delete_is_an_error_of_that_snapshot_only():
    def delete(node, vmid, kind, name):
        if name == 'x':
            raise ConnectionError('node unreachable')
        return {'success': True}
    m = types.SimpleNamespace(delete_snapshot=delete)
    out = sn.delete_per_guest([[{'mgr': m, 'node': 'n', 'vmid': 1, 'vm_type': 'qemu', 'name': n} for n in ('x', 'y')]])
    assert [(j['state'], j['why']) for j in out] == [('error', 'node unreachable'), ('gone', '')]


# --- the policy prune ---------------------------------------------------------------------

PID = 'abcdef012345'
PREFIX = f'pegaprox-{PID[:12]}-'


class _Owned(_Pve):
    def list_snapshots(self, node, vmid, kind):
        now = time.time()
        return [{'name': n, 'snaptime': now - int(n.rsplit('-', 1)[1]) * 86400} for n in sorted(self.snaps[vmid])]


@pytest.fixture
def _lease(monkeypatch):
    monkeypatch.setattr(ha, 'confirm_step', lambda what: True)


def test_the_prune_names_what_pve_said_for_a_delete_that_failed(_lease):
    names = [f'{PREFIX}{i}' for i in range(4)]
    said = 'rbd error: error setting snapshot context: (2) No such file or directory'
    pve = _Owned({100: names}, fail={names[2]: said})
    errors = []
    pruned = sn._prune(pve, 'pve1', 100, 'qemu', {'id': PID, 'retention_count': 1, 'retention_days': 0}, errors)
    assert pve.collisions == []
    assert pruned == 2 and pve.snaps[100] == {names[0], names[2]}
    assert errors == [f'{names[2]}: {said}']


def test_the_prune_stops_at_a_guest_whose_delete_still_runs(_lease, monkeypatch):
    monkeypatch.setattr(sn, 'SNAP_DELETE_WAIT', 0.3, raising=False)
    names = [f'{PREFIX}{i}' for i in range(4)]
    pve = _Owned({100: names}, never={(100, names[1])})
    errors = []
    pruned = sn._prune(pve, 'pve1', 100, 'qemu', {'id': PID, 'retention_count': 1, 'retention_days': 0}, errors)
    assert pve.sent == [(100, names[1])], 'the prune went on while the guest was still locked'
    assert pruned == 0
    assert errors[0].startswith(f'{names[1]}: its delete task still runs in Proxmox')
    assert errors[1:] == [f'{n}: not started, the delete of {names[1]} still runs' for n in names[2:]]
