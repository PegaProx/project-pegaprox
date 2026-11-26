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
import requests

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
    assert [(s['snapshot_name'], s['state']) for s in body['started']] == [('s1', 'running')]
    assert body['started'][0]['why'].startswith('its delete task still runs in Proxmox')
    assert body['errors'] == ['Failed to delete s2 of VM 100: not started, the delete of s1 still runs']


def test_nothing_new_starts_once_the_request_ran_out_of_time(api, admin, monkeypatch):
    """One guest at a time, the second behind a delete that does not end. Once that one is let
    go there is no time left to wait for another task, so the second is not sent."""
    clock = _Virtual()
    monkeypatch.setattr(manager_mod, 'time', clock)
    monkeypatch.setattr(sn, 'time', clock)
    monkeypatch.setattr(sn, 'BULK_DELETE_GUESTS', 1, raising=False)
    pve = api.set_manager(CID, _Pve({100: ['s1'], 101: ['s9']}, never={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'), (101, 's9'))
    assert pve.sent == [(100, 's1')]
    assert code == 202 and pve.gone() == 0
    assert [(s['snapshot_name'], s['state']) for s in body['started']] == [('s1', 'running')]
    assert body['errors'] == ['Failed to delete s9 of VM 101: not started, the request ran out of its 90s']


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


# --- an XCP-ng pool, the federation's exit and the time a request takes -------------------

class _OneCallPool:
    """An XCP-ng pool as XcpngManager talks to it: every call goes over the one XML-RPC
    connection of its session, and a call that comes while another is still on it breaks
    both (http.client says Request-sent to the one, Idle to the other). A delete runs
    within the call, there is no task to wait for."""

    cluster_type = 'xcpng'
    is_connected = True

    def __init__(self, snaps):
        self.snaps = {str(vmid): set(names) for vmid, names in snaps.items()}
        self.config = types.SimpleNamespace(name='xcp')
        self.on_the_line = None
        self.broken = []

    def delete_snapshot(self, node, vmid, vm_type='qemu', snapname=''):
        if self.on_the_line is not None:
            self.broken.append((vmid, snapname))
            self.on_the_line = None
            return {'error': 'Request-sent'}
        me = self.on_the_line = (vmid, snapname)
        gevent.sleep(0.005)             # the round trip to the pool
        if self.on_the_line != me:
            return {'error': 'Idle'}
        self.on_the_line = None
        self.snaps[str(vmid)].discard(snapname)
        return {'success': True}


def test_the_guests_of_an_xcp_ng_pool_go_one_after_the_other(api, admin):
    pool = api.set_manager(CID, _OneCallPool({'u1': ['a', 'b'], 'u2': ['a', 'b'], 'u3': ['a', 'b']}))
    code, body = _bulk(admin, ('u1', 'a'), ('u2', 'a'), ('u3', 'a'), ('u1', 'b'), ('u2', 'b'), ('u3', 'b'))
    assert pool.broken == [], f'calls came while another was on the session: {pool.broken}'
    assert code == 200 and body['deleted'] == 6, body
    assert not body['errors']
    assert all(not left for left in pool.snaps.values())


def test_an_xcp_ng_session_of_the_real_xenapi_takes_every_delete(monkeypatch):
    """The same with XenAPI.Session itself, talking to a pool on this host."""
    XenAPI = pytest.importorskip('XenAPI')
    from socketserver import ThreadingMixIn
    from xmlrpc.server import SimpleXMLRPCServer
    import pegaprox.core.xcpng as xcpng_mod
    from pegaprox.core.xcpng import XcpngManager

    snaps = {f'OpaqueRef:vm-{u}': {f'OpaqueRef:s-{u}-{n}': n for n in ('a', 'b')} for u in ('u1', 'u2', 'u3')}

    class Xapi:
        def _dispatch(self, method, params):
            time.sleep(0.01)
            ok = lambda v: {'Status': 'Success', 'Value': v}
            if method == 'session.login_with_password':
                return ok('OpaqueRef:sess')
            if method == 'VM.get_by_uuid':
                return ok(f'OpaqueRef:vm-{params[1]}')
            if method == 'VM.get_snapshots':
                return ok(list(snaps[params[1]]))
            for vm in snaps.values():
                if params[-1] in vm:
                    if method == 'VM.get_name_label':
                        return ok(vm[params[-1]])
                    if method == 'VM.destroy':
                        vm.pop(params[-1])
                        return ok('')
            return {'Status': 'Failure', 'ErrorDescription': ['UNKNOWN', method]}

    class Server(ThreadingMixIn, SimpleXMLRPCServer):
        daemon_threads = True

    srv = Server(('127.0.0.1', 0), logRequests=False, allow_none=True)
    srv.register_instance(Xapi())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        m = XcpngManager.__new__(XcpngManager)
        m.id, m.stop_event, m.is_connected = 'xcp1', threading.Event(), True
        m._last_keepalive = time.time() + 3600
        m.logger = logging.getLogger('xcp-test')
        m._session = XenAPI.Session(f'http://127.0.0.1:{srv.server_address[1]}/')
        m._session.xenapi.login_with_password('root', 'pw', '1.0', 'PegaProx')
        monkeypatch.setattr(xcpng_mod, 'get_db', lambda: types.SimpleNamespace(xcpng_resolve_vmid=lambda cid, vmid: str(vmid)))
        jobs = [[{'mgr': m, 'cluster_id': 'xcp1', 'node': 'h1', 'vmid': u, 'vm_type': 'qemu', 'name': n} for n in ('a', 'b')]
                for u in ('u1', 'u2', 'u3')]
        out = sn.delete_per_guest(jobs)
    finally:
        srv.shutdown()
        srv.server_close()
    assert [(j['vmid'], j['name'], j['state'], j['why']) for j in out] == [
        (u, n, 'gone', '') for u in ('u1', 'u2', 'u3') for n in ('a', 'b')]
    assert all(not vm for vm in snaps.values())


class _Fenced(_Pve):
    """_Pve behind the federation's exit: the transport asks guard_exit before the DELETE
    leaves, and the manager answers a refusal as a failed delete."""

    def delete_snapshot(self, node, vmid, vm_type, name):
        from pegaprox.core import federation
        try:
            federation.guard_exit(CID, f'DELETE /nodes/{node}/{vm_type}/{vmid}/snapshot/{name}')
        except federation.LeaseRefused as e:
            return {'success': False, 'error': str(e)}
        return super().delete_snapshot(node, vmid, vm_type, name)


def test_a_delete_the_federation_refuses_is_its_409_also_while_ha_is_off(api, admin, monkeypatch):
    """The deletes run in workers of their own. Without the request's note of the refusal the
    caller heard a 500 of the route instead of FED_NO_LEASE."""
    from pegaprox.core import federation
    monkeypatch.setattr(federation, 'enabled', lambda: True)
    monkeypatch.setattr(federation, 'dr_enabled', lambda: True)
    monkeypatch.setattr(federation, 'takes_writes_for', lambda cid: False)
    assert ha.guard_on() is False
    pve = api.set_manager(CID, _Fenced({100: ['s1'], 101: ['s1']}))
    code, body = _bulk(admin, (100, 's1'), (101, 's1'))
    assert pve.sent == []
    assert code == 409 and body.get('code') == 'FED_NO_LEASE', (code, body)


class _Virtual:
    """A clock that moves only when somebody sleeps on it: the time a wait would take,
    without taking it. One guest at a time sleeps on it in these tests."""

    def __init__(self):
        self.now = 1_000_000.0

    def __getattr__(self, name):
        return getattr(time, name)

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        gevent.sleep(0)


class _Timed(_Pve):
    """_Pve whose delete tasks take `dur` seconds of `clock` instead of a number of reads."""

    def __init__(self, snaps, clock, dur):
        super().__init__(snaps, reads=0)
        self.clock, self.dur = clock, dur

    def delete_snapshot(self, node, vmid, vm_type, name):
        res = super().delete_snapshot(node, vmid, vm_type, name)
        self.tasks[res['task']]['ends'] = self.clock.now + self.dur
        return res

    def _api_get(self, url, **kw):
        t = self.tasks[url.split('/tasks/', 1)[1].rsplit('/status', 1)[0]]
        if t['holds']:
            t['left'] = 1 if self.clock.now < t['ends'] else 0
        return super()._api_get(url, **kw)


def test_a_delete_task_of_half_a_second_is_seen_ended_within_a_second(monkeypatch):
    """The snapshots of a guest go one after the other, so the time between the end of a
    task and our next look at it is paid once per snapshot. With a status read every 2s
    a guest of thirty snapshots took a minute whatever PVE needed."""
    clock = _Virtual()
    monkeypatch.setattr(manager_mod, 'time', clock)
    pve = _Timed({100: ['s1']}, clock, 0.5)
    res = pve.delete_snapshot('pve1', 100, 'qemu', 's1')
    sent = clock.now
    assert sn._delete_done(pve, 'pve1', res) == ('gone', '')
    assert clock.now - sent <= 1.0, f'the end of a 0.5s task was seen {clock.now - sent:.2f}s after it was sent'


def test_sixteen_guests_have_their_delete_running_side_by_side(api, admin):
    """The overview lists up to 200 snapshots, of as many guests: four at a time and a wait
    of seconds each made that minutes."""
    pve = api.set_manager(CID, _Pve({100 + i: ['s1'] for i in range(16)}))
    code, body = _bulk(admin, *[(100 + i, 's1') for i in range(16)])
    assert code == 200 and body['deleted'] == 16 == pve.gone(), body
    assert pve.peak == 16, f'only {pve.peak} guests had their delete running at the same time'


def test_the_request_answers_before_a_proxy_gives_up_on_it(api, admin, monkeypatch):
    """A delete task that does not end is not waited for longer than the request may take:
    Cloudflare answers 524 after 100s, Firefox gives up after 300s, and the UI then said
    'Failed' while the server went on."""
    clock = _Virtual()
    monkeypatch.setattr(manager_mod, 'time', clock)
    monkeypatch.setattr(sn, 'time', clock)
    pve = api.set_manager(CID, _Pve({100: ['s1', 's2']}, never={(100, 's1')}))
    started = clock.now
    code, body = _bulk(admin, (100, 's1'), (100, 's2'))
    took = clock.now - started
    assert took <= sn.BULK_DELETE_SECONDS, f'the request took {took:.0f}s'
    assert pve.sent == [(100, 's1')]
    assert code == 202 and pve.gone() == 0
    assert [(s['snapshot_name'], s['state']) for s in body['started']] == [('s1', 'running')]
    assert body['errors'] == ['Failed to delete s2 of VM 100: not started, the delete of s1 still runs']


# --- a delete Proxmox took and we did not see end ------------------------------------------
# Before the bulk delete waited for its tasks, every delete Proxmox took was audited as
# 'snapshot.deleted'. One still running when the request answers, or whose task cannot be
# read, is neither deleted nor failed: it is in the audit log as started, and the answer says
# so per snapshot instead of naming it among the failures. One whose task Proxmox ended with
# an error is a failure, and in the audit log as failed; a DELETE Proxmox refused outright
# started nothing there and is not. A DELETE Proxmox did not answer may or may not have
# started (further down): in the audit log as sent, never as started.

class _Blind(_Pve):
    """_Pve whose task status cannot be read for the deletes in `blind` (the node stops
    answering /tasks once the delete went out)."""

    def __init__(self, snaps, blind=(), **kw):
        super().__init__(snaps, **kw)
        self.blind = set(blind)

    def _api_get(self, url, **kw):
        upid = url.split('/tasks/', 1)[1].rsplit('/status', 1)[0]
        t = self.tasks[upid]
        if (t['vmid'], t['name']) in self.blind:
            return types.SimpleNamespace(status_code=595, json=lambda: {})
        return super()._api_get(url, **kw)


def _audit(db, action):
    return [r['details'] for r in db.conn.execute(
        'SELECT details FROM audit_log WHERE action=? ORDER BY id', (action,)).fetchall()]


def test_a_delete_still_running_in_proxmox_is_audited_as_started_and_answered_as_such(api, admin, db, monkeypatch):
    monkeypatch.setattr(sn, 'SNAP_DELETE_WAIT', 0.3, raising=False)
    pve = api.set_manager(CID, _Pve({100: ['s1']}, never={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'))
    upid = next(iter(pve.tasks))
    assert code == 202, (code, body)
    assert body['success'] is True and body['deleted'] == 0 and not body['errors'], body
    assert [{k: s[k] for k in ('cluster_id', 'node', 'vmid', 'vm_type', 'snapshot_name', 'state', 'task')}
            for s in body['started']] == [
        {'cluster_id': CID, 'node': 'pve1', 'vmid': 100, 'vm_type': 'qemu', 'snapshot_name': 's1',
         'state': 'running', 'task': upid}]
    assert _audit(db, 'snapshot.delete_started') == [
        f"QEMU 100 - snapshot 's1' delete started, still running in Proxmox ({upid}) [cluster_1]"]
    assert _audit(db, 'snapshot.deleted') == []


def test_a_delete_whose_task_cannot_be_read_is_audited_as_started_with_its_result_not_read(api, admin, db, monkeypatch):
    monkeypatch.setattr(sn, 'SNAP_DELETE_WAIT', 0.3, raising=False)
    pve = api.set_manager(CID, _Blind({100: ['s1', 's2'], 101: ['s1']}, blind={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'), (101, 's1'))
    upid = next(u for u, t in pve.tasks.items() if t['vmid'] == 100)
    assert (100, 's2') not in pve.sent, 'the next delete of the guest went out while its lock may still be held'
    assert code == 200 and body['deleted'] == 1, body
    assert body['errors'] == ['Failed to delete s2 of VM 100: not started, the delete of s1 may still run']
    assert [(s['vmid'], s['state'], s['task']) for s in body['started']] == [(100, 'unread', upid)]
    assert 'status could not be read' in body['started'][0]['why']
    assert _audit(db, 'snapshot.delete_started') == [
        f"QEMU 100 - snapshot 's1' delete started, result not read ({upid}) [cluster_1]"]
    assert _audit(db, 'snapshot.deleted') == ["QEMU 101 - snapshot 's1' deleted [cluster_1]"]


def test_a_delete_whose_task_proxmox_ended_with_an_error_is_a_failure_and_audited_as_failed(api, admin, db):
    """PVE took the delete and its task failed half way: AbstractConfig::snapshot_delete set
    snapstate 'delete' and removed the snapshot of one disk before the second failed. Who
    started that is in the audit log, as before #1347 every delete PVE took was."""
    said = 'rbd error: error setting snapshot context: (2) No such file or directory'
    pve = api.set_manager(CID, _Pve({100: ['pre-upgrade']}, fail={'pre-upgrade': said}))
    code, body = _bulk(admin, (100, 'pre-upgrade'))
    upid = next(iter(pve.tasks))
    assert code == 500 and body['success'] is False
    assert body['errors'] == [f'Failed to delete pre-upgrade of VM 100: {said}']
    assert _audit(db, 'snapshot.delete_failed') == [
        f"QEMU 100 - snapshot 'pre-upgrade' delete failed in Proxmox: {said} ({upid}) [cluster_1]"]
    assert _audit(db, 'snapshot.delete_started') == [] and _audit(db, 'snapshot.deleted') == []


class _Refusing(_Pve):
    """_Pve that refuses the DELETE of the snapshots in `refuse` itself, with no task."""

    def __init__(self, snaps, refuse=(), **kw):
        super().__init__(snaps, **kw)
        self.refuse = set(refuse)

    def delete_snapshot(self, node, vmid, vm_type, name):
        if (int(vmid), name) in self.refuse:
            return {'success': False, 'error': '{"data":null,"errors":{"snapname":"invalid format"}}'}
        return super().delete_snapshot(node, vmid, vm_type, name)


def test_a_delete_proxmox_refused_without_a_task_is_a_failure_and_not_audited(api, admin, db):
    pve = api.set_manager(CID, _Refusing({100: ['s1']}, refuse={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'))
    assert code == 500 and body['success'] is False
    assert body['errors'] == ['Failed to delete s1 of VM 100: {"data":null,"errors":{"snapname":"invalid format"}}']
    assert pve.tasks == {} and pve.gone() == 0
    assert _audit(db, 'snapshot.delete_failed') == [] and _audit(db, 'snapshot.delete_started') == []
    assert _audit(db, 'snapshot.deleted') == []


def test_a_delete_still_on_its_way_when_the_request_answers_is_unanswered(monkeypatch):
    """The workers are not stopped when the request has to answer. A delete whose call to
    Proxmox has not come back by then may or may not have reached it: unanswered, not
    started. The snapshot after it in the same guest was not sent."""
    import pegaprox.utils.concurrent as conc
    real = conc.run_per_node
    monkeypatch.setattr(conc, 'run_per_node', lambda fns, max_concurrent, timeout: real(fns, max_concurrent=max_concurrent, timeout=0.2))
    monkeypatch.setattr(sn, 'BULK_DELETE_SECONDS', 0.1, raising=False)
    sent = []

    def delete(node, vmid, kind, name):
        sent.append(name)
        gevent.sleep(0.6)
        return {'success': True}
    m = types.SimpleNamespace(delete_snapshot=delete)
    jobs = [[{'mgr': m, 'node': 'n', 'vmid': 1, 'vm_type': 'qemu', 'name': n} for n in ('a', 'b')]]
    out = sn.delete_per_guest(jobs)
    assert [(j['name'], j['state']) for j in out] == [('a', 'unanswered'), ('b', 'skipped')]
    assert out[0]['why'] == ('its delete was on its way, no answer from Proxmox before the request ended: '
                             'it may or may not have started')
    gevent.sleep(0.8)
    assert sent == ['a'], 'the worker started a delete after the request had answered'


# --- a slow node and a DELETE PVE did not answer in time --------------------------------------

class _SlowReads(_Pve):
    """_Pve on a node that answers task status reads only after the manager's timeout (slow
    ZFS): each read costs `api_timeout` seconds of `clock` and ends in a ReadTimeout. Its
    DELETE takes `took` seconds."""

    api_timeout = 10

    def __init__(self, snaps, clock, took, **kw):
        super().__init__(snaps, **kw)
        self.clock, self.took = clock, took

    def delete_snapshot(self, node, vmid, vm_type, name):
        self.clock.now += self.took
        return super().delete_snapshot(node, vmid, vm_type, name)

    def _api_get(self, url, **kw):
        self.clock.now += self.api_timeout
        raise requests.exceptions.ReadTimeout(f'Read timed out. (read timeout={self.api_timeout})')


def test_slow_status_reads_do_not_carry_the_answer_past_the_bound_of_the_request(api, admin, db, monkeypatch):
    """_wait_for_task runs past its timeout by a read and its 5s back-off when reads are slow,
    and the read after it took another 10s: behind Cloudflare (100s) the browser got a 524
    instead of the answer, while the server wrote its audit rows."""
    clock = _Virtual()
    monkeypatch.setattr(manager_mod, 'time', clock)
    monkeypatch.setattr(sn, 'time', clock)
    pve = api.set_manager(CID, _SlowReads({100: ['s1']}, clock, took=9))
    started = clock.now
    code, body = _bulk(admin, (100, 's1'))
    took = clock.now - started
    upid = next(iter(pve.tasks))
    assert took <= sn.BULK_DELETE_SECONDS, f'the request took {took:.0f}s'
    assert code == 202, (code, body)
    assert [(s['snapshot_name'], s['state'], s['task']) for s in body['started']] == [('s1', 'unread', upid)]
    assert _audit(db, 'snapshot.delete_started') == [
        f"QEMU 100 - snapshot 's1' delete started, result not read ({upid}) [cluster_1]"]


def _manager(api_delete):
    # what PegaProxManager.delete_snapshot reads of its manager
    return types.SimpleNamespace(host='10.0.0.1', api_port=8006, is_connected=True, _api_delete=api_delete)


def _raise(exc):
    def call(url, **kw):
        raise exc
    return call


def test_the_manager_tells_a_delete_pve_did_not_answer_from_one_that_could_not_connect():
    """A ReadTimeout is no answer in time, and no proof the DELETE went out either (urllib3
    raises it also for a TLS handshake that hung, see below): it may or may not have started,
    so it is unanswered and not a refusal. A connect timeout or a refused connection sent
    nothing and stays a failure."""
    res = PegaProxManager.delete_snapshot(_manager(_raise(requests.exceptions.ReadTimeout('Read timed out.'))),
                                          'pve1', 100, 'qemu', 's1')
    assert res['success'] is False and res.get('unanswered') is True, res
    for exc in (requests.exceptions.ConnectTimeout('Connect timed out'), requests.exceptions.ConnectionError('refused')):
        res = PegaProxManager.delete_snapshot(_manager(_raise(exc)), 'pve1', 100, 'qemu', 's1')
        assert res['success'] is False and not res.get('unanswered'), res


class _NoAnswer(_Pve):
    """_Pve behind the manager's own DELETE. For the snapshots in `slow` PVE starts the task
    but answers after the manager's timeout (busy pmxcfs), so requests raises ReadTimeout."""

    delete_snapshot = PegaProxManager.delete_snapshot

    def __init__(self, snaps, slow=(), **kw):
        super().__init__(snaps, **kw)
        self.slow = set(slow)

    def _api_delete(self, url, **kw):
        node, kind, vmid, _, name = url.split('/')[-5:]
        upid = _Pve.delete_snapshot(self, node, int(vmid), kind, name)['task']
        if (int(vmid), name) in self.slow:
            raise requests.exceptions.ReadTimeout('Read timed out. (read timeout=10)')
        return types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': upid})


NOT_ANSWERED = 'its delete was sent, no answer from Proxmox: it may or may not have started'
SENT_AUDIT = "QEMU 100 - snapshot 's1' delete sent, no answer from Proxmox: it may or may not have started [cluster_1]"


def test_a_delete_pve_did_not_answer_in_time_is_sent_unanswered_and_the_guest_waits(api, admin, db):
    pve = api.set_manager(CID, _NoAnswer({100: ['s1', 's2'], 101: ['s1']}, slow={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'), (101, 's1'))
    assert pve.collisions == [] and (100, 's2') not in pve.sent, 'the next delete went into the lock of the unanswered one'
    assert code == 200 and body['deleted'] == 1 and pve.snaps[101] == set(), body
    assert [(s['vmid'], s['snapshot_name'], s['state'], s['task']) for s in body['started']] == [(100, 's1', 'unanswered', None)]
    assert body['started'][0]['why'].startswith(NOT_ANSWERED)
    assert body['errors'] == ['Failed to delete s2 of VM 100: not started, the delete of s1 may still run']
    assert body['message'] == ('1 snapshot(s) deleted, 1 delete(s) sent with no answer from Proxmox, '
                               'they may or may not have started')
    assert _audit(db, 'snapshot.delete_sent') == [SENT_AUDIT]
    assert _audit(db, 'snapshot.delete_started') == []


class _OwnedNoAnswer(_NoAnswer, _Owned):
    pass


def test_the_prune_stops_at_a_guest_whose_delete_pve_did_not_answer(_lease):
    names = [f'{PREFIX}{i}' for i in range(4)]
    pve = _OwnedNoAnswer({100: names}, slow={(100, names[1])})
    errors = []
    pruned = sn._prune(pve, 'pve1', 100, 'qemu', {'id': PID, 'retention_count': 1, 'retention_days': 0}, errors)
    assert pve.sent == [(100, names[1])], 'the prune went on into the lock of the unanswered delete'
    assert pruned == 0
    assert errors[0].startswith(f'{names[1]}: {NOT_ANSWERED}')
    assert errors[1:] == [f'{n}: not started, the delete of {names[1]} may still run' for n in names[2:]]


# --- a ReadTimeout before the DELETE went out -----------------------------------------------
# urllib3 2.x does the TLS handshake of a new pooled connection under the read timeout and
# raises ReadTimeoutError when it hangs, which requests raises as ReadTimeout: the same
# exception as a DELETE PVE did not answer, while here only the ClientHello was sent. So the
# bulk delete may not call it started. It still holds the guest's next snapshots back: from
# the exception alone the two cases cannot be told apart.

@pytest.fixture
def mute_tls():
    """A listener on 127.0.0.1 that takes the connection and the ClientHello and never answers
    the TLS handshake. Yields (port, what it received)."""
    import socket
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    got, conns = [], []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
                conns.append(c)
                got.append(c.recv(65536))
            except OSError:
                return
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1], got
    srv.close()
    for c in conns:
        c.close()


class _MuteTls(_NoAnswer):
    """_NoAnswer whose DELETE of the snapshots in `mute` goes to `port` with requests, where the
    TLS handshake never ends: the fake PVE never sees it."""

    def __init__(self, snaps, port, mute=(), **kw):
        super().__init__(snaps, **kw)
        self.port, self.mute = port, set(mute)

    def _api_delete(self, url, **kw):
        node, kind, vmid, _, name = url.split('/')[-5:]
        if (int(vmid), name) in self.mute:
            return requests.Session().delete(f'https://127.0.0.1:{self.port}/api2/json/nodes/{node}/{kind}/{vmid}'
                                             f'/snapshot/{name}', timeout=0.5)
        return super()._api_delete(url, **kw)


def test_a_read_timeout_of_the_tls_handshake_is_raised_before_the_delete_went_out(mute_tls):
    port, got = mute_tls
    with pytest.raises(requests.exceptions.ReadTimeout):
        requests.Session().delete(f'https://127.0.0.1:{port}/api2/json/nodes/pve1/qemu/100/snapshot/s1', timeout=0.5)
    # one TLS record, a handshake (0x16) holding a ClientHello (0x01): no request went out
    assert len(got) == 1 and got[0][0] == 0x16 and got[0][5] == 0x01, got


def test_a_delete_that_hung_in_the_tls_handshake_is_not_audited_as_started(api, admin, db, mute_tls):
    port, got = mute_tls
    pve = api.set_manager(CID, _MuteTls({100: ['s1', 's2'], 101: ['s1']}, port, mute={(100, 's1')}))
    code, body = _bulk(admin, (100, 's1'), (100, 's2'), (101, 's1'))
    assert len(got) == 1 and got[0][0] == 0x16, 'the DELETE did not hang in the TLS handshake'
    assert (100, 's1') not in pve.sent and 's1' in pve.snaps[100], 'PVE got the DELETE after all'
    # what PVE may still be doing cannot be told from the exception: the guest's next snapshot waits
    assert (100, 's2') not in pve.sent and pve.snaps[100] == {'s1', 's2'}, 'the next delete of the guest went out'
    assert body['errors'] == ['Failed to delete s2 of VM 100: not started, the delete of s1 may still run']
    assert code == 200 and body['deleted'] == 1 and pve.snaps[101] == set(), body
    assert [(s['vmid'], s['snapshot_name'], s['state'], s['task']) for s in body['started']] == [(100, 's1', 'unanswered', None)]
    assert body['started'][0]['why'].startswith(NOT_ANSWERED)
    assert 'started in Proxmox' not in body['message'], body['message']
    assert _audit(db, 'snapshot.delete_started') == []
    assert _audit(db, 'snapshot.delete_sent') == [SENT_AUDIT]


def test_the_prune_does_not_call_a_delete_that_hung_in_the_tls_handshake_started(_lease, mute_tls):
    port, got = mute_tls
    names = [f'{PREFIX}{i}' for i in range(3)]

    class Pve(_MuteTls, _Owned):
        pass
    pve = Pve({100: names}, port, mute={(100, names[1])})
    errors = []
    pruned = sn._prune(pve, 'pve1', 100, 'qemu', {'id': PID, 'retention_count': 1, 'retention_days': 0}, errors)
    assert pruned == 0 and pve.sent == [] and len(got) == 1
    assert errors[0].startswith(f'{names[1]}: {NOT_ANSWERED}') and 'started it' not in errors[0]
    assert errors[1:] == [f'{names[2]}: not started, the delete of {names[1]} may still run']
