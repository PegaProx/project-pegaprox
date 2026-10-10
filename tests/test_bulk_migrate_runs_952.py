"""Bulk migration one guest after another, a few at a time or all at once (#952).

POST /api/clusters/<cid>/vms/bulk-migrate with a mode hands the guests to a run on the
server (core/bulk_migrate.py): sequential starts the next guest when Proxmox says the
migration task before it has ended, parallel keeps up to N in flight, all starts every
migration at once as the call always did. GET /api/bulk-migrations(/<id>) follows it,
POST .../cancel starts no further guest.

The cluster manager is faked: its migration tasks run until a test ends them, and the
guest list says where each guest is. The worker polls every few milliseconds here.

MK Oct 2026
"""
import threading
import time
import types

import pytest

from test_ha_api import ha_env, _standby_of_active, _active_with_standby  # noqa: F401 (ha_env is a fixture)

from pegaprox.core import bulk_migrate as bulk

NODES = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'},
         'pve3': {'status': 'offline', 'offline': True}}
GUESTS = [
    {'vmid': 100, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 101, 'name': 'db', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 102, 'name': 'cache', 'node': 'pve1', 'type': 'qemu', 'status': 'stopped'},
    {'vmid': 200, 'name': 'ct', 'node': 'pve1', 'type': 'lxc', 'status': 'running'},
    {'vmid': 201, 'name': 'ct2', 'node': 'pve1', 'type': 'lxc', 'status': 'running'},
    {'vmid': 300, 'name': 'there', 'node': 'pve2', 'type': 'qemu', 'status': 'running'},
]


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(bulk, 'POLL_SECONDS', 0.02)
    monkeypatch.setattr(bulk, 'LAND_SECONDS', 0.5)
    bulk.reset_for_tests()
    yield
    # no run may outlive its test: it would act on the next test's managers
    for run in bulk.runs():
        bulk.cancel(run, 'teardown')
    deadline = time.time() + 5
    while time.time() < deadline and any(r.state == 'running' for r in bulk.runs()):
        for p in _Pve.alive:
            p.finish_all()
        time.sleep(0.02)
    _Pve.alive.clear()
    bulk.reset_for_tests()


def _wait(cond, seconds=5.0, what='condition'):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if cond():
            return
        time.sleep(0.01)
    assert cond(), f'timed out waiting for {what}'


class _Pve:
    """The manager of a Proxmox cluster as far as a run calls it. A migration task runs
    until finish(); a finished one moves its guest, a hamigrate one only when moved()."""
    alive = []

    def __init__(self, api, cluster_id='cluster_1', guests=GUESTS, fail=(), ha=(), cluster_type='proxmox'):
        self.lock = threading.Lock()
        self.guests = {g['vmid']: dict(g) for g in guests}
        self.tasks = {}
        self.started = []
        self.reads = []
        self.fail, self.ha = set(fail), set(ha)
        self.flying = self.peak = 0
        m = api.make_fake_manager(cluster_id=cluster_id, cluster_type=cluster_type,
                                  get_node_status={k: dict(v) for k, v in NODES.items()})
        m.config.name = cluster_id
        m.is_connected = True
        m.get_vm_resources.side_effect = lambda max_age=0: self.resources()
        m.migrate_vm_manual.side_effect = self._migrate
        m.get_task_status.side_effect = self._status
        m.get_tasks.return_value = []
        self.mgr = api.set_manager(cluster_id, m)
        _Pve.alive.append(self)

    def resources(self):
        with self.lock:
            return [dict(g) for g in self.guests.values()]

    def _migrate(self, node, vmid, vm_type, target, online=True, options=None):
        with self.lock:
            self.started.append((vmid, node, target, online, dict(options or {})))
            if vmid in self.fail:
                return {'success': False, 'error': '{"data":null,"message":"VM %d is locked (backup)\\n"}' % vmid}
            kind = 'hamigrate' if vmid in self.ha else ('qmigrate' if vm_type == 'qemu' else 'vzmigrate')
            upid = f'UPID:{node}:{vmid:08X}:00000001:6700AAAA:{kind}:{vmid}:root@pam:'
            self.tasks[upid] = {'vmid': vmid, 'status': 'running', 'target': target, 'kind': kind}
            self.flying += 1
            self.peak = max(self.peak, self.flying)
            return {'success': True, 'task': upid}

    def _status(self, node, upid):
        with self.lock:
            self.reads.append(upid)
            t = self.tasks.get(upid)
            if t is None:
                return None
            if t['status'] == 'running':
                return {'status': 'running', 'upid': upid}
            return {'status': 'stopped', 'exitstatus': t['exitstatus'], 'upid': upid}

    def running(self):
        with self.lock:
            return sorted(t['vmid'] for t in self.tasks.values() if t['status'] == 'running')

    def finish(self, vmid, exitstatus='OK'):
        with self.lock:
            upid = next(u for u, t in self.tasks.items() if t['vmid'] == vmid and t['status'] == 'running')
            t = self.tasks[upid]
            t['status'], t['exitstatus'] = 'stopped', exitstatus
            self.flying -= 1
            if t['kind'] != 'hamigrate' and (exitstatus == 'OK' or exitstatus.startswith('WARNINGS')):
                self.guests[vmid]['node'] = t['target']

    def finish_all(self):
        for vmid in self.running():
            self.finish(vmid)

    def set(self, vmid, **kw):
        with self.lock:
            self.guests[vmid].update(kw)

    def order(self):
        with self.lock:
            return [s[0] for s in self.started]


def _post(client, cluster_id='cluster_1', **body):
    return client.post(f'/api/clusters/{cluster_id}/vms/bulk-migrate', json=body)


def _start(client, vmids, mode='sequential', target='pve2', cluster_id='cluster_1', **kw):
    r = _post(client, cluster_id=cluster_id, vms=[{'vmid': v, 'node': 'pve1', 'type': 'qemu'} for v in vmids],
              target=target, mode=mode, **kw)
    assert r.status_code == 202, r.get_data(as_text=True)
    return r.get_json()['run']


def _run(client, run_id):
    r = client.get(f'/api/bulk-migrations/{run_id}')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['run']


def _states(client, run_id):
    return {row['vmid']: row['state'] for row in _run(client, run_id)['rows']}


def _over(run_id):
    run = bulk.get(run_id)
    return run is not None and run.state != 'running'


def _audit(seed, action):
    return [tuple(r) for r in seed.db.conn.execute(
        'SELECT user, action, details, cluster FROM audit_log WHERE action = ? ORDER BY id', (action,)).fetchall()]


# --- the order of things --------------------------------------------------------------------

def test_one_at_a_time_starts_the_next_when_the_task_before_ended(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101, 200])
    assert run['mode'] == 'sequential' and run['target'] == 'pve2' and run['state'] == 'running'
    assert run['mine'] is True and run['user'] == 'root'
    _wait(lambda: pve.running() == [100], what='the first migration')
    time.sleep(0.15)
    # several polls later the second has not started: the first is still migrating
    assert pve.order() == [100]
    assert _states(c, run['id']) == {100: 'migrating', 101: 'wait', 200: 'wait'}
    assert _run(c, run['id'])['current'] == [100]
    pve.finish(100)
    _wait(lambda: pve.running() == [101], what='the second migration')
    assert _states(c, run['id'])[100] == 'done'
    pve.finish(101, 'WARNINGS: 2')
    _wait(lambda: pve.running() == [200], what='the third migration')
    pve.finish(200)
    _wait(lambda: _over(run['id']), what='the end of the run')
    view = _run(c, run['id'])
    assert view['state'] == 'done' and view['finished'] and view['current'] == []
    assert {r['vmid']: (r['state'], r['to'], r['note']) for r in view['rows']} == {
        100: ('done', 'pve2', ''), 101: ('done', 'pve2', 'WARNINGS: 2'), 200: ('done', 'pve2', '')}
    assert pve.order() == [100, 101, 200] and pve.peak == 1
    # what Proxmox got: the server's own idea of each guest, online, nothing else
    assert pve.started == [(100, 'pve1', 'pve2', True, {}), (101, 'pve1', 'pve2', True, {}),
                           (200, 'pve1', 'pve2', True, {})]
    (start,) = _audit(seed, 'vm.bulk_migrated')
    assert start == ('root', 'vm.bulk_migrated',
                     f"Bulk migration {run['id']} of 3 guest(s) to pve2, one at a time (100, 101, 200) [cluster_1]",
                     'cluster_1')
    (end,) = _audit(seed, 'vm.bulk_migrate_finished')
    assert end[2] == f"Bulk migration {run['id']} to pve2 done: done 3 [cluster_1]"


def test_only_the_task_in_flight_is_asked_about(api, seed):
    """Ten guests one after another: every status read is for the migration that runs,
    none for the nine that wait."""
    many = [dict(GUESTS[0], vmid=400 + i, name=f'lab{i}') for i in range(10)]
    pve = _Pve(api, guests=many)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [g['vmid'] for g in many])
    for g in many:
        _wait(lambda g=g: pve.running() == [g['vmid']], what=f"migration of {g['vmid']}")
        time.sleep(0.05)
        reads = {pve.tasks[u]['vmid'] for u in pve.reads}
        assert reads <= {x['vmid'] for x in many[:many.index(g) + 1]}
        pve.finish(g['vmid'])
    _wait(lambda: _over(run['id']))
    assert pve.peak == 1 and len(pve.started) == 10


def test_a_few_at_a_time_keeps_that_many_in_flight(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101, 102, 200, 201], mode='parallel', parallel=2)
    assert run['parallel'] == 2
    _wait(lambda: pve.running() == [100, 101], what='two in flight')
    time.sleep(0.15)
    assert pve.order() == [100, 101]
    pve.finish(101)
    _wait(lambda: pve.running() == [100, 102], what='the third one')
    pve.finish(100)
    pve.finish(102)
    _wait(lambda: pve.running() == [200, 201], what='the last two')
    pve.finish_all()
    _wait(lambda: _over(run['id']))
    assert pve.peak == 2
    assert set(_states(c, run['id']).values()) == {'done'}
    assert ', 2 at a time (100, 101, 102, 200, 201)' in _audit(seed, 'vm.bulk_migrated')[0][2]


def test_all_at_once_starts_everything_and_follows_nothing(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101, 102, 200, 201], mode='all')
    _wait(lambda: _over(run['id']), what='every start')
    assert pve.running() == [100, 101, 102, 200, 201] and pve.peak == 5
    assert set(_states(c, run['id']).values()) == {'started'}
    assert pve.reads == []
    assert all(r['task'].startswith('UPID:pve1:') for r in _run(c, run['id'])['rows'])


def test_a_failure_is_listed_and_the_run_goes_on(api, seed):
    pve = _Pve(api, fail=(101,))
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101, 102, 200])
    _wait(lambda: pve.running() == [100])
    pve.finish(100, 'migration aborted: storage local-zfs not available on pve2')
    # 101 refuses to start, 102 starts right after
    _wait(lambda: pve.running() == [102], what='the guest after the refused one')
    pve.finish(102)
    _wait(lambda: pve.running() == [200])
    pve.finish(200)
    _wait(lambda: _over(run['id']))
    rows = {r['vmid']: (r['state'], r['note']) for r in _run(c, run['id'])['rows']}
    assert rows == {100: ('failed', 'migration aborted: storage local-zfs not available on pve2'),
                    101: ('failed', 'VM 101 is locked (backup)'),
                    102: ('done', ''), 200: ('done', '')}
    assert _run(c, run['id'])['counts'] == {'failed': 2, 'done': 2}
    (end,) = _audit(seed, 'vm.bulk_migrate_finished')
    assert 'done 2, failed 2 (100, 101)' in end[2]


def test_cancel_starts_nothing_more_and_lets_the_running_one_finish(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101, 102])
    _wait(lambda: pve.running() == [100])
    assert _run(c, run['id'])['may_cancel'] is True
    r = c.post(f"/api/bulk-migrations/{run['id']}/cancel")
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['run']['cancelled_by'] == 'root' and r.get_json()['run']['may_cancel'] is False
    time.sleep(0.15)
    # the migration in flight goes on, nothing else starts
    assert pve.order() == [100] and _states(c, run['id'])[100] == 'migrating'
    assert _run(c, run['id'])['may_cancel'] is False
    pve.finish(100)
    _wait(lambda: _over(run['id']))
    view = _run(c, run['id'])
    assert view['state'] == 'cancelled'
    assert {r['vmid']: r['state'] for r in view['rows']} == {100: 'done', 101: 'cancelled', 102: 'cancelled'}
    assert view['rows'][1]['note'] == 'Not started: cancelled by root'
    (row,) = _audit(seed, 'vm.bulk_migrate_cancelled')
    assert row[2] == f"Bulk migration {run['id']} to pve2 (started by root): 2 guest(s) not started [cluster_1]"
    # once over, there is nothing to cancel
    assert c.post(f"/api/bulk-migrations/{run['id']}/cancel").status_code == 409


def test_a_guest_under_proxmox_ha_counts_once_it_has_moved(api, seed):
    """The hamigrate task only hands the request to the CRM; the next guest waits until
    the HA guest has left its node."""
    pve = _Pve(api, ha=(100,))
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101])
    _wait(lambda: pve.running() == [100])
    pve.set(100, hastate='migrate', lock='migrate')
    pve.finish(100)
    time.sleep(0.8)   # longer than LAND_SECONDS: the CRM is busy with it, that is no failure
    assert pve.order() == [100] and _states(c, run['id'])[100] == 'migrating'
    pve.set(100, node='pve2', hastate='started', lock='')
    _wait(lambda: pve.running() == [101], what='the guest after the HA one')
    assert _states(c, run['id'])[100] == 'done'
    pve.finish(101)
    _wait(lambda: _over(run['id']))


def test_an_ha_request_nothing_moves_fails_after_the_settle_time(api, seed):
    pve = _Pve(api, ha=(100,))
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101])
    _wait(lambda: pve.running() == [100])
    pve.set(100, hastate='started')
    pve.finish(100)
    _wait(lambda: pve.running() == [101], what='the next guest after the settle time')
    row = _run(c, run['id'])['rows'][0]
    assert (row['state'], row['note']) == ('failed', 'Proxmox HA did not move it')
    pve.finish(101)
    _wait(lambda: _over(run['id']))


def test_ha_that_places_the_guest_elsewhere_says_where(api, seed):
    pve = _Pve(api, ha=(100,))
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100])
    _wait(lambda: pve.running() == [100])
    pve.finish(100, 'command ha-manager migrate failed')
    pve.set(100, node='pve4')
    _wait(lambda: _over(run['id']))
    row = _run(c, run['id'])['rows'][0]
    assert (row['state'], row['to'], row['note']) == ('done', 'pve4', 'Proxmox HA placed it on pve4')


def test_a_guest_that_moved_meanwhile_is_taken_from_where_it_is(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101, 102])
    _wait(lambda: pve.running() == [100])
    pve.set(101, node='pve2')          # already where it should go
    pve.set(102, node='pve4')          # somewhere else
    pve.finish(100)
    _wait(lambda: pve.running() == [102])
    assert pve.started[-1][:3] == (102, 'pve4', 'pve2')
    assert _run(c, run['id'])['rows'][1]['note'] == 'Already on pve2'
    pve.finish(102)
    _wait(lambda: _over(run['id']))


def test_the_options_reach_proxmox(api, seed):
    pve = _Pve(api)
    # offline: Proxmox moves no running guest that way, the preflight would skip them
    pve.set(100, status='stopped')
    pve.set(200, status='stopped')
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 200], mode='all', online=False, with_local_disks=True)
    _wait(lambda: _over(run['id']))
    # local disks for a VM only: a container moves its volumes with it
    assert pve.started == [(100, 'pve1', 'pve2', False, {'with_local_disks': True}),
                           (200, 'pve1', 'pve2', False, {})]


# --- what the request must be ----------------------------------------------------------------

@pytest.mark.parametrize('body,error', [
    ({'mode': 'fast'}, 'mode is sequential, parallel or all'),
    ({'mode': 'parallel', 'parallel': 1}, 'parallel is a number from 2 to 5'),
    ({'mode': 'parallel', 'parallel': 6}, 'parallel is a number from 2 to 5'),
    ({'mode': 'parallel', 'parallel': True}, 'parallel is a number from 2 to 5'),
    ({'mode': 'sequential', 'online': 'yes'}, 'online and with_local_disks are true or false'),
    ({'mode': 'sequential', 'with_local_disks': 1}, 'online and with_local_disks are true or false'),
    ({'mode': 'sequential', 'target': '../pve2'}, 'Target node is required'),
    ({'mode': 'sequential', 'target': 'pve9'}, 'pve9 is no node of this cluster'),
    ({'mode': 'sequential', 'target': 'pve3'}, 'pve3 is not online'),
    ({'mode': 'sequential', 'vms': [{'vmid': True}]}, 'vms holds something that is no VMID'),
    ({'mode': 'sequential', 'vms': ['１００']}, 'vms holds something that is no VMID'),
    ({'mode': 'sequential', 'vms': [100, 999]}, 'Not on this cluster or out of reach: 999'),
])
def test_a_request_out_of_shape_starts_nothing(api, seed, body, error):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    body = dict({'vms': [100], 'target': 'pve2'}, **body)
    r = _post(c, **body)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['error'] == error
    assert pve.started == [] and bulk.runs() == []


def test_the_batch_cap_holds_for_a_run_too(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, vms=list(range(1, 1002)), target='pve2', mode='sequential')
    assert r.status_code == 400 and 'max 1000' in r.get_json()['error']
    assert pve.started == []


def test_what_cannot_move_is_listed_and_the_rest_runs(api, seed, monkeypatch):
    import pegaprox.api.history as history
    pve = _Pve(api)
    monkeypatch.setattr(history, 'load_affinity_rules', lambda: {'rules': [
        {'cluster_id': 'cluster_1', 'enabled': True, 'vms': [101], 'type': 'separate'}]})
    # the preflight hands in where every guest of the set ends up (vm_nodes) and the rules
    monkeypatch.setattr(history, 'check_affinity_violation', lambda cid, vmid, target, **kw: {
        'violation': True, 'enforce': True, 'rule': 'keep-apart', 'message': 'x'})
    c = api.as_user(seed.user('root', role='admin'))
    first = _start(c, [100])
    _wait(lambda: pve.running() == [100])
    run = _start(c, [100, 101, 300, 102, 102])
    rows = {r['vmid']: (r['state'], r['note']) for r in run['rows']}
    # 102 may be on its way already when the answer is written
    assert rows.pop(102) in (('wait', ''), ('migrating', ''))
    assert rows == {100: ('skipped', 'Another bulk migration moves it already'),
                    101: ('skipped', "Affinity rule 'keep-apart' keeps it off pve2"),
                    300: ('skipped', 'Already on pve2')}
    assert run['total'] == 4
    _wait(lambda: 102 in pve.running())
    pve.finish_all()
    _wait(lambda: _over(run['id']) and _over(first['id']))
    assert pve.order() == [100, 102]


def test_nothing_left_to_move_starts_no_run(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, vms=[300], target='pve2', mode='sequential')
    assert r.status_code == 400
    assert r.get_json() == {'error': 'None of these guests is left to migrate',
                            'skipped': [{'vmid': 300, 'reason': 'Already on pve2'}]}
    assert bulk.runs() == [] and pve.started == []
    assert _audit(seed, 'vm.bulk_migrated') == []


def test_a_cluster_takes_a_limited_number_of_runs(api, seed, monkeypatch):
    monkeypatch.setattr(bulk, 'RUNNING_PER_CLUSTER', 2)
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    _start(c, [100])
    _start(c, [101])
    r = _post(c, vms=[102], target='pve2', mode='sequential')
    assert r.status_code == 409
    assert 'running on this cluster already' in r.get_json()['error']
    _wait(lambda: pve.running() == [100, 101])
    assert len(bulk.runs()) == 2


def test_without_a_mode_the_call_answers_as_before(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, vms=[{'vmid': 100, 'node': 'pve1', 'type': 'qemu'},
                      {'vmid': 101, 'node': 'pve1', 'type': 'qemu'}], target='pve2')
    assert r.status_code == 200
    body = r.get_json()
    assert body['total'] == 2 and body['successful'] == 2 and 'run' not in body
    assert pve.running() == [100, 101] and bulk.runs() == []


# --- who may ---------------------------------------------------------------------------------

def test_the_anonymous_caller_gets_nothing(api):
    pve = _Pve(api)
    assert _post(api.anon(), vms=[100], target='pve2', mode='sequential').status_code == 401
    assert api.anon().get('/api/bulk-migrations').status_code == 401
    assert pve.started == []


def test_a_viewer_and_a_user_without_migrate_start_nothing(api, seed):
    pve = _Pve(api)
    for who in (seed.user('watcher', role='viewer'), seed.user('ops', role='user', denied=['vm.migrate'])):
        r = _post(api.as_user(who), vms=[100], target='pve2', mode='sequential')
        assert r.status_code == 403, who['username']
    assert pve.started == [] and bulk.runs() == []


def test_a_vm_acl_user_moves_their_guests_and_sees_only_those(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.vm_acl('cluster_1', 100, users=['portal'])
    seed.vm_acl('cluster_1', 101, users=['portal'])
    pve = _Pve(api)
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    # a guest outside the grant gets the answer of one that does not exist
    r = _post(portal, vms=[100, 102], target='pve2', mode='sequential')
    assert r.status_code == 400 and r.get_json()['error'] == 'Not on this cluster or out of reach: 102'
    assert pve.started == []
    run = _start(portal, [100, 101])
    _wait(lambda: pve.running() == [100])
    # an admin's run on the same cluster: the portal user sees none of its guests
    admin = api.as_user(seed.user('root', role='admin'))
    other = _start(admin, [102, 101], mode='parallel', parallel=2)
    assert [r['vmid'] for r in other['rows']] == [102, 101]
    assert {r['id'] for r in portal.get('/api/bulk-migrations').get_json()['runs']} == {run['id'], other['id']}
    seen = portal.get(f"/api/bulk-migrations/{other['id']}").get_json()['run']
    # 101 is theirs (skipped: their own run moves it), 102 is not
    assert [r['vmid'] for r in seen['rows']] == [101] and seen['total'] == 1
    assert seen['mine'] is False and seen['may_cancel'] is False
    # and it is not theirs to cancel
    assert portal.post(f"/api/bulk-migrations/{other['id']}/cancel").status_code == 403
    assert _run(admin, run['id'])['may_cancel'] is True
    pve.finish_all()


def test_a_run_asks_again_before_each_guest(api, seed, monkeypatch):
    """The grant on 101 goes while the run waits for 100: 101 is not moved."""
    seed.tenant('acme', clusters=['cluster_1'])
    seed.vm_acl('cluster_1', 100, users=['portal'])
    seed.vm_acl('cluster_1', 101, users=['portal'])
    monkeypatch.setattr(bulk, 'AUTHZ_SECONDS', 0)
    pve = _Pve(api)
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    run = _start(portal, [100, 101])
    _wait(lambda: pve.running() == [100])
    seed.db.delete_vm_acl('cluster_1', 101)
    from pegaprox.utils.rbac import invalidate_vm_acls_cache
    invalidate_vm_acls_cache()
    pve.finish(100)
    _wait(lambda: _over(run['id']))
    row = bulk.get(run['id']).rows_copy()[1]
    assert (row['state'], row['note']) == ('skipped', 'Permission denied: vm.migrate')
    assert pve.order() == [100]


def test_a_disabled_account_moves_nothing_more(api, seed, monkeypatch):
    monkeypatch.setattr(bulk, 'AUTHZ_SECONDS', 0)
    pve = _Pve(api)
    ops = seed.user('ops', role='user')
    run = _start(api.as_user(ops), [100, 101])
    _wait(lambda: pve.running() == [100])
    stored = seed.db.get_user('ops')
    stored['enabled'] = False
    seed.db.save_user('ops', stored)
    pve.finish(100)
    _wait(lambda: _over(run['id']))
    assert [r['state'] for r in bulk.get(run['id']).rows_copy()] == ['done', 'skipped']
    assert pve.order() == [100]


def test_a_confined_admin_and_another_tenant_neither_see_nor_act(api, seed):
    seed.tenant('globex', clusters=['cluster_2'])
    pve = _Pve(api)
    _Pve(api, cluster_id='cluster_2')
    admin = api.as_user(seed.user('root', role='admin'))
    run = _start(admin, [100, 101])
    _wait(lambda: pve.running() == [100])
    confined = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                     tenant_permissions={'globex': {'role': 'user'}}))
    other = api.as_user(seed.user('milton', role='user', tenant_id='globex'))
    for c in (confined, other):
        assert _post(c, vms=[101], target='pve2', mode='sequential').status_code == 403
        assert c.get('/api/bulk-migrations').get_json() == {'runs': []}
        assert c.get(f"/api/bulk-migrations/{run['id']}").status_code == 404
        assert c.post(f"/api/bulk-migrations/{run['id']}/cancel").status_code == 404
    assert bulk.get(run['id']).cancelled_by == ''
    assert pve.order() == [100]
    pve.finish_all()


def test_an_unknown_run_is_not_found(api, seed):
    c = api.as_user(seed.user('root', role='admin'))
    for path in ('/api/bulk-migrations/0123456789abcdef', '/api/bulk-migrations/..'):
        assert c.get(path).status_code == 404
    assert c.post('/api/bulk-migrations/0123456789abcdef/cancel').status_code == 404


def test_an_operator_of_the_whole_cluster_may_cancel_someone_elses_run(api, seed):
    pve = _Pve(api)
    run = _start(api.as_user(seed.user('root', role='admin')), [100, 101])
    _wait(lambda: pve.running() == [100])
    ops = api.as_user(seed.user('ops', role='user'))
    assert _run(ops, run['id'])['may_cancel'] is True
    assert ops.post(f"/api/bulk-migrations/{run['id']}/cancel").status_code == 200
    pve.finish_all()
    _wait(lambda: _over(run['id']))
    assert _audit(seed, 'vm.bulk_migrate_cancelled')[0][0] == 'ops'


def test_an_xcpng_pool_wants_its_own_permission(api, seed):
    pve = _Pve(api, cluster_id='xcp1', cluster_type='xcpng')
    c = api.as_user(seed.user('ops', role='user', denied=['xapi.vm.migrate']))
    for body in ({'mode': 'sequential'}, {}):
        r = _post(c, cluster_id='xcp1', vms=[{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}], target='pve2', **body)
        assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied: xapi.vm.migrate'
    assert pve.started == []


def test_a_standby_starts_and_cancels_nothing(ha_env, seed):  # noqa: F811
    api = ha_env.api
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [100, 101])
    _wait(lambda: pve.running() == [100])
    _standby_of_active(ha_env)
    r = _post(c, vms=[102], target='pve2', mode='sequential')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = c.post(f"/api/bulk-migrations/{run['id']}/cancel")
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    # and a run of this process stops starting guests once it is a standby
    pve.finish(100)
    _wait(lambda: _over(run['id']))
    stopped = bulk.get(run['id'])
    assert stopped.state == 'stopped' and 'standby' in stopped.reason
    first, second = stopped.rows_copy()
    # the one in flight finishes in Proxmox, followed or let go depending on the moment
    assert first['state'] in ('done', 'unknown') and second['state'] == 'cancelled'
    assert pve.order() == [100]
    # counterproof: the active it pairs with does
    _active_with_standby(ha_env)
    assert _post(c, vms=[102], target='pve2', mode='sequential').status_code == 202
    _wait(lambda: 102 in pve.running())
    pve.finish_all()


def test_a_cancel_that_has_answered_lets_no_guest_be_claimed():
    run = bulk.BulkRun('c1', 'c1', 'root', {}, '', 'pve2', 'sequential', 1, True, False,
                       [bulk.new_row({'vmid': v, 'node': 'pve1', 'type': 'qemu'}) for v in (1, 2)])
    assert bulk._claim(run)['vmid'] == 1
    assert bulk.cancel(run, 'root') is True
    assert bulk._claim(run) is None
    assert [r['state'] for r in run.rows_copy()] == ['migrating', 'wait']
    assert bulk.cancel(run, 'root') is False


def test_a_forwarding_standby_reads_the_runs_on_the_active():
    from pegaprox.core import ha
    assert {'/api/bulk-migrations', '/api/bulk-migrations/<run_id>'} <= ha.FORWARDED_READS


def test_the_routes_are_served_once(api):
    rules = sorted((r.rule, sorted(r.methods - {'HEAD', 'OPTIONS'})) for r in api.app.url_map.iter_rules()
                   if 'bulk-migrat' in r.rule)
    assert rules == [('/api/bulk-migrations', ['GET']),
                     ('/api/bulk-migrations/<run_id>', ['GET']),
                     ('/api/bulk-migrations/<run_id>/cancel', ['POST']),
                     ('/api/clusters/<cluster_id>/vms/bulk-migrate', ['POST'])]


# --- the pieces --------------------------------------------------------------------------------

UPID = 'UPID:pve1:0000ABCD:00000001:6700AAAA:qmigrate:100:root@pam:'


@pytest.mark.parametrize('answer,state', [
    ({'status': 'running'}, ('running', '')),
    ({'status': 'stopped', 'exitstatus': 'OK'}, ('ok', 'OK')),
    ({'status': 'stopped', 'exitstatus': 'WARNINGS: 3'}, ('ok', 'WARNINGS: 3')),
    ({'status': 'stopped', 'exitstatus': 'migration problems'}, ('failed', 'migration problems')),
    ({'status': 'stopped'}, ('failed', 'failed')),
    (None, None),
    ({}, None),
])
def test_the_task_status_as_a_run_reads_it(answer, state):
    mgr = types.SimpleNamespace(cluster_type='proxmox', asked=[])
    mgr.get_task_status = lambda node, upid: mgr.asked.append((node, upid)) or answer
    assert bulk.task_state(mgr, UPID) == state
    assert mgr.asked == [('pve1', UPID)]


@pytest.mark.parametrize('upid', ['', 'UPID:pve1:', 'UPID:../x:1:1:1:qmigrate:100:root@pam:',
                                  'UPID:pve1:1:1:1:qmigrate:100:root@pam:/../../x'])
def test_a_task_id_out_of_shape_is_never_asked_about(upid):
    mgr = types.SimpleNamespace(cluster_type='proxmox', get_task_status=lambda n, u: pytest.fail('asked'))
    assert bulk.task_state(mgr, upid) is None


def test_an_xcpng_task_is_looked_up_where_pegaprox_follows_it():
    tasks = [{'upid': 'a1b2c3d4', 'status': 'completed'}, {'upid': 'e5f6a7b8', 'status': 'running'},
             {'upid': 'c0ffee00', 'status': 'failed'}]
    mgr = types.SimpleNamespace(cluster_type='xcpng', get_tasks=lambda limit=50: tasks)
    assert bulk.task_state(mgr, 'a1b2c3d4') == ('ok', '')
    assert bulk.task_state(mgr, 'e5f6a7b8') == ('running', '')
    assert bulk.task_state(mgr, 'c0ffee00') == ('failed', 'failed')
    assert bulk.task_state(mgr, 'deadbeef') is None


class _Resp:
    status_code = 200

    def json(self):
        return {'data': {'status': 'stopped', 'exitstatus': 'OK'}}


def test_the_manager_reads_one_task_status(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(user='root@pam', host='10.0.0.1', name='c1', api_port=8006)
    m.current_host = '10.0.0.1'
    import logging
    m.logger = logging.getLogger('test-bulk-migrate')
    asked = []
    monkeypatch.setattr(m, '_api_get', lambda url, **kw: asked.append(url) or _Resp(), raising=False)
    assert m.get_task_status('pve1', UPID) == {'status': 'stopped', 'exitstatus': 'OK'}
    assert asked == [f'https://10.0.0.1:8006/api2/json/nodes/pve1/tasks/{UPID}/status']
    for node, upid in (('../pve1', UPID), ('pve1', 'UPID:x/../y'), ('pve1', 'UPID:a?b'), ('pve1', 'nope')):
        assert m.get_task_status(node, upid) is None
    assert len(asked) == 1


def test_finished_runs_are_kept_an_hour_and_fifty_at_most(monkeypatch):
    def _done(age):
        run = bulk.BulkRun('c1', 'c1', 'root', {}, '', 'pve2', 'sequential', 1, True, False,
                           [bulk.new_row({'vmid': 1, 'node': 'pve1', 'type': 'qemu'})])
        run.state, run.finished = 'done', time.time() - age
        bulk._runs[run.id] = run
        return run
    old = _done(bulk.KEEP_SECONDS + 5)
    fresh = [_done(i) for i in range(bulk.KEEP_FINISHED + 3)]
    ids = {r.id for r in bulk.runs()}
    assert old.id not in ids and len(ids) == bulk.KEEP_FINISHED
    # the oldest of the fresh ones went first
    assert {r.id for r in fresh[-3:]} & ids == set()
