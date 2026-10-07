"""Several backups restored in one go.

POST /api/clusters/<cid>/backup-restore/batch takes one backup per guest from one storage,
checks every one as POST /backup-restore checks it, and hands them to a run on the server
(core/batch_restore.py): one at a time or a few at once, the next once Proxmox reports the
task of one before it has ended. GET /api/batch-restores(/<id>) follows it, POST .../cancel
starts no further restore.

The cluster manager is faked: a restore task runs until a test ends it. The worker polls
every few milliseconds here.

MK Oct 2026
"""
import threading
import time

import pytest

from test_ha_api import ha_env, _standby_of_active  # noqa: F401 (ha_env is a fixture)

from pegaprox.core import batch_restore as batch
import pegaprox.utils.rbac as rbac

CID = 'cluster_1'
NODES = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'},
         'pve3': {'status': 'offline', 'offline': True}}
GUESTS = [
    {'vmid': 100, 'name': 'web', 'node': 'pve1', 'type': 'qemu'},
    {'vmid': 101, 'name': 'db', 'node': 'pve2', 'type': 'qemu'},
    {'vmid': 200, 'name': 'ct', 'node': 'pve1', 'type': 'lxc'},
    {'vmid': 1000, 'name': 'taken', 'node': 'pve1', 'type': 'qemu'},
]


def _vol(vmid, kind='vm', store='pbs'):
    return f'{store}:backup/{kind}/{vmid}/2026-10-06T19:00:01Z'


def _local(vmid, kind='qemu'):
    return f'local:backup/vzdump-{kind}-{vmid}-2026_10_06-21_00_01.vma.zst'


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(batch, 'POLL_SECONDS', 0.02)
    batch.reset_for_tests()
    yield
    for run in batch.runs():
        batch.cancel(run, 'teardown')
    deadline = time.time() + 5
    while time.time() < deadline and any(r.state == 'running' for r in batch.runs()):
        for p in _Pve.alive:
            p.finish_all()
        time.sleep(0.02)
    _Pve.alive.clear()
    batch.reset_for_tests()


def _wait(cond, seconds=5.0, what='condition'):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if cond():
            return
        time.sleep(0.01)
    assert cond(), f'timed out waiting for {what}'


class _Resp:
    def __init__(self, status, data=None, message=None):
        self.status_code = status
        self._body = {'data': data} if message is None else {'data': None, 'message': message}
        self.text = ''

    def json(self):
        return self._body


class _Pve:
    """Proxmox as a batch restore calls it: POST /nodes/<n>/qemu|lxc, the task status"""
    alive = []

    def __init__(self, api, cluster_id=CID, guests=GUESTS, fail=()):
        self.lock = threading.Lock()
        self.tasks = {}
        self.started = []
        self.fail = set(fail)
        self.flying = self.peak = 0
        m = api.make_fake_manager(cluster_id)
        m.is_connected = True
        m.host, m.api_port = '192.0.2.10', 8006
        m.config.name = cluster_id
        m.get_node_status.return_value = {k: dict(v) for k, v in NODES.items()}
        m.get_vm_resources.side_effect = lambda max_age=0: [dict(g) for g in guests]
        m._api_post.side_effect = self._post
        m.get_task_status.side_effect = self._status
        self.mgr = api.set_manager(cluster_id, m)
        _Pve.alive.append(self)

    def _post(self, url, data=None, timeout=None, **kw):
        path = url.split('/api2/json', 1)[1]
        node, kind = path.split('/')[2], path.split('/')[3]
        with self.lock:
            self.started.append((node, kind, dict(data)))
            vmid = int(data['vmid'])
            if vmid in self.fail:
                return _Resp(500, message=f'unable to restore VM {vmid} - storage full\n')
            upid = f'UPID:{node}:{vmid:08X}:00000001:6700AAAA:{"qmrestore" if kind == "qemu" else "vzrestore"}:{vmid}:root@pam:'
            self.tasks[upid] = {'vmid': vmid, 'status': 'running'}
            self.flying += 1
            self.peak = max(self.peak, self.flying)
            return _Resp(200, upid)

    def _status(self, node, upid):
        with self.lock:
            t = self.tasks.get(upid)
            if t is None:
                return None
            if t['status'] == 'running':
                return {'status': 'running'}
            return {'status': 'stopped', 'exitstatus': t['exitstatus']}

    def running(self):
        with self.lock:
            return sorted(t['vmid'] for t in self.tasks.values() if t['status'] == 'running')

    def finish(self, vmid, exitstatus='OK'):
        with self.lock:
            t = next(t for t in self.tasks.values() if t['vmid'] == vmid and t['status'] == 'running')
            t['status'], t['exitstatus'] = 'stopped', exitstatus
            self.flying -= 1

    def finish_all(self):
        for vmid in self.running():
            self.finish(vmid)

    def targets(self):
        with self.lock:
            return [int(d['vmid']) for _n, _k, d in self.started]


def _post(client, cluster_id=CID, **body):
    return client.post(f'/api/clusters/{cluster_id}/backup-restore/batch', json=body)


def _start(client, volids, mode='new', target_node='pve1', **kw):
    r = _post(client, items=[{'volid': v} for v in volids], mode=mode, target_node=target_node, **kw)
    assert r.status_code == 202, r.get_data(as_text=True)
    return r.get_json()['run']


def _run(client, run_id):
    r = client.get(f'/api/batch-restores/{run_id}')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['run']


def _over(run_id):
    run = batch.get(run_id)
    return run is not None and run.state != 'running'


def _audit(seed, action):
    return [tuple(r) for r in seed.db.conn.execute(
        'SELECT user, action, details FROM audit_log WHERE action = ? ORDER BY id', (action,)).fetchall()]


def _admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


# --- the order of things --------------------------------------------------------------------

def test_one_at_a_time_into_new_vmids(api, seed):
    pve = _Pve(api)
    c = _admin(api, seed)
    run = _start(c, [_vol(100), _vol(200, 'ct'), _vol(101)], first_vmid=999, target_storage='local-zfs')
    assert (run['mode'], run['run'], run['storage'], run['state']) == ('new', 'sequential', 'pbs', 'running')
    # 1000 is taken: the next free ones from 999 on
    assert [(r['vmid'], r['target_vmid'], r['type'], r['node']) for r in run['rows']] == [
        (100, 999, 'qemu', 'pve1'), (200, 1001, 'lxc', 'pve1'), (101, 1002, 'qemu', 'pve1')]
    _wait(lambda: pve.running() == [999], what='the first restore')
    time.sleep(0.15)
    assert pve.targets() == [999]
    pve.finish(999)
    _wait(lambda: pve.running() == [1001], what='the second restore')
    pve.finish(1001, 'WARNINGS: 1')
    _wait(lambda: pve.running() == [1002], what='the third restore')
    pve.finish(1002)
    _wait(lambda: _over(run['id']), what='the end of the batch')
    view = _run(c, run['id'])
    assert view['state'] == 'done' and view['counts'] == {'done': 3}
    assert [(r['state'], r['note']) for r in view['rows']] == [('done', ''), ('done', 'WARNINGS: 1'), ('done', '')]
    # what Proxmox got is what the single restore sends
    assert pve.started == [
        ('pve1', 'qemu', {'vmid': 999, 'archive': _vol(100), 'storage': 'local-zfs'}),
        ('pve1', 'lxc', {'vmid': 1001, 'ostemplate': _vol(200, 'ct'), 'restore': 1, 'storage': 'local-zfs'}),
        ('pve1', 'qemu', {'vmid': 1002, 'archive': _vol(101), 'storage': 'local-zfs'})]
    assert pve.peak == 1
    (start,) = _audit(seed, 'backup.batch_restore')
    assert start[0] == 'root' and '100->999, 200->1001, 101->1002' in start[2]
    assert len(_audit(seed, 'backup.restored')) == 3
    (end,) = _audit(seed, 'backup.batch_restore_finished')
    assert 'from pbs done: done 3' in end[2]


def test_a_few_at_a_time(api, seed):
    pve = _Pve(api)
    c = _admin(api, seed)
    run = _start(c, [_vol(100), _vol(101), _vol(200, 'ct')], run='parallel', parallel=2, first_vmid=2000)
    _wait(lambda: pve.running() == [2000, 2001], what='two restores')
    time.sleep(0.1)
    assert pve.running() == [2000, 2001]
    pve.finish(2001)
    _wait(lambda: pve.running() == [2000, 2002], what='the third restore')
    pve.finish_all()
    _wait(lambda: _over(run['id']))
    assert pve.peak == 2 and _run(c, run['id'])['parallel'] == 2


def test_overwrite_restores_each_over_its_guest_where_it_lives(api, seed):
    pve = _Pve(api)
    c = _admin(api, seed)
    r = _post(c, items=[{'volid': _vol(100)}, {'volid': _vol(101)}], mode='overwrite', target_node='pve1')
    assert r.status_code == 400 and r.get_json()['code'] == 'CONFIRM_REQUIRED'
    assert pve.started == []
    run = _start(c, [_vol(100), _vol(101), _vol(555)], mode='overwrite', confirm=True, target_node='pve2')
    assert [(r['target_vmid'], r['node']) for r in run['rows']] == [(100, 'pve1'), (101, 'pve2'), (555, 'pve2')]
    for vmid in (100, 101, 555):
        _wait(lambda v=vmid: pve.running() == [v])
        pve.finish(vmid)
    _wait(lambda: _over(run['id']))
    assert [(n, d.get('force')) for n, _k, d in pve.started] == [('pve1', 1), ('pve2', 1), ('pve2', 1)]


def test_a_restore_proxmox_refuses_fails_and_the_next_one_starts(api, seed):
    pve = _Pve(api, fail={3000})
    c = _admin(api, seed)
    run = _start(c, [_vol(100), _vol(101)], first_vmid=3000)
    _wait(lambda: pve.running() == [3001], what='the second restore')
    pve.finish(3001, 'command failed: exit code 133')
    _wait(lambda: _over(run['id']))
    rows = _run(c, run['id'])['rows']
    assert rows[0]['state'] == 'failed' and 'storage full' in rows[0]['note']
    assert (rows[1]['state'], rows[1]['note']) == ('failed', 'command failed: exit code 133')


def test_a_cancel_starts_nothing_more(api, seed):
    pve = _Pve(api)
    c = _admin(api, seed)
    run = _start(c, [_vol(100), _vol(101), _vol(200, 'ct')], first_vmid=4000)
    _wait(lambda: pve.running() == [4000])
    viewer = api.as_user(seed.user('looker', role='viewer'))
    assert _run(viewer, run['id'])['may_cancel'] is False
    assert viewer.post(f"/api/batch-restores/{run['id']}/cancel").status_code == 403
    r = c.post(f"/api/batch-restores/{run['id']}/cancel")
    assert r.status_code == 200 and r.get_json()['run']['may_cancel'] is False
    assert c.post(f"/api/batch-restores/{run['id']}/cancel").status_code == 409
    pve.finish(4000)
    _wait(lambda: _over(run['id']))
    view = _run(c, run['id'])
    assert view['state'] == 'cancelled' and view['cancelled_by'] == 'root'
    assert [r['state'] for r in view['rows']] == ['done', 'cancelled', 'cancelled']
    assert pve.targets() == [4000]
    assert _audit(seed, 'backup.batch_restore_cancelled')[0][0] == 'root'


def test_the_list_shows_the_batches_newest_first(api, seed):
    _Pve(api)
    c = _admin(api, seed)
    a = _start(c, [_vol(100)], first_vmid=5000)
    b = _start(c, [_vol(101)], first_vmid=5100)
    got = c.get('/api/batch-restores').get_json()['runs']
    assert [r['id'] for r in got] == [b['id'], a['id']]
    assert all('rows' not in r and r['mine'] for r in got)


# --- what the body may say ---------------------------------------------------------------------

@pytest.mark.parametrize('body,needle', [
    ({'mode': 'test'}, "mode is 'new' or 'overwrite'"),
    ({'run': 'all'}, "run is 'sequential' or 'parallel'"),
    ({'run': 'parallel', 'parallel': 9}, 'parallel is a number from 2 to 4'),
    ({'run': 'parallel', 'parallel': True}, 'parallel is a number'),
    ({'target_node': '../x'}, 'target_node is required'),
    ({'target_node': 'pve9'}, 'pve9 is no node of this cluster'),
    ({'target_node': 'pve3'}, 'pve3 is not online'),
    ({'target_storage': 'bad storage'}, 'target_storage is a storage ID'),
    ({'items': []}, 'items lists 1 to 100 backups'),
    ({'items': [{'volid': _vol(v)} for v in range(100, 202)]}, 'items lists 1 to 100 backups'),
    ({'items': 'pbs:backup/vm/100/x'}, 'items lists'),
    ({'items': [{'volid': 'no-colon'}]}, 'names a backup volume'),
    ({'items': [{'volid': 'pbs:backup/vm/100/x y'}]}, 'names a backup volume'),
    ({'items': [{'volid': 12}]}, 'names a backup volume'),
    ({'items': [{'volid': _vol(100)}, {'volid': _local(101)}]}, 'come from one storage'),
    ({'items': [{'volid': _vol(100)}, {'volid': _vol(100, store='pbs').replace('19:00', '20:00')}]}, 'One backup per guest'),
    ({'items': [{'volid': 'pbs:iso/debian.iso'}]}, 'Cannot tell which guest'),
    ({'first_vmid': 'abc'}, 'first_vmid is a number'),
    ({'first_vmid': 5}, 'first_vmid is a number'),
    ({'items': [{'volid': _vol(100), 'target_vmid': 7000}, {'volid': _vol(101), 'target_vmid': 7000}]},
     'Two items name the same target_vmid'),
    ({'items': [{'volid': _vol(100), 'target_vmid': [1]}]}, 'target_vmid is a number'),
])
def test_a_body_out_of_shape_is_a_400(api, seed, body, needle):
    pve = _Pve(api)
    full = {'items': [{'volid': _vol(100)}], 'mode': 'new', 'target_node': 'pve1'}
    full.update(body)
    r = _post(_admin(api, seed), **full)
    assert r.status_code == 400, r.data
    assert needle in r.get_json()['error'], r.get_json()
    assert pve.started == [] and batch.runs() == []


def test_a_body_that_is_no_object_is_a_400(api, seed):
    _Pve(api)
    c = _admin(api, seed)
    for raw in ('[1,2]', '"x"', 'not json'):
        r = c.post(f'/api/clusters/{CID}/backup-restore/batch', data=raw, content_type='application/json')
        assert r.status_code == 400, raw


def test_a_vzdump_file_names_its_guest_too(api, seed):
    pve = _Pve(api)
    c = _admin(api, seed)
    run = _start(c, [_local(100), _local(200, 'lxc')], first_vmid=8000)
    assert [(r['vmid'], r['type']) for r in run['rows']] == [(100, 'qemu'), (200, 'lxc')]
    _wait(lambda: pve.running() == [8000])
    pve.finish_all()


def test_a_cluster_without_guests_takes_a_restore(api, seed):
    pve = _Pve(api, guests=[])
    run = _start(_admin(api, seed), [_vol(100), _vol(101)])
    assert [r['target_vmid'] for r in run['rows']] == [100, 101]
    _wait(lambda: pve.running() == [100])
    pve.finish_all()


def test_a_target_vmid_that_is_taken_is_a_409(api, seed):
    pve = _Pve(api)
    r = _post(_admin(api, seed), items=[{'volid': _vol(100), 'target_vmid': 1000}], mode='new', target_node='pve1')
    assert r.status_code == 409 and r.get_json()['error'] == 'A target VMID is taken already'
    assert pve.started == []


def test_what_is_taken_is_said_only_after_the_backups_are_checked(api, seed):
    """A caller learns nothing about guests beyond them from a clash: the refusal comes first"""
    pve = _Pve(api)
    first = _start(_admin(api, seed), [_vol(101)], mode='overwrite', confirm=True)
    seed.tenant('acme', clusters=['cluster_9'])
    bob = api.as_user(seed.user('bob', role='user', tenant_id='acme'))
    seed.vm_acl(CID, 100, ['bob'])
    r = _post(bob, items=[{'volid': _vol(101)}], mode='overwrite', confirm=True, target_node='pve1')
    assert r.status_code == 403 and 'refused' in r.get_json()
    r = _post(bob, items=[{'volid': _vol(200, 'ct'), 'target_vmid': 1000}], mode='new', target_node='pve1')
    assert r.status_code == 403
    # with a backup of their own they may hear that the VMID is taken, as Proxmox would say
    r = _post(bob, items=[{'volid': _vol(100), 'target_vmid': 1000}], mode='new', target_node='pve1')
    assert r.status_code == 409
    _wait(lambda: pve.running() == [101])
    pve.finish_all()
    _wait(lambda: _over(first['id']))


def test_a_guest_another_batch_restores_is_not_taken_twice(api, seed):
    pve = _Pve(api)
    c = _admin(api, seed)
    first = _start(c, [_vol(100), _vol(101)], mode='overwrite', confirm=True)
    r = _post(c, items=[{'volid': _vol(101)}], mode='overwrite', confirm=True, target_node='pve1')
    assert r.status_code == 409
    # a new batch steps around the VMIDs the first one restores into
    second = _start(c, [_vol(200, 'ct')], first_vmid=100)
    assert second['rows'][0]['target_vmid'] == 102
    _wait(lambda: pve.running() == [100, 102])
    deadline = time.time() + 5
    while not _over(first['id']) and time.time() < deadline:
        pve.finish_all()
        time.sleep(0.02)
    assert _over(first['id']) and pve.targets() == [100, 102, 101]


# --- who may ---------------------------------------------------------------------------------

def test_one_backup_out_of_reach_and_none_starts(api, seed):
    pve = _Pve(api)
    seed.tenant('acme', clusters=['cluster_9'])
    bob = api.as_user(seed.user('bob', role='user', tenant_id='acme'))
    seed.vm_acl(CID, 100, ['bob'])
    r = _post(bob, items=[{'volid': _vol(100)}, {'volid': _vol(101)}], mode='overwrite', confirm=True,
              target_node='pve1')
    assert r.status_code == 403, r.data
    assert r.get_json()['refused'] == [{'volid': _vol(101), 'vmid': 101,
                                        'error': 'Permission denied for source backup'}]
    assert pve.started == [] and batch.runs() == []
    # their own guest alone goes
    run = _start(bob, [_vol(100)], mode='overwrite', confirm=True)
    _wait(lambda: pve.running() == [100])
    pve.finish_all()
    _wait(lambda: _over(run['id']))


def test_a_scoped_caller_restores_new_guests_only_onto_their_nodes(api, seed):
    pve = _Pve(api)
    seed.tenant('acme', clusters=['cluster_9'])
    bob = api.as_user(seed.user('bob', role='user', tenant_id='acme'))
    seed.vm_acl(CID, 100, ['bob'])
    r = _post(bob, items=[{'volid': _vol(100)}], mode='new', target_node='pve2', first_vmid=9000)
    assert r.status_code == 403 and 'node' in r.get_json()['error']
    run = _start(bob, [_vol(100)], target_node='pve1', first_vmid=9000)
    _wait(lambda: pve.running() == [9000])
    pve.finish_all()
    assert pve.targets() == [9000]


def test_new_guests_keep_to_the_tenant_range(api, seed):
    pve = _Pve(api)
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID],
                                   'vmid_range_start': 1500, 'vmid_range_end': 1999})
    ops = api.as_user(seed.user('ranged_op', role='user', tenant_id='ranged'))
    r = _post(ops, items=[{'volid': _vol(100)}, {'volid': _vol(101)}], mode='new', target_node='pve1',
              first_vmid=1999)
    assert r.status_code == 403
    assert [x['vmid'] for x in r.get_json()['refused']] == [101] and '1500-1999' in r.get_json()['refused'][0]['error']
    assert pve.started == []
    run = _start(ops, [_vol(100), _vol(101)], first_vmid=1500)
    assert [x['target_vmid'] for x in run['rows']] == [1500, 1501]
    _wait(lambda: pve.running() == [1500])
    pve.finish_all()


def test_a_caller_without_vm_backup_starts_nothing(api, seed):
    pve = _Pve(api)
    c = api.as_user(seed.user('looker', role='viewer'))
    assert _post(c, items=[{'volid': _vol(100)}], mode='new', target_node='pve1').status_code == 403
    assert pve.started == []


def test_a_confined_admin_and_another_tenant_neither_see_nor_act(api, seed):
    seed.tenant('globex', clusters=['cluster_2'])
    pve = _Pve(api)
    _Pve(api, cluster_id='cluster_2')
    run = _start(_admin(api, seed), [_vol(100), _vol(101)], first_vmid=6000)
    _wait(lambda: pve.running() == [6000])
    confined = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                     tenant_permissions={'globex': {'role': 'user'}}))
    other = api.as_user(seed.user('milton', role='user', tenant_id='globex'))
    for c in (confined, other):
        assert _post(c, items=[{'volid': _vol(101)}], mode='new', target_node='pve1').status_code == 403
        assert c.get('/api/batch-restores').get_json() == {'runs': []}
        assert c.get(f"/api/batch-restores/{run['id']}").status_code == 404
        assert c.post(f"/api/batch-restores/{run['id']}/cancel").status_code == 404
    assert batch.get(run['id']).cancelled_by == ''
    pve.finish_all()


def test_a_scoped_caller_sees_only_their_rows(api, seed):
    pve = _Pve(api)
    run = _start(_admin(api, seed), [_vol(100), _vol(101)], first_vmid=6100)
    seed.tenant('acme', clusters=['cluster_9'])
    bob = api.as_user(seed.user('bob', role='user', tenant_id='acme'))
    seed.vm_acl(CID, 100, ['bob'])
    view = _run(bob, run['id'])
    assert [r['vmid'] for r in view['rows']] == [100] and view['total'] == 1 and view['mine'] is False
    assert view['may_cancel'] is False
    pve.finish_all()


def test_a_disabled_account_restores_nothing_more(api, seed, monkeypatch):
    monkeypatch.setattr(batch, 'AUTHZ_SECONDS', 0)
    pve = _Pve(api)
    ops = seed.user('ops', role='user')
    run = _start(api.as_user(ops), [_vol(100), _vol(101)], first_vmid=6200)
    _wait(lambda: pve.running() == [6200])
    stored = seed.db.get_user('ops')
    stored['enabled'] = False
    seed.db.save_user('ops', stored)
    pve.finish(6200)
    _wait(lambda: _over(run['id']))
    rows = batch.get(run['id']).rows_copy()
    assert [r['state'] for r in rows] == ['done', 'skipped'] and 'disabled' in rows[1]['note']
    assert pve.targets() == [6200]


def test_a_permission_taken_away_meanwhile_skips_the_rest(api, seed, monkeypatch):
    monkeypatch.setattr(batch, 'AUTHZ_SECONDS', 0)
    pve = _Pve(api)
    seed.tenant('acme', clusters=['cluster_9'])
    bob = api.as_user(seed.user('bob', role='user', tenant_id='acme'))
    seed.vm_acl(CID, 100, ['bob'])
    seed.vm_acl(CID, 101, ['bob'])
    run = _start(bob, [_vol(100), _vol(101)], mode='overwrite', confirm=True)
    _wait(lambda: pve.running() == [100])
    seed.db.delete_vm_acl(CID, 101)
    rbac.invalidate_vm_acls_cache()
    pve.finish(100)
    _wait(lambda: _over(run['id']))
    rows = batch.get(run['id']).rows_copy()
    assert [(r['state'], r['note']) for r in rows] == [('done', ''), ('skipped', 'Permission denied for source backup')]
    assert pve.targets() == [100]


def test_a_standby_starts_and_cancels_nothing(ha_env, seed):  # noqa: F811
    api = ha_env.api
    pve = _Pve(api)
    c = api.as_user(seed.user('root', role='admin'))
    run = _start(c, [_vol(100), _vol(101)], first_vmid=6300)
    _wait(lambda: pve.running() == [6300])
    _standby_of_active(ha_env)
    r = _post(c, items=[{'volid': _vol(200, 'ct')}], mode='new', target_node='pve1')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = c.post(f"/api/batch-restores/{run['id']}/cancel")
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    # and the batch of this process starts nothing more once it is a standby
    pve.finish(6300)
    _wait(lambda: _over(run['id']))
    stopped = batch.get(run['id'])
    assert stopped.state == 'stopped' and 'standby' in stopped.reason
    assert [r['state'] for r in stopped.rows_copy()][1] == 'cancelled'
    assert pve.targets() == [6300]


def test_a_forwarding_standby_reads_the_batches_on_the_active():
    from pegaprox.core import ha
    assert {'/api/batch-restores', '/api/batch-restores/<run_id>'} <= ha.FORWARDED_READS


def test_the_routes_are_served_once(api):
    rules = sorted((r.rule, sorted(r.methods - {'HEAD', 'OPTIONS'})) for r in api.app.url_map.iter_rules()
                   if 'batch-restore' in r.rule or 'backup-restore' in r.rule)
    assert rules == [('/api/batch-restores', ['GET']),
                     ('/api/batch-restores/<run_id>', ['GET']),
                     ('/api/batch-restores/<run_id>/cancel', ['POST']),
                     ('/api/clusters/<cluster_id>/backup-restore', ['POST']),
                     ('/api/clusters/<cluster_id>/backup-restore/batch', ['POST'])]


def test_an_unknown_batch_is_not_found(api, seed):
    c = _admin(api, seed)
    for path in ('/api/batch-restores/0123456789abcdef', '/api/batch-restores/..'):
        assert c.get(path).status_code == 404
    assert c.post('/api/batch-restores/0123456789abcdef/cancel').status_code == 404


def test_too_many_batches_on_one_cluster(api, seed, monkeypatch):
    monkeypatch.setattr(batch, 'RUNNING_PER_CLUSTER', 1)
    pve = _Pve(api)
    c = _admin(api, seed)
    _start(c, [_vol(100)], first_vmid=6400)
    r = _post(c, items=[{'volid': _vol(101)}], mode='new', target_node='pve1', first_vmid=6500)
    assert r.status_code == 409 and 'running on this cluster already' in r.get_json()['error']
    pve.finish_all()


def test_the_single_restore_goes_the_same_way(api, seed):
    pve = _Pve(api)
    r = _admin(api, seed).post(f'/api/clusters/{CID}/backup-restore', json={
        'volid': _vol(200, 'ct'), 'target_node': 'pve2', 'target_vmid': 777, 'mode': 'new',
        'target_storage': 'local-zfs'})
    assert r.status_code == 200 and r.get_json()['upid'].startswith('UPID:pve2:')
    # a container comes back through pct's create: the archive as ostemplate, restore set
    assert pve.started == [('pve2', 'lxc', {'vmid': 777, 'ostemplate': _vol(200, 'ct'), 'restore': 1,
                                            'storage': 'local-zfs'})]
    pve.fail.add(778)
    r = _admin(api, seed).post(f'/api/clusters/{CID}/backup-restore', json={
        'volid': _vol(100), 'target_node': 'pve2', 'target_vmid': 778, 'mode': 'new'})
    assert r.status_code == 500 and 'storage full' in r.get_json()['error'] and r.get_json()['pve_status'] == 500
