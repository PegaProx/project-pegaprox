"""The bulk snapshot delete waits for each delete task (#1347).

PVE answers a snapshot DELETE with a task and takes the guest's lock only inside it. The
bulk delete sent the next DELETE as soon as the one before was accepted, so the later
tasks of the same guest failed on the lock ("VM is locked") while the answer counted
every snapshot as deleted. Each task is now waited for before the next delete goes out,
and only a task that ended OK counts, as the retention prune does.
"""
import pytest


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_adm', role='admin'))


def _mgr(api, task_ok):
    calls = []
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True

    def delete_snapshot(node, vmid, vm_type, snapname):
        calls.append(('delete', snapname))
        return {'success': True, 'task': f'UPID:n1:{snapname}'}

    def wait_for_task(node, upid, timeout=600):
        calls.append(('wait', upid))
        return task_ok(upid)

    m.delete_snapshot.side_effect = delete_snapshot
    m._wait_for_task.side_effect = wait_for_task
    api.set_manager('cluster_1', m)
    return m, calls


def _items(*names):
    return {'snapshots': [{'cluster_id': 'cluster_1', 'node': 'n1', 'vmid': 100,
                           'vm_type': 'qemu', 'snapshot_name': n} for n in names]}


def test_each_delete_task_ends_before_the_next_delete(api, admin):
    m, calls = _mgr(api, lambda upid: True)
    r = admin.post('/api/snapshots/delete', json=_items('s1', 's2', 's3'))
    body = r.get_json()
    assert body['success'] is True and body['deleted'] == 3, r.get_data(as_text=True)
    assert calls == [('delete', 's1'), ('wait', 'UPID:n1:s1'),
                     ('delete', 's2'), ('wait', 'UPID:n1:s2'),
                     ('delete', 's3'), ('wait', 'UPID:n1:s3')]


def test_a_delete_task_that_failed_is_not_counted(api, admin):
    m, calls = _mgr(api, lambda upid: not upid.endswith(':s2'))
    r = admin.post('/api/snapshots/delete', json=_items('s1', 's2', 's3'))
    body = r.get_json()
    assert body['deleted'] == 2, r.get_data(as_text=True)
    assert len(body['errors']) == 1 and 's2' in body['errors'][0] and 'UPID:n1:s2' in body['errors'][0]


def test_a_refused_delete_is_not_waited_for(api, admin):
    m, calls = _mgr(api, lambda upid: True)
    m.delete_snapshot.side_effect = lambda *a: {'success': False, 'error': 'snapshot does not exist'}
    r = admin.post('/api/snapshots/delete', json=_items('s1'))
    assert r.status_code == 500 and 'snapshot does not exist' in r.get_json()['errors'][0]
    assert calls == []
