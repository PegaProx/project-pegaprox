"""A scheduled backup task writes to the storage it was created with.

The create and update routes took backup_storage, but the save left it out of the stored
task and the load had nothing to read back. The scheduler loop and POST .../run both load
the task from the database, so every scheduled backup went to 'local'.

The manager here is a double of the real one, so a method it does not have, or a call it
does not take, fails the test. The one before had every method: it took the storage as a
fourth argument, which XcpngManager.backup_vm takes by name only, so on XCP-ng every
scheduled backup raised a TypeError. PegaProxManager has no backup_vm at all; the storage
is followed on XCP-ng, whose manager has the call, and Proxmox VE refuses a backup task
before it is stored (test_scheduled_tasks_report_their_outcome.py).

MK Nov 2026
"""
import json
from unittest.mock import create_autospec

import pytest

from pegaprox.background import scheduler
from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager


@pytest.fixture
def root(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def backups(api):
    sent = []
    m = create_autospec(XcpngManager, instance=True)
    m.cluster_type = 'xcpng'

    def backup(node, vmid, vm_type='qemu', **kw):
        sent.append(kw['storage'])
        return 'OpaqueRef:backup-task'
    m.backup_vm.side_effect = backup
    api.set_manager('cluster_1', m)
    return sent


@pytest.fixture
def pve(api):
    m = create_autospec(PegaProxManager, instance=True)
    api.set_manager('cluster_1', m)
    return m


def _create(client, **over):
    body = {'name': 'nightly', 'cluster_id': 'cluster_1', 'target_type': 'qemu', 'target_id': '101',
            'target_node': 'pve1', 'action': 'backup', 'backup_storage': 'pbs-x'}
    body.update(over)
    r = client.post('/api/scheduled-tasks', json=body)
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()


def _loaded(task_id):
    return next(t for t in scheduler.load_scheduled_tasks()['tasks'] if t['id'] == task_id)


def test_the_loaded_task_backs_up_to_the_storage_it_was_created_with(root, backups):
    task = _create(root)
    assert task['backup_storage'] == 'pbs-x'
    assert scheduler.execute_scheduled_task(_loaded(task['id'])) is None
    assert backups == ['pbs-x']


def test_run_now_backs_up_to_the_chosen_storage(root, backups):
    task = _create(root)
    r = root.post(f"/api/scheduled-tasks/{task['id']}/run")
    assert r.status_code == 200, r.get_data(as_text=True)
    assert backups == ['pbs-x']


def test_a_save_of_another_task_and_an_edit_keep_it(root, backups):
    task = _create(root)
    _create(root, name='other', backup_storage='nfs-b')
    # every save rewrites all rows from what was loaded
    assert root.put(f"/api/scheduled-tasks/{task['id']}", json={'schedule_time': '03:00'}).status_code == 200
    assert _loaded(task['id']).get('backup_storage') == 'pbs-x'
    assert root.put(f"/api/scheduled-tasks/{task['id']}", json={'backup_storage': 'nfs-b'}).status_code == 200
    assert _loaded(task['id']).get('backup_storage') == 'nfs-b'


def test_rows_stored_without_a_storage_read_as_local(db):
    db.conn.execute(
        "INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, config, "
        "enabled, created_at) VALUES ('t1', 'cluster_1', 'older', 'backup', ?, ?, 1, '2026-01-01')",
        (json.dumps({'schedule_type': 'daily', 'schedule_time': '05:00', 'schedule_day': 0}),
         json.dumps({'config': {}, 'action': 'backup', 'target_type': 'qemu', 'target_id': '101',
                     'target_node': 'pve1'})))
    db.conn.execute(
        "INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, config, "
        "enabled, created_at) VALUES ('t2', 'cluster_1', 'legacy', 'backup', ?, ?, 1, '2026-01-01')",
        (json.dumps({'schedule_type': 'daily', 'schedule_time': '05:00', 'schedule_day': 0}),
         json.dumps({'foo': 'bar'})))
    db.conn.commit()
    assert _loaded('t1').get('backup_storage') == 'local'
    assert _loaded('t2').get('backup_storage') == 'local'
    assert _loaded('t2')['config'] == {'foo': 'bar'}


def test_on_proxmox_ve_a_backup_task_is_refused_before_it_is_stored(root, pve):
    assert not hasattr(pve, 'backup_vm')
    r = root.post('/api/scheduled-tasks', json={
        'name': 'nightly', 'cluster_id': 'cluster_1', 'target_type': 'qemu', 'target_id': '101',
        'target_node': 'pve1', 'action': 'backup', 'backup_storage': 'pbs-x'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'not supported for Proxmox VE scheduled tasks' in r.get_json()['error']
    assert scheduler.load_scheduled_tasks()['tasks'] == []
    assert pve.mock_calls == []
