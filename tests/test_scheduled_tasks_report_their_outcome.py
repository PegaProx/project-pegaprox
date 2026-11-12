"""A scheduled task says what it did: the run route and the scheduler report the outcome.

execute_scheduled_task called start_vm, stop_vm, restart_vm, shutdown_vm and backup_vm,
which only XcpngManager has. On Proxmox VE every such task raised an AttributeError that
the log called a failure, while POST /api/scheduled-tasks/<id>/run answered that the task
was executed; a snapshot the cluster refused was audited as executed too, and on XCP-ng the
backup call raised a TypeError (the storage went in by position).

Those actions are refused on Proxmox VE now, with a reason that names what to use instead:
at create and update, and for a row stored long ago at run time, where the scheduler logs
it at warning and audits the failure, and the run route answers 400. They are not made to
run, or tasks saved long ago would start acting after the update. A snapshot works as
before and its failure is reported; XCP-ng keeps its power actions. The managers here are
doubles of the real ones, so a method they lack fails the test.

MK Nov 2026
"""
import json
import logging
from datetime import datetime
from unittest.mock import create_autospec

import pytest

from pegaprox.background import scheduler
from pegaprox.core import ha
from pegaprox.core.esxi_cluster import ESXiClusterManager
from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager

PVE, XCP, ESXI = 'pve_c', 'xcp_c', 'esxi_c'
REFUSED = ('start', 'stop', 'restart', 'shutdown', 'backup')


@pytest.fixture
def root(api, seed):
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def pve(api):
    m = create_autospec(PegaProxManager, instance=True)
    m.create_snapshot.return_value = {'success': True, 'task': 'UPID:pve1:snapshot'}
    return api.set_manager(PVE, m)


@pytest.fixture
def xcp(api):
    m = create_autospec(XcpngManager, instance=True)
    m.cluster_type = 'xcpng'
    for meth in ('start_vm', 'stop_vm', 'restart_vm', 'shutdown_vm'):
        getattr(m, meth).return_value = 'OpaqueRef:task'
    m.create_snapshot.return_value = {'success': True}
    # what XcpngManager.backup_vm answers: XCP-ng backups are Xen Orchestra's
    m.backup_vm.return_value = None
    return api.set_manager(XCP, m)


def _body(cluster, action, **over):
    body = {'name': f'{action} nightly', 'cluster_id': cluster, 'target_type': 'qemu',
            'target_id': '101', 'target_node': 'pve1', 'action': action}
    body.update(over)
    return body


def _create(client, cluster, action, **over):
    r = client.post('/api/scheduled-tasks', json=_body(cluster, action, **over))
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()


def _stored_row(db, tid, cluster, action, last_run=None):
    """A task saved before this release, as the table holds it."""
    db.conn.execute(
        "INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, config, enabled, "
        "last_run, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, '2026-01-01')",
        (tid, cluster, f'old {action}', action,
         json.dumps({'schedule_type': 'daily', 'schedule_time': '04:30', 'schedule_day': 0}),
         json.dumps({'config': {}, 'action': action, 'target_type': 'qemu', 'target_id': '101',
                     'target_node': 'pve1', 'backup_storage': 'local'}), last_run))
    db.conn.commit()


def _row(db, tid):
    return dict(db.conn.execute('SELECT * FROM scheduled_tasks WHERE id = ?', (tid,)).fetchone())


def _audits(db):
    return [(r['user'], r['action'], r['details'])
            for r in db.query("SELECT user, action, details FROM audit_log "
                              "WHERE action LIKE 'scheduled_task.%' ORDER BY id")]


def _tasks():
    return scheduler.load_scheduled_tasks()['tasks']


# --- Proxmox VE: create and update ------------------------------------------------------

@pytest.mark.parametrize('action', REFUSED)
def test_proxmox_ve_refuses_to_create_a_task_it_cannot_run(root, pve, action):
    r = root.post('/api/scheduled-tasks', json=_body(PVE, action))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['error'] == scheduler.PVE_REFUSAL
    assert 'snapshot policy' in scheduler.PVE_REFUSAL and 'backup job' in scheduler.PVE_REFUSAL
    assert _tasks() == []
    assert pve.mock_calls == []


def test_a_cluster_unknown_here_is_taken_for_proxmox_ve(root):
    r = root.post('/api/scheduled-tasks', json=_body('gone', 'stop'))
    assert r.status_code == 400 and r.get_json()['error'] == scheduler.PVE_REFUSAL


def test_an_edit_into_such_a_task_is_refused_and_changes_nothing(root, pve):
    task = _create(root, PVE, 'snapshot')
    r = root.put(f"/api/scheduled-tasks/{task['id']}", json={'action': 'start', 'name': 'renamed'})
    assert r.status_code == 400 and r.get_json()['error'] == scheduler.PVE_REFUSAL
    kept = next(t for t in _tasks() if t['id'] == task['id'])
    assert (kept['action'], kept['name']) == ('snapshot', 'snapshot nightly')
    assert root.put(f"/api/scheduled-tasks/{task['id']}", json={'name': 'renamed'}).status_code == 200


def test_a_stored_task_stays_until_it_is_edited(root, pve, db):
    _stored_row(db, 'old1', PVE, 'start')
    assert [t['id'] for t in root.get('/api/scheduled-tasks').get_json()['tasks']] == ['old1']
    r = root.put('/api/scheduled-tasks/old1', json={'schedule_time': '05:00'})
    assert r.status_code == 400 and r.get_json()['error'] == scheduler.PVE_REFUSAL
    assert json.loads(_row(db, 'old1')['schedule'])['schedule_time'] == '04:30'
    assert root.delete('/api/scheduled-tasks/old1').status_code == 200
    assert _tasks() == []


def test_an_unknown_action_is_refused(root, pve):
    r = root.post('/api/scheduled-tasks', json=_body(PVE, 'reformat'))
    assert r.status_code == 400 and 'Unknown action' in r.get_json()['error']


# --- Proxmox VE: a stored task at run time ----------------------------------------------

@pytest.mark.parametrize('action', REFUSED)
def test_run_now_of_a_stored_task_answers_the_refusal(root, pve, db, action):
    _stored_row(db, 'old1', PVE, action)
    r = root.post('/api/scheduled-tasks/old1/run')
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['error'] == scheduler.PVE_REFUSAL
    assert pve.mock_calls == []
    assert _row(db, 'old1')['last_run'] is None, 'a run that did not happen was stamped'
    assert _audits(db) == [('scheduler', 'scheduled_task.failed',
                            f"Task 'old {action}' was not run: {scheduler.PVE_REFUSAL}")]


def test_the_scheduler_logs_the_refusal_at_warning_and_audits_it(pve, db, monkeypatch, caplog):
    _stored_row(db, 'old1', PVE, 'backup')
    monkeypatch.setattr(ha, 'schedule_now', lambda: datetime(2026, 11, 12, 4, 30, 5))
    with caplog.at_level(logging.WARNING):
        scheduler.run_scheduled_tasks()
    hits = [r for r in caplog.records if 'old backup' in r.getMessage()]
    assert hits and all(r.levelno == logging.WARNING for r in hits), caplog.text
    assert scheduler.PVE_REFUSAL in hits[0].getMessage()
    assert _audits(db) == [('scheduler', 'scheduled_task.failed',
                            f"Task 'old backup' was not run: {scheduler.PVE_REFUSAL}")]
    assert pve.mock_calls == []
    # the slot is used up as for any task the loop took, so it is said once a day
    assert _row(db, 'old1')['last_run'].startswith('2026-11-12T04:30')


# --- snapshot keeps working, and says when it did not ------------------------------------

def test_a_snapshot_task_runs_on_proxmox_ve(root, pve, db):
    task = _create(root, PVE, 'snapshot')
    r = root.post(f"/api/scheduled-tasks/{task['id']}/run")
    assert r.status_code == 200, r.get_data(as_text=True)
    (call,) = pve.create_snapshot.call_args_list
    node, vmid, vt, name, desc, vmstate = call.args
    assert (node, vmid, vt, desc, vmstate) == ('pve1', 101, 'qemu', 'Scheduled snapshot', False)
    assert name.startswith('scheduled_')
    assert _audits(db)[-1][:2] == ('scheduler', 'scheduled_task.executed')
    assert next(t for t in _tasks() if t['id'] == task['id'])['last_run']


def test_a_snapshot_the_cluster_refuses_is_reported_as_failed(root, pve, db):
    pve.create_snapshot.return_value = {'success': False,
                                        'error': 'Snapshots are not supported for this storage type'}
    task = _create(root, PVE, 'snapshot')
    r = root.post(f"/api/scheduled-tasks/{task['id']}/run")
    assert r.status_code == 500, r.get_data(as_text=True)
    assert 'Snapshots are not supported for this storage type' in r.get_json()['error']
    assert _audits(db)[-1][:2] == ('scheduler', 'scheduled_task.failed')
    assert not next(t for t in _tasks() if t['id'] == task['id'])['last_run']


def test_a_task_whose_cluster_is_gone_answers_404(root, db):
    _stored_row(db, 'old1', 'gone', 'snapshot')
    r = root.post('/api/scheduled-tasks/old1/run')
    assert r.status_code == 404 and r.get_json()['error'] == 'Cluster not found'


# --- XCP-ng keeps what it has -----------------------------------------------------------

@pytest.mark.parametrize('action,method', [('start', 'start_vm'), ('stop', 'stop_vm'),
                                           ('restart', 'restart_vm'), ('shutdown', 'shutdown_vm')])
def test_xcpng_runs_its_power_actions(root, xcp, db, action, method):
    task = _create(root, XCP, action)
    r = root.post(f"/api/scheduled-tasks/{task['id']}/run")
    assert r.status_code == 200, r.get_data(as_text=True)
    getattr(xcp, method).assert_called_once_with('pve1', 101, 'qemu')
    assert _audits(db)[-1][:2] == ('scheduler', 'scheduled_task.executed')


def test_an_xcpng_action_that_started_no_task_is_reported(root, xcp):
    xcp.start_vm.return_value = None
    task = _create(root, XCP, 'start')
    r = root.post(f"/api/scheduled-tasks/{task['id']}/run")
    assert r.status_code == 500 and 'started no task' in r.get_json()['error']


def test_an_xcpng_backup_is_called_as_the_manager_takes_it_and_reports_none_started(root, xcp, db):
    task = _create(root, XCP, 'backup', backup_storage='sr-1')
    r = root.post(f"/api/scheduled-tasks/{task['id']}/run")
    xcp.backup_vm.assert_called_once_with('pve1', 101, 'qemu', storage='sr-1')
    assert r.status_code == 500 and 'started no task' in r.get_json()['error']
    assert _audits(db)[-1][:2] == ('scheduler', 'scheduled_task.failed')


def test_a_cluster_without_the_call_refuses_the_task(root, api):
    m = create_autospec(ESXiClusterManager, instance=True)
    m.cluster_type = 'esxi'
    api.set_manager(ESXI, m)
    r = root.post('/api/scheduled-tasks', json=_body(ESXI, 'snapshot'))
    assert r.status_code == 400 and 'not supported for scheduled tasks on this cluster' in r.get_json()['error']
