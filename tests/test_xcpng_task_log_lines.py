"""The task log of an XCP-ng task reads line by line.

The log route joins what get_node_task_log hands it with '\n'. The Proxmox manager hands
a list of lines; the XCP-ng one handed the text itself, so the join put a newline after
every character and the task bar printed one character per line.
NS Nov 2026
"""
import threading

import pytest

from pegaprox.core.xcpng import XcpngManager

CL = 'cluster_1'
REF = 'a1b2c3d4'


def _xcpng(tasks):
    x = XcpngManager.__new__(XcpngManager)
    x.id = CL
    x.cluster_type = 'xcpng'
    x.is_connected = True
    x._task_lock = threading.Lock()
    x._active_tasks = dict(tasks)
    x._api = lambda: None          # no XAPI session: no progress line
    return x


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _task(**kw):
    t = {'action': 'start', 'status': 'completed', 'vmid': 101, 'started': '2026-11-01T09:00:00'}
    t.update(kw)
    return t


def test_the_log_route_answers_lines_not_characters(api, admin):
    api.set_manager(CL, _xcpng({REF: _task(status='failed', error='VM_BAD_POWER_STATE')}))
    r = admin.get(f'/api/clusters/{CL}/nodes/h1/tasks/{REF}/log')
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    body = r.get_json()
    # what the task bar prints (dashboard.js fetchTaskLog: data.log in a <pre>)
    assert body['log'].splitlines() == ['Action: start', 'Status: failed', 'VMID: 101',
                                        'Started: 2026-11-01T09:00:00', 'Error: VM_BAD_POWER_STATE']
    assert body['lines'] == body['log'].splitlines()


def test_an_unknown_task_says_so_on_one_line(api, admin):
    api.set_manager(CL, _xcpng({}))
    body = admin.get(f'/api/clusters/{CL}/nodes/h1/tasks/{REF}/log').get_json()
    assert body['lines'] == [f'Task {REF} not found']
    assert body['log'] == f'Task {REF} not found'


def test_a_reader_that_tails_gets_only_the_lines_after_start(api, admin):
    api.set_manager(CL, _xcpng({REF: _task()}))
    body = admin.get(f'/api/clusters/{CL}/nodes/h1/tasks/{REF}/log?start=2').get_json()
    assert body['lines'] == ['VMID: 101', 'Started: 2026-11-01T09:00:00']
    body = admin.get(f'/api/clusters/{CL}/nodes/h1/tasks/{REF}/log?start=9').get_json()
    assert body['lines'] == [] and body['log'] == ''
