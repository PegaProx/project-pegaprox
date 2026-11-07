"""wait_for_reboot=False of a rolling update reaches the update task.

The dialog and the schedule offer it and the run reads it, but the task waited for the node
either way, so the setting never changed anything for a node the task rebooted.
"""
import threading
import time
import types

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager, UpdateTask
from pegaprox.models.tasks import UpdateTask as ModelUpdateTask
from test_rolling_update_reboot_953 import _FastTime, _updating_manager  # noqa: F401

NO_WAIT = {'status': 'running', 'wait_for_reboot': False, 'current_node': 'blade1'}
WAITS = [{'status': 'running', 'wait_for_reboot': True, 'current_node': 'blade1'},
         {'status': 'running', 'current_node': 'blade1'},
         # another node's run says nothing about a node updated by hand meanwhile
         dict(NO_WAIT, current_node='blade2'),
         dict(NO_WAIT, status='completed'), {}, None]


def _task_manager(monkeypatch, rolling):
    monkeypatch.setattr(mgrmod, 'time', _FastTime())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    m = _updating_manager(True)
    m._rolling_update = rolling
    m.nodes_in_maintenance = {'blade1': object()}
    m.asked = []
    m._wait_for_node_online = lambda node, timeout=600: m.asked.append(node) or True
    return m


def test_the_task_does_not_wait_when_the_run_said_so(monkeypatch):
    m = _task_manager(monkeypatch, NO_WAIT)
    task = UpdateTask('blade1', reboot=True)
    PegaProxManager._perform_node_update(m, 'blade1', task)
    assert m.asked == []
    assert task.status == 'completed' and task.reboot_issued is True
    assert task.back_online is False, "nobody saw the node come back"
    # the node is on its way down: the run takes it out of maintenance, with its retry
    m.exit_maintenance_mode.assert_not_called()


@pytest.mark.parametrize('rolling', WAITS)
def test_the_task_waits_otherwise(monkeypatch, rolling):
    m = _task_manager(monkeypatch, rolling)
    task = UpdateTask('blade1', reboot=True)
    PegaProxManager._perform_node_update(m, 'blade1', task)
    assert m.asked == ['blade1'] and task.back_online is True
    m.exit_maintenance_mode.assert_called_once()


@pytest.mark.parametrize('rolling, waits', [(NO_WAIT, False)] + [(r, True) for r in WAITS])
def test_an_xcpng_host_the_same(monkeypatch, rolling, waits):
    from pegaprox.core import xcpng
    monkeypatch.setattr(xcpng.time, 'sleep', lambda s: None)
    out = types.SimpleNamespace(read=lambda *a: b'', channel=types.SimpleNamespace(recv_exit_status=lambda: 0))
    ssh = types.SimpleNamespace(exec_command=lambda cmd, timeout=None: (None, out, out), close=lambda: None)
    asked = []
    mgr = types.SimpleNamespace(id='x1', _rolling_update=rolling, _get_host_ip=lambda n: '10.0.0.9',
                                _ssh_connect=lambda ip: ssh,
                                _wait_for_host_online=lambda n, timeout=300: asked.append(n) or True)
    task = ModelUpdateTask('blade1', True)
    xcpng.XcpngManager._perform_node_update(mgr, 'blade1', task)
    assert bool(asked) is waits
    assert task.status == 'completed' and task.reboot_issued is True and task.back_online is waits


class _YieldingTime(_FastTime):
    @staticmethod
    def sleep(_s):
        time.sleep(0.001)


def test_the_run_goes_on_without_waiting_through_the_real_task(api, seed, monkeypatch):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'time', _YieldingTime())
    monkeypatch.setattr(mgrmod, 'time', _FastTime())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    fake = api.make_fake_manager()
    fake.get_node_status.return_value = {'blade1': {'status': 'online'}}
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in ('blade1', 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.exit_maintenance_mode.return_value = True
    fake.nodes_in_maintenance = {}
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    real = _updating_manager(True)
    real.asked = []
    real._wait_for_node_online = lambda node, timeout=600: real.asked.append(node) or True

    def start(node, reboot=True):
        real._rolling_update = fake._rolling_update
        task = UpdateTask(node, reboot=reboot)
        PegaProxManager._perform_node_update(real, node, task)
        return task
    fake.start_node_update.side_effect = start
    api.set_manager('cluster_1', fake)
    r = api.as_user(seed.user('root', role='admin')).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': True, 'skip_up_to_date': False, 'skip_evacuation': True, 'wait_for_reboot': False})
    assert r.status_code == 200, r.data
    deadline = time.time() + 20
    while time.time() < deadline and fake._rolling_update.get('status') == 'running':
        time.sleep(0.01)
    state = fake._rolling_update
    logs = '\n'.join(state['logs'])
    assert state['status'] == 'completed', logs
    assert real.asked == [], logs
    assert 'Not waiting for blade1 (wait_for_reboot=False)' in logs, logs
    assert 'rebooted during the update and is back online' not in logs, logs
    assert state['node_state']['blade1']['rebooted'] is True, logs
