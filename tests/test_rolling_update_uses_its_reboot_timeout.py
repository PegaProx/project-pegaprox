"""The reboot timeout of a rolling update is the one the wait uses.

The update task always waited 600 s (300 s on XCP-ng) for the node, whatever the run asked
for, and the run's own update timeout kept counting during that wait. A server that takes
20 minutes to boot failed even with reboot_timeout=1800.
"""
import threading
import time
import types

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager, UpdateTask
from pegaprox.models.tasks import UpdateTask as ModelUpdateTask
from test_rolling_update_reboot_953 import _FastTime, _updating_manager  # noqa: F401


@pytest.mark.parametrize('rolling, expected', [
    ({'status': 'running', 'reboot_timeout': 1800}, 1800), ({'status': 'running', 'reboot_timeout': 60}, 60),
    # a run that ended long ago says nothing about a node updated by hand now
    ({'status': 'completed', 'reboot_timeout': 60}, 600), ({}, 600), (None, 600)])
def test_the_update_task_waits_as_long_as_the_run_says(monkeypatch, rolling, expected):
    monkeypatch.setattr(mgrmod, 'time', _FastTime())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    m = _updating_manager(True)
    m._rolling_update = rolling
    asked = []
    m._wait_for_node_online = lambda node, timeout=600: asked.append(timeout) or True
    PegaProxManager._perform_node_update(m, 'blade1', UpdateTask('blade1', reboot=True))
    assert asked == [expected]


class _LongTask(UpdateTask):
    """Stays in one phase for a number of looks at its status, then finishes."""
    looks = 0

    def __init__(self, phase, looks):
        super().__init__('blade1', reboot=True)
        self.__dict__.update(phase=phase, reboot_issued=True, back_online=True, _left=looks)

    @property
    def status(self):
        if self.__dict__['_left'] <= 0:
            return 'completed'
        self.__dict__['_left'] -= 1
        return 'waiting_online'

    @status.setter
    def status(self, value):
        pass


class _YieldingTime(_FastTime):
    """No real waiting, but the rest of the process gets its turn."""
    @staticmethod
    def sleep(_s):
        time.sleep(0.001)


def _start(api, seed, monkeypatch, task):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'time', _YieldingTime())
    fake = api.make_fake_manager()
    fake.get_node_status.return_value = {'blade1': {'status': 'online'}}
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in ('blade1', 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.start_node_update.return_value = task
    fake.exit_maintenance_mode.return_value = False
    fake.nodes_in_maintenance = {}
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    api.set_manager('cluster_1', fake)
    r = api.as_user(seed.user('root', role='admin')).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': True, 'skip_up_to_date': False, 'skip_evacuation': True})
    assert r.status_code == 200, r.data
    return fake


def _logs_until(fake, done):
    deadline = time.time() + 20
    while time.time() < deadline:
        state = fake._rolling_update or {}
        if done(state):
            break
        time.sleep(0.02)
    return state


def test_a_long_reboot_does_not_use_up_the_update_timeout(api, seed, monkeypatch):
    # the default update timeout is 900 s: this is far more looks than that at 10 s each
    fake = _start(api, seed, monkeypatch, _LongTask('wait_online', 400))
    state = _logs_until(fake, lambda s: s.get('status') != 'running' or any('timed out' in x for x in s.get('logs', [])))
    logs = '\n'.join(state['logs'])
    state['status'] = 'cancelled'
    assert 'timed out' not in logs, logs
    assert 'updated successfully' in logs, logs


def test_a_stuck_install_still_times_out(api, seed, monkeypatch):
    fake = _start(api, seed, monkeypatch, _LongTask('updating', 10 ** 9))
    state = _logs_until(fake, lambda s: any('timed out' in x for x in s.get('logs', [])))
    logs = '\n'.join(state['logs'])
    state['status'] = 'cancelled'
    assert 'timed out' in logs, logs


@pytest.mark.parametrize('rolling, expected', [({'status': 'running', 'reboot_timeout': 1800}, 1800),
                                              ({'status': 'completed', 'reboot_timeout': 60}, 300), ({}, 300)])
def test_an_xcpng_host_waits_as_long_as_the_run_says(monkeypatch, rolling, expected):
    from pegaprox.core import xcpng
    monkeypatch.setattr(xcpng.time, 'sleep', lambda s: None)
    out = types.SimpleNamespace(read=lambda *a: b'', channel=types.SimpleNamespace(recv_exit_status=lambda: 0))
    ssh = types.SimpleNamespace(exec_command=lambda cmd, timeout=None: (None, out, out), close=lambda: None)
    asked = []
    mgr = types.SimpleNamespace(id='x1', _rolling_update=rolling, _get_host_ip=lambda n: '10.0.0.9',
                                _ssh_connect=lambda ip: ssh,
                                _wait_for_host_online=lambda n, timeout=300: asked.append(timeout) or True)
    xcpng.XcpngManager._perform_node_update(mgr, 'h1', ModelUpdateTask('h1', True))
    assert asked == [expected]
