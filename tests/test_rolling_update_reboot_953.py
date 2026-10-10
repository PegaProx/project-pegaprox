# #953 - the update task sends the reboot and waits for the node to come back before it
# reports 'completed'. The rolling-update loop then read reboot_issued, logged "requires a
# reboot - rebooting" and polled 120s for an offline state that had ended minutes earlier:
# "did not go offline within 120s", then "back online (0s)". After that it warned
# "maintenance exit failed" for a node the update task had already taken out.

import threading
import time
from unittest.mock import MagicMock

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager, UpdateTask
from pegaprox.models.tasks import UpdateTask as ModelUpdateTask


class _FastTime:
    """The module's time, minus the waiting."""
    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def sleep(_s):
        pass


# -- the update task -----------------------------------------------------------

def _ssh():
    s = MagicMock()
    s.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())
    return s


def _updating_manager(back):
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.nodes_in_maintenance = {}
    m._get_node_ip = lambda node: '10.0.0.5'
    m._ssh_connect = lambda ip, **kw: _ssh()
    # needrestart is not installed (exit 1): the reboot is forced, as on the reported node
    m._ssh_execute = lambda ssh, cmd, task=None: (1 if 'dpkg -s needrestart' in cmd else 0, '', '')
    m._wait_for_node_online = lambda node: back
    m._schedule_update_clear = lambda node, task: None
    m.exit_maintenance_mode = MagicMock(return_value=True)
    return m


def test_the_update_task_records_that_the_node_came_back(monkeypatch):
    monkeypatch.setattr(mgrmod, 'time', _FastTime())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    task = UpdateTask('blade1', reboot=True)
    PegaProxManager._perform_node_update(_updating_manager(True), 'blade1', task)
    assert task.status == 'completed', task.error
    assert task.reboot_issued is True
    assert task.back_online is True, "the task saw the node come back but did not say so"


def test_a_node_that_never_came_back_is_not_marked_back(monkeypatch):
    monkeypatch.setattr(mgrmod, 'time', _FastTime())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    task = UpdateTask('blade1', reboot=True)
    PegaProxManager._perform_node_update(_updating_manager(False), 'blade1', task)
    assert task.status == 'failed' and task.phase == 'wait_timeout', task.error
    assert task.reboot_issued is True
    assert task.back_online is False


def test_a_fresh_task_claims_no_reboot():
    """reboot_issued used to be absent until the reboot block ran, and the loop read
    the absence as 'a reboot happened'."""
    for cls in (UpdateTask, ModelUpdateTask):
        t = cls('n1')
        assert t.reboot_issued is False and t.back_online is False, cls


# -- the rolling-update loop ---------------------------------------------------

def _run(api, seed, monkeypatch, task):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'time', _FastTime())
    root = seed.user('root', role='admin')
    fake = api.make_fake_manager()
    fake.get_node_status.return_value = {'blade1': {'status': 'online'}}
    # the quorum gate before the node goes down reads /cluster/status: three votes, one may go
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in ('blade1', 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.start_node_update.return_value = task
    fake.exit_maintenance_mode.return_value = False   # what the real one says for an untracked node
    fake.nodes_in_maintenance = {}                    # the update task already took it out
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    api.set_manager('cluster_1', fake)

    r = api.as_user(root).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': True, 'skip_up_to_date': False, 'skip_evacuation': True})
    assert r.status_code == 200, r.data
    deadline = time.time() + 20
    while time.time() < deadline and fake._rolling_update.get('status') == 'running':
        time.sleep(0.05)
    state = fake._rolling_update
    assert state['status'] == 'completed', state['logs']
    return '\n'.join(state['logs']), fake


def _finished_task(back):
    t = UpdateTask('blade1', reboot=True)
    t.status, t.phase = 'completed', 'done'
    t.reboot_issued = True
    t.back_online = back
    return t


def test_the_run_does_not_wait_again_for_a_reboot_the_task_saw(api, seed, monkeypatch):
    logs, _ = _run(api, seed, monkeypatch, _finished_task(True))
    assert 'requires a reboot' not in logs, logs
    assert 'did not go offline' not in logs, logs
    assert 'back online (0s)' not in logs, logs
    assert 'blade1 rebooted during the update and is back online' in logs
    assert 'blade1 updated successfully' in logs


def test_no_failed_exit_for_a_node_the_task_took_out_of_maintenance(api, seed, monkeypatch):
    logs, fake = _run(api, seed, monkeypatch, _finished_task(True))
    assert 'maintenance exit failed' not in logs, logs
    fake.exit_maintenance_mode.assert_not_called()


def test_a_reboot_the_task_did_not_see_through_is_still_waited_for(api, seed, monkeypatch):
    """Counter-check: the skip needs the task's own confirmation, not just the reboot."""
    logs, _ = _run(api, seed, monkeypatch, _finished_task(False))
    assert 'requires a reboot' in logs, logs
