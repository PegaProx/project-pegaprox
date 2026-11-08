# #953 - "maintenance exit failed (will retry at end of run)" for a node that was fine.
# The update task takes the node out of maintenance itself once it is back, and it does so
# while the rolling-update loop sleeps its 30s before the exit. The loop then called
# exit_maintenance_mode for a node no longer in the manager's list, which answers False for
# that, and logged the answer as a failed exit. Only a node still in maintenance after the
# exit is one; that one keeps the warning and its retry at the end of the run.

import threading
import time

from pegaprox.core.manager import UpdateTask
from pegaprox.models.tasks import MaintenanceTask

NODE = 'blade1'


class _Clock:
    """The module's time; a sleep is over at once and can let something happen meanwhile."""
    def __init__(self, during_sleep=None):
        self.slept = []
        self.during_sleep = during_sleep

    def __getattr__(self, name):
        return getattr(time, name)

    def sleep(self, s):
        self.slept.append(s)
        if self.during_sleep:
            self.during_sleep(s)


def _finished_task(rebooted=True):
    t = UpdateTask(NODE, reboot=True)
    t.status, t.phase = 'completed', 'done'
    t.reboot_issued = rebooted
    t.back_online = rebooted
    return t


def _manager(api, cluster_type='proxmox', node_status=None):
    fake = api.make_fake_manager(cluster_type=cluster_type)
    fake.get_node_status.return_value = node_status or {NODE: {'status': 'online'}}
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in (NODE, 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.maintenance_lock = threading.Lock()
    task = MaintenanceTask(NODE)
    task.status = 'completed'
    fake.nodes_in_maintenance = {NODE: task}     # the run put it in
    fake._rolling_update = None
    return fake


def _exit_as_the_manager_does(fake, own_call_fails=False, task_exits_meanwhile=False):
    """exit_maintenance_mode as the manager answers: False for a node not in its list, False
    and the node left in it when ha-manager would not let go of it, True once it is out."""
    calls = []

    def _exit(node, who='system'):
        calls.append(node)
        if task_exits_meanwhile:
            # the update task's own exit got through while this one tried ha-manager
            fake.nodes_in_maintenance.pop(node, None)
        if node not in fake.nodes_in_maintenance:
            return False
        if own_call_fails and len(calls) == 1:
            return False
        fake.nodes_in_maintenance.pop(node, None)
        return True

    fake.exit_maintenance_mode.side_effect = _exit
    return calls


def _run(api, seed, monkeypatch, fake, clock):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'time', clock)
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', fake)
    r = api.as_user(root).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': True, 'skip_up_to_date': False, 'skip_evacuation': True})
    assert r.status_code == 200, r.data
    deadline = time.time() + 20
    while time.time() < deadline and fake._rolling_update.get('status') == 'running':
        time.sleep(0.05)
    state = fake._rolling_update
    assert state['status'] == 'completed', state['logs']
    return '\n'.join(state['logs']), state


def test_a_node_the_task_took_out_during_the_wait_is_no_failed_exit(api, seed, monkeypatch):
    fake = _manager(api)
    fake.start_node_update.return_value = _finished_task()
    calls = _exit_as_the_manager_does(fake)

    def _the_task_exits(s):
        if s == 30:
            fake.nodes_in_maintenance.pop(NODE, None)

    clock = _Clock(_the_task_exits)
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    assert 30 in clock.slept, "the node rebooted: the loop waits before the exit"
    assert 'maintenance exit failed' not in logs, logs
    assert 'still in maintenance, retrying' not in logs, logs
    assert state['node_state'][NODE]['in_maintenance'] is False
    assert not state['failed_nodes'], state['failed_nodes']
    assert f'{NODE} updated successfully' in logs
    assert len(calls) <= 1, calls


def test_a_node_the_task_took_out_while_the_exit_ran_is_no_failed_exit(api, seed, monkeypatch):
    """The loop's own ha-manager call failed, the update task's got through at the same time:
    the node is out, which is all the warning was meant to say something about."""
    fake = _manager(api)
    fake.start_node_update.return_value = _finished_task(rebooted=False)
    calls = _exit_as_the_manager_does(fake, own_call_fails=True, task_exits_meanwhile=True)
    logs, state = _run(api, seed, monkeypatch, fake, _Clock())
    assert calls == [NODE], "the node was in maintenance when the loop came to it"
    assert 'maintenance exit failed' not in logs, logs
    assert state['node_state'][NODE]['in_maintenance'] is False
    assert not state['failed_nodes'], state['failed_nodes']


def test_an_exit_that_really_failed_warns_and_is_retried_at_the_end(api, seed, monkeypatch):
    """Counter-check: the node stays in maintenance after the exit, the run says so and
    takes it out at its end."""
    fake = _manager(api)
    fake.start_node_update.return_value = _finished_task()
    calls = _exit_as_the_manager_does(fake, own_call_fails=True)
    logs, state = _run(api, seed, monkeypatch, fake, _Clock())
    assert f'⚠ {NODE} maintenance exit failed (will retry at end of run)' in logs, logs
    assert 'Cleanup: 1 node(s) still in maintenance, retrying' in logs, logs
    assert f'✓ {NODE} maintenance cleared on retry' in logs, logs
    assert calls == [NODE, NODE], "one exit in the node's turn, one in the cleanup"
    assert state['node_state'][NODE]['in_maintenance'] is False
    assert NODE not in fake.nodes_in_maintenance


def test_an_exit_that_keeps_failing_is_reported_stuck(api, seed, monkeypatch):
    fake = _manager(api)
    fake.start_node_update.return_value = _finished_task()
    fake.exit_maintenance_mode.return_value = False      # ha-manager never lets go
    logs, state = _run(api, seed, monkeypatch, fake, _Clock())
    assert f'{NODE} maintenance exit failed (will retry at end of run)' in logs, logs
    assert f'{NODE} STILL stuck' in logs, logs
    assert [f['node'] for f in state['failed_nodes']] == [NODE]


def test_a_proxmox_node_counts_by_the_list_not_by_a_cached_status(api, seed, monkeypatch):
    """The node status of a Proxmox cluster is cached for a few seconds and copies the list
    from when it was read: a node the task took out a moment ago can still show there."""
    fake = _manager(api, node_status={NODE: {'status': 'online', 'maintenance_mode': True}})
    fake.start_node_update.return_value = _finished_task(rebooted=False)
    _exit_as_the_manager_does(fake, own_call_fails=True, task_exits_meanwhile=True)
    logs, state = _run(api, seed, monkeypatch, fake, _Clock())
    assert 'maintenance exit failed' not in logs, logs
    assert state['node_state'][NODE]['in_maintenance'] is False


def test_an_xcpng_host_still_disabled_is_a_failed_exit(api, seed, monkeypatch):
    """An XCP-ng host is in maintenance while it is disabled, whatever the list says (a restart
    of PegaProx forgets the list, the host stays disabled)."""
    fake = _manager(api, cluster_type='xcpng',
                    node_status={NODE: {'status': 'online', 'maintenance_mode': True}})
    fake.start_node_update.return_value = _finished_task(rebooted=False)

    def _exit(node, who='system'):
        fake.nodes_in_maintenance.pop(node, None)        # the list has it no more
        return None                                      # host.enable did not go through
    fake.exit_maintenance_mode.side_effect = _exit
    logs, state = _run(api, seed, monkeypatch, fake, _Clock())
    assert f'{NODE} maintenance exit failed (will retry at end of run)' in logs, logs


def test_an_xcpng_host_enabled_again_is_no_failed_exit(api, seed, monkeypatch):
    fake = _manager(api, cluster_type='xcpng',
                    node_status={NODE: {'status': 'online', 'maintenance_mode': False}})
    fake.start_node_update.return_value = _finished_task(rebooted=False)

    def _exit(node, who='system'):
        fake.nodes_in_maintenance.pop(node, None)
        return None
    fake.exit_maintenance_mode.side_effect = _exit
    logs, state = _run(api, seed, monkeypatch, fake, _Clock())
    assert 'maintenance exit failed' not in logs, logs
    assert state['node_state'][NODE]['in_maintenance'] is False
