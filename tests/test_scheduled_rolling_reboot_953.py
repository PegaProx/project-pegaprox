"""Scheduled rolling updates must read the reboot outcome of each completed task (#953)."""

import threading
import time

from pegaprox.core.manager import UpdateTask


NODE = 'blade1'


class _Clock:
    """Record requested waits while letting the scheduled worker yield briefly."""

    def __init__(self):
        """Start with no requested waits."""
        self.slept = []

    def __getattr__(self, name):
        """Delegate date and clock reads to the real time module."""
        return getattr(time, name)

    def sleep(self, seconds):
        """Record the requested delay without making a regression take minutes."""
        self.slept.append(seconds)
        time.sleep(0.001)


def _completed_task(rebooted, back_online):
    """Return a node update task that has finished its own reboot handling."""
    task = UpdateTask(NODE, reboot=True)
    task.status, task.phase = 'completed', 'done'
    task.reboot_issued = rebooted
    task.back_online = back_online
    return task


def _run(api, monkeypatch, task):
    """Run one scheduled node update through the real scheduler worker."""
    import pegaprox.api.schedules as schedules_mod

    clock = _Clock()
    monkeypatch.setattr(schedules_mod, 'time', clock)
    fake = api.make_fake_manager()
    fake.get_node_status.return_value = {NODE: {'status': 'online'}}
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in (NODE, 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.start_node_update.return_value = task
    fake.exit_maintenance_mode.return_value = False
    fake.nodes_in_maintenance = {}
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    api.set_manager('cluster_1', fake)

    schedules_mod.execute_scheduled_rolling_update(fake, 'cluster_1', {
        'config': {'include_reboot': True, 'skip_up_to_date': False,
                   'skip_evacuation': True, 'wait_for_reboot': True}
    })
    deadline = time.time() + 20
    while time.time() < deadline and (fake._rolling_update or {}).get('status') == 'running':
        time.sleep(0.01)
    state = fake._rolling_update
    assert state['status'] == 'completed', state['logs']
    return state, clock


def test_schedule_does_not_claim_a_reboot_that_never_happened(api, monkeypatch):
    """A completed update with reboot_issued=False must skip the offline wait."""
    state, clock = _run(api, monkeypatch, _completed_task(False, False))
    logs = '\n'.join(state['logs'])
    assert state['node_state'][NODE]['rebooted'] is False
    assert f'Waiting for {NODE} to reboot' not in logs
    assert 5 not in clock.slept


def test_schedule_does_not_wait_for_an_already_finished_reboot(api, monkeypatch):
    """A task that saw its node return must not wait for another offline event."""
    state, clock = _run(api, monkeypatch, _completed_task(True, True))
    logs = '\n'.join(state['logs'])
    assert state['node_state'][NODE]['rebooted'] is True
    assert f'{NODE} rebooted during the update and is back online' in logs
    assert f'Waiting for {NODE} to reboot' not in logs
    assert 5 not in clock.slept


def test_schedule_still_waits_if_the_task_cannot_confirm_recovery(api, monkeypatch):
    """An issued reboot without a confirmed return keeps the fallback wait."""
    state, clock = _run(api, monkeypatch, _completed_task(True, False))
    logs = '\n'.join(state['logs'])
    assert state['node_state'][NODE]['rebooted'] is True
    assert f'Waiting for {NODE} to reboot' in logs
    assert 5 in clock.slept
