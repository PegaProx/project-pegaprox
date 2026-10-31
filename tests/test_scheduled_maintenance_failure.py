"""A scheduled update must stop when entering maintenance fails, even without evacuation."""

import threading

import pytest

from pegaprox.models.tasks import MaintenanceTask, UpdateTask
from test_rolling_templates_affinity_763_954 import _FastTime, _finish


@pytest.mark.parametrize('failure', ['refused', 'failed', 'partial'])
def test_refused_maintenance_does_not_force_start_an_update(api, monkeypatch, failure):
    """A false or failed maintenance result never reaches the forced updater."""
    import pegaprox.api.schedules as schedules

    monkeypatch.setattr(schedules, 'time', _FastTime())
    manager = api.make_fake_manager()
    manager.get_node_status.return_value = {'blade1': {'status': 'online'}}
    manager._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in ('blade1', 'blade2', 'blade3')]
    manager.get_ceph_health_summary.return_value = None
    manager.nodes_in_maintenance = {}
    manager.maintenance_lock = threading.Lock()
    manager._rolling_update = None
    update = UpdateTask('blade1', reboot=False)
    update.status = 'completed'
    manager.start_node_update.return_value = update

    def enter(node, **kwargs):
        """Refuse before or after registering a partially prepared host."""
        task = MaintenanceTask(node)
        task.status, task.error = 'failed', 'host disable failed'
        if failure == 'partial':
            manager.nodes_in_maintenance[node] = task
        return task if failure == 'failed' else None

    def leave(node):
        """Clear a partial maintenance entry during failure cleanup."""
        manager.nodes_in_maintenance.pop(node, None)
        return True

    manager.enter_maintenance_mode.side_effect = enter
    manager.exit_maintenance_mode.side_effect = leave
    api.set_manager('cluster_1', manager)
    schedules.execute_scheduled_rolling_update(manager, 'cluster_1', {
        'config': {'include_reboot': False, 'skip_up_to_date': False, 'skip_evacuation': True}
    })
    state = _finish(manager)
    assert state['status'] == 'failed', state['logs']
    assert 'maintenance' in state['error'].lower()
    assert state['completed_nodes'] == []
    manager.start_node_update.assert_not_called()
    if failure == 'partial':
        manager.exit_maintenance_mode.assert_called_once_with('blade1')
        assert manager.nodes_in_maintenance == {}
