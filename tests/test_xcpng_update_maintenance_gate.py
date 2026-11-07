"""XCP-ng updates use the same completed-maintenance gate as Proxmox updates."""

import logging
import threading
from types import SimpleNamespace

import pytest

from pegaprox.core import xcpng
from pegaprox.models.tasks import UpdateTask


def _manager(monkeypatch, status):
    """Build an XCP-ng manager that records worker starts without reaching a host."""
    manager = xcpng.XcpngManager.__new__(xcpng.XcpngManager)
    manager.logger = logging.getLogger('xcpng-update-test')
    manager.nodes_in_maintenance = {} if status is None else {'host1': SimpleNamespace(status=status)}
    manager.nodes_updating = {}
    manager.update_lock = threading.Lock()
    manager._perform_node_update = lambda *args: None
    starts = []

    class Worker:
        """Record the async updater that would be started."""

        def __init__(self, **kwargs):
            """Keep the worker's target and arguments for assertions."""
            self.kwargs = kwargs

        def start(self):
            """Record the worker without running SSH or yum."""
            starts.append(self.kwargs)

    monkeypatch.setattr(xcpng, 'threading', SimpleNamespace(Thread=Worker))
    monkeypatch.setattr(xcpng.ha, 'as_job', lambda fn, *args: fn)
    return manager, starts


@pytest.mark.parametrize('status', ['completed', 'completed_with_errors'])
def test_an_evacuated_host_can_start_its_update(monkeypatch, status):
    """The maintenance record made by the rolling run must permit its update."""
    manager, starts = _manager(monkeypatch, status)
    task = manager.start_node_update('host1', reboot=False)
    assert isinstance(task, UpdateTask)
    assert manager.nodes_updating['host1'] is task
    assert len(starts) == 1
    assert starts[0]['args'] == ('host1', task)


@pytest.mark.parametrize('status', [None, 'pending', 'evacuating', 'failed'])
def test_an_unprepared_host_cannot_start_a_normal_update(monkeypatch, status):
    """Missing or unfinished maintenance does not launch the update worker."""
    manager, starts = _manager(monkeypatch, status)
    assert manager.start_node_update('host1') is None
    assert manager.nodes_updating == {}
    assert starts == []


def test_explicit_force_can_still_skip_the_maintenance_gate(monkeypatch):
    """The caller's existing force opt-out remains available."""
    manager, starts = _manager(monkeypatch, None)
    assert isinstance(manager.start_node_update('host1', force=True), UpdateTask)
    assert len(starts) == 1


def test_a_running_update_is_reused_instead_of_starting_another(monkeypatch):
    """A prepared host keeps its current update task and worker."""
    manager, starts = _manager(monkeypatch, 'completed')
    task = UpdateTask('host1', reboot=False)
    task.status = 'updating'
    manager.nodes_updating['host1'] = task
    assert manager.start_node_update('host1') is task
    assert starts == []
