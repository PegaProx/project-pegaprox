"""Shared rolling-update refresh cancellation and synchronous-provider controls."""

import threading

import pytest

from test_rolling_skip_check_refresh_1135 import _AptNode, _Clock, _manager, NODE
import pegaprox.api.settings as settings_mod
import pegaprox.core.manager as mgrmod
from pegaprox.core import rolling_runs


def _run_observed(api, seed, monkeypatch, fake, clock, *, check_updates=True):
    """Join the real shared worker even after a fixture cancels its persisted run."""
    done = threading.Event()
    original = settings_mod.run_rolling_update

    def observed(*args, **kwargs):
        """Mark worker completion, rather than treating a canceled row as completion."""
        try:
            return original(*args, **kwargs)
        finally:
            done.set()

    monkeypatch.setattr(settings_mod, 'run_rolling_update', observed)
    monkeypatch.setattr(settings_mod, 'time', clock)
    monkeypatch.setattr(mgrmod, 'time', clock)
    api.set_manager('cluster_1', fake)
    root = seed.user('root', role='admin')
    response = api.as_user(root).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': False, 'skip_up_to_date': check_updates, 'skip_evacuation': True})
    assert response.status_code == 200, response.data
    assert done.wait(10), 'shared rolling worker did not finish'
    return fake._rolling_update


@pytest.mark.parametrize('done_after', [None, 0], ids=['running', 'completed'])
def test_cancel_during_refresh_stops_polling_without_reading_updates(api, seed, monkeypatch, done_after):
    """Cancel on the first real task-status poll, before the cache read or maintenance."""
    clock = _Clock()
    apt = _AptNode(clock, done_after=done_after, before=('pve-manager',))
    fake = _manager(api, apt)
    original_poll = apt.api_get

    def cancel_on_poll(*args, **kwargs):
        """Publish cancellation while the manager is waiting on the remote task."""
        response = original_poll(*args, **kwargs)
        rolling_runs.change(fake, status='cancelled')
        return response

    fake._api_get.side_effect = cancel_on_poll
    state = _run_observed(api, seed, monkeypatch, fake, clock)
    assert state['status'] == 'cancelled'
    assert apt.polls == 1
    assert apt.read_at is None
    fake.enter_maintenance_mode.assert_not_called()
    fake.start_node_update.assert_not_called()


def test_cancel_during_package_read_does_not_record_a_skip(api, seed, monkeypatch):
    """An empty list read concurrently with cancel must not mark the node completed."""
    clock = _Clock()
    apt = _AptNode(clock, done_after=0, after=())
    fake = _manager(api, apt)

    def cancel_on_read(node):
        """Return an otherwise valid empty package list after cancellation."""
        rolling_runs.change(fake, status='cancelled')
        return apt.updates(node)

    fake.get_node_apt_updates.side_effect = cancel_on_read
    state = _run_observed(api, seed, monkeypatch, fake, clock)
    assert state['status'] == 'cancelled'
    assert state['skipped_nodes'] == []
    fake.enter_maintenance_mode.assert_not_called()
    fake.start_node_update.assert_not_called()


def test_cancel_after_quorum_check_does_not_enter_maintenance(api, seed, monkeypatch):
    """The maintenance-state refresh may take long enough for a user to cancel."""
    clock = _Clock()
    apt = _AptNode(clock, done_after=0)
    fake = _manager(api, apt)
    fake.refresh_maintenance_status.side_effect = lambda: rolling_runs.change(fake, status='cancelled')
    state = _run_observed(api, seed, monkeypatch, fake, clock, check_updates=False)
    assert state['status'] == 'cancelled'
    fake.enter_maintenance_mode.assert_not_called()
    fake.start_node_update.assert_not_called()


@pytest.mark.parametrize('provider, expected_delay', [('xcpng', 0), ('proxmox', 3)])
def test_no_task_refresh_delay_matches_provider(api, seed, monkeypatch, provider, expected_delay):
    """SSH yum is already synchronous; preserve the legacy PVE no-UPID delay."""
    clock = _Clock()
    apt = _AptNode(clock, done_after=0, after=())
    fake = _manager(api, apt, cluster_type=provider)
    apt.started = clock.now
    fake.refresh_node_apt.side_effect = None
    fake.refresh_node_apt.return_value = {'success': True, 'task': None}
    state = _run_observed(api, seed, monkeypatch, fake, clock)
    assert state['status'] == 'completed'
    assert apt.read_at - apt.started == expected_delay
    assert state['skipped_nodes'] == [NODE]
    fake._wait_for_task.assert_not_called()
    fake.start_node_update.assert_not_called()
