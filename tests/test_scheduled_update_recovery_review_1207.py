"""Recovery and cleanup contracts for scheduled rolling updates (#1207)."""
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as manager_mod
import pegaprox.core.xcpng as xcpng_mod
import test_scheduled_rolling_reboot_953 as scheduled
from pegaprox.core.manager import PegaProxManager, UpdateTask
from pegaprox.core.xcpng import XcpngManager
from test_rolling_update_reboot_953 import _FastTime, _updating_manager


def _scheduled(api, monkeypatch, task, *, external_exit=False, cancel=False):
    events = []
    threads = []
    fake = api.make_fake_manager()
    monkeypatch.setattr(api, 'make_fake_manager', lambda: fake)

    class Clock(scheduled._Clock):
        def sleep(self, seconds):
            events.append(('sleep', seconds))
            super().sleep(seconds)

    monkeypatch.setattr(scheduled, '_Clock', Clock)

    def enter(node, **kwargs):
        fake.nodes_in_maintenance[node] = object()

    def start(node, **kwargs):
        events.append(('update', kwargs))
        if external_exit or (task.status == 'completed' and kwargs.get('auto_exit_maintenance', True)):
            fake.nodes_in_maintenance.pop(node, None)
            events.append(('worker_exit', node))
        if cancel:
            fake._rolling_update['status'] = 'cancelled'
        return task

    def leave(node):
        events.append(('exit', node))
        return fake.nodes_in_maintenance.pop(node, None) is not None

    fake.enter_maintenance_mode.side_effect = enter
    fake.start_node_update.side_effect = start
    fake.exit_maintenance_mode.side_effect = leave
    import pegaprox.api.schedules as schedules_mod
    attach = schedules_mod.rolling_runs.attach

    def track_worker(manager, cluster_id, thread=None):
        threads.append(thread)
        return attach(manager, cluster_id, thread)

    monkeypatch.setattr(schedules_mod.rolling_runs, 'attach', track_worker)
    state, clock = scheduled._run(
        api, monkeypatch, task, expected_status='cancelled' if cancel else 'completed')
    assert threads
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive(), 'scheduled cleanup did not finish'
    return fake, state, clock, events


def test_schedule_settles_before_its_owned_maintenance_exit(api, monkeypatch):
    """A completed updater cannot clear maintenance before the schedule's HA wait."""
    fake, state, clock, events = _scheduled(
        api, monkeypatch, scheduled._completed_task(True, True))
    assert 30 in clock.slept
    assert fake.start_node_update.call_args.kwargs['auto_exit_maintenance'] is False
    assert ('worker_exit', scheduled.NODE) not in events
    assert events.index(('sleep', 30)) < events.index(('exit', scheduled.NODE))
    assert fake.nodes_in_maintenance == {}


def test_schedule_still_settles_if_an_external_actor_already_cleared_maintenance(api, monkeypatch):
    """Maintenance membership is not evidence that HA services have settled."""
    fake, state, clock, events = _scheduled(
        api, monkeypatch, scheduled._completed_task(True, True), external_exit=True)
    assert 30 in clock.slept
    assert fake.nodes_in_maintenance == {}


@pytest.mark.parametrize('cancel', [False, True])
def test_failed_or_cancelled_schedule_cleans_its_owned_maintenance(api, monkeypatch, cancel):
    """Moving cleanup ownership must not strand a failed or cancelled run."""
    task = scheduled._completed_task(True, True)
    if not cancel:
        task.status = 'failed'
    fake, state, clock, events = _scheduled(api, monkeypatch, task, cancel=cancel)
    assert fake.nodes_in_maintenance == {}
    assert ('exit', scheduled.NODE) in events
    if not cancel:
        assert state['failed_nodes'][0]['node'] == scheduled.NODE


def test_missing_recovery_confirmation_keeps_the_fallback_wait(api, monkeypatch):
    """Legacy tasks without back_online still take the scheduled recovery path."""
    task = scheduled._completed_task(True, False)
    del task.back_online
    state, clock = scheduled._run(api, monkeypatch, task)
    assert 5 in clock.slept
    assert f'Waiting for {scheduled.NODE} to reboot' in '\n'.join(state['logs'])


@pytest.mark.parametrize('defer', [False, True])
def test_proxmox_worker_preserves_default_exit_but_can_leave_cleanup_to_caller(monkeypatch, defer):
    """Standalone updates retain auto-exit; scheduled workers leave it to their caller."""
    monkeypatch.setattr(manager_mod, 'time', _FastTime())
    monkeypatch.setattr(manager_mod, '_read_capped', lambda *a, **kw: '0')
    manager = _updating_manager(True)
    manager.nodes_in_maintenance = {scheduled.NODE: object()}
    task = UpdateTask(scheduled.NODE, reboot=True)
    if defer:
        task.auto_exit_maintenance = False
    PegaProxManager._perform_node_update(manager, scheduled.NODE, task)
    assert task.status == 'completed', task.error
    if defer:
        manager.exit_maintenance_mode.assert_not_called()
    else:
        manager.exit_maintenance_mode.assert_called_once_with(scheduled.NODE)


@pytest.mark.parametrize('manager_class', [PegaProxManager, XcpngManager])
def test_cleanup_ownership_is_recorded_before_the_update_worker_starts(monkeypatch, manager_class):
    """Both manager interfaces accept the scheduler's cleanup choice before launch."""
    seen = []

    class Thread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def start(self):
            seen.append(self.kwargs['args'][1].auto_exit_maintenance)

    monkeypatch.setattr(manager_mod, 'GEVENT_PATCHED', False)
    monkeypatch.setattr(threading, 'Thread', Thread)
    manager = manager_class.__new__(manager_class)
    manager.logger = MagicMock()
    manager.nodes_updating = {}
    manager.nodes_in_maintenance = {}
    manager.update_lock = threading.Lock()
    manager._perform_node_update = MagicMock()
    task = manager.start_node_update(scheduled.NODE, force=True, auto_exit_maintenance=False)
    assert task.auto_exit_maintenance is False
    assert seen == [False]


class _PollingClock:
    def __init__(self):
        self.now = 0

    def sleep(self, seconds):
        self.now += seconds

    def time(self):
        return self.now


@pytest.mark.parametrize('ready_after', [None, 1, 2])
def test_xcp_recovery_requires_a_target_routed_rpc(monkeypatch, ready_after):
    """An open target port and a live master do not prove the target XAPI is ready."""
    import socket
    api = MagicMock()
    api.host.get_all.return_value = ['master-ref', 'target-ref']
    api.host.get_hostname.side_effect = lambda ref: {'master-ref': 'master', 'target-ref': 'target'}[ref]
    api.host.get_name_label.side_effect = api.host.get_hostname.side_effect
    calls = []

    def get_time(ref):
        calls.append(ref)
        if ref == 'master-ref':
            return '20261101T00:00:00Z'
        if ready_after is None or len(calls) < ready_after:
            raise OSError('target XAPI not ready')
        return '20261101T00:00:00Z'

    api.host.get_servertime.side_effect = get_time
    manager = XcpngManager.__new__(XcpngManager)
    manager._api = lambda: api
    manager._get_host_ip = lambda node: '192.0.2.10'
    manager._cached_nodes = ['stale']
    connect = MagicMock()
    monkeypatch.setattr(socket, 'create_connection', connect)
    monkeypatch.setattr(xcpng_mod, 'time', _PollingClock())
    online = manager._wait_for_host_online('target', timeout=30)
    assert online is (ready_after is not None)
    assert calls and set(calls) == {'target-ref'}
    connect.assert_called_with(('192.0.2.10', 443), timeout=5)
    assert manager._cached_nodes == (None if online else ['stale'])
