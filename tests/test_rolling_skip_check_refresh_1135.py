# #1135 - "Skip up-to-date nodes" started the apt update of the node and read its package
# list 3s later. On a slow mirror the apt update was not through by then, the read got the
# list of the one before, and a node with updates waiting could be skipped as up-to-date.
# The check now waits for the apt update task (the manager's own _wait_for_task, against a
# fake Proxmox here) and reads the list after it. A refresh that fails, or one still running
# after the wait, leaves the run going on with the cached list and a warning that says so.

import functools
import threading
import time

import pegaprox.core.manager as mgrmod
from pegaprox.core import rolling_runs
from pegaprox.core.manager import PegaProxManager, UpdateTask

NODE = 'blade1'
UPID = 'UPID:blade1:0000A1B2:00C3D4E5:6720F000:aptupdate::root@pam:'
WAIT = 180


class _Clock:
    """Time as the run and the manager see it: a sleep moves it on at once."""
    def __init__(self):
        self.now = 1_800_000_000.0

    def __getattr__(self, name):
        return getattr(time, name)

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s


class _Response:
    def __init__(self, data):
        self.status_code = 200
        self._data = data

    def json(self):
        return {'data': self._data}


class _AptNode:
    """The apt update of one node: running until done_after seconds after it started, then
    stopped with exitstatus. The package list says what the last finished apt update read."""
    def __init__(self, clock, done_after, exitstatus='OK', before=(), after=('pve-manager', 'qemu-server')):
        self.clock = clock
        self.done_after = done_after
        self.exitstatus = exitstatus
        self.before, self.after = list(before), list(after)
        self.started = None
        self.polls = 0
        self.read_at = None

    def _done(self):
        return self.started is not None and self.done_after is not None \
            and self.clock.now - self.started >= self.done_after

    def refresh(self, node):
        self.started = self.clock.now
        return {'success': True, 'task': UPID}

    def api_get(self, url, *a, **k):
        assert url.endswith(f'/nodes/{NODE}/tasks/{UPID}/status'), url
        self.polls += 1
        if self._done():
            return _Response({'status': 'stopped', 'exitstatus': self.exitstatus})
        return _Response({'status': 'running'})

    def updates(self, node):
        self.read_at = self.clock.now
        fresh = self._done() and self.exitstatus == 'OK'
        return [{'Package': p} for p in (self.after if fresh else self.before)]


def _finished_task():
    t = UpdateTask(NODE, reboot=False)
    t.status, t.phase = 'completed', 'done'
    return t


def _manager(api, apt, cluster_type='proxmox'):
    fake = api.make_fake_manager(cluster_type=cluster_type)
    fake.get_node_status.return_value = {NODE: {'status': 'online'}}
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in (NODE, 'blade2', 'blade3')]
    fake.get_ceph_health_summary.return_value = None
    fake.start_node_update.return_value = _finished_task()
    fake.nodes_in_maintenance = {}
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    fake.host, fake.api_port = '10.0.0.5', 8006
    fake.refresh_node_apt.side_effect = apt.refresh
    fake.get_node_apt_updates.side_effect = apt.updates
    fake._api_get.side_effect = apt.api_get
    # the real wait of the manager, polling the fake node above
    fake._wait_for_task.side_effect = functools.partial(PegaProxManager._wait_for_task, fake)
    return fake


def _run(api, seed, monkeypatch, fake, clock):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'time', clock)
    monkeypatch.setattr(mgrmod, 'time', clock)
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', fake)
    r = api.as_user(root).post('/api/clusters/cluster_1/updates/rolling', json={
        'include_reboot': False, 'skip_up_to_date': True, 'skip_evacuation': True})
    assert r.status_code == 200, r.data
    deadline = time.time() + 20
    while time.time() < deadline and fake._rolling_update.get('status') == 'running':
        time.sleep(0.05)
    state = fake._rolling_update
    assert state['status'] == 'completed', state['logs']
    return '\n'.join(state['logs']), state


def test_the_list_is_read_once_a_slow_apt_update_is_through(api, seed, monkeypatch):
    clock = _Clock()
    apt = _AptNode(clock, done_after=45)        # a slow mirror, well past the old 3s
    fake = _manager(api, apt)
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    assert apt.read_at - apt.started >= 45, "the list was read before the apt update was through"
    assert 'SKIPPING' not in logs, logs
    assert f'Found 2 updates available on {NODE}' in logs, logs
    assert 'may be stale' not in logs, logs
    assert NODE in state['completed_nodes'] and NODE not in state['skipped_nodes']
    # one look at the task every 2s, not a busy loop against the node
    assert apt.polls <= 45 // 2 + 2, apt.polls


def test_a_node_up_to_date_after_the_refresh_is_still_skipped(api, seed, monkeypatch):
    clock = _Clock()
    apt = _AptNode(clock, done_after=20, before=('pve-manager',), after=())
    fake = _manager(api, apt)
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    assert f'{NODE} is already up-to-date - SKIPPING' in logs, logs
    assert state['skipped_nodes'] == [NODE]
    fake.start_node_update.assert_not_called()


def test_an_apt_update_still_running_after_the_wait_goes_on_with_the_cached_list(api, seed, monkeypatch):
    clock = _Clock()
    apt = _AptNode(clock, done_after=None, before=('pve-manager',))   # never through
    fake = _manager(api, apt)
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    waited = apt.read_at - apt.started
    assert WAIT <= waited < WAIT + 10, f"waited {waited}s for the apt update"
    assert f'Package lists of {NODE} not refreshed' in logs, logs
    assert 'reading the cached list, it may be stale' in logs, logs
    # not aborted: the cached list decides, here one update
    assert f'Found 1 updates available on {NODE}' in logs, logs
    assert NODE in state['completed_nodes']


def test_a_failed_apt_update_goes_on_with_the_cached_list_at_once(api, seed, monkeypatch):
    clock = _Clock()
    apt = _AptNode(clock, done_after=6, exitstatus="command 'apt-get update' failed: exit code 100",
                   before=('pve-manager',))
    fake = _manager(api, apt)
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    assert apt.read_at - apt.started < 15, "a task that ended failed is not waited out"
    assert 'it may be stale' in logs, logs
    assert f'Found 1 updates available on {NODE}' in logs, logs


def test_a_refresh_proxmox_refused_goes_on_with_the_cached_list(api, seed, monkeypatch):
    clock = _Clock()
    apt = _AptNode(clock, done_after=0, before=())
    fake = _manager(api, apt)
    fake.refresh_node_apt.side_effect = None
    fake.refresh_node_apt.return_value = {'success': False, 'error': '403 Permission check failed'}
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    assert apt.polls == 0, "no task to wait on"
    assert f'Package lists of {NODE} not refreshed (403 Permission check failed)' in logs, logs
    assert f'{NODE} is already up-to-date - SKIPPING' in logs, logs


def test_a_refresh_that_raises_without_a_message_still_says_so(api, seed, monkeypatch):
    # str() of a bare TimeoutError is '', which used to read as "nothing went wrong"
    clock = _Clock()
    apt = _AptNode(clock, done_after=0, before=('pve-manager',))
    fake = _manager(api, apt)
    fake.refresh_node_apt.side_effect = TimeoutError()
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    assert f'Package lists of {NODE} not refreshed (TimeoutError)' in logs, logs
    assert f'Found 1 updates available on {NODE}' in logs, logs


def test_an_xcpng_refresh_has_no_task_to_wait_on(api, seed, monkeypatch):
    """yum makecache runs over SSH and is done when the call returns; nothing to poll."""
    clock = _Clock()
    apt = _AptNode(clock, done_after=0)
    fake = _manager(api, apt, cluster_type='xcpng')
    fake.refresh_node_apt.side_effect = None
    fake.refresh_node_apt.return_value = {'success': True, 'task': None}
    apt.started = clock.now
    logs, state = _run(api, seed, monkeypatch, fake, clock)
    fake._wait_for_task.assert_not_called()
    assert 'may be stale' not in logs, logs
    assert f'Found 2 updates available on {NODE}' in logs, logs


def test_scheduled_run_waits_for_apt_refresh_before_skipping(api, seed, monkeypatch):
    """A slow refresh must not make a scheduled run skip newly available updates."""
    import pegaprox.api.schedules as schedules_mod

    clock = _Clock()
    apt = _AptNode(clock, done_after=45, before=(), after=('pve-manager',))
    fake = _manager(api, apt)
    api.set_manager('cluster_1', fake)
    monkeypatch.setattr(schedules_mod, 'time', clock)
    monkeypatch.setattr(mgrmod, 'time', clock)

    schedules_mod.execute_scheduled_rolling_update(fake, 'cluster_1', {
        'config': {'include_reboot': False, 'skip_up_to_date': True, 'skip_evacuation': True}
    })
    deadline = time.time() + 20
    while time.time() < deadline and (fake._rolling_update or {}).get('status') == 'running':
        time.sleep(0.05)

    state = fake._rolling_update
    assert state['status'] == 'completed', state['logs']
    assert apt.read_at - apt.started >= 45, 'package list read before refresh completed'
    assert state['completed_nodes'] == [NODE]
    assert state['skipped_nodes'] == []
    fake.start_node_update.assert_called_once_with(NODE, reboot=False, force=True)


def test_cancelling_scheduled_refresh_stops_before_maintenance(api, seed, monkeypatch):
    """Cancellation during a slow apt task wait must not enter maintenance or update."""
    import pegaprox.api.schedules as schedules_mod

    clock = _Clock()
    apt = _AptNode(clock, done_after=None, before=('pve-manager',))
    fake = _manager(api, apt)
    entered = threading.Event()
    release = threading.Event()
    original_get = apt.api_get

    def hold_first_poll(url, *args, **kwargs):
        """Hold the task-status request until the cancel route changes run state."""
        entered.set()
        assert release.wait(10), 'cancel route never released the apt poll'
        return original_get(url, *args, **kwargs)

    fake._api_get.side_effect = hold_first_poll
    api.set_manager('cluster_1', fake)
    monkeypatch.setattr(schedules_mod, 'time', clock)
    monkeypatch.setattr(mgrmod, 'time', clock)

    schedules_mod.execute_scheduled_rolling_update(fake, 'cluster_1', {
        'config': {'include_reboot': False, 'skip_up_to_date': True, 'skip_evacuation': True}
    })
    try:
        assert entered.wait(5), 'scheduled refresh did not reach task polling'
        client = api.as_user(seed.user('scheduled_cancel', role='admin'))
        response = client.delete('/api/clusters/cluster_1/updates/rolling')
        assert response.status_code == 200, response.data
        assert response.get_json()['cleanup'] == 'running'
    finally:
        release.set()

    deadline = time.time() + 10
    while time.time() < deadline and rolling_runs.worker_here('cluster_1', fake):
        time.sleep(0.05)
    assert not rolling_runs.worker_here('cluster_1', fake), 'scheduled worker did not finish'
    assert fake._rolling_update['status'] == 'cancelled'
    fake.enter_maintenance_mode.assert_not_called()
    fake.start_node_update.assert_not_called()


def test_scheduled_xcpng_refresh_reads_without_extra_delay(api, seed, monkeypatch):
    """A completed synchronous yum refresh needs no further fixed wait."""
    import pegaprox.api.schedules as schedules_mod

    clock = _Clock()
    apt = _AptNode(clock, done_after=0, before=(), after=('kernel',))
    fake = _manager(api, apt, cluster_type='xcpng')

    def refresh(_node):
        """Model XCP-ng's SSH refresh completing before it returns."""
        apt.started = clock.now
        return {'success': True, 'task': None}

    fake.refresh_node_apt.side_effect = refresh
    api.set_manager('cluster_1', fake)
    monkeypatch.setattr(schedules_mod, 'time', clock)
    monkeypatch.setattr(mgrmod, 'time', clock)

    schedules_mod.execute_scheduled_rolling_update(fake, 'cluster_1', {
        'config': {'include_reboot': False, 'skip_up_to_date': True, 'skip_evacuation': True}
    })
    deadline = time.time() + 10
    while time.time() < deadline and (fake._rolling_update or {}).get('status') == 'running':
        time.sleep(0.05)

    assert fake._rolling_update['status'] == 'completed', fake._rolling_update['logs']
    assert apt.read_at == apt.started, 'scheduled yum refresh added an unnecessary delay'
    fake._wait_for_task.assert_not_called()
