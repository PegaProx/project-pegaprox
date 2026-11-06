"""A snapshot remove over SOAP ends when ESXi says it ended (#1249).

_soap_delete_snapshot waited for a task state ending in ".success" or ".error", but
pyVmomi's state is the plain word: str(vim.TaskInfo.State.success) is "success". The loop
never saw the end of a task, so every remove took its full 120 seconds and answered
"remove timed out", also after ESXi was done in 15. In a live clone that time is downtime.
A remove that failed read as a timeout too, and its reason was lost.

The real pyVmomi state values are used, and the clock is counted instead of waited for.
"""
import time
import types

import pytest

vim = pytest.importorskip('pyVmomi').vim

from pegaprox.core.vmware import VMwareManager  # noqa: E402


class _Task:
    """A RemoveSnapshot task that reads running for a few polls, then its last state."""

    def __init__(self, states, error=None):
        self._states = list(states)
        self._error = error

    @property
    def info(self):
        state = self._states.pop(0) if len(self._states) > 1 else self._states[0]
        return types.SimpleNamespace(state=state, error=self._error)


def _remove(monkeypatch, task):
    naps = []
    monkeypatch.setattr(time, 'sleep', naps.append)
    snap = types.SimpleNamespace(_moId='snap-1', RemoveSnapshot_Task=lambda **kw: task)
    tree = types.SimpleNamespace(snapshot=snap, name='_pegaprox_clone_snap', childSnapshotList=[])
    vm = types.SimpleNamespace(snapshot=types.SimpleNamespace(rootSnapshotList=[tree]))
    mgr = VMwareManager.__new__(VMwareManager)
    mgr._soap_get_managed_object = lambda kind, moid: vm
    return mgr._soap_delete_snapshot('vm-1', 'snap-1'), naps


def test_a_finished_remove_answers_when_esxi_is_done(monkeypatch):
    running, done = vim.TaskInfo.State.running, vim.TaskInfo.State.success
    got, naps = _remove(monkeypatch, _Task([running] * 15 + [done]))
    assert got == {'data': 'deleted'}
    assert len(naps) == 16, f'waited {len(naps)}s for a task that ended after 16 polls'


def test_a_failed_remove_says_why(monkeypatch):
    got, naps = _remove(monkeypatch, _Task([vim.TaskInfo.State.running, vim.TaskInfo.State.error],
                                           error=types.SimpleNamespace(msg='disk is locked')))
    assert got == {'error': 'remove failed: disk is locked'}
    assert len(naps) == 2


def test_a_remove_still_running_after_the_limit_says_so(monkeypatch):
    got, naps = _remove(monkeypatch, _Task([vim.TaskInfo.State.running]))
    assert got == {'error': 'remove timed out'}
    assert len(naps) == 120


@pytest.mark.parametrize('error,attempts,limit', [
    ('remove failed: Operation timed out on the datastore', 2, 120),
    ('remove timed out', 1, 'fold'),
    ('HTTPSConnectionPool: Read timed out', 1, 'fold'),
])
def test_only_a_remove_still_running_gets_the_long_wait(monkeypatch, error, attempts, limit):
    """ESXi's own words can say "timed out" too. A task that ended in failure is not running
    on, and with the source off the long wait for it would only be downtime."""
    from pegaprox.core import v2p
    from test_v2p_clone_delta_1124 import Run

    limits = []
    run = Run(monkeypatch)
    drops = []

    def _drop(vm_id, snapshot_id):
        drops.append(snapshot_id)
        return {'error': error}

    def _wait(mgr, vm_id, backing, timeout, poll=10):
        limits.append(timeout)
        return True

    monkeypatch.setattr(run.esxi, 'delete_snapshot', _drop)
    monkeypatch.setattr(v2p, '_wait_clone_snap_consolidated', _wait)
    run.go()
    # a later clean-up asks once more where the snapshot is still there, so at least
    assert len(drops) >= attempts, drops
    assert limits and (limits[0] == 120 if limit == 120 else limits[0] != 120), limits
