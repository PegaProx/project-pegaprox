"""The shared pool deadline includes waiting for a slot to submit work."""

import gevent
import pytest
from gevent.event import Event
from gevent.pool import Pool

from pegaprox.utils import concurrent
from pegaprox.core import manager


@pytest.fixture(params=[concurrent, manager], ids=['utils', 'manager'])
def helper(request):
    """Exercise both implementations of the shared pool helper."""
    return request.param


def test_a_full_batch_returns_before_its_deadline_and_keeps_result_positions(monkeypatch, helper):
    """A hanging worker cannot trap submission of the rest of a large batch."""
    pool = Pool(1)
    monkeypatch.setattr(helper, 'GEVENT_POOL', pool)
    monkeypatch.setattr(helper, 'GEVENT_AVAILABLE', True)
    started = []
    stopped = []

    def hang():
        """Hold the only slot until the batch gives up."""
        started.append('hang')
        try:
            Event().wait()
        finally:
            stopped.append('hang')

    def queued():
        """Record work that must remain unstarted after the deadline."""
        started.append('queued')
        return 'late'

    call = gevent.spawn(helper.run_concurrent, [lambda: 'first', hang, queued], timeout=0.05)
    try:
        call.join(timeout=1)
        assert call.ready(), 'waiting for a pool slot escaped the batch timeout'
        assert call.get() == ['first', None, None]
        gevent.sleep(0)
        assert started == ['hang']
        assert stopped == ['hang']
        assert pool.free_count() == 1
    finally:
        call.kill()
        pool.kill()


def test_waiting_for_another_batch_does_not_kill_its_worker(monkeypatch, helper):
    """An occupied shared pool times out the waiter without cancelling its owner."""
    pool = Pool(1)
    monkeypatch.setattr(helper, 'GEVENT_POOL', pool)
    monkeypatch.setattr(helper, 'GEVENT_AVAILABLE', True)
    held = pool.spawn(Event().wait)
    call = gevent.spawn(helper.run_concurrent, [lambda: 'queued'], timeout=0.05)
    try:
        call.join(timeout=1)
        assert call.ready(), 'an occupied shared pool escaped the batch timeout'
        assert call.get() == [None]
        assert not held.ready()
    finally:
        call.kill()
        pool.kill()


def test_a_batch_larger_than_the_pool_keeps_completed_results(monkeypatch, helper):
    """Healthy work still runs through a bounded pool in input order."""
    monkeypatch.setattr(helper, 'GEVENT_POOL', Pool(2))
    monkeypatch.setattr(helper, 'GEVENT_AVAILABLE', True)
    tasks = [lambda value=value: value for value in range(8)]
    assert helper.run_concurrent(tasks, timeout=1) == list(range(8))


def test_an_explicit_manager_pool_still_reads_the_whole_healthy_batch(monkeypatch):
    """A dedicated sweep must not leave stable-order tail guests unread on every run."""
    pool = Pool(1)
    monkeypatch.setattr(manager, 'GEVENT_AVAILABLE', True)

    def read(value):
        """Complete one healthy read within its normal IO deadline."""
        gevent.sleep(0.01)
        return value

    tasks = [lambda value=value: read(value) for value in range(8)]
    assert manager.run_concurrent(tasks, timeout=0.02, pool=pool) == list(range(8))
    assert pool.free_count() == 1
