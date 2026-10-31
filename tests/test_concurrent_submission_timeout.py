"""The shared pool deadline includes waiting for a slot to submit work."""

import gevent
from gevent.event import Event
from gevent.pool import Pool

from pegaprox.utils import concurrent


def test_a_full_batch_returns_before_its_deadline_and_keeps_result_positions(monkeypatch):
    """A hanging worker cannot trap submission of the rest of a large batch."""
    pool = Pool(1)
    monkeypatch.setattr(concurrent, 'GEVENT_POOL', pool)
    monkeypatch.setattr(concurrent, 'GEVENT_AVAILABLE', True)
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

    call = gevent.spawn(concurrent.run_concurrent, [lambda: 'first', hang, queued], timeout=0.05)
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


def test_waiting_for_another_batch_does_not_kill_its_worker(monkeypatch):
    """An occupied shared pool times out the waiter without cancelling its owner."""
    pool = Pool(1)
    monkeypatch.setattr(concurrent, 'GEVENT_POOL', pool)
    monkeypatch.setattr(concurrent, 'GEVENT_AVAILABLE', True)
    held = pool.spawn(Event().wait)
    call = gevent.spawn(concurrent.run_concurrent, [lambda: 'queued'], timeout=0.05)
    try:
        call.join(timeout=1)
        assert call.ready(), 'an occupied shared pool escaped the batch timeout'
        assert call.get() == [None]
        assert not held.ready()
    finally:
        call.kill()
        pool.kill()


def test_a_batch_larger_than_the_pool_keeps_completed_results(monkeypatch):
    """Healthy work still runs through a bounded pool in input order."""
    monkeypatch.setattr(concurrent, 'GEVENT_POOL', Pool(2))
    monkeypatch.setattr(concurrent, 'GEVENT_AVAILABLE', True)
    tasks = [lambda value=value: value for value in range(8)]
    assert concurrent.run_concurrent(tasks, timeout=1) == list(range(8))
