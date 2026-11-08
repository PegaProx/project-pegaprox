"""One account must not be able to hold the whole request pool open.

An SSE stream is an open response, so it occupies a request-pool slot for its
whole life. The #777 idle-connection reaper cannot help — the stream is not idle.
There was no bound on how many a single account could open, so any authenticated
user could exhaust the pool and take the UI down for everyone.

The cap supersedes that user's OLDEST stream rather than refusing the new one:
the frontend reconnects on its own watchdog, and refusing would lock a user out
of their own session after a few reloads. MK
"""
import json
import queue

import pytest

import pegaprox.api.realtime as rt
import pegaprox.globals as ppglobals


@pytest.fixture
def registry():
    ppglobals.sse_clients.clear()
    try:
        yield ppglobals.sse_clients
    finally:
        ppglobals.sse_clients.clear()


def _register(user, n, at):
    ppglobals.sse_clients[f'{user}-{n}'] = {
        'queue': queue.Queue(), 'user': user, 'clusters': None, 'is_admin': False,
        'connected_at': at, 'auth_method': 'test',
    }


def test_streams_under_the_cap_are_untouched(registry):
    for i in range(3):
        _register('alice', i, f'2026-09-06T10:0{i}:00')

    rt._supersede_oldest_streams('alice')

    assert len(registry) == 3


def test_the_oldest_stream_is_superseded_at_the_cap(registry):
    for i in range(rt.MAX_SSE_STREAMS_PER_USER):
        _register('alice', i, f'2026-09-06T10:{i:02d}:00')

    rt._supersede_oldest_streams('alice')          # about to register one more

    assert len(registry) == rt.MAX_SSE_STREAMS_PER_USER - 1
    assert 'alice-0' not in registry, 'the oldest stream should have gone first'
    assert f'alice-{rt.MAX_SSE_STREAMS_PER_USER - 1}' in registry


def test_one_user_cannot_evict_another(registry):
    for i in range(rt.MAX_SSE_STREAMS_PER_USER + 5):
        _register('alice', i, f'2026-09-06T10:{i:02d}:00')
    _register('bob', 0, '2026-09-06T09:00:00')     # older than every one of alice's

    rt._supersede_oldest_streams('alice')

    assert 'bob-0' in registry, "alice's cap must not reach bob's stream"


def test_a_superseded_generator_lets_go_of_its_connection(api, seed, monkeypatch):
    """Dropping the registry entry is only half of it — the generator has to notice, or it
    keeps the pool slot and sends keepalives to a queue nobody reads."""
    ppglobals.sse_clients.clear()
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    try:
        seed.user('alice', role='user')
        token = rt.create_sse_token('alice', None)
        with api.app.test_request_context(f'/api/sse/updates?token={token}'):
            gen = rt.sse_updates().response
        client_id = next(iter(ppglobals.sse_clients))

        assert 'connected' in next(gen)
        ppglobals.sse_clients[client_id]['queue'].put_nowait('{"type":"heartbeat"}')
        assert 'heartbeat' in next(gen)

        ppglobals.sse_clients.pop(client_id)        # superseded by a newer stream
        with pytest.raises(StopIteration):
            next(gen)
    finally:
        ppglobals.sse_clients.clear()
