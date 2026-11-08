"""An open SSE stream has to keep re-checking the account behind it.

The re-check shipped inside the `except queue.Empty` arm of the queue read, which
reads like the idle tick but isn't one: broadcast.py sends a heartbeat frame to
every client once a second, so the queue is never empty and the whole check was
dead. And had it ever run it would have raised — it calls _stream_identity, which
read `request.session`, while the response generator is iterated by the WSGI
server after the request context is gone.

These drive the generator the way the server does: outside a request context. MK
"""
import json
import queue as queue_module

import pytest

import pegaprox.api.realtime as rt
import pegaprox.globals as ppglobals


def _open_stream(app, client_token_user, monkeypatch):
    """Return (generator, client_id) for one connected SSE client, with the request
    context already popped — which is where the real server iterates it."""
    with app.test_request_context(f'/api/sse/updates?token={client_token_user}'):
        resp = rt.sse_updates()
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    client_id = next(iter(ppglobals.sse_clients))
    return resp.response, client_id


@pytest.fixture
def sse(api, seed, monkeypatch):
    """One authenticated SSE stream for a seeded user, with the re-check interval
    turned down so a test doesn't have to wait 30 seconds."""
    ppglobals.sse_clients.clear()
    # raising=False so these still run against a tree without the constant, and fail on
    # the behaviour rather than on the attribute
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)

    user = seed.user('alice', role='user')
    token = rt.create_sse_token('alice', None)

    gen, client_id = _open_stream(api.app, token, monkeypatch)
    try:
        yield rt, gen, client_id, user
    finally:
        gen.close()
        ppglobals.sse_clients.clear()


def _drain(gen, n=1):
    """Pull n frames out of the generator, as the WSGI server would."""
    out = []
    for _ in range(n):
        out.append(next(gen))
    return out


def test_first_frame_is_the_connect_envelope(sse):
    _, gen, client_id, _ = sse

    frame = _drain(gen)[0]

    assert json.loads(frame[len('data: '):])['type'] == 'connected'


def test_stream_survives_a_recheck_outside_the_request_context(sse):
    """The re-check runs after every frame now, and the generator is iterated with
    no request context — reading request.session there raises RuntimeError, which
    `except GeneratorExit` does not catch."""
    _, gen, client_id, _ = sse
    _drain(gen)                                    # connect envelope
    ppglobals.sse_clients[client_id]['queue'].put_nowait('{"type":"heartbeat"}')

    frame = _drain(gen)[0]

    assert 'heartbeat' in frame
    assert client_id in ppglobals.sse_clients, 'the stream tore itself down'


def test_disabling_the_account_closes_the_stream_while_frames_flow(sse, db):
    """The defect: with a heartbeat every second the queue never runs dry, so a
    re-check that only fires on queue.Empty never fires at all."""
    _, gen, client_id, user = sse
    _drain(gen)
    q = ppglobals.sse_clients[client_id]['queue']

    db.save_user('alice', {**user, 'enabled': False})

    # keep the queue busy the whole time — that is production, and it is exactly the
    # condition under which the old placement never fired
    for _ in range(4):
        q.put_nowait('{"type":"heartbeat"}')
    with pytest.raises(StopIteration):
        _drain(gen, 4)

    assert client_id not in ppglobals.sse_clients


def test_stream_identity_works_with_no_request_context(api, seed):
    """It is called from inside the response generator, which the WSGI server iterates
    after the request context is popped. `request` is an unbound LocalProxy there and
    raises RuntimeError — which getattr(..., None) does not swallow."""
    seed.user('alice', role='user')

    acct = rt._stream_identity('alice')

    assert acct['username'] == 'alice'
    assert acct.get('enabled', True) is True


def test_demotion_starts_filtering_an_admins_frames(api, seed, db, monkeypatch):
    """is_admin is captured at connect; the re-check has to refresh it or a demoted
    admin keeps receiving unfiltered resources/vm_config/tasks frames."""
    ppglobals.sse_clients.clear()
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    try:
        seed.user('root_admin', role='admin')
        token = rt.create_sse_token('root_admin', None, 'admin')
        gen, client_id = _open_stream(api.app, token, monkeypatch)
        try:
            _drain(gen)
            assert ppglobals.sse_clients[client_id]['is_admin'] is True

            db.save_user('root_admin', {'username': 'root_admin', 'role': 'user',
                                        'enabled': True, 'password': 'x'})
            # the re-check sits after the yield, so it runs when the server comes back
            # for the NEXT frame — queue two and pull both
            q = ppglobals.sse_clients[client_id]['queue']
            q.put_nowait('{"type":"heartbeat"}')
            q.put_nowait('{"type":"heartbeat"}')
            _drain(gen, 2)

            assert ppglobals.sse_clients[client_id]['is_admin'] is False
        finally:
            gen.close()
    finally:
        ppglobals.sse_clients.clear()


def test_the_recheck_does_not_hang_off_the_queue_timeout():
    """Structural: broadcast.py heartbeats every client every second, so anything
    that only runs in the Empty arm is dead code by construction."""
    lines = open('pegaprox/api/realtime.py').read().split('\n')
    start = next(i for i, l in enumerate(lines) if l.strip() == 'except queue_module.Empty:')
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].strip() and (len(lines[i]) - len(lines[i].lstrip())) <= indent)
    empty_arm = '\n'.join(lines[start:end])
    body = '\n'.join(lines[start - 40:end + 40])

    assert '_stream_identity' not in empty_arm, 'the re-check is back on the idle path'
    assert 'SSE_REAUTHZ_INTERVAL' in body


def test_a_demotion_reaches_the_filters_not_just_the_boolean(api, seed, db, monkeypatch):
    """is_admin gates whether the filters RUN; effective_role is what they decide with. The
    re-check refreshed only the boolean, so a demoted admin's frames started going through a
    filter that still resolved the identity as an admin and passed everything anyway."""
    ppglobals.sse_clients.clear()
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    try:
        seed.user('root_admin', role='admin')
        token = rt.create_sse_token('root_admin', None, 'admin')
        gen, client_id = _open_stream(api.app, token, monkeypatch)
        try:
            _drain(gen)
            assert ppglobals.sse_clients[client_id]['effective_role'] == 'admin'

            db.save_user('root_admin', {'username': 'root_admin', 'role': 'user',
                                        'enabled': True, 'password': 'x'})
            q = ppglobals.sse_clients[client_id]['queue']
            q.put_nowait('{"type":"heartbeat"}')
            q.put_nowait('{"type":"heartbeat"}')
            _drain(gen, 2)

            ci = ppglobals.sse_clients[client_id]
            assert ci['is_admin'] is False
            assert ci['effective_role'] == 'user', \
                'the filters would still decide as an admin'
        finally:
            gen.close()
    finally:
        ppglobals.sse_clients.clear()


def test_one_failed_identity_read_does_not_drop_the_stream(sse, monkeypatch):
    """_stream_identity returns None both for "the account is gone" and for "the read
    failed". The re-check runs for every client every 30s, so treating a WAL-contention
    blip as a deletion would drop every stream at once and stampede them all back in."""
    _, gen, client_id, _ = sse
    _drain(gen)
    q = ppglobals.sse_clients[client_id]['queue']

    calls = {'n': 0}
    real = rt._stream_identity

    def _flaky(username, *a, **kw):
        calls['n'] += 1
        return None if calls['n'] == 1 else real(username, *a, **kw)
    monkeypatch.setattr(rt, '_stream_identity', _flaky)

    for _ in range(4):
        q.put_nowait('{"type":"heartbeat"}')
    _drain(gen, 4)

    assert calls['n'] >= 2, 'the re-check did not run'
    assert client_id in ppglobals.sse_clients, 'one blip tore the stream down'


def test_a_genuinely_deleted_account_still_closes(sse, monkeypatch):
    """The tolerance must not become a hole: two misses in a row still fail closed."""
    _, gen, client_id, _ = sse
    _drain(gen)
    q = ppglobals.sse_clients[client_id]['queue']
    monkeypatch.setattr(rt, '_stream_identity', lambda *a, **kw: None)

    for _ in range(6):
        q.put_nowait('{"type":"heartbeat"}')
    with pytest.raises(StopIteration):
        _drain(gen, 6)

    assert client_id not in ppglobals.sse_clients
