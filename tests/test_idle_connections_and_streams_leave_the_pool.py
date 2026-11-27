"""Idle keep-alive connections and SSE streams hold no request slot.

pywsgi serves a connection in one greenlet of the request pool from accept to close. Every
open dashboard tab held a slot with its SSE stream for good, and every browser about five
more with the kept-alive sockets it waits on between two polls: 32, 64 and 128 slots were
full at about 6, 11 and 21 users, and gevent stops accepting for everybody once they are.

An SSE stream now leaves the pool when it starts, as a console does, and counts against an
instance cap of its own (PEGAPROX_MAX_SSE_STREAMS) next to the account's. A kept-alive
connection waits for its next request outside the pool and takes a slot again when the
request line is there, up to PEGAPROX_MAX_IDLE_CONNECTIONS of them; past that it waits in
its slot as before. What left the pool is ended on shutdown, the pool's own stop() no
longer reaches it.

MK Nov 2026
"""
import os
import re
import signal
import socket
import subprocess
import sys
import time

import gevent
import gevent.pool
import pytest
from flask import Flask
from gevent.pywsgi import WSGIHandler, WSGIServer
from werkzeug.test import EnvironBuilder

import pegaprox.api.realtime as rt
import pegaprox.app as app_mod
import pegaprox.globals as ppglobals
import pegaprox.utils.realtime as rtu
from pegaprox.core.federation import LEASE_PATH
from pegaprox.core.federation_relay import RELAY_PATH

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def registry():
    ppglobals.sse_clients.clear()
    try:
        yield ppglobals.sse_clients
    finally:
        ppglobals.sse_clients.clear()


@pytest.fixture
def serve(monkeypatch, registry):
    """A pywsgi server as app.py runs it: the mixin, a pool of `slots`, registered."""
    monkeypatch.setattr(rtu, '_request_pools', [])
    servers = []

    def start(app, slots=4, **attrs):
        handler = type('Handler', (app_mod._IdleTimeoutMixin, WSGIHandler), attrs)
        pool = gevent.pool.Pool(slots)
        rtu.register_request_pool(pool)
        srv = WSGIServer(('127.0.0.1', 0), app, handler_class=handler, spawn=pool,
                         log=None, error_log=None)
        srv.start()
        servers.append(srv)
        return srv, pool

    yield start
    for srv in servers:
        srv.stop(timeout=1)
    rtu.end_out_of_pool(timeout=2)


def _answer(s):
    """(head, body) of one answer with a Content-Length."""
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    m = re.search(rb'(?im)^content-length:\s*(\d+)', head)
    while m and len(body) < int(m.group(1)):
        chunk = s.recv(65536)
        if not chunk:
            break
        body += chunk
    return head, body


def _ask(s, path):
    s.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
    return _answer(s)


def _kept_alive(port, path='/api/health'):
    """A connection that asked for `path`, read the answer and stays open, as a browser
    keeps it for the next request."""
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    head, _ = _ask(s, path)
    assert b' 200 ' in head.split(b'\r\n', 1)[0], head[:80]
    return s


def _get(port, path, within):
    """A request on a new connection; b'' when nothing came back within `within`."""
    s = socket.create_connection(('127.0.0.1', port), timeout=within)
    try:
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
        return _answer(s)[0]
    except socket.timeout:
        return b''
    finally:
        s.close()


def _stream(port, token, within=3):
    """An open SSE stream once its first frame is in, or None when it was not served."""
    s = socket.create_connection(('127.0.0.1', port), timeout=within)
    s.sendall(f'GET /api/sse/updates?token={token} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
    data = b''
    try:
        while b'connected' not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    if b'connected' not in data:
        s.close()
        return None
    return s, data


def _until(done, within=3):
    end = time.monotonic() + within
    while time.monotonic() < end:
        if done():
            return True
        gevent.sleep(0.05)
    return done()


def _ends(s, within=3):
    """True when the server closes the connection within `within`."""
    s.settimeout(within)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                return True
    except socket.timeout:
        return False
    except OSError:
        return True


def _wake(client_id):
    q = ppglobals.sse_clients[client_id]['queue']
    return lambda: q.put_nowait('{"type":"heartbeat"}')


# --- the pool serves requests, not connections ------------------------------------------

def test_idle_keep_alives_and_streams_leave_room_for_a_request(api, seed, serve, registry):
    seed.user('alice', role='user')
    srv, pool = serve(api.app, slots=4)
    port = srv.server_port

    idle = [_kept_alive(port) for _ in range(4)]
    streams = []
    for i in range(2):
        got = _stream(port, rt.create_sse_token('alice', None))
        assert got is not None, f'SSE stream {i} was not served: idle connections fill the pool'
        streams.append(got[0])
    assert len(registry) == 2

    t0 = time.monotonic()
    head = _get(port, '/api/health', within=3)
    assert b' 200 ' in head.split(b'\r\n', 1)[0], \
        'a new request waited behind four idle connections and two streams in a pool of four'
    assert time.monotonic() - t0 < 3
    assert _until(lambda: pool.free_count() == 4), \
        f'{4 - pool.free_count()} of 4 slots still held by idle connections and streams'

    # an idle connection is still good for its next request
    head, body = _ask(idle[0], '/api/health')
    assert b' 200 ' in head.split(b'\r\n', 1)[0] and body
    for s in idle + streams:
        s.close()


def _tiny_app():
    web = Flask('pool-slots')

    @web.route('/ping')
    def ping():
        return 'pong'

    @web.route('/slow')
    def slow():
        gevent.sleep(0.8)
        return 'slow'
    return web


def test_the_next_request_of_a_kept_alive_connection_waits_for_a_slot(serve):
    """Out of the pool only while it waits: the pool still bounds the requests in flight."""
    srv, pool = serve(_tiny_app(), slots=1)
    port = srv.server_port
    idle = _kept_alive(port, '/ping')
    assert _until(lambda: pool.free_count() == 1)

    busy = socket.create_connection(('127.0.0.1', port), timeout=5)
    busy.sendall(b'GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n')
    assert _until(lambda: pool.free_count() == 0), 'the slow request got no slot'

    t0 = time.monotonic()
    head, body = _ask(idle, '/ping')
    waited = time.monotonic() - t0
    assert body == b'pong'
    assert waited > 0.4, f'the kept-alive request ran next to a full pool ({waited:.2f}s)'
    assert _answer(busy)[1] == b'slow'
    for s in (idle, busy):
        s.close()


def test_past_the_idle_cap_a_connection_waits_in_its_slot(serve):
    """What waits outside the pool is bounded: past the cap the old behaviour."""
    srv, pool = serve(_tiny_app(), slots=4, _max_idle=1)
    port = srv.server_port
    idle = [_kept_alive(port, '/ping') for _ in range(3)]
    assert _until(lambda: pool.free_count() == 2), \
        f'{4 - pool.free_count()} of 4 slots held by three idle connections, one may wait outside'
    gevent.sleep(0.2)
    assert pool.free_count() == 2, f'{4 - pool.free_count()} slots held, one waits outside'
    for s in idle:
        s.close()
    assert _until(lambda: pool.free_count() == 4)


def _peer_app():
    web = Flask('ha-peer')

    def answer():
        return 'ok' if web.config.get('signed') else ('refused', 403)
    for i, path in enumerate(('/api/ha/peer/renew', LEASE_PATH, RELAY_PATH)):
        web.add_url_rule(path, f'peer{i}', answer, methods=['POST'])
    return web


@pytest.mark.parametrize('path, signed, held', [
    ('/api/ha/peer/renew', True, 1), ('/api/ha/peer/renew', False, 0),
    (LEASE_PATH, True, 1), (LEASE_PATH, False, 0),
    (RELAY_PATH, True, 0),
])
def test_a_members_lease_connection_keeps_its_slot(serve, path, signed, held):
    """An HA member renews many times a second on one kept-alive connection, a federation
    member asks for its lease votes every ten seconds and gives them five; a renewal must
    never wait behind a pool full of slow requests. A refused call gets nothing, and
    neither does a relayed call, which a member sends on as many connections as it likes."""
    web = _peer_app()
    web.config['signed'] = signed
    srv, pool = serve(web, slots=2)
    s = socket.create_connection(('127.0.0.1', srv.server_port), timeout=5)
    s.sendall(f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n'.encode())
    head, _ = _answer(s)
    assert (b' 200 ' in head.split(b'\r\n', 1)[0]) is signed
    gevent.sleep(0.2)
    assert 2 - pool.free_count() == held, f'{2 - pool.free_count()} slots held after {path}'
    s.close()


def test_an_idle_connection_still_ends_after_the_keep_alive_window(serve):
    srv, pool = serve(_tiny_app(), slots=2, _idle_timeout=0.6)
    s = _kept_alive(srv.server_port, '/ping')
    assert _until(lambda: pool.free_count() == 2, within=0.4), 'the idle connection kept its slot'
    assert _ends(s, within=3), 'an idle connection outlived its keep-alive window outside the pool'
    assert _until(lambda: not app_mod._idle_out), 'a connection that ended still counts as waiting'
    s.close()


# --- SSE streams -------------------------------------------------------------------------

def _open_view(app, token):
    with app.test_request_context(f'/api/sse/updates?token={token}'):
        return app.make_response(rt.sse_updates())


def test_the_instance_refuses_the_stream_past_its_cap(api, seed, registry, monkeypatch):
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS', 2)
    for name in ('alice', 'bob', 'carol'):
        seed.user(name, role='user')
    assert _open_view(api.app, rt.create_sse_token('alice', None)).status_code == 200
    assert _open_view(api.app, rt.create_sse_token('bob', None)).status_code == 200

    late = _open_view(api.app, rt.create_sse_token('carol', None))
    assert late.status_code == 503
    assert late.headers.get('Retry-After')
    assert late.get_json()['code'] == 'SSE_FULL'
    assert sorted(c['user'] for c in registry.values()) == ['alice', 'bob'], \
        'a refused stream was registered, or somebody else lost theirs'


def test_the_account_cap_still_supersedes_on_a_full_instance(api, seed, registry, monkeypatch):
    """One past the account's own cap replaces its oldest stream, so it never counts
    against the instance: a full instance still takes it."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS', 2)
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_USER', 1)
    seed.user('alice', role='user')
    seed.user('bob', role='user')
    assert _open_view(api.app, rt.create_sse_token('alice', None)).status_code == 200
    first = next(iter(registry))
    assert _open_view(api.app, rt.create_sse_token('bob', None)).status_code == 200

    again = _open_view(api.app, rt.create_sse_token('alice', None))
    assert again.status_code == 200, 'the full instance refused the stream that replaces her own'
    assert first not in registry, "alice's oldest stream was not superseded"
    assert sorted(c['user'] for c in registry.values()) == ['alice', 'bob']


def test_a_full_instance_lets_an_account_replace_its_own_oldest_stream(api, seed, registry,
                                                                     monkeypatch):
    """The dashboard reconnects every five minutes with a fresh token, and the stream it
    just closed is registered until its next frame finds the socket gone: on a full
    instance that reconnect replaces the account's oldest stream instead of being refused,
    as a console does. An account without a stream here is still refused, and a feed of
    another site is not one of the account's streams to replace."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS', 2)
    for name in ('alice', 'bob', 'carol'):
        seed.user(name, role='user')
    assert _open_view(api.app, rt.create_sse_token('alice', None)).status_code == 200
    first = next(iter(registry))
    assert _open_view(api.app, rt.create_sse_token('bob', None)).status_code == 200

    again = _open_view(api.app, rt.create_sse_token('alice', None))
    assert again.status_code == 200, \
        'the full instance refused the reconnect of an account that holds a stream'
    assert first not in registry, "alice's oldest stream was not replaced"
    assert sorted(c['user'] for c in registry.values()) == ['alice', 'bob']
    assert _open_view(api.app, rt.create_sse_token('carol', None)).status_code == 503

    # a feed another site opened for alice, older than her stream: hers is replaced
    def feed(cid, user):
        registry[cid] = {'user': user, 'fed_stream': 'site-b', 'connected_at': '2026',
                         'queue': None, 'clusters': []}

    def browser_stream_of(user):
        return next(cid for cid, c in registry.items()
                    if c['user'] == user and not c.get('fed_stream'))
    registry.pop(browser_stream_of('bob'))
    feed('fed-1', 'alice')
    hers = browser_stream_of('alice')
    assert _open_view(api.app, rt.create_sse_token('alice', None)).status_code == 200
    assert 'fed-1' in registry and hers not in registry, \
        'the reconnect replaced the feed of another site, not her own stream'

    # and a feed alone is no stream of the account's here: carol's only entry is one
    registry.pop(browser_stream_of('alice'))
    feed('fed-2', 'carol')
    assert _open_view(api.app, rt.create_sse_token('carol', None)).status_code == 503
    assert sorted(registry) == ['fed-1', 'fed-2']


def _head_view(app, token):
    with app.test_request_context(f'/api/sse/updates?token={token}', method='HEAD'):
        return app.make_response(rt.sse_updates())


def test_a_head_neither_takes_nor_drops_a_stream(api, seed, registry, monkeypatch):
    """Flask answers HEAD on the stream's route, and a HEAD has no body to stream."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_USER', 1)
    seed.user('alice', role='user')
    assert _open_view(api.app, rt.create_sse_token('alice', None)).status_code == 200
    first = next(iter(registry))

    head = _head_view(api.app, rt.create_sse_token('alice', None))
    assert head.status_code == 200
    assert list(registry) == [first], 'a HEAD registered a stream and pushed out her open one'
    assert _head_view(api.app, 'not-a-token').status_code == 401


def test_heads_leave_no_stream_behind(api, seed, serve, registry, monkeypatch):
    """Werkzeug sends no body for a HEAD, so the stream's generator never ran and its
    clean-up never came: each HEAD kept one of the instance's streams until a restart."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS', 3)
    seed.user('mallory', role='viewer')
    seed.user('alice', role='user')
    srv, pool = serve(api.app, slots=4)
    token = rt.create_sse_token('mallory', None)
    for _ in range(5):
        s = socket.create_connection(('127.0.0.1', srv.server_port), timeout=3)
        s.sendall(f'HEAD /api/sse/updates?token={token} HTTP/1.1\r\nHost: localhost\r\n'
                  'Connection: close\r\n\r\n'.encode())
        head, _ = _answer(s)
        assert b' 200 ' in head.split(b'\r\n', 1)[0], head[:80]
        s.close()
    assert _until(lambda: not registry), f'{len(registry)} streams registered after five HEADs'
    got = _stream(srv.server_port, rt.create_sse_token('alice', None))
    assert got is not None, 'the next account got no stream'
    got[0].close()


def test_a_stream_is_let_go_when_its_answer_closes_before_it_started(api, seed, registry):
    """A generator closed before its first frame skips its finally; the answer's close
    still lets the stream go, whoever closes it without reading the body."""
    seed.user('alice', role='user')
    environ = EnvironBuilder(path='/api/sse/updates', base_url='http://localhost',
                             query_string={'token': rt.create_sse_token('alice', None)}
                             ).get_environ()
    status = []
    body = api.app(environ, lambda st, headers, exc_info=None: status.append(st))
    assert status and status[0].startswith('200'), status
    assert len(registry) == 1
    body.close()
    assert not registry, 'the stream of an answer closed before its first frame is still registered'


def test_a_typo_in_the_idle_budget_does_not_stop_the_instance(tmp_path):
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(tmp_path / 'config')}
    code = ('import pegaprox.app as a\n'
            'from pegaprox.utils.realtime import fd_budget\n'
            'print(a._MAX_IDLE_CONNECTIONS, fd_budget(8))\n')
    for value, expect in (('lots', None), ('0', 0), ('5', 5)):
        run = subprocess.run([sys.executable, '-c', code], cwd=str(tmp_path), timeout=60,
                             env={**env, 'PEGAPROX_MAX_IDLE_CONNECTIONS': value},
                             capture_output=True, text=True)
        assert run.returncode == 0, f'PEGAPROX_MAX_IDLE_CONNECTIONS={value}:\n{run.stderr[-2000:]}'
        got, default = (int(x) for x in run.stdout.split()[-2:])
        assert got == (default if expect is None else expect), (value, got)


def test_a_stream_gives_its_slot_back_and_says_it_ends_the_connection(api, seed, serve, registry):
    seed.user('alice', role='user')
    srv, pool = serve(api.app, slots=2)
    s, data = _stream(srv.server_port, rt.create_sse_token('alice', None))
    assert _until(lambda: pool.free_count() == 2), 'the open stream still holds its slot'
    head = data.split(b'\r\n\r\n', 1)[0].lower()
    # the greenlet that left the pool serves nothing on this connection after the stream
    assert b'connection: close' in head, head
    s.close()


def test_a_stream_out_of_the_pool_ends_when_its_client_goes_away(api, seed, serve, registry):
    seed.user('alice', role='user')
    srv, pool = serve(api.app, slots=2)
    s, _ = _stream(srv.server_port, rt.create_sse_token('alice', None))
    client_id = next(iter(registry))
    wake = _wake(client_id)
    assert _until(lambda: pool.free_count() == 2), 'the stream did not leave the pool'
    s.close()

    def gone():
        if client_id in registry:
            wake()
        return client_id not in registry
    assert _until(gone), 'the stream of a client that went away is still registered'


def test_a_stream_out_of_the_pool_ends_with_its_session(api, seed, serve, registry):
    seed.user('alice', role='user')
    srv, pool = serve(api.app, slots=2)
    s, _ = _stream(srv.server_port, rt.create_sse_token('alice', None, sid='s-gone'))
    client_id = next(iter(registry))
    wake = _wake(client_id)
    assert _until(lambda: pool.free_count() == 2), 'the stream did not leave the pool'

    rtu.end_session_channels('alice', sids={'s-gone'})
    wake()
    assert _ends(s), 'the stream of an ended session kept its connection'
    s.close()


def test_shutdown_ends_the_streams_that_left_the_pool(api, seed, serve, registry):
    seed.user('alice', role='user')
    srv, pool = serve(api.app, slots=2)
    s, _ = _stream(srv.server_port, rt.create_sse_token('alice', None))
    client_id = next(iter(registry))
    assert _until(lambda: pool.free_count() == 2), 'the stream did not leave the pool'

    srv.stop(timeout=1)
    rtu.end_out_of_pool(timeout=2)
    assert _ends(s), 'the stream outlived the shutdown'
    assert client_id not in registry, 'the stream ended without its clean-up'
    s.close()


_SERVER = r"""
import gevent.monkey; gevent.monkey.patch_all()
import sys

import gevent
from flask import Flask, Response

import pegaprox.app as app_mod
from pegaprox.utils.realtime import _leave_request_pool

web = Flask('out-of-the-pool')
ended = []


@web.route('/ping')
def ping():
    return 'pong'


@web.route('/stream')
def stream():
    def body():
        _leave_request_pool()
        try:
            yield 'data: open\n\n'
            while True:
                gevent.sleep(0.2)
                yield ': keepalive\n\n'
        finally:
            ended.append('stream')
    return Response(body(), mimetype='text/event-stream', headers={'Connection': 'close'})


app_mod._start_gevent_server(web, '127.0.0.1', int(sys.argv[1]), None, None, 4)
# serve_forever() has returned and _start_gevent_server with it
print('ENDED ' + ','.join(ended), flush=True)
print('WAITING OUTSIDE %d' % len(app_mod._idle_out or ()), flush=True)
"""


def test_the_server_ends_what_left_the_pool_once_it_stopped(tmp_path):
    """The real server and its SIGTERM: the pool's stop() no longer reaches a stream or an
    idle connection that left it, so both are ended once serve_forever() returned."""
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    log_path = tmp_path / 'server.log'
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(tmp_path / 'config'),
           'PEGAPROX_LEGACY_CONSOLE_PORTS': '0'}
    with open(log_path, 'w') as log:
        proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port)], cwd=str(tmp_path),
                                env=env, stdout=log, stderr=subprocess.STDOUT)
    held = []
    try:
        end = time.monotonic() + 60
        while True:
            try:
                socket.create_connection(('127.0.0.1', port), timeout=1).close()
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > end:
                    pytest.fail('test server did not come up:\n' + log_path.read_text())
                time.sleep(0.2)

        s = socket.create_connection(('127.0.0.1', port), timeout=5)
        held.append(s)
        s.sendall(b'GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n')
        data = b''
        while b'open' not in data:
            chunk = s.recv(65536)
            assert chunk, 'the stream was not served'
            data += chunk
        held.append(_kept_alive(port, '/ping'))
        time.sleep(0.3)

        proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(30)
        except subprocess.TimeoutExpired:
            pytest.fail('a SIGTERM did not stop the server:\n' + log_path.read_text())
    finally:
        for s in held:
            s.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(5)

    out = log_path.read_text()
    assert code == 0, out
    assert 'ENDED stream' in out.splitlines(), f'the stream outlived the server:\n{out}'
    assert 'WAITING OUTSIDE 0' in out.splitlines(), \
        f'an idle connection outlived the server:\n{out}'


# --- a dropped stream still holds its connection until its generator ends ---------------

@pytest.fixture
def db_conns(monkeypatch):
    """The database connections opened from here on; call it for how many are still open.
    Descriptors are no measure: SQLite keeps a closed connection's open while another one
    of the process holds a lock on the file."""
    import pegaprox.core.dbcrypto as dbcrypto
    opened = []
    real = dbcrypto.connect

    def connect(*a, **kw):
        conn = real(*a, **kw)
        opened.append(conn)
        return conn
    monkeypatch.setattr(dbcrypto, 'connect', connect)

    def still_open():
        n = 0
        for conn in opened:
            try:
                conn.total_changes
                n += 1
            except Exception:
                pass
        return n
    return still_open


def test_a_superseded_stream_ends_at_once(api, seed, serve, registry, monkeypatch):
    """Dropped from the registry, its generator waited up to 30 s on its queue before it
    looked, out of the pool and counted nowhere. It is woken now."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_SESSION', 1)
    seed.user('alice', role='user')
    srv, _ = serve(api.app, slots=2)
    first, _ = _stream(srv.server_port, rt.create_sse_token('alice', None, sid='s1'))
    second, _ = _stream(srv.server_port, rt.create_sse_token('alice', None, sid='s1'))
    first.settimeout(3)
    rest = b''
    try:
        while True:
            chunk = first.recv(65536)
            if not chunk:
                break
            rest += chunk
    except socket.timeout:
        pytest.fail('the superseded stream kept its connection')
    # what woke it is never sent
    assert b'object' not in rest, rest[-200:]
    assert _until(lambda: not rtu._dropped_streams), 'its generator never said it ended'
    assert len(registry) == 1
    for s in (first, second):
        s.close()


def test_a_stream_of_an_ended_session_ends_without_a_frame(api, seed, serve, registry):
    seed.user('alice', role='user')
    srv, _ = serve(api.app, slots=2)
    s, _ = _stream(srv.server_port, rt.create_sse_token('alice', None, sid='s-gone'))
    rtu.end_session_channels('alice', sids={'s-gone'})
    assert _ends(s, within=3), 'the stream of an ended session waited for its next frame'
    assert _until(lambda: not rtu._dropped_streams)
    s.close()


def test_one_token_reopened_holds_no_more_connections_than_the_cap(api, seed, serve, registry,
                                                                   monkeypatch):
    """A viewer reopening streams on one token: each new one replaced its own oldest, and
    the replaced ones lived on for half a minute outside every cap."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS', 5)
    seed.user('alice', role='viewer')
    srv, _ = serve(api.app, slots=4)
    token = rt.create_sse_token('alice', None, sid='s1')
    socks = []
    for _ in range(30):
        got = _stream(srv.server_port, token)
        if got:
            socks.append(got[0])
    assert len(socks) == 30, 'a reconnect of a session that holds a stream was refused'
    assert _until(lambda: len(rtu._left_pool()) <= 5, within=5), \
        f'{len(rtu._left_pool())} streams still live out of the pool, the cap is 5'
    for s in socks:
        s.close()


def test_dropped_streams_count_against_the_account_until_they_end(api, seed, registry,
                                                                monkeypatch):
    """A generator that waits in a write to a client that reads nothing ends late: until
    then its stream counts, and a session's worth of those over the cap refuses even the
    session's own reconnect."""
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_SESSION', 1)
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_USER', 2)
    seed.user('alice', role='user')
    token = rt.create_sse_token('alice', None, sid='s1')
    # views only, their generators never run: what they replace stays dropped, not ended
    assert _open_view(api.app, token).status_code == 200
    assert _open_view(api.app, token).status_code == 200
    assert len(rtu._dropped_streams) == 1
    assert _open_view(api.app, token).status_code == 200
    late = _open_view(api.app, token)
    assert late.status_code == 429, 'three dropped and one live stream did not refuse'
    assert late.get_json()['code'] == 'SSE_ACCOUNT_FULL'

    with ppglobals.sse_clients_lock:
        rtu.stream_ended(next(iter(rtu._dropped_streams)))
    assert _open_view(api.app, token).status_code == 200, \
        'a dropped stream that ended still counted'


def test_dropped_streams_count_against_the_instance_until_they_end(api, seed, registry,
                                                                 monkeypatch):
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS', 2)
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_SESSION', 1)
    seed.user('alice', role='user')
    seed.user('bob', role='user')
    hers = rt.create_sse_token('alice', None, sid='s-a')
    assert _open_view(api.app, hers).status_code == 200
    assert _open_view(api.app, rt.create_sse_token('bob', None, sid='s-b')).status_code == 200
    assert _open_view(api.app, hers).status_code == 200, 'her reconnect on a full instance'
    late = _open_view(api.app, hers)
    assert late.status_code == 503, 'two live streams and a dropped one on a cap of two'
    assert sorted(c['user'] for c in registry.values()) == ['alice', 'bob']


def test_a_stream_holds_no_database_connection_while_it_waits(api, seed, serve, registry,
                                                              db_conns):
    seed.user('alice', role='user')
    srv, _ = serve(api.app, slots=4)
    socks = [_stream(srv.server_port, rt.create_sse_token('alice', None))[0] for _ in range(6)]
    assert _until(lambda: len(rtu._left_pool()) == 6)
    assert _until(lambda: db_conns() == 0), \
        f'{db_conns()} database connections held by six open streams'
    for s in socks:
        s.close()


def _db_app(db):
    web = Flask('idle-db')

    @web.route('/who')
    def who():
        db.get_user('alice')
        return 'ok'
    return web


@pytest.mark.parametrize('with_db, kept', [(0, 0), (2, 2), (100, 3)])
def test_past_a_number_of_idle_connections_one_gives_its_database_connection_up(
        seed, serve, db, db_conns, monkeypatch, with_db, kept):
    seed.user('alice', role='user')
    monkeypatch.setattr(app_mod, '_IDLE_WITH_DB', with_db)
    srv, _ = serve(_db_app(db), slots=4)
    idle = [_kept_alive(srv.server_port, '/who') for _ in range(3)]
    gevent.sleep(0.2)
    assert _until(lambda: db_conns() == kept, within=2), \
        f'{db_conns()} of three idle connections hold a database connection, {kept} may'
    # and the one that gave it up opens a new one for its next request
    head, body = _ask(idle[-1], '/who')
    assert body == b'ok'
    for s in idle:
        s.close()
