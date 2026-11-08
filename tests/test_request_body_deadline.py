"""A request body has to arrive in time until somebody has signed in for it (#1052).

handle() clears the socket timeout once the TLS handshake is done, and _IdleTimeoutMixin
bounded the request line and the headers only. A POST that announces a Content-Length and
never sends the body therefore parked in get_json() for as long as the client liked - and a
route that answers without reading the body parked one step later, in pywsgi's discard of
the rest. Each of those holds a slot of the request pool, no login needed, so `workers` of
them is the whole server.

The body now has PEGAPROX_BODY_TIMEOUT seconds to arrive. The clock comes off where a
request is known to be somebody's (require_auth, a standby's forwarded write, a group
member's signed call), so an ISO upload over a slow link is not cut off. For an account
only a large body comes off it, and only while the account has room next to its
WebSockets (#988): a signed-in viewer could otherwise hold the pool the same way.

These run the real app behind a real gevent pywsgi server with the real mixin and a pool of
two, which is the property that matters: two withheld bodies used to be the whole pool.
"""
import json
import socket
import time

import gevent
import pytest
from gevent.pool import Pool
from gevent.pywsgi import WSGIHandler, WSGIServer

import pegaprox.app as app_mod
import pegaprox.api.auth as auth_api
import pegaprox.utils.auth as authmod
import pegaprox.utils.realtime as rtu

DEADLINE = 0.5
# where the server hangs the clock on a request (utils/auth.py BODY_DEADLINE_ENVIRON)
CLOCK = 'pegaprox.body_deadline'
# above authmod._SMALL_BODY: what an upload looks like
LARGE = 80 * 1024


@pytest.fixture(autouse=True)
def _no_held(monkeypatch):
    monkeypatch.setattr(rtu, '_held_ws', {})
    monkeypatch.setattr(rtu, '_held_bodies', {}, raising=False)


@pytest.fixture
def serve(api, monkeypatch):
    """Start the integration app behind gevent pywsgi with the mixin production composes."""
    # signing in is not what these test: let /api/auth/login reach its get_json()
    monkeypatch.setattr(auth_api, 'initialization_state', lambda: authmod.INIT_INITIALIZED)
    monkeypatch.setattr(auth_api, 'login_attempts_by_ip', {})
    monkeypatch.setattr(auth_api, 'login_attempts_by_user', {})
    servers = []

    def start(slots=2, base=WSGIHandler, pool=None):
        handler = type('Handler', (app_mod._IdleTimeoutMixin, base),
                       {'_body_timeout': DEADLINE})
        srv = WSGIServer(('127.0.0.1', 0), api.app, handler_class=handler,
                         spawn=Pool(slots) if pool is None else pool, log=None, error_log=None)
        srv.start()
        servers.append(srv)
        return srv.server_port

    yield start
    for srv in servers:
        srv.stop(timeout=1)


def _connect(port, head, body=b''):
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(head.encode() + body)
    return s


def _post_head(path, length, extra=''):
    return (f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n'
            f'Content-Length: {length}\r\n{extra}\r\n')


def _read_until_closed(s, within):
    """Everything the server sends, and whether it closed the connection within `within`."""
    s.settimeout(0.1)
    data, end = b'', time.monotonic() + within
    while time.monotonic() < end:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return data, True
        if not chunk:
            return data, True
        data += chunk
    return data, False


def _status(data):
    return data.split(b'\r\n', 1)[0]


def test_withheld_bodies_do_not_hold_the_pool(serve):
    """The finding: two logins that never send their body were a pool of two."""
    port = serve(slots=2)
    parked = [_connect(port, _post_head('/api/auth/login', 64)) for _ in range(2)]
    gevent.sleep(0.1)

    health = _connect(port, 'GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n')
    answer, _ = _read_until_closed(health, within=DEADLINE + 4)

    assert b' 200 ' in _status(answer), \
        f'a withheld body still holds its pool slot: /api/health got {answer[:80]!r}'
    for s in parked:
        data, closed = _read_until_closed(s, within=3)
        assert b' 400 ' in _status(data), data[:120]
        assert closed, 'the rest of the body is still owed: the connection has to close'
        s.close()
    health.close()


def _gevent_websocket_handler():
    from geventwebsocket.handler import WebSocketHandler
    return WebSocketHandler


@pytest.mark.parametrize('base', ['pywsgi', 'geventwebsocket'])
@pytest.mark.parametrize('upgrade', ['Connection: Upgrade\r\n', 'Upgrade: websocket\r\n',
                                     'Connection: Upgrade\r\nUpgrade: websocket\r\n'])
def test_asking_for_an_upgrade_does_not_take_the_clock_off(serve, base, upgrade):
    """pywsgi gives a request that asks for an upgrade its raw rfile as wsgi.input. A POST
    is never upgraded, so the login read its body from there, past the clock."""
    port = serve(slots=2, base=WSGIHandler if base == 'pywsgi' else _gevent_websocket_handler())
    parked = [_connect(port, _post_head('/api/auth/login', 64, upgrade)) for _ in range(2)]
    gevent.sleep(0.1)

    health = _connect(port, 'GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n')
    answer, _ = _read_until_closed(health, within=DEADLINE + 4)

    assert b' 200 ' in _status(answer), \
        f'an upgrade header kept the withheld body off the clock: /api/health got {answer[:80]!r}'
    for s in parked:
        data, closed = _read_until_closed(s, within=3)
        assert closed, 'the rest of the body is still owed: the connection has to close'
        s.close()
    health.close()


def test_a_route_that_never_reads_the_body_is_bounded_too(serve):
    """pywsgi reads off an unread body after the response to keep the connection - a
    withheld one parked right there."""
    port = serve(slots=2)
    s = _connect(port, 'GET /api/health HTTP/1.1\r\nHost: localhost\r\n'
                       'Content-Length: 100\r\n\r\n')

    data, closed = _read_until_closed(s, within=DEADLINE + 3)

    assert b' 200 ' in _status(data)
    assert closed, 'the discard of the withheld body still holds the slot'
    s.close()


def test_an_anonymous_body_that_stalls_halfway_is_cut_off(serve):
    port = serve()
    body = json.dumps({'username': 'x' * 40}).encode()
    s = _connect(port, _post_head('/api/auth/login', len(body)), body[:len(body) // 2])

    data, closed = _read_until_closed(s, within=DEADLINE + 3)

    assert b' 400 ' in _status(data)
    assert b'Username and password required' not in data, 'the whole body was read'
    assert closed
    s.close()


def test_an_anonymous_body_sent_promptly_is_read(serve):
    """The login form keeps working: its body arrives with the headers."""
    port = serve()
    body = json.dumps({'username': 'someone'}).encode()
    s = _connect(port, _post_head('/api/auth/login', len(body), 'Connection: close\r\n'), body)

    data, _ = _read_until_closed(s, within=5)

    assert b'Username and password required' in data
    s.close()


def _put_prefs(port, sid, body):
    head = ('PUT /api/user/preferences HTTP/1.1\r\nHost: localhost\r\n'
            'Content-Type: application/json\r\nX-Requested-With: XMLHttpRequest\r\n'
            f'Origin: http://localhost\r\nX-Session-ID: {sid}\r\nConnection: close\r\n'
            f'Content-Length: {len(body)}\r\n\r\n')
    return _connect(port, head)


def _dribble(s, body, parts=4):
    step = len(body) // parts + 1
    for i in range(0, len(body), step):
        gevent.sleep(DEADLINE)                     # `parts` x the deadline in all
        try:
            s.sendall(body[i:i + step])
        except OSError:
            return


def test_a_signed_in_upload_may_take_longer_than_the_deadline(serve, api, seed):
    """An ISO upload over a slow link: require_auth takes the clock off before the route
    reads the body, so it may take as long as it needs."""
    seed.user('alice', role='user')
    sid = api.as_user({'username': 'alice', 'role': 'user'}).session_id
    port = serve()
    body = json.dumps({'theme': 'nord', 'pad': 'x' * LARGE}).encode()
    s = _put_prefs(port, sid, body)
    _dribble(s, body)

    data, _ = _read_until_closed(s, within=5)

    assert b' 200 ' in _status(data), data[:200]
    assert api.as_user({'username': 'alice', 'role': 'user'}).get(
        '/api/user/preferences').get_json()['theme'] == 'nord'
    assert rtu._held_bodies == {}, 'the finished upload still counts against its account'
    s.close()


def test_a_small_signed_in_body_keeps_its_clock(serve, api, seed):
    """A body this size comes with its headers; one that does not is not an upload."""
    seed.user('alice', role='user')
    sid = api.as_user({'username': 'alice', 'role': 'user'}).session_id
    port = serve()
    body = json.dumps({'theme': 'nord', 'pad': 'x' * 200}).encode()
    s = _put_prefs(port, sid, body)
    _dribble(s, body)

    data, closed = _read_until_closed(s, within=3)

    assert b' 400 ' in _status(data), data[:200]
    assert closed
    s.close()


def test_one_account_cannot_hold_the_pool_with_bodies_it_never_sends(serve, api, seed,
                                                                    monkeypatch):
    """#988 next to #1052: a viewer that withholds large bodies on routes it may call held
    one slot each for as long as it liked. They count against the account like its
    WebSockets; past that a body keeps its clock."""
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 2)
    seed.user('vic', role='viewer')
    sid = api.as_user({'username': 'vic', 'role': 'viewer'}).session_id
    slots = 8
    pool = Pool(slots)
    port = serve(pool=pool)
    head = (f'GET /api/user/preferences HTTP/1.1\r\nHost: localhost\r\nX-Session-ID: {sid}\r\n'
            f'Content-Length: {10 * LARGE}\r\n\r\n')
    parked = [_connect(port, head) for _ in range(5)]
    gevent.sleep(DEADLINE + 0.5)            # past the deadline of those that keep it

    end = time.monotonic() + 3
    while slots - pool.free_count() > 2 and time.monotonic() < end:
        gevent.sleep(0.05)

    assert slots - pool.free_count() == 2, \
        f'{slots - pool.free_count()} slots held by one viewer with bodies it never sends'
    for s in parked:
        s.close()
    end = time.monotonic() + 3
    while rtu._held_bodies and time.monotonic() < end:
        gevent.sleep(0.05)
    assert rtu._held_bodies == {}, 'a body that ended still counts against its account'


def test_bodies_and_websockets_share_the_account_cap(monkeypatch):
    """A WebSocket never hangs up an upload, and an account's slow bodies and sockets
    together hold at most one more than the cap."""
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 2)
    keys = [rtu.hold_body('vic'), rtu.hold_body('vic')]
    assert None not in keys
    assert rtu.hold_body('vic') is None, 'a third body came off its clock past the cap'
    assert rtu.hold_body('bob') is not None, 'the cap of one account held up another'

    class _Ws:
        sock = None
    with app_mod.Flask(__name__).test_request_context('/'):
        rtu.hold_websocket('vic', _Ws())
        rtu.hold_websocket('vic', _Ws())
    assert sum(1 for u, _ in rtu._held_ws.values() if u == 'vic') == 1
    assert len([u for u in rtu._held_bodies.values() if u == 'vic']) == 2

    rtu.release_body(keys[0])
    assert rtu.hold_body('vic') is None, 'two bodies and a socket are the cap and one over'


def test_a_websocket_upgrade_still_finds_its_socket():
    """simple-websocket takes the socket from wsgi.input, through .rfile when it has no
    .raw. An upgrade's wsgi.input is the clock as well, and the raw stream is behind it."""
    class _Input:
        rfile = object()

        def _discard(self):
            pass

    class _Base:
        wsgi_input = None

        def get_environ(self):
            self.wsgi_input = _Input()
            return {'wsgi.input': self.wsgi_input.rfile}

    class _H(app_mod._IdleTimeoutMixin, _Base):
        _body_timeout = DEADLINE

    h = _H()
    env = h.get_environ()

    assert env['wsgi.input'] is h.wsgi_input is env[CLOCK]
    assert not hasattr(env['wsgi.input'], 'raw')
    assert env['wsgi.input'].rfile is _Input.rfile


def test_a_disabled_body_bound_leaves_the_stream_alone():
    """PEGAPROX_BODY_TIMEOUT=0 restores what was there before."""
    class _Base:
        wsgi_input = None

        def get_environ(self):
            self.wsgi_input = object()
            return {'wsgi.input': self.wsgi_input}

    class _H(app_mod._IdleTimeoutMixin, _Base):
        _body_timeout = 0

    h = _H()
    env = h.get_environ()

    assert env['wsgi.input'] is h.wsgi_input
    assert CLOCK not in env


# --- where the clock comes off -------------------------------------------------------

class _Clock:
    lifted = False
    release = None

    def lift(self, release=None):
        self.lifted = True
        self.release = release


def test_require_auth_takes_the_clock_off(api, seed):
    seed.user('alice', role='user')
    clock = _Clock()

    r = api.as_user({'username': 'alice', 'role': 'user'}).put(
        '/api/user/preferences', json={'theme': 'nord', 'pad': 'x' * LARGE},
        environ_base={CLOCK: clock})

    assert r.status_code == 200
    assert clock.lifted
    assert authmod.BODY_DEADLINE_ENVIRON == CLOCK
    # the account's share comes back when the server is done with the request
    assert list(rtu._held_bodies.values()) == ['alice']
    clock.release()
    assert rtu._held_bodies == {}


def test_require_auth_leaves_a_small_body_its_clock(api, seed):
    seed.user('alice', role='user')
    clock = _Clock()

    r = api.as_user({'username': 'alice', 'role': 'user'}).put(
        '/api/user/preferences', json={'theme': 'nord'}, environ_base={CLOCK: clock})

    assert r.status_code == 200
    assert not clock.lifted
    assert rtu._held_bodies == {}


def test_an_anonymous_request_keeps_its_clock(api):
    clock = _Clock()

    r = api.anon().put('/api/user/preferences', json={'theme': 'nord'},
                       environ_base={CLOCK: clock})

    assert r.status_code == 401
    assert not clock.lifted


def test_a_forbidden_request_keeps_its_clock(api, seed):
    """Signed in is not enough: only a request that goes on to its route is let off."""
    seed.user('vic', role='viewer')
    clock = _Clock()

    r = api.as_user({'username': 'vic', 'role': 'viewer'}).post(
        '/api/users', json={'username': 'x'}, environ_base={CLOCK: clock})

    assert r.status_code == 403
    assert not clock.lifted


@pytest.mark.parametrize('signed', [True, False])
def test_a_members_signed_headers_take_the_clock_off(api, monkeypatch, signed):
    """#625: a forwarded write comes to the active as one signed envelope, upload and all.
    The signature over its headers is checked before the body is read."""
    import pegaprox.api.ha as ha_api
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'signed_before_body', lambda *a: signed)
    clock = _Clock()

    with api.app.test_request_context('/api/ha/peer/forward', method='POST',
                                      environ_base={CLOCK: clock}):
        assert ha_api.signed_member_call() is signed

    assert clock.lifted is signed


def test_a_standby_lifts_the_clock_before_it_reads_a_forwarded_write(api, monkeypatch):
    """#625: on a standby the browser's upload is read by forward_to_active, before any
    route and its require_auth."""
    import pegaprox.api.ha as ha_api
    from pegaprox.core import ha
    clock = _Clock()
    seen = {}
    monkeypatch.setattr(authmod, 'validate_session', lambda sid: {'user': 'alice', 'role': 'admin'})
    monkeypatch.setattr(ha, 'forwarding', lambda: True)

    def _forward(session):
        seen['lifted'] = clock.lifted
        return 'forwarded'
    monkeypatch.setattr(ha_api, '_forward', _forward)

    with api.app.test_request_context('/api/clusters/c1/vms', method='POST',
                                      data=b'{"pad": "' + b'x' * LARGE + b'"}',
                                      content_type='application/json',
                                      headers={'X-Session-ID': 'sid'},
                                      environ_base={CLOCK: clock}):
        assert ha_api.forward_to_active() == 'forwarded'

    assert seen == {'lifted': True}
    assert list(rtu._held_bodies.values()) == ['alice'], 'the upload is not counted'


def test_without_a_session_a_standby_forwards_nothing_and_lifts_nothing(api, monkeypatch):
    import pegaprox.api.ha as ha_api
    clock = _Clock()
    monkeypatch.setattr(authmod, 'validate_session', lambda sid: None)

    with api.app.test_request_context('/api/clusters/c1/vms', method='POST', data=b'{}',
                                      content_type='application/json',
                                      environ_base={CLOCK: clock}):
        assert ha_api.forward_to_active() is None

    assert not clock.lifted


def test_lifting_outside_a_request_does_nothing():
    authmod.lift_body_deadline()
