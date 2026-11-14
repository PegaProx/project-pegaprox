"""A PBS that was down when PegaProx connected to it stayed "not connected" (#1156).

PBSManager.connect() ran at the start (load_pbs_servers) and on the add, edit and test
routes, and the API calls log in again on a 401 only. The reporter's PegaProx container
came up while the PBS VM on the other host was still booting, the one connect failed, and
the server stayed offline until the container was restarted.

retry_disconnected() is one pass of the loop that now tries such a server again: 30 s
after the failed attempt, doubling up to 5 min, back to 30 s after a success. A PBS that
answers and turns the login down waits the full 5 min every time. One line in the log
per change, not per attempt. A server deleted, disabled or rebuilt meanwhile is left
alone. The wire is a fake session, the clock a fake monotonic one; the managers, the
registry and the pass are the real ones.
"""
import logging
import threading
import types

import pytest
import requests

import pegaprox.globals as ppglobals
from pegaprox.core import pbs as corepbs
from pegaprox.core.pbs import PBSManager, retry_disconnected, reconnect_soon, RETRY_FIRST, RETRY_MAX


class _Clock:
    def __init__(self, at=1000.0):
        self.at = at

    def __call__(self):
        return self.at


class _Resp:
    def __init__(self, status):
        self.status_code = status

    def json(self):
        return {'data': {'version': '4.0', 'ticket': 't', 'CSRFPreventionToken': 'c'}}


class _Pbs:
    """The PBS on the other end. `state` is 'down' (nothing listens), an HTTP status, or
    'up' (200). Records the clock at every login it gets."""

    def __init__(self, clock, state='down'):
        self.clock, self.state = clock, state
        self.headers = {}
        self.cookies = types.SimpleNamespace(set=lambda *a, **k: None)
        self.logins = []
        self.on_login = None

    def _answer(self):
        self.logins.append(self.clock())
        if self.on_login:
            self.on_login()
        if self.state == 'down':
            raise requests.exceptions.ConnectionError('Connection refused')
        return _Resp(200 if self.state == 'up' else self.state)

    def get(self, url, **kw):
        return self._answer()

    def post(self, url, **kw):
        return self._answer()


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    import time as _time
    monkeypatch.setattr(corepbs, 'time', types.SimpleNamespace(
        monotonic=c, time=_time.time, sleep=_time.sleep))
    return c


@pytest.fixture
def registry():
    saved = dict(ppglobals.pbs_managers)
    ppglobals.pbs_managers.clear()
    try:
        yield ppglobals.pbs_managers
    finally:
        ppglobals.pbs_managers.clear()
        ppglobals.pbs_managers.update(saved)


def _server(registry, clock, pbs_id='pbs1', state='down', token=True, **cfg):
    """A server as load_pbs_servers leaves it: built, registered, connected once."""
    base = {'name': pbs_id, 'host': '10.0.0.5'}
    if token:
        base.update(api_token_id='root@pam!pegaprox', api_token_secret='s3cr3t-value')
    else:
        base.update(user='root@pam', password='pw-value')
    m = PBSManager(pbs_id, dict(base, **cfg))
    m._session = _Pbs(clock, state)
    m.connect()
    registry[pbs_id] = m
    return m


def _run(clock, until, step=1):
    """The loop, a pass every `step` seconds of the fake clock up to `until`."""
    while clock.at < until:
        clock.at += step
        retry_disconnected()


def _gaps(times):
    return [round(b - a) for a, b in zip(times, times[1:])]


# -- the reporter's case ------------------------------------------------------------------------

def test_a_pbs_that_was_still_booting_connects_once_it_is_up(registry, clock):
    m = _server(registry, clock)
    assert m.connected is False

    _run(clock, clock.at + 100)
    assert m.connected is False
    m._session.state = 'up'
    _run(clock, clock.at + RETRY_MAX + 1)

    assert m.connected is True, 'nothing but a restart of PegaProx brought it back'
    assert m.last_error == ''


@pytest.mark.parametrize('token', [True, False], ids=['api_token', 'ticket'])
def test_both_logins_are_retried(registry, clock, token):
    m = _server(registry, clock, token=token)
    m._session.state = 'up'
    _run(clock, clock.at + RETRY_FIRST)
    assert m.connected is True


# -- how often ---------------------------------------------------------------------------------

def test_a_server_that_stays_down_is_tried_ever_less_often_up_to_five_minutes(registry, clock):
    m = _server(registry, clock)
    _run(clock, clock.at + 1100)

    assert _gaps(m._session.logins) == [30, 60, 120, 240, 300, 300]


def test_after_a_success_the_next_outage_starts_again_at_thirty_seconds(registry, clock):
    m = _server(registry, clock)
    _run(clock, clock.at + 500)
    m._session.state = 'up'
    while not m.connected:
        clock.at += 1
        retry_disconnected()

    # the PBS goes away right after, before another pass ran, and a login after a 401
    # finds it gone
    m._session.state = 'down'
    m.connect()
    start = len(m._session.logins)
    _run(clock, clock.at + 200)

    assert _gaps(m._session.logins[start - 1:]) == [30, 60]


@pytest.mark.parametrize('status', [401, 403])
def test_a_refused_login_waits_the_full_five_minutes_every_time(registry, clock, status):
    m = _server(registry, clock, state=status)
    assert m._auth_refused is True
    _run(clock, clock.at + 3 * RETRY_MAX + 5)

    assert _gaps(m._session.logins) == [RETRY_MAX] * 3


def test_a_server_error_is_not_taken_for_a_refusal(registry, clock):
    """A PBS that answers 503 while its proxy starts is on its way up, not saying no."""
    m = _server(registry, clock, state=503)
    assert m._auth_refused is False
    _run(clock, clock.at + 200)
    assert _gaps(m._session.logins) == [30, 60]


def test_a_token_without_its_secret_counts_as_refused(registry, clock):
    m = _server(registry, clock, token=False, user='root@pam!pegaprox', password='')
    assert m.connect() is False and m._auth_refused is True


def test_two_passes_at_the_same_moment_try_a_server_once(registry, clock):
    m = _server(registry, clock)
    clock.at += RETRY_FIRST
    assert retry_disconnected() == 1
    assert retry_disconnected() == 0
    assert len(m._session.logins) == 2


def test_a_connect_from_a_route_counts_as_the_last_attempt(registry, clock):
    """The test or edit route just tried: the loop does not repeat it right after."""
    m = _server(registry, clock)
    clock.at += RETRY_FIRST - 1
    m.connect()
    clock.at += 2
    assert retry_disconnected() == 0


# -- what it leaves alone ---------------------------------------------------------------------

def test_a_disabled_server_is_not_tried(registry, clock):
    m = _server(registry, clock, enabled=False)
    _run(clock, clock.at + RETRY_MAX)
    assert len(m._session.logins) == 1


def test_a_server_deleted_during_the_pass_is_not_tried(registry, clock):
    a = _server(registry, clock, 'pbs_a')
    clock.at += 1
    b = _server(registry, clock, 'pbs_b')
    # a is the older one and goes first; while it connects, b is deleted
    a._session.on_login = lambda: registry.pop('pbs_b', None)
    clock.at += RETRY_FIRST

    assert retry_disconnected() == 1
    assert len(b._session.logins) == 1


def test_a_server_rebuilt_during_the_pass_is_not_tried_in_its_old_form(registry, clock):
    """The edit route (or a standby reload) puts a new manager under the same id. The old
    one, with the old host and credentials, must not log in anywhere any more."""
    a = _server(registry, clock, 'pbs_a')
    clock.at += 1
    old_b = _server(registry, clock, 'pbs_b')
    new_b = PBSManager('pbs_b', {'name': 'pbs_b', 'host': '10.0.0.6',
                                 'api_token_id': 'root@pam!new', 'api_token_secret': 'other'})
    new_b._session = _Pbs(clock, 'up')

    def _edit():
        registry['pbs_b'] = new_b
    a._session.on_login = _edit
    clock.at += RETRY_FIRST

    retry_disconnected()
    assert len(old_b._session.logins) == 1, 'the replaced manager logged in again'
    assert registry['pbs_b'] is new_b


def test_a_pass_starts_no_thread_per_server(registry, clock, monkeypatch):
    servers = [_server(registry, clock, f'pbs{i}') for i in range(40)]

    def _no_thread(*a, **k):
        raise AssertionError('a pass started a thread')
    monkeypatch.setattr(corepbs.threading, 'Thread', _no_thread)
    clock.at += RETRY_FIRST

    assert retry_disconnected() == 40
    assert all(len(s._session.logins) == 2 for s in servers)


# -- the log -----------------------------------------------------------------------------------

def _said(caplog, text):
    return [r for r in caplog.records if text in r.getMessage() and r.levelno >= logging.WARNING]


def test_a_long_outage_is_one_line_in_the_log_and_the_return_another(registry, clock, caplog):
    m = _server(registry, clock)
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        _run(clock, clock.at + 1600)
        m._session.state = 'up'
        _run(clock, clock.at + RETRY_MAX + 1)

    loud = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(loud) == 2, loud
    assert 'still not connected' in loud[0] and 'Connection failed' in loud[0]
    # seven tries ran into the outage, the eighth found the PBS up
    assert 'reconnected after 8 retries' in loud[1]


def test_a_refused_login_is_said_once_with_what_to_check(registry, clock, caplog):
    m = _server(registry, clock, state=401)
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        _run(clock, clock.at + 4 * RETRY_MAX)

    assert len(m._session.logins) == 5
    loud = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(loud) == 1, loud
    assert 'HTTP 401' in loud[0] and 'API token' in loud[0]


def test_a_change_from_down_to_refused_is_said(registry, clock, caplog):
    m = _server(registry, clock)
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        _run(clock, clock.at + 100)
        m._session.state = 401
        _run(clock, clock.at + 2 * RETRY_MAX)

    assert len(_said(caplog, 'still not connected')) == 1
    assert len(_said(caplog, 'turns the login down')) == 1


def test_connected_again_through_a_route_closes_what_the_log_said(registry, clock, caplog):
    m = _server(registry, clock)
    _run(clock, clock.at + 100)
    m._session.state = 'up'
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        m.connect()             # the test route
        retry_disconnected()
    assert len(_said(caplog, 'connected again')) == 1
    assert m._retry_said == '' and m._retry_delay == 0


# -- someone is looking --------------------------------------------------------------------------

def test_a_kick_brings_the_next_try_forward_and_does_not_connect_itself(registry, clock):
    m = _server(registry, clock)
    _run(clock, clock.at + 1100)            # the last try 50 s ago, the next one due in 250
    assert clock.at - m._session.logins[-1] == 50
    logins = len(m._session.logins)
    corepbs._retry_wake.clear()

    reconnect_soon(m)
    assert len(m._session.logins) == logins, 'the kick logged in on the request thread'
    assert corepbs._retry_wake.is_set()

    m._session.state = 'up'
    clock.at += 1
    retry_disconnected()
    assert m.connected is True


def test_a_kick_does_not_shorten_the_wait_of_a_refused_login(registry, clock):
    m = _server(registry, clock, state=401)
    reconnect_soon(m)
    _run(clock, clock.at + RETRY_MAX - 1)
    assert len(m._session.logins) == 1


def test_the_status_route_kicks_and_answers_at_once(api, seed, registry, clock, monkeypatch):
    m = _server(registry, clock)
    admin = api.as_user(seed.user('pbs_admin', role='admin'))
    kicked = []
    monkeypatch.setattr('pegaprox.api.pbs.reconnect_soon', lambda mgr: kicked.append(mgr))

    r = admin.get('/api/pbs/pbs1/status')

    assert r.status_code == 503, r.get_data(as_text=True)
    assert kicked == [m]
    assert len(m._session.logins) == 1, 'the route waited for a login'


# -- the loop -------------------------------------------------------------------------------------

def test_the_loop_is_started_once(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(corepbs, '_retry_loop', lambda: release.wait(5))
    monkeypatch.setattr(corepbs, '_retry_thread', None)
    try:
        corepbs.start_reconnect_loop()
        first = corepbs._retry_thread
        corepbs.start_reconnect_loop()
        assert corepbs._retry_thread is first and first.daemon
    finally:
        release.set()


def test_main_starts_the_loop_once_after_the_managers_in_every_role():
    """The loop is what brings the reporter's PBS back. A start that went missing from main()
    would leave every other test in here green."""
    import ast
    import inspect
    from pegaprox import app as app_mod
    fn = ast.parse(inspect.getsource(app_mod.main)).body[0]

    def calls(name, trees):
        return [n.lineno for tree in trees for n in ast.walk(tree) if isinstance(n, ast.Call)
                and (getattr(n.func, 'attr', None) or getattr(n.func, 'id', None)) == name]
    starts = calls('start_reconnect_loop', [fn])
    assert len(starts) == 1, 'main() starts the loop exactly once'
    managers = calls('_start_managers', [fn])
    assert managers and min(managers) < starts[0], 'the loop starts after the PBS managers exist'
    # a standby with the live view has PBS managers as well, so no role check around it
    guarded = [n for n in ast.walk(fn) if isinstance(n, ast.If) and 'standby' in ast.unparse(n.test)]
    assert not calls('start_reconnect_loop', guarded)
