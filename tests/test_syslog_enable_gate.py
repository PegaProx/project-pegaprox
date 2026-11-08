"""An unauthenticated listener must not come up because a read failed.

`_syslog_loop` decides whether to bind port 1514 from `syslog_enabled`. The default is
on, so a failed read only bites the operator who switched it OFF - and for them a
transient problem at boot silently re-opened an unauthenticated port.

The first attempt at this gate wrapped `load_server_settings()` in try/except. That
looks right and is not, which is why this file now drives the database rather than the
helper: **load_server_settings catches its own errors and returns its DEFAULTS**, and
`syslog_enabled` defaults to True. Nothing is ever raised, so the except branch could
only ever catch a failed import - a locked database walked straight through it as
"the operator wants the receiver".

So the tests below break the DATABASE, not the helper. If a future refactor makes the
gate trust `load_server_settings()` again, these go red; a test that merely makes that
helper raise would stay green and prove nothing.

The default still applies when the read SUCCEEDS and finds nothing. It is the difference
between "nobody said" and "we could not ask" that matters. MK
"""
import pytest

import pegaprox.background.syslog_server as S


class _DeadDb:
    """A database that refuses every way in, the way a locked or missing file does."""

    @property
    def conn(self):
        raise RuntimeError('database is locked')

    def get_server_settings(self):
        raise RuntimeError('database is locked')

    def _decrypt(self, value):
        return value


@pytest.fixture
def no_bind(monkeypatch):
    """Record whether the loop got as far as opening anything."""
    got = {'db': False, 'udp': False, 'tcp': False}
    monkeypatch.setattr(S, '_init_db', lambda: got.__setitem__('db', True))
    monkeypatch.setattr(S, '_udp_listener', lambda *a, **k: got.__setitem__('udp', True))
    monkeypatch.setattr(S, '_tcp_listener', lambda *a, **k: got.__setitem__('tcp', True))
    monkeypatch.setattr(S, '_drain_loop', lambda *a, **k: None)
    import gevent
    monkeypatch.setattr(gevent, 'sleep', lambda *_a, **_k: None)
    monkeypatch.setattr(gevent, 'spawn', lambda fn, *a, **k: fn(*a, **k))
    monkeypatch.setattr(gevent, 'joinall', lambda *a, **k: None)
    return got


def _kill_the_database(monkeypatch):
    """Break every route to the settings store, leaving the real helper in place."""
    import pegaprox.core.db as DB
    import pegaprox.api.helpers as H
    monkeypatch.setattr(DB, 'get_db', lambda *a, **k: _DeadDb())
    monkeypatch.setattr(H, 'get_db', lambda *a, **k: _DeadDb())


def _healthy_store(monkeypatch, values):
    """A settings store that answers, carrying `values`."""
    import pegaprox.api.helpers as H
    monkeypatch.setattr(S, '_settings_store_readable', lambda: True)
    monkeypatch.setattr(H, 'load_server_settings', lambda: values)


def test_a_dead_database_does_not_open_the_port(no_bind, monkeypatch):
    """The real failure mode, driven end to end.

    Note what is NOT stubbed: load_server_settings runs for real. It swallows the
    database error and reports syslog_enabled=True, exactly as it does in production.
    The gate has to disbelieve that on its own.
    """
    _kill_the_database(monkeypatch)

    # First, pin down the premise: the helper really does claim the receiver is wanted.
    from pegaprox.api.helpers import load_server_settings
    assert load_server_settings().get('syslog_enabled') is True, \
        'premise changed - the helper no longer reports the permissive default here'

    S._syslog_loop()

    assert not no_bind['db'], 'it initialised the store despite not knowing if it is wanted'
    assert not no_bind['udp'] and not no_bind['tcp'], \
        'an unauthenticated listener came up while the settings store was unreadable'


def test_an_explicit_off_still_wins(no_bind, monkeypatch):
    _healthy_store(monkeypatch, {'syslog_enabled': False})
    S._syslog_loop()
    assert not no_bind['udp'] and not no_bind['tcp']


def test_the_default_is_still_on_when_we_could_actually_ask(no_bind, monkeypatch):
    """The mirror. Failing closed on a read error must not turn into failing closed on a
    perfectly good settings file that simply never mentions syslog."""
    _healthy_store(monkeypatch, {})
    S._syslog_loop()
    assert no_bind['udp'] and no_bind['tcp'], 'the receiver stopped starting by default'


def test_a_transient_failure_heals(no_bind, monkeypatch):
    """Boot order matters here - settings are often not readable for the first second."""
    import pegaprox.api.helpers as H
    calls = {'n': 0}

    def _flaky_probe():
        calls['n'] += 1
        if calls['n'] < 3:
            raise RuntimeError('not ready yet')
        return True

    monkeypatch.setattr(S, '_settings_store_readable', _flaky_probe)
    monkeypatch.setattr(H, 'load_server_settings', lambda: {})

    S._syslog_loop()

    assert calls['n'] == 3, f'it gave up after {calls["n"]} attempt(s)'
    assert no_bind['udp'], 'it never recovered once settings became readable'


def test_it_does_not_sleep_after_the_last_attempt(monkeypatch, no_bind):
    """A pointless final wait delays the log line that tells the operator what is wrong."""
    naps = {'n': 0}
    import gevent
    monkeypatch.setattr(gevent, 'sleep', lambda *_a, **_k: naps.__setitem__('n', naps['n'] + 1))
    monkeypatch.setattr(S, '_settings_store_readable',
                        lambda: (_ for _ in ()).throw(RuntimeError('still locked')))

    S._syslog_loop()

    assert naps['n'] == S.SYSLOG_SETTINGS_ATTEMPTS - 1, \
        f"slept {naps['n']}x for {S.SYSLOG_SETTINGS_ATTEMPTS} attempts"
    assert not no_bind['udp'] and not no_bind['tcp']
