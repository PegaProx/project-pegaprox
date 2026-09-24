"""An unauthenticated listener must not come up because a read failed.

`_syslog_loop` decided whether to bind port 1514 from `syslog_enabled`, and swallowed a
failed settings read into "fall through to default-on". The default is on, so that only
bites the operator who switched it OFF - and for them a transient read failure at boot
silently re-opened an unauthenticated port.

The default still applies when the read SUCCEEDS and finds nothing. It is the difference
between "nobody said" and "we could not ask" that matters. MK
"""
import pytest

import pegaprox.background.syslog_server as S


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


def _settings(monkeypatch, behaviour):
    import pegaprox.api.helpers as H
    monkeypatch.setattr(H, 'load_server_settings', behaviour)


def test_an_unreadable_settings_store_does_not_open_the_port(no_bind, monkeypatch):
    def _boom():
        raise RuntimeError('database is locked')
    _settings(monkeypatch, _boom)

    S._syslog_loop()

    assert not no_bind['db'], 'it initialised the store despite not knowing if it is wanted'
    assert not no_bind['udp'] and not no_bind['tcp'], \
        'an unauthenticated listener came up on a failed settings read'


def test_an_explicit_off_still_wins(no_bind, monkeypatch):
    _settings(monkeypatch, lambda: {'syslog_enabled': False})
    S._syslog_loop()
    assert not no_bind['udp'] and not no_bind['tcp']


def test_the_default_is_still_on_when_we_could_actually_ask(no_bind, monkeypatch):
    """The mirror. Failing closed on a read error must not turn into failing closed on a
    perfectly good settings file that simply never mentions syslog."""
    _settings(monkeypatch, lambda: {})
    S._syslog_loop()
    assert no_bind['udp'] and no_bind['tcp'], 'the receiver stopped starting by default'


def test_a_transient_failure_heals(no_bind, monkeypatch):
    """Boot order matters here - settings are often not readable for the first second."""
    calls = {'n': 0}

    def _flaky():
        calls['n'] += 1
        if calls['n'] < 3:
            raise RuntimeError('not ready yet')
        return {}
    _settings(monkeypatch, _flaky)

    S._syslog_loop()

    assert calls['n'] == 3, f'it gave up after {calls["n"]} attempt(s)'
    assert no_bind['udp'], 'it never recovered once settings became readable'
