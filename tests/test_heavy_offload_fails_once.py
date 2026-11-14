"""A heavy read or write that fails runs once, in the worker thread.

_heavy_read_offload and run_heavy_write had the threadpool apply inside the `except` meant
for "no hub here". The threadpool raises what the job raised, so a failed read (a locked
database after the 30 s busy timeout, a wrong key, an error in the transform) was taken
for a missing hub and run a second time, inline: synchronous SQLite on the hub, every
greenlet waiting on it, which is the stall these functions are there to prevent.
run_off_hub already looked the hub up alone. MK
"""
import sqlite3

import pytest
from gevent import monkey

from pegaprox.core import dbcrypto

_os_thread = monkey.get_original('threading', 'get_ident')


def _locked(calls):
    def run(*a, **kw):
        calls.append(_os_thread())
        raise sqlite3.OperationalError('database is locked')
    return run


def test_a_failing_heavy_read_runs_once_off_the_hub(monkeypatch):
    calls = []
    monkeypatch.setattr(dbcrypto, '_heavy_read_now', _locked(calls))

    with pytest.raises(sqlite3.OperationalError):
        dbcrypto.run_heavy_read('SELECT 1')

    assert len(calls) == 1, f'the read ran {len(calls)} times'
    assert calls[0] != _os_thread(), 'the read ran on the hub thread'


def test_a_cached_read_that_fails_runs_once_and_stores_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(dbcrypto, '_heavy_read_now', _locked(calls))

    with pytest.raises(sqlite3.OperationalError):
        dbcrypto.run_heavy_read('SELECT 1', cache_key='a failing window')

    assert len(calls) == 1, f'the read ran {len(calls)} times'
    assert 'a failing window' not in dbcrypto._HEAVY_CACHE


def test_a_failing_transform_is_not_run_again(monkeypatch):
    """The transform parses what the read returned, a large window of it at times."""
    monkeypatch.setattr(dbcrypto, '_heavy_read_now',
                        lambda sql, params, transform=None: transform(['a row']))
    calls = []

    with pytest.raises(sqlite3.OperationalError):
        dbcrypto.run_heavy_read('SELECT 1', transform=_locked(calls))

    assert len(calls) == 1, f'the transform ran {len(calls)} times'


def test_a_failing_heavy_write_runs_once_off_the_hub(monkeypatch, tmp_path):
    import pegaprox.constants as constants
    monkeypatch.setattr(constants, 'DATABASE_FILE', str(tmp_path / 'pegaprox.db'))
    calls = []

    with pytest.raises(sqlite3.OperationalError):
        dbcrypto.run_heavy_write(build=_locked(calls))

    assert len(calls) == 1, f'the write ran {len(calls)} times'
    assert calls[0] != _os_thread(), 'the write ran on the hub thread'

