"""What the heavy-read cache keeps, and for how long.

core/dbcrypto.run_heavy_read keeps a read for a minute under its key. An entry used to stay
until the next read of the same key replaced it, so a window nobody asked for again was held
for good, and every `days` a caller passed kept one more: gigabytes of parsed metrics at a
few thousand guests. Expired entries go on every cached read and after every metrics save,
past PEGAPROX_HEAVY_READ_MAX_KEYS keys the ones that expire first make room, and the minute
counts from when the value is there, not from when the read began.
MK Oct 2026
"""
import os
import subprocess
import sys
import types

import pytest

from pegaprox.core import dbcrypto

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(key, ttl=None):
    return dbcrypto.run_heavy_read('SELECT 1 AS one', cache_key=key, ttl=ttl,
                                   transform=lambda rows: [tuple(r) for r in rows])


def test_an_expired_entry_goes_on_the_next_read_of_any_key(db):
    now = dbcrypto._time.monotonic()
    dbcrypto._HEAVY_CACHE['old window'] = (now - 1, ['a parsed month'])
    dbcrypto._HEAVY_CACHE['young'] = (now + 30, ['still good'])
    assert _read('another') == [(1,)]
    assert 'old window' not in dbcrypto._HEAVY_CACHE
    assert dbcrypto._HEAVY_CACHE['young'][1] == ['still good']


def test_a_metrics_save_lets_go_of_expired_entries_too(db):
    from pegaprox.background import metrics_store
    dbcrypto._HEAVY_CACHE['old window'] = (dbcrypto._time.monotonic() - 1, ['a parsed month'])
    metrics_store.save({'clusters': {}}, '2026-10-21T10:00:00', '2026-01-01T00:00:00')
    assert 'old window' not in dbcrypto._HEAVY_CACHE


def test_past_the_key_cap_the_entries_that_expire_first_make_room(db, monkeypatch):
    monkeypatch.setattr(dbcrypto, '_HEAVY_MAX_KEYS', 3)
    now = dbcrypto._time.monotonic()
    for key, left in (('soon', 5), ('later', 40), ('latest', 50)):
        dbcrypto._HEAVY_CACHE[key] = (now + left, key)
    _read('new')
    assert set(dbcrypto._HEAVY_CACHE) == {'later', 'latest', 'new'}
    # the entry just stored stays even where it expires first
    _read('short lived', ttl=1)
    assert 'short lived' in dbcrypto._HEAVY_CACHE and len(dbcrypto._HEAVY_CACHE) == 3


def test_the_ttl_counts_from_when_the_value_is_there(db, monkeypatch):
    clock = [1000.0]
    fake_time = types.SimpleNamespace(monotonic=lambda: clock[0])
    monkeypatch.setattr(dbcrypto, '_time', fake_time)

    def slow_fetch(sql, params, transform=None):
        clock[0] += 10          # a read of ten seconds
        return ['rows']
    monkeypatch.setattr(dbcrypto, '_heavy_read_offload', slow_fetch)
    dbcrypto.run_heavy_read('SELECT 1', cache_key='window', ttl=60)
    assert dbcrypto._HEAVY_CACHE['window'][0] == 1070.0
    clock[0] = 1065.0
    assert dbcrypto.run_heavy_read('SELECT 1', cache_key='window', ttl=60) == ['rows']
    assert clock[0] == 1065.0, 'served from the cache, no second read'


def test_a_failed_read_leaves_no_entry_and_the_next_one_tries_again(db, monkeypatch):
    calls = []

    def failing(sql, params, transform=None):
        calls.append(1)
        raise RuntimeError('locked')
    monkeypatch.setattr(dbcrypto, '_heavy_read_offload', failing)
    for _ in range(2):
        try:
            dbcrypto.run_heavy_read('SELECT 1', cache_key='window')
        except RuntimeError:
            pass
    assert calls == [1, 1] and 'window' not in dbcrypto._HEAVY_CACHE


def test_a_statement_list_is_read_in_one_transaction(db):
    """run_heavy_read's list form: one list of rows per statement."""
    got = dbcrypto.run_heavy_read([('SELECT 1 AS a', ()), ('SELECT ? AS b', (2,))],
                                  transform=lambda res: [[tuple(r) for r in rows] for rows in res])
    assert got == [[(1,)], [(2,)]]


@pytest.mark.parametrize('raw,cap', [('abc', 64), ('1.5', 64), ('', 64), (' ', 64), ('0', 1), ('-3', 1), ('10', 10)])
def test_a_key_cap_that_is_no_whole_number_does_not_stop_the_start(tmp_path, raw, cap):
    """The cap is read when dbcrypto is imported: a value int() does not take raised there,
    and PegaProx did not start. It falls back to 64 now, and a cap below 1 is 1."""
    env = dict(os.environ, PEGAPROX_HEAVY_READ_MAX_KEYS=raw,
               PEGAPROX_CONFIG_DIR=str(tmp_path / 'config'), PEGAPROX_LOG_DIR=str(tmp_path / 'logs'))
    run = subprocess.run([sys.executable, '-c', 'from pegaprox.core import dbcrypto; print(dbcrypto._HEAVY_MAX_KEYS)'],
                         cwd=_ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    assert run.stdout.split()[-1] == str(cap)
