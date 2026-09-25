"""API tokens are keyed by username, and a username is free again the moment the
account row goes.

delete_user removed the account first and revoked its pgx_ bearer tokens
afterwards, inside a try/except that only logged a warning. So a database error
on the revocation left the tokens live and valid for a name that no longer
existed — and since tokens match on the name, recreating it handed the new
account's identity to whoever still held the old bearer. The response said
success either way.

The order is the fix: revoke first, and let a failure fail the deletion. The
failure mode that leaves behind is an account whose tokens are revoked, which is
the harmless direction — the previous one left credentials without an owner.

Binding tokens to an immutable account id instead of the name is the better
answer and is a schema change; it is written up for the next design pass rather
than smuggled in here. Aikido ai_pentest 700487639. MK
"""
import time

import pytest

USERS = '/api/users'


def _add_token(db, username, token_hash='hash-abc'):
    db.conn.execute(
        "INSERT INTO api_tokens (token_hash, token_prefix, username, name, created_at, revoked) "
        "VALUES (?, ?, ?, ?, ?, 0)",
        (token_hash, 'pgx_abc', username, 'ci-runner', time.strftime('%Y-%m-%dT%H:%M:%S')))
    db.conn.commit()


def _live_tokens(db, username):
    return db.conn.execute(
        "SELECT COUNT(*) FROM api_tokens WHERE username = ? AND revoked = 0",
        (username,)).fetchone()[0]


@pytest.fixture
def boss(api, seed):
    return api.as_user(seed.user('boss', role='admin'))


def test_a_normal_deletion_revokes_the_tokens(boss, seed):
    seed.user('doomed', role='user')
    _add_token(seed.db, 'doomed')
    assert _live_tokens(seed.db, 'doomed') == 1

    r = boss.delete(f'{USERS}/doomed')
    assert r.status_code == 200, r.data
    assert _live_tokens(seed.db, 'doomed') == 0


def test_a_failed_revocation_does_not_report_a_successful_deletion(boss, seed, monkeypatch):
    """The property. Whatever happens, the caller must never be told the account is
    gone while a usable bearer for that name is still in the table."""
    seed.user('doomed', role='user')
    _add_token(seed.db, 'doomed')

    _real = seed.db.execute

    def _fails_on_tokens(sql, *args, **kwargs):
        if 'api_tokens' in str(sql):
            raise RuntimeError('database is having a moment')
        return _real(sql, *args, **kwargs)

    monkeypatch.setattr(seed.db, 'execute', _fails_on_tokens)

    r = boss.delete(f'{USERS}/doomed')

    still_live = _live_tokens(seed.db, 'doomed')
    gone = seed.db.get_user('doomed') is None
    assert not (gone and still_live), (
        'the account was deleted with a live token left behind for its name')
    assert r.status_code != 200, f'and it was reported as done: {r.data}'


def test_the_name_cannot_be_recreated_into_a_live_token(boss, seed, monkeypatch):
    """The consequence spelled out: recreate the username after a failed delete and
    the old bearer must not authenticate as the new account."""
    seed.user('doomed', role='user')
    _add_token(seed.db, 'doomed')

    _real = seed.db.execute
    monkeypatch.setattr(seed.db, 'execute', lambda sql, *a, **k: (
        (_ for _ in ()).throw(RuntimeError('boom')) if 'api_tokens' in str(sql)
        else _real(sql, *a, **k)))

    boss.delete(f'{USERS}/doomed')
    monkeypatch.undo()

    if seed.db.get_user('doomed') is None:
        # the account really did go — then nothing may still be valid for that name
        assert _live_tokens(seed.db, 'doomed') == 0, \
            'a live token is waiting for whoever takes this username next'
