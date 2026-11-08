"""Re-migration must never empty the users table it cannot refill.

_migrate_from_legacy decides it needs to re-migrate users when the first local
row has an empty password_salt (or the column check errors), then runs
DELETE FROM users and calls _migrate_users(). That call writes nothing when the
legacy encrypted user file is gone or no longer decrypts — which is the state of
every install past the migration era. So one bad row emptied the whole table,
admins included, with nothing to restore from, and the next request landed in
the first-run setup wizard: anyone reaching the URL creates the administrator.

This runs from PegaProxDB.__init__, so it is a start-up path. MK
"""
import pytest

import pegaprox.core.db as dbmod


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """A throwaway DB with the module globals pointed at it and the singleton dropped.

    USERS_FILE_ENCRYPTED is repointed too — otherwise these tests read whatever legacy
    file happens to sit in the developer's real config dir."""
    saved = (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
             dbmod._db, dbmod.PegaProxDB._instance)
    dbmod.CONFIG_DIR = str(tmp_path)
    dbmod.DATABASE_FILE = str(tmp_path / 'pegaprox.db')
    dbmod.KEY_FILE = str(tmp_path / '.pegaprox.key')
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    monkeypatch.setattr(dbmod, 'USERS_FILE_ENCRYPTED', str(tmp_path / 'users.enc'))
    try:
        yield dbmod.PegaProxDB()
    finally:
        (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
         dbmod._db, dbmod.PegaProxDB._instance) = saved


def _add_user(db, username, salt):
    db.conn.execute(
        "INSERT OR REPLACE INTO users (username, password_salt, password_hash, role, "
        "auth_source) VALUES (?, ?, ?, ?, ?)", (username, salt, 'hash', 'admin', 'local'))
    db.conn.commit()


def _usernames(db):
    cur = db.conn.cursor()
    cur.execute("SELECT username FROM users")
    return sorted(r[0] for r in cur.fetchall())


def test_saltless_row_does_not_wipe_the_accounts(fresh):
    """No legacy file on disk — so there is nothing to restore and the accounts must stay."""
    _add_user(fresh, 'admin', '')            # the row that triggers re-migration
    _add_user(fresh, 'operator', 'realsalt')

    fresh._migrate_from_legacy()

    assert _usernames(fresh) == ['admin', 'operator']


def test_forced_remigration_without_a_legacy_file_keeps_the_accounts(fresh):
    _add_user(fresh, 'admin', 'realsalt')
    fresh._force_remigrate_users = True

    fresh._migrate_from_legacy()

    assert _usernames(fresh) == ['admin']


def test_remigration_still_replaces_the_rows_when_there_is_something_to_restore(fresh, monkeypatch):
    """The behaviour we must not lose: with a readable legacy file the stale rows go."""
    _add_user(fresh, 'stale', '')
    legacy = {'restored': {'password_salt': 's', 'password_hash': 'h', 'role': 'admin'}}
    monkeypatch.setattr(fresh, '_read_legacy_users', lambda: legacy, raising=False)

    def _fake_migrate():
        _add_user(fresh, 'restored', 's')
        return True
    monkeypatch.setattr(fresh, '_migrate_users', _fake_migrate)

    fresh._migrate_from_legacy()

    assert _usernames(fresh) == ['restored']


def test_read_legacy_users_returns_none_when_the_file_is_absent(fresh):
    assert fresh._read_legacy_users() is None
