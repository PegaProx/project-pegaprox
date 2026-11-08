"""users.enc is retired once the database holds the accounts (#1053).

The pre-SQLite user file was never retired after the import, and two paths read it
again long after it had gone stale:

  * the salt-repair re-migration, which fires when the first local row has an empty
    password_salt (a restore without secrets leaves exactly that) and replaces the
    whole users table with the file: old passwords, old roles, deleted accounts back
  * load_users(), which fell back to the file whenever the database raised

Now the file is moved aside (users.enc.migrated) at the first start that finds the
accounts in the database, or right after it was imported, and load_users() has no
fallback: an unreadable store signs nobody in.

NS Oct 2026
"""
import json
import os

import pytest

import pegaprox.core.db as dbmod
import pegaprox.utils.auth as authmod


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """Throwaway DB with the module globals - including the legacy file - repointed."""
    saved = (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
             dbmod._db, dbmod.PegaProxDB._instance)
    dbmod.CONFIG_DIR = str(tmp_path)
    dbmod.DATABASE_FILE = str(tmp_path / 'pegaprox.db')
    dbmod.KEY_FILE = str(tmp_path / '.pegaprox.key')
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    monkeypatch.setattr(dbmod, 'USERS_FILE_ENCRYPTED', str(tmp_path / 'users.enc'))
    import pegaprox.core.config as cfgmod
    monkeypatch.setattr(cfgmod, 'CONFIG_DIR', str(tmp_path), raising=False)
    monkeypatch.setattr(cfgmod, 'KEY_FILE', str(tmp_path / '.pegaprox.key'), raising=False)
    try:
        yield dbmod.PegaProxDB()
    finally:
        (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
         dbmod._db, dbmod.PegaProxDB._instance) = saved


LEGACY = {'pegaprox': {'password_salt': 'argon2', 'password_hash': 'LEGACY-DEFAULT', 'role': 'admin'},
          'fired': {'password_salt': 'argon2', 'password_hash': 'h', 'role': 'admin'}}


def _write_legacy(users=LEGACY):
    from pegaprox.core.config import get_fernet
    with open(dbmod.USERS_FILE_ENCRYPTED, 'wb') as f:
        f.write(get_fernet().encrypt(json.dumps(users).encode()))


def _hash(db, username):
    r = db.conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    return None if r is None else r[0]


def _strip_salt(db, username):
    # what restoring a backup made without secrets leaves behind
    db.conn.execute("UPDATE users SET password_salt = '', password_hash = '' WHERE username = ?",
                    (username,))
    db.conn.commit()


def test_a_saltless_row_no_longer_brings_the_old_accounts_back(fresh):
    """An install migrated long ago: the live table moved on (rotated password, an account
    deleted), the legacy file did not."""
    _write_legacy()
    fresh.save_user('pegaprox', {'password_salt': 'argon2', 'password_hash': 'ROTATED',
                                 'role': 'admin', 'enabled': True})
    fresh.save_user('ops', {'password_salt': 'argon2', 'password_hash': 'OPS',
                            'role': 'user', 'enabled': True})
    fresh._migrate_from_legacy()       # the first start with the database holding them

    _strip_salt(fresh, 'pegaprox')
    fresh._migrate_from_legacy()       # the next start

    assert _hash(fresh, 'ops') == 'OPS', 'the live accounts were replaced by the legacy file'
    assert _hash(fresh, 'fired') is None, 'an account the legacy file still lists came back'
    assert _hash(fresh, 'pegaprox') != 'LEGACY-DEFAULT'


def test_the_file_is_moved_aside_not_deleted(fresh):
    _write_legacy()
    fresh.save_user('ops', {'password_salt': 'argon2', 'password_hash': 'OPS',
                            'role': 'user', 'enabled': True})

    fresh._migrate_from_legacy()

    assert not os.path.exists(dbmod.USERS_FILE_ENCRYPTED)
    assert os.path.exists(dbmod.USERS_FILE_ENCRYPTED + '.migrated')


def test_a_genuine_first_import_still_happens_and_then_retires_the_file(fresh):
    """The mirror: on a real first migration the file is the source."""
    _write_legacy()

    fresh._migrate_from_legacy()

    assert _hash(fresh, 'pegaprox') == 'LEGACY-DEFAULT'
    assert not os.path.exists(dbmod.USERS_FILE_ENCRYPTED)


def test_the_salt_column_repair_still_restores_from_the_file_once(fresh):
    """The case the re-migration exists for: a database from before password_salt."""
    _write_legacy()
    fresh.save_user('pegaprox', {'password_salt': '', 'password_hash': 'x',
                                 'role': 'admin', 'enabled': True})
    fresh._force_remigrate_users = True

    fresh._migrate_from_legacy()

    assert _hash(fresh, 'pegaprox') == 'LEGACY-DEFAULT'
    assert not os.path.exists(dbmod.USERS_FILE_ENCRYPTED)


def test_load_users_does_not_fall_back_to_the_legacy_file(fresh, monkeypatch):
    _write_legacy()
    monkeypatch.setattr(authmod, 'USERS_FILE_ENCRYPTED', dbmod.USERS_FILE_ENCRYPTED, raising=False)

    def broken():
        raise RuntimeError('file is not a database')
    monkeypatch.setattr(authmod, 'get_db', broken)

    assert authmod.load_users() == {}, 'a broken database signed people in from users.enc'
