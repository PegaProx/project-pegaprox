"""The encrypted copy a migration writes is 0600 from the moment it exists.

SQLite creates a new file with the umask, 0644 as a rule, and the chmod that was meant to
tighten it sat after the return of _encrypt_via_sqlcipher_export, so it never ran. The
final pegaprox.db got its 0600 after the swap, but a migration that stopped at the row
count check left the candidate behind at 0644. MK
"""
import os
import sqlite3
import stat

import pytest

from pegaprox.cli import migrate_db
from pegaprox.core import dbcrypto, keystore

pytestmark = pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher',
                                reason='the encryption needs sqlcipher3')


@pytest.fixture
def plain_db(tmp_path):
    path = str(tmp_path / 'pegaprox.db')
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE t (a)')
    conn.executemany('INSERT INTO t VALUES (?)', [(i,) for i in range(5)])
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def usual_umask():
    old = os.umask(0o022)
    yield
    os.umask(old)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_the_encrypted_copy_is_0600(plain_db, tmp_path, usual_umask):
    new = str(tmp_path / 'pegaprox.db.encrypted.new')

    rows = migrate_db._encrypt_via_sqlcipher_export(plain_db, new, b'\x11' * 32)

    assert rows == 5
    assert _mode(new) == 0o600, f'the encrypted copy is {oct(_mode(new))}'


def test_a_stale_copy_from_an_earlier_run_is_replaced_by_a_0600_one(plain_db, tmp_path,
                                                                    usual_umask):
    new = str(tmp_path / 'pegaprox.db.encrypted.new')
    with open(new, 'wb') as f:
        f.write(b'left over')
    os.chmod(new, 0o644)

    migrate_db._encrypt_via_sqlcipher_export(plain_db, new, b'\x11' * 32)

    assert _mode(new) == 0o600
    assert dbcrypto.detect_db_state(new) != 'corrupt'


def test_a_failed_check_leaves_the_copy_behind_at_0600(plain_db, usual_umask, monkeypatch,
                                                       capsys):
    """The CLI keeps the candidate for the operator to look at when the counts differ."""
    mk = keystore._from_env_value('ab' * 32, source='env')
    monkeypatch.setattr(keystore, 'load_master_key', lambda: mk)

    def mismatch(plain, enc):
        raise RuntimeError("row count mismatch on table 't': plain=5 encrypted=4")
    monkeypatch.setattr(migrate_db, '_verify_row_counts', mismatch)

    assert migrate_db.main(['--db', plain_db, '--yes']) == 5

    new = plain_db + '.encrypted.new'
    assert os.path.exists(new)
    assert _mode(new) == 0o600, f'the copy left for the operator is {oct(_mode(new))}'
    assert 'Inspect the encrypted candidate' in capsys.readouterr().out
