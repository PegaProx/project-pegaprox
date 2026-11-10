"""The key files the database depends on, and the plain copy the encryption keeps, are on
disk by content and by name before anything depends on them.

A file written without an fsync can come back empty after a power cut in the writeback
window, and a new file's name can be gone with it. A first start wrote the master key and
the field key that way and sealed the database with them right after, and the start after
the power cut refused the empty key. The plain copy the encryption keeps before the swap,
the one copy that opens without the key, was not synced either, nor the name of the copy of
the old key a rotation keeps before it writes over the key file. MK Nov 2026
"""
import builtins
import os
import sqlite3

import pytest

from pegaprox.core import dbcrypto, keystore


class _Syncs:
    """Each fsync in order, by the real path of the file or directory it was for, and the
    marks a test sets where something depends on what came before."""

    def __init__(self, monkeypatch):
        self.events = []
        real = os.fsync

        def fsync(fd):
            self.events.append(os.path.realpath(os.readlink(f'/proc/self/fd/{fd}')))
            return real(fd)
        monkeypatch.setattr(os, 'fsync', fsync)

    def before(self, mark):
        return self.events[:self.events.index(mark)]


def _real(path):
    return os.path.realpath(str(path))


def test_a_master_key_made_on_a_first_start_is_on_disk_by_content_and_name(tmp_path, monkeypatch):
    path = tmp_path / 'config' / '.pegaprox.key'
    syncs = _Syncs(monkeypatch)
    mk = keystore._generate_at(path, source='generated:CONFIG_DIR', is_legacy=True)
    assert len(mk.key_raw) == 32 and path.read_bytes() == mk.key_b64
    assert syncs.events == [_real(path), _real(path.parent)]


def test_the_keys_the_database_makes_on_a_first_start_are_on_disk_by_content_and_name(db, monkeypatch):
    """The field key, and the Fernet key that is also the legacy master key of the SQLCipher
    backend."""
    import pegaprox.core.db as dbmod
    files = [os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'), dbmod.KEY_FILE]
    for f in files:
        os.remove(f)
    syncs = _Syncs(monkeypatch)
    db._init_encryption()
    for f in files:
        assert os.path.getsize(f) > 0
        # the file, then the directory that holds its name
        assert _real(f) in syncs.events
        assert _real(dbmod.CONFIG_DIR) in syncs.events[syncs.events.index(_real(f)) + 1:]


@pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher', reason='the encryption needs sqlcipher3')
def test_the_plain_copy_is_on_disk_before_the_encrypted_file_takes_its_place(tmp_path, monkeypatch):
    path = str(tmp_path / 'pegaprox.db')
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE t (a)')
    conn.execute("INSERT INTO t VALUES ('a row')")
    conn.commit()
    conn.close()
    mk = keystore._from_env_value('ab' * 32, source='env')
    monkeypatch.setattr(keystore, 'load_master_key', lambda: mk)
    syncs = _Syncs(monkeypatch)
    real = os.replace

    def replace(src, dst, *a, **kw):
        if str(dst) == path:
            syncs.events.append('swap')
        return real(src, dst, *a, **kw)
    monkeypatch.setattr(os, 'replace', replace)
    res = dbcrypto._run_inline_migration(path)
    assert res['action'] == 'migrated' and dbcrypto.detect_db_state(path) == 'encrypted'
    copy = res['backup_path']
    assert sqlite3.connect(copy).execute('SELECT a FROM t').fetchall() == [('a row',)]
    assert _real(copy) in syncs.before('swap')
    assert _real(tmp_path) in syncs.before('swap')


def test_a_rotation_has_the_copy_of_the_old_key_on_disk_before_it_writes_over_the_key(db, monkeypatch):
    """A power cut in that write leaves a short key file, and the start refuses it and
    points at the copy: by then the copy has to be there by its name, too."""
    import pegaprox.core.db as dbmod
    key = _real(os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'))
    syncs = _Syncs(monkeypatch)

    def opening(file, mode='r', *a, **kw):
        if 'w' in mode and _real(file) == key:
            syncs.events.append('key written over')
        return builtins.open(file, mode, *a, **kw)
    monkeypatch.setattr(dbmod, 'open', opening, raising=False)
    stats = db.rotate_encryption_key()
    assert stats['success'] is True and not stats['errors'], stats
    before = syncs.before('key written over')
    assert _real(stats['key_backup']) in before
    assert _real(dbmod.CONFIG_DIR) in before
