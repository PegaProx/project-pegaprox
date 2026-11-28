"""The database encryption at the first start of a version: what it does when it cannot run,
when it is opted out of, and what it keeps.

1.5.0 put sqlcipher3 on more installs, and with it the one-time conversion of a plain
database. Five things went wrong around it:

- the opt-out PEGAPROX_DISABLE_AUTO_ENCRYPT skipped the conversion, but every connection was
  still keyed, and a keyed connection does not read a plain file: PegaProx could not open its
  own database
- a conversion that failed (a full disk) was only logged, the start went on keying the plain
  file with the same result, the message advised a `migrate-db --reencrypt` that does not
  exist, and every restart left one more plain copy behind
- on Windows the conversion imported fcntl, and os.fsync on a read-only handle fails there
- the plain copy kept the old mtime of the database, so a database last written more than an
  hour before lost its copy at the next start, and the log said to delete it by hand
- a key file with loose permissions on an encrypted database read as "the current master key
  does not unlock it"

And around those: the conversion and --migrate-db took the plain file while another process
(a running PegaProx, a sqlite3 shell) had it open, and the swap left that process's plain -wal
beside the encrypted file; a copy left in the same second stopped the next conversion; the
opt-out kept old copies for good; and a plain file that did not open here (no permission, a
full disk) was called encrypted with another key, or damaged.

The conversions here are real SQLCipher ones in temp directories, with the key store pointed
at the test's own places. MK Nov 2026
"""
import base64
import errno
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

from pegaprox.cli import migrate_db
from pegaprox.core import dbcrypto, keystore

# the Windows tests read the access mode of a handle with it, as Windows itself would
_real_fcntl = pytest.importorskip('fcntl')
ROOT = Path(__file__).resolve().parent.parent
needs_sqlcipher = pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher', reason='needs sqlcipher3')
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()
OTHER_KEY = base64.urlsafe_b64encode(bytes(range(100, 132))).decode()


class Install:
    """A config directory and a key store that looks only at the test's own places."""

    def __init__(self, tmp_path, monkeypatch):
        self.mp = monkeypatch
        self.cfg = tmp_path / 'config'
        self.cfg.mkdir()
        self.db = str(self.cfg / 'pegaprox.db')
        for var in ('PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY', 'PEGAPROX_DISABLE_AUTO_ENCRYPT',
                    'PEGAPROX_PLAIN_BACKUP_RETENTION_S'):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv('PEGAPROX_DB_KEY', KEY)
        monkeypatch.setenv('HOME', str(tmp_path / 'home'))
        monkeypatch.setattr(keystore, 'SYSTEM_KEY_PATH', tmp_path / 'etc' / 'secret.key')
        monkeypatch.setattr(keystore, '_legacy_key_path', lambda: self.cfg / '.pegaprox.key')
        self.again()

    def again(self):
        """The next start: another process, nothing this one decided is left."""
        self.mp.setattr(keystore, '_CACHED', None)
        self.mp.setattr(dbcrypto, '_AUTO_MIG_DONE', set())
        self.mp.setattr(dbcrypto, '_CONVERSION_FAILED', set(), raising=False)
        self.mp.setattr(dbcrypto, '_OPENS_PLAIN', {}, raising=False)

    def ensure(self):
        return dbcrypto.ensure_db_encrypted(self.db)

    def leftovers(self):
        return sorted(f for f in os.listdir(self.cfg) if '.plain.bak.' in f or '.encrypted.new' in f)

    def copies(self):
        return sorted(str(self.cfg / f) for f in os.listdir(self.cfg) if '.plain.bak.' in f)

    def rows(self):
        conn = dbcrypto.connect(self.db)
        try:
            return conn.execute('SELECT a FROM t ORDER BY a').fetchall()
        finally:
            conn.close()


@pytest.fixture
def inst(tmp_path, monkeypatch):
    return Install(tmp_path, monkeypatch)


@pytest.fixture
def log(caplog):
    caplog.set_level(logging.DEBUG, logger='pegaprox.core.dbcrypto')
    return caplog


def plain_db(path, rows=50, blob=0):
    c = sqlite3.connect(path)
    c.execute('PRAGMA journal_mode = WAL')
    c.execute('CREATE TABLE t (a INTEGER, b BLOB)')
    c.executemany('INSERT INTO t VALUES (?, ?)', [(i, os.urandom(blob)) for i in range(rows)])
    c.commit()
    c.close()


def errors(caplog):
    # what the code under test said: a full run once caught the "Error loading schedules" line a
    # scheduler of an earlier test's app logged on the root logger meanwhile, as the first error
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.ERROR and r.name.startswith(('pegaprox.core.dbcrypto', 'pegaprox.cli.migrate_db'))]


# --- a plain database is converted, and stays readable ------------------------------------------

@needs_sqlcipher
def test_a_plain_database_is_encrypted_and_reads_as_before(inst):
    plain_db(inst.db)
    r = inst.ensure()
    assert r['action'] == 'migrated' and r['rows_copied'] == 50
    assert dbcrypto.file_state(inst.db) == 'encrypted'
    assert inst.rows() == [(i,) for i in range(50)]
    # the next start finds it done
    inst.again()
    assert inst.ensure()['action'] == 'noop'
    assert inst.rows() == [(i,) for i in range(50)]


# --- the opt-out ------------------------------------------------------------------------------------

@needs_sqlcipher
def test_the_opt_out_keeps_a_plain_database_plain_and_open_across_starts(inst, monkeypatch, log):
    plain_db(inst.db)
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    for n in range(3):
        inst.again()
        assert inst.ensure() == {'action': 'opt-out'}
        conn = dbcrypto.connect(inst.db)
        conn.execute('INSERT INTO t (a) VALUES (?)', (1000 + n,))
        conn.commit()
        conn.close()
        assert dbcrypto.file_state(inst.db) == 'plain'
        assert inst.leftovers() == []
    assert inst.rows()[-3:] == [(1000,), (1001,), (1002,)]
    # plain SQLite indeed: the interpreter's own sqlite3 reads it
    assert sqlite3.connect(inst.db).execute('SELECT count(*) FROM t').fetchone() == (53,)
    assert 'stays plain SQLite and opens without the key' in log.text
    assert errors(log) == []


@needs_sqlcipher
def test_without_the_opt_out_a_plain_file_is_keyed_and_the_error_names_real_commands(inst):
    """The counterpart of the test above: connect() does key a plain file, so the opt-out
    test passes because of the opt-out."""
    plain_db(inst.db)
    with pytest.raises(RuntimeError, match='could not unlock') as e:
        dbcrypto.connect(inst.db)
    msg = str(e.value)
    assert 'still plain SQLite' in msg and 'pegaprox_multi_cluster.py --migrate-db' in msg
    assert 'reencrypt' not in msg


@needs_sqlcipher
def test_with_the_opt_out_an_encrypted_database_still_opens_with_the_key(inst, monkeypatch):
    plain_db(inst.db)
    assert inst.ensure()['action'] == 'migrated'
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    inst.again()
    assert inst.ensure() == {'action': 'opt-out'}
    assert inst.rows() == [(i,) for i in range(50)]
    assert dbcrypto.file_state(inst.db) == 'encrypted'


@needs_sqlcipher
def test_with_the_opt_out_a_wrong_key_still_refuses_the_start(inst, monkeypatch):
    plain_db(inst.db)
    assert inst.ensure()['action'] == 'migrated'
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    monkeypatch.setenv('PEGAPROX_DB_KEY', OTHER_KEY)
    inst.again()
    with pytest.raises(RuntimeError, match='does not unlock it'):
        inst.ensure()


@needs_sqlcipher
def test_with_the_opt_out_a_new_database_is_still_created_encrypted(inst, monkeypatch):
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    assert inst.ensure() == {'action': 'opt-out'}
    conn = dbcrypto.connect(inst.db)
    conn.execute('CREATE TABLE t (a INTEGER)')
    conn.commit()
    conn.close()
    assert dbcrypto.file_state(inst.db) == 'encrypted'


@needs_sqlcipher
def test_the_state_of_a_file_is_read_once_not_at_every_connection(inst, monkeypatch):
    plain_db(inst.db)
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    inst.ensure()
    reads = []
    real = dbcrypto.file_state
    monkeypatch.setattr(dbcrypto, 'file_state', lambda p: reads.append(p) or real(p))
    for _ in range(5):
        dbcrypto.connect(inst.db).close()
    assert reads == [inst.db]
    # without the opt-out an encrypted database is keyed without a look at the file
    monkeypatch.delenv('PEGAPROX_DISABLE_AUTO_ENCRYPT')
    inst.again()
    assert inst.ensure()['action'] == 'migrated'
    reads.clear()
    for _ in range(5):
        dbcrypto.connect(inst.db).close()
    assert reads == []


# --- a conversion that fails ------------------------------------------------------------------------

class _FillsUp:
    """A sqlcipher3 connection to the encrypted copy on which the export runs out of room:
    max_page_count makes SQLite answer SQLITE_FULL as on a full disk."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, *args):
        if 'sqlcipher_export' in sql:
            self._conn.execute('PRAGMA max_page_count = 2')
        return self._conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _little_free(monkeypatch, free, when=lambda: True):
    """shutil.disk_usage reports `free` bytes free while when() is True, as on a full disk."""
    real = shutil.disk_usage

    def disk_usage(path):
        if not when():
            return real(path)
        u = real(path)
        return type(u)(u.total, u.total - free, free)
    monkeypatch.setattr(shutil, 'disk_usage', disk_usage)


def _disk_full_at(where, inst, monkeypatch):
    """Make the disk run full at one step of the conversion while full['on'] is True."""
    full = {'on': True}
    # and it reports what a full disk reports
    _little_free(monkeypatch, 1024 ** 2, lambda: full['on'])
    if where == 'copy':
        real = shutil.copyfile

        def copyfile(src, dst, *a, **kw):
            if not full['on']:
                return real(src, dst, *a, **kw)
            with open(src, 'rb') as s, open(dst, 'wb') as d:
                d.write(s.read(65536))
            raise OSError(errno.ENOSPC, 'No space left on device')
        monkeypatch.setattr(shutil, 'copyfile', copyfile)
    elif where == 'export':
        import sqlcipher3
        real = sqlcipher3.connect

        def connect(path, *a, **kw):
            conn = real(path, *a, **kw)
            return _FillsUp(conn) if full['on'] and str(path) == inst.db + '.encrypted.new' else conn
        monkeypatch.setattr(sqlcipher3, 'connect', connect)
    else:
        real = os.replace

        def replace(src, dst, *a, **kw):
            if full['on'] and str(dst) == inst.db:
                raise OSError(errno.ENOSPC, 'No space left on device')
            return real(src, dst, *a, **kw)
        monkeypatch.setattr(os, 'replace', replace)
    return full


@needs_sqlcipher
@pytest.mark.parametrize('where', ['copy', 'export', 'swap'])
def test_a_full_disk_leaves_the_plain_database_open_and_nothing_behind(inst, monkeypatch, log, where):
    # about 3 MB, so the space the message asks for is a figure one can check
    plain_db(inst.db, rows=300, blob=10000)
    size = os.path.getsize(inst.db) + (os.path.getsize(inst.db + '-wal') if os.path.exists(inst.db + '-wal') else 0)
    full = _disk_full_at(where, inst, monkeypatch)
    # two starts that systemd makes one after the other
    for _ in range(2):
        inst.again()
        log.clear()
        r = inst.ensure()
        assert r['action'] == 'failed'
        assert dbcrypto.file_state(inst.db) == 'plain'
        assert inst.leftovers() == []
        # this start runs on it, plain
        assert inst.rows() == [(i,) for i in range(300)]
        said = errors(log)
        assert len(said) == 1, said
        assert f'not enough free space in {inst.cfg}' in said[0]
        # two copies, the larger encrypted one, and room for a journal and a -shm
        need = 2 * size + size // 32 + 64 * 1024
        assert f'needs about {need / 1024 ** 2:.1f} MB free, 1.0 MB are free now' in said[0]
        assert 'Nothing was changed' in said[0] and 'the next start tries again' in said[0]
        assert 'could not unlock' not in log.text and 'reencrypt' not in log.text
    # room again: the next start encrypts it
    full['on'] = False
    inst.again()
    r = inst.ensure()
    assert r['action'] == 'migrated'
    assert dbcrypto.file_state(inst.db) == 'encrypted'
    assert inst.rows() == [(i,) for i in range(300)]
    assert inst.copies() == [r['backup_path']]


@needs_sqlcipher
def test_any_other_failure_of_the_conversion_says_its_cause_and_starts_plain(inst, monkeypatch, log):
    plain_db(inst.db)

    def mismatch(plain, enc):
        raise RuntimeError("row count mismatch on table 't': plain=50 encrypted=49")
    monkeypatch.setattr(migrate_db, '_verify_row_counts', mismatch)
    r = inst.ensure()
    assert r['action'] == 'failed'
    said = errors(log)
    assert len(said) == 1
    assert "RuntimeError: row count mismatch on table 't': plain=50 encrypted=49" in said[0]
    assert 'free space' not in said[0]
    assert inst.leftovers() == []
    assert inst.rows() == [(i,) for i in range(50)]


@needs_sqlcipher
def test_what_a_failed_attempt_cannot_remove_is_named(inst, monkeypatch, log):
    plain_db(inst.db)
    # a directory where the encrypted copy goes: neither the export nor the clean-up gets it away
    os.mkdir(inst.db + '.encrypted.new')
    r = inst.ensure()
    assert r['action'] == 'failed'
    assert errors(log)[0].endswith(f'could not remove {inst.db}.encrypted.new: delete it by hand.')
    # its own plain copy went
    assert inst.copies() == []


@needs_sqlcipher
def test_a_key_the_key_store_refuses_still_stops_the_start_on_a_plain_database(inst, tmp_path, monkeypatch):
    """A deliberate refusal, not a failed conversion: the start stops with the key store's reason."""
    plain_db(inst.db)
    key = tmp_path / 'secret.key'
    key.write_bytes(KEY.encode())
    key.chmod(0o644)
    monkeypatch.delenv('PEGAPROX_DB_KEY')
    monkeypatch.setenv('PEGAPROX_KEY_FILE', str(key))
    inst.again()
    with pytest.raises(RuntimeError, match='loose permissions'):
        inst.ensure()
    assert dbcrypto.file_state(inst.db) == 'plain' and inst.leftovers() == []


# --- the start lines of main(), run from the source in a child --------------------------------------

_START = r'''
import ast, errno, logging, os, shutil, sys
root = sys.argv[1]
sys.path.insert(0, root)
logging.basicConfig(level=logging.WARNING, format='%(levelname)s %(message)s')
real = shutil.copyfile
def copyfile(src, dst, *a, **kw):
    # the disk is full while pegaprox.db is copied; syslog.db comes after it
    if os.path.basename(src) == 'pegaprox.db':
        raise OSError(errno.ENOSPC, 'No space left on device')
    return real(src, dst, *a, **kw)
shutil.copyfile = copyfile
src = os.path.join(root, 'pegaprox', 'app.py')
main = next(n for n in ast.parse(open(src, encoding='utf-8').read()).body
            if isinstance(n, ast.FunctionDef) and n.name == 'main')
block = min((n for n in ast.walk(main) if isinstance(n, ast.Try) and any(
    getattr(c.func, 'attr', None) == 'ensure_db_encrypted' for c in ast.walk(n) if isinstance(c, ast.Call))),
    key=lambda n: n.end_lineno - n.lineno)
exec(compile(ast.Module(body=[block], type_ignores=[]), src, 'exec'),
     {'__name__': 'start', 'os': os, 'sys': sys, 'logging': logging})
from pegaprox.core import dbcrypto
conn = dbcrypto.connect(os.path.join('config', 'pegaprox.db'))
print('ROWS', conn.execute('SELECT count(*) FROM t').fetchone()[0])
print('SYSLOG', dbcrypto.file_state(os.path.join('config', 'syslog.db')))
'''


def _child_env(tmp_path, **extra):
    """The environment of a child that is a PegaProx on tmp_path/config: nothing of the
    PEGAPROX_ settings the test run itself has (a PEGAPROX_CONFIG_DIR sent the child to that
    directory, where it converted a database with the test's key)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PEGAPROX_', 'CREDENTIALS_'))}
    env.update(HOME=str(tmp_path / 'home'), PEGAPROX_DB_KEY=KEY,
               PEGAPROX_CONFIG_DIR=str(tmp_path / 'config'), **extra)
    return env


def test_a_child_gets_its_own_config_directory_whatever_the_run_has(tmp_path, monkeypatch):
    monkeypatch.setenv('PEGAPROX_CONFIG_DIR', str(tmp_path / 'elsewhere'))
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    monkeypatch.setenv('CREDENTIALS_DIRECTORY', str(tmp_path / 'creds'))
    env = _child_env(tmp_path)
    assert env['PEGAPROX_CONFIG_DIR'] == str(tmp_path / 'config')
    assert 'PEGAPROX_DISABLE_AUTO_ENCRYPT' not in env and 'CREDENTIALS_DIRECTORY' not in env


@needs_sqlcipher
def test_the_start_goes_on_plain_and_says_it_once(tmp_path):
    cfg = tmp_path / 'config'
    cfg.mkdir()
    plain_db(str(cfg / 'pegaprox.db'))
    plain_db(str(cfg / 'syslog.db'))
    r = subprocess.run([sys.executable, '-I', '-B', '-c', _START, str(ROOT)], cwd=tmp_path,
                       env=_child_env(tmp_path), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert '[FATAL]' not in r.stdout and 'auto-encrypt check failed' not in r.stderr
    assert ('pegaprox.db could not be encrypted and stays plain for now (see the [DBCRYPTO] error '
            'in the log), the next start tries again') in r.stdout
    errs = [ln for ln in r.stderr.splitlines() if ln.startswith('ERROR')]
    assert len(errs) == 1 and 'could not encrypt' in errs[0] and 'not enough free space' in errs[0]
    # the database opened plain, and the loop went on to syslog.db
    assert 'ROWS 50' in r.stdout
    assert 'SYSLOG encrypted' in r.stdout and 'syslog.db auto-encrypted' in r.stdout
    assert not [f for f in os.listdir(cfg) if f.startswith('pegaprox.db.plain.bak.')]


# --- the plain copy ---------------------------------------------------------------------------------

@needs_sqlcipher
def test_the_plain_copy_is_dated_by_the_conversion_and_stays_its_hour(inst, log):
    plain_db(inst.db)
    two_hours_ago = time.time() - 7200
    os.utime(inst.db, (two_hours_ago, two_hours_ago))
    r = inst.ensure()
    copy = r['backup_path']
    assert abs(os.path.getmtime(copy) - time.time()) < 60
    assert sqlite3.connect(copy).execute('SELECT count(*) FROM t').fetchone() == (50,)
    done = [m.getMessage() for m in log.records if 'auto-encrypt complete' in m.getMessage()]
    assert len(done) == 1
    assert (f'The plain copy {copy} is kept for about an hour, then the first start of PegaProx '
            'after that shreds it') in done[0]
    assert 'copy it somewhere safe if you want to keep it' in done[0]
    assert 'delete manually' not in log.text
    # a restart right after it (the second restart of a package upgrade) leaves it
    inst.again()
    assert inst.ensure()['action'] == 'noop'
    assert os.path.exists(copy)
    # counterproof: dated as copy2 dated it, the same start shreds it
    os.utime(copy, (two_hours_ago, two_hours_ago))
    inst.again()
    inst.ensure()
    assert not os.path.exists(copy)


@needs_sqlcipher
def test_the_note_follows_the_retention_setting(inst, monkeypatch):
    monkeypatch.setenv('PEGAPROX_PLAIN_BACKUP_RETENTION_S', '0')
    assert dbcrypto.plain_copy_note('/x.bak') == (
        'The plain copy /x.bak is shredded at the next start of PegaProx. It holds every stored '
        'credential in the clear: copy it somewhere safe if you want to keep it.')
    monkeypatch.setenv('PEGAPROX_PLAIN_BACKUP_RETENTION_S', '7200')
    assert 'is kept for about 2 hours, then' in dbcrypto.plain_copy_note('/x.bak')
    monkeypatch.setenv('PEGAPROX_PLAIN_BACKUP_RETENTION_S', '900')
    assert 'is kept for about 15 minutes, then' in dbcrypto.plain_copy_note('/x.bak')


@needs_sqlcipher
def test_the_cli_dates_its_copy_now_and_says_what_happens_to_it(inst, capsys):
    plain_db(inst.db)
    old = time.time() - 7200
    os.utime(inst.db, (old, old))
    assert migrate_db.main(['--db', inst.db, '--yes']) == 0
    copy, = inst.copies()
    assert abs(os.path.getmtime(copy) - time.time()) < 60
    assert os.stat(copy).st_mode & 0o777 == 0o600
    out = capsys.readouterr().out
    assert f'The plain copy {copy} is kept for about an hour' in out
    assert 'shred -u' not in out and 'delete manually' not in out


@needs_sqlcipher
def test_a_quote_in_the_path_does_not_break_the_export(tmp_path):
    where = tmp_path / "o'brien"
    where.mkdir()
    db = str(where / 'pegaprox.db')
    plain_db(db, rows=7)
    assert migrate_db._encrypt_via_sqlcipher_export(db, db + '.new', b'\x11' * 32) == 7
    # counterproof: the statement as it was written into the text before
    import sqlcipher3
    c = sqlcipher3.connect(str(tmp_path / 'other.db'))
    c.execute(f"PRAGMA key = \"x'{'11' * 32}'\"")
    with pytest.raises(sqlcipher3.OperationalError):
        c.execute(f"ATTACH DATABASE '{db}' AS plaintext KEY ''")
    c.close()


# --- the key: right, wrong, and loose ---------------------------------------------------------------

@needs_sqlcipher
def test_an_encrypted_database_opens_with_its_key_and_refuses_another(inst, monkeypatch):
    plain_db(inst.db)
    assert inst.ensure()['action'] == 'migrated'
    inst.again()
    assert inst.ensure()['action'] == 'noop'
    assert inst.rows() == [(i,) for i in range(50)]
    monkeypatch.setenv('PEGAPROX_DB_KEY', OTHER_KEY)
    inst.again()
    with pytest.raises(RuntimeError, match='is encrypted but the current master key does not unlock it'):
        inst.ensure()


def _key_file(path, data, mode):
    path.write_bytes(data.encode())
    path.chmod(mode)
    return path


@needs_sqlcipher
def test_a_loose_key_file_on_an_encrypted_database_is_named_as_such(inst, tmp_path, monkeypatch, capsys):
    key = _key_file(tmp_path / 'secret.key', KEY, 0o600)
    monkeypatch.delenv('PEGAPROX_DB_KEY')
    monkeypatch.setenv('PEGAPROX_KEY_FILE', str(key))
    plain_db(inst.db)
    inst.again()
    assert inst.ensure()['action'] == 'migrated'
    key.chmod(0o644)
    inst.again()
    with pytest.raises(RuntimeError) as e:
        inst.ensure()
    msg = str(e.value)
    assert msg.startswith(f'[DBCRYPTO] {inst.db} is encrypted, and its master key cannot be used: ')
    assert f'key at {key} has loose permissions (644)' in msg and 'must be 0600 or 0640' in msg
    assert msg.endswith('Refusing to start.')
    assert 'does not unlock' not in msg
    # --migrate-db says the same
    inst.again()
    assert migrate_db.main(['--db', inst.db, '--dry-run']) == 6
    out = capsys.readouterr().out
    assert 'loose permissions' in out and "doesn't unlock" not in out


@needs_sqlcipher
def test_counterproof_a_wrong_key_file_with_good_permissions_is_still_the_wrong_key(inst, tmp_path, monkeypatch):
    key = _key_file(tmp_path / 'secret.key', KEY, 0o600)
    monkeypatch.delenv('PEGAPROX_DB_KEY')
    monkeypatch.setenv('PEGAPROX_KEY_FILE', str(key))
    plain_db(inst.db)
    inst.again()
    assert inst.ensure()['action'] == 'migrated'
    _key_file(key, OTHER_KEY, 0o600)
    inst.again()
    with pytest.raises(RuntimeError, match='does not unlock it') as e:
        inst.ensure()
    assert 'loose permissions' not in str(e.value)


@needs_sqlcipher
def test_a_key_file_that_cannot_be_read_is_named_too(inst, tmp_path, monkeypatch):
    key = _key_file(tmp_path / 'secret.key', KEY, 0o600)
    monkeypatch.delenv('PEGAPROX_DB_KEY')
    monkeypatch.setenv('PEGAPROX_KEY_FILE', str(key))
    plain_db(inst.db)
    inst.again()
    assert inst.ensure()['action'] == 'migrated'
    real = Path.read_bytes

    def read_bytes(self):
        if self == key:
            raise PermissionError(errno.EACCES, 'Permission denied', str(key))
        return real(self)
    monkeypatch.setattr(Path, 'read_bytes', read_bytes)
    inst.again()
    with pytest.raises(RuntimeError, match=r'master key cannot be used: \[KEYSTORE\] the master key cannot be loaded: '
                       r'\[Errno 13\] Permission denied'):
        inst.ensure()


# --- Windows ------------------------------------------------------------------------------------

class FakeMsvcrt(types.ModuleType):
    """msvcrt.locking as Windows does it: a byte range of a file, held by one handle. Holders
    are tracked by the file, so a second open of the lock file is "another process"."""
    LK_UNLCK, LK_LOCK, LK_NBLCK = 0, 1, 2

    def __init__(self):
        super().__init__('msvcrt')
        self.calls = []
        self.held = {}
        self.busy_rounds = 0
        self.on_wait = None

    def locking(self, fd, mode, nbytes):
        at = os.lseek(fd, 0, os.SEEK_CUR)
        st = os.fstat(fd)
        key = (st.st_dev, st.st_ino, at, nbytes)
        self.calls.append((mode, at, nbytes))
        holder = self.held.get(key)
        if mode == self.LK_UNLCK:
            assert holder == fd, 'unlock of a range this handle does not hold'
            del self.held[key]
            return
        if holder is not None and holder != fd:
            if mode == self.LK_NBLCK:
                raise OSError(errno.EACCES, 'Permission denied')
            if self.busy_rounds:
                self.busy_rounds -= 1
                raise OSError(errno.EDEADLOCK, 'Resource deadlock avoided')
            # the other process finishes and lets go
            if self.on_wait:
                self.on_wait()
            del self.held[key]
        self.held[key] = fd


@pytest.fixture
def windows(monkeypatch):
    """fcntl gone, msvcrt there, and os.fsync and os.open as on Windows: FlushFileBuffers
    refuses a read-only handle, and a directory does not open."""
    monkeypatch.setitem(sys.modules, 'fcntl', None)
    fake = FakeMsvcrt()
    monkeypatch.setitem(sys.modules, 'msvcrt', fake)
    monkeypatch.setattr(dbcrypto, '_WINDOWS', True)
    _windows_io(monkeypatch)
    return fake


def _windows_io(monkeypatch):
    real_fsync, real_open = os.fsync, os.open

    def fsync(fd):
        if _real_fcntl.fcntl(fd, _real_fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY:
            raise OSError(errno.EBADF, 'Bad file descriptor')
        return real_fsync(fd)

    def open_(path, flags, *a, **kw):
        if os.path.isdir(path):
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return real_open(path, flags, *a, **kw)
    monkeypatch.setattr(os, 'fsync', fsync)
    monkeypatch.setattr(os, 'open', open_)


@needs_sqlcipher
def test_windows_encrypts_with_an_msvcrt_lock(inst, windows):
    # the test is on the branch it means to be on
    with pytest.raises(ImportError):
        import fcntl  # noqa: F401
    plain_db(inst.db)
    r = inst.ensure()
    assert r['action'] == 'migrated', r
    assert windows.calls == [(windows.LK_NBLCK, 0, 1), (windows.LK_UNLCK, 0, 1)]
    assert windows.held == {}
    inst.again()
    assert inst.ensure()['action'] == 'noop'
    assert inst.rows() == [(i,) for i in range(50)]


@needs_sqlcipher
def test_windows_waits_for_another_start_that_holds_the_lock(inst, windows):
    plain_db(inst.db)
    other = os.open(inst.db + '.migration.lock', os.O_RDWR | os.O_CREAT, 0o600)
    windows.locking(other, windows.LK_NBLCK, 1)
    windows.calls.clear()
    windows.busy_rounds = 2

    def the_other_start_converts():
        # what the other start did while this one waited
        new = inst.db + '.peer.new'
        migrate_db._encrypt_via_sqlcipher_export(inst.db, new, keystore.load_master_key().key_raw)
        os.replace(new, inst.db)
    windows.on_wait = the_other_start_converts
    try:
        r = inst.ensure()
    finally:
        os.close(other)
    assert r == {'action': 'waited-for-peer', 'state_after': 'encrypted'}
    assert [c[0] for c in windows.calls] == [windows.LK_NBLCK, windows.LK_LOCK, windows.LK_LOCK,
                                             windows.LK_LOCK, windows.LK_UNLCK]
    assert inst.rows() == [(i,) for i in range(50)]


@needs_sqlcipher
def test_without_any_lock_module_the_start_goes_on_plain(inst, monkeypatch, log):
    """What 1.5.0 did on every Windows install, as a failed conversion now."""
    monkeypatch.setitem(sys.modules, 'fcntl', None)
    monkeypatch.setitem(sys.modules, 'msvcrt', None)
    plain_db(inst.db)
    r = inst.ensure()
    assert r['action'] == 'failed'
    said = errors(log)
    assert len(said) == 1 and 'ModuleNotFoundError: import of msvcrt halted' in said[0]
    assert inst.rows() == [(i,) for i in range(50)]


def test_on_windows_a_file_is_synced_through_a_handle_that_may_write(tmp_path, monkeypatch):
    path = tmp_path / 'copy'
    path.write_bytes(b'x' * 100)
    wal = tmp_path / 'pegaprox.db-wal'
    wal.write_bytes(b'w' * 100)
    _windows_io(monkeypatch)
    # counterproof: the POSIX way fails where Windows fails
    with pytest.raises(OSError) as e:
        dbcrypto.sync_file(str(path))
    assert e.value.errno == errno.EBADF
    with pytest.raises(OSError):
        dbcrypto.sync_wal(str(tmp_path / 'pegaprox.db'))
    monkeypatch.setattr(dbcrypto, '_WINDOWS', True)
    dbcrypto.sync_file(str(path))
    assert dbcrypto.sync_wal(str(tmp_path / 'pegaprox.db')) is True


# --- every command a message names exists ---------------------------------------------------------

def _known_flags():
    top = set(re.findall(r"'(--[a-z-]+)' in sys\.argv", (ROOT / 'pegaprox_multi_cluster.py').read_text()))
    sub = set(re.findall(r"add_argument\('(--[a-z-]+)'", (ROOT / 'pegaprox' / 'cli' / 'migrate_db.py').read_text()))
    return top, sub


def _unknown_commands(text):
    top, sub = _known_flags()
    bad = [f for f in re.findall(r'pegaprox_multi_cluster\.py (--[a-z-]+)', text) if f not in top]
    bad += [f for f in re.findall(r'migrate-db (--[a-z-]+)', text) if f not in sub]
    bad += re.findall(r'\bpegaprox migrate-db\b', text)
    return bad


def _strings(rel):
    """Every string in the source of `rel`, f-strings by their text parts: what it can say."""
    import ast
    tree = ast.parse((ROOT / rel).read_text(encoding='utf-8'))
    return '\n'.join(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def test_every_command_the_messages_of_this_path_name_exists():
    # counterproof: the advice 1.5.0 gave
    assert _unknown_commands('run `pegaprox migrate-db --reencrypt` with both keys') == [
        '--reencrypt', 'pegaprox migrate-db']
    for rel in ('pegaprox/core/dbcrypto.py', 'pegaprox/cli/migrate_db.py', 'pegaprox/cli/set_port.py',
                'pegaprox/app.py'):
        said = _strings(rel)
        assert _unknown_commands(said) == [], rel
    assert 'pegaprox_multi_cluster.py --keystore-status' in _strings('pegaprox/core/dbcrypto.py')
    # and the ones it names are there
    top, _ = _known_flags()
    assert {'--migrate-db', '--keystore-status'} <= top


# --- another process on the database ------------------------------------------------------------

_HOLDER = r'''
import os, sqlite3, sys
db, how = sys.argv[1], sys.argv[2]
if how == 'pegaprox':
    # what main() and db.py do: the lock of the config directory, then one connection kept
    sys.path.insert(0, sys.argv[3])
    from pegaprox.core import dbcrypto, ha
    ha.lock_config_dir(os.path.join(os.path.dirname(db), '.pegaprox.lock'))
    dbcrypto.ensure_db_encrypted(db)
    conn = dbcrypto.connect(db, check_same_thread=False)
else:
    # a sqlite3 shell or a backup job, the commits still in its -wal
    conn = sqlite3.connect(db)
conn.execute('PRAGMA journal_mode = WAL')
conn.execute('PRAGMA wal_autocheckpoint = 0')
for i in range(10):
    conn.execute('INSERT INTO t (a) VALUES (?)', (100 + i,))
    conn.commit()
print('ready', flush=True)
sys.stdin.readline()
for i in range(10):
    conn.execute('INSERT INTO t (a) VALUES (?)', (200 + i,))
    conn.commit()
conn.close()
print('done', flush=True)
'''


class Holder:
    """A process that has the plain database open: 60 rows while it waits, 70 when it is
    done. 'pegaprox' is a PegaProx under the opt-out, 'sqlite3' anything else."""

    def __init__(self, inst, tmp_path, how):
        self.p = subprocess.Popen(
            [sys.executable, '-I', '-B', '-c', _HOLDER, inst.db, how, str(ROOT)], cwd=tmp_path,
            env=_child_env(tmp_path, PEGAPROX_DISABLE_AUTO_ENCRYPT='1'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.p.stdout.readline()
        if line.strip() != 'ready':
            self.p.kill()
            raise AssertionError(line + self.p.stderr.read())

    def finish(self):
        out, err = self.p.communicate('\n', timeout=60)
        return 'done' in out, err


def intact(db, rows):
    """The database opens with the key and holds `rows` rows, undamaged."""
    import sqlcipher3
    c = sqlcipher3.connect(db)
    try:
        c.execute(f"PRAGMA key = \"x'{bytes(range(32)).hex()}'\"")
        c.execute('PRAGMA cipher_compatibility = 4')
        return (c.execute('SELECT count(*) FROM t').fetchone()[0] == rows
                and c.execute('PRAGMA integrity_check').fetchone()[0] == 'ok')
    except Exception:
        return False
    finally:
        c.close()


def plain_rows(path):
    c = sqlite3.connect(path)
    try:
        return c.execute('SELECT count(*) FROM t').fetchone()[0]
    finally:
        c.close()


def _guards_off(monkeypatch):
    """The conversion as 1.5.0 made it: no look at who else has the file, no check before the
    swap, and the CLI without the lock of the config directory."""
    monkeypatch.setattr(dbcrypto, 'plain_alone', dbcrypto._file_mark)
    monkeypatch.setattr(dbcrypto, 'check_before_swap', lambda db, mark: None)
    monkeypatch.setattr(migrate_db, '_hold_config_dir', lambda folder: None)


@needs_sqlcipher
def test_the_cli_refuses_while_pegaprox_runs_on_the_database(inst, tmp_path, capsys):
    plain_db(inst.db)
    srv = Holder(inst, tmp_path, 'pegaprox')
    try:
        assert migrate_db.main(['--db', inst.db, '--yes']) == 7
        out = capsys.readouterr().out
        assert f'[BLOCKED] PegaProx (process {srv.p.pid}) is running on {inst.cfg}. Nothing was changed.' in out
        assert 'Stop PegaProx first' in out
        assert dbcrypto.file_state(inst.db) == 'plain' and inst.leftovers() == []
    finally:
        done, err = srv.finish()
    assert done, err
    # what it wrote after the refusal is there, and the run after it converts all of it
    assert plain_rows(inst.db) == 70
    assert migrate_db.main(['--db', inst.db, '--yes']) == 0
    assert intact(inst.db, 70)
    copy, = inst.copies()
    assert plain_rows(copy) == 70


_TAKE_LOCK = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from pegaprox.core import ha
try:
    ha.lock_config_dir(sys.argv[2])
    print('took it')
except ha.HaError as e:
    print(e)
'''


@needs_sqlcipher
def test_no_pegaprox_starts_on_the_directory_while_the_cli_converts(inst, tmp_path, monkeypatch):
    plain_db(inst.db)
    lock = inst.cfg / '.pegaprox.lock'
    lock.write_text('4242\n')   # left by the PegaProx that was stopped for this

    def start_one():
        return subprocess.run([sys.executable, '-I', '-B', '-c', _TAKE_LOCK, str(ROOT), str(lock)],
                              cwd=tmp_path, env=_child_env(tmp_path), capture_output=True, text=True,
                              timeout=60).stdout.strip()
    during = []
    real = migrate_db._convert

    def convert(*a):
        during.append(start_one())
        return real(*a)
    monkeypatch.setattr(migrate_db, '_convert', convert)
    assert migrate_db.main(['--db', inst.db, '--yes']) == 0
    assert during == [f'Another PegaProx process {os.getpid()} runs on {inst.cfg} - one config directory '
                      'takes one process']
    # and lets go when it is done
    assert start_one() == 'took it'


@needs_sqlcipher
def test_counterproof_the_cli_beside_a_running_pegaprox_damages_the_database(inst, tmp_path, monkeypatch):
    plain_db(inst.db)
    _guards_off(monkeypatch)
    srv = Holder(inst, tmp_path, 'pegaprox')
    try:
        assert migrate_db.main(['--db', inst.db, '--yes']) == 0
    finally:
        srv.finish()
    assert dbcrypto.file_state(inst.db) == 'encrypted'
    assert not intact(inst.db, 70)


@needs_sqlcipher
def test_the_cli_refuses_while_any_other_process_has_the_database_open(inst, tmp_path, capsys):
    """Where there is no lock of the config directory (Windows, a lock file never made) the
    database itself tells: leaving WAL mode needs it to itself."""
    plain_db(inst.db)
    holder = Holder(inst, tmp_path, 'sqlite3')
    try:
        assert migrate_db.main(['--db', inst.db, '--yes']) == 7
        out = capsys.readouterr().out
        assert f'[BLOCKED] another process has {inst.db} open' in out and 'database is locked' in out
        assert inst.leftovers() == []
    finally:
        done, err = holder.finish()
    assert done, err
    assert plain_rows(inst.db) == 70


@needs_sqlcipher
def test_a_start_leaves_a_database_another_process_has_open_plain(inst, tmp_path, log):
    plain_db(inst.db)
    holder = Holder(inst, tmp_path, 'sqlite3')
    try:
        r = inst.ensure()
        assert r['action'] == 'failed'
        said = errors(log)
        assert len(said) == 1 and f'another process has {inst.db} open' in said[0]
        assert 'Nothing was changed' in said[0] and inst.leftovers() == []
        assert dbcrypto.file_state(inst.db) == 'plain'
    finally:
        done, err = holder.finish()
    assert done, err
    # the next start has it alone: every row of the -wal is in the copy and in the database
    inst.again()
    r = inst.ensure()
    assert r['action'] == 'migrated'
    assert intact(inst.db, 70)
    assert plain_rows(r['backup_path']) == 70


@needs_sqlcipher
def test_counterproof_a_start_beside_another_process_damages_the_database(inst, tmp_path, monkeypatch):
    plain_db(inst.db)
    _guards_off(monkeypatch)
    holder = Holder(inst, tmp_path, 'sqlite3')
    try:
        r = inst.ensure()
    finally:
        holder.finish()
    assert r['action'] == 'migrated'
    assert not intact(inst.db, 70)
    # and its copy lacks what was still in the -wal
    assert plain_rows(r['backup_path']) == 50


@needs_sqlcipher
@pytest.mark.skipif(hasattr(os, 'geteuid') and os.geteuid() == 0, reason='root writes a 0444 file')
def test_a_wal_this_user_cannot_write_leaves_the_database_plain(inst, log):
    plain_db(inst.db, rows=20)
    # a commit left in the -wal by a process of another user
    subprocess.run([sys.executable, '-I', '-c',
                    'import os, sqlite3, sys; c = sqlite3.connect(sys.argv[1]); '
                    'c.execute("PRAGMA wal_autocheckpoint = 0"); c.execute("INSERT INTO t (a) VALUES (99)"); '
                    'c.commit(); os._exit(0)', inst.db], check=True)
    for side in ('-wal', '-shm'):
        os.chmod(inst.db + side, 0o444)
    r = inst.ensure()
    assert r['action'] == 'failed'
    assert 'or its -wal or -shm file cannot be written by this user' in errors(log)[0]
    assert dbcrypto.file_state(inst.db) == 'plain' and inst.leftovers() == []
    for side in ('-wal', '-shm'):
        os.chmod(inst.db + side, 0o600)
    inst.again()
    assert inst.ensure()['action'] == 'migrated'
    assert intact(inst.db, 21)


@needs_sqlcipher
@pytest.mark.parametrize('how', ['wal', 'rollback'])
def test_a_write_during_the_conversion_stops_the_swap(inst, monkeypatch, log, how):
    """Another process that opens the file after the start took it: a -wal beside it, or a
    commit straight into the file."""
    plain_db(inst.db)
    real = migrate_db._verify_row_counts

    def verify_and_meanwhile(plain, enc):
        real(plain, enc)
        c = sqlite3.connect(plain)
        if how == 'wal':
            c.execute('PRAGMA journal_mode = WAL')
            c.execute('PRAGMA wal_autocheckpoint = 0')
        c.execute('INSERT INTO t (a) VALUES (777)')
        c.commit()
        if how == 'wal':
            # still open when the swap comes
            meanwhile.append(c)
        else:
            c.close()
    meanwhile = []
    monkeypatch.setattr(migrate_db, '_verify_row_counts', verify_and_meanwhile)
    r = inst.ensure()
    for c in meanwhile:
        c.close()
    assert r['action'] == 'failed'
    said = errors(log)[0]
    assert ('turned up while' in said) if how == 'wal' else ('another process wrote to' in said)
    assert dbcrypto.file_state(inst.db) == 'plain' and inst.leftovers() == []
    assert plain_rows(inst.db) == 51
    # counterproof: without the check the row written meanwhile is gone, or the file damaged
    monkeypatch.setattr(dbcrypto, 'check_before_swap', lambda db, mark: None)
    inst.again()
    assert inst.ensure()['action'] == 'migrated'
    for c in meanwhile:
        c.close()
    assert not intact(inst.db, 52)


# --- the name of the plain copy -----------------------------------------------------------------

@needs_sqlcipher
def test_a_copy_left_in_the_same_second_does_not_stop_the_conversion(inst, monkeypatch):
    plain_db(inst.db)
    now = int(time.time())
    monkeypatch.setattr(time, 'time', lambda: float(now))
    # a start killed half way, started again within the second
    left = Path(f'{inst.db}.plain.bak.{now}')
    left.write_bytes(b'cut short')
    r = inst.ensure()
    assert r['action'] == 'migrated', r
    assert r['backup_path'] == f'{left}.1'
    assert plain_rows(r['backup_path']) == 50
    assert left.read_bytes() == b'cut short'
    assert sorted(inst.copies()) == [str(left), f'{left}.1']


@needs_sqlcipher
def test_the_cli_takes_the_next_free_name_for_its_copy_too(inst, monkeypatch, capsys):
    plain_db(inst.db)
    now = int(time.time())
    monkeypatch.setattr(time, 'time', lambda: float(now))
    for name in (f'{inst.db}.plain.bak.{now}', f'{inst.db}.plain.bak.{now}.1'):
        Path(name).write_bytes(b'x')
    assert migrate_db.main(['--db', inst.db, '--yes']) == 0
    copy = f'{inst.db}.plain.bak.{now}.2'
    assert plain_rows(copy) == 50 and os.stat(copy).st_mode & 0o777 == 0o600
    assert f'Plain backup:    {copy}' in capsys.readouterr().out


# --- the copies under the opt-out and without SQLCipher ------------------------------------------

def _aged_copy(inst, hours):
    copy = Path(f'{inst.db}.plain.bak.{int(time.time() - hours * 3600)}')
    copy.write_bytes(b'every credential in the clear')
    then = time.time() - hours * 3600
    os.utime(copy, (then, then))
    return copy


@needs_sqlcipher
def test_the_opt_out_still_shreds_a_copy_past_its_window(inst, monkeypatch, log):
    plain_db(inst.db)
    assert inst.ensure()['action'] == 'migrated'
    old = _aged_copy(inst, 2)
    young = _aged_copy(inst, 0.25)
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    inst.again()
    assert inst.ensure() == {'action': 'opt-out'}
    assert not old.exists()
    assert 'shredded stale plaintext backup' in log.text
    # counterproof: one within its window stays, as it does without the opt-out
    assert young.exists()


def test_without_sqlcipher_a_copy_past_its_window_is_shredded_too(inst, monkeypatch):
    plain_db(inst.db)
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlite-plain')
    old = _aged_copy(inst, 2)
    young = _aged_copy(inst, 0.25)
    assert inst.ensure()['action'] == 'no-backend'
    assert not old.exists() and young.exists()


# --- a plain file that does not open here --------------------------------------------------------

@needs_sqlcipher
@pytest.mark.skipif(hasattr(os, 'geteuid') and os.geteuid() == 0, reason='root reads a 000 file')
def test_a_database_this_user_cannot_read_is_not_called_damaged(inst, capsys):
    plain_db(inst.db)
    os.chmod(inst.db, 0)
    try:
        with pytest.raises(RuntimeError) as e:
            inst.ensure()
        msg = str(e.value)
        assert msg.startswith(f'[DBCRYPTO] {inst.db} cannot be read by this process '
                              '(PermissionError: Permission denied).')
        assert 'needs read and write access' in msg and msg.endswith('Refusing to start.')
        assert 'estore' not in msg and 'unlock' not in msg and 'neither plain' not in msg
        inst.again()
        assert migrate_db.main(['--db', inst.db, '--dry-run']) == 7
        out = capsys.readouterr().out
        assert 'cannot be read by this process' in out and 'estore' not in out
    finally:
        os.chmod(inst.db, 0o600)


def _plain_probe_fails(monkeypatch, inst, error):
    real = sqlite3.connect

    def connect(path, *a, **kw):
        if str(path) == inst.db:
            raise sqlite3.OperationalError(error)
        return real(path, *a, **kw)
    monkeypatch.setattr(sqlite3, 'connect', connect)


@needs_sqlcipher
def test_a_plain_database_on_a_full_disk_is_named_as_such(inst, monkeypatch):
    """At 0 bytes free SQLite cannot make the -shm of a WAL database and says 'disk I/O
    error'. That read as 'encrypted, and the current master key does not unlock it'."""
    plain_db(inst.db)
    _little_free(monkeypatch, 0)
    _plain_probe_fails(monkeypatch, inst, 'disk I/O error')
    with pytest.raises(RuntimeError) as e:
        inst.ensure()
    msg = str(e.value)
    assert msg == (f'[DBCRYPTO] {inst.db} is plain SQLite, and it cannot be opened because {inst.cfg} '
                   'is full (0 bytes free; OperationalError: disk I/O error). Free up space there. '
                   'Refusing to start.')


@needs_sqlcipher
def test_counterproof_with_room_the_same_error_is_not_called_a_full_disk(inst, monkeypatch):
    plain_db(inst.db)
    _little_free(monkeypatch, 50 * 1024 ** 3)
    _plain_probe_fails(monkeypatch, inst, 'disk I/O error')
    with pytest.raises(RuntimeError) as e:
        inst.ensure()
    msg = str(e.value)
    assert 'is plain SQLite, and SQLite cannot open it here (OperationalError: disk I/O error)' in msg
    assert 'is full' not in msg and 'unlock' not in msg and 'estore' not in msg


@needs_sqlcipher
def test_a_damaged_plain_database_is_damaged_not_a_wrong_key(inst):
    """The other side: a plain file that is broken still says restore, and no longer asks for
    another key."""
    plain_db(inst.db, rows=500)
    with open(inst.db, 'r+b') as fh:
        fh.seek(100)
        fh.write(b'\xff' * 4000)
    with pytest.raises(RuntimeError) as e:
        inst.ensure()
    assert 'neither plain SQLite nor a valid encrypted DB' in str(e.value)
    assert 'Restore from backup' in str(e.value) and 'master key' not in str(e.value)


# --- what a full disk is asked for ---------------------------------------------------------------

def _export_fails(monkeypatch, error):
    def export(plain, enc, key):
        raise sqlite3.OperationalError(error)
    monkeypatch.setattr(migrate_db, '_encrypt_via_sqlcipher_export', export)


@needs_sqlcipher
def test_an_io_error_with_too_little_room_is_a_full_disk(inst, monkeypatch, log):
    plain_db(inst.db, rows=300, blob=1000)
    _little_free(monkeypatch, 100 * 1024)
    _export_fails(monkeypatch, 'disk I/O error')
    assert inst.ensure()['action'] == 'failed'
    said = errors(log)[0]
    assert f'not enough free space in {inst.cfg}' in said and '100 KB are free now' in said


@needs_sqlcipher
def test_counterproof_an_io_error_with_room_is_said_as_it_is(inst, monkeypatch, log):
    plain_db(inst.db, rows=300, blob=1000)
    _little_free(monkeypatch, 50 * 1024 ** 3)
    _export_fails(monkeypatch, 'disk I/O error')
    assert inst.ensure()['action'] == 'failed'
    said = errors(log)[0]
    assert '(OperationalError: disk I/O error)' in said and 'free space' not in said


@needs_sqlcipher
def test_a_small_database_is_asked_for_room_for_its_journal_and_shm_as_well(inst, monkeypatch, log):
    """2 x 8 KB was 'needs about 16 KB free, 52 KB are free now', for a conversion that had
    just failed for want of room."""
    plain_db(inst.db, rows=5)
    assert os.path.getsize(inst.db) < 16 * 1024
    full = _disk_full_at('copy', inst, monkeypatch)
    _little_free(monkeypatch, 52 * 1024, lambda: full['on'])
    assert inst.ensure()['action'] == 'failed'
    said = errors(log)[0]
    need, free = map(int, re.search(r'needs about (\d+) KB free, (\d+) KB are free now', said).groups())
    assert free == 52 and need > free


@needs_sqlcipher
def test_the_free_space_is_left_out_where_it_would_contradict_the_reason(inst, monkeypatch, log):
    """ENOSPC from a quota, or from another writer that has let go again: 'needs 81 KB, 50 GB
    are free now' would read as nonsense."""
    plain_db(inst.db, rows=5)
    full = _disk_full_at('copy', inst, monkeypatch)
    _little_free(monkeypatch, 50 * 1024 ** 3, lambda: full['on'])
    assert inst.ensure()['action'] == 'failed'
    said = errors(log)[0]
    assert 'not enough free space' in said and 'are free now' not in said
