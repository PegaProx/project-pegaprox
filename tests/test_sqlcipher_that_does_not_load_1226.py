"""A sqlcipher3 that is installed but does not load is said out loud, not taken for none.

The python3-sqlcipher3 deb of the appliance build carried one x86_64 build for Python 3.13
and installs on arm64 all the same. There `import sqlcipher3` fails, dbcrypto fell back to
plain SQLite and said so at INFO, the line for "not installed", before logging is set up:
nobody saw it, and --keystore-status said only sqlite-plain. Not installed stays that INFO
line; installed and not loading is a WARNING with the reason and the platform, and the
reason is in --keystore-status and the compliance view. The fallback itself is the same.

The import runs for real in a child (python -I), with the interpreter's own packages off
sys.path and a sqlcipher3 put in front, or none at all. MK Nov 2026
"""
import base64
import importlib.machinery
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

from pegaprox.core import dbcrypto, keystore

ROOT = Path(__file__).resolve().parent.parent

_PROBE = r'''
import json, logging, sys
root, fake, tmp = sys.argv[1:4]
sys.path[:] = [p for p in sys.path if 'site-packages' not in p and 'dist-packages' not in p]
if fake:
    sys.path.insert(0, fake)
sys.path.insert(0, root)
said = []
class Keep(logging.Handler):
    def emit(self, record):
        said.append([record.levelname, record.getMessage()])
log = logging.getLogger('pegaprox.core.dbcrypto')
log.addHandler(Keep())
log.setLevel(logging.DEBUG)
from pathlib import Path
from pegaprox.core import dbcrypto, keystore
keystore.SYSTEM_KEY_PATH = Path(tmp) / 'etc' / 'secret.key'
conn = dbcrypto.connect(str(Path(tmp) / 'plain.db'))
conn.execute('CREATE TABLE t (a)')
conn.commit()
conn.close()
print(json.dumps({
    'said': said,
    'backend': dbcrypto.BACKEND,
    'driver': dbcrypto._sqlite_module.__name__,
    'error': getattr(dbcrypto, 'SQLCIPHER_ERROR', None),
    'header': open(Path(tmp) / 'plain.db', 'rb').read(16).decode('latin-1'),
    'db': dbcrypto.backend_status(),
    'keystore': keystore.health_status(),
    'ensure': dbcrypto.ensure_db_encrypted(str(Path(tmp) / 'plain.db')),
}))
'''


def _other_build_name():
    """A file name the import system of this interpreter does not take: the one in the deb,
    or the same build for the other machine where this one is that build."""
    taken = importlib.machinery.EXTENSION_SUFFIXES
    for suffix in ('.cpython-313-x86_64-linux-gnu.so', '.cpython-313-aarch64-linux-gnu.so'):
        if suffix not in taken:
            return '_sqlite3' + suffix
    raise AssertionError(taken)


def _fake(tmp_path, kind):
    """A sqlcipher3 package as it lands on a machine it was not built for."""
    pkg = tmp_path / 'fake' / 'sqlcipher3'
    pkg.mkdir(parents=True)
    if kind == 'elf':
        (pkg / '__init__.py').write_text(
            "raise ImportError('/usr/lib/python3/dist-packages/sqlcipher3/"
            "_sqlite3.cpython-313-x86_64-linux-gnu.so: wrong ELF class: ELFCLASS64')\n")
    elif kind == 'oserror':
        (pkg / '__init__.py').write_text("raise OSError(12, 'Cannot allocate memory')\n")
    elif kind == 'empty':
        # what is left of the directory the two packages share once one of them goes
        (pkg / '__pycache__').mkdir()
    else:
        # the layout of the real package, with a build for another machine or Python
        (pkg / '__init__.py').write_text('from sqlcipher3.dbapi2 import *\n')
        (pkg / 'dbapi2.py').write_text('from sqlcipher3._sqlite3 import *\n')
        (pkg / _other_build_name()).write_bytes(b'\x7fELF' + os.urandom(60))
    return tmp_path / 'fake'


def _env(tmp_path):
    env = {k: v for k, v in os.environ.items()
           if k not in ('PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY', 'PEGAPROX_DISABLE_AUTO_ENCRYPT')}
    env['HOME'] = str(tmp_path / 'home')
    env['PEGAPROX_CONFIG_DIR'] = str(tmp_path / 'config')
    env['PEGAPROX_DB_KEY'] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return env


def _probe(tmp_path, fake):
    r = subprocess.run([sys.executable, '-I', '-B', '-c', _PROBE, str(ROOT), str(fake or ''), str(tmp_path)],
                       cwd=tmp_path, env=_env(tmp_path), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-3000:]
    return json.loads(r.stdout)


def _bare_import(tmp_path, fake):
    """stderr of a process that imports dbcrypto before any logging is set up, as the
    server does (pegaprox.app pulls it in long before main() configures logging)."""
    code = ("import sys\n"
            "sys.path[:] = [p for p in sys.path if 'site-packages' not in p and 'dist-packages' not in p]\n"
            f"sys.path[:0] = [p for p in ({str(ROOT)!r}, {str(fake or '')!r}) if p]\n"
            "import pegaprox.core.dbcrypto\n")
    r = subprocess.run([sys.executable, '-I', '-B', '-c', code], cwd=tmp_path, env=_env(tmp_path),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-3000:]
    return r.stderr


@pytest.mark.parametrize('kind,reason', [
    ('elf', 'ImportError: /usr/lib/python3/dist-packages/sqlcipher3/_sqlite3.cpython-313-x86_64-linux-gnu.so: '
            'wrong ELF class: ELFCLASS64'),
    ('other-build', "ModuleNotFoundError: No module named 'sqlcipher3._sqlite3'"),
    ('oserror', 'OSError: [Errno 12] Cannot allocate memory'),
    ('empty', 'ImportError: the sqlcipher3 found has no driver in it'),
])
def test_an_installed_sqlcipher3_that_does_not_load_is_a_warning(tmp_path, kind, reason):
    out = _probe(tmp_path, _fake(tmp_path, kind))
    mine = [s for s in out['said'] if '[DBCRYPTO]' in s[1]]
    assert [level for level, _ in mine] == ['WARNING'], mine
    text = mine[0][1]
    assert 'is installed but does not load on this machine' in text
    assert reason in text
    assert f'({platform.machine()}, Python {platform.python_version()})' in text
    # the same CPU with another Python lands here too
    assert ('stays plain SQLite until a package built for this machine and this Python version '
            'is installed') in text
    assert 'architecture' not in text
    assert str(tmp_path / 'fake' / 'sqlcipher3') in text
    assert 'not available' not in text
    assert out['error'] == reason


def test_one_that_is_not_installed_keeps_its_info_line(tmp_path):
    out = _probe(tmp_path, None)
    mine = [s for s in out['said'] if '[DBCRYPTO]' in s[1]]
    assert [level for level, _ in mine] == ['INFO'], mine
    assert "sqlcipher3 not available (No module named 'sqlcipher3')" in mine[0][1]
    assert out['error'] is None
    assert out['db']['sqlcipher_error'] is None and out['keystore']['sqlcipher_error'] is None
    assert out['db']['note'] == ('Full DB encryption unavailable on this platform. '
                                 'Sensitive fields are still encrypted individually with AES-256-GCM.')
    assert out['keystore']['recommendation'] is None
    assert out['ensure'] == {'action': 'no-backend', 'reason': 'sqlcipher3 not installed'}


@pytest.mark.parametrize('kind', ['elf', 'other-build', 'empty'])
def test_the_fallback_is_plain_sqlite_as_before(tmp_path, kind):
    out = _probe(tmp_path, _fake(tmp_path, kind))
    assert out['backend'] == 'sqlite-plain' and out['driver'] == 'sqlite3'
    assert out['header'] == 'SQLite format 3\x00'
    assert out['ensure'] == {'action': 'no-backend', 'reason': 'sqlcipher3 does not load'}


def test_keystore_status_carries_the_reason(tmp_path):
    out = _probe(tmp_path, _fake(tmp_path, 'other-build'))
    reason = "ModuleNotFoundError: No module named 'sqlcipher3._sqlite3'"
    db, ks = out['db'], out['keystore']
    assert db['backend'] == 'sqlite-plain' and db['encrypted_at_rest'] is False
    assert db['sqlcipher_error'] == reason
    assert 'does not load on this machine' in db['note'] and reason in db['note']
    assert db['note'].endswith('Sensitive fields are still encrypted individually with AES-256-GCM.')
    assert ks['ok'] and ks['tier'] == 1 and ks['sqlcipher_error'] == reason
    assert 'does not load on this machine' in ks['recommendation']


@pytest.mark.parametrize('kind', ['other-build', 'empty'])
def test_without_logging_set_up_the_warning_still_reaches_stderr(tmp_path, kind):
    said = _bare_import(tmp_path, _fake(tmp_path, kind))
    assert 'is installed but does not load on this machine' in said
    assert _bare_import(tmp_path, None) == ''


# --- the start lines of main(), run from the source without starting anything -------------

_START = r'''
import ast, logging, os, sys
root, fake = sys.argv[1:3]
sys.path[:] = [p for p in sys.path if 'site-packages' not in p and 'dist-packages' not in p]
if fake:
    sys.path.insert(0, fake)
sys.path.insert(0, root)
src = os.path.join(root, 'pegaprox', 'app.py')
main = next(n for n in ast.parse(open(src, encoding='utf-8').read()).body
            if isinstance(n, ast.FunctionDef) and n.name == 'main')
block = min((n for n in ast.walk(main) if isinstance(n, ast.Try) and any(
    getattr(c.func, 'attr', None) == 'ensure_db_encrypted' for c in ast.walk(n) if isinstance(c, ast.Call))),
    key=lambda n: n.end_lineno - n.lineno)
exec(compile(ast.Module(body=[block], type_ignores=[]), src, 'exec'),
     {'__name__': 'start', 'os': os, 'sys': sys, 'logging': logging})
'''


def _start(tmp_path, fake, db):
    """What the auto-encrypt step of main() prints for config/pegaprox.db in `db` state."""
    cfg = tmp_path / 'config'
    cfg.mkdir()
    if db == 'plain':
        import sqlite3
        c = sqlite3.connect(cfg / 'pegaprox.db')
        c.execute('CREATE TABLE t (a)')
        c.commit()
        c.close()
    else:
        # all that is read without a key: no SQLite magic in front
        (cfg / 'pegaprox.db').write_bytes(os.urandom(8192))
    r = subprocess.run([sys.executable, '-I', '-B', '-c', _START, str(ROOT), str(fake or '')],
                       cwd=tmp_path, env=_env(tmp_path), capture_output=True, text=True, timeout=120)
    assert 'auto-encrypt check failed' not in r.stderr, r.stderr[-3000:]
    return r, str(cfg / 'pegaprox.db')


def test_the_start_line_says_why_a_plain_database_stays_plain(tmp_path):
    r, _ = _start(tmp_path, _fake(tmp_path, 'other-build'), 'plain')
    assert r.returncode == 0, r.stdout + r.stderr
    assert ("sqlcipher3 is installed but does not load here (ModuleNotFoundError: No module named "
            "'sqlcipher3._sqlite3') - pegaprox.db stays plain until a package built for this "
            "machine and this Python version is installed") in r.stdout
    assert 'not installed' not in r.stdout


def test_without_a_package_the_start_line_is_the_old_one(tmp_path):
    r, _ = _start(tmp_path, None, 'plain')
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'sqlcipher3 not installed - pegaprox.db stays plain (field-level encryption still active)' in r.stdout
    assert 'does not load' not in r.stdout


def test_an_encrypted_database_it_cannot_open_stops_the_start(tmp_path):
    """Moved to arm64, or a pip install replaced by the deb: before, the line said the
    database stays plain and the first query failed with "file is not a database"."""
    r, db = _start(tmp_path, _fake(tmp_path, 'other-build'), 'encrypted')
    assert r.returncode == 1, r.stdout + r.stderr
    fatal = [ln for ln in r.stdout.splitlines() if ln.startswith('[FATAL]')]
    assert len(fatal) == 1, r.stdout
    assert '[DBCRYPTO] The SQLCipher package (sqlcipher3 at ' in fatal[0]
    assert "is installed but does not load on this machine" in fatal[0]
    assert "ModuleNotFoundError: No module named 'sqlcipher3._sqlite3'" in fatal[0]
    assert fatal[0].endswith(f'{db} is encrypted and does not open until a package built for this '
                             'machine and this Python version is installed. Refusing to start.')
    assert 'stays plain' not in r.stdout


def test_one_that_is_missing_stops_the_start_too(tmp_path):
    r, db = _start(tmp_path, None, 'encrypted')
    assert r.returncode == 1, r.stdout + r.stderr
    assert (f'[FATAL] [DBCRYPTO] {db} is encrypted and sqlcipher3 is not installed, so it does not '
            'open.') in r.stdout
    assert 'stays plain' not in r.stdout


@pytest.mark.parametrize('error', [None, 'ImportError: wrong ELF class: ELFCLASS32'])
def test_the_opt_out_does_not_open_an_encrypted_database_either(tmp_path, monkeypatch, error):
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlite-plain')
    monkeypatch.setattr(dbcrypto, 'SQLCIPHER_ERROR', error, raising=False)
    monkeypatch.setenv('PEGAPROX_DISABLE_AUTO_ENCRYPT', '1')
    db = tmp_path / 'pegaprox.db'
    db.write_bytes(os.urandom(8192))
    with pytest.raises(RuntimeError, match='is encrypted and .* Refusing to start'):
        dbcrypto.ensure_db_encrypted(str(db))
    plain = tmp_path / 'plain.db'
    plain.write_bytes(b'SQLite format 3\x00' + bytes(4080))
    assert dbcrypto.ensure_db_encrypted(str(plain)) == {'action': 'opt-out'}


# --- the status where the key's own message is ---------------------------------------------

@pytest.fixture
def broken(monkeypatch):
    monkeypatch.setattr(dbcrypto, 'SQLCIPHER_ERROR', 'ImportError: wrong ELF class: ELFCLASS32', raising=False)
    monkeypatch.setattr(dbcrypto, '_SQLCIPHER_AT', '/usr/lib/python3/dist-packages/sqlcipher3', raising=False)


def test_with_no_key_the_message_says_it_too(tmp_path, monkeypatch, broken):
    for var in ('PEGAPROX_DB_KEY', 'PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.setattr(keystore, 'SYSTEM_KEY_PATH', tmp_path / 'etc' / 'secret.key')
    monkeypatch.setattr(keystore, '_legacy_key_path', lambda: tmp_path / 'config' / '.pegaprox.key')
    monkeypatch.setattr(keystore, '_CACHED', None)
    st = keystore.health_status()
    assert st['ok'] is False and st['source'] == 'none'
    assert st['message'].startswith('No master key found')
    assert 'sqlcipher3 at /usr/lib/python3/dist-packages/sqlcipher3) is installed but does not load' in st['message']
    assert st['sqlcipher_error'] == 'ImportError: wrong ELF class: ELFCLASS32'


def test_a_key_recommendation_keeps_its_text_and_gets_the_line(tmp_path, monkeypatch, broken):
    for var in ('PEGAPROX_DB_KEY', 'PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY'):
        monkeypatch.delenv(var, raising=False)
    key = tmp_path / 'etc' / 'secret.key'
    key.parent.mkdir()
    key.write_bytes(base64.urlsafe_b64encode(os.urandom(32)))
    key.chmod(0o600)
    monkeypatch.setattr(keystore, 'SYSTEM_KEY_PATH', key)
    monkeypatch.setattr(keystore, '_CACHED', None)
    st = keystore.health_status()
    assert st['ok'] and st['tier'] == 4
    assert st['recommendation'].startswith('Key is outside the DB directory')
    assert 'does not load on this machine' in st['recommendation']


# --- the compliance view the security page shows --------------------------------------------

def _compliance(api, seed):
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).get('/api/security/compliance')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def test_the_compliance_view_recommends_a_package_for_this_machine(api, seed, broken):
    body = _compliance(api, seed)
    said = [r for r in body['recommendations'] if 'does not load on this machine' in r]
    assert len(said) == 1 and 'wrong ELF class' in said[0]
    assert body['encryption']['sqlcipher_error'] == 'ImportError: wrong ELF class: ELFCLASS32'


def test_the_compliance_view_says_nothing_when_it_loads(api, seed, monkeypatch):
    monkeypatch.setattr(dbcrypto, 'SQLCIPHER_ERROR', None, raising=False)
    body = _compliance(api, seed)
    assert body['encryption']['sqlcipher_error'] is None
    assert not any('SQLCipher' in r for r in body['recommendations'])


def _set_port_on(tmp_path, monkeypatch, head):
    from pegaprox import constants
    from pegaprox.cli import set_port
    db = tmp_path / 'config' / 'pegaprox.db'
    db.parent.mkdir()
    db.write_bytes(head + os.urandom(4096))
    monkeypatch.setattr(constants, 'DATABASE_FILE', str(db))
    monkeypatch.setattr(constants, 'CONFIG_OWNED_BY_US', True)
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlite-plain')
    return set_port.main(['8443']), str(db)


def test_set_port_says_why_it_cannot_open_an_encrypted_database(tmp_path, monkeypatch, capsys, broken):
    code, db = _set_port_on(tmp_path, monkeypatch, os.urandom(16))
    err = capsys.readouterr().err
    assert code == 4
    assert 'is installed but does not load on this machine' in err and 'wrong ELF class' in err
    assert f'{db} is encrypted and does not open until' in err


def test_set_port_without_a_package_keeps_its_line(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dbcrypto, 'SQLCIPHER_ERROR', None, raising=False)
    code, db = _set_port_on(tmp_path, monkeypatch, os.urandom(16))
    assert code == 4
    assert capsys.readouterr().err == f'{db} is encrypted, and sqlcipher3 does not import here\n'


def test_migrate_db_says_why_it_is_blocked(tmp_path, monkeypatch, capsys, broken):
    from pegaprox.cli import migrate_db
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlite-plain')
    assert migrate_db.main(['--db', str(tmp_path / 'pegaprox.db'), '--dry-run']) == 2
    out = capsys.readouterr().out
    assert '[BLOCKED]' in out and 'does not load on this machine' in out and 'wrong ELF class' in out
