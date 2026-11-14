"""`--set-port` writes the listen port through dbcrypto, so it works on a SQLCipher database.

deploy.sh and the appliance setup wrote it with the sqlite3 CLI. That cannot open a SQLCipher
database, the error went to /dev/null, and every encrypted install got "set the port
manually" instead of its port. MK Nov 2026
"""
import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from pegaprox import constants
from pegaprox.cli import set_port
from pegaprox.core import dbcrypto, keystore

ROOT = Path(__file__).resolve().parent.parent
needs_sqlcipher = pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher', reason='needs sqlcipher3')
KEY = base64.urlsafe_b64encode(bytes(range(32)))


def _settings_table(conn):
    conn.execute('CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT)')
    conn.execute("INSERT INTO server_settings VALUES ('domain', '\"\"')")
    conn.commit()
    conn.close()


def encrypted_db(path, key=KEY):
    import sqlcipher3
    c = sqlcipher3.connect(str(path))
    c.execute(f"PRAGMA key = \"x'{base64.urlsafe_b64decode(key).hex()}'\"")
    c.execute('PRAGMA cipher_compatibility = 4')
    c.execute('PRAGMA journal_mode = WAL')
    _settings_table(c)


def stored_port(path, key=KEY):
    if dbcrypto.file_state(str(path)) == 'plain':
        c = sqlite3.connect(path)
    else:
        import sqlcipher3
        c = sqlcipher3.connect(str(path))
        c.execute(f"PRAGMA key = \"x'{base64.urlsafe_b64decode(key).hex()}'\"")
        c.execute('PRAGMA cipher_compatibility = 4')
    try:
        row = c.execute("SELECT value FROM server_settings WHERE key = 'port'").fetchone()
    finally:
        c.close()
    # read back the way db.get_server_setting does
    return json.loads(row[0]) if row else None


@pytest.fixture
def install(tmp_path, monkeypatch):
    """The config directory of an install, its key in PEGAPROX_DB_KEY."""
    cfg = tmp_path / 'config'
    cfg.mkdir()
    monkeypatch.setattr(constants, 'DATABASE_FILE', str(cfg / 'pegaprox.db'))
    monkeypatch.setattr(constants, 'CONFIG_OWNED_BY_US', True)
    monkeypatch.setenv('PEGAPROX_DB_KEY', KEY.decode())
    monkeypatch.setattr(keystore, '_CACHED', None)
    yield cfg / 'pegaprox.db'
    keystore.reset_cache()


@needs_sqlcipher
def test_the_port_goes_into_an_encrypted_database(install, capsys):
    encrypted_db(install)
    # what the installers did, and why it never worked here
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(install).execute(
            "INSERT OR REPLACE INTO server_settings (key, value) VALUES ('port', '8443')")
    assert set_port.main(['8443']) == 0
    assert stored_port(install) == 8443
    assert 'port 8443 is in' in capsys.readouterr().out
    # stored like save_server_setting stores it
    assert set_port.main(['443']) == 0 and stored_port(install) == 443


def test_the_port_goes_into_a_plain_database_without_sqlcipher(install, monkeypatch):
    c = sqlite3.connect(install)
    _settings_table(c)
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlite-plain')
    monkeypatch.setattr(dbcrypto, '_sqlite_module', sqlite3)
    assert set_port.main(['8006']) == 0
    assert stored_port(install) == 8006


@needs_sqlcipher
def test_a_plain_database_with_sqlcipher_is_left_to_the_next_start(install, capsys):
    c = sqlite3.connect(install)
    _settings_table(c)
    assert set_port.main(['8443']) == 4
    assert stored_port(install) is None
    assert 'next start of PegaProx encrypts it' in capsys.readouterr().err


def test_no_database_yet_makes_none(install, capsys):
    assert set_port.main(['8443']) == 4
    assert not install.exists()
    assert 'start PegaProx once' in capsys.readouterr().err


@needs_sqlcipher
def test_it_never_makes_a_key(install, monkeypatch, tmp_path):
    """With no key anywhere the key store would generate one next to the database."""
    encrypted_db(install)
    monkeypatch.delenv('PEGAPROX_DB_KEY')
    for var in ('PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.setattr(keystore, 'SYSTEM_KEY_PATH', tmp_path / 'etc' / 'secret.key')
    monkeypatch.setattr(keystore, '_legacy_key_path', lambda: install.parent / '.pegaprox.key')
    assert set_port.main(['8443']) == 4
    assert not (install.parent / '.pegaprox.key').exists()


@needs_sqlcipher
def test_a_wrong_key_writes_nothing(install, monkeypatch, capsys):
    encrypted_db(install)
    monkeypatch.setenv('PEGAPROX_DB_KEY', base64.urlsafe_b64encode(bytes(32)).decode())
    assert set_port.main(['8443']) == 5
    assert stored_port(install) is None
    assert 'could not write the port' in capsys.readouterr().err


def test_someone_elses_config_dir_is_refused(install, monkeypatch, capsys):
    """root in the service's directory would leave a -wal and -shm it cannot open."""
    c = sqlite3.connect(install)
    _settings_table(c)
    monkeypatch.setattr(constants, 'CONFIG_OWNED_BY_US', False)
    assert set_port.main(['8443']) == 3
    assert stored_port(install) is None
    assert 'run this as the user PegaProx runs as' in capsys.readouterr().err


@pytest.mark.parametrize('argv', [[], ['0'], ['65536'], ['80', '81'], ['-1'], ['https']])
def test_only_a_port_is_taken(install, argv, capsys):
    assert set_port.main(argv) == 2
    assert 'usage:' in capsys.readouterr().err


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@needs_sqlcipher
def test_the_entry_point_runs_it(tmp_path):
    """As the installers call it: pegaprox_multi_cluster.py --set-port, from the directory
    the service runs in. Without the branch the server itself would start, so the database
    names a free port for it, never 5000, and the run is short."""
    (tmp_path / 'config').mkdir()
    db = tmp_path / 'config' / 'pegaprox.db'
    encrypted_db(db)
    import sqlcipher3
    c = sqlcipher3.connect(str(db))
    c.execute(f"PRAGMA key = \"x'{base64.urlsafe_b64decode(KEY).hex()}'\"")
    c.execute("INSERT INTO server_settings VALUES ('port', ?)", (json.dumps(_free_port()),))
    c.commit()
    c.close()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PEGAPROX_', 'CREDENTIALS_'))}
    env.update(PEGAPROX_DB_KEY=KEY.decode(), HOME=str(tmp_path / 'home'), PEGAPROX_HTTP_PORT='-1')
    cmd = [sys.executable, '-B', str(ROOT / 'pegaprox_multi_cluster.py'), '--set-port']
    r = subprocess.run(cmd + ['8443'], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert stored_port(db) == 8443
    r = subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 2
