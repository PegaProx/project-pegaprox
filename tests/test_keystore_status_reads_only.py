"""`--keystore-status` only reads, and says which database files are encrypted.

It resolved the master key the way the server does, and the server generates one where it
finds none. Run as root from /opt it left a fresh key in /opt/config; run before the first
start it would have made the service's own key, owned by root and unreadable for the
service. Its paths were relative to wherever it ran, and its hint named a command that does
not exist. encrypted_at_rest said whether the SQLCipher driver is there, not whether the
database is. MK Nov 2026
"""
import base64
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from pegaprox.core import dbcrypto, keystore

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def no_key(tmp_path, monkeypatch):
    """No tier has a key: no env, no systemd credential, none in /etc, ~ or config/."""
    for var in ('PEGAPROX_DB_KEY', 'PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.setattr(keystore, 'SYSTEM_KEY_PATH', tmp_path / 'etc' / 'secret.key')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(keystore, '_legacy_key_path', lambda: Path('config') / '.pegaprox.key')
    monkeypatch.setattr(keystore, '_CACHED', None)   # put back after the test
    return tmp_path


def test_the_status_creates_no_key_where_there_is_none(no_key):
    st = keystore.health_status()
    assert st['ok'] is False and st['source'] == 'none'
    assert not (no_key / 'config' / '.pegaprox.key').exists()
    assert st['config_dir'] == str(no_key / 'config')
    assert str(no_key / 'config') in st['message']


def test_the_server_still_creates_its_key_on_the_first_start(no_key):
    mk = keystore.load_master_key()
    assert mk.source == 'generated:CONFIG_DIR'
    assert (no_key / 'config' / '.pegaprox.key').is_file()


def test_a_legacy_key_is_named_by_its_full_path_with_steps_that_exist(no_key):
    (no_key / 'config').mkdir()
    (no_key / 'config' / '.pegaprox.key').write_bytes(base64.urlsafe_b64encode(os.urandom(32)))
    st = keystore.health_status()
    assert st['ok'] and st['is_legacy'] and st['tier'] == 6
    assert st['source_path'] == str(no_key / 'config' / '.pegaprox.key')
    rec = st['recommendation']
    assert 'secure-key' not in rec
    assert str(no_key / 'config' / '.pegaprox.key') in rec and '/etc/pegaprox/secret.key' in rec


def test_the_status_reports_the_key_the_server_holds(no_key):
    held = keystore.MasterKey(b'x', b'y', 'env:PEGAPROX_DB_KEY')
    keystore._CACHED = held
    assert keystore.peek_master_key() is held


# --- the database files ----------------------------------------------------------------------

def test_file_state_reads_the_header(tmp_path):
    plain = tmp_path / 'plain.db'
    sqlite3.connect(plain).execute('CREATE TABLE t (a)').connection.commit()
    (tmp_path / 'empty.db').write_bytes(b'')
    (tmp_path / 'salted.db').write_bytes(os.urandom(4096))
    assert dbcrypto.file_state(str(plain)) == 'plain'
    assert dbcrypto.file_state(str(tmp_path / 'empty.db')) == 'empty'
    assert dbcrypto.file_state(str(tmp_path / 'salted.db')) == 'encrypted'
    assert dbcrypto.file_state(str(tmp_path / 'nothing.db')) == 'missing'


@pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher', reason='needs the sqlcipher3 driver')
def test_file_state_of_a_real_sqlcipher_database(tmp_path):
    import sqlcipher3
    path = tmp_path / 'enc.db'
    c = sqlcipher3.connect(str(path))
    c.execute("PRAGMA key = \"x'%s'\"" % ('ab' * 32))
    c.execute('CREATE TABLE t (a)')
    c.commit()
    c.close()
    assert dbcrypto.file_state(str(path)) == 'encrypted'


@pytest.mark.parametrize('pegaprox_db,expected', [('plain', False), ('encrypted', True), (None, False)])
def test_encrypted_at_rest_goes_by_the_files(tmp_path, monkeypatch, pegaprox_db, expected):
    import pegaprox.constants
    monkeypatch.setattr(pegaprox.constants, 'CONFIG_DIR', str(tmp_path))
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlcipher')
    if pegaprox_db == 'plain':
        sqlite3.connect(tmp_path / 'pegaprox.db').execute('CREATE TABLE t (a)').connection.commit()
    elif pegaprox_db == 'encrypted':
        (tmp_path / 'pegaprox.db').write_bytes(os.urandom(4096))
    st = dbcrypto.backend_status()
    assert st['encrypted_at_rest'] is expected
    assert st['files'][str(tmp_path / 'pegaprox.db')] == (pegaprox_db or 'missing')
    if pegaprox_db == 'plain':
        assert 'still plain' in st['note']


# --- the command itself ----------------------------------------------------------------------

@pytest.mark.skipif(Path('/etc/pegaprox/secret.key').exists(), reason='this host has a tier 4 key')
def test_the_command_run_elsewhere_leaves_no_key_behind(tmp_path):
    env = {k: v for k, v in os.environ.items()
           if k not in ('PEGAPROX_DB_KEY', 'PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY', 'PEGAPROX_CONFIG_DIR')}
    env['HOME'] = str(tmp_path / 'home')
    run = subprocess.run([sys.executable, str(ROOT / 'pegaprox_multi_cluster.py'), '--keystore-status'],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    out = json.loads(run.stdout[run.stdout.index('\n{') + 1:])
    assert out['keystore']['source'] == 'none'
    assert out['keystore']['config_dir'] == str(tmp_path / 'config')
    assert not list(tmp_path.rglob('.pegaprox.key'))
    assert set(out['db']['files'].values()) == {'missing'}
