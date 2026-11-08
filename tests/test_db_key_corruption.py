"""A damaged AES key file must not be silently replaced.

_init_encryption used to regenerate .pegaprox_aes256.key whenever it wasn't 32
bytes. A truncated write (disk full, power cut, half-restored backup) therefore
turned into permanent, silent loss of every encrypted field in the DB — cluster
passwords, SSH keys, BMC passwords, the server_settings secrets — plus the audit
HMAC chain, which is signed with the same key. Start-up refuses now, matching the
"no encryption backend" check further down the same method. MK
"""
import os

import pytest

import pegaprox.core.db as dbmod


@pytest.fixture
def key_dir(tmp_path):
    """Point the db module at a throwaway CONFIG_DIR and drop the singleton."""
    saved = (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
             dbmod._db, dbmod.PegaProxDB._instance)
    dbmod.CONFIG_DIR = str(tmp_path)
    dbmod.DATABASE_FILE = str(tmp_path / 'pegaprox.db')
    dbmod.KEY_FILE = str(tmp_path / '.pegaprox.key')
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    try:
        yield tmp_path
    finally:
        (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
         dbmod._db, dbmod.PegaProxDB._instance) = saved


def _key_path(key_dir):
    return key_dir / '.pegaprox_aes256.key'


@pytest.mark.parametrize('content', [
    b'',                    # zero-length: the classic truncated write
    b'\x01' * 16,           # half a key
    b'\x02' * 31,           # one byte short
    b'\x03' * 64,           # too long — hex-encoded by hand, say
])
def test_short_or_long_key_refuses_to_start(key_dir, content):
    _key_path(key_dir).write_bytes(content)

    with pytest.raises(RuntimeError) as exc:
        dbmod.PegaProxDB()

    assert 'expected 32' in str(exc.value)
    assert _key_path(key_dir).read_bytes() == content, 'the damaged key was overwritten'


def test_first_start_still_generates_a_key(key_dir):
    assert not _key_path(key_dir).exists()

    dbmod.PegaProxDB()

    key = _key_path(key_dir).read_bytes()
    assert len(key) == 32
    assert os.stat(_key_path(key_dir)).st_mode & 0o777 == 0o600


def test_an_intact_key_is_reused_not_rewritten(key_dir):
    existing = os.urandom(32)
    _key_path(key_dir).write_bytes(existing)
    os.chmod(_key_path(key_dir), 0o600)

    db = dbmod.PegaProxDB()

    assert _key_path(key_dir).read_bytes() == existing
    assert db.aes_key == existing
