"""#1226 - the key step names a python3-sqlcipher3 that is there and does not load.

On arm64 apt took the python3-sqlcipher3 deb with only an x86_64 build in it. The key step
could not check whether the key next to an encrypted database opens it and asked "is
python3-sqlcipher3 installed?", which it was. It says now that the package does not load on
this machine and why, the same sentence dbcrypto logs. What it refuses and what it writes
stay as they were.

master_key.py runs as on a host (python -I), with the interpreter's own packages off
sys.path and a sqlcipher3 for another machine in front, or none at all. NS Nov 2026
"""
import base64
import importlib.machinery
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'packaging' / 'debian' / 'master_key.py'
ME = pwd.getpwuid(os.getuid()).pw_name

_RUN = r'''
import sys, types
helper, fake, *args = sys.argv[1:]
sys.path[:] = [p for p in sys.path if 'site-packages' not in p and 'dist-packages' not in p]
if fake:
    sys.path.insert(0, fake)
mod = types.ModuleType('pp_master_key_noload')
mod.__file__ = helper
exec(compile(open(helper, encoding='utf-8').read(), helper, 'exec'), mod.__dict__)
sys.exit(mod.main(args))
'''


def _fake(tmp_path):
    """The real package's layout with a build this interpreter does not take."""
    pkg = tmp_path / 'fake' / 'sqlcipher3'
    pkg.mkdir(parents=True)
    (pkg / '__init__.py').write_text('from sqlcipher3.dbapi2 import *\n')
    (pkg / 'dbapi2.py').write_text('from sqlcipher3._sqlite3 import *\n')
    taken = importlib.machinery.EXTENSION_SUFFIXES
    suffix = next(s for s in ('.cpython-313-x86_64-linux-gnu.so', '.cpython-313-aarch64-linux-gnu.so')
                  if s not in taken)
    (pkg / f'_sqlite3{suffix}').write_bytes(b'\x7fELF' + os.urandom(60))
    return tmp_path / 'fake'


class Host:
    def __init__(self, tmp):
        self.key = tmp / 'etc' / 'pegaprox' / 'secret.key'
        self.state = tmp / 'var' / 'lib' / 'pegaprox'
        self.config = self.state / 'config'
        self.db = self.config / 'pegaprox.db'
        self.legacy = self.config / '.pegaprox.key'
        self.home = tmp / 'home'
        (tmp / 'etc').mkdir()
        self.config.mkdir(parents=True)
        self.home.mkdir()

    def run(self, fake):
        args = [sys.executable, '-I', '-B', '-c', _RUN, str(HELPER), str(fake or ''),
                '--key', str(self.key), '--state-dir', str(self.state), '--user', ME,
                '--key-owner', ME, '--home', str(self.home)]
        return subprocess.run(args, capture_output=True, text=True, timeout=120)


def _write_key(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(base64.urlsafe_b64encode(os.urandom(32)))
    path.chmod(0o600)


def _refusal(stderr):
    return [ln for ln in stderr.splitlines() if ln.startswith('pegaprox: cannot check whether')]


@pytest.fixture
def host(tmp_path):
    return Host(tmp_path)


def test_a_package_that_does_not_load_is_named_as_that(host, tmp_path):
    host.db.write_bytes(os.urandom(8192))
    _write_key(host.legacy)
    r = host.run(_fake(tmp_path))
    assert r.returncode == 1, r.stdout + r.stderr
    said = _refusal(r.stderr)
    assert len(said) == 1, r.stderr
    assert 'is installed but does not load on this machine' in said[0]
    assert "ModuleNotFoundError: No module named 'sqlcipher3._sqlite3'" in said[0]
    assert 'is python3-sqlcipher3 installed?' not in said[0]
    assert said[0].endswith('Not copying a key that may be the wrong one. Nothing was changed.')
    assert not host.key.exists()


def test_one_that_is_missing_is_still_asked_about(host):
    host.db.write_bytes(os.urandom(8192))
    _write_key(host.legacy)
    r = host.run(None)
    assert r.returncode == 1, r.stdout + r.stderr
    said = _refusal(r.stderr)
    assert len(said) == 1 and '(is python3-sqlcipher3 installed?). Not copying' in said[0]
    assert 'does not load' not in r.stderr
    assert not host.key.exists()


def test_a_fresh_install_still_gets_its_key_and_hears_why_it_stays_plain(host, tmp_path):
    r = host.run(_fake(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.is_file() and 'created the master key' in r.stdout
    assert 'is installed but does not load on this machine' in r.stderr


def test_a_key_in_etc_next_to_an_encrypted_database_is_kept_as_before(host, tmp_path):
    host.db.write_bytes(os.urandom(8192))
    _write_key(host.key)
    before = host.key.read_bytes()
    r = host.run(_fake(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.read_bytes() == before
