"""`--print-key` writes the key and nothing else to stdout.

docs/SECURITY.md pipes it into `systemd-creds encrypt`. The start-up lines of
pegaprox_multi_cluster.py (gevent, the fd limit, the websocket patch) went to stdout as
well, and in a pipe they came out after the key: the credential held the key plus three
lines of text, and PegaProx could not read a key from it.

MK Nov 2026
"""
import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pegaprox.core import keystore

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(Path('/etc/pegaprox/secret.key').exists(), reason='this host has a tier 4 key')
def test_the_key_is_alone_on_stdout(tmp_path):
    (tmp_path / 'config').mkdir()
    key = base64.urlsafe_b64encode(os.urandom(32))
    (tmp_path / 'config' / '.pegaprox.key').write_bytes(key + b'\n')
    (tmp_path / 'config' / '.pegaprox.key').chmod(0o600)
    env = {k: v for k, v in os.environ.items()
           if k not in ('PEGAPROX_DB_KEY', 'PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY',
                        'PEGAPROX_CONFIG_DIR', 'PEGAPROX_NO_GEVENT')}
    env['HOME'] = str(tmp_path / 'home')
    run = subprocess.run([sys.executable, str(ROOT / 'pegaprox_multi_cluster.py'), '--print-key'],
                         cwd=tmp_path, env=env, capture_output=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    assert run.stdout == key
    # what systemd-creds wraps from it is read back as that key
    cred = tmp_path / 'db-key'
    cred.write_bytes(run.stdout)
    assert keystore._from_file(cred, source='systemd-credential', strict_perms=False).key_b64 == key
    # the start-up lines are still there, on stderr
    assert b'[ws-patch]' in run.stderr
