"""#826 (avsdev-cw) - let the config and log directories live somewhere else.

The reporter keeps container logs on volatile storage that is not backed up, and
backs the state directory up on a different schedule. Today both are relative
paths resolved against the working directory, which is /opt/PegaProx, /var/lib/
pegaprox or /app depending on how you installed - so "put the state somewhere
else" means moving the whole install.

Everything else in constants.py is derived from these two with os.path.join, so
the two env vars are enough; the derived paths have to be checked all the same,
because deriving them before reading the env would silently ignore it.
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _constants_with(env, cwd):
    """Import pegaprox.constants in a FRESH interpreter under the given env.

    A reload inside this process would not do: the module has already been
    imported by the suite, its directories already created, and half the code
    base holds `from pegaprox.constants import *` bindings taken at import time.
    """
    child = dict(os.environ)
    child.pop('PEGAPROX_CONFIG_DIR', None)
    child.pop('PEGAPROX_LOG_DIR', None)
    child.update(env)
    child['PYTHONPATH'] = ROOT
    code = (
        'import json, pegaprox.constants as c;'
        'print(json.dumps({k: getattr(c, k) for k in ('
        '"CONFIG_DIR", "LOG_DIR", "DATABASE_FILE", "KEY_FILE",'
        '"SERVER_SETTINGS_FILE", "SSL_CERT_FILE", "BRANDING_DIR")}))'
    )
    out = subprocess.run([sys.executable, '-c', code], cwd=str(cwd), env=child,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-1500:]
    import json
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_the_defaults_are_unchanged(tmp_path):
    """Every existing install resolves both against the working directory. That
    must not move, or an upgrade loses its database."""
    got = _constants_with({}, tmp_path)
    assert got['CONFIG_DIR'] == 'config'
    assert got['LOG_DIR'] == 'logs'
    assert got['DATABASE_FILE'] == os.path.join('config', 'pegaprox.db')


def test_the_config_directory_can_be_moved(tmp_path):
    target = tmp_path / 'state' / 'pegaprox'
    got = _constants_with({'PEGAPROX_CONFIG_DIR': str(target)}, tmp_path)
    assert got['CONFIG_DIR'] == str(target)
    assert target.is_dir(), 'the directory was not created'


def test_everything_derived_from_it_moves_too(tmp_path):
    """The database, the master key, the settings, the TLS pair and the branding
    assets all hang off CONFIG_DIR. One of them left behind would split the state
    across two directories, which is worse than not supporting this at all."""
    target = tmp_path / 'elsewhere'
    got = _constants_with({'PEGAPROX_CONFIG_DIR': str(target)}, tmp_path)
    for key in ('DATABASE_FILE', 'KEY_FILE', 'SERVER_SETTINGS_FILE', 'SSL_CERT_FILE', 'BRANDING_DIR'):
        assert got[key].startswith(str(target)), f'{key} stayed behind: {got[key]}'


def test_the_log_directory_can_be_moved_on_its_own(tmp_path):
    """The reporter's whole point: logs on volatile storage, state on backed-up
    storage. They have to be settable independently."""
    logs = tmp_path / 'volatile' / 'log'
    got = _constants_with({'PEGAPROX_LOG_DIR': str(logs)}, tmp_path)
    assert got['LOG_DIR'] == str(logs)
    assert got['CONFIG_DIR'] == 'config', 'moving the logs moved the config too'


def test_a_nested_path_is_created_not_refused(tmp_path):
    """mkdir without parents=True fails on the first run for exactly the layout
    people will use (/srv/backup/pegaprox/config)."""
    target = tmp_path / 'a' / 'b' / 'c'
    _constants_with({'PEGAPROX_CONFIG_DIR': str(target)}, tmp_path)
    assert target.is_dir()


def test_the_config_directory_keeps_its_private_mode(tmp_path):
    """It holds the master key and the encrypted database. 0700 is not optional
    just because the path moved."""
    target = tmp_path / 'private'
    _constants_with({'PEGAPROX_CONFIG_DIR': str(target)}, tmp_path)
    mode = oct(os.stat(target).st_mode & 0o777)
    assert mode == '0o700', f'mode is {mode}'


def test_a_blank_value_falls_back_instead_of_writing_to_the_root(tmp_path):
    """PEGAPROX_CONFIG_DIR= in a unit file is a realistic accident."""
    got = _constants_with({'PEGAPROX_CONFIG_DIR': '   ', 'PEGAPROX_LOG_DIR': ''}, tmp_path)
    assert got['CONFIG_DIR'] == 'config'
    assert got['LOG_DIR'] == 'logs'
