"""One SSH login for every path to a PVE node (#1322).

A cluster with the API user 'someuser@pve!token', a stored key and a sudo account on the
nodes: everything through _ssh_connect logged in as 'someuser', while the sensor and
in-band BMC reads went as root, every hour, from the metrics collector. About half the
paths took the API user's name, the other half root; nine HA paths took the name even
with an SSH user set. The rule now is the one the dialog and the docs state: the SSH
user, root when none is set.

The cluster password only goes along for the login it belongs to: an @pam account's for
that same user, no other realm's at all.

MK Nov 2026
"""
import os
import re
import types

import pytest

import pegaprox
from pegaprox.utils.ssh import node_login, ssh_password_for
from test_node_exec_stored_key_1224 import _fake_paramiko, _real_manager

PKG = os.path.dirname(pegaprox.__file__)


def _cfg(**kw):
    base = dict(user='root@pam', pass_='pw', ssh_user='', ssh_key='', ssh_disabled=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


# --- the rule ---------------------------------------------------------------------------

@pytest.mark.parametrize('ssh_user,user,login', [
    ('', 'someuser@pve!token', 'root'),
    ('', 'pegaprox@pve', 'root'),
    ('', 'admin@pam', 'root'),
    ('ops', 'root@pam', 'ops'),
    (' ops ', 'root@pam', 'ops'),
    (None, 'admin@pam', 'root'),
])
def test_the_login_is_the_ssh_user_else_root(ssh_user, user, login):
    assert node_login(_cfg(ssh_user=ssh_user, user=user)) == login


@pytest.mark.parametrize('user,ssh_user,offered', [
    ('root@pam', '', True),
    ('root@pam', 'root', True),
    ('admin@pam', 'admin', True),
    ('root', '', True),                 # no realm, as an XCP-ng host has it
    ('admin@pam', '', False),           # admin's password, root's login
    ('root@pam', 'ops', False),         # root's password, ops' login
    ('pegaprox@pve', '', False),        # a PVE realm password is none on the node
    ('pegaprox@pve', 'pegaprox', False),
    ('ldapuser@corp', 'ldapuser', False),
    ('root@pam!pegaprox', '', False),   # the token secret
])
def test_the_cluster_password_goes_only_to_the_login_it_belongs_to(user, ssh_user, offered):
    assert ssh_password_for(_cfg(user=user, ssh_user=ssh_user)) == ('pw' if offered else '')


def test_no_password_with_ssh_switched_off():
    assert ssh_password_for(_cfg(ssh_disabled=True)) == ''


# --- the paths --------------------------------------------------------------------------

def test_ssh_connect_logs_in_as_root_on_a_token_cluster_without_an_ssh_user(db, monkeypatch):
    """The reported setup: node shell, rolling updates and the checks went as 'ops'."""
    seen = []
    _fake_paramiko(monkeypatch, seen)
    m = _real_manager()
    assert m._ssh_connect('10.0.0.7', retries=1, failure={}) is not None
    assert seen[0]['username'] == 'root'


def test_ssh_connect_logs_in_as_the_ssh_user(db, monkeypatch):
    seen = []
    _fake_paramiko(monkeypatch, seen)
    m = _real_manager(ssh_user='someuser')
    assert m._ssh_connect('10.0.0.7', retries=1, failure={}) is not None
    assert seen[0]['username'] == 'someuser'


def _sensor_manager(**cfg):
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(**dict(dict(user='someuser@pve!token', pass_='secret',
                                                 ssh_user='', ssh_key='KEY', ssh_disabled=False), **cfg))
    m.ssh_blocked_reason = lambda **k: None
    m.is_connected = True
    m._get_node_ip = lambda node: '10.0.0.7'
    return m


@pytest.mark.parametrize('ssh_user,login', [('', 'root'), ('someuser', 'someuser')])
def test_the_sensor_read_logs_in_as_every_other_path(ssh_user, login):
    m = _sensor_manager(ssh_user=ssh_user)
    seen = []
    m._ssh_read_output = lambda ip, user, cmd, timeout=30: seen.append(user) or None
    m.get_node_sensors('pve1')
    assert seen == [login]


@pytest.mark.parametrize('ssh_user,login', [('', 'root'), ('someuser', 'someuser')])
def test_the_inband_bmc_read_logs_in_as_every_other_path(ssh_user, login):
    from pegaprox.core import bmc
    m = _sensor_manager(ssh_user=ssh_user)
    seen = []
    m._ssh_run_command_with_key_output = lambda ip, user, cmd, key, timeout=15: seen.append(user) or None
    m._ssh_run_command_output = lambda ip, user, cmd, timeout=15: seen.append(user) or None
    m.ssh_password_to_offer = lambda host: ''
    bmc.read_node_bmc_inband(m, 'pve1')
    assert seen and set(seen) == {login}


def test_the_connection_check_names_the_login_it_makes():
    from pegaprox.core import conncheck
    assert conncheck._ssh_user(types.SimpleNamespace(config=_cfg(user='pegaprox@pve'))) == 'root'
    assert conncheck._ssh_user(types.SimpleNamespace(config=_cfg(ssh_user='ops'))) == 'ops'


# Every PVE node path asks node_login. PBS, XCP-ng and the ESXi hosts have their own
# configs and rules; these files are not walked.
_OWN_RULES = {'core/pbs.py', 'core/xcpng.py', 'core/esxi_cluster.py', 'utils/ssh.py', 'utils/oidc.py'}
_DERIVED = re.compile(r"split\(['\"]@['\"]\)\[0\]")
_ROOT_DEFAULT = re.compile(r"ssh_user['\"]?\s*,\s*(None|''|\"\")\s*\)\s*or\s*(['\"]root|\()"
                           r"|\.ssh_user\s+(or\s*['\"]root|if\b)")
# api_password_for compares the login with the @pam account's name, it derives no login
_ALLOWED = {('core/manager.py', "if login != user.split('@')[0]:")}


def test_no_path_derives_the_login_on_its_own():
    found = []
    for root, _dirs, files in os.walk(PKG):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, PKG).replace(os.sep, '/')
            if rel in _OWN_RULES:
                continue
            with open(path, encoding='utf-8') as f:
                for no, line in enumerate(f, 1):
                    code = line.split('#', 1)[0].strip()
                    if not code or (rel, code) in _ALLOWED:
                        continue
                    if _DERIVED.search(code) or _ROOT_DEFAULT.search(code):
                        found.append(f'{rel}:{no}: {code}')
    assert found == [], 'a login of its own instead of node_login():\n' + '\n'.join(found)
