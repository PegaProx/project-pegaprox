"""The node shell pins a host key only where the pin can be stored, and before the login.

The node shell used to run in its own process from a script with its own copy of the
host-key policy, which never picked up what utils/ssh_security.py does since the save of
a new host key may fail: refuse first use when known_hosts or its folder cannot be
written, and write the file through a temp file and a rename. Its policy took any unknown
key in memory, logged in, and dropped the failed save without a word, so the next shell
to that node trusted whatever key it met again.

That process is gone (Nov 2026). The only node shell is the main port route, which asks
apply_host_key_policy before the connect and persist_host_keys after it. These tests run
it with the real ssh_security against a known_hosts in a temp folder and a stand-in SSH
client whose connect asks the policy the way paramiko does, so "logins" is what reached
the node with the password. The policy and the write on their own are covered by
test_known_hosts_pin_reaches_disk.py and test_host_key_persist_merge.py.
MK Nov 2026
"""
import json
import os

import paramiko
import pytest

import pegaprox.api.vms as vms
import pegaprox.utils.ssh_security as sec
from test_node_shell_target_1143 import _cluster, _let_go, _token  # noqa: F401

NODE = '10.0.0.12'
_KEYS = {}

needs_non_root = pytest.mark.skipif(os.geteuid() == 0, reason='root writes read-only files')


def _key(name, kind=paramiko.RSAKey):
    if (name, kind) not in _KEYS:
        _KEYS[(name, kind)] = kind.generate(1024) if kind is paramiko.RSAKey else kind.generate()
    return _KEYS[(name, kind)]


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    folder = tmp_path / 'config'
    folder.mkdir()
    path = str(folder / '.ssh_known_hosts')
    monkeypatch.setattr(sec, '_KNOWN_HOSTS', path)
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    yield path
    os.chmod(str(folder), 0o700)
    if os.path.exists(path):
        os.chmod(path, 0o600)


class _Page:
    def __init__(self, *incoming):
        self.incoming = list(incoming)
        self.sent = []

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        return self.incoming.pop(0) if self.incoming else None

    def close(self, *a, **k):
        pass


def _client_class(server_key, logins, on_connect=None):
    class _Client(paramiko.SSHClient):
        """connect() checks the host key the way SSHClient.connect does, then logs in."""

        def connect(self, hostname, port=22, username=None, password=None, **kw):
            if on_connect:
                on_connect()
            name = hostname if port == 22 else f'[{hostname}]:{port}'
            known = self._host_keys.lookup(name)
            if known is None:
                self._policy.missing_host_key(self, name, server_key)
            else:
                ours = known.get(server_key.get_name()) or list(known.values())[0]
                if ours != server_key:
                    raise paramiko.BadHostKeyException(name, server_key, ours)
            logins.append((hostname, username, password))

        def invoke_shell(self, **kw):
            raise paramiko.SSHException('the test opens no shell')
    return _Client


def open_shell(api, seed, monkeypatch, server_key, on_connect=None):
    """One node shell to pve2 (NODE) through the main port route with a password, the
    real host-key handling of ssh_security around it. (logins, what the page was told)"""
    logins = []
    monkeypatch.setattr(paramiko, 'SSHClient', _client_class(server_key, logins, on_connect))
    # what vms imported is what the shell calls: the real functions, nothing in between
    assert vms.apply_host_key_policy is sec.apply_host_key_policy
    assert vms.persist_host_keys is sec.persist_host_keys
    _cluster(api)
    tok = _token(api, seed.user('root', role='admin'))
    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    page = _Page(json.dumps({'username': 'root', 'password': 'secret'}))
    with api.app.test_request_context(f'/api/clusters/cluster_1/nodes/pve2/shellws?token={tok}'):
        view(page, 'cluster_1', 'pve2')
    return logins, ''.join(m for m in page.sent if isinstance(m, str))


def pin(path, host, key):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    hk.add(host, key.get_name(), key)
    hk.save(path)


def raw(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def disk(path):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    return hk


def _leftovers(path):
    folder = os.path.dirname(path)
    return sorted(n for n in os.listdir(folder) if n != os.path.basename(path))


OPENED = 'the test opens no shell'


# --- first use only with a known_hosts that takes the pin ---------------------------------

@needs_non_root
def test_a_folder_that_takes_no_new_file_refuses_first_use_before_the_login(api, seed, monkeypatch,
                                                                            known_hosts):
    os.chmod(os.path.dirname(known_hosts), 0o500)

    for offered in ('genuine', 'other'):
        logins, said = open_shell(api, seed, monkeypatch, _key(offered))
        assert logins == [], 'the password went to a host whose key was never pinned'
        assert 'could not be written' in said and OPENED not in said, said
    assert not os.path.exists(known_hosts)


@needs_non_root
def test_a_read_only_known_hosts_refuses_first_use_before_the_login(api, seed, monkeypatch,
                                                                    known_hosts):
    pin(known_hosts, 'node-a', _key('node-a'))
    os.chmod(known_hosts, 0o444)
    before = raw(known_hosts)

    logins, said = open_shell(api, seed, monkeypatch, _key('genuine'))
    assert logins == []
    assert 'could not be written' in said, said
    assert raw(known_hosts) == before


@needs_non_root
def test_a_pinned_host_still_opens_with_known_hosts_read_only(api, seed, monkeypatch, known_hosts):
    """Counterproof: the refusal is about first use only. A node whose key is on disk
    already needs no write and keeps its shell."""
    pin(known_hosts, NODE, _key('node'))
    os.chmod(known_hosts, 0o444)

    logins, said = open_shell(api, seed, monkeypatch, _key('node'))
    assert logins == [(NODE, 'root', 'secret')], said


def test_a_writable_known_hosts_pins_on_first_use_and_holds_the_pin(api, seed, monkeypatch,
                                                                    known_hosts):
    pin(known_hosts, 'node-a', _key('node-a'))

    logins, said = open_shell(api, seed, monkeypatch, _key('genuine'))
    assert logins == [(NODE, 'root', 'secret')], said
    assert disk(known_hosts).lookup(NODE)['ssh-rsa'] == _key('genuine')
    assert disk(known_hosts).lookup('node-a')['ssh-rsa'] == _key('node-a')
    assert _leftovers(known_hosts) == []

    # the next shell meets another key, of the same type or another, and is refused
    # before the login
    for other in (_key('other'), _key('other', paramiko.ECDSAKey)):
        logins, said = open_shell(api, seed, monkeypatch, other)
        assert logins == [], said
        assert 'SSH error' in said and 'does not match' in said, said
    assert disk(known_hosts).lookup(NODE)['ssh-rsa'] == _key('genuine')


def test_strict_mode_refuses_first_use_in_the_shell(api, seed, monkeypatch, known_hosts):
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: True)
    logins, said = open_shell(api, seed, monkeypatch, _key('genuine'))
    assert logins == [] and 'strict host-key checking' in said, said
    assert not os.path.exists(known_hosts)
    # counterproof: a node seeded out of band opens
    pin(known_hosts, NODE, _key('genuine'))
    logins, said = open_shell(api, seed, monkeypatch, _key('genuine'))
    assert logins == [(NODE, 'root', 'secret')], said


# --- a standby that serves users (#625) -----------------------------------------------------

def _standby(monkeypatch):
    """A warm standby the leader made serve users: consoles open here, but its
    known_hosts is the leader's copy that the next sync replaces."""
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'serving', lambda: True)


def test_a_serving_standby_opens_a_shell_to_a_node_the_leader_pinned_only(api, seed, monkeypatch,
                                                                          known_hosts):
    pin(known_hosts, NODE, _key('node'))
    _standby(monkeypatch)

    # the key the leader pinned goes through, and nothing is written
    before = raw(known_hosts)
    logins, said = open_shell(api, seed, monkeypatch, _key('node'))
    assert logins == [(NODE, 'root', 'secret')], said
    assert raw(known_hosts) == before

    # a node the leader has not pinned is no first use here
    os.unlink(known_hosts)
    logins, said = open_shell(api, seed, monkeypatch, _key('node'))
    assert logins == [], said
    assert f'host key of {NODE} is not known here yet' in said, said
    assert not os.path.exists(known_hosts)


def test_the_same_shell_pins_on_first_use_off_a_standby(api, seed, monkeypatch, known_hosts):
    """Counterproof: the instance that acts trusts the node on first sight."""
    logins, said = open_shell(api, seed, monkeypatch, _key('node'))
    assert logins == [(NODE, 'root', 'secret')], said
    assert disk(known_hosts).lookup(NODE) is not None
