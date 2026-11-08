"""A known_hosts file we cannot read, and a pin recorded while we were connecting.

Unreadable (#1115): paramiko's load() raises on a truncated entry (what an interrupted
save leaves) and on a file it may not open, and keeps only what came before. Every
loader swallowed that, so each pin behind the damaged line read as an unknown host and
was trusted on first use, before the password went out. persist_host_keys() refuses to
write such a file, so the state repeated on every connect. Now a host missing from what
could be read is refused; a host whose pin did load still verifies.

The race (#1025): verify_transport_host_key() re-read the file inside the lock and then
add()ed its key, replacing a pin another first-use connection had saved since the
lookup. The SSH console server did worse: save_host_keys() wrote the set it loaded
before connecting over the file. The pin on disk wins now.

NS Oct 2026
"""
import asyncio
import json
import os
import types

import paramiko
import pytest

import pegaprox.utils.ssh_security as sec
from test_ha_v2_surface import _AsyncWS, _Resp, _ssh_server, SHELL

_KEYS = {}


def _key(name, kind=paramiko.RSAKey):
    if (name, kind) not in _KEYS:
        _KEYS[(name, kind)] = kind.generate(1024) if kind is paramiko.RSAKey else kind.generate()
    return _KEYS[(name, kind)]


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    path = str(tmp_path / 'ssh_known_hosts')
    monkeypatch.setattr(sec, '_KNOWN_HOSTS', path)
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    return path


def _pin(path, host, key):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    hk.add(host, key.get_name(), key)
    hk.save(path)


def _damage(path):
    # a valid pin above, a half-written entry below: load() raises ValueError on it
    with open(path, 'a') as f:
        f.write('half-written ssh-rsa AAAAB3NzaC1yc2EAAAAD\n')


def _raw(path):
    with open(path) as f:
        return f.read()


def _disk(path):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    return hk


class _Transport:
    def __init__(self, key):
        self._key = key

    def get_remote_server_key(self):
        return self._key


# --- unreadable: the SSHClient paths --------------------------------------------------------

def test_client_policy_refuses_a_new_host_when_known_hosts_is_damaged(known_hosts):
    _pin(known_hosts, 'good-host', _key('good'))
    _damage(known_hosts)
    client = sec.apply_host_key_policy(paramiko.SSHClient(), paramiko)

    with pytest.raises(paramiko.SSHException, match='could not be read'):
        client._policy.missing_host_key(client, 'new-host', _key('new'))
    assert client.get_host_keys().lookup('new-host') is None
    # the pin in front of the damaged line still loaded, so that host verifies as before
    assert client.get_host_keys().lookup('good-host')[_key('good').get_name()] == _key('good')


@pytest.mark.skipif(os.geteuid() == 0, reason='root reads a mode 000 file')
def test_client_policy_refuses_when_known_hosts_cannot_be_opened(known_hosts):
    _pin(known_hosts, 'good-host', _key('good'))
    os.chmod(known_hosts, 0)
    try:
        client = sec.apply_host_key_policy(paramiko.SSHClient(), paramiko)
        with pytest.raises(paramiko.SSHException, match='could not be read'):
            client._policy.missing_host_key(client, 'good-host', _key('attacker'))
    finally:
        os.chmod(known_hosts, 0o600)


def test_client_policy_still_trusts_first_use_on_a_readable_file(known_hosts):
    """The mirror: a healthy file keeps trust-on-first-use as it was."""
    _pin(known_hosts, 'good-host', _key('good'))
    client = sec.apply_host_key_policy(paramiko.SSHClient(), paramiko)

    client._policy.missing_host_key(client, 'new-host', _key('new'))
    sec.persist_host_keys(client)

    assert _disk(known_hosts).lookup('new-host')[_key('new').get_name()] == _key('new')


# --- unreadable: the Transport path ---------------------------------------------------------

def test_transport_refuses_a_new_host_when_known_hosts_is_damaged(known_hosts):
    _pin(known_hosts, 'good-host', _key('good'))
    _damage(known_hosts)
    before = _raw(known_hosts)

    with pytest.raises(paramiko.SSHException, match='could not be read'):
        sec.verify_transport_host_key(_Transport(_key('new')), 'new-host', paramiko)
    assert _raw(known_hosts) == before

    # a pinned host in front of the damaged line is checked as before, both ways
    sec.verify_transport_host_key(_Transport(_key('good')), 'good-host', paramiko)
    with pytest.raises(paramiko.BadHostKeyException):
        sec.verify_transport_host_key(_Transport(_key('attacker')), 'good-host', paramiko)


def test_transport_still_pins_on_a_readable_file(known_hosts):
    sec.verify_transport_host_key(_Transport(_key('new')), 'new-host', paramiko, port=2222)
    assert _disk(known_hosts).lookup('[new-host]:2222') is not None


# --- the race: a pin saved between our lookup and our write ---------------------------------

def _racing(monkeypatch, path, host, key):
    """Somebody pins `host` with `key` after the lookup. strict_host_keys_enabled() is the
    last call before the locked write, so it is the seam (as in the persist-merge tests)."""
    def _check():
        _pin(path, host, key)
        return False
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', _check)


def test_a_racing_key_does_not_replace_a_pin_saved_meanwhile(known_hosts, monkeypatch):
    _racing(monkeypatch, known_hosts, 'node-a', _key('genuine'))

    with pytest.raises(paramiko.BadHostKeyException):
        sec.verify_transport_host_key(_Transport(_key('racer')), 'node-a', paramiko)

    assert _disk(known_hosts).lookup('node-a')['ssh-rsa'] == _key('genuine'), \
        'the racing key replaced the pin'


def test_a_racing_key_of_another_type_is_refused_too(known_hosts, monkeypatch):
    _racing(monkeypatch, known_hosts, 'node-a', _key('genuine', paramiko.ECDSAKey))

    with pytest.raises(paramiko.SSHException, match='unpinned key type'):
        sec.verify_transport_host_key(_Transport(_key('racer')), 'node-a', paramiko)
    assert 'ssh-rsa' not in _disk(known_hosts).lookup('node-a')


def test_the_same_key_pinned_meanwhile_is_accepted(known_hosts, monkeypatch):
    """Two first-use connections to the same genuine host: the second one goes through."""
    _racing(monkeypatch, known_hosts, 'node-a', _key('genuine'))
    sec.verify_transport_host_key(_Transport(_key('genuine')), 'node-a', paramiko)
    assert _disk(known_hosts).lookup('node-a')['ssh-rsa'] == _key('genuine')


# --- the SSH console server (the generated standalone script) -------------------------------

NODE = '192.0.2.10'


class _Browser(_AsyncWS):
    def __init__(self, path, *incoming):
        super().__init__(path)
        self.incoming = list(incoming)

    async def recv(self):
        if self.incoming:
            return self.incoming.pop(0)
        raise ConnectionError('nothing more to say')


def _run_shell(monkeypatch, path, server_key, on_connect=None):
    """Open a node shell through the script with real paramiko host-key handling; the
    connect meets `server_key` the way SSHClient.connect would."""
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', path)
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    # the main app names the node's own address; the connection host stands in for none (#1143)
    answer = _Resp(200, {'valid': True, 'known_hosts_only': False,
                         'cluster_context': {'host': NODE, 'node_ips': {'n1': NODE}}})
    ns, _asked = _ssh_server({'/api/ws/token/validate': answer})

    class _Client(paramiko.SSHClient):
        def connect(self, host, **kw):
            if on_connect:
                on_connect()
            pinned = self._host_keys.lookup(host)
            if pinned is None:
                self._policy.missing_host_key(self, host, server_key)
            elif pinned.get(server_key.get_name()) != server_key:
                raise paramiko.BadHostKeyException(host, server_key, pinned.get(server_key.get_name()))

        def invoke_shell(self, **kw):
            raise paramiko.SSHException('no shell in this test')

    fake = types.SimpleNamespace(**vars(paramiko))
    fake.SSHClient = _Client
    ns['paramiko'] = fake
    ws = _Browser(f'{SHELL}?token=t', json.dumps({'username': 'root', 'password': 'pw'}))
    asyncio.run(ns['ssh_handler'](ws))
    return ''.join(m for m in ws.sent if isinstance(m, str))


def test_console_refuses_a_new_host_when_known_hosts_is_damaged(known_hosts, monkeypatch):
    _pin(known_hosts, '192.0.2.99', _key('other'))
    _damage(known_hosts)
    before = _raw(known_hosts)

    said = _run_shell(monkeypatch, known_hosts, _key('node'))

    assert 'could not be read' in said and 'no shell in this test' not in said, said
    assert 'ValueError' not in said, 'the parse error went to the browser'
    assert _raw(known_hosts) == before, 'the damaged file was written over'


def test_console_still_opens_a_pinned_host_when_known_hosts_is_damaged(known_hosts, monkeypatch):
    _pin(known_hosts, NODE, _key('node'))
    _damage(known_hosts)
    before = _raw(known_hosts)

    said = _run_shell(monkeypatch, known_hosts, _key('node'))

    assert 'no shell in this test' in said, said
    assert _raw(known_hosts) == before


def test_console_keeps_a_pin_recorded_while_it_connected(known_hosts, monkeypatch):
    """The main app pins another node while this shell connects; the shell's save must
    not write its older picture of the file over that."""
    said = _run_shell(monkeypatch, known_hosts, _key('node'),
                      on_connect=lambda: _pin(known_hosts, '192.0.2.20', _key('other')))

    assert 'no shell in this test' in said, said
    on_disk = _disk(known_hosts)
    assert on_disk.lookup(NODE) is not None, 'first use no longer pins'
    assert on_disk.lookup('192.0.2.20') is not None, 'a pin recorded meanwhile was erased'


def test_console_does_not_replace_a_pin_with_its_first_use_key(known_hosts, monkeypatch):
    said = _run_shell(monkeypatch, known_hosts, _key('racer'),
                      on_connect=lambda: _pin(known_hosts, NODE, _key('genuine')))

    assert 'no shell in this test' in said, said
    assert _disk(known_hosts).lookup(NODE)['ssh-rsa'] == _key('genuine')
