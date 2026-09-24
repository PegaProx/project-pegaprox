"""Persisting one SSH client's host keys must not erase everybody else's pins.

persist_host_keys() was a bare client.save_host_keys(), and paramiko writes the set the
client loaded when it was built, truncating the file. So anything pinned after that
client connected was thrown away on its way out:

  * a keyboard-interactive login, which pins through verify_transport_host_key() on a
    Transport we build ourselves - a different code path with its own file write, and
    the reason that function exists at all;
  * any second client that happened to learn a host first.

An erased pin is not a loud failure. The host simply reads as unknown next time and is
trust-on-first-use'd again, which is the exact property the pin was there to remove -
and with strict host keys on it turns into a refused connection instead.

Aikido ai_pentest 700486900. MK
"""
import os

import paramiko
import pytest

import pegaprox.utils.ssh_security as sec


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    path = str(tmp_path / 'ssh_known_hosts')
    monkeypatch.setattr(sec, '_KNOWN_HOSTS', path)
    return path



_KEYS = {}


def _stable_key(name):
    if name not in _KEYS:
        _KEYS[name] = paramiko.RSAKey.generate(1024)
    return _KEYS[name]


def _client_holding(*entries):
    """A paramiko SSHClient whose in-memory host keys are exactly `entries`."""
    c = paramiko.SSHClient()
    for host, key in entries:
        c.get_host_keys().add(host, key.get_name(), key)
    return c


def _pin_on_disk(path, host, key):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    hk.add(host, key.get_name(), key)
    hk.save(path)


def _hosts_on_disk(path):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    return sorted(hk.keys())


def test_a_pin_written_after_the_client_connected_survives(known_hosts):
    """The Transport path: it pins straight into the file while a client is still open."""
    old = _stable_key('a')
    client = _client_holding(('node-a', old))          # client built here...
    _pin_on_disk(known_hosts, 'node-b', _stable_key('b'))   # ...pin added afterwards

    sec.persist_host_keys(client)

    assert _hosts_on_disk(known_hosts) == ['node-a', 'node-b']


def test_two_clients_do_not_erase_each_others_hosts(known_hosts):
    first = _client_holding(('node-a', _stable_key('a')))
    second = _client_holding(('node-b', _stable_key('b')))

    sec.persist_host_keys(first)
    sec.persist_host_keys(second)

    assert _hosts_on_disk(known_hosts) == ['node-a', 'node-b']


def test_the_stored_key_wins_over_a_stale_one_in_memory(known_hosts):
    """A client carrying an outdated key for a host must not push it back over the
    pin somebody just recorded - that is a downgrade, not a persist."""
    current = _stable_key('b')
    _pin_on_disk(known_hosts, 'node-a', current)
    stale = _stable_key('a')
    client = _client_holding(('node-a', stale))

    sec.persist_host_keys(client)

    hk = paramiko.hostkeys.HostKeys()
    hk.load(known_hosts)
    assert hk.lookup('node-a')[current.get_name()] == current


def test_a_new_host_is_still_written(known_hosts):
    """The thing the function is for."""
    sec.persist_host_keys(_client_holding(('node-new', _stable_key('a'))))

    assert _hosts_on_disk(known_hosts) == ['node-new']


def test_nothing_new_leaves_the_file_untouched(known_hosts):
    key = _stable_key('a')
    _pin_on_disk(known_hosts, 'node-a', key)
    before = os.stat(known_hosts).st_mtime_ns

    sec.persist_host_keys(_client_holding(('node-a', key)))

    assert os.stat(known_hosts).st_mtime_ns == before


def test_a_read_only_directory_is_not_fatal(known_hosts, monkeypatch):
    """Best-effort is part of the contract - an appliance can ship a read-only config."""
    def _boom(*a, **kw):
        raise PermissionError('read-only file system')
    monkeypatch.setattr(paramiko.hostkeys.HostKeys, 'save', _boom)

    sec.persist_host_keys(_client_holding(('node-a', _stable_key('a'))))   # must not raise
