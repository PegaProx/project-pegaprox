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


# --- the other writer had the same bug ---------------------------------------------
# persist_host_keys() re-reads inside the lock and merges. verify_transport_host_key()
# did not: it loaded the file near the top of the function, did its lookup, and then took
# the lock only around save(). Anything pinned between that load and that save was
# written away. Aikido ai_pentest 700489044. MK


class _FakeTransport:
    def __init__(self, key):
        self._key = key

    def get_remote_server_key(self):
        return self._key


def test_tofu_via_transport_keeps_a_pin_written_in_the_meantime(known_hosts, monkeypatch):
    """The property: a key recorded by another writer after we loaded must survive.

    Drives the real interleaving - let verify_transport_host_key() get as far as its
    strict-mode check, have somebody else pin a different host, then let it save.
    """
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)

    other_key = _stable_key('other-host')
    new_key = _stable_key('new-host')

    # Somebody else's pin lands while we are mid-flight. strict_host_keys_enabled() is
    # the last thing called before the add/save, so it is the honest seam.
    def _racing_check():
        _pin_on_disk(known_hosts, 'other-host', other_key)
        return False
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', _racing_check)

    sec.verify_transport_host_key(_FakeTransport(new_key), 'new-host', paramiko, port=22)

    on_disk = _hosts_on_disk(known_hosts)
    assert 'new-host' in on_disk, 'the key we just verified was not pinned'
    assert 'other-host' in on_disk, \
        'a pin written while this call was in flight was erased'


def test_tofu_via_transport_still_pins_on_an_empty_file(known_hosts, monkeypatch):
    """The mirror: re-reading inside the lock must not stop it pinning at all."""
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    key = _stable_key('lonely-host')

    sec.verify_transport_host_key(_FakeTransport(key), 'lonely-host', paramiko, port=22)

    assert 'lonely-host' in _hosts_on_disk(known_hosts)


def test_a_non_standard_port_is_still_pinned_under_its_bracketed_name(known_hosts, monkeypatch):
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    key = _stable_key('port-host')

    sec.verify_transport_host_key(_FakeTransport(key), 'port-host', paramiko, port=2222)

    assert '[port-host]:2222' in _hosts_on_disk(known_hosts)


# --- a file we cannot read must not be replaced -------------------------------------
# Both writers reloaded inside the lock and, when that load failed, carried on with an
# EMPTY set and saved - replacing known_hosts with just what the caller happened to hold.
# paramiko's load() raises ValueError on a truncated entry and it raises for the whole
# file, so one half-written line (what an interrupted save leaves) lost every good pin
# before it. Losing a pin puts that host back on trust-on-first-use; failing to add one
# only means the next connect pins it. So: do not write when we could not read. MK


def _corrupt_after_a_good_pin(path, host, key):
    """A valid entry followed by a truncated one - the shape an interrupted save leaves."""
    _pin_on_disk(path, host, key)
    with open(path, 'a') as f:
        f.write('half-written ssh-rsa AAAAB3NzaC1yc2EAAAAD\n')


def _raw(path):
    with open(path) as f:
        return f.read()


def test_persist_does_not_replace_a_file_it_could_not_parse(known_hosts):
    good = _stable_key('good-host')
    _corrupt_after_a_good_pin(known_hosts, 'good-host', good)
    before = _raw(known_hosts)

    sec.persist_host_keys(_client_holding(('other-host', _stable_key('other-host'))))

    assert _raw(known_hosts) == before, \
        'the unreadable file was overwritten, taking the pins in it with it'


def test_tofu_via_transport_does_not_replace_a_file_it_could_not_parse(known_hosts, monkeypatch):
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    good = _stable_key('good-host-2')
    _corrupt_after_a_good_pin(known_hosts, 'good-host-2', good)
    before = _raw(known_hosts)

    try:
        sec.verify_transport_host_key(
            _FakeTransport(_stable_key('new-host-2')), 'new-host-2', paramiko, port=22)
    except Exception:
        pass  # the caller's connect try/except owns this; the file is what matters

    assert _raw(known_hosts) == before, \
        'the unreadable file was overwritten, taking the pins in it with it'


def test_a_readable_file_is_still_written(known_hosts):
    """The mirror: refusing to write on a read error must not stop ordinary persistence."""
    sec.persist_host_keys(_client_holding(('fresh-host', _stable_key('fresh-host'))))
    assert 'fresh-host' in _hosts_on_disk(known_hosts)
