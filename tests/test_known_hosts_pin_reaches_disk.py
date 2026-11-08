"""A host is trusted on first use only when its pin can be stored, and a failed write
must not take other pins with it.

verify_transport_host_key() pins an unknown host and returns, and the caller sends the
password. When the save failed (read-only file, disk full) the error was swallowed and
the function returned as if the key were pinned. Nothing was stored, so the next connect
met an unknown host again and trusted whatever key it was shown, with no log line. The
SSHClient path did the same: the policy took the key in memory and persist_host_keys()
dropped the failed save after the login. The Transport path now refuses when the save
fails, and the policy refuses before the login when known_hosts or its folder cannot be
written, the way an unreadable file is refused. A save that still fails after that is
logged. Hosts already pinned keep working.

paramiko's save() also truncates before it writes, so a write that failed half way left
a shorter file that still parsed, and every pin after the cut read as unknown. known_hosts
is now written to a temp file next to it and renamed over.
MK Oct 2026
"""
import errno
import logging
import os
import stat

import paramiko
import pytest

import pegaprox.utils.ssh_security as sec

_KEYS = {}

needs_non_root = pytest.mark.skipif(os.geteuid() == 0, reason='root writes read-only files')


def _key(name):
    if name not in _KEYS:
        _KEYS[name] = paramiko.RSAKey.generate(1024)
    return _KEYS[name]


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    folder = tmp_path / 'config'
    folder.mkdir()
    path = str(folder / '.ssh_known_hosts')
    monkeypatch.setattr(sec, '_KNOWN_HOSTS', path)
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    monkeypatch.setattr(sec, 'pins_host_keys_here', lambda: True)
    yield path
    os.chmod(str(folder), 0o700)
    if os.path.exists(path):
        os.chmod(path, 0o600)


class _Transport:
    def __init__(self, key):
        self._key = key

    def get_remote_server_key(self):
        return self._key


def _pin(path, *hosts):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    for host in hosts:
        hk.add(host, _key(host).get_name(), _key(host))
    hk.save(path)


def _raw(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def _disk(path):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    return hk


def _no_space(self, filename):
    raise OSError(errno.ENOSPC, 'No space left on device')


def _disk_full_after_one_line(monkeypatch):
    """save() writes its first entry and then runs out of space."""
    def _half(self, filename):
        with open(filename, 'w') as f:
            f.write(self._entries[0].to_line())
        raise OSError(errno.ENOSPC, 'No space left on device')
    monkeypatch.setattr(paramiko.hostkeys.HostKeys, 'save', _half)


def _leftovers(path):
    folder = os.path.dirname(path)
    return sorted(n for n in os.listdir(folder) if n != os.path.basename(path))


# --- the Transport path: the pin is written before the password -------------------------

def test_transport_refuses_first_use_when_the_pin_cannot_be_saved(known_hosts, monkeypatch):
    _pin(known_hosts, 'node-a')
    real_save = paramiko.hostkeys.HostKeys.save
    monkeypatch.setattr(paramiko.hostkeys.HostKeys, 'save', _no_space)

    for offered in ('genuine', 'attacker'):
        with pytest.raises(paramiko.SSHException, match='could not be written'):
            sec.verify_transport_host_key(_Transport(_key(offered)), 'node-new', paramiko)
    assert _disk(known_hosts).lookup('node-new') is None

    # counterproof: a host pinned before keeps verifying, both ways, with saving still broken
    sec.verify_transport_host_key(_Transport(_key('node-a')), 'node-a', paramiko)
    with pytest.raises(paramiko.BadHostKeyException):
        sec.verify_transport_host_key(_Transport(_key('attacker')), 'node-a', paramiko)

    # and once the disk takes it again, first use pins as before
    monkeypatch.setattr(paramiko.hostkeys.HostKeys, 'save', real_save)
    sec.verify_transport_host_key(_Transport(_key('genuine')), 'node-new', paramiko)
    assert _disk(known_hosts).lookup('node-new')['ssh-rsa'] == _key('genuine')
    with pytest.raises(paramiko.BadHostKeyException):
        sec.verify_transport_host_key(_Transport(_key('attacker')), 'node-new', paramiko)


@needs_non_root
def test_transport_refuses_first_use_on_a_read_only_file(known_hosts):
    """A rename would get past a read-only file; the in-place write it replaces did not."""
    _pin(known_hosts, 'node-a')
    os.chmod(known_hosts, 0o444)
    before = _raw(known_hosts)

    with pytest.raises(paramiko.SSHException, match='could not be written'):
        sec.verify_transport_host_key(_Transport(_key('node-new')), 'node-new', paramiko)
    assert _raw(known_hosts) == before

    sec.verify_transport_host_key(_Transport(_key('node-a')), 'node-a', paramiko)


@needs_non_root
def test_transport_refuses_first_use_when_the_folder_takes_no_new_file(known_hosts):
    os.chmod(os.path.dirname(known_hosts), 0o500)

    with pytest.raises(paramiko.SSHException, match='could not be written'):
        sec.verify_transport_host_key(_Transport(_key('node-new')), 'node-new', paramiko)
    assert not os.path.exists(known_hosts)


# --- the SSHClient path: the policy checks before login that the save can happen ----------

@needs_non_root
def test_client_policy_refuses_first_use_when_known_hosts_is_read_only(known_hosts):
    _pin(known_hosts, 'node-a')
    os.chmod(known_hosts, 0o444)
    client = sec.apply_host_key_policy(paramiko.SSHClient(), paramiko)

    with pytest.raises(paramiko.SSHException, match='could not be written'):
        client._policy.missing_host_key(client, 'node-new', _key('node-new'))
    assert client.get_host_keys().lookup('node-new') is None
    # the pinned host is loaded as before, so paramiko checks it against its pin
    assert client.get_host_keys().lookup('node-a')['ssh-rsa'] == _key('node-a')


@needs_non_root
def test_client_policy_refuses_first_use_when_the_folder_takes_no_new_file(known_hosts):
    os.chmod(os.path.dirname(known_hosts), 0o500)
    client = sec.apply_host_key_policy(paramiko.SSHClient(), paramiko)

    with pytest.raises(paramiko.SSHException, match='could not be written'):
        client._policy.missing_host_key(client, 'node-new', _key('node-new'))


def test_client_policy_still_pins_first_use_on_a_writable_file(known_hosts):
    """The mirror: a healthy file keeps trust-on-first-use."""
    _pin(known_hosts, 'node-a')
    client = sec.apply_host_key_policy(paramiko.SSHClient(), paramiko)

    client._policy.missing_host_key(client, 'node-new', _key('node-new'))
    sec.persist_host_keys(client)

    on_disk = _disk(known_hosts)
    assert on_disk.lookup('node-new')['ssh-rsa'] == _key('node-new')
    assert on_disk.lookup('node-a')['ssh-rsa'] == _key('node-a')


def test_a_failed_persist_is_logged_not_raised(known_hosts, monkeypatch, caplog):
    monkeypatch.setattr(paramiko.hostkeys.HostKeys, 'save', _no_space)
    client = paramiko.SSHClient()
    client.get_host_keys().add('node-new', 'ssh-rsa', _key('node-new'))

    with caplog.at_level(logging.WARNING, logger='pegaprox.ssh'):
        sec.persist_host_keys(client)   # must not raise

    assert any('not pinned' in r.getMessage() for r in caplog.records), caplog.text


# --- a write that fails half way leaves the old file whole ---------------------------------

def test_a_half_written_persist_keeps_every_pin(known_hosts, monkeypatch):
    _pin(known_hosts, 'node-a', 'node-b', 'node-c')
    before = _raw(known_hosts)
    _disk_full_after_one_line(monkeypatch)
    client = paramiko.SSHClient()
    client.get_host_keys().add('node-new', 'ssh-rsa', _key('node-new'))

    sec.persist_host_keys(client)

    assert _raw(known_hosts) == before, 'a failed write shortened known_hosts'
    assert _leftovers(known_hosts) == []


def test_a_half_written_transport_pin_keeps_every_pin(known_hosts, monkeypatch):
    _pin(known_hosts, 'node-a', 'node-b', 'node-c')
    before = _raw(known_hosts)
    _disk_full_after_one_line(monkeypatch)

    with pytest.raises(paramiko.SSHException, match='could not be written'):
        sec.verify_transport_host_key(_Transport(_key('node-new')), 'node-new', paramiko)

    assert _raw(known_hosts) == before, 'a failed write shortened known_hosts'
    assert _leftovers(known_hosts) == []


def test_a_half_written_removal_keeps_every_other_pin(known_hosts, monkeypatch):
    _pin(known_hosts, 'node-a', 'node-b', 'node-c')
    before = _raw(known_hosts)
    real_open = open

    class _Full:
        def __init__(self, f):
            self.f = f

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.f.close()

        def writelines(self, lines):
            self.f.write(list(lines)[0])
            raise OSError(errno.ENOSPC, 'No space left on device')

    def _open(path, mode='r', *a, **kw):
        f = real_open(path, mode, *a, **kw)
        return _Full(f) if 'w' in mode else f
    monkeypatch.setattr(sec, 'open', _open, raising=False)

    sec.remove_host_keys(['node-a'])

    assert _raw(known_hosts) == before, 'a failed removal shortened known_hosts'
    assert _leftovers(known_hosts) == []

    # counterproof: with room on the disk the removal goes through and keeps the rest
    monkeypatch.setattr(sec, 'open', real_open)
    assert sec.remove_host_keys(['node-a']) == 1
    assert sorted(_disk(known_hosts).keys()) == ['node-b', 'node-c']


def test_the_rewritten_file_keeps_its_mode_and_its_link(known_hosts, tmp_path):
    """The rename swaps the file, so what the old in-place write kept must carry over."""
    real = tmp_path / 'elsewhere' / 'known_hosts'
    real.parent.mkdir()
    _pin(str(real), 'node-a')
    os.chmod(str(real), 0o640)
    os.symlink(str(real), known_hosts)

    sec.verify_transport_host_key(_Transport(_key('node-new')), 'node-new', paramiko)

    assert os.path.islink(known_hosts)
    assert stat.S_IMODE(os.stat(str(real)).st_mode) == 0o640
    assert sorted(_disk(str(real)).keys()) == ['node-a', 'node-new']
    assert os.listdir(str(real.parent)) == ['known_hosts']
