"""The lock of the config directory on Windows (#1390).

ha.lock_config_dir took an flock, and without fcntl it returned None: on Windows a second
PegaProx on the same config directory ran next to the first, and --migrate-db, whose
_hold_config_dir gave up the same way, converted the database under a running PegaProx.
Both lock byte 0 of the lock file with msvcrt there now, as dbcrypto locks a conversion.

Windows is played on Linux: fcntl does not import, msvcrt is a fake that keeps byte range
locks per handle, os.pread and os.pwrite are gone, and a byte another handle locked can be
neither read nor written, as on Windows. MK Nov 2026
"""
import errno
import logging
import os
import sys
import types

import pytest

from pegaprox.cli import migrate_db
from pegaprox.core import dbcrypto, ha
from tests.test_db_encryption_first_start import (  # noqa: F401 - inst is a fixture by name
    inst, needs_sqlcipher, plain_db, plain_rows)


class FakeMsvcrt(types.ModuleType):
    """msvcrt.locking as Windows does it: bytes of a file held by one handle, and a closed
    handle holds nothing. calls keeps (inode, mode, offset, length) of every call."""
    LK_UNLCK, LK_LOCK, LK_NBLCK = 0, 1, 2

    def __init__(self):
        super().__init__('msvcrt')
        self.calls = []
        self.held = {}
        self.broken = None

    def _keys(self, fd, start, n):
        st = os.fstat(fd)
        return [(st.st_dev, st.st_ino, start + i) for i in range(n)]

    def locking(self, fd, mode, nbytes):
        at = os.lseek(fd, 0, os.SEEK_CUR)
        self.calls.append((os.fstat(fd).st_ino, mode, at, nbytes))
        if self.broken:
            raise OSError(self.broken, os.strerror(self.broken))
        keys = self._keys(fd, at, nbytes)
        if mode == self.LK_UNLCK:
            if any(self.held.get(k) != fd for k in keys):
                raise OSError(errno.EACCES, 'Permission denied')
            for k in keys:
                del self.held[k]
            return
        if any(self.held.get(k, fd) != fd for k in keys):
            raise OSError(errno.EACCES, 'Permission denied')
        for k in keys:
            self.held[k] = fd

    def on(self, path):
        """The calls on the file at `path`, without the inode."""
        ino = os.stat(path).st_ino
        return [c[1:] for c in self.calls if c[0] == ino]

    def check(self, fd, n):
        """What Windows does to a read or write of n bytes at the position of fd."""
        st = os.fstat(fd)
        if not any(k[:2] == (st.st_dev, st.st_ino) for k in self.held):
            return
        at = os.lseek(fd, 0, os.SEEK_CUR)
        if any(self.held.get(k, fd) != fd for k in self._keys(fd, at, n)):
            raise PermissionError(errno.EACCES, 'Permission denied')

    def drop(self, fd):
        for k in [k for k, v in self.held.items() if v == fd]:
            del self.held[k]


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setitem(sys.modules, 'fcntl', None)
    fake = FakeMsvcrt()
    monkeypatch.setitem(sys.modules, 'msvcrt', fake)
    monkeypatch.setattr(migrate_db, '_WINDOWS', True, raising=False)
    monkeypatch.setitem(ha._config_lock, 'fd', ha._config_lock['fd'])
    monkeypatch.delattr(os, 'pread')
    monkeypatch.delattr(os, 'pwrite')
    real_read, real_write, real_close = os.read, os.write, os.close

    def read(fd, n):
        fake.check(fd, n)
        return real_read(fd, n)

    def write(fd, data):
        fake.check(fd, len(data))
        return real_write(fd, data)

    def close(fd):
        fake.drop(fd)
        return real_close(fd)
    monkeypatch.setattr(os, 'read', read)
    monkeypatch.setattr(os, 'write', write)
    monkeypatch.setattr(os, 'close', close)
    return fake


def other_process(fake, path, pid):
    """Another process that runs PegaProx on the directory of `path`: its pid behind byte 0,
    and byte 0 locked by a handle of its own."""
    with open(path, 'wb') as f:
        f.write(f'\n{pid}\n'.encode())
    fd = os.open(path, os.O_RDWR)
    fake.locking(fd, fake.LK_NBLCK, 1)
    return fd


# --- ha.lock_config_dir ----------------------------------------------------------------------

def test_a_second_pegaprox_on_the_config_directory_is_refused_on_windows(tmp_path, windows):
    with pytest.raises(ImportError):
        import fcntl  # noqa: F401
    lock = tmp_path / '.pegaprox.lock'
    fd = ha.lock_config_dir(str(lock))
    try:
        with pytest.raises(ha.HaError) as e:
            ha.lock_config_dir(str(lock))
        assert str(e.value) == (f'Another PegaProx process {os.getpid()} runs on {tmp_path} - one config '
                                'directory takes one process')
        assert windows.on(lock) == [(windows.LK_NBLCK, 0, 1)] * 2
        # byte 0 is the lock, the pid is behind it where the refused one could read it
        assert lock.read_bytes() == f'\n{os.getpid()}\n'.encode()
        assert list(windows.held.values()) == [fd]
    finally:
        if fd is not None:
            os.close(fd)
    # and the lock goes with the handle
    fd = ha.lock_config_dir(str(lock))
    assert fd is not None
    os.close(fd)


def test_windows_names_the_other_process_that_holds_the_directory(tmp_path, windows):
    lock = tmp_path / '.pegaprox.lock'
    other = other_process(windows, lock, 4242)
    try:
        with pytest.raises(ha.HaError, match=f'Another PegaProx process 4242 runs on {tmp_path} '):
            ha.lock_config_dir(str(lock))
    finally:
        os.close(other)
    assert windows.held == {}


def test_a_lock_that_does_not_work_on_windows_does_not_keep_pegaprox_down(tmp_path, windows, caplog):
    windows.broken = errno.EINVAL
    with caplog.at_level(logging.WARNING):
        assert ha.lock_config_dir(str(tmp_path / '.pegaprox.lock')) is None
    assert 'running without the config directory lock' in caplog.text


def test_without_fcntl_and_msvcrt_pegaprox_still_starts(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'fcntl', None)
    monkeypatch.setitem(sys.modules, 'msvcrt', None)
    assert ha.lock_config_dir(str(tmp_path / '.pegaprox.lock')) is None


def test_linux_keeps_its_flock_and_the_pid_at_the_start_of_the_file(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'msvcrt', None)
    lock = tmp_path / '.pegaprox.lock'
    fd = ha.lock_config_dir(str(lock))
    try:
        assert fd is not None
        assert lock.read_bytes() == f'{os.getpid()}\n'.encode()
    finally:
        os.close(fd)


# --- migrate_db ------------------------------------------------------------------------------

@needs_sqlcipher
def test_the_cli_refuses_on_windows_while_pegaprox_runs(inst, windows, capsys):
    plain_db(inst.db)
    lock = inst.cfg / '.pegaprox.lock'
    srv = ha.lock_config_dir(str(lock))
    try:
        rc = migrate_db.main(['--db', inst.db, '--yes'])
        out = capsys.readouterr().out
        assert rc == 7, out
    finally:
        if srv is not None:
            os.close(srv)
    assert f'[BLOCKED] PegaProx (process {os.getpid()}) is running on {inst.cfg}. Nothing was changed.' in out
    assert 'Stop PegaProx first (its service, or the PegaProx process)' in out and 'systemctl' not in out
    assert dbcrypto.file_state(inst.db) == 'plain' and inst.leftovers() == []
    assert plain_rows(inst.db) == 50


@needs_sqlcipher
def test_no_pegaprox_starts_on_windows_while_the_cli_converts(inst, windows, monkeypatch):
    plain_db(inst.db)
    lock = inst.cfg / '.pegaprox.lock'
    lock.write_bytes(b'\n4242\n')   # left by the PegaProx that was stopped for this
    during = []
    real = migrate_db._convert

    def convert(*a):
        try:
            ha.lock_config_dir(str(lock))
            during.append('took it')
        except ha.HaError as e:
            during.append(str(e))
        return real(*a)
    monkeypatch.setattr(migrate_db, '_convert', convert)
    assert migrate_db.main(['--db', inst.db, '--yes']) == 0
    assert during == [f'Another PegaProx process {os.getpid()} runs on {inst.cfg} - one config directory '
                      'takes one process']
    assert dbcrypto.file_state(inst.db) == 'encrypted'
    # the run undid its lock before it closed the file, Windows lets go of a closed one late
    assert windows.on(lock) == [(windows.LK_NBLCK, 0, 1), (windows.LK_NBLCK, 0, 1),
                                (windows.LK_UNLCK, 0, 1)]
    fd = ha.lock_config_dir(str(lock))
    assert fd is not None
    os.close(fd)


def test_the_cli_names_the_other_process_on_windows(tmp_path, windows):
    lock = tmp_path / '.pegaprox.lock'
    other = other_process(windows, lock, 4242)
    try:
        with pytest.raises(RuntimeError, match=f'^PegaProx \\(process 4242\\) is running on {tmp_path}$'):
            migrate_db._hold_config_dir(str(tmp_path))
    finally:
        os.close(other)
    assert windows.held == {}


def test_the_cli_on_windows_creates_no_lock_file(tmp_path, windows):
    """Run as an administrator it would be a file the service account cannot open."""
    cfg = tmp_path / 'config'
    cfg.mkdir()
    assert migrate_db._hold_config_dir(str(cfg)) is None
    assert os.listdir(cfg) == [] and windows.calls == []


def test_the_cli_without_fcntl_and_msvcrt_goes_on_as_before(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'fcntl', None)
    monkeypatch.setitem(sys.modules, 'msvcrt', None)
    (tmp_path / '.pegaprox.lock').write_bytes(b'')
    assert migrate_db._hold_config_dir(str(tmp_path)) is None


@pytest.mark.parametrize('on_windows', [False, True])
def test_the_stop_advice_names_what_the_platform_has(tmp_path, monkeypatch, capsys, on_windows):
    monkeypatch.setattr(migrate_db, '_WINDOWS', on_windows, raising=False)
    monkeypatch.setattr(dbcrypto, 'BACKEND', 'sqlcipher')

    def running(folder):
        raise RuntimeError(f'PegaProx (process 4242) is running on {folder}')
    monkeypatch.setattr(migrate_db, '_hold_config_dir', running)
    assert migrate_db.main(['--db', str(tmp_path / 'pegaprox.db'), '--yes']) == 7
    advice = capsys.readouterr().out.strip().splitlines()[-1].strip()
    if on_windows:
        assert advice == 'Stop PegaProx first (its service, or the PegaProx process), then run this again.'
    else:
        assert advice == 'Stop PegaProx first (sudo systemctl stop pegaprox), then run this again.'
