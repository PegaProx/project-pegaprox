"""The lock of the config directory on Windows (#1390).

ha.lock_config_dir took an flock, and without fcntl it returned None: on Windows a second
PegaProx on the same config directory ran next to the first, and --migrate-db, whose
_hold_config_dir gave up the same way, converted the database under a running PegaProx.
Both lock one byte of the lock file with msvcrt there now, as dbcrypto locks a conversion:
byte 0 at first, which kept backup tools (robocopy, Explorer, zip) from reading the file for
as long as PegaProx ran, now a byte 1 GiB in, far past the end, with the pid at the start.

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

# the byte both lock, where SQLite keeps its PENDING_BYTE
LOCKED = 1 << 30


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
    """Another process that runs PegaProx on the directory of `path`: its pid at the start,
    and the byte at LOCKED locked by a handle of its own."""
    with open(path, 'wb') as f:
        f.write(f'{pid}\n'.encode())
    fd = os.open(path, os.O_RDWR)
    os.lseek(fd, LOCKED, os.SEEK_SET)
    fake.locking(fd, fake.LK_NBLCK, 1)
    return fd


def backup_tool_reads(path):
    """What robocopy does with the file: another handle, which reads all of it."""
    fd = os.open(path, os.O_RDONLY)
    try:
        return os.read(fd, 1 << 16)
    finally:
        os.close(fd)


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
        assert windows.on(lock) == [(windows.LK_NBLCK, LOCKED, 1)] * 2
        # the pid at the start, where the refused one read it, as with flock
        assert lock.read_bytes() == f'{os.getpid()}\n'.encode()
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


def test_a_backup_tool_reads_the_lock_file_while_pegaprox_runs_on_windows(tmp_path, windows):
    """Windows refuses a locked byte to every other handle, reads too. With byte 0 locked,
    robocopy failed on the file for as long as PegaProx ran, and by default it retries for
    days."""
    lock = tmp_path / '.pegaprox.lock'
    fd = ha.lock_config_dir(str(lock))
    try:
        assert fd is not None
        assert backup_tool_reads(lock) == f'{os.getpid()}\n'.encode()
        assert windows.on(lock) == [(windows.LK_NBLCK, LOCKED, 1)]
        # locked past the end, written at the start: the file stays a few bytes long
        assert os.path.getsize(lock) == len(f'{os.getpid()}\n')
    finally:
        if fd is not None:
            os.close(fd)


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
    lock.write_bytes(b'4242\n')   # left by the PegaProx that was stopped for this
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
    assert windows.on(lock) == [(windows.LK_NBLCK, LOCKED, 1), (windows.LK_NBLCK, LOCKED, 1),
                                (windows.LK_UNLCK, LOCKED, 1)]
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


def test_a_backup_tool_reads_the_lock_file_while_the_cli_holds_it_on_windows(tmp_path, windows):
    lock = tmp_path / '.pegaprox.lock'
    lock.write_bytes(b'4242\n')
    fd = migrate_db._hold_config_dir(str(tmp_path))
    try:
        assert fd is not None
        assert backup_tool_reads(lock) == f'{os.getpid()}\n'.encode()
        assert windows.on(lock) == [(windows.LK_NBLCK, LOCKED, 1)]
    finally:
        if fd is not None:
            migrate_db._let_go(fd)
    # undone on the byte it locked, before the close
    assert windows.on(lock)[-1] == (windows.LK_UNLCK, LOCKED, 1)
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


# --- the server and the CLI ------------------------------------------------------------------

def test_the_server_and_the_cli_shut_each_other_out_on_windows(tmp_path, windows):
    lock = tmp_path / '.pegaprox.lock'
    srv = ha.lock_config_dir(str(lock))
    try:
        with pytest.raises(RuntimeError, match=f'^PegaProx \\(process {os.getpid()}\\) is running on '):
            migrate_db._hold_config_dir(str(tmp_path))
    finally:
        os.close(srv)
    cli = migrate_db._hold_config_dir(str(tmp_path))
    try:
        assert cli is not None
        with pytest.raises(ha.HaError, match=f'^Another PegaProx process {os.getpid()} runs on '):
            ha.lock_config_dir(str(lock))
    finally:
        if cli is not None:
            migrate_db._let_go(cli)
    assert {c[1:] for c in windows.on(lock)} == {(LOCKED, 1)}
    assert windows.held == {}


def test_the_server_and_the_cli_name_the_same_byte():
    """migrate_db does not import ha, so it keeps the number of its own."""
    assert ha.CONFIG_LOCK_BYTE == migrate_db._RUNNING_LOCK_BYTE == LOCKED


def test_the_byte_lock_of_dbcrypto_waits_on_the_byte_it_is_given(tmp_path, windows, monkeypatch):
    """The config directory lock never waits, a conversion does: the waiting goes to the
    byte of the first try. Without `at` it is byte 0, the one the conversion lock keeps."""
    path = tmp_path / 'x.lock'
    path.write_bytes(b'')
    other = os.open(path, os.O_RDWR)
    os.lseek(other, LOCKED, os.SEEK_SET)
    windows.locking(other, windows.LK_NBLCK, 1)
    real = windows.locking

    def locking(fd, mode, n):
        if mode == windows.LK_LOCK:
            windows.drop(other)     # the other process is done and lets go
        return real(fd, mode, n)
    monkeypatch.setattr(windows, 'locking', locking)
    fd = os.open(path, os.O_RDWR)
    plain = os.open(path, os.O_RDWR)
    try:
        assert dbcrypto._lock_first_byte(windows, fd, str(path), at=LOCKED) is True
        assert windows.on(path) == [(windows.LK_NBLCK, LOCKED, 1)] * 2 + [(windows.LK_LOCK, LOCKED, 1)]
        assert [k[2] for k, v in windows.held.items() if v == fd] == [LOCKED]
        assert dbcrypto._lock_first_byte(windows, plain, str(path), wait=False) is False
        assert windows.on(path)[-1] == (windows.LK_NBLCK, 0, 1)
    finally:
        for d in (fd, plain, other):
            os.close(d)
