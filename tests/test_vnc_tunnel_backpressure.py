"""The SSH tunnel's local leg waits for a slow console reader instead of ending the console.

_Pumper copies what PVE sends over the SSH channel into the local socket the console relay
reads from, and that relay reads at the browser's pace. The local socket is non-blocking
for the select loop, and the write to it was a plain sendall: once its buffer was full,
sendall raised, the pumper took that for the end of the session and closed both sides. A
single large framebuffer update to a slow browser dropped the console, with nothing but a
DEBUG line to say why.

The socket buffers are shrunk to 4 KB on purpose, so a 1 MB burst fills them on any kernel
without depending on its autotuning; with default buffers the same thing takes a burst of a
few MB.
"""
import logging
import socket
import threading
import time

import gevent

from pegaprox.utils import vnc_tunnel

BURST = 1024 * 1024
PATTERN = bytes(range(256)) * 64          # 16 KB, so a dropped or doubled chunk shows


class _Channel:
    """paramiko channel stand-in: one end of a socketpair the test keeps filling."""

    def __init__(self, sock):
        self._s = sock

    def fileno(self):
        return self._s.fileno()

    def recv_ready(self):
        return True

    def recv(self, n):
        return self._s.recv(n)

    def sendall(self, d):
        self._s.sendall(d)

    def exit_status_ready(self):
        return False

    def close(self):
        try:
            self._s.close()
        except Exception:
            pass


def _leg():
    """(pumper, reader socket, PVE-side feeder socket, listener) with small buffers."""
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.bind(('127.0.0.1', 0))
    lst.listen(1)
    reader = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    reader.connect(lst.getsockname())
    local, _ = lst.accept()
    local.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    ch_in, ch_out = socket.socketpair()
    pumper = vnc_tunnel._Pumper(local, _Channel(ch_in), 0)
    pumper.start()
    return pumper, reader, ch_out, lst


def _feed(sock, total):
    def run():
        try:
            for _ in range(total // len(PATTERN)):
                sock.sendall(PATTERN)
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


def _stall(seconds, pumper):
    deadline = time.time() + seconds
    while time.time() < deadline and pumper.is_alive():
        gevent.sleep(0.05)


def _read(sock, total, seconds=10.0):
    sock.settimeout(seconds)
    got = bytearray()
    try:
        while len(got) < total:
            d = sock.recv(65536)
            if not d:
                break
            got += d
    except socket.timeout:
        pass
    return bytes(got)


def test_a_stalled_reader_gets_the_whole_burst_once_it_reads_again():
    pumper, reader, ch_out, lst = _leg()
    try:
        _feed(ch_out, BURST)
        _stall(1.5, pumper)        # the browser is busy, the relay does not read
        assert pumper.is_alive(), 'the tunnel gave up on a full local buffer'
        got = _read(reader, BURST)
        assert len(got) == BURST, f'reader got {len(got)} of {BURST} bytes, then the end'
        assert got == PATTERN * (BURST // len(PATTERN)), 'the stream arrived damaged'
        assert pumper.is_alive()
    finally:
        pumper.stop()
        for s in (reader, ch_out, lst):
            s.close()


def test_a_reader_that_never_comes_back_ends_the_leg_after_the_deadline(monkeypatch):
    monkeypatch.setattr(vnc_tunnel._Pumper, 'LOCAL_SEND_TIMEOUT', 1.0, raising=False)
    pumper, reader, ch_out, lst = _leg()
    try:
        _feed(ch_out, BURST)
        _stall(0.5, pumper)
        assert pumper.is_alive(), 'ended before the reader had its time'
        _stall(5.0, pumper)
        assert not pumper.is_alive(), 'a reader that is gone kept the leg open'
    finally:
        pumper.stop()
        for s in (reader, ch_out, lst):
            s.close()


class _BrokenChannel(_Channel):
    def recv(self, n):
        raise EOFError('channel reset')


def test_a_leg_that_ends_on_its_own_says_why(caplog):
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.bind(('127.0.0.1', 0))
    lst.listen(1)
    reader = socket.create_connection(lst.getsockname())
    local, _ = lst.accept()
    ch_in, ch_out = socket.socketpair()
    ch_out.sendall(b'x')           # so select reports the channel readable
    pumper = vnc_tunnel._Pumper(local, _BrokenChannel(ch_in), 0)
    with caplog.at_level(logging.INFO):
        pumper.start()
        pumper.join(5)
    try:
        assert not pumper.is_alive()
        assert any(r.levelno >= logging.INFO and 'channel reset' in r.getMessage()
                   for r in caplog.records), [(r.levelname, r.getMessage()) for r in caplog.records]
    finally:
        for s in (reader, ch_out, lst):
            s.close()
