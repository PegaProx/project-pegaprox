"""simple-websocket writes frames with send(), which may write only part of them.

#945.5 — a console behind a reverse proxy streamed about 1.6 MB and then closed
with 1002 Protocol Error after a black screen. `self.sock.send(out_data)` is
allowed to write fewer bytes than asked and report how many; simple-websocket
1.1.0 does not loop, so under load the tail of a large framebuffer update is
dropped and the stream is misaligned from then on.

Measured against a socket that deliberately short-writes, because that is the
condition; asserting that the patch "is applied" would prove nothing.

MK Sep 2026
"""
import socket
import threading

import pytest

from pegaprox.utils.ws_sendall import _SendAllSocket, apply_sendall_patch


class _ShortWriteSocket:
    """A socket that writes at most 1024 bytes per send(), like a loaded one."""

    CHUNK = 1024

    def __init__(self, sink):
        self.sink = sink
        self.send_calls = 0

    def send(self, data):
        self.send_calls += 1
        part = data[:self.CHUNK]
        self.sink.extend(part)
        return len(part)

    def sendall(self, data):
        view = memoryview(data)
        while view:
            written = self.send(view)
            view = view[written:]

    def fileno(self):
        return -1


def test_a_short_writing_socket_loses_the_tail_without_the_wrapper():
    """The bug itself, so the next reader can see what is being prevented."""
    sink = bytearray()
    raw = _ShortWriteSocket(sink)
    frame = b'x' * 64_000

    written = raw.send(frame)          # what simple-websocket does

    assert written == 1024
    assert len(sink) == 1024, 'precondition: this socket short-writes'
    assert len(sink) < len(frame), 'the remaining 62 KB never reached the client'


def test_the_wrapper_writes_the_whole_frame():
    sink = bytearray()
    wrapped = _SendAllSocket(_ShortWriteSocket(sink))
    frame = b'x' * 64_000

    written = wrapped.send(frame)

    assert written == len(frame), 'send() must report the full length'
    assert bytes(sink) == frame, 'the frame arrived truncated or reordered'


def test_the_wrapper_forwards_everything_else():
    raw = _ShortWriteSocket(bytearray())
    wrapped = _SendAllSocket(raw)
    assert wrapped.fileno() == -1
    assert wrapped.send_calls == 0
    wrapped.send(b'abc')
    assert raw.send_calls == 1, 'attribute writes/reads must reach the real socket'


def test_a_real_socketpair_round_trips_a_large_frame():
    """The wrapper has to behave on an actual socket, not only on a fake."""
    a, b = socket.socketpair()
    received = bytearray()

    def _drain():
        while len(received) < 1_000_000:
            chunk = b.recv(65536)
            if not chunk:
                break
            received.extend(chunk)

    t = threading.Thread(target=_drain, daemon=True)
    t.start()
    try:
        payload = bytes(range(256)) * 3907          # ~1 MB, like a framebuffer update
        n = _SendAllSocket(a).send(payload)
        assert n == len(payload)
        t.join(timeout=10)
        assert bytes(received) == payload, 'the large frame did not arrive intact'
    finally:
        a.close()
        b.close()


def test_the_patch_is_idempotent():
    assert apply_sendall_patch() in (True, False)
    first = apply_sendall_patch()
    assert apply_sendall_patch() == first


def test_simple_websocket_ends_up_wrapped():
    apply_sendall_patch()
    from simple_websocket import ws as _ws
    assert getattr(_ws.Base, '_pegaprox_sendall', False), \
        'simple-websocket still writes frames with a bare send()'
