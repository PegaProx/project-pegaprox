"""Make simple-websocket write whole frames.

# What & why
`simple_websocket` 1.1.0 writes every outbound frame with `self.sock.send(...)`
in five places. `send()` is allowed to write fewer bytes than it was given and
report how many; it is the caller's job to loop. simple-websocket does not, so
whenever a single write does not drain - which is what happens under load, and a
VNC framebuffer update is exactly that - the rest of the frame is dropped. The
stream stays open but is now misaligned, the client decodes garbage, and the
session ends with 1002 Protocol Error after a black screen.

Reported as the fifth of five findings in #945, against a console behind a
reverse proxy: the session streamed ~1.6 MB and then died. It is an upstream
bug, but it is cheap to close on our side and we cannot wait for a release.

# How
`sendall()` already has exactly the required semantics, on a plain socket, an
SSL socket and a gevent socket alike. So the socket handed to simple-websocket
is wrapped in a thin object that forwards everything untouched except `send`,
which becomes `sendall` and reports the full length. Wrapping the socket rather
than patching five call sites means a future release that adds a sixth is
covered too.

MK Sep 2026 (#945)
"""
import contextlib
import logging
import os
import socket
import threading

_PATCHED = False

# MK Nov 2026 - how long one frame may take to go out before the peer counts as gone
_SEND_TIMEOUT = float(os.environ.get('PEGAPROX_WS_SEND_TIMEOUT', '120'))


def _send_deadline():
    try:
        from gevent import Timeout, monkey
        if _SEND_TIMEOUT > 0 and monkey.is_module_patched('socket'):
            return Timeout(_SEND_TIMEOUT, socket.timeout('the peer took no data in time'))
    except Exception:
        pass
    return contextlib.nullcontext()


class _SendAllSocket:
    """Forwards to the real socket; `send` writes everything or raises.

    MK Nov 2026 - one writer at a time. simple-websocket's own thread writes its pings,
    pongs and close frames on the socket the route sends its frames on. Two writes at once
    break a TLS record (OpenSSL refuses a second write while one is half out, and the
    socket is closed) and on a plain socket put the ping inside a frame; a VNC console on a
    slow link met that at its first ping. And a deadline per frame: a peer that takes
    nothing for that long is gone, and holds no console after it. A socket.timeout, which
    simple-websocket's thread ends on like on any socket error."""

    __slots__ = ('_sock', '_write_lock')

    def __init__(self, sock):
        object.__setattr__(self, '_sock', sock)
        object.__setattr__(self, '_write_lock', threading.Lock())

    def send(self, data, *args, **kwargs):
        with self._write_lock:
            with _send_deadline():
                self._sock.sendall(data, *args, **kwargs)
        return len(data)

    # everything else is the real socket's business
    def __getattr__(self, name):
        return getattr(self._sock, name)

    def __setattr__(self, name, value):
        setattr(self._sock, name, value)

    def __repr__(self):
        return f'<sendall {self._sock!r}>'


def apply_sendall_patch():
    """Idempotent. Returns True if simple-websocket is now write-complete."""
    global _PATCHED
    if _PATCHED:
        return True
    try:
        from simple_websocket import ws as _ws
    except Exception:
        return False

    base = getattr(_ws, 'Base', None)
    if base is None:
        return False
    if getattr(base, '_pegaprox_sendall', False):
        # already wrapped by another import of this module: the docstring promises
        # "True if simple-websocket is now write-complete", and it is. MK Sep 2026 (scan)
        _PATCHED = True
        return True

    original_init = base.__init__

    def _init(self, sock=None, *args, **kwargs):
        original_init(self, sock, *args, **kwargs)
        # __init__ stores the socket on self.sock; wrap whatever ended up there
        current = getattr(self, 'sock', None)
        if current is not None and not isinstance(current, _SendAllSocket):
            self.sock = _SendAllSocket(current)

    base.__init__ = _init
    base._pegaprox_sendall = True
    _PATCHED = True
    logging.info('[ws-patch] simple-websocket frames are written with sendall (#945)')
    return True
