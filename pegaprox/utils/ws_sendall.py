"""Make simple-websocket write whole frames.

# What & why
`simple_websocket` 1.1.0 writes every outbound frame with `self.sock.send(...)`
in five places. `send()` is allowed to write fewer bytes than it was given and
report how many; it is the caller's job to loop. simple-websocket does not, so
whenever a single write does not drain — which is what happens under load, and a
VNC framebuffer update is exactly that — the rest of the frame is dropped. The
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
import logging

_PATCHED = False


class _SendAllSocket:
    """Forwards to the real socket; `send` writes everything or raises."""

    __slots__ = ('_sock',)

    def __init__(self, sock):
        object.__setattr__(self, '_sock', sock)

    def send(self, data, *args, **kwargs):
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
