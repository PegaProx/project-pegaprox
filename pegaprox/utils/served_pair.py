"""The certificate a TLS listener serves follows cert.pem and key.pem on disk.

# What & why
Every listener loaded its pair once, at start. An ACME renewal (the background thread,
30 days before expiry) wrote the new pair next to it, the listeners kept the old one, and
the only sign was an INFO line that a production start does not log. An install that
nobody restarted served a certificate running out while the settings said renewed.

# How
The context a listener starts with gets an SNI callback. OpenSSL calls it in every
handshake, with or without a server name, and the callback may hand the connection
another context. Before that it compares the inode, size and mtime of both files with
the last ones it tried; when they changed, it builds a new context from them. A pair
that does not load (cut, mismatched, half written) changes nothing and the listener
keeps what it serves. One stat per handshake, a load only when the files change.

The callback works the same for the gevent server, the asyncio VNC server and the SSH
console process, which has no other way to hear of a new pair. MK
"""
import _ssl
import hashlib
import logging
import os
import ssl

# the pairs this process serves, for serves()
_listeners = []


def server_context(cert_file, key_file):
    """A plain server context with the pair loaded."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return context


def _set_sni_callback(context, callback):
    # past gevent's sni_callback setter: its wrapper takes every connection for an SSL
    # socket and fails on the SSLObject of an asyncio server (the VNC port), so the
    # handshake failed there. _handshake unwraps gevent's socket itself.
    base = getattr(_ssl, '_SSLContext', None)
    if base is not None and isinstance(context, base):
        base.sni_callback.__set__(context, callback)
    else:
        context.sni_callback = callback


def _stamp(*paths):
    try:
        return tuple((st.st_ino, st.st_size, st.st_mtime_ns) for st in map(os.stat, paths))
    except OSError:
        return None


def _digest(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


class ServedPair:
    """The pair one listener serves. build(cert, key) makes a loaded context; the one
    for the start raises like load_cert_chain does, so a bad pair still stops the start."""

    def __init__(self, cert_file, key_file, build=server_context):
        self.cert_file = cert_file
        self.key_file = key_file
        self.error = None
        self._build = build
        self._tried = self._reported = _stamp(cert_file, key_file)
        self._digest = _digest(cert_file)
        self.context = self._current = build(cert_file, key_file)
        _set_sni_callback(self.context, self._handshake)
        _listeners.append(self)

    def refresh(self, report=False):
        """Load the pair on disk if it changed since the last try. report: say at
        WARNING, once for each change of the files, that it did not load."""
        stamp = _stamp(self.cert_file, self.key_file)
        if stamp is None:
            self._tried, self.error = None, 'the certificate or its key cannot be read'
        elif stamp != self._tried:
            self._tried = stamp
            digest = _digest(self.cert_file)
            try:
                context = self._build(self.cert_file, self.key_file)
            except Exception as e:
                # in a handshake this can be a pair caught between its two renames,
                # the next change of the files tries again
                self.error = str(e) or type(e).__name__
                logging.debug(f"[TLS] {self.cert_file} does not load yet: {self.error}")
            else:
                self._current, self._digest, self.error = context, digest, None
                logging.info(f"[TLS] Serving the certificate in {self.cert_file} from now on")
        if report and self.error and self._reported != self._tried:
            self._reported = self._tried
            logging.warning(f"[TLS] {self.cert_file} and its key do not load ({self.error}), "
                            "still serving the previous certificate")

    def serves_disk(self):
        """True if this listener hands out the pair that is on disk now."""
        self.refresh(report=True)
        return self._digest is not None and self._digest == _digest(self.cert_file)

    def _handshake(self, conn, server_name, context):
        # never fail a handshake over this, the previous pair is still a good answer
        try:
            ref = getattr(conn, '_sslsock', None)   # gevent passes the socket under its SSL one
            if callable(ref):
                conn = ref()
            self.refresh()
            if self._current is not context:
                conn.context = self._current
        except Exception as e:
            logging.debug(f"[TLS] Could not switch the certificate: {e}")


def serves(cert_file):
    """True if every listener of this process serves the pair at cert_file as it is on
    disk now, False if one still serves an older one, None if none serves it."""
    path = os.path.abspath(cert_file)
    mine = [p for p in _listeners if os.path.abspath(p.cert_file) == path]
    if not mine:
        return None
    return all([p.serves_disk() for p in mine])


def load_error(cert_file):
    """Why the pair at cert_file did not load into a listener, '' if it did."""
    path = os.path.abspath(cert_file)
    return next((p.error for p in _listeners if os.path.abspath(p.cert_file) == path and p.error), '')
