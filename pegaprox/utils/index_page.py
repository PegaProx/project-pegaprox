"""The page itself (web/index.html), cached and compressed the way a browser expects.

# What & why
The bundle is ~13 MB and every browser of every admin loads it. It went out through
send_from_directory, and flask-compress compressed it again on every request. It also
appended ":zstd" (":br", ...) to the file's ETag, the browser revalidated with that tag,
Werkzeug only knew the plain one, so a reload never got its 304: 200, 3.3 MB and a fresh
13 MB compression each time. A file response is a stream, and flask-compress leaves
gzip out for a stream by default, so a client that only offers gzip got all 13 MB. With
air-gap on the route read the file on every request and sent it no-store.

# How
The file is read once per generation (path, mtime_ns, size, air-gap flag) with the
air-gap prelude already in. Each coding is compressed once, off the hub, the first time
a client asks for it, and every variant has its own strong ETag (a hash of the page
plus the coding), so a 304 never waits for a compression. Only the current generation
of a file is kept. The response carries Content-Encoding and Vary itself and is marked
so the app's flask-compress hook leaves it alone (app.py).

The language files of the page (web/i18n/<lang>.json, 0.6 to 0.7 MB each) go out the same
way through serve_file, each with its own generation.

MK Nov 2026
"""
import gzip
import hashlib
import logging
import os
import stat
import threading

from flask import Response, current_app, request, send_from_directory

try:
    import brotlicffi as _brotli
except ImportError:
    try:
        import brotli as _brotli
    except ImportError:
        _brotli = None

# the same modules flask-compress takes (its compat.py)
try:
    from compression import zstd as _zstd
except ImportError:
    try:
        from backports import zstd as _zstd
    except ImportError:
        _zstd = None

INDEX_FILE = 'index.html'

# NS May 2026 - with air-gap on the loader must see the flag on its very first read,
# before /auth/check answers, or a fresh browser asks cdn.jsdelivr first
AIR_GAP_PRELUDE = (
    b"<script>"
    b"try{localStorage.setItem('pegaprox-air-gap','1');}catch(_){}"
    b"window.__pegaproxAirGap=true;"
    b"</script>"
)

CACHE_CONTROL = 'no-cache, private'

# Levels for one compression per generation, measured on the 13 MB bundle (one EPYC core,
# CPU time): gzip 5 0.42 s / 3.44 MB, br 4 0.39 s / 2.98 MB, zstd 9 0.43 s / 2.71 MB.
# One level up costs 30-100 % more time for 2-6 % fewer bytes.
GZIP_LEVEL = 5
BR_QUALITY = 4
ZSTD_LEVEL = 9


def _gzip(data):
    return gzip.compress(data, compresslevel=GZIP_LEVEL, mtime=0)


def _br(data):
    return _brotli.compress(data, quality=BR_QUALITY)


def _zst(data):
    return _zstd.compress(data, level=ZSTD_LEVEL)


def _codings():
    """(name, compressor) in the order a tie is broken, the order flask-compress uses."""
    out = []
    if _zstd is not None:
        out.append(('zstd', _zst))
    if _brotli is not None:
        out.append(('br', _br))
    out.append(('gzip', _gzip))
    return tuple(out)


CODINGS = _codings()


def negotiate(accept_encoding, offered=None):
    """The coding to send for an Accept-Encoding value, None for the file as it is.

    q=0 refuses a coding, '*' stands for every coding not named, the highest q wins and a
    tie goes to the first of `offered`. identity named with a higher q than every coding
    wins too. Nothing acceptable, or no header at all, is the file as it is."""
    if offered is None:
        offered = [name for name, _ in CODINGS]
    if not accept_encoding:
        return None
    q = {}
    for part in accept_encoding.split(','):
        name, _, params = part.partition(';')
        name = name.strip().lower()
        if not name:
            continue
        weight = 1.0
        for param in params.split(';'):
            key, _, value = param.partition('=')
            if key.strip().lower() == 'q':
                try:
                    weight = float(value.strip())
                except ValueError:
                    weight = None
        # a q that is no number in 0..1 (nan included) makes the entry void
        if weight is None or not 0.0 <= weight <= 1.0:
            continue
        q[name] = weight
    star = q.get('*', 0.0)
    best, best_q = None, 0.0
    for name in offered:
        weight = q.get(name, star)
        if weight > best_q:
            best, best_q = name, weight
    if best is not None and q.get('identity', 0.0) > best_q:
        return None
    return best


def _off_hub(fn, *args):
    """fn(*args) in gevent's threadpool when the process runs on gevent, so the hub serves
    on while 13 MB are hashed or compressed; inline otherwise. fn takes no lock and logs
    nothing."""
    try:
        from gevent import get_hub
        from gevent.monkey import is_module_patched
    except ImportError:
        return fn(*args)
    if not is_module_patched('threading'):
        return fn(*args)
    return get_hub().threadpool.apply(fn, args)


def _read(path, prelude):
    """(key, bytes, sha256 hex) of the file. The key comes from the open file before the
    read; a read that got another length than that stat said (a write in progress) is not
    kept."""
    with open(path, 'rb') as fh:
        st = os.fstat(fh.fileno())
        raw = fh.read()
    if len(raw) != st.st_size:
        raise OSError(f'{path} changed while it was read')
    if prelude:
        if b'<head>' in raw:
            raw = raw.replace(b'<head>', b'<head>' + prelude, 1)
        else:
            raw = prelude + raw
    return (path, st.st_mtime_ns, st.st_size, prelude), raw, hashlib.sha256(raw).hexdigest()


class _Generation:
    """One read of the file: the bytes, its tag and the codings made of it so far."""

    def __init__(self, key, raw, digest):
        self.key = key
        self.raw = raw
        # the whole hash, for a route that compares a version the client names with it
        self.digest = digest
        self.tag = digest[:32]
        self.coded = {}
        self.failed = set()
        self.locks = {name: threading.Lock() for name, _ in CODINGS}

    def offered(self):
        return [name for name, _ in CODINGS if name not in self.failed]

    def etag(self, coding):
        return self.tag if coding is None else f'{self.tag}-{coding}'

    def body(self, coding):
        """The bytes of a coding, None when it cannot be made (then it is not offered
        again for this generation, a broken compressor must not run per request)."""
        if coding is None:
            return self.raw
        data = self.coded.get(coding)
        if data is not None:
            return data
        # the first client of a coding compresses it, the others wait for that one
        with self.locks[coding]:
            data = self.coded.get(coding)
            if data is None and coding not in self.failed:
                try:
                    data = _off_hub(dict(CODINGS)[coding], self.raw)
                except Exception:
                    logging.exception(f"[index] {coding} of {os.path.basename(self.key[0])} failed, "
                                      f"it goes out as it is")
                    self.failed.add(coding)
                    return None
                self.coded[coding] = data
        return data


# the latest generation of each file served, by path. The callers name their files from
# fixed lists, so this holds the page and the language files and nothing else.
_current = {}
_load_lock = threading.Lock()


def _generation(path, st, prelude):
    key = (path, st.st_mtime_ns, st.st_size, prelude)
    gen = _current.get(path)
    if gen is not None and gen.key == key:
        return gen
    with _load_lock:
        gen = _current.get(path)
        if gen is None or gen.key != key:
            gen = _Generation(*_off_hub(_read, path, prelude))
            # the previous generation goes with this, requests still on it keep their own
            _current[path] = gen
    return gen


def serve_index(directory, air_gap=False):
    """The response for a route that sends index.html out of `directory` (relative to the
    app root like send_from_directory). A file that is missing or cannot be read goes
    through send_from_directory, which answers it the way the routes always did."""
    return serve_file(directory, INDEX_FILE, 'text/html', CACHE_CONTROL,
                      AIR_GAP_PRELUDE if air_gap else None)


def serve_file(directory, filename, mimetype, cache_control, prelude=None):
    """serve_index for any file the caller names (never a name taken from the request as
    it is). cache_control is the header, or a function of the file's sha256 hex that
    returns it. A prelude goes in after the first <head>."""
    path = os.path.join(current_app.root_path, directory, filename)
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return send_from_directory(directory, filename)
        gen = _generation(path, st, prelude or None)
    except FileNotFoundError:
        return send_from_directory(directory, filename)
    except OSError as e:
        logging.warning(f"[index] could not read {path}: {e}")
        return send_from_directory(directory, filename)

    coding = negotiate(request.headers.get('Accept-Encoding', ''), gen.offered())
    if request.if_none_match.contains_weak(gen.etag(coding)):
        resp = Response(status=304)
    else:
        body = gen.body(coding)
        if body is None:
            coding, body = None, gen.raw
        resp = Response(body, mimetype=mimetype)
        if coding:
            resp.headers['Content-Encoding'] = coding
    resp.set_etag(gen.etag(coding))
    resp.headers['Vary'] = 'Accept-Encoding'
    resp.headers['Cache-Control'] = cache_control(gen.digest) if callable(cache_control) else cache_control
    # app.py: flask-compress leaves a response alone that carries its own coding
    resp.pp_encoded = True
    return resp
