"""The page (web/index.html) is cached and compressed the way a browser expects.

flask-compress appended ":zstd" to the file's ETag and compressed the 13 MB again on
every request. The browser revalidated with that tag and Werkzeug only knew the plain
one, so a reload never got a 304. A file response is a stream and flask-compress never
gzips a stream, so a client that only offers gzip got the page as it is. With air-gap on
the page went out no-store and without any ETag.

Now the file is read once, each coding is compressed once and has its own ETag, a reload
gets its 304, Accept-Encoding is honoured with its q-values, and the air-gap flag
changes the ETag. The other files flask-compress codes (/static, the plugin pages, the
service worker) get their 304 too. Everything goes through the real app and its routes.
"""
import gzip
import os
import types
import zlib

import gevent
import gevent.monkey
import pytest

import pegaprox.api.plugins as plugins_mod
import pegaprox.api.settings as settings_mod
from pegaprox.api.helpers import save_server_settings

try:
    import brotlicffi as brotli
except ImportError:
    try:
        import brotli
    except ImportError:
        brotli = None
try:
    from compression import zstd
except ImportError:
    try:
        from backports import zstd
    except ImportError:
        zstd = None

CODINGS = [c for c, mod in (('zstd', zstd), ('br', brotli), ('gzip', gzip)) if mod is not None]
BEST = CODINGS[0]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLUGIN_PAGES = [('/portal', 'client_portal', 'portal.html'),
                ('/portal/my-vms', 'client_portal', 'portal.html'),
                ('/status', 'status_page', 'status.html')]

PRELUDE = (b"<script>try{localStorage.setItem('pegaprox-air-gap','1');}catch(_){}"
           b"window.__pegaproxAirGap=true;</script>")


def _page(text=b'one'):
    rows = b''.join(b'<div class="row-%d">PegaProx page %s</div>\n' % (i, text) for i in range(4000))
    return (b'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n'
            b'<title>PegaProx</title>\n</head>\n<body>\n' + rows + b'</body>\n</html>\n')


@pytest.fixture
def page(tmp_path, monkeypatch):
    web = tmp_path / 'web'
    web.mkdir()
    f = web / 'index.html'
    f.write_bytes(_page())
    monkeypatch.setattr(settings_mod, 'WEB_DIR', str(web))
    return f


@pytest.fixture
def fetch(api):
    client = api.app.test_client()

    def _fetch(path='/', method='get', coding=None, etag=None, **headers):
        if coding is not None:
            headers['Accept-Encoding'] = coding
        if etag is not None:
            headers['If-None-Match'] = etag
        return getattr(client, method)(path, headers=headers, base_url='http://localhost')
    return _fetch


def _air_gap(on):
    assert save_server_settings({'air_gap_mode': on})


def _decoded(resp):
    return _decode(resp.headers.get('Content-Encoding'), resp.get_data())


def _decode(enc, data):
    if enc is None:
        return data
    if enc == 'gzip':
        return gzip.decompress(data)
    if enc == 'br':
        return brotli.decompress(data)
    if enc == 'zstd':
        return zstd.decompress(data)
    if enc == 'deflate':
        return zlib.decompress(data)
    raise AssertionError(f'unexpected coding {enc}')


def _count_compressions(monkeypatch, calls):
    """Count every compression of a body, whichever way it is made: brotli.compress and
    zstd.compress build a (Zstd)Compressor too, flask-compress streams with one, gzip goes
    through gzip.compress or a zlib stream with a gzip header."""
    real_gzip, real_obj = gzip.compress, zlib.compressobj

    def counted_gzip(*a, **kw):
        calls.append('gzip')
        return real_gzip(*a, **kw)

    def counted_obj(*a, **kw):
        wbits = kw.get('wbits', a[2] if len(a) > 2 else None)
        if wbits == zlib.MAX_WBITS + 16:
            calls.append('gzip')
        return real_obj(*a, **kw)
    monkeypatch.setattr(gzip, 'compress', counted_gzip)
    monkeypatch.setattr(zlib, 'compressobj', counted_obj)

    def counted_class(mod, attr, name):
        real = getattr(mod, attr)

        def make(*a, **kw):
            calls.append(name)
            return real(*a, **kw)
        # zstd.compress reads the flush modes off the class
        for flag in ('CONTINUE', 'FLUSH_BLOCK', 'FLUSH_FRAME'):
            if hasattr(real, flag):
                setattr(make, flag, getattr(real, flag))
        monkeypatch.setattr(mod, attr, make)
    if brotli is not None:
        counted_class(brotli, 'Compressor', 'br')
    if zstd is not None:
        counted_class(zstd, 'ZstdCompressor', 'zstd')


@pytest.mark.parametrize('coding', CODINGS)
def test_a_reload_gets_a_304_with_the_etag_of_its_coding(fetch, page, coding):
    first = fetch(coding=coding)
    assert first.status_code == 200
    assert first.headers.get('Content-Encoding') == coding
    assert _decoded(first) == page.read_bytes()
    etag = first.headers['ETag']
    assert first.headers['Vary'] == 'Accept-Encoding'

    again = fetch(coding=coding, etag=etag)
    assert again.status_code == 304, (again.status_code, etag)
    assert again.get_data() == b''
    assert again.headers['ETag'] == etag
    assert again.headers['Vary'] == 'Accept-Encoding'
    assert again.headers['Cache-Control'] == 'no-cache, private'

    # a list, and the weak form, are the same validator for If-None-Match
    assert fetch(coding=coding, etag=f'"other", {etag}').status_code == 304
    assert fetch(coding=coding, etag=f'W/{etag}').status_code == 304
    assert fetch(coding=coding, etag='*').status_code == 304
    assert fetch(coding=coding, etag='"other"').status_code == 200


def test_every_coding_and_the_plain_page_have_their_own_etag(fetch, page):
    tags = {c: fetch(coding=c).headers['ETag'] for c in CODINGS}
    tags[None] = fetch().headers['ETag']
    assert len(set(tags.values())) == len(tags), tags
    assert all(not t.startswith('W/') for t in tags.values()), tags
    # the tag of another coding is no validator for this one
    assert fetch(coding='gzip', etag=tags[None]).status_code == 200
    assert fetch(etag=tags['gzip']).status_code == 200


def test_a_client_that_only_offers_gzip_gets_gzip(fetch, page):
    # the second one is what python-requests sends without brotli
    for offer in ('gzip', 'gzip, deflate', 'GZIP;q=1.0'):
        r = fetch(coding=offer)
        assert r.status_code == 200
        assert r.headers.get('Content-Encoding') == 'gzip', (offer, r.headers.get('Content-Encoding'))
        assert _decoded(r) == page.read_bytes()
        assert int(r.headers['Content-Length']) == len(r.get_data())


def test_a_client_without_a_coding_we_keep_gets_the_file_as_it_is(fetch, page):
    raw = page.read_bytes()
    tags = set()
    for offer in ('deflate', 'compress, x-unknown', None, '', 'identity'):
        r = fetch(coding=offer)
        assert r.status_code == 200
        assert 'Content-Encoding' not in r.headers, (offer, r.headers.get('Content-Encoding'))
        assert r.get_data() == raw
        assert r.headers['Cache-Control'] == 'no-cache, private'
        assert r.headers['Vary'] == 'Accept-Encoding'
        assert r.mimetype == 'text/html'
        tags.add(r.headers['ETag'])
        assert fetch(coding=offer, etag=r.headers['ETag']).status_code == 304
    assert len(tags) == 1, tags


def test_q_values_are_honoured_and_q0_refuses(fetch, page):
    raw = page.read_bytes()
    second = CODINGS[1] if len(CODINGS) > 1 else None
    cases = [
        (', '.join(f'{c};q=0' for c in CODINGS), None),
        ('zstd;q=0, br;q=0, gzip', 'gzip'),
        ('zstd;q=0, br, gzip', 'br' if brotli is not None else 'gzip'),
        ('gzip;q=0', None),
        ('*;q=0', None),
        ('*', BEST),
        (f'{BEST};q=0, *', second),
        ('gzip;q=0.9, br;q=0.5, zstd;q=0.1', 'gzip'),
        ('identity;q=1, gzip;q=0.5', None),
        ('gzip;q=bogus', None),
    ]
    for offer, want in cases:
        r = fetch(coding=offer)
        assert r.status_code == 200
        assert r.headers.get('Content-Encoding') == want, (offer, r.headers.get('Content-Encoding'), want)
        assert _decoded(r) == raw, offer


@pytest.mark.parametrize('coding', [BEST, None])
def test_head_answers_like_get_without_the_body(fetch, page, coding):
    got = fetch(coding=coding)
    head = fetch(method='head', coding=coding)
    assert head.status_code == 200
    assert head.get_data() == b''
    assert head.headers.get('Content-Encoding') == got.headers.get('Content-Encoding')
    assert head.headers['ETag'] == got.headers['ETag']
    assert head.headers.get('Content-Length') == str(len(got.get_data()))
    assert fetch(method='head', coding=coding, etag=got.headers['ETag']).status_code == 304
    assert head.headers['Cache-Control'] == 'no-cache, private'


def test_the_air_gap_prelude_comes_with_the_flag_and_changes_the_etag(fetch, page):
    raw = page.read_bytes()
    plain = fetch(coding=BEST)
    assert _decoded(plain) == raw and PRELUDE not in _decoded(plain)
    plain_tag = plain.headers['ETag']

    _air_gap(True)
    # the cached plain page is no validator for the air-gapped one
    gapped = fetch(coding=BEST, etag=plain_tag)
    assert gapped.status_code == 200
    body = _decoded(gapped)
    assert body.startswith(raw.split(b'<head>')[0] + b'<head>' + PRELUDE)
    assert body.count(PRELUDE) == 1
    assert body.replace(PRELUDE, b'', 1) == raw
    gapped_tag = gapped.headers.get('ETag')
    assert gapped_tag and gapped_tag != plain_tag
    assert gapped.headers['Cache-Control'] == 'no-cache, private'
    assert fetch(coding=BEST, etag=gapped_tag).status_code == 304
    raw_gapped = fetch()
    assert raw_gapped.get_data() == body and raw_gapped.headers['ETag'] not in (gapped_tag, plain_tag)

    _air_gap(False)
    back = fetch(coding=BEST, etag=gapped_tag)
    assert back.status_code == 200
    assert _decoded(back) == raw
    assert back.headers['ETag'] == plain_tag


def test_the_oidc_callback_gets_the_same_page(fetch, page):
    _air_gap(True)
    root = fetch(coding=BEST)
    callback = fetch('/oidc/callback?code=abc&state=xyz', coding=BEST)
    assert callback.status_code == 200
    assert _decoded(callback) == _decoded(root)
    assert PRELUDE in _decoded(callback)
    assert callback.headers['ETag'] == root.headers['ETag']
    assert callback.headers['Cache-Control'] == 'no-cache, private'
    assert fetch('/oidc/callback?code=abc&state=xyz', coding=BEST,
                 etag=root.headers['ETag']).status_code == 304


def test_a_changed_removed_and_restored_file_is_read_again(fetch, page):
    first = fetch(coding=BEST)
    tag1 = first.headers['ETag']
    assert fetch(coding=BEST, etag=tag1).status_code == 304

    # other size
    page.write_bytes(_page(b'two, longer'))
    second = fetch(coding=BEST, etag=tag1)
    assert second.status_code == 200
    assert _decoded(second) == page.read_bytes()
    tag2 = second.headers['ETag']
    assert tag2 != tag1
    assert fetch(coding=BEST, etag=tag2).status_code == 304

    # same size, other bytes, other mtime
    mtime = os.stat(page).st_mtime_ns
    page.write_bytes(_page(b'six, longer'))
    os.utime(page, ns=(mtime + 2_000_000_000, mtime + 2_000_000_000))
    third = fetch(coding=BEST, etag=tag2)
    assert third.status_code == 200
    assert _decoded(third) == page.read_bytes()
    assert third.headers['ETag'] not in (tag1, tag2)

    # a missing page is the 404 send_from_directory gives, and it comes back after
    data = page.read_bytes()
    page.unlink()
    assert fetch(coding=BEST).status_code == 404
    assert fetch(coding=BEST, etag=third.headers['ETag']).status_code == 404
    page.write_bytes(data)
    assert _decoded(fetch(coding=BEST)) == data


@pytest.mark.parametrize('coding', CODINGS)
def test_each_coding_is_compressed_once_not_per_request(api, fetch, page, monkeypatch, coding):
    calls = []
    _count_compressions(monkeypatch, calls)

    def one():
        # the body is read in the greenlet that asked for it
        r = fetch(coding=coding)
        return r.headers.get('Content-Encoding'), r.get_data()
    # three at the same time, then one more
    jobs = [gevent.spawn(one) for _ in range(3)]
    gevent.joinall(jobs, timeout=60, raise_error=True)
    answers = [j.value for j in jobs] + [one()]
    assert [enc for enc, _ in answers] == [coding] * 4
    assert len({body for _, body in answers}) == 1
    assert _decode(coding, answers[0][1]) == page.read_bytes()
    assert calls.count(coding) == 1, calls


def test_a_compression_runs_off_the_hub_and_once_for_all_who_wait(fetch, page, monkeypatch):
    """On the real bundle a compression takes about 0.4 s of C code that never yields. On
    the hub it would hold every other request of the process that long."""
    real_sleep = gevent.monkey.get_original('time', 'sleep')
    real_gzip = gzip.compress
    calls = []

    def slow_gzip(*a, **kw):
        calls.append('gzip')
        # blocks its thread like the compressor does, gevent's sleep would yield
        real_sleep(0.3)
        return real_gzip(*a, **kw)
    monkeypatch.setattr(gzip, 'compress', slow_gzip)
    # the file is read, the plain page needs no compression
    assert fetch().get_data() == page.read_bytes()

    done = []

    def one(coding):
        r = fetch(coding=coding)
        body = r.get_data()
        done.append(coding)
        return r.headers.get('Content-Encoding'), body
    jobs = [gevent.spawn(one, 'gzip') for _ in range(3)] + [gevent.spawn(one, None)]
    gevent.joinall(jobs, timeout=60, raise_error=True)
    # the plain page was answered while the three waited for one compression
    assert done[0] is None, done
    assert calls == ['gzip'], calls
    assert [j.value[0] for j in jobs] == ['gzip', 'gzip', 'gzip', None]
    assert len({j.value[1] for j in jobs[:3]}) == 1
    assert gzip.decompress(jobs[0].value[1]) == page.read_bytes()


def test_the_security_headers_stay_on_the_page_and_its_304(fetch, page):
    first = fetch(coding=BEST)
    again = fetch(coding=BEST, etag=first.headers['ETag'])
    assert again.status_code == 304
    for r in (first, again):
        assert r.headers['X-Content-Type-Options'] == 'nosniff'
        assert r.headers['X-Frame-Options'] == 'SAMEORIGIN'
        assert r.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        assert 'geolocation=()' in r.headers['Permissions-Policy']
        csp = r.headers['Content-Security-Policy']
        assert "default-src 'self'" in csp and "frame-ancestors 'self'" in csp
        assert 'sandbox' not in csp


def test_a_gzip_client_gets_static_css_gzipped_and_its_304(fetch):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'static', 'css', 'tailwind.min.css')
    with open(path, 'rb') as fh:
        css = fh.read()
    r = fetch('/static/css/tailwind.min.css', coding='gzip')
    assert r.status_code == 200
    assert r.headers.get('Content-Encoding') == 'gzip'
    assert gzip.decompress(r.get_data()) == css
    again = fetch('/static/css/tailwind.min.css', coding='gzip', etag=r.headers['ETag'])
    assert again.status_code == 304
    # the cache policy of /static is untouched
    assert r.headers['Cache-Control'] == 'no-cache'


@pytest.mark.parametrize('coding', CODINGS)
def test_static_js_goes_out_compressed_and_its_reload_gets_a_304(fetch, coding):
    # Python 3.12+ sends .js as text/javascript, which flask-compress was not told about
    for name in ('chart.umd.min.js', 'novnc/core/display.js'):
        with open(os.path.join(ROOT, 'static', 'js', name), 'rb') as fh:
            js = fh.read()
        r = fetch(f'/static/js/{name}', coding=coding)
        assert r.status_code == 200
        assert r.headers.get('Content-Encoding') == coding, (name, r.mimetype)
        assert _decode(coding, r.get_data()) == js
        again = fetch(f'/static/js/{name}', coding=coding, etag=r.headers['ETag'])
        assert again.status_code == 304, (name, r.headers['ETag'])
        assert r.headers['Cache-Control'] == 'no-cache'


@pytest.fixture
def plugin_pages(tmp_path, monkeypatch):
    folder = tmp_path / 'plugins'
    pages = {}
    for _, plugin, name in PLUGIN_PAGES:
        (folder / plugin).mkdir(parents=True, exist_ok=True)
        pages[plugin] = _page(plugin.encode())
        (folder / plugin / name).write_bytes(pages[plugin])
        monkeypatch.setitem(plugins_mod._loaded_plugins, plugin, types.SimpleNamespace())
    monkeypatch.setattr(plugins_mod, 'PLUGINS_DIR', str(folder))
    return pages


@pytest.mark.parametrize('coding', CODINGS)
@pytest.mark.parametrize('url,plugin,name', PLUGIN_PAGES)
def test_a_plugin_page_reload_gets_a_304_in_every_coding(fetch, plugin_pages, url, plugin, name, coding):
    # a streamed body keeps its request context until it is read, so each one is read at once
    r = fetch(url, coding=coding)
    assert r.status_code == 200
    assert r.headers.get('Content-Encoding') == coding
    assert _decode(coding, r.get_data()) == plugin_pages[plugin]
    etag = r.headers['ETag']

    again = fetch(url, coding=coding, etag=etag)
    assert again.status_code == 304, (url, coding, etag)
    assert again.get_data() == b''
    assert again.headers['ETag'] == etag
    assert fetch(url, method='head', coding=coding, etag=etag).status_code == 304
    stale = fetch(url, coding=coding, etag='"other"')
    assert stale.status_code == 200
    assert _decode(coding, stale.get_data()) == plugin_pages[plugin]


@pytest.mark.parametrize('coding', CODINGS)
def test_the_service_worker_reload_gets_a_304_and_keeps_its_headers(fetch, coding):
    with open(os.path.join(ROOT, 'web', 'sw.js'), 'rb') as fh:
        sw = fh.read()
    r = fetch('/sw.js', coding=coding)
    assert r.status_code == 200
    assert r.headers.get('Content-Encoding') == coding
    assert _decode(coding, r.get_data()) == sw
    again = fetch('/sw.js', coding=coding, etag=r.headers['ETag'])
    assert again.status_code == 304
    assert again.get_data() == b''
    for resp in (r, again):
        assert resp.headers['Cache-Control'] == 'no-cache, no-store, must-revalidate'
        assert resp.headers['Service-Worker-Allowed'] == '/'
