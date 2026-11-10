"""GET /i18n/<lang>.json serves the language files of the page (web/i18n, written by build.sh).

English is part of the bundle, every other language is a file the page fetches with ?v=<the first
16 hex of its sha256>. The route takes the eight names of UI_LANGUAGE_LOCKS without English and
nothing else to the disk. It goes out through the helper of the page (utils/index_page.py): read
once, each coding compressed once with its own ETag, a reload gets its 304. A request whose v names
the file as it is now may keep it for good, any other revalidates. Public like '/', since the login
form shows in the language too, and held by the same guards as '/' (the IP lists) and by no other.
MK Nov 2026
"""
import gzip
import hashlib
import json
import os

import pytest

import pegaprox.api.settings as settings_mod

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
LANGS = ['de', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
IMMUTABLE = 'public, max-age=31536000, immutable'


def _decode(enc, data):
    if enc is None:
        return data
    return {'gzip': gzip.decompress, 'br': getattr(brotli, 'decompress', None),
            'zstd': getattr(zstd, 'decompress', None)}[enc](data)


def _body(lang, text='eins'):
    words = {f'key{i}': f'{lang} {text} {i} ' + 'Wort ' * 8 for i in range(3000)}
    return (json.dumps(words, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def _v(data):
    return hashlib.sha256(data).hexdigest()[:16]


@pytest.fixture
def web(tmp_path, monkeypatch):
    """A web dir of our own: the page, a file per language, and two that are no language."""
    root = tmp_path / 'web'
    (root / 'i18n').mkdir(parents=True)
    (root / 'index.html').write_bytes(b'<!DOCTYPE html><html><head></head><body>page</body></html>')
    for lang in LANGS:
        (root / 'i18n' / f'{lang}.json').write_bytes(_body(lang))
    (root / 'i18n' / 'en.json').write_bytes(b'{"en": "not served"}\n')
    (root / 'i18n' / 'secrets.json').write_bytes(b'{"no": "way"}\n')
    monkeypatch.setattr(settings_mod, 'WEB_DIR', str(root))
    return root


@pytest.fixture
def fetch(api):
    client = api.app.test_client()

    def _fetch(path, method='get', coding=None, etag=None, **kw):
        headers = kw.pop('headers', {})
        if coding is not None:
            headers['Accept-Encoding'] = coding
        if etag is not None:
            headers['If-None-Match'] = etag
        return getattr(client, method)(path, headers=headers, base_url='http://localhost', **kw)
    return _fetch


def test_each_language_file_is_served_as_json(fetch, web):
    for lang in LANGS:
        r = fetch(f'/i18n/{lang}.json')
        assert r.status_code == 200, lang
        assert r.mimetype == 'application/json'
        assert r.get_data() == (web / 'i18n' / f'{lang}.json').read_bytes()
        assert r.headers['Vary'] == 'Accept-Encoding'


@pytest.mark.parametrize('path', [
    '/i18n/en.json',            # English is in the bundle
    '/i18n/secrets.json',       # a file in the folder is no language
    '/i18n/xx.json', '/i18n/DE.json', '/i18n/de.json.json', '/i18n/de',
    '/i18n/..%2findex.json', '/i18n/%2e%2e.json', '/i18n/../index.html',
    '/i18n/', '/i18n',
])
def test_nothing_but_the_eight_languages_reaches_the_disk(fetch, web, path):
    assert fetch('/i18n/de.json').status_code == 200
    r = fetch(path)
    assert r.status_code == 404, (path, r.status_code)
    assert b'not served' not in r.get_data() and b'way' not in r.get_data()
    assert b'page' not in r.get_data()


def test_the_route_takes_the_languages_the_ui_ships_but_english(fetch, web):
    from pegaprox.api.helpers import UI_LANGUAGE_LOCKS
    served = sorted(lang for lang in UI_LANGUAGE_LOCKS if fetch(f'/i18n/{lang}.json').status_code == 200)
    assert served == sorted(LANGS) == sorted(set(UI_LANGUAGE_LOCKS) - {'en'})


def test_a_v_that_names_the_file_keeps_it_for_good_and_any_other_revalidates(fetch, web):
    data = (web / 'i18n' / 'de.json').read_bytes()
    good = fetch(f'/i18n/de.json?v={_v(data)}')
    assert good.status_code == 200
    assert good.headers['Cache-Control'] == IMMUTABLE
    other = _v((web / 'i18n' / 'fr.json').read_bytes())
    for query in ('', '?v=', '?v=0000000000000000', f'?v={other}', f'?v={_v(data)[:12]}',
                  f'?v={hashlib.sha256(data).hexdigest()}', f'?v={_v(data).upper()}'):
        r = fetch(f'/i18n/de.json{query}')
        assert r.status_code == 200, query
        assert r.get_data() == data
        assert r.headers['Cache-Control'] == 'no-cache', query

    # a new file: the old v is no promise any more, the new one is
    (web / 'i18n' / 'de.json').write_bytes(_body('de', 'zwei, anders'))
    new = (web / 'i18n' / 'de.json').read_bytes()
    stale = fetch(f'/i18n/de.json?v={_v(data)}')
    assert stale.get_data() == new and stale.headers['Cache-Control'] == 'no-cache'
    assert fetch(f'/i18n/de.json?v={_v(new)}').headers['Cache-Control'] == IMMUTABLE


@pytest.mark.parametrize('coding', CODINGS + [None])
def test_each_coding_has_its_etag_and_a_reload_gets_a_304(fetch, web, coding):
    data = (web / 'i18n' / 'ko.json').read_bytes()
    for query in ('', f'?v={_v(data)}'):
        first = fetch(f'/i18n/ko.json{query}', coding=coding)
        assert first.status_code == 200
        assert first.headers.get('Content-Encoding') == coding
        assert _decode(coding, first.get_data()) == data
        if coding:
            assert len(first.get_data()) < len(data) // 3
        etag = first.headers['ETag']
        again = fetch(f'/i18n/ko.json{query}', coding=coding, etag=etag)
        assert again.status_code == 304, (query, coding)
        assert again.get_data() == b''
        assert again.headers['Cache-Control'] == first.headers['Cache-Control']
        head = fetch(f'/i18n/ko.json{query}', method='head', coding=coding)
        assert head.status_code == 200 and head.get_data() == b''
        assert head.headers['Content-Length'] == str(len(first.get_data()))
    tags = {fetch('/i18n/ko.json', coding=c).headers['ETag'] for c in CODINGS + [None]}
    assert len(tags) == len(CODINGS) + 1


def test_a_missing_file_is_a_404(fetch, web):
    (web / 'i18n' / 'pt.json').unlink()
    assert fetch('/i18n/pt.json').status_code == 404
    assert fetch('/i18n/es.json').status_code == 200


# --- the guards: those of '/', and no other ----------------------------------------------------

def _both(fetch, **kw):
    return fetch('/', **kw).status_code, fetch('/i18n/de.json', **kw).status_code


def test_no_session_is_needed(fetch, web):
    assert _both(fetch) == (200, 200)


def test_the_ip_allow_list_holds_it_like_the_page(fetch, web, monkeypatch):
    monkeypatch.setattr(settings_mod, '_ip_whitelist_enabled', True)
    monkeypatch.setattr(settings_mod, '_ip_whitelist', {'10.9.9.0/24'})
    monkeypatch.setattr(settings_mod, '_ip_blacklist', set())
    assert _both(fetch, environ_base={'REMOTE_ADDR': '192.0.2.7'}) == (403, 403)
    assert _both(fetch, environ_base={'REMOTE_ADDR': '10.9.9.4'}) == (200, 200)
    monkeypatch.setattr(settings_mod, '_ip_blacklist', {'10.9.9.4'})
    assert _both(fetch, environ_base={'REMOTE_ADDR': '10.9.9.4'}) == (403, 403)


def test_a_standby_serves_it_like_the_page(fetch, web, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'takes_writes', lambda: False)
    assert _both(fetch) == (200, 200)


def test_a_portal_only_account_gets_it_like_the_page(api, db, fetch, web):
    from pegaprox.utils.auth import create_session, hash_password
    salt, pw_hash = hash_password('Cust-Pass-123!')
    db.save_user('cust', {'password_salt': salt, 'password_hash': pw_hash, 'role': 'user', 'enabled': True,
                          'auth_source': 'local', 'language': 'de', 'portal_only': True, 'tenant_id': 'default'})
    with api.app.test_request_context('/', base_url='http://localhost'):
        sid = create_session('cust', 'user')
    headers = {'X-Session-ID': sid, 'Cookie': f'session_id={sid}'}
    assert _both(fetch, headers=dict(headers)) == (200, 200)
    # the API stays closed to it, the hook is not out of the way
    assert fetch('/api/clusters', headers=dict(headers)).status_code == 403

