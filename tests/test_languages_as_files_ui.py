"""Every language but English is a file of its own (web/i18n/<lang>.json), English stays in the bundle.

translations.js was 7.5 of the 13 MB of web/index.html, and a browser shows one language with English
as its fallback. web/Dev/build.sh keeps the English block in the bundle as written, writes every other
block evaluated to web/i18n/<lang>.json and puts the first 16 hex of each file's sha256 into the
<head>. The head asks for the language the page opens in right away, next to the libraries. contexts.js
mounts the app once that file is in (in English after 4 s, switching when it comes), loads the language
the user, the lock or the server switches to before the page switches, and stays in English when a
file does not come.

The build tests read what build.sh wrote. The runtime tests drive the bundle in headless Chromium
against the fake server of tests/test_ha_ui.py, which serves web/i18n like the real route does
(GET /i18n/<lang>.json, tests/test_the_language_files_are_served.py).
LW Nov 2026
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

import pytest

from test_ha_ui import BASE, _FakeServer, browser  # noqa: F401 (browser is a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
MARKER = 'window.__pegaproxI18nFiles = {};'
IMMUTABLE = 'public, max-age=31536000, immutable'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _raw(*parts):
    with open(os.path.join(ROOT, *parts), 'rb') as fh:
        return fh.read()


def _bundle():
    return _read('web', 'index.html')


def _file_hashes(bundle):
    """The lang -> hash map build.sh put into the <head>, {} when there is none."""
    m = re.search(r'window\.__pegaproxI18nFiles = (\{[^;]*\});', bundle)
    return json.loads(m.group(1)) if m else {}


def _source_block(src, lang):
    start = src.index(f'\n            {lang}: {{\n')
    return src[start:src.index('\n            },', start)]


# --- the build ---------------------------------------------------------------------------------

def test_web_i18n_holds_one_file_per_language_but_english():
    folder = os.path.join(ROOT, 'web', 'i18n')
    have = sorted(os.listdir(folder)) if os.path.isdir(folder) else []
    assert have == sorted(f'{lang}.json' for lang in LANGS), have
    src = _read('web', 'src', 'translations.js')
    blocks = re.findall(r'^            ([a-z]{2}): \{$', src, re.M)
    assert sorted(blocks) == sorted(LANGS + ['en']), blocks
    supported = re.search(r"const SUPPORTED_LANGS = \[([^\]]*)\]", _read('web', 'src', 'contexts.js')).group(1)
    assert sorted(re.findall(r"'([a-z]{2})'", supported)) == sorted(LANGS + ['en'])


# the text of every string literal (escapes and all), to look values up in a few MB at once
LITERAL = re.compile(r"""'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`""")
KEY = re.compile(r"""^                (?:([A-Za-z_$][\w$]*)|'([^'\\]+)'|"([^"\\]+)")\s*:""", re.M)


def _literals(text):
    return {a or b or c for a, b, c in LITERAL.findall(text)}


def test_english_stays_in_the_bundle_and_the_others_left_it():
    bundle = _bundle()
    assert re.search(r'const translations\s*=\s*\{\s*en\s*:\s*\{', bundle)
    # as written in the source, the way the bundle always carried it
    assert 'bpNavTab:"Blueprints & Templates"' in bundle and "loginButton:'Sign In'" in bundle
    start = bundle.index('const translations=')
    declared = _literals(bundle[start:bundle.index('const LanguageContext', start)])
    everywhere = _literals(bundle)
    english = _literals(_source_block(_read('web', 'src', 'translations.js'), 'en'))
    for lang in LANGS:
        own = {v for v in json.loads(_raw('web', 'i18n', f'{lang}.json')).values()
               if len(v) >= 25 and v not in english}
        assert len(own) > 1000, (lang, len(own))
        assert not own & declared, (lang, sorted(own & declared)[:3])
        # a few German fallbacks stand in the code itself (t('x') || '...'), not the language
        assert len(own & everywhere) <= len(own) // 100, (lang, sorted(own & everywhere)[:3])


def test_each_language_file_is_its_block_of_the_source_evaluated():
    src = _read('web', 'src', 'translations.js')
    for lang in LANGS:
        assert os.path.isfile(os.path.join(ROOT, 'web', 'i18n', f'{lang}.json')), lang
        raw = _raw('web', 'i18n', f'{lang}.json')
        # one line of JSON, the keys of the block in their order, every value a string
        assert raw.endswith(b'}\n') and raw.count(b'\n') == 1, lang
        data = json.loads(raw)
        assert all(isinstance(v, str) for v in data.values()), lang
        keys = [a or b or c for a, b, c in KEY.findall(_source_block(src, lang))]
        assert set(data) == set(keys), (lang, sorted(set(keys) ^ set(data))[:5])
        assert list(data) == list(dict.fromkeys(keys)), lang
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed, the values are not compared')
    script = ("const vm = require('vm'), fs = require('fs');"
              "const t = vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8') + '\\n;translations;', {});"
              "const out = {}; for (const k of Object.keys(t)) out[k] = JSON.stringify(t[k]);"
              "process.stdout.write(JSON.stringify(out));")
    run = subprocess.run([node, '-e', script, os.path.join(ROOT, 'web', 'src', 'translations.js')],
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-500:]
    blocks = json.loads(run.stdout)
    for lang in LANGS:
        assert _read('web', 'i18n', f'{lang}.json') == blocks[lang] + '\n', lang


def test_the_bundle_names_each_file_by_its_hash():
    bundle = _bundle()
    files = _file_hashes(bundle)
    assert sorted(files) == sorted(LANGS), files
    for lang, h in files.items():
        assert re.fullmatch(r'[0-9a-f]{16}', h), (lang, h)
        assert h == hashlib.sha256(_raw('web', 'i18n', f'{lang}.json')).hexdigest()[:16], lang
    # in the <head>, ahead of the libraries, so the file is on its way while they load
    assert bundle.index('window.__pegaproxI18nFiles') < bundle.index("'/static/js/react.production.min.js'")
    assert bundle.index('window.__pegaproxI18nFiles') < bundle.index('</head>')
    # the shell keeps the empty map for build.sh, and the dev build (--restore) leaves it empty
    shell = _read('web', 'index.html.original')
    assert shell.count(MARKER) == 1 and MARKER not in bundle


def test_the_route_keeps_the_built_files_for_good_by_the_hash_of_the_bundle(api):
    client = api.app.test_client()
    files = _file_hashes(_bundle())
    assert sorted(files) == sorted(LANGS)
    for lang, h in files.items():
        r = client.get(f'/i18n/{lang}.json?v={h}', base_url='http://localhost')
        assert r.status_code == 200, lang
        assert r.get_data() == _raw('web', 'i18n', f'{lang}.json')
        assert r.headers['Cache-Control'] == IMMUTABLE, lang
        assert r.mimetype == 'application/json'


# --- runtime -----------------------------------------------------------------------------------

# every text #root shows, from the first render on
WATCH_ROOT = """(() => {
    window.__rootTexts = [];
    new MutationObserver(() => {
        const root = document.getElementById('root');
        const text = root ? root.textContent : '';
        const seen = window.__rootTexts;
        if (text && seen[seen.length - 1] !== text) seen.push(text.slice(0, 4000));
    }).observe(document, { childList: true, subtree: true, characterData: true });
})();"""

# the login form (loginTitle) and the dashboard without clusters (addCluster), per language
TITLE = {'en': 'Sign in to PegaProx', 'de': 'Bei PegaProx anmelden', 'fr': 'Connexion à PegaProx',
         'it': 'Accedi a PegaProx', 'pl': 'Zaloguj do PegaProx'}
ADD = {'it': 'Aggiungi cluster', 'fr': 'Ajouter un Cluster'}


class _Page:
    """The bundle against _FakeServer, with what localStorage holds before the first script and a
    hand on the language files: held back (hold) or answered with a status of their own (status),
    for the first status_times of them when that is set. clock installs Playwright's clock, time
    runs as usual until a test moves it on."""

    def __init__(self, browser, server, storage=None, status=None, hold=False, locale='en-US',
                 status_times=None, clock=False):
        self.server = server
        self.ctx = browser.new_context(viewport={'width': 1400, 'height': 900}, locale=locale)
        if clock:
            self.ctx.clock.install()
        seed = {'pegaprox-shortcuts-hint-shown': '1'}
        seed.update(storage or {})
        self.ctx.add_init_script("""(() => { try {
            for (const u of ['admin', 'viewer']) localStorage.setItem('pegaprox_sponsor_v2:' + u, String(Date.now() + 1e10));
            const seed = %s;
            for (const k of Object.keys(seed)) localStorage.setItem(k, seed[k]);
        } catch (e) {} })();""" % json.dumps(seed))
        self.ctx.add_init_script(WATCH_ROOT)
        self.status, self.hold, self.status_times = status, hold, status_times
        self.held, self.files = [], []
        self.errors, self.warnings = [], []
        self.page = self.ctx.new_page()
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('console', self._console)
        self.page.route('**/*', self._handle)
        self.page.goto(BASE + '/', wait_until='load')

    def _console(self, msg):
        if msg.type == 'error' and 'Failed to load resource' not in msg.text:
            self.errors.append(msg.text[:300])
        if msg.type == 'warning' and '[i18n]' in msg.text:
            self.warnings.append(msg.text)

    def _handle(self, route):
        url = route.request.url
        if '/i18n/' in url:
            self.files.append(url[len(BASE):])
            if self.hold:
                self.held.append(route)
                return None
            if self.status and self.status_times != 0:
                if self.status_times:
                    self.status_times -= 1
                return route.fulfill(status=self.status, body='{"error": "nope"}',
                                     headers={'Content-Type': 'application/json'})
        return self.server.handle(route)

    def release(self):
        self.hold = False
        held, self.held = self.held, []
        for route in held:
            self.server.handle(route)

    def texts(self):
        return self.page.evaluate('() => window.__rootTexts')

    def see(self, text, timeout=8000):
        self.page.get_by_text(text, exact=True).first.wait_for(timeout=timeout)

    def close(self):
        self.ctx.close()


@pytest.fixture
def open_page(browser):
    pages = []

    def _open(storage=None, status=None, hold=False, locale='en-US', logged_out=True, status_times=None,
              clock=False, **server_kw):
        server_kw.setdefault('role', 'standalone')
        server = _FakeServer(**server_kw)
        server.logged_out = logged_out
        p = _Page(browser, server, storage=storage, status=status, hold=hold, locale=locale,
                  status_times=status_times, clock=clock)
        pages.append(p)
        return p
    yield _open
    for p in pages:
        p.close()


def _url(lang):
    return f'/i18n/{lang}.json?v={_file_hashes(_bundle()).get(lang, "?")}'


def _form(p, timeout=12000):
    """Waits for the login form, in whichever language."""
    p.page.wait_for_function('(titles) => titles.some(t => (document.getElementById("root") || {}).textContent'
                             '.includes(t))', arg=list(TITLE.values()), timeout=timeout)


def _shows(p, lang, texts=None):
    """Whether the login form is up in lang and in nothing else."""
    texts = p.texts() if texts is None else texts
    form = [t for t in texts if any(title in t for title in TITLE.values())]
    return bool(form) and all(TITLE[lang] in t for t in form)


LOCK_FR = json.dumps({'layout': '', 'language': 'fr', 'admins': False})


@pytest.mark.parametrize('storage,locale,lang', [
    ({'pegaprox-language': 'de'}, 'en-US', 'de'),
    # what the cached lock pins outranks the user's own pick
    ({'pegaprox-language': 'de', 'pegaprox-ui-lock': LOCK_FR}, 'en-US', 'fr'),
    # nothing stored: the browser's language
    ({}, 'it-IT', 'it'),
])
def test_runtime_the_page_opens_in_its_language_from_the_first_render(open_page, storage, locale, lang):
    p = open_page(storage=storage, locale=locale)
    _form(p)
    p.page.wait_for_timeout(300)
    # one file, the one of the opening language by the hash of the bundle
    assert p.files == [_url(lang)], p.files
    # the form never showed in another language, not even for a moment
    assert _shows(p, lang), p.texts()
    assert not p.errors and not p.warnings, (p.errors, p.warnings)


@pytest.mark.parametrize('status', [404, 500])
def test_runtime_a_language_file_that_fails_leaves_the_page_in_english(open_page, status):
    p = open_page(storage={'pegaprox-language': 'de'}, status=status)
    _form(p)
    p.page.wait_for_timeout(300)
    assert p.files == [_url('de')]
    assert _shows(p, 'en'), p.texts()
    # no key stands in for a text, nothing threw, and it was said once
    root = p.page.locator('#root').inner_text()
    assert 'loginTitle' not in root and 'loginButton' not in root
    assert not p.errors, p.errors
    assert len(p.warnings) == 1 and 'de' in p.warnings[0], p.warnings
    # the form works
    p.page.locator('input').first.fill('admin')


def test_runtime_picking_the_language_again_asks_again_for_a_file_that_failed(open_page):
    # the <head> got a 503 (a restart, a failover), the server is fine by the time the user clicks
    p = open_page(storage={'pegaprox-language': 'de'}, status=503, status_times=1)
    _form(p)
    p.page.wait_for_timeout(300)
    assert p.files == [_url('de')] and _shows(p, 'en'), (p.files, p.texts())
    # DE is the language the page has, so the click changes nothing but the file is asked for again
    p.page.locator('button[title="Deutsch"]').click()
    p.see(TITLE['de'])
    assert p.files == [_url('de'), _url('de')], p.files
    assert p.page.get_by_text(TITLE['en'], exact=True).count() == 0
    assert not p.errors and len(p.warnings) == 1, (p.errors, p.warnings)


def test_runtime_the_session_restore_asks_again_for_the_language_of_the_account(open_page):
    # signed in, German for the account and in the browser; the early request failed
    p = open_page(storage={'pegaprox-language': 'de'}, status=503, status_times=1,
                  logged_out=False, language='de')
    p.see('Cluster hinzufügen', timeout=12000)
    assert p.page.get_by_text('Add Cluster', exact=True).count() == 0
    assert p.files == [_url('de'), _url('de')], p.files
    assert not p.errors and len(p.warnings) == 1, (p.errors, p.warnings)


def test_runtime_an_early_request_that_stalls_lets_go_of_its_language(open_page):
    # the request of the <head> never gets an answer; the page starts in English after 4 s
    p = open_page(storage={'pegaprox-language': 'de'}, hold=True, clock=True)
    _form(p)
    assert p.files == [_url('de')] and len(p.held) == 1 and _shows(p, 'en')
    # past the 15 s every language request gets, counted from the <head>
    p.ctx.clock.fast_forward('00:12')
    p.page.wait_for_timeout(300)
    # that request is gone for good; the next ones get their answer
    p.hold, p.held = False, []
    p.page.locator('button[title="English"]').click()
    p.page.locator('button[title="Deutsch"]').click()
    p.see(TITLE['de'])
    assert p.files == [_url('de'), _url('de')], p.files
    # the stall was said once, as any other file that did not come
    assert len(p.warnings) == 1 and 'de' in p.warnings[0], p.warnings
    assert not p.errors, p.errors


def test_runtime_a_slow_file_lets_the_page_start_in_english_and_switch_when_it_comes(open_page):
    p = open_page(storage={'pegaprox-language': 'de'}, hold=True)
    t0 = time.time()
    _form(p)
    waited = time.time() - t0
    # it waited for the file a while (4 s from the start of the bundle), then went ahead
    assert waited > 2.5, waited
    assert p.files == [_url('de')] and len(p.held) == 1
    assert _shows(p, 'en')
    p.release()
    p.see(TITLE['de'])
    assert p.page.get_by_text(TITLE['en'], exact=True).count() == 0
    # asked for once, the early request of the <head> was taken over
    assert p.files == [_url('de')]
    assert not p.errors and not p.warnings, (p.errors, p.warnings)


def test_runtime_switching_loads_the_file_first_and_keeps_the_old_language_meanwhile(open_page):
    p = open_page(storage={'pegaprox-language': 'en'}, hold=True)
    p.see(TITLE['en'])
    # English is in the bundle, nothing to fetch
    assert p.files == []
    p.page.locator('button[title="Deutsch"]').click()
    p.page.wait_for_timeout(500)
    assert p.files == [_url('de')]
    # while the file is on the way the form stays English, no key shows
    assert p.page.get_by_text(TITLE['en'], exact=True).count() == 1
    assert 'loginTitle' not in p.page.locator('#root').inner_text()
    assert p.page.evaluate("() => localStorage.getItem('pegaprox-language')") == 'de'
    p.release()
    p.see(TITLE['de'])
    assert _shows(p, 'de', p.texts()[-1:])
    # back to English needs nothing, and German again is there already
    p.page.locator('button[title="English"]').click()
    p.see(TITLE['en'])
    p.page.locator('button[title="Deutsch"]').click()
    p.see(TITLE['de'])
    assert p.files == [_url('de')]
    assert not p.errors and not p.warnings, (p.errors, p.warnings)


def test_runtime_the_language_of_the_account_and_a_switch_after_sign_in_load_their_files(open_page):
    # the server says Italian on session restore, the browser holds nothing
    p = open_page(logged_out=False, language='it')
    p.see(ADD['it'])
    assert p.files == [_url('it')], p.files
    assert p.page.evaluate("() => localStorage.getItem('pegaprox-language')") == 'it'
    # a switch of a signed-in user goes to the server as well
    p.page.locator('button[title="Français"]').click()
    p.see(ADD['fr'])
    assert p.files == [_url('it'), _url('fr')], p.files
    assert ('PUT', '/api/user/preferences') in p.server.calls
    assert not p.errors and not p.warnings, (p.errors, p.warnings)


def test_runtime_a_lock_that_arrives_loads_its_language(open_page):
    lock = {'layout': '', 'language': 'pl', 'admins': False}
    p = open_page(storage={'pegaprox-language': 'en'},
                  extra={('GET', '/api/interface/lock'): (200, lock)})
    p.see(TITLE['pl'])
    p.page.wait_for_timeout(300)
    assert p.files == [_url('pl')], p.files
    # the cached copy makes the next page open in Polish right away
    assert json.loads(p.page.evaluate("() => localStorage.getItem('pegaprox-ui-lock')"))['language'] == 'pl'
    assert not p.errors and not p.warnings, (p.errors, p.warnings)
