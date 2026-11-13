"""Numbers and dates by the UI language, and the update check without force first, in Corporate
Redesigned (Preview) (round 8, stage B3).

- Numbers and dates of the preview follow the UI language, not the browser: one helper (crLocale in
  cr.js) turns the language shown into its BCP 47 tag (de, en, zh-CN, pl, fr, es, pt, ko, it) and
  every toLocaleString / toLocaleDateString / toLocaleTimeString / Intl.NumberFormat /
  Intl.DateTimeFormat call of the cr files gets it; the cr files format fmtDate, fmtTime and fmtClock
  dates through its twins. An English page in a German browser shows "7.4M" packets and 11/22/2026,
  a German page in an English browser "7,4 Mio." and 22.11.2026. Classic code keeps the browser.
- The Updates check dialog leaves "ignore the server's copy" (force) unticked; ticking it still
  sends force.

The browser locale is the context's (navigator.language and Intl's default). PEGAPROX_CR_BUNDLE=<file>
serves another bundle, PEGAPROX_CR_SRC=<dir> reads other sources (the counterproof against the stage
start). Skips without Playwright. LW Nov 2026
"""
import os
import re

import pytest

import test_corp_redesigned_node_cfg_ui as cfg
import test_corp_redesigned_node_ui as nodeui
import test_corp_redesigned_perf_ui as perf
import test_corp_redesigned_updates_ui as upd
from test_corp_redesigned_guard_ui import DETERMINISTIC, NODE_CERTS, NODE_TASK_LIST, _GuardApp, _corp_cluster

LAYOUT = 'corporate-redesigned'
ROOT = os.path.join(os.path.dirname(__file__), '..')
SRC = os.environ.get('PEGAPROX_CR_SRC') or os.path.join(ROOT, 'web', 'src')
# the brief's table: UI language -> BCP 47 tag
TAGS = {'de': 'de', 'en': 'en', 'zh': 'zh-CN', 'pl': 'pl', 'fr': 'fr', 'es': 'es', 'pt': 'pt', 'ko': 'ko', 'it': 'it', 'ru': 'ru'}
NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'
COMPACT = "{ notation: 'compact', maximumFractionDigits: 1 }"
# fmtDate's parts (constants.js), 24 h as the default time format
DATE_PARTS = ("{ year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', "
              "second: '2-digit', hour12: false }")


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


class _InLocale:
    """A browser whose new contexts carry a browser locale."""

    def __init__(self, br, locale):
        self.br, self.locale = br, locale

    def new_context(self, **kw):
        return self.br.new_context(locale=self.locale, **kw)


@pytest.fixture
def opener(browser):
    apps = []

    def _open(server, locale='en-US', viewport=(1600, 1000), br=None):
        app = _GuardApp(_InLocale(br or browser, locale), server, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _browser_lang(page):
    return page.evaluate('() => navigator.language')


def _num(page, tag, n):
    return page.evaluate(f'([tag, n]) => new Intl.NumberFormat(tag || undefined, {COMPACT}).format(n)', [tag, n])


def _day(page, tag, sec):
    return page.evaluate('([tag, sec]) => new Date(sec * 1000).toLocaleDateString(tag || undefined)', [tag, sec])


def _stamp(page, tag, sec):
    return page.evaluate(f'([tag, sec]) => new Intl.DateTimeFormat(tag || undefined, {DATE_PARTS}).format(new Date(sec * 1000))', [tag, sec])


def _nics(app):
    page = app.page
    perf._node_monitor(app)
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    page.locator('[data-cr-pf-group="nics"]').click()
    page.locator('[data-cr-pf-nics-read]').click()
    page.locator('[data-cr-pf-nics="ok"]').wait_for(timeout=8000)
    return page.locator('[data-cr-pf-nic="eno1"] td').all_inner_texts()


def _certs(app, lang):
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('[data-cr-tabs="node"] [data-cr-tab="configure"]').click()
    label = {'en': 'Certificates', 'de': 'Zertifikate'}[lang]
    page.locator('.corp-subnav-item', has_text=re.compile(rf'^\s*{label}\s*$')).first.click()
    sec = cfg._sec(page, 'certs')
    sec.locator('[data-cr-nc-cert="pve-ssl.pem"]').wait_for(timeout=8000)
    return sec


# --- 13. numbers and dates by the UI language ------------------------------------------------------

# (UI language, browser locale): each pair formats apart, so the browser's own form is told from ours
PAIRS = [('en', 'de-DE'), ('de', 'en-US'), ('zh', 'en-US')]


@pytest.mark.parametrize('lang,locale', PAIRS, ids=[f'{a}-ui-{b}-browser' for a, b in PAIRS])
def test_runtime_packet_counters_follow_the_ui_language(opener, lang, locale):
    app = opener(perf._PfServer(layout=LAYOUT, language=lang), locale)
    page = app.page
    assert _browser_lang(page) == locale
    cells = _nics(app)
    want, browser_form = _num(page, TAGS[lang], 7_400_000), _num(page, None, 7_400_000)
    assert want != browser_form, (want, browser_form)
    # eno1: 7.4 million packets received, 3.1 million sent
    assert want in cells and _num(page, TAGS[lang], 3_100_000) in cells, (want, cells)
    assert browser_form not in cells, cells
    _no_errors(app)


@pytest.mark.parametrize('lang,locale', PAIRS[:2], ids=[f'{a}-ui-{b}-browser' for a, b in PAIRS[:2]])
def test_runtime_certificate_dates_follow_the_ui_language(opener, lang, locale):
    app = opener(cfg._CfgServer(layout=LAYOUT, language=lang), locale)
    page = app.page
    sec = _certs(app, lang)
    ssl = [c for c in NODE_CERTS if c['filename'] == 'pve-ssl.pem'][0]
    until = sec.locator('[data-cr-nc-cert="pve-ssl.pem"] [data-cr-nc-k="until"]').inner_text()
    want, browser_form = _day(page, TAGS[lang], ssl['notafter']), _day(page, None, ssl['notafter'])
    assert want != browser_form, (want, browser_form)
    assert want in until and browser_form not in until, (want, until)
    since = sec.locator('[data-cr-nc-cert="pve-ssl.pem"] [data-cr-nc-k="from"]').inner_text()
    assert _day(page, TAGS[lang], ssl['notbefore']) in since, since
    _no_errors(app)


@pytest.mark.parametrize('lang,locale', PAIRS[:2], ids=[f'{a}-ui-{b}-browser' for a, b in PAIRS[:2]])
def test_runtime_a_task_start_follows_the_ui_language(opener, lang, locale):
    """The node task list dates through fmtDate's parts in the UI language (crDate, cr_tasks.js)."""
    app = opener(nodeui._NodeServer(layout=LAYOUT, language=lang), locale)
    page = app.page
    nodeui._open_node(page)
    page.locator('[data-cr-tabs="node"] [data-cr-tab="monitor"]').click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Tasks\s*$')).first.click()
    page.locator('[data-cr-nt][data-cr-nt-read="ok"]').wait_for(timeout=8000)
    task = NODE_TASK_LIST[1]
    row = nodeui._trow(page, task['upid']).inner_text()
    want, browser_form = _stamp(page, TAGS[lang], task['starttime']), _stamp(page, None, task['starttime'])
    assert want != browser_form, (want, browser_form)
    assert want in row and browser_form not in row, (want, row)
    _no_errors(app)


def test_runtime_a_language_switch_formats_again(opener):
    """The language picked in the profile reaches the formatters without a reload."""
    app = opener(perf._PfServer(layout=LAYOUT, language='en'), 'en-US')
    page = app.page
    assert _num(page, 'en', 7_400_000) in _nics(app)
    page.evaluate('() => window.__crLangProbe = 1')
    _switch_language(page, 'de')
    want = _num(page, 'de', 7_400_000)
    page.wait_for_function('(want) => Array.from(document.querySelectorAll(\'[data-cr-pf-nic="eno1"] td\')).some(td => td.innerText.trim() === want)',
                           arg=want, timeout=8000)
    # the same page, no reload
    assert page.evaluate('() => window.__crLangProbe') == 1
    _no_errors(app)


def _switch_language(page, code):
    page.locator('[data-user-menu]').first.click()
    page.locator('button', has_text='My Profile').first.click()
    sel = page.locator('select[aria-label="Select language"]')
    sel.wait_for(timeout=5000)
    sel.select_option(code)
    page.keyboard.press('Escape')


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_layout_german_counters_and_dates_fit(opener, browser, firefox, engine, width):
    br = browser if engine == 'chromium' else firefox
    app = opener(perf._PfServer(layout=LAYOUT, language='de'), 'en-US', viewport=(width, 900), br=br)
    page = app.page
    _nics(app)
    assert page.evaluate(NO_SIDEWAYS), f'sideways scroll at {width} in {engine}'
    over = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-pf-nic="eno1"] td'))
        .filter(td => td.scrollWidth > td.clientWidth + 1).map(td => td.innerText)''')
    assert over == [], over
    _no_errors(app)


# --- 13. the one helper, in the sources -------------------------------------------------------------

def _src(name):
    with open(os.path.join(SRC, name), encoding='utf-8') as f:
        return f.read()


def _cr_files():
    return sorted(f for f in os.listdir(SRC) if re.match(r'^cr(_\w+)?\.js$', f))


LOCALE_CALL = re.compile(r'\.toLocale(?:Date|Time)?String\(([^)]*)\)|new Intl\.(?:NumberFormat|DateTimeFormat)\(([^,)]*)')


def test_source_the_one_helper_maps_the_nine_ui_languages():
    cr = _src('cr.js')
    m = re.search(r'const CR_LOCALE_TAGS = \{([^}]*)\}', cr)
    assert m, 'cr.js has the table of UI language to BCP 47 tag (CR_LOCALE_TAGS)'
    got = dict(re.findall(r"(\w+): '([\w-]+)'", m.group(1)))
    assert got == TAGS, got
    langs = re.search(r"const SUPPORTED_LANGS = \[([^\]]*)\]", _src('contexts.js')).group(1)
    assert sorted(re.findall(r"'(\w+)'", langs)) == sorted(TAGS)
    assert 'function crLocale(lang = crUi.lang)' in cr
    # the dashboard tells the language it draws in, only for the preview
    assert re.search(r'const \{ t, language \} = useTranslation\(\);', _src('dashboard.js'))
    assert 'if (isCorpRedesigned) crUiLocale(language);' in _src('dashboard.js')


def test_source_every_locale_call_of_the_cr_files_gets_the_ui_language():
    bad = []
    for name in _cr_files():
        s = _src(name)
        for m in LOCALE_CALL.finditer(s):
            arg = (m.group(1) if m.group(1) is not None else m.group(2)).strip()
            line = s.count('\n', 0, m.start()) + 1
            # crDtf in cr.js hands the tag it took from crLocale() on as loc
            if not (arg.startswith('crLocale(') or (name == 'cr.js' and arg == 'loc')):
                bad.append(f'{name}:{line}: {m.group(0)}')
        # the classic fmtDate / fmtTime / fmtClock format in the browser's locale
        for m in re.finditer(r'(?<![\w.])fmt(?:Date|Time|Clock)\(', s):
            bad.append(f'{name}:{s.count(chr(10), 0, m.start()) + 1}: {m.group(0)} (classic, browser locale)')
    assert bad == [], bad


# what node_modals.js formats in the browser's locale: all of it classic (the QDevice job log in a
# classic layout, QdeviceDetail, NodeModal and the classic branches of CorporateNodeDetailView); a
# variant part has no call of its own
NODE_MODALS_CLASSIC = [
    "d.toLocaleTimeString()", "readAt.toLocaleTimeString()", "(s.rx_packets || 0).toLocaleString()", "(s.tx_packets || 0).toLocaleString()",
    "data.time?.localtime ? new Date(data.time", "new Date(c.notafter * 1000).toLocaleDateString()",
    "new Date(t.starttime*1000).toLocaleString()", "new Date(task.starttime * 1000).toLocaleString()",
    "new Date(data.time.localtime * 1000).toLocaleString(undefined, { timeZone: 'UTC' })",
    "new Date(data.time.time * 1000).toLocaleString(undefined, { timeZone: 'UTC' })",
    "new Date(cert.notafter * 1000).toLocaleDateString()",
]


def test_source_node_modals_formats_only_in_classic_parts():
    lines = [ln for ln in _src('node_modals.js').split('\n')
             if LOCALE_CALL.search(ln) or re.search(r'(?<![\w.])fmt(?:Date|Time|Clock)\(', ln)]
    assert len(lines) == len(NODE_MODALS_CLASSIC), [ln.strip()[:160] for ln in lines]
    for ln, want in zip(lines, NODE_MODALS_CLASSIC):
        assert want in ln, (want, ln.strip()[:200])


# --- 12. the update check: force unticked first --------------------------------------------------

def test_runtime_the_update_check_does_not_force_by_default(opener):
    app = opener(upd._UpdServer(layout=LAYOUT))
    page = app.page
    upd._tab(app)
    dlg = upd._open_check(page)
    tick = dlg.locator('[data-cr-upd-force]')
    assert not tick.is_checked(), 'force is unticked when the dialog opens'
    assert tick.is_enabled()
    assert 'answers with its copy' in dlg.locator('[data-cr-upd-copy-note]').inner_text()
    page.locator('[data-cr-upd-confirm="check"]').click()
    upd._need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    assert [p[2] for p in upd._upd(app, 'POST', '/updates/check')] == [{'force': False}]
    # still selectable, and a new dialog starts unticked again
    dlg = upd._open_check(page)
    tick = dlg.locator('[data-cr-upd-force]')
    assert not tick.is_checked()
    tick.check()
    assert dlg.locator('[data-cr-upd-copy-note]').count() == 0
    page.locator('[data-cr-upd-confirm="check"]').click()
    assert upd._poll(app, lambda: len(upd._upd(app, 'POST', '/updates/check')) == 2)
    assert [p[2] for p in upd._upd(app, 'POST', '/updates/check')] == [{'force': False}, {'force': True}]
    _no_errors(app)
