"""The HTTP redirect field says what -1 and 0 do, and under it what the server runs.

The hint said "HTTP on same port redirects automatically" next to -1 as the default, while -1
switched exactly that off, and "0 = auto" without saying auto needs root. The server settings
now carry http_redirect_state (same_port, extra_port, extra_error), and a line under the field
shows it: green for the redirects that run, yellow for an extra port that did not come up, grey
when none runs. The grey line names reverse proxy mode only when it is on: the Flask fallback
server runs no redirect either. The two reasons the server names itself are translated.

Source checks, then the page itself in Chromium with the fake server of the pixel guard; the
runtime part skips where Playwright or the browser is not installed. LW Nov 2026
"""
import os
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
STATE_KEYS = ['httpRedirectStateSamePort', 'httpRedirectStateExtra', 'httpRedirectStateExtraFailed',
              'httpRedirectStateOff', 'httpRedirectStateNone', 'httpRedirectReasonPrivilege',
              'httpRedirectReasonInUse']
PLACEHOLDERS = {'httpRedirectStateSamePort': {'{port}'}, 'httpRedirectStateExtra': {'{port}'},
                'httpRedirectStateExtraFailed': {'{port}', '{reason}'}, 'httpRedirectStateOff': set(),
                'httpRedirectStateNone': set(), 'httpRedirectReasonPrivilege': set(),
                'httpRedirectReasonInUse': set()}


def _src(name):
    return (ROOT / 'web' / 'src' / name).read_text(encoding='utf-8')


def _blocks():
    lines = _src('translations.js').split('\n')
    starts = [(i, m.group(1)) for i, line in enumerate(lines)
              for m in [re.match(r'^ {12}([a-z]{2}): \{$', line)] if m]
    out = {}
    for n, (i, lang) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        keys = {}
        for j in range(i + 1, end):
            m = re.match(r"^ {16}([A-Za-z0-9_]+): '((?:[^'\\]|\\.)*)',?$", lines[j])
            if m:
                keys.setdefault(m.group(1), []).append((j, m.group(2)))
        out[lang] = keys
    return out


def _field():
    """The JSX of the redirect port field, from its label to the end of its cell."""
    src = _src('settings_modal.js')
    at = src.index("{t('httpRedirectPort') || 'HTTP Redirect Port'}")
    return src[at:src.index('{/* Reverse Proxy */}', at)]


@pytest.mark.parametrize('lang', LANGS)
def test_each_language_has_the_state_lines_once_right_after_the_hint(lang):
    block = _blocks()[lang]
    (hint_line, _), = block['httpRedirectPortHint']
    for n, key in enumerate(STATE_KEYS, 1):
        assert len(block.get(key, [])) == 1, f'{key} is {len(block.get(key, []))} times in {lang}'
        line, value = block[key][0]
        assert line == hint_line + n, f'{key} in {lang} is not with the hint'
        assert set(re.findall(r'\{\w+\}', value)) == PLACEHOLDERS[key], (lang, key, value)
        assert not any('‐' <= ch <= '―' or ch == '−' for ch in value), (lang, key)


@pytest.mark.parametrize('lang', LANGS)
def test_the_hint_says_what_minus_one_and_auto_do(lang):
    (_, hint), = _blocks()[lang]['httpRedirectPortHint']
    assert '-1 = ' in hint and '0 = ' in hint and '80' in hint, hint
    assert 'CAP_NET_BIND_SERVICE' in hint, hint
    assert 'HTTP-01' in hint, hint
    # the old hint offered 80 as an "on" value and called -1 "off"
    assert '80 = ' not in hint, hint
    assert not any('‐' <= ch <= '―' or ch == '−' for ch in hint), lang


def test_the_english_hint_no_longer_calls_minus_one_off():
    (_, hint), = _blocks()['en']['httpRedirectPortHint']
    assert '-1 = no extra port (default)' in hint
    assert 'Plain HTTP on the HTTPS port itself is always redirected' in hint


def test_the_field_shows_the_state_and_the_save_leaves_it_out():
    src = _src('settings_modal.js')
    assert 'http_redirect_state: data.http_redirect_state || null,' in src
    field = _field()
    assert '{serverSettings.http_redirect_state && (() => {' in field
    # the grey line picks one of two keys (below), every other key is looked up as it is
    for key in STATE_KEYS:
        if key not in ('httpRedirectStateOff', 'httpRedirectStateNone'):
            assert f"t('{key}')" in field, key
    # server values go in through a function: a string replacement reads $& and $`
    assert ".replace('{port}', () => String(st.same_port))" in field
    assert ".replace('{reason}', () => reason)" in field
    # the reasons as app.py words them, anything else as it came
    app_src = (ROOT / 'pegaprox' / 'app.py').read_text(encoding='utf-8')
    assert "_NEEDS_PORT_PRIVILEGE = 'needs root or CAP_NET_BIND_SERVICE'" in app_src
    assert "why = 'already in use'" in app_src
    assert "st.extra_error === 'needs root or CAP_NET_BIND_SERVICE' ? t('httpRedirectReasonPrivilege')" in field
    assert "st.extra_error === 'already in use' ? t('httpRedirectReasonInUse') : st.extra_error;" in field
    assert "t(serverSettings.reverse_proxy_enabled ? 'httpRedirectStateOff' : 'httpRedirectStateNone')" in field
    assert "'0 = auto (80 if root), -1 = disabled'" not in field
    # it is the server's to say: the save sends the number only
    save = src[src.index('const handleSaveServerSettings = async () => {'):]
    save = save[:save.index('\n            };\n')]
    assert "formData.append('http_redirect_port'" in save
    assert 'http_redirect_state' not in save


# -- runtime -------------------------------------------------------------------------------

BUNDLE = ROOT / 'web' / 'index.html'
NONE = {'same_port': None, 'extra_port': None, 'extra_error': ''}
SAME_EN = ('text-green-400', 'Running: plain HTTP on port 5000 is redirected to HTTPS')
SAME_DE = ('text-green-400', 'Aktiv: HTTP auf Port 5000 wird auf HTTPS umgeleitet')
# name: (language, http_redirect_state, reverse_proxy_enabled, the lines under the hint)
CASES = {
    'both': ('en', {'same_port': 5000, 'extra_port': 80, 'extra_error': ''}, False,
             [SAME_EN, ('text-green-400', 'Running: extra port 80 redirects to HTTPS')]),
    'refused': ('en', {'same_port': 5000, 'extra_port': 80, 'extra_error': 'needs root or CAP_NET_BIND_SERVICE'},
                False, [SAME_EN, ('text-yellow-400', 'Extra port 80 is not available: needs root or CAP_NET_BIND_SERVICE')]),
    'same only': ('en', {'same_port': 5000, 'extra_port': None, 'extra_error': ''}, False, [SAME_EN]),
    'reverse proxy': ('en', NONE, True,
                      [('text-gray-500', 'No redirect here: in reverse proxy mode the proxy handles HTTPS')]),
    # PEGAPROX_SERVER=flask, or no gevent: no redirect, and no reverse proxy either
    'flask fallback': ('en', NONE, False,
                       [('text-gray-500', 'No redirect here: the running server does not redirect plain HTTP')]),
    'refused de': ('de', {'same_port': 5000, 'extra_port': 80, 'extra_error': 'needs root or CAP_NET_BIND_SERVICE'},
                   False, [SAME_DE, ('text-yellow-400', 'Zusatzport 80 nicht verfügbar: braucht root oder CAP_NET_BIND_SERVICE')]),
    'in use de': ('de', {'same_port': 5000, 'extra_port': 8080, 'extra_error': 'already in use'}, False,
                  [SAME_DE, ('text-yellow-400', 'Zusatzport 8080 nicht verfügbar: bereits belegt')]),
    'os error de': ('de', {'same_port': 5000, 'extra_port': 8080, 'extra_error': 'Cannot assign requested address'},
                    False, [SAME_DE, ('text-yellow-400', 'Zusatzport 8080 nicht verfügbar: Cannot assign requested address')]),
}
TITLE = {'en': 'PegaProx Settings', 'de': 'PegaProx Einstellungen'}
# the lines in the cell of the field, after its hint
LINES = '''() => {
  const input = document.querySelector('input[type="number"][min="-1"]');
  if (!input) return null;
  const [hint, ...rest] = Array.from(input.parentElement.querySelectorAll('p'));
  return rest.map(p => [Array.from(p.classList).find(c => c.startsWith('text-') && c !== 'text-xs') || '', p.textContent]);
}'''


@pytest.fixture(scope='module')
def chromium():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.mark.parametrize('name', list(CASES))
def test_runtime_the_line_under_the_field_shows_the_state(chromium, name):
    from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer
    lang, state, behind_proxy, wanted = CASES[name]
    settings = {'domain': '', 'port': 5000, 'http_redirect_port': -1, 'http_redirect_state': state,
                'reverse_proxy_enabled': behind_proxy}
    server = _GuardServer(bundle=BUNDLE.read_bytes(), layout='modern', language=lang,
                          extra={('GET', '/api/settings/server'): (200, settings)})
    app = _GuardApp(chromium, server, storage={'pegaprox-language': lang})
    try:
        # _GuardApp.open_settings, with the title in this language
        app.page.locator('body').click(position={'x': 5, 'y': 400})
        app.page.keyboard.press('g')
        app.page.keyboard.press(',')
        app.page.get_by_text(TITLE[lang]).first.wait_for(timeout=5000)
        app.page.get_by_role('button', name='Server', exact=True).first.click()
        app.page.locator('input[type="number"][min="-1"]').first.wait_for(timeout=10000)
        lines = None
        for _ in range(20):
            lines = app.page.evaluate(LINES)
            if lines:
                break
            app.page.wait_for_timeout(150)
        assert [tuple(line) for line in lines or []] == wanted
        assert not [e for e in app.errors if 'pageerror' in e], app.errors
    finally:
        app.close()
