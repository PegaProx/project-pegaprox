"""Classic Corporate says it is frozen and offers the switch to Corporate Redesigned.

Classic Corporate only gets fixes from now on. A bar under its header says so, with a Switch
now button and Dismiss; a header button switches as well and stays after the bar is closed.
The switch saves only ui_layout, so the palette of the top bar toggle (light, dark or the
system choice) carries over. Neither shows in Corporate Redesigned, Modern or Cloud, nor
under an admin lock that pins Corporate (the server would refuse the switch there).

The runtime tests drive the built bundle in headless Chromium against the lock-aware fake
server of tests/test_interface_lock_ui.py and skip where Playwright is not installed.
LW Nov 2026
"""
import re

import pytest

from test_ha_ui import LANGS, TOASTS_JS, _blocks, browser  # noqa: F401  (browser is a fixture)
from test_interface_lock_ui import HA_CHAIN, open_page  # noqa: F401  (open_page is a fixture)

KEYS = ('corpClassicDeprecated', 'corpClassicSwitchNow', 'corpClassicSwitchTitle')
BAR = '[data-corp-classic-notice]'
SWITCH = '[data-corp-switch]'
DASHES = (chr(0x2014), chr(0x2013))


def _value(block, key):
    found = re.search(rf"^\s*{key}: '((?:[^'\\]|\\.)*)',$", block, re.M)
    assert found, key
    return found.group(1)


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_in_every_language_once_before_the_ha_chain(lang):
    block = _blocks()[lang]
    chain = block.index(HA_CHAIN)
    for key in KEYS:
        assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)
        assert block.index(f'{key}:') < chain, (lang, key)
        assert not any(d in _value(block, key) for d in DASHES), (lang, key)


@pytest.mark.parametrize('lang', LANGS)
def test_the_notice_names_the_new_layout_and_where_to_switch_back(lang):
    block = _blocks()[lang]
    text = _value(block, 'corpClassicDeprecated')
    assert 'Corporate Redesigned' in text, lang
    assert _value(block, 'myProfile') in text, lang


# --- runtime -------------------------------------------------------------------------------

def _shown(app):
    return app.page.locator(BAR).count(), app.page.locator(SWITCH).count()


def _variant(app):
    return app.page.evaluate("document.body.dataset.corpVariant || ''")


@pytest.mark.parametrize('via', ['bar', 'header'])
def test_runtime_classic_corporate_switches_to_the_redesign(open_page, via):
    app = open_page(layout='corporate', language='en')
    assert _shown(app) == (1, 1)
    text = app.page.locator(BAR).inner_text()
    assert 'Classic Corporate is deprecated' in text and 'My Profile' in text, text
    if via == 'bar':
        app.page.locator(BAR).get_by_role('button', name=re.compile('Switch now', re.I)).click()
    else:
        app.page.locator(SWITCH).click()
    app.page.wait_for_function("() => document.body.dataset.corpVariant === 'redesigned'", timeout=8000)
    assert app.server.puts == [(200, {'ui_layout': 'corporate-redesigned'})]
    assert app.page.evaluate("document.body.getAttribute('data-layout')") == 'corporate'
    assert _shown(app) == (0, 0)
    assert 'Layout Style: Corporate Redesigned' in app.page.evaluate(TOASTS_JS)
    assert not app.errors, app.errors


def test_runtime_the_light_palette_survives_the_switch(open_page):
    app = open_page(layout='corporate', language='en', theme='corporateLight',
                    init_js="try { localStorage.setItem('corp-theme', 'light'); } catch (e) {}")
    assert app.page.evaluate("document.body.dataset.corpTheme") == 'light'
    app.page.locator(SWITCH).click()
    app.page.wait_for_function("() => document.body.dataset.corpVariant === 'redesigned'", timeout=8000)
    app.page.wait_for_timeout(300)
    assert app.page.evaluate("document.body.dataset.corpTheme") == 'light'
    assert app.page.evaluate("localStorage.getItem('corp-theme')") == 'light'
    assert not app.errors, app.errors


def test_runtime_a_system_choice_survives_the_switch(open_page):
    app = open_page(layout='corporate', language='en', theme='system',
                    init_js="try { localStorage.setItem('pegaprox-theme', 'system'); } catch (e) {}")
    app.page.locator(SWITCH).click()
    app.page.wait_for_function("() => document.body.dataset.corpVariant === 'redesigned'", timeout=8000)
    app.page.wait_for_timeout(300)
    assert app.page.evaluate("localStorage.getItem('pegaprox-theme')") == 'system'
    assert not app.errors, app.errors


def test_runtime_dismiss_closes_the_bar_for_good_and_keeps_the_header_button(open_page):
    app = open_page(layout='corporate', language='en')
    app.page.locator(BAR).get_by_role('button', name=re.compile('Dismiss', re.I)).click()
    app.page.wait_for_timeout(300)
    assert _shown(app) == (0, 1)
    assert app.page.evaluate("localStorage.getItem('corp-classic-notice')") == 'closed'
    app.page.reload(wait_until='load')
    app.wait_for_app()
    assert _shown(app) == (0, 1)
    assert app.server.puts == []
    assert _variant(app) == ''
    assert not app.errors, app.errors


def test_runtime_the_bar_speaks_the_page_language(open_page):
    app = open_page(layout='corporate', language='de')
    text = app.page.locator(BAR).inner_text()
    assert 'abgekündigt' in text and 'Mein Profil' in text, text
    assert 'corpClassic' not in app.page.locator('header').inner_text() + text
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate-redesigned', 'modern', 'cloud'])
def test_runtime_other_layouts_show_neither(open_page, layout):
    app = open_page(layout=layout, language='en')
    assert _shown(app) == (0, 0)
    assert not app.errors, app.errors


@pytest.mark.parametrize('own', ['corporate', 'corporate-redesigned'])
def test_runtime_a_corporate_lock_shows_neither(open_page, own):
    # the lock pins classic Corporate, also over a user's own Corporate Redesigned
    app = open_page(admin=False, layout=own, language='en', lock={'layout': 'corporate'})
    assert app.page.evaluate("document.body.getAttribute('data-layout')") == 'corporate'
    assert _variant(app) == ''
    assert _shown(app) == (0, 0)
    assert not app.errors, app.errors


def test_runtime_a_refused_switch_stays_classic_and_follows_the_lock(open_page):
    # the lock read failed, so the page offers the switch, and the server refuses it
    app = open_page(admin=False, layout='corporate', language='en', lock={'layout': 'corporate'},
                    lock_fails=True)
    assert _shown(app) == (1, 1)
    app.page.locator(SWITCH).click()
    app.page.wait_for_timeout(1200)
    assert app.server.puts == [(403, {'ui_layout': 'corporate-redesigned'})]
    assert _variant(app) == ''
    assert _shown(app) == (0, 0)
    assert any('administrator' in x for x in app.page.evaluate(TOASTS_JS)), app.page.evaluate(TOASTS_JS)
    assert not app.errors, app.errors
