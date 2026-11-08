"""Automatic failover ships as a beta (#625): the cards say so.

Where the server offers it, the automatic failover card and the witness card carry a small
"Beta" badge next to their title, and the leader reads one line under the switch: new in
this release, try it first, the way back to manual is always open. A server that does not
offer it shows none of it: it sends auto: null and no card renders, and one that reports a
voter config but refuses the switch or the witness code (409 HA_AUTO_NOT_SHIPPED) turns
both into the note the cards had before, haAutoNotShipped.

The runtime tests drive the built bundle in headless Chromium against the fake server of
test_ha_auto_ui.py; they skip where Playwright is not installed.
LW
"""
import ast
import re

import pytest

from test_ha_auto_ui import (  # noqa: F401  (browser is a fixture)
    EM_DASH, NOT_SHIPPED, NOT_SHIPPED_NOTE, _GroupServer, _auto, _row, _running, _switch, _value, _witness, browser)
from test_ha_ui import LANGS, PASSWORD, _App, _block, _blocks, _member, _open_ha, _read, _toasts

NOTE = ('Beta: new in this release. Try it in your setup before you rely on it; you can switch back to '
        'manual failover at any time.')
WITNESS_NOT_SHIPPED = 'A witness votes in automatic failover only, so it can be added once this release offers it.'


@pytest.fixture(scope='module')
def stage2():
    modal = _read('web', 'src', 'settings_modal.js')
    return modal[modal.index('// LW Oct 2026 (#625) - stage 2 of the group, for HaPanel'):]


# -- source ---------------------------------------------------------------------------------------------

def test_the_server_offers_it_and_still_knows_the_refusal():
    """The beta is the constant switched on; the refusal stays for a server that has it off."""
    vote = _read('pegaprox', 'core', 'ha_vote.py')
    tree = ast.parse(vote)
    value = {n.targets[0].id: n.value.value for n in tree.body
             if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant)}
    assert value['AUTO_MODE_SHIPPED'] is True
    assert value['NOT_SHIPPED_ERROR'] == NOT_SHIPPED
    assert _value(_blocks()['en'], 'haAutoNotShipped') == NOT_SHIPPED_NOTE


def test_the_badge_and_the_line_go_with_the_refusal(stage2):
    auto = _block(stage2, 'function HaAutoCard(', 'function HaWitnessCard(')
    witness = _block(stage2, 'function HaWitnessCard(', 'function HaZoneCard(')
    assert "const HA_BETA_BADGE = '" in stage2
    # next to each title, gone once the server refused
    assert '{!notShipped && <span className={HA_BETA_BADGE} data-ha-beta="auto">{t(\'haAutoBeta\')}</span>}' in auto
    assert auto.index("{t('haAutoTitle')}</label>") < auto.index('data-ha-beta="auto"') < auto.index('data-ha-auto-mode={mode}')
    assert '{!notShipped && <span className={HA_BETA_BADGE} data-ha-beta="witness">{t(\'haAutoBeta\')}</span>}' in witness
    assert witness.index("'haWitnessTitle' : 'haWitnessAddTitle')}") < witness.index('data-ha-beta="witness"')
    # the line where the switch is, on the leader
    line = ("{leader && !notShipped && <p className=\"text-xs text-purple-300\" data-ha-auto-beta-note>"
            "{t('haAutoBetaNote')}</p>}")
    assert auto.count(line) == 1
    assert auto.index('id="pgha-auto"') < auto.index(line) < auto.index('{notShipped && !on && (')
    # the note of a server that refuses stays
    assert "{t('haAutoNotShipped')}" in auto and "{t('haWitnessNotShipped')}" in witness


def test_the_english_line_is_the_agreed_one():
    en = _blocks()['en']
    assert _value(en, 'haAutoBeta') == 'Beta'
    assert _value(en, 'haAutoBetaNote') == NOTE


@pytest.mark.parametrize('lang', LANGS)
def test_every_language_has_both_and_the_line_starts_with_its_badge(lang):
    block = _blocks()[lang]
    badge, note = _value(block, 'haAutoBeta'), _value(block, 'haAutoBetaNote')
    assert badge.strip() and note.startswith(badge), (lang, badge, note)
    assert EM_DASH not in note
    if lang != 'en':
        assert note != NOTE, lang
    # right next to the note of a server that refuses, in the stage 2 block
    lines = [m.group(1) for m in re.finditer(r'^ +(\w+): ', block, re.M)]
    at = lines.index('haAutoNotShipped')
    assert lines[at + 1:at + 3] == ['haAutoBeta', 'haAutoBetaNote'], lang


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('HA_BETA_BADGE', 'data-ha-auto-beta-note', 'data-ha-beta', "t('haAutoBetaNote')", NOTE):
        assert needle in bundle, needle


def test_house_rules():
    for text in (_read('tests', 'test_ha_beta_ui.py'), _block(_read('web', 'src', 'settings_modal.js'),
                                                               'const HA_BETA_BADGE', 'const HA_GROUP_FIELD')):
        assert EM_DASH not in text
        assert 'VM' + 'ware' not in text and 'v' + 'Center' not in text


# -- runtime --------------------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _GroupServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _beside_title(card):
    """Where the badge sits against the title of its card: the gap from the end of the title
    and how far apart their middles are vertically. None without a badge."""
    return card.evaluate('''(card) => {
        const badge = card.querySelector('[data-ha-beta]');
        const h4 = card.querySelector('h4');
        if (!badge || !h4) return null;
        // the label of the switch on the leader, the title span on a member, the bare text otherwise
        const el = h4.querySelector('label') || h4.querySelector('span:not([data-ha-beta]):not([data-ha-auto-mode])');
        let r;
        if (el) {
            r = el.getBoundingClientRect();
        } else {
            const range = document.createRange();
            range.selectNodeContents([...h4.childNodes].find(n => n.nodeType === 3 && n.textContent.trim()));
            r = range.getBoundingClientRect();
        }
        const b = badge.getBoundingClientRect();
        return { gap: b.left - r.right, dy: Math.abs((b.top + b.bottom) / 2 - (r.top + r.bottom) / 2) };
    }''')


def _writes(app):
    return [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith('/api/ha/')]


@pytest.mark.parametrize('mode', ['manual', 'auto'])
def test_runtime_the_leader_reads_beta_at_both_cards_and_the_line_under_the_switch(open_app, mode):
    """Before the switch and once it is on: the way back to manual is the same switch."""
    app = open_app(auto=_auto() if mode == 'manual' else _running(), shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    witness = panel.locator('[data-ha-witness]')
    assert card.get_attribute('data-ha-auto') == mode
    for box, kind in ((card, 'auto'), (witness, 'witness')):
        badge = box.locator('[data-ha-beta]')
        assert badge.count() == 1 and badge.get_attribute('data-ha-beta') == kind
        assert badge.inner_text().strip() == 'Beta'
        at = _beside_title(box)
        assert 0 <= at['gap'] <= 16 and at['dy'] <= 4, (kind, at)
    note = card.locator('[data-ha-auto-beta-note]')
    assert note.inner_text().strip() == NOTE
    # under the switch, in the same card
    switch, line = _switch(page).bounding_box(), note.bounding_box()
    assert line['y'] >= switch['y'] + switch['height'] - 0.5, (switch, line)
    assert _switch(page).get_attribute('aria-checked') == ('true' if mode == 'auto' else 'false')
    assert _switch(page).is_enabled()
    # the titles are what they were: the switch is named by its label alone
    assert witness.locator('h4').inner_text().strip() == ('Add a witness' if mode == 'manual' else 'Witness')
    assert panel.locator('[data-ha-auto-not-shipped], [data-ha-witness-not-shipped]').count() == 0
    assert not _writes(app)
    assert not app.errors, app.errors


def test_runtime_a_member_reads_the_badges_and_has_no_line(open_app):
    """No switch on a member, so nothing to say under it; the badges show all the same."""
    app = open_app(role='standby', members=[_member('b', role='active', source=True), _member('c')],
                   auto=_auto(mode='auto_pending', witness=_witness(), members=[_row('b'), _row('c')]), shipped=True)
    page = app.page
    panel = _open_ha(app, 'standby')
    panel.locator('[data-ha-witness]').wait_for(timeout=3000)
    assert panel.locator('[data-ha-auto] [data-ha-beta="auto"]').count() == 1
    assert panel.locator('[data-ha-witness] [data-ha-beta="witness"]').count() == 1
    at = _beside_title(panel.locator('[data-ha-auto]'))
    assert 0 <= at['gap'] <= 16 and at['dy'] <= 4, at
    assert _switch(page).count() == 0
    assert panel.locator('[data-ha-auto-beta-note]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['active', 'standby'])
def test_runtime_a_server_without_it_shows_no_beta(open_app, role):
    """auto: null, as a server with automatic failover off sends it: no card, no badge, no line."""
    kw = {'members': [_member('b', role='active', source=True)]} if role == 'standby' else {}
    app = open_app(role=role, **kw)
    panel = _open_ha(app, role)
    panel.locator('[data-ha-zone]').wait_for(timeout=3000)
    assert panel.locator('[data-ha-auto], [data-ha-witness]').count() == 0
    assert panel.locator('[data-ha-beta], [data-ha-auto-beta-note]').count() == 0
    assert 'Beta' not in panel.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_refused_switch_takes_the_beta_away(open_app):
    """A server that reports a voter config and still refuses the switch: the badges and the
    line go, the note of a release without it comes, on both cards."""
    app = open_app(auto=_auto())
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    # what the status said: offered, until the server says otherwise
    assert panel.locator('[data-ha-beta]').count() == 2
    assert card.locator('[data-ha-auto-beta-note]').count() == 1
    _switch(page).click()
    page.fill('#pgha-auto-password', PASSWORD)
    card.get_by_role('button', name='Switch on').click()
    card.locator('[data-ha-auto-not-shipped]').wait_for(timeout=3000)
    assert card.locator('[data-ha-auto-not-shipped]').inner_text().strip() == NOT_SHIPPED_NOTE
    assert panel.locator('[data-ha-witness-not-shipped]').inner_text().strip() == WITNESS_NOT_SHIPPED
    assert panel.locator('[data-ha-beta], [data-ha-auto-beta-note]').count() == 0
    assert 'Beta' not in panel.inner_text()
    assert _switch(page).is_disabled()
    assert not any('not available' in t for t in _toasts(page))
    assert not app.errors, app.errors


def test_runtime_a_refused_witness_code_takes_the_beta_away_too(open_app):
    app = open_app(auto=_auto())
    page = app.page
    panel = _open_ha(app, 'active')
    witness = panel.locator('[data-ha-witness]')
    assert witness.locator('[data-ha-beta]').count() == 1
    page.fill('#pgha-witness-password', PASSWORD)
    witness.get_by_role('button', name='Create witness code').click()
    witness.locator('[data-ha-witness-not-shipped]').wait_for(timeout=3000)
    assert panel.locator('[data-ha-beta], [data-ha-auto-beta-note]').count() == 0
    assert panel.locator('[data-ha-auto-not-shipped]').inner_text().strip() == NOT_SHIPPED_NOTE
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', LANGS)
def test_runtime_the_badge_and_the_line_in_every_language(open_app, lang):
    block = _blocks()[lang]
    app = open_app(language=lang, auto=_auto(), shipped=True)
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.locator('button', has_text=_value(block, 'pgHaTab')).first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    note = panel.locator('[data-ha-auto-beta-note]').inner_text().strip()
    assert not re.search(r'\bhaAuto\w*', panel.inner_text())
    if lang != 'en':
        # t() falls back to English where a language misses the key
        assert note != NOTE, lang
    assert note == _value(block, 'haAutoBetaNote')
    badges = panel.locator('[data-ha-beta]').evaluate_all('r => r.map(x => x.innerText.trim())')
    assert badges == [_value(block, 'haAutoBeta')] * 2
    assert not app.errors, app.errors
