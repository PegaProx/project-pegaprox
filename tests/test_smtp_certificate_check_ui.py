"""The SMTP section of the settings modal says whether the mail server's certificate is checked.

Mail used to go out over STARTTLS or SSL without a look at the relay's certificate, so
anyone on the path could pose as the relay and read the SMTP password and every alert.
The server now checks it (smtp_verify_tls), and a relay with a self-signed certificate
needs a way to turn that off. The box shows while TLS or SSL is on, goes with the save
and with the test mail like the other smtp_* fields, shows what the server says is in
effect, and turning it off puts a warning right below it.

A box that renders but never reaches the request would look like a setting that is not
there, so the runtime tests drive the built bundle in headless Chromium against the fake
server of test_ha_ui.py and read what the page sends. They skip where Playwright is not
installed.
LW Oct 2026
"""
import re

import pytest

from test_ha_ui import (  # noqa: F401  (browser is a fixture)
    LANGS, SSE_TOKEN, _App, _FakeServer, _blocks, _classes, _read, browser)

KEYS = ('smtpVerifyTls', 'smtpVerifyTlsWarning')
HA_CHAIN = '// LW Oct 2026 (#625) - the banners of a group that fails over automatically, for every user'
BOX_START = "{(serverSettings.smtp_tls || serverSettings.smtp_ssl) && ("
BOX_END = '{/* Test Email */}'
DASHES = (chr(0x2014), chr(0x2013))

LABEL = {'en': 'Verify the server certificate', 'de': 'Serverzertifikat prüfen'}
WARNING = {'en': 'The certificate of the mail server is not checked.',
           'de': 'Das Zertifikat des Mailservers wird nicht geprüft.'}
TITLE = {'en': 'PegaProx Settings', 'de': 'PegaProx Einstellungen'}
SAVE = {'en': 'Save SMTP Settings', 'de': 'SMTP Einstellungen speichern'}
TEST = {'en': 'Send Test Email', 'de': 'Test-Email senden'}


@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


def _box(modal):
    at = modal.index(BOX_START)
    return modal[at:modal.index(BOX_END, at)]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS:
        found = len(re.findall(rf'^\s*{key}:', block, re.M))
        assert found == 1, f'{key} is {found} times in {lang} - t() would show the raw key or the wrong one'


@pytest.mark.parametrize('lang', LANGS)
def test_the_new_keys_stay_out_of_the_pinned_ha_chain(lang):
    # the end of each language is a chain of HA blocks that other tests pin in order
    block = _blocks()[lang]
    chain = block.index(HA_CHAIN)
    for key in KEYS:
        assert block.index(f'{key}:') < chain, (lang, key)


def test_the_box_uses_the_new_keys_and_its_own_field(modal):
    box = _box(modal)
    assert "t('smtpVerifyTls')" in box and "t('smtpVerifyTlsWarning')" in box
    assert 'checked={serverSettings.smtp_verify_tls !== false}' in box
    assert 'smtp_verify_tls: e.target.checked' in box
    # the warning only while the check is off
    assert '{serverSettings.smtp_verify_tls === false && (' in box


def test_no_dash_in_what_this_change_added(modal):
    added = _box(modal) + ''.join(
        line for line in _read('web', 'src', 'translations.js').splitlines(True)
        if re.match(r'^\s*smtpVerifyTls(Warning)?:', line))
    assert not [d for d in DASHES if d in added]


def test_every_class_is_in_the_static_tailwind_build(modal):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_box(modal)) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('smtp_verify_tls:serverSettings.smtp_verify_tls!==false',
                   'smtp_verify_tls:data.smtp_verify_tls!==false', 'smtpVerifyTlsWarning'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

SETTINGS = {'domain': 'pegaprox-b.example', 'port': 5000, 'smtp_enabled': True,
            'smtp_host': 'mail.example.com', 'smtp_port': 587, 'smtp_user': 'alerts',
            'smtp_password': '', 'smtp_from_email': 'pegaprox@example.com',
            'smtp_from_name': 'PegaProx Alerts', 'smtp_tls': True, 'smtp_ssl': False,
            'smtp_verify_tls': True, 'alert_email_recipients': ['ops@example.com'], 'alert_cooldown': 300}
SAVE_CALL = ('POST', '/api/settings/server')
TEST_CALL = ('POST', '/api/settings/smtp/test')


def _extra(**settings):
    return {('GET', '/api/settings/server'): (200, dict(SETTINGS, **settings)),
            ('GET', '/api/plugins'): (200, []),
            SAVE_CALL: (200, {'success': True}),
            TEST_CALL: (200, {'success': True, 'message': 'Test email sent'}),
            **SSE_TOKEN}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(language='en', **settings):
        app = _App(browser, _FakeServer(role='standalone', layout='modern', language=language,
                                        extra=_extra(**settings)))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _to_smtp(app, lang='en'):
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.get_by_text(TITLE[lang]).first.wait_for(timeout=5000)
    page.get_by_role('button', name='Server', exact=True).first.click()
    page.get_by_role('button', name=SAVE[lang]).first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _box_of(page, lang='en'):
    return page.get_by_label(LABEL[lang], exact=True)


def _bodies(app, call):
    out, i = [], 0
    for m, p in app.server.calls:
        if p != call[1]:
            continue
        if m == call[0]:
            out.append(app.server.bodies[p][i])
        if m != 'GET':  # the fake server keeps no body for a read
            i += 1
    return out


def _send(app, call, button, seconds=4):
    """Click the button and return the body of the request it sent."""
    before = len(_bodies(app, call))
    reads = app.server.calls.count(('GET', '/api/settings/server'))
    app.page.get_by_role('button', name=button).first.click()
    for _ in range(seconds * 10):
        if len(_bodies(app, call)) > before:
            break
        app.page.wait_for_timeout(100)
    sent = _bodies(app, call)
    assert len(sent) > before, f'{call} was not sent: {app.server.calls[-5:]}'
    if call == SAVE_CALL:
        # the save reads the settings again: let that land before the next click
        for _ in range(seconds * 10):
            if app.server.calls.count(('GET', '/api/settings/server')) > reads:
                break
            app.page.wait_for_timeout(100)
        app.page.wait_for_timeout(300)
    return sent[-1]


def _warning(page, lang='en'):
    return page.get_by_text(WARNING[lang])


def test_runtime_the_box_reaches_the_test_mail_and_the_save(open_app):
    app = open_app()
    page = _to_smtp(app)
    box = _box_of(page)
    assert box.is_visible() and box.is_checked()
    assert _warning(page).count() == 0

    # the default goes out as it is, next to the fields that were there before
    page.get_by_placeholder('test@example.com').fill('ops@example.com')
    sent = _send(app, TEST_CALL, TEST['en'])
    assert sent['smtp_verify_tls'] is True
    assert sent['smtp_tls'] is True and sent['smtp_ssl'] is False and sent['smtp_host'] == 'mail.example.com'
    assert _send(app, SAVE_CALL, SAVE['en'])['smtp_verify_tls'] is True

    # turned off for a self-signed relay: the warning shows and both requests say so
    box = _box_of(page)
    box.uncheck()
    _warning(page).first.wait_for(timeout=3000)
    assert box.locator('xpath=ancestor::div[1]').inner_text().count('Security Warning') == 1
    sent = _send(app, TEST_CALL, TEST['en'])
    assert sent['smtp_verify_tls'] is False and sent['email'] == 'ops@example.com'
    sent = _send(app, SAVE_CALL, SAVE['en'])
    assert sent['smtp_verify_tls'] is False and sent['smtp_tls'] is True and sent['smtp_enabled'] is True
    assert not app.errors, app.errors


def test_runtime_the_box_shows_what_the_server_has_in_effect(open_app):
    # a relay the server already sends to unchecked: the page must not switch it back on
    app = open_app(smtp_verify_tls=False)
    page = _to_smtp(app)
    box = _box_of(page)
    assert box.is_visible() and not box.is_checked()
    _warning(page).first.wait_for(timeout=3000)
    assert _send(app, SAVE_CALL, SAVE['en'])['smtp_verify_tls'] is False

    # and turning the check back on clears the warning and is saved
    _box_of(page).check()
    page.wait_for_timeout(200)
    assert _warning(page).count() == 0
    assert _send(app, SAVE_CALL, SAVE['en'])['smtp_verify_tls'] is True
    assert not app.errors, app.errors


def test_runtime_the_box_shows_only_with_tls_or_ssl(open_app):
    app = open_app(smtp_verify_tls=False)
    page = _to_smtp(app)
    assert _box_of(page).is_visible()
    # plain SMTP has no certificate to check
    page.get_by_label('Use TLS (STARTTLS)').uncheck()
    page.wait_for_timeout(200)
    assert _box_of(page).count() == 0 and _warning(page).count() == 0
    page.get_by_label('Use SSL (SSL/TLS)').check()
    _box_of(page).wait_for(timeout=3000)
    assert not _box_of(page).is_checked()
    _warning(page).first.wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(language='de', smtp_verify_tls=False)
    page = _to_smtp(app, 'de')
    assert _box_of(page, 'de').is_visible()
    _warning(page, 'de').first.wait_for(timeout=3000)
    body = page.locator('body').inner_text()
    assert 'smtpVerifyTls' not in body and 'Sicherheitswarnung' in body
    assert not app.errors, app.errors
