"""The LDAP tab says when the saved settings send passwords readable or unchecked, and takes the CA.

A directory set up before STARTTLS and the certificate check became the defaults keeps
running in plain text or without the check. The tab shows an amber note while the saved
settings have LDAP on or a server set and the transport is plain text or unverified: what
that means and what to do. It is about the saved settings, so ticking a box in the form does
not hide it, saving does. What runs is what the server reads it as (ldap_transport), so a
server stored with an ldap:// scheme and LDAPS ticked is plain text there too. The CA
textarea shows with the Verify TLS Certificate box, goes out with the save and the test and
comes back with the read. LDAPS and STARTTLS exclude each other in the form, and an IP
address in the server field with the check on gets a line about the name check. The test
result lists the Transport step and, for a refused certificate, the hint that points to the
CA field.

The runtime tests drive the built bundle in headless Chromium against the fake server of
test_ha_ui.py, with a save that the next read answers with. They skip where Playwright is
not installed. LW Nov 2026
"""
import json
import re
from urllib.parse import urlparse

import pytest

from test_ha_ui import SSE_TOKEN, _App, _FakeServer, _classes, _read, browser  # noqa: F401 (browser is a fixture)

CA = ('-----BEGIN CERTIFICATE-----\n'
      'MIIBdzCCAR2gAwIBAgIUQ29ycCBSb290IENBIGZvciB0aGUgVUkgdGVzdDAKBggqhkjOPQQDAjAXMRUwEwYDVQQD\n'
      '-----END CERTIFICATE-----')
NOTE = '[data-ldap-transport-note]'
PLAIN_TEXT = 'LDAP runs in plain text'
UNCHECKED_TEXT = 'LDAP uses TLS without checking the certificate'
DASHES = (chr(0x2014), chr(0x2013))

FRESH = {'ldap_enabled': False, 'ldap_server': '', 'ldap_port': 389, 'ldap_use_ssl': False,
         'ldap_use_starttls': True, 'ldap_verify_tls': True, 'ldap_ca_cert': '',
         'ldap_bind_dn': '', 'ldap_base_dn': '', 'ldap_group_mappings': []}
PLAIN = dict(FRESH, ldap_enabled=True, ldap_server='dc1.corp.example', ldap_use_starttls=False,
             ldap_verify_tls=False, ldap_bind_dn='CN=svc,DC=corp,DC=example',
             ldap_base_dn='DC=corp,DC=example', ldap_bind_password='********')
UNCHECKED = dict(PLAIN, ldap_use_starttls=True)
SAVE_CALL = ('POST', '/api/settings/server')
TEST_CALL = ('POST', '/api/settings/ldap/test')


@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


def _tab(modal):
    at = modal.index("{activeTab === 'ldap' && (")
    return modal[at:modal.index("{activeTab === 'oidc' && (", at)]


# --- source --------------------------------------------------------------------------------

def test_the_note_reads_the_saved_settings_not_the_form(modal):
    tab = _tab(modal)
    assert '{ldapSaved && ldapSaved.on && !(ldapSaved.tls && ldapSaved.verified) && (' in tab
    load = modal[modal.index('// MK: Feb 2026 - Load LDAP settings'):]
    load = load[:load.index('// NS: Load OIDC')]
    assert 'setLdapSaved({' in load and "ldap_ca_cert: data.ldap_ca_cert || ''" in load


def test_no_dash_in_what_the_tab_says(modal):
    tab = _tab(modal)
    added = [line for line in tab.splitlines() if 'ldapSaved' in line or 'CA Certificate' in line
             or 'plain text' in line or 'ldapTestResult.hint' in line or 'trust store' in line]
    assert added and not [d for d in DASHES if d in ''.join(added)]


def test_every_class_is_in_the_static_tailwind_build(modal):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_tab(modal)) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('data-ldap-transport-note', 'ldap_ca_cert:data.ldap_ca_cert', PLAIN_TEXT, UNCHECKED_TEXT):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _answer(saved):
    """The settings read: what is stored, and ldap_transport as the server works it out."""
    from pegaprox.utils.ldap import ldap_transport
    kind, checked = ldap_transport(saved.get('ldap_server'), saved.get('ldap_use_ssl'),
                                   saved.get('ldap_use_starttls'), saved.get('ldap_verify_tls'))
    return dict(saved, ldap_transport={'kind': kind, 'checked': checked})


class _SettingsServer(_FakeServer):
    """The fake of test_ha_ui.py, with a settings save that the next read answers with."""

    def __init__(self, settings, test_answer=None, save_answer=None):
        self.saved = dict(settings)
        extra = {('GET', '/api/settings/server'): (200, _answer(self.saved)),
                 ('GET', '/api/plugins'): (200, []),
                 SAVE_CALL: save_answer or (200, {'success': True}),
                 TEST_CALL: (200, test_answer or {'success': True, 'steps': []}),
                 **SSE_TOKEN}
        super().__init__(role='standalone', layout='modern', extra=extra)

    def handle(self, route):
        req = route.request
        if req.method == 'POST' and urlparse(req.url).path == SAVE_CALL[1] and self.extra[SAVE_CALL][0] == 200:
            body = json.loads(req.post_data or '{}')
            self.saved.update({k: v for k, v in body.items() if k != 'ldap_bind_password'})
            self.extra[('GET', '/api/settings/server')] = (200, _answer(self.saved))
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(settings, **kw):
        app = _App(browser, _SettingsServer(settings, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _to_ldap(app):
    page = app.page
    app.open_settings()
    page.get_by_role('button', name='LDAP / AD', exact=True).first.click()
    page.get_by_role('button', name='Save LDAP Settings').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _bodies(app, call):
    return list(app.server.bodies.get(call[1], []))


def _click_and_wait(app, call, button, seconds=4):
    before = len(_bodies(app, call))
    reads = app.server.calls.count(('GET', '/api/settings/server'))
    app.page.get_by_role('button', name=button, exact=True).first.click()
    for _ in range(seconds * 10):
        if len(_bodies(app, call)) > before:
            break
        app.page.wait_for_timeout(100)
    sent = _bodies(app, call)
    assert len(sent) > before, f'{call} was not sent: {app.server.calls[-5:]}'
    if call == SAVE_CALL and app.server.extra[SAVE_CALL][0] == 200:
        for _ in range(seconds * 10):
            if app.server.calls.count(('GET', '/api/settings/server')) > reads:
                break
            app.page.wait_for_timeout(100)
    app.page.wait_for_timeout(400)
    return sent[-1]


def _note(page):
    return page.locator(NOTE)


def _ca(page):
    return page.get_by_label('CA Certificate (PEM)')


def test_runtime_a_fresh_install_starts_encrypted_and_checked_without_a_note(open_app):
    app = open_app(FRESH)
    page = _to_ldap(app)
    assert page.get_by_label('STARTTLS', exact=True).is_checked()
    assert not page.get_by_label('SSL (LDAPS, port 636)').is_checked()
    assert page.get_by_label('Verify TLS Certificate').is_checked()
    assert _ca(page).is_visible() and _ca(page).input_value() == ''
    assert _note(page).count() == 0
    assert not app.errors, app.errors


def test_runtime_plain_text_shows_the_note_until_the_fix_is_saved(open_app):
    app = open_app(PLAIN)
    page = _to_ldap(app)
    note = _note(page)
    note.first.wait_for(timeout=3000)
    assert note.get_attribute('data-ldap-transport-note') == 'plain'
    text = note.inner_text()
    assert PLAIN_TEXT in text and 'readable' in text and 'STARTTLS or LDAPS' in text
    # no TLS, no certificate to check and no CA to paste
    assert _ca(page).count() == 0 and page.get_by_label('Verify TLS Certificate').count() == 0

    page.get_by_label('STARTTLS', exact=True).check()
    _ca(page).wait_for(timeout=3000)
    page.get_by_label('Verify TLS Certificate').check()
    _ca(page).fill(CA)
    # the form is not saved yet: the note is about what runs
    assert _note(page).count() == 1

    sent = _click_and_wait(app, SAVE_CALL, 'Save LDAP Settings')
    assert sent['ldap_use_starttls'] is True and sent['ldap_verify_tls'] is True
    assert sent['ldap_ca_cert'] == CA
    assert _note(page).count() == 0
    # and the CA comes back with the read that followed the save
    assert app.server.calls.count(('GET', '/api/settings/server')) >= 2
    assert _ca(page).input_value() == CA
    assert not app.errors, app.errors


def test_runtime_tls_without_the_check_has_its_own_note(open_app):
    app = open_app(UNCHECKED)
    page = _to_ldap(app)
    _note(page).first.wait_for(timeout=3000)
    assert _note(page).get_attribute('data-ldap-transport-note') == 'unverified'
    text = _note(page).inner_text()
    assert UNCHECKED_TEXT in text and 'pose as the directory' in text and 'CA certificate' in text
    assert _ca(page).is_visible()
    page.get_by_label('Verify TLS Certificate').check()
    assert _note(page).count() == 1
    _click_and_wait(app, SAVE_CALL, 'Save LDAP Settings')
    assert _note(page).count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('settings,shown', [
    (dict(PLAIN, ldap_enabled=False), True),                       # a server is set
    (dict(PLAIN, ldap_server=''), True),                           # LDAP is on
    (dict(PLAIN, ldap_enabled=False, ldap_server=''), False),      # neither: nothing runs
    (dict(PLAIN, ldap_use_ssl=True, ldap_verify_tls=True), False),
    (dict(PLAIN, ldap_use_starttls=True, ldap_verify_tls=True), False),
    # ldap3 goes by the scheme: plain text, whatever the toggles say
    (dict(PLAIN, ldap_server='ldap://dc1.corp.example', ldap_use_ssl=True, ldap_verify_tls=True), True),
])
def test_runtime_the_note_follows_the_saved_settings(open_app, settings, shown):
    app = open_app(settings)
    page = _to_ldap(app)
    assert _note(page).count() == (1 if shown else 0)
    assert not app.errors, app.errors


def test_runtime_a_ca_the_server_turns_down_is_said_and_the_note_stays(open_app):
    err = ('The LDAP CA certificate could not be read. Paste one or more PEM certificates, '
           'each starting with -----BEGIN CERTIFICATE-----.')
    app = open_app(UNCHECKED, save_answer=(400, {'error': err, 'code': 'LDAP_CA_CERT_INVALID'}))
    page = _to_ldap(app)
    page.get_by_label('Verify TLS Certificate').check()
    _ca(page).fill('not a certificate')
    _click_and_wait(app, SAVE_CALL, 'Save LDAP Settings')
    page.get_by_text('The LDAP CA certificate could not be read').first.wait_for(timeout=3000)
    assert _note(page).count() == 1
    assert not [e for e in app.errors if '400' not in e], app.errors


def test_runtime_the_test_shows_the_transport_step(open_app):
    answer = {'success': True, 'message': 'LDAP connection successful', 'steps': [
        {'step': 'Server connection', 'status': 'ok', 'detail': 'dc1.corp.example:389'},
        {'step': 'STARTTLS', 'status': 'ok'},
        {'step': 'Transport', 'status': 'ok',
         'detail': 'STARTTLS, certificate checked against the CA certificate in the settings'},
        {'step': 'Service account bind', 'status': 'ok', 'detail': 'CN=svc,DC=corp,DC=example'}]}
    app = open_app(dict(UNCHECKED, ldap_verify_tls=True, ldap_ca_cert=CA), test_answer=answer)
    page = _to_ldap(app)
    sent = _click_and_wait(app, TEST_CALL, 'Test')
    assert sent['ldap_ca_cert'] == CA and sent['ldap_verify_tls'] is True
    row = page.get_by_text('Transport', exact=True).first.locator('xpath=..')
    row.wait_for(timeout=3000)
    assert 'certificate checked against the CA certificate in the settings' in row.inner_text()
    assert '✓' in row.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_plain_transport_is_a_warning_and_a_refused_certificate_shows_the_hint(open_app):
    hint = ('If the directory certificate comes from an internal CA, paste that CA certificate into '
            '"CA Certificate" in the LDAP settings.')
    plain = {'success': True, 'steps': [
        {'step': 'Server connection', 'status': 'ok', 'detail': 'dc1.corp.example:389'},
        {'step': 'Transport', 'status': 'warning', 'detail': 'plain text - passwords cross the network readable'}]}
    app = open_app(PLAIN, test_answer=plain)
    page = _to_ldap(app)
    _click_and_wait(app, TEST_CALL, 'Test')
    row = page.get_by_text('Transport', exact=True).first.locator('xpath=..')
    assert '⚠' in row.inner_text() and 'plain text' in row.inner_text()

    app.server.extra[TEST_CALL] = (200, {'success': False, 'hint': hint,
                                         'error': 'wrap socket error: certificate verify failed',
                                         'steps': [{'step': 'Server connection', 'status': 'ok'},
                                                   {'step': 'STARTTLS', 'status': 'error',
                                                    'detail': 'certificate verify failed'}]})
    _click_and_wait(app, TEST_CALL, 'Test')
    page.get_by_text(hint).first.wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_a_stored_scheme_shows_the_plain_text_note(open_app):
    app = open_app(dict(PLAIN, ldap_server='ldap://dc1.corp.example', ldap_use_ssl=True, ldap_verify_tls=True))
    page = _to_ldap(app)
    _note(page).first.wait_for(timeout=3000)
    assert _note(page).get_attribute('data-ldap-transport-note') == 'plain'
    # the form still shows the toggles as stored; the save takes the scheme apart
    assert page.get_by_label('SSL (LDAPS, port 636)').is_checked()
    assert not app.errors, app.errors


def test_runtime_ldaps_and_starttls_exclude_each_other(open_app):
    app = open_app(FRESH)
    page = _to_ldap(app)
    ldaps, starttls = page.get_by_label('SSL (LDAPS, port 636)'), page.get_by_label('STARTTLS', exact=True)
    port = page.locator('input[type="number"]').first
    assert starttls.is_checked() and not ldaps.is_checked()
    ldaps.check()
    page.wait_for_timeout(150)
    assert ldaps.is_checked() and not starttls.is_checked() and port.input_value() == '636'
    starttls.check()
    page.wait_for_timeout(150)
    assert starttls.is_checked() and not ldaps.is_checked() and port.input_value() == '389'
    sent = _click_and_wait(app, SAVE_CALL, 'Save LDAP Settings')
    assert sent['ldap_use_starttls'] is True and sent['ldap_use_ssl'] is False
    assert not app.errors, app.errors


def test_runtime_an_ip_address_with_the_check_on_gets_a_line(open_app):
    app = open_app(FRESH)
    page = _to_ldap(app)
    server = page.get_by_placeholder('ldap.example.com')
    line = page.locator('[data-ldap-ip-hint]')
    for value, shown in (('10.0.0.5', True), ('dc1.corp.example', False), ('fd00::5', True),
                         ('ldaps://192.168.1.10:636', True), ('cafe:389', False)):
        server.fill(value)
        page.wait_for_timeout(100)
        assert line.count() == (1 if shown else 0), value
    server.fill('10.0.0.5')
    page.get_by_label('Verify TLS Certificate').uncheck()
    page.wait_for_timeout(100)
    assert line.count() == 0
    assert not app.errors, app.errors
