"""An ESXi server with a wrong stored password does not sign the user off (#1142).

authFetch showed the "session expired" overlay for every 401 outside /auth/ and /sse, and
the ESXi routes handed the server's own 401 on. So a server whose password had changed
threw the user out at each click on it, and its settings could not be reached to fix or
remove it.

The browser now acts only on PegaProx's own 401: one carrying a code of
PegaProxApiErrors.SESSION_LOST. Any other 401 goes to the caller as an error, and
/auth/check is asked once whether the session is really gone (#144 keeps working behind a
proxy that answers 401 on its own). The server view shows what the server answered: for
UPSTREAM_AUTH that it refused the stored credentials, with the server's words and a way to
its settings; edit and remove stay in the header, in both layouts.

Source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, the way the other *_ui.py
tests do. They skip where Playwright is not installed. LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import SSE_TOKEN, _App, _FakeServer, _classes, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
KEYS = ['esxiCredentialsRefused', 'esxiCredentialsHint', 'esxiEditServer', 'esxiRemoveServer']
REFUSED = 'The ESXi server refused the stored credentials (HTTP 401)'
SERVER = {'id': 'v1', 'name': 'lab esxi', 'host': 'esx1.lab', 'port': 443, 'username': 'root',
          'server_type': 'esxi', 'ssl_verify': False, 'enabled': True, 'connected': False,
          'last_error': 'Authentication failed - check username/password', 'notes': '',
          'linked_clusters': []}
UPSTREAM = (502, {'error': REFUSED, 'code': 'UPSTREAM_AUTH', 'upstream_status': 401,
                  'detail': 'HTTP 401: {"error_type":"UNAUTHENTICATED"}'})
OURS = (401, {'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'})
# what an older backend, or a proxy in front, answers: a 401 without our code
FOREIGN = (401, {'error_type': 'UNAUTHENTICATED'})
READS = ('vms', 'hosts', 'datastores', 'networks', 'clusters')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (pos, lang) in enumerate(starts)}


def _added_blocks():
    dash = _read('web', 'src', 'dashboard.js')
    return [
        _between(_read('web', 'src', 'api_errors.js'), '// LW Oct 2026 (#1142)', '};'),
        _between(dash, '// when a 401 without one of our codes last made us ask', 'const authFetch = React'),
        _between(dash, '// LW Oct 2026 (#1142) - only a 401 with one', 'setConnectionError(null);'),
        _between(dash, '{/* LW Oct 2026 (#1142) - a server that refuses', '{vmwareActiveTab === \'vms\' && !vmwareSelectedVm && ('),
        _between(dash, 'const openVmwareEdit = (vmw) => {', 'const handleDeleteVMware = async'),
    ]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_string_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS:
        n = len(re.findall(rf'^\s*{key}:', block, re.M))
        assert n == 1, f'{key} is {n} times in {lang} - the UI would show the key'


def test_every_new_key_is_used():
    dash = _read('web', 'src', 'dashboard.js')
    for key in KEYS:
        assert f"t('{key}')" in dash, key


def test_the_overlay_waits_for_our_own_code():
    dash = _read('web', 'src', 'dashboard.js')
    fetcher = _between(dash, 'const authFetch = React.useCallback(', '}, [getAuthHeaders]);')
    # setSessionExpired only under our code, or after /auth/check said the session is gone
    assert fetcher.count('setSessionExpired(true)') == 2
    assert 'if (PegaProxApiErrors.sessionLost(body)) {' in fetcher
    assert "d.authenticated === false) setSessionExpired(true)" in fetcher
    # the add-cluster form signs off only on our own 401 too, the last other place reading one
    add = _between(dash, 'const handleAddCluster = async', 'const handleDeleteCluster = async')
    assert "response?.status === 401 && PegaProxApiErrors.sessionLost(err)" in add
    assert not re.search(r'status\s*===?\s*401\)', dash.replace('response?.status === 401 && ', ''))
    codes = re.search(r'SESSION_LOST: \[(.*?)\]', _read('web', 'src', 'api_errors.js'), re.S).group(1)
    assert sorted(re.findall(r"'([A-Z_]+)'", codes)) == sorted([
        'AUTH_REQUIRED', 'ACCOUNT_DELETED', 'ACCOUNT_DISABLED', 'INVALID_SESSION', 'INVALID_TOKEN',
        'HA_FORWARD_STALE_SIGN_IN'])


def test_no_em_dash_in_what_this_change_added():
    for block in _added_blocks():
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    for block in _blocks().values():
        for line in block.splitlines():
            if re.match(r'^\s*(esxiCredentials|esxiEditServer|esxiRemoveServer)', line):
                assert '\u2014' not in line and '\u2013' not in line, line


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _added_blocks():
        names |= _classes(block)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('SESSION_LOST', 'sessionLost(body)', 'data-esxi-error', 'data-session-expired',
                   'esxiCredentialsRefused', 'data-esxi-remove'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):
    apps = []

    def _open(vms=UPSTREAM, **kw):
        extra = dict(SSE_TOKEN)
        extra[('GET', '/api/vmware')] = (200, [SERVER])
        for what in READS:
            extra[('GET', f'/api/vmware/v1/{what}')] = vms if what == 'vms' else UPSTREAM
        extra[('PUT', '/api/vmware/v1')] = (200, dict(SERVER, connected=True, last_error=None))
        extra[('DELETE', '/api/vmware/v1')] = (200, {'message': 'VMware server lab esxi deleted'})
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _open_server(app):
    page = app.page
    page.locator('button', has_text='lab esxi').first.click()
    assert _wait_for_call(app, ('GET', '/api/vmware/v1/vms'), seconds=5)
    page.wait_for_timeout(600)
    return page


# the overlay by what it is, a portal on top of everything that says so, so the check also
# reads a bundle from before #1142 that had no data attribute on it
OVERLAY_JS = """() => Array.from(document.querySelectorAll('body > div.fixed'))
    .some(d => d.style.zIndex === '100000' && /Session expired/.test(d.innerText))"""


def _signed_in(app):
    page = app.page
    return (not page.evaluate(OVERLAY_JS)
            and ('POST', '/api/auth/logout') not in app.server.calls
            and page.locator('header').count() + page.locator('.cloud-shell').count() > 0)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_refused_esxi_password_keeps_the_user_in_and_says_why(open_app, layout):
    app = open_app(layout=layout)
    page = _open_server(app)
    panel = page.locator('[data-esxi-error="UPSTREAM_AUTH"]')
    panel.wait_for(timeout=5000)
    text = panel.inner_text()
    assert 'The ESXi server refused the stored credentials' in text
    assert page.locator('[data-esxi-error-message]').inner_text().strip() == REFUSED
    assert 'Check the user name and password in the settings of this server, or remove it.' in text
    # clicking around the server keeps the session: tabs, refresh
    page.locator('[data-esxi-remove]').wait_for(timeout=3000)
    page.locator('[data-esxi-edit]').first.click()
    page.get_by_text('Edit ESXi Server').first.wait_for(timeout=3000)
    page.get_by_role('button', name='Cancel').first.click()
    n = app.server.calls.count(('GET', '/api/vmware/v1/vms'))
    panel.locator('button', has_text='Reconnect').click()
    page.wait_for_timeout(800)
    assert app.server.calls.count(('GET', '/api/vmware/v1/vms')) > n
    _shot(page, f'{layout}_esxi_credentials_refused.png')
    assert _signed_in(app), app.server.calls[-10:]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_failing_server_can_be_fixed(open_app, layout):
    app = open_app(layout=layout)
    page = _open_server(app)
    page.locator('[data-esxi-error-edit]').click()
    dialog = page.locator('div.fixed', has_text='Edit ESXi Server').last
    dialog.wait_for(timeout=3000)
    dialog.locator('input[type="password"]').fill('the-new-password')
    # the server takes it: the next read lists the guests
    app.server.extra[('GET', '/api/vmware/v1/vms')] = (200, [{'vm': 'vm-1', 'name': 'web01',
                                                               'power_state': 'POWERED_ON'}])
    dialog.locator('button', has_text='Update').click()
    assert _wait_for_call(app, ('PUT', '/api/vmware/v1'))
    body = app.server.bodies['/api/vmware/v1'][-1]
    assert body['password'] == 'the-new-password' and body['host'] == 'esx1.lab'
    page.get_by_text('web01').first.wait_for(timeout=5000)
    assert page.locator('[data-esxi-error]').count() == 0
    assert _signed_in(app)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_fixed_server_is_read_again_as_a_whole(open_app, layout):
    """The edit read only the VM list again. Hosts and datastores waited a minute for their
    poll and networks have none, so the fixed server said Hosts: 0, Datastores: 0 and had
    no networks until it was picked once more."""
    app = open_app(layout=layout)
    page = _open_server(app)
    page.locator('[data-esxi-error-edit]').click()
    dialog = page.locator('div.fixed', has_text='Edit ESXi Server').last
    dialog.wait_for(timeout=3000)
    dialog.locator('input[type="password"]').fill('the-new-password')
    for what, rows in (('vms', [{'vm': 'vm-1', 'name': 'web01', 'power_state': 'POWERED_ON'}]),
                       ('hosts', [{'host': 'host-1', 'name': 'esx1.lab'}]),
                       ('datastores', [{'datastore': 'ds-1', 'name': 'datastore1'}]),
                       ('networks', [{'network': 'net-1', 'name': 'VM Network'}]),
                       ('clusters', [])):
        app.server.extra[('GET', f'/api/vmware/v1/{what}')] = (200, rows)
    dialog.locator('button', has_text='Update').click()
    assert _wait_for_call(app, ('PUT', '/api/vmware/v1'))
    page.get_by_text('web01').first.wait_for(timeout=5000)
    # well before the minute of the hosts and datastores poll
    page.get_by_text('Hosts: 1').first.wait_for(timeout=3000)
    page.get_by_text('Datastores: 1').first.wait_for(timeout=3000)
    page.locator('button', has_text='Networks').first.click()
    page.get_by_text('VM Network').first.wait_for(timeout=3000)
    assert _signed_in(app)
    assert not app.errors, app.errors


@pytest.mark.parametrize('code', ['AUTH_REQUIRED', 'ACCOUNT_DELETED', 'ACCOUNT_DISABLED', 'INVALID_SESSION',
                                  'INVALID_TOKEN', 'HA_FORWARD_STALE_SIGN_IN'])
def test_runtime_every_code_of_a_lost_session_still_signs_off(open_app, code):
    """Every 401 PegaProx answers for a session or token that is gone shows the overlay at
    once, in the corporate layout too, without waiting for /auth/check."""
    app = open_app(layout='corporate', vms=(401, {'error': 'gone', 'code': code}))
    checks = app.server.calls.count(('GET', '/api/auth/check'))
    page = _open_server(app)
    page.wait_for_function(OVERLAY_JS, timeout=5000)
    assert page.locator('[data-session-expired]').count() == 1
    assert app.server.calls.count(('GET', '/api/auth/check')) == checks


def test_runtime_401s_without_our_code_ask_once_in_a_while(open_app):
    """A burst of 401s without our code asks /auth/check once, not once per answer."""
    app = open_app(layout='modern', vms=FOREIGN)
    for what in READS:
        app.server.extra[('GET', f'/api/vmware/v1/{what}')] = FOREIGN
    checks = app.server.calls.count(('GET', '/api/auth/check'))
    page = _open_server(app)
    page.locator('[data-esxi-error="connection"]').wait_for(timeout=5000)
    page.locator('[data-esxi-error] button', has_text='Reconnect').click()
    page.wait_for_timeout(1000)
    assert app.server.calls.count(('GET', '/api/vmware/v1/vms')) >= 2
    assert app.server.calls.count(('GET', '/api/auth/check')) == checks + 1
    assert _signed_in(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_failing_server_can_be_removed(open_app, layout):
    app = open_app(layout=layout)
    page = _open_server(app)
    page.locator('[data-esxi-error="UPSTREAM_AUTH"]').wait_for(timeout=5000)
    app.server.extra[('GET', '/api/vmware')] = (200, [])
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-esxi-remove]').click()
    assert _wait_for_call(app, ('DELETE', '/api/vmware/v1'))
    page.wait_for_timeout(800)
    assert page.locator('button', has_text='lab esxi').count() == 0
    assert page.locator('[data-esxi-error]').count() == 0
    assert _signed_in(app)
    assert not app.errors, app.errors


def test_runtime_our_own_401_still_signs_off(open_app):
    """Counterproof: a 401 with AUTH_REQUIRED is the session, and the overlay says so."""
    app = open_app(layout='modern', vms=OURS)
    page = _open_server(app)
    page.wait_for_function(OVERLAY_JS, timeout=5000)
    assert page.locator('[data-session-expired]').count() == 1


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_401_without_our_code_asks_before_it_signs_off(open_app, layout):
    """What an older backend or a proxy answers: no code. The session is still there, so
    the user stays in and the server says it could not be read."""
    app = open_app(layout=layout, vms=FOREIGN)
    checks = app.server.calls.count(('GET', '/api/auth/check'))
    page = _open_server(app)
    page.wait_for_timeout(1000)     # the 401, and the check it sets off
    assert _signed_in(app), 'a 401 without our code signed the user off'
    # /auth/check was asked once more, and said the session is fine
    assert app.server.calls.count(('GET', '/api/auth/check')) == checks + 1
    page.locator('[data-esxi-error="connection"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_401_without_our_code_signs_off_when_the_session_is_gone(open_app):
    """#144 behind a proxy: the session ran out and the 401 came from in front of us. The
    check says so, and the overlay comes."""
    app = open_app(layout='modern', vms=FOREIGN)
    app.server.logged_out = True    # /auth/check: authenticated false from now on
    _open_server(app)
    app.page.wait_for_function(OVERLAY_JS, timeout=5000)


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='corporate', language='de')
    page = _open_server(app)
    panel = page.locator('[data-esxi-error="UPSTREAM_AUTH"]')
    panel.wait_for(timeout=5000)
    assert 'Der ESXi-Server hat die gespeicherten Zugangsdaten abgelehnt' in panel.inner_text()
    assert panel.locator('button', has_text='Server bearbeiten').count() == 1
    assert page.locator('[data-esxi-remove]').get_attribute('title') == 'Server entfernen'
    _shot(page, 'corporate_esxi_credentials_refused_de.png')
    assert not app.errors, app.errors
