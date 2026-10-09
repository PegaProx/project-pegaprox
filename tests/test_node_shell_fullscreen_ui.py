"""The node shell keeps its one session in fullscreen (#1143).

Fullscreen mounted a second terminal on top of the tab's: a second WebSocket and SSH
login, the credentials asked again, an empty scrollback, and the first session open
underneath. Now the box of the one terminal fills the window, as that overlay did, and
the terminal refits to it. Escape stays the shell's, the button leaves.

The dialog shows the address the server names and takes none; the page sends no ?ip=.

Source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, with the page's
WebSocket swapped for a stand-in that counts the sockets and plays the shell server,
in the Modern layout and in Corporate, where the node modal opens from the node's
detail view. They skip where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, NODE_READS, SSE_TOKEN, VM, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ['nodeShellAddressFromServer']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _panel():
    return _between(_read('web', 'src', 'node_modals.js'), 'function NodeShellPanel(', '// NS May 2026')


def _terminal():
    return _between(_read('web', 'src', 'node_modals.js'), 'function NodeShellTerminal(', 'function NodeShellPanel(')


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'
    assert f"t('{key}')" in _terminal()


def test_the_german_block_keeps_its_flag():
    tr = _read('web', 'src', 'translations.js')
    assert tr.index('            de: {') < tr.index("nodeShellAddressFromServer: 'Ermittelt der Server'") < tr.index('            en: {')


def test_one_terminal_and_no_fullscreen_copy():
    nm = _read('web', 'src', 'node_modals.js')
    modal = nm[nm.index('function NodeModal('):nm.index('function ConsoleModal(')]
    assert 'shellFullscreen' not in nm
    assert modal.count('<NodeShellPanel ') == 1 and '<NodeShellTerminal' not in modal
    assert _panel().count('<NodeShellTerminal ') == 1


def test_the_page_names_no_target():
    term = _terminal()
    assert '&ip=' not in term and 'allowManualIp' not in term
    assert 'credentials.host' not in term and 'readOnly' in term


def test_fullscreen_takes_no_key_from_the_shell():
    """The browser's fullscreen keeps Escape for itself, and a listener of the panel's own
    would take it before the terminal: the panel has neither."""
    panel = _panel()
    assert 'requestFullscreen' not in panel and 'fullscreenchange' not in panel
    assert 'keydown' not in panel and 'addEventListener' not in panel


def test_no_em_dash_in_what_this_change_added():
    for block in (_panel(),):
        assert '\u2014' not in block and '\u2013' not in block
    tr = _read('web', 'src', 'translations.js')
    for v in re.findall(r"^\s*nodeShellAddressFromServer: ('.*'),$", tr, re.M):
        assert '\u2014' not in v and '\u2013' not in v, v


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    for name in set(re.findall(r'<Icons\.([A-Za-z]+)', _panel())):
        assert re.search(rf'^\s*{name}: \(', icons, re.M), name


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_panel())
    host = _between(_terminal(), 'data-shell-host', 'placeholder=')
    names |= _classes(host)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function NodeShellPanel(', 'data-node-shell-toggle', 'nodeShellAddressFromServer',
                   'data-shell-host'):
        assert needle in built, needle
    assert 'shellFullscreen' not in built and '/shellws?token=${encodeURIComponent(wsToken)}&ip=' not in built


# --- runtime -------------------------------------------------------------------------------

NODE = '/api/clusters/c1/nodes/pve1'

# the page's WebSocket, swapped: every socket is kept, opens on its own a moment later,
# and say() hands it what the shell server would send
STAND_IN = """() => {
    const made = [];
    class StandIn {
        constructor(url) {
            this.url = String(url); this.readyState = 0; this.sent = []; this.closed = false;
            this.onopen = this.onmessage = this.onclose = this.onerror = null;
            made.push(this);
            setTimeout(() => { if (this.readyState) return; this.readyState = 1; this.onopen && this.onopen({}); }, 20);
        }
        send(data) { this.sent.push(String(data)); }
        close(code) {
            if (this.readyState >= 2) return;
            this.readyState = 3; this.closed = true;
            this.onclose && this.onclose({ code: code || 1000, reason: '' });
        }
        say(data) { this.onmessage && this.onmessage({ data }); }
        addEventListener() {}
        removeEventListener() {}
    }
    StandIn.CONNECTING = 0; StandIn.OPEN = 1; StandIn.CLOSING = 2; StandIn.CLOSED = 3;
    window.WebSocket = StandIn;
    window.__shells = () => made.filter(s => s.url.includes('/shellws'));
}"""

# the live updates stream, connected: without it the "Live updates disconnected" banner
# comes up after 4 s and lies over the top of the window, the fullscreen header too
LIVE = """(() => {
    class Live {
        constructor(url) {
            this.url = String(url); this.readyState = 0;
            this.onopen = this.onmessage = this.onerror = null;
            setTimeout(() => { this.readyState = 1; this.onopen && this.onopen({}); }, 10);
        }
        addEventListener() {}
        removeEventListener() {}
        close() { this.readyState = 2; }
    }
    window.EventSource = Live;
})();"""


class _Live:
    """The browser, its pages started with LIVE."""

    def __init__(self, browser):
        self._browser = browser

    def new_context(self, **kw):
        ctx = self._browser.new_context(**kw)
        ctx.add_init_script(LIVE)
        return ctx


def _reads(ip_source='manager_get_node_ip'):
    reads = dict(NODE_READS)
    reads[('GET', NODE + '/ip')] = (200, {'ip': '10.0.0.11' if ip_source != 'cluster_host_fallback' else '10.0.0.1',
                                          'node': 'pve1', 'source': ip_source})
    reads[('POST', '/api/ws/token')] = (200, {'token': 'tok-1', 'expires_in': 60})
    reads.update(SSE_TOKEN)
    reads[('POST', '/api/sse/token')] = (200, {'token': 'sse-1', 'expires_in': 600})
    return reads


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = kw.pop('extra', None) or _reads()
        kw.setdefault('role', 'standalone')
        app = _App(_Live(browser), _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                                               extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _until(page, js, timeout=5000):
    page.wait_for_function(js, timeout=timeout)


def _shells(page):
    return page.evaluate('() => window.__shells().map(s => ({url: s.url, open: s.readyState === 1, '
                         'closed: s.closed, sent: s.sent}))')


def _say(page, msg, i=0):
    data = msg if isinstance(msg, str) else json.dumps(msg)
    page.evaluate('([i, d]) => window.__shells()[i].say(d)', [i, data])


def _resizes(page, i=0):
    return [json.loads(m) for m in _shells(page)[i]['sent'] if m.startswith('{"type":"resize"')]


def _tab(app, name):
    """A tab of the node modal, in either layout's tab bar."""
    if app.server.layout == 'corporate':
        app.page.locator('.corp-vm-modal-tab', has_text=name).click()
    else:
        app.page.locator('button', has_text=name).last.click()


def _open_shell(app):
    page = app.page
    page.evaluate(STAND_IN)
    if app.server.layout == 'corporate':
        # Corporate opens the node modal from the node's detail view: Actions, Node Settings
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        child = page.locator('.corp-tree-child', has_text='pve1').first
        child.wait_for(timeout=5000)
        child.click()
        page.locator('.corp-toolbar button', has_text='Actions').last.click()
        page.locator('.corp-dropdown').last.get_by_text('Node Settings').click()
        page.locator('.corp-vm-modal').wait_for(timeout=5000)
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
        page.locator('button[title="Node Configuration"]').first.click()
        page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    _tab(app, 'Shell')
    page.locator('[data-node-shell="tab"]').wait_for(timeout=5000)
    _until(page, '() => window.__shells().length === 1 && window.__shells()[0].readyState === 1', 10000)
    page.locator('[data-shell-login]').wait_for(timeout=5000)
    return page


def _log_in(page):
    _say(page, {'status': 'need_credentials', 'node': 'pve1', 'ip': '10.0.0.11'})
    page.locator('[data-shell-login] input[type="password"]').fill('secret')
    page.locator('[data-shell-login] button', has_text='Connect').click()
    page.locator('[data-shell-login]').wait_for(state='hidden', timeout=3000)
    _until(page, '() => window.__shells()[0].sent.some(m => m.includes(\'"password":"secret"\'))')
    _say(page, {'status': 'connecting'})
    _say(page, {'status': 'connected'})
    _say(page, 'root@pve1:~# echo first-session\r\nfirst-session\r\nroot@pve1:~# ')
    _until(page, '() => (document.querySelector(".xterm-rows") || {}).innerText.includes("first-session")')
    # the connected terminal tells the PTY its size once
    _until(page, '() => window.__shells()[0].sent.some(m => m.startsWith(\'{"type":"resize"\'))')
    page.evaluate('() => { window.__term = document.querySelector("[data-node-shell] .xterm"); }')


def _same_terminal(page):
    return page.evaluate('() => document.querySelectorAll(".xterm").length === 1 && '
                         'document.querySelector("[data-node-shell] .xterm") === window.__term')


def _one_session(app, page):
    shells = _shells(page)
    assert len(shells) == 1 and shells[0]['open'] and not shells[0]['closed'], shells
    assert app.server.calls.count(('POST', '/api/ws/token')) == 1
    assert page.locator('[data-shell-login]').count() == 0
    assert _same_terminal(page)
    # the scrollback is the session's: a refit repaints the rows on the next frame
    _until(page, '() => (document.querySelector(".xterm-rows") || {}).innerText.includes("first-session")', 3000)


ON_TOP = '''() => [[800, 500], [5, 990], [1595, 990], [5, 5], [1595, 5]]
    .every(([x, y]) => !!document.elementFromPoint(x, y).closest("[data-node-shell]"))'''


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_fullscreen_keeps_the_one_session(open_app, layout):
    app = open_app(layout=layout)
    page = _open_shell(app)
    url = _shells(page)[0]['url']
    assert '/api/clusters/c1/nodes/pve1/shellws?token=tok-1' in url and 'ip=' not in url, url
    _log_in(page)
    tab = _resizes(page)[-1]
    told = len(_resizes(page))

    page.locator('[data-node-shell-toggle]').click()
    page.locator('[data-node-shell="window"]').wait_for(timeout=3000)
    # the whole window, over the modal it sits in, and not the browser's fullscreen
    box = page.locator('[data-node-shell]').bounding_box()
    assert (box['x'], box['y'], box['width'], box['height']) == (0, 0, 1600, 1000), box
    assert page.evaluate(ON_TOP)
    assert page.evaluate('() => document.fullscreenElement') is None
    # refit to the larger box, and the PTY hears of it
    _until(page, f'() => window.__shells()[0].sent.filter(m => m.startsWith(\'{{"type":"resize"\')).length > {told}')
    big = _resizes(page)[-1]
    assert big['cols'] > tab['cols'] and big['rows'] > tab['rows'], (tab, big)
    _one_session(app, page)
    # what is typed in fullscreen goes to the same session
    page.locator('[data-node-shell] .xterm').click()
    page.keyboard.type('uptime')
    _until(page, '() => window.__shells()[0].sent.includes("u")')
    assert page.locator('[data-node-shell-toggle]').inner_text().strip() == 'Exit fullscreen'

    # the button leaves it, and the tab size comes back
    page.locator('[data-node-shell-toggle]').click()
    page.locator('[data-node-shell="tab"]').wait_for(timeout=3000)
    _until(page, '() => { const r = window.__shells()[0].sent.filter(m => m.startsWith(\'{"type":"resize"\'));'
                 f' return JSON.parse(r[r.length - 1]).cols === {tab["cols"]}; }}')
    _one_session(app, page)
    assert page.locator('[data-node-shell-toggle]').inner_text().strip() == 'Fullscreen'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_escape_in_fullscreen_is_the_shells(open_app, layout):
    """vim, less and readline need Escape, and the overlay before passed it on. The browser's
    fullscreen keeps it, and the window fill where the browser refused that took it to
    leave: this stands for a browser that refuses."""
    app = open_app(layout=layout)
    page = _open_shell(app)
    _log_in(page)
    page.evaluate('() => { Element.prototype.requestFullscreen = function () {'
                  ' return Promise.reject(new Error("not allowed here")); }; }')
    page.locator('[data-node-shell-toggle]').click()
    page.locator('[data-node-shell="window"]').wait_for(timeout=3000)
    page.locator('[data-node-shell] .xterm').click()
    page.keyboard.press('Escape')
    _until(page, '() => window.__shells()[0].sent.includes("\\u001b")')
    page.wait_for_timeout(300)
    assert page.locator('[data-node-shell="window"]').count() == 1
    _one_session(app, page)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_counter_does_see_a_second_session(open_app, layout):
    """Counterproof for "one WebSocket": leaving the Shell tab and coming back is a new
    session, and the stand-in counts it and sees the first one closed."""
    app = open_app(layout=layout)
    page = _open_shell(app)
    _log_in(page)
    _tab(app, 'Summary')
    page.locator('[data-node-shell]').wait_for(state='detached', timeout=3000)
    _tab(app, 'Shell')
    _until(page, '() => window.__shells().length === 2 && window.__shells()[1].readyState === 1')
    page.wait_for_timeout(500)
    shells = _shells(page)
    assert len(shells) == 2 and shells[0]['closed'] and not shells[1]['closed'], shells
    # one terminal per visit: the tab's loading spinner no longer mounts it twice (the
    # first of the two used to open a socket after it was gone, and nothing closed that)
    assert app.server.calls.count(('POST', '/api/ws/token')) == 2
    assert not app.errors, app.errors


def test_runtime_the_corporate_detail_views_shell_is_one_session(open_app):
    """Corporate's node detail view has a Shell tab of its own, without fullscreen: one
    session per visit there as well."""
    app = open_app(layout='corporate')
    page = app.page
    page.evaluate(STAND_IN)
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    child = page.locator('.corp-tree-child', has_text='pve1').first
    child.wait_for(timeout=5000)
    child.click()
    strip = page.locator('.corp-tab-strip').last
    strip.get_by_text('Shell').click()
    _until(page, '() => window.__shells().length === 1 && window.__shells()[0].readyState === 1', 10000)
    page.wait_for_timeout(800)
    assert len(_shells(page)) == 1 and app.server.calls.count(('POST', '/api/ws/token')) == 1
    assert page.locator('[data-node-shell]').count() == 0
    # the login dialog lies over the whole window, the tab strip too
    page.locator('[data-shell-login] button', has_text='Cancel').click()
    strip.get_by_text('Summary').click()
    _until(page, '() => window.__shells()[0].closed')
    assert not app.errors, app.errors


def test_runtime_the_dialog_shows_the_servers_address_and_takes_none(open_app):
    """The node IP lookup fell back to the connection host: the dialog shows no address
    until the shell server names the node's own, and the field cannot be typed in."""
    app = open_app(layout='modern', extra=_reads('cluster_host_fallback'))
    page = _open_shell(app)
    host = page.locator('[data-shell-host]')
    assert host.input_value() == '' and host.get_attribute('placeholder') == 'Looked up by the server'
    assert host.get_attribute('readonly') is not None
    # Connect waits for a password only
    page.locator('[data-shell-login] input[type="password"]').fill('secret')
    assert page.locator('[data-shell-login] button', has_text='Connect').is_enabled()
    _say(page, {'status': 'need_credentials', 'node': 'pve1', 'ip': '10.0.0.11'})
    _until(page, '() => document.querySelector("[data-shell-host]").value === "10.0.0.11"')
    # an XCP-ng pool's stand-in is said to be one as well
    app3 = open_app(layout='modern', extra=_reads('xcpng_fallback'))
    assert _open_shell(app3).locator('[data-shell-host]').input_value() == ''
    # counterproof: an address of the node's own lookup is shown right away
    app2 = open_app(layout='modern')
    page2 = _open_shell(app2)
    assert page2.locator('[data-shell-host]').input_value() == '10.0.0.11'
    assert not app.errors and not app2.errors and not app3.errors, (app.errors, app2.errors, app3.errors)


def test_runtime_a_refusal_is_readable_at_once(open_app):
    app = open_app(layout='modern')
    page = _open_shell(app)
    _say(page, {'status': 'error', 'message': 'Could not find the address of node pve1'})
    page.locator('[data-shell-login]').wait_for(state='hidden', timeout=3000)
    _until(page, '() => (document.querySelector(".xterm-rows") || {}).innerText.includes("Could not find the address of node pve1")')
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de', extra=_reads('cluster_host_fallback'))
    page = app.page
    page.evaluate(STAND_IN)
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Konfiguration"]').first.click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    page.locator('button', has_text='Shell').last.click()
    page.locator('[data-shell-login]').wait_for(timeout=8000)
    assert page.locator('[data-shell-host]').get_attribute('placeholder') == 'Ermittelt der Server'
    assert page.locator('[data-node-shell-toggle]').inner_text().strip() == 'Vollbild'
    assert not app.errors, app.errors
