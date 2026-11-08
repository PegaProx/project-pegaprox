"""#767 — the console in its own browser window.

The feature is entirely in the bundle, so what a Python test can usefully hold down
is the handful of couplings that break silently in a browser:

  * the URL the pop-out button builds and the URL the standalone view parses are
    written in two different files and nothing connects them but this test;
  * the standalone branch has to sit between the 2FA gate and the layout picker.
    Move it one gate later and every popup for a first-login account renders the
    layout chooser instead of a console;
  * a missing translation key does not throw — t() hands back the key string, so
    the button's tooltip silently becomes "openInOwnWindow".

Runtime behaviour was verified against Testi (qemu 130 and three containers on
vserver-zap106363-2) in a real browser; this is the part that can regress in a
diff without anyone opening a console. NS
"""
import re

import pytest


SRC = 'web/src/'
LANGS = ('de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it')


@pytest.fixture(scope='module')
def modals():
    return open(SRC + 'node_modals.js', encoding='utf-8').read()


@pytest.fixture(scope='module')
def dash():
    return open(SRC + 'dashboard.js', encoding='utf-8').read()


def test_the_popout_url_is_the_one_the_standalone_view_parses(modals, dash):
    """Producer and consumer of the ?console= link, in two files."""
    assert "`${window.location.origin}/?console=${encodeURIComponent(key)}`" in modals
    assert "`${cid}:${vm.type}:${vm.vmid}:${vm.node}`" in modals

    assert "URLSearchParams(window.location.search).get('console')" in dash
    assert 'const [clusterId, type, vmid, node] = parts' in dash


def test_the_node_from_the_address_bar_is_held_to_a_hostname(dash):
    """It rides straight into /api/clusters/<id>/vms/<node>/... — in the app that string comes
    from the cluster, here it comes from whatever someone typed."""
    body = dash[dash.index('function StandaloneConsole'):dash.index('        function App() {')]

    assert "/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(node" in body
    assert 'parts.length !== 4' in body


def test_the_url_is_checked_before_anything_is_built_out_of_it(dash):
    """A view driven entirely off a query string. A typo should say so rather than turn into
    /vms/<node>/<type>/NaN/console against a real cluster."""
    body = dash[dash.index('function StandaloneConsole'):dash.index('        function App() {')]

    assert "(type !== 'qemu' && type !== 'lxc')" in body
    assert "/^\\d+$/.test(vmid)" in body
    assert "setState({ status: 'error', error: 'malformed' })" in body


def test_a_pasted_link_can_still_be_closed(dash):
    """window.close() is a no-op in a tab the user opened themselves; without the fallback
    the X button does nothing and there is no way back to the dashboard."""
    body = dash[dash.index('function StandaloneConsole'):dash.index('        function App() {')]

    assert 'if (!window.closed) window.location.assign' in body


def test_the_standalone_branch_sits_between_the_2fa_gate_and_the_layout_picker(dash):
    app = dash[dash.index('        function App() {'):]
    app = app[:app.index('ReactDOM')] if 'ReactDOM' in app else app

    two_fa = app.index('requires2FASetup')
    branch = app.index('if (consoleKey) {')
    picker = app.index('if (!user.layout_chosen)')

    assert two_fa < branch < picker, \
        'a console window must be authenticated, but must not be gated on the layout picker'


def test_the_standalone_view_asks_for_nothing_it_does_not_need(dash):
    """Two O(1) reads — the cluster list for the host, one VM config for the label — and that
    is the whole window's cost. A per-window resource poll would multiply by however many
    consoles an operator has open, which on a 10k estate is the whole point of not doing it."""
    body = dash[dash.index('function StandaloneConsole'):dash.index('        function App() {')]

    assert body.count('fetch(') == 2
    assert '/clusters`' in body and '/config`' in body
    assert 'resources' not in body and 'sse' not in body.lower()


def test_the_label_on_the_console_comes_from_the_cluster_not_the_link(dash, modals):
    """The header drops the vmid the moment it has a name, so a name taken from the query
    string would let whoever writes the link choose what an operator reads above a live root
    console. The link carries the key only; the name is resolved and falls back to the vmid."""
    body = dash[dash.index('function StandaloneConsole'):dash.index('        function App() {')]

    assert "get('name')" not in body, 'the window is reading its label out of the URL again'
    assert '&name=' not in modals, 'the pop-out link is carrying a label again'
    assert "g.name || g.hostname" in body
    assert "const label = `${type === 'lxc' ? 'CT' : 'VM'} ${vmid}`" in body


def test_the_popup_does_not_offer_to_pop_itself_out_again(modals):
    """Both header rows — corporate and modern — guard the button on !standalone."""
    console = modals[modals.index('function ConsoleModal('):]
    console = console[:console.index('\n        function ', 10)]

    assert console.count('onClick={popOutConsole}') == 2
    assert console.count('{!standalone && (') == 2
    assert 'standalone = false }' in modals[modals.index('function ConsoleModal('):][:400]


def test_the_console_fills_a_window_of_its_own(modals):
    """82vh inside a popup leaves a black gutter; standalone borrows the fullscreen geometry
    without claiming the browser Fullscreen API is engaged."""
    console = modals[modals.index('function ConsoleModal('):]

    assert 'const fillWindow = isFullscreen || standalone;' in console
    assert 'isFullscreen ? \'w-full h-full' not in console, 'geometry still keyed on isFullscreen'


@pytest.mark.parametrize('key', ['openInOwnWindow', 'popupBlocked', 'openingConsole',
                                 'consoleWindowFailed', 'consoleLinkMalformed',
                                 'consoleNoClusterAccess'])
def test_the_new_strings_exist_in_every_language(key):
    """t() returns the key itself when it is missing, so `t('x') || 'fallback'` never fires —
    a language block without the key shows the raw key to the user."""
    src = open(SRC + 'translations.js', encoding='utf-8').read()
    starts = {lang: m.start() for lang in LANGS
              for m in [re.search(r'^ +%s: \{' % lang, src, re.M)] if m}
    assert len(starts) == len(LANGS), f'language blocks found: {sorted(starts)}'

    order = sorted(starts.items(), key=lambda kv: kv[1])
    for i, (lang, pos) in enumerate(order):
        end = order[i + 1][1] if i + 1 < len(order) else len(src)
        assert re.search(r'^ +%s: ' % key, src[pos:end], re.M), f'{key} missing from {lang}'


def test_the_shipped_bundle_was_rebuilt():
    """web/index.html is generated from web/src — a source-only commit ships nothing."""
    bundle = open('web/index.html', encoding='utf-8').read()

    assert 'StandaloneConsole' in bundle
    assert 'popOutConsole' in bundle
