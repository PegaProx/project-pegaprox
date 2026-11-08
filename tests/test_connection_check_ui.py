"""The connection check in the web UI: the cluster menu (Corporate), the card button
(Modern) and the modal that shows what POST .../connection-check found.

The route is tested in tests/test_connection_check.py. These read the source and the
bundle, and the runtime tests drive the built bundle in headless Chromium against the
fake server of tests/test_ha_ui.py; they skip where Playwright is not installed.
LW
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, _classes, _read, browser, open_app  # noqa: F401 (fixtures)

SHOTS = os.environ.get('CONN_CHECK_SHOTS', '')
PATH = '/api/clusters/c1/connection-check'


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def modal(dash):
    start = dash.index('        // LW Oct 2026 - the connection check of one PVE cluster')
    return dash[start:dash.index('        // NS: Mar 2026 - Topology View redesign (#142)', start)]


def _used_keys(src):
    keys = set(re.findall(r"'(connCheck[A-Za-z0-9]+)'", src))
    return keys | set(re.findall(r"t\('(connCheck[A-Za-z0-9]+)'\)", src))


def _lang_blocks():
    tr = _read('web', 'src', 'translations.js')
    starts = {lang: re.search(r'^            %s: \{$' % lang, tr, re.M).start() for lang in LANGS}
    order = sorted(starts, key=starts.get)
    out = {}
    for i, lang in enumerate(order):
        end = starts[order[i + 1]] if i + 1 < len(order) else len(tr)
        out[lang] = tr[starts[lang]:end]
    return out


# -- source ----------------------------------------------------------------------------------

def test_every_key_exists_once_per_language_and_none_is_unused(dash):
    used = _used_keys(dash)
    assert len(used) > 80
    defined = set()
    for lang, block in _lang_blocks().items():
        for key in used:
            n = len(re.findall(r'^                %s: ' % key, block, re.M))
            assert n == 1, (lang, key, n)
        defined |= set(re.findall(r'^                (connCheck[A-Za-z0-9]+): ', block, re.M))
    assert defined == used, defined ^ used


def test_placeholders_survive_translation():
    blocks = _lang_blocks()
    for key in ('connCheckPrivAll', 'connCheckQuorate', 'connCheckMaxSkew', 'connCheckCheckedAt',
                'connCheckHintCredAuthBackoff'):
        want = None
        for lang, block in blocks.items():
            line = re.search(r'^                %s: (.*)$' % key, block, re.M).group(1)
            found = sorted(re.findall(r'\{[a-z]+\}', line))
            want = want or found
            assert found == want and found, (lang, key, found)


def test_every_hint_and_feature_the_server_sends_has_words(modal):
    from pegaprox.core import conncheck
    src = open(conncheck.__file__, encoding='utf-8').read()
    hints = set(re.findall(r"hint='([a-z0-9_]+)'", src))
    hints |= set(re.findall(r": '((?:ssh|api|cred)_[a-z0-9_]+)'", src))
    hints |= set(re.findall(r"reason = '([a-z_]+)' if not connected else '([a-z_]+)'", src)[0])
    assert {'ssh_auth_refused', 'cred_token_note', 'needs_connection', 'api_tls_mismatch'} <= hints
    for h in hints:
        assert f'{h}:' in modal, h
    for _privs, _path, features in conncheck.PRIVILEGE_NEEDS:
        for f in features:
            assert f'{f}: ' in modal, f


def test_no_em_dash_and_icons_exist(modal, dash):
    assert '\u2014' not in modal and '\u2013' not in modal
    icons = _read('web', 'src', 'icons.js')
    for name in set(re.findall(r'Icons\.([A-Za-z]+)', modal)) | {'CheckCircle', 'AlertTriangle', 'XCircle', 'Info'}:
        assert re.search(r'\b%s: \(' % name, icons), name
    for block in _lang_blocks().values():
        for line in re.findall(r'^                connCheck[A-Za-z0-9]+: .*$', block, re.M):
            assert '\u2014' not in line, line


def test_every_class_is_in_the_static_tailwind_build(modal, dash):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    at = dash.index("{isAdmin && onCheckConnection")
    button = dash[at:dash.index('</button>', at)]
    names = _classes(modal) | _classes(button)
    assert len(names) > 40
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_menu_and_the_button_respect_the_standby_and_the_type(dash):
    menu = dash[dash.index("...(cluster.cluster_type === 'xcpng' ? [] : ["):]
    menu = menu[:menu.index(']),') + 3]
    # perm: can() keeps only what reads on a read-only standby (contexts.js)
    assert "perm: 'cluster.config'" in menu and 'setConnCheckCluster(cluster)' in menu
    item = dash[dash.index('function ClusterSidebarItem('):dash.index('// LW Oct 2026 - the connection check of one PVE cluster')]
    btn = item.index('{isAdmin && onCheckConnection')
    # inside the !haReadOnly block of the Modern card
    assert item.rfind('{!haReadOnly && (', 0, btn) > item.rfind(')}', 0, item.rfind('{!haReadOnly && (', 0, btn))


def test_the_bundle_was_rebuilt(dash):
    bundle = _read('web', 'index.html')
    for needle in ('function ConnectionCheckModal(', '/connection-check', 'connCheckHintSshAuthRefused',
                   'onCheckConnection'):
        assert needle in bundle, needle


# -- runtime -----------------------------------------------------------------------------------

REPORT = {
    'cluster_id': 'c1', 'cluster_type': 'proxmox', 'connected': True, 'ssh_checked': True,
    'checked_at': '2026-10-04T10:00:00+00:00', 'duration_ms': 2400,
    'summary': {'ok': 6, 'warn': 3, 'fail': 2, 'skip': 1},
    'items': [
        {'id': 'credentials', 'kind': 'credentials', 'status': 'ok', 'hint': None, 'type': 'minted_token',
         'user': 'root@pam', 'token_id': 'root@pam!pegaprox', 'active': 'token', 'has_password': True},
        {'id': 'api:10.0.0.1', 'kind': 'api_host', 'status': 'ok', 'hint': None, 'host': '10.0.0.1',
         'role': 'primary', 'ms': 41, 'fingerprint': 'AA:' * 31 + 'AA', 'tls': 'match', 'http': 200, 'node': 'pve1'},
        {'id': 'api:10.0.0.2', 'kind': 'api_host', 'status': 'warn', 'hint': 'api_tls_mismatch', 'host': '10.0.0.2',
         'role': 'fallback', 'ms': 55, 'fingerprint': 'CC:' * 31 + 'CC', 'tls': 'mismatch', 'http': 200, 'node': 'pve2'},
        {'id': 'api:10.0.0.3', 'kind': 'api_host', 'status': 'fail', 'hint': 'api_unreachable', 'host': '10.0.0.3',
         'role': 'fallback', 'ms': 5003, 'fingerprint': None, 'tls': 'unknown', 'http': None,
         'detail': 'timed out'},
        {'id': 'privileges', 'kind': 'privileges', 'status': 'warn', 'hint': 'priv_missing', 'checked': 22,
         'missing': [{'privs': ['VM.Migrate'], 'path': '/vms', 'features': ['migration'], 'partial': False},
                     {'privs': ['VM.Console'], 'path': '/vms', 'features': ['consoles'], 'partial': True}]},
        {'id': 'quorum', 'kind': 'quorum', 'status': 'ok', 'hint': None, 'quorate': True, 'standalone': False,
         'nodes_total': 3, 'nodes_online': 3, 'offline': []},
        {'id': 'versions', 'kind': 'versions', 'status': 'ok', 'hint': None,
         'nodes': {'pve1': '9.0.3', 'pve2': '9.0.3', 'pve3': '9.0.5'}, 'unknown': []},
        {'id': 'clock', 'kind': 'clock', 'status': 'warn', 'hint': 'clock_skew',
         'nodes': {'pve1': 0.2, 'pve2': -0.4, 'pve3': 12.5}, 'max_skew': 12.5},
        {'id': 'ssh:pve1', 'kind': 'ssh', 'status': 'ok', 'hint': None, 'node': 'pve1', 'user': 'root',
         'method': 'password', 'ip': '10.0.0.1', 'code': 'OK'},
        {'id': 'ssh:pve2', 'kind': 'ssh', 'status': 'fail', 'hint': 'ssh_auth_refused', 'node': 'pve2',
         'user': 'root', 'method': 'password', 'ip': '10.0.0.2', 'code': 'AUTH_REFUSED',
         'detail': 'Authentication failed.'},
        {'id': 'ssh:pve3', 'kind': 'ssh', 'status': 'skip', 'hint': 'ssh_node_offline', 'node': 'pve3',
         'code': 'NODE_OFFLINE'},
    ],
}
XCP = dict(CLUSTER, id='x1', name='Pool', display_name='Pool', cluster_type='xcpng')


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _open_from_corporate_menu(app):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    menu.get_by_text('Check connection').click()
    page.locator('[data-conn-check="c1"]').wait_for(timeout=3000)


def _run(app):
    app.page.locator('[data-conn-check] button', has_text='Run check').click()
    app.page.locator('[data-check-item="ssh:pve2"]').wait_for(timeout=5000)


def test_runtime_corporate_menu_runs_the_check_and_shows_the_fixes(open_app):
    app = open_app(role='standalone', layout='corporate', clusters=[CLUSTER],
                   extra={('POST', PATH): (200, REPORT)})
    page = app.page
    _open_from_corporate_menu(app)
    dialog = page.locator('[data-conn-check="c1"]')
    assert 'XCP-ng pools and Proxmox Backup Server' in dialog.inner_text()
    # nothing is sent until the admin asks
    assert ('POST', PATH) not in app.server.calls
    _run(app)
    assert app.server.bodies[PATH] == [{'ssh': True}]
    text = dialog.inner_text()
    for needle in ('6 passed', '3 warnings', '2 failed', '1 skipped', 'API token created by PegaProx',
                   'root@pam!pegaprox', 'certificate differs from the node', 'TLS-inspecting proxy',
                   'This server cannot reach the address', 'VM.Migrate', 'Migration, load balancing, maintenance mode',
                   'only on some guests, pools or storages', 'Quorate, 3 of 3 nodes online', 'pve3 +12.5 s',
                   'Largest difference to this server: 12.5 s', 'AUTH_REFUSED', 'The node refused the login',
                   'fail2ban', 'root@10.0.0.2', 'The node is offline and was not contacted', 'took 2.4 s'):
        assert needle in text, needle
    assert page.locator('[data-check-item="ssh:pve2"]').get_attribute('data-check-status') == 'fail'
    _shot(app, 'corporate-results.png')

    # without SSH this time
    dialog.locator('input[type="checkbox"]').uncheck()
    app.server.extra[('POST', PATH)] = (200, dict(REPORT, ssh_checked=False,
                                                  items=[i for i in REPORT['items'] if i['kind'] != 'ssh']))
    dialog.locator('button', has_text='Run again').click()
    page.get_by_text('SSH logins were not tested').wait_for(timeout=5000)
    assert app.server.bodies[PATH][-1] == {'ssh': False}
    assert not app.errors, app.errors


def test_runtime_modern_card_button_opens_it(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER],
                   extra={('POST', PATH): (200, REPORT)})
    page = app.page
    page.locator('button[title="Check connection"]').first.click()
    page.locator('[data-conn-check="c1"]').wait_for(timeout=3000)
    _shot(app, 'modern-intro.png')
    _run(app)
    assert 'Hardware' not in page.locator('[data-conn-check]').inner_text()
    _shot(app, 'modern-results.png')
    page.locator('[data-conn-check] button[title="Close"]').click()
    assert page.locator('[data-conn-check]').count() == 0
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(role='standalone', layout='corporate', language='de', clusters=[CLUSTER],
                   extra={('POST', PATH): (200, REPORT)})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
    page.locator('.corp-context-menu').first.get_by_text('Verbindung prüfen').click()
    page.locator('[data-conn-check] button', has_text='Prüfung starten').click()
    page.locator('[data-check-item="ssh:pve2"]').wait_for(timeout=5000)
    text = page.locator('[data-conn-check]').inner_text()
    assert 'Der Node hat die Anmeldung abgelehnt' in text and 'Quorum vorhanden, 3 von 3 Nodes online' in text
    _shot(app, 'corporate-de.png')
    assert not app.errors, app.errors


def test_runtime_a_refusal_shows_the_servers_words(open_app):
    app = open_app(role='standalone', layout='corporate', clusters=[CLUSTER],
                   extra={('POST', PATH): (403, {'error': 'Access denied: this action affects the whole cluster'})})
    _open_from_corporate_menu(app)
    app.page.locator('[data-conn-check] button', has_text='Run check').click()
    app.see('Access denied: this action affects the whole cluster')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_nothing_to_click_on_a_standby_for_a_viewer_or_for_xcpng(open_app, layout):
    for kw in ({'role': 'standby', 'clusters': [CLUSTER]}, {'role': 'standalone', 'admin': False, 'clusters': [CLUSTER]},
               {'role': 'standalone', 'clusters': [XCP]}):
        app = open_app(layout=layout, **kw)
        page = app.page
        name = kw['clusters'][0]['name']
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text=name).first.click(button='right')
            menu = page.locator('.corp-context-menu').first
            menu.wait_for(timeout=3000)
            assert 'Check connection' not in menu.inner_text(), kw
            page.keyboard.press('Escape')
        else:
            page.get_by_text(name).first.wait_for(timeout=3000)
            assert page.locator('button[title="Check connection"]').count() == 0, kw
        assert ('POST', PATH) not in app.server.calls
        assert not app.errors, (kw, app.errors)


def test_runtime_a_forwarding_standby_hands_it_to_the_active(open_app):
    """Forwarding on: the standby shows the actions again and the active runs the check."""
    app = open_app(role='standby', layout='corporate', clusters=[CLUSTER], forward_writes=True)
    _open_from_corporate_menu(app)
    app.page.locator('[data-conn-check] button', has_text='Run check').click()
    app.page.wait_for_timeout(800)
    assert ('POST', PATH) in app.server.forwarded
