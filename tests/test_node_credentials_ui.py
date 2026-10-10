"""Node credentials in the web UI (#1136): the section of the re-configure dialog, the
notice after a cluster was added whose nodes refused the login, and the refused nodes
in the connection check.

The routes are tested in tests/test_node_credentials_1136.py. These read the source and
the bundle, and drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed. LW
"""
import re
import time

import pytest

from test_ha_ui import CLUSTER, LANGS, _classes, _read, browser, open_app  # noqa: F401 (fixtures)

BASE = '/api/clusters/c1/node-credentials'
EXPORT = {'name': 'Testi', 'host': '10.0.0.1', 'user': 'root@pam', 'ssl_verification': False,
          'migration_threshold': 20, 'migration_tolerance': 10, 'check_interval': 300, 'auto_migrate': False,
          'balance_containers': False, 'balance_local_disks': False, 'dry_run': False,
          'cluster_type': 'proxmox', 'vnc_tunnel': False, 'ssh_disabled': False}
STATE = {'cluster_id': 'c1', 'ssh_user': 'root', 'ssh_key': False, 'ssh_disabled': False, 'token_auth': False,
         'cluster_password': True, 'max_length': 256, 'nodes': [
             {'node': 'pve1', 'member': True, 'online': True, 'has_password': False, 'updated_at': None,
              'updated_by': None, 'last_check': {'code': 'OK', 'detail': '', 'credential': 'cluster',
                                                 'checked_at': '2026-10-10T10:00:00'}},
             {'node': 'pve2', 'member': True, 'online': True, 'has_password': False, 'updated_at': None,
              'updated_by': None, 'last_check': {'code': 'AUTH_REFUSED', 'detail': 'Authentication failed.',
                                                 'credential': 'cluster', 'checked_at': '2026-10-10T10:00:00'}},
             {'node': 'pve3', 'member': True, 'online': False, 'has_password': True,
              'updated_at': '2026-10-09T08:00:00', 'updated_by': 'alice', 'last_check': None}]}


def _section(src):
    start = src.index('        // LW Oct 2026 (#1136) - the root password of single nodes')
    return src[start:src.index('        function AddClusterModal(', start)]


@pytest.fixture(scope='module')
def modals():
    return _read('web', 'src', 'create_modals.js')


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def notice(dash):
    start = dash.index('                    {/* LW Oct 2026 (#1136) - nodes of a new cluster that refused the login, or whose')
    return dash[start:dash.index('                    {/* #256: Re-configure cluster password dialog */}', start)]


def _lang_blocks():
    tr = _read('web', 'src', 'translations.js')
    starts = {lang: re.search(r'^            %s: \{$' % lang, tr, re.M).start() for lang in LANGS}
    order = sorted(starts, key=starts.get)
    out = {}
    for i, lang in enumerate(order):
        end = starts[order[i + 1]] if i + 1 < len(order) else len(tr)
        out[lang] = tr[starts[lang]:end]
    return out


# -- source ------------------------------------------------------------------------------------

def test_every_key_exists_once_per_language_and_none_is_unused(modals, dash):
    used = set(re.findall(r"t\('(nodeCreds[A-Za-z0-9]+)'\)", modals + dash))
    assert len(used) >= 25, sorted(used)
    for lang, block in _lang_blocks().items():
        defined = set(re.findall(r'^                (nodeCreds[A-Za-z0-9]+): ', block, re.M))
        assert defined == used, (lang, defined ^ used)
        for key in used | {'sshKeyExplanation'}:
            assert len(re.findall(r'^                %s: ' % key, block, re.M)) == 1, (lang, key)


def test_placeholders_survive_translation():
    blocks = _lang_blocks()
    for key in ('nodeCredsSaved', 'nodeCredsCleared', 'nodeCredsSetBy', 'nodeCredsRefusedNotice',
                'nodeCredsRefusedHint', 'nodeCredsCheckedAt', 'nodeCredsClearedByMove'):
        want = None
        for lang, block in blocks.items():
            line = re.search(r'^                %s: (.*)$' % key, block, re.M).group(1)
            found = sorted(re.findall(r'\{[a-z]+\}', line))
            want = want or found
            assert found == want and found, (lang, key, found)


def test_the_ssh_hint_no_longer_says_only_a_key_helps():
    for lang, block in _lang_blocks().items():
        line = re.search(r'^                sshKeyExplanation: (.*)$', block, re.M).group(1)
        assert 'Node' in line or 'node' in line or '节点' in line or '노드' in line or 'nœud' in line \
            or 'nodo' in line or 'nó' in line or 'węz' in line, lang
    en = re.search(r'^                sshKeyExplanation: (.*)$', _lang_blocks()['en'], re.M).group(1)
    assert 'Node credentials' in en and 'do not share one root password' not in en


def test_no_em_dash_icons_exist_and_classes_are_in_the_build(modals, dash, notice):
    section = _section(modals)
    new_code = section + notice
    assert '\u2014' not in new_code and '\u2013' not in new_code
    for block in _lang_blocks().values():
        for line in re.findall(r'^                (?:nodeCreds[A-Za-z0-9]+|sshKeyExplanation): .*$', block, re.M):
            assert '\u2014' not in line and '\u2013' not in line, line
    icons = _read('web', 'src', 'icons.js')
    for name in set(re.findall(r'Icons\.([A-Za-z]+)', new_code)):
        assert re.search(r'\b%s: \(' % name, icons), name
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(new_code)
    assert len(names) > 30
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_a_standby_gets_no_buttons(modals, notice):
    section = _section(modals)
    assert "const { haReadOnly } = useAuth();" in section
    # the field with its buttons per node, and the check
    assert section.count('{!haReadOnly && ') == 2
    assert '{!haReadOnly && (' in notice


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function NodeCredentialsSection(', '/node-credentials', 'nodeCredsRefusedNotice',
                   'watchNodeLogins', 'data-check-refused', 'nodeCredsClearedByMove'):
        assert needle in bundle, needle


# -- runtime -------------------------------------------------------------------------------------

def _extra(state=STATE):
    return {('POST', '/api/auth/verify-password'): (200, {'success': True}),
            ('GET', '/api/clusters/c1/config/export'): (200, EXPORT),
            ('GET', BASE): (200, state),
            ('PUT', f'{BASE}/pve2'): (200, {'success': True, 'node': 'pve2', 'has_password': True}),
            ('DELETE', f'{BASE}/pve3'): (200, {'success': True, 'node': 'pve3', 'has_password': False}),
            ('POST', f'{BASE}/check'): (200, {'cluster_id': 'c1', 'nodes': [], 'refused': ['pve2'],
                                              'checked': ['pve1', 'pve2']})}


def _reauth(page):
    page.get_by_placeholder('Your Password').fill('correct horse')
    page.get_by_placeholder('Your Password').press('Enter')


def _open_reconfigure(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
        menu = page.locator('.corp-context-menu').first
        menu.wait_for(timeout=3000)
        menu.get_by_text('Re-configure Cluster').click()
    else:
        page.locator('button[title="Re-configure Cluster"]').first.click()
    _reauth(page)
    page.locator('[data-node-creds="c1"]').wait_for(timeout=5000)


def _wait(page, cond, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        page.wait_for_timeout(100)
    return False


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_section_lists_sets_clears_and_checks(open_app, layout):
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=_extra())
    page = app.page
    _open_reconfigure(app, layout)
    box = page.locator('[data-node-creds="c1"]')
    # collapsed until asked for, and nothing is read before
    assert ('GET', BASE) not in app.server.calls
    box.get_by_text('Node credentials').click()
    page.locator('[data-node-cred="pve2"]').wait_for(timeout=5000)
    states = {n: page.locator(f'[data-node-cred="{n}"]').get_attribute('data-node-cred-state')
              for n in ('pve1', 'pve2', 'pve3')}
    assert states == {'pve1': 'cluster', 'pve2': 'refused', 'pve3': 'own'}
    text = box.inner_text()
    for needle in ('Uses the cluster password', 'Login refused', 'Own password set', 'Login works',
                   'set by alice', 'offline', 'AUTH_REFUSED', 'cluster password'):
        assert needle in text, needle

    # Enter in the field saves this node and does not submit the dialog
    field = page.locator('[data-node-cred="pve2"] input[type="password"]')
    field.fill('pve2-own-root')
    field.press('Enter')
    assert _wait(page, lambda: app.server.bodies.get(f'{BASE}/pve2'))
    assert app.server.bodies[f'{BASE}/pve2'] == [{'password': 'pve2-own-root'}]
    assert '/api/clusters/c1/reconfigure' not in app.server.bodies
    app.see('Password of pve2 saved')
    assert field.input_value() == ''

    page.locator('[data-node-cred="pve3"] button', has_text='Use cluster password').click()
    assert _wait(page, lambda: ('DELETE', f'{BASE}/pve3') in app.server.calls)
    app.see('pve3 uses the cluster password again')

    box.locator('button', has_text='Check logins').click()
    assert _wait(page, lambda: ('POST', f'{BASE}/check') in app.server.calls)
    # pve1 has no password of its own: no button to clear one
    assert page.locator('[data-node-cred="pve1"] button', has_text='Use cluster password').count() == 0
    # the value never shows up anywhere on the page
    assert 'pve2-own-root' not in page.content()
    assert not app.errors, app.errors


def test_runtime_a_refused_save_shows_the_servers_words(open_app):
    extra = _extra()
    extra[('PUT', f'{BASE}/pve2')] = (400, {'error': 'The password must not contain control characters or line breaks'})
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], extra=extra)
    page = app.page
    _open_reconfigure(app, 'modern')
    page.locator('[data-node-creds="c1"]').get_by_text('Node credentials').click()
    page.locator('[data-node-cred="pve2"] input[type="password"]').fill('x')
    page.locator('[data-node-cred="pve2"] button', has_text='Save').click()
    app.see('The password must not contain control characters or line breaks')
    assert not app.errors, app.errors


def test_runtime_a_token_cluster_and_ssh_off_say_so(open_app):
    state = dict(STATE, token_auth=True, ssh_disabled=True, cluster_password=False)
    app = open_app(role='standalone', layout='corporate', clusters=[CLUSTER], extra=_extra(state))
    page = app.page
    _open_reconfigure(app, 'corporate')
    page.locator('[data-node-creds="c1"]').get_by_text('Node credentials').click()
    page.locator('[data-node-cred="pve1"]').wait_for(timeout=5000)
    text = page.locator('[data-node-creds="c1"]').inner_text()
    assert 'logs in with an API token' in text and 'SSH is switched off for this cluster' in text
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(role='standalone', layout='modern', language='de', clusters=[CLUSTER], extra=_extra())
    page = app.page
    page.locator('button[title="Cluster neu konfigurieren"]').first.click()
    page.locator('input[type="password"]').first.fill('correct horse')
    page.locator('input[type="password"]').first.press('Enter')
    box = page.locator('[data-node-creds="c1"]')
    box.wait_for(timeout=5000)
    box.get_by_text('Node-Zugangsdaten').click()
    page.locator('[data-node-cred="pve2"]').wait_for(timeout=5000)
    text = box.inner_text()
    assert 'Anmeldung abgelehnt' in text and 'Nutzt das Cluster-Passwort' in text and 'Eigenes Passwort gesetzt' in text
    assert not app.errors, app.errors


def _add_cluster(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('button[title="Add Cluster"]').first.click()
    else:
        page.locator('button', has_text='Add Cluster').first.click()
        page.get_by_role('button', name=re.compile(r'^Proxmox VE')).first.click()
    page.get_by_placeholder('Production Cluster').fill('Lab Two')
    page.get_by_placeholder('proxmox.example.com').fill('10.0.9.1')
    page.get_by_placeholder('root@pam or user@pam!tokenid').fill('root@pam')
    page.locator('input[type="password"][placeholder="Password"]').fill('cluster-pw')
    page.locator('form button[type="submit"]').last.click()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_refusal_after_adding_leads_to_the_section(open_app, layout):
    c2 = '/api/clusters/c2/node-credentials'
    state = dict(STATE, cluster_id='c2')
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra={
        ('POST', '/api/clusters'): (201, {'id': 'c2', 'message': 'Cluster added successfully', 'node_check': True}),
        ('GET', c2): (200, state),
        ('POST', '/api/auth/verify-password'): (200, {'success': True}),
        ('GET', '/api/clusters/c2/config/export'): (200, dict(EXPORT, name='Lab Two', host='10.0.9.1')),
    })
    page = app.page
    _add_cluster(app, layout)
    note = page.locator('[data-node-creds-notice="c2"]')
    note.wait_for(timeout=15000)
    assert 'pve2 refused the login to Lab Two' in note.inner_text()
    note.locator('button', has_text='Open node credentials').click()
    assert page.locator('[data-node-creds-notice]').count() == 0
    _reauth(page)
    # the dialog opens on the section, already expanded
    page.locator('[data-node-creds="c2"] [data-node-cred="pve2"]').wait_for(timeout=5000)
    assert page.locator('[data-node-cred="pve2"]').get_attribute('data-node-cred-state') == 'refused'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_re_configure_that_cleared_node_passwords_says_so(open_app, layout):
    """Pointed at another address, the server drops the nodes' own passwords
    (node_passwords_cleared); the notice names them and leads back to the section."""
    extra = _extra()
    extra[('POST', '/api/clusters/c1/reconfigure')] = (200, {
        'success': True, 'message': 'Cluster re-configured successfully',
        'node_passwords_cleared': ['pve2', 'pve3']})
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=extra)
    page = app.page
    _open_reconfigure(app, layout)
    page.get_by_placeholder('proxmox.example.com').fill('10.0.0.50')
    page.locator('input[type="password"][placeholder="Password"]').fill('cluster-pw')
    page.locator('form button[type="submit"]').last.click()
    note = page.locator('[data-node-creds-notice="c1"]')
    note.wait_for(timeout=5000)
    assert note.get_attribute('data-node-creds-reason') == 'moved'
    body = app.server.bodies['/api/clusters/c1/reconfigure'][-1]
    assert body['host'] == '10.0.0.50'
    text = note.inner_text()
    assert 'the own passwords of pve2, pve3 were cleared' in text and 'refused' not in text
    note.locator('button', has_text='Open node credentials').click()
    _reauth(page)
    page.locator('[data-node-creds="c1"] [data-node-cred="pve2"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_re_configure_that_cleared_nothing_shows_no_notice(open_app):
    extra = _extra()
    extra[('POST', '/api/clusters/c1/reconfigure')] = (200, {'success': True})
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], extra=extra)
    page = app.page
    _open_reconfigure(app, 'modern')
    page.locator('input[type="password"][placeholder="Password"]').fill('cluster-pw')
    page.locator('form button[type="submit"]').last.click()
    assert _wait(page, lambda: '/api/clusters/c1/reconfigure' in app.server.bodies)
    page.wait_for_timeout(300)
    assert page.locator('[data-node-creds-notice]').count() == 0
    assert not app.errors, app.errors


def test_runtime_no_notice_when_every_node_logged_in(open_app):
    c2 = '/api/clusters/c2/node-credentials'
    fine = dict(STATE, cluster_id='c2', nodes=[dict(STATE['nodes'][0])])
    app = open_app(role='standalone', layout='corporate', clusters=[CLUSTER], extra={
        ('POST', '/api/clusters'): (201, {'id': 'c2', 'node_check': True}),
        ('GET', c2): (200, fine)})
    _add_cluster(app, 'corporate')
    assert _wait(app.page, lambda: ('GET', c2) in app.server.calls, timeout=12)
    app.page.wait_for_timeout(500)
    assert app.page.locator('[data-node-creds-notice]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_connection_check_names_the_refused_nodes(open_app):
    report = {'cluster_id': 'c1', 'cluster_type': 'proxmox', 'connected': True, 'ssh_checked': True,
              'checked_at': '2026-10-10T10:00:00+00:00', 'duration_ms': 900,
              'summary': {'ok': 1, 'warn': 0, 'fail': 1, 'skip': 0}, 'refused': ['pve2'],
              'items': [{'id': 'ssh:pve1', 'kind': 'ssh', 'status': 'ok', 'hint': None, 'node': 'pve1',
                         'user': 'root', 'method': 'password', 'ip': '10.0.0.1', 'code': 'OK', 'credential': 'node'},
                        {'id': 'ssh:pve2', 'kind': 'ssh', 'status': 'fail', 'hint': 'ssh_auth_refused',
                         'node': 'pve2', 'user': 'root', 'method': 'password', 'ip': '10.0.0.2',
                         'code': 'AUTH_REFUSED', 'credential': 'cluster'}]}
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER],
                   extra={('POST', '/api/clusters/c1/connection-check'): (200, report)})
    page = app.page
    page.locator('button[title="Check connection"]').first.click()
    page.locator('[data-conn-check] button', has_text='Run check').click()
    page.locator('[data-check-refused]').wait_for(timeout=5000)
    assert 'Refused by pve2' in page.locator('[data-check-refused]').inner_text()
    text = page.locator('[data-conn-check]').inner_text()
    assert 'root@10.0.0.1 - password (own password)' in text and '(cluster password)' in text
    assert not app.errors, app.errors
