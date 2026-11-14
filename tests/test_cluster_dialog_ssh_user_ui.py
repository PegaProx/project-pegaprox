"""The SSH user of a Proxmox VE cluster in the Add / Re-configure Cluster dialog (#1322).

The server took ssh_user on PUT /api/clusters/<id> only, the dialog had no field for it,
and a save in Re-configure built the cluster from the form, so a user set over the API was
gone afterwards. The SSH section now has the field (empty means root), Re-configure fills
it from the export and opens the section when a user is set, and the key field says a
stored key is kept when it is left empty. The help text names the SSH user's
authorized_keys instead of root's alone.

The runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py and skip where Playwright is not installed. LW
"""
import re
import time

import pytest

from test_ha_ui import CLUSTER, LANGS, _blocks, _classes, _read, browser, open_app  # noqa: F401 (fixtures)

KEYS = ('sshUser', 'sshUserHint', 'sshKeyStoredKeep', 'sshKeyExplanation')
EXPORT = {'name': 'Testi', 'host': '10.0.0.1', 'user': 'someuser@pve!pegaprox', 'ssl_verification': False,
          'migration_threshold': 20, 'migration_tolerance': 10, 'check_interval': 300, 'auto_migrate': False,
          'balance_containers': False, 'balance_local_disks': False, 'dry_run': False,
          'cluster_type': 'proxmox', 'vnc_tunnel': False, 'ssh_disabled': False}
STATE = {'cluster_id': 'c1', 'ssh_user': 'root', 'ssh_key': True, 'ssh_disabled': False, 'token_auth': True,
         'cluster_password': False, 'max_length': 256, 'nodes': []}
KEEP_EN = 'A key is stored for this cluster. Leave this empty to keep it, or paste a new one to replace it.'
PEM = '-----BEGIN OPENSSH PRIVATE KEY-----'


# -- source ------------------------------------------------------------------------------------

def _modal():
    src = _read('web', 'src', 'create_modals.js')
    start = src.index('function AddClusterModal(')
    return src[start:src.index('\n        }\n', src.index('const handleSubmit', start))]


def _ssh_section(modal):
    start = modal.index("{t('sshKeyExplanation')}")
    return modal[start:modal.index("t('sshDisabled')", start)]


@pytest.mark.parametrize('lang', LANGS)
def test_every_language_has_the_texts_once_and_none_at_the_pinned_end(lang):
    block = _blocks()[lang]
    lines = block.split('\n')
    for key in KEYS:
        found = [i for i, ln in enumerate(lines) if ln.startswith(f'                {key}: ')]
        assert len(found) == 1, (lang, key, found)
        assert found[0] < len(lines) - 100, (lang, key)
        line = lines[found[0]]
        assert '\u2014' not in line and '\u2013' not in line, (lang, key)
    if lang != 'en':
        for key in ('sshUserHint', 'sshKeyStoredKeep'):
            mine = re.search(r'^                %s: (.*)$' % key, block, re.M).group(1)
            en = re.search(r'^                %s: (.*)$' % key, _blocks()['en'], re.M).group(1)
            assert mine != en, (lang, key)


@pytest.mark.parametrize('lang', LANGS)
def test_the_help_text_names_the_ssh_users_keys_and_the_pam_rule(lang):
    line = re.search(r'^                sshKeyExplanation: (.*)$', _blocks()[lang], re.M).group(1)
    assert '~/.ssh/authorized_keys' in line and '/root/.ssh/authorized_keys' in line, lang
    assert '@pam' in line and 'root@pam' in line, lang
    en = re.search(r'^                sshKeyExplanation: (.*)$', _blocks()['en'], re.M).group(1)
    assert 'as the SSH user below' in en and 'Node credentials' in en
    assert "its public key must be in /root/.ssh/authorized_keys on every node" not in en


def test_the_field_sits_in_the_ssh_section_and_goes_out_with_the_form():
    modal = _modal()
    section = _ssh_section(modal)
    assert section.index('data-ssh-user') < section.index('value={config.ssh_key}')
    assert re.search(r"<input type=\"text\" data-ssh-user value=\{config\.ssh_user \|\| ''\} "
                     r"onChange=\{e => setConfig\(\{\.\.\.config, ssh_user: e\.target\.value\}\)\}", section)
    assert 'placeholder="root"' in section and "t('sshUserHint')" in section
    assert ("placeholder={reconfigureConfig?.has_ssh_key ? t('sshKeyStoredKeep') : "
            "'-----BEGIN OPENSSH PRIVATE KEY-----'}") in section
    src = _read('web', 'src', 'create_modals.js')
    factory = src[src.index('const emptyProxmoxConfig = () => ({'):src.index('const emptyXcpConfig')]
    assert "ssh_user: ''" in factory
    assert "ssh_user: rc.ssh_user || ''" in modal
    assert 'if (rc.ssh_user) setShowSshSettings(true);' in modal


def test_classes_are_in_the_css_and_the_bundle_was_rebuilt():
    section = _ssh_section(_modal())
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(section) if n not in have)
    assert not missing, missing
    bundle = _read('web', 'index.html')
    for needle in ('data-ssh-user', 'sshKeyStoredKeep', 'sshUserHint', KEEP_EN):
        assert needle in bundle, needle


# -- runtime -----------------------------------------------------------------------------------

def _extra(export=EXPORT):
    return {('POST', '/api/auth/verify-password'): (200, {'success': True}),
            ('GET', '/api/clusters/c1/config/export'): (200, export),
            ('GET', '/api/clusters/c1/node-credentials'): (200, STATE),
            ('POST', '/api/clusters/c1/reconfigure'): (200, {'success': True}),
            ('POST', '/api/clusters'): (201, {'id': 'c2', 'message': 'Cluster added successfully'})}


def _wait(page, cond, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        page.wait_for_timeout(100)
    return False


def _open_reconfigure(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
        menu = page.locator('.corp-context-menu').first
        menu.wait_for(timeout=3000)
        menu.get_by_text('Re-configure Cluster').click()
    elif layout == 'corporate-redesigned':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('[data-cr-objhead="cluster"] button[title="Re-configure Cluster"]').click()
    else:
        page.locator('button[title="Re-configure Cluster"]').first.click()
    page.get_by_placeholder('Your Password').fill('correct horse')
    page.get_by_placeholder('Your Password').press('Enter')
    page.locator('[data-node-creds="c1"]').wait_for(timeout=5000)
    return page


def _ssh_toggle(page):
    return page.locator('form button[type="button"]', has_text=re.compile(r'^\s*SSH Key'))


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
def test_runtime_re_configure_shows_and_sends_the_stored_ssh_user(open_app, layout):
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER],
                   extra=_extra(dict(EXPORT, ssh_user='someuser', has_ssh_key=True)))
    page = _open_reconfigure(app, layout)
    field = page.locator('[data-ssh-user]')
    field.wait_for(timeout=3000)          # open without a click: a user is set
    assert field.input_value() == 'someuser'
    assert field.get_attribute('placeholder') == 'root'
    key = page.locator('form textarea').first
    assert key.get_attribute('placeholder') == KEEP_EN
    assert 'Empty means root.' in page.locator('form').inner_text()

    field.fill('ops')
    page.locator('input[type="password"][placeholder="Token Secret"]').fill('token-secret')
    page.locator('form button[type="submit"]').last.click()
    assert _wait(page, lambda: '/api/clusters/c1/reconfigure' in app.server.bodies)
    body = app.server.bodies['/api/clusters/c1/reconfigure'][-1]
    assert body['ssh_user'] == 'ops' and body['ssh_key'] == ''
    assert not app.errors, app.errors


def test_runtime_re_configure_without_a_user_or_key_stays_as_before(open_app):
    """No user set: the section stays closed, the field is empty with root as placeholder,
    the key field shows the usual key placeholder, and an empty user goes out as ''."""
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER],
                   extra=_extra(dict(EXPORT, user='root@pam', ssh_user='', has_ssh_key=False)))
    page = _open_reconfigure(app, 'modern')
    assert page.locator('[data-ssh-user]').count() == 0
    _ssh_toggle(page).click()
    field = page.locator('[data-ssh-user]')
    field.wait_for(timeout=3000)
    assert field.input_value() == ''
    assert page.locator('form textarea').first.get_attribute('placeholder') == PEM
    page.locator('input[type="password"][placeholder="Password"]').fill('cluster-pw')
    page.locator('form button[type="submit"]').last.click()
    assert _wait(page, lambda: '/api/clusters/c1/reconfigure' in app.server.bodies)
    assert app.server.bodies['/api/clusters/c1/reconfigure'][-1]['ssh_user'] == ''
    assert not app.errors, app.errors


def test_runtime_an_export_without_the_new_fields_leaves_the_field_empty(open_app):
    """An older server sends neither ssh_user nor has_ssh_key."""
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], extra=_extra())
    page = _open_reconfigure(app, 'modern')
    _ssh_toggle(page).click()
    page.locator('[data-ssh-user]').wait_for(timeout=3000)
    assert page.locator('[data-ssh-user]').input_value() == ''
    assert page.locator('form textarea').first.get_attribute('placeholder') == PEM
    assert not app.errors, app.errors


def test_runtime_adding_a_cluster_sends_the_ssh_user(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], extra=_extra())
    page = app.page
    page.locator('button', has_text='Add Cluster').first.click()
    page.get_by_role('button', name=re.compile(r'^Proxmox VE')).first.click()
    page.get_by_placeholder('Production Cluster').fill('Lab Two')
    page.get_by_placeholder('proxmox.example.com').fill('10.0.9.1')
    page.get_by_placeholder('root@pam or user@pam!tokenid').fill('pegaprox@pve')
    page.locator('input[type="password"][placeholder="Password"]').fill('cluster-pw')
    _ssh_toggle(page).click()
    page.locator('[data-ssh-user]').fill('ops')
    assert page.locator('form textarea').first.get_attribute('placeholder') == PEM
    page.locator('form button[type="submit"]').last.click()
    assert _wait(page, lambda: '/api/clusters' in app.server.bodies)
    body = app.server.bodies['/api/clusters'][-1]
    assert body['ssh_user'] == 'ops' and body['user'] == 'pegaprox@pve'
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(role='standalone', layout='modern', language='de', clusters=[CLUSTER],
                   extra=_extra(dict(EXPORT, ssh_user='someuser', has_ssh_key=True)))
    page = app.page
    page.locator('button[title="Cluster neu konfigurieren"]').first.click()
    pw = page.locator('input[type="password"]').first
    pw.fill('correct horse')
    pw.press('Enter')
    field = page.locator('[data-ssh-user]')
    field.wait_for(timeout=5000)
    form = page.locator('form').inner_text()
    assert 'SSH-Benutzer' in form and 'Leer heißt root.' in form
    assert 'Für diesen Cluster ist ein Key hinterlegt.' in page.locator('form textarea').first.get_attribute('placeholder')
    assert not app.errors, app.errors
