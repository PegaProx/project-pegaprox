"""Re-configure Cluster can drop a stored SSH key, and a blank key field is no key (#1251).

An empty key field keeps the stored key (#1322), which left no way to remove one. With a key
stored the SSH section now has a box that sends ssh_key_remove. It is off while a key is
typed in, a field with nothing but whitespace in it does not count as one, and the key itself
is never read back. The route is tested in tests/test_reconfigure_keeps_ssh_1251.py; the
runtime tests drive the built bundle in headless Chromium and skip where Playwright is not
installed. NS
"""
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, _blocks, _read, browser, open_app  # noqa: F401 (fixtures)
from test_cluster_dialog_ssh_user_ui import EXPORT, _extra, _modal, _open_reconfigure, _ssh_section, _ssh_toggle, _wait

URL = '/api/clusters/c1/reconfigure'
KEY = 'sshKeyRemove'


# -- source ------------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_language_has_the_label_once_and_none_at_the_pinned_end(lang):
    block = _blocks()[lang]
    lines = block.split('\n')
    found = [i for i, ln in enumerate(lines) if ln.startswith(f'                {KEY}: ')]
    assert len(found) == 1 and found[0] < len(lines) - 100, (lang, found)
    assert '\u2014' not in lines[found[0]] and '\u2013' not in lines[found[0]], lang
    if lang != 'en':
        mine = re.search(r'^                %s: (.*)$' % KEY, block, re.M).group(1)
        en = re.search(r'^                %s: (.*)$' % KEY, _blocks()['en'], re.M).group(1)
        assert mine != en, lang


def test_the_box_sits_in_the_ssh_section_for_a_stored_key_only_and_goes_out_with_the_form():
    section = _ssh_section(_modal())
    box = section[section.index('reconfigureConfig?.has_ssh_key && ('):]
    assert 'data-ssh-key-remove' in box and "t('sshKeyRemove')" in box
    assert "disabled={!!(config.ssh_key || '').trim()}" in box
    src = _read('web', 'src', 'create_modals.js')
    factory = src[src.index('const emptyProxmoxConfig = () => ({'):src.index('const emptyXcpConfig')]
    assert 'ssh_key_remove: false' in factory
    assert "ssh_key: '', ssh_key_remove: false, ssh_disabled: rc.ssh_disabled || false" in _modal()


# -- runtime -----------------------------------------------------------------------------------

def _dialog(open_app, layout='modern', **export):
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=_extra(dict(EXPORT, **export)))
    page = _open_reconfigure(app, layout)
    if not page.locator('[data-ssh-user]').count():
        _ssh_toggle(page).click()
    page.locator('[data-ssh-user]').wait_for(timeout=3000)
    return app, page


def _save(app, page):
    page.locator('input[type="password"][placeholder="Token Secret"]').fill('token-secret')
    page.locator('form button[type="submit"]').last.click()
    assert _wait(page, lambda: URL in app.server.bodies), 'the dialog sent nothing'
    return app.server.bodies[URL][-1]


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
def test_runtime_a_save_leaves_the_stored_key_alone(open_app, layout):
    app, page = _dialog(open_app, layout, ssh_user='ops', has_ssh_key=True)
    assert page.locator('[data-ssh-key-remove]').count() == 1
    body = _save(app, page)
    assert body['ssh_key'] == '' and body['ssh_key_remove'] is False and body['ssh_user'] == 'ops'
    assert not app.errors, app.errors


def test_runtime_the_stored_key_can_be_removed(open_app):
    app, page = _dialog(open_app, has_ssh_key=True)
    page.locator('[data-ssh-key-remove]').check()
    body = _save(app, page)
    assert body['ssh_key_remove'] is True and body['ssh_key'] == ''
    assert not app.errors, app.errors


def test_runtime_the_box_is_off_while_a_key_is_typed_and_not_for_whitespace(open_app):
    app, page = _dialog(open_app, has_ssh_key=True)
    remove, key = page.locator('[data-ssh-key-remove]'), page.locator('form textarea').first
    key.fill('-----BEGIN OPENSSH PRIVATE KEY-----')
    assert remove.is_disabled()
    key.fill(' \n ')
    assert remove.is_enabled()
    key.fill('')
    assert remove.is_enabled()


def test_runtime_no_stored_key_no_box(open_app):
    app, page = _dialog(open_app, has_ssh_key=False)
    assert page.locator('[data-ssh-key-remove]').count() == 0
    app2, page2 = _dialog(open_app)         # an older server sends no has_ssh_key at all
    assert page2.locator('[data-ssh-key-remove]').count() == 0


def test_runtime_adding_a_cluster_has_no_such_box(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], extra=_extra())
    page = app.page
    page.locator('button', has_text='Add Cluster').first.click()
    page.get_by_role('button', name=re.compile(r'^Proxmox VE')).first.click()
    _ssh_toggle(page).click()
    page.locator('[data-ssh-user]').wait_for(timeout=3000)
    assert page.locator('[data-ssh-key-remove]').count() == 0
    assert not app.errors, app.errors
