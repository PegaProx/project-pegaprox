"""The Create Container wizard wants a root password or an SSH key before Create is enabled.

The server refuses a container with neither (test_container_create_needs_a_credential.py),
so the wizard says so up front: under the password and key fields a short hint, and Create
stays disabled with the same hint as its title until one of the two is filled in. A key of
only blanks does not count. Modern and both Corporate layouts share the step content and
gate their own Create button.

The runtime tests drive the built bundle against the fake server of tests/test_ha_ui.py in
headless Chromium and skip where Playwright is not installed.
"""
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, _App, _blocks, _FakeServer, _read, browser  # noqa: F401

KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0yTestKeyTestKeyTestKeyTestKeyTest0 ops@example'
TEMPLATE = 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst'
HINT_EN = 'Enter a root password or an SSH public key to create the container.'
VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'stopped', 'node': 'pve1',
      'cpu': 0, 'cpu_percent': 0, 'maxcpu': 2, 'mem': 0, 'maxmem': 4294967296,
      'mem_percent': 0, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 0}


# -- source ------------------------------------------------------------------------------------

def _modal():
    src = _read('web', 'src', 'create_modals.js')
    start = src.index('function CreateVmModal(')
    return src[start:src.index('// Add Cluster Modal', start)]


@pytest.mark.parametrize('lang', LANGS)
def test_the_hint_is_translated_next_to_the_key_field_texts(lang):
    block = _blocks()[lang]
    found = re.findall(r"^ +ctCredentialRequired: '((?:[^'\\]|\\.)+)',$", block, re.M)
    assert len(found) == 1, (lang, found)
    en = re.findall(r"^ +ctCredentialRequired: '([^']+)',$", _blocks()['en'], re.M)[0]
    assert en == HINT_EN
    if lang != 'en':
        assert found[0] != en, lang
    lines = block.split('\n')
    at = next(i for i, ln in enumerate(lines) if ln.strip().startswith('ctCredentialRequired:'))
    assert lines[at - 1].strip().startswith('sshKeyHintMultiple:'), lines[at - 1]
    assert at < len(lines) - 100


def test_both_create_buttons_wait_for_a_password_or_a_key():
    modal = _modal()
    m = re.search(r"const ctNeedsCredential = ([^;]+);", modal)
    assert m, 'ctNeedsCredential is not defined'
    rule = m.group(1)
    for part in ('!isQemu', '!config.password', "(config.ssh_public_keys || '').trim()"):
        assert part in rule, (part, rule)
    gated = re.findall(r"disabled=\{loading \|\| \(!isQemu && !config\.template\) \|\| ctNeedsCredential\}\s*"
                       r"title=\{ctNeedsCredential \? t\('ctCredentialRequired'\) : undefined\}", modal)
    assert len(gated) == 2, gated     # the Corporate and the Modern footer
    assert "disabled={loading || (!isQemu && !config.template)}" not in modal


def test_the_hint_sits_under_the_key_field():
    modal = _modal()
    step = modal[modal.index('case 1: // Template'):modal.index('case 2: // Ressourcen')]
    assert step.index("t('sshKeyHintMultiple')") < step.index("t('ctCredentialRequired')")
    assert re.search(r"\{ctNeedsCredential && \(\s*<p data-ct-credential-hint[^>]*>"
                     r"\{t\('ctCredentialRequired'\)\}</p>", step), step[-600:]


# -- runtime -----------------------------------------------------------------------------------

class _CtServer(_FakeServer):
    """The fake server with the reads the container wizard makes on node pve1."""

    def __init__(self, **kw):
        super().__init__(**kw)
        node = '/api/clusters/c1/nodes/pve1'
        self.extra.update({
            ('GET', '/api/clusters/c1/nodes'): (200, [{'node': 'pve1', 'status': 'online'}]),
            ('GET', f'{node}/storage'): (200, [{'storage': 'local-lvm', 'type': 'lvmthin',
                                                'content': 'rootdir,images', 'avail': 10 ** 11,
                                                'total': 2 * 10 ** 11, 'active': 1, 'enabled': 1}]),
            ('GET', f'{node}/networks'): (200, [{'iface': 'vmbr0', 'type': 'bridge'}]),
            ('GET', f'{node}/templates'): (200, [{'volid': TEMPLATE, 'name': 'debian-12-standard',
                                                  'type': 'lxc'}]),
            ('GET', f'{node}/nextid'): (200, {'vmid': 105}),
            ('POST', f'{node}/lxc'): (200, {'success': True, 'vmid': 105}),
        })


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout):
        app = _App(browser, _CtServer(role='standalone', layout=layout, clusters=[CLUSTER],
                                      metrics={}, resources=[VM]))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open_wizard(app, layout):
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('button', has_text='Resources').first.click()
    page.locator('button', has_text='Create new Container').first.click()
    page.locator('input[placeholder="my-container"]').wait_for(timeout=8000)
    return page


def _step(page, label, times=1):
    for _ in range(times):
        page.locator('button', has_text=re.compile(rf'^\s*{label}\s*$')).last.click()
        page.wait_for_timeout(150)


def _create_button(page):
    """The wizard's own Create, right after its Back (the dashboard has a button of that name too)."""
    return page.locator('button', has_text=re.compile(r'^\s*Back\s*$')).last.locator(
        'xpath=following-sibling::button[1]')


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
def test_runtime_create_waits_for_a_password_or_a_key(open_app, layout):
    app = open_app(layout)
    page = _open_wizard(app, layout)
    password = page.locator('input[type="password"][placeholder="••••••••"]')
    keys = page.locator('textarea[placeholder^="ssh-rsa"]')
    hint = page.locator('[data-ct-credential-hint]')
    create = _create_button(page)

    page.locator('input[placeholder="my-container"]').fill('ct-new')
    _step(page, 'Next')
    page.locator('select').filter(has=page.locator(f'option[value="{TEMPLATE}"]')).first.select_option(TEMPLATE)
    assert hint.inner_text() == HINT_EN
    _step(page, 'Next', 4)
    assert create.inner_text().strip() == 'Create new Container'
    assert create.is_disabled()
    assert create.get_attribute('title') == HINT_EN

    _step(page, 'Back', 4)
    password.fill('chosen-root-pw')
    assert hint.count() == 0
    _step(page, 'Next', 4)
    assert not create.is_disabled() and create.get_attribute('title') is None

    _step(page, 'Back', 4)
    password.fill('')
    keys.fill('   \n  ')
    assert hint.count() == 1             # blanks are no key
    _step(page, 'Next', 4)
    assert create.is_disabled()

    _step(page, 'Back', 4)
    keys.fill(KEY)
    assert hint.count() == 0
    _step(page, 'Next', 4)
    assert not create.is_disabled()
    create.click()
    page.wait_for_timeout(500)
    [sent] = app.server.bodies['/api/clusters/c1/nodes/pve1/lxc']
    assert sent['ssh_public_keys'] == KEY and sent['template'] == TEMPLATE and sent['password'] == ''
    assert not app.errors, app.errors
