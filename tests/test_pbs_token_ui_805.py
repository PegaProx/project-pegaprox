"""The two PBS forms and an API token (#805).

The route side is tested in tests/test_pbs_api_token_805.py. Here the page:

- the edit dialog's Test button tests through POST /api/pbs/<id>/test, the route that
  fills the '********' of a stored secret in from the server. It used the route for a
  new server, so the mask itself went to PBS and every test of a saved server failed;
- the add dialog, which has nothing stored, keeps testing with what was typed;
- the PBS tab of Add Cluster takes a token the way its PVE tab does, user@realm!tokenid
  as the user name and the secret in the second field, and says so.

Runtime tests drive the built bundle in headless Chromium with the fake server of
test_ha_ui.py and skip where Playwright is not installed.
LW
"""
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, _App, _blocks, _classes, _FakeServer, _read, browser  # noqa: F401

PBS = {'id': 'p1', 'name': 'backup1', 'host': '10.0.0.5', 'port': 8007, 'user': 'root@pam',
       'api_token_id': 'svc@pbs!backup', 'using_api_token': True, 'connected': True,
       'linked_clusters': [], 'fingerprint': '', 'ssl_verify': False, 'notes': '',
       'ssh_user': '', 'ssh_port': 22, 'has_ssh_key': False}
TESTED = {'success': True, 'version': {'version': '4.0.11'}, 'datastores': 2}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('clusters', [CLUSTER])
        app = _App(browser, _FakeServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _pbs_tests(app):
    return [c for c in app.server.calls if c[0] == 'POST' and c[1].startswith('/api/pbs') and 'test' in c[1]]


def test_runtime_the_edit_dialog_tests_the_saved_server(open_app):
    app = open_app(extra={('GET', '/api/pbs'): (200, [PBS]),
                          ('POST', '/api/pbs/p1/test'): (200, TESTED)})
    page = app.page
    page.get_by_text('backup1').first.click()
    page.locator('button', has_text='Edit').first.click()
    page.locator('button', has_text='Test Connection').first.click()
    page.get_by_text('Connection successful! PBS v4.0.11 - 2 datastore(s)').wait_for(timeout=5000)

    assert _pbs_tests(app) == [('POST', '/api/pbs/p1/test')]
    body, = app.server.bodies['/api/pbs/p1/test']
    # the stored secrets go as the mask, the server fills them in
    assert body['password'] == '********' and body['api_token_secret'] == '********'
    assert body['host'] == '10.0.0.5' and body['port'] == 8007
    assert not app.errors, app.errors


def test_runtime_the_add_dialog_tests_what_was_typed(open_app):
    app = open_app(extra={('GET', '/api/pbs'): (200, []),
                          ('POST', '/api/pbs/test-connection'): (200, TESTED)})
    page = app.page
    page.get_by_text('Add Backup Server').first.click()
    dialog = page.locator('div.fixed', has_text='Test Connection').last
    dialog.locator('input[placeholder="pbs.example.com"]').fill('10.0.0.7')
    dialog.locator('input[placeholder="user@pam!tokenname"]').fill('svc@pbs!backup')
    dialog.locator('input[placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]').fill('typed-value')
    dialog.locator('button', has_text='Test Connection').click()
    page.get_by_text('Connection successful!').first.wait_for(timeout=5000)

    assert _pbs_tests(app) == [('POST', '/api/pbs/test-connection')]
    body, = app.server.bodies['/api/pbs/test-connection']
    assert body['api_token_secret'] == 'typed-value'
    assert not app.errors, app.errors


def _add_cluster_pbs_tab(app):
    page = app.page
    # the header's Add Cluster menu opens the Add Cluster dialog on its PBS tab
    page.locator('button', has_text='Add Cluster').first.click()
    page.locator('button', has_text='Proxmox Backup Server').first.click()
    form = page.locator('form').filter(has=page.locator('input[placeholder="pbs.example.com"]')).first
    form.wait_for(timeout=5000)
    return form


def test_runtime_the_add_cluster_pbs_tab_takes_a_token(open_app):
    app = open_app(extra={('GET', '/api/pbs'): (200, []),
                          ('POST', '/api/pbs'): (201, dict(PBS, id='p9', name='bk'))})
    page = app.page
    form = _add_cluster_pbs_tab(app)
    assert form.get_by_text('Password / Token').count() == 1
    assert form.get_by_text('For API tokens: user@realm!tokenid').count() == 1

    form.locator('input[placeholder="Backup Server 1"]').fill('bk')
    form.locator('input[placeholder="pbs.example.com"]').fill('10.0.0.8')
    user = form.locator('input[placeholder="root@pam"]')
    user.fill('svc@pbs!backup')
    secret = form.locator('input[type="password"]').first
    assert secret.get_attribute('placeholder') == 'Token Secret'
    secret.fill('typed-value')
    form.locator('button[type="submit"]').click()
    page.wait_for_timeout(800)

    assert app.server.calls.count(('POST', '/api/pbs')) == 1
    body, = [b for b in app.server.bodies['/api/pbs'] if b]   # the GETs have none
    assert body['user'] == 'svc@pbs!backup' and body['password'] == 'typed-value'
    assert not app.errors, app.errors


def test_runtime_the_add_cluster_pbs_tab_still_reads_password_for_a_user(open_app):
    app = open_app(extra={('GET', '/api/pbs'): (200, [])})
    form = _add_cluster_pbs_tab(app)
    assert form.locator('input[type="password"]').first.get_attribute('placeholder') == 'Password'
    assert not app.errors, app.errors


# -- source ------------------------------------------------------------------------------

def _pbs_tab():
    src = _read('web', 'src', 'create_modals.js')
    start = src.index("{connectionType === 'pbs' && (<>")
    return src[start:src.index('</>)}', start)]


@pytest.mark.parametrize('lang', LANGS)
def test_the_keys_the_pbs_tab_uses_exist_once_per_language(lang):
    block = _blocks()[lang]
    keys = set(re.findall(r"t\('(passwordOrToken|apiTokenHint)'\)", _pbs_tab()))
    assert keys == {'passwordOrToken', 'apiTokenHint'}
    for key in keys:
        assert len(re.findall(r'^ +%s: ' % key, block, re.M)) == 1, (lang, key)


def test_every_class_of_the_pbs_tab_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_pbs_tab()) if n not in have)
    assert not missing, missing


def test_no_em_dash_in_the_credential_row():
    row = _pbs_tab()
    row = row[row.index("{t('username')}"):row.index('Fingerprint')]
    assert '\u2014' not in row


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    assert 'handleTestPBS(pbsForm,editingPBS?.id)' in bundle
    assert '/pbs/${encodeURIComponent(pbsId)}/test`' in bundle
