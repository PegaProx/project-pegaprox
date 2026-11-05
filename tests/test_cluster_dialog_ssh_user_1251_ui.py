"""The cluster dialog has an SSH user, and a save with SSH untouched sends what was there (#1251).

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py; skips
where Playwright is not installed. The route is tested in tests/test_reconfigure_keeps_ssh_1251.py.
"""
import re

import pytest

from test_ha_ui import CLUSTER, browser, open_app  # noqa: F401
from test_node_credentials_ui import EXPORT, _extra, _open_reconfigure

URL = '/api/clusters/c1/reconfigure'


def _dialog(open_app, layout, **export):
    extra = _extra()
    extra[('GET', '/api/clusters/c1/config/export')] = (200, {**EXPORT, **export})
    extra[('POST', URL)] = (200, {'success': True})
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=extra)
    _open_reconfigure(app, layout)
    app.page.locator('button', has_text='SSH Key (Optional)').first.click()
    return app, app.page


def _save(app):
    page = app.page
    page.locator('.modal-backdrop input[type="password"]').first.fill('typed-again')
    page.locator('.modal-backdrop button[type="submit"]').first.click()
    for _ in range(50):
        if app.server.bodies.get(URL):
            break
        page.wait_for_timeout(100)
    assert app.server.bodies.get(URL), 'the dialog sent nothing'
    return app.server.bodies[URL][-1]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_save_sends_the_ssh_user_and_leaves_the_key_alone(open_app, layout):
    app, page = _dialog(open_app, layout, ssh_user='backupadmin', has_ssh_key=True)
    assert page.locator('[data-cluster-ssh-user]').input_value() == 'backupadmin'
    assert page.locator('[data-cluster-ssh-key-stored]').count() == 1
    body = _save(app)
    assert body['ssh_user'] == 'backupadmin' and body['ssh_key'] == '' and body['ssh_key_remove'] is False
    assert not app.errors, app.errors


def test_runtime_the_ssh_user_can_be_typed_and_shows_its_default(open_app):
    app, page = _dialog(open_app, 'modern', user='pegaprox@pve')
    field = page.locator('[data-cluster-ssh-user]')
    assert field.get_attribute('placeholder') == 'pegaprox'
    assert page.locator('[data-cluster-ssh-key-stored]').count() == 0, 'offers to remove a key that is not there'
    field.fill('root')
    assert _save(app)['ssh_user'] == 'root'


def test_runtime_the_stored_key_can_be_removed_but_not_while_one_is_typed(open_app):
    app, page = _dialog(open_app, 'modern', has_ssh_key=True)
    remove = page.locator('[data-cluster-ssh-key-remove]')
    key = page.locator('.modal-backdrop textarea').first
    key.fill('-----BEGIN OPENSSH PRIVATE KEY-----')
    assert remove.is_disabled()
    key.fill('')
    remove.check()
    assert _save(app)['ssh_key_remove'] is True


def test_runtime_add_cluster_offers_the_field_with_no_stored_key_control(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER])
    page = app.page
    page.locator('button', has_text='Add Cluster').first.click()
    page.get_by_role('button', name=re.compile(r'^Proxmox VE')).first.click()
    page.locator('button', has_text='SSH Key (Optional)').first.click()
    assert page.locator('[data-cluster-ssh-user]').count() == 1
    assert page.locator('[data-cluster-ssh-key-stored]').count() == 0
