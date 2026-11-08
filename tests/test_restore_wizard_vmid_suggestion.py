"""The restore wizard of a PBS snapshot takes the suggested VMID only where it can be used, and never over a typed one.

A full tenant range answers with Proxmox's next id, which the restore would then refuse; the batch restore already left it out.
The suggestion is read again on every switch back to "new", and it replaced what the user had typed.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import re

from test_ha_ui import CLUSTER, NODE_METRICS, PBS, VM, browser, _App, _FakeServer  # noqa: F401

NEXTID = '/api/clusters/c1/nextid'
STORE = '/api/pbs/p1/datastores/alpha'
SNAP = {'backup-type': 'vm', 'backup-id': '100', 'backup-time': 1780000000, 'size': 1073741824}


def _wizard(browser, nextid):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        ('GET', '/api/pbs'): (200, [dict(PBS, linked_clusters=['c1'])]),
        ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
        ('GET', '/api/pbs/p1/datastores'): (200, [{'name': 'alpha', 'used': 1, 'avail': 9}]),
        ('GET', f'{STORE}/groups'): (200, [{'backup-type': 'vm', 'backup-id': '100', 'backup-count': 1, 'last-backup': 1780000000}]),
        ('GET', f'{STORE}/namespaces'): (200, []),
        ('GET', f'{STORE}/snapshots'): (200, [SNAP]),
        ('GET', NEXTID): nextid}))
    page = app.page
    page.get_by_text('backup01').first.click()
    page.get_by_role('button', name='Datastores').first.click()
    page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
    page.locator('button[title="Restore Backup"]').first.click()
    wizard = page.locator('.fixed.inset-0', has_text='Target VMID').last
    wizard.wait_for(timeout=5000)
    return app, wizard


def _vmid(wizard):
    return wizard.locator('input[type="number"]').first


def _wait_read(app, page, n):
    for _ in range(40):
        if app.server.calls.count(('GET', NEXTID)) >= n:
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(300)


def test_runtime_a_free_id_is_suggested(browser):  # noqa: F811
    app, wizard = _wizard(browser, (200, {'vmid': 900}))
    try:
        _wait_read(app, app.page, 1)
        assert _vmid(wizard).input_value() == '900'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_full_tenant_range_keeps_the_default(browser):  # noqa: F811
    app, wizard = _wizard(browser, (200, {'vmid': 900, 'range': [100, 110], 'range_exhausted': True}))
    try:
        _wait_read(app, app.page, 1)
        assert _vmid(wizard).input_value() == '1100'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_typed_id_survives_a_switch_of_the_mode(browser):  # noqa: F811
    app, wizard = _wizard(browser, (200, {'vmid': 900}))
    try:
        page = app.page
        _wait_read(app, page, 1)
        _vmid(wizard).fill('4242')
        wizard.get_by_role('button', name='overwrite', exact=True).click()
        wizard.get_by_role('button', name='new', exact=True).click()
        _wait_read(app, page, 2)
        assert app.server.calls.count(('GET', NEXTID)) >= 2
        assert _vmid(wizard).input_value() == '4242'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
