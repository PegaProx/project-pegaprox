"""Both migration dialogs warn about every missing device in the PVE boot order."""

import pytest

from test_ha_ui import browser  # noqa: F401
from test_migration_preflight_ui import xc_app, _cross_dialog, SRC_CFG  # noqa: F401
from test_virtiofs_ui import _migrate


def _dialog(app, layout, dialog):
    """Open either migration dialog using the selected layout's action menu."""
    if dialog == 'local':
        return _migrate(app, layout)
    if layout == 'modern':
        return _cross_dialog(app)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.get_by_text('web01').first.click()
    page.get_by_role('button', name='Actions', exact=True).first.click()
    page.get_by_role('button', name='Cross-Cluster Migrate').first.click()
    page.get_by_text('Cross-Cluster Migration', exact=True).wait_for(timeout=5000)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('dialog', ['local', 'cross'])
@pytest.mark.parametrize('boot', [
    'legacy=cdn,order=scsi0;ide2;net0;net1',
    'legacy=cdn,order=scsi0 ; ide2 ; net0 ; net1',
])
def test_missing_later_boot_devices_are_shown(xc_app, layout, dialog, boot):
    """A missing disk or NIC after an existing first disk is still a boot issue."""
    config = dict(SRC_CFG, boot=boot)
    app = xc_app(layout=layout, src_cfg=config)
    view = _dialog(app, layout, dialog)
    warning = view.get_by_text('Boot Order Issue', exact=True)
    warning.wait_for(timeout=5000)
    assert warning.locator('..').locator('code').inner_text() == 'ide2, net1'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('dialog', ['local', 'cross'])
@pytest.mark.parametrize('boot', ['order=scsi0;net0', 'order=scsi0; net0',
                                  'order=scsi0 net0', 'cdn'])
def test_existing_devices_and_legacy_order_have_no_warning(xc_app, layout, dialog, boot):
    """Configured boot devices and the legacy BIOS order do not produce false warnings."""
    config = dict(SRC_CFG, boot=boot)
    app = xc_app(layout=layout, src_cfg=dict(SRC_CFG, boot='order=missing0'))
    view = _dialog(app, layout, dialog)
    warning = view.get_by_text('Boot Order Issue', exact=True)
    warning.wait_for(timeout=5000)
    _update_config(app.page, config)
    warning.wait_for(state='hidden', timeout=5000)
    assert not app.errors, app.errors


def _update_config(page, config):
    """Process a real config update after the initial warning has rendered."""
    page.evaluate("""config => window.dispatchEvent(new CustomEvent('pegaprox-vm-config', {
        detail: {vmid: 100, vm_type: 'qemu', cluster_id: 'cluster_1', config}
    }))""", config)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('dialog', ['local', 'cross'])
@pytest.mark.parametrize('missing', [False, True], ids=['implicit-net0', 'missing-net1'])
def test_qemu_implicit_net0_matches_the_server(xc_app, layout, dialog, missing):
    """QEMU's implicit net0 is valid, while an absent net1 still needs attention."""
    config = dict(SRC_CFG, boot='order=net0;net1' if missing else 'order=net0')
    config.pop('net0', None)
    app = xc_app(layout=layout, src_cfg=dict(SRC_CFG, boot='order=missing0'))
    view = _dialog(app, layout, dialog)
    warning = view.get_by_text('Boot Order Issue', exact=True)
    warning.wait_for(timeout=5000)
    _update_config(app.page, config)
    if missing:
        code = warning.locator('..').locator('code')
        from playwright.sync_api import expect
        expect(code).to_have_text('net1')
    else:
        warning.wait_for(state='hidden', timeout=5000)
    assert not app.errors, app.errors
