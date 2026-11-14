"""A container's next NIC is named after its netN, not eth0 again.

The add dialog started every container NIC as eth0, so net1 of a container that already had net0 = eth0 got a second eth0.
Proxmox takes the config without a check on the name.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
from test_ha_ui import CLUSTER, browser, _App, _FakeServer  # noqa: F401
from test_lxc_features_passthrough_ui import CT, CT_CONFIG, _open_config, _tab

CT_URL = '/api/clusters/c1/vms/pve1/lxc/101'
NET0 = {'id': 'net0', 'value': 'name=eth0,bridge=vmbr0,ip=dhcp', 'name': 'eth0', 'bridge': 'vmbr0', 'ip': 'dhcp'}


def _add_dialog(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[CT], extra={
        ('GET', f'{CT_URL}/config'): (200, dict(CT_CONFIG, networks=[NET0])),
        ('POST', f'{CT_URL}/networks'): (200, {'success': True})}))
    _open_config(app, 'ct101')
    _tab(app, 'Network').click()
    app.page.get_by_role('button', name='Add Network').last.click()
    dialog = app.page.locator('.fixed.inset-0', has_text='Interface Name').last
    dialog.wait_for(timeout=5000)
    return app, dialog


def _field(dialog, label):
    return dialog.locator(f'xpath=.//label[normalize-space()="{label}"]/following-sibling::input[1]')


def test_runtime_net1_is_offered_as_eth1(browser):  # noqa: F811
    app, dialog = _add_dialog(browser)
    try:
        assert _field(dialog, 'Interface ID').input_value() == 'net1'
        assert _field(dialog, 'Interface Name').input_value() == 'eth1'
        dialog.get_by_role('button', name='Add', exact=True).click()
        app.page.wait_for_timeout(500)
        body = [b for b in app.server.bodies.get(f'{CT_URL}/networks', []) if b][-1]
        assert body['net_id'] == 'net1' and body['name'] == 'eth1', body
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_the_name_follows_the_id_until_it_is_typed(browser):  # noqa: F811
    app, dialog = _add_dialog(browser)
    try:
        _field(dialog, 'Interface ID').fill('net3')
        assert _field(dialog, 'Interface Name').input_value() == 'eth3'
        _field(dialog, 'Interface Name').fill('lan')
        _field(dialog, 'Interface ID').fill('net4')
        assert _field(dialog, 'Interface Name').input_value() == 'lan'
    finally:
        app.ctx.close()
