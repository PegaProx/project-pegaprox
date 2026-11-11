"""The Cloud layout creates a subnet with what Proxmox takes for a subnet.

Its Add subnet dialog offered DHCP none/dnsmasq and sent the pick as `dhcp`. A PVE subnet has
no such property (gateway, snat, dnszoneprefix, dhcp-range and dhcp-dns-server; dhcp=dnsmasq
belongs to the zone), so picking dnsmasq made PVE refuse the whole create. The classic dialog
never sent it.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

SDN = '/api/clusters/c1/datacenter/sdn'
SUBNETS = SDN + '/vnets/vnet1/subnets'
DATA = {'available': True, 'zones': [{'zone': 'zone1', 'type': 'vlan', 'bridge': 'vmbr0'}],
        'vnets': [{'vnet': 'vnet1', 'zone': 'zone1'}], 'subnets': [], 'controllers': []}


def _dialog(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='cloud', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', SDN): (200, DATA), ('POST', SUBNETS): (200, {'success': True})}))
    page = app.page
    page.locator('.cloud-nav-item', has_text='SDN').first.click()
    page.locator('.cloud-link-btn', has_text='Add subnet').first.click()
    modal = page.locator('.cloud-modal-footer').locator('xpath=../..')
    modal.locator('select.cloud-input').first.select_option('vnet1')
    modal.locator('input.cloud-input[placeholder="10.0.10.0/24"]').fill('10.0.10.0/24')
    return app, page, modal


def test_runtime_a_new_subnet_carries_no_dhcp_property(browser):  # noqa: F811
    app, page, modal = _dialog(browser)
    try:
        for pick in modal.locator('select.cloud-input').all()[1:]:
            if pick.locator('option[value="dnsmasq"]').count():
                pick.select_option('dnsmasq')
        modal.locator('input.cloud-input[placeholder="10.0.10.1"]').fill('10.0.10.1')
        page.locator('.cloud-modal-footer button[type="submit"]').click()
        page.wait_for_timeout(500)
        body = [b for b in app.server.bodies.get(SUBNETS, []) if b][-1]
        assert body == {'subnet': '10.0.10.0/24', 'gateway': '10.0.10.1', 'snat': 0}, body
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_the_dialog_offers_no_dhcp_pick(browser):  # noqa: F811
    app, page, modal = _dialog(browser)
    try:
        assert modal.locator('option[value="dnsmasq"]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
