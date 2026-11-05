"""The Hypervisor Migration dialog offers a network for each NIC of an ESXi guest moving to XCP-ng.

The plan had no source NICs ('networks': []), so the dialog drew no network mapping and
every migration from the UI made a VM without a network interface. The plan now lists each
adapter with its port group; the dialog keys the map by the NIC's index, and the runner
attaches the mapped networks in that order. The plan served here is built by the real
plan_esxi_to_xcpng.

Runtime tests drive the built bundle in headless Chromium with the fake server of
test_ha_ui.py and skip where Playwright is not installed. MK Nov 2026
"""
import json
import types

import pegaprox.core.xhm as xhm_core
from test_ha_ui import _App, _FakeServer, browser  # noqa: F401  (browser is a fixture)

ESXI = {'id': 'esxi1', 'name': 'esx', 'display_name': 'esx', 'host': '10.0.0.5', 'connected': True,
        'status': 'running', 'cluster_type': 'esxi', 'type': 'esxi', 'enabled': True}
XCP = {'id': 'xcp1', 'name': 'pool', 'display_name': 'pool', 'host': '10.0.0.9', 'connected': True,
       'status': 'running', 'cluster_type': 'xcpng', 'type': 'xcpng', 'enabled': True}
GUEST = {'vmid': 5, 'name': 'vm1', 'type': 'qemu', 'status': 'stopped', 'node': 'esx'}
NICS = [{'label': 'Network adapter 1', 'network': 'VM Network', 'mac_address': 'm1'},
        {'label': 'Network adapter 2', 'network': 'Backup LAN', 'mac_address': 'm2'}]


def _real_plan(monkeypatch):
    src = types.SimpleNamespace(cluster_type='esxi', is_connected=True, get_vm_disks_for_export=lambda vmid: {'data': {
        'name': 'vm1', 'power_state': 'POWERED_OFF', 'guest_os': '', 'cpu_count': 2, 'memory_mb': 2048,
        'disks': [{'key': '2000', 'label': 'Hard disk 1', 'vmdk_file': '[ds1] vm1/vm1.vmdk', 'capacity_bytes': 1 << 30}],
        'nics': NICS}})
    tgt = types.SimpleNamespace(cluster_type='xcpng', is_connected=True, id='xcp1', config=types.SimpleNamespace(name='pool'),
                                get_storages=lambda: [{'storage': 'sr1', 'uuid': 'u1', 'type': 'lvm', 'avail': 1 << 40, 'total': 1 << 41}],
                                get_networks=lambda: [{'name': 'net-a', 'uuid': 'na', 'iface': 'xenbr0'},
                                                      {'name': 'net-b', 'uuid': 'nb', 'iface': 'xenbr1'}])
    monkeypatch.setitem(xhm_core.cluster_managers, 'esxi1', src)
    monkeypatch.setitem(xhm_core.cluster_managers, 'xcp1', tgt)
    plan = xhm_core.plan_esxi_to_xcpng('esxi1', '5', 'xcp1')
    assert 'error' not in plan, plan
    return json.loads(json.dumps(plan))


def _pick(page, label, value):
    page.locator(f'label:has-text("{label}") + select').first.select_option(value)


def test_runtime_each_esxi_nic_gets_a_network_and_the_map_goes_by_its_index(browser, monkeypatch):
    plan = _real_plan(monkeypatch)
    srv = _FakeServer(role='standalone', clusters=[ESXI, XCP], extra={
        ('GET', '/api/clusters/esxi1/resources'): (200, [GUEST]),
        ('GET', '/api/clusters/xcp1/resources'): (200, []),
        ('GET', '/api/xhm/plan'): (200, plan),
        ('GET', '/api/xhm/migrations'): (200, []),
        ('POST', '/api/xhm/migrate'): (200, {'migration_id': 'm1'}),
    })
    app = _App(browser, srv)
    try:
        page = app.page
        page.get_by_role('button', name='Hypervisor Migration').first.click()
        _pick(page, 'Source Cluster', 'esxi1')
        _pick(page, 'Target Cluster', 'xcp1')
        page.wait_for_timeout(400)
        _pick(page, 'Source VM', '5')
        page.get_by_role('button', name='Analyze').or_(page.get_by_role('button', name='Plan')).first.click()
        mapping = page.get_by_text('Network Mapping').first
        mapping.wait_for(timeout=5000)
        rows = mapping.locator('xpath=..').locator('div.flex')
        assert rows.count() == 2, rows.all_inner_texts()
        assert 'VM Network' in rows.nth(0).inner_text() and 'Backup LAN' in rows.nth(1).inner_text()
        rows.nth(1).locator('select').select_option('net-b')
        storage = page.locator('label:has-text("Target Storage") + select').first
        if storage.count():
            storage.select_option(index=1)
        page.get_by_role('button', name='Start Migration').first.click()
        page.wait_for_timeout(800)
        body, = srv.bodies['/api/xhm/migrate']
        assert body['network_map'] == {'1': 'net-b'}, body
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
