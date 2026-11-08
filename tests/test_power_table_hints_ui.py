"""The per-VM power table says what a row cannot show plainly.

A guest that is gone and ran before hosts were tracked has no host to charge: the host cell
says so (its share is in Unallocated) instead of staying empty with a "~". A guest whose
memory reads over 100 % gets a hint: Proxmox counts the QEMU process, which a guest without
the balloon driver can push past its RAM. Runtime tests drive the built bundle.
"""
import re

from test_ha_ui import _blocks
from test_power_host_profiles_965_ui import ROW, _open_power, _summary, open_app, browser  # noqa: F401

PER_VM = '/api/clusters/c1/power/per-vm'
KEYS = ['powerNoHost', 'powerMemOverAssigned']


def test_every_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_runtime_a_guest_without_a_host_and_memory_over_100(open_app):
    gone = dict(ROW, vmid='129', name='129', node='', node_estimated=True, kwh=0, by_node={},
                monthly_kwh=0, monthly_cost=0, monthly_co2=0)
    vista = dict(ROW, vmid='123', name='Windows-Vista', avg_mem_pct=115.4, by_node={'pve1': 8.9})
    app = open_app(summary=_summary())
    app.server.extra[('GET', PER_VM)] = (200, {'enough_data': True, 'cluster_id': 'c1', 'days': 30,
                                                'rows': [ROW, gone, vista]})
    page = _open_power(app)
    row = page.locator('tr').filter(has_text='129').last
    row.wait_for(timeout=5000)
    host = row.locator('td').nth(2)
    assert host.inner_text().strip() == '-'
    assert 'No host recorded' in host.locator('[data-power-no-host]').get_attribute('title')
    vm = page.locator('tr').filter(has_text='Windows-Vista').last
    assert vm.locator('[data-power-mem-over]').count() == 1
    assert 'QEMU process' in vm.locator('[data-power-mem-over]').get_attribute('title')
    # an ordinary row gets neither
    plain = page.locator('tr').filter(has_text='web01').last
    assert plain.locator('[data-power-no-host], [data-power-mem-over]').count() == 0
    assert '~' in plain.locator('td').nth(2).inner_text()
    assert not app.errors, app.errors
