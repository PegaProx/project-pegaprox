"""Corporate capacity cards against datastore fixtures, not a live cluster."""
import pytest

from test_ha_ui import CLUSTER, VM, _App, _FakeServer, browser  # noqa: F401

expect = pytest.importorskip('playwright.sync_api').expect
GiB = 1024 ** 3
PBS = {'storage': 'pbs', 'type': 'pbs', 'content': 'backup',
       'total': 80 * 1024 * GiB, 'used': 40 * 1024 * GiB}
LOCAL = {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir',
         'total': 4 * 1024 * GiB, 'used': 1024 * GiB}


@pytest.mark.parametrize('role', ['active', 'standby'])
@pytest.mark.parametrize('kind,shared,local,value,capacity', [
    ('proxmox', [PBS], [LOCAL], '25.0%', '1024.0 GB / 4096.0 GB'),
    ('proxmox', [PBS], [], '0.0%', '0 / 0'),
    ('xcpng', [{'storage': 'Local SR', 'total': 4096 * GiB, 'used': 1024 * GiB}], [],
     '25.0%', '1024.0 GB / 4096.0 GB'),
])
def test_corporate_capacity_excludes_backups_without_falling_back_to_rootfs(
        browser, role, kind, shared, local, value, capacity):
    cluster = dict(CLUSTER, cluster_type=kind)
    server = _FakeServer(role=role, layout='corporate', clusters=[cluster], resources=[VM],
                         metrics={'pve1': {'cpu_percent': 1, 'disk_total': 200 * GiB,
                                           'disk_used': 100 * GiB}},
                         extra={('GET', '/api/clusters/c1/datastores'):
                                (200, {'shared': shared, 'local': {'pve1': local}})})
    app = _App(browser, server)
    try:
        page = app.page
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        card = page.locator('.corp-overview-grid').first.locator('.corp-overview-card').nth(2)
        expect(card.locator('.corp-overview-value')).to_have_text(value)
        expect(card.locator('.corp-overview-sub')).to_have_text(capacity)
        assert not [e for e in app.errors if 'pageerror' in e], app.errors
        assert not [c for c in server.calls if c[0] != 'GET' and '/clusters/' in c[1]]
    finally:
        app.ctx.close()
