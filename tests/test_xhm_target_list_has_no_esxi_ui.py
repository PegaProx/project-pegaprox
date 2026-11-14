"""The Hypervisor Migration dialog offers no ESXi host as a target.

Every migration it can start ends on Proxmox or XCP-ng: ESXi is a source only. The target
list left out the source's own kind and nothing else, so an ESXi host showed up for a
Proxmox or an XCP-ng source and the plan came back as an error. Now the list has the
other kinds without ESXi, and an ESXi source still gets Proxmox and XCP-ng.

Drives the built bundle in headless Chromium with the fake server of the pixel guard;
skips where Playwright is not installed. LW Nov 2026
"""
import pathlib

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, browser  # noqa: F401  (browser is a fixture)

BUNDLE = pathlib.Path(__file__).resolve().parent.parent / 'web' / 'index.html'
PVE = {'id': 'c1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1', 'connected': True,
       'status': 'running', 'enabled': True}
ESXI = {'id': 'esxi1', 'name': 'esx', 'display_name': 'esx', 'host': '10.0.0.5', 'connected': True,
        'status': 'running', 'cluster_type': 'esxi', 'type': 'esxi', 'enabled': True}
XCP = {'id': 'xcp1', 'name': 'pool', 'display_name': 'pool', 'host': '10.0.0.9', 'connected': True,
       'status': 'running', 'cluster_type': 'xcpng', 'type': 'xcpng', 'enabled': True}


@pytest.fixture
def dialog(browser):
    srv = _GuardServer(bundle=BUNDLE.read_bytes(), layout='modern', extra={
        ('GET', '/api/xhm/migrations'): (200, []),
        ('GET', '/api/clusters/esxi1/resources'): (200, []),
        ('GET', '/api/clusters/xcp1/resources'): (200, []),
    })
    srv.clusters = [PVE, ESXI, XCP]
    app = _GuardApp(browser, srv)
    try:
        app.page.get_by_role('button', name='Hypervisor Migration').first.click()
        app.page.locator('label:has-text("Source Cluster") + select').first.wait_for(timeout=10000)
        yield app
    finally:
        app.close()


def _targets_for(page, source):
    page.locator('label:has-text("Source Cluster") + select').first.select_option(source)
    page.wait_for_timeout(300)
    return page.locator('label:has-text("Target Cluster") + select').first.locator('option').evaluate_all(
        'opts => opts.map(o => o.value).filter(Boolean)')


@pytest.mark.parametrize('source, targets', [('c1', ['xcp1']), ('xcp1', ['c1']), ('esxi1', ['c1', 'xcp1'])])
def test_runtime_esxi_is_never_a_target(dialog, source, targets):
    assert _targets_for(dialog.page, source) == targets
    assert not dialog.errors, dialog.errors
