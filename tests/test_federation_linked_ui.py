"""Linked mode in the UI: the clusters of the other sites of the federation in the sidebar.

Each other site gets a section of its own below this site's clusters, in Modern, Corporate
Redesigned and Cloud (classic Corporate stays as it is). A remote cluster opens like one of
this site's, and its calls go to its own id, which the server relays. A site that gives the
caller nothing says why; an account of another site is pointed to its home.

Runs the built bundle in headless Chromium against the fake server of tests/test_ha_ui.py.
Skips where Playwright is not installed.
LW Nov 2026
"""
import pytest

from test_ha_ui import CLUSTER, VM, browser, open_app  # noqa: F401

IID = 'b' * 32
RID = f'pve-b~{IID}'
SITE = {'iid': IID, 'site': 'hamburg', 'url': 'https://b.example:5000', 'state': 'ok',
        'perms': ['vm.view', 'vm.start'], 'release': '1.5.0',
        'clusters': [{'id': RID, 'name': 'Prod Hamburg', 'cluster_type': 'proxmox',
                      'connected': True, 'nodes': 3, 'vms': 40}]}


def _linked(sites, home=None):
    return {('GET', '/api/federation/linked'): (200, {'home': home, 'sites': sites})}


def _open(open_app, layout, sites=(SITE,), home=None, status=200):
    extra = _linked(list(sites), home) if status == 200 else {
        ('GET', '/api/federation/linked'): (status, {'code': 'FED_DISABLED', 'error': 'off'})}
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], resources=[VM], extra=extra)
    return app


@pytest.mark.parametrize('layout', ['modern', 'corporate-redesigned'])
def test_runtime_another_sites_cluster_has_a_section_and_opens(open_app, layout):
    app = _open(open_app, layout)
    page = app.page
    section = page.locator(f'[data-fed-site="{IID}"]')
    section.wait_for(timeout=8000)
    assert 'hamburg' in section.inner_text().lower()
    item = page.locator(f'[data-fed-cluster="{RID}"]')
    assert item.is_visible() and 'Prod Hamburg' in item.inner_text()
    # the local cluster is still there, in its own place
    assert page.get_by_text('Testi').first.is_visible()
    item.click()
    page.wait_for_timeout(1500)
    asked = [u for u in app.server.urls if f'/api/clusters/{RID}/' in u]
    assert asked, [u for u in app.server.urls if '/api/clusters/' in u][-10:]
    assert not app.errors, app.errors


def test_runtime_expanding_a_remote_cluster_reads_through_its_id(open_app):
    app = _open(open_app, 'modern')
    page = app.page
    item = page.locator(f'[data-fed-cluster="{RID}"]')
    item.wait_for(timeout=8000)
    chevron = item.locator('button[aria-expanded]').first
    assert chevron.get_attribute('aria-expanded') == 'false'
    chevron.click()
    page.wait_for_timeout(1500)
    asked = {u.split('?')[0] for u in app.server.urls if f'/api/clusters/{RID}/' in u}
    assert f'http://pegaprox.test/api/clusters/{RID}/resources' in asked, asked
    assert chevron.get_attribute('aria-expanded') == 'true'
    assert not app.errors, app.errors


def test_runtime_a_remote_cluster_opens_from_the_keyboard(open_app):
    app = _open(open_app, 'modern')
    page = app.page
    item = page.locator(f'[data-fed-cluster="{RID}"]')
    item.wait_for(timeout=8000)
    item.focus()
    page.keyboard.press('Enter')
    page.wait_for_timeout(1500)
    asked = [u for u in app.server.urls if f'/api/clusters/{RID}/' in u]
    assert asked, [u for u in app.server.urls if '/api/clusters/' in u][-10:]
    assert not app.errors, app.errors


def test_runtime_classic_corporate_shows_no_section(open_app):
    app = _open(open_app, 'corporate')
    page = app.page
    page.wait_for_timeout(1500)
    assert page.locator('[data-fed-site]').count() == 0
    assert not app.errors, app.errors


def test_runtime_cloud_lists_it_with_its_site(open_app):
    app = _open(open_app, 'cloud')
    page = app.page
    page.wait_for_timeout(1500)
    options = page.evaluate('''() => Array.from(document.querySelectorAll('select option'))
        .map(o => o.textContent)''')
    assert any('Prod Hamburg (hamburg)' in o for o in options), options
    assert not app.errors, app.errors


def test_runtime_a_site_that_gives_nothing_says_why(open_app):
    refused = dict(SITE, state='unmapped', clusters=[], perms=[])
    app = _open(open_app, 'modern', sites=[refused])
    page = app.page
    line = page.locator('[data-fed-site-state="unmapped"]')
    line.wait_for(timeout=8000)
    assert 'map your tenant and role' in line.inner_text()
    assert page.locator('[data-fed-cluster]').count() == 0


def test_runtime_an_account_of_another_site_is_pointed_home(open_app):
    home = {'iid': IID, 'site': 'hamburg', 'url': 'https://b.example:5000'}
    app = _open(open_app, 'modern', sites=[], home=home)
    page = app.page
    line = page.locator('[data-fed-home]')
    line.wait_for(timeout=8000)
    assert 'hamburg' in line.inner_text() and 'https://b.example:5000' in line.inner_text()


def test_runtime_with_the_federation_off_nothing_shows(open_app):
    app = _open(open_app, 'modern', status=404)
    page = app.page
    page.wait_for_timeout(1500)
    assert page.locator('[data-fed-site], [data-fed-home]').count() == 0
    assert not app.errors, app.errors


# --- the source -------------------------------------------------------------------------------

def _read(*parts):
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_pickers_keep_this_sites_clusters():
    """Remote rows live in their own list: the pickers that write this site's data (groups,
    permissions, blueprints, migrations) keep listing `clusters`, and only the lookups by id
    that open a view ask allClusters."""
    dash = _read('web', 'src', 'dashboard.js')
    main = dash[dash.index('function PegaProxDashboard('):dash.index('function Force2FASetupModal(')]
    assert 'const allClusters = useMemo(' in main
    import re
    assert not re.search(r'(?<![A-Za-z_])clusters\.find\(', main)
    assert '<CrossClusterMigrateModal vm={dashCrossClusterVm} sourceCluster={selectedCluster} clusters={clusters}' in main


def test_a_remote_console_goes_through_this_instance():
    modals = _read('web', 'src', 'node_modals.js')
    assert modals.count('fedConsoleUrl(clusterId, {') == 3
    assert '/api/federation/console?' in modals
    # the stable VNC mode keeps a handle at this instance's console server: never for a remote id
    assert "!String(clusterId).includes('~')" in modals
    # and no hint to accept the certificate of a console port the tunnel does not use
    assert "!reverseProxyEnabled && !fedRemote && (" in modals
    assert modals.count('!fedRemote') == 2


def test_the_dialogs_and_the_pop_out_know_remote_clusters():
    dash = _read('web', 'src', 'dashboard.js')
    main = dash[dash.index('function PegaProxDashboard('):dash.index('function Force2FASetupModal(')]
    # the config dialogs find the cluster type of a remote cluster
    assert '<ConfigModal' in main and 'allClusters={clusters}' not in main
    assert 'new Map(allClusters.map(c => [c.id, c]))' in main
    # the pop-out console checks a remote id against the linked sites
    assert "remote ? `${API_URL}/federation/linked` : `${API_URL}/clusters`" in dash


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function RemoteClusterItem(', '/federation/linked', 'fedConsoleUrl', 'data-fed-dr'):
        assert needle in bundle, needle
