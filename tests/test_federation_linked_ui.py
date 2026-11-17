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
    # the name is the control that opens it, a button of its own next to the chevron
    name = item.locator('button[data-fed-select]')
    assert name.inner_text() == 'Prod Hamburg'
    name.focus()
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
    permissions, blueprints) keep listing `clusters`, and only the lookups by id that open a
    view ask allClusters."""
    dash = _read('web', 'src', 'dashboard.js')
    main = dash[dash.index('function PegaProxDashboard('):dash.index('function Force2FASetupModal(')]
    assert 'const allClusters = useMemo(' in main
    import re
    assert not re.search(r'(?<![A-Za-z_])clusters\.find\(', main)
    # the migration dialog lists the other sites' clusters as targets (/api/federation/migrate)
    assert '<CrossClusterMigrateModal vm={dashCrossClusterVm} sourceCluster={selectedCluster} clusters={allClusters}' in main


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
    # past the first 500 other sites' guests the list says how many more there are
    tables = _read('web', 'src', 'tables.js')
    assert "{rows.length > 500 && (" in tables and 'data-remote-guests-more' in tables
    # the pop-out console checks a remote id against the linked sites
    assert "remote ? `${API_URL}/federation/linked` : `${API_URL}/clusters`" in dash


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function RemoteClusterItem(', '/federation/linked', 'fedConsoleUrl', 'data-fed-dr',
                   'function SiteAuthProvider(', 'data-all-guests-remote', 'federation/migrate'):
        assert needle in bundle, needle


# --- what the other site lets the account do, and the way there ------------------------------------

def _resources_of(page, row):
    row.click()
    page.wait_for_timeout(800)
    page.locator('button', has_text='Resources').first.click()
    page.wait_for_timeout(1200)


@pytest.mark.parametrize('admin_there', [False, True])
def test_runtime_a_remote_cluster_answers_with_that_sites_permissions(open_app, admin_there):
    """An admin here who holds vm.view and vm.start at the other site gets no deploy button
    in that site's cluster, and does in this site's; an admin there gets it there too."""
    app = _open(open_app, 'modern', sites=[dict(SITE, admin=admin_there)])
    page = app.page
    page.locator(f'[data-fed-cluster="{RID}"]').wait_for(timeout=8000)
    _resources_of(page, page.get_by_text('Testi').first)
    assert page.locator('[data-bp-nav="resources"]').count() == 1
    _resources_of(page, page.locator(f'[data-fed-cluster="{RID}"]'))
    assert page.locator(f'[data-fed-view="{IID}"]').is_visible()
    assert page.locator('[data-bp-nav="resources"]').count() == (1 if admin_there else 0)
    assert not app.errors, app.errors


def test_runtime_the_view_of_a_remote_cluster_leads_to_its_site(open_app):
    app = _open(open_app, 'modern')
    page = app.page
    row = page.locator(f'[data-fed-cluster="{RID}"]')
    row.wait_for(timeout=8000)
    # the row and the view both link to the cluster at its site, never to a plain address
    assert row.locator('[data-fed-open]').get_attribute('href') == 'https://b.example:5000/?cluster=pve-b'
    row.click()
    bar = page.locator(f'[data-fed-view="{IID}"]')
    bar.wait_for(timeout=8000)
    assert 'hamburg' in bar.inner_text()
    assert bar.locator('a').get_attribute('href') == 'https://b.example:5000/?cluster=pve-b'
    # site recovery and the cluster's settings are that site's
    tabs = page.evaluate('''() => Array.from(document.querySelectorAll('button'))
        .map(b => b.textContent.trim())''')
    assert 'Site Recovery' not in tabs, tabs
    assert not app.errors, app.errors


def test_runtime_a_remote_row_has_its_own_menu(open_app):
    app = _open(open_app, 'corporate-redesigned')
    page = app.page
    row = page.locator(f'[data-fed-cluster="{RID}"]')
    row.wait_for(timeout=8000)
    row.click(button='right')
    page.get_by_text('Open at hamburg').first.wait_for(timeout=5000)
    body = page.inner_text('body')
    # renamed, re-configured and removed at its site; no guest to create without vm.create there
    assert 'Rename' not in body and 'Remove Cluster' not in body and 'New VM' not in body
    assert not app.errors, app.errors


@pytest.mark.parametrize('admin_there', [False, True])
def test_runtime_a_remote_rows_menu_asks_that_site_alone(open_app, admin_there):
    """A viewer here who is an admin at the other site gets that site's entries on its row;
    what this site lets the account do does not take them away."""
    extra = _linked([dict(SITE, admin=admin_there)])
    app = open_app(role='standalone', layout='corporate-redesigned', clusters=[CLUSTER],
                   resources=[VM], extra=extra, admin=False, permissions=['cluster.view', 'vm.view'])
    page = app.page
    row = page.locator(f'[data-fed-cluster="{RID}"]')
    row.wait_for(timeout=8000)
    row.click(button='right')
    page.get_by_text('Open at hamburg').first.wait_for(timeout=5000)
    assert ('New VM' in page.inner_text('body')) is admin_there
    assert not app.errors, app.errors


def test_runtime_the_guest_list_has_the_other_sites_guests(open_app):
    app = _open(open_app, 'modern')
    page = app.page
    page.locator(f'[data-fed-cluster="{RID}"]').wait_for(timeout=8000)
    page.locator('[data-sidebar-guests]').first.click()
    section = page.locator('[data-all-guests-remote]')
    section.wait_for(timeout=10000)
    text = section.inner_text()
    assert 'web01' in text and 'hamburg' in text and 'Prod Hamburg' in text
    assert any(f'/api/clusters/{RID}/resources' in u for u in app.server.urls)
    assert not app.errors, app.errors


def test_runtime_only_remote_clusters_still_offer_the_global_views(open_app):
    """A site without clusters of its own shows the other sites' clusters and the global
    entries, not the card for an instance without any cluster."""
    extra = _linked([SITE])
    app = open_app(role='standalone', layout='modern', clusters=[], resources=[VM], extra=extra)
    page = app.page
    page.locator(f'[data-fed-cluster="{RID}"]').wait_for(timeout=8000)
    assert page.locator('[data-sidebar-guests]').count() == 1
    # the overview of all clusters counts the other site's, and the world map is there
    overview = page.locator('button', has_text='All Clusters').filter(has_text='cluster(s)')
    assert overview.count() == 1 and '1 cluster(s)' in overview.inner_text()
    assert page.locator('button', has_text='World Map').filter(has_text='Cluster locations').count() == 1
    assert not app.errors, app.errors


def test_the_cluster_view_asks_the_site_that_leads_it():
    dash = _read('web', 'src', 'dashboard.js')
    ctx = _read('web', 'src', 'contexts.js')
    assert 'function SiteAuthProvider({ fed, children })' in ctx
    view = dash[dash.index('<SiteAuthProvider fed={selectedCluster.fed}>'):dash.index('</SiteAuthProvider>')]
    assert 'canSnapshot={siteCan(' in view and "siteCan('vm.create')" in view
    # the standby rule holds for a remote cluster as well
    helper = dash[dash.index('const siteCan = '):]
    helper = helper[:helper.index('};')]
    assert '(!haReadOnly || haReadPermission(permission))' in helper
    # a menu entry of another site's cluster, node, pool or guest asks that site's permissions
    menu = dash[dash.index('const buildContextMenuItems = (type, target) => {'):]
    menu = menu[:menu.index('return out;')]
    assert 'const kept = site ? raw.filter(siteAllows) : raw.filter(menuAllows);' in menu
    assert 'const sub = site ? item.submenu.filter(siteAllows) : item.submenu.filter(menuAllows);' in menu


def test_a_migration_to_another_site_goes_through_the_federation():
    dash = _read('web', 'src', 'dashboard.js')
    # the guest table's dialog offers the other sites' clusters too
    table = dash[dash.index('<ResourceTable '):]
    assert 'migrateTargets={allClusters}' in table[:table.index('/>')]
    # replication stays between this site's clusters
    assert 'allClusters.filter(c => c.id !== clusterId && c.connected && !c.fed)' in _read('web', 'src', 'vm_config.js')
    modals = _read('web', 'src', 'vm_modals.js')
    assert "`${API_URL}/${crossSite ? 'federation/migrate' : 'cross-cluster-migrate'}`" in dash
    # a remote target is a connected Proxmox VE cluster; the preflight is for one site's two
    assert "&& (!c.fed || (c.connected && (c.cluster_type || 'proxmox') === 'proxmox'))" in modals
    assert 'if (!targetCluster || !targetNode || check.busy || crossSite) return;' in modals
