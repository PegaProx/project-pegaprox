"""The cluster update manager is a first-level tab in both classic layouts (#1193)."""
import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, _App, _FakeServer, _wait_for_call, browser  # noqa: F401


@pytest.fixture
def ui(browser):
    apps = []

    def _open(layout, role='standalone', **kw):
        extra = dict(SSE_TOKEN)
        for cid in ('c1', 'c2'):
            extra[('GET', f'/api/clusters/{cid}/updates/status')] = (200, {'success': True})
            extra[('GET', f'/api/clusters/{cid}/updates/schedule')] = (200, {'enabled': False})
            extra[('POST', f'/api/clusters/{cid}/updates/check')] = (
                200, {'success': True, 'nodes': {'pve1': {'count': 1, 'updates': []}}, 'pbs': {},
                      'summary': {'total_updates': 1, 'nodes_with_updates': 1, 'total_nodes': 1}})
        kw.setdefault('clusters', [CLUSTER])
        app = _App(browser, _FakeServer(layout=layout, role=role, extra=extra, **kw))
        apps.append(app)
        return app

    yield _open
    for app in apps:
        app.ctx.close()


def _cluster(app, layout, name='Testi'):
    if layout == 'corporate':
        app.page.locator('.corp-tree-item', has_text=name).first.click()
    else:
        app.page.get_by_text(name, exact=True).first.click()
    app.page.get_by_role('button', name='Resources', exact=True).first.wait_for(timeout=5000)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('role', ['standalone', 'standby'])
def test_updates_open_directly_and_settings_no_longer_mounts_them(ui, layout, role):
    app = ui(layout, role)
    page = app.page
    _cluster(app, layout)
    nav = page.get_by_role('button', name='Update Manager', exact=True)
    assert nav.count() == 1
    nav.click()
    manager = page.locator('[data-update-manager]')
    manager.wait_for(timeout=5000)
    assert manager.is_visible()
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/updates/status'))
    check = ('POST', '/api/clusters/c1/updates/check')
    assert _wait_for_call(app, check, seconds=2) == (role != 'standby')
    manager.get_by_text('Update Manager', exact=True).click()
    assert manager.get_by_role('button', name='Check for Updates', exact=True).count() == (role != 'standby')
    page.get_by_role('button', name='Settings', exact=True).last.click()
    assert page.locator('[data-update-manager]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('can_update', [False, True])
def test_update_actions_require_node_update_permission(ui, layout, can_update):
    permissions = ['cluster.view'] + (['node.update'] if can_update else [])
    app = ui(layout, admin=False, permissions=permissions)
    _cluster(app, layout)
    app.page.get_by_role('button', name='Update Manager', exact=True).click()
    manager = app.page.locator('[data-update-manager]')
    manager.wait_for(timeout=5000)
    manager.get_by_text('1 Updates available', exact=True).wait_for(timeout=5000)
    manager.get_by_text('Update Manager', exact=True).click()
    rolling = manager.get_by_role('button', name='Start Rolling Update', exact=True)
    if can_update:
        rolling.wait_for(timeout=5000)
    assert rolling.count() == int(can_update)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_cve_report_opens_the_selected_clusters_update_manager(ui, layout):
    app = ui(layout)
    app.server.extra[('POST', '/api/clusters/c1/reports/cve-scan')] = (
        200, {'summary': {'nodes_scanned': 1, 'total_updates': 1, 'total_cves': 0},
              'nodes': [{'node': 'pve-cve', 'total_count': 1, 'cve_count': 0, 'packages': []}]})
    page = app.page
    _cluster(app, layout)
    page.get_by_role('button', name='Reports', exact=True).first.click()
    page.get_by_role('button', name='CVE Scanner', exact=True).click()
    page.get_by_role('button', name='Scan All Nodes', exact=True).click()
    page.get_by_role('button', name='pve-cve').click()
    page.get_by_role('button', name='Open Update Manager', exact=True).click()
    manager = page.locator('[data-update-manager]')
    manager.wait_for(timeout=5000)
    manager.get_by_text('1 Updates available', exact=True).wait_for(timeout=5000)
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/updates/status'))
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_switching_clusters_reads_the_selected_clusters_update_status(ui, layout):
    branch = dict(CLUSTER, id='c2', name='Branch', display_name='Branch')
    app = ui(layout, clusters=[CLUSTER, branch])
    _cluster(app, layout)
    app.page.get_by_role('button', name='Update Manager', exact=True).click()
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/updates/status'))
    _cluster(app, layout, 'Branch')
    app.page.get_by_role('button', name='Update Manager', exact=True).click()
    assert _wait_for_call(app, ('GET', '/api/clusters/c2/updates/status'))
    assert app.page.locator('[data-update-manager]').count() == 1
    assert not app.errors, app.errors
