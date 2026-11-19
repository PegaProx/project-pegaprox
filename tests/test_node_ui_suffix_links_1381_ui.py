"""#1381 - "Open in Proxmox" in the node detail and the VM detail panel ignored the node suffix.

A cluster with a node URL suffix (#689) links its nodes as https://<node>.<suffix>:8006, so the
certificate made for the FQDN fits. The node cards, compact rows and guest tables did that, but the
header of the Corporate node detail and the VM detail panel of the compact view built the link from
the node address alone and opened https://<ip>:8006. Both now take the cluster's suffix; a cluster
without one keeps the address.

The pages are the built bundle (web/index.html) in headless Chromium against the fakes of
test_corp_redesigned_node_ui.py and test_ha_ui.py. window.open is replaced to catch the URL. Skips
without Playwright.
"""
import pytest

from test_corp_redesigned_guard_ui import _GuardApp
from test_corp_redesigned_node_ui import _NodeServer, _no_errors, _open_summary, browser, playwright  # noqa: F401 (fixtures)
from test_corp_redesigned_dashboard_ui import CLUSTERS
from test_ha_ui import CLUSTER, VM, _App, _FakeServer, _open_resources

SUFFIX = 'lab.example'
NODE_IP = '10.0.0.11'   # what the node fake answers on /nodes/pve1/ip

CATCH_OPEN = '() => { window.__opened = []; window.open = (u) => { window.__opened.push(String(u)); return null; }; }'


def _with_suffix(clusters, suffix):
    return [dict(c, node_ui_suffix=suffix) if c['id'] == 'c1' else c for c in clusters]


@pytest.fixture
def opener(browser):
    apps = []

    def _open(kind, clusters=None, **kw):
        if kind == 'node':
            server = _NodeServer(**kw)
            server.clusters = list(clusters)
            app = _GuardApp(browser, server)
        else:
            app = _App(browser, _FakeServer(clusters=clusters, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _opened(page, click):
    page.evaluate(CATCH_OPEN)
    click()
    page.wait_for_function('() => window.__opened.length > 0', timeout=3000)
    return page.evaluate('() => window.__opened')


def _node_header_link(app, layout):
    page = app.page
    _open_summary(page) if layout == 'corporate-redesigned' else _open_classic_node(page)
    if layout == 'corporate-redesigned':
        button = page.locator('[data-cr-objhead="node"] button', has_text='Open in Proxmox')
    else:
        button = page.locator('button[title="Open in Proxmox"]').first
    button.wait_for(timeout=8000)
    return _opened(page, button.click)


def _open_classic_node(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='pve1').first.click()


@pytest.mark.parametrize('layout', ['corporate-redesigned', 'corporate'])
def test_runtime_the_node_header_links_the_node_by_its_suffix(opener, layout):
    app = opener('node', layout=layout, clusters=_with_suffix(CLUSTERS, SUFFIX))
    opened = _node_header_link(app, layout)
    assert opened == [f'https://pve1.{SUFFIX}:8006/#v1:0:=node%2Fpve1:4:=aptrepositories:=contentIso:::9::'], opened
    _no_errors(app)


@pytest.mark.parametrize('layout', ['corporate-redesigned', 'corporate'])
def test_runtime_without_a_suffix_the_node_header_keeps_the_address(opener, layout):
    app = opener('node', layout=layout, clusters=CLUSTERS)
    opened = _node_header_link(app, layout)
    assert opened == [f'https://{NODE_IP}:8006/#v1:0:=node%2Fpve1:4:=aptrepositories:=contentIso:::9::'], opened
    _no_errors(app)


def _detail_panel_link(app):
    page = app.page
    _open_resources(app)
    page.locator('button[title="Compact View"]').first.click()
    page.get_by_text('Select a VM from the list').wait_for(timeout=3000)
    page.locator('div.cursor-pointer', has_text='web01').first.click()
    page.get_by_text('Quick Actions').wait_for(timeout=3000)
    # the rows of the list have their own link, which already took the suffix: only the panel's
    panel = page.locator('div.lg\\:col-span-2').filter(has_text='Quick Actions')
    button = panel.locator('button[title="Open in Proxmox"]')
    button.wait_for(timeout=3000)
    assert button.count() == 1
    return _opened(page, button.click)


def test_runtime_the_vm_detail_panel_links_the_node_by_its_suffix(opener):
    app = opener('vm', role='active', layout='modern', clusters=[dict(CLUSTER, node_ui_suffix=SUFFIX)],
                 resources=[dict(VM, node_ip='10.0.0.11')])
    assert _detail_panel_link(app) == [f'https://pve1.{SUFFIX}:8006/#v1:0:=qemu%2F100:4:::::::']
    assert not app.errors, app.errors


def test_runtime_without_a_suffix_the_vm_detail_panel_keeps_the_address(opener):
    app = opener('vm', role='active', layout='modern', clusters=[CLUSTER], resources=[dict(VM, node_ip='10.0.0.11')])
    assert _detail_panel_link(app) == ['https://10.0.0.11:8006/#v1:0:=qemu%2F100:4:::::::']
    assert not app.errors, app.errors
