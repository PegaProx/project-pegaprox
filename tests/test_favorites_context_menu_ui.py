"""A favorite in the corporate sidebar opens the right-click menu its row in the tree has:
cluster, node and guest. A guest whose cluster is not loaded yet keeps the browser's menu
instead of an empty one.

LW Oct 2026
"""
import pytest

from test_ha_ui import CLUSTER, VM, _App, _FakeServer, browser  # noqa: F401

FAVS = {'vms': [{'cluster_id': 'c1', 'vmid': 100, 'vm_type': 'qemu', 'node': 'pve1', 'name': 'web01'}],
        'nodes': [{'cluster_id': 'c1', 'node': 'pve1'}], 'clusters': ['c1']}


@pytest.fixture
def app(browser):  # noqa: F811
    srv = _FakeServer(role='standalone', layout='corporate', clusters=[CLUSTER], resources=[VM],
                      extra={('GET', '/api/user/favorites'): (200, FAVS)})
    a = _App(browser, srv)
    yield a
    a.ctx.close()


def _menu_after_right_click(page, key):
    page.keyboard.press('Escape')
    page.locator(f'[data-fav-row="{key}"]').first.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    return menu.inner_text()


def test_runtime_a_favorite_has_the_menu_of_its_tree_row(app):
    page = app.page
    page.locator('[data-testid="sidebar-favorites"]').first.wait_for(timeout=5000)
    # the guest's live data comes with its cluster
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(800)
    assert 'Refresh' in _menu_after_right_click(page, 'c:c1')
    node_menu = _menu_after_right_click(page, 'n:c1:pve1')
    assert node_menu.strip(), node_menu
    vm_menu = _menu_after_right_click(page, 'v:c1:100')
    assert {'Migrate', 'Shutdown'} & set(vm_menu.split('\n')), vm_menu
    assert not app.errors, app.errors
