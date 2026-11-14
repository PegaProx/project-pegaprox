"""The guest menu's Assign to Pool asked for admin.users (#1238).

Its entries sent PUT /api/clusters/<id>/pools/<pool> with add_members / remove_members.
That route edits the pool itself and is gated on admin.users, so a user holding only
pool.assign got 403 MISSING_PERMISSION from the menu, although the members routes that
#766 moved to pool.assign (with the per-guest check of _authorize_pool_assignment) exist
for exactly this. The menu now adds with POST .../members and removes with
DELETE .../members/<vmid>.

Runtime tests drive the built bundle in headless Chromium with the fake server of
test_ha_ui.py and skip where Playwright is not installed.
"""
import pytest

from test_ha_ui import CLUSTER, VM, _App, _FakeServer, browser  # noqa: F401

FAVS = {'vms': [{'cluster_id': 'c1', 'vmid': 100, 'vm_type': 'qemu', 'node': 'pve1', 'name': 'web01'}],
        'nodes': [], 'clusters': []}
POOLS = [{'poolid': 'team-a', 'comment': '', 'members': []},
         {'poolid': 'team-b', 'comment': '', 'members': [{'vmid': 100, 'type': 'qemu', 'node': 'pve1'}]}]
OK = (200, {'success': True})


@pytest.fixture
def app(browser):  # noqa: F811
    srv = _FakeServer(role='standalone', layout='corporate', clusters=[CLUSTER], resources=[VM], extra={
        ('GET', '/api/user/favorites'): (200, FAVS),
        ('GET', '/api/clusters/c1/pools'): (200, POOLS),
        ('POST', '/api/clusters/c1/pools/team-a/members'): OK,
        ('DELETE', '/api/clusters/c1/pools/team-b/members/100'): OK,
    })
    a = _App(browser, srv)
    page = a.page
    page.locator('[data-testid="sidebar-favorites"]').first.wait_for(timeout=5000)
    # the pools come with the cluster's sidebar data
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(800)
    yield a
    a.ctx.close()


def _pool_menu(page):
    page.keyboard.press('Escape')
    page.locator('[data-fav-row="v:c1:100"]').first.click(button='right')
    page.locator('.corp-context-menu button', has_text='Assign to Pool').first.hover()
    sub = page.locator('.corp-context-menu').nth(1)
    sub.wait_for(timeout=3000)
    return sub


def _pool_writes(app):
    return [c for c in app.server.calls if c[0] != 'GET' and '/pools/' in c[1]]


def test_runtime_assigning_uses_the_members_route(app):
    page = app.page
    _pool_menu(page).locator('button', has_text='team-a').first.click()
    page.wait_for_timeout(500)

    assert _pool_writes(app) == [('POST', '/api/clusters/c1/pools/team-a/members')], (
        f'the menu did not add through the pool.assign route: {_pool_writes(app)}')
    assert app.server.bodies['/api/clusters/c1/pools/team-a/members'][-1] == {'vmid': 100, 'type': 'qemu'}
    assert not app.errors, app.errors


def test_runtime_removing_uses_the_members_route(app):
    page = app.page
    _pool_menu(page).locator('button', has_text='Remove from Pool').first.click()
    page.wait_for_timeout(500)

    assert _pool_writes(app) == [('DELETE', '/api/clusters/c1/pools/team-b/members/100')], (
        f'the menu did not remove through the pool.assign route: {_pool_writes(app)}')
    assert not app.errors, app.errors
