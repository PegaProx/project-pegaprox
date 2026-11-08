"""A click anywhere outside a dropdown of the header closes it, also below the header.

The dropdowns put a fixed inset-0 catcher behind themselves. A backdrop-filter on the header of
the Modern layout made the header, not the window, what fixed measures from, so the catcher
ended at the lower edge of the header: a click on the page reached the page and left the menu open.
A second catcher on the body now takes the page, and the header keeps its blur.

Drives the built bundle with a real mouse in headless Chromium and Firefox with the fake server
of tests/test_ha_ui.py; skips where Playwright or the browser is not installed.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer

ENGINES = ['chromium', 'firefox']
LAYOUTS = ['modern', 'corporate']
PLACEHOLDER = {'modern': 'Search all clusters...', 'corporate': 'Search in all inventories...'}
SEARCH = {('GET', '/api/global/search'): (200, {'query': 'web', 'count': 1, 'tag_suggestions': [], 'results': [
    {'type': 'vm', 'name': 'web01', 'vmid': 100, 'node': 'pve1', 'status': 'running', 'cluster_id': 'c1',
     'cluster_name': 'lab', 'match_field': 'name'}]})}


@pytest.fixture(scope='module')
def browsers():
    state, started = {'pw': None}, {}

    def get(name):
        if name in started:
            return started[name]
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            pytest.skip('Playwright is not installed')
        if state['pw'] is None:
            try:
                state['pw'] = sync_playwright().start()
            except Exception as e:
                pytest.skip(f'Playwright does not start here: {e}')
        try:
            started[name] = getattr(state['pw'], name).launch(headless=True)
        except Exception as e:
            pytest.skip(f'no {name} for Playwright: {e}')
        return started[name]
    yield get
    for br in started.values():
        br.close()
    if state['pw'] is not None:
        state['pw'].stop()


@pytest.fixture
def open_app(browsers):
    apps = []

    def _open(engine, layout, clusters=(CLUSTER,)):
        app = _App(browsers(engine), _FakeServer(role='standalone', layout=layout, clusters=list(clusters), resources=[VM],
                                                 metrics=NODE_METRICS, extra={**SSE_TOKEN, **SEARCH}))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _click_the_page(page):
    # low on the page, well below the header and below any dropdown
    page.mouse.click(800, 900)
    page.wait_for_timeout(200)


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_user_menu_closes_on_a_click_on_the_page(open_app, engine, layout):
    app = open_app(engine, layout)
    page = app.page
    page.locator('[data-user-menu]').first.click()
    menu = page.locator('[data-user-menu] ~ div.absolute')
    menu.wait_for(timeout=5000)
    _click_the_page(page)
    assert menu.count() == 0, 'the menu stayed open'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_search_results_close_on_a_click_on_the_page(open_app, engine, layout):
    app = open_app(engine, layout)
    page = app.page
    page.fill(f'input[placeholder="{PLACEHOLDER[layout]}"]', 'web')
    results = page.locator('.pp-search-results')
    results.wait_for(timeout=5000)
    _click_the_page(page)
    assert results.count() == 0, 'the results stayed open'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_add_cluster_closes_on_a_click_on_the_page(open_app, engine):
    app = open_app(engine, 'modern', clusters=())
    page = app.page
    page.locator('header button', has_text='Add Cluster').first.click()
    entry = page.get_by_text('Proxmox Backup Server')
    entry.first.wait_for(timeout=5000)
    _click_the_page(page)
    assert entry.count() == 0, 'the dropdown stayed open'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_the_click_that_closes_the_menu_does_not_reach_the_page(open_app, engine):
    app = open_app(engine, 'modern')
    page = app.page
    page.locator('[data-user-menu]').first.click()
    page.locator('[data-user-menu] ~ div.absolute').wait_for(timeout=5000)
    hit = page.evaluate('''() => {
      const n = document.elementFromPoint(800, 900);
      return n && n.matches('body > .fixed.inset-0');
    }''')
    assert hit, 'something on the page is what a click there reaches'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_the_notifications_close_on_a_click_on_the_page(open_app, engine):
    app = open_app(engine, 'modern')
    page = app.page
    page.locator('header button[title="Notifications"]').first.click()
    panel = page.locator('header div.absolute.w-80')
    panel.wait_for(timeout=5000)
    _click_the_page(page)
    assert panel.count() == 0, 'the dropdown stayed open'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_click_elsewhere_in_the_header_closes_it_too(open_app, engine, layout):
    app = open_app(engine, layout)
    page = app.page
    page.locator('[data-user-menu]').first.click()
    menu = page.locator('[data-user-menu] ~ div.absolute')
    menu.wait_for(timeout=5000)
    page.mouse.click(700, 8)
    page.wait_for_timeout(200)
    assert menu.count() == 0, 'the menu stayed open'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('width', [1600, 600])
def test_runtime_everything_in_the_modern_header_can_be_clicked(open_app, engine, width):
    """Not only what has a z-index of its own: the layer of the blur must stay behind all of it."""
    app = open_app(engine, 'modern')
    page = app.page
    page.set_viewport_size({'width': width, 'height': 900})
    page.wait_for_timeout(300)
    covered = page.evaluate('''() => {
      const out = [];
      for (const n of document.querySelectorAll('header button, header a, header input, header select')) {
        const r = n.getBoundingClientRect();
        if (!r.width || !r.height) continue;
        const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
        if (!top || !(n === top || n.contains(top))) out.push([n.tagName, String(n.className).slice(0, 40), top && String(top.className).slice(0, 40)]);
      }
      return out;
    }''')
    assert covered == [], covered
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_the_drawer_opens_from_the_header_on_a_narrow_window(open_app, engine):
    app = open_app(engine, 'modern')
    page = app.page
    page.set_viewport_size({'width': 600, 'height': 900})
    # a selection set while the app loads closes the drawer again
    page.wait_for_timeout(1500)
    box = page.locator('.pp-drawer-toggle').bounding_box()
    page.mouse.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
    page.locator('.pp-sidebar.pp-sidebar-open').wait_for(timeout=5000)
    assert not app.errors, app.errors
