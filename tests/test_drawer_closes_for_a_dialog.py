"""A dialog opened from the phone drawer can be used.

The drawer has z-index 1200 and its backdrop 1100, a dialog 50. A dialog opened from a button in the
drawer opened under both: to the user nothing happened, and a tap on a field reached the drawer.
The drawer now closes when a dialog appears.

Drives the built bundle with a real mouse at phone width in headless Chromium and Firefox with the
fake server of tests/test_ha_ui.py; skips where Playwright or the browser is not installed.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer

ENGINES = ['chromium', 'firefox']
OPENS_A_DIALOG = [('modern', 'Manage Groups'), ('modern', 'Add Backup Server'), ('modern', 'Add ESXi Server'),
                  ('modern', 'Rename Cluster'), ('corporate', 'Manage Groups'), ('corporate', 'Add Cluster')]

COVERED = '''() => {
  const all = [...document.querySelectorAll('.fixed.inset-0, .modal-backdrop, .corp-vm-modal-overlay')]
    .filter(n => !/pointer-events-none|z-40/.test(n.className));
  const d = all[all.length - 1];
  if (!d) return ['no dialog'];
  const out = [];
  for (const n of d.querySelectorAll('input, select, button')) {
    const r = n.getBoundingClientRect();
    if (!r.width || r.y + r.height / 2 > innerHeight) continue;
    const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
    if (!d.contains(top)) out.push([(n.placeholder || n.textContent || n.tagName).trim().slice(0, 20), top && String(top.className).slice(0, 30)]);
  }
  return out;
}'''


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
def drawer(browsers):
    apps = []

    def _open(engine, layout):
        app = _App(browsers(engine), _FakeServer(role='standalone', layout=layout, clusters=[CLUSTER], resources=[VM],
                                                 metrics=NODE_METRICS, extra=dict(SSE_TOKEN)))
        apps.append(app)
        page = app.page
        page.set_viewport_size({'width': 412, 'height': 800})
        # a selection set while the app loads closes the drawer again
        page.wait_for_timeout(1500)
        _tap(page, page.locator('.pp-drawer-toggle').first)
        page.locator('.pp-sidebar.pp-sidebar-open').wait_for(timeout=5000)
        page.wait_for_timeout(300)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _tap(page, loc):
    box = loc.bounding_box()
    page.mouse.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)


def _in_drawer(page, name):
    at = page.evaluate('''(name) => [...document.querySelectorAll('.pp-sidebar button')].findIndex(
        b => ((b.title || '') + (b.getAttribute('aria-label') || '') + b.textContent).includes(name))''', name)
    assert at >= 0, name
    return page.locator('.pp-sidebar button').nth(at)


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout,name', OPENS_A_DIALOG)
def test_runtime_a_dialog_from_the_drawer_is_on_top_and_can_be_used(drawer, engine, layout, name):
    app = drawer(engine, layout)
    page = app.page
    _tap(page, _in_drawer(page, name))
    page.locator('.pp-sidebar-open').wait_for(state='detached', timeout=5000)
    page.wait_for_timeout(300)
    assert page.evaluate(COVERED) == []
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_a_field_of_that_dialog_takes_what_is_typed(drawer, engine):
    app = drawer(engine, 'modern')
    page = app.page
    _tap(page, _in_drawer(page, 'Manage Groups'))
    field = page.locator('input[placeholder^="Group Name"]').first
    field.wait_for(timeout=5000)
    page.locator('.pp-sidebar-open').wait_for(state='detached', timeout=5000)
    page.wait_for_timeout(300)
    _tap(page, field)
    page.keyboard.type('lab')
    assert field.input_value() == 'lab'
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_drawer_stays_open_without_a_dialog(drawer, engine, layout):
    """Whatever the app adds to the page while it sits there, the live data of the rows for one."""
    app = drawer(engine, layout)
    page = app.page
    page.wait_for_timeout(1500)
    assert page.locator('.pp-sidebar.pp-sidebar-open').count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_the_tools_dropdown_in_the_drawer_leaves_it_open(drawer, engine):
    """Its click catcher is a fixed inset-0 as well, and it is not a dialog."""
    app = drawer(engine, 'corporate')
    page = app.page
    _tap(page, _in_drawer(page, 'Tools'))
    page.wait_for_timeout(500)
    assert page.locator('.pp-sidebar.pp-sidebar-open').count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ENGINES)
def test_runtime_the_drawer_opens_again_after_the_dialog_was_closed(drawer, engine):
    app = drawer(engine, 'modern')
    page = app.page
    _tap(page, _in_drawer(page, 'Manage Groups'))
    page.locator('.pp-sidebar-open').wait_for(state='detached', timeout=5000)
    page.wait_for_timeout(300)
    _tap(page, page.locator('.fixed.inset-0.flex button').first)
    page.locator('.fixed.inset-0.flex').first.wait_for(state='detached', timeout=5000)
    _tap(page, page.locator('.pp-drawer-toggle').first)
    page.locator('.pp-sidebar.pp-sidebar-open').wait_for(timeout=5000)
    assert not app.errors, app.errors
