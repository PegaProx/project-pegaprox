"""Every control of the header stays in the window, at every width a desktop browser has.

The shell clips sideways (#727), so what does not fit into the header has no scrollbar to reach it
by. At 1366 wide the Modern layout lost Add Cluster and the user menu with its logout, and at 1024
wide the Cloud layout lost its settings as well.

Drives the built bundle in headless Chromium and Firefox with the fake server of the pixel guard;
skips where Playwright or the browser is not installed.
"""
import json
import pathlib
import re

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer

ENGINES = ['chromium', 'firefox']
LAYOUTS = ['modern', 'corporate', 'corporate-redesigned', 'cloud']
# 820 and below is the phone layout of (#189), which has its own tests. 1920 is the one line header the
# others are counted against, 1600 to 1880 is where the box of the header is narrower than its row in
# one language or another
WIDTHS = [1920, 1880, 1830, 1800, 1765, 1700, 1645, 1620, 1600, 1599, 1500, 1440, 1366, 1280, 1100, 1024, 900, 821]
WIDE = 1920
ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE = ROOT / 'web' / 'index.html'
SOURCE = ROOT / 'web' / 'index.html.original'

OUT = '''() => {
  const roots = document.querySelectorAll('header, .cloud-topbar');
  const out = [];
  let count = 0;
  for (const root of roots) for (const n of root.querySelectorAll('button, a, input, select')) {
    const r = n.getBoundingClientRect();
    if (!r.width || !r.height || n.closest('.cr-skip') || n.classList.contains('cr-skip')) continue;
    count++;
    const x = r.x + r.width / 2, y = r.y + r.height / 2;
    const top = document.elementFromPoint(x, y);
    const hit = !!top && (n === top || n.contains(top) || top.contains(n));
    if (r.left < -1 || r.right > innerWidth + 1 || !hit) {
      out.push([(n.getAttribute('title') || n.getAttribute('aria-label') || n.textContent || n.tagName).trim().slice(0, 20),
                Math.round(r.left), Math.round(r.right)]);
    }
  }
  return {roots: roots.length, out, count};
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
def open_at(browsers):
    apps = []

    def _open(engine, layout, width=1600, language='en'):
        app = _GuardApp(browsers(engine), _GuardServer(bundle=BUNDLE.read_bytes(), layout=layout, language=language),
                        storage={'pegaprox-language': language}, viewport=(width, 800))
        apps.append(app)
        # the fake has no event stream, so 4 s after the load a banner (sticky, z-index 100) floats over the top of
        # the page, and a header seen after it reads as covered
        app.page.add_style_tag(content='[style*="sticky"][style*="z-index: 100"] { display: none !important; }')
        return app
    yield _open
    for app in apps:
        app.close()


def _controls_lost(page, widths=WIDTHS):
    """Per width, the header controls that are outside the window or covered, or a count that differs."""
    lost, wide = {}, None
    for width in widths:
        page.set_viewport_size({'width': width, 'height': 800})
        # on a busy machine the header is still settling right after the resize
        for _ in range(20):
            page.wait_for_timeout(150)
            seen = page.evaluate(OUT)
            if not seen['out'] and (wide is None or seen['count'] == wide):
                break
        assert seen['roots'] == 1, (width, seen)
        if width == WIDE:
            wide = seen['count']
        # a rule that hides a control instead of wrapping it leaves nothing outside the window
        if seen['out'] or seen['count'] != wide:
            lost[width] = seen['out'] or f"{seen['count']} controls, {wide} at {WIDE}"
    return lost


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_every_control_of_the_header_is_in_the_window(open_at, engine, layout):
    app = open_at(engine, layout)
    app.page.wait_for_timeout(500)
    lost = _controls_lost(app.page)
    assert not lost, lost


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('language', ['de', 'fr', 'pl', 'ru'])
def test_runtime_the_modern_header_fits_in_its_longer_languages(open_at, engine, language):
    """Their labels are longer than the English ones: the French row needs 1826 for one line."""
    app = open_at(engine, 'modern', language=language)
    # measured in English the row would fit: wait for the header to speak the language
    label = json.loads((ROOT / 'web' / 'i18n' / f'{language}.json').read_text(encoding='utf-8'))['addCluster']
    app.page.locator('header').get_by_text(label).first.wait_for(timeout=10000)
    lost = _controls_lost(app.page, WIDTHS[:7])
    assert not lost, lost


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('width', [1366, 1024, 900])
def test_runtime_the_logout_can_be_reached_with_the_mouse_in_modern(open_at, engine, width):
    app = open_at(engine, 'modern', width=width)
    page = app.page
    page.wait_for_timeout(500)
    box = page.locator('[data-user-menu]').first.bounding_box()
    assert box['x'] + box['width'] <= width, box
    page.mouse.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
    entry = page.locator('[data-user-menu] ~ div.absolute button').last
    entry.wait_for(timeout=5000)
    item = entry.bounding_box()
    assert 0 <= item['x'] and item['x'] + item['width'] <= width, item


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', ['modern', 'cloud'])
def test_runtime_the_page_starts_below_a_header_of_two_lines(open_at, engine, layout):
    app = open_at(engine, layout, width=1024)
    page = app.page
    page.wait_for_timeout(500)
    found = page.evaluate('''() => {
      const h = document.querySelector('header, .cloud-topbar').getBoundingClientRect();
      const main = document.querySelector('.pp-main-wrap, .cloud-body');
      return {header: h.bottom, main: main.getBoundingClientRect().top};
    }''')
    assert found['main'] >= found['header'] - 1, found
    # one line is 109 in Modern and 71 in Cloud, so this is the second line
    assert found['header'] > {'modern': 120, 'cloud': 100}[layout], found


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('width', [820, 600, 412])
def test_runtime_the_cloud_top_bar_stays_in_the_window_of_a_phone(open_at, engine, width):
    """Cloud has no phone layout of its own, and its side navigation stays open as the user left it."""
    app = open_at(engine, 'cloud', width=width)
    page = app.page
    page.wait_for_timeout(500)
    seen = page.evaluate(OUT)
    assert seen['roots'] == 1 and seen['out'] == [], seen


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', ['modern', 'corporate-redesigned'])
@pytest.mark.parametrize('width', [820, 412])
def test_runtime_the_phone_keeps_the_action_row_it_had(open_at, engine, layout, width):
    """Wrapping is for desktop widths: below 821 the row of (#189) stays where it began."""
    app = open_at(engine, layout, width=width)
    page = app.page
    page.wait_for_timeout(500)
    got = page.evaluate("getComputedStyle(document.querySelector('.pp-header-actions')).justifyContent")
    assert got != 'flex-end', got


def test_the_wrap_rules_are_in_the_source():
    """CI has no browser, so the browser tests above skip there: this reads the rules themselves."""
    css = SOURCE.read_text(encoding='utf-8')

    def body(selector):
        found = re.search(r'^\s*' + re.escape(selector) + r' \{([^}]*)\}', css, re.M)
        assert found, selector
        return found.group(1).replace(' ', '')
    media = re.search(r'@media \(min-width: 821px\) and \(max-width: (\d+)px\) \{\s*\.pp-header-actions \{([^}]*)\}', css)
    assert media and 'flex-wrap:wrap' in media.group(2).replace(' ', ''), 'the header actions of Modern wrap'
    # the box of the header ends at 1600 and, with ten language buttons, the row of the French labels fits on
    # one line only from 1826: wrapping has to reach that
    assert int(media.group(1)) >= 1826
    assert 'flex-wrap:wrap' in body('.cloud-topbar')
    assert 'flex-wrap:wrap' in body('.cloud-topbar-actions')
