"""The cluster tabs of Corporate Redesigned wrap to a second line, as classic Corporate's do.

The strip scrolled sideways behind a thin scrollbar: at 1280 px Plugins, Updates and Settings
sat out of sight, in German and Russian four tabs, and the last one was hidden still at
1600 px. Now every tab is in the window and takes a click where it is drawn. The other strips
of the preview (node, guest, modules) still scroll, and so does the cluster strip of a phone.

Drives the built bundle in headless Chromium with the fake server of the object views; skips
where Playwright or the browser is not installed.
"""
import json
import os

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, browser  # noqa: F401
from test_corp_redesigned_objects_ui import LAYOUT, _cluster, _ObjServer, _open_node

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _settings_label(language):
    if language == 'en':
        return 'Settings'
    with open(os.path.join(ROOT, 'web', 'i18n', f'{language}.json'), encoding='utf-8') as fh:
        return json.load(fh)['settings']


@pytest.fixture
def open_cr(browser):  # noqa: F811
    apps = []

    def _open(width, language='en'):
        app = _GuardApp(browser, _ObjServer(layout=LAYOUT, language=language),
                        storage={'pegaprox-language': language}, viewport=(width, 900))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# each tab of the strip: inside the strip and the window, and the topmost element at its middle
TABS = '''() => {
  const strip = document.querySelector('[data-cr-tabs="cluster"]');
  const s = strip.getBoundingClientRect();
  return {scroll: strip.scrollWidth - strip.clientWidth, page: document.documentElement.scrollWidth - innerWidth,
          tabs: [...strip.querySelectorAll('[role="tab"]')].map(b => {
            const r = b.getBoundingClientRect();
            const x = r.left + r.width / 2, y = r.top + r.height / 2;
            const top = document.elementFromPoint(x, y);
            return {id: b.dataset.crTab, label: b.innerText.trim(), x, y,
                    inside: r.left >= s.left - 1 && r.right <= s.right + 1 && r.right <= innerWidth && r.width > 0,
                    hit: !!top && (top === b || b.contains(top))};
          })};
}'''


@pytest.mark.parametrize('language', ['en', 'de', 'ru'])
@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_every_cluster_tab_is_in_sight_and_takes_a_click(open_cr, width, language):
    app = open_cr(width, language)
    page = app.page
    _cluster(page)
    label = _settings_label(language)
    page.locator('[data-cr-tabs="cluster"] [data-cr-tab="settings"]', has_text=label).wait_for(timeout=10000)
    seen = page.evaluate(TABS)
    ids = [x['id'] for x in seen['tabs']]
    assert ids[0] == 'overview' and ids[-1] == 'settings' and len(ids) >= 12, ids
    assert seen['scroll'] <= 1 and seen['page'] <= 0, seen
    lost = [x['label'] for x in seen['tabs'] if not (x['inside'] and x['hit'])]
    assert not lost, (lost, seen)
    # a click where the tab is drawn, without scrolling anything into view first
    for tab in reversed(seen['tabs']):
        now = next(x for x in page.evaluate(TABS)['tabs'] if x['id'] == tab['id'])
        assert now['inside'] and now['hit'], now
        page.mouse.click(now['x'], now['y'])
        page.locator(f'[data-cr-tabs="cluster"] [data-cr-tab="{tab["id"]}"][aria-selected="true"]').wait_for(timeout=5000)


def test_runtime_the_strip_takes_a_second_line_only_when_it_needs_one(open_cr):
    app = open_cr(1920)
    page = app.page
    _cluster(page)
    page.locator('[data-cr-tabs="cluster"] [data-cr-tab="settings"]').wait_for(timeout=10000)
    tops = page.evaluate('''() => [...new Set([...document.querySelectorAll('[data-cr-tabs="cluster"] [role="tab"]')]
        .map(b => Math.round(b.getBoundingClientRect().top)))]''')
    assert len(tops) == 1, tops
    page.set_viewport_size({'width': 1280, 'height': 900})
    page.wait_for_timeout(300)
    tops = page.evaluate('''() => [...new Set([...document.querySelectorAll('[data-cr-tabs="cluster"] [role="tab"]')]
        .map(b => Math.round(b.getBoundingClientRect().top)))]''')
    assert len(tops) == 2, tops


STYLE = '''(w) => { const s = getComputedStyle(document.querySelector(`[data-cr-tabs="${w}"]`));
                    return [s.flexWrap, s.overflowX]; }'''


def test_runtime_the_other_strips_and_the_phone_keep_scrolling(open_cr):
    app = open_cr(1280)
    page = app.page
    _open_node(page)
    page.locator('[data-cr-tabs="node"]').wait_for(timeout=8000)
    assert page.evaluate(STYLE, 'node') == ['nowrap', 'auto']
    # the phone hides the tree, so the cluster is picked first and the window narrowed after
    app = open_cr(1280)
    page = app.page
    _cluster(page)
    assert page.evaluate(STYLE, 'cluster') == ['wrap', 'visible']
    page.set_viewport_size({'width': 820, 'height': 900})
    page.wait_for_timeout(300)
    assert page.evaluate(STYLE, 'cluster') == ['nowrap', 'auto']
