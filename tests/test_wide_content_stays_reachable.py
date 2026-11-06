"""Tabs, card actions and tables that do not fit stay reachable at laptop widths.

The shell clips sideways (#727), so whatever runs past the edge of the window has no scrollbar to
reach it by. Corporate lost its Settings tab at 1366, Modern the hardening tab, and at 1024 several
tabs, the actions of a resource card and the last column of the node tables went with them.

Drives the built bundle in headless Chromium with the fake server of the pixel guard; skips where
Playwright is not installed.
"""
import pathlib

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, VIEW_READS, VIEW_RESOURCES, VIEW_STORAGE, go
from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401

BUNDLE = pathlib.Path(__file__).resolve().parent.parent / 'web' / 'index.html'
WIDTHS = [1366, 1280, 1024]
CASES = [('corporate', 'alerts'), ('corporate', 'insights'), ('corporate', 'perf'), ('corporate', 'node_certs'),
         ('corporate', 'node_repos'), ('corporate', 'node_network'), ('modern', 'harden'), ('modern', 'insights')]

# a control is lost when its middle is out of the window and no box around it, itself inside the window, scrolls sideways
LOST = '''() => {
  const out = [];
  for (const n of document.querySelectorAll('.pp-main-row button, .pp-main-row a[href], .pp-main-row input, .pp-main-row select')) {
    if (n.closest('.pp-sidebar')) continue;
    const r = n.getBoundingClientRect();
    if (r.width < 4 || r.height < 4 || getComputedStyle(n).visibility === 'hidden') continue;
    const x = (r.left + r.right) / 2;
    if (x >= 0 && x <= innerWidth) continue;
    let scroller = false;
    for (let p = n.parentElement; p; p = p.parentElement) {
      const o = getComputedStyle(p).overflowX, q = p.getBoundingClientRect();
      if ((o === 'auto' || o === 'scroll') && p.scrollWidth > p.clientWidth + 1 && q.left >= -1 && q.right <= innerWidth + 1) { scroller = true; break; }
    }
    if (!scroller) out.push([(n.getAttribute('title') || n.textContent || n.tagName).trim().slice(0, 24), Math.round(r.left), Math.round(r.right)]);
  }
  return out;
}'''


@pytest.mark.parametrize('layout,view', CASES)
def test_runtime_nothing_in_the_page_runs_out_of_the_window(browser, layout, view):  # noqa: F811
    server = _GuardServer(bundle=BUNDLE.read_bytes(), layout=layout, extra=VIEW_READS.get(view), resources=VIEW_RESOURCES.get(view))
    app = _GuardApp(browser, server, storage=VIEW_STORAGE.get(view))
    try:
        go(app, layout, view)
        page = app.page
        lost = {}
        for width in WIDTHS:
            page.set_viewport_size({'width': width, 'height': 700})
            page.wait_for_timeout(200)
            found = page.evaluate(LOST)
            if found:
                lost[width] = found
        assert not lost, lost
    finally:
        app.close()


@pytest.mark.parametrize('width', [1366, 1280, 1024])
def test_runtime_more_actions_of_a_resource_card_opens_with_the_mouse(browser, width):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra=dict(SSE_TOKEN)))
    try:
        page = app.page
        page.set_viewport_size({'width': width, 'height': 800})
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Resources').first.click()
        more = page.locator('button[title="More Actions"]').first
        more.wait_for(timeout=6000)
        page.wait_for_timeout(300)
        # the page scrolls, not the card: Playwright's own scrolling would slide a cut off button into the card
        page.evaluate('''() => {
          const r = document.querySelector('button[title="More Actions"]').getBoundingClientRect();
          window.scrollBy(0, r.top - innerHeight / 2);
        }''')
        page.wait_for_timeout(200)
        box = more.bounding_box()
        at = page.evaluate('''([x, y]) => {
          const top = document.elementFromPoint(x, y);
          return !!top && !!top.closest('button[title="More Actions"]');
        }''', [box['x'] + box['width'] / 2, box['y'] + box['height'] / 2])
        assert at, ('the card cuts the button off', box)
        page.mouse.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
        page.get_by_text('Force Stop').first.wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
