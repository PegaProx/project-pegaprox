"""The buttons at the end of a row of a page stay on the screen of a phone.

The shell clips sideways (#727), so what runs past the edge has no scrollbar to reach it by. On a
phone that took Configure and Actions of a guest, Scan now and Refresh, the export buttons and the
longer time ranges.

Drives the built bundle in headless Chromium with the fake server of the pixel guard; skips where
Playwright is not installed.
"""
import pathlib

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, VIEW_READS, VIEW_RESOURCES, VIEW_STORAGE, go
from test_ha_ui import browser  # noqa: F401

BUNDLE = pathlib.Path(__file__).resolve().parent.parent / 'web' / 'index.html'
WIDTHS = [600, 412]
CASES = [('corporate', v) for v in ('config', 'drift', 'perf', 'node_network', 'rep_costs', 'rep_power', 'topology', 'tasks', 'alerts')] + \
        [('modern', v) for v in ('drift', 'rep_costs', 'rep_power', 'topology')]

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
def test_runtime_nothing_in_the_page_runs_off_a_phone(browser, layout, view):  # noqa: F811
    server = _GuardServer(bundle=BUNDLE.read_bytes(), layout=layout, extra=VIEW_READS.get(view), resources=VIEW_RESOURCES.get(view))
    app = _GuardApp(browser, server, storage=VIEW_STORAGE.get(view))
    try:
        go(app, layout, view)
        page = app.page
        lost = {}
        for width in WIDTHS:
            page.set_viewport_size({'width': width, 'height': 800})
            page.wait_for_timeout(200)
            found = page.evaluate(LOST)
            if found:
                lost[width] = found
        assert not lost, lost
    finally:
        app.close()
