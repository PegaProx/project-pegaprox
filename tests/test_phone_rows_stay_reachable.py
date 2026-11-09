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
        [('modern', v) for v in ('drift', 'rep_costs', 'rep_power', 'topology')] + \
        [('corporate-redesigned', v) for v in ('compliance', 'perf')] + [('cloud', 'updates'), ('corporate', 'vm'), ('corporate', 'harden')]

# a control is lost when its middle is out of the window and no box around it, itself inside the window, scrolls sideways
LOST = '''() => {
  const out = [];
  for (const n of document.querySelectorAll('.pp-main-row button, .pp-main-row a[href], .pp-main-row input, .pp-main-row select, .cloud-content button, .cloud-content input')) {
    if (n.closest('.pp-sidebar, .cloud-topbar')) continue;
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

# what a rule on the shape of rows can do wrong: reach into the Cloud topbar, whose nine flags then wrapped it to
# the height of a phone, and squeeze a column until its text lies over the next one (the Summary of a guest in
# Corporate). The topbar is asked by the rules themselves, not by its height: the topbar has a phone rule of its own
# (test_header_controls_stay_on_screen) that wraps it so its controls stay in the window.
ROWS_IN_TOPBAR = '''() => {
  const rules = [];
  const walk = (list, on) => { for (const r of list) {
    if (r.media) walk(r.cssRules, on && matchMedia(r.media.mediaText).matches);
    else if (on && r.selectorText && r.selectorText.includes('.pp-main-row') && (r.style.flexWrap || r.style.minWidth)) rules.push(r.selectorText);
  } };
  for (const s of document.styleSheets) { try { walk(s.cssRules, true); } catch (e) {} }
  const bar = document.querySelector('.cloud-topbar');
  return bar ? [...bar.querySelectorAll('*')].filter(e => rules.some(s => e.matches(s)))
    .map(e => ['topbar', String(e.className).slice(0, 40)]).slice(0, 5) : [];
}'''
TEXT_ON_TEXT = '''() => {
  const boxes = [...document.querySelectorAll('.pp-main-row *')].filter(e => !e.children.length && e.textContent.trim().length > 1)
    .map(e => [e, e.getBoundingClientRect()]).filter(([e, q]) => q.width > 2 && q.height > 2 && getComputedStyle(e).visibility !== 'hidden');
  const out = [];
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i][1], b = boxes[j][1];
    const w = Math.min(a.right, b.right) - Math.max(a.left, b.left), h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
    if (w > 3 && h > 5) out.push([boxes[i][0].textContent.trim().slice(0, 16), boxes[j][0].textContent.trim().slice(0, 16)]);
  }
  return out.slice(0, 5);
}'''
NO_TEXT_ON_TEXT = [('corporate', 'vm')]
# a button squeezed below its label: the label then runs out of it and over its neighbour
CLIPPED_LABELS = '''() => [...document.querySelectorAll('.pp-main-row button')].filter(b => b.getBoundingClientRect().width > 4 && b.scrollWidth > b.clientWidth + 1)
  .map(b => [b.textContent.trim().slice(0, 24), b.clientWidth, b.scrollWidth]).slice(0, 5)'''
NO_CLIPPED_LABELS = [('corporate', 'harden')]


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
            found += page.evaluate(ROWS_IN_TOPBAR)
            if (layout, view) in NO_TEXT_ON_TEXT:
                found += page.evaluate(TEXT_ON_TEXT)
            if (layout, view) in NO_CLIPPED_LABELS:
                found += page.evaluate(CLIPPED_LABELS)
            if found:
                lost[width] = found
        assert not lost, lost
    finally:
        app.close()
