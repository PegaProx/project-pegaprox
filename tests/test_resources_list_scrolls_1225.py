"""The list view of a cluster's resources scrolls sideways instead of cutting columns off (#1225).

The table sat in a box with overflow hidden. With the sidebar beside it, the Modern table
was wider than that box below a window width of about 1900 pixels (1456 pixels of table
in a 1188 pixel box at 1600), so the columns on the right, the guest actions among them,
were cut off with no scroll bar to reach them. Corporate had the same box.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py;
skips where Playwright is not installed.
"""
import pytest

from test_ha_ui import CLUSTER, VM, browser, open_app  # noqa: F401

GUESTS = [dict(VM, vmid=100 + i, name=f'web-server-with-a-longer-name-{i:02d}', id=f'qemu/{100 + i}')
          for i in range(4)]

REACH = r'''() => {
  const table = document.querySelector('th[data-col="vmid"]').closest('table');
  const box = table.parentElement;
  const ths = table.querySelectorAll('thead th');
  const last = ths[ths.length - 1].getBoundingClientRect(), pane = box.getBoundingClientRect();
  return {wider: table.getBoundingClientRect().width > box.clientWidth,
          lastRight: Math.round(last.right), paneRight: Math.round(pane.right)};
}'''


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_last_column_can_be_scrolled_into_view(open_app, layout):
    app = open_app(role='active', layout=layout, clusters=[CLUSTER], resources=GUESTS)
    page = app.page
    page.set_viewport_size({'width': 1280, 'height': 700})
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text(GUESTS[0]['name']).first.wait_for(timeout=5000)
    if layout == 'modern':
        page.locator('button[title="List View"]').first.click()
    page.locator('table th[data-col="vmid"]').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)

    # the way a user reaches the right edge: a sideways wheel over the table
    page.locator('table th[data-col="vmid"]').first.hover()
    page.mouse.wheel(3000, 0)
    page.wait_for_timeout(300)
    got = page.evaluate(REACH)
    if layout == 'modern':
        assert got['wider'], f'the table fits at 1280 pixels, the test no longer shows the case: {got}'
    assert got['lastRight'] <= got['paneRight'] + 1, f'the last column stays out of reach: {got}'
    assert not app.errors, app.errors
