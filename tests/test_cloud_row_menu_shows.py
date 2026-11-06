"""The action menu of a row in the Cloud lists is on the screen when it opens.

A hovered .cloud-card has a transform, and with one the card, not the window, is what
position:fixed measures from. The pointer is on the card when it opens the menu, so the
menu landed about 180 pixels lower and 240 further right, and the overflow of the table
card cut it off: three dots that showed nothing. Playwright's click() got through anyway,
because it scrolls a clipped element into view, so these tests use the mouse as a user does.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py;
skips where Playwright is not installed.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, VM, VM_CONFIG, browser, open_app  # noqa: F401

GUESTS = [dict(VM, vmid=100 + i, name=f'web{i:02d}', id=f'qemu/{100 + i}') for i in range(8)]


def _list(open_app, height=1000):
    app = open_app(role='standalone', layout='cloud', clusters=[CLUSTER], resources=GUESTS,
                   extra={('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): (200, VM_CONFIG)})
    page = app.page
    page.set_viewport_size({'width': 1600, 'height': height})
    page.locator('.cloud-nav-item', has_text='Virtual Machines').first.click()
    page.locator('.cloud-table-row', has_text='web00').first.wait_for(timeout=5000)
    return app, page


def _open_menu(page, name):
    box = page.locator('.cloud-table-row', has_text=name).first.locator('button').last.bounding_box()
    page.mouse.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
    page.locator('.cloud-menu').wait_for(timeout=5000)
    # the hover has lifted the card by now, as it has for anyone who moved there
    page.wait_for_timeout(200)
    return box


HIT = '''(name) => {
  const item = [...document.querySelectorAll('.cloud-menu-item')].find(b => b.textContent.trim() === name);
  const r = item.getBoundingClientRect();
  const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
  return {x: r.x + r.width / 2, y: r.y + r.height / 2, hit: !!top && item.contains(top)};
}'''


def test_runtime_the_menu_opens_beside_its_three_dots(open_app):
    app, page = _list(open_app)
    dots = _open_menu(page, 'web00')
    menu = page.locator('.cloud-menu').bounding_box()
    assert menu['x'] + menu['width'] <= 1600, menu
    assert menu['y'] >= dots['y'] + dots['height'] and menu['y'] <= dots['y'] + dots['height'] + 8, (menu, dots)
    assert page.evaluate(HIT, 'Edit')['hit'], 'something else is where the menu says its item is'
    assert not app.errors, app.errors


def test_runtime_the_mouse_reaches_an_item(open_app):
    app, page = _list(open_app)
    _open_menu(page, 'web00')
    at = page.evaluate(HIT, 'Edit')
    page.mouse.click(at['x'], at['y'])
    page.locator('.cloud-menu').wait_for(state='detached', timeout=5000)
    page.locator('input[value="web01"]').first.wait_for(timeout=8000)
    assert not app.errors, app.errors


def test_runtime_a_click_inside_the_menu_does_not_open_the_row(open_app):
    """On the body the menu is still a child of the row for React, whose click opens the guest."""
    app, page = _list(open_app)
    _open_menu(page, 'web00')
    box = page.locator('.cloud-menu').bounding_box()
    # the padding at the side: the very corner is outside the round border, and Firefox goes by that
    page.mouse.click(box['x'] + 3, box['y'] + box['height'] / 2)
    page.wait_for_timeout(300)
    assert page.locator('.cloud-table-row', has_text='web00').count() == 1, 'the guest opened'
    assert not app.errors, app.errors


def test_runtime_a_click_beside_the_menu_closes_it(open_app):
    app, page = _list(open_app)
    _open_menu(page, 'web00')
    page.mouse.click(700, 120)
    page.locator('.cloud-menu').wait_for(state='detached', timeout=5000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('name', ['web06', 'web07'])
def test_runtime_a_low_row_keeps_the_whole_menu_on_the_screen(open_app, name):
    app, page = _list(open_app, height=720)
    row = page.locator('.cloud-table-row', has_text=name).first
    row.scroll_into_view_if_needed()
    page.wait_for_timeout(200)
    _open_menu(page, name)
    menu = page.locator('.cloud-menu').bounding_box()
    assert menu['y'] >= 0 and menu['y'] + menu['height'] <= 720, menu
    assert not app.errors, app.errors


def test_runtime_the_menu_of_a_host_opens_beside_its_three_dots(open_app):
    """The host cards do not cut the menu off, so it only landed in the wrong place there."""
    app = open_app(role='standalone', layout='cloud', clusters=[CLUSTER], resources=GUESTS, metrics=NODE_METRICS)
    page = app.page
    page.set_viewport_size({'width': 1600, 'height': 1000})
    page.locator('.cloud-nav-item', has_text='Hosts').first.click()
    dots = page.locator('.cloud-node-card').first.locator('.cloud-icon-btn').last
    dots.wait_for(timeout=5000)
    box = dots.bounding_box()
    page.mouse.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
    page.locator('.cloud-menu').wait_for(timeout=5000)
    page.wait_for_timeout(200)
    menu = page.locator('.cloud-menu').bounding_box()
    assert box['y'] + box['height'] <= menu['y'] <= box['y'] + box['height'] + 8, (menu, box)
    assert abs(menu['x'] + menu['width'] - (box['x'] + box['width'])) <= 12, (menu, box)
    assert not app.errors, app.errors


FOCUS = '''() => {
  const a = document.activeElement, m = document.querySelector('.cloud-menu');
  return {inMenu: !!m && m.contains(a), label: a.textContent.trim(), dots: a.classList.contains('cloud-icon-btn'), open: !!m};
}'''


def _open_by_key(page, name):
    dots = page.locator('.cloud-table-row', has_text=name).first.locator('button').last
    dots.focus()
    page.keyboard.press('Enter')
    page.locator('.cloud-menu').wait_for(timeout=5000)
    return dots


def test_runtime_tab_walks_from_the_three_dots_into_the_menu_and_back(open_app):
    """The menu is the last thing on the page, not the next thing after its button."""
    app, page = _list(open_app)
    _open_by_key(page, 'web00')
    assert page.evaluate(FOCUS)['dots'], 'opening must leave the focus on the button'
    page.keyboard.press('Tab')
    first = page.evaluate(FOCUS)
    assert first['inMenu'], first
    page.keyboard.press('Shift+Tab')
    back = page.evaluate(FOCUS)
    assert back['dots'] and back['open'], back
    assert not app.errors, app.errors


def test_runtime_enter_on_an_item_reached_by_tab_runs_it(open_app):
    app, page = _list(open_app)
    _open_by_key(page, 'web00')
    while page.evaluate(FOCUS)['label'] != 'Edit':
        page.keyboard.press('Tab')
        assert page.evaluate(FOCUS)['inMenu'], page.evaluate(FOCUS)
    page.keyboard.press('Enter')
    page.locator('.cloud-menu').wait_for(state='detached', timeout=5000)
    page.locator('input[value="web01"]').first.wait_for(timeout=8000)
    assert not app.errors, app.errors


def test_runtime_tab_past_the_last_item_closes_the_menu_on_the_three_dots(open_app):
    app, page = _list(open_app)
    _open_by_key(page, 'web00')
    count = page.locator('.cloud-menu button:not(:disabled)').count()
    for _ in range(count):
        page.keyboard.press('Tab')
        assert page.evaluate(FOCUS)['inMenu'], page.evaluate(FOCUS)
    page.keyboard.press('Tab')
    page.locator('.cloud-menu').wait_for(state='detached', timeout=5000)
    assert page.evaluate(FOCUS)['dots'], page.evaluate(FOCUS)
    assert not app.errors, app.errors


def test_runtime_a_short_window_scrolls_the_menu_to_its_last_item(open_app):
    app, page = _list(open_app, height=400)
    _open_menu(page, 'web00')
    menu = page.locator('.cloud-menu').bounding_box()
    assert menu['y'] >= 0 and menu['y'] + menu['height'] <= 400, menu
    page.mouse.move(menu['x'] + menu['width'] / 2, menu['y'] + menu['height'] / 2)
    page.mouse.wheel(0, 2000)
    page.wait_for_timeout(300)
    assert page.locator('.cloud-menu').count() == 1, 'scrolling the menu closed it'
    last = page.evaluate('''() => {
      const items = document.querySelectorAll('.cloud-menu-item');
      const r = items[items.length - 1].getBoundingClientRect();
      const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
      return items[items.length - 1].contains(top);
    }''')
    assert last, 'the last item cannot be reached'
    assert not app.errors, app.errors


def test_runtime_a_resize_still_closes_the_menu(open_app):
    app, page = _list(open_app)
    _open_menu(page, 'web00')
    page.set_viewport_size({'width': 1500, 'height': 900})
    page.locator('.cloud-menu').wait_for(state='detached', timeout=5000)
    assert not app.errors, app.errors
