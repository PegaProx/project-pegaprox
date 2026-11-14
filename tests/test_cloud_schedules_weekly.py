"""The Cloud schedules page offers what works.

Weekly was on offer with nothing to pick days with, so the route answered 400 "Days are required" and the page said "HTTP 400". The
run button of a row called a route that does not exist.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

PATH = '/api/schedules'
ROW = {'id': 's1', 'cluster_id': 'c1', 'vmid': 100, 'action': 'start', 'schedule_type': 'daily', 'time': '03:00', 'enabled': 1}


def _page(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='cloud', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', PATH): (200, [ROW]), ('POST', PATH): (200, {'id': 's2'})}))
    page = app.page
    page.locator('.cloud-nav-item', has_text='Schedules').first.click()
    page.locator('.cloud-table-row', has_text='#100').first.wait_for(timeout=5000)
    return app, page


def _new_weekly(page):
    page.locator('.cloud-link-btn').first.click()
    page.locator('.cloud-input[type="number"]').first.fill('100')
    page.locator('select.cloud-input', has=page.locator('option[value="weekly"]')).first.select_option('weekly')


def test_runtime_weekly_sends_the_days_picked(browser):  # noqa: F811
    app, page = _page(browser)
    try:
        _new_weekly(page)
        page.locator('[data-cloud-sched-day="monday"]').check()
        page.locator('[data-cloud-sched-day="friday"]').check()
        page.locator('.cloud-modal-footer button[type="submit"]').click()
        page.wait_for_timeout(500)
        body = [b for b in app.server.bodies.get(PATH, []) if b][-1]
        assert body['schedule_type'] == 'weekly' and body['days'] == ['monday', 'friday'], body
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_weekly_without_a_day_sends_nothing(browser):  # noqa: F811
    app, page = _page(browser)
    try:
        _new_weekly(page)
        page.locator('.cloud-modal-footer button[type="submit"]').click()
        page.wait_for_timeout(400)
        assert ('POST', PATH) not in app.server.calls
    finally:
        app.ctx.close()


def test_runtime_a_row_offers_no_run_that_cannot_work(browser):  # noqa: F811
    app, page = _page(browser)
    try:
        assert page.locator('.cloud-table-row button[title="Run now"]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_click_on_the_caption_or_the_gap_ticks_no_day(browser):  # noqa: F811
    app, page = _page(browser)
    try:
        _new_weekly(page)
        group = page.locator('[data-cloud-sched-days]')
        group.wait_for(timeout=5000)
        ticked = lambda: page.locator('[data-cloud-sched-day]:checked').count()  # noqa: E731
        # the caption sits at the top left of the field around the group; check after each click,
        # two clicks on one checkbox would cancel out
        field = group.locator('xpath=..').bounding_box()
        page.mouse.click(field['x'] + 6, field['y'] + 6)
        page.wait_for_timeout(150)
        assert ticked() == 0, 'caption'
        # a point of the group that no day covers
        gap = group.evaluate('''g => { const r = g.getBoundingClientRect();
            for (let y = r.top + 2; y < r.bottom; y += 4) for (let x = r.right - 2; x > r.left; x -= 4)
                if (document.elementFromPoint(x, y) === g) return [x, y];
            return null; }''')
        assert gap, 'no blank spot in the day group'
        page.mouse.click(gap[0], gap[1])
        page.wait_for_timeout(150)
        assert ticked() == 0, 'gap'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
