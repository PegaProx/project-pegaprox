"""After a rule is deleted the datacenter firewall reads the list again.

Proxmox renumbers what follows. The rows here kept their old pos, so the next delete or toggle hit the rule after the one on the row. A refused delete said nothing either.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

RULES = '/api/clusters/c1/datacenter/firewall/rules'
LIST = [{'pos': 0, 'type': 'in', 'action': 'ACCEPT', 'enable': 1, 'comment': 'first'},
        {'pos': 1, 'type': 'in', 'action': 'DROP', 'enable': 1, 'comment': 'second'}]


def _rules(browser, answer):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', RULES): (200, LIST), ('DELETE', RULES + '/0'): answer}))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text='Firewall').first.click()
    page.get_by_text('first').first.wait_for(timeout=6000)
    page.on('dialog', lambda d: d.accept())
    return app, page


def _delete_first(page):
    row = page.locator('tr', has_text='first').first
    row.locator('button').last.click()
    page.wait_for_timeout(500)


def _delete(page, comment):
    row = page.locator('tr', has_text=comment).first
    row.locator('button').last.click()


def test_runtime_the_list_is_read_again_after_a_delete(browser):  # noqa: F811
    app, page = _rules(browser, (200, {}))
    try:
        # Proxmox renumbers, and a rule added meanwhile elsewhere can only come from a fresh read
        app.server.extra[('GET', RULES)] = (200, [dict(LIST[1], pos=0), {'pos': 1, 'type': 'in', 'action': 'ACCEPT', 'enable': 1, 'comment': 'third'}])
        _delete(page, 'first')
        page.get_by_text('third').first.wait_for(timeout=5000)
        page.locator('tr', has_text='first').first.wait_for(state='detached', timeout=5000)
        _delete(page, 'second')
        page.wait_for_timeout(500)
        assert app.server.calls.count(('DELETE', RULES + '/0')) == 2, app.server.calls[-8:]
        assert ('DELETE', RULES + '/1') not in app.server.calls
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('fail', ['refused', 'network'])
def test_runtime_without_a_fresh_list_the_rest_moves_up(browser, fail):  # noqa: F811
    app, page = _rules(browser, (200, {}))
    try:
        if fail == 'refused':
            app.server.extra[('GET', RULES)] = (502, {'error': 'upstream'})
        else:
            page.route('**' + RULES, lambda r: r.abort() if r.request.method == 'GET' else r.fallback())
        _delete(page, 'first')
        page.locator('tr', has_text='first').first.wait_for(state='detached', timeout=5000)
        _delete(page, 'second')
        page.wait_for_timeout(500)
        assert app.server.calls.count(('DELETE', RULES + '/0')) == 2, app.server.calls[-8:]
        assert ('DELETE', RULES + '/1') not in app.server.calls
    finally:
        app.ctx.close()


def test_runtime_a_delete_that_cannot_reach_the_server_says_so(browser):  # noqa: F811
    app, page = _rules(browser, (200, {}))
    try:
        page.route('**' + RULES + '/0', lambda r: r.abort())
        _delete(page, 'first')
        page.locator('.toast-enter', has_text='Connection Error').first.wait_for(timeout=5000)
        assert page.locator('tr', has_text='first').count() >= 1
    finally:
        app.ctx.close()


def test_runtime_a_refused_delete_says_why_and_keeps_the_row(browser):  # noqa: F811
    app, page = _rules(browser, (403, {'error': 'not allowed here'}))
    try:
        _delete_first(page)
        page.locator('.toast-enter', has_text='not allowed here').first.wait_for(timeout=5000)
        assert page.locator('tr', has_text='first').count() >= 1
    finally:
        app.ctx.close()
