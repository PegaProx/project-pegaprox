"""A security setting the server refuses says so, and the form goes back to the stored value.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

SERVER = '/api/settings/server'
STORED = {'password_min_length': 8, 'password_require_uppercase': True}


def _open(browser, answer):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', SERVER): (200, STORED), ('POST', SERVER): answer}))
    app.open_settings()
    page = app.page
    page.locator('button', has_text='Security').first.click()
    page.get_by_text('Uppercase').first.wait_for(timeout=6000)
    return app, page


def _uppercase(page):
    return page.locator('label', has_text='Uppercase').locator('input[type=checkbox]').first


def test_runtime_a_refused_change_says_why_and_the_box_goes_back(browser):  # noqa: F811
    app, page = _open(browser, (403, {'error': 'not allowed here'}))
    try:
        box = _uppercase(page)
        assert box.is_checked()
        box.click()
        page.locator('.toast-enter', has_text='not allowed here').first.wait_for(timeout=5000)
        page.wait_for_function(
            "() => [...document.querySelectorAll('label')].find(l => l.textContent.includes('Uppercase'))"
            ".querySelector('input').checked", timeout=5000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_saved_change_stays(browser):  # noqa: F811
    app, page = _open(browser, (200, {}))
    try:
        box = _uppercase(page)
        box.click()
        page.wait_for_timeout(400)
        assert ('POST', SERVER) in app.server.calls
        assert not box.is_checked()
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_standby_refusal_is_said_in_the_ui_words(browser):  # noqa: F811
    """The server's sentence is English only; the standby refusal has a text of its own in every language."""
    app, page = _open(browser, (409, {'code': 'HA_STANDBY', 'error': 'raw standby sentence'}))
    try:
        _uppercase(page).click()
        page.locator('.toast-enter', has_text='Actions and consoles are only available on the active instance').first.wait_for(timeout=5000)
        assert page.locator('.toast-enter', has_text='raw standby sentence').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
