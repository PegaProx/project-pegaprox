"""The audit log's user filter and the Users tab's folder filter are two filters.

They shared one state: a folder chosen on Users emptied the audit log (no entry has a user
called like a folder id), a user chosen in the audit log emptied the Users table, and the
audit select showed neither. Refresh also handed the click event to the fetch as an offset.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

USERS = [{'username': 'alice', 'role': 'admin', 'enabled': True, 'user_folder': 'f1'},
         {'username': 'bert', 'role': 'user', 'enabled': True, 'user_folder': ''}]
LOG = [{'timestamp': '2026-11-06T10:00:00', 'user': 'alice', 'action': 'user.login', 'details': 'line of alice'},
       {'timestamp': '2026-11-06T10:01:00', 'user': 'bert', 'action': 'user.login', 'details': 'line of bert'}]


def _open(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra={
        **SSE_TOKEN,
        ('GET', '/api/users'): (200, USERS),
        ('GET', '/api/user-folders'): (200, [{'id': 'f1', 'name': 'Team one'}]),
        ('GET', '/api/audit/search'): (200, {'entries': LOG, 'total': 2, 'offset': 0})}))
    app.open_settings()
    return app, app.page


def _tab(page, name):
    page.locator('button', has_text=name).first.click()
    page.wait_for_timeout(300)


def test_runtime_a_folder_on_users_leaves_the_audit_log_alone(browser):  # noqa: F811
    app, page = _open(browser)
    try:
        _tab(page, 'User Management')
        page.locator('button', has_text='Team one').first.click()
        page.wait_for_timeout(200)
        _tab(page, 'Audit Log')
        page.get_by_text('line of bert').first.wait_for(timeout=5000)
        assert page.get_by_text('line of alice').count() >= 1
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_user_in_the_audit_log_leaves_the_users_table_alone(browser):  # noqa: F811
    app, page = _open(browser)
    try:
        _tab(page, 'Audit Log')
        page.get_by_text('line of bert').first.wait_for(timeout=5000)
        page.locator('select', has=page.locator('option', has_text='All Users')).first.select_option('alice')
        page.wait_for_timeout(200)
        assert page.get_by_text('line of bert').count() == 0
        _tab(page, 'User Management')
        page.locator('td', has_text='bert').first.wait_for(timeout=5000)
        assert page.locator('td', has_text='alice').count() >= 1
    finally:
        app.ctx.close()


def test_runtime_refresh_asks_for_a_real_offset(browser):  # noqa: F811
    app, page = _open(browser)
    try:
        _tab(page, 'Audit Log')
        page.get_by_text('line of bert').first.wait_for(timeout=5000)
        before = len(app.server.urls)
        page.locator('button', has_text='Refresh').first.click()
        page.wait_for_timeout(500)
        asked = [u for u in app.server.urls[before:] if '/api/audit/search' in u]
        assert asked and all('offset=0' in u for u in asked), asked
    finally:
        app.ctx.close()
