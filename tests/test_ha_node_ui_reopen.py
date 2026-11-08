"""a node part's answer that lands after the HA settings of the same cluster were
closed and opened again, while the status of the reopen is still on its way.

LW Oct 2026 (#625)
"""
import re

import pytest

from test_ha_ui import _App, browser  # noqa: F401
from test_ha_node_ui import (_HeldClusters, _c1_values, _close_ha_settings, _open_ha_settings, _wait_for,
                             _send_claim, _send_fence, IPMI_PVE1)


@pytest.fixture
def held(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _HeldClusters(**kw))
        apps.append(app)
        return app
    yield _open
    for a in apps:
        a.ctx.close()


def _release_only(server, method, path):
    keep = []
    for args in server.held:
        if (args[2], '/api/clusters/%s/ha%s' % (args[1], args[3])) == (method, path):
            server.answer(*args)
        else:
            keep.append(args)
    server.held = keep


def _reopen_c1(app):
    page = app.page
    page.get_by_role('button', name=re.compile('Split-Brain Prevention')).click()
    m = page.locator('[data-ha-cluster-settings]')
    m.wait_for(timeout=5000)
    return m


PARTS = {
    'fencing': (('PUT', '/api/clusters/c1/ha/config'), _send_fence),
    'claim': (('POST', '/api/clusters/c1/ha/claim'), _send_claim),
}


@pytest.mark.parametrize('part', list(PARTS))
def test_part_answer_after_reopen_shows_a_default_form_and_save_writes_it(held, part):
    req, send = PARTS[part]
    app = held(two_node=True, fencing=IPMI_PVE1)
    _c1_values(app.server)
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    assert modal.locator('input[type="number"]').first.input_value() == '111'
    app.server.hold.add(req)
    send(app, modal)
    assert _wait_for(page, lambda: app.server.holds(*req))
    _close_ha_settings(page)
    app.server.hold.add(('GET', '/api/clusters/c1/ha/status'))
    app.server.hold.add(('GET', '/api/clusters/c1/ha'))
    m = _reopen_c1(app)
    assert _wait_for(page, lambda: app.server.holds('GET', '/api/clusters/c1/ha/status'))
    loading = m.locator('[data-ha-settings-loading]').count()
    _release_only(app.server, *req)
    page.wait_for_timeout(1000)
    nums = [f.input_value() for f in m.locator('input[type="number"]').all()]
    two = m.locator('label', has_text='Enable 2-Node Cluster Mode').locator('input')
    two_checked = two.is_checked() if two.count() else None
    save = m.get_by_role('button', name='Save Settings')
    print(part, 'loading before', loading, 'after part answer: numbers', nums, '2-node', two_checked,
          'save live', save.is_enabled(), 'c1 really: 111/7, two_node', app.server.two_node)
    n_before = len(app.server.bodies.get('/api/clusters/c1/ha/config', []))
    if save.is_enabled():
        save.click()
        _wait_for(page, lambda: len(app.server.bodies.get('/api/clusters/c1/ha/config', [])) > n_before)
    sent = app.server.bodies.get('/api/clusters/c1/ha/config', [])[n_before:]
    print(part, 'Save sent:', sent, 'c1 two_node after:', app.server.two_node)
    assert not sent, f'a form of defaults was saved over c1: {sent}'
