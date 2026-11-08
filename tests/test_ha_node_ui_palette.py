"""the HA settings stay open while the command palette (Ctrl+K, z-[100] above the
modal at z-50) switches the selected cluster. What do they show, and where does Save write?

LW Oct 2026 (#625)
"""
import pytest

from test_ha_ui import BASE, PASSWORD, _App, browser  # noqa: F401
from test_ha_node_ui import (_HeldClusters, _c1_values, _close_ha_settings, _open_ha_settings, _wait_for,
                             IPMI_PVE1, C1_UNSAFE)


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


def _palette_to(page, name):
    page.keyboard.press('Control+k')
    box = page.get_by_placeholder('Type to search clusters, VMs, actions…')
    box.wait_for(timeout=5000)
    box.fill(name)
    page.wait_for_timeout(200)
    box.press('Enter')
    page.wait_for_timeout(500)


def _writes_to(app, cid):
    return [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith(f'/api/clusters/{cid}/ha')]


@pytest.mark.parametrize('how', ['held', 'refused'])
def test_palette_switch_keeps_c1_form_and_save_writes_it_to_c2(held, how):
    kw = dict(two_node=True, c2={'two_node': False})
    if how == 'refused':
        kw['c2_refusal'] = (503, {'error': 'Cluster not reachable'})
    app = held(**kw)
    _c1_values(app.server)
    page = app.page
    modal = _open_ha_settings(app)
    assert modal.locator('input[type="number"]').first.input_value() == '111'
    if how == 'held':
        app.server.hold.add(('GET', '/api/clusters/c2/ha/status'))
        app.server.hold.add(('GET', '/api/clusters/c2/ha'))
    _palette_to(page, 'Zweit')
    if how == 'held':
        assert _wait_for(page, lambda: app.server.holds('GET', '/api/clusters/c2/ha/status'))
    else:
        assert _wait_for(page, lambda: ('GET', '/api/clusters/c2/ha/status') in app.server.calls)
        page.wait_for_timeout(800)
    still_open = page.locator('[data-ha-cluster-settings]').count()
    header = modal.inner_text().split('\n')[:3] if still_open else None
    delay = modal.locator('input[type="number"]').first.input_value() if still_open else None
    two = modal.locator('label', has_text='Enable 2-Node Cluster Mode').locator('input').is_checked() if still_open else None
    save_live = modal.get_by_role('button', name='Save Settings').is_enabled() if still_open else None
    print(how, 'open', still_open, 'header', header, 'delay', delay, '2-node', two, 'save live', save_live)
    if still_open and save_live:
        modal.get_by_role('button', name='Save Settings').click()
        _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c2/ha/config'))
    sent = app.server.bodies.get('/api/clusters/c2/ha/config')
    print(how, 'PUT to c2:', sent)
    assert not sent, f'c1 form values written to c2 after a palette switch ({how}): {sent}'


def test_palette_switch_node_parts_show_c1_and_write_c2(held):
    """c1 has a fence on pve1, an unsafe switch on, its own claim; c2 none of it."""
    app = held(c2={'two_node': True}, **C1_UNSAFE)
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    app.server.hold.add(('GET', '/api/clusters/c2/ha/status'))
    app.server.hold.add(('GET', '/api/clusters/c2/ha'))
    _palette_to(page, 'Zweit')
    assert _wait_for(page, lambda: app.server.holds('GET', '/api/clusters/c2/ha/status'))
    shown = {
        'open': page.locator('[data-ha-cluster-settings]').count(),
        'pve1 fence': page.locator('select[aria-label="Type pve1"]').input_value()
        if page.locator('select[aria-label="Type pve1"]').count() else None,
        'unsafe on': page.get_by_role('switch', name='Unsafe two-node recovery').get_attribute('aria-checked')
        if page.get_by_role('switch', name='Unsafe two-node recovery').count() else None,
        'claim': modal.locator('[data-ha-node-claim]').get_attribute('data-ha-node-claim')
        if modal.locator('[data-ha-node-claim]').count() else None,
    }
    print('after palette to c2 (status held):', shown, 'header',
          modal.inner_text().split('\n')[:3] if modal.count() else None)
    # a switch of the cluster closes the settings: what is shown is never another cluster's
    assert shown['open'] == 0, shown
    # the unsafe switch reads on: a click switches it off - on c2
    if shown['unsafe on'] == 'true':
        page.get_by_role('switch', name='Unsafe two-node recovery').click()
        _wait_for(page, lambda: _writes_to(app, 'c2'))
    print('writes to c2:', _writes_to(app, 'c2'), app.server.bodies.get('/api/clusters/c2/ha/config'))
    assert not _writes_to(app, 'c2'), 'a node part showing c1 wrote to c2'
    assert shown['pve1 fence'] in (None, ''), shown


def test_palette_switch_carries_a_typed_fence_draft(held):
    """A fence row typed for c1 (and its BMC password) stays in the part after the switch."""
    app = held(c2={'two_node': True}, fencing=IPMI_PVE1)
    page = app.page
    modal = _open_ha_settings(app)
    page.select_option('select[aria-label="Type pve2"]', 'ipmi')
    page.fill('input[aria-label="Host pve2"]', '10.0.0.102')
    page.fill('input[aria-label="Password pve2"]', 'typed-for-c1')
    _palette_to(page, 'Zweit')
    page.wait_for_timeout(800)  # c2's status is here now
    pve2 = page.locator('select[aria-label="Type pve2"]').input_value() if page.locator('select[aria-label="Type pve2"]').count() else None
    pw = page.locator('input[aria-label="Password pve2"]').input_value() if page.locator('input[aria-label="Password pve2"]').count() else None
    print('after palette to c2: open', page.locator('[data-ha-cluster-settings]').count(), 'header',
          modal.inner_text().split('\n')[:3] if modal.count() else None, 'pve2 type', pve2, 'pw', pw)
    if page.get_by_role('button', name='Save fencing').count() and page.get_by_role('button', name='Save fencing').is_enabled():
        page.get_by_role('button', name='Save fencing').click()
        _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c2/ha/config'))
    print('PUT to c2:', app.server.bodies.get('/api/clusters/c2/ha/config'))
    assert not app.server.bodies.get('/api/clusters/c2/ha/config'), 'c1 fence draft written to c2'
