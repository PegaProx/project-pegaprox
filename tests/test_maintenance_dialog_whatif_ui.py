"""The maintenance dialog runs the 'maintenance' what-if of the node and says what the
evacuation would do; a blocked verdict needs a tick; a refused check falls back to the old
capacity text; the preflight reasons speak the language of the user.

Runtime proof in the built bundle (web/index.html), in the three layouts.
NS Oct 2026
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, VM, _App, _FakeServer, browser  # noqa: F401

WHATIF = ('POST', '/api/clusters/c1/whatif')
MAINT = '/api/clusters/c1/nodes/pve2/maintenance'
PREVIEW = ('GET', '/api/clusters/c1/nodes/pve2/maintenance-preview')
METRICS = {n: dict(NODE_METRICS['pve1']) for n in ('pve1', 'pve2')}


def _row(vmid, name, outcome='moved', critical=False, restore='proven', target='pve1'):
    return {'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve2', 'outcome': outcome, 'target': target,
            'critical': critical, 'tags': ['critical'] if critical else [], 'tenants': ['acme'],
            'restore': {'state': restore}, 'reason': {'code': 'moved_live', 'args': {}}, 'text': 'moved by live migration'}


def _report(level, reasons=(), guests=None, over=()):
    guests = guests if guests is not None else [_row(100, 'billing-db', critical=True), _row(101, 'web01', restore='not_proven')]
    nodes = [{'node': n, 'over_cpu': False, 'over_mem': True} for n in over]
    return {'supported': True, 'scenario': {'type': 'maintenance'}, 'guests': guests, 'nodes': nodes, 'limits': [],
            'summary': {'moved': sum(1 for g in guests if g['outcome'] == 'moved'),
                        'restarted': 0, 'down': sum(1 for g in guests if g['outcome'] == 'down')},
            'risk': {'tenants': {'items': [{'id': 'acme', 'name': 'Acme', 'affected': 2, 'down': 0, 'critical': 1}],
                                 'readable': True, 'basis': 'assumed'}},
            'verdict': {'level': level, 'reasons': list(reasons)}}


WARN = _report('warning', [
    {'level': 'warning', 'code': 'critical_affected', 'args': {'count': 1, 'names': 'billing-db'},
     'text': '1 critical guest is affected: billing-db'},
    {'level': 'warning', 'code': 'restore_unproven', 'args': {'count': 1},
     'text': '1 affected guest has no proven restore'}], over=('pve1',))
BLOCKED = _report('blocked', [
    {'level': 'blocked', 'code': 'guests_down', 'args': {'count': 1},
     'text': '1 guest cannot be placed anywhere and stays down'}],
    guests=[_row(100, 'billing-db', critical=True), _row(102, 'legacy', outcome='down', target=None)])


def _server(layout, language='en', extra=None, **kw):
    ex = {WHATIF: (200, WARN), ('PUT', MAINT): (200, {'message': 'ok'})}
    ex.update(extra or {})
    return _FakeServer(role='standalone', layout=layout, language=language, clusters=[CLUSTER], resources=[VM],
                       metrics=METRICS, extra=ex, **kw)


def _open_dialog(app, layout):
    """The way to the maintenance dialog of pve2 in each layout"""
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
        buttons = page.locator('button[title="Enter Maintenance Mode"]')
        buttons.first.wait_for(timeout=8000)
        buttons.nth(1).click()
    elif layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        row = page.locator('.corp-node-row', has_text='pve2').first
        row.wait_for(timeout=8000)
        row.get_by_text('pve2').first.click()
        row.locator('.corp-toolbar').wait_for(timeout=3000)
        row.locator('.corp-toolbar button', has_text='Enter Maintenance Mode').click()
    else:
        page.get_by_text('Hosts', exact=True).first.click()
        card = page.locator('.cloud-node-card', has_text='pve2')
        card.wait_for(timeout=8000)
        card.locator('button').last.click()
        page.get_by_text('Maintenance mode', exact=True).first.click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    dialog.wait_for(timeout=5000)
    return dialog


@pytest.fixture
def opened(browser):
    apps = []

    def _open(layout, **kw):
        app = _App(browser, _server(layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_dialog_shows_the_verdict_and_the_critical_guest(opened, layout):
    app = opened(layout)
    dialog = _open_dialog(app, layout)
    verdict = dialog.locator('[data-testid="whatif-verdict"]')
    verdict.wait_for(timeout=5000)
    assert verdict.get_attribute('data-verdict') == 'warning'
    assert 'Warning' in verdict.inner_text()
    assert '1 critical guest is affected: billing-db' in verdict.inner_text()
    assert 'billing-db' in dialog.locator('[data-testid="maint-critical"]').inner_text()
    assert dialog.locator('[data-testid="maint-moves"]').inner_text().startswith('2 guests move')
    assert 'web01' in dialog.locator('[data-testid="maint-unproven"]').inner_text()
    tenants = dialog.locator('[data-testid="maint-tenants"]')
    assert 'Acme' in tenants.inner_text() and tenants.locator('[data-whatif-basis="assumed"]').count() == 1
    assert 'pve1' in dialog.locator('[data-testid="maint-over"]').inner_text()
    assert app.server.calls.count(('POST', '/api/clusters/c1/whatif')) == 1, 'one what-if per opening'
    assert app.server.bodies['/api/clusters/c1/whatif'][-1] == {'type': 'maintenance', 'nodes': ['pve2']}
    assert dialog.locator('[data-testid="maint-ack"]').count() == 0
    dialog.locator('[data-testid="maint-enable"]').click()
    deadline = 40
    while deadline and MAINT not in app.server.bodies:
        app.page.wait_for_timeout(100)
        deadline -= 1
    assert app.server.bodies[MAINT][-1] == {'enable': True, 'migrate_templates': False, 'relax_anti_affinity': False}
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_blocked_verdict_needs_the_tick_before_enable_works(opened, layout):
    app = opened(layout, extra={WHATIF: (200, BLOCKED)})
    dialog = _open_dialog(app, layout)
    dialog.locator('[data-testid="whatif-verdict"][data-verdict="blocked"]').wait_for(timeout=5000)
    enable = dialog.locator('[data-testid="maint-enable"]')
    assert enable.is_disabled()
    assert 'legacy' in dialog.locator('[data-testid="maint-down"]').inner_text()
    enable.click(force=True)
    app.page.wait_for_timeout(400)
    assert MAINT not in app.server.bodies, 'a disabled button acted'
    dialog.locator('[data-testid="maint-ack"]').check()
    assert enable.is_enabled()
    enable.click()
    deadline = 40
    while deadline and MAINT not in app.server.bodies:
        app.page.wait_for_timeout(100)
        deadline -= 1
    assert MAINT in app.server.bodies
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_refused_check_falls_back_to_the_old_text_and_never_blocks(opened, layout):
    preview = {'headroom_sufficient': False, 'over_threshold': [], 'guest_count': 3}
    app = opened(layout, extra={WHATIF: (403, {'error': 'forbidden'}), PREVIEW: (200, preview)})
    dialog = _open_dialog(app, layout)
    fallback = dialog.locator('[data-testid="maint-fallback"]')
    fallback.wait_for(timeout=5000)
    assert 'may not have enough free RAM' in fallback.inner_text()
    assert dialog.locator('[data-testid="whatif-verdict"]').count() == 0
    assert dialog.locator('[data-testid="maint-ack"]').count() == 0
    dialog.locator('[data-testid="maint-enable"]').click()
    deadline = 40
    while deadline and MAINT not in app.server.bodies:
        app.page.wait_for_timeout(100)
        deadline -= 1
    assert MAINT in app.server.bodies
    assert not app.errors, app.errors


def test_runtime_a_failed_check_and_a_failed_preview_still_leave_the_action(opened):
    app = opened('modern', extra={WHATIF: (500, {'error': 'boom'}), PREVIEW: (500, {'error': 'boom'})})
    dialog = _open_dialog(app, 'modern')
    fallback = dialog.locator('[data-testid="maint-fallback"]')
    fallback.wait_for(timeout=5000)
    assert 'Nothing to report' in fallback.inner_text()
    assert dialog.locator('[data-testid="maint-enable"]').is_enabled()
    dialog.locator('[data-testid="maint-cancel"]').click()
    dialog.wait_for(state='detached', timeout=3000)
    assert MAINT not in app.server.bodies
    assert not app.errors, app.errors


def test_runtime_disabling_maintenance_keeps_its_simple_confirmation(browser):
    metrics = {n: dict(NODE_METRICS['pve1']) for n in ('pve1', 'pve2')}
    metrics['pve2']['maintenance_mode'] = True
    server = _FakeServer(role='standalone', layout='cloud', clusters=[CLUSTER], resources=[VM], metrics=metrics,
                         extra={('DELETE', MAINT): (200, {'message': 'ok'}), WHATIF: (200, WARN)})
    app = _App(browser, server)
    try:
        seen = []
        app.page.on('dialog', lambda d: (seen.append(d.message), d.accept()))
        app.page.get_by_text('Hosts', exact=True).first.click()
        card = app.page.locator('.cloud-node-card', has_text='pve2')
        card.wait_for(timeout=8000)
        card.locator('button').last.click()
        app.page.get_by_text('Disable maintenance', exact=True).first.click()
        deadline = 40
        while deadline and ('DELETE', MAINT) not in server.calls:
            app.page.wait_for_timeout(100)
            deadline -= 1
        assert ('DELETE', MAINT) in server.calls
        assert seen and 'pve2' in seen[0]
        assert app.page.locator('[data-testid="maint-dialog"]').count() == 0
        assert WHATIF not in server.calls, 'disabling asks no what-if'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
