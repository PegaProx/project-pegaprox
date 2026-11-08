"""A second click on Create before the answer makes nothing twice.

The routes insert under a fresh id and check for no duplicate, so a double click on a slow request made two site recovery plans.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import pathlib
import re

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLANS = '/api/site-recovery/plans'
OTHER = dict(CLUSTER, id='c2', name='Zweit')


def test_runtime_a_double_click_makes_one_plan(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER, OTHER], resources=[VM], metrics=NODE_METRICS,
                                    permissions=['site_recovery.view', 'site_recovery.manage', 'cluster.view', 'vm.view'], extra={
        **SSE_TOKEN, ('GET', PLANS): (200, []), ('POST', PLANS): (200, {'id': 'p1'})}))
    try:
        page = app.page
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Site Recovery').first.click()
        page.locator('button', has_text='Create Plan').first.click()
        modal = page.locator('.fixed.inset-0', has_text='Create Plan').last
        modal.wait_for(timeout=5000)
        modal.locator('input').first.fill('dr')
        selects = modal.locator('select')
        selects.nth(0).select_option('c1')
        selects.nth(1).select_option('c2')
        modal.locator('button', has_text='Create').last.evaluate('b => { b.click(); b.click(); }')
        page.wait_for_timeout(600)
        posts = [c for c in app.server.calls if c == ('POST', PLANS)]
        assert len(posts) == 1, app.server.calls[-8:]
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_the_replication_dialog_has_the_same_guard():
    """Its dialog takes a cluster with live storage data to open, so this one is read from the source."""
    src = (ROOT / 'web' / 'src' / 'vm_config.js').read_text(encoding='utf-8')
    body = src[src.index('const handleCreateXRepl = async'):src.index('const handleDeleteXRepl = async')]
    assert re.search(r'if \(creatingXRepl\.current\) return;\s+creatingXRepl\.current = true;', body)
    assert re.search(r'finally \{\s+creatingXRepl\.current = false;', body)


def test_the_group_settings_replication_dialog_has_the_same_guard():
    """The group settings modal posts to the same route from its own handler."""
    src = (ROOT / 'web' / 'src' / 'vm_modals.js').read_text(encoding='utf-8')
    start = src.index('function GroupSettingsModal(')
    body = src[src.index('const handleCreateXRepl = async', start):src.index('const handleDeleteXRepl = async', start)]
    assert re.search(r'if \(creatingXRepl\.current\) return;\s+creatingXRepl\.current = true;', body)
    assert re.search(r'finally \{\s+creatingXRepl\.current = false;', body)
    assert 'const creatingXRepl = useRef(false);' in src[start:src.index('const handleCreateXRepl = async', start)]
