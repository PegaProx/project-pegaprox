"""The classic modules inside Corporate Redesigned (Preview).

Datacenter, datastore, automation (with the hardening tab), reports, timeline, site recovery,
plugins, cluster settings, the PegaProx settings, all guests, a group, a backup server, an
ESXi host and the hypervisor migration keep their own logic; the scoped stylesheet gives them
the panels, type scale, controls and accent of the preview. Each one opens without a console
error, the page never scrolls sideways at 1600 or 1280 px, a tab strip that does not fit
scrolls instead of hiding its last tabs, and the breadcrumb names the module. Runs against the
fake server of tests/test_ha_ui.py and skips without Playwright. LW Oct 2026
"""
import re

import pytest

from test_corp_redesigned_dashboard_ui import CLUSTERS, _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp
from test_ha_ui import ESXI_READS, PBS

LAYOUT = 'corporate-redesigned'
XCP = {'id': 'x1', 'name': 'Xen', 'display_name': 'Xen', 'host': '10.0.9.1', 'connected': True,
       'status': 'running', 'cluster_type': 'xcpng', 'enabled': True}
EXTRA = {**ESXI_READS, ('GET', '/api/pbs'): (200, [PBS])}


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(theme='', **kw):
        app = _GuardApp(browser, _DashServer(layout=LAYOUT, clusters=CLUSTERS + [XCP], extra=EXTRA, **kw), corp_theme=theme)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _tab(tid, sub=None):
    def go(page):
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator(f'[data-cr-tab="{tid}"]').click()
        if sub:
            page.wait_for_timeout(500)
            page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*' + re.escape(sub) + r'\s*$')).first.click()
    return go


def _tool(name):
    def go(page):
        page.locator(f'[data-corp-tool="{name}"]').first.click()
    return go


def _entry(label):
    def go(page):
        page.locator('.cr-sidebar').get_by_text(label, exact=True).first.click()
    return go


def _settings(page):
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)


# (view, how to get there, the last breadcrumb, a text the module shows)
MODULES = [
    ('datacenter', _tab('datacenter'), 'Datacenter', 'Summary'),
    ('datastore', _tab('datastore'), 'Datastore', None),
    ('automation', _tab('automation'), 'Automation', 'Scheduled Actions'),
    ('hardening', _tab('automation', 'Harden PVE Node'), 'Automation', 'Check Status'),
    # round 3 (stage J): the trail of the reports and compliance tabs ends with their sub tab
    ('reports', _tab('reports'), 'Summary', 'Summary'),
    ('timeline', _tab('timeline'), 'Timeline', None),
    ('site-recovery', _tab('site-recovery'), 'Site Recovery', 'Site Recovery'),
    ('plugins', _tab('plugins'), 'Plugins', None),
    ('settings', _tab('settings'), 'Settings', 'Balancing Configuration'),
    ('pegaprox-settings', _settings, None, 'User Management'),
    ('all-guests', _tool('guests'), None, None),
    ('group', _entry('EU'), 'EU', None),
    ('pbs', _entry('backup01'), 'backup01', 'Dashboard'),
    ('esxi', _entry('esx01'), None, None),
    ('migration', _tool('xhm'), None, None),
]


def _over(page):
    return page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')


@pytest.mark.parametrize('view,go,crumb,shows', MODULES, ids=[m[0] for m in MODULES])
def test_runtime_every_module_opens_in_the_preview_skin(open_app, view, go, crumb, shows):
    app = open_app()
    page = app.page
    go(page)
    page.wait_for_timeout(1200)
    if shows:
        page.get_by_text(shows).first.wait_for(timeout=8000)
    assert page.evaluate('() => document.body.dataset.corpVariant') == 'redesigned'
    if crumb:
        last = page.locator('.cr-crumbs li .cr-crumb-text').last.inner_text().strip()
        assert last == crumb, last
    assert _over(page) == 0
    page.set_viewport_size({'width': 1280, 'height': 1000})
    page.wait_for_timeout(500)
    assert _over(page) == 0
    # the panels of the module take the preview's panel colour, nothing keeps the classic card blue
    cards = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-main .bg-proxmox-card'))
        .filter(e => e.getClientRects().length).map(e => getComputedStyle(e).backgroundColor)''')
    assert all(c in ('rgb(32, 51, 62)', 'rgba(0, 0, 0, 0)') or c.startswith('rgba(32, 51, 62') for c in cards), set(cards)
    assert app.errors == []


def test_runtime_a_tab_strip_that_does_not_fit_scrolls_to_its_last_tab(open_app):
    app = open_app()
    page = app.page
    page.set_viewport_size({'width': 1280, 'height': 1000})
    _tab('automation')(page)
    strip = page.locator('.corp-tab-strip', has=page.locator('button', has_text='Harden PVE Node'))
    strip.wait_for(timeout=8000)
    info = strip.evaluate('e => ({ sw: e.scrollWidth, cw: e.clientWidth, ox: getComputedStyle(e).overflowX })')
    assert info['sw'] > info['cw'] and info['ox'] == 'auto', info
    page.locator('.corp-tab-strip button', has_text='Harden PVE Node').click()
    page.get_by_text('Check Status').first.wait_for(timeout=8000)
    assert _over(page) == 0
    assert app.errors == []


def test_runtime_toggles_sliders_and_primary_buttons_take_the_accent(open_app):
    app = open_app()
    page = app.page
    _tab('settings')(page)
    page.locator('.toggle-switch.active').first.wait_for(timeout=8000)
    assert page.locator('.toggle-switch.active').first.evaluate('e => getComputedStyle(e).backgroundColor') == 'rgb(85, 182, 208)'
    size = page.locator('.toggle-switch').first.evaluate('e => [e.offsetWidth, e.offsetHeight]')
    assert size == [34, 18]
    btn = page.locator('.cr-main button.bg-proxmox-orange').first
    assert btn.evaluate('e => getComputedStyle(e).color') == 'rgb(13, 28, 34)'
    assert app.errors == []


def test_runtime_the_light_theme_carries_through_the_modules(open_app):
    app = open_app(theme='light')
    page = app.page
    _tab('datacenter')(page)
    page.get_by_text('Summary').first.wait_for(timeout=8000)
    page.wait_for_timeout(800)
    # round 4: the Summary is the preview's own page (its panels), the other sections keep the classic cards
    panels = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-main [data-cr-dc-sum] .cr-panel, .cr-main .cr-dc-tiles'))
        .filter(e => e.getClientRects().length).map(e => getComputedStyle(e).backgroundColor)''')
    assert panels and all(c == 'rgb(255, 255, 255)' for c in panels), set(panels)
    page.locator('.corp-subnav-item', has_text='Cluster').first.click()
    page.wait_for_timeout(800)
    cards = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-main .bg-proxmox-card'))
        .filter(e => e.getClientRects().length).map(e => getComputedStyle(e).backgroundColor)''')
    assert cards and all(c == 'rgb(255, 255, 255)' for c in cards), set(cards)
    assert _over(page) == 0
    assert app.errors == []
