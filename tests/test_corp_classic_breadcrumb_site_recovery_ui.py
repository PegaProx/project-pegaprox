"""The breadcrumb of classic Corporate names the Site Recovery tab.

The last segment of the breadcrumb is the open tab. It was t(activeTab), with one exception
for the timeline, and the id of the Site Recovery tab is 'site-recovery' while its string
is siteRecovery: the breadcrumb read "site-recovery". The tab strip beside it and the
breadcrumb of Corporate Redesigned both say "Site Recovery".

The runtime test drives the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py and skips where Playwright is not installed.
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRUMB = '.corp-breadcrumb-current'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# --- source --------------------------------------------------------------------------------

def test_the_classic_breadcrumb_looks_the_tab_up_under_its_own_key():
    src = _read('web', 'src', 'dashboard.js')
    [line] = [ln for ln in src.splitlines() if 'corp-breadcrumb-current' in ln and 'activeTab' in ln and 't(' in ln]
    assert "'site-recovery': 'siteRecovery'" in line
    # the id of the tab and its string are what the tab strip uses
    assert "{ id: 'site-recovery', labelKey: 'siteRecovery'" in src


def test_the_bundle_was_rebuilt():
    assert "t({timeline:'tlTab','site-recovery':'siteRecovery'}[activeTab]||activeTab)" in _read('web', 'index.html')


# --- runtime -------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):  # noqa: F811
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                                        extra=dict(SSE_TOKEN), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open_tab(app, name):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    strip = page.locator('.corp-tab-strip').first
    strip.wait_for(timeout=8000)
    # the fake server has no event stream, so its reconnect bar can lie over the strip
    strip.locator('button', has_text=re.compile(rf'^\s*{name}\s*$')).first.dispatch_event('click')
    page.wait_for_timeout(400)
    return page


def test_runtime_the_breadcrumb_says_site_recovery(open_app):
    app = open_app(layout='corporate', language='en')
    page = _open_tab(app, 'Site Recovery')
    assert page.locator(CRUMB).last.inner_text().strip() == 'Site Recovery'
    crumbs = page.locator(f'{CRUMB}, .corp-breadcrumb-segment').all_inner_texts()
    assert not any('site-recovery' in c for c in crumbs), crumbs
    assert not app.errors, app.errors


def test_runtime_the_other_tabs_read_as_before(open_app):
    """Counterproof: a tab whose id is its key, and the timeline with its own key."""
    app = open_app(layout='corporate', language='en')
    page = _open_tab(app, 'Resources')
    assert page.locator(CRUMB).last.inner_text().strip() == 'Resources'
    page.locator('.corp-tab-strip').first.locator('button', has_text=re.compile(r'^\s*Timeline\s*$')).first.dispatch_event('click')
    page.wait_for_timeout(400)
    assert page.locator(CRUMB).last.inner_text().strip() == 'Timeline'
