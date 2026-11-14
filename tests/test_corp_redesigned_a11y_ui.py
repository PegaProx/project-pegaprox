"""Accessibility of Corporate Redesigned (Preview) in the browser.

Every control of the preview's shell and views has a name a screen reader can say, the
keyboard reaches the content through a skip link and walks header, sidebar and content in
that order, the inventory is an ARIA tree with the tree keys, tables and tabs say what is
sorted and selected, the focus ring is the preview's own, reduced motion stops the animations
and the text colours keep a 4.5:1 contrast on every surface in both themes. Runs against the
fake server of tests/test_ha_ui.py and skips without Playwright. LW Oct 2026
"""
import pytest

from test_corp_redesigned_dashboard_ui import _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp

LAYOUT = 'corporate-redesigned'


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
        app = _GuardApp(browser, _DashServer(layout=LAYOUT, **kw), corp_theme=theme)
        apps.append(app)
        app.page.locator('[data-cr-dashboard]').wait_for(timeout=15000)
        return app
    yield _open
    for app in apps:
        app.close()


# a close enough accessible name: what Chromium would read for these elements
UNNAMED = '''(scopes) => {
    const name = (el) => {
        const l = el.getAttribute('aria-label');
        if (l && l.trim()) return l.trim();
        const by = el.getAttribute('aria-labelledby');
        if (by) return by.split(/\\s+/).map(id => (document.getElementById(id) || {}).textContent || '').join(' ').trim();
        if (el.labels && el.labels.length) return Array.from(el.labels).map(x => x.textContent).join(' ').trim();
        const text = (el.textContent || '').trim();
        if (text && el.tagName !== 'SELECT' && el.tagName !== 'INPUT') return text;
        if (el.tagName === 'SELECT' && el.selectedOptions && el.selectedOptions.length && el.title) return el.title;
        return (el.getAttribute('title') || el.getAttribute('placeholder') || '').trim();
    };
    const sel = 'button, a[href], select, input:not([type=hidden]), textarea, [role=button], [role=tab], [role=treeitem], [role=menuitem], [tabindex="0"]';
    const out = [];
    scopes.forEach(s => document.querySelectorAll(s).forEach(root => root.querySelectorAll(sel).forEach(el => {
        if (!el.getClientRects().length || el.closest('[aria-hidden="true"]')) return;
        if (!name(el)) out.push(`${s}: ${el.outerHTML.slice(0, 140)}`);
    })));
    return out;
}'''
SCOPES = ['header.cr-header', '.cr-sidebar', '.cr-taskcenter', '[data-cr-dashboard]', '[data-cr-topo-root]',
          '[data-cr-compliance]', '[data-cr-objhead]', '[data-cr-tabs]']


def _open_cluster(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=10000)


def test_runtime_every_control_has_a_name(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-tc-toggle]').click()
    page.wait_for_timeout(400)
    missing = page.evaluate(UNNAMED, SCOPES)
    _open_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('[data-cr-objhead="node"]').wait_for(timeout=8000)
    missing += page.evaluate(UNNAMED, SCOPES)
    page.locator('[data-cr-tab="compliance"]').click()
    page.locator('[data-cr-compliance]').wait_for(timeout=8000)
    page.wait_for_timeout(800)
    missing += page.evaluate(UNNAMED, SCOPES)
    page.locator('[data-corp-tool="topology"]').first.click()
    page.locator('[data-cr-topo-root]').wait_for(timeout=10000)
    page.wait_for_timeout(600)
    missing += page.evaluate(UNNAMED, SCOPES)
    assert missing == [], "\n".join(missing)
    # the classic header buttons have a name in the preview, the user menu says it opens one
    tools = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-header-tools button'))
        .map(b => b.getAttribute('aria-label'))''')
    assert all(tools), tools
    menu = page.locator('header.cr-header [data-user-menu]')
    assert menu.get_attribute('aria-label') == 'User menu' and menu.get_attribute('aria-haspopup') == 'menu'
    assert menu.get_attribute('aria-expanded') == 'false'
    menu.focus()
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelector("header.cr-header [data-user-menu]").getAttribute("aria-expanded") === "true"', timeout=3000)
    assert app.errors == []


def test_runtime_the_skip_link_and_the_tab_order(open_app):
    app = open_app()
    page = app.page
    page.evaluate('() => document.activeElement && document.activeElement.blur()')
    page.keyboard.press('Tab')
    skip = page.locator('[data-cr-skip]')
    assert page.evaluate('() => document.activeElement.hasAttribute("data-cr-skip")')
    box = skip.bounding_box()
    assert box and box['y'] >= 0 and box['height'] > 10, box
    page.keyboard.press('Enter')
    assert page.evaluate('() => document.activeElement.id') == 'cr-main'
    # from the top: the header first, then the sidebar, then the content
    skip.focus()
    seen = ['header']
    for _ in range(140):
        page.keyboard.press('Tab')
        where = page.evaluate('''() => { const a = document.activeElement;
            return a.closest('header.cr-header') ? 'header' : a.closest('.cr-sidebar') ? 'sidebar' : a.closest('#cr-main') ? 'main' : 'other'; }''')
        if where != 'other' and (not seen or seen[-1] != where):
            seen.append(where)
        if where == 'main':
            break
    assert seen[:3] == ['header', 'sidebar', 'main'], seen
    assert app.errors == []


def test_runtime_the_inventory_is_a_tree_with_the_tree_keys(open_app):
    app = open_app()
    page = app.page
    trees = page.evaluate('() => Array.from(document.querySelectorAll(".cr-sidebar [role=tree]")).map(t => t.getAttribute("aria-label"))')
    assert trees == ['EU', 'Ungrouped'], trees
    testi = page.locator('.cr-sidebar [role=treeitem][aria-level="1"]', has_text='Testi')
    assert testi.get_attribute('aria-expanded') == 'false' and testi.get_attribute('aria-selected') == 'false'
    testi.focus()
    page.keyboard.press('ArrowRight')
    page.wait_for_function('''() => Array.from(document.querySelectorAll('.cr-sidebar [role=treeitem][aria-level="1"]'))
        .find(e => e.textContent.includes('Testi')).getAttribute('aria-expanded') === 'true' ''', timeout=8000)
    page.locator('.cr-sidebar [role=group] [role=treeitem]').first.wait_for(timeout=8000)
    page.keyboard.press('ArrowDown')
    first = page.evaluate('() => [document.activeElement.getAttribute("role"), document.activeElement.getAttribute("aria-level"), document.activeElement.textContent.trim()]')
    assert first[:2] == ['treeitem', '2'] and first[2].startswith('pve1'), first
    page.keyboard.press('ArrowDown')
    assert page.evaluate('() => document.activeElement.textContent.trim()').startswith('pve2')
    page.keyboard.press('ArrowLeft')
    assert 'Testi' in page.evaluate('() => document.activeElement.textContent')
    page.keyboard.press('ArrowLeft')
    page.wait_for_function('''() => Array.from(document.querySelectorAll('.cr-sidebar [role=treeitem][aria-level="1"]'))
        .find(e => e.textContent.includes('Testi')).getAttribute('aria-expanded') === 'false' ''', timeout=8000)
    page.keyboard.press('Enter')
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=8000)
    assert testi.get_attribute('aria-selected') == 'true'
    # a pick in the tree is announced as selected on its row
    page.locator('.cr-sidebar [role=group] [role=treeitem]', has_text='web01').click()
    page.locator('[data-cr-objhead="vm"]').wait_for(timeout=8000)
    assert page.locator('.cr-sidebar [role=group] [role=treeitem][aria-selected="true"]').inner_text().strip() == 'web01'
    assert app.errors == []


def test_runtime_tables_and_tabs_say_what_is_sorted_and_selected(open_app):
    app = open_app()
    page = app.page
    th = page.locator('[data-cr-table="dash-clusters"] th[data-cr-col="name"]')
    assert th.get_attribute('aria-sort') == 'ascending'
    assert page.locator('[data-cr-table="dash-clusters"] th[data-cr-col="cpu"]').get_attribute('aria-sort') == 'none'
    assert page.locator('[data-cr-table="dash-clusters"] table').get_attribute('role') == 'grid'
    _open_cluster(page)
    tabs = page.locator('[data-cr-tabs="cluster"]')
    assert tabs.get_attribute('role') == 'tablist'
    assert tabs.locator('[role=tab][aria-selected="true"]').count() == 1
    assert app.errors == []


def test_runtime_the_focus_ring_is_the_preview_s_own(open_app):
    app = open_app()
    page = app.page
    row = page.locator('[data-cr-table="dash-clusters"] tbody tr.cr-row').first
    row.focus()
    page.keyboard.press('ArrowDown')
    ring = page.evaluate('() => { const s = getComputedStyle(document.activeElement); return [s.outlineStyle, s.outlineWidth, s.outlineColor]; }')
    assert ring == ['solid', '2px', 'rgb(112, 200, 223)'], ring
    page.locator('[data-cr-palette]').focus()
    page.keyboard.press('Shift+Tab')
    page.keyboard.press('Tab')
    ring = page.evaluate('() => { const s = getComputedStyle(document.activeElement); return [s.outlineStyle, s.outlineWidth]; }')
    assert ring == ['solid', '2px'], ring
    assert app.errors == []


def test_runtime_reduced_motion_stops_the_animations(open_app):
    app = open_app()
    page = app.page
    # the spinner of the preview and a classic one (the harness itself switches transitions off)
    probe = '''() => {
        const a = document.createElement('span'); a.className = 'cr-spinner';
        const b = document.createElement('span'); b.className = 'animate-spin';
        document.querySelector('#cr-main').append(a, b);
        const out = [a, b].map(e => [getComputedStyle(e).animationDuration, getComputedStyle(e).animationIterationCount]);
        a.remove(); b.remove();
        return out;
    }'''
    assert page.evaluate(probe) == [['0.8s', 'infinite'], ['1s', 'infinite']]
    page.emulate_media(reduced_motion='reduce')
    assert page.evaluate(probe) == [['1e-05s', '1'], ['1e-05s', '1']]
    assert app.errors == []


def _lum(hex_):
    hex_ = hex_.strip().lstrip('#')
    ch = [int(hex_[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    ch = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in ch]
    return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]


def _ratio(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


@pytest.mark.parametrize('theme', ['', 'light'])
def test_runtime_the_text_colours_keep_their_contrast(open_app, theme):
    app = open_app(theme=theme)
    page = app.page
    names = ['--cr-text-primary', '--cr-text-secondary', '--cr-text-muted', '--cr-accent', '--cr-success', '--cr-warning',
             '--cr-error', '--cr-bg-primary', '--cr-bg-secondary', '--cr-bg-panel', '--cr-bg-elevated', '--cr-bg-sunken']
    tok = page.evaluate('(n) => Object.fromEntries(n.map(k => [k, getComputedStyle(document.body).getPropertyValue(k).trim()]))', names)
    low = []
    for fg in ('--cr-text-primary', '--cr-text-secondary', '--cr-text-muted', '--cr-accent', '--cr-success', '--cr-warning', '--cr-error'):
        for bg in ('--cr-bg-primary', '--cr-bg-secondary', '--cr-bg-panel', '--cr-bg-elevated', '--cr-bg-sunken'):
            r = _ratio(tok[fg], tok[bg])
            if r < 4.5:
                low.append((fg, bg, round(r, 2)))
    assert low == [], low
    assert app.errors == []
