"""The shell of Corporate Redesigned (Preview) in the browser: the compact header, the
inventory sidebar and the task center.

The header lays out the controls of the classic header (the same search, theme switch,
settings, task and user buttons) next to a context picker, a breadcrumb trail and a visible
Ctrl+K button for the existing command palette. The sidebar is the classic one with its own
width and fold state, kept under cr-* keys. The task center draws the TaskBar's data. All of
it runs against the fake server of tests/test_ha_ui.py and skips without Playwright.
LW Oct 2026
"""
import re

import pytest

from test_corp_redesigned_guard_ui import CT, DETERMINISTIC, FIXED, NODE_METRICS, TASKS, VM, _GuardApp, _GuardServer, _upid

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

    def _open(layout=LAYOUT, corp_theme='', storage=None, **kw):
        app = _GuardApp(browser, _GuardServer(layout=layout, **kw), corp_theme=corp_theme, storage=storage)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _crumbs(page):
    return page.evaluate('''() => Array.from(document.querySelectorAll('.cr-crumbs li'))
        .map(li => li.innerText.replace('/', '').trim())''')


def _side_width(page):
    return round(page.locator('.pp-sidebar.cr-sidebar').bounding_box()['width'])


def _no_errors(app):
    assert not app.errors, app.errors


# --- header ------------------------------------------------------------------------------------

def test_runtime_the_header_has_every_control(open_app):
    app = open_app()
    page = app.page
    header = page.locator('header.cr-header')
    assert round(header.bounding_box()['height']) == 40
    theme = ', '.join(f'.cr-header-tools button[title="{x}"]' for x in ('Light Mode', 'Dark Mode', 'Follow system'))
    for sel in ('.cr-brand button[title="All Clusters Overview"]', 'nav.cr-crumbs',
                '.pp-header-search input', '[data-cr-palette]', theme,
                '.cr-header-tools button[title="PegaProx Settings"]', '[data-user-menu]'):
        assert header.locator(sel).count() == 1, sel
    # as in classic Corporate: no cluster picker and no language switcher up here
    assert header.locator('select').count() == 0
    # the classic header is not there, and nothing of the header spills over the viewport
    assert page.locator('header.sticky').count() == 0
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 1600
    # the in-field hint of the classic search gives way to the button
    assert not page.locator('.cr-header .pp-header-search kbd').is_visible()
    assert page.locator('[data-cr-palette]').get_attribute('aria-keyshortcuts') == 'Control+K'
    _no_errors(app)


@pytest.mark.parametrize('how', ['button', 'keys'])
def test_runtime_ctrl_k_opens_the_existing_palette(open_app, how):
    app = open_app()
    page = app.page
    if how == 'button':
        page.locator('[data-cr-palette]').click()
    else:
        page.locator('body').click(position={'x': 800, 'y': 600})
        page.keyboard.press('Control+k')
    box = page.get_by_placeholder(re.compile('Type to search clusters'))
    box.wait_for(timeout=5000)
    box.fill('Testi')
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 3', timeout=5000)
    assert _crumbs(page) == ['All', 'Testi', 'Overview']
    _no_errors(app)


def test_runtime_the_breadcrumbs_follow_and_navigate(open_app):
    app = open_app()
    page = app.page
    assert _crumbs(page) == ['All']
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 4', timeout=5000)
    assert _crumbs(page) == ['All', 'Testi', 'Overview', 'pve1']
    assert page.locator('.cr-crumbs li').last.locator('[aria-current="page"]').count() == 1
    page.locator('[data-cr-crumb="tab"] button').click()
    assert _crumbs(page) == ['All', 'Testi', 'Overview']
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 4', timeout=5000)
    assert _crumbs(page) == ['All', 'Testi', 'Resources', 'web01']
    page.locator('[data-cr-crumb="cluster"] button').click()
    assert _crumbs(page) == ['All', 'Testi', 'Overview']
    page.locator('[data-cr-crumb="all"] button').click()
    assert _crumbs(page) == ['All']
    # a global view names itself
    page.locator('[data-corp-tool="topology"]').click()
    assert _crumbs(page) == ['All', 'Topology']
    _no_errors(app)


def test_runtime_the_tree_switches_the_cluster_without_a_header_picker(open_app):
    two = [{'id': 'c1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1', 'connected': True,
            'status': 'running', 'cluster_type': 'proxmox', 'enabled': True},
           {'id': 'c2', 'name': 'prod', 'display_name': 'Production', 'host': '10.0.0.2', 'connected': False,
            'status': 'error', 'cluster_type': 'proxmox', 'enabled': True}]
    app = open_app()
    app.server.clusters = two
    page = app.page
    page.reload()
    app.wait_for_app()
    assert page.locator('header.cr-header select').count() == 0
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 3', timeout=5000)
    assert _crumbs(page) == ['All', 'Testi', 'Overview']
    assert page.locator('.corp-tab-strip').count() >= 1
    page.locator('[data-cr-crumb="all"] button').click()
    assert _crumbs(page) == ['All']
    _no_errors(app)


def _profile(page):
    page.locator('[data-user-menu]').click()
    page.get_by_text('My Profile').first.click()
    page.locator('select[aria-label="Select language"], [data-ui-lock="language"]').first.wait_for(timeout=5000)


def test_runtime_the_language_lives_in_my_profile_as_in_classic_corporate(open_app):
    app = open_app()
    page = app.page
    assert page.locator('select[aria-label="Select language"]').count() == 0
    _profile(page)
    select = page.locator('select[aria-label="Select language"]')
    assert select.count() == 1 and select.input_value() == 'en'
    assert page.locator('header.cr-header select').count() == 0
    # a pinned language says so in My Profile and offers no switch
    locked = open_app(extra={('GET', '/api/interface/lock'): (200, {'layout': '', 'language': 'en', 'admins': True})})
    locked.page.wait_for_timeout(500)
    _profile(locked.page)
    assert locked.page.locator('[data-ui-lock="language"]').count() == 1
    assert locked.page.locator('select[aria-label="Select language"]').count() == 0
    # classic Corporate still keeps it out of its header
    classic = open_app(layout='corporate')
    assert classic.page.locator('header select[aria-label="Select language"]').count() == 0
    _no_errors(app)


# --- sidebar -----------------------------------------------------------------------------------

def test_runtime_the_sidebar_resizes_and_keeps_it_under_its_own_key(open_app):
    app = open_app()
    page = app.page
    assert _side_width(page) == 264
    grip = page.locator('[data-cr-side-handle]').bounding_box()
    page.mouse.move(grip['x'] + 3, grip['y'] + 200)
    page.mouse.down()
    page.mouse.move(grip['x'] + 50, grip['y'] + 200, steps=5)
    page.mouse.move(grip['x'] + 83, grip['y'] + 200, steps=5)
    page.mouse.up()
    assert abs(_side_width(page) - 344) <= 2
    page.locator('[data-cr-side-handle]').focus()
    page.keyboard.press('ArrowLeft')
    assert abs(_side_width(page) - 328) <= 2
    stored = page.evaluate('() => [localStorage.getItem("cr-sidebar-w"), localStorage.getItem("corp-sidebar-w")]')
    assert abs(int(stored[0]) - 328) <= 2 and stored[1] is None
    # it stops at its limits
    for _ in range(30):
        page.keyboard.press('ArrowRight')
    assert _side_width(page) == 520
    page.reload()
    app.wait_for_app()
    assert _side_width(page) == 520
    page.locator('[data-cr-side-handle]').dblclick()
    assert _side_width(page) == 264
    _no_errors(app)


def test_runtime_a_big_tree_resizes_on_release_behind_a_guide_line(open_app):
    metrics = {f'pve{i}': dict(NODE_METRICS['pve1']) for i in range(1, 21)}
    guests = [dict(VM, vmid=1000 + i, name=f'g{i:04d}', node=f'pve{1 + i % 20}') for i in range(1600)]
    app = open_app(resources=guests, metrics=metrics)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function('() => document.querySelectorAll(".corp-tree-child").length > 1600', timeout=20000)
    grip = page.locator('[data-cr-side-handle]').bounding_box()
    page.mouse.move(grip['x'] + 3, grip['y'] + 200)
    page.mouse.down()
    page.mouse.move(grip['x'] + 83, grip['y'] + 200, steps=6)
    # the guide follows, the sidebar waits
    assert page.locator('.cr-side-guide').count() == 1
    assert _side_width(page) == 264
    guide_x = page.locator('.cr-side-guide').bounding_box()['x']
    page.mouse.up()
    assert page.locator('.cr-side-guide').count() == 0
    assert abs(_side_width(page) - 344) <= 2
    assert abs(guide_x + 1 - page.locator('.pp-sidebar.cr-sidebar').bounding_box()['x'] - 344) <= 3
    _no_errors(app)


def test_runtime_the_sidebar_folds_to_a_rail_and_stays_folded(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-fold]').click()
    assert _side_width(page) == 44
    assert page.locator('.cr-rail').is_visible()
    assert not page.locator('.cr-sidebar .corp-sidebar-search').is_visible()
    assert page.evaluate('() => localStorage.getItem("cr-sidebar-collapsed")') == '1'
    page.reload()
    app.wait_for_app()
    assert _side_width(page) == 44
    # a view picked on the rail opens the sidebar on it
    page.locator('.cr-rail button[aria-label="Pool View"]').click()
    assert _side_width(page) == 264
    assert page.locator('.cr-sidebar .corp-view-switcher button.active').get_attribute('title') == 'Pool View'
    page.locator('[data-cr-fold]').click()
    page.locator('.cr-rail button[aria-label="Filter..."]').click()
    page.wait_for_function('() => document.activeElement && document.activeElement.classList.contains("corp-sidebar-search")', timeout=3000)
    assert page.evaluate('() => localStorage.getItem("cr-sidebar-collapsed")') == '0'
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_own_sidebar_width(open_app):
    app = open_app(layout='corporate', storage={'cr-sidebar-w': '400', 'cr-sidebar-collapsed': '1'})
    page = app.page
    assert round(page.locator('.pp-sidebar').bounding_box()['width']) == 224
    assert page.locator('.cr-rail, [data-cr-side-handle], [data-cr-fold]').count() == 0
    assert page.locator('.corp-resize-handle').count() == 1
    _no_errors(app)


def test_runtime_the_tree_walks_with_the_arrow_keys(open_app):
    app = open_app()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    first = page.locator('.cr-sidebar .corp-tree-child').first
    first.wait_for(timeout=5000)
    first.focus()
    page.keyboard.press('ArrowDown')
    page.keyboard.press('ArrowDown')
    assert page.evaluate('() => document.activeElement.innerText.trim()') == 'ct01'
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 4', timeout=5000)
    assert _crumbs(page)[-1] == 'ct01'
    _no_errors(app)


def test_runtime_the_notice_stays_in_the_sidebar_and_the_footer(open_app):
    app = open_app()
    page = app.page
    notices = page.locator('#pegaprox-legal-notice')
    assert notices.count() == 2
    assert page.locator('.cr-sidebar #pegaprox-legal-notice').is_visible()
    assert page.locator('footer #pegaprox-legal-notice').count() == 1
    page.locator('[data-cr-fold]').click()
    # folded, the footer one is still on the page
    assert page.locator('footer #pegaprox-legal-notice').count() == 1
    _no_errors(app)


# --- task center -------------------------------------------------------------------------------

# the task table by column key: [[key, text], ...] per row
TASK_ROWS = '''() => {
    const t = document.querySelector('[data-cr-table="tasks"]');
    const keys = Array.from(t.querySelectorAll('thead th')).map(th => th.dataset.crCol);
    return Array.from(t.querySelectorAll('tbody tr.cr-row')).map(tr => {
        const o = {};
        Array.from(tr.cells).forEach((td, i) => { o[keys[i]] = td.innerText.trim(); });
        const b = tr.querySelector('.cr-badge');
        o._badge = b.className; o._title = b.title;
        return o;
    });
}'''
# round 4: a count nothing was read for yet has no number (None here)
COUNTS = '''() => Object.fromEntries(Array.from(document.querySelectorAll('.cr-tc-hit [data-cr-tc-count]'))
    .map(x => [x.dataset.crTcCount, x.dataset.n === undefined ? null : Number(x.dataset.n)]))'''


def test_runtime_the_task_center_shows_the_states_of_the_task_bar(open_app):
    app = open_app()
    page = app.page
    bar = page.locator('.cr-taskcenter')
    # the All Clusters view lists every cluster's tasks
    assert page.locator('[data-cr-tc-scopetext]').inner_text() == 'All Clusters'
    assert page.evaluate('() => document.body.dataset.crTasks') == '1'
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n === "1"', timeout=8000)
    assert page.locator('[data-cr-tc-scopetext]').inner_text() == 'Testi'
    # round 4: Cancelled is always there, Queued is not read before the drawer opened
    assert page.evaluate(COUNTS) == {'running': 1, 'queued': None, 'completed': 1, 'failed': 2, 'cancelled': 0}
    assert 'VM Migration (100)' in page.locator('[data-cr-tc-latest]').inner_text()
    assert page.locator('[data-cr-tc-latest-cluster]').inner_text() == 'Testi'
    # the bar sits on the status bar, which stays visible
    tc, sb = bar.bounding_box(), page.locator('.corp-status-bar').bounding_box()
    assert round(tc['y'] + tc['height']) == round(sb['y']) and page.locator('.corp-status-bar').is_visible()

    page.locator('[data-cr-tc-toggle]').click()
    assert page.locator('[data-cr-tc-toggle]').get_attribute('aria-expanded') == 'true'
    rows = page.evaluate(TASK_ROWS)
    assert [[r['type'], r['state']] for r in rows] == [['VM Migration', 'Running'], ['Backup', 'Done'], ['CT Start', 'Failed'], ['Snapshot', 'Failed']]
    assert [r['duration'] for r in rows] == ['10m 0s', '5m 0s', '5s', '10s']
    # a row opens the task bar's own detail dialog, with its log
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row', has_text='Backup').click()
    page.get_by_text('Task Output').first.wait_for(timeout=5000)
    assert any(p.startswith('/api/clusters/c1/nodes/pve2/tasks/') and p.endswith('/log') for _, p in app.server.calls)
    # above the header: the backdrop takes the click in the corner and closes it
    page.mouse.click(5, 5)
    page.get_by_text('Task Output').first.wait_for(state='detached', timeout=3000)
    # round 4: no Hide task bar any more; the bar itself collapses the drawer and stays
    assert page.locator('.cr-taskcenter [data-cr-tc-hidebar]').count() == 0
    page.locator('[data-cr-tc-toggle]').click()
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    assert page.locator('.cr-taskcenter').count() == 1 and page.evaluate('() => document.body.dataset.crTasks') == '1'
    assert page.locator('.cr-header-tools button[title="Tasks"]').count() == 0
    _no_errors(app)


# "WARNINGS: n": the backup ran and left something worth a look in its log
WARNED = {'upid': _upid('pve2', 5, 'vzdump', 101), 'node': 'pve2', 'type': 'vzdump', 'vmid': '101',
          'status': 'stopped', 'exitstatus': 'WARNINGS: 1', 'starttime': FIXED - 1800, 'endtime': FIXED - 1740,
          'user': 'root@pam'}


def test_runtime_a_task_that_ended_with_warnings_is_done_not_failed(open_app):
    app = open_app(extra={('GET', '/api/clusters/c1/tasks'): (200, TASKS[:1] + [WARNED] + TASKS[1:])})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n === "1"', timeout=8000)
    # the collapsed bar counts the warned backup as completed, not as failed, and says so in the tooltip
    assert page.evaluate(COUNTS) == {'running': 1, 'queued': None, 'completed': 2, 'failed': 2, 'cancelled': 0}
    assert page.locator('[data-cr-tc-count="completed"]').get_attribute('title') == '1 with warnings'
    page.locator('[data-cr-tc-toggle]').click()
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.wait_for(timeout=8000)
    rows = page.evaluate(TASK_ROWS)
    assert [[r['resource'], r['state']] for r in rows] == [['web01 (100)', 'Running'], ['ct01 (101)', 'Done'], ['db01 (102)', 'Done'],
                                                         ['ct01 (101)', 'Failed'], ['web01 (100)', 'Failed']]
    warned, ok = rows[1], rows[2]
    # done, in the warning tone, and the badge and the result tell what the task said
    assert 'cr-badge-warning' in warned['_badge'] and warned['_title'] == 'WARNINGS: 1' and warned['result'].startswith('WARNINGS: 1')
    assert 'cr-badge-success' in ok['_badge'] and ok['_title'] == ''
    chips = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('.cr-taskcenter [data-cr-filter]'))
        .map(b => [b.dataset.crFilter, b.querySelector('.cr-seg-n').innerText]))''')
    assert chips['failed'] == '2' and chips['completed'] == '2' and chips['all'] == '5'
    page.locator('.cr-taskcenter [data-cr-filter="failed"]').click()
    shown = [r['resource'] for r in page.evaluate(TASK_ROWS)]
    assert shown == ['ct01 (101)', 'web01 (100)']
    _no_errors(app)


def test_runtime_classic_corporate_keeps_the_classic_task_bar(open_app):
    app = open_app(layout='corporate')
    page = app.page
    assert page.locator('.cr-taskcenter').count() == 0
    assert page.locator('.pp-taskbar .cursor-pointer').count() == 1
    assert page.evaluate('() => document.body.dataset.crTasks || null') is None
    _no_errors(app)


def test_runtime_the_skin_adds_no_dom_per_guest(open_app):
    """The sidebar of the preview is the classic tree: the same rows, nothing extra per guest."""
    metrics = {f'pve{i}': dict(NODE_METRICS['pve1']) for i in range(1, 11)}
    guests = [dict(VM if i % 4 else CT, vmid=1000 + i, name=f'g{i:04d}', node=f'pve{1 + i % 10}') for i in range(400)]
    counts = {}
    for layout in ('corporate', LAYOUT):
        app = open_app(layout=layout, resources=guests, metrics=metrics)
        page = app.page
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.wait_for_function('() => document.querySelectorAll(".corp-tree-child").length >= 410', timeout=20000)
        counts[layout] = page.evaluate('() => document.querySelector(".corp-inline-tree").getElementsByTagName("*").length')
        _no_errors(app)
    assert counts['corporate'] == counts[LAYOUT], counts
