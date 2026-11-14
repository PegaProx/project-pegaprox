"""CrTable, the dense table of Corporate Redesigned (Preview), in the browser.

Its first real user is the task center: sorting, the status filter, the resource filter,
resizing and hiding a column, and that both survive a reload. The task list stops at 50, so for the
big-list behaviour (only the rows in view in the DOM, sticky header, keyboard, the loading,
empty and error rows, storage that throws) the test takes the CrTable component from the
React fiber of the task center's table and mounts it again with its own rows, next to the
app, under the same skin. Nothing in the bundle exists for the test. LW Oct 2026
"""
import json

import pytest

from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp, _GuardServer

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
def app(browser):
    a = _GuardApp(browser, _GuardServer(layout=LAYOUT))
    yield a
    a.close()


def _open_tasks(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    # round 4: the drawer comes back open after a reload when it was left open, so only a closed one is opened
    toggle = page.locator('[data-cr-tc-toggle]')
    toggle.wait_for(timeout=8000)
    if toggle.get_attribute('aria-expanded') != 'true':
        toggle.click()
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.wait_for(timeout=8000)


def _rows(page, table='tasks'):
    return page.evaluate(f'''() => Array.from(document.querySelectorAll('[data-cr-table="{table}"] tbody tr.cr-row'))
        .map(tr => Array.from(tr.cells).map(td => td.innerText.trim()))''')


def _col(page, key, table='tasks'):
    return page.locator(f'[data-cr-table="{table}"] th[data-cr-col="{key}"]')


def _no_errors(app):
    assert not app.errors, app.errors


# --- through the task center -------------------------------------------------------------------

def test_runtime_sort_filter_and_search(app):
    page = app.page
    _open_tasks(page)
    assert len(_rows(page)) == 4
    status = _col(page, 'state')
    assert status.get_attribute('aria-sort') == 'none'
    status.locator('button').click()
    assert status.get_attribute('aria-sort') == 'ascending'
    # by urgency: running, queued, failed, cancelled, done
    assert [r[0] for r in _rows(page)] == ['Running', 'Failed', 'Failed', 'Done']
    status.locator('button').click()
    assert status.get_attribute('aria-sort') == 'descending'
    assert [r[0] for r in _rows(page)] == ['Done', 'Failed', 'Failed', 'Running']
    status.locator('button').click()
    assert status.get_attribute('aria-sort') == 'none'

    page.locator('[data-cr-filter="failed"]').click()
    assert sorted(r[1] for r in _rows(page)) == ['CT Start', 'Snapshot']
    assert page.locator('[data-cr-filter="failed"]').get_attribute('aria-pressed') == 'true'
    page.locator('[data-cr-filter="all"]').click()
    page.get_by_placeholder('Filter by guest, VMID or node').fill('db01')
    assert [r[1] for r in _rows(page)] == ['Backup']
    assert page.locator('[data-cr-table="tasks"] .cr-table-count').inner_text() == '1 of 4'
    page.get_by_placeholder('Filter by guest, VMID or node').fill('nothing like it')
    assert page.locator('[data-cr-table="tasks"] td.cr-state').inner_text() == 'Nothing matches the filter'
    _no_errors(app)


def test_runtime_a_column_resizes_hides_and_both_survive_a_reload(app):
    page = app.page
    _open_tasks(page)
    th = _col(page, 'node')
    before = th.bounding_box()['width']
    grip = th.locator('.cr-col-grip').bounding_box()
    page.mouse.move(grip['x'] + 3, grip['y'] + 10)
    page.mouse.down()
    page.mouse.move(grip['x'] + 40, grip['y'] + 10, steps=4)
    page.mouse.move(grip['x'] + 63, grip['y'] + 10, steps=4)
    page.mouse.up()
    after = th.bounding_box()['width']
    assert abs(after - before - 60) <= 2, (before, after)
    # the keyboard does the same in steps of 16
    th.locator('.cr-col-grip').focus()
    page.keyboard.press('ArrowLeft')
    assert abs(th.bounding_box()['width'] - (after - 16)) <= 2

    page.locator('[data-cr-table="tasks"] [data-cr-colmenu]').click()
    page.locator('.cr-menu input[data-cr-col="user"]').uncheck()
    page.keyboard.press('Escape')
    assert _col(page, 'user').count() == 0
    stored = json.loads(page.evaluate('() => localStorage.getItem("cr-table:tasks")'))
    assert stored['h'] == {'user': True} and abs(stored['w']['node'] - (after - 16)) <= 2

    page.reload()
    app.wait_for_app()
    _open_tasks(page)
    assert _col(page, 'user').count() == 0
    assert abs(_col(page, 'node').bounding_box()['width'] - (after - 16)) <= 2
    # reset brings the defaults back and forgets the key
    page.locator('[data-cr-table="tasks"] [data-cr-colmenu]').click()
    page.locator('[data-cr-reset]').click()
    assert _col(page, 'user').count() == 1
    assert abs(_col(page, 'node').bounding_box()['width'] - before) <= 2
    assert page.evaluate('() => localStorage.getItem("cr-table:tasks")') is None
    _no_errors(app)


def test_runtime_the_last_visible_column_cannot_be_hidden(app):
    page = app.page
    _open_tasks(page)
    page.locator('[data-cr-table="tasks"] [data-cr-colmenu]').click()
    boxes = page.locator('.cr-menu input[type="checkbox"]')
    for i in range(boxes.count() - 1):
        boxes.nth(i).uncheck()
    last = boxes.nth(boxes.count() - 1)
    assert last.is_checked() and last.is_disabled()
    assert page.locator('[data-cr-table="tasks"] thead th').count() == 1
    _no_errors(app)


# --- the component on its own ------------------------------------------------------------------

MOUNT = '''(opts) => {
    if (!window.__crProbe) {
        const host = document.querySelector('[data-cr-table="tasks"]');
        const key = Object.keys(host).find(k => k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$'));
        let f = host[key], Table = null, Ctx = null, value = null;
        while (f) {
            if (!Table && f.type && f.type.name === 'CrTable') Table = f.type;
            if (f.type && f.type._context && f.memoizedProps && f.memoizedProps.value
                && typeof f.memoizedProps.value.t === 'function') { Ctx = f.type._context; value = f.memoizedProps.value; break; }
            f = f.return;
        }
        const el = document.createElement('div');
        el.id = 'cr-probe';
        el.style.cssText = 'position:fixed;top:60px;left:320px;width:900px;height:420px;z-index:9999;display:flex;flex-direction:column';
        document.body.appendChild(el);
        const root = ReactDOM.createRoot ? ReactDOM.createRoot(el) : null;
        window.__crProbe = { Table, Ctx, value, root, el, clicked: [] };
    }
    const p = window.__crProbe;
    const rows = Array.from({ length: opts.n }, (_, i) => ({
        id: 'r' + i, name: 'guest-' + String(i).padStart(4, '0'), cpu: (i * 37) % 100, node: 'pve' + (i % 7) }));
    const columns = [
        { key: 'name', label: 'Name', flex: true, min: 120 },
        { key: 'cpu', label: 'CPU', width: 90, align: 'right', render: r => r.cpu + '%' },
        { key: 'node', label: 'Node', width: 110 },
    ];
    const props = { id: 'probe', columns, rows, rowKey: r => r.id, searchable: true, maxHeight: opts.maxHeight || 300,
                    loading: !!opts.loading, error: opts.error || null, emptyText: opts.emptyText,
                    onRowClick: r => p.clicked.push(r.id) };
    const tree = React.createElement(p.Ctx.Provider, { value: p.value }, React.createElement(p.Table, props));
    if (p.root) p.root.render(tree); else ReactDOM.render(tree, p.el);
    return !!p.Table && !!p.Ctx;
}'''


def _mount(page, **opts):
    assert page.evaluate(MOUNT, opts)
    page.wait_for_timeout(150)


def _probe_rows(page):
    return page.evaluate('''() => Array.from(document.querySelectorAll('#cr-probe tbody tr.cr-row'))
        .map(tr => tr.cells[0].innerText)''')


@pytest.fixture
def probe(app):
    _open_tasks(app.page)
    return app


def test_runtime_a_big_list_keeps_only_the_rows_in_view(probe):
    page = probe.page
    _mount(page, n=1000)
    rendered = _probe_rows(page)
    assert rendered[0] == 'guest-0000' and 10 < len(rendered) < 60, len(rendered)
    heights = page.evaluate('''() => Array.from(document.querySelectorAll('#cr-probe tbody tr.cr-row'))
        .slice(0, 5).map(tr => tr.getBoundingClientRect().height)''')
    assert heights == [26] * 5, heights
    scroller = page.locator('#cr-probe .cr-table-scroll')
    full = page.evaluate('() => document.querySelector("#cr-probe .cr-table-scroll").scrollHeight')
    assert abs(full - (1000 * 26 + 28)) <= 4, full
    scroller.evaluate('el => { el.scrollTop = el.scrollHeight; el.dispatchEvent(new Event("scroll")); }')
    page.wait_for_timeout(150)
    rendered = _probe_rows(page)
    assert rendered[-1] == 'guest-0999' and len(rendered) < 60
    # the header stays on top of the scrolled rows
    tops = page.evaluate('''() => [document.querySelector('#cr-probe .cr-table-scroll').getBoundingClientRect().top,
                                   document.querySelector('#cr-probe thead th').getBoundingClientRect().top]''')
    assert abs(tops[0] - tops[1]) <= 1, tops
    # sorting and searching work on all rows, not on the rendered window
    page.locator('#cr-probe th[data-cr-col="name"] button').click()
    page.locator('#cr-probe th[data-cr-col="name"] button').click()
    scroller.evaluate('el => { el.scrollTop = 0; el.dispatchEvent(new Event("scroll")); }')
    page.wait_for_timeout(100)
    assert _probe_rows(page)[0] == 'guest-0999'
    page.locator('#cr-probe input[type="search"]').fill('guest-0500')
    assert _probe_rows(page) == ['guest-0500']
    _no_errors(probe)


def test_runtime_a_small_list_is_drawn_whole(probe):
    page = probe.page
    _mount(page, n=150)
    assert len(_probe_rows(page)) == 150
    _no_errors(probe)


def test_runtime_the_keyboard_walks_the_rows(probe):
    page = probe.page
    _mount(page, n=500)
    page.locator('#cr-probe tbody tr.cr-row').first.focus()
    for _ in range(3):
        page.keyboard.press('ArrowDown')
    assert page.evaluate('() => document.activeElement.dataset.rowIndex') == '3'
    page.keyboard.press('Enter')
    assert page.evaluate('() => window.__crProbe.clicked') == ['r3']
    page.keyboard.press('End')
    page.wait_for_timeout(100)
    assert page.evaluate('() => [document.activeElement.dataset.rowIndex, document.activeElement.cells[0].innerText]') \
        == ['499', 'guest-0499']
    page.keyboard.press('Home')
    page.wait_for_timeout(100)
    assert page.evaluate('() => document.activeElement.dataset.rowIndex') == '0'
    # one row is in the tab order, the focused one
    assert page.evaluate('() => document.querySelectorAll("#cr-probe tbody tr[tabindex=\\"0\\"]").length') == 1
    _no_errors(probe)


@pytest.mark.parametrize('opts,text', [
    ({'n': 0, 'loading': True}, 'Loading...'),
    ({'n': 0, 'error': 'Read failed: 500'}, 'Read failed: 500'),
    ({'n': 0}, 'Nothing to show'),
    ({'n': 0, 'emptyText': 'No guests here'}, 'No guests here'),
])
def test_runtime_loading_error_and_empty_get_a_row_of_their_own(probe, opts, text):
    page = probe.page
    _mount(page, **opts)
    state = page.locator('#cr-probe td.cr-state')
    assert state.inner_text().strip() == text
    assert (state.get_attribute('role') == 'alert') == ('error' in opts)
    _no_errors(probe)


def test_runtime_storage_that_throws_breaks_nothing(probe):
    page = probe.page
    page.evaluate('''() => {
        Storage.prototype.getItem = () => { throw new Error('blocked'); };
        Storage.prototype.setItem = () => { throw new Error('blocked'); };
        Storage.prototype.removeItem = () => { throw new Error('blocked'); };
    }''')
    _mount(page, n=40)
    th = page.locator('#cr-probe th[data-cr-col="node"]')
    before = th.bounding_box()['width']
    th.locator('.cr-col-grip').focus()
    page.keyboard.press('ArrowRight')
    assert abs(th.bounding_box()['width'] - before - 16) <= 2
    page.locator('#cr-probe [data-cr-colmenu]').click()
    page.locator('.cr-menu input[data-cr-col="cpu"]').uncheck()
    assert page.locator('#cr-probe th[data-cr-col="cpu"]').count() == 0
    _no_errors(probe)
