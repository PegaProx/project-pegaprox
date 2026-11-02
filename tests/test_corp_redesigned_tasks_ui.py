"""The global task center of Corporate Redesigned (Preview) in the browser.

The collapsed bar is one control across the whole width and counts the tasks in scope; the
drawer above it lists them in a CrTable with filters, a live duration, progress only where the
task log reports one, the exit text of a failed task and its log on demand, links into the
inventory, and the classic detail dialog with its cancel button. "All clusters" shows the SSE
frames the stream already carries and reads the other clusters once when the drawer opens,
at most four at a time. Queued rows come from the bulk migration and batch restore registries.

The server hands a finished PVE task over with the exit text in status and no exitstatus
(manager.get_tasks); once that is fixed the shape of #590 arrives (stopped plus exitstatus).
Both have to give the same states, so the counts run against both.

PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the round 1 build).
Runs against the fake server of tests/test_ha_ui.py and skips without Playwright. LW Oct 2026
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import time
import urllib.parse

import pytest

from test_corp_redesigned_dashboard_ui import EDGE, PROD, PROD_GUESTS, _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, NODE_METRICS, _GuardApp
from test_ha_ui import BASE, CLUSTER, TOASTS_JS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None


def _upid(node, n, kind, vmid, user='root@pam'):
    return f'UPID:{node}:{n:08X}:00000000:{FIXED - n:08X}:{kind}:{vmid}:{user}:'


def _task(node, n, kind, vmid, result, age, took=None, **kw):
    """One task; result is 'running' or the text PVE ended it with."""
    t = {'upid': _upid(node, n, kind, vmid), 'node': node, 'type': kind, 'id': str(vmid) if vmid != '' else '',
         'user': 'root@pam', 'starttime': FIXED - age, '_result': result}
    if vmid != '':
        t['vmid'] = vmid if not str(vmid).isdigit() else int(vmid)
    if result != 'running':
        t['endtime'] = FIXED - age + (took if took is not None else 30)
    t.update(kw)
    return t


def shaped(tasks, shape):
    """real: what the server sends today (the exit text in status). 590: stopped + exitstatus."""
    out = []
    for t in tasks:
        t = dict(t)
        result = t.pop('_result')
        if result == 'running':
            t['status'] = 'running'
        elif shape == 'real':
            t['status'] = result
        else:
            t['status'], t['exitstatus'] = 'stopped', result
        out.append(t)
    return out


RUN = _task('pve1', 1, 'qmigrate', 100, 'running', 600, pegaprox_user='admin')
OK = _task('pve2', 2, 'vzdump', 102, 'OK', 3600, 300)
WARN = _task('pve2', 3, 'vzdump', 101, 'WARNINGS: 2', 3700, 60)
ERR = _task('pve1', 4, 'vzdump', 100, 'job errors', 3800, 45)
INT = _task('pve1', 5, 'qmigrate', 101, 'interrupted by signal', 3900, 20)
CMD = _task('pve2', 6, 'qmstart', 102, "command 'qmstart 102' failed: exit code 1", 4000, 2)
NODE = _task('pve2', 7, 'aptupdate', '', 'OK', 4100, 12)
UNKNOWN = _task('pve1', 8, 'qmstart', 999, 'OK', 4200, 3)
C1 = [RUN, OK, WARN, ERR, INT, CMD, NODE, UNKNOWN]
# label, tone of the badge, the result text the row shows
WANT = {
    RUN['upid']: ('Running', 'info', ''),
    OK['upid']: ('Done', 'success', 'OK'),
    WARN['upid']: ('Done', 'warning', 'WARNINGS: 2'),
    ERR['upid']: ('Failed', 'error', 'job errors'),
    INT['upid']: ('Cancelled', 'warning', 'interrupted by signal'),
    CMD['upid']: ('Failed', 'error', "command 'qmstart 102' failed: exit code 1"),
    NODE['upid']: ('Done', 'success', 'OK'),
    UNKNOWN['upid']: ('Done', 'success', 'OK'),
}
COUNTS = {'running': 1, 'queued': 0, 'completed': 4, 'failed': 2, 'cancelled': 1}

C2_RUN = _task('prod1', 11, 'qmigrate', 200, 'running', 300)
C2_ERR = _task('prod2', 12, 'vzdump', 201, 'job errors', 5000, 60)
C2 = [C2_RUN, C2_ERR]

LOG_RUN = ['task started by HA resource agent', 'drive-scsi0: transferred 1.1 GiB of 32.0 GiB (3.44%) in 10s']
LOG_ERR = ['INFO: starting new backup job: vzdump 100 --mode snapshot', 'ERROR: Backup of VM 100 failed - job errors',
           'INFO: Failed at 2026-10-30 07:57:05']

SSE = """(() => {
    const made = [];
    class Live {
        constructor(url) {
            this.url = String(url); this.readyState = 0;
            this.onopen = this.onmessage = this.onerror = null;
            made.push(this);
            setTimeout(() => { this.readyState = 1; this.onopen && this.onopen({}); }, 10);
        }
        addEventListener() {}
        removeEventListener() {}
        close() { this.readyState = 2; }
    }
    window.EventSource = Live;
    window.__sse = {
        made,
        say: (o) => made.filter(s => s.readyState === 1).forEach(s => s.onmessage && s.onmessage({ data: JSON.stringify(o) })),
    };
})();"""

# every interval the page starts from now on, with its delay. Evaluated once the page runs:
# the fixed clock of the harness puts its own timers in place before any init script of ours
INTERVALS = """(() => {
    const live = new Map();
    const set = window.setInterval, clear = window.clearInterval;
    window.setInterval = function (fn, ms, ...a) { const id = set.call(window, fn, ms, ...a); live.set(id, ms); return id; };
    window.clearInterval = function (id) { live.delete(id); return clear.call(window, id); };
    window.__secondBeats = () => Array.from(live.values()).filter(ms => ms === 1000).length;
})();"""

LONGTASKS = """(() => {
    window.__long = [];
    try {
        new PerformanceObserver(l => l.getEntries().forEach(e => window.__long.push(Math.round(e.duration))))
            .observe({ entryTypes: ['longtask'] });
    } catch (e) {}
})();"""


class _TaskServer(_DashServer):
    """The dashboard fake plus task lists per cluster, task logs, cancel, and the two job
    registries. Reads of the listed clusters can be held to count what is in flight."""

    def __init__(self, shape='real', lists=None, logs=None, bulk=None, restores=None, sse=False,
                 cancel=(200, {'success': True}), extra=None, **kw):
        reads = {('GET', '/api/bulk-migrations'): (200, {'runs': list(bulk or [])}),
                 ('GET', '/api/batch-restores'): (200, {'runs': list(restores or [])}),
                 ('POST', '/api/sse/subscribe'): (200, {'success': True})}
        if sse:
            reads[('POST', '/api/sse/token')] = (200, {'token': 'tok', 'expires_in': 600})
        reads.update(extra or {})
        super().__init__(extra=reads, bundle=BUNDLE, **kw)
        self.shape = shape
        self.lists = {'c1': shaped(C1, shape), 'c2': shaped(C2, shape)} if lists is None else lists
        self.logs = {RUN['upid']: list(LOG_RUN), ERR['upid']: list(LOG_ERR)} if logs is None else logs
        self.cancel = cancel
        self.hold = set()       # cluster ids whose task reads wait for release()
        self.held_tasks = []
        self.log_reads = []     # (cluster, node, upid, start)
        self.deletes = []

    def release_tasks(self, n=None):
        take = self.held_tasks[:n] if n else self.held_tasks
        self.held_tasks = self.held_tasks[len(take):]
        for route, cid in take:
            route.fulfill(status=200, body=json.dumps(self.lists.get(cid, [])), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        if req.url.startswith(BASE):
            path = urllib.parse.unquote(re.sub(r'^https?://[^/]+', '', req.url).split('?')[0])
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(req.url).query)

            def answer(data, status=200):
                self.calls.append((req.method, path))
                self.urls.append(req.url)
                return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

            m = re.fullmatch(r'/api/clusters/([^/]+)/nodes/([^/]+)/tasks/(.+)/log', path)
            if m and req.method == 'GET':
                start = int(query.get('start', ['0'])[0])
                self.log_reads.append((m.group(1), m.group(2), m.group(3), start))
                lines = self.logs.get(m.group(3), [])[start:]
                return answer({'log': '\n'.join(lines), 'lines': lines})
            m = re.fullmatch(r'/api/clusters/([^/]+)/nodes/([^/]+)/tasks/(.+)', path)
            if m and req.method == 'DELETE':
                self.deletes.append((m.group(1), m.group(2), m.group(3)))
                return answer(self.cancel[1], self.cancel[0])
            m = re.fullmatch(r'/api/clusters/([^/]+)/tasks', path)
            if m and req.method == 'GET' and m.group(1) in self.lists:
                if m.group(1) in self.hold:
                    self.calls.append((req.method, path))
                    self.held_tasks.append((route, m.group(1)))
                    return None
                return answer(self.lists[m.group(1)])
        return super().handle(route)


class _Browser:
    """The browser, its pages started with the given scripts."""

    def __init__(self, browser, scripts):
        self._browser, self._scripts = browser, scripts

    def new_context(self, **kw):
        ctx = self._browser.new_context(**kw)
        for s in self._scripts:
            ctx.add_init_script(s)
        return ctx


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

    def _open(layout=LAYOUT, theme='', storage=None, viewport=(1600, 1000), scripts=(), **kw):
        sse = kw.get('sse', False)
        server = _TaskServer(layout=layout, **kw)
        wrapped = _Browser(browser, ([SSE] if sse else []) + list(scripts))
        app = _GuardApp(wrapped, server, corp_theme=theme, storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -----------------------------------------------------------------------------------

def _need(page, selector, what, timeout=8000):
    """Wait for a selector; a missing one fails with the property it stands for."""
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _click(page, selector, what):
    _need(page, selector, what)
    page.locator(selector).first.click()


def _bar(page):
    _need(page, '.cr-tc-hit', 'the collapsed bar is one button across the whole width')
    return page.locator('.cr-tc-hit')


# the toggle and the task table carry the same hooks as in round 1, so a test of something
# round 1 already showed reaches that and fails on it there, not on a missing selector
TOGGLE = '[data-cr-tc-toggle]'


def _is_open(page):
    return page.locator(TOGGLE).first.get_attribute('aria-expanded') == 'true'


def _open(page):
    _need(page, TOGGLE, 'the task center has its toggle')
    if not _is_open(page):
        page.locator(TOGGLE).first.click()
    _need(page, '[data-cr-table="tasks"] tbody tr', 'the toggle opens the task list')


def _pick_testi(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=10000)


ROWS = '''() => {
    const t = document.querySelector('[data-cr-table="tasks"]');
    if (!t) return null;
    const keys = Array.from(t.querySelectorAll('thead th')).map(th => th.dataset.crCol);
    return Array.from(t.querySelectorAll('tbody tr.cr-row')).map(tr => {
        const o = {};
        Array.from(tr.cells).forEach((td, i) => { o[keys[i]] = td.innerText.trim(); });
        const k = tr.querySelector('[data-cr-tc-key]');
        o._key = k ? k.dataset.crTcKey.split('|').slice(1).join('|') : '';
        const b = tr.querySelector('.cr-badge');
        o._badge = b ? b.className : '';
        o._title = b ? b.title : '';
        o._busy = !!tr.querySelector('[data-cr-tc-busy]');
        const p = tr.querySelector('[data-cr-tc-pct]');
        o._pct = p ? p.dataset.crTcPct : null;
        o._links = Array.from(tr.querySelectorAll('[data-cr-tc-target]')).map(x => x.dataset.crTcTarget + ':' + x.innerText.trim());
        o._showlog = !!tr.querySelector('[data-cr-tc-showlog]');
        o._buttons = Array.from(tr.querySelectorAll('button')).map(x => x.innerText.trim());
        return o;
    });
}'''


def _rows(page):
    return page.evaluate(ROWS) or []


def _counts(page):
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('.cr-tc-hit [data-cr-tc-count]'))
        .map(x => [x.dataset.crTcCount, Number(x.dataset.n)]))''')


def _wait_rows(page, n, what):
    try:
        page.wait_for_function('(n) => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === n', arg=n, timeout=8000)
    except Exception:
        raise AssertionError(f'{what}: {len(_rows(page))} rows instead of {n}') from None


def _no_errors(app):
    assert not app.errors, app.errors


def _tasks_reads(server, cid=None):
    return [p for m, p in server.calls if m == 'GET' and re.fullmatch(r'/api/clusters/[^/]+/tasks', p)
            and (cid is None or p == f'/api/clusters/{cid}/tasks')]


# --- the collapsed bar -------------------------------------------------------------------------

@pytest.mark.parametrize('where', [0.05, 0.5, 0.95])
def test_runtime_the_whole_bar_opens_the_drawer(open_app, where):
    app = open_app()
    page = app.page
    bar = _bar(page)
    box = bar.bounding_box()
    assert box['width'] >= 1599 and box['height'] >= 32, ('the bar spans the width and is at least 32 px high', box)
    assert bar.evaluate('b => b.tagName') == 'BUTTON' and bar.get_attribute('aria-expanded') == 'false'
    # round 4: the bar is the header, a chevron shows its state and the name says what a press does;
    # no "Show tasks" or "Hide tasks" words next to it (the same toggle twice)
    assert bar.get_attribute('aria-label') == 'Show tasks' and bar.locator('.cr-tc-chev svg').count() == 1
    assert not re.search(r'(Show|Hide) tasks', bar.inner_text()), bar.inner_text()
    page.mouse.click(box['x'] + box['width'] * where, box['y'] + box['height'] / 2)
    _need(page, '#cr-tc-drawer', f'a click at {int(where * 100)} % of the bar opens the drawer', timeout=3000)
    assert bar.get_attribute('aria-expanded') == 'true' and bar.get_attribute('aria-label') == 'Hide tasks'
    ctl = bar.get_attribute('aria-controls')
    assert ctl and page.locator(f'#{ctl}').count() == 1, 'aria-controls names the drawer'
    # open, the same bar sits on top of the drawer, and the panel still ends on the status bar
    page.wait_for_timeout(300)
    top = page.locator('[data-cr-tc-bar]').bounding_box()
    drawer = page.locator('#cr-tc-drawer').bounding_box()
    status = page.locator('.corp-status-bar').bounding_box()
    assert abs(top['y'] + top['height'] - drawer['y']) <= 1.5, ('the drawer hangs under the bar', top, drawer)
    assert abs(drawer['y'] + drawer['height'] - status['y']) <= 1.5, ('the drawer ends on the status bar', drawer, status)
    _no_errors(app)


def _press(page, x, y, hold=120):
    """A real press: down, a short hold, up. Classic Corporate shrinks a pressed button, so a
    release near the edge of a wide one can land beside it."""
    page.mouse.move(x, y)
    page.mouse.down()
    page.wait_for_timeout(hold)
    page.mouse.up()


def test_runtime_a_press_on_the_outer_edges_of_the_bar_opens_it_too(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    box = _bar(page).bounding_box()
    w, y = box['width'], box['y'] + box['height'] / 2
    for x in (2, 12, w / 2, w - 12, w - 3):
        _press(page, x, y)
        try:
            page.locator('#cr-tc-drawer').wait_for(timeout=1500)
        except Exception:
            raise AssertionError(f'a press at x={int(x)} of the {int(w)} px bar opens the drawer') from None
        page.locator(TOGGLE).click()
        page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    # the wide controls in the drawer take a press at their edge as well: a column head and a menu entry
    _open(page)
    head = page.locator('[data-cr-table="tasks"] th[data-cr-col="type"]')
    hb = head.locator('.cr-th-btn').bounding_box()
    _press(page, hb['x'] + 2, hb['y'] + hb['height'] / 2)
    page.wait_for_timeout(200)
    assert head.get_attribute('aria-sort') != 'none', 'a press at the edge of a column head sorts by it'
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.focus()
    page.keyboard.press('Shift+F10')
    item = page.locator('.corp-context-menu button', has_text='Show log')
    item.wait_for(timeout=3000)
    ib = item.bounding_box()
    _press(page, ib['x'] + ib['width'] - 2, ib['y'] + ib['height'] / 2)
    _need(page, '[data-cr-tc-log]', 'a press at the edge of a menu entry runs it', timeout=3000)
    _no_errors(app)


def test_runtime_it_opens_closes_and_reopens_and_the_focus_goes_back_to_the_bar(open_app):
    app = open_app()
    page = app.page
    bar = _bar(page)
    focused = '() => document.activeElement && document.activeElement.classList.contains("cr-tc-hit")'
    # round 4: the bar closes it (on its button, or beside its own controls) and so does Escape
    for how in ('bar', 'edge', 'escape', 'bar', 'edge', 'escape'):
        bar.click()
        _need(page, '#cr-tc-drawer', f'the drawer opens again (before closing it by {how})', timeout=3000)
        page.locator('[data-cr-table="tasks"] [data-cr-filter="all"]').focus()
        if how == 'bar':
            bar.click()
        elif how == 'edge':
            _need(page, '[data-cr-tc-bar]', 'the bar is the header of the open drawer')
            box = page.locator('[data-cr-tc-bar]').bounding_box()
            page.mouse.click(box['x'] + box['width'] - 3, box['y'] + box['height'] / 2)
        else:
            page.keyboard.press('Escape')
        page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
        assert bar.get_attribute('aria-expanded') == 'false'
        assert page.evaluate(focused), f'the focus is back on the bar after closing by {how}'
    # the keyboard toggles it as a button does
    bar.focus()
    page.keyboard.press('Enter')
    _need(page, '#cr-tc-drawer', 'Enter opens the drawer', timeout=3000)
    page.keyboard.press(' ')
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    # no second or third toggle: no close button, no Hide task bar, and the bar never goes away
    bar.click()
    _need(page, '#cr-tc-drawer', 'the bar opens the drawer', timeout=3000)
    assert page.locator('[data-cr-tc-close], [data-cr-tc-hidebar]').count() == 0
    assert page.get_by_text('Hide task bar').count() == 0
    assert page.locator('.cr-taskcenter').count() == 1 and page.locator('[data-cr-tasks-show]').count() == 0
    _no_errors(app)


def test_runtime_the_focus_ring_of_the_bar_is_visible(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-palette]').focus()
    bar = _bar(page)
    bar.focus()
    page.keyboard.press('Shift+Tab')
    page.keyboard.press('Tab')
    ring = page.evaluate('() => { const s = getComputedStyle(document.activeElement); return [document.activeElement.className, s.outlineStyle, s.outlineWidth]; }')
    assert 'cr-tc-hit' in ring[0] and ring[1:] == ['solid', '2px'], ring
    _no_errors(app)


# --- what it counts, in both task shapes ---------------------------------------------------------

@pytest.mark.parametrize('shape', ['real', '590'])
def test_runtime_the_counts_and_states_follow_the_backend(open_app, shape):
    app = open_app(shape=shape)
    page = app.page
    _pick_testi(page)
    _open(page)
    _wait_rows(page, len(C1), 'every task of the cluster is listed')
    rows = _rows(page)
    for t in C1:
        label, tone, _result = WANT[t['upid']]
        row = _row(rows, t, 'the list shows every task')
        shown = (row.get('state') or row.get('status') or '', row['_badge'])
        assert shown[0] == label and f'cr-badge-{tone}' in shown[1], \
            f'{shape} shape: a task that ended with {t["_result"]!r} is {label} ({tone}), shown as {shown}'
    for t in C1:
        row = _row(rows, t, 'the list shows every task')
        assert (row.get('result') or '').replace('Show log', '').strip() == WANT[t['upid']][2], \
            f'{shape} shape: the row shows what {t["_result"]!r} said'
    assert _row(rows, WARN, 'the warned backup')['_title'] == 'WARNINGS: 2'
    # round 4: Queued is a number once the two registries answered (the drawer asks them on open)
    page.wait_for_function('() => document.querySelector(\'.cr-tc-hit [data-cr-tc-count="queued"]\').dataset.n !== undefined', timeout=5000)
    counts = _counts(page)
    assert counts == {**{k: v for k, v in COUNTS.items() if k != 'cancelled'}, 'cancelled': 1}, \
        f'the bar counts Running, Queued, Completed and Failed as the backend has them: {counts}'
    # the strip counts the same
    strip = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-tc-strip] [data-cr-filter]'))
        .map(b => [b.dataset.crFilter, Number(b.querySelector('.cr-seg-n').innerText)]))''')
    assert strip == {'all': 8, **COUNTS}, strip
    _no_errors(app)


def _same(row, task):
    """The row of a task: by its key, or by its start time (unique in the fake) where a build
    has no key on its rows."""
    if row.get('_key'):
        return row['_key'] == task['upid']
    return row.get('starttime') == datetime.datetime.fromtimestamp(task['starttime']).strftime('%d.%m.%Y, %H:%M:%S')


def _row(rows, task, what):
    hit = [r for r in rows if _same(r, task)]
    assert hit, f'{what}: no row for the task {task["type"]} {task.get("vmid", "")} started {task["starttime"]}'
    return hit[0]


def _toast(page, text, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if any(text in x for x in page.evaluate(TOASTS_JS)):
            return
        page.wait_for_timeout(100)
    raise AssertionError(f'no toast saying {text!r}: {page.evaluate(TOASTS_JS)}')


DERIVE = r'''
const table = JSON.parse(process.argv[1]);
const out = table.map(([task]) => crTaskState(task) + (crTaskWarned(task) ? '+warned' : ''));
console.log(JSON.stringify(out));
'''


def test_the_state_rule_takes_both_shapes_and_xcpng():
    """The rule as the bundle under test has it (compiled, the functions keep their names)."""
    node = shutil.which('node')
    if not node:
        pytest.skip('no node here')
    src = BUNDLE or open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    start = src.find('function crTaskResult(')
    start = start if start >= 0 else src.index('function crTaskState(')
    end = src.index('const CR_TASK_TONE', start)
    table = [
        [{'status': 'running'}, 'running'],
        [{'starttime': 1}, 'running'],
        [{'status': 'queued'}, 'queued'],
        [{'status': 'OK', 'endtime': 2}, 'done'],
        [{'status': 'stopped', 'exitstatus': 'OK'}, 'done'],
        [{'status': 'stopped'}, 'done'],
        [{'status': 'WARNINGS: 2'}, 'done+warned'],
        [{'status': 'stopped', 'exitstatus': 'WARNINGS: 1'}, 'done+warned'],
        [{'status': 'job errors'}, 'failed'],
        [{'status': 'stopped', 'exitstatus': 'job errors'}, 'failed'],
        [{'status': "command 'qmstart 102' failed: exit code 1"}, 'failed'],
        [{'status': 'unexpected status'}, 'failed'],
        [{'status': 'interrupted by signal'}, 'cancelled'],
        [{'status': 'stopped', 'exitstatus': 'interrupted by signal'}, 'cancelled'],
        [{'status': 'failed', 'exitstatus': 'job errors', 'error': 'job errors'}, 'failed'],
        [{'status': 'error'}, 'failed'],
        [{'status': 'cancelled'}, 'cancelled'],
        # XCP-ng: completed / failed and no end time
        [{'status': 'completed', 'starttime': 1}, 'done'],
        [{'status': 'failed', 'starttime': 1}, 'failed'],
    ]
    js = src[start:end] + DERIVE
    got = subprocess.run([node, '-e', js, json.dumps(table)], capture_output=True, text=True, timeout=30)
    assert got.returncode == 0, got.stderr
    wrong = [(task, want, have) for (task, want), have in zip(table, json.loads(got.stdout)) if want != have]
    assert not wrong, f'tasks that get the wrong state: {wrong}'


# --- duration, progress, the log ------------------------------------------------------------

def test_runtime_a_running_task_s_duration_and_progress_move(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    page.evaluate(INTERVALS)
    page.wait_for_timeout(600)
    beats = page.evaluate('() => window.__secondBeats()')
    _open(page)
    run = _row(_rows(page), RUN, 'the running task is listed')
    assert run['duration'] == '10m 0s', run
    app.ctx.clock.set_fixed_time(datetime.datetime.fromtimestamp(FIXED + 5, tz=datetime.timezone.utc))
    try:
        page.wait_for_function('''() => Array.from(document.querySelectorAll('[data-cr-table="tasks"] tbody tr.cr-row'))
            .some(tr => tr.innerText.includes('10m 5s'))''', timeout=4000)
    except Exception:
        raise AssertionError('the duration of a running task moves with the clock') from None
    run = _row(_rows(page), RUN, 'the running task is listed')
    assert run['_busy'] and run['_pct'] is None, ('a running task without a percentage shows a busy bar', run)
    # one 1 s beat while a running row is on screen, none once the drawer is closed
    assert page.evaluate('() => window.__secondBeats()') == beats + 1, 'a 1 s beat runs while a running task is shown'
    done = _row(_rows(page), OK, 'the finished backup is listed')
    assert done['duration'] == '5m 0s', 'a finished task keeps its duration'
    # a filter without a running row stops the beat
    _click(page, '[data-cr-filter="failed"]', 'the status filter offers Failed')
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.__secondBeats()') == beats, 'no beat without a running task on screen'
    page.locator('[data-cr-filter="all"]').click()

    # the percentage comes from the log of the open task, and moves with it
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row', has_text='10m 5s').click()
    _need(page, '[data-cr-tc-dialog]', 'a row opens the detail dialog')
    page.wait_for_function('() => document.querySelector("[data-cr-tc-dialog-progress] [data-cr-tc-pct]")', timeout=5000)
    assert page.locator('[data-cr-tc-dialog-progress] [data-cr-tc-pct]').get_attribute('data-cr-tc-pct') == '3.4'
    reads = [r for r in app.server.log_reads if r[2] == RUN['upid']]
    assert reads == [('c1', 'pve1', RUN['upid'], 0)], reads
    app.server.logs[RUN['upid']].append('drive-scsi0: transferred 15.2 GiB of 32.0 GiB (47.50%) in 2m')
    page.wait_for_function('() => document.querySelector("[data-cr-tc-dialog-progress] [data-cr-tc-pct]").dataset.crTcPct === "47.5"', timeout=5000)
    tails = [r[3] for r in app.server.log_reads if r[2] == RUN['upid']]
    assert tails[:2] == [0, 2], ('the open task reads only the new lines', tails)
    # only that task's log is read
    assert {r[2] for r in app.server.log_reads} == {RUN['upid']}
    page.keyboard.press('Escape')
    page.locator('[data-cr-tc-dialog]').wait_for(state='detached', timeout=3000)
    page.locator(TOGGLE).click()
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.__secondBeats()') == beats
    n = len(app.server.log_reads)
    page.wait_for_timeout(2500)
    assert len(app.server.log_reads) == n, 'no log is read once the task is closed'
    _no_errors(app)


def test_runtime_no_percentage_without_a_progress_line(open_app):
    logs = {RUN['upid']: ['task started', 'migration active, transferred 1.1 GiB of 4.0 GiB VM-state, 110.0 MiB/s']}
    app = open_app(logs=logs)
    page = app.page
    _pick_testi(page)
    _open(page)
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.click()
    page.get_by_text('migration active').first.wait_for(timeout=5000)
    assert page.locator('[data-cr-tc-dialog-progress] [data-cr-tc-busy]').count() == 1, \
        'a running task whose log has no percentage shows a busy bar in its dialog'
    assert page.locator('[data-cr-tc-dialog] [data-cr-tc-pct]').count() == 0, 'a throughput line is no percentage'
    _no_errors(app)


def test_runtime_a_failed_task_shows_its_error_and_its_log(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _open(page)
    err = _row(_rows(page), ERR, 'the failed backup is listed')
    assert (err.get('result') or '').startswith('job errors') and err['_showlog'], ('the exit text and Show log sit on the row', err)
    ok = _row(_rows(page), OK, 'the finished backup is listed')
    assert not ok['_showlog']
    cell = page.locator('[data-cr-table="tasks"] tbody tr.cr-row', has_text='job errors').first
    assert 'cr-tc-result-error' in cell.locator('.cr-tc-result').get_attribute('class')
    assert app.server.log_reads == [], 'no log is read before it is asked for'
    cell.locator('[data-cr-tc-showlog]').click()
    _need(page, '[data-cr-tc-log]', 'Show log opens the log next to the list')
    page.wait_for_function('() => document.querySelector("[data-cr-tc-log] pre") && document.querySelector("[data-cr-tc-log] pre").innerText.includes("ERROR: Backup of VM 100 failed")', timeout=5000)
    page.wait_for_timeout(2500)
    assert app.server.log_reads == [('c1', 'pve1', ERR['upid'], 0)], ('one read, of that task only', app.server.log_reads)
    assert 'job errors' in page.locator('[data-cr-tc-log]').inner_text()
    # the list stays usable next to it
    assert page.locator('[data-cr-table="tasks"] tbody tr.cr-row').count() == len(C1)
    page.locator('[data-cr-tc-log-close]').click()
    page.locator('[data-cr-tc-log]').wait_for(state='detached', timeout=3000)
    _no_errors(app)


def _pane_on_the_running_task(app):
    """Show log on the running migration, from the row menu, and wait until it is read again."""
    page = app.page
    _pick_testi(page)
    _open(page)
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.focus()
    page.keyboard.press('Shift+F10')
    page.locator('.corp-context-menu button', has_text='Show log').click()
    _need(page, f'[data-cr-tc-log="c1|{RUN["upid"]}"]', 'the row menu opens the log of the running task')
    for _ in range(40):
        if len([r for r in app.server.log_reads if r[2] == RUN['upid']]) >= 2:
            break
        page.wait_for_timeout(100)
    assert len(app.server.log_reads) >= 2, ('the open log of a running task is read again', app.server.log_reads)


def test_runtime_the_log_pane_reads_nothing_once_the_drawer_is_closed(open_app):
    app = open_app()
    page = app.page
    _pane_on_the_running_task(app)
    page.locator(TOGGLE).click()
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    n = len(app.server.log_reads)
    page.wait_for_timeout(5000)
    assert len(app.server.log_reads) == n, ('a closed drawer reads no log', app.server.log_reads[n:])
    # the pane went with the drawer, so opening it again reads nothing either
    page.locator(TOGGLE).click()
    _need(page, '[data-cr-table="tasks"] tbody tr.cr-row', 'the drawer opens again')
    page.wait_for_timeout(2500)
    assert page.locator('[data-cr-tc-log]').count() == 0, 'the pane closed with the drawer'
    assert len(app.server.log_reads) == n, app.server.log_reads[n:]
    _no_errors(app)


def test_runtime_a_cluster_switch_closes_the_log_pane_of_the_cluster_before(open_app):
    app = open_app()
    page = app.page
    _pane_on_the_running_task(app)
    page.locator('.corp-tree-item', has_text='Prod').first.click()
    page.wait_for_function('() => document.querySelector("[data-cr-tc-scopetext]").innerText === "Prod"', timeout=8000)
    _wait_rows(page, len(C2), "the drawer lists Prod's tasks")
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-tc-log]').count() == 0, "the pane does not keep showing a task of Testi under Prod's list"
    n = len(app.server.log_reads)
    page.wait_for_timeout(5000)
    assert len(app.server.log_reads) == n, ('nothing reads the log of the cluster before', app.server.log_reads[n:])
    _no_errors(app)


# --- navigation ----------------------------------------------------------------------------

def test_runtime_the_resource_opens_the_guest_the_node_and_the_cluster(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _open(page)
    rows = _rows(page)
    assert _row(rows, ERR, 'the failed backup is listed')['_links'] == ['guest:web01 (100)'], 'a guest of the inventory is a link'
    assert _row(rows, UNKNOWN, 'the start of an unknown guest is listed')['_links'] == [], 'a guest that is not in the inventory is plain text'
    assert _row(rows, NODE, 'the node task is listed')['_links'] == ['node:pve2'], 'a node task leads to its node'
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row', has_text='db01 (102)').first.locator('[data-cr-tc-target="guest"]').click()
    page.locator('[data-cr-objhead="vm"]').wait_for(timeout=8000)
    assert 'db01' in page.locator('[data-cr-objhead="vm"]').inner_text()
    # the drawer stays open, so the next one is a click away
    assert _is_open(page)
    page.locator('[data-cr-table="tasks"] [data-cr-tc-target="node"]').first.click()
    page.locator('[data-cr-objhead="node"]').wait_for(timeout=8000)
    assert 'pve2' in page.locator('[data-cr-objhead="node"]').inner_text()
    # all clusters: the cluster column leads to the cluster
    _click(page, '[data-cr-tc-scope-pick="all"]', 'the scope switch offers All clusters')
    page.locator('[data-cr-table="tasks"] th[data-cr-col="cluster"]').wait_for(timeout=5000)
    page.locator('[data-cr-table="tasks"] [data-cr-tc-target="cluster"]', has_text='Prod').first.wait_for(timeout=8000)
    page.locator('[data-cr-table="tasks"] [data-cr-tc-target="cluster"]', has_text='Prod').first.click()
    page.wait_for_function('() => document.querySelector("[data-cr-objhead=\\"cluster\\"]") && document.querySelector("[data-cr-objhead=\\"cluster\\"]").innerText.includes("Prod")', timeout=8000)
    _no_errors(app)


def _portal(n, vmid, kind='portalstart'):
    """A portal action as broadcast.py puts it into the list: vmid 0 when it names no guest."""
    return {'upid': f'audit-{n}', 'node': '', 'type': kind, 'status': 'stopped', 'exitstatus': 'OK',
            'starttime': FIXED - 20 - n, 'endtime': FIXED - 20 - n, 'user': '', 'pegaprox_user': 'customer',
            'id': str(vmid) if vmid else '', 'vmid': vmid, 'cluster_id': 'c1', '_portal': True}


def test_runtime_a_portal_task_without_a_guest_names_no_resource(open_app):
    app = open_app(lists={'c1': shaped(C1, 'real') + [_portal(1, 0, 'portalpassword'), _portal(2, 101)], 'c2': shaped(C2, 'real')})
    page = app.page
    _pick_testi(page)
    _open(page)
    _wait_rows(page, len(C1) + 2, 'the portal actions are listed')
    rows = {r['_key']: r for r in _rows(page)}
    assert rows['audit-1']['resource'] == '' and rows['audit-1']['_links'] == [], ('vmid 0 is no guest', rows['audit-1'])
    assert rows['audit-2']['_links'] == ['guest:ct01 (101)'], rows['audit-2']
    # and the resource filter does not find it by that 0
    page.locator('[data-cr-tc-q]').fill('0')
    page.wait_for_timeout(300)
    assert 'audit-1' not in {r['_key'] for r in _rows(page)}
    _no_errors(app)


# --- cancel --------------------------------------------------------------------------------

def test_runtime_cancel_is_the_classic_one(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _open(page)
    # no shortcut in the list: no cancel button on any row
    assert not any('Cancel' in ' '.join(r['_buttons']) for r in _rows(page))
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.click()
    page.get_by_text('Task Output').first.wait_for(timeout=5000)
    assert page.get_by_text('VM Migration (100)').count() >= 1
    page.get_by_role('button', name='Cancel task').click()
    page.get_by_text('Task Output').first.wait_for(state='detached', timeout=3000)
    # the classic one asks nothing and sends one DELETE for this cluster, node and task
    for _ in range(20):
        if app.server.deletes:
            break
        page.wait_for_timeout(100)
    assert app.server.deletes == [('c1', 'pve1', RUN['upid'])], app.server.deletes
    _toast(page, 'Task cancelled')
    page.wait_for_function('''() => Array.from(document.querySelectorAll('[data-cr-table="tasks"] tbody tr.cr-row'))
        .some(tr => tr.innerText.includes('VM Migration') && tr.querySelector('.cr-badge').innerText.trim() === 'Cancelled')''', timeout=3000)
    _no_errors(app)


def test_runtime_cancel_names_the_cluster_of_the_task_and_shows_a_refusal(open_app):
    app = open_app(cancel=(403, {'error': 'Permission denied: vm.stop'}))
    page = app.page
    _pick_testi(page)
    _open(page)
    _click(page, '[data-cr-tc-scope-pick="all"]', 'the scope switch offers All clusters, so a task of another cluster can be cancelled')
    row = page.locator('[data-cr-table="tasks"] tbody tr.cr-row', has_text='prod1').first
    row.wait_for(timeout=8000)
    row.click()
    page.get_by_text('Task Output').first.wait_for(timeout=5000)
    page.get_by_role('button', name='Cancel task').click()
    for _ in range(30):
        if app.server.deletes:
            break
        page.wait_for_timeout(100)
    assert app.server.deletes == [('c2', 'prod1', C2_RUN['upid'])], app.server.deletes
    _toast(page, 'Permission denied: vm.stop')
    _no_errors(app)


# --- filters, keyboard ------------------------------------------------------------------------

def test_runtime_the_filters_work_and_survive_a_reload(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _open(page)
    _click(page, '[data-cr-filter="failed"]', 'the status filter offers Failed')
    assert sorted(r['result'].replace('Show log', '').strip() for r in _rows(page)) == sorted(["command 'qmstart 102' failed: exit code 1", 'job errors'])
    _click(page, '[data-cr-filter="completed"]', 'the status filter offers Completed')
    assert len(_rows(page)) == 4
    page.locator('[data-cr-filter="all"]').click()
    _need(page, '[data-cr-tc-type]', 'the list filters by operation')
    page.locator('[data-cr-tc-type]').select_option('vzdump')
    assert {r['type'] for r in _rows(page)} == {'Backup'} and len(_rows(page)) == 3
    # the strip counts what the other filters leave
    assert page.locator('[data-cr-filter="failed"] .cr-seg-n').inner_text() == '1'
    page.locator('[data-cr-tc-type]').select_option('')
    page.locator('[data-cr-tc-q]').fill('pve2')
    assert len(_rows(page)) == 4 and all(r['node'] == 'pve2' for r in _rows(page))
    page.locator('[data-cr-tc-q]').fill('web01')
    assert {r['resource'] for r in _rows(page)} == {'web01 (100)'}
    page.locator('[data-cr-tc-q]').fill('102')
    assert len(_rows(page)) == 2
    page.locator('[data-cr-filter="failed"]').click()
    stored = json.loads(page.evaluate('() => localStorage.getItem("cr-tc-filters")'))
    assert stored == {'status': 'failed', 'type': '', 'cluster': '', 'q': '102'}, stored
    page.reload()
    app.wait_for_app()
    _pick_testi(page)
    _open(page)
    assert page.locator('[data-cr-filter="failed"]').get_attribute('aria-pressed') == 'true'
    assert page.locator('[data-cr-tc-q]').input_value() == '102'
    _wait_rows(page, 1, 'the remembered filters apply after a reload')
    clear = page.locator('[data-cr-tc-clearfilters]')
    assert clear.inner_text().strip() == 'Clear filters (2)'
    clear.click()
    _wait_rows(page, len(C1), 'clearing the filters shows every task again')
    # nothing matches: the empty row says it is the filter
    page.locator('[data-cr-tc-q]').fill('nothing like it')
    assert page.locator('[data-cr-table="tasks"] td.cr-state').inner_text() == 'Nothing matches the filter'
    _no_errors(app)


def test_runtime_a_remembered_cluster_that_is_gone_is_left_out(open_app):
    stored = json.dumps({'status': 'all', 'type': '', 'cluster': 'gone', 'q': ''})
    app = open_app(storage={'cr-tc-filters': stored})
    page = app.page
    _open(page)
    _need(page, '[data-cr-tc-cluster]', 'All clusters filters by cluster')
    assert page.locator('[data-cr-tc-cluster]').input_value() == ''
    page.wait_for_function('() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === 10', timeout=8000)
    _no_errors(app)


def test_runtime_keyboard_only(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _need(page, TOGGLE, 'the task center has its toggle')
    page.locator(TOGGLE).focus()
    page.keyboard.press('Enter')
    _need(page, '[data-cr-table="tasks"]', 'Enter on the bar opens the drawer')
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.wait_for(timeout=8000)
    # Tab walks into the drawer and reaches the table
    seen = []
    for _ in range(90):
        page.keyboard.press('Tab')
        where = page.evaluate('''() => { const a = document.activeElement;
            return a.closest('.cr-taskcenter') && !a.matches('[data-cr-tc-toggle]') ? (a.matches('tr.cr-row') ? 'row' : 'drawer') : 'other'; }''')
        seen.append(where)
        if where == 'row':
            break
    assert seen[0] == 'drawer' and seen[-1] == 'row', ('Tab goes from the bar into the drawer and reaches the rows', seen)
    for want in ('1', '2'):
        page.keyboard.press('ArrowDown')
        page.wait_for_function('(w) => document.activeElement.dataset.rowIndex === w', arg=want, timeout=3000)
    page.keyboard.press('Enter')
    page.get_by_text('Task Output').first.wait_for(timeout=5000)
    assert page.evaluate('() => !!document.activeElement.closest("[data-cr-tc-dialog]")'), 'the dialog takes the focus'
    page.keyboard.press('Escape')
    page.get_by_text('Task Output').first.wait_for(state='detached', timeout=3000)
    assert page.evaluate('() => document.activeElement.dataset.rowIndex') == '2', 'the focus is back on the row'
    # the row menu holds the log
    page.keyboard.press('Shift+F10')
    page.locator('.corp-context-menu').first.wait_for(timeout=3000)
    page.locator('.corp-context-menu button', has_text='Show log').click()
    _need(page, '[data-cr-tc-log]', 'the row menu opens the log')
    # the menu hands the focus back to its row and lets go of the keyboard
    page.locator('.corp-context-menu').wait_for(state='detached', timeout=3000)
    page.wait_for_function('() => document.activeElement.dataset.rowIndex === "2"', timeout=3000)
    page.keyboard.press('Escape')
    page.locator('[data-cr-tc-log]').wait_for(state='detached', timeout=3000)
    page.keyboard.press('Escape')
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    assert page.evaluate('() => document.activeElement.classList.contains("cr-tc-hit")'), 'Escape gives the focus back to the bar'
    _no_errors(app)


IN_DIALOG = '() => { const a = document.activeElement; return a && a.closest("[data-cr-tc-dialog]") ? (a.getAttribute("aria-label") || a.innerText.trim() || a.tagName) : null; }'


def test_runtime_the_dialog_holds_the_tab_key_and_hands_the_focus_back(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _open(page)
    page.locator('[data-cr-table="tasks"] tbody tr.cr-row').first.focus()
    page.keyboard.press('Enter')
    _need(page, '[data-cr-tc-dialog]', 'Enter on a row opens the dialog')
    assert page.locator('[data-cr-tc-dialog]').get_attribute('aria-modal') == 'true'
    page.wait_for_function('() => !!document.activeElement.closest("[data-cr-tc-dialog]")', timeout=3000)
    # close, refresh, the log and cancel of the running task: Tab goes round them and never behind the overlay
    seen = []
    for key in ['Tab'] * 8 + ['Shift+Tab'] * 8:
        page.keyboard.press(key)
        where = page.evaluate(IN_DIALOG)
        assert where, f'{key} keeps the focus in the modal dialog (after {seen})'
        seen.append(where)
    assert seen[:8] == ['Refresh', 'Task Output', 'Cancel task', 'Close'] * 2, seen
    assert seen[8:] == ['Cancel task', 'Task Output', 'Refresh', 'Close'] * 2, seen
    page.keyboard.press('Escape')
    page.locator('[data-cr-tc-dialog]').wait_for(state='detached', timeout=3000)
    # round 4 (Hide task bar is gone): the focus is back on the row the dialog came from, and the
    # next Escape closes the drawer and hands it to the bar
    page.wait_for_function('() => document.activeElement && document.activeElement.matches("tr.cr-row")', timeout=3000)
    page.keyboard.press('Escape')
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    assert page.evaluate('() => document.activeElement.classList.contains("cr-tc-hit")'), 'the focus is on the bar'
    _no_errors(app)


def test_runtime_loading_empty_and_error_get_their_own_row(open_app):
    # loading: the cluster's list is on its way
    app = open_app()
    page = app.page
    app.server.hold = {'c1'}
    _pick_testi(page)
    _need(page, TOGGLE, 'the task center has its toggle')
    page.locator(TOGGLE).click()
    _need(page, '[data-cr-table="tasks"] td.cr-state', 'the list says what it is waiting for')
    assert page.locator('[data-cr-table="tasks"] td.cr-state').inner_text().strip() == 'Loading...', 'loading, not "no tasks"'
    app.server.hold = set()
    app.server.release_tasks()
    _wait_rows(page, len(C1), 'the answer fills the list')
    # empty: the cluster has none
    empty = open_app(lists={'c1': [], 'c2': shaped(C2, 'real')})
    _pick_testi(empty.page)
    empty.page.locator(TOGGLE).click()
    empty.page.wait_for_function('() => (document.querySelector(\'[data-cr-table="tasks"] td.cr-state\') || {}).innerText === "No tasks available"', timeout=8000)
    # error: the read failed
    broken = open_app(lists={'c2': shaped(C2, 'real')}, extra={('GET', '/api/clusters/c1/tasks'): (500, {'error': 'boom'})})
    _pick_testi(broken.page)
    broken.page.locator(TOGGLE).click()
    broken.page.wait_for_function('() => (document.querySelector(\'[data-cr-table="tasks"] td.cr-state\') || {}).innerText === "The list could not be loaded"', timeout=8000)
    assert broken.page.locator('[data-cr-table="tasks"] td.cr-state').get_attribute('role') == 'alert'
    _no_errors(app)


STATE_ROW = '() => (document.querySelector(\'[data-cr-table="tasks"] td.cr-state\') || {}).innerText || ""'


def _state_stays(page, want, what, ms=2500):
    """The state row says want now and still says it after ms."""
    try:
        page.wait_for_function(f'() => ({STATE_ROW})() === {json.dumps(want)}', timeout=8000)
    except Exception:
        raise AssertionError(f'{what}: the list says {page.evaluate(STATE_ROW)!r}, not {want!r}') from None
    page.wait_for_timeout(ms)
    assert page.evaluate(STATE_ROW) == want, f'{what}: the list says {page.evaluate(STATE_ROW)!r} after {ms} ms, not {want!r}'


def test_runtime_an_empty_cluster_stays_empty_over_frames_and_a_collapse(open_app):
    app = open_app(lists={'c1': [], 'c2': []}, sse=True)
    page = app.page
    page.wait_for_function('() => window.__sse && window.__sse.made.some(s => s.readyState === 1)', timeout=8000)
    _pick_testi(page)
    page.locator(TOGGLE).click()
    _state_stays(page, 'No tasks available', 'a cluster whose read gave none has no tasks', ms=300)
    # the stream sends [] for a cluster without tasks, in cooldown or out of reach alike: it is no answer, and takes none back
    page.evaluate('() => window.__sse.say({type: "tasks", cluster_id: "c1", data: []})')
    _state_stays(page, 'No tasks available', 'an empty frame does not turn the answer back into loading', ms=1000)
    # round 4: collapse it by the bar and open it again: the answer is still known, no read is needed for it
    reads = len(_tasks_reads(app.server, 'c1'))
    page.locator(TOGGLE).click()
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    page.evaluate('() => window.__sse.say({type: "tasks", cluster_id: "c1", data: []})')
    page.locator(TOGGLE).click()
    _state_stays(page, 'No tasks available', 'after a collapse and an empty frame the empty cluster is still empty')
    assert len(_tasks_reads(app.server, 'c1')) == reads
    _no_errors(app)


# --- scope and reads --------------------------------------------------------------------------

def _more(n):
    """n further connected clusters with two tasks each."""
    cl, lists = [], {}
    for i in range(1, n + 1):
        cid = f'k{i:02d}'
        cl.append(dict(PROD, id=cid, name=f'Lab{i:02d}', display_name=f'Lab{i:02d}', group_id=None))
        lists[cid] = shaped([_task(f'lab{i}', 100 + i, 'vzdump', 300 + i, 'OK', 7000 + i, 40)], 'real')
    return cl, lists


def test_runtime_the_scope_follows_the_view(open_app):
    app = open_app()
    page = app.page
    _need(page, '.cr-taskcenter[data-cr-tc-scope]', 'the task center has a scope')
    assert page.locator('.cr-taskcenter').get_attribute('data-cr-tc-scope') == 'all', 'All clusters on the All Clusters view'
    _pick_testi(page)
    page.wait_for_function('() => document.querySelector(".cr-taskcenter").dataset.crTcScope === "cluster"', timeout=5000)
    assert page.locator('[data-cr-tc-scopetext]').inner_text() == 'Testi'
    _open(page)
    assert page.locator('[data-cr-table="tasks"] th[data-cr-col="cluster"]').count() == 0
    _click(page, '[data-cr-tc-scope-pick="all"]', 'the scope switch offers All clusters')
    page.locator('[data-cr-table="tasks"] th[data-cr-col="cluster"]').wait_for(timeout=5000)
    page.wait_for_function('() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === 10', timeout=8000)
    _no_errors(app)


def test_runtime_all_clusters_takes_the_stream_and_reads_the_rest_four_at_a_time(open_app):
    extra, lists = _more(6)
    lists.update({'c1': shaped(C1, 'real'), 'c2': shaped(C2, 'real')})
    app = open_app(sse=True, clusters=[CLUSTER, PROD, EDGE] + extra, lists=lists)
    page = app.page
    _need(page, '[data-cr-tc-count="running"]', 'the bar counts the tasks of every cluster the stream carries')
    page.wait_for_function('() => window.__sse && window.__sse.made.some(s => s.readyState === 1)', timeout=8000)
    # frames of two clusters arrive over the stream
    page.evaluate('(d) => window.__sse.say({type: "tasks", cluster_id: "c2", data: d})', shaped(C2, 'real'))
    page.evaluate('(d) => window.__sse.say({type: "tasks", cluster_id: "k01", data: d})', lists['k01'])
    page.wait_for_function('() => Number(document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n) === 1', timeout=5000)
    assert _tasks_reads(app.server) == [], 'the stream needs no read'
    # opening reads the rest: four at a time, nothing for the streamed or disconnected ones
    app.server.hold = {'c1', 'k02', 'k03', 'k04', 'k05', 'k06'}
    _open(page)
    for _ in range(50):
        if len(app.server.held_tasks) >= 4:
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(400)
    assert len(app.server.held_tasks) == 4, ('at most four reads in flight', len(app.server.held_tasks))
    app.server.release_tasks()
    for _ in range(50):
        if len(app.server.held_tasks) >= 2:
            break
        page.wait_for_timeout(100)
    app.server.release_tasks()
    page.wait_for_function('() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length === 16', timeout=8000)
    reads = sorted(_tasks_reads(app.server))
    assert reads == sorted(f'/api/clusters/{c}/tasks' for c in ('c1', 'k02', 'k03', 'k04', 'k05', 'k06')), reads
    # each cluster says when its list was read
    page.locator('[data-cr-tc-coverage]').click()
    states = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-tc-cover]'))
        .map(x => [x.dataset.crTcCover, x.dataset.st]))''')
    assert states == {'c1': 'read', 'c2': 'live', 'c3': 'offline', 'k01': 'live', 'k02': 'read', 'k03': 'read',
                      'k04': 'read', 'k05': 'read', 'k06': 'read'}, states
    assert page.locator('[data-cr-tc-coverage]').inner_text().strip() == 'Read 8 of 8 clusters'
    assert 'read at' in page.locator('[data-cr-tc-cover="k02"]').inner_text()
    page.keyboard.press('Escape')
    # no timer reads anything: nothing more without a user action
    app.server.hold = set()
    n = len(_tasks_reads(app.server))
    page.wait_for_timeout(6000)
    assert len(_tasks_reads(app.server)) == n, 'nothing is read on a timer'
    # refresh reads again, except what the stream keeps live
    page.locator('[data-cr-tc-refresh]').click()
    for _ in range(50):
        if len(_tasks_reads(app.server)) >= n + 6:
            break
        page.wait_for_timeout(100)
    assert len(_tasks_reads(app.server)) == n + 6, _tasks_reads(app.server)[n:]
    _no_errors(app)


def test_runtime_a_cluster_that_refuses_its_list_says_so(open_app):
    app = open_app(extra={('GET', '/api/clusters/c2/tasks'): (403, {'error': 'Permission denied'})},
                   lists={'c1': shaped(C1, 'real')})
    page = app.page
    _open(page)
    _need(page, '[data-cr-tc-coverage]', 'All clusters says how many clusters were read')
    page.wait_for_function('() => document.querySelector("[data-cr-tc-coverage]").innerText.includes("Read 1 of 2")', timeout=8000)
    page.locator('[data-cr-tc-coverage]').click()
    assert page.locator('[data-cr-tc-cover="c2"]').get_attribute('data-st') == 'denied'
    assert 'No access' in page.locator('[data-cr-tc-cover="c2"]').inner_text()
    _no_errors(app)


# --- queued -------------------------------------------------------------------------------

BULK = {'id': 'b1', 'cluster_id': 'c1', 'cluster': 'Testi', 'user': 'ops', 'mine': False, 'target': 'pve2',
        'mode': 'parallel', 'parallel': 2, 'state': 'running', 'created': FIXED - 120, 'finished': None, 'total': 5,
        'counts': {'wait': 3, 'migrating': 1, 'done': 1}, 'current': [100]}
DONE_BULK = dict(BULK, id='b2', state='done', counts={'done': 5}, current=[])
RESTORE = {'id': 'r1', 'cluster_id': 'c2', 'cluster': 'Prod', 'user': 'ops', 'mine': False, 'storage': 'pbs1',
           'node': 'prod1', 'state': 'running', 'created': FIXED - 60, 'finished': None, 'total': 2,
           'counts': {'wait': 1, 'restoring': 1}, 'current': [201]}


def test_runtime_queued_comes_from_the_two_job_registries(open_app):
    app = open_app(bulk=[BULK, DONE_BULK], restores=[RESTORE])
    page = app.page
    _pick_testi(page)
    _need(page, '[data-cr-tc-count="queued"]', 'the bar counts what is queued')
    q = page.locator('[data-cr-tc-count="queued"]')
    # round 4: not read yet is no 0 but its own state, and says when it is read
    assert q.get_attribute('data-n') is None and q.get_attribute('data-cr-tc-unread') == '', q.evaluate('e => e.outerHTML')
    assert q.locator('b').inner_text() == '-'
    assert 'Bulk migrations and batch restores' in q.get_attribute('title')
    assert 'Read when the task list opens.' in q.get_attribute('title')
    reads = lambda p: sum(1 for m, x in app.server.calls if m == 'GET' and x == p)  # noqa: E731
    before = (reads('/api/bulk-migrations'), reads('/api/batch-restores'))
    _open(page)
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="queued"]\').dataset.n === "1"', timeout=5000)
    page.wait_for_timeout(500)
    assert (reads('/api/bulk-migrations'), reads('/api/batch-restores')) == (before[0] + 1, before[1] + 1), 'one read of each per open'
    row = next(r for r in _rows(page) if r['state'] == 'Queued')
    assert row['type'] == 'Bulk migration' and row['result'] == '3 waiting of 5' and row['progress'] == '1 of 5', row
    # this cluster only shows its own; all clusters shows the restore of Prod too
    _click(page, '[data-cr-tc-scope-pick="all"]', 'the scope switch offers All clusters')
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="queued"]\').dataset.n === "2"', timeout=5000)
    restore = next(r for r in _rows(page) if r['type'] == 'Batch restore')
    assert restore['result'] == '1 waiting of 2' and restore['resource'] == 'pbs1'
    # a scope switch reads no registry again; the next open does
    assert (reads('/api/bulk-migrations'), reads('/api/batch-restores')) == (before[0] + 1, before[1] + 1)
    page.locator(TOGGLE).click()
    page.locator(TOGGLE).click()
    page.wait_for_timeout(600)
    assert (reads('/api/bulk-migrations'), reads('/api/batch-restores')) == (before[0] + 2, before[1] + 2)
    assert 'Read at' in page.locator('[data-cr-tc-count="queued"]').get_attribute('title')
    _no_errors(app)


def test_runtime_a_user_without_backup_view_asks_no_restore_registry(open_app):
    app = open_app(admin=False, permissions=['vm.view', 'cluster.view', 'node.view', 'storage.view'], bulk=[BULK])
    page = app.page
    _pick_testi(page)
    _open(page)
    _need(page, '[data-cr-tc-count="queued"]', 'the bar counts what is queued')
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="queued"]\').dataset.n === "1"', timeout=5000)
    page.wait_for_timeout(500)
    assert ('GET', '/api/batch-restores') not in app.server.calls
    _no_errors(app)


# --- room on the page, the settings modal, size -------------------------------------------------

# the lowest visible point of the page content once it is scrolled to its end: an element
# inside a scroll box counts only as far as the box shows it
LAST_BOTTOM = '''() => {
    window.scrollTo(0, document.documentElement.scrollHeight);
    const main = document.querySelector('#cr-main');
    let max = main.getBoundingClientRect().bottom;
    const clip = (el) => {
        let b = Infinity;
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
            const cs = getComputedStyle(p);
            if (cs.position === 'fixed') return -1;
            if (cs.overflowY !== 'visible') b = Math.min(b, p.getBoundingClientRect().bottom);
        }
        return b;
    };
    document.querySelectorAll('#cr-main *, footer').forEach(el => {
        const r = el.getBoundingClientRect();
        if (!r.height || !r.width) return;
        const cs = getComputedStyle(el);
        if (cs.position === 'fixed' || cs.visibility === 'hidden') return;
        const c = clip(el);
        if (c < 0) return;
        max = Math.max(max, Math.min(r.bottom, c));
    });
    return max;
}'''


@pytest.mark.parametrize('view', ['dashboard', 'cluster', 'guests', 'module'])
def test_runtime_the_bar_never_covers_the_end_of_a_page(open_app, view):
    app = open_app(viewport=(1280, 720))
    page = app.page
    _need(page, '.cr-taskcenter', 'the task center is there')
    if view == 'cluster':
        _pick_testi(page)
    elif view == 'guests':
        page.locator('.cr-sidebar').get_by_text('All Guests').first.click()
        page.wait_for_timeout(1500)
    elif view == 'module':
        _pick_testi(page)
        page.locator('[data-cr-tab="automation"]').click()
        page.wait_for_timeout(1500)
    page.wait_for_timeout(800)
    top = page.locator('.cr-taskcenter').bounding_box()['y']
    bottom = page.evaluate(LAST_BOTTOM)
    page.wait_for_timeout(200)
    bottom = page.evaluate(LAST_BOTTOM)
    assert bottom <= top + 0.5, (view, 'the end of the page sits above the bar', bottom, top)
    side = page.locator('.cr-sidebar > .sticky').bounding_box()
    assert side['y'] + side['height'] <= top + 0.5, ('the sidebar ends above the bar', side, top)
    _no_errors(app)


ON_TOP = '''() => { const b = document.querySelector('.cr-taskcenter').getBoundingClientRect();
    const e = document.elementFromPoint(b.left + b.width / 2, b.bottom - 8); return !!(e && e.closest('.cr-taskcenter')); }'''


@pytest.mark.parametrize('view', ['pbs', 'esxi', 'topology-full'])
def test_runtime_the_bar_is_there_in_every_view_but_full_screen_topology(open_app, view):
    from test_corp_redesigned_modules_ui import EXTRA
    app = open_app(extra=EXTRA)
    page = app.page
    _need(page, '.cr-taskcenter', 'the task center is there')
    if view == 'topology-full':
        page.locator('[data-corp-tool="topology"]').first.click()
        page.locator('[data-cr-topo-full]').click()
        page.wait_for_timeout(600)
        assert not page.evaluate(ON_TOP), 'full screen topology covers the bar, the one exception'
        _no_errors(app)
        return
    page.locator('.cr-sidebar').get_by_text('backup01' if view == 'pbs' else 'esx01', exact=True).first.click()
    page.wait_for_timeout(1200)
    assert page.evaluate(ON_TOP), f'the bar is visible on the {view} view'
    _open(page)
    _need(page, '#cr-tc-drawer', f'the drawer opens on the {view} view')
    _no_errors(app)


@pytest.mark.parametrize('viewport', [(1600, 1000), (1280, 720)])
def test_runtime_the_settings_modal_ends_above_the_bar(open_app, viewport):
    app = open_app(viewport=viewport)
    page = app.page
    _need(page, '.cr-taskcenter', 'the task center is there')
    app.open_settings()
    page.wait_for_timeout(500)
    box = page.locator('.cr-taskcenter').bounding_box()
    hit = page.evaluate('([x, y]) => { const e = document.elementFromPoint(x, y); return !!(e && e.closest(".cr-taskcenter")); }',
                        [box['x'] + box['width'] / 2, box['y'] + box['height'] - 8])
    assert hit, 'the bar stays visible and in front while the settings are open'
    overlay = page.locator('.corp-vm-modal-overlay').first.bounding_box()
    modal = page.locator('.corp-vm-modal').first.bounding_box()
    assert overlay['y'] + overlay['height'] <= box['y'] + 0.5, ('the overlay ends above the bar', overlay, box)
    assert modal['y'] + modal['height'] <= box['y'] + 0.5, ('nothing of the settings lies under the bar', modal, box)
    # the drawer opens over the settings, and goes again
    bar = page.locator(TOGGLE)
    bar.click()
    _need(page, '#cr-tc-drawer', 'the bar opens the drawer over the settings')
    bar.click()
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    assert page.get_by_text('PegaProx Settings').first.is_visible()
    _no_errors(app)


# the tab strip of the open consoles (dashboard.js, fixed with an inline bottom: 0 and z-index 60)
CONSOLE_TABS = '''() => {
    const strip = Array.from(document.querySelectorAll('body div')).find(d => d.style.position === 'fixed' && d.style.zIndex === '60' && d.style.bottom === '0px');
    if (!strip) return null;
    const bar = document.querySelector('.cr-taskcenter').getBoundingClientRect();
    const tabs = Array.from(strip.firstElementChild.children).map(t => {
        const r = t.getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + 3);
        return { top: r.top, bottom: r.bottom, text: t.querySelector('span').innerText.trim(), mine: !!(hit && strip.contains(hit)) };
    });
    return { bar: bar.top, bottom: strip.firstElementChild.getBoundingClientRect().bottom, tabs };
}'''


def test_runtime_the_tabs_of_two_open_consoles_sit_on_the_bar(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    # the console overlay of the first one lies over the sidebar, so the second comes through its row menu by events
    for name in ('web01', 'ct01'):
        page.evaluate('''(name) => {
            const el = Array.from(document.querySelectorAll('.corp-tree-child')).find(e => e.innerText.includes(name));
            const r = el.getBoundingClientRect();
            el.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: r.left + 10, clientY: r.top + 5 }));
        }''', name)
        page.locator('.corp-context-menu').first.wait_for(timeout=4000)
        page.evaluate('''() => { const m = Array.from(document.querySelectorAll('.corp-context-menu')).pop();
            Array.from(m.querySelectorAll('.corp-ctx-item')).find(e => e.innerText.trim() === 'Console').click(); }''')
        page.locator('.corp-context-menu').wait_for(state='detached', timeout=3000)
    page.wait_for_function(f'() => {{ const s = ({CONSOLE_TABS})(); return s && s.tabs.length === 2; }}', timeout=5000)
    page.wait_for_timeout(300)
    got = page.evaluate(CONSOLE_TABS)
    assert [x['text'] for x in got['tabs']] == ['web01', 'ct01'], got
    assert got['bottom'] <= got['bar'] + 0.5, ('the tabs of the open consoles end on the task bar, not under it', got)
    assert all(x['mine'] for x in got['tabs']), ('every console tab is clickable to its top edge', got)
    # the fake has no VNC behind the consoles, that is all the console says
    assert all('VNC' in e for e in app.errors), app.errors


def test_runtime_the_drawer_resizes_by_mouse_and_keys_and_keeps_its_height(open_app):
    app = open_app()
    page = app.page
    _open(page)
    _need(page, '#cr-tc-drawer', 'the task list is a drawer of its own')
    _need(page, '[data-cr-tc-grip]', 'the drawer has a handle that resizes it by mouse and keys')
    drawer = page.locator('#cr-tc-drawer')
    h0 = drawer.bounding_box()['height']
    assert abs(h0 - 450) <= 2, ('about 45 % of the viewport by default', h0)
    grip = page.locator('[data-cr-tc-grip]')
    g = grip.bounding_box()
    x, y = g['x'] + g['width'] / 2, g['y'] + g['height'] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    page.mouse.move(x, y - 60, steps=4)
    page.mouse.move(x, y - 100, steps=4)
    page.mouse.up()
    h1 = drawer.bounding_box()['height']
    assert abs(h1 - (h0 + 100)) <= 3, (h0, h1)
    grip.focus()
    page.keyboard.press('ArrowDown')
    assert abs(drawer.bounding_box()['height'] - (h1 - 16)) <= 2
    assert abs(int(grip.get_attribute('aria-valuenow')) - (h1 - 16)) <= 1
    page.keyboard.press('Home')
    assert abs(drawer.bounding_box()['height'] - 160) <= 1
    page.keyboard.press('End')
    assert abs(drawer.bounding_box()['height'] - 800) <= 1
    page.keyboard.press('ArrowDown')
    assert page.evaluate('() => localStorage.getItem("cr-tc-h")') == '784'
    page.reload()
    app.wait_for_app()
    _open(page)
    assert abs(page.locator('#cr-tc-drawer').bounding_box()['height'] - 784) <= 1, 'the height survives a reload'
    _no_errors(app)


def test_runtime_the_drawer_rises_and_reduced_motion_stops_it(open_app):
    app = open_app()
    page = app.page
    _open(page)
    _need(page, '#cr-tc-drawer', 'the task list is a drawer of its own')
    assert page.evaluate('() => getComputedStyle(document.querySelector("#cr-tc-drawer")).animationName') == 'cr-tc-rise'
    page.emulate_media(reduced_motion='reduce')
    assert page.evaluate('() => getComputedStyle(document.querySelector("#cr-tc-drawer")).animationName') == 'none'
    _no_errors(app)


def test_runtime_on_a_phone_the_bar_ends_the_page(open_app):
    app = open_app(viewport=(400, 860))
    page = app.page
    _need(page, '.cr-taskcenter', 'the task center is there')
    assert page.evaluate('() => getComputedStyle(document.querySelector(".cr-taskcenter")).position') == 'static'
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 400
    _open(page)
    page.wait_for_timeout(300)
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 400, 'no sideways scroll with the drawer open'
    _no_errors(app)


# --- scale ----------------------------------------------------------------------------------

def _fleet(n_clusters, n_tasks):
    clusters, lists = [], {}
    for c in range(n_clusters):
        cid = f'f{c:03d}'
        clusters.append({'id': cid, 'name': f'fleet{c:03d}', 'display_name': f'fleet{c:03d}', 'host': f'10.9.{c // 250}.{c % 250}',
                         'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True})
        rows = []
        for i in range(n_tasks):
            res = 'running' if i == 0 else ('job errors' if i % 7 == 0 else ('WARNINGS: 1' if i % 11 == 0 else 'OK'))
            # started minutes ago: a task that just started opens the drawer on its own (#738)
            rows.append(_task(f'n{c:03d}-{i % 4}', c * 1000 + i, 'vzdump' if i % 3 else 'qmigrate', 1000 + i, res,
                              600 + c * 50 + i, 20))
        lists[cid] = shaped(rows, 'real')
    return clusters, lists


@pytest.mark.parametrize('source', ['stream', 'reads'])
def test_runtime_200_clusters_with_50_tasks_each_stay_smooth(open_app, source):
    clusters, lists = _fleet(200, 50)
    app = open_app(sse=source == 'stream', clusters=clusters, lists=lists, status={}, scripts=[LONGTASKS],
                   extra={('GET', '/api/cluster-groups'): (200, [])})
    page = app.page
    _need(page, TOGGLE, 'the task center has its toggle')
    took = {}
    if source == 'stream':
        page.wait_for_function('() => window.__sse && window.__sse.made.some(s => s.readyState === 1)', timeout=15000)
        t0 = time.time()
        page.evaluate('(all) => Object.entries(all).forEach(([cid, d]) => window.__sse.say({type: "tasks", cluster_id: cid, data: d}))', lists)
        _need(page, '[data-cr-tc-count="running"]', 'the bar counts the tasks of every cluster the stream carries')
        page.wait_for_function('() => Number(document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n) === 200', timeout=15000)
        took['200 frames to bar counts'] = time.time() - t0
    t0 = time.time()
    page.locator(TOGGLE).click()
    try:
        page.wait_for_function('''() => { const c = document.querySelector('[data-cr-table="tasks"] .cr-table-count');
            return c && c.innerText.trim() === '10000 of 10000'; }''', timeout=60000)
    except Exception:
        raise AssertionError('All clusters lists the 10000 tasks of the 200 clusters') from None
    took['open drawer to 10000 rows'] = time.time() - t0
    if source == 'reads':
        assert len(_tasks_reads(app.server)) == 200
    rows = page.evaluate('() => document.querySelectorAll(\'[data-cr-table="tasks"] tbody tr.cr-row\').length')
    assert rows < 120, ('the table draws only the rows in view', rows)
    t0 = time.time()
    page.locator('[data-cr-table="tasks"] th[data-cr-col="duration"] button').click()
    page.wait_for_function('() => document.querySelector(\'[data-cr-table="tasks"] th[data-cr-col="duration"]\').getAttribute("aria-sort") === "ascending"', timeout=5000)
    took['sort 10000 rows'] = time.time() - t0
    t0 = time.time()
    page.locator('[data-cr-filter="failed"]').click()
    page.wait_for_function('''() => { const c = document.querySelector('[data-cr-table="tasks"] .cr-table-count');
        return c && /^1400 of 10000$/.test(c.innerText.trim()); }''', timeout=5000)
    took['status filter'] = time.time() - t0
    t0 = time.time()
    page.locator('[data-cr-tc-q]').fill('n150-2')
    page.wait_for_function('''() => { const c = document.querySelector('[data-cr-table="tasks"] .cr-table-count');
        return c && !/^1400 of/.test(c.innerText.trim()); }''', timeout=5000)
    took['resource filter'] = time.time() - t0
    page.locator('[data-cr-tc-clearfilters]').click()
    if source == 'stream':
        # 3 s of frames, each its own event as the stream delivers them: every cluster reports
        # three times, one more of its tasks finished each time
        page.evaluate('''(all) => {
            window.__frames = [];
            for (let k = 1; k <= 3; k++) Object.entries(all).forEach(([cid, d]) => window.__frames.push(JSON.stringify(
                {type: 'tasks', cluster_id: cid, data: d.map((t, i) => i < k ? {...t, status: 'OK', endtime: t.starttime + 5} : t)})));
        }''', lists)
        page.evaluate('() => { window.__long = []; }')
        page.evaluate('''() => window.__frames.forEach((f, i) => setTimeout(() =>
            window.__sse.made.filter(s => s.readyState === 1).forEach(s => s.onmessage({ data: f })), i * 5))''')
        page.wait_for_timeout(3500)
        page.wait_for_function('() => Number(document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n) === 0', timeout=10000)
        longest = max(page.evaluate('() => window.__long') or [0])
        took['longest main-thread task during frames (ms)'] = longest
        assert longest < 300, ('no main-thread task over 300 ms while frames arrive', longest)
    print('\nscale', source, json.dumps({k: round(v, 3) if isinstance(v, float) else v for k, v in took.items()}))
    assert took['open drawer to 10000 rows'] < (2.0 if source == 'stream' else 30.0), took
    assert took['sort 10000 rows'] < 1.0 and took['status filter'] < 1.0 and took['resource filter'] < 1.0, took
    _no_errors(app)


# --- classic stays classic --------------------------------------------------------------------

DIALOG = '''() => { const t = Array.from(document.querySelectorAll('.fixed.inset-0')).find(e => e.innerText.includes('Task Output'));
    return t ? t.outerHTML : null; }'''


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_the_classic_detail_dialog_and_bar_are_the_markup_of_the_base(browser, layout):
    """The dialog became one render for both; without the preview's options it is the old markup."""
    from test_corp_redesigned_guard_ui import BASE_REV, _GuardServer, _corp_cluster, _modern_cluster
    try:
        base = subprocess.run(['git', 'show', f'{BASE_REV}:web/index.html'], cwd=ROOT, capture_output=True,
                              check=True, timeout=60).stdout.decode('utf-8')
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f'the base revision {BASE_REV} is not in this clone')
    seen = {}
    for name, bundle in (('base', base), ('new', None)):
        app = _GuardApp(browser, _GuardServer(layout=layout, bundle=bundle))
        try:
            page = app.page
            (_corp_cluster if layout == 'corporate' else _modern_cluster)(page)
            page.locator('.pp-taskbar .cursor-pointer').first.click()
            page.wait_for_function('() => document.querySelector(".pp-taskbar").offsetHeight >= 300', timeout=5000)
            out = {'bar': page.evaluate('() => document.querySelector(".pp-taskbar").outerHTML')}
            for label in ('VM Migration', 'CT Start', 'Snapshot'):
                page.locator('.pp-taskbar tbody tr', has_text=label).first.click()
                page.get_by_text('Task Output').first.wait_for(timeout=5000)
                page.wait_for_timeout(300)
                out[label] = page.evaluate(DIALOG)
                assert out[label] and 'Task Output' in out[label], f'{name}: the dialog of {label} was found'
                # its own close button (in classic Corporate the corner of the backdrop lies under the header)
                page.locator('.fixed.inset-0', has_text='Task Output').first.locator('button').first.click()
                page.get_by_text('Task Output').first.wait_for(state='detached', timeout=3000)
            seen[name] = out
            assert not app.errors, app.errors
        finally:
            app.close()
    for key in seen['base']:
        assert seen['new'][key] == seen['base'][key], f'{layout}: the classic {key} changed'


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_the_classic_layouts_keep_the_classic_bar(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    page.wait_for_timeout(800)
    assert page.locator('.cr-taskcenter, .cr-tc-hit').count() == 0
    assert page.locator('.pp-taskbar .cursor-pointer').count() == 1
    assert page.evaluate('() => document.body.dataset.crTasks || null') is None
    _no_errors(app)
