"""Timeline, shell and subscription in Corporate Redesigned, in the browser.

Round 9 draws the Timeline of a cluster, a node and a guest as the task center's table (TimelineView
keeps its reads, filters and pages and hands them to CrTimeline in web/src/cr_nodemisc.js): the
severity as a badge, the event, the node and the guest, what is known about an event and what
happened shortly before it opened in its row. The node Shell gets a bar above the one terminal with
the session's state, where it logs in, a new session once it ended and the filled window. The node
Subscription shows what the node reports; a field it does not report says so, an empty answer is
not read as "no subscription". Classic Corporate keeps its lists.

The pure parts are checked through window.PegaProxNodeMisc. PEGAPROX_CR_BUNDLE=<file> serves another
bundle (the counterproof against the build before this stage). Skips without Playwright. LW Nov 2026
"""
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, FIXED, NODE_BASE_READS, NODE_SUB, TIMELINE_READS, _GuardApp,
                                           _GuardServer, _corp_cluster, _tl_event)

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NODE = '/api/clusters/c1/nodes/pve1'
SUB = NODE + '/subscription'
TL = '/api/timeline'
TL_BASE = TIMELINE_READS[('GET', TL)][1]

# an audit event with what is known about it and two events shortly before it, on top of the guard's three
AUDIT = dict(_tl_event('audit:7', 'audit', 120, 'warning', 'audit', 'Firewall rule changed on pve1', node='pve1'),
             details='rule 4: ACCEPT tcp/22 from 10.0.0.0/24',
             shortly_before=[{'id': 'task:u9', 'kind': 'task', 'seconds_before': 95, 'what': 'task', 'title': 'vzdump 100',
                              'node': 'pve1', 'params': {}},
                             {'id': 'alert:a7', 'kind': 'alert', 'seconds_before': 30, 'what': 'alert.fired',
                              'title': 'web01 CPU above 80%', 'node': None, 'params': {}}])
TL_RICH = dict(TL_BASE, events=[AUDIT] + TL_BASE['events'])
OLDER = _tl_event('task:u0', 'task', 7200, 'info', 'task', 'aptupdate', node='pve1', params={'type': 'aptupdate'})


class _MiscServer(_GuardServer):
    """The guard fake with the node's base reads, its subscription and the timeline; each answer
    settable while the page runs: a (code, body) pair, a function of the request, 'hold' or 'abort'."""

    def __init__(self, **kw):
        routes = kw.pop('routes', {})
        super().__init__(bundle=BUNDLE, **kw)
        self.routes = dict(NODE_BASE_READS)
        self.routes[('GET', SUB)] = (200, NODE_SUB)
        self.routes[('GET', TL)] = (200, TL_RICH)
        self.routes.update(routes)
        self.held = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        if callable(how):
            how = how(req)
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def reads(self, path):
        return len([c for c in self.calls if c == ('GET', path)])

    def queries(self, path=TL):
        return [parse_qs(urlparse(u).query) for u in self.urls if urlparse(u).path == path]


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _MiscServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _until(page, check, what, tries=40):
    for _ in range(tries):
        if check():
            return
        page.wait_for_timeout(100)
    raise AssertionError(what)


def _node_tab(page, label, redesigned=True):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    if redesigned:
        page.locator('[data-cr-tabs="node"] [role="tab"]', has_text=label).click()
    else:
        page.locator('.corp-tab-strip button', has_text=label).first.click()


def _node_timeline(page, redesigned=True):
    _node_tab(page, 'Monitor', redesigned)
    page.locator('[data-corp-node-timeline]').first.click()


def _fmt(page, value, date_only=False):
    """What crFmtDate draws in English: the UI language's format, not the browser's."""
    return page.evaluate("""([v, dateOnly]) => {
        const o = { year: 'numeric', month: '2-digit', day: '2-digit', hour12: false };
        if (!dateOnly) Object.assign(o, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const d = typeof v === 'number' ? new Date(v * 1000) : Array.isArray(v) ? new Date(v[0], v[1] - 1, v[2]) : new Date(v);
        return new Intl.DateTimeFormat('en', o).format(d);
    }""", [value, date_only])


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def misc_page(browser):
    app = _GuardApp(browser, _MiscServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeMisc'):
        app.close()
        pytest.fail('the bundle has no timeline, shell and subscription helpers (window.PegaProxNodeMisc)')
    yield app.page
    app.close()


def _sub(page, read):
    return page.evaluate('(r) => window.PegaProxNodeMisc.subModel(r === "__undef__" ? undefined : r)', read)


def test_rules_the_subscription_answer_and_its_states(misc_page):
    assert _sub(misc_page, '__undef__')['state'] == 'loading'
    failed = _sub(misc_page, {'__crFail': {'status': 500, 'error': 'boom', 'code': ''}})
    assert failed['state'] == 'error' and failed['fail']['error'] == 'boom'
    assert _sub(misc_page, ['x'])['state'] == 'error'
    # get_node_subscription answers {} for a node it could not read: that is no answer, not "no subscription"
    assert _sub(misc_page, {})['state'] == 'empty'
    assert _sub(misc_page, {'status': '', 'key': None})['state'] == 'empty'
    ok = _sub(misc_page, NODE_SUB)
    assert ok['state'] == 'ok' and ok['status'] == 'active' and ok['tone'] == 'success'
    assert ok['levelKey'] == 'crSubLevelC' and ok['checktime'] == FIXED - 86400 and ok['url'].startswith('https://')
    # the older capitalised word is the same state; the states PVE knows, each with its tone
    assert _sub(misc_page, {'status': 'Active'})['status'] == 'active'
    for status, tone in (('new', 'neutral'), ('notfound', 'neutral'), ('expired', 'error'), ('invalid', 'error'),
                         ('suspended', 'error')):
        assert _sub(misc_page, {'status': status})['tone'] == tone, status
    odd = _sub(misc_page, {'status': 'Grace', 'serverid': 'X'})
    assert odd['status'] == 'other' and odd['raw'] == 'Grace' and odd['tone'] == 'neutral' and odd['label'] == ''
    assert _sub(misc_page, {'serverid': 'X'})['status'] == 'none'
    assert _sub(misc_page, {'status': 'notfound'})['none'] is True
    # only a https link is drawn as one; a check time as text of digits is still a time
    assert _sub(misc_page, {'status': 'active', 'url': 'javascript:alert(1)'})['url'] == ''
    assert _sub(misc_page, {'status': 'active', 'url': 'http://shop.example'})['url'] == ''
    assert _sub(misc_page, {'status': 'active', 'checktime': '1793350800'})['checktime'] == 1793350800
    assert _sub(misc_page, {'status': 'active', 'checktime': 'yesterday'})['checktime'] is None


def test_rules_the_key_is_masked_and_a_due_date_is_its_calendar_day(misc_page):
    mask = lambda k: misc_page.evaluate('(k) => window.PegaProxNodeMisc.subMask(k)', k)
    dot = '•'
    assert mask('pve1c-0a1b2c3d4e') == 'pve1c-' + dot * 6 + '3d4e'
    assert mask('ABCDEFGHIJ') == dot * 6 + 'GHIJ'
    assert mask('pve1c') == dot * 6 and mask('') == '' and mask(None) == ''
    day = lambda v: misc_page.evaluate('(v) => { const d = window.PegaProxNodeMisc.subDay(v); return d && [d.getFullYear(), d.getMonth() + 1, d.getDate()]; }', v)
    assert day('2027-01-15') == [2027, 1, 15]
    assert day('2026-01-15 00:00:00') == [2026, 1, 15]
    assert day('2027-02-30') is None and day('soon') is None and day(None) is None


def test_rules_timeline_tones_are_the_task_centers(misc_page):
    tone = lambda s: misc_page.evaluate('(s) => window.PegaProxNodeMisc.tlTone(s)', s)
    assert [tone(s) for s in ('critical', 'warning', 'info', 'odd', None)] == ['error', 'warning', 'neutral', 'neutral', 'neutral']
    more = lambda e: misc_page.evaluate('(e) => window.PegaProxNodeMisc.tlHasMore(e)', e)
    assert more(AUDIT) and more({'details': 'x'}) and not more(TL_BASE['events'][0]) and not more(None)


def test_every_new_text_exists_in_english_and_german():
    src = open(os.path.join(ROOT, 'web', 'src', 'cr_nodemisc.js'), encoding='utf-8').read()
    keys = sorted(set(re.findall(r"'(cr(?:Tl|Sh|Sub)[A-Z][A-Za-z]*)'", src)))
    assert len(keys) >= 35, keys
    tr = open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8').read()
    de = tr[tr.index('\n            de: {'):tr.index('\n            en: {')]
    en = tr[tr.index('\n            en: {'):tr.index('\n            zh: {')]
    for k in keys:
        assert re.search(rf'\n\s+{k}: ', en), f'{k} missing in en'
        assert re.search(rf'\n\s+{k}: ', de), f'{k} missing in de'
    assert '\u2014' not in src and '\u2013' not in src


# --- the timeline ------------------------------------------------------------------------------

def test_runtime_the_node_timeline_is_the_task_centers_table(open_app):
    app = open_app()
    page = app.page
    _node_timeline(page)
    tl = page.locator('[data-cr-tl="node"][data-cr-tl-read="ok"]')
    tl.wait_for(timeout=8000)
    assert tl.get_attribute('data-timeline') == 'node'
    rows = tl.locator('tr.cr-row')
    assert rows.count() == 4
    # the severity as a badge in the task center's tone, the row marked like a failed or warning task
    for sev, tone, mark in (('critical', 'error', 'cr-nt-row-failed'), ('warning', 'warning', 'cr-nt-row-warn'),
                            ('info', 'neutral', None)):
        badge = tl.locator(f'[data-tl-sev="{sev}"] .cr-badge').first
        assert f'cr-badge-{tone}' in badge.get_attribute('class'), sev
        row = tl.locator('tr.cr-row', has=page.locator(f'[data-tl-sev="{sev}"]')).first
        if mark:
            assert mark in row.get_attribute('class'), sev
    offline = tl.locator('tr.cr-row', has=page.locator('[data-tl-sev="critical"]')).first
    assert offline.locator('[data-tl-text]').inner_text() == 'Node pve2 went offline'
    assert 'cr-tc-result-error' in offline.locator('[data-tl-text]').get_attribute('class')
    # the time in the UI language's format through crFmtDate, not the browser's toLocaleString
    iso = TL_BASE['events'][0]['time']
    assert offline.locator('td').nth(2).inner_text().strip() == _fmt(page, iso)
    assert tl.locator('[data-tl-badge="node"]').first.inner_text().strip() == 'Node state'
    # the node of the page is no column of its own (the column menu shows it), the guest column is there
    assert tl.locator('th[data-cr-col="node"]').count() == 0 and tl.locator('[data-tl-open-node]').count() == 0
    assert tl.locator('th[data-cr-col="guest"]').count() == 1
    # only the first read, the node's filter on it
    q = app.server.queries()[-1]
    assert q['cluster'] == ['c1'] and q['node'] == ['pve1'] and q['limit'] == ['50'] and 'kinds' not in q
    # the old list of round 4 is not drawn in Corporate Redesigned
    assert page.locator('[data-tl-row]').count() == 0
    _no_errors(app)


def test_runtime_the_filters_read_with_the_servers_filter_and_clear_again(open_app):
    app = open_app()
    page = app.page
    _node_timeline(page)
    page.locator('[data-cr-tl-read="ok"]').wait_for(timeout=8000)
    n = len(app.server.queries())
    page.locator('[data-tl-filter-kind]').select_option('alert')
    _until(page, lambda: len(app.server.queries()) == n + 1, 'the kind reads again')
    page.locator('[data-tl-filter-severity]').select_option('critical')
    page.locator('[data-cr-tl-clear]').wait_for(timeout=5000)
    _until(page, lambda: len(app.server.queries()) == n + 2, 'the severity reads again')
    q = app.server.queries()[-1]
    assert q['kinds'] == ['alert'] and q['severity'] == ['critical']
    page.locator('[data-tl-range]').select_option('1')
    _until(page, lambda: len(app.server.queries()) == n + 3, 'the range reads again')
    q1 = app.server.queries()[-1]
    assert q1['from'] != q['from'] and q1['kinds'] == ['alert']
    page.locator('[data-cr-tl-clear]').click()
    _until(page, lambda: len(app.server.queries()) == n + 4, 'Clear reads again, once')
    page.wait_for_timeout(300)
    last = app.server.queries()[-1]
    assert 'kinds' not in last and 'severity' not in last
    assert page.locator('[data-cr-tl-clear]').count() == 0
    assert page.locator('[data-tl-filter-kind]').input_value() == '' and page.locator('[data-tl-range]').input_value() == '1'
    assert len(app.server.queries()) == n + 4
    _no_errors(app)


def test_runtime_what_is_known_and_what_happened_shortly_before_open_in_the_row(open_app):
    app = open_app()
    page = app.page
    _node_timeline(page)
    tl = page.locator('[data-cr-tl-read="ok"]')
    tl.wait_for(timeout=8000)
    # only the event with something more has the toggle; it says how many happened shortly before
    assert tl.locator('[data-cr-tl-toggle]').count() == 1
    toggle = tl.locator('[data-cr-tl-toggle="audit:7"]')
    assert toggle.inner_text().strip() == '2' and toggle.get_attribute('aria-expanded') == 'false'
    assert toggle.get_attribute('title') == '2 happened shortly before'
    toggle.click()
    detail = tl.locator('[data-cr-tl-detail="audit:7"]')
    detail.wait_for(timeout=5000)
    assert detail.locator('[data-tl-details]').inner_text() == 'rule 4: ACCEPT tcp/22 from 10.0.0.0/24'
    assert detail.locator('[data-tl-link]').count() == 2
    assert '10 min' in detail.locator('[data-tl-links-note]').inner_text()
    link = detail.locator('[data-tl-link="task:u9"]').inner_text()
    assert '2 min before' in link and 'vzdump 100' in link
    assert 'Fired: web01 CPU above 80%' in detail.locator('[data-tl-link="alert:a7"]').inner_text()
    assert toggle.get_attribute('aria-expanded') == 'true'
    # the row itself opens and closes it too; a row with nothing more does nothing
    tl.locator('tr.cr-row', has=page.locator('[data-cr-tl-toggle="audit:7"]')).locator('[data-tl-text]').click()
    page.wait_for_timeout(200)
    assert tl.locator('[data-cr-tl-detail]').count() == 0
    tl.locator('tr.cr-row', has=page.locator('[data-tl-sev="info"]')).first.click()
    page.wait_for_timeout(200)
    assert tl.locator('[data-cr-tl-detail]').count() == 0
    _no_errors(app)


def test_runtime_loading_failed_empty_and_leader_away_each_say_so(open_app):
    app = open_app(routes={('GET', TL): 'hold'})
    page = app.page
    _node_timeline(page)
    page.locator('[data-cr-tl="node"][data-cr-tl-read="loading"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-tl] .cr-state .cr-spinner').count() == 1
    # failed: the callout with Retry, the table says it too; Retry reads again
    app.server.routes[('GET', TL)] = (500, {'error': 'database locked'})
    app.server.held.pop().fulfill(status=500, body='{"error": "database locked"}', headers={'Content-Type': 'application/json'})
    err = page.locator('[data-tl-error]')
    err.wait_for(timeout=5000)
    assert err.get_attribute('data-cr-nc-state') == 'error' and 'could not be loaded' in err.inner_text()
    assert page.locator('[data-cr-tl-read="error"] .cr-state-error').count() == 1
    app.server.routes[('GET', TL)] = (200, dict(TL_BASE, events=[], next_before=None))
    n = app.server.reads(TL)
    err.locator('[data-cr-nc-retry]').click()
    empty = page.locator('[data-cr-tl-read="empty"] [data-tl-empty]')
    empty.wait_for(timeout=5000)
    assert empty.inner_text() == 'Nothing happened in this time range.' and app.server.reads(TL) == n + 1
    # with a filter the empty list says that nothing matches
    page.locator('[data-tl-filter-kind]').select_option('backup')
    page.locator('[data-tl-empty]', has_text='No event matches this filter.').wait_for(timeout=5000)
    # a standby whose leader does not answer: said, and no table that reads as empty
    app.server.routes[('GET', TL)] = (503, {'error': 'leader away', 'code': 'HA_ACTIVE_UNREACHABLE'})
    page.locator('[data-tl-refresh]').click()
    away = page.locator('[data-cr-tl-read="away"] [data-tl-leader-away]')
    away.wait_for(timeout=5000)
    assert page.locator('[data-cr-tl] table').count() == 0 and page.locator('[data-tl-error]').count() == 0
    _no_errors(app)


def test_runtime_older_events_come_on_request_and_append(open_app):
    def page_of(req):
        q = parse_qs(urlparse(req.url).query)
        if q.get('before') == ['2026-10-30T07:00:00+00:00']:
            return 200, dict(TL_BASE, events=[OLDER], next_before=None)
        return 200, dict(TL_RICH, next_before='2026-10-30T07:00:00+00:00')
    app = open_app(routes={('GET', TL): page_of})
    page = app.page
    _node_timeline(page)
    page.locator('[data-cr-tl-read="ok"]').wait_for(timeout=8000)
    more = page.locator('[data-tl-more]')
    assert '4 events loaded' in page.locator('.cr-tl-foot').inner_text()
    more.click()
    page.locator('[data-cr-tl] td', has_text='aptupdate').wait_for(timeout=5000)
    assert page.locator('[data-cr-tl] tr.cr-row').count() == 5
    assert app.server.queries()[-1]['before'] == ['2026-10-30T07:00:00+00:00']
    assert page.locator('[data-tl-more]').count() == 0
    _no_errors(app)


def test_runtime_the_cluster_and_the_guest_draw_the_same_table(open_app):
    app = open_app()
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="timeline"]').click()
    tl = page.locator('[data-cr-tl="cluster"][data-cr-tl-read="ok"]')
    tl.wait_for(timeout=8000)
    # the cluster: other nodes and guests open their views
    tl.locator('[data-tl-open-node="pve2"]').click()
    page.locator('[data-cr-tabs="node"]').wait_for(timeout=5000)
    page.locator('[data-cr-crumb]', has_text='pve2').first.wait_for(timeout=5000)
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.locator('[data-cr-tabs="guest"] [data-corp-vm-timeline]').click()
    guest = page.locator('[data-cr-tl="guest"][data-cr-tl-read="ok"]')
    guest.wait_for(timeout=8000)
    # the guest is the page: no guest column, the guest's own filter on the read
    assert guest.locator('th[data-cr-col="guest"]').count() == 0 and guest.locator('[data-tl-open-guest]').count() == 0
    assert app.server.queries()[-1]['vmid'] == ['100']
    assert 'Everything that happened to this guest and its host' in guest.inner_text()
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_timeline_list(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _node_timeline(page, redesigned=False)
    page.locator('[data-tl-row="audit:7"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-tl]').count() == 0 and page.locator('[data-timeline="node"]').count() == 1
    _no_errors(app)


# --- the shell ---------------------------------------------------------------------------------

class _Shell:
    """The shell socket of the node: asks for the login, answers it, can end the session. The mock
    takes the sockets of documents loaded after it, so the page loads once more."""

    def __init__(self, app, refuse=False):
        self.sockets = []
        self.sent = []
        self.refuse = refuse
        app.page.route_web_socket(re.compile(r'.*/shellws.*'), self._on)
        app.page.reload(wait_until='load')
        app.wait_for_app()

    def _on(self, ws):
        self.sockets.append(ws)
        if self.refuse:
            # what the server says when it cannot open the shell before any login (a close from in
            # here would stall the mock, the test closes the socket afterwards)
            ws.send(json.dumps({'status': 'error', 'message': 'No address known for node pve1'}))
            return
        ws.on_message(lambda m: self._msg(ws, m))
        ws.send(json.dumps({'status': 'need_credentials', 'node': 'pve1', 'ip': '10.0.0.11'}))

    def _msg(self, ws, m):
        self.sent.append(m)
        try:
            data = json.loads(m)
        except (TypeError, ValueError):
            return
        if isinstance(data, dict) and data.get('username'):
            ws.send(json.dumps({'status': 'connected'}))


def _badge(page):
    return page.locator('[data-cr-nsh-badge]').get_attribute('data-cr-nsh-badge')


def _login(page):
    dialog = page.locator('[data-shell-login]')
    dialog.wait_for(timeout=8000)
    dialog.locator('input[type="password"]').fill('secret')
    dialog.locator('button', has_text='Connect').click()


def test_runtime_the_shell_bar_follows_the_session(open_app):
    app = open_app()
    page = app.page
    shell = _Shell(app)
    _node_tab(page, 'Shell')
    page.locator('[data-cr-nsh="tab"][data-cr-nsh-state="login"]').wait_for(timeout=10000)
    assert page.locator('[data-cr-nsh-badge] .cr-badge').inner_text().strip() == 'Waiting for login'
    assert page.locator('[data-cr-nsh-at]').inner_text() == '10.0.0.11'
    assert page.locator('[data-cr-nsh-port]').inner_text() == 'Shell port 82'
    # the one terminal of the classic tab, clipped like it (#727), 500 px high
    term = page.locator('[data-cr-nsh-term]')
    assert term.evaluate('el => getComputedStyle(el).overflow') == 'clip' and round(term.bounding_box()['height']) == 500
    assert term.locator('.xterm').count() == 1
    _login(page)
    page.locator('[data-cr-nsh-state="connected"]').wait_for(timeout=5000)
    assert 'cr-badge-success' in page.locator('[data-cr-nsh-badge] .cr-badge').get_attribute('class')
    assert page.locator('[data-cr-nsh-at]').inner_text() == 'root@10.0.0.11'
    assert page.locator('[data-cr-nsh-reconnect]').count() == 0
    assert json.loads(shell.sent[0])['username'] == 'root'
    # the session ends: said, and Reconnect opens a new socket with a new login
    shell.sockets[0].close(code=1000, reason='')
    page.locator('[data-cr-nsh-state="disconnected"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-nsh-ended="disconnected"]').inner_text() == 'The session ended. Reconnect opens a new one.'
    page.locator('[data-cr-nsh-reconnect]').click()
    page.locator('[data-cr-nsh-state="login"]').wait_for(timeout=10000)
    assert len(shell.sockets) == 2 and page.locator('[data-cr-nsh-term] .xterm').count() == 1
    _no_errors(app)


def test_runtime_a_shell_that_never_connected_is_not_an_ended_session(open_app):
    app = open_app()
    page = app.page
    shell = _Shell(app, refuse=True)
    _node_tab(page, 'Shell')
    page.locator('[data-cr-nsh-state="error"]').wait_for(timeout=10000)
    # then the socket closes: a session that never was is not an ended one
    shell.sockets[0].close(code=1011, reason='')
    page.wait_for_timeout(500)
    assert page.locator('[data-cr-nsh-state="error"]').count() == 1
    assert page.locator('[data-cr-nsh-badge] .cr-badge').inner_text().strip() == 'Not connected'
    assert 'cr-badge-error' in page.locator('[data-cr-nsh-badge] .cr-badge').get_attribute('class')
    assert page.locator('[data-cr-nsh-ended="error"]').count() == 1
    assert page.locator('[data-cr-nsh-reconnect]').count() == 1
    _no_errors(app)


def test_runtime_the_filled_window_keeps_the_session(open_app):
    app = open_app()
    page = app.page
    shell = _Shell(app)
    _node_tab(page, 'Shell')
    _login(page)
    page.locator('[data-cr-nsh-state="connected"]').wait_for(timeout=10000)
    page.locator('[data-cr-nsh-term] .xterm').evaluate('el => { el.dataset.crMark = "same"; }')
    page.locator('[data-cr-nsh-full]').click()
    page.locator('[data-cr-nsh="window"]').wait_for(timeout=5000)
    box = page.locator('[data-cr-nsh-term]').bounding_box()
    assert box['height'] > 850 and box['width'] > 1500
    assert page.locator('[data-cr-nsh-full]').get_attribute('aria-pressed') == 'true'
    assert page.locator('.cr-nsh-full .cr-nn-title').inner_text() == 'pve1 - Shell'
    # same terminal, same socket, still connected
    assert page.locator('[data-cr-nsh-term] .xterm').get_attribute('data-cr-mark') == 'same'
    assert len(shell.sockets) == 1 and page.locator('[data-cr-nsh-state="connected"]').count() == 1
    page.locator('[data-cr-nsh-full]').click()
    page.locator('[data-cr-nsh="tab"]').wait_for(timeout=5000)
    assert round(page.locator('[data-cr-nsh-term]').bounding_box()['height']) == 500
    assert page.locator('[data-cr-nsh-term] .xterm').get_attribute('data-cr-mark') == 'same'
    _no_errors(app)


def test_runtime_classic_corporate_keeps_the_bare_terminal(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _Shell(app)
    _node_tab(page, 'Shell', redesigned=False)
    page.locator('[data-shell-login]').wait_for(timeout=10000)
    assert page.locator('[data-cr-nsh]').count() == 0
    box = page.locator('div.bg-black', has=page.locator('.xterm')).first
    assert round(box.bounding_box()['height']) == 500
    _no_errors(app)


# --- the subscription --------------------------------------------------------------------------

def _kv(page, k):
    return page.locator(f'[data-cr-nc-kv="subscription"] [data-cr-nc-k="{k}"] dd')


def test_runtime_the_subscription_shows_what_the_node_reports(open_app):
    app = open_app()
    page = app.page
    _node_tab(page, 'Subscription')
    sec = page.locator('[data-cr-sub][data-cr-sub-state="ok"]')
    sec.wait_for(timeout=8000)
    badge = sec.locator('[data-cr-sub-status="active"] .cr-badge')
    assert badge.inner_text().strip() == 'Active' and 'cr-badge-success' in badge.get_attribute('class')
    assert _kv(page, 'level').inner_text() == 'Community (c)'
    assert _kv(page, 'product').inner_text() == NODE_SUB['productname']
    assert _kv(page, 'serverid').inner_text() == NODE_SUB['serverid']
    # the key with its middle hidden until asked
    key = sec.locator('[data-cr-sub-key]')
    assert key.get_attribute('data-cr-sub-key') == 'masked' and key.inner_text() == 'pve1c-' + '•' * 6 + '3d4e'
    sec.locator('[data-cr-sub-reveal]').click()
    assert key.inner_text() == NODE_SUB['key'] and sec.locator('[data-cr-sub-reveal]').inner_text() == 'Hide'
    sec.locator('[data-cr-sub-reveal]').click()
    assert key.get_attribute('data-cr-sub-key') == 'masked'
    # dates through crFmtDate: the reported calendar days, the check time as a time
    assert _kv(page, 'registered').inner_text() == _fmt(page, [2026, 1, 15], date_only=True)
    assert _kv(page, 'nextdue').inner_text() == _fmt(page, [2027, 1, 15], date_only=True)
    assert _kv(page, 'checked').inner_text() == _fmt(page, FIXED - 86400)
    link = sec.locator('[data-cr-sub-url] a')
    assert link.get_attribute('href') == NODE_SUB['url'] and link.get_attribute('target') == '_blank'
    assert 'noopener' in link.get_attribute('rel')
    # one read of the classic route on open, Refresh reads it again
    assert app.server.reads(SUB) == 1
    sec.locator('[data-cr-sub-reload]').click()
    _until(page, lambda: app.server.reads(SUB) == 2, 'Refresh reads the subscription again')
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-updating]")', timeout=5000)
    assert [c for c in app.server.calls if c[0] != 'GET' and 'subscription' in c[1]] == []
    assert page.locator('table.corp-property-grid').count() == 0
    _no_errors(app)


def test_runtime_a_subscription_read_that_failed_or_came_back_empty_is_said(open_app):
    app = open_app(routes={('GET', SUB): 'hold'})
    page = app.page
    _node_tab(page, 'Subscription')
    page.locator('[data-cr-sub-state="loading"] [data-cr-nc-state="loading"]').wait_for(timeout=8000)
    app.server.held.pop().fulfill(status=500, body='{"error": "Could not connect"}', headers={'Content-Type': 'application/json'})
    err = page.locator('[data-cr-sub-state="error"] [data-cr-nc-state="error"]')
    err.wait_for(timeout=5000)
    assert err.inner_text().startswith('The subscription of the node could not be read: Could not connect')
    assert page.locator('[data-cr-sub-status]').count() == 0
    # the empty answer of get_node_subscription: not "no subscription", not a state
    app.server.routes[('GET', SUB)] = (200, {})
    err.locator('[data-cr-nc-retry]').click()
    empty = page.locator('[data-cr-sub-state="empty"] [data-cr-nc-state="warning"]')
    empty.wait_for(timeout=5000)
    assert 'pve1 reported no subscription data' in empty.inner_text() and 'read that failed' in empty.inner_text()
    assert page.locator('[data-cr-sub-status]').count() == 0
    _no_errors(app)


def test_runtime_no_subscription_an_unknown_word_and_missing_fields(open_app):
    app = open_app(routes={('GET', SUB): (200, {'status': 'notfound', 'serverid': 'ABCD', 'message': 'There is no subscription key',
                                                 'checktime': FIXED - 60})})
    page = app.page
    _node_tab(page, 'Subscription')
    sec = page.locator('[data-cr-sub-state="ok"]')
    sec.wait_for(timeout=8000)
    badge = sec.locator('[data-cr-sub-status="notfound"] .cr-badge')
    assert badge.inner_text().strip() == 'No subscription' and 'cr-badge-neutral' in badge.get_attribute('class')
    assert [k.get_attribute('data-cr-nc-k') for k in sec.locator('[data-cr-nc-k]').all()] == ['serverid', 'checked']
    assert sec.locator('[data-cr-sub-message]').inner_text() == 'There is no subscription key'
    # a word the page does not know is shown as the node said it; a field the node left out says so
    app.server.routes[('GET', SUB)] = (200, {'status': 'Grace', 'level': 'x', 'url': 'javascript:alert(1)'})
    sec.locator('[data-cr-sub-reload]').click()
    page.locator('[data-cr-sub-status="other"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-sub-status="other"] .cr-badge').inner_text().strip() == 'Grace'
    assert _kv(page, 'level').inner_text() == 'x'
    for k in ('product', 'serverid', 'key', 'registered', 'nextdue', 'checked'):
        assert _kv(page, k).locator('[data-cr-nc-missing]').inner_text() == 'not reported', k
    assert page.locator('[data-cr-sub-url]').count() == 0
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_subscription_grid(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _node_tab(page, 'Subscription', redesigned=False)
    page.locator('table.corp-property-grid', has_text='Community Subscription').wait_for(timeout=8000)
    assert page.locator('[data-cr-sub]').count() == 0
    _no_errors(app)


# --- layout ------------------------------------------------------------------------------------

@pytest.mark.parametrize('width', [1600, 1280, 1024])
@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_no_sideways_scroll(open_app, request, width, engine):
    app = open_app(viewport=(width, 900), br=request.getfixturevalue('firefox') if engine == 'firefox' else None)
    page = app.page
    _Shell(app)
    fits = lambda: page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth')
    _node_timeline(page)
    page.locator('[data-cr-tl-read="ok"]').wait_for(timeout=8000)
    page.locator('[data-cr-tl-toggle="audit:7"]').click()
    page.locator('[data-cr-tl-detail]').wait_for(timeout=5000)
    assert fits(), f'timeline at {width}'
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Subscription').click()
    page.locator('[data-cr-sub-state="ok"]').wait_for(timeout=8000)
    assert fits(), f'subscription at {width}'
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Shell').click()
    page.locator('[data-cr-nsh-state="login"]').wait_for(timeout=10000)
    assert fits(), f'shell at {width}'
    _no_errors(app)
