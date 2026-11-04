"""Summary, tasks and guests of a node in Corporate Redesigned (Preview), in the browser.

Round 6 draws three parts of the node view in the preview from web/src/cr_node.js. Summary: the
node's health from what the view already holds (cluster metrics, the node summary, the sensors the
Hardware tab read, the active alerts the alert strip read), each condition with the limit it was
judged by, CPU and memory open Monitor > Performance. A value that is not there says "not
reported", an offline node's zeros are no measurement. Tasks: the node's task list by state as
Proxmox VE keeps it (no end time running, "OK", "WARNINGS: n", anything else failed) with counts,
a search by type, UPID and user, failed tasks marked, and a row that opens its log (and its status
while it runs). Guests: the node's guests searched, filtered by type and state, sorted by CPU and
memory, a row opens the guest, the agent state only where the resource list carries it. Classic
Corporate keeps its tables.

The pure parts are checked through window.PegaProxNodeSum. PEGAPROX_CR_BUNDLE=<file> serves another
bundle (the counterproof against the build before this stage). Skips without Playwright. LW Nov 2026
"""
import copy
import datetime
import json
import os
import re
from urllib.parse import unquote

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, FIXED, GUESTS_PVE1, HW_CONSENT, METRICS, NODE_HW, NODE_IP,
                                           NODE_SENSORS, NODE_SUMMARY, NODE_TASK_LIST, NODE_TEMPS, RF_CONSENT,
                                           _GuardApp, _GuardServer, _corp_cluster)

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

NODE = '/api/clusters/c1/nodes/pve1'
TASKS = NODE + '/tasks'
ALERTS = '/api/clusters/c1/active-alerts'
RUNNING, OK, WARNED, MIGRATE, APT, CTSTART = [t['upid'] for t in NODE_TASK_LIST]
LOGS = {
    RUNNING: ['INFO: starting new backup job: vzdump 100', 'INFO:  12% (3.8 GiB of 32.0 GiB) in 5s'],
    OK: ['start VM 100: UPID ok', 'TASK OK'],
    WARNED: ['INFO: backup of CT 101', 'WARN: something to look at', 'TASK WARNINGS: 2'],
    MIGRATE: ['2026-10-30 07:30:00 starting migration of VM 100', 'migration aborted', 'TASK ERROR: migration aborted'],
}
ALERT_ROWS = [
    {'id': 'a1', 'alert_id': 'r1', 'severity': 'critical', 'message': 'pve1 memory above 95 %', 'target_type': 'node',
     'target_name': 'pve1', 'metric': 'mem', 'current_value': 96, 'threshold': 95, 'operator': '>',
     'triggered_at': '2026-10-30T08:00:00', 'last_fired_at': '2026-10-30T08:55:00', 'acked_at': None, 'acked_by': None,
     'escalation_step': 0, 'object_key': '', 'muted_until': None},
    {'id': 'a2', 'alert_id': 'r2', 'severity': 'warning', 'message': 'pve2 cpu', 'target_type': 'node',
     'target_name': 'pve2', 'metric': 'cpu', 'current_value': 85, 'threshold': 80, 'operator': '>',
     'triggered_at': '2026-10-30T08:00:00', 'last_fired_at': '2026-10-30T08:55:00', 'acked_at': None, 'acked_by': None,
     'escalation_step': 0, 'object_key': '', 'muted_until': None},
]


class _NodeServer(_GuardServer):
    """The guard fake with the node's summary, its task list with logs and status, its sensors and
    the active alerts; each answer settable while the page runs: (code, body), 'hold' or 'abort'."""

    def __init__(self, routes=None, logs=None, status=None, **kw):
        kw.setdefault('resources', GUESTS_PVE1)
        super().__init__(bundle=BUNDLE, **kw)
        self.routes = {
            ('GET', NODE + '/ip'): (200, NODE_IP),
            ('GET', NODE + '/summary'): (200, NODE_SUMMARY),
            ('GET', TASKS): (200, NODE_TASK_LIST),
            ('GET', NODE + '/rrddata'): (200, {'timeframe': 'hour', 'node': 'pve1', 'timestamps': [], 'metrics': {}}),
            ('GET', NODE + '/sensors'): (200, NODE_SENSORS),
            ('GET', NODE + '/temperature-history'): (200, NODE_TEMPS),
            ('GET', '/api/hardware-monitoring/consent'): (200, HW_CONSENT),
            ('GET', '/api/hardware-monitoring/redfish-consent'): (200, RF_CONSENT),
            ('GET', NODE + '/hardware'): (200, NODE_HW),
            ('GET', ALERTS): (200, {'active_alerts': []}),
        }
        self.routes.update(routes or {})
        self.logs = dict(LOGS, **(logs or {}))
        self.status = dict(status or {})
        self.held = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.match(r'^' + re.escape(TASKS) + r'/(.+)/(log|status)$', path)
        if m and req.method == 'GET':
            upid, what = unquote(m.group(1)), m.group(2)
            self.calls.append(('GET', f'{TASKS}/<{upid}>/{what}'))
            if what == 'log':
                how = self.logs.get(upid, (403, {'error': 'Access denied to this task'}))
                if isinstance(how, list):
                    how = (200, {'log': '\n'.join(how), 'lines': how})
            else:
                seq = self.status.get(upid) or [(502, {'error': 'Task status could not be read'})]
                how = seq.pop(0) if len(seq) > 1 else seq[0]
            code, data = how
            return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        how = self.routes.get((req.method, path))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def reads(self, path):
        return len([c for c in self.calls if c == ('GET', path)])


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

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, storage=None, **kw):
        app = _GuardApp(br or browser, _NodeServer(layout=layout, **kw), viewport=viewport, storage=storage)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _open_node(page):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()


def _tab(page, name):
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text=name).click()


def _open_summary(page):
    _open_node(page)
    page.locator('[data-cr-ns]').wait_for(timeout=8000)


def _open_tasks(page, wait=True):
    _open_node(page)
    _tab(page, 'Monitor')
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Tasks\s*$')).first.click()
    if wait:
        page.locator('[data-cr-nt][data-cr-nt-read="ok"]').wait_for(timeout=8000)


def _open_guests(page):
    _open_node(page)
    _tab(page, 'VMs')
    page.locator('[data-cr-ng]').wait_for(timeout=8000)


def _tile(page, tid):
    return page.locator(f'[data-cr-stat="ns-{tid}"]')


def _trow(page, upid):
    return page.locator('tr.cr-row', has=page.locator(f'[data-cr-nt-row="{upid}"]'))


def _shown_tasks(page):
    return page.eval_on_selector_all('[data-cr-nt] [data-cr-nt-row]', 'els => els.map(e => e.getAttribute("data-cr-nt-row"))')


def _shown_guests(page):
    return page.eval_on_selector_all('[data-cr-ng] [data-cr-ng-row]', 'els => els.map(e => Number(e.getAttribute("data-cr-ng-row")))')


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def sum_page(browser):
    app = _GuardApp(browser, _NodeServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeSum'):
        app.close()
        pytest.fail('the bundle has no node summary helpers (window.PegaProxNodeSum)')
    yield app.page
    app.close()


def _state(page, task, kind='proxmox'):
    return page.evaluate('([t, k]) => window.PegaProxNodeSum.taskState(t, k)', [task, kind])


def _model(page, **kw):
    return page.evaluate('(a) => window.PegaProxNodeSum.model(a)', kw)


def test_rules_task_states_follow_proxmox(sum_page):
    base = {'upid': 'UPID:pve1:1', 'type': 'qmstart', 'starttime': FIXED - 60}
    assert _state(sum_page, base) == 'running'
    # no end time is running whatever the status says
    assert _state(sum_page, dict(base, status='OK')) == 'running'
    assert _state(sum_page, dict(base, endtime=FIXED, status='OK')) == 'ok'
    assert _state(sum_page, dict(base, endtime=FIXED, status='WARNINGS: 2')) == 'warning'
    for text in ('migration aborted', "command 'qm start 100' failed: exit code 1", 'unexpected status', '', None, 'ok'):
        assert _state(sum_page, dict(base, endtime=FIXED, status=text)) == 'failed', text
    # XCP-ng words, as the task center reads them
    assert _state(sum_page, dict(base, status='completed', endtime=FIXED), 'xcpng') == 'ok'
    assert _state(sum_page, dict(base, status='failed', endtime=FIXED), 'xcpng') == 'failed'
    assert _state(sum_page, dict(base, status='running'), 'xcpng') == 'running'


def test_rules_task_search_by_type_upid_and_user(sum_page):
    task = NODE_TASK_LIST[3]
    match = lambda q: sum_page.evaluate('([t, q]) => window.PegaProxNodeSum.taskMatch(t, q)', [task, q])
    assert match('') and match('qmig') and match('ADMIN@pve') and match(task['upid'][5:20])
    # the result text is not searched
    assert not match('aborted') and not match('vzdump')


def test_rules_summary_figures_and_limits(sum_page):
    live = dict(METRICS['pve1'])
    m = _model(sum_page, metrics=live, summary=NODE_SUMMARY, hw=None, alerts=None, node='pve1')
    assert m['state'] == 'online' and m['overall'] == 'normal' and not [i for i in m['items'] if i['level'] != 'info']
    assert round(m['mem'], 1) == 20.0 and m['cpu'] == 5.0 and round(m['swap'], 2) == 6.25 and m['cpus'] == 8
    assert m['load'] == [0.1, 0.2, 0.3] and m['up'] == 86400
    assert 'alerts' in m['missing']
    hot = _model(sum_page, metrics=dict(live, cpu_percent=85.0, mem_used=33e9), summary=NODE_SUMMARY, hw=None,
                 alerts=None, node='pve1')
    levels = {i['id']: i['level'] for i in hot['items']}
    assert levels == {'cpu': 'warning', 'mem': 'critical'} and hot['overall'] == 'critical'
    assert hot['items'][0]['id'] == 'mem', 'the critical condition comes first'
    # load above the logical CPUs, swap without any, a recent start
    s = dict(NODE_SUMMARY, loadavg=['9.50', '4.0', '2.0'], swap={'used': 0, 'total': 0}, uptime=600)
    m = _model(sum_page, metrics=live, summary=s, hw=None, alerts=None, node='pve1')
    levels = {i['id']: i['level'] for i in m['items']}
    assert levels == {'load': 'warning', 'uptime': 'info'} and m['noSwap'] and m['swap'] is None
    assert m['overall'] == 'warning'


def test_rules_summary_never_reads_a_missing_value_as_good(sum_page):
    off = dict(METRICS['pve1'], status='offline', offline=True, cpu_percent=0, mem_used=0, mem_total=0, disk_used=0,
               disk_total=0, uptime=0)
    m = _model(sum_page, metrics=off, summary={}, hw=None, alerts=None, node='pve1')
    assert m['overall'] == 'critical' and m['items'][0]['id'] == 'status'
    assert m['cpu'] is None and m['mem'] is None and m['root'] is None and m['sum'] == 'empty'
    assert {'cpu', 'mem', 'swap', 'root', 'load', 'uptime'} <= set(m['missing'])
    # no metrics at all and a failed summary read: not known, not normal
    m = _model(sum_page, metrics={}, summary=None, hw=None, alerts=None, node='pve1')
    assert m['overall'] == 'unknown' and m['sum'] == 'error' and 'status' in m['missing']
    # an unreadable load is said as such
    m = _model(sum_page, metrics=dict(METRICS['pve1']), summary=dict(NODE_SUMMARY, loadavg=['n/a']), hw=None,
               alerts=None, node='pve1')
    assert m['loadBad'] and not [i for i in m['items'] if i['id'] == 'load']


def test_rules_summary_hardware_and_alerts(sum_page):
    live = dict(METRICS['pve1'])
    # hardware not read yet is said, and does not count as normal hardware
    m = _model(sum_page, metrics=live, summary=NODE_SUMMARY, hw={}, alerts=None, node='pve1')
    assert m['hw']['state'] == 'unread' and 'hwUnread' in m['missing']
    hot = {'sensors': [{'chip': 'coretemp', 'label': 'Package id 0', 'kind': 'temp', 'value': 101.0, 'max': 80.0,
                        'crit': 100.0, 'alarm': False}]}
    m = _model(sum_page, metrics=live, summary=NODE_SUMMARY, hw={'read': hot}, alerts=None, node='pve1')
    assert m['hw']['state'] == 'critical' and m['overall'] == 'critical'
    assert [i for i in m['items'] if i['id'] == 'hw'][0]['vars']['list'] == 'Package id 0'
    # lm-sensors found nothing: no state, never normal
    m = _model(sum_page, metrics=live, summary=NODE_SUMMARY, hw={'read': {'sensors': []}}, alerts=None, node='pve1')
    assert m['hw']['state'] == 'none' and 'hw' in m['missing']
    seen = {'cid': 'c1', 'state': 'ok', 'rows': ALERT_ROWS}
    m = _model(sum_page, metrics=live, summary=NODE_SUMMARY, hw=None, alerts=seen, node='pve1')
    assert m['alerts']['n'] == 1 and m['alerts']['sev']['critical'] == 1 and m['overall'] == 'critical'
    m = _model(sum_page, metrics=live, summary=NODE_SUMMARY, hw=None, alerts=dict(seen, state='error', rows=None), node='pve1')
    # a failed alert read is not "no warning"
    assert m['alerts']['state'] == 'error' and 'alertsFailed' in m['missing'] and m['overall'] == 'unknown'


NOW = FIXED * 1000
LM_FINE = {'sensors': [{'chip': 'coretemp-isa-0000', 'label': 'Package id 0', 'kind': 'temp', 'value': 54.0, 'max': 80.0,
                        'crit': 100.0, 'alarm': False}]}
HW_PSU_FAILED = dict(NODE_HW, health='critical',
                     health_reasons=[{'source': 'sensor', 'label': 'PS2 Status', 'severity': 'critical'}],
                     sensors=[dict(x, reading='Failure detected', status='critical') if x['name'] == 'PS2 Status' else x
                              for x in NODE_HW['sensors']])


def _bmc(hw, at=NOW, loading=False):
    return {'node': 'pve1', 'loading': loading, 'consent': True, 'hw': hw, 'at': at}


def test_rules_a_failed_or_old_read_is_not_no_warning(sum_page):
    live = dict(METRICS['pve1'])
    base = dict(metrics=live, summary=NODE_SUMMARY, hw=None, alerts=None, node='pve1', now=NOW)
    model = lambda **kw: _model(sum_page, **dict(base, **kw))
    # plain "not read yet" leaves the badge as it is
    assert model()['overall'] == 'normal' and model(hw={})['overall'] == 'normal'
    # a failed or empty summary read, a failed sensor read, a failed in-band read: not fully known
    assert model(summary=None)['overall'] == 'unknown'
    assert model(summary={})['overall'] == 'unknown'
    assert model(hw={'read': {'__crFail': {'status': 502, 'error': 'ssh failed', 'code': ''}}})['overall'] == 'unknown'
    assert model(hw={'read': LM_FINE, 'bmc': _bmc({'error': 'Failed to read hardware'})})['overall'] == 'unknown'
    # an alert read of the strip stands for now for three of its rounds, then it is old
    fresh = {'cid': 'c1', 'state': 'ok', 'rows': [], 'at': NOW - 30000}
    assert model(alerts=fresh)['overall'] == 'normal' and model(alerts=fresh)['alerts']['state'] == 'ok'
    old = model(alerts=dict(fresh, rows=ALERT_ROWS, at=NOW - 4 * 60000))
    assert old['alerts']['state'] == 'old' and 'alertsOld' in old['missing'] and old['overall'] == 'unknown'
    assert not [i for i in old['items'] if i['id'] == 'alerts'] and old['alAge'] == 4 * 60000


def test_rules_the_hardware_tile_keeps_in_band_and_says_what_is_missing(sum_page):
    live = dict(METRICS['pve1'])
    base = dict(metrics=live, summary=NODE_SUMMARY, alerts=None, node='pve1', now=NOW)
    model = lambda hw: _model(sum_page, **dict(base, hw=hw))
    m = model({'read': LM_FINE, 'readAt': NOW, 'bmc': _bmc(HW_PSU_FAILED)})
    assert m['hw']['state'] == 'critical' and m['overall'] == 'critical' and not m['hw']['inbandUnread']
    assert 'PS2 Status' in [i for i in m['items'] if i['id'] == 'hw'][0]['vars']['list']
    # lm-sensors read, in-band not (still loading when the tab was left, or never handed up)
    for bmc in (None, _bmc(None, loading=True)):
        m = model({'read': LM_FINE, 'readAt': NOW, 'bmc': bmc})
        assert m['hw']['state'] == 'normal' and m['hw']['inbandUnread'] and not m['hw']['lmUnread'], bmc
    # the age is that of the older read
    m = model({'read': LM_FINE, 'readAt': NOW - 12 * 60000, 'bmc': _bmc(NODE_HW, at=NOW - 2 * 60000)})
    assert m['hwAge'] == 12 * 60000


def test_rules_guest_filter_and_agent(sum_page):
    match = lambda g, **f: sum_page.evaluate('([g, f]) => window.PegaProxNodeSum.guestMatch(g, f)', [g, f])
    agent = lambda g: sum_page.evaluate('(g) => window.PegaProxNodeSum.guestAgent(g)', g)
    web, ct, _, app02, tpl, ct02 = GUESTS_PVE1
    assert match(web, type='qemu') and not match(ct, type='qemu') and match(ct, type='lxc')
    assert match(tpl, status='stopped') and not match(web, status='stopped') and match(dict(web, status='paused'), status='other')
    assert match(dict(web, tags='prod;web'), q='prod') and match(web, q='100') and match(dict(web, ip='10.0.0.50'), q='10.0.0.5')
    assert not match(web, q='ct0')
    assert [agent(g) for g in (web, app02, ct, tpl)] == ['up', 'down', 'ct', 'off']
    # a running VM the sweep did not report is unknown, never up
    assert agent(dict(web, agent_running=None)) == 'unknown' and agent({k: v for k, v in web.items() if k != 'agent_running'}) == 'unknown'


# --- the summary at runtime -------------------------------------------------------------------

def test_runtime_summary_health_and_links_to_performance(open_app):
    app = open_app()
    page = app.page
    _open_summary(page)
    ns = page.locator('[data-cr-ns]')
    assert ns.get_attribute('data-cr-ns-overall') == 'normal'
    assert 'No warning' in page.locator('[data-cr-ns-badge]').inner_text()
    assert '5.0%' in _tile(page, 'cpu').inner_text() and '8 logical CPUs' in _tile(page, 'cpu').inner_text()
    assert '20.0%' in _tile(page, 'mem').inner_text() and '6.3%' in _tile(page, 'swap').inner_text()
    assert 'KSM shares 0 B' in _tile(page, 'mem').inner_text()
    assert '0.10' in _tile(page, 'load').inner_text() and '1d 0h 0m' in _tile(page, 'uptime').inner_text()
    assert 'Not read yet' in _tile(page, 'hw').inner_text()
    assert 'hwUnread' in page.locator('[data-cr-ns-missing]').get_attribute('data-cr-ns-missing')
    # the system information card sits under it (round 7), the header and the tabs are the same
    page.locator('[data-cr-nsi]').get_by_text('E5-2680').first.wait_for(timeout=5000)
    assert page.locator('[data-cr-objhead="node"]').count() == 1
    _tile(page, 'cpu').click()
    page.locator('.corp-subnav-item.active', has_text='Performance').wait_for(timeout=5000)
    assert page.locator('[data-cr-tabs="node"] [role="tab"][aria-selected="true"]').inner_text().strip() == 'Monitor'
    # from another sub tab of Monitor too
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Tasks\s*$')).first.click()
    _tab(page, 'Summary')
    _tile(page, 'mem').click()
    page.locator('.corp-subnav-item.active', has_text='Performance').wait_for(timeout=5000)
    _tab(page, 'Summary')
    _tile(page, 'hw').click()
    page.locator('[data-cr-nh]').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_summary_highlights_critical_conditions(open_app):
    hot = dict(METRICS, pve1=dict(METRICS['pve1'], cpu_percent=95.5, mem_used=29e9))
    app = open_app(metrics=hot, routes={('GET', ALERTS): (200, {'active_alerts': ALERT_ROWS})})
    page = app.page
    _open_summary(page)
    ns = page.locator('[data-cr-ns]')
    page.locator('[data-cr-ns-item="alerts"]').wait_for(timeout=8000)
    assert ns.get_attribute('data-cr-ns-overall') == 'critical'
    assert 'cr-stat-error' in _tile(page, 'cpu').get_attribute('class')
    assert 'cr-stat-warning' in _tile(page, 'mem').get_attribute('class')
    items = page.eval_on_selector_all('[data-cr-ns-item]', 'els => els.map(e => [e.dataset.crNsItem, e.dataset.crNsLevel])')
    assert items[:2] == [['cpu', 'critical'], ['alerts', 'critical']] and ['mem', 'warning'] in items
    assert 'above 90 %' in page.locator('[data-cr-ns-item="cpu"]').inner_text()
    # the alert of pve2 is not this node's
    assert _tile(page, 'alerts').inner_text().split('\n')[1].strip() == '1'
    assert page.locator('[data-cr-ns-item="cpu"]').evaluate('e => getComputedStyle(e).fontWeight') in ('600', '700')
    _no_errors(app)


def test_runtime_summary_of_an_offline_node(open_app):
    off = dict(METRICS, pve1=dict(METRICS['pve1'], status='offline', offline=True, cpu_percent=0, mem_used=0,
                                  mem_total=0, disk_used=0, disk_total=0, uptime=0))
    app = open_app(metrics=off, routes={('GET', NODE + '/summary'): (200, {})})
    page = app.page
    _open_summary(page)
    page.locator('[data-cr-ns-sum="empty"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-ns]').get_attribute('data-cr-ns-overall') == 'critical'
    assert page.locator('[data-cr-ns-item="status"][data-cr-ns-level="critical"]').count() == 1
    for tid in ('cpu', 'mem', 'root', 'swap', 'load', 'uptime'):
        assert 'not reported' in _tile(page, tid).inner_text(), tid
        assert '0.0%' not in _tile(page, tid).inner_text(), tid
    # the zeros of an offline node are drawn nowhere on the tab: the capacity card is in the tiles
    page.locator('[data-cr-nsi]').wait_for(timeout=5000)
    assert page.get_by_text('Capacity & Usage').count() == 0
    assert not re.search(r'(?<![\d.])0(\.0)? B\b', page.locator('body').inner_text())
    _no_errors(app)


def test_runtime_summary_read_states(open_app):
    app = open_app(routes={('GET', NODE + '/summary'): 'hold'})
    page = app.page
    _open_node(page)
    page.locator('[data-cr-ns-sum="loading"]').wait_for(timeout=8000)
    app.server.routes[('GET', NODE + '/summary')] = (500, {'error': 'Cluster not connected'})
    for r in app.server.held:
        r.fulfill(status=500, body='{"error": "x"}', headers={'Content-Type': 'application/json'})
    page.locator('[data-cr-ns-sum="error"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-ns]').get_attribute('data-cr-ns-overall') == 'unknown'
    before = app.server.reads(NODE + '/summary')
    app.server.routes[('GET', NODE + '/summary')] = (200, NODE_SUMMARY)
    page.locator('[data-cr-ns-retry]').click()
    page.locator('[data-cr-ns-sum]').wait_for(state='detached', timeout=8000)
    assert app.server.reads(NODE + '/summary') == before + 1
    assert '0.10' in _tile(page, 'load').inner_text()
    _no_errors(app)


def test_runtime_summary_takes_the_hardware_the_tab_read(open_app):
    hot = {'sensors': [dict(NODE_SENSORS['sensors'][0], value=101.0)] + NODE_SENSORS['sensors'][1:]}
    app = open_app(routes={('GET', NODE + '/sensors'): (200, hot)})
    page = app.page
    _open_summary(page)
    reads = app.server.reads(NODE + '/sensors')
    assert reads == 0, 'the summary reads no sensors itself'
    _tab(page, 'Hardware')
    page.locator('[data-cr-nh-src="lm"][data-cr-nh-src-state="ok"]').wait_for(timeout=8000)
    _tab(page, 'Summary')
    page.locator('[data-cr-ns-item="hw"]').wait_for(timeout=8000)
    assert 'Package id 0' in page.locator('[data-cr-ns-item="hw"]').inner_text()
    assert 'cr-stat-error' in _tile(page, 'hw').get_attribute('class')
    assert page.locator('[data-cr-ns]').get_attribute('data-cr-ns-overall') == 'critical'
    _no_errors(app)


def test_runtime_the_summary_keeps_the_in_band_state_after_the_hardware_tab(open_app):
    app = open_app(routes={('GET', NODE + '/sensors'): (200, LM_FINE), ('GET', NODE + '/hardware'): (200, HW_PSU_FAILED)})
    page = app.page
    _open_summary(page)
    _tab(page, 'Hardware')
    page.locator('[data-cr-nh-src="bmc"][data-cr-nh-src-state="ok"]').wait_for(timeout=8000)
    page.locator('[data-cr-nh-src="lm"][data-cr-nh-src-state="ok"]').wait_for(timeout=8000)
    _tab(page, 'Summary')
    page.locator('[data-cr-ns-item="hw"]').wait_for(timeout=8000)
    assert 'PS2 Status' in page.locator('[data-cr-ns-item="hw"]').inner_text()
    assert 'cr-stat-error' in _tile(page, 'hw').get_attribute('class')
    assert page.locator('[data-cr-ns]').get_attribute('data-cr-ns-overall') == 'critical'
    _no_errors(app)


def test_runtime_the_hardware_tile_says_what_was_not_read_and_how_old_it_is(open_app):
    app = open_app(routes={('GET', NODE + '/sensors'): (200, LM_FINE), ('GET', NODE + '/hardware'): 'hold'})
    page = app.page
    _open_summary(page)
    _tab(page, 'Hardware')
    page.locator('[data-cr-nh-src="lm"][data-cr-nh-src-state="ok"]').wait_for(timeout=8000)
    _tab(page, 'Summary')
    tile = _tile(page, 'hw')
    tile.wait_for(timeout=8000)
    assert 'in-band not read' in tile.inner_text() and 'min ago' not in tile.inner_text(), tile.inner_text()
    # twelve minutes on, the same read says its age
    app.ctx.clock.set_fixed_time(datetime.datetime.fromtimestamp(FIXED + 12 * 60, tz=datetime.timezone.utc))
    _tab(page, 'Monitor')
    _tab(page, 'Summary')
    page.wait_for_function('() => /read 12 min ago/.test(document.querySelector(\'[data-cr-stat="ns-hw"]\').innerText)', timeout=8000)
    _no_errors(app)


# --- the tasks at runtime ---------------------------------------------------------------------

def test_runtime_tasks_by_state_with_counts_and_failed_marked(open_app):
    app = open_app()
    page = app.page
    _open_tasks(page)
    reads = app.server.reads(TASKS)
    counts = {e: page.locator(f'[data-cr-nt-count="{e}"]').inner_text() for e in ('all', 'ok', 'running', 'warning', 'failed')}
    assert counts == {'all': '6', 'ok': '2', 'running': '1', 'warning': '1', 'failed': '2'}
    states = page.eval_on_selector_all('[data-cr-nt-state]', 'els => els.map(e => e.dataset.crNtState)')
    assert states == ['running', 'ok', 'warning', 'failed', 'ok', 'failed']
    assert 'cr-nt-row-failed' in _trow(page, MIGRATE).get_attribute('class')
    assert 'cr-nt-row-warn' in _trow(page, WARNED).get_attribute('class')
    assert 'cr-nt-row-failed' not in _trow(page, OK).get_attribute('class')
    assert page.locator('[data-cr-nt-failed-note="2"]').count() == 1
    assert 'cr-nt-seg-failed' in page.locator('[data-cr-nt-filter="failed"]').get_attribute('class')
    # the result of a failed task is there in the error colour, the user and the guest too
    assert 'migration aborted' in _trow(page, MIGRATE).inner_text() and 'admin@pve' in _trow(page, MIGRATE).inner_text()
    assert _trow(page, MIGRATE).locator('.cr-tc-result-error').count() == 1
    assert 'web01 (100)' in _trow(page, OK).inner_text()
    page.locator('[data-cr-nt-show-failed]').click()
    assert _shown_tasks(page) == [MIGRATE, CTSTART]
    page.locator('[data-cr-nt-filter="warning"]').click()
    assert _shown_tasks(page) == [WARNED]
    page.locator('[data-cr-nt-filter="running"]').click()
    assert _shown_tasks(page) == [RUNNING]
    page.locator('[data-cr-nt-filter="ok"]').click()
    assert _shown_tasks(page) == [OK, APT]
    page.locator('[data-cr-nt-clear]').click()
    assert len(_shown_tasks(page)) == 6
    assert app.server.reads(TASKS) == reads, 'filters ask nothing'
    _no_errors(app)


def test_runtime_tasks_search(open_app):
    app = open_app()
    page = app.page
    _open_tasks(page)
    q = page.locator('[data-cr-nt-q]')
    q.fill('admin@pve')
    assert _shown_tasks(page) == [MIGRATE]
    q.fill('vzdump')
    assert _shown_tasks(page) == [RUNNING, WARNED]
    q.fill(APT.split(':')[2])
    assert _shown_tasks(page) == [APT]
    q.fill('aborted')
    assert _shown_tasks(page) == []
    assert page.locator('[data-cr-nt] .cr-state-row').inner_text().strip() != ''
    page.locator('[data-cr-nt-filter="failed"]').click()
    q.fill('vzstart')
    assert _shown_tasks(page) == [CTSTART]
    _no_errors(app)


def test_runtime_a_task_row_opens_its_log_with_its_state(open_app):
    app = open_app()
    page = app.page
    _open_tasks(page)
    _trow(page, MIGRATE).click()
    pane = page.locator(f'[data-cr-nt-log="{MIGRATE}"]')
    pane.wait_for(timeout=5000)
    pane.get_by_text('TASK ERROR: migration aborted').wait_for(timeout=5000)
    assert pane.locator('.cr-tc-log-head').inner_text().count('Failed') == 1
    assert pane.get_attribute('data-cr-nt-log-state') == 'failed'
    assert pane.locator('[data-cr-tc-details]').count() == 0
    assert app.server.reads(f'{TASKS}/<{MIGRATE}>/log') == 1
    assert 'corp-row-selected' in _trow(page, MIGRATE).get_attribute('class')
    _trow(page, WARNED).click()
    pane = page.locator(f'[data-cr-nt-log="{WARNED}"]')
    pane.get_by_text('TASK WARNINGS: 2').wait_for(timeout=5000)
    assert 'Warning' in pane.locator('.cr-tc-log-head').inner_text()
    _trow(page, APT).click()
    # a log the caller may not read says so
    page.locator(f'[data-cr-nt-log="{APT}"] .cr-state-error').wait_for(timeout=5000)
    page.locator('[data-cr-tc-log-close]').click()
    assert page.locator('[data-cr-nt-log]').count() == 0
    # no status is asked for a task that ended
    assert not [c for c in app.server.calls if '/tasks/' in c[1] and c[1].endswith('/status')]
    _no_errors(app)


def test_runtime_a_running_task_ends_in_its_log(open_app):
    app = open_app(status={RUNNING: [(200, {'status': 'running', 'upid': RUNNING}),
                                     (200, {'status': 'stopped', 'exitstatus': 'WARNINGS: 1', 'upid': RUNNING})]})
    page = app.page
    _open_tasks(page)
    reads = app.server.reads(TASKS)
    ended = [dict(NODE_TASK_LIST[0], endtime=FIXED + 30, status='WARNINGS: 1')] + NODE_TASK_LIST[1:]
    _trow(page, RUNNING).click()
    pane = page.locator(f'[data-cr-nt-log="{RUNNING}"]')
    pane.get_by_text('12% (3.8 GiB').wait_for(timeout=5000)
    assert pane.get_attribute('data-cr-nt-log-state') == 'running'
    assert 'Running' in pane.locator('.cr-tc-log-head').inner_text()
    app.server.routes[('GET', TASKS)] = (200, ended)
    page.locator(f'[data-cr-nt-log="{RUNNING}"][data-cr-nt-log-state="warning"]').wait_for(timeout=12000)
    assert 'Warning' in pane.locator('.cr-tc-log-head').inner_text()
    page.wait_for_function(f'() => document.querySelector(\'[data-cr-nt-row="{RUNNING}"]\').dataset.crNtState === "warning"', timeout=8000)
    assert app.server.reads(f'{TASKS}/<{RUNNING}>/status') == 2
    assert app.server.reads(TASKS) == reads + 1, 'the list is read again for the end time'
    _no_errors(app)


def test_runtime_task_list_states(open_app):
    app = open_app(routes={('GET', TASKS): 'hold'})
    page = app.page
    _open_tasks(page, wait=False)
    page.locator('[data-cr-nt][data-cr-nt-read="loading"]').wait_for(timeout=8000)
    assert 'Loading' in page.locator('[data-cr-nt] .cr-state-row').inner_text()
    for r in app.server.held:
        r.fulfill(status=502, body=json.dumps({'error': 'Proxmox API not reachable'}), headers={'Content-Type': 'application/json'})
    page.locator('[data-cr-nt-error]').wait_for(timeout=8000)
    assert 'Proxmox API not reachable' in page.locator('[data-cr-nt-error]').inner_text()
    assert page.locator('[data-cr-nt-count="all"]').inner_text() == '-'
    app.server.routes[('GET', TASKS)] = (200, [])
    page.locator('[data-cr-nt-retry]').click()
    page.locator('[data-cr-nt][data-cr-nt-read="empty"]').wait_for(timeout=8000)
    # the route fails a failed read now, so an empty answer carries no doubt
    assert page.locator('[data-cr-nt] .cr-state-row').inner_text().strip() == 'No tasks reported for pve1.'
    assert page.locator('[data-cr-nt-count="failed"]').inner_text() == '0'
    _no_errors(app)


def test_runtime_a_task_guest_opens_the_guest(open_app):
    app = open_app()
    page = app.page
    _open_tasks(page)
    _trow(page, OK).locator('[data-cr-nt-guest="100"]').click()
    page.locator('.cr-objhead-name', has_text='web01').wait_for(timeout=8000)
    assert page.locator('[data-cr-nt-log]').count() == 0
    _no_errors(app)


# --- the guests at runtime --------------------------------------------------------------------

def test_runtime_guests_search_filter_sort_and_agent(open_app):
    app = open_app()
    page = app.page
    _open_guests(page)
    assert _shown_guests(page) == [103, 101, 105, 104, 100]
    types = page.locator('[data-cr-ng-types]')
    states = page.locator('[data-cr-ng-states]')
    seg = lambda loc: loc.locator('button').evaluate_all('bs => bs.map(b => b.textContent)')
    assert seg(types) == ['All5', 'VM3', 'CT2']
    assert seg(states) == ['All5', 'Running3', 'Stopped2', 'Other0']
    types.locator('[data-cr-ng-filter="lxc"]').click()
    assert _shown_guests(page) == [101, 105]
    states.locator('[data-cr-ng-filter="stopped"]').click()
    assert _shown_guests(page) == [105]
    page.locator('[data-cr-ng-clear]').click()
    page.locator('[data-cr-ng-q]').fill('app')
    assert _shown_guests(page) == [103]
    page.locator('[data-cr-ng-q]').fill('')
    # CPU and memory sort, the stopped ones stay at the end
    page.locator('[data-cr-ng] th[data-cr-col="cpu"] button').click()
    page.locator('[data-cr-ng] th[data-cr-col="cpu"] button').click()
    assert _shown_guests(page)[:3] == [103, 100, 101]
    page.locator('[data-cr-ng] th[data-cr-col="mem"] button').click()
    assert _shown_guests(page)[:3] == [101, 100, 103]
    page.locator('[data-cr-ng] th[data-cr-col="mem"] button').click()
    assert _shown_guests(page)[:3] == [103, 100, 101]
    agents = dict(page.eval_on_selector_all('[data-cr-ng] tr.cr-row', """rows => rows.map(r => [
        Number(r.querySelector('[data-cr-ng-row]').dataset.crNgRow), r.querySelector('[data-cr-ng-agent]').dataset.crNgAgent])"""))
    assert agents == {100: 'up', 103: 'down', 101: 'ct', 104: 'off', 105: 'ct'}
    assert page.locator('[data-cr-ng-row="104"]').get_by_text('Template').count() == 1
    assert page.locator('[data-cr-ng-cpu]').count() == 3
    # a row opens the guest the way the classic table does
    page.locator('tr.cr-row', has=page.locator('[data-cr-ng-row="103"]')).click()
    page.locator('.cr-objhead-name', has_text='app02').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_guests_ask_nothing_per_guest(open_app):
    many = GUESTS_PVE1 + [dict(GUESTS_PVE1[0], vmid=1000 + i, name=f'g{i:03d}', agent_running=i % 3 == 0) for i in range(240)]
    app = open_app(resources=many)
    page = app.page
    _open_node(page)
    page.locator('[data-cr-ns]').wait_for(timeout=8000)
    page.wait_for_timeout(500)
    before = list(app.server.calls)
    _tab(page, 'VMs')
    page.locator('[data-cr-ng]').wait_for(timeout=8000)
    page.wait_for_timeout(1500)
    new = [c for c in app.server.calls[len(before):] if re.search(r'/vms/|/agent|/qemu/|/lxc/', c[1])]
    assert new == []
    assert page.locator('[data-cr-ng-types] [data-cr-ng-filter="all"]').text_content().endswith('245')
    # above 200 rows only what is in view is in the page
    assert page.locator('[data-cr-ng] tr.cr-row').count() < 120


def test_runtime_guests_empty(open_app):
    app = open_app(resources=[dict(GUESTS_PVE1[0], node='pve2')])
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    _tab(page, 'VMs')
    page.locator('[data-cr-ng]').wait_for(timeout=8000)
    assert 'No guests of pve1' in page.locator('[data-cr-ng] .cr-state-row').inner_text()
    _no_errors(app)


# --- classic and layout -----------------------------------------------------------------------

def test_runtime_classic_corporate_is_unchanged(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.get_by_text('E5-2680').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-ns]').count() == 0
    page.locator('.corp-tab-strip button', has_text='Monitor').first.click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Tasks\s*$')).first.click()
    page.get_by_text('migration aborted').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-nt]').count() == 0
    table = page.locator('.corp-datagrid').filter(has=page.get_by_text('migration aborted', exact=True))
    assert table.locator('thead th').count() == 4
    page.locator('.corp-tab-strip button', has_text='VMs').first.click()
    page.get_by_text('tpl-debian').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-ng]').count() == 0
    table = page.locator('.corp-datagrid').filter(has=page.get_by_text('tpl-debian', exact=True))
    assert table.locator('thead th').count() == 6
    assert not [c for c in app.server.calls if '/tasks/' in c[1] and (c[1].endswith('/log') or c[1].endswith('/status'))]


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('firefox', 1600), ('firefox', 1280)])
def test_runtime_layout_without_sideways_scroll(open_app, firefox, browser, engine, width):
    hot = dict(METRICS, pve1=dict(METRICS['pve1'], cpu_percent=95.5))
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser, metrics=hot)
    page = app.page
    _open_summary(page)
    page.locator('[data-cr-ns-item="cpu"]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS)
    assert page.locator('[data-cr-ns]').evaluate('e => e.getBoundingClientRect().right <= window.innerWidth')
    _tab(page, 'Monitor')
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Tasks\s*$')).first.click()
    page.locator('[data-cr-nt][data-cr-nt-read="ok"]').wait_for(timeout=8000)
    _trow(page, MIGRATE).click()
    page.locator(f'[data-cr-nt-log="{MIGRATE}"]').get_by_text('TASK ERROR').wait_for(timeout=5000)
    assert page.evaluate(_NO_SIDEWAYS)
    # the task view stays inside the page: nothing cut off at the right edge, the table fits
    for sel in ('[data-cr-nt]', '[data-cr-nt-failed-note]', f'[data-cr-nt-log="{MIGRATE}"]'):
        assert page.locator(sel).evaluate('e => e.getBoundingClientRect().right <= window.innerWidth'), sel
    scroll = page.locator('[data-cr-nt] .cr-table-scroll')
    assert scroll.evaluate('e => e.scrollWidth <= e.clientWidth + 1'), 'the task table scrolls sideways'
    _tab(page, 'VMs')
    page.locator('[data-cr-ng]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS)
    assert page.locator('[data-cr-ng]').evaluate('e => e.getBoundingClientRect().right <= window.innerWidth')
    scroll = page.locator('[data-cr-ng] .cr-table-scroll')
    assert scroll.evaluate('e => e.scrollWidth <= e.clientWidth + 1'), 'the guest table scrolls sideways'
    _no_errors(app)


def test_runtime_widened_task_columns_scroll_inside_the_table(open_app):
    """The Monitor sub tabs sit in a flex row: columns a user widened scroll inside the table and
    never push the view out of the page."""
    app = open_app(viewport=(1280, 900), storage={'cr-table:node-tasks': json.dumps({'w': {'result': 900}})})
    page = app.page
    _open_tasks(page)
    for sel in ('[data-cr-nt]', '[data-cr-nt-failed-note]', '[data-cr-nt-reload]'):
        assert page.locator(sel).evaluate('e => e.getBoundingClientRect().right <= window.innerWidth'), sel
    scroll = page.locator('[data-cr-nt] .cr-table-scroll')
    assert scroll.evaluate('e => e.scrollWidth > e.clientWidth + 100'), 'the widened column is not there'
    assert page.evaluate(_NO_SIDEWAYS)
    _no_errors(app)
