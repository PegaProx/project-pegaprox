"""The Updates tab in Corporate Redesigned (Preview), round 4.

The update manager of a cluster as a tab of its own beside Settings in the variant, on the routes of the
classic section: opening it reads the server's copy of the last check (/updates-overview, it asks
no node), the rolling update of the cluster and its schedule, nothing else; a check (apt update on
every online node) only runs from its own button and dialog; nothing installs except a rolling
update started in its dialog or armed in the schedule. The page says what the sources do not
carry: no security or critical class for Proxmox VE, no reboot-required state (only "kernel
package pending"), no guest packages, no package versions in the history; unread, failed and
missing are states, never a 0. The start dialog has safe defaults (no reboot, skip evacuation only
after a danger tick), a node order sent as node_order, an advisory marked as calculated here, and
the gates the engine itself enforces. In the variant the Settings tab only links here, so the
classic auto-check on mount never fires. Classic Corporate, Modern and Cloud keep their section to
the pixel (tests/test_corp_redesigned_guard_ui.py, view "updates").

The fake serves the real shapes of pegaprox/api/settings.py (check, status, overview, rolling,
history, plan), schedules.py (schedule) and whatif.py (headroom). PEGAPROX_CR_BUNDLE=<file> serves
another bundle (the counterproof). LW Nov 2026
"""
import copy
import json
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, _GuardApp, _GuardServer
from test_ha_ui import CLUSTER, NODE_METRICS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
AT = FIXED - 3 * 3600          # the server's copy of the last check, three hours old


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _node(name, **kw):
    m = dict(NODE_METRICS['pve1'], pveversion='pve-manager/9.0.3/0a1b2c3d', kversion='Linux 6.14.8-2-pve #1 SMP PREEMPT_DYNAMIC')
    m.update(kw)
    return m


# five nodes, one of each kind: updates with a kernel, up to date, a failed check, offline (so not in
# the check), in maintenance with updates
METRICS = {
    'pve1': _node('pve1'),
    'pve2': _node('pve2'),
    'pve3': _node('pve3'),
    # the offline branch of manager.get_node_status
    'pve4': {'status': 'offline', 'cpu_percent': 0, 'mem_percent': 0, 'mem_used': 0, 'mem_total': 0, 'disk_percent': 0,
             'disk_used': 0, 'disk_total': 0, 'netin': 0, 'netout': 0, 'score': 0, 'uptime': 0, 'maintenance_mode': False,
             'maintenance_task': None, 'maintenance_acknowledged': False, 'offline': True, 'last_seen': None},
    'pve5': _node('pve5', maintenance_mode=True),
}
PKG = {
    'pve1': [{'Package': 'pve-manager', 'OldVersion': '9.0.3', 'Version': '9.0.10', 'Origin': 'Proxmox', 'Section': 'admin', 'Priority': 'optional'},
             {'Package': 'proxmox-kernel-6.14', 'OldVersion': '6.14.8-2', 'Version': '6.14.11-1', 'Origin': 'Proxmox', 'Section': 'kernel'},
             {'Package': 'proxmox-kernel-helper', 'OldVersion': '9.0.2', 'Version': '9.0.3', 'Origin': 'Proxmox', 'Section': 'admin'},
             {'Package': 'libssl3', 'OldVersion': '3.0.15-1~deb12u1', 'Version': '3.0.17-1~deb12u2', 'Origin': 'Debian', 'Section': 'libs'},
             {'Package': 'proxmox-kernel-6.14.11-1-pve-signed', 'Version': '6.14.11-1', 'Origin': 'Proxmox', 'Section': 'kernel'}],
    'pve2': [],
    'pve5': [{'Package': 'zfsutils-linux', 'OldVersion': '2.3.2-pve1', 'Version': '2.3.4-pve1', 'Origin': 'Proxmox', 'Section': 'admin'},
             {'Package': 'curl', 'OldVersion': '7.88.1-10+deb12u12', 'Version': '7.88.1-10+deb12u14', 'Origin': 'Debian', 'Section': 'web'}],
}


def _host(name, ok=True, count=None, kernel=False, channel='no-subscription', warnings=0, sub='notfound', kind='node',
          security=None, stale=False, at=AT):
    """One row of /api/updates-overview as settings._overview_host builds it."""
    return {'ok': ok, 'count': count if ok else None, 'security': security, 'kernel': kernel, 'channel': channel,
            'repo_warnings': warnings, 'subscription': sub, 'cluster_id': 'c1', 'cluster_name': 'Testi', 'kind': kind,
            'name': name, 'pbs_id': 'p1' if kind == 'pbs' else None, 'checked_at': at, 'stale': stale}


def _overview(state='ok', stale=False, rolling=None, hosts=None, at=AT):
    entry = {'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': state, 'count': 0, 'checked_at': None, 'stale': False,
             'rolling': rolling}
    if state != 'ok':
        return {'hosts': [], 'clusters': [entry]}
    if hosts is None:
        hosts = [_host('pve1', count=5, kernel=True, stale=stale, at=at), _host('pve2', count=0, stale=stale, at=at),
                 _host('pve3', ok=False, channel='enterprise', warnings=1, stale=stale, at=at),
                 _host('pve5', count=2, stale=stale, at=at),
                 _host('backup01', count=1, kind='pbs', stale=stale, at=at)]
    entry.update(count=sum(h['count'] or 0 for h in hosts if h['kind'] == 'node'), checked_at=at, stale=stale)
    return {'hosts': hosts, 'clusters': [entry]}


def _check_answer(cached=False, age=0):
    nodes = {
        'pve1': {'success': True, 'updates': PKG['pve1'], 'count': 5, 'retries': 0, 'channel': 'no-subscription',
                 'repo_warnings': 0, 'subscription': 'notfound'},
        'pve2': {'success': True, 'updates': [], 'count': 0, 'retries': 0, 'channel': 'no-subscription',
                 'repo_warnings': 0, 'subscription': 'notfound'},
        'pve3': {'success': False, 'error': 'apt refresh failed: the apt refresh task did not finish cleanly', 'updates': [],
                 'count': -1, 'channel': 'enterprise', 'repo_warnings': 1, 'subscription': 'notfound'},
        'pve5': {'success': True, 'updates': PKG['pve5'], 'count': 2, 'retries': 0, 'channel': 'no-subscription',
                 'repo_warnings': 0, 'subscription': 'notfound'},
    }
    out = {'success': True, 'nodes': nodes, 'pbs': {},
           'summary': {'total_updates': 7, 'nodes_with_updates': 2, 'nodes_failed': 1, 'total_nodes': 4, 'pbs_with_updates': 0,
                       'total_pbs': 0, 'checked_at': '2026-10-30 08:58:00'},
           'cached': cached}
    if cached:
        out['cached_age_sec'] = age
    return out


# all nodes offline: settings.py answers success with no node and does not cache it
NO_NODE_ANSWER = {'success': True, 'nodes': {}, 'summary': {'total_updates': 0, 'nodes_with_updates': 0, 'total_nodes': 0,
                                                            'checked_at': '2026-10-30 08:59:00'}}


def _run(status='running', **kw):
    """A rolling update as updates/status returns it (rolling_runs state, settings.py begin)."""
    r = {'run_id': 'r-41', 'cluster_id': 'c1', 'status': status, 'started_at': '2026-10-30 08:40:00', 'started_by': 'admin',
         'completed_at': None, 'include_reboot': False, 'skip_up_to_date': True, 'skip_evacuation': False, 'wait_for_reboot': True,
         'pause_on_evacuation_error': True, 'allow_local_disks': False, 'ceph_health_gate': 'off', 'migrate_templates': False,
         'relax_anti_affinity': False, 'force_all': False, 'evacuation_timeout': 1800, 'update_timeout': 900, 'reboot_timeout': 600,
         'notify_channels': [], 'nodes': ['pve1', 'pve2', 'pve3'], 'current_index': 1, 'current_node': 'pve2',
         'current_step': 'evacuating', 'completed_nodes': ['pve1'], 'skipped_nodes': [], 'failed_nodes': [], 'rebooting_nodes': [],
         'paused_reason': None, 'paused_details': None, 'resume_at': None, 'quorum_risk_accepted': [], 'cancel_report': [],
         'logs': ['[08:40:00] Rolling update started', '[08:44:10] pve1 updated', '[08:45:00] Moving 2 guests off pve2'],
         'node_state': {'pve1': {'phase': 'done', 'phase_at': FIXED - 900, 'result': 'done', 'updated': True, 'rebooted': False,
                                 'in_maintenance': False, 'moved': [], 'moved_count': 3},
                        'pve2': {'phase': 'evacuating', 'phase_at': FIXED - 60, 'result': None, 'updated': False, 'rebooted': False,
                                 'in_maintenance': True, 'moved': [], 'moved_count': 1}}}
    r.update(kw)
    return r


QUORUM_DETAILS = {'node': 'pve2', 'reason': 'would_lose', 'expected': 3, 'needed': 2, 'have': 2, 'after': 1, 'offline': ['pve3'],
                  'qdevice': {'present': True, 'connected': False, 'not_connected': ['pve1']}, 'phase': 'maintenance',
                  'message': 'Not going on before pve2 goes into maintenance: taking pve2 down would leave 1 of 3 votes'}

HISTORY = [
    {'run_id': 'r-40', 'status': 'completed', 'started_at': '2026-10-29 03:00:00', 'completed_at': '2026-10-29 03:41:12',
     'started_by': 'scheduler', 'scheduled': True, 'cancelled_by': None, 'nodes': 3, 'completed': 2, 'skipped': 0, 'failed': 1,
     'failed_nodes': [{'node': 'pve3', 'error': 'Node update failed'}], 'paused_reason': None, 'error': None, 'cancel_report': [],
     'include_reboot': True, 'logs': ['[03:00:00] Scheduled rolling update started', '[03:41:12] pve3 failed']},
    {'run_id': 'r-39', 'status': 'cancelled', 'started_at': '2026-10-28 14:10:00', 'completed_at': '2026-10-28 14:22:00',
     'started_by': 'admin', 'scheduled': False, 'cancelled_by': 'admin', 'nodes': 3, 'completed': 1, 'skipped': 1, 'failed': 0,
     'failed_nodes': [], 'paused_reason': 'quorum', 'error': None,
     'cancel_report': [{'kind': 'guests_stay', 'node': 'pve2', 'count': 2}], 'include_reboot': False, 'logs': []},
    {'run_id': 'r-38', 'status': 'completed', 'started_at': '2026-10-21 09:00:00', 'completed_at': '2026-10-21 09:30:00',
     'started_by': 'admin', 'scheduled': False, 'cancelled_by': None, 'nodes': 2, 'completed': 2, 'skipped': 0, 'failed': 0,
     'failed_nodes': [], 'paused_reason': None, 'error': None, 'cancel_report': [], 'include_reboot': False, 'logs': ['done']},
]
SCHEDULE_OFF = {'enabled': False, 'schedule_type': 'recurring', 'day': 'sunday', 'time': '03:00', 'include_reboot': True,
                'skip_evacuation': False, 'skip_up_to_date': True, 'evacuation_timeout': 1800, 'migrate_templates': False,
                'relax_anti_affinity': False, 'last_run': None, 'next_run': None}
SCHEDULE_ON = dict(SCHEDULE_OFF, enabled=True, day='saturday', time='02:30', include_reboot=True, reboot_timeout=1200,
                   last_run='2026-10-25 02:30:00', next_run='2026-11-01 02:30:00')
PLAN = {'supported': True, 'templates': [], 'negative_rules': [], 'own_rules': [], 'still_off': [], 'held': [],
        'balancer_separates': True}
HEADROOM = {'supported': True, 'scenario': {'type': 'headroom', 'depth': 1, 'guests': 'all'}, 'generated_at': '2026-10-30T09:00:00Z',
            'summary': {}, 'guests': [], 'nodes': [], 'limits': [], 'verdict': {'level': 'warning', 'reasons': []},
            'headroom': {'depth': 1, 'checked': 3, 'failing': 1, 'ok': False, 'basis': 'calculated',
                         'combinations': [{'failed': ['pve1'], 'quorate': True, 'votes_left': 2, 'votes_needed': 2, 'guests': 4,
                                           'moved_mem': 0, 'unplaced': 1, 'over_mem': ['pve2'], 'over_cpu': [], 'worst_mem_pct': 93.0,
                                           'worst_cpu_pct': 40.0, 'mem_reserve': 0, 'cpu_reserve': 1.0, 'ok': False,
                                           'checked': 'placed', 'basis': 'calculated'},
                                          {'failed': ['pve2'], 'ok': True, 'unplaced': 0, 'over_mem': [], 'over_cpu': []},
                                          {'failed': ['pve3'], 'ok': True, 'unplaced': 0, 'over_mem': [], 'over_cpu': []}]}}


class _UpdServer(_GuardServer):
    """The guard fake plus the update manager routes with the state of a cluster in memory."""

    def __init__(self, cluster=None, overview=None, run=None, history=None, schedule=None, check=None, metrics=None, **kw):
        super().__init__(bundle=BUNDLE, metrics=copy.deepcopy(METRICS if metrics is None else metrics), **kw)
        self.clusters = [dict(CLUSTER, **(cluster or {}))]
        self.overview = (200, _overview()) if overview is None else overview
        self.run = run                                  # the rolling_update of updates/status, or (status, body)
        self.history = (200, {'runs': HISTORY}) if history is None else history
        self.schedule = dict(SCHEDULE_OFF if schedule is None else schedule)
        self.check = (200, _check_answer()) if check is None else check
        self.apt = {n: (200, list(p)) for n, p in PKG.items()}
        self.resume_answer = None
        self.cancel_answer = None
        self.start_answer = None
        self.schedule_answer = None
        self.hold_check = False
        self.held = []
        self.reqs = []                                  # (method, path, body) of every update route

    def _upd(self, method, path, body, url):
        if path == '/api/updates-overview':
            return self.overview
        if path == '/api/alert-channels':
            return 200, [{'id': 'ch-ops', 'name': 'Ops mail'}, {'id': 'ch-chat', 'name': 'Chat'}]
        if path == '/api/clusters/c1/proxmox-ha/resources':
            return 200, [{'sid': 'vm:100', 'state': 'started'}, {'sid': 'ct:101', 'state': 'started'}]
        if path == '/api/clusters/c1/whatif' and method == 'POST':
            return 200, HEADROOM
        m = re.fullmatch(r'/api/clusters/c1/nodes/([^/]+)/apt/updates', path)
        if m:
            return self.apt.get(m.group(1), (500, {'error': 'Failed to check updates', 'updates': []}))
        if path == '/api/clusters/c1/updates/status':
            if isinstance(self.run, tuple):
                return self.run
            return 200, {'success': True, 'rolling_update': copy.deepcopy(self.run), 'last_check': '2026-10-30 08:58:00'}
        if path == '/api/clusters/c1/updates/check':
            return self.check
        if path == '/api/clusters/c1/updates/schedule':
            if method == 'GET':
                return 200, dict(self.schedule)
            if self.schedule_answer:
                return self.schedule_answer
            perms = self.permissions
            if body.get('enabled', False) and body.get('include_reboot', True) and not self.admin and 'node.reboot' not in perms:
                return 403, {'error': 'Scheduling a node reboot needs the node.reboot permission'}
            # what schedules.py stores and answers (wait_for_reboot is not a column, it goes)
            sched = {k: body.get(k, d) for k, d in (('enabled', False), ('schedule_type', 'recurring'), ('day', 'sunday'),
                                                     ('time', '03:00'), ('include_reboot', True), ('skip_evacuation', False),
                                                     ('skip_up_to_date', True), ('evacuation_timeout', 1800),
                                                     ('reboot_timeout', 600), ('migrate_templates', False),
                                                     ('relax_anti_affinity', False))}
            # schedules.py:1457 stores last_run None on every save (R-B1), whatever ran before
            sched.update(last_run=None, next_run='2026-11-01 03:00:00' if sched['enabled'] else None)
            self.schedule = sched
            return 200, {'success': True, 'schedule': sched}
        if path == '/api/clusters/c1/updates/rolling/history':
            return self.history
        if path == '/api/clusters/c1/updates/rolling/plan':
            return 200, PLAN
        if path == '/api/clusters/c1/updates/rolling' and method == 'POST':
            if self.start_answer:
                return self.start_answer
            nodes = body.get('node_order') or list(self.metrics)
            self.run = _run(nodes=nodes, current_node=nodes[0], current_index=0, completed_nodes=[], node_state={},
                            include_reboot=bool(body.get('include_reboot')), current_step='starting', logs=[])
            return 200, {'success': True, 'message': 'Rolling update started', 'nodes': nodes}
        if path == '/api/clusters/c1/updates/rolling' and method == 'DELETE':
            if self.cancel_answer:
                return self.cancel_answer
            self.run = dict(self.run, status='cancelled', completed_at='2026-10-30 09:01:00', cancelled_by='admin',
                            cancel_report=[{'kind': 'maintenance', 'node': 'pve2'}])
            return 200, {'success': True, 'message': 'Rolling update cancelled', 'not_undone': self.run['cancel_report']}
        if path == '/api/clusters/c1/updates/rolling/resume':
            if self.resume_answer:
                return self.resume_answer
            self.run = dict(self.run, status='running', paused_reason=None, paused_details=None)
            return 200, {'success': True, 'message': 'Resumed', 'was_paused_for': 'quorum'}
        return None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if path.startswith('/api/') and (path == '/api/updates-overview' or path == '/api/alert-channels'
                                        or re.match(r'/api/clusters/c1/(updates|nodes/[^/]+/apt|proxmox-ha|whatif$)', path)):
            body = json.loads(req.post_data) if req.post_data else {}
            if self.role == 'standby' and req.method != 'GET':
                return super().handle(route)
            got = self._upd(req.method, path, body, req.url)
            if got is not None:
                self.calls.append((req.method, path))
                self.urls.append(req.url)
                self.reqs.append((req.method, path, body))
                status, data = got
                if path.endswith('/updates/check') and self.hold_check:
                    self.held.append((route, status, data))
                    return None
                return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        return super().handle(route)

    def release(self):
        held, self.held, self.hold_check = self.held, [], False
        for route, status, data in held:
            route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})


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
    try:
        ff = pw.firefox.launch(headless=True)
    except Exception:
        ff = None
    yield {'chromium': br, 'firefox': ff}
    br.close()
    if ff:
        ff.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), layout=LAYOUT, theme='', storage=None, **kw):
        br = browser[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = _GuardApp(br, _UpdServer(layout=layout, **kw), corp_theme=theme, viewport=viewport, storage=storage)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -----------------------------------------------------------------------------------

def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _poll(app, cond, seconds=8):
    deadline = time.time() + seconds
    while time.time() < deadline and not cond():
        app.page.wait_for_timeout(100)
    return cond()


def _tab(app, wait=True):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    tab = page.locator('[data-cr-tab="updates"]')
    try:
        tab.wait_for(timeout=8000)
    except Exception:
        raise AssertionError('the cluster has the Updates tab of the preview (no such tab)') from None
    tab.click()
    _need(page, '[data-cr-updates]', 'the Updates tab shows the update manager of the preview')
    if wait:
        page.wait_for_function('() => !document.querySelector("[data-cr-upd-state=loading]")', timeout=8000)
        page.locator('[data-cr-upd-card="rolling"] [data-cr-upd-status]').first.wait_for(timeout=8000)
    return page


def _stat(page, sid):
    return page.locator(f'[data-cr-stat="{sid}"] .cr-stat-value').inner_text().strip()


def _sub(page, sid):
    return page.locator(f'[data-cr-stat="{sid}"] .cr-stat-sub').inner_text().strip()


def _upd(app, method=None, tail=None):
    return [r for r in app.server.reqs if (method is None or r[0] == method) and (tail is None or r[1].endswith(tail))]


def _writes(app):
    # the app's own stream token is no write of this page
    return [(m, p) for m, p in app.server.calls if m != 'GET' and p != '/api/sse/token']


def _over(page):
    return page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')


def _mark(app):
    """The index of the next request: what the page asks from here on."""
    return len(app.server.calls)


def _since(app, i, pred=None):
    return [c for c in app.server.calls[i:] if pred is None or pred(c)]


UPDATE_PATHS = re.compile(r'^/api/(updates-overview|alert-channels|clusters/c1/(updates|nodes/[^/]+/apt|proxmox-ha|whatif|reports))')


# --- source ------------------------------------------------------------------------------------

def test_the_classic_section_stays_and_the_preview_has_its_own_tab():
    dash = _read('web', 'src', 'dashboard.js')
    # the tab only in the variant, right before Settings; Automation has no updates sub tab
    assert ("...(isCorpRedesigned ? [{ id: 'updates', labelKey: 'crUpdTab', icon: Icons.Download }] : []),\n"
            "                    { id: 'settings', labelKey: 'settings', icon: Icons.Settings },") in dash
    assert dash.count("{activeTab === 'updates' && isCorpRedesigned && selectedCluster?.id && (") == 1
    assert "automationSubTab === 'updates'" not in dash and "setAutomationSubTab('updates')" not in dash
    # the Settings tab: a link in the variant, the classic section everywhere else
    assert ("{isCorpRedesigned\n                                                        ? <CrUpdatesLink onOpen={() => setActiveTab('updates')} />\n"
            "                                                        : <UpdateManagerSection key={selectedCluster.id}") in dash
    assert dash.count('holds(') == 10
    cr = _read('web', 'src', 'cr_updates.js')
    assert 'window.confirm' not in cr and not re.search(r'(?<![\w.])confirm\(', cr)
    # the routes and bodies of the classic section; every flag explicit
    assert "body: JSON.stringify({ force: !!force })" in cr
    for flag in ('include_reboot', 'wait_for_reboot', 'skip_up_to_date', 'skip_evacuation', 'pause_on_evacuation_error',
                 'allow_local_disks', 'migrate_templates', 'relax_anti_affinity'):
        assert f'{flag}: !!' in cr, flag
    assert "accept_quorum_risk: true" in cr and "write('POST', '/updates/rolling/resume')" in cr
    # one node / one backup server on its own (round 9, full parity): the classic routes and bodies, only
    # from their dialogs; force only after the server asked for maintenance mode
    assert cr.count('/update`') == 2
    assert "const body = force ? { reboot, force: true } : { reboot };" in cr
    assert "body: JSON.stringify({ reboot }) });" in cr
    assert cr.count('onStart={startNode}') == 1 and cr.count('onStart={startPbs}') == 1
    # no package list in the browser's storage: nothing is written, the one read is the copy a classic
    # check left there, for Copy as text
    assert 'localStorage.setItem' not in cr and 'crWrite(' not in cr
    assert re.findall(r'localStorage\.\w+\([^)]*\)', cr) == ["localStorage.getItem(`updateCheck_${cid}`)"]
    assert '\u2014' not in cr and '\u2013' not in cr


def test_every_key_of_the_tab_is_in_english_and_german_before_the_pinned_block():
    cr = _read('web', 'src', 'cr_updates.js') + _read('web', 'src', 'dashboard.js')
    keys = sorted(set(re.findall(r"'(crUpd[A-Za-z]+)'", cr)))
    assert len(keys) > 200
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[a:b] for (a, lang), b in zip(starts, ends)}
    vals = {}
    for lang in ('en', 'de'):
        marker = blocks[lang].index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in keys:
            found = re.findall(rf'^                {k}: "((?:[^"\\]|\\.)*)",$', blocks[lang], re.M)
            assert len(found) == 1, (lang, k)
            assert '\u2014' not in found[0] and '\u2013' not in found[0], (lang, k)
            assert blocks[lang].index(f'                {k}: ') < marker, (lang, k)
            vals[(lang, k)] = found[0]
    for k in keys:
        assert sorted(re.findall(r'\{\w+\}', vals[('en', k)])) == sorted(re.findall(r'\{\w+\}', vals[('de', k)])), k
    # what the page never says about a node
    every = ' '.join(v for (lang, _), v in vals.items() if lang == 'en')
    assert 'reboot required' not in every.lower().replace('reboot-required flag', '')


# --- the rules, as the bundle has them ---------------------------------------------------------

RULES = r'''
const out = {};
const c = { id: 'c1', cluster_type: 'proxmox' };
const metrics = JSON.parse(process.argv[1]);
const ov = { state: 'ok', body: JSON.parse(process.argv[2]) };
const m = crUpdModel({ cluster: c, metrics, ov, now: AT_MS });
out.ok = { state: m.state, total: m.total, withUpdates: m.withUpdates, upToDate: m.upToDate, read: m.read, failed: m.failed,
           missing: m.missing, kernel: m.kernel, security: m.security, stale: m.stale, age: m.age, pbs: m.pbs.length,
           rows: m.rows.map(r => [r.name, r.st, r.pending, r.count]) };
out.unchecked = crUpdModel({ cluster: c, metrics, ov: { state: 'ok', body: { hosts: [], clusters: [{ cluster_id: 'c1', state: 'unchecked' }] } } });
out.unchecked = [out.unchecked.state, out.unchecked.total, out.unchecked.rows.map(r => r.pending)];
const conf = crUpdModel({ cluster: c, metrics, ov: { state: 'ok', body: { hosts: [], clusters: [{ cluster_id: 'c1', state: 'confined' }] } } });
out.confined = [conf.state, conf.total, conf.rows.map(r => r.pending)];
out.states = [crUpdModel({ cluster: c, metrics, ov: null }).state, crUpdModel({ cluster: c, metrics, ov: { state: 'forbidden' } }).state,
              crUpdModel({ cluster: c, metrics, ov: { state: 'error', code: 500 } }).state,
              crUpdModel({ cluster: c, metrics, ov: { state: 'ok', body: { hosts: [], clusters: [] } } }).state,
              crUpdModel({ cluster: { id: 'c1', cluster_type: 'esxi' }, metrics, ov }).state,
              crUpdModel({ cluster: c, metrics, ov: { state: 'ok', body: { nope: 1 } } }).state];
const xb = JSON.parse(process.argv[2]);
xb.hosts.forEach(h => { if (h.kind === 'node' && h.ok) h.security = 1; });
// no node list: a host of the check is "no status read" while the list was never read, "not in the node list" once it was
out.nolist = [crUpdModel({ cluster: c, metrics: {}, ov, nodesRead: false }).rows.map(r => r.st)[0],
              crUpdModel({ cluster: c, metrics: {}, ov, nodesRead: true }).rows.map(r => r.st)[0]];
out.xcp = crUpdModel({ cluster: { id: 'c1', cluster_type: 'xcpng' }, metrics, ov: { state: 'ok', body: xb } }).security;
out.kernel = ['proxmox-kernel-6.14', 'proxmox-kernel-helper', 'pve-kernel-helper', 'linux-image-amd64', 'libssl3', 'kernel-tools'].map(crUpdKernelKind);
const run = (x) => { const v = crUpdRunView(x); return [v.status, v.tone, v.withFailures, v.finished, v.current, v.phase, v.chips.map(ch => ch.state).join(',')]; };
out.running = run({ status: 'running', nodes: ['a', 'b', 'c'], completed_nodes: ['a'], current_node: 'b', current_step: 'updating',
                    node_state: { b: { phase: 'evacuating' } } });
out.doneFailed = run({ status: 'completed', nodes: ['a', 'b'], completed_nodes: ['a'], failed_nodes: [{ node: 'b', error: 'x' }], current_node: 'b' });
out.doneOk = run({ status: 'completed', nodes: ['a'], completed_nodes: ['a'] });
out.hidden = run({ status: 'paused', nodes: ['a', 'b'], completed_nodes: [], current_node: 'a', current_step: 'paused_quorum' });
console.log(JSON.stringify(out));
'''


def test_the_rules_of_the_page():
    """The pure rules as the bundle under test has them (compiled, the functions keep their names)."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('no node here')
    src = BUNDLE or _read('web', 'index.html')
    try:
        rules = src[src.index('const CR_UPD='):src.index('const crUpd={')]
    except ValueError:
        raise AssertionError('the bundle has no rules of the redesigned update manager') from None
    pre = 'const crFill = (s, vars) => Object.keys(vars).reduce((o, k) => o.split(`{${k}}`).join(vars[k]), s || "");\n'
    script = pre + rules + RULES.replace('AT_MS', str((AT + 3 * 3600) * 1000))
    got = subprocess.run([node, '-e', script, json.dumps(METRICS), json.dumps(_overview())], capture_output=True, text=True, timeout=30)
    assert got.returncode == 0, got.stderr
    out = json.loads(got.stdout)
    ok = out['ok']
    # a failed check and a node missing from it count as not read, never as 0; the backup server stays apart
    assert ok['state'] == 'ok' and ok['total'] == 7 and ok['withUpdates'] == 2 and ok['upToDate'] == 1 and ok['read'] == 3
    assert ok['failed'] == ['pve3'] and ok['missing'] == ['pve4'] and ok['kernel'] == 1 and ok['pbs'] == 1
    assert ok['security'] is None and ok['stale'] is False and ok['age'] == 3 * 3600
    assert ok['rows'] == [['pve1', 'online', 'ok', 5], ['pve2', 'online', 'ok', 0], ['pve3', 'online', 'failed', None],
                          ['pve4', 'offline', 'missing', None], ['pve5', 'maintenance', 'ok', 2]]
    assert out['unchecked'] == ['unchecked', None, ['unchecked'] * 5]
    assert out['confined'] == ['confined', None, ['unknown'] * 5]
    assert out['states'] == ['loading', 'forbidden', 'unread', 'notlisted', 'unsupported', 'unread']
    assert out['xcp'] == 3
    assert out['nolist'] == ['nostatus', 'unlisted']
    assert out['kernel'] == ['image', 'helper', 'helper', 'image', None, None]
    assert out['running'] == ['running', 'info', False, 1, 'b', 'evacuating', 'done,current,pending']
    assert out['doneFailed'] == ['completed', 'warning', True, 2, None, None, 'done,failed']
    assert out['doneOk'] == ['completed', 'success', False, 1, None, None, 'done']
    # a confined caller gets no node_state: the step of the run, never a made up phase
    assert out['hidden'] == ['paused', 'warning', False, 0, 'a', 'paused_quorum', 'current,pending']


# --- runtime: opening ----------------------------------------------------------------------------

def test_runtime_opening_reads_three_things_and_asks_no_node(open_app):
    app = open_app()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(500)
    i = _mark(app)
    _tab(app)
    page.wait_for_timeout(1500)
    got = sorted(set(_since(app, i, lambda c: UPDATE_PATHS.match(c[1]))))
    assert got == [('GET', '/api/clusters/c1/updates/schedule'), ('GET', '/api/clusters/c1/updates/status'),
                   ('GET', '/api/updates-overview')], got
    assert _writes(app) == []
    # the status is read once a minute while nothing runs (the classic section read it every 3 s)
    page.wait_for_timeout(5000)
    assert len(_since(app, i, lambda c: c[1].endswith('/updates/status'))) == 1
    assert app.errors == []


def test_runtime_two_hundred_nodes_are_still_three_reads(open_app):
    many = {f'n{i:03d}': _node(f'n{i:03d}') for i in range(200)}
    hosts = [_host(n, count=i % 4, kernel=i % 7 == 0) for i, n in enumerate(many)]
    app = open_app(metrics=many, overview=(200, _overview(hosts=hosts)))
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(500)
    i = _mark(app)
    _tab(app)
    page.locator('[data-cr-table="upd-nodes"] tbody tr').first.wait_for(timeout=8000)
    page.wait_for_timeout(1000)
    assert len(_since(app, i, lambda c: UPDATE_PATHS.match(c[1]))) == 3
    assert _stat(page, 'upd-nodes') == str(sum(1 for i in range(200) if i % 4))
    assert app.errors == []


def test_runtime_the_tiles_say_what_the_sources_carry(open_app):
    app = open_app()
    page = _tab(app)
    assert _stat(page, 'upd-total') == '7'
    assert 'without 2 nodes not read' in _sub(page, 'upd-total')
    assert _stat(page, 'upd-nodes') == '2' and 'of 3 read nodes, 1 up to date' in _sub(page, 'upd-nodes')
    assert _stat(page, 'upd-unread') == '2'
    assert 'check failed: pve3' in _sub(page, 'upd-unread') and 'not in the check: pve4' in _sub(page, 'upd-unread')
    # Proxmox VE gives no suite: security is not reported, never 0
    assert _stat(page, 'upd-security') == 'Not reported'
    assert _stat(page, 'upd-kernel') == '1'
    assert 'after a reboot' in _sub(page, 'upd-kernel')
    assert 'not a reboot-required flag' in page.locator('[data-cr-stat="upd-kernel"]').get_attribute('title')
    assert _stat(page, 'upd-checked') == '3 h ago'
    text = page.locator('[data-cr-updates]').inner_text()
    assert 'Reboot required' not in text and 'reboot required' not in text
    # no guest figure: one explanation on its own tab
    page.locator('[data-cr-tab="upd-guests"]').click()
    guests = page.locator('[data-cr-upd-guests="no-source"]').inner_text()
    assert 'No source for guest OS updates' in guests and not re.search(r'\d', guests)
    assert app.errors == []


@pytest.mark.parametrize('case', ['unchecked', 'stale', 'confined', 'failed', 'denied', 'no-node-view'])
def test_runtime_an_unread_or_old_overview_is_never_a_zero(open_app, case):
    kw = {'unchecked': {'overview': (200, _overview(state='unchecked'))},
          'stale': {'overview': (200, _overview(stale=True, at=FIXED - 26 * 3600))},
          'confined': {'overview': (200, _overview(state='confined'))},
          'failed': {'overview': (500, {'error': 'boom'})},
          'denied': {'overview': (403, {'error': 'Permission denied'})},
          'no-node-view': {'admin': False, 'permissions': ['cluster.view']}}[case]
    app = open_app(**kw)
    page = _tab(app)
    tiles = [_stat(page, s) for s in ('upd-total', 'upd-nodes', 'upd-unread', 'upd-kernel')]
    if case == 'stale':
        assert tiles == ['7', '2', '2', '1']
        _need(page, '[data-cr-upd-note="stale"]', 'an old check says how old')
        assert 'more than 24 hours' in page.locator('[data-cr-upd-note="stale"]').inner_text()
        assert 'older than 24 hours' in _sub(page, 'upd-checked')
    else:
        assert tiles == ['-', '-', '-', '-'], tiles
        assert _stat(page, 'upd-checked') == '-'
        note = {'unchecked': 'unchecked', 'confined': 'confined', 'failed': 'unread', 'denied': 'forbidden',
                'no-node-view': 'forbidden'}[case]
        _need(page, f'[data-cr-upd-note="{note}"]', f'{case} is its own state')
        pend = page.locator('[data-cr-upd-pending]').evaluate_all('els => els.map(e => e.getAttribute("data-cr-upd-pending"))')
        assert '0' not in page.locator('[data-cr-table="upd-nodes"] tbody').inner_text().split()
        assert all(p in ('unchecked', 'unknown') for p in pend), pend
    if case == 'confined':
        # the packages are the cluster's: no check, no start, no package read for a confined account
        assert page.locator('[data-cr-upd-open="check"]').is_disabled()
        assert page.locator('[data-cr-upd-open="start"]').is_disabled()
        page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve1').first.click()
        _need(page, '[data-cr-upd-detail="pve1"]', 'the node opens')
        page.wait_for_timeout(500)
        assert _upd(app, 'GET', '/apt/updates') == []
    if case == 'no-node-view':
        assert _upd(app, 'GET', '/updates-overview') == [] and _upd(app, 'GET', '/updates/status') == []
        _need(page, '[data-cr-upd-status="forbidden"]', 'the run status says it is not readable')
    assert _writes(app) == []
    assert app.errors == []


# --- runtime: the check ------------------------------------------------------------------------

def _open_check(page):
    page.locator('[data-cr-upd-open="check"]').click()
    _need(page, '[data-cr-upd-dialog="check"]', 'Check now opens its dialog')
    return page.locator('[data-cr-upd-dialog="check"]')


def test_runtime_a_check_runs_only_after_its_dialog(open_app):
    app = open_app()
    page = _tab(app)
    dlg = _open_check(page)
    what = dlg.inner_text()
    assert 'apt update on every online node' in what and 'installs nothing' in what
    assert '4 online nodes are checked' in what and 'Offline and not checked: pve4' in what
    page.keyboard.press('Escape')
    assert page.locator('[data-cr-upd-dialog]').count() == 0
    assert _upd(app, 'POST') == []
    # focus is back on the button
    assert page.evaluate('() => document.activeElement.getAttribute("data-cr-upd-open")') == 'check'
    app.server.hold_check = True
    _open_check(page)
    page.locator('[data-cr-upd-confirm="check"]').click()
    _need(page, '[data-cr-upd-check-state="running"]', 'a running check says so')
    assert page.locator('[data-cr-upd-open="check"]').is_disabled()
    i = _mark(app)
    app.server.release()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    posts = _upd(app, 'POST', '/updates/check')
    # force starts unticked (round 8, N-O4): a copy younger than 24 h may answer
    assert len(posts) == 1 and posts[0][2] == {'force': False}
    card = page.locator('[data-cr-upd-card="check"]').inner_text()
    assert 'server time of the check: 2026-10-30 08:58:00' in card
    assert '3 of 4 nodes read' in card and 'Check failed on: pve3' in card
    # the overview is read again after the answer, nothing else
    _poll(app, lambda: _since(app, i, lambda c: c[1] == '/api/updates-overview'))
    assert [c for c in _since(app, i, lambda c: UPDATE_PATHS.match(c[1]))] == [('GET', '/api/updates-overview')]
    # the package list of the session's answer, not a read of the node
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve1').first.click()
    _need(page, '[data-cr-upd-pkg-source="check"]', 'the panel takes the list of the check answer')
    assert page.locator('[data-cr-upd-pkg]').count() == 5 and _upd(app, 'GET', '/apt/updates') == []
    assert app.errors == []


@pytest.mark.parametrize('answer', ['cached', 'no-node', 'refused', 'standby-answer'])
def test_runtime_the_check_answer_says_what_it_is(open_app, answer):
    check = {'cached': (200, _check_answer(cached=True, age=7200)), 'no-node': (200, NO_NODE_ANSWER),
             'refused': (403, {'error': 'Permission denied: node.update'}),
             'standby-answer': (409, {'error': 'This is a standby instance.', 'code': 'HA_STANDBY'})}[answer]
    app = open_app(check=check)
    page = _tab(app)
    _open_check(page)
    if answer == 'cached':
        assert not page.locator('[data-cr-upd-force]').is_checked()
        assert 'answers with its copy' in page.locator('[data-cr-upd-copy-note]').inner_text()
    page.locator('[data-cr-upd-confirm="check"]').click()
    card = page.locator('[data-cr-upd-card="check"]')
    if answer == 'cached':
        _need(page, '[data-cr-upd-cached]', 'a copy says it is one')
        assert "server's copy of an earlier check, 2 h old" in card.inner_text()
        assert _upd(app, 'POST', '/updates/check')[0][2] == {'force': False}
    elif answer == 'no-node':
        _need(page, '[data-cr-upd-check-empty]', 'no node reached is said')
        assert 'This is not "no updates"' in card.inner_text()
    else:
        _need(page, '[data-cr-upd-check-state="error"]', 'a refusal is shown inline')
        assert ('node.update' if answer == 'refused' else 'standby') in card.inner_text()
    assert app.errors == []


# --- runtime: permissions and the standby --------------------------------------------------------

@pytest.mark.parametrize('who', ['viewer', 'standby', 'no-reboot'])
def test_runtime_who_may_do_what(open_app, who):
    kw = {'viewer': {'admin': False, 'permissions': ['node.view', 'cluster.view']},
          'standby': {'role': 'standby'},
          'no-reboot': {'admin': False, 'permissions': ['node.view', 'cluster.view', 'node.update']}}[who]
    app = open_app(**kw)
    page = _tab(app)
    if who in ('viewer', 'standby'):
        for b in ('check', 'start', 'schedule'):
            assert page.locator(f'[data-cr-upd-open="{b}"]').is_disabled(), b
        why = page.locator('[data-cr-upd-why="check"]').inner_text()
        assert ('node.update' in why) if who == 'viewer' else ('standby' in why)
        if who == 'standby':
            _need(page, '[data-cr-upd-note="standby"]', 'a standby says it')
        # reading stays
        page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve1').first.click()
        _need(page, '[data-cr-upd-pkg-source="node"]', 'the package list of a node can be read')
    else:
        page.locator('[data-cr-upd-open="start"]').click()
        _need(page, '[data-cr-upd-dialog="start"]', 'the start dialog opens')
        box = page.locator('[data-cr-upd-opt="include_reboot"]')
        assert box.is_disabled() and not box.is_checked()
        assert 'node.reboot' in page.locator('[data-cr-upd-dialog="start"]').inner_text()
        page.locator('[data-cr-upd-confirm="start"]').click()
        _poll(app, lambda: _upd(app, 'POST', '/updates/rolling'))
        assert _upd(app, 'POST', '/updates/rolling')[0][2]['include_reboot'] is False
    if who != 'no-reboot':
        assert _writes(app) == []
    assert app.errors == []


# --- runtime: the node table and its panel ------------------------------------------------------

def test_runtime_the_node_table_and_a_nodes_packages(open_app):
    app = open_app()
    page = _tab(app)
    st = page.locator('[data-cr-upd-st]').evaluate_all('els => els.map(e => e.getAttribute("data-cr-upd-st"))')
    assert st == ['online', 'online', 'online', 'offline', 'maintenance'], st
    pend = page.locator('[data-cr-upd-pending]').evaluate_all('els => els.map(e => [e.getAttribute("data-cr-upd-pending"), e.innerText])')
    assert pend == [['ok', '5'], ['ok', 'Up to date'], ['failed', 'Check failed'], ['missing', 'Not in the check'], ['ok', '2']], pend
    assert page.locator('[data-cr-upd-kernel]').count() == 1
    row = page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve1').first
    assert '9.0.3' in row.inner_text() and '6.14.8-2-pve' in row.inner_text()
    assert 'Enterprise' in page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve3').first.inner_text()
    # Enter opens the node; its list is read once from the node, the age said unknown
    row.focus()
    page.keyboard.press('Enter')
    panel = page.locator('[data-cr-sidepanel="updates-node"]')
    panel.wait_for(timeout=4000)
    _need(page, '[data-cr-upd-pkg-source="node"]', 'without a check answer the list comes from the node')
    assert 'age is unknown' in panel.locator('[data-cr-upd-pkg-source]').inner_text()
    assert len(_upd(app, 'GET', '/nodes/pve1/apt/updates')) == 1
    assert '5 packages, 4 from Proxmox, 2 kernel packages' in panel.inner_text()
    kinds = panel.locator('[data-cr-upd-pkg]').evaluate_all(
        'els => els.map(e => [e.dataset.crUpdPkg, Array.from(e.querySelectorAll("[data-cr-upd-flag]")).map(f => f.dataset.crUpdFlag).join()])')
    assert dict(kinds) == {'pve-manager': '', 'proxmox-kernel-6.14': 'kernel', 'proxmox-kernel-helper': 'helper', 'libssl3': '',
                           'proxmox-kernel-6.14.11-1-pve-signed': 'kernel'}
    # a package without a current version is new, its versions in full
    assert 'new' in panel.locator('[data-cr-upd-pkg="proxmox-kernel-6.14.11-1-pve-signed"]').inner_text()
    assert '3.0.17-1~deb12u2' in panel.locator('[data-cr-upd-pkg="libssl3"]').inner_text()
    assert 'Not reported' in panel.inner_text()
    page.keyboard.press('Escape')
    assert panel.count() == 0
    assert 'pve1' in page.evaluate('() => document.activeElement.innerText')
    # an offline node is not read; a node with a failed read says why; an empty list is said
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve4').first.click()
    _need(page, '[data-cr-upd-pkg-source="none"]', 'an offline node is not read')
    assert _upd(app, 'GET', '/nodes/pve4/apt/updates') == []
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve3').first.click()
    _need(page, '[data-cr-upd-pkg-error]', 'a failed read is an error, not an empty list')
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve2').first.click()
    _need(page, '[data-cr-upd-pkg-empty]', 'an empty list says so')
    # the node view is one click away
    page.locator('[data-cr-upd-open-node="pve2"]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-updates]")', timeout=5000)
    assert _writes(app) == []
    assert app.errors == []


# --- runtime: the start dialog -------------------------------------------------------------------

def _open_start(page):
    page.locator('[data-cr-upd-open="start"]').click()
    _need(page, '[data-cr-upd-dialog="start"]', 'Start rolling update opens its dialog')
    return page.locator('[data-cr-upd-dialog="start"]')


def test_runtime_the_start_dialog_has_safe_defaults_and_sends_the_order(open_app):
    app = open_app()
    page = _tab(app)
    dlg = _open_start(page)
    # nothing read before: the plan, the channels and the HA resources come with the dialog
    for tail in ('/updates/rolling/plan', '/alert-channels', '/proxmox-ha/resources'):
        assert len(_upd(app, 'GET', tail)) == 1, tail
    opt = lambda k: page.locator(f'[data-cr-upd-opt="{k}"]')
    assert not opt('include_reboot').is_checked() and not opt('skip_evacuation').is_checked()
    assert opt('skip_up_to_date').is_checked() and opt('pause_on_evacuation_error').is_checked()
    assert not opt('allow_local_disks').is_checked()
    picks = page.locator('[data-cr-upd-pick]').evaluate_all('els => els.map(e => [e.dataset.crUpdPick, e.checked, e.disabled])')
    assert picks == [['pve1', True, False], ['pve2', True, False], ['pve3', True, False], ['pve4', False, True], ['pve5', False, False]]
    assert 'pve5' in page.locator('[data-cr-upd-maint-note]').inner_text()
    adv = page.locator('[data-cr-upd-advisory]').inner_text()
    assert 'calculated here, not checked by the engine' in adv
    assert 'Offline now and left out: pve4' in adv and 'In maintenance now: pve5' in adv
    assert '2 guests are managed by Proxmox VE HA' in adv
    gates = page.locator('[data-cr-upd-gates]').inner_text()
    assert 'stay quorate' in gates and 'Free CPU and memory' in gates
    assert 'minutes' not in dlg.locator('[data-cr-upd-order-note]').inner_text()
    # skip evacuation needs its own tick
    opt('skip_evacuation').check()
    _need(page, '[data-cr-upd-danger="skip_evacuation"]', 'skipping the evacuation is a danger to confirm')
    assert page.locator('[data-cr-upd-confirm="start"]').is_disabled()
    page.locator('[data-cr-upd-ack="skip_evacuation"]').check()
    assert not page.locator('[data-cr-upd-confirm="start"]').is_disabled()
    opt('skip_evacuation').uncheck()
    # pve3 first, pve2 left out
    page.locator('[data-cr-upd-up="pve3"]').click()
    page.locator('[data-cr-upd-up="pve3"]').click()
    page.locator('[data-cr-upd-pick="pve2"]').uncheck()
    page.locator('[data-cr-upd-channel="ch-ops"]').click()
    assert 'Start on 2 nodes' in page.locator('[data-cr-upd-confirm="start"]').inner_text()
    page.locator('[data-cr-upd-confirm="start"]').click()
    _poll(app, lambda: _upd(app, 'POST', '/updates/rolling'))
    body = _upd(app, 'POST', '/updates/rolling')[0][2]
    assert body == {'include_reboot': False, 'wait_for_reboot': True, 'skip_up_to_date': True, 'skip_evacuation': False,
                    'pause_on_evacuation_error': True, 'allow_local_disks': False, 'evacuation_timeout': 1800,
                    'reboot_timeout': 600, 'ceph_health_gate': 'off', 'notify_channels': ['ch-ops'],
                    'migrate_templates': False, 'relax_anti_affinity': False, 'node_order': ['pve3', 'pve1']}, body
    # the dialog closes and the run shows at once
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=4000)
    _need(page, '[data-cr-upd-run="running"]', 'the started run is shown')
    assert app.errors == []


def test_runtime_a_refused_start_stays_in_the_dialog(open_app):
    app = open_app()
    app.server.start_answer = (400, {'error': 'A rolling update of this cluster is paused: continue or cancel it first'})
    page = _tab(app)
    _open_start(page)
    page.locator('[data-cr-upd-confirm="start"]').click()
    _need(page, '[data-cr-upd-note="start-refused"]', 'the refusal is shown in the dialog')
    assert 'continue or cancel it first' in page.locator('[data-cr-upd-note="start-refused"]').inner_text()
    assert page.locator('[data-cr-upd-dialog="start"]').count() == 1
    assert app.errors == []


def test_runtime_the_headroom_is_calculated_only_on_a_click(open_app):
    app = open_app()
    page = _tab(app)
    _open_start(page)
    assert _upd(app, 'POST', '/whatif') == []
    page.locator('[data-cr-upd-room]').click()
    _need(page, '[data-cr-upd-room-result="failing"]', 'the result of the what-if engine is shown')
    posts = _upd(app, 'POST', '/whatif')
    assert len(posts) == 1 and posts[0][2] == {'type': 'headroom', 'depth': 1, 'guests': 'all'}
    adv = page.locator('[data-cr-upd-advisory]').inner_text()
    assert '1 of 3 cases' in adv and 'pve1 out: 1 unplaced, over threshold: pve2' in adv
    assert 'not a check the rolling update makes' in adv
    assert app.errors == []


# --- runtime: the run --------------------------------------------------------------------------

def test_runtime_a_running_update_shows_where_it_is_and_is_read_often(open_app):
    app = open_app(run=_run())
    page = _tab(app)
    _need(page, '[data-cr-upd-run="running"]', 'the run is shown')
    run = page.locator('[data-cr-upd-run]')
    assert page.locator('[data-cr-upd-run-phase="evacuating"]').inner_text() == 'Moving guests'
    assert '1 updated, 0 skipped, 0 failed of 3' in run.inner_text()
    chips = page.locator('[data-cr-upd-chip]').evaluate_all('els => els.map(e => [e.dataset.crUpdChip, e.dataset.state])')
    assert chips == [['pve1', 'done'], ['pve2', 'current'], ['pve3', 'pending']]
    # the bar counts the finished node only
    w = page.locator('.cr-upd-bar-done').evaluate('e => e.style.width')
    assert w == '33.33%', w
    assert page.locator('[data-cr-upd-open="start"]').is_disabled()
    assert 'one at a time' in page.locator('[data-cr-upd-why="start"]').inner_text()
    i = _mark(app)
    page.wait_for_timeout(9000)
    n = len(_since(app, i, lambda c: c[1].endswith('/updates/status')))
    assert 2 <= n <= 3, n
    # the log is one click away
    page.locator('[data-cr-upd-log] summary').click()
    assert 'Moving 2 guests off pve2' in page.locator('[data-cr-upd-log] pre').inner_text()
    assert app.errors == []


def test_runtime_a_run_held_for_its_quorum_continues_only_through_the_server(open_app):
    app = open_app(run=_run(status='paused', paused_reason='quorum', paused_details=QUORUM_DETAILS, current_step='paused_quorum'))
    page = _tab(app)
    _need(page, '[data-cr-upd-paused="quorum"]', 'the quorum pause is shown')
    held = page.locator('[data-cr-upd-paused]').inner_text()
    assert 'it would leave 1 of 3 votes' in held and 'needs 2' in held and 'Offline: pve3' in held
    assert 'does not count for pve1' in held
    # Continue anyway asks first, Escape keeps the run as it is
    page.locator('[data-cr-upd-act="anyway"]').click()
    _need(page, '[data-cr-upd-dialog="anyway"]', 'Continue anyway asks first')
    assert 'Take pve2 down although' in page.locator('[data-cr-upd-dialog="anyway"]').inner_text()
    page.keyboard.press('Escape')
    assert _upd(app, 'POST', '/rolling/resume') == []
    page.locator('[data-cr-upd-act="anyway"]').click()
    page.locator('[data-cr-upd-confirm="anyway"]').click()
    _poll(app, lambda: _upd(app, 'POST', '/rolling/resume'))
    assert _upd(app, 'POST', '/rolling/resume')[0][2] == {'accept_quorum_risk': True}
    _need(page, '[data-cr-upd-run="running"]', 'the run goes on as the server says')
    assert app.errors == []


@pytest.mark.parametrize('reason', ['interrupted', 'evacuation_failures', 'node_failure'])
def test_runtime_every_pause_says_why_and_continue_sends_no_risk(open_app, reason):
    details = {'interrupted': {'node': 'pve2', 'phase': 'updating', 'message': ''},
               'evacuation_failures': {'node': 'pve2', 'message': '2 guests could not be moved off pve2 \u2014 handle them, then Continue',
                                       'failed_vms': [{'vmid': 100, 'name': 'web01', 'error': 'no free memory'}]},
               'node_failure': {'node': 'pve2', 'message': 'pve2 failed: Update timed out'}}[reason]
    app = open_app(run=_run(status='paused', paused_reason=reason, paused_details=details, current_step='paused'))
    page = _tab(app)
    box = page.locator(f'[data-cr-upd-paused="{reason}"]')
    box.wait_for(timeout=8000)
    text = box.inner_text()
    if reason == 'interrupted':
        assert 'PegaProx stopped while pve2 was in the phase updating' in text
    elif reason == 'evacuation_failures':
        assert 'web01 (100)' in text and 'no free memory' in text and '\u2014' not in text
    else:
        assert 'Update timed out' in text
    assert page.locator('[data-cr-upd-act="anyway"]').count() == 0
    page.locator('[data-cr-upd-act="continue"]').click()
    _poll(app, lambda: _upd(app, 'POST', '/rolling/resume'))
    assert _upd(app, 'POST', '/rolling/resume')[0][2] == {}
    assert app.errors == []


def test_runtime_cancel_asks_and_a_refusal_is_inline(open_app):
    app = open_app(run=_run(status='paused', paused_reason='node_failure', paused_details={'node': 'pve2', 'message': 'x'}))
    app.server.cancel_answer = (409, {'error': 'This rolling update is being continued or cancelled right now'})
    page = _tab(app)
    page.locator('[data-cr-upd-act="cancel"]').click()
    _need(page, '[data-cr-upd-dialog="cancel"]', 'Cancel asks first')
    assert 'Guests that were moved stay where they are' in page.locator('[data-cr-upd-dialog="cancel"]').inner_text()
    page.locator('[data-cr-upd-confirm="cancel"]').click()
    _need(page, '[data-cr-upd-act-error]', 'the refusal is shown at the run')
    assert 'being continued or cancelled' in page.locator('[data-cr-upd-act-error]').inner_text()
    app.server.cancel_answer = None
    page.locator('[data-cr-upd-act="cancel"]').click()
    page.locator('[data-cr-upd-confirm="cancel"]').click()
    _need(page, '[data-cr-upd-run="cancelled"]', 'the cancelled run stays with its report')
    _need(page, '[data-cr-upd-cancel-report]', 'what a cancel could not undo is listed')
    assert 'pve2 is still in maintenance' in page.locator('[data-cr-upd-cancel-report]').inner_text()
    assert [m for m, _ in _writes(app)].count('DELETE') == 2
    assert app.errors == []


def test_runtime_continue_on_a_rebooting_run_needs_node_reboot(open_app):
    app = open_app(admin=False, permissions=['node.view', 'cluster.view', 'node.update'],
                   run=_run(status='paused', paused_reason='reboot_timeout', include_reboot=True,
                            paused_details={'node': 'pve2', 'message': 'pve2 did not come back'}))
    page = _tab(app)
    _need(page, '[data-cr-upd-needs-reboot]', 'the missing permission is said')
    assert page.locator('[data-cr-upd-act="continue"]').is_disabled()
    assert not page.locator('[data-cr-upd-act="cancel"]').is_disabled()
    assert app.errors == []


def test_runtime_a_finished_run_with_a_failed_node_is_not_green(open_app):
    app = open_app(run=_run(status='completed', completed_at='2026-10-30 08:58:00', completed_nodes=['pve1', 'pve2'],
                            failed_nodes=[{'node': 'pve3', 'error': 'Node update failed'}], current_node='pve3'))
    page = _tab(app)
    _need(page, '[data-cr-upd-run="completed"]', 'the finished run is shown')
    status = page.locator('[data-cr-upd-run-status]')
    assert status.inner_text() == 'Completed with 1 failed'
    assert 'cr-badge-warning' in status.get_attribute('class')
    assert page.locator('[data-cr-upd-run-ok]').count() == 0
    assert 'Node update failed' in page.locator('[data-cr-upd-run-failed]').inner_text()
    assert 'Run a check to see what is left' in page.locator('[data-cr-upd-run-recheck]').inner_text()
    # no check of its own after the run; Hide clears the run on the server as classic does,
    # and this fake has no such route, so the run is hidden here only
    page.wait_for_timeout(1000)
    page.locator('[data-cr-upd-run-dismiss]').click()
    assert page.locator('[data-cr-upd-run]').count() == 0
    _poll(app, lambda: _writes(app))
    assert _writes(app) == [('POST', '/api/clusters/c1/updates/rolling/clear')]
    assert app.errors == []


# --- runtime: the schedule -----------------------------------------------------------------------

def test_runtime_the_schedule_card_and_its_dialog(open_app):
    app = open_app(schedule=SCHEDULE_ON)
    page = _tab(app)
    card = page.locator('[data-cr-upd-card="schedule"]')
    _need(page, '[data-cr-upd-sched-state="armed"]', 'an armed schedule says when')
    assert 'every Saturday at 02:30 (server time)' in card.inner_text()
    assert '2026-11-01 02:30:00 (server time)' in page.locator('[data-cr-upd-sched-next]').inner_text()
    last = page.locator('[data-cr-upd-sched-last]').inner_text()
    assert 'started 2026-10-25 02:30:00' in last and 'history' in last
    worker = page.locator('[data-cr-upd-sched-worker]')
    assert 'does not pause on a failed node' in worker.inner_text() and 'no Ceph gate' in worker.inner_text()
    assert 'quorum is checked' in worker.get_attribute('title')
    page.locator('[data-cr-upd-open="schedule"]').click()
    _need(page, '[data-cr-upd-dialog="schedule"]', 'the schedule dialog opens')
    sopt = lambda k: page.locator(f'[data-cr-upd-sopt="{k}"]')
    assert sopt('enabled').is_checked() and sopt('include_reboot').is_checked()
    # the switch of the classic dialog, with the stored value (none stored: the route's true)
    assert sopt('wait_for_reboot').is_checked()
    sopt('include_reboot').uncheck()
    sopt('day').select_option('daily')
    sopt('time').fill('04:15')
    assert 'every day at 04:15 (server time), without reboots' in page.locator('[data-cr-upd-sched-summary]').inner_text()
    page.locator('[data-cr-upd-confirm="schedule"]').click()
    _poll(app, lambda: _upd(app, 'POST', '/updates/schedule'))
    body = _upd(app, 'POST', '/updates/schedule')[0][2]
    assert body == {'enabled': True, 'schedule_type': 'recurring', 'day': 'daily', 'time': '04:15', 'include_reboot': False,
                    'skip_evacuation': False, 'skip_up_to_date': True, 'wait_for_reboot': True, 'evacuation_timeout': 1800,
                    'reboot_timeout': 1200, 'migrate_templates': False, 'relax_anti_affinity': False}, body
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=4000)
    # the card shows what the server stored, read again after the save
    _need(page, '[data-cr-upd-sched-when]:has-text("every day at 04:15")', 'the card shows the saved schedule')
    assert len(_upd(app, 'GET', '/updates/schedule')) == 2
    assert app.errors == []


def test_runtime_a_new_schedule_starts_without_a_reboot(open_app):
    app = open_app(admin=False, permissions=['node.view', 'cluster.view', 'node.update'])
    page = _tab(app)
    _need(page, '[data-cr-upd-sched-state="off"]', 'no schedule is its own state')
    page.locator('[data-cr-upd-open="schedule"]').click()
    sopt = lambda k: page.locator(f'[data-cr-upd-sopt="{k}"]')
    # the stored default says include_reboot true; a schedule that is not armed starts without
    assert not sopt('enabled').is_checked() and not sopt('include_reboot').is_checked() and sopt('include_reboot').is_disabled()
    sopt('enabled').check()
    sopt('skip_evacuation').check()
    _need(page, '[data-cr-upd-danger="schedule-skip"]', 'an armed schedule without evacuation is a danger to confirm')
    assert page.locator('[data-cr-upd-confirm="schedule"]').is_disabled()
    page.locator('[data-cr-upd-ack="schedule-skip"]').check()
    page.locator('[data-cr-upd-confirm="schedule"]').click()
    _poll(app, lambda: _upd(app, 'POST', '/updates/schedule'))
    body = _upd(app, 'POST', '/updates/schedule')[0][2]
    assert body['include_reboot'] is False and body['skip_evacuation'] is True and body['enabled'] is True
    assert app.errors == []


def test_runtime_a_schedule_refused_by_the_server_stays_in_the_dialog(open_app):
    app = open_app(schedule=SCHEDULE_ON)
    app.server.schedule_answer = (500, {'error': 'Schedule operation failed'})
    page = _tab(app)
    page.locator('[data-cr-upd-open="schedule"]').click()
    page.locator('[data-cr-upd-confirm="schedule"]').click()
    _need(page, '[data-cr-upd-note="schedule-refused"]', 'the refusal is shown in the dialog')
    assert 'Schedule operation failed' in page.locator('[data-cr-upd-note="schedule-refused"]').inner_text()
    assert page.locator('[data-cr-upd-dialog="schedule"]').count() == 1
    # what the card shows is still the stored schedule
    assert 'every Saturday at 02:30' in page.locator('[data-cr-upd-card="schedule"]').inner_text()
    assert app.errors == []


# --- runtime: the history ------------------------------------------------------------------------

def test_runtime_the_history_is_read_when_opened(open_app):
    app = open_app()
    page = _tab(app)
    assert _upd(app, 'GET', '/rolling/history') == []
    page.locator('[data-cr-tab="upd-history"]').click()
    page.locator('[data-cr-table="upd-history"] tbody tr').first.wait_for(timeout=8000)
    assert len(_upd(app, 'GET', '/rolling/history')) == 1
    st = page.locator('[data-cr-upd-hist-status]').evaluate_all('els => els.map(e => [e.dataset.crUpdHistStatus, e.innerText])')
    assert st == [['completed', 'Completed with 1 failed'], ['cancelled', 'Cancelled'], ['completed', 'Completed']], st
    assert page.locator('[data-cr-upd-hist-scheduled]').count() == 1
    assert '2 updated, 0 skipped, 1 failed of 3' in page.locator('[data-cr-upd-hist-counts]').first.inner_text()
    page.locator('[data-cr-table="upd-history"] tbody tr', has_text='Scheduler').first.click()
    _need(page, '[data-cr-upd-hist-failed="pve3"]', 'an open run lists its failed nodes')
    assert 'pve3 failed' in page.locator('[data-cr-upd-hist-detail="r-40"]').inner_text()
    foot = page.locator('[data-cr-upd-hist-foot]').inner_text()
    assert 'Not recorded by the server' in foot and 'versions before and after' in foot
    # the tab switch keeps the list; a reload is a click
    page.locator('[data-cr-tab="upd-nodes"]').click()
    page.locator('[data-cr-tab="upd-history"]').click()
    page.wait_for_timeout(300)
    assert len(_upd(app, 'GET', '/rolling/history')) == 1
    page.locator('[data-cr-upd-hist-reload]').click()
    _poll(app, lambda: len(_upd(app, 'GET', '/rolling/history')) == 2)
    assert app.errors == []


def test_runtime_a_history_not_readable_is_said(open_app):
    app = open_app(history=(403, {'error': 'Access is limited to part of this cluster'}))
    page = _tab(app)
    page.locator('[data-cr-tab="upd-history"]').click()
    _need(page, '[data-cr-upd-note="history-denied"]', 'a refused history says so, never "no runs"')
    assert 'No rolling update has run' not in page.locator('[data-cr-upd-tab="history"]').inner_text()
    assert app.errors == []


# --- runtime: the way in -----------------------------------------------------------------------

def test_runtime_updates_is_a_tab_beside_settings_not_under_automation(open_app):
    app = open_app()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _need(page, '[data-cr-tab="settings"]', 'the cluster has its tab strip')
    ids = page.evaluate("""() => [...document.querySelector('[data-cr-tab="settings"]').closest('[role=tablist]')
                                   .querySelectorAll('[data-cr-tab]')].map(b => b.dataset.crTab)""")
    assert 'updates' in ids and ids.index('updates') == ids.index('settings') - 1, ids
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(400)
    # the sub tab strip of Automation, not the cluster strip that now carries the tab
    _need(page, '.corp-tab-strip:not([data-cr-tabs]) button', 'Automation has its sub tab strip')
    subs = page.locator('.corp-tab-strip:not([data-cr-tabs]) button')
    assert subs.filter(has_text=re.compile(r'^\s*Scheduled Actions\s*$')).count() == 1
    assert subs.filter(has_text=re.compile(r'^\s*Updates\s*$')).count() == 0
    assert page.locator('[data-cr-updates]').count() == 0
    assert app.errors == []


def test_runtime_the_settings_tab_links_here_and_fires_no_check(open_app):
    app = open_app()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="settings"]').click()
    _need(page, '[data-cr-upd-link]', 'the variant shows the link card in Settings')
    page.wait_for_timeout(1500)
    assert _upd(app, 'POST') == [] and _upd(app, 'GET', '/updates/status') == []
    assert page.locator('[data-update-manager] h3', has_text='Update Manager').count() == 1
    page.locator('[data-cr-upd-link-open]').click()
    _need(page, '[data-cr-updates]', 'the link opens the Updates tab')
    assert page.locator('[data-cr-tab="updates"][aria-selected="true"]').count() == 1
    assert app.errors == []


def test_runtime_the_pending_updates_panel_opens_the_updates_tab(open_app):
    app = open_app()
    page = app.page
    _need(page, '[data-updates-overview-row="c1:node:pve1"]', 'the dashboard has the pending updates panel')
    page.locator('[data-updates-overview-row="c1:node:pve1"]').click()
    _need(page, '[data-cr-updates]', 'a row of the panel opens the Updates tab of its cluster')
    assert _upd(app, 'POST') == []
    assert app.errors == []


def test_runtime_classic_corporate_keeps_its_section(open_app):
    app = open_app(layout='corporate', storage={'updateCheck_c1': json.dumps({'time': '2026-10-30T08:00:00.000Z',
                                                                                'summary': _check_answer()['summary'],
                                                                                'nodes': _check_answer()['nodes']})})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.wait_for_timeout(400)
    assert page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Updates\s*$')).count() == 0
    page.locator('button', has_text=re.compile(r'^\s*Settings\s*$')).last.click()
    _need(page, '[data-update-manager] h3', 'classic Settings has its Update Manager')
    assert page.locator('[data-cr-upd-link]').count() == 0
    assert app.errors == []


def test_runtime_the_session_keeps_a_check_over_a_tab_switch(open_app):
    app = open_app()
    page = _tab(app)
    _open_check(page)
    page.locator('[data-cr-upd-confirm="check"]').click()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(300)
    page.locator('[data-cr-tab="updates"]').click()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer of the session is still there')
    assert len(_upd(app, 'POST', '/updates/check')) == 1
    # Copy as text (#1192) takes the lists of that answer, versions in full, a failed node named
    page.evaluate('''() => Object.defineProperty(navigator, 'clipboard', { configurable: true,
        value: { writeText: async (s) => { window.__copied = s; } } })''')
    page.locator('[data-cr-upd-copy]').click()
    _need(page, '[data-cr-upd-copy-msg]', 'the copy says it worked')
    text = page.evaluate('() => window.__copied')
    assert text.startswith('Pending updates - Testi\n') and 'Checked (server time): 2026-10-30 08:58:00' in text
    assert '3.0.17-1~deb12u2' in text and 'pve3 - Check failed: apt refresh failed' in text
    assert 'Incomplete: 1 host(s) could not be checked' in text
    assert app.errors == []


@pytest.mark.parametrize('name', ['Testi-$&', 'Testi-$$', "Testi-$'", 'Testi-$`'])
def test_runtime_the_copied_heading_keeps_the_cluster_name_as_it_is(open_app, name):
    # String.replace reads '$&', '$$', "$'" and '$`' in a replacement string as patterns (#1192)
    app = open_app(cluster={'name': name, 'display_name': name})
    page = _tab(app)
    _open_check(page)
    page.locator('[data-cr-upd-confirm="check"]').click()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    page.evaluate('''() => Object.defineProperty(navigator, 'clipboard', { configurable: true,
        value: { writeText: async (s) => { window.__copied = s; } } })''')
    page.locator('[data-cr-upd-copy]').click()
    _need(page, '[data-cr-upd-copy-msg]', 'the copy says it worked')
    assert page.evaluate('() => window.__copied').splitlines()[0] == f'Pending updates - {name}'
    assert app.errors == []


# --- runtime: keyboard and layout ----------------------------------------------------------------

def test_runtime_the_dialogs_hold_the_tab_key(open_app):
    app = open_app()
    page = _tab(app)
    _open_start(page)
    for _ in range(60):
        page.keyboard.press('Tab')
        inside = page.evaluate('() => !!document.activeElement.closest("[data-cr-upd-dialog]")')
        assert inside
    page.keyboard.press('Escape')
    assert page.locator('[data-cr-upd-dialog]').count() == 0
    # the focus goes back in an effect, a moment after the dialog left the page
    page.wait_for_function('() => document.activeElement.getAttribute("data-cr-upd-open") === "start"', timeout=3000)
    # the inner tabs go with the arrow keys
    page.locator('[data-cr-tab="upd-nodes"]').focus()
    page.keyboard.press('ArrowRight')
    _need(page, '[data-cr-upd-tab="history"]', 'ArrowRight opens the history')
    assert app.errors == []


@pytest.mark.parametrize('engine,size,theme', [('chromium', (1600, 1000), ''), ('chromium', (1280, 800), ''),
                                               ('firefox', (1600, 1000), ''), ('firefox', (1280, 800), ''),
                                               ('chromium', (1600, 1000), 'light')],
                         ids=['chromium-1600', 'chromium-1280', 'firefox-1600', 'firefox-1280', 'light-1600'])
def test_runtime_it_fits_without_sideways_scroll(open_app, engine, size, theme):
    app = open_app(engine=engine, viewport=size, theme=theme, run=_run(status='paused', paused_reason='quorum',
                                                                       paused_details=QUORUM_DETAILS))
    page = _tab(app)
    _need(page, '[data-cr-upd-run="paused"]', 'the run is shown')
    assert _over(page) <= 0
    inner = page.locator('[data-cr-table="upd-nodes"] .cr-table-scroll').evaluate('e => e.scrollWidth - e.clientWidth')
    assert inner <= 1, inner
    # the tiles in one row (1600) or two rows of three (1280), the three cards side by side
    tops = sorted({round(page.locator(f'[data-cr-stat="{s}"]').bounding_box()['y'])
                   for s in ('upd-total', 'upd-security', 'upd-nodes', 'upd-unread', 'upd-kernel', 'upd-checked')})
    assert len(tops) == (1 if size[0] >= 1500 else 2), tops
    cards = [page.locator(f'[data-cr-upd-card="{c}"]').bounding_box() for c in ('check', 'rolling', 'schedule')]
    assert cards[0]['y'] == cards[1]['y'] == cards[2]['y'] and cards[0]['x'] < cards[1]['x'] < cards[2]['x']
    # every tile's text stays inside its tile
    clipped = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-upd-tiles] .cr-stat')).filter(e =>
        Array.from(e.children).some(c => c.scrollWidth > c.clientWidth + 1)).map(e => e.dataset.crStat)''')
    assert clipped == [], clipped
    # the run is paused, so Start is off: its dialog has a test of its own below
    for dlg in ('schedule', 'check'):
        page.locator(f'[data-cr-upd-open="{dlg}"]').click()
        box = page.locator(f'[data-cr-upd-dialog="{dlg}"]')
        box.wait_for(timeout=4000)
        b = box.bounding_box()
        assert b['x'] >= 0 and b['y'] >= 0 and b['x'] + b['width'] <= size[0] and b['y'] + b['height'] <= size[1], (dlg, b)
        assert box.evaluate('e => e.scrollWidth - e.clientWidth') <= 1
        page.keyboard.press('Escape')
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve1').first.click()
    panel = page.locator('[data-cr-sidepanel="updates-node"]')
    panel.wait_for(timeout=4000)
    # the panel slides in: measured once it stands still
    prev = None
    for _ in range(30):
        pb = panel.bounding_box()
        if pb == prev:
            break
        prev = pb
        page.wait_for_timeout(100)
    assert pb['x'] + pb['width'] <= size[0] and pb['x'] >= 0
    page.locator('[data-cr-upd-pkgs]').first.wait_for(timeout=4000)
    assert page.locator('[data-cr-upd-pkgs]').evaluate('e => e.parentElement.scrollWidth - e.parentElement.clientWidth') <= 1
    if theme == 'light':
        bg = page.locator('[data-cr-upd-card="check"]').evaluate('e => getComputedStyle(e).backgroundColor')
        assert bg == 'rgb(255, 255, 255)', bg
    assert app.errors == []


@pytest.mark.parametrize('engine,size', [('chromium', (1600, 1000)), ('chromium', (1280, 800)), ('firefox', (1280, 800))],
                         ids=['chromium-1600', 'chromium-1280', 'firefox-1280'])
def test_runtime_the_start_dialog_fits(open_app, engine, size):
    app = open_app(engine=engine, viewport=size)
    page = _tab(app)
    _open_start(page)
    box = page.locator('[data-cr-upd-dialog="start"]')
    b = box.bounding_box()
    assert b['x'] >= 0 and b['y'] >= 0 and b['x'] + b['width'] <= size[0] and b['y'] + b['height'] <= size[1], b
    body = box.locator('.cr-sb-dbody')
    assert body.evaluate('e => e.scrollWidth - e.clientWidth') <= 1
    # the confirm button stays in view, the body scrolls
    cb = page.locator('[data-cr-upd-confirm="start"]').bounding_box()
    assert cb['y'] + cb['height'] <= size[1]
    assert app.errors == []


# --- stage X: what the review of round 4 found -----------------------------------------------------

def test_runtime_the_next_account_of_the_tab_sees_no_check_of_the_one_before(open_app):
    # R-02: the package lists of a check stay with the account that ran it
    from test_corp_redesigned_harden_ui import _relogin
    app = open_app()
    page = _tab(app)
    _open_check(page)
    page.locator('[data-cr-upd-confirm="check"]').click()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    assert not page.locator('[data-cr-upd-copy]').is_disabled()
    _relogin(app, ['cluster.view', 'node.view', 'node.update'])
    page = _tab(app)
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-upd-check-state]').count() == 0, 'no check answer of the account before'
    # Copy works from the server's overview now, never from the check of the account before
    assert page.locator('[data-cr-upd-copy]').get_attribute('data-cr-upd-copy') == 'model'
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text='pve1').first.click()
    _need(page, '[data-cr-upd-pkg-source="node"]', 'the panel reads the node, the check of the account before is gone')
    assert len(_upd(app, 'POST', '/updates/check')) == 1
    assert app.errors == []


def test_runtime_no_check_while_a_run_goes_and_no_start_without_a_status(open_app):
    # R-06: a check runs apt update on the node a run is upgrading; a start waits for a status read
    app = open_app(run=_run())
    page = _tab(app)
    _need(page, '[data-cr-upd-run="running"]', 'the run is shown')
    assert page.locator('[data-cr-upd-open="check"]').is_disabled()
    assert 'also on the one it is upgrading' in page.locator('[data-cr-upd-why="check"]').inner_text()
    app2 = open_app(run=(500, {'error': 'boom'}))
    page2 = _tab(app2)
    _need(page2, '[data-cr-upd-status="unread"]', 'a failed status read is said')
    assert page2.locator('[data-cr-upd-open="start"]').is_disabled()
    assert 'not current' in page2.locator('[data-cr-upd-why="start"]').inner_text()
    assert not page2.locator('[data-cr-upd-open="check"]').is_disabled()
    assert _writes(app) == [] and _writes(app2) == []
    assert app.errors == [] and app2.errors == []


def test_runtime_a_saved_schedule_does_not_claim_it_never_ran(open_app):
    # R-08: the server clears last_run on every save; no value is not "never started"
    app = open_app(schedule=SCHEDULE_ON)
    page = _tab(app)
    page.locator('[data-cr-upd-open="schedule"]').click()
    _need(page, '[data-cr-upd-dialog="schedule"]', 'the schedule dialog opens')
    page.locator('[data-cr-upd-sopt="time"]').fill('04:15')
    page.locator('[data-cr-upd-confirm="schedule"]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=4000)
    _need(page, '[data-cr-upd-sched-when]:has-text("04:15")', 'the card shows the saved schedule')
    last = page.locator('[data-cr-upd-sched-last]').inner_text()
    assert 'never' not in last, last
    assert 'no start recorded since the schedule was last saved' in last, last
    assert page.locator('[data-cr-upd-sched-history]').count() == 1
    page.locator('[data-cr-upd-sched-history]').click()
    _need(page, '[data-cr-upd-tab="history"]', 'the history is one click away')
    assert app.errors == []


def test_runtime_after_the_check_dialog_the_focus_stays_on_its_card(open_app):
    # R-14: the opener is disabled while the check runs; the focus goes to the card, not the page
    app = open_app()
    page = _tab(app)
    page.locator('[data-cr-upd-open="check"]').focus()
    page.keyboard.press('Enter')
    _need(page, '[data-cr-upd-dialog="check"]', 'Check now opens its dialog')
    app.server.hold_check = True
    page.locator('[data-cr-upd-confirm="check"]').click()
    _need(page, '[data-cr-upd-check-state="running"]', 'a running check says so')
    page.wait_for_timeout(300)
    where = page.evaluate('() => document.activeElement === document.body ? "BODY" : document.activeElement.getAttribute("data-cr-upd-card")')
    assert where == 'check', where
    app.server.release()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    assert app.errors == []


def test_runtime_a_save_without_node_reboot_says_it_drops_the_reboot(open_app):
    # R-17: the server refuses a reboot without node.reboot, so the save stores none; the dialog says so
    app = open_app(schedule=SCHEDULE_ON, admin=False, permissions=['node.view', 'cluster.view', 'node.update'])
    page = _tab(app)
    page.locator('[data-cr-upd-open="schedule"]').click()
    _need(page, '[data-cr-upd-note="reboot-dropped"]', 'the dialog says this save drops the reboot')
    assert 'without a reboot' in page.locator('[data-cr-upd-note="reboot-dropped"]').inner_text()
    # with the right the note is not there
    app2 = open_app(schedule=SCHEDULE_ON)
    page2 = _tab(app2)
    page2.locator('[data-cr-upd-open="schedule"]').click()
    _need(page2, '[data-cr-upd-dialog="schedule"]', 'the schedule dialog opens')
    assert page2.locator('[data-cr-upd-note="reboot-dropped"]').count() == 0
    assert app.errors == [] and app2.errors == []


def test_runtime_a_click_beside_the_start_dialog_keeps_it(open_app):
    # R-19: the start and schedule dialogs hold many choices; the check dialog still closes beside it
    app = open_app()
    page = _tab(app)
    _open_start(page)
    page.locator('[data-cr-upd-pick="pve2"]').uncheck()
    page.mouse.click(5, 300)
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-upd-dialog="start"]').count() == 1
    assert not page.locator('[data-cr-upd-pick="pve2"]').is_checked()
    page.keyboard.press('Escape')
    page.locator('[data-cr-upd-open="schedule"]').click()
    _need(page, '[data-cr-upd-dialog="schedule"]', 'the schedule dialog opens')
    page.mouse.click(5, 300)
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-upd-dialog="schedule"]').count() == 1
    page.keyboard.press('Escape')
    _open_check(page)
    page.mouse.click(5, 300)
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-upd-dialog]').count() == 0
    assert _upd(app, 'POST') == []
    assert app.errors == []


def test_runtime_the_page_no_longer_sends_one_node_elsewhere(open_app):
    # R-07 closed in round 9 (full parity): one node and one backup server are upgraded on this page, so
    # neither the link card nor the page points to the classic layout for them
    app = open_app()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="settings"]').click()
    _need(page, '[data-cr-upd-link-open]', 'the Settings tab links to the Updates tab')
    assert page.locator('[data-cr-upd-link-missing]').count() == 0
    page.locator('[data-cr-upd-link-open]').click()
    _need(page, '[data-cr-upd-pbs]', 'the backup servers of the check are a table of their own')
    assert page.locator('[data-cr-upd-not-here]').count() == 0
    assert 'classic' not in page.locator('[data-cr-updates]').inner_text().lower()
    assert _upd(app, 'POST') == []
    assert app.errors == []
