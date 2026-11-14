"""The Updates tab of Corporate Redesigned, round 9: one node and one backup server on their own, and
the security class of a CVE scan.

Full parity with classic Corporate: the classic Update Manager upgrades a single node (POST
.../nodes/<n>/update {reboot}, again with force when the server asks for maintenance mode first) and
a single backup server (POST /pbs/<id>/update {reboot}) and reads their task every 5 s. The variant
sends the same requests from its own dialogs (a test drives the classic section and compares the
bodies), shows the task the server holds for a host, re-reads the overview when it ends (asks no
node) and never starts a check by itself. Proxmox VE's update list has no suite; a CVE scan of this
session reads it (apt-get -s), so the variant shows its security counts, the scanner's critical mark
and the node's reboot-required flag with the scan's time, and marks a package only for the same
version. Without a scan the page says "not reported" as before.

The fake extends the round 4 one (tests/test_corp_redesigned_updates_ui.py) with the shapes of
pegaprox/api/vms.py (node update), pbs.py (update, apt/updates) and reports.py (cve-scan).
PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). LW Nov 2026
"""
import copy
import json
import re

import pytest

import test_corp_redesigned_updates_ui as U
from test_corp_redesigned_updates_ui import _need, _poll, _tab, _stat, _sub, _over
from test_corp_redesigned_updates_ui import browser  # noqa: F401  (the module's Chromium and Firefox)

# the shape of manager.UpdateTask.to_dict
def _task(node, status='updating', **kw):
    t = {'node': node, 'reboot': False, 'started_at': '2026-10-30T09:00:00.123456', 'completed_at': None, 'status': status,
         'phase': 'apt_dist_upgrade', 'output_lines': [{'timestamp': '2026-10-30T09:00:05', 'text': '[OK] apt update'},
                                                       {'timestamp': '2026-10-30T09:00:20', 'text': 'Unpacking curl ...'}],
         'error': None, 'packages_upgraded': 0, 'duration_seconds': 20.0}
    t.update(kw)
    return t


# a CVE scan of the cluster as reports.scan_all_nodes_cves answers it, on the packages of the round 4 fake
CVE = {
    'cluster_id': 'c1', 'cluster_name': 'Testi', 'scanned_at': '2026-10-30T09:30:00+00:00',
    'nodes': [
        {'node': 'pve1', 'timestamp': '2026-10-30T09:29:40', 'os': 'Debian GNU/Linux 12', 'kernel': '6.14.8-2-pve',
         'pve_version': '9.0.3', 'reboot_required': True, 'debsecan_available': False, 'cves': [],
         'packages': [{'name': 'libssl3', 'current': '3.0.15-1~deb12u1', 'available': '3.0.17-1~deb12u2',
                       'source': 'Debian-Security:12/stable-security [amd64]', 'security': True, 'severity': 'critical'},
                      {'name': 'pve-manager', 'current': '9.0.3', 'available': '9.0.10',
                       'source': 'Proxmox:bookworm/pve-no-subscription [amd64]', 'security': False, 'severity': 'normal'}],
         'cve_count': 0, 'security_count': 1, 'total_count': 2},
        {'node': 'pve2', 'timestamp': '2026-10-30T09:29:41', 'reboot_required': False, 'packages': [], 'cves': [],
         'cve_count': 0, 'security_count': 0, 'total_count': 0},
        {'node': 'pve3', 'error': 'SSH connection failed'},
        {'node': 'pve4', 'error': 'Node offline'},
        # an older scan: its curl is not the version the list offers now, so it marks nothing
        {'node': 'pve5', 'timestamp': '2026-10-30T09:29:42', 'reboot_required': False, 'cves': [],
         'packages': [{'name': 'curl', 'current': '7.88.1-10+deb12u12', 'available': '7.88.1-10+deb12u13',
                       'source': 'Debian-Security:12/stable-security [amd64]', 'security': True, 'severity': 'security'}],
         'cve_count': 0, 'security_count': 1, 'total_count': 1},
    ],
    'summary': {'nodes_scanned': 5, 'nodes_ok': 1, 'total_cves': 0, 'total_security': 2, 'total_updates': 3,
                'debsecan_available': False}}

PBS_PKG = [{'Package': 'proxmox-backup-server', 'OldVersion': '4.0.11-1', 'Version': '4.0.14-1', 'Origin': 'Proxmox'}]


class _HostServer(U._UpdServer):
    """The round 4 fake plus the node update, the backup server routes and the CVE scan."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.node_answer = {}         # node -> (status, body) for the next POST
        self.tasks = {}               # node -> list of tasks, one popped per GET (the last one stays)
        self.pbs_tasks = []           # same for p1
        self.pbs_answer = None
        self.pbs_apt = (200, {'updates': PKG_COPY(), 'count': 1})
        self.cve = (200, copy.deepcopy(CVE))

    def _host(self, method, path, body):
        m = re.fullmatch(r'/api/clusters/c1/nodes/([^/]+)/update', path)
        if m:
            name = m.group(1)
            if method == 'POST':
                if name in self.node_answer:
                    return self.node_answer.pop(name)
                task = _task(name, status='starting', phase='init', output_lines=[], reboot=bool(body.get('reboot', True)))
                return 200, {'success': True, 'message': f'Update started for {name}', 'task': task}
            q = self.tasks.get(name) or []
            if not q:
                return 200, {'is_updating': False}
            return 200, (q.pop(0) if len(q) > 1 else q[0])
        if path == '/api/pbs/p1/update':
            if method == 'POST':
                if self.pbs_answer:
                    return self.pbs_answer
                return 200, {'success': True, 'status': 'starting', 'phase': 'init'}
            q = self.pbs_tasks
            if not q:
                return 200, {'is_updating': False}
            return 200, (q.pop(0) if len(q) > 1 else q[0])
        if path == '/api/pbs/p1/apt/updates':
            return self.pbs_apt
        if path == '/api/clusters/c1/reports/cve-scan' and method == 'POST':
            return self.cve
        return None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if re.fullmatch(r'/api/clusters/c1/nodes/[^/]+/update|/api/pbs/p1/(update|apt/updates)|/api/clusters/c1/reports/cve-scan', path):
            if self.role == 'standby' and req.method != 'GET':
                return super().handle(route)
            body = json.loads(req.post_data) if req.post_data else {}
            got = self._host(req.method, path, body)
            if got is not None:
                self.calls.append((req.method, path))
                self.reqs.append((req.method, path, body))
                status, data = got
                return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        return super().handle(route)


def PKG_COPY():
    return copy.deepcopy(PBS_PKG)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), layout=U.LAYOUT, theme='', storage=None, **kw):
        br = browser[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = U._GuardApp(br, _HostServer(layout=layout, **kw), corp_theme=theme, viewport=viewport, storage=storage)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _reqs(app, method, tail):
    return [r for r in app.server.reqs if r[0] == method and r[1].endswith(tail)]


def _open_node(page, name):
    page.locator('[data-cr-table="upd-nodes"] tbody tr', has_text=name).first.click()
    page.locator(f'[data-cr-upd-detail="{name}"]').wait_for(timeout=5000)
    return page.locator('[data-cr-sidepanel="updates-node"]')


# --- one node on its own -------------------------------------------------------------------------

def test_runtime_one_node_is_updated_from_its_dialog_and_its_task_is_followed(open_app):
    app = open_app()
    page = _tab(app)
    panel = _open_node(page, 'pve5')
    # the panel reads the task the server holds once; nothing is held yet
    _need(page, '[data-cr-upd-job="pve5"][data-state="none"]', 'the panel says no upgrade is held for the node')
    assert len(_reqs(app, 'GET', '/nodes/pve5/update')) == 1
    app.server.tasks['pve5'] = [_task('pve5', status='updating'),
                                _task('pve5', status='completed', completed_at='2026-10-30T09:04:00.5', packages_upgraded=2)]
    calls = U._mark(app)
    panel.locator('[data-cr-upd-open="node-update"]').click()
    dlg = page.locator('[data-cr-upd-dialog="node-update"]')
    dlg.wait_for(timeout=4000)
    assert 'pve5' in dlg.inner_text() and '2 pending packages' in dlg.inner_text()
    # no kernel pending: the reboot starts unticked, as the classic dialog sets it
    assert not dlg.locator('[data-cr-upd-opt="node-reboot"]').is_checked()
    assert dlg.locator('[data-cr-upd-node-maint]').count() == 0       # pve5 is in maintenance mode
    assert U._since(app, calls, lambda c: c[0] == 'POST') == []        # nothing sent before the click
    dlg.locator('[data-cr-upd-confirm="node-update"]').click()
    _poll(app, lambda: _reqs(app, 'POST', '/nodes/pve5/update'))
    assert [r[2] for r in _reqs(app, 'POST', '/nodes/pve5/update')] == [{'reboot': False}]
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=4000)
    # the task is read every 5 s until it ends; the node row shows it
    _need(page, '[data-cr-upd-job="pve5"][data-state="updating"]', 'the running task shows', timeout=9000)
    assert 'Unpacking curl' in panel.locator('[data-cr-upd-job-out]').inner_text()
    _need(page, '[data-cr-upd-node-job]', 'the node table shows the task of the node')
    over = len([c for c in app.server.calls if c[1] == '/api/updates-overview'])
    _need(page, '[data-cr-upd-job="pve5"][data-state="completed"]', 'the finished task shows', timeout=9000)
    assert panel.locator('[data-cr-upd-job-pkgs]').inner_text().strip() == '2'
    assert 'run a check' in panel.locator('[data-cr-upd-job-after]').inner_text()
    # it ended: the overview again (asks no node), no check, and no more task reads
    assert _poll(app, lambda: len([c for c in app.server.calls if c[1] == '/api/updates-overview']) > over)
    n = len(_reqs(app, 'GET', '/nodes/pve5/update'))
    page.wait_for_timeout(6000)
    assert len(_reqs(app, 'GET', '/nodes/pve5/update')) == n
    assert _reqs(app, 'POST', '/updates/check') == []
    assert [w for w in U._writes(app) if not w[1].endswith('/nodes/pve5/update')] == []
    assert app.errors == []


# the refusal of vms.py start_node_update outside maintenance mode, English with a code
NOT_IN_MAINT = (400, {'error': 'Node pve1 is not in maintenance mode', 'code': 'NOT_IN_MAINTENANCE', 'node': 'pve1'})


def test_runtime_a_node_outside_maintenance_asks_again_and_sends_force(open_app):
    app = open_app()
    page = _tab(app)
    app.server.node_answer['pve1'] = NOT_IN_MAINT
    panel = _open_node(page, 'pve1')
    panel.locator('[data-cr-upd-open="node-update"]').click()
    dlg = page.locator('[data-cr-upd-dialog="node-update"]')
    dlg.wait_for(timeout=4000)
    # a kernel is pending: the reboot starts ticked (classic), the kernel note and the maintenance hint are there
    assert dlg.locator('[data-cr-upd-opt="node-reboot"]').is_checked()
    _need(page, '[data-cr-upd-note="node-kernel"]', 'a pending kernel is said')
    _need(page, '[data-cr-upd-node-maint]', 'a node outside maintenance mode is said before the click')
    dlg.locator('[data-cr-upd-confirm="node-update"]').click()
    _need(page, '[data-cr-upd-confirm="node-force"]', 'the server asked for maintenance mode: the dialog asks again')
    _need(page, '[data-cr-upd-note="node-force"]', 'the danger is said')
    assert 'cr-btn-danger' in dlg.locator('[data-cr-upd-confirm="node-force"]').get_attribute('class')
    assert dlg.locator('[data-cr-upd-opt="node-reboot"]').is_disabled()
    assert len(_reqs(app, 'POST', '/nodes/pve1/update')) == 1
    dlg.locator('[data-cr-upd-confirm="node-force"]').click()
    _poll(app, lambda: len(_reqs(app, 'POST', '/nodes/pve1/update')) == 2)
    assert [r[2] for r in _reqs(app, 'POST', '/nodes/pve1/update')] == [{'reboot': True}, {'reboot': True, 'force': True}]
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=4000)
    assert app.errors == []


def test_runtime_the_variant_sends_what_the_classic_section_sends(open_app):
    # the classic Update Manager of classic Corporate, driven to the same two requests (its confirm() accepted)
    classic = open_app(layout='corporate', storage={'updateCheck_c1': json.dumps({'time': '2026-10-30T08:00:00.000Z',
                                                                                    'summary': U._check_answer()['summary'],
                                                                                    'nodes': U._check_answer()['nodes']})})
    classic.server.node_answer['pve1'] = NOT_IN_MAINT
    page = classic.page
    page.on('dialog', lambda d: d.accept())
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Settings\s*$')).last.click()
    _need(page, '[data-update-manager] h3', 'classic Settings has its Update Manager')
    page.locator('[data-update-manager] h3').first.click()          # the classic card opens on its header
    page.locator('[data-update-manager] span.text-sm.font-medium', has_text=re.compile(r'^pve1$')).first.click()
    page.locator('button', has_text='Update this Node').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Start Update\s*$')).first.click()
    _poll(classic, lambda: len(_reqs(classic, 'POST', '/nodes/pve1/update')) == 2)
    want = [r[2] for r in _reqs(classic, 'POST', '/nodes/pve1/update')]
    assert want == [{'reboot': True}, {'reboot': True, 'force': True}], want
    app = open_app()
    app.server.node_answer['pve1'] = NOT_IN_MAINT
    page = _tab(app)
    _open_node(page, 'pve1').locator('[data-cr-upd-open="node-update"]').click()
    page.locator('[data-cr-upd-confirm="node-update"]').click()
    page.locator('[data-cr-upd-confirm="node-force"]').click()
    _poll(app, lambda: len(_reqs(app, 'POST', '/nodes/pve1/update')) == 2)
    assert [r[2] for r in _reqs(app, 'POST', '/nodes/pve1/update')] == want
    assert app.errors == []


@pytest.mark.parametrize('who', ['viewer', 'standby', 'no-reboot'])
def test_runtime_who_may_update_one_node(open_app, who):
    kw = {'viewer': {'admin': False, 'permissions': ['node.view', 'cluster.view']},
          'standby': {'role': 'standby'},
          'no-reboot': {'admin': False, 'permissions': ['node.view', 'cluster.view', 'node.update']}}[who]
    app = open_app(**kw)
    page = _tab(app)
    panel = _open_node(page, 'pve1')
    btn = panel.locator('[data-cr-upd-open="node-update"]')
    if who != 'no-reboot':
        assert btn.is_disabled()
        why = panel.locator('[data-cr-upd-why="node"]').inner_text()
        assert ('node.update' in why) if who == 'viewer' else ('standby' in why), why
        assert U._writes(app) == []
    else:
        btn.click()
        box = page.locator('[data-cr-upd-opt="node-reboot"]')
        assert box.is_disabled() and not box.is_checked()
        assert 'node.reboot' in page.locator('[data-cr-upd-dialog="node-update"]').inner_text()
        page.locator('[data-cr-upd-confirm="node-update"]').click()
        _poll(app, lambda: _reqs(app, 'POST', '/nodes/pve1/update'))
        assert _reqs(app, 'POST', '/nodes/pve1/update')[0][2] == {'reboot': False}
    # an up-to-date node and a node whose check failed offer no update
    _open_node(page, 'pve2')
    assert page.locator('[data-cr-upd-open="node-update"]').count() == 0
    _open_node(page, 'pve3')
    assert page.locator('[data-cr-upd-open="node-update"]').count() == 0
    assert app.errors == []


def test_runtime_a_refused_node_update_stays_in_the_dialog(open_app):
    app = open_app()
    page = _tab(app)
    app.server.node_answer['pve5'] = (500, {'error': 'Update konnte nicht gestartet werden'})
    _open_node(page, 'pve5').locator('[data-cr-upd-open="node-update"]').click()
    page.locator('[data-cr-upd-confirm="node-update"]').click()
    _need(page, '[data-cr-upd-dialog-error]', 'a refusal is said in the dialog')
    assert 'nicht gestartet' in page.locator('[data-cr-upd-dialog-error]').inner_text()
    assert page.locator('[data-cr-upd-dialog="node-update"]').count() == 1
    assert page.locator('[data-cr-upd-confirm="node-force"]').count() == 0
    assert app.errors == []


def test_runtime_a_failed_task_is_red_and_its_error_said(open_app):
    app = open_app()
    app.server.tasks['pve1'] = [_task('pve1', status='failed', error='apt-get dist-upgrade exited with 100',
                                      completed_at='2026-10-30T09:02:00')]
    page = _tab(app)
    panel = _open_node(page, 'pve1')
    _need(page, '[data-cr-upd-job="pve1"][data-state="failed"]', 'a failed task the server holds is shown')
    assert 'cr-badge-error' in panel.locator('[data-cr-upd-job="pve1"] .cr-badge').first.get_attribute('class')
    assert 'exited with 100' in panel.locator('[data-cr-upd-job-error]').inner_text()
    # held, not running: no poll
    n = len(_reqs(app, 'GET', '/nodes/pve1/update'))
    page.wait_for_timeout(5600)
    assert len(_reqs(app, 'GET', '/nodes/pve1/update')) == n
    assert app.errors == []


# --- one backup server on its own ----------------------------------------------------------------

def test_runtime_backup_servers_are_a_table_with_packages_and_their_upgrade(open_app):
    app = open_app()
    # nothing held when the page opens; the upgrade then runs and ends
    run = [{'is_updating': True, 'status': 'updating', 'phase': 'apt_dist_upgrade', 'error': None,
            'output_lines': ['Setting up proxmox-backup-server ...'], 'packages_upgraded': 0, 'reboot': False,
            'started_at': '2026-10-30T09:10:00', 'completed_at': None},
           {'is_updating': False, 'status': 'completed', 'phase': 'done', 'error': None, 'output_lines': ['[OK] done'],
            'packages_upgraded': 1, 'reboot': False, 'started_at': '2026-10-30T09:10:00',
            'completed_at': '2026-10-30T09:12:00'}]
    page = _tab(app)
    _need(page, '[data-cr-upd-pbs-row="backup01"]', 'the backup server of the check is a row')
    # the upgrade task of each backup server is read once on open (the classic section reads them too)
    assert _poll(app, lambda: len(_reqs(app, 'GET', '/pbs/p1/update')) == 1)
    page.wait_for_timeout(300)
    assert len(_reqs(app, 'GET', '/pbs/p1/update')) == 1
    page.locator('[data-cr-table="upd-pbs"] tbody tr', has_text='backup01').first.click()
    _need(page, '[data-cr-upd-pbs-detail="backup01"] [data-cr-upd-pkgs]', 'an opened row reads and shows its packages')
    assert len(_reqs(app, 'GET', '/pbs/p1/apt/updates')) == 1
    det = page.locator('[data-cr-upd-pbs-detail="backup01"]')
    assert '4.0.11-1' in det.inner_text() and '4.0.14-1' in det.inner_text()
    det.locator('[data-cr-upd-open="pbs-update"]').click()
    dlg = page.locator('[data-cr-upd-dialog="pbs-update"]')
    dlg.wait_for(timeout=4000)
    assert not dlg.locator('[data-cr-upd-opt="pbs-reboot"]').is_checked()
    assert 'apt dist-upgrade' in dlg.inner_text()
    app.server.pbs_tasks = run
    dlg.locator('[data-cr-upd-confirm="pbs-update"]').click()
    _poll(app, lambda: _reqs(app, 'POST', '/pbs/p1/update'))
    assert [r[2] for r in _reqs(app, 'POST', '/pbs/p1/update')] == [{'reboot': False}]
    _need(page, '[data-cr-upd-pbs-job="updating"]', 'the row shows the running upgrade', timeout=6000)
    _need(page, '[data-cr-upd-pbs-job="completed"]', 'and its end', timeout=9000)
    assert _reqs(app, 'POST', '/updates/check') == []
    assert app.errors == []


def test_runtime_a_backup_server_upgrade_needs_admin_settings(open_app):
    app = open_app(admin=False, permissions=['node.view', 'cluster.view', 'node.update', 'pbs.view'])
    page = _tab(app)
    page.locator('[data-cr-table="upd-pbs"] tbody tr', has_text='backup01').first.click()
    btn = page.locator('[data-cr-upd-open="pbs-update"]')
    btn.wait_for(timeout=5000)
    assert btn.is_disabled()
    assert 'admin.settings' in page.locator('[data-cr-upd-why="pbs"]').inner_text()
    assert U._writes(app) == []
    assert app.errors == []


# --- the security class from a CVE scan of the session --------------------------------------------

def _scan(app):
    page = app.page
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text='CVE Scanner').first.click()
    page.locator('[data-cr-cve-scan]').click()
    _poll(app, lambda: _reqs(app, 'POST', '/reports/cve-scan'))
    page.wait_for_timeout(500)
    page.locator('[data-cr-tab="updates"]').click()
    _need(page, '[data-cr-updates]', 'back on the Updates tab')
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-state=loading]")', timeout=8000)


def test_runtime_without_a_scan_security_stays_not_reported_and_points_to_the_scanner(open_app):
    app = open_app()
    page = _tab(app)
    assert _stat(page, 'upd-security') == 'Not reported'
    line = page.locator('[data-cr-upd-sec-source="none"]')
    assert 'no suite' in line.inner_text()
    assert page.locator('[data-cr-upd-sec]').count() == 0          # no security column without a scan
    page.locator('[data-cr-upd-open-cve]').click()
    _need(page, '[data-cr-cve]', 'the button opens the CVE Scanner of the cluster')
    assert _reqs(app, 'POST', '/reports/cve-scan') == []           # opening it scans nothing
    assert app.errors == []


def test_runtime_a_cve_scan_of_the_session_lends_the_security_class(open_app):
    app = open_app()
    page = _tab(app)
    _scan(app)
    assert _stat(page, 'upd-security') == '2'
    assert '3 of 5 nodes' in _sub(page, 'upd-security')
    # one of them is critical by the scanner's mark: the tile is red
    assert 'cr-stat-error' in page.locator('[data-cr-stat="upd-security"]').get_attribute('class')
    _need(page, '[data-cr-upd-sec-source="scan"]', 'the page says where the security figures come from')
    sec = page.locator('[data-cr-upd-sec]').evaluate_all('els => els.map(e => e.getAttribute("data-cr-upd-sec"))')
    assert sec == ['1', '0', 'failed', 'failed', '1'], sec
    panel = _open_node(page, 'pve1')
    assert page.locator('[data-cr-upd-detail-sec="scan"]').inner_text().startswith('1, 1 of them critical, in the CVE scan')
    assert page.locator('[data-cr-upd-detail-reboot="yes"]').count() == 1
    _need(page, '[data-cr-upd-pkg="libssl3"]', 'the package list is read')
    flags = panel.locator('[data-cr-upd-pkg]').evaluate_all(
        'els => els.map(e => [e.dataset.crUpdPkg, Array.from(e.querySelectorAll("[data-cr-upd-flag]")).map(f => f.dataset.crUpdFlag).join()])')
    assert dict(flags)['libssl3'] == 'critical' and dict(flags)['pve-manager'] == '', flags
    # pve5: the scan named another curl version, so the list marks nothing; the count is the scan's
    panel = _open_node(page, 'pve5')
    _need(page, '[data-cr-upd-pkg="curl"]', 'the package list of pve5 is read')
    assert panel.locator('[data-cr-upd-pkg="curl"] [data-cr-upd-flag]').count() == 0
    assert page.locator('[data-cr-upd-detail-reboot="no"]').count() == 1
    _open_node(page, 'pve3')
    assert page.locator('[data-cr-upd-detail-sec="failed"]').count() == 1
    assert len(_reqs(app, 'POST', '/reports/cve-scan')) == 1      # the Updates tab never scans
    assert app.errors == []


def test_runtime_pending_failed_and_missing_are_error_and_warning(open_app):
    app = open_app()
    page = _tab(app)
    assert 'cr-badge-error' in page.locator('[data-cr-upd-pending="failed"] .cr-badge').get_attribute('class')
    assert 'cr-badge-warning' in page.locator('[data-cr-upd-pending="missing"] .cr-badge').get_attribute('class')
    assert app.errors == []


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('size', [(1600, 1000), (1280, 900), (1024, 800)])
def test_runtime_backup_servers_panel_and_dialog_fit(open_app, engine, size):
    app = open_app(engine=engine, viewport=size)
    # a task the server still holds (ended, so the node can be updated again), with its output
    app.server.tasks['pve1'] = [_task('pve1', status='completed', completed_at='2026-10-30T09:04:00', packages_upgraded=5,
                                      output_lines=[{'timestamp': '2026-10-30T09:01:00', 'text': 'x' * 400}])]
    page = _tab(app)
    page.locator('[data-cr-table="upd-pbs"] tbody tr', has_text='backup01').first.click()
    _need(page, '[data-cr-upd-pbs-detail="backup01"] [data-cr-upd-pkgs]', 'the backup server row opens')
    assert _over(page) <= 0, ('page', engine, size)
    panel = _open_node(page, 'pve1')
    _need(page, '[data-cr-upd-job="pve1"][data-state="completed"]', 'the task shows')
    assert _over(page) <= 0, ('panel', engine, size)
    box = panel.bounding_box()
    out = panel.locator('[data-cr-upd-job-out]').bounding_box()
    assert out['x'] + out['width'] <= box['x'] + box['width'] + 1
    panel.locator('[data-cr-upd-open="node-update"]').click()
    dlg = page.locator('[data-cr-upd-dialog="node-update"]')
    dlg.wait_for(timeout=4000)
    b = dlg.bounding_box()
    assert b['x'] >= 0 and b['x'] + b['width'] <= size[0], (engine, size, b)
    assert _over(page) <= 0, ('dialog', engine, size)
    assert app.errors == []
