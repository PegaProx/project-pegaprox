"""Corporate Redesigned: data protection, reports and automation views against what the routes
answer.

Backup SLA keeps the "Not in a backup job" filter over a Refresh and names the storages the server
could not read. The Timeline's "Open view" of a rolling update leads to the Updates tab and its
history. Copy as text writes what the classic text writes (the total, the type of a package, the
backup servers) and works without a check of this session (the browser's copy of a classic check,
else the counts of the server's overview), so a standby can copy too. The schedule dialog offers
"wait for reboot" with the stored value and sends it; Hide clears a finished run on the server as
classic does, and a refusal hides it here only and says so. A failed CVE scan is a failed state with
its reason and a retry (no "HTTP undefined" for a scan that got no answer). A failed per guest read
of costs or power is said, not "No VMs". The Drift page names the cluster by its display name. The
topology draws the guests of a bridge and the unlinked guests through a virtual table.

The fakes serve the shapes of pegaprox/api/clusters.py (backup-sla with unread), timeline.py
(rolling_update events), settings.py (check with pbs, overview, rolling/clear), schedules.py
(schedule with wait_for_reboot), reports.py (cve-scan), costs/power per-vm and topology.
PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). Skips without Playwright.
LW Nov 2026
"""
import copy
import json
import os
import re

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, FIXED, REP_READS, REP_TOPOLOGY,
                                           SLA_READS, SLA_REPORT, _corp_cluster, _GuardApp, _GuardServer)
from test_corp_redesigned_updates_ui import (SCHEDULE_OFF, _check_answer, _need, _open_check, _poll, _run, _tab as _upd_tab,
                                             _UpdServer, _upd)
from test_corp_redesigned_drift_ui import _DriftServer
from test_ha_ui import BASE, CLUSTER

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
SLA = '/api/clusters/c1/backup-sla'
COVERAGE = '/api/backup-coverage'
CVE = '/api/clusters/c1/reports/cve-scan'
COVERAGE_OK = {'guests': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 102, 'name': 'mail01', 'type': 'qemu',
                           'node': 'pve2', 'status': 'stopped', 'template': False, 'tags': []},
                          {'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 103, 'name': 'proxy01', 'type': 'lxc',
                           'node': 'pve1', 'status': 'running', 'template': False, 'tags': []}],
               'clusters': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok', 'count': 2, 'checked_at': FIXED - 60}]}


class _Srv(_GuardServer):
    """The guard fake; an extra answer 'abort' drops the request (authFetch answers null for it)."""

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if req.url.startswith(BASE) and self.extra.get((req.method, path)) == 'abort':
            self.calls.append((req.method, path))
            return route.abort('connectionrefused')
        return super().handle(route)


class _UpdClear(_UpdServer):
    """The update fake plus POST updates/rolling/clear as settings.py answers it."""

    def __init__(self, clear=None, **kw):
        super().__init__(**kw)
        self.clear = clear

    def _upd(self, method, path, body, url):
        if path == '/api/clusters/c1/updates/schedule' and method == 'POST':
            got = super()._upd(method, path, body, url)
            # schedules.py keeps wait_for_reboot (a column, the stored value when the key is left out)
            if got and got[0] == 200:
                self.schedule['wait_for_reboot'] = body.get('wait_for_reboot', self.schedule.get('wait_for_reboot', True)) is not False
            return got
        if path == '/api/clusters/c1/updates/rolling/clear' and method == 'POST':
            if self.clear:
                return self.clear
            run = self.run if isinstance(self.run, dict) else None
            if run and run.get('status') in ('completed', 'failed', 'cancelled'):
                self.run = None
                return 200, {'success': True, 'message': 'Status cleared'}
            if run:
                return 400, {'error': 'Cannot clear running update'}
            return 200, {'success': True, 'message': 'Nothing to clear'}
        return super()._upd(method, path, body, url)

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if path == '/api/clusters/c1/updates/rolling/clear':
            if self.role == 'standby':
                return super(_UpdServer, self).handle(route)
            got = self._upd(req.method, path, {}, req.url)
            self.calls.append((req.method, path))
            self.reqs.append((req.method, path, {}))
            return route.fulfill(status=got[0], body=json.dumps(got[1]), headers={'Content-Type': 'application/json'})
        return super().handle(route)


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
def apps(browser):
    made = []

    def _make(server, storage=None):
        app = _GuardApp(browser, server, storage=storage)
        made.append(app)
        return app
    yield _make
    for app in made:
        app.close()


def _guard(apps, extra=None, storage=None, **kw):
    r = {}
    for v in REP_READS.values():
        r.update(v)
    r.update(SLA_READS)
    r[('GET', COVERAGE)] = (200, COVERAGE_OK)
    r.update(extra or {})
    return apps(_Srv(bundle=BUNDLE, layout=LAYOUT, extra=r, **kw), storage=storage)


def _errs(app):
    # the dashboard's authFetch logs the request it got no answer for (the abort cases)
    return [e for e in app.errors if 'authFetch err: TypeError: Failed to fetch' not in e]


def _copy_hook(page):
    page.evaluate('''() => Object.defineProperty(navigator, 'clipboard', { configurable: true,
        value: { writeText: async (s) => { window.__copied = s; } } })''')


def _copied(page):
    page.locator('[data-cr-upd-copy]').click()
    _need(page, '[data-cr-upd-copy-msg]', 'the copy says it worked')
    return page.evaluate('() => window.__copied')


# --- Backup SLA ---------------------------------------------------------------------------------------

def _sla(app):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip button', has_text='Backup SLA').first.click()
    _need(page, '[data-cr-sla] [data-cr-sla-row]', 'the guest table of the Backup SLA is filled')
    return page


def _sla_rows(page):
    return page.locator('[data-cr-table="sla-guests"] tbody tr [data-cr-sla-row]').evaluate_all('xs => xs.map(x => x.dataset.crSlaRow)')


def test_runtime_e7_refresh_keeps_the_not_in_a_job_filter(apps):
    app = _guard(apps)
    page = _sla(app)
    chip = page.locator('[data-cr-sla-chip="nojob"]')
    chip.wait_for(timeout=8000)
    chip.click()
    assert chip.get_attribute('aria-pressed') == 'true'
    assert sorted(_sla_rows(page)) == ['102', '103']
    reads = len([u for u in app.server.urls if '/api/backup-coverage' in u])
    page.locator('[data-cr-sla-refresh]').click()
    _poll(app, lambda: len([u for u in app.server.urls if '/api/backup-coverage?refresh=1' in u]) >= 1)
    page.wait_for_timeout(600)
    assert len([u for u in app.server.urls if '/api/backup-coverage' in u]) == reads + 1
    assert page.locator('[data-cr-sla-chip="nojob"]').get_attribute('aria-pressed') == 'true', 'the filter is kept'
    assert sorted(_sla_rows(page)) == ['102', '103']
    assert app.errors == []


def test_runtime_e7_a_refresh_whose_job_read_fails_lifts_the_filter(apps):
    app = _guard(apps)
    page = _sla(app)
    page.locator('[data-cr-sla-chip="nojob"]').click()
    app.server.extra[('GET', COVERAGE)] = (500, {'error': 'coverage failed'})
    page.locator('[data-cr-sla-refresh]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-sla-chip=nojob]")', timeout=8000)
    assert page.locator('[data-cr-sla-chip="all"]').get_attribute('aria-pressed') == 'true'
    assert app.errors == []


def test_runtime_e11_storages_the_server_could_not_read_are_named(apps):
    report = dict(SLA_REPORT, unread=[{'storage': 'pbs-main', 'node': 'pve1', 'error': 'read timed out'},
                                      {'storage': 'local', 'node': 'pve2', 'error': 'HTTP 500'}])
    app = _guard(apps, extra={('GET', SLA): (200, report)})
    page = _sla(app)
    note = page.locator('[data-cr-sla-unread-stores]')
    _need(page, '[data-cr-sla-unread-stores]', 'the page says which storages the server could not read')
    text = note.inner_text()
    assert 'could not read 2 storage(s): pbs-main (pve1), local (pve2)' in text and 'may show no backup' in text, text
    assert app.errors == []


# --- the Timeline leads to the Updates tab ----------------------------------------------------------

def test_runtime_f1_open_view_of_a_rolling_update_opens_the_updates_history(apps):
    ev = {'id': 'rolling_update:r-40:ended', 'time': '2026-10-29T03:41:12+00:00', 'kind': 'rolling_update', 'severity': 'warning',
          'cluster': 'c1', 'node': None, 'guest': None, 'guest_name': '', 'title': 'rolling update ended (completed)', 'details': '',
          'what': 'rolling.ended', 'params': {'status': 'completed', 'nodes': 3, 'failed': ['pve3'], 'by': 'scheduler'},
          'source': {'route': '/api/clusters/c1/updates/rolling/history', 'id': 'r-40:ended'}}
    tl = {'events': [ev], 'sources': {}, 'correlation': {'window_minutes': 10}, 'next_before': None}
    app = apps(_UpdClear(layout=LAYOUT, extra={('GET', '/api/timeline'): (200, tl)}))
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="timeline"]').click()
    btn = page.locator('[data-tl-open-view]').first
    btn.wait_for(timeout=8000)
    btn.click()
    _need(page, '[data-cr-updates]', 'the run opens the update manager of the layout, not the Settings link card')
    assert page.locator('[data-cr-tab="updates"]').get_attribute('aria-selected') == 'true'
    _need(page, '[data-cr-upd-tab="history"]', 'on its history')
    _poll(app, lambda: _upd(app, 'GET', '/updates/rolling/history'))
    assert _upd(app, 'GET', '/updates/rolling/history')
    assert app.errors == []


# --- Copy as text ------------------------------------------------------------------------------------

def _with_pbs():
    a = _check_answer()
    a['pbs'] = {'backup01': {'success': True, 'pbs_id': 'p1', 'count': 2,
                             'updates': [{'Package': 'proxmox-backup-server', 'Version': '4.0.14'},
                                         {'Package': 'proxmox-backup-client', 'Version': '4.0.14'}]}}
    a['summary'] = dict(a['summary'], total_updates=9, pbs_with_updates=1, total_pbs=1)
    return a


def test_runtime_f2_the_text_has_the_total_the_type_and_the_backup_servers(apps):
    app = apps(_UpdClear(layout=LAYOUT, check=(200, _with_pbs())))
    page = _upd_tab(app)
    _open_check(page)
    page.locator('[data-cr-upd-confirm="check"]').click()
    _need(page, '[data-cr-upd-check-state="ok"]', 'the answer is shown')
    _copy_hook(page)
    text = _copied(page)
    assert '\n9 Updates available\n' in text, text
    assert 'Proxmox Backup Server' in text and 'backup01 - 2 updates' in text and 'proxmox-backup-server  4.0.14' in text, text
    # the Type column of the classic text, beside the origin
    head = next(line for line in text.splitlines() if line.strip().startswith('Package') and 'Origin' in line)
    assert re.search(r'Package\s+\S.*\s+Type\s+Origin$', head), head
    assert re.search(r'proxmox-kernel-6\.14\s+6\.14\.8-2\s+6\.14\.11-1\s+Kernel', text), text
    assert re.search(r'pve-manager\s+9\.0\.3\s+9\.0\.10\s+Update', text), text
    assert 'pve1 - 5 updates - Kernel' in text, text
    assert app.errors == []


def test_runtime_f2_without_a_check_the_browser_copy_of_a_classic_check_is_copied(apps):
    # the classic check of this account (security.js writes who ran it; the fake logs in as admin)
    cached = {'time': '2026-10-30T08:00:00.000Z', 'user': 'admin', 'summary': {'total_updates': 3, 'nodes_failed': 0, 'total_pbs': 1},
              'nodes': {'pve1': {'success': True, 'count': 1, 'updates': [
                  {'Package': 'libssl3', 'OldVersion': '3.0.15', 'Version': '3.0.17', 'Origin': 'Debian', 'Section': 'libs'}]}}}
    app = apps(_UpdClear(layout=LAYOUT), storage={'updateCheck_c1': json.dumps(cached)})
    page = _upd_tab(app)
    btn = page.locator('[data-cr-upd-copy]')
    assert not btn.is_disabled() and btn.get_attribute('data-cr-upd-copy') == 'browser'
    _copy_hook(page)
    text = _copied(page)
    assert 'libssl3' in text and '3 Updates available' in text and 'Last checked:' in text, text
    assert 'the packages of 1 backup server(s) are not loaded here' in text, text
    assert _upd(app, 'POST', '/updates/check') == []
    assert app.errors == []


def test_runtime_f2_a_standby_copies_the_counts_of_the_overview(apps):
    app = apps(_UpdClear(layout=LAYOUT, role='standby'))
    page = _upd_tab(app)
    btn = page.locator('[data-cr-upd-copy]')
    assert not btn.is_disabled() and btn.get_attribute('data-cr-upd-copy') == 'model'
    _copy_hook(page)
    text = _copied(page)
    assert 'pve1 - 5 updates - Kernel' in text and 'pve3 - Check failed' in text, text
    assert 'Proxmox Backup Server' in text and 'backup01 - 1 updates' in text, text
    assert 'a check lists them' in text, text
    assert _upd(app, 'POST') == []
    assert app.errors == []


# --- wait for reboot in the schedule -----------------------------------------------------------------

def test_runtime_f8_the_schedule_keeps_and_sends_wait_for_reboot(apps):
    stored = dict(SCHEDULE_OFF, enabled=True, include_reboot=True, wait_for_reboot=False, reboot_timeout=1200,
                  last_run=None, next_run='2026-11-01 03:00:00')
    app = apps(_UpdClear(layout=LAYOUT, schedule=stored))
    page = _upd_tab(app)
    page.locator('[data-cr-upd-open="schedule"]').click()
    _need(page, '[data-cr-upd-dialog="schedule"]', 'the schedule dialog opens')
    box = page.locator('[data-cr-upd-sopt="wait_for_reboot"]')
    _need(page, '[data-cr-upd-sopt="wait_for_reboot"]', 'the dialog offers the classic wait for reboot switch')
    assert not box.is_checked(), 'the stored value'
    assert page.locator('[data-cr-upd-sopt="reboot_timeout"]').is_disabled(), 'no reboot timeout without waiting'
    page.locator('[data-cr-upd-confirm="schedule"]').click()
    _poll(app, lambda: _upd(app, 'POST', '/updates/schedule'))
    assert _upd(app, 'POST', '/updates/schedule')[0][2]['wait_for_reboot'] is False
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=4000)
    page.locator('[data-cr-upd-open="schedule"]').click()
    page.locator('[data-cr-upd-sopt="wait_for_reboot"]').check()
    page.locator('[data-cr-upd-confirm="schedule"]').click()
    _poll(app, lambda: len(_upd(app, 'POST', '/updates/schedule')) == 2)
    assert _upd(app, 'POST', '/updates/schedule')[1][2]['wait_for_reboot'] is True
    assert app.errors == []


# --- Hide clears the run on the server --------------------------------------------------------------

def _done_run():
    return _run(status='completed', completed_at='2026-10-30 08:58:00', completed_nodes=['pve1', 'pve2', 'pve3'],
                current_node=None, node_state={})


def test_runtime_f9_hide_clears_the_finished_run_on_the_server(apps):
    app = apps(_UpdClear(layout=LAYOUT, run=_done_run()))
    page = _upd_tab(app)
    _need(page, '[data-cr-upd-run="completed"]', 'the finished run is shown')
    assert 'on the server' in page.locator('[data-cr-upd-run-dismiss]').get_attribute('title')
    page.locator('[data-cr-upd-run-dismiss]').click()
    _poll(app, lambda: _upd(app, 'POST', '/updates/rolling/clear'))
    assert [r[:2] for r in _upd(app, 'POST')] == [('POST', '/api/clusters/c1/updates/rolling/clear')]
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-run]")', timeout=5000)
    # the status is read again and the server has no run any more
    _poll(app, lambda: app.server.run is None and len(_upd(app, 'GET', '/updates/status')) >= 2)
    assert page.locator('[data-cr-upd-hide-msg]').count() == 0
    assert app.errors == []


def test_runtime_f9_a_refused_clear_hides_here_only_and_says_why(apps):
    app = apps(_UpdClear(layout=LAYOUT, run=_done_run(), clear=(403, {'error': 'Permission denied: node.update'})))
    page = _upd_tab(app)
    page.locator('[data-cr-upd-run-dismiss]').click()
    _need(page, '[data-cr-upd-hide-msg]', 'the page says the run is hidden here only')
    text = page.locator('[data-cr-upd-hide-msg]').inner_text()
    assert 'Hidden in this browser only' in text and 'Permission denied: node.update' in text, text
    assert page.locator('[data-cr-upd-run]').count() == 0
    assert app.errors == []


# --- a failed CVE scan --------------------------------------------------------------------------

def _cve(app):
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text='CVE Scanner').first.click()
    page.locator('[data-cr-cve]').first.wait_for(timeout=8000)
    return page


@pytest.mark.parametrize('case', ['abort', '403', '503'])
def test_runtime_f4_a_failed_scan_is_a_failed_state_with_its_reason(apps, case):
    answer = {'abort': 'abort', '403': (403, {'error': 'Access denied: not available to a scoped account'}),
              '503': (503, {'error': 'Cluster not connected'})}[case]
    app = _guard(apps, extra={('POST', CVE): answer})
    page = _cve(app)
    page.locator('[data-cr-cve-scan]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-cve]").dataset.crCve === "failed"', timeout=8000)
    note = page.locator('[data-cr-nc-for="cve-failed"]')
    text = note.inner_text()
    expect = {'abort': 'PegaProx gave no answer', '403': 'Access denied: not available to a scoped account',
              '503': 'Cluster not connected'}[case]
    assert 'The last scan failed' in text and expect in text, text
    assert 'HTTP undefined' not in page.locator('body').inner_text()
    assert page.locator('[data-cr-nc-sec="cve-none"]').count() == 0, 'not "no scan has run in this session"'
    # the retry scans again
    app.server.extra[('POST', CVE)] = REP_READS['rep_cve'][('POST', CVE)]
    note.locator('button', has_text='Retry').click()
    page.wait_for_function('() => document.querySelector("[data-cr-cve]").dataset.crCve === "ok"', timeout=8000)
    assert _errs(app) == []


# --- a failed per guest read ------------------------------------------------------------------

@pytest.mark.parametrize('mod', ['costs', 'power'])
def test_runtime_efx1_a_failed_per_guest_read_is_said(apps, mod):
    path = f'/api/clusters/c1/{mod}/per-vm'
    app = _guard(apps, extra={('GET', path): (500, {'error': 'per guest figures failed'})})
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text={'costs': 'Cost Dashboard', 'power': 'Power & Carbon'}[mod]).first.click()
    sel = f'[data-cr-md-rows-failed="{"cost" if mod == "costs" else "power"}"]'
    _need(page, sel, 'the per guest panel says its read failed')
    assert 'per guest figures failed' in page.locator(sel).inner_text()
    panel = page.locator('[data-cr-cost-guests]' if mod == 'costs' else '[data-cr-power-guests]')
    assert 'No VMs' not in panel.inner_text()
    # the summary of the page is still drawn from its own read
    assert page.locator('[data-cr-cost-tiles]' if mod == 'costs' else '[data-cr-power]').count() >= 1
    app.server.extra[('GET', path)] = REP_READS['rep_costs' if mod == 'costs' else 'rep_power'][('GET', path)]
    page.locator(sel).locator('button', has_text='Retry').click()
    page.locator(f'[data-cr-table="{"cost" if mod == "costs" else "power"}-guests"] tbody tr.cr-row').first.wait_for(timeout=8000)
    assert app.errors == []


# --- the topology at 10k guests ------------------------------------------------------------------

def test_runtime_f6_ten_thousand_guests_on_a_bridge_are_a_virtual_table(apps):
    topo = copy.deepcopy(REP_TOPOLOGY)
    for i in range(10000):
        vid = 1000 + i
        topo['nodes'].append({'id': f'vm:{vid}', 'kind': 'vm', 'label': f'g{vid}', 'parent_id': 'node:pve1',
                              'meta': {'vmid': vid, 'status': 'running', 'tags': ''}})
        topo['links'].append({'source': f'vm:{vid}', 'target': 'br:pve1:vmbr0', 'kind': 'attached'})
    for i in range(2000):
        vid = 20000 + i
        topo['nodes'].append({'id': f'ct:{vid}', 'kind': 'ct', 'label': f'u{vid}', 'parent_id': 'node:pve1',
                              'meta': {'vmid': vid, 'status': 'stopped', 'tags': ''}})
    topo['counts'] = {'nodes': 2, 'bridges': 3, 'vms': 10002, 'cts': 2001}
    app = _guard(apps, extra={('GET', '/api/clusters/c1/topology'): (200, topo)})
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text='Network Topology').first.click()
    page.wait_for_function('() => (document.querySelector("[data-cr-net]") || {}).dataset?.crNet === "ok"', timeout=20000)
    page.locator('[data-cr-net-chip="br:pve1:vmbr0"]').click()
    det = page.locator('[data-cr-net-detail="br:pve1:vmbr0"]')
    det.wait_for(timeout=10000)
    assert 'Guests attached (10001)' in det.text_content()
    # every guest row the panel holds, whatever its markup (a list item or a table row)
    drawn = page.evaluate('() => document.querySelectorAll("[data-cr-net-detail] li, [data-cr-net-detail] tbody tr").length')
    assert 0 < drawn < 300, f'only the rows in view are drawn, not 10001 ({drawn})'
    # the search of the table finds one guest of the 10001
    page.locator('[data-cr-net-guests] input[type="search"]').fill('g10999')
    page.wait_for_function('() => document.querySelectorAll("[data-cr-net-guests] [data-cr-net-guest]").length === 1', timeout=8000)
    page.locator('[data-cr-net-orphans-toggle]').click()
    page.locator('[data-cr-net-orphan]').first.wait_for(timeout=8000)
    orphans = page.evaluate('() => document.querySelectorAll("[data-cr-net-orphans] li, [data-cr-net-orphans] tbody tr").length')
    assert 0 < orphans < 300, f'the unlinked guests are drawn as they come into view ({orphans})'
    assert page.evaluate('() => document.querySelectorAll("*").length') < 20000
    assert app.errors == []


# --- the cluster's display name on the Drift page --------------------------------------------------

def test_runtime_f5_the_drift_page_names_the_cluster_by_its_display_name(apps):
    cl = dict(CLUSTER, name='testi-raw', display_name='Testi Prod Site')
    from test_corp_redesigned_dashboard_ui import EDGE, PROD
    srv = _DriftServer(layout=LAYOUT, clusters=[cl, PROD, EDGE])
    app = apps(srv)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi Prod Site').first.click()
    page.locator('[data-cr-tab="compliance"]').click()
    page.locator('[data-compliance-sub="drift"]').click()
    page.locator('[data-cr-drift] .cr-pagehead-sub').wait_for(timeout=20000)
    assert page.locator('[data-cr-drift] .cr-pagehead-sub').inner_text().strip() == 'Testi Prod Site'
    assert app.errors == []
