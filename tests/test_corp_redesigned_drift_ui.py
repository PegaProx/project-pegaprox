"""Config drift of Corporate Redesigned (Preview) in the browser.

DriftTab hands the page to CrDrift, which reads the three drift routes itself so that each read
has a state of its own: loading, a refusal (403), an unknown cluster (404), the leader away
(503), an error or no answer at all are said as such and never drawn as "no findings" or as a
green category. The risk overview counts the open findings per category and colours a category
only from what the last completed scan read; nothing is scored. A finding opens in the side
panel (CrSidePanel) with the baseline and the value at detection per changed property, as the
finding stores them, secrets hidden and long values whole. Every action goes to the existing
route with the classic body and confirmation, and the page says what the server answered (a
skipped scan is no success, a refused promote is no promote). The policy checks map every
result, an unknown one to "not evaluated", and their switch goes through savePolicy. Buttons
follow admin.audit, cluster.config, the admin role and a read-only standby. Classic Corporate
and Modern keep the classic tab (the pixel guard proves it to the pixel).

The fake serves the shapes of pegaprox/api/drift.py (naive server times, by_kind, kinds,
coverage, policy checks with pass/fail/not_checked/disabled) and honours status, kind, category
and limit. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the build
before stage F). Runs against the fake server of tests/test_ha_ui.py and skips without
Playwright. LW Oct 2026
"""
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_corp_redesigned_dashboard_ui import _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp
from test_ha_ui import BASE

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

KINDS = ['vm_config', 'storage', 'network', 'cluster_options', 'firewall', 'ha_rules', 'backup_jobs', 'access']
SCAN_AT = '2026-10-30T08:30:00.412000'
READ = {'vm_config': 'checked', 'storage': 'checked', 'network': 'partial', 'cluster_options': 'checked',
        'firewall': 'not_checked', 'ha_rules': 'no_baseline', 'backup_jobs': 'checked', 'access': 'checked'}
COVER = {'vm_config': {'scopes': 3, 'baselined': 3}, 'storage': {'scopes': 2, 'baselined': 2},
         'network': {'scopes': 4, 'baselined': 4}, 'cluster_options': {'scopes': 1, 'baselined': 1},
         'ha_rules': {'scopes': 1, 'baselined': 0}, 'backup_jobs': {'scopes': 3, 'baselined': 3},
         'access': {'scopes': 4, 'baselined': 4}}
LONG_BEFORE = 'A' * 1200 + 'old-tail'
LONG_AFTER = 'A' * 1200 + 'new-tail'
SECRET_A = '<redacted:0123456789abcdef>'
SECRET_B = '<redacted:fedcba9876543210>'


def _ev(eid, kind, scope, severity, diff, at, status='open', category='deviation', **kw):
    row = {'id': eid, 'cluster_id': 'c1', 'kind': kind, 'scope': scope, 'severity': severity,
           'summary': f'{kind} {scope}: ' + ', '.join(d['path'] for d in diff[:4]), 'detected_at': at,
           'status': status, 'acknowledged_at': None, 'acknowledged_by': None, 'category': category,
           'confirmed_by': None, 'confirmed_at': None, 'change_id': None, 'diff': diff}
    row.update(kw)
    return row


def events():
    rule = {'action': 'ACCEPT', 'dport': '22', 'enable': 1, 'type': 'in'}
    return [
        _ev(41, 'vm_config', 'qemu/100', 'warning', [
            {'path': 'cores', 'op': 'changed', 'before': 4, 'after': 8},
            {'path': 'memory', 'op': 'changed', 'before': '8192', 'after': '16384'},
            {'path': 'net0', 'op': 'changed', 'before': 'virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1,tag=10',
             'after': 'virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=0,tag=20'},
            {'path': 'cipassword', 'op': 'changed', 'before': SECRET_A, 'after': SECRET_B},
            {'path': 'onboot', 'op': 'added', 'before': None, 'after': 1}], '2026-10-30T08:10:04.512000'),
        _ev(40, 'firewall', 'cluster/rules', 'warning', [
            {'path': 'rule 0003', 'op': 'changed', 'before': rule, 'after': dict(rule, action='DROP')}], '2026-10-30T08:09:00.000000'),
        _ev(39, 'storage', 'nfs-backup', 'warning', [
            {'path': '*', 'op': 'removed', 'after': None,
             'before': {'type': 'nfs', 'server': '10.0.0.5', 'export': '/backup', 'content': 'backup', 'password': 'old-cleartext'}}],
            '2026-10-30T08:08:00.000000'),
        _ev(38, 'vm_config', 'lxc/101', 'info', [
            {'path': '*', 'op': 'unknown', 'after': None, 'node-offline': 'pve2',
             'before': {'hostname': 'ct01', 'memory': 512, 'cores': 1}}], '2026-10-30T08:07:00.000000'),
        _ev(37, 'access', 'policy:access_admin_role', 'critical', [
            {'path': 'ops@pve', 'op': 'violation', 'before': None, 'after': 'Administrator on /'},
            {'path': 'ci@pve!deploy', 'op': 'violation', 'before': None, 'after': 'Administrator on /vms'}],
            '2026-10-30T08:06:00.000000', category='policy_violation'),
        _ev(36, 'network', 'pve1/vmbr0', 'critical', [
            {'path': 'address', 'op': 'changed', 'before': '10.0.0.1/24', 'after': '10.0.0.2/24'}], '2026-10-30T08:05:00.000000',
            change_id='chg-1', change_title='Re-IP pve1'),
        _ev(35, 'vm_config', 'qemu/555', 'info', [
            {'path': 'description', 'op': 'added', 'before': None, 'after': 'gone guest'}], '2026-10-30T08:04:00.000000'),
        _ev(34, 'cluster_options', 'global', 'warning', [
            {'path': 'keyboard', 'op': 'changed', 'before': 'en-us', 'after': 'de'}], '2026-10-30T08:03:00.000000',
            category='incident', confirmed_by='admin', confirmed_at='2026-10-30T08:20:00.000000'),
        _ev(33, 'vm_config', 'qemu/100', 'info', [
            {'path': 'description', 'op': 'changed', 'before': LONG_BEFORE, 'after': LONG_AFTER}], '2026-10-29T21:00:00.000000'),
        _ev(30, 'backup_jobs', 'backup-6f1c', 'info', [
            {'path': 'schedule', 'op': 'changed', 'before': '21:00', 'after': '22:00'}], '2026-10-29T20:00:00.000000',
            status='acknowledged', acknowledged_by='ops', acknowledged_at='2026-10-29T20:30:00.000000'),
    ]


def checks():
    viol = [{'path': f'user{i}@pve', 'detail': 'Administrator on /'} for i in range(7)]
    return [
        {'id': 'access_admin_role', 'kind': 'access', 'severity': 'critical', 'enabled': True, 'allow': ['root@pam'],
         'status': 'fail', 'violations': viol},
        {'id': 'access_token_expiry', 'kind': 'access', 'severity': 'warning', 'enabled': True, 'status': 'fail',
         'violations': [{'path': 'ci@pve!deploy', 'detail': 'token never expires'}]},
        {'id': 'firewall_cluster_enabled', 'kind': 'firewall', 'severity': 'warning', 'enabled': True,
         'status': 'not_checked', 'violations': []},
        {'id': 'backup_none_disabled', 'kind': 'backup_jobs', 'severity': 'warning', 'enabled': True, 'status': 'pass',
         'violations': []},
    ]


class _DriftServer(_DashServer):
    """The dashboard fake plus the drift routes of pegaprox/api/drift.py, with their gates.

    fail: {'status'|'events'|'policy': (code, body) or 'abort'}; hold: reads that wait for
    release(); scan: 'ok' | 'skipped' | (code, body). perms decide like the server: reads
    admin.audit, baseline/promote/policy also cluster.config, incidents the admin role."""

    def __init__(self, evs=None, read=None, cover=None, scan_at=SCAN_AT, baselines=25, pol=None, fail=None,
                 scan='ok', refuse=None, perms=None, admin=True, extra=None, **kw):
        self.drift_perms = set(perms or [])
        super().__init__(admin=admin, permissions=sorted(self.drift_perms), extra=extra or {},
                         bundle=BUNDLE, **kw)
        self.evs = events() if evs is None else evs
        self.read = dict(READ if read is None else read)
        self.cover = dict(COVER if cover is None else cover)
        self.scan_at = scan_at
        self.baselines = baselines
        self.pol = checks() if pol is None else pol
        self.pol_at = scan_at
        self.fail = dict(fail or {})
        self.scan_mode = scan
        self.refuse = dict(refuse or {})    # 'promote' | 'incident' | 'policy' -> (code, body)
        self.held = []
        self.hold = set()
        self.posts = []                     # (path, body) of every drift write
        self.reads = []                     # the query of every events read

    # --- the gates ---
    def holds(self, perm):
        return self.admin or perm in self.drift_perms

    def _missing(self, perm):
        return 403, {'error': 'Permission denied', 'code': 'MISSING_PERMISSION', 'required': perm}

    def _baseline_refusal(self, what='changing a drift baseline'):
        if self.holds('cluster.config'):
            return None
        return 403, {'error': f'Permission denied: {what} needs cluster.config', 'code': 'MISSING_PERMISSION',
                     'required': 'cluster.config'}

    # --- the answers ---
    def status_body(self):
        by_kind, sev, cat, total, planned = {}, {'critical': 0, 'warning': 0, 'info': 0}, \
            {'deviation': 0, 'policy_violation': 0, 'incident': 0}, 0, 0
        for e in self.evs:
            if e['status'] != 'open':
                continue
            d = by_kind.setdefault(e['kind'], {'critical': 0, 'warning': 0, 'info': 0})
            d[e['severity']] += 1
            sev[e['severity']] += 1
            cat[e['category']] += 1
            total += 1
            planned += 1 if e['category'] == 'deviation' and e.get('change_id') else 0
        last = max((e['detected_at'] for e in self.evs), default=None)
        return {'cluster_id': 'c1', 'open_total': total, 'by_kind': by_kind, 'by_severity': sev, 'by_category': cat,
                'planned': planned, 'baselines': self.baselines, 'last_event_at': last,
                'kinds': self.read if self.scan_at else {}, 'coverage': self.cover if self.scan_at else {},
                'last_scan_at': self.scan_at}

    def events_body(self, q):
        status = q.get('status', ['open'])[0]
        kind = q.get('kind', [''])[0]
        category = q.get('category', [''])[0]
        try:
            limit = int(q.get('limit', ['100'])[0])
        except ValueError:
            limit = 0
        if limit < 1:
            return 400, {'error': 'limit must be a whole number from 1 to 500'}
        if kind and kind not in KINDS:
            return 400, {'error': 'unknown kind', 'kinds': KINDS}
        if category and category not in ('deviation', 'policy_violation', 'incident'):
            return 400, {'error': 'unknown category'}
        rows = [e for e in self.evs if (status == 'all' or e['status'] == status) and (not kind or e['kind'] == kind)
                and (not category or e['category'] == category)]
        rows.sort(key=lambda e: e['detected_at'], reverse=True)
        return 200, {'events': [json.loads(json.dumps(e)) for e in rows[:min(limit, 500)]]}

    def policy_view(self):
        out = []
        for c in self.pol:
            c = json.loads(json.dumps(c))
            if not c['enabled']:
                c['status'] = 'disabled'
            out.append(c)
        return {'checks': out, 'last_scan_at': self.pol_at}

    def release(self):
        held, self.held = self.held, []
        for route, status, body in held:
            route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE):
            return super().handle(route)
        u = urlparse(req.url)
        path, q = u.path, parse_qs(u.query)
        m = re.fullmatch(r'/api/clusters/c1/drift/(status|events|policy|scan|baseline)', path)
        e = re.fullmatch(r'/api/drift/events/(\d+)/(acknowledge|incident)', path)
        if not m and not e:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}

        def answer(status, data):
            if what in self.hold:
                self.held.append((route, status, data))
                return None
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

        what = (m.group(1) if m else e.group(2))
        if req.method == 'GET':
            if what == 'events':
                self.reads.append({k: v[0] for k, v in q.items()})
            failed = self.fail.get(what)
            if failed == 'abort':
                return route.abort()
            if failed:
                return answer(*failed)
            if what == 'status':
                return answer(200, self.status_body())
            if not self.holds('admin.audit'):
                return answer(*self._missing('admin.audit'))
            if what == 'events':
                return answer(*self.events_body(q))
            return answer(200, self.policy_view())
        self.posts.append((path, body))
        if not self.holds('admin.audit') and what != 'incident':
            return answer(*self._missing('admin.audit'))
        if what == 'policy':
            refused = self.refuse.get('policy') or self._baseline_refusal()
            if refused:
                return answer(*refused)
            for cid, spec in (body.get('checks') or {}).items():
                c = next(x for x in self.pol if x['id'] == cid)
                if 'enabled' in spec:
                    c['enabled'] = spec['enabled']
                    if spec['enabled'] and c.get('status') in (None, 'disabled'):
                        c['status'] = 'not_checked'
                if 'allow' in spec:
                    c['allow'] = sorted(set(spec['allow']))
            return answer(200, dict(self.policy_view(), ok=True))
        if what == 'scan':
            if body.get('seed'):
                refused = self._baseline_refusal()
                if refused:
                    return answer(*refused)
            if self.scan_mode == 'skipped':
                return answer(200, {'error': 'cluster offline', 'status': 'skipped'})
            if isinstance(self.scan_mode, tuple):
                return answer(*self.scan_mode)
            self.scan_at = '2026-10-30T09:00:05.000000'
            self.pol_at = self.scan_at
            return answer(200, {'ok': True, 'cluster_id': 'c1', 'events_count': 2, 'seeded_baselines': 3 if body.get('seed') else 0,
                                'removed': [], 'suppressed_offline': 1, 'suppressed_unread': 2, 'unread': ['firewall'],
                                'already_open': 4, 'kinds': self.read, 'coverage': self.cover,
                                'not_checked': ['firewall', 'ha_rules', 'network'], 'policy_failed': [], 'events': []})
        if what == 'baseline':
            refused = self._baseline_refusal()
            if refused:
                return answer(*refused)
            for x in self.evs:
                if x['status'] == 'open' and x['category'] == 'deviation':
                    x['status'] = 'superseded'
            return answer(200, {'ok': True, 'baselines': 31, 'kept_unread': 2, 'unread': ['firewall']})
        ev = next((x for x in self.evs if x['id'] == int(e.group(1))), None)
        if ev is None:
            return answer(404, {'error': 'not found'})
        if what == 'incident':
            if not self.admin:
                return answer(403, {'error': 'Forbidden', 'code': 'INSUFFICIENT_PERMISSIONS'})
            if self.refuse.get('incident'):
                return answer(*self.refuse['incident'])
            if body.get('incident'):
                ev.update(category='incident', confirmed_by='admin', confirmed_at='2026-10-30T09:01:00.000000', change_id=None)
            else:
                ev.update(category='policy_violation' if ev['scope'].startswith('policy:') else 'deviation',
                          confirmed_by='', confirmed_at=None)
            return answer(200, {'ok': True, 'category': ev['category']})
        if ev['category'] == 'policy_violation':
            refused = self._baseline_refusal('acknowledging a policy violation')
            if refused:
                return answer(*refused)
        if body.get('promote'):
            if ev['category'] == 'policy_violation':
                return answer(400, {'error': 'a policy violation has no baseline to promote'})
            refused = self.refuse.get('promote') or self._baseline_refusal()
            if refused:
                return answer(*refused)
        ev.update(status='acknowledged', acknowledged_by='admin', acknowledged_at='2026-10-30T09:02:00.000000')
        return answer(200, {'ok': True})


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

    def _open(layout=LAYOUT, viewport=(1600, 1000), wait=True, **kw):
        app = _GuardApp(browser, _DriftServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        if layout == LAYOUT:
            _drift(app.page, wait=wait)
        return app
    yield _open
    for app in apps:
        app.close()


def _drift(page, wait=True):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="compliance"]').click()
    page.locator('[data-compliance-sub="drift"]').click()
    page.locator('[data-cr-drift]').wait_for(timeout=20000)
    if wait:
        page.wait_for_function('() => document.querySelector("[data-cr-drift-loaded]") || document.querySelector("[data-cr-drift-whole]")'
                               ' || document.querySelector("[data-cr-table=drift-findings] td.cr-state-error")', timeout=20000)


def _txt(page, sel):
    return page.locator(sel).first.inner_text().strip()


def _stat(page, sid):
    return page.locator(f'[data-cr-drift] [data-cr-stat="{sid}"] .cr-stat-value').inner_text().strip()


def _card(page, kind):
    box = page.locator(f'[data-cr-drift-kind="{kind}"]')
    return {'read': box.get_attribute('data-cr-drift-read'), 'tone': box.get_attribute('data-cr-drift-tone'),
            'total': box.locator('[data-cr-drift-total]').get_attribute('data-cr-drift-total'), 'text': box.inner_text(),
            'pressed': box.get_attribute('aria-pressed')}


def _ids(page):
    return page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-table="drift-findings"] [data-cr-drift-row]'))
        .map(e => Number(e.dataset.crDriftRow))''')


def _open_row(page, eid):
    page.locator(f'[data-cr-drift-row="{eid}"]').click()
    page.locator(f'[data-cr-sidepanel="drift"] [data-cr-drift-detail="{eid}"]').wait_for(timeout=5000)
    return page.locator('[data-cr-sidepanel="drift"]')


def _settled_panel(page, eid):
    """The panel once its slide-in is over, for anything that measures it."""
    panel = _open_row(page, eid)
    panel.evaluate('(p) => Promise.all(p.getAnimations().map(a => a.finished))')
    return panel


def _props(panel):
    return panel.evaluate('''(p) => Array.from(p.querySelectorAll('[data-cr-drift-prop]')).map(tr => ({
        prop: tr.dataset.crDriftProp, op: tr.dataset.crDriftOp,
        cells: Array.from(tr.children).map(td => td.innerText.trim())}))''')


def _wait_rows(page, ids, timeout=8000):
    page.wait_for_function('(want) => JSON.stringify(Array.from(document.querySelectorAll(\'[data-cr-table="drift-findings"] [data-cr-drift-row]\'))'
                           '.map(e => Number(e.dataset.crDriftRow))) === JSON.stringify(want)', arg=ids, timeout=timeout)


# --- the overview -----------------------------------------------------------------------------

def test_runtime_the_overview_counts_and_colours_only_what_was_read(open_app):
    app = open_app()
    page = app.page
    # 9 open: 2 critical (the policy violation, the network change), 4 warning, 3 info
    assert _stat(page, 'open') == '9'
    assert '2 critical, 4 warning, 3 info' in _txt(page, '[data-cr-drift] [data-cr-stat="open"]')
    assert _stat(page, 'violations') == '1' and _stat(page, 'incidents') == '1' and _stat(page, 'planned') == '1'
    assert _stat(page, 'baselines') == '25'
    # the scan time is the server's, printed as it is and said to be server time
    assert _stat(page, 'scan') == '2026-10-30 08:30'
    assert 'server time' in _txt(page, '[data-cr-drift] [data-cr-stat="scan"]')
    vm, storage, net, fw = _card(page, 'vm_config'), _card(page, 'storage'), _card(page, 'network'), _card(page, 'firewall')
    ha, backup, access, opts = _card(page, 'ha_rules'), _card(page, 'backup_jobs'), _card(page, 'access'), _card(page, 'cluster_options')
    assert vm['tone'] == 'warning' and vm['total'] == '4' and 'Baselined: 3 of 3' in vm['text']
    # read in full, nothing open: the only green
    assert backup['tone'] == 'success' and backup['total'] == '0' and 'No open findings' in backup['text']
    # a removed storage is open: coloured, the count says so
    assert storage['tone'] == 'warning' and storage['total'] == '1'
    # partly read: coloured by what is open, captioned, never green
    assert net['read'] == 'partial' and net['tone'] == 'error' and 'Partly checked' in net['text']
    # not read, no baseline: grey, whatever is stored, and never "No open findings"
    assert fw['read'] == 'not_checked' and fw['tone'] == 'neutral' and fw['total'] == '1' and 'Not checked' in fw['text']
    assert ha['read'] == 'no_baseline' and ha['tone'] == 'neutral' and 'No baseline yet' in ha['text'] and 'Baselined: 0 of 1' in ha['text']
    assert 'No open findings' not in fw['text'] + ha['text']
    assert access['tone'] == 'error' and opts['tone'] == 'warning'
    assert page.locator('[data-cr-drift-kind="access"] .cr-drift-sevbar').get_attribute('aria-label') == '1 critical, 0 warning, 0 info'
    note = _txt(page, '[data-cr-drift-countnote]')
    assert 'Acknowledged findings are not counted' in note and 'not re-checked' in note
    # no score anywhere
    assert '%' not in page.locator('[data-cr-drift-overview]').inner_text()
    assert app.errors == []


def test_runtime_a_category_card_filters_on_the_server(open_app):
    app = open_app()
    page = app.page
    page.locator('[data-cr-drift-kind="vm_config"]').click()
    _wait_rows(page, [41, 38, 35, 33])
    assert app.server.reads[-1]['kind'] == 'vm_config' and app.server.reads[-1]['limit'] == '500'
    assert _card(page, 'vm_config')['pressed'] == 'true'
    assert page.locator('[data-cr-drift-filter="kind"]').input_value() == 'vm_config'
    assert page.locator('[data-cr-drift-loaded]').get_attribute('data-cr-drift-of') == '4'
    assert '4 loaded of 4 open.' in _txt(page, '[data-cr-drift-loaded]')
    page.locator('[data-cr-drift-kind="vm_config"]').click()
    _wait_rows(page, [41, 40, 39, 38, 37, 36, 35, 34, 33])
    assert 'kind' not in app.server.reads[-1]
    assert app.errors == []


@pytest.mark.parametrize('case', ['noscan', 'clean', 'partial'])
def test_runtime_no_findings_is_said_only_for_what_was_read(open_app, case):
    if case == 'noscan':
        app = open_app(evs=[], scan_at=None)
    elif case == 'clean':
        app = open_app(evs=[], read={k: 'checked' for k in KINDS})
    else:
        app = open_app(evs=[], read=dict({k: 'checked' for k in KINDS}, network='partial'))
    page = app.page
    page.locator('[data-cr-table="drift-findings"] td.cr-state').wait_for(timeout=8000)
    empty = _txt(page, '[data-cr-table="drift-findings"] td.cr-state')
    cards = [_card(page, k) for k in KINDS]
    if case == 'noscan':
        # nothing compared since the server started: grey everywhere, and the page says why
        assert all(c['read'] == 'noscan' and c['tone'] == 'neutral' for c in cards), cards
        assert page.locator('[data-cr-drift-noscan]').count() == 1
        assert _stat(page, 'scan') == '-'
        assert 'says nothing about the current configuration' in empty
    elif case == 'clean':
        assert all(c['tone'] == 'success' for c in cards)
        assert page.locator('[data-cr-drift-noscan]').count() == 0
        assert empty == 'No open findings. Every category was read in the last completed scan.'
    else:
        # partly read and nothing open is not green, and the list says what was not read in full
        net = _card(page, 'network')
        assert net['tone'] == 'neutral' and 'Partly checked' in net['text'] and 'No open findings' not in net['text']
        assert sum(c['tone'] == 'success' for c in cards) == 7
        assert empty == 'No open findings among what was read. Not fully checked in the last scan: Network.'
    # the classic sentence never comes back
    assert 'matches baseline' not in page.locator('[data-cr-drift]').inner_text()
    assert app.errors == []


# --- read states --------------------------------------------------------------------------------

@pytest.mark.parametrize('case', ['events500', 'events_offline', 'status500', 'forbidden', 'notfound', 'away', 'policy500'])
def test_runtime_a_failed_read_is_never_empty_or_green(open_app, case):
    fail = {
        'events500': {'events': (500, {'error': 'internal error'})},
        'events_offline': {'events': 'abort'},
        'status500': {'status': (500, {'error': 'internal error'})},
        'forbidden': {'events': (403, {'error': 'Access denied: this action affects the whole cluster'}),
                      'status': (403, {'error': 'Access denied: this action affects the whole cluster'})},
        'notfound': {'status': (404, {'error': 'cluster not found'}), 'events': (404, {'error': 'cluster not found'})},
        'away': {'events': (503, {'code': 'HA_ACTIVE_UNREACHABLE', 'error': 'The active instance cannot be reached'})},
        'policy500': {'policy': (500, {'error': 'internal error'})},
    }[case]
    app = open_app(fail=fail)
    page = app.page
    page.wait_for_timeout(600)
    text = page.locator('[data-cr-drift]').inner_text()
    assert 'matches baseline' not in text
    # the list never claims to be empty; a category card may, from the status read that did answer
    if page.locator('.cr-drift-findings').count():
        assert 'No open findings' not in page.locator('.cr-drift-findings').inner_text()
    if reads_failed := ('status' in fail):
        assert page.locator('[data-cr-drift-kind]').count() == 0
    if case == 'events500':
        err = _txt(page, '[data-cr-table="drift-findings"] td.cr-state-error')
        assert err.startswith('Could not be read') and 'internal error' in err and 'HTTP 500' in err
        assert page.locator('[data-cr-drift-loaded]').count() == 0
    elif case == 'events_offline':
        assert 'PegaProx could not be reached.' in _txt(page, '[data-cr-table="drift-findings"] td.cr-state-error')
    elif case == 'status500':
        # the counts are unknown, not zero: no card and no stat, the list still shows
        assert page.locator('[data-cr-drift-kind]').count() == 0 and page.locator('[data-cr-stat="open"]').count() == 0
        assert 'HTTP 500' in _txt(page, '[data-cr-drift-state="error"]')
        assert _ids(page)[:2] == [41, 40]
        assert '9 loaded.' in _txt(page, '[data-cr-drift-loaded]')
    elif case in ('forbidden', 'notfound', 'away'):
        state = {'forbidden': 'forbidden', 'notfound': 'notfound', 'away': 'away'}[case]
        assert page.locator(f'[data-cr-drift-whole="{state}"]').count() == 1
        assert page.locator('[data-cr-drift-kind], [data-cr-table="drift-findings"], [data-cr-drift-policy]').count() == 0
        assert page.locator('[data-cr-drift-scan], [data-cr-drift-baseline]').count() == 0
        if case == 'forbidden':
            assert 'admin.audit' in text and 'affects the whole cluster' in text
        if case == 'away':
            assert 'Only the leader' in text
    else:
        assert 'HTTP 500' in _txt(page, '[data-cr-drift-policy] [data-cr-drift-state="error"]')
        assert page.locator('[data-cr-drift-check]').count() == 0
        assert page.locator('[data-cr-drift-kind]').count() == 8
    assert all('authFetch' in e or '50' in e or '40' in e for e in app.errors), app.errors


def test_runtime_a_failed_refresh_drops_what_was_shown(open_app):
    """Classic kept the last good answer when a refresh failed, without a word. Here the counts
    and the rows of before go, and the read says it failed."""
    app = open_app()
    page = app.page
    assert _stat(page, 'open') == '9' and 41 in _ids(page)
    app.server.fail = {'status': (500, {'error': 'internal error'}), 'events': (502, {'error': 'bad gateway'})}
    page.locator('[data-cr-drift-refresh]').click()
    page.locator('[data-cr-table="drift-findings"] td.cr-state-error').wait_for(timeout=8000)
    assert page.locator('[data-cr-drift-kind], [data-cr-stat="open"]').count() == 0
    assert 'HTTP 500' in _txt(page, '[data-cr-drift-state="error"]')
    assert _ids(page) == [] and 'HTTP 502' in _txt(page, '[data-cr-table="drift-findings"] td.cr-state-error')
    assert page.locator('[data-cr-drift-loaded]').count() == 0


def test_runtime_a_read_in_flight_shows_loading_not_empty(open_app):
    app = open_app(evs=[])
    page = app.page
    app.server.hold.add('events')
    page.locator('[data-cr-drift-refresh]').click()
    page.wait_for_timeout(400)
    assert app.server.held, 'the refresh read was not held'
    state = _txt(page, '[data-cr-table="drift-findings"] td.cr-state')
    assert 'Loading' in state and 'No open findings' not in state
    app.server.hold.clear()
    app.server.release()
    page.wait_for_function('() => /No open findings/.test(document.querySelector("[data-cr-table=drift-findings] td.cr-state").innerText)', timeout=8000)
    assert app.errors == []


def test_runtime_another_cluster_starts_from_nothing(open_app):
    """DriftTab is mounted without a key: the rows of the cluster before must not stay when the
    next one's read fails."""
    app = open_app(extra={('GET', '/api/clusters/c2/drift/status'): (500, {'error': 'internal error'}),
                          ('GET', '/api/clusters/c2/drift/events'): (500, {'error': 'internal error'}),
                          ('GET', '/api/clusters/c2/drift/policy'): (500, {'error': 'internal error'})})
    page = app.page
    assert 41 in _ids(page)
    _open_row(page, 41)
    page.locator('.corp-tree-item', has_text='Prod').first.click()
    # the tab stays: the same DriftTab now shows the other cluster
    page.wait_for_function('() => /Prod/.test(document.querySelector("[data-cr-drift] .cr-pagehead-sub").innerText)', timeout=8000)
    page.locator('[data-cr-drift] [data-cr-drift-state="error"]').first.wait_for(timeout=8000)
    page.locator('[data-cr-table="drift-findings"] td.cr-state-error').wait_for(timeout=8000)
    assert _ids(page) == []
    assert page.locator('[data-cr-drift-kind]').count() == 0
    assert page.locator('[data-cr-sidepanel]').count() == 0
    assert any('/clusters/c2/drift/events' in u for u in app.server.urls)


# --- the side panel -------------------------------------------------------------------------------

def test_runtime_the_panel_compares_what_the_finding_stores(open_app):
    app = open_app()
    page = app.page
    panel = _open_row(page, 41)
    assert panel.get_attribute('role') == 'dialog'
    title_id = panel.get_attribute('aria-labelledby')
    assert page.locator(f'#{title_id}').inner_text() == 'VM Config: web01 (100)'
    props = {p['prop']: p for p in _props(panel)}
    assert props['cores']['op'] == 'changed' and props['cores']['cells'][1:4] == ['4', '8', 'Modified']
    # memory has a known unit (MiB); the raw number stays next to it
    assert props['memory']['cells'][1] == '8 GiB (8192 MiB)' and props['memory']['cells'][2] == '16 GiB (16384 MiB)'
    # an option string says which parts changed, the value stays whole
    net = props['net0']['cells'][2]
    assert 'virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=0,tag=20' in net and 'firewall: 1 → 0' in net and 'tag: 10 → 20' in net
    # a secret shows that it changed, never a digest
    assert props['cipassword']['cells'][1:3] == ['hidden', 'changed (value hidden)']
    assert 'redacted' not in panel.inner_text()
    # added: no baseline value is made up
    assert props['onboot']['op'] == 'added' and props['onboot']['cells'][1] == 'not in baseline'
    assert props['onboot']['cells'][2] == 'On (1)'
    foot = panel.locator('.cr-drift-foot-note').inner_text()
    assert 'Only changed properties are listed' in foot and 'not the live configuration' in foot
    assert 'Detected' in panel.inner_text() and '2026-10-30 08:10 (server time)' in panel.inner_text()

    # a firewall rule: one row per field that differs, the rest counted
    panel = _open_row(page, 40)
    props = _props(panel)
    assert [(p['prop'], p['op']) for p in props] == [('action', 'changed')]
    assert props[0]['cells'][0] == 'rule 0003 action' and props[0]['cells'][1:3] == ['ACCEPT', 'DROP']
    assert 'Unchanged fields of rule 0003, not listed: 3.' in panel.inner_text()

    # gone: the baseline fields, nothing current, a cleartext secret of an old row masked
    panel = _open_row(page, 39)
    props = {p['prop']: p for p in _props(panel)}
    assert set(props) == {'type', 'server', 'export', 'content', 'password'}
    assert all(p['op'] == 'removed' and p['cells'][2] == 'not present' for p in props.values())
    assert props['password']['cells'][1] == 'hidden' and 'old-cleartext' not in panel.inner_text()
    assert panel.locator('[data-cr-drift-why="removed"]').count() == 1

    # not verified: the node did not answer, nothing about the current state
    panel = _open_row(page, 38)
    assert 'pve2 did not answer' in panel.locator('[data-cr-drift-why="unknown"]').inner_text()
    assert all(p['op'] == 'unknown' and p['cells'][2] == 'not verified (node offline)' for p in _props(panel))

    # a rule has no baseline
    panel = _open_row(page, 37)
    props = _props(panel)
    assert [p['prop'] for p in props] == ['ops@pve', 'ci@pve!deploy']
    assert all(p['op'] == 'violation' and p['cells'][1] == 'no baseline (rule)' for p in props)
    assert props[0]['cells'][2] == 'Administrator on /'

    # a long value is shown whole, the end where it differs included
    panel = _open_row(page, 33)
    after = _props(panel)[0]['cells'][2]
    assert after == LONG_AFTER
    # planned: the change plan is named
    panel = _open_row(page, 36)
    assert 'Planned: Re-IP pve1' in panel.locator('[data-cr-drift-meta="status"]').inner_text()
    assert '\u2014' not in page.locator('[data-cr-drift]').inner_text() + panel.inner_text()
    assert app.errors == []


def test_runtime_the_panel_takes_the_keyboard_and_gives_it_back(open_app):
    app = open_app()
    page = app.page
    row = page.locator('[data-cr-table="drift-findings"] tr', has=page.locator('[data-cr-drift-row="40"]'))
    row.focus()
    page.keyboard.press('Enter')
    panel = page.locator('[data-cr-sidepanel="drift"]')
    panel.wait_for(timeout=5000)
    assert page.evaluate('() => !!document.activeElement.closest("[data-cr-sidepanel]")')
    assert panel.get_attribute('aria-modal') == 'false'
    page.keyboard.press('Escape')
    page.wait_for_function('() => !document.querySelector("[data-cr-sidepanel]")', timeout=3000)
    # the focus goes back in an effect, a moment after the panel left the page
    page.wait_for_function('() => !!(document.activeElement.closest("tr") && document.activeElement.querySelector("[data-cr-drift-row=\\"40\\"]"))', timeout=3000)
    # the close button does the same; another row opens in the same panel
    _open_row(page, 41)
    _open_row(page, 37)
    assert page.locator('[data-cr-sidepanel]').count() == 1
    page.locator('[data-cr-sp-close]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-sidepanel]")', timeout=3000)
    page.wait_for_function('() => !!(document.activeElement.closest("tr") && document.activeElement.querySelector("[data-cr-drift-row=\\"37\\"]"))', timeout=3000)
    assert app.errors == []


@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_the_panel_leaves_the_task_bar_free(open_app, width):
    app = open_app(viewport=(width, 1000))
    page = app.page
    panel = _settled_panel(page, 41)
    box = panel.bounding_box()
    bar = page.locator('.cr-taskcenter').bounding_box()
    head = page.locator('.cr-header').bounding_box()
    assert box['y'] + box['height'] <= bar['y'] + 0.5, (box, bar)
    assert box['y'] >= head['y'] + head['height'] - 0.5
    assert abs(box['x'] + box['width'] - width) < 1
    assert (box['width'] <= 561) if width == 1600 else (box['width'] <= 490)
    assert box['width'] >= 340
    # the footer stays in view with a long body
    foot = page.locator('.cr-sp-foot').bounding_box()
    assert foot['y'] + foot['height'] <= box['y'] + box['height'] + 0.5
    # no sideways scroll of the page
    assert page.evaluate('() => document.scrollingElement.scrollWidth <= window.innerWidth')
    assert app.errors == []


def test_runtime_the_panel_does_not_slide_with_reduced_motion(browser):
    app = _GuardApp(browser, _DriftServer(layout=LAYOUT))
    try:
        app.page.emulate_media(reduced_motion='reduce')
        _drift(app.page)
        panel = _open_row(app.page, 41)
        assert panel.evaluate('(p) => getComputedStyle(p).animationName') == 'none'
        app.page.emulate_media(reduced_motion='no-preference')
        app.page.locator('[data-cr-sp-close]').click()
        panel = _open_row(app.page, 41)
        assert panel.evaluate('(p) => getComputedStyle(p).animationName') == 'cr-sp-in'
    finally:
        app.close()


# --- actions --------------------------------------------------------------------------------------

def test_runtime_acknowledge_and_promote_say_what_the_server_said(open_app):
    app = open_app()
    page = app.page
    panel = _open_row(page, 35)
    panel.locator('[data-cr-drift-ack="35"]').click()
    # the list is read again: acknowledged is no longer open, the panel of it closes, the message stays
    page.wait_for_function('() => !document.querySelector("[data-cr-table=drift-findings] [data-cr-drift-row=\\"35\\"]")', timeout=5000)
    page.wait_for_function('() => !document.querySelector("[data-cr-sidepanel]")', timeout=5000)
    assert ('/api/drift/events/35/acknowledge', {'promote': False}) in app.server.posts
    msg = _txt(page, '[data-cr-drift-msg="success"]')
    assert msg.startswith('Finding #35: Acknowledged.') and 'the next scan raises it again' in msg
    # the focus is not lost with the row
    assert page.evaluate('() => !!document.activeElement.closest("[data-cr-table=drift-findings]")')
    # promote: the server's answer does not say whether a baseline was written, the page does not claim it
    _open_row(page, 41)
    page.locator('[data-cr-sidepanel] [data-cr-drift-promote="41"]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-table=drift-findings] [data-cr-drift-row=\\"41\\"]")', timeout=5000)
    assert ('/api/drift/events/41/acknowledge', {'promote': True}) in app.server.posts
    assert 'does not say whether it did' in _txt(page, '[data-cr-drift-msg="success"]')
    assert app.errors == []


def test_runtime_a_refused_promote_is_no_promote(open_app):
    refusal = (403, {'error': 'Permission denied: changing a drift baseline needs cluster.config',
                     'code': 'MISSING_PERMISSION', 'required': 'cluster.config'})
    app = open_app(refuse={'promote': refusal})
    page = app.page
    panel = _open_row(page, 41)
    panel.locator('[data-cr-drift-promote="41"]').click()
    panel.locator('[data-cr-drift-msg="error"]').wait_for(timeout=5000)
    assert panel.locator('[data-cr-drift-msg]').inner_text() == \
        'Not done: Permission denied: changing a drift baseline needs cluster.config'
    assert page.locator('[data-cr-table="drift-findings"] [data-cr-drift-row="41"]').count() == 1
    assert _txt(page, '[data-cr-sidepanel] [data-cr-drift-meta="status"] dd').startswith('Open')
    assert all('403' in e for e in app.errors), app.errors


@pytest.mark.parametrize('eid', [39, 38])
def test_runtime_promote_is_off_for_what_has_no_current_state(open_app, eid):
    app = open_app()
    page = app.page
    panel = _open_row(page, eid)
    btn = panel.locator(f'[data-cr-drift-promote="{eid}"]')
    assert btn.is_disabled()
    reason = btn.get_attribute('title')
    assert ('Only a baseline reset accepts it' in reason) if eid == 39 else ('node did not answer' in reason)
    assert page.locator(f'[data-cr-table="drift-findings"] [data-cr-drift-promote="{eid}"]').is_disabled()
    # policy rows and incidents have no promote at all
    assert page.locator('[data-cr-drift-promote="37"], [data-cr-drift-promote="34"]').count() == 0
    assert app.errors == []


def test_runtime_confirm_incident_keeps_the_confirmation(open_app):
    app = open_app()
    page = app.page
    asked = []
    page.once('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    page.locator('[data-cr-table="drift-findings"] [data-cr-drift-incident="41"]').click()
    page.wait_for_timeout(400)
    assert asked == ['Confirm this event as an incident?']
    assert not any(p.endswith('/incident') for p, _ in app.server.posts)
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-cr-table="drift-findings"] [data-cr-drift-incident="41"]').click()
    page.locator('[data-cr-drift-msg="success"]').wait_for(timeout=5000)
    assert ('/api/drift/events/41/incident', {'incident': True}) in app.server.posts
    page.locator('[data-cr-table="drift-findings"] [data-cr-drift-row="41"]').wait_for(timeout=5000)
    page.wait_for_function('() => document.querySelector("[data-cr-table=drift-findings] [data-cr-drift-withdraw=\\"41\\"]")', timeout=5000)
    # withdrawing asks nothing, as in classic
    page.locator('[data-cr-table="drift-findings"] [data-cr-drift-withdraw="41"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-table=drift-findings] [data-cr-drift-incident=\\"41\\"]")', timeout=5000)
    assert ('/api/drift/events/41/incident', {'incident': False}) in app.server.posts
    assert app.errors == []


@pytest.mark.parametrize('mode', ['ok', 'skipped', 'refused'])
def test_runtime_a_scan_reads_its_answer(open_app, mode):
    scan = {'ok': 'ok', 'skipped': 'skipped',
            'refused': (403, {'error': 'Access denied: this action affects the whole cluster'})}[mode]
    app = open_app(scan=scan)
    page = app.page
    page.locator('[data-cr-drift-scan]').click()
    page.locator('[data-cr-drift-pagemsg]').wait_for(timeout=8000)
    msg = page.locator('[data-cr-drift-pagemsg]')
    text = msg.inner_text()
    if mode == 'ok':
        # read in full: what was not read and what was not verified is said, not just "complete"
        assert msg.get_attribute('data-cr-drift-pagemsg') == 'done'
        assert 'New findings: 2.' in text and 'Still open from before: 4.' in text
        assert 'Not read this time, baselines kept: Firewall (objects: 2).' in text
        assert 'Not verified on offline nodes: 1.' in text
        page.wait_for_function('() => /09:00/.test(document.querySelector("[data-cr-drift] [data-cr-stat=scan]").innerText)', timeout=5000)
    elif mode == 'skipped':
        # HTTP 200, but nothing was scanned
        assert msg.get_attribute('data-cr-drift-pagemsg') == 'skipped'
        assert 'cluster offline' in text and 'Nothing was compared' in text and 'completed' not in text
        assert 'Scan complete' not in page.locator('body').inner_text()
        assert _stat(page, 'scan') == '2026-10-30 08:30'
    else:
        assert msg.get_attribute('data-cr-drift-pagemsg') == 'error'
        assert text == 'Scan refused: Access denied: this action affects the whole cluster'
    assert len([p for p, _ in app.server.posts if p.endswith('/scan')]) == 1
    assert all('403' in e for e in app.errors), app.errors


def test_runtime_a_running_scan_cannot_start_twice(open_app):
    app = open_app()
    page = app.page
    app.server.hold.add('scan')
    btn = page.locator('[data-cr-drift-scan]')
    btn.click()
    page.wait_for_function('() => /Scanning/.test(document.querySelector("[data-cr-drift-scan]").innerText)', timeout=5000)
    assert btn.is_disabled() and page.locator('[data-cr-drift-baseline]').is_disabled()
    btn.click(force=True)
    page.wait_for_timeout(1300)
    assert len(app.server.held) == 1 and len([p for p, _ in app.server.posts if p.endswith('/scan')]) == 1
    app.server.hold.clear()
    app.server.release()
    page.locator('[data-cr-drift-pagemsg="done"]').wait_for(timeout=8000)
    assert not btn.is_disabled()
    assert app.errors == []


@pytest.mark.parametrize('who', ['admin', 'auditor'])
def test_runtime_the_first_baseline_needs_cluster_config(open_app, who):
    kw = {'admin': True} if who == 'admin' else {'admin': False, 'perms': ['admin.audit', 'cluster.view']}
    app = open_app(baselines=0, **kw)
    page = app.page
    note = _txt(page, '[data-cr-drift-nobaseline]')
    page.locator('[data-cr-drift-scan]').click()
    page.locator('[data-cr-drift-pagemsg]').wait_for(timeout=8000)
    body = [b for p, b in app.server.posts if p.endswith('/scan')][0]
    if who == 'admin':
        assert body == {'seed': True} and 'cluster.config' not in note
    else:
        # an auditor's seed would be refused: the scan runs without it and the page says so
        assert body == {'seed': False} and 'needs the cluster.config permission' in note
    assert app.errors == []


def test_runtime_reset_baseline_asks_and_reports(open_app):
    app = open_app()
    page = app.page
    asked = []
    page.once('dialog', lambda d: (asked.append(d.message), d.accept()))
    page.locator('[data-cr-drift-baseline]').click()
    page.locator('[data-cr-drift-pagemsg="baseline"]').wait_for(timeout=8000)
    assert asked and asked[0].startswith('Reset baseline from current cluster state?')
    text = _txt(page, '[data-cr-drift-pagemsg]')
    assert 'Objects stored as the new baseline: 31.' in text and '(Firewall): 2.' in text
    # deviations are superseded, the violation and the incident stay
    _wait_rows(page, [37, 34])
    assert app.errors == []


# --- policy checks ----------------------------------------------------------------------------------

def test_runtime_policy_checks_show_their_real_state(open_app):
    pol = checks()
    pol.append({'id': 'mock_like', 'kind': 'access', 'severity': 'warning', 'enabled': True, 'status': 'ok', 'violations': []})
    pol.append({'id': 'switched_off', 'kind': 'firewall', 'severity': 'warning', 'enabled': False, 'status': 'pass', 'violations': []})
    app = open_app(pol=pol)
    page = app.page
    res = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-drift-check]'))
        .map(r => [r.dataset.crDriftCheck, [r.dataset.crDriftResult, r.querySelectorAll('td')[4].innerText.trim(), r.querySelectorAll('td')[5].innerText.trim()]]))''')
    assert res['access_admin_role'][0] == 'fail' and res['access_admin_role'][1].startswith('Failed')
    assert 'violations: 7' in res['access_admin_role'][1]
    assert res['access_token_expiry'][0] == 'warning' and res['access_token_expiry'][1].startswith('Failed - warning')
    assert res['firewall_cluster_enabled'][:2] == ['not_evaluated', 'Not evaluated']
    assert res['backup_none_disabled'][:2] == ['pass', 'Passed']
    # a status this page does not know is not evaluated, never passed; off is off whatever it said before
    assert res['mock_like'][:2] == ['not_evaluated', 'Not evaluated']
    assert res['switched_off'][:2] == ['off', 'Off']
    # the evaluation time only where the last scan evaluated it
    assert res['access_admin_role'][2] == '2026-10-30 08:30' and res['backup_none_disabled'][2] == '2026-10-30 08:30'
    assert res['firewall_cluster_enabled'][2] == '-' and res['switched_off'][2] == '-'
    # every violation, not the first five
    page.locator('[data-cr-drift-expand="access_admin_role"]').click()
    detail = page.locator('[data-cr-drift-pdetail="access_admin_role"]')
    assert detail.locator('[data-cr-drift-violations] li').count() == 7
    assert page.locator('[data-cr-drift-expand="access_admin_role"]').get_attribute('aria-expanded') == 'true'
    # a pass with what it was evaluated on
    page.locator('[data-cr-drift-expand="backup_none_disabled"]').click()
    assert page.locator('[data-cr-drift-pdetail="backup_none_disabled"] [data-cr-drift-evaluated]').get_attribute('data-cr-drift-evaluated') == '3'
    page.locator('[data-cr-drift-expand="firewall_cluster_enabled"]').click()
    assert 'It is not counted as passed.' in page.locator('[data-cr-drift-pdetail="firewall_cluster_enabled"]').inner_text()
    assert app.errors == []


def test_runtime_the_policy_switch_goes_through_save_policy(open_app):
    app = open_app()
    page = app.page
    sw = page.locator('[data-cr-drift-enable="backup_none_disabled"]')
    assert sw.is_checked()
    sw.click()
    page.wait_for_function('() => !document.querySelector("[data-cr-drift-enable=backup_none_disabled]").checked', timeout=5000)
    assert ('/api/clusters/c1/drift/policy', {'checks': {'backup_none_disabled': {'enabled': False}}}) in app.server.posts
    row = page.locator('[data-cr-drift-check="backup_none_disabled"]')
    assert row.get_attribute('data-cr-drift-result') == 'off'
    # the classic handler's toast
    page.get_by_text('Policy saved').first.wait_for(timeout=5000)
    # a changed allow list is not evaluated until the next scan, and the row says so
    page.locator('[data-cr-drift-expand="access_admin_role"]').click()
    page.locator('[data-cr-drift-allow="access_admin_role"]').fill('root@pam, ops@pve')
    page.locator('[data-cr-drift-allow-save="access_admin_role"]').click()
    page.locator('[data-cr-drift-changed="access_admin_role"]').wait_for(timeout=5000)
    assert ('/api/clusters/c1/drift/policy', {'checks': {'access_admin_role': {'allow': ['root@pam', 'ops@pve']}}}) in app.server.posts
    assert 'changed, not re-evaluated' in page.locator('[data-cr-drift-check="access_admin_role"]').inner_text()
    page.locator('[data-cr-drift-scan]').click()
    page.locator('[data-cr-drift-pagemsg="done"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-drift-changed]').count() == 0
    assert app.errors == []


def test_runtime_a_refused_policy_change_says_why(open_app):
    refusal = (403, {'error': 'Permission denied: changing a drift baseline needs cluster.config',
                     'code': 'MISSING_PERMISSION', 'required': 'cluster.config'})
    app = open_app(refuse={'policy': refusal})
    page = app.page
    page.locator('[data-cr-drift-enable="backup_none_disabled"]').click()
    page.locator('[data-cr-drift-pmsg="backup_none_disabled"]').wait_for(timeout=5000)
    assert _txt(page, '[data-cr-drift-pmsg="backup_none_disabled"]') == \
        'Not done: Permission denied: changing a drift baseline needs cluster.config'
    assert page.locator('[data-cr-drift-enable="backup_none_disabled"]').is_checked()
    assert all('403' in e for e in app.errors), app.errors


# --- permissions --------------------------------------------------------------------------------------

@pytest.mark.parametrize('who', ['auditor', 'auditor_config', 'admin'])
def test_runtime_buttons_follow_what_the_server_asks(open_app, who):
    kw = {'auditor': {'admin': False, 'perms': ['admin.audit', 'cluster.view']},
          'auditor_config': {'admin': False, 'perms': ['admin.audit', 'cluster.view', 'cluster.config']},
          'admin': {'admin': True}}[who]
    app = open_app(**kw)
    page = app.page
    count = lambda sel: page.locator(f'[data-cr-table="drift-findings"] {sel}').count()
    config = who != 'auditor'
    assert page.locator('[data-cr-drift-scan]').count() == 1
    assert page.locator('[data-cr-drift-baseline]').count() == (1 if config else 0)
    assert count('[data-cr-drift-ack="41"]') == 1
    # a policy violation is acknowledged with cluster.config only
    assert count('[data-cr-drift-ack="37"]') == (1 if config else 0)
    assert count('[data-cr-drift-promote="41"]') == (1 if config else 0)
    assert count('[data-cr-drift-incident="41"]') == (1 if who == 'admin' else 0)
    sw = page.locator('[data-cr-drift-enable="access_admin_role"]')
    assert sw.is_disabled() != config
    if not config:
        assert 'cluster.config' in page.locator('[data-cr-drift-check="access_admin_role"] .cr-switch').get_attribute('title')
    assert app.errors == []


def test_runtime_an_account_without_admin_audit_reads_nothing(open_app):
    app = open_app(admin=False, perms=['node.maintenance', 'cluster.view'])
    page = app.page
    page.locator('[data-cr-drift-whole="forbidden"]').wait_for(timeout=8000)
    assert 'admin.audit' in page.locator('[data-cr-drift]').inner_text()
    assert page.locator('[data-cr-drift-kind]').count() == 0
    assert all('403' in e for e in app.errors), app.errors


def test_runtime_a_read_only_standby_acts_on_nothing(open_app):
    app = open_app(role='standby')
    page = app.page
    page.locator('[data-cr-drift-readonly]').wait_for(timeout=8000)
    assert page.locator('[data-cr-drift-scan], [data-cr-drift-baseline], [data-cr-drift-ack], [data-cr-drift-promote], '
                        '[data-cr-drift-incident]').count() == 0
    assert page.locator('[data-cr-drift-enable="access_admin_role"]').is_disabled()
    assert app.server.posts == []


# --- the list -----------------------------------------------------------------------------------------

def test_runtime_filters_search_and_what_is_loaded(open_app):
    app = open_app()
    page = app.page
    assert _ids(page) == [41, 40, 39, 38, 37, 36, 35, 34, 33]
    loaded = page.locator('[data-cr-drift-loaded]')
    assert loaded.get_attribute('data-cr-drift-loaded') == '9'
    assert loaded.get_attribute('data-cr-drift-of') == '9'
    # an older finding of the same object is marked
    assert page.locator('[data-cr-drift-row="33"]').locator('xpath=ancestor::tr').locator('[data-cr-drift-older]').count() == 1
    assert page.locator('[data-cr-drift-row="41"]').locator('xpath=ancestor::tr').locator('[data-cr-drift-older]').count() == 0
    page.locator('[data-cr-drift-show="acknowledged"]').click()
    _wait_rows(page, [30])
    assert app.server.reads[-1]['status'] == 'acknowledged'
    assert page.locator('[data-cr-drift-loaded]').get_attribute('data-cr-drift-of') == ''
    page.locator('[data-cr-drift-show="all"]').click()
    _wait_rows(page, [41, 40, 39, 38, 37, 36, 35, 34, 33, 30])
    page.locator('[data-cr-drift-filter="category"]').select_option('policy_violation')
    _wait_rows(page, [37])
    assert app.server.reads[-1] == {'status': 'all', 'limit': '500', 'category': 'policy_violation'}
    page.locator('[data-cr-drift-filter="category"]').select_option('')
    page.locator('[data-cr-drift-show="open"]').click()
    _wait_rows(page, [41, 40, 39, 38, 37, 36, 35, 34, 33])
    # the search works on the loaded rows: names from the inventory count
    page.locator('[data-cr-drift] input[type="search"]').fill('web01')
    _wait_rows(page, [41, 33])
    assert app.errors == []


def test_runtime_a_capped_list_says_how_much_is_missing(open_app):
    many = [_ev(1000 + i, 'vm_config', f'qemu/{2000 + i}', 'info',
                [{'path': 'description', 'op': 'changed', 'before': 'a', 'after': str(i)}],
                f'2026-10-30T07:{i // 60 % 60:02d}:{i % 60:02d}.000000') for i in range(650)]
    app = open_app(evs=many)
    page = app.page
    loaded = page.locator('[data-cr-drift-loaded]')
    assert loaded.get_attribute('data-cr-drift-loaded') == '500' and loaded.get_attribute('data-cr-drift-of') == '650'
    assert '500 loaded of 650 open. The server sends at most 500 findings, newest first.' in loaded.inner_text()
    # drawn as a window, not 500 rows
    assert 0 < page.locator('[data-cr-table="drift-findings"] tbody tr.cr-row').count() < 120
    assert app.errors == []


def test_runtime_resources_lead_to_the_object(open_app):
    app = open_app()
    page = app.page
    row = lambda eid: page.locator(f'[data-cr-drift-row="{eid}"]').locator('xpath=ancestor::tr')
    # a guest that is not in the inventory is plain text and says so
    assert row(35).locator('[data-cr-drift-go]').count() == 0
    assert 'not in the inventory you can see' in row(35).locator('.cr-drift-res').get_attribute('title')
    # a whole-cluster scope leads to the Datacenter section that holds it (round 3, stage J); the
    # access policy has no such section and stays text
    assert row(34).locator('[data-cr-drift-go="cluster"]').count() == 1
    assert 'Datacenter > Options' in row(34).locator('.cr-drift-res').get_attribute('title')
    assert row(37).locator('[data-cr-drift-go]').count() == 0
    # a network scope opens its node
    assert row(36).locator('[data-cr-drift-go="node"]').inner_text() == 'vmbr0 (pve1)'
    row(41).locator('[data-cr-drift-go="guest"]').click()
    page.locator('[data-cr-drift]').wait_for(state='detached', timeout=8000)
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.locator('[data-cr-crumb="guest"]', has_text='web01').wait_for(timeout=5000)
    assert app.errors == []


def test_runtime_the_timeline_opens_the_finding(open_app):
    tl = {'events': [{'id': 'drift:39', 'time': '2026-10-30T07:08:00+00:00', 'kind': 'drift', 'severity': 'warning',
                      'cluster': 'c1', 'node': None, 'guest': None, 'guest_name': '', 'title': 'storage nfs-backup: object removed',
                      'details': '', 'what': 'drift', 'params': {'drift_kind': 'storage', 'scope': 'nfs-backup', 'status': 'open'},
                      'source': {'route': '/api/clusters/c1/drift/events', 'id': '39'}}],
          'sources': {}, 'correlation': {'window_minutes': 10}, 'next_before': None}
    app = open_app(wait=False, extra={('GET', '/api/timeline'): (200, tl)})
    page = app.page
    page.locator('[data-cr-tab="timeline"]').click()
    page.locator('[data-tl-open-view="compliance"]').click()
    page.locator('[data-cr-sidepanel="drift"] [data-cr-drift-detail="39"]').wait_for(timeout=8000)
    assert page.locator('[data-compliance-sub="drift"]').get_attribute('class').find('active') >= 0
    assert app.errors == []


def test_runtime_the_page_speaks_german(open_app):
    app = open_app(language='de')
    page = app.page
    # titles are upper case by CSS, which innerText follows
    text = page.locator('[data-cr-drift]').inner_text().lower()
    for word in ('risikoübersicht', 'offene befunde', 'letzter abgeschlossener scan', 'befunde', 'nicht ausgewertet'):
        assert word in text, word
    assert app.errors == []


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_keep_the_classic_drift_tab(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.locator('[data-compliance-sub="drift"]').click()
    page.locator('[data-drift-kind="vm_config"]').wait_for(timeout=10000)
    assert page.locator('[data-cr-drift]').count() == 0
    # the classic reads: one round of three, the list with its limit of 200
    assert any('/drift/events?status=open&limit=200' in u for u in app.server.urls)
    assert app.errors == []


@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_nothing_overlaps_in_firefox(firefox, width):
    """Round 2 shipped an overlap only Firefox drew: the cards, the table and the panel are
    measured there too."""
    app = _GuardApp(firefox, _DriftServer(layout=LAYOUT), viewport=(width, 1000))
    try:
        page = app.page
        _drift(page)
        boxes = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-drift-kind]')).map(e => {
            const r = e.getBoundingClientRect(); return [r.left, r.top, r.right, r.bottom]; })''')
        for i, a in enumerate(boxes):
            for b in boxes[i + 1:]:
                assert a[2] <= b[0] + 0.5 or b[2] <= a[0] + 0.5 or a[3] <= b[1] + 0.5 or b[3] <= a[1] + 0.5, (a, b)
        # the card texts fit their card
        assert page.evaluate('''() => Array.from(document.querySelectorAll('.cr-drift-card-head, .cr-drift-card-counts'))
            .every(e => e.scrollWidth <= e.clientWidth + 1)''')
        assert page.evaluate('() => document.scrollingElement.scrollWidth <= window.innerWidth')
        panel = _settled_panel(page, 41)
        box = panel.bounding_box()
        bar = page.locator('.cr-taskcenter').bounding_box()
        assert box['y'] + box['height'] <= bar['y'] + 0.5
        # the comparison cells stay inside the panel
        assert panel.evaluate('''(p) => { const r = p.getBoundingClientRect();
            return Array.from(p.querySelectorAll('.cr-drift-cmp td, .cr-drift-cmp th')).every(c => c.getBoundingClientRect().right <= r.right + 1); }''')
        assert app.errors == []
    finally:
        app.close()


# --- after the review of round 3 -------------------------------------------------------------------

class _NoGuestList(_DriftServer):
    """The guest list of the cluster cannot be read (the dashboard seeds an empty one)."""

    def handle(self, route):
        path = re.sub(r'^https?://[^/]+', '', route.request.url).split('?')[0]
        if path == '/api/clusters/c1/resources':
            return route.fulfill(status=500, body=json.dumps({'error': 'resources down'}), headers={'Content-Type': 'application/json'})
        return super().handle(route)


def test_runtime_an_unread_guest_list_is_not_said_to_hide_the_guest(browser):
    app = _GuardApp(browser, _NoGuestList(layout=LAYOUT), viewport=(1600, 1000))
    try:
        page = app.page
        _drift(page)
        titles = page.evaluate("() => Array.from(document.querySelectorAll('.cr-drift-res')).map(e => e.title)")
        guests = [x for x in titles if x.startswith(('VM ', 'CT '))]
        assert guests and all(x.endswith('the inventory of the cluster is not loaded') for x in guests), titles
        assert not [x for x in titles if 'not in the inventory you can see' in x], titles
        panel = _open_row(page, 41)
        meta = panel.locator('[data-cr-drift-meta="resource"]').inner_text()
        assert 'the inventory of the cluster is not loaded' in meta and 'you can see' not in meta, meta
    finally:
        app.close()


def test_runtime_a_guest_that_is_not_in_the_read_list_still_says_so(open_app):
    # the list was read and the guest is not in it: that claim stays
    app = open_app()
    page = app.page
    title = page.locator('[data-cr-drift-row="35"]').locator('xpath=ancestor::tr').locator('.cr-drift-res').get_attribute('title')
    assert title.endswith('not in the inventory you can see'), title
    assert app.errors == []


def test_runtime_aria_controls_names_only_what_is_there(open_app):
    app = open_app()
    page = app.page
    dangling = '''() => Array.from(document.querySelectorAll('[aria-controls]')).flatMap(el => el.getAttribute('aria-controls')
        .split(/\\s+/).filter(id => !document.getElementById(id)).map(id => el.tagName + ' ' + id))'''
    assert page.evaluate(dangling) == []
    exp = page.locator('[data-cr-drift-expand="access_admin_role"]')
    exp.click()
    assert exp.get_attribute('aria-controls') == 'cr-drift-pd-access_admin_role'
    assert page.evaluate(dangling) == []
    assert app.errors == []


def test_runtime_policy_texts_are_said_in_the_users_language(open_app):
    pol = checks()
    pol[1] = dict(pol[1], status='pass', violations=[])
    # a check of a newer server: its id, never a key
    pol.append({'id': 'storage_shared_only', 'kind': 'storage', 'severity': 'info', 'enabled': True, 'status': 'fail',
                'violations': [{'path': 'local-zfs', 'detail': 'local storage holds guests'}]})
    app = open_app(pol=pol, language='de')
    page = app.page
    names = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-drift-check]'))
        .map(r => [r.dataset.crDriftCheck, r.querySelectorAll('td')[1].innerText.trim()]))''')
    assert names['storage_shared_only'] == 'storage_shared_only', names
    assert not [n for n in names.values() if n.startswith('driftCheck_')], names
    page.locator('[data-cr-drift-expand="access_admin_role"]').click()
    first = page.locator('[data-cr-drift-pdetail="access_admin_role"] [data-cr-drift-violations] li').first.inner_text()
    assert first == 'user0@pve Administrator auf /', first
    # the unknown check keeps the server's words
    page.locator('[data-cr-drift-expand="storage_shared_only"]').click()
    assert 'local storage holds guests' in page.locator('[data-cr-drift-pdetail="storage_shared_only"]').inner_text()
    # the token check passes without saying how many tokens it read: that is said
    page.locator('[data-cr-drift-expand="access_token_expiry"]').click()
    note = page.locator('[data-cr-drift-pdetail="access_token_expiry"] [data-cr-drift-evaluated="unknown"]')
    assert 'wie viele API-Tokens' in note.inner_text()
    # the comparison of a policy finding: the violation in German as well
    panel = _open_row(page, 37)
    cells = {p['prop']: p['cells'] for p in _props(panel)}
    assert cells['ops@pve'][2] == 'Administrator auf /', cells
    assert app.errors == []


def test_runtime_the_token_check_says_it_does_not_count_its_tokens(open_app):
    pol = checks()
    pol[1] = dict(pol[1], status='pass', violations=[])
    app = open_app(pol=pol)
    page = app.page
    page.locator('[data-cr-drift-expand="access_token_expiry"]').click()
    detail = page.locator('[data-cr-drift-pdetail="access_token_expiry"]')
    assert 'The server does not say how many API tokens it read' in detail.inner_text()
    # the backup check keeps its count, the failing admin check has its offenders
    page.locator('[data-cr-drift-expand="backup_none_disabled"]').click()
    assert page.locator('[data-cr-drift-pdetail="backup_none_disabled"] [data-cr-drift-evaluated]').get_attribute('data-cr-drift-evaluated') == '3'
    assert app.errors == []
