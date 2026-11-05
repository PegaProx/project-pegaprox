"""Automation > Harden PVE Node in Corporate Redesigned (Preview), round 4.

The tab keeps the three routes of the classic one with the same request bodies (the check of
one node, the apply one POST per control with force only for sshd_hardening after the red
tick, the rollback one POST for the list) and draws them differently: nothing is ticked after
a check, a passing check is "Passed" and never "Applied", what an apply or a rollback answered
stays for the session until it is dismissed (the check after it does not wipe it), Apply and
Rollback have their own selection and their own confirmation that lists the controls with
what each declares ("not declared" for files and cluster traffic), rollback only for the
controls whose catalog entry says so, audit only controls are not offered for Apply, a failed
check is a state with the server's reason, 0 of 0 is neutral. Standby, XCP-ng and a user
without node.maintenance change nothing. Classic Corporate, Modern and Cloud keep their tab
to the pixel (tests/test_corp_redesigned_guard_ui.py, view "harden").

The fake serves the real shapes of pegaprox/api/reports.py (verbose check with status,
evidence, command and not_checked, the summary, the catalog with rollback for the four
controls that declare backup_files, the blocked answer of the lockout guard, the rollback
errors). PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). LW Nov 2026
"""
import json
import os
import re
import time
import urllib.parse

import pytest

from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp, _GuardServer
from test_ha_ui import CLUSTER
from test_hardening_custom_profiles_ui import BUILTIN, CIS, DEFAULTS, IDS, VSNFD

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

# what manager.py declares: backup_files on these four only (catalog[].rollback)
ROLLBACK = ('ssh_crypto', 'sshd_hardening', 'pam_nullok_removal', 'default_umask')
CATALOG = [{'id': c, 'templated': c in DEFAULTS, 'param_keys': list(DEFAULTS.get(c, {})),
            'defaults': dict(DEFAULTS.get(c, {})), 'rollback': c in ROLLBACK} for c in IDS]
PASS = {'fs_modules', 'journald', 'file_perms', 'apparmor', 'ssh_perms'}
UNREAD = {'core_dumps', 'process_acct'}
EVIDENCE = {'journald': 'Storage=persistent\nCompress=yes', 'ssh_crypto': 'ciphers aes128-ctr,3des-cbc',
            'apparmor': '42 profiles are in enforce mode.'}
NOOP = {'net_protocols'} | set(VSNFD)
VSNFD_SET = ['fs_modules', 'journald', 'ssh_crypto', 'pw_quality', 'net_protocols'] + VSNFD


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


class _HdServer(_GuardServer):
    """The guard fake plus the node hardening routes with the state of a node in memory."""

    def __init__(self, cluster=None, has_key=True, check_answer=None, catalog=True, apply_fail=None, **kw):
        super().__init__(bundle=BUNDLE, **kw)
        c = dict(CLUSTER, **(cluster or {}))
        self.clusters = [c]
        self.has_key = has_key                  # the server's mgr.config.ssh_key
        self.check_answer = check_answer        # (status, body) instead of a real check
        self.catalog = catalog
        self.apply_fail = dict(apply_fail or {'pve_fail2ban': 'SSH command failed'})
        self.state = {}                         # node -> {id: True/False/None}
        self.snap = set()                       # (node, id) with a saved file
        self.checks, self.applies, self.rollbacks = [], [], []
        self.hold_apply = False
        self.held_apply = []

    def node_state(self, node):
        if node not in self.state:
            self.state[node] = {c: (True if c in PASS else None if c in UNREAD else False) for c in IDS}
        return self.state[node]

    def hd_check(self, url, node):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        verbose = (q.get('verbose') or [''])[0] in ('1', 'true', 'yes')
        profile = (q.get('profile') or [''])[0]
        self.checks.append({'node': node, 'verbose': verbose, 'profile': profile})
        if self.check_answer:
            return self.check_answer
        extra = {}
        if profile.startswith('custom:'):
            p = next(x for x in self.profiles if x['id'] == profile[7:])
            ids = p['controls']
            extra = {'profile': profile, 'requested_profile': profile, 'profile_name': p['name'],
                     'dropped_controls': p.get('dropped_controls') or []}
        else:
            ids = VSNFD_SET if profile == 'vs-nfd' else CIS
        st = self.node_state(node)
        if verbose:
            controls = {}
            for c in ids:
                e = {'status': st[c], 'evidence': EVIDENCE.get(c, ''), 'command': f"grep -q pegaprox /etc/{c}.conf && echo OK || echo FAIL"}
                if st[c] is None:
                    e['not_checked'] = 'The check printed neither OK nor FAIL'
                controls[c] = e
        else:
            controls = {c: st[c] for c in ids}
        vals = [st[c] for c in ids]
        summary = {'total': len(vals), 'passed': vals.count(True), 'failed': vals.count(False), 'not_checked': vals.count(None)}
        summary['checked'] = summary['passed'] + summary['failed']
        return 200, {'node': node, 'controls': controls, 'verbose': verbose, 'profile': profile or 'cis-l1',
                     'requested_profile': profile or 'cis-l1', 'summary': summary, **extra}

    def hd_apply(self, node, body):
        self.applies.append(body)
        controls = list(body.get('controls') or [])
        results = {}
        if 'sshd_hardening' in controls and not self.has_key and not body.get('force'):
            controls.remove('sshd_hardening')
            results['sshd_hardening'] = {'success': False, 'blocked': True,
                                         'error': 'Blocked: SSH Access Hardening disables root password login and would cut off '
                                                  'PegaProx access to this cluster (no SSH key is configured). Add an SSH key to '
                                                  'the cluster first, or re-apply with force to override.'}
        st = self.node_state(node)
        for c in controls:
            if c in self.apply_fail:
                results[c] = {'success': False, 'error': self.apply_fail[c]}
                continue
            if c in ROLLBACK:
                self.snap.add((node, c))
            if c not in NOOP:
                st[c] = True
            results[c] = {'success': True}
        ok = sum(1 for v in results.values() if v.get('success'))
        return 200, {'node': node, 'results': results, 'applied': ok, 'total': len(body.get('controls') or [])}

    def hd_rollback(self, node, body):
        self.rollbacks.append(body)
        results = {}
        for c in body.get('controls') or []:
            if c not in ROLLBACK:
                results[c] = {'success': False, 'error': 'control has no rollback snapshot (not reversible)'}
            elif (node, c) not in self.snap:
                results[c] = {'success': False, 'error': 'no snapshot found \u2014 control was never applied (or already rolled back)'}
            else:
                self.snap.discard((node, c))
                self.node_state(node)[c] = False
                results[c] = {'success': True}
        ok = sum(1 for v in results.values() if v.get('success'))
        return 200, {'node': node, 'results': results, 'restored': ok, 'total': len(body.get('controls') or [])}

    def hd_release(self):
        held, self.held_apply, self.hold_apply = self.held_apply, [], False
        for route, status, data in held:
            route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/c1/nodes/([^/]+)/hardening(/rollback)?', path)
        if m or (path == '/api/hardening/profiles' and req.method == 'GET'):
            self.calls.append((req.method, path))
            self.urls.append(req.url)
            body = json.loads(req.post_data) if req.post_data else {}
            if not m:
                if self.catalog is not True:
                    status, data = self.catalog
                else:
                    status, data = 200, dict(self.listing(), catalog=CATALOG, builtin=BUILTIN)
            elif req.method == 'GET':
                status, data = self.hd_check(req.url, m.group(1))
            elif m.group(2):
                status, data = self.hd_rollback(m.group(1), body)
            else:
                status, data = self.hd_apply(m.group(1), body)
                if self.hold_apply:
                    self.held_apply.append((route, status, data))
                    return None
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
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

    def _open(engine='chromium', viewport=(1600, 1000), **kw):
        br = browser[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = _GuardApp(br, _HdServer(layout=LAYOUT, **kw), viewport=viewport)
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


def _tab(app, node='pve1'):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="automation"]').click()
    page.wait_for_timeout(300)
    page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Harden PVE Node\s*$')).first.click()
    _need(page, '[data-cr-harden]', 'the Harden tab is the redesigned view')
    if node:
        page.locator('[data-cr-hd-node]').select_option(node)
    return page


def _check(app):
    page = app.page
    n = len(app.server.checks)
    page.locator('[data-cr-hd-check-btn]').click()
    _poll(app, lambda: len(app.server.checks) > n)
    page.wait_for_function('() => !document.querySelector("[data-cr-hd-loading]") && document.querySelector("[data-cr-hd-report], [data-cr-hd-error]")', timeout=8000)
    page.wait_for_timeout(150)


def _poll(app, cond, seconds=8):
    deadline = time.time() + seconds
    while time.time() < deadline and not cond():
        app.page.wait_for_timeout(100)
    return cond()


def _stat(page, sid):
    return page.locator(f'[data-cr-stat="{sid}"] .cr-stat-value').inner_text().strip()


def _state(page, cid):
    return page.locator(f'[data-cr-hd-check="{cid}"]').get_attribute('data-cr-hd-state')


def _pick(page, cid):
    page.locator(f'[data-cr-hd-pick="{cid}"]').check()


def _picked(page):
    return page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-hd-pick]:checked")).map(e => e.dataset.crHdPick)')


def _writes(app):
    return [c for c in app.server.calls if c[0] != 'GET' and 'hardening' in c[1]]


def _mode(page, m):
    page.locator(f'[data-cr-hd-mode-btn="{m}"]').click()
    page.wait_for_function('m => document.querySelector(`[data-cr-hd-mode-btn="${m}"]`).getAttribute("aria-pressed") === "true"', arg=m)


# --- source ------------------------------------------------------------------------------------

def test_the_access_list_is_the_one_of_the_classic_tab():
    dash = _read('web', 'src', 'dashboard.js')
    cr = _read('web', 'src', 'cr_harden.js')
    classic = re.search(r"const HARDEN_ACCESS_CONTROLS = \[([^\]]*)\]", dash).group(1)
    mine = re.search(r"const CR_HD_ACCESS = \[([^\]]*)\]", cr).group(1)
    assert re.findall(r"'(\w+)'", classic) == re.findall(r"'(\w+)'", mine)


def test_the_classic_tab_is_only_gated_and_the_preview_has_its_own_branch():
    dash = _read('web', 'src', 'dashboard.js')
    assert dash.count("{automationSubTab === 'hardening' && !isCorpRedesigned && (") == 1
    assert dash.count("{automationSubTab === 'hardening' && isCorpRedesigned && selectedCluster?.id && (") == 1
    # the classic handlers keep their request bodies; the preview sends the same ones
    cr = _read('web', 'src', 'cr_harden.js')
    assert "params: params && params[id] ? { [id]: params[id] } : {}," in cr
    assert "...(id === 'sshd_hardening' && force ? { force: true } : {})," in cr
    assert "body: JSON.stringify({ controls: ids })," in cr
    assert 'window.confirm' not in cr and 'confirm(' not in cr.replace('onConfirm(', '')


def test_every_key_of_the_tab_is_in_english_and_german_before_the_pinned_block():
    cr = _read('web', 'src', 'cr_harden.js')
    keys = sorted(set(re.findall(r"'(crHd[A-Za-z]+)'", cr)))
    assert len(keys) > 80
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[a:b] for (a, lang), b in zip(starts, ends)}
    for lang in ('en', 'de'):
        marker = blocks[lang].index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in keys:
            found = re.findall(rf'^                {k}: "((?:[^"\\]|\\.)*)",$', blocks[lang], re.M)
            assert len(found) == 1, (lang, k)
            assert '\u2014' not in found[0] and '\u2013' not in found[0], (lang, k)
            assert blocks[lang].index(f'                {k}: ') < marker, (lang, k)
    en = {k: re.search(rf'^                {k}: "(.*)",$', blocks['en'], re.M).group(1) for k in keys}
    de = {k: re.search(rf'^                {k}: "(.*)",$', blocks['de'], re.M).group(1) for k in keys}
    for k in keys:
        assert sorted(re.findall(r'\{\w+\}', en[k])) == sorted(re.findall(r'\{\w+\}', de[k])), k
        assert 'Applied' not in en[k] or k in ('crHdOutApplied',), k


# --- runtime: reading -------------------------------------------------------------------------

def test_runtime_nothing_is_read_from_the_node_until_check_status(open_app):
    app = open_app()
    page = _tab(app, node=None)
    _need(page, '[data-cr-hd-empty="no-node"]', 'no node picked is its own state')
    page.locator('[data-cr-hd-node]').select_option('pve1')
    _need(page, '[data-cr-hd-empty="not-checked"]', 'a picked node is "not checked yet", not an empty list')
    page.wait_for_timeout(500)
    assert app.server.checks == [] and not page.locator('[data-cr-hd-report]').count()
    assert page.locator('[data-cr-hd-check-btn]').inner_text().strip() == 'Check Status'
    assert app.errors == []


def test_runtime_the_check_counts_passed_failed_not_checked_and_ticks_nothing(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    assert app.server.checks == [{'node': 'pve1', 'verbose': True, 'profile': ''}]
    total, passed, unread = len(CIS), len(PASS), len(UNREAD)
    assert (_stat(page, 'hd-passed'), _stat(page, 'hd-failed'), _stat(page, 'hd-unchecked'), _stat(page, 'hd-pending')) == \
        (str(passed), str(total - passed - unread), str(unread), '0')
    assert _stat(page, 'hd-coverage') == f'{round((total - unread) * 100 / total)}%'
    assert page.locator('[data-cr-hd-progress]').get_attribute('data-cr-hd-progress') == 'checked'
    # one badge per control: "Passed" for a passing check, never "Applied"
    assert _state(page, 'journald') == 'passed' and _state(page, 'mount_options') == 'failed' and _state(page, 'core_dumps') == 'unchecked'
    body = page.locator('[data-cr-harden]').inner_text()
    assert 'Applied' not in body and 'controls active' not in body
    # nothing is ticked after a check, in either mode
    assert _picked(page) == []
    _mode(page, 'rollback')
    assert _picked(page) == []
    assert app.errors == []


def test_runtime_zero_of_zero_is_neutral_and_never_green(open_app):
    unread = {c: {'status': None, 'evidence': '', 'command': 'x', 'not_checked': 'No output came back for this control'} for c in CIS}
    app = open_app(check_answer=(200, {'node': 'pve1', 'controls': unread, 'verbose': True, 'profile': 'cis-l1',
                                       'requested_profile': 'cis-l1', 'summary': {'total': 44, 'passed': 0, 'failed': 0,
                                                                                  'not_checked': 44, 'checked': 0}}))
    page = _tab(app)
    _check(app)
    assert _stat(page, 'hd-passed') == '0' and _stat(page, 'hd-unchecked') == str(len(CIS))
    assert 'nothing checked yet' in page.locator('[data-cr-stat="hd-passed"]').inner_text()
    assert page.locator('[data-cr-hd-progress]').get_attribute('data-cr-hd-progress') == 'none'
    green = page.evaluate('''() => getComputedStyle(document.body).getPropertyValue('--cr-success').trim()''')
    colours = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-hd-summary] .cr-stat-value, [data-cr-hd-progress] *'))
        .map(e => getComputedStyle(e).color)''')
    assert all(c != 'rgb(100, 185, 74)' for c in colours), (green, colours)
    assert page.locator('.cr-cmp-bar-pass').evaluate('e => e.getBoundingClientRect().width') == 0
    # the reason of the server is in the detail
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='Disable Core Dumps').click()
    _need(page, '[data-cr-sidepanel="harden-control"]', 'a row opens its detail')
    assert 'No output came back for this control' in page.locator('[data-cr-hd-detail-check]').inner_text()
    assert app.errors == []


def test_runtime_a_failed_check_is_a_state_with_the_reason_of_the_server(open_app):
    ssh = {'error': 'Cannot read pve1 over SSH: timed out', 'code': 'SSH_FAILED', 'hint': 'Check the SSH settings',
           'node': 'pve1', 'cluster_wide': False}
    app = open_app(check_answer=(502, ssh))
    page = _tab(app)
    _check(app)
    note = page.locator('[data-cr-hd-error]')
    assert note.get_attribute('data-cr-hd-error') == 'ssh'
    assert 'Cannot read pve1 over SSH: timed out' in note.inner_text()
    assert not page.locator('[data-cr-hd-report]').count()
    # a confined caller: the server's sentence, as a state
    app.server.check_answer = (403, {'error': 'Access denied: this action affects the whole cluster'})
    _check(app)
    assert page.locator('[data-cr-hd-error]').get_attribute('data-cr-hd-error') == 'denied'
    assert 'affects the whole cluster' in page.locator('[data-cr-hd-error]').inner_text()
    # a good check, then a failing one: the list stays and says how old it is
    app.server.check_answer = None
    _check(app)
    assert not page.locator('[data-cr-hd-error]').count() and page.locator('[data-cr-hd-report]').count() == 1
    app.server.check_answer = (503, {'error': 'Cluster offline'})
    _check(app)
    assert page.locator('[data-cr-hd-error]').get_attribute('data-cr-hd-error') == 'offline'
    assert page.locator('[data-cr-hd-stale]').count() == 1 and page.locator('[data-cr-hd-report]').count() == 1
    assert app.errors == []


def test_runtime_without_node_maintenance_nothing_is_asked(open_app):
    app = open_app(admin=False, permissions=['cluster.view', 'vm.view'])
    page = _tab(app)
    _need(page, '[data-cr-hd-state="no-permission"]', 'the missing permission is said')
    assert page.locator('[data-cr-hd-check-btn]').is_disabled()
    assert app.server.checks == []
    assert app.errors == []


# --- runtime: apply and rollback ----------------------------------------------------------------

def test_runtime_audit_only_controls_are_not_offered_for_apply(open_app):
    app = open_app()
    page = _tab(app)
    page.locator('[data-cr-hd-profile]').select_option('vs-nfd')
    _check(app)
    assert app.server.checks[-1]['profile'] == 'vs-nfd'
    for c in ['net_protocols'] + VSNFD:
        box = page.locator(f'[data-cr-hd-pick="{c}"]')
        assert box.is_disabled(), c
        assert 'Audit only' in box.get_attribute('title'), c
        assert page.locator(f'[data-cr-hd-check="{c}"]').locator('xpath=ancestor::tr').locator('[data-cr-hd-flag="audit"]').count() == 1
    assert not page.locator('[data-cr-hd-pick="pw_quality"]').is_disabled()
    # a passing check has nothing to apply
    assert page.locator('[data-cr-hd-pick="journald"]').is_disabled()
    assert app.errors == []


def test_runtime_apply_and_rollback_keep_their_own_selection(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    _pick(page, 'mount_options')
    _pick(page, 'ssh_crypto')
    assert sorted(_picked(page)) == ['mount_options', 'ssh_crypto']
    assert page.locator('[data-cr-hd-go="apply"]').inner_text().strip() == 'Apply selected (2)'
    _mode(page, 'rollback')
    # rollback: only the four the catalog declares, nothing carried over
    assert _picked(page) == []
    assert page.locator('[data-cr-hd-mode-btn="rollback"] .cr-seg-n').inner_text() == '4'
    enabled = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-hd-pick]:not(:disabled)")).map(e => e.dataset.crHdPick).sort()')
    assert enabled == sorted(ROLLBACK)
    assert 'no rollback' in page.locator('[data-cr-hd-pick="mount_options"]').get_attribute('title')
    _pick(page, 'default_umask')
    assert page.locator('[data-cr-hd-go="rollback"]').inner_text().strip() == 'Roll back selected (1)'
    _mode(page, 'apply')
    assert sorted(_picked(page)) == ['mount_options', 'ssh_crypto']
    assert _writes(app) == []
    assert app.errors == []


def test_runtime_apply_goes_through_the_preview_and_keeps_every_answer(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    for c in ('mount_options', 'ssh_crypto', 'pve_fail2ban', 'audit_boot'):
        _pick(page, c)
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg = page.locator('[data-cr-hd-dialog="apply"]')
    dlg.wait_for(timeout=4000)
    text = dlg.inner_text()
    assert 'Apply 4 controls to pve1' in text and 'Declared by the control, not read from the node' in text
    # one row per control with its flags; files and cluster traffic are not declared
    assert dlg.locator('[data-cr-hd-plan-row]').count() == 4
    row = dlg.locator('[data-cr-hd-plan-row="ssh_crypto"]')
    assert 'yes, tick needed' in row.inner_text() and row.locator('[data-cr-hd-plan-rollback="yes"]').count() == 1
    assert dlg.locator('[data-cr-hd-plan-row="mount_options"] [data-cr-hd-plan-rollback="no"]').count() == 1
    assert dlg.locator('td', has_text='not declared').count() == 8
    assert '3 of 4 have no rollback' in dlg.locator('[data-cr-hd-risk="no-rollback"]').inner_text()
    assert 'Audit at Boot' in dlg.locator('[data-cr-hd-risk="reboot"]').inner_text() and dlg.locator('[data-cr-hd-risk="login"]').count() == 1
    # the access tick of classic holds the confirm
    assert dlg.locator('[data-cr-hd-confirm]').is_disabled() and _writes(app) == []
    dlg.locator('[data-cr-hd-ack="access"]').check()
    app.server.hold_apply = True
    dlg.locator('[data-cr-hd-confirm]').click()
    assert _poll(app, lambda: len(app.server.held_apply) == 1)
    # while it runs: pending, the running one and the queued ones; no second start
    page.locator('[data-cr-hd-run="apply"]').wait_for(timeout=4000)
    assert _stat(page, 'hd-pending') == '4'
    assert _state(page, 'mount_options') == 'running' and _state(page, 'audit_boot') == 'queued'
    assert page.locator('[data-cr-hd-check-btn]').is_disabled() and page.locator('[data-cr-hd-pick="file_perms"]').count() == 1
    assert page.locator('[data-cr-hd-pick="cron_hardening"]').is_disabled()
    app.server.hd_release()
    page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
    _poll(app, lambda: len(app.server.checks) == 2)
    page.wait_for_timeout(500)
    # the bodies of classic, one control per POST in the order of the list, no force
    assert app.server.applies == [{'controls': [c], 'params': {}} for c in ('mount_options', 'ssh_crypto', 'audit_boot', 'pve_fail2ban')]
    # the check after it ran, and what the apply answered is still there
    assert _state(page, 'mount_options') == 'passed' and _state(page, 'pve_fail2ban') == 'failed'
    kinds = page.evaluate('() => Object.fromEntries(Array.from(document.querySelectorAll("[data-cr-hd-out]")).map(e => [e.dataset.crHdOut, e.dataset.crHdKind]))')
    assert kinds == {'mount_options': 'applied', 'ssh_crypto': 'applied', 'pve_fail2ban': 'apply-failed', 'audit_boot': 'applied'}
    assert 'Applied this session' in page.locator('[data-cr-hd-out="mount_options"]').inner_text()
    assert '3 of 4 done' in page.locator('[data-cr-hd-last="apply"]').inner_text()
    # the reason of the failure in the detail, and a dismiss that is local
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='fail2ban').click()
    _need(page, '[data-cr-sidepanel="harden-control"]', 'the detail opens')
    assert page.locator('[data-cr-hd-out-error]').inner_text() == 'SSH command failed'
    assert page.locator('[data-cr-hd-history="not-recorded"]').count() == 1
    calls = len(app.server.calls)
    page.locator('[data-cr-hd-dismiss="pve_fail2ban"]').click()
    assert page.locator('[data-cr-hd-out="pve_fail2ban"]').count() == 0 and page.locator('[data-cr-hd-out]').count() == 3
    page.keyboard.press('Escape')
    page.locator('[data-cr-sidepanel]').wait_for(state='detached', timeout=4000)
    page.locator('[data-cr-hd-dismiss-all]').click()
    assert page.locator('[data-cr-hd-out]').count() == 0
    assert len(app.server.calls) == calls
    assert app.errors == []


def test_runtime_the_lockout_tick_sends_force_for_sshd_hardening_only(open_app):
    app = open_app(cluster={'has_ssh_key': False}, has_key=False)
    page = _tab(app)
    _check(app)
    _pick(page, 'sshd_hardening')
    _pick(page, 'pam_faillock')
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg = page.locator('[data-cr-hd-dialog="apply"]')
    dlg.wait_for(timeout=4000)
    assert dlg.locator('[data-cr-hd-lockout]').count() == 1
    dlg.locator('[data-cr-hd-ack="access"]').check()
    assert dlg.locator('[data-cr-hd-confirm]').is_disabled()
    dlg.locator('[data-cr-hd-ack="lockout"]').check()
    dlg.locator('[data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
    # pam_faillock carries its (empty) service_user default, as classic sends it
    assert app.server.applies == [{'controls': ['sshd_hardening'], 'params': {}, 'force': True},
                                  {'controls': ['pam_faillock'], 'params': {'pam_faillock': {'service_user': ''}}}]
    assert app.errors == []


def test_runtime_the_server_guard_answers_blocked_without_the_tick(open_app):
    # the cluster list does not say whether a key exists: no red tick, the server guard holds
    app = open_app(has_key=False)
    page = _tab(app)
    _check(app)
    _pick(page, 'sshd_hardening')
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg = page.locator('[data-cr-hd-dialog="apply"]')
    assert dlg.locator('[data-cr-hd-lockout]').count() == 0
    dlg.locator('[data-cr-hd-ack="access"]').check()
    dlg.locator('[data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-out="sshd_hardening"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-hd-out="sshd_hardening"]').get_attribute('data-cr-hd-kind') == 'blocked'
    assert _state(page, 'sshd_hardening') == 'failed'
    assert app.server.applies == [{'controls': ['sshd_hardening'], 'params': {}}]
    assert app.errors == []


def test_runtime_values_typed_in_the_detail_go_with_the_apply(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='Backup Nameserver').click()
    _need(page, '[data-cr-hd-params="backup_dns"]', 'a templated control takes its values in the detail')
    page.locator('[data-cr-hd-params="backup_dns"] [data-cr-hd-param="dns1"]').fill('10.0.0.53')
    page.keyboard.press('Escape')
    _pick(page, 'backup_dns')
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg = page.locator('[data-cr-hd-dialog="apply"]')
    assert 'dns1 = 10.0.0.53' in dlg.locator('[data-cr-hd-plan-values="backup_dns"]').inner_text()
    dlg.locator('[data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
    assert app.server.applies == [{'controls': ['backup_dns'], 'params': {'backup_dns': {'dns1': '10.0.0.53', 'dns2': '9.9.9.9'}}}]
    assert app.errors == []


def test_runtime_rollback_orders_the_ssh_pair_newest_first_and_says_what_it_restores(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    for c in ('ssh_crypto', 'sshd_hardening'):
        _pick(page, c)
        page.locator('[data-cr-hd-go="apply"]').click()
        dlg = page.locator('[data-cr-hd-dialog="apply"]')
        dlg.locator('[data-cr-hd-ack="access"]').check()
        dlg.locator('[data-cr-hd-confirm]').click()
        page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
        _poll(app, lambda: not page.locator('[data-cr-hd-run]').count())
        page.wait_for_timeout(300)
    _mode(page, 'rollback')
    _pick(page, 'ssh_crypto')
    _pick(page, 'sshd_hardening')
    page.locator('[data-cr-hd-go="rollback"]').click()
    dlg = page.locator('[data-cr-hd-dialog="rollback"]')
    dlg.wait_for(timeout=4000)
    assert dlg.locator('[data-cr-hd-risk="whole-files"]').count() == 1 and dlg.locator('[data-cr-hd-risk="sshd-restart"]').count() == 1
    order = dlg.locator('[data-cr-hd-risk="ssh-order"]').inner_text()
    assert order.index('SSH Access Hardening') < order.index('SSH Cryptographic Hardening'), order
    rows = dlg.locator('[data-cr-hd-plan-row]').evaluate_all('rs => rs.map(r => r.dataset.crHdPlanRow)')
    assert rows == ['sshd_hardening', 'ssh_crypto']
    dlg.locator('[data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-last="rollback"]').wait_for(timeout=8000)
    assert app.server.rollbacks == [{'controls': ['sshd_hardening', 'ssh_crypto']}]
    assert page.locator('[data-cr-hd-out="ssh_crypto"]').get_attribute('data-cr-hd-kind') == 'rolled-back'
    assert app.errors == []


def test_runtime_rollback_without_a_known_order_warns_and_shows_the_refusal(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    _mode(page, 'rollback')
    _pick(page, 'ssh_crypto')
    _pick(page, 'sshd_hardening')
    page.locator('[data-cr-hd-go="rollback"]').click()
    dlg = page.locator('[data-cr-hd-dialog="rollback"]')
    dlg.wait_for(timeout=4000)
    assert dlg.locator('[data-cr-hd-risk="ssh-order-unknown"]').count() == 1
    # Escape cancels, nothing is sent
    page.keyboard.press('Escape')
    assert dlg.count() == 0 and _writes(app) == []
    page.locator('[data-cr-hd-go="rollback"]').click()
    page.locator('[data-cr-hd-dialog="rollback"] [data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-last="rollback"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-hd-out="ssh_crypto"]').get_attribute('data-cr-hd-kind') == 'rollback-failed'
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='SSH Cryptographic Hardening').click()
    err = page.locator('[data-cr-hd-out-error]').inner_text()
    assert err.startswith('no snapshot found - control was never applied') and '\u2014' not in err
    assert app.errors == []


def test_runtime_a_standby_and_an_xcpng_pool_check_but_change_nothing(open_app):
    app = open_app(role='standby')
    page = _tab(app)
    _need(page, '[data-cr-hd-state="standby"]', 'a standby says it changes nothing')
    _check(app)
    assert page.locator('[data-cr-hd-go]').count() == 0 and page.locator('[data-cr-hd-mode-btn="apply"]').is_disabled()
    assert page.locator('[data-cr-hd-pick="mount_options"]').is_disabled()
    assert page.locator('[data-hp-manage]').count() == 0
    xcp = open_app(cluster={'cluster_type': 'xcpng'})
    page = _tab(xcp)
    _need(page, '[data-cr-hd-state="xcpng"]', 'XCP-ng says Apply and Rollback are off')
    _check(xcp)
    assert page.locator('[data-cr-hd-go]').count() == 0
    assert 'XCP-ng' in page.locator('[data-cr-hd-pick="mount_options"]').get_attribute('title')
    assert _writes(app) == [] and _writes(xcp) == []
    assert app.errors == [] and xcp.errors == []


# --- runtime: the detail, the session, the rest of the tab --------------------------------------

def test_runtime_the_detail_shows_evidence_command_and_what_is_declared(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    row = page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='SSH Cryptographic Hardening')
    row.focus()
    page.keyboard.press('Enter')
    panel = page.locator('[data-cr-sidepanel="harden-control"]')
    panel.wait_for(timeout=4000)
    assert 'CIS 5.1.6, 5.1.12, 5.1.15 · pve1' in panel.inner_text()
    assert panel.locator('[data-cr-hd-evidence]').inner_text() == EVIDENCE['ssh_crypto']
    assert 'grep -q pegaprox' in panel.locator('[data-cr-hd-command]').inner_text()
    assert 'Restores the files saved' in panel.locator('[data-cr-hd-decl-rollback]').inner_text()
    declared = panel.locator('[data-cr-hd-declared-list]').inner_text()
    assert declared.count('not declared') == 2
    assert panel.locator('[data-cr-hd-history="not-recorded"]').count() == 1
    page.keyboard.press('Escape')
    assert panel.count() == 0
    assert 'SSH Cryptographic Hardening' in page.evaluate('() => document.activeElement.innerText')
    # a control without detail says so
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='Mount Options Hardening').click()
    assert page.locator('[data-cr-hd-no-evidence]').count() == 1
    assert 'None: the change stays' in page.locator('[data-cr-hd-decl-rollback]').inner_text()
    assert app.errors == []


def test_runtime_the_session_survives_a_sub_tab_switch(open_app):
    app = open_app()
    page = _tab(app)
    _check(app)
    at = _stat(page, 'hd-at')
    page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Scheduled Actions\s*$')).first.click()
    page.wait_for_timeout(300)
    page.locator('.corp-tab-strip button', has_text=re.compile(r'^\s*Harden PVE Node\s*$')).first.click()
    _need(page, '[data-cr-hd-report]', 'the last check of the session is still there')
    assert _stat(page, 'hd-at') == at and len(app.server.checks) == 1
    assert app.errors == []


def test_runtime_profiles_and_exports_stay_reachable(open_app):
    app = open_app()
    page = _tab(app)
    _need(page, '[data-hp-manage]', 'Manage profiles is there for a manager')
    page.locator('[data-hp-manage]').click()
    _need(page, '[data-hp-dialog]', 'it opens the classic dialog')
    page.locator('[data-hp-dialog] button[aria-label="Close"]').first.click()
    page.wait_for_timeout(300)
    assert page.locator('[data-hp-dialog]').count() == 0
    page.locator('[data-cr-hd-profile]').select_option('custom:fedcba9876543210')
    assert page.locator('[data-cr-hd-export="pdf"]').is_disabled()
    app.server.check_answer = None
    _check(app)
    assert app.server.checks[-1]['profile'] == 'custom:fedcba9876543210'
    assert page.locator('[data-hp-ran]').inner_text() == 'Backup hosts'
    assert page.locator('[data-cr-hd-check]').count() == 2
    assert not page.locator('[data-cr-hd-export="pdf"]').is_disabled() and not page.locator('[data-cr-hd-export="png"]').is_disabled()
    # save selection takes the picks of the Profile mode (stage X: any control, a passed one too)
    page.locator('[data-cr-hd-profile]').select_option('')
    _check(app)
    _mode(page, 'profile')
    _pick(page, 'mount_options')
    page.locator('[data-hp-save-selection]').click()
    _need(page, '[data-hp-dialog]', 'save selection opens the editor')
    assert app.errors == []


@pytest.mark.parametrize('engine,size', [('chromium', (1600, 1000)), ('chromium', (1280, 800)),
                                         ('firefox', (1600, 1000)), ('firefox', (1280, 800))],
                         ids=['chromium-1600', 'chromium-1280', 'firefox-1600', 'firefox-1280'])
def test_runtime_the_tab_fits_without_sideways_scroll(open_app, engine, size):
    app = open_app(engine=engine, viewport=size)
    page = _tab(app)
    _check(app)
    over = '() => document.documentElement.scrollWidth - window.innerWidth'
    assert page.evaluate(over) <= 0
    inner = page.locator('[data-cr-table="hd-controls"] .cr-table-scroll').evaluate('e => e.scrollWidth - e.clientWidth')
    assert inner <= 1, inner
    _pick(page, 'mount_options')
    _pick(page, 'ssh_crypto')
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg = page.locator('[data-cr-hd-dialog="apply"]')
    dlg.wait_for(timeout=4000)
    box = dlg.bounding_box()
    assert box['x'] >= 0 and box['x'] + box['width'] <= size[0] and box['y'] >= 0
    assert page.evaluate(over) <= 0
    page.keyboard.press('Escape')
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='Journald Hardening').click()
    panel = page.locator('[data-cr-sidepanel="harden-control"]')
    panel.wait_for(timeout=4000)
    # the slide-in has to end first
    panel.evaluate('e => Promise.all(e.getAnimations().map(a => a.finished))')
    pb = panel.bounding_box()
    assert pb['x'] + pb['width'] <= size[0] + 0.5
    assert page.evaluate(over) <= 0
    assert app.errors == []


# --- stage X: what the review of round 4 found -----------------------------------------------------

def _relogin(app, perms, username='ops'):
    """Logout from the user menu and sign in as another account in the same page load (the page is
    not reloaded on a logout, contexts.js)."""
    page = app.page
    page.get_by_label('User menu').click()
    page.get_by_text('Logout', exact=True).click()
    page.wait_for_selector('input[type=password]', timeout=8000)
    srv = app.server
    user = {'username': username, 'role': 'viewer', 'display_name': username, 'ui_layout': srv.layout, 'layout_chosen': True,
            'theme': '', 'language': 'en', 'permissions': perms, 'enabled': True}
    srv.extra[('POST', '/api/auth/login')] = (200, {'success': True, 'session_id': 'sid2', 'user': user, 'default_theme': 'proxmoxDark'})
    srv.logged_out, srv.admin, srv.permissions = False, False, perms
    page.fill('input[type=text], input[name=username], input#username', username)
    page.fill('input[type=password]', 'x')
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelector("header")', timeout=10000)
    page.wait_for_timeout(800)
    return page


def test_runtime_the_next_account_of_the_tab_starts_without_the_check_of_the_one_before(open_app):
    # R-02: what one account checked and applied is not shown to the next one of the same page load
    app = open_app()
    page = _tab(app)
    _check(app)
    _pick(page, 'mount_options')
    page.locator('[data-cr-hd-go="apply"]').click()
    page.locator('[data-cr-hd-dialog="apply"] [data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-hd-out="mount_options"]').count() == 1
    checks = len(app.server.checks)
    # another account that may harden: it sees nothing of the check, the answers or the last run
    page = _relogin(app, ['cluster.view', 'node.view', 'vm.view', 'node.maintenance'])
    page = _tab(app)
    _need(page, '[data-cr-hd-empty="not-checked"]', 'the next account starts with nothing checked')
    assert page.locator('[data-cr-hd-report]').count() == 0 and page.locator('[data-cr-hd-last]').count() == 0
    assert page.locator('[data-cr-hd-pick]').count() == 0
    assert len(app.server.checks) == checks
    assert app.errors == []


def test_runtime_a_passed_control_goes_into_a_profile_and_applies_again_with_a_new_value(open_app):
    # R-05: Save selection as profile has its own pick (any control, passed and audit only ones too);
    # a passed templated control can be applied again once another value is typed for it
    app = open_app()
    app.server.node_state('pve1')['backup_dns'] = True
    page = _tab(app)
    _check(app)
    assert page.locator('[data-hp-save-selection]').is_disabled(), 'nothing picked for a profile yet'
    box = page.locator('[data-cr-hd-pick="backup_dns"]')
    assert box.is_disabled() and 'Type another value' in box.get_attribute('title')
    assert page.locator('[data-cr-hd-pick="journald"]').is_disabled()
    _mode(page, 'profile')
    assert page.locator('[data-cr-hd-mode-btn="profile"] .cr-seg-n').inner_text() == str(len(CIS))
    for c in ('journald', 'net_protocols', 'mount_options'):
        _pick(page, c)
    assert page.locator('[data-cr-hd-go="profile"]').inner_text().strip() == 'Save selection as profile (3)'
    page.locator('[data-hp-save-selection]').click()
    editor = page.locator('[data-hp-editor]')
    editor.wait_for(timeout=4000)
    for c in ('journald', 'net_protocols', 'mount_options'):
        assert editor.locator(f'[data-hp-control="{c}"] input[type="checkbox"]').is_checked(), c
    assert editor.locator('[data-hp-count]').inner_text().startswith('3 of ')
    page.locator('[data-hp-dialog] button', has_text=re.compile(r'^\s*Cancel\s*$')).first.click()
    page.wait_for_timeout(300)
    # back to Apply: the profile picks are not applied, the passed one is offered once a value differs
    _mode(page, 'apply')
    assert _picked(page) == []
    page.locator('[data-cr-table="hd-controls"] tbody tr.cr-row', has_text='Backup Nameserver').click()
    page.locator('[data-cr-hd-params="backup_dns"] [data-cr-hd-param="dns1"]').fill('10.0.0.53')
    page.keyboard.press('Escape')
    assert not box.is_disabled()
    _pick(page, 'backup_dns')
    page.locator('[data-cr-hd-go="apply"]').click()
    page.locator('[data-cr-hd-dialog="apply"] [data-cr-hd-confirm]').click()
    page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
    assert app.server.applies == [{'controls': ['backup_dns'], 'params': {'backup_dns': {'dns1': '10.0.0.53', 'dns2': '9.9.9.9'}}}]
    assert app.errors == []


def test_runtime_the_dialog_says_when_the_node_is_in_maintenance_or_updating(open_app):
    # R-06: the node list knows; the apply and rollback routes do not look, so the dialog says it
    from test_corp_redesigned_guard_ui import METRICS
    metrics = {'pve1': dict(METRICS['pve1'], maintenance_mode=True, is_updating=True), 'pve2': dict(METRICS['pve2'])}
    app = open_app(metrics=metrics)
    page = _tab(app)
    _check(app)
    _pick(page, 'mount_options')
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg = page.locator('[data-cr-hd-dialog="apply"]')
    dlg.wait_for(timeout=4000)
    assert 'pve1 is in maintenance mode' in dlg.locator('[data-cr-hd-risk="node-maintenance"]').inner_text()
    assert 'An update runs on pve1 now' in dlg.locator('[data-cr-hd-risk="node-updating"]').inner_text()
    page.keyboard.press('Escape')
    # a node without either: no such line
    page.locator('[data-cr-hd-node]').select_option('pve2')
    _check(app)
    _pick(page, 'mount_options')
    page.locator('[data-cr-hd-go="apply"]').click()
    dlg.wait_for(timeout=4000)
    assert dlg.locator('[data-cr-hd-risk^="node-"]').count() == 0
    assert app.errors == []


def test_runtime_after_the_apply_dialog_the_focus_stays_in_the_tab(open_app):
    # R-14: the Apply button is disabled while the run goes; the focus goes to the report, not the page
    app = open_app()
    page = _tab(app)
    _check(app)
    _pick(page, 'mount_options')
    page.locator('[data-cr-hd-go="apply"]').focus()
    page.keyboard.press('Enter')
    page.locator('[data-cr-hd-dialog="apply"]').wait_for(timeout=4000)
    app.server.hold_apply = True
    page.locator('[data-cr-hd-dialog="apply"] [data-cr-hd-confirm]').click()
    assert _poll(app, lambda: len(app.server.held_apply) == 1)
    page.wait_for_timeout(300)
    where = page.evaluate('() => document.activeElement === document.body ? "BODY" : document.activeElement.hasAttribute("data-cr-hd-report")')
    assert where is True, where
    app.server.hd_release()
    page.locator('[data-cr-hd-last="apply"]').wait_for(timeout=8000)
    assert app.errors == []


def test_runtime_enter_right_after_arrow_down_opens_the_row_below(open_app):
    # CrTable: the focus of a keyboard move came from a passive effect, so Enter pressed right after
    # ArrowDown (its own input task) reached the row before and opened its detail. Four times in a row.
    app = open_app()
    page = _tab(app)
    _check(app)
    title = lambda i: page.locator(f'[data-cr-table="hd-controls"] tbody tr[data-row-index="{i}"] .cr-hd-ctl .cr-strong').inner_text()
    page.locator('[data-cr-table="hd-controls"] tbody tr[data-row-index="0"]').focus()
    for i in range(1, 5):
        want = title(i)
        page.keyboard.press('ArrowDown')
        page.keyboard.press('Enter')
        panel = page.locator('[data-cr-sidepanel="harden-control"]')
        panel.wait_for(timeout=4000)
        got = panel.locator('.cr-sp-title').inner_text()
        assert got == want, (i, got, want)
        page.keyboard.press('Escape')
        panel.wait_for(state='detached', timeout=4000)
        page.wait_for_function(f'() => document.activeElement?.dataset?.rowIndex === "{i}"', timeout=4000)
    assert app.errors == []
