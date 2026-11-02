"""The compliance dashboard of Corporate Redesigned (Preview) in the browser.

The preview draws the answers ComplianceDashboardTab already reads. A control whose result did
not come back is "not checked": it is never added to the passed ones, no score and no rate
divides by it, and the coverage says how much was checked at all. Framework cards score only
what was checked, the custom hardening profiles keep their card (data-hp-score), and the report
button runs the classic report. The server side of the same rule is
tests/test_compliance_score_is_honest.py. Runs against the fake server of tests/test_ha_ui.py
and skips without Playwright. LW Oct 2026
"""
import json
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_corp_redesigned_dashboard_ui import _DashServer, _stat
from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp
from test_ha_ui import BASE
from test_hardening_custom_profiles_ui import P1

LAYOUT = 'corporate-redesigned'

# True passed, False failed, None no result. ssh_perms on pve1 comes back verbose, with evidence
VERDICTS = {
    'pve1': {'fs_modules': True, 'core_dumps': False, 'mount_options': None, 'journald': True,
             'ssh_perms': {'status': False, 'actual': 'PermitRootLogin yes'},
             'pam_faillock': False, 'backup_dns': None},
    'pve2': {'fs_modules': True, 'core_dumps': True, 'mount_options': True, 'journald': None, 'ssh_perms': True,
             'pam_faillock': True, 'backup_dns': True},
}
BUILTIN = ['fs_modules', 'core_dumps', 'mount_options', 'journald', 'ssh_perms']


class _CmpServer(_DashServer):
    """Testi with three nodes: pve1 and pve2 answer the check, pve3 cannot be reached."""

    def __init__(self, nodes_status=200, cluster_wide=False, **kw):
        extra = {('GET', '/api/clusters/c1/nodes'): (nodes_status, [{'node': n} for n in ('pve1', 'pve2', 'pve3')]
                                                     if nodes_status == 200 else {'error': 'nope'})}
        extra.update(kw.pop('extra', {}))
        super().__init__(extra=extra, **kw)
        self.cluster_wide = cluster_wide

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/c1/nodes/([^/]+)/hardening', path)
        if req.url.startswith(BASE) and m and req.method == 'GET':
            self.calls.append((req.method, path))
            self.urls.append(req.url)
            node = m.group(1)
            profile = (parse_qs(urlparse(req.url).query).get('profile') or [''])[0]
            if self.cluster_wide:
                status, body = 409, {'error': 'No SSH credentials', 'code': 'SSH_NO_CREDENTIALS', 'cluster_wide': True}
            elif node not in VERDICTS:
                status, body = 502, {'error': 'SSH failed', 'code': 'SSH_FAILED'}
            else:
                ids = P1['controls'] if profile == f'custom:{P1["id"]}' else BUILTIN
                status, body = 200, {'node': node, 'profile': profile, 'controls': {c: VERDICTS[node][c] for c in ids}}
            return route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})
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
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, **kw):
        app = _GuardApp(browser, _CmpServer(layout=layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _compliance(page, rows=True):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="compliance"]').click()
    page.locator('[data-cr-compliance]').wait_for(timeout=20000)
    if rows:
        page.wait_for_function('() => document.querySelectorAll("[data-cr-table=cmp-nodes] tr.cr-row").length === 3', timeout=20000)
        page.wait_for_function('() => !/^-$/.test((document.querySelector("[data-cr-stat=checked] .cr-stat-value") || {}).innerText || "-")', timeout=20000)


def _rows(page, table):
    return page.evaluate('''(t) => Array.from(document.querySelectorAll(`[data-cr-table="${t}"] tbody tr.cr-row`))
        .map(tr => Array.from(tr.querySelectorAll('td')).map(td => td.innerText.trim()))''', table)


def _states(page):
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-table="cmp-controls"] tbody tr.cr-row'))
        .map(tr => [tr.querySelectorAll('td')[2].innerText.trim(), tr.querySelector('[data-cr-cmp-state]').dataset.crCmpState]))''')


def _wait_for_url(page, app, needle, timeout=20):
    # the request goes out from an effect after the render that dropped the card
    for _ in range(int(timeout * 5)):
        if any(needle in u for u in app.server.urls):
            return
        page.wait_for_timeout(200)
    raise AssertionError(f'no request with {needle}')


def _card(page, fw):
    box = page.locator(f'[data-cr-fw="{fw}"]')
    return {'score': box.locator('[data-cr-fw-score]').get_attribute('data-cr-fw-score'),
            'text': box.inner_text(),
            'report': box.locator('[data-cr-fw-report]').is_enabled() if box.locator('[data-cr-fw-report]').count() else None}


def test_runtime_not_checked_is_never_passed(open_app):
    app = open_app()
    page = app.page
    _compliance(page)
    # pve1: 2 of 4 checked passed (50 %), pve2: 4 of 4 (100 %); one result each did not come back
    assert _stat(page, 'score')['value'] == '75%'        # (50 + 100) / 2; counting the gaps as passed would say 80 %
    assert _stat(page, 'passed')['value'] == '6'
    assert _stat(page, 'failed')['value'] == '2'
    assert _stat(page, 'unchecked')['value'] == '2'
    assert _stat(page, 'coverage')['value'] == '80%'     # 8 of 10 results checked
    assert 'of 8 checked results' in _stat(page, 'passed')['sub']
    assert _stat(page, 'nodes')['value'] == '2/3'
    assert '1 unavailable' in _stat(page, 'nodes')['sub']
    assert _stat(page, 'checked')['value'] != '-'
    # one row per control; a control without any result never reads as passed
    assert _states(page) == {'fs_modules': 'passed', 'core_dumps': 'failed', 'ssh_perms': 'failed',
                             'mount_options': 'partly', 'journald': 'partly'}
    rows = {r[2]: r for r in _rows(page, 'cmp-controls')}
    assert rows['core_dumps'][4:7] == ['1', '1', '0'] and rows['core_dumps'][7] == 'Failed on pve1'
    assert rows['mount_options'][4:7] == ['1', '0', '1'] and rows['mount_options'][7] == 'No result from pve1'
    # the evidence column is there because pve1 sent some
    assert page.locator('[data-cr-table="cmp-controls"] th[data-cr-col="evidence"]').count() == 1
    assert any('PermitRootLogin yes' in ' '.join(r) for r in _rows(page, 'cmp-controls'))
    # the chips: not checked holds the partly checked ones too
    counts = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-cmp-show]'))
        .map(b => [b.dataset.crCmpShow, b.querySelector('.cr-seg-n').innerText]))''')
    assert counts == {'all': '5', 'failed': '2', 'unchecked': '2', 'passed': '1'}
    page.locator('[data-cr-cmp-show="passed"]').click()
    assert list(_states(page)) == ['fs_modules']
    page.locator('[data-cr-cmp-show="unchecked"]').click()
    assert sorted(_states(page)) == ['journald', 'mount_options']
    # the nodes: scores, the reason pve3 has none
    nodes = {r[1]: r for r in _rows(page, 'cmp-nodes')}
    assert nodes['pve1'][2:6] == ['50%', '2', '2', '1'] and nodes['pve2'][2:6] == ['100%', '4', '0', '1']
    assert nodes['pve3'][2] == '-' and 'unavailable' in nodes['pve3'][6].lower()
    assert app.errors == []


def test_runtime_framework_cards_score_only_what_was_checked(open_app):
    app = open_app()
    page = app.page
    _compliance(page)
    bsi = _card(page, 'bsi')
    assert bsi['score'] == '75'                       # 6 of 8 checked BSI results
    assert '6 of 8 checked passed' in bsi['text'] and '2 not checked' in bsi['text']
    assert bsi['report'] is True
    assert page.locator('[data-cr-fw="bsi"] .cr-cmp-bar').get_attribute('aria-label') == '6 passed, 2 failed, 2 not checked'
    # nothing of FIPS or VS-NfD was checked: no percentage, no report
    for fw in ('fips', 'vsnfd'):
        card = _card(page, fw)
        assert card['score'] == '' and 'No checked controls yet' in card['text'] and card['report'] is False, fw
    # NIS2 is an indicator: no report even with data
    nis2 = _card(page, 'nis2')
    assert 'Indicator' in nis2['text'] and nis2['report'] is False
    # no long dash in what the preview prints
    assert '\u2014' not in page.locator('[data-cr-compliance]').inner_text()
    # a card's controls button narrows the control table to that framework
    page.locator('[data-cr-fw="stig"] [data-cr-fw-show]').click()
    assert page.locator('[data-cr-cmp-fw]').input_value() == 'stig'
    assert sorted(_states(page)) == ['core_dumps', 'fs_modules', 'ssh_perms']
    # the report button runs the classic report (mapping read, or the missing PDF library)
    page.locator('[data-cr-fw="bsi"] [data-cr-fw-report]').click()
    page.wait_for_function('''() => document.body.innerText.includes('PDF library not loaded')
        || document.body.innerText.includes('Could not load compliance mapping')
        || document.body.innerText.includes('Generating')''', timeout=8000)
    assert app.errors == []


def test_runtime_custom_profiles_keep_their_card(open_app):
    app = open_app()
    page = app.page
    _compliance(page)
    sel = page.locator('[data-cr-cmp-profile]')
    assert sel.locator('optgroup option').all_inner_texts() == ['Backup hosts', 'Web tier']
    sel.select_option(f'custom:{P1["id"]}')
    page.locator('[data-hp-score]').wait_for(timeout=20000)
    page.wait_for_function('() => document.querySelector("[data-hp-score] [data-cr-fw-score]").dataset.crFwScore === "80"', timeout=20000)
    card = page.locator('[data-hp-score]').inner_text()
    # pve1: fs_modules passed, pam_faillock failed, backup_dns no result; pve2 all three passed
    assert 'Web tier' in card and '4 of 5 checked passed' in card and '1 not checked' in card
    assert any(f'profile=custom%3A{P1["id"]}' in u or f'profile=custom:{P1["id"]}' in u for u in app.server.urls)
    assert page.locator('[data-cr-cmp-fw] option[value="custom"]').inner_text() == 'Web tier'
    # another built-in profile asks the nodes again with that profile
    sel.select_option('vs-nfd')
    page.wait_for_function('() => !document.querySelector("[data-hp-score]")', timeout=20000)
    _wait_for_url(page, app, 'profile=vs-nfd')
    assert app.errors == []


def test_runtime_a_cluster_without_ssh_says_why(open_app):
    app = open_app(cluster_wide=True)
    page = app.page
    _compliance(page, rows=False)
    page.locator('[data-cr-cmp-cluster-error]').wait_for(timeout=20000)
    text = page.locator('[data-cr-cmp-cluster-error]').inner_text()
    assert 'Compliance checks cannot run on this cluster' in text and 'SSH' in text
    # the classic reason carries a long dash; the preview prints a hyphen
    assert '\u2014' not in text
    assert _stat(page, 'score')['value'] == '-' and _stat(page, 'passed')['value'] == '0'
    assert _stat(page, 'coverage')['value'] == '-'
    assert app.errors == []


def test_runtime_a_failed_node_list_shows_nothing_as_passed(open_app):
    app = open_app(nodes_status=500)
    page = app.page
    _compliance(page, rows=False)
    page.wait_for_function('() => document.querySelector("[data-cr-table=cmp-nodes] td.cr-state")', timeout=20000)
    page.wait_for_timeout(500)
    assert _stat(page, 'score')['value'] == '-'
    assert _stat(page, 'passed')['value'] == '0' and _stat(page, 'coverage')['value'] == '-'
    assert _stat(page, 'checked')['value'] == '-'
    assert _card(page, 'bsi')['score'] == ''
    assert app.errors == [] or all('500' in e for e in app.errors)


def test_runtime_the_control_titles_follow_a_language_switch(open_app):
    """My Profile switches the language in place. The control rows are worked out once per
    answer, their titles must still come along, as the rest of the page does."""
    app = open_app()
    page = app.page
    _compliance(page)
    titles = lambda: {r[2]: r[1] for r in _rows(page, 'cmp-controls')}
    assert titles()['core_dumps'] == 'Disable core dumps'
    asked = len([c for c in app.server.calls if c[1].endswith('/hardening')])
    page.locator('[data-user-menu]').click()
    page.get_by_text('My Profile').first.click()
    page.locator('select[aria-label="Select language"]').select_option('de')
    # the page around the rows is German now
    page.locator('[data-cr-stat="passed"]', has_text='Bestanden').wait_for(timeout=5000)
    page.locator('[data-cr-cmp-show="unchecked"]', has_text='Nicht geprüft').wait_for(timeout=5000)
    assert titles()['core_dumps'] == 'Core-Dumps deaktivieren'
    assert titles()['journald'] == 'journald persistent + komprimiert'
    # from the answers it already had: the switch asks the nodes nothing
    assert len([c for c in app.server.calls if c[1].endswith('/hardening')]) == asked
    assert _stat(page, 'score')['value'] == '75%'
    assert app.errors == []


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_keep_the_classic_dashboard(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.get_by_text('Compliance Dashboard').first.wait_for(timeout=20000)
    assert page.locator('[data-cr-compliance]').count() == 0
    page.locator('[data-compliance-sub="hardening"]').wait_for(timeout=5000)
    assert app.errors == []
